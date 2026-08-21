//! Preemptive round-robin scheduler with real context switches, including
//! switching page tables (CR3) and the kernel stack used for interrupts /
//! syscalls (TSS.RSP0) when hopping between kernel and userspace tasks.
//!
//! SMP-aware: each CPU has its own scheduler instance accessed via LAPIC ID.
//! Protected by spinlocks to prevent cross-core race conditions.
//! Task structures are individually heap-allocated (Boxed) to guarantee
//! stable memory addresses and prevent dangling pointers during resizes.
//!
//! Advanced Scheduling Modes:
//! 1. Fair Scheduling (Default out of the box):
//!    - CFS-like scheduling sorted by virtual completion time (vruntime).
//!    - Tasks stored in a custom balanced WAVL-tree.
//!    - Higher weight tasks grow vruntime slower and get proportionally more CPU time.
//! 2. Deadline Scheduling:
//!    - Guaranteed CPU time (capacity) per period.
//!    - High priority: always executed before any Fair tasks.
//!    - Multi-task deadline scheduled via Earliest Deadline First (EDF).

use crate::task::{Task, TaskKind};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use huesos_arch::{LockRank, RankedIrqSafeTicketLock};
use huesos_lifecycle::{InsertOutcome, TaskGraveyard};
use huesos_object::{KernelObject, Process};
use huesos_sched::{
    clock::TscClock,
    eevdf::{EevdfKey, EevdfTree},
    job::{JobId, JobState},
    task_operations, AdmissionControl, CbsReservation, CpuIndex, TaskDirectory, TaskId as V2TaskId,
    TaskInbox, TaskLocation, TaskSlotAllocator,
};
use x86_64::VirtAddr;

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 64;
/// Fixed capacity of the per-CPU fair runqueue tree.
pub const MAX_FAIR_TASKS: usize = 256;
/// Approximate service charged per scheduler tick, in ns. The periodic
/// LAPIC timer fires at ~100 Hz, so a tick is ~10 ms; this is only a
/// nominal accounting unit until the tickless deadline path lands.
pub const TICK_SERVICE_NS: u64 = 10_000_000;
/// Nominal tick period in ns used to re-arm the TSC-deadline timer.
pub const TICK_NS: u64 = 10_000_000;
/// Whether this CPU runs the one-shot TSC-deadline scheduler timer.
static TSC_DEADLINE_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// Task IDs are opaque capabilities implemented by `huesos_sched::TaskId`: a
// global slot index plus a slot generation. CPU ownership is deliberately NOT
// encoded in the ID; migration publishes a new owner through the directory and
// keeps the identity stable. A delayed wake carrying an older generation can
// therefore never wake an unrelated task after slot reuse, and no alias table
// is needed when a task migrates.
static TASK_DIRECTORY: TaskDirectory = TaskDirectory::new();
static TASK_SLOTS: TaskSlotAllocator = TaskSlotAllocator::new();
/// Per-CPU bitmap inbox for allocation-free async remote operations.
static CPU_INBOX: [TaskInbox; MAX_CPUS] = [const { TaskInbox::new() }; MAX_CPUS];
/// Kernel Job accounting. Slot 0 is the root/system Job; all tasks default
/// to it until a privileged policy assigns them a resource domain.
static JOB_TABLE: spin::Once<RankedIrqSafeTicketLock<JobState<MAX_CPUS>>> = spin::Once::new();
/// Per-CPU CBS + threaded-IRQ admission ceilings. The initial 80% ceiling is
/// shared by all reservations on a CPU; the remaining 20% is reserved for
/// Fair work, hard IRQs, IPIs, and scheduler overhead.
static CBS_ADMISSION: [RankedIrqSafeTicketLock<AdmissionControl>; MAX_CPUS] = [const {
    RankedIrqSafeTicketLock::new(AdmissionControl::production_default(), LockRank::SCHEDULER)
}; MAX_CPUS];

/// Resolve a Task ID to its current owner and owner-local queue slot.
fn task_location(id: u64) -> Option<TaskLocation> {
    TASK_DIRECTORY.locate(V2TaskId::from_raw(id)?).ok()
}

/// Bit N set => dense CPU index N is online for load-balancing/IPI routing.
/// Firmware LAPIC IDs are intentionally not used as bit positions because they
/// can be sparse or greater than `MAX_CPUS`; `lapic_id_for_cpu_index` resolves
/// the APIC ID at the final IPI boundary.
static ONLINE_CPUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

const RUNQUEUE_TOKEN_FREE: usize = usize::MAX;
const TOKEN_MAILBOX_EMPTY: usize = 0;
const TOKEN_MAILBOX_FILLING: usize = 1;
const TOKEN_MAILBOX_PENDING: usize = 2;
const TOKEN_MAILBOX_GRANTED: usize = 3;
const TOKEN_WAIT_ITERS: usize = 100_000;

static RUNQUEUE_TOKENS: [AtomicUsize; MAX_CPUS] =
    [const { AtomicUsize::new(RUNQUEUE_TOKEN_FREE) }; MAX_CPUS];
static TOKEN_MAILBOX_STATE: [AtomicUsize; MAX_CPUS] =
    [const { AtomicUsize::new(TOKEN_MAILBOX_EMPTY) }; MAX_CPUS];
static TOKEN_MAILBOX_REQUESTER: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];
static TOKEN_MAILBOX_REQUEST_ID: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static NEXT_TOKEN_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

struct RunqueueTokenGuard {
    cpu: usize,
    remote: bool,
    request_id: u64,
}

impl Drop for RunqueueTokenGuard {
    fn drop(&mut self) {
        if self.remote {
            RUNQUEUE_TOKENS[self.cpu].store(RUNQUEUE_TOKEN_FREE, Ordering::Release);
            if TOKEN_MAILBOX_REQUEST_ID[self.cpu].load(Ordering::Acquire) == self.request_id {
                TOKEN_MAILBOX_STATE[self.cpu].store(TOKEN_MAILBOX_EMPTY, Ordering::Release);
            }
        }
    }
}

fn process_runqueue_token_mailbox(cpu: usize) {
    if cpu >= MAX_CPUS || TOKEN_MAILBOX_STATE[cpu].load(Ordering::Acquire) != TOKEN_MAILBOX_PENDING
    {
        return;
    }
    let requester = TOKEN_MAILBOX_REQUESTER[cpu].load(Ordering::Acquire);
    if requester >= MAX_CPUS {
        TOKEN_MAILBOX_STATE[cpu].store(TOKEN_MAILBOX_EMPTY, Ordering::Release);
        return;
    }
    if RUNQUEUE_TOKENS[cpu]
        .compare_exchange(
            RUNQUEUE_TOKEN_FREE,
            requester,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
        && TOKEN_MAILBOX_STATE[cpu]
            .compare_exchange(
                TOKEN_MAILBOX_PENDING,
                TOKEN_MAILBOX_GRANTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        // Requester canceled after we acquired the token but before the
        // grant was published. Do not leave a token nobody will release.
        RUNQUEUE_TOKENS[cpu].store(RUNQUEUE_TOKEN_FREE, Ordering::Release);
    }
}

fn cancel_runqueue_token_request(cpu: usize, requester: usize, request_id: u64) {
    if TOKEN_MAILBOX_REQUEST_ID[cpu].load(Ordering::Acquire) != request_id {
        return;
    }
    if TOKEN_MAILBOX_STATE[cpu]
        .compare_exchange(
            TOKEN_MAILBOX_PENDING,
            TOKEN_MAILBOX_EMPTY,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        return;
    }
    if TOKEN_MAILBOX_REQUEST_ID[cpu].load(Ordering::Acquire) == request_id
        && TOKEN_MAILBOX_STATE[cpu].load(Ordering::Acquire) == TOKEN_MAILBOX_GRANTED
    {
        let _ = RUNQUEUE_TOKENS[cpu].compare_exchange(
            requester,
            RUNQUEUE_TOKEN_FREE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let _ = TOKEN_MAILBOX_STATE[cpu].compare_exchange(
            TOKEN_MAILBOX_GRANTED,
            TOKEN_MAILBOX_EMPTY,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn acquire_runqueue_token(cpu: usize) -> Option<RunqueueTokenGuard> {
    let current = cpu_id();
    if cpu >= MAX_CPUS {
        return None;
    }
    if cpu == current {
        return Some(RunqueueTokenGuard {
            cpu,
            remote: false,
            request_id: 0,
        });
    }
    if !is_cpu_online(cpu) {
        return None;
    }
    let request_id = NEXT_TOKEN_REQUEST_ID.fetch_add(1, Ordering::Relaxed).max(1);
    for _ in 0..TOKEN_WAIT_ITERS {
        if TOKEN_MAILBOX_STATE[cpu]
            .compare_exchange(
                TOKEN_MAILBOX_EMPTY,
                TOKEN_MAILBOX_FILLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            TOKEN_MAILBOX_REQUESTER[cpu].store(current, Ordering::Release);
            TOKEN_MAILBOX_REQUEST_ID[cpu].store(request_id, Ordering::Release);
            TOKEN_MAILBOX_STATE[cpu].store(TOKEN_MAILBOX_PENDING, Ordering::Release);
            if let Some(apic_id) = lapic_id_for_cpu_index(cpu) {
                huesos_arch::lapic::ipi_reschedule(apic_id);
            }
            break;
        }
        core::hint::spin_loop();
    }
    for _ in 0..TOKEN_WAIT_ITERS {
        if TOKEN_MAILBOX_REQUEST_ID[cpu].load(Ordering::Acquire) == request_id
            && TOKEN_MAILBOX_STATE[cpu].load(Ordering::Acquire) == TOKEN_MAILBOX_GRANTED
        {
            return Some(RunqueueTokenGuard {
                cpu,
                remote: true,
                request_id,
            });
        }
        core::hint::spin_loop();
    }
    cancel_runqueue_token_request(cpu, current, request_id);
    None
}

/// Hardware-timer-driven monotonic clock. Only CPU 0 advances it, so SMP does
/// not make time run faster. Cooperative yields never affect this clock.
static MONOTONIC_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// --- Scheduler observability counters (aggregate, for boot/CI evidence) ---

/// Total completed context switches across all CPUs.
static OBS_CTX_SWITCHES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Remote wake publications routed through the inbox.
static OBS_REMOTE_WAKES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Coalesced reschedule IPIs actually sent.
static OBS_RESCHED_IPIS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Inbox drain passes (unique slots processed).
static OBS_INBOX_DRAINS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Per-CPU IRQ event storm accounting (pending/masked), aggregated.
static OBS_IRQ_STORM_MASKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Fixed-point TSC clock, calibrated once during late init. Used for
/// nanosecond scheduling time; the periodic LAPIC tick remains the wait
/// clock until the tickless deadline path replaces it.
static TSC_CLOCK: spin::Once<TscClock> = spin::Once::new();

/// Mark the current CPU as online for task placement.
pub fn mark_cpu_online() {
    let id = cpu_id();
    if id < 64 {
        ONLINE_CPUS.fetch_or(1u64 << id, Ordering::SeqCst);
    }
}

/// True if the given LAPIC id has a live scheduler ready for work.
pub fn is_cpu_online(cpu: usize) -> bool {
    if cpu >= 64 {
        return false;
    }
    (online_cpu_mask() & (1u64 << cpu)) != 0
}

/// Dense CPU mask for online scheduler instances.
pub fn online_cpu_mask() -> u64 {
    ONLINE_CPUS.load(Ordering::SeqCst)
}

/// Number of online CPUs.
pub fn online_cpu_count() -> usize {
    online_cpu_mask().count_ones() as usize
}

/// Dense CPU index of the caller.
pub fn current_cpu_index() -> usize {
    cpu_id()
}

/// Number of online CPUs other than the caller, used by global TLB shootdowns.
pub fn online_remote_cpu_count() -> usize {
    ONLINE_CPUS
        .load(Ordering::SeqCst)
        .count_ones()
        .saturating_sub(1) as usize
}

/// Saved CPU context for a task.
pub type SchedContext = huesos_arch::context_switch::Context;

#[derive(Clone, Copy)]
struct SwitchTarget {
    old: *mut SchedContext,
    new: *const SchedContext,
    new_guards: *mut huesos_sched::ExecutionGuards,
}

/// Install the incoming Task's preemption/migration state immediately before
/// switching stacks. Every caller has already dropped the scheduler lock and
/// keeps local interrupts disabled.
fn perform_context_switch(target: SwitchTarget) {
    OBS_CTX_SWITCHES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: Task allocations are stable while schedulable; the scheduler
    // selected `new`, owns its guard state, and disabled local interrupts.
    unsafe {
        huesos_arch::cpu_local::install_execution_guards(target.new_guards);
        huesos_arch::context_switch::context_switch(target.old, target.new);
    }
}

/// Scheduling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    /// Fair (CFS-like) scheduling.
    Fair {
        /// Task weight (nice level equivalent).
        weight: u64,
        /// Virtual runtime in tick-scaling.
        vruntime: u64,
    },
    /// Deadline real-time scheduling.
    Deadline {
        /// Execution capacity in ticks per period.
        capacity: u64,
        /// Period in ticks.
        period: u64,
        /// Remaining budget in current period.
        remaining_budget: u64,
        /// Absolute tick when current period ends.
        deadline: u64,
    },
}

static PER_CPU_SCHEDULERS: [RankedIrqSafeTicketLock<Scheduler>; MAX_CPUS] =
    [const { RankedIrqSafeTicketLock::new(Scheduler::new(), LockRank::SCHEDULER) }; MAX_CPUS];

struct TaskSlot {
    // The allocation keeps Context addresses stable while the slot vector
    // grows. Reuse replaces the value only after the old task was reaped.
    task: Box<Task>,
}

impl Deref for TaskSlot {
    type Target = Task;

    fn deref(&self) -> &Self::Target {
        &self.task
    }
}

impl DerefMut for TaskSlot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.task
    }
}

struct Scheduler {
    /// Dense CPU index owning this scheduler instance (set at init).
    cpu: usize,
    tasks: Vec<TaskSlot>,
    /// Reaped reusable indexes. Each index appears at most once.
    free_slots: Vec<usize>,
    current: usize,
    fair_queue: EevdfTree<MAX_FAIR_TASKS>,
    ticks: u64,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            cpu: 0,
            tasks: Vec::new(),
            free_slots: Vec::new(),
            current: 0,
            fair_queue: EevdfTree::new(),
            ticks: 0,
        }
    }

    /// Create a task with a fresh stable global ID and publish its location.
    ///
    /// Returns `None` when the global 8192-slot Task capacity is exhausted.
    fn add_task(&mut self, cpu: usize, create: impl FnOnce(u64) -> Task) -> Option<u64> {
        let index = loop {
            let Some(index) = self.free_slots.pop() else {
                break self.tasks.len();
            };
            let Some(slot) = self.tasks.get_mut(index) else {
                continue;
            };
            if matches!(&slot.kind, TaskKind::Reaped) {
                break index;
            }
        };

        let (slot, generation) = TASK_SLOTS.allocate()?;
        let Some(task_id) = V2TaskId::new(slot, generation) else {
            let _ = TASK_SLOTS.free(slot);
            return None;
        };
        let id = task_id.raw();
        // Publish before insertion: nobody can observe this fresh identity
        // until the creator is handed the returned ID.
        let owner = CpuIndex::new(cpu)?;
        if TASK_DIRECTORY.publish(task_id, owner, index).is_err() {
            let _ = TASK_SLOTS.free(slot);
            return None;
        }

        let task = create(id);
        let policy = task.sched_policy;
        if index == self.tasks.len() {
            self.tasks.push(TaskSlot {
                task: Box::new(task),
            });
        } else {
            let slot = &mut self.tasks[index];
            *slot.task = task;
        }
        if index > 0 {
            if let SchedPolicy::Fair { vruntime, .. } = policy {
                self.fair_queue
                    .insert(fair_key_of(vruntime, id), u128::from(vruntime))
                    .expect("fair queue capacity");
            }
        }
        Some(id)
    }

    /// Whether `id` currently names a live Task on *this* CPU at the
    /// directory's local index. The full identity comparison rejects stale
    /// generations from the same reused slot.
    fn task_matches(&self, id: u64) -> bool {
        let Some(location) = task_location(id) else {
            return false;
        };
        if location.owner.as_usize() != self.cpu {
            return false;
        }
        self.tasks
            .get(location.local_index as usize)
            .is_some_and(|slot| slot.id == id)
    }

    fn apply_task_environment(&self, idx: usize) {
        let task = &self.tasks[idx];
        let stack_top = task.kernel_stack_top();
        if stack_top != 0 {
            huesos_arch::gdt::set_kernel_stack(VirtAddr::new(stack_top));
            huesos_arch::syscall::set_kernel_stack(stack_top);
        }
        if let TaskKind::User { process } = &task.kind {
            huesos_object::set_current_process(Arc::clone(process));
        }
    }

    fn tick(&mut self) -> Option<SwitchTarget> {
        self.ticks += 1;

        // 1. Release Deadline tasks whose period has ended
        for idx in 1..self.tasks.len() {
            let t = &mut self.tasks[idx];
            if t.finished.load(Ordering::Relaxed) {
                continue;
            }
            if let SchedPolicy::Deadline {
                capacity,
                period,
                remaining_budget,
                deadline,
            } = &mut t.sched_policy
            {
                if self.ticks >= *deadline {
                    *deadline = self.ticks + *period;
                    *remaining_budget = *capacity;
                }
            }
        }

        // 2. Update stats for currently running task
        if self.current > 0 {
            if let TaskKind::User { process } = &self.tasks[self.current].kind {
                let _ = process.charge_cpu_tick();
            }
            // Charge the running task's Job with one tick of service. This
            // feeds the Job hard-cap oracle and the per-CPU demand snapshots
            // used by the (future) cross-CPU deficit balancer.
            let job_id = self.tasks[self.current].job_id;
            let now = monotonic_ns();
            if let Some(table) = JOB_TABLE.get() {
                let mut jobs = table.lock();
                let _ = jobs.charge(self.cpu, TICK_SERVICE_NS);
                let _ = jobs.maybe_replenish(now);
                let _ = job_id;
            }
            let task_id = self.tasks[self.current].id;
            let finished = self.tasks[self.current].finished.load(Ordering::Relaxed);
            let blocked = self.tasks[self.current].blocked.load(Ordering::Relaxed);

            match &mut self.tasks[self.current].sched_policy {
                SchedPolicy::Fair { weight, vruntime } => {
                    let delta = (1024 * 1000) / (*weight).max(1);
                    *vruntime += delta;
                    if !finished && !blocked {
                        self.fair_queue
                            .insert(fair_key_of(*vruntime, task_id), u128::from(*vruntime))
                            .expect("fair queue capacity");
                    }
                }
                SchedPolicy::Deadline {
                    remaining_budget, ..
                } => {
                    *remaining_budget = remaining_budget.saturating_sub(1);
                }
            }
        }

        // 3. Pick the next task to run
        let mut next_idx = 0;

        // Try Deadline tasks first (Earliest Deadline First)
        let mut best_deadline = u64::MAX;
        for idx in 1..self.tasks.len() {
            let t = &self.tasks[idx];
            if t.finished.load(Ordering::Relaxed) || t.blocked.load(Ordering::Relaxed) {
                continue;
            }
            if let SchedPolicy::Deadline {
                remaining_budget,
                deadline,
                ..
            } = t.sched_policy
            {
                if remaining_budget > 0 && deadline < best_deadline {
                    best_deadline = deadline;
                    next_idx = idx;
                }
            }
        }

        // If no Deadline task is ready, schedule from Fair queue.
        // Skip tasks that finished or are blocked (parked on a wait queue).
        if next_idx == 0 {
            while let Some(key) = self.fair_queue.pop_min() {
                let task_id = key.task_id;
                let Some(location) = task_location(task_id) else {
                    continue;
                };
                if location.owner.as_usize() != self.cpu {
                    continue;
                }
                let idx = location.local_index as usize;
                let Some(task) = self.tasks.get(idx) else {
                    continue;
                };
                if task.id != task_id {
                    continue;
                }
                if task.finished.load(Ordering::Relaxed) || task.blocked.load(Ordering::Relaxed) {
                    continue;
                }
                next_idx = idx;
                break;
            }
        }

        let old_index = self.current;
        if next_idx == old_index {
            // Keep running the same task
            return None;
        }

        self.current = next_idx;
        self.apply_task_environment(self.current);

        let old_ptr = &raw mut self.tasks[old_index].context;
        let new_ptr = &raw const self.tasks[self.current].context;
        let new_guards = &raw mut self.tasks[self.current].execution_guards;

        Some(SwitchTarget {
            old: old_ptr,
            new: new_ptr,
            new_guards,
        })
    }

    fn current_task(&self) -> Option<&Task> {
        self.tasks.get(self.current).map(|slot| &**slot)
    }
}

/// Build a runqueue key from the legacy (vruntime, task_id) pair.
fn fair_key_of(vruntime: u64, task_id: u64) -> EevdfKey {
    EevdfKey {
        virtual_start: u128::from(vruntime),
        task_id,
    }
}

/// Return the dense CPU index of the current CPU via GS_BASE.
///
/// LAPIC IDs are firmware-assigned and may be sparse or greater than 63 on real
/// machines. Scheduler arrays, task IDs, and current-process state use this
/// dense index instead; LAPIC IDs are consulted only at the IPI boundary.
fn cpu_id() -> usize {
    (unsafe { huesos_arch::cpu_local::current_cpu_index() }).min(MAX_CPUS - 1)
}

fn lapic_id_for_cpu_index(cpu: usize) -> Option<u8> {
    huesos_arch::cpu_local::lapic_id_for_index(cpu).and_then(|id| u8::try_from(id).ok())
}

/// Register the current CPU's scheduler pointer in its `CpuLocal`.
///
/// # Safety
/// Must be called once per CPU after `cpu_local::init_gs_base`.
unsafe fn register_scheduler_ptr(sched: *mut Scheduler) {
    let ptr = huesos_arch::cpu_local::cpu_local_ptr();
    unsafe { (*ptr).scheduler = sched as *mut () };
}

fn run_current_cpu_scheduler_interrupt(hardware_tick: bool) {
    huesos_arch::interrupts::disable();
    if !huesos_arch::preemption::can_preempt() && !hardware_tick {
        // Preemption is temporarily disabled. Honour the reschedule request
        // by marking a deferred flag but do not switch. The outermost
        // preemption re-enable will check and take the switch.
        huesos_arch::interrupts::enable();
        return;
    }
    let cpu = cpu_id();
    // Drain pending remote operations (wakes) from the allocation-free inbox
    // before making a scheduling decision.
    let drained = CPU_INBOX[cpu].drain(|slot| process_inbox_task(cpu, slot));
    if drained > 0 {
        OBS_INBOX_DRAINS.fetch_add(
            u64::try_from(drained).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
    process_runqueue_token_mailbox(cpu);
    if hardware_tick && cpu == 0 {
        MONOTONIC_TICKS.fetch_add(1, Ordering::SeqCst);
    }
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let switch_context = guard.tick();
    drop(guard); // Release the lock before performing context switch!

    if hardware_tick {
        // Wake any waiters whose timeout expired against hardware time.
        huesos_object::wait::notify_tick(MONOTONIC_TICKS.load(Ordering::SeqCst));
        // One-shot TSC-deadline mode: re-arm the next deadline now that this
        // tick has been serviced. The periodic LAPIC path is untouched.
        if TSC_DEADLINE_ACTIVE.load(Ordering::Relaxed) {
            if let Some(clock) = TSC_CLOCK.get() {
                let now = huesos_arch::rdtsc();
                let deadline = now.saturating_add(clock.ns_to_cycles(TICK_NS));
                // SAFETY: LAPIC base/init already ran for this CPU.
                unsafe { huesos_arch::lapic::timer_arm_tsc_deadline(deadline, 0x20) };
            }
        }
    }

    if let Some(target) = switch_context {
        perform_context_switch(target);
    }
    huesos_arch::interrupts::enable();
}

/// Initialize the scheduler for the current CPU and register the timer callback.
/// Called once per CPU.
pub fn init() {
    // Calibrate the TSC once (on whichever CPU reaches init first; all APs
    // share the BSP-derived frequency via the static).
    TSC_CLOCK.call_once(|| {
        let hz = huesos_arch::lapic::calibrate_tsc_hz();
        TscClock::from_frequency(hz).unwrap_or_else(|_| {
            // Fallback: 1 GHz keeps conversions finite even if calibration
            // is unusable; the boot log below flags it as degraded.
            TscClock::from_frequency(1_000_000_000).expect("1 GHz fallback")
        })
    });
    let was_enabled = x86_64::instructions::interrupts::are_enabled();
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    guard.cpu = cpu;
    unsafe { register_scheduler_ptr(&mut *guard) };
    let _idle_id = guard.add_task(cpu, |id| {
        Task::new_idle(
            id,
            *b"idle\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        )
    });
    let idle_guards = &raw mut guard.tasks[0].execution_guards;
    drop(guard);
    // SAFETY: task zero is a stable Box retained by this CPU's scheduler for
    // its complete online lifetime; local interrupts remain disabled.
    unsafe { huesos_arch::cpu_local::install_execution_guards(idle_guards) };
    if was_enabled {
        huesos_arch::interrupts::enable();
    }

    huesos_arch::timer_callback::set_timer_callback(&|| {
        run_current_cpu_scheduler_interrupt(true);
    });
    huesos_arch::timer_callback::set_reschedule_callback(&|| {
        run_current_cpu_scheduler_interrupt(false);
    });
    huesos_arch::preemption::set_reschedule_hook(deferred_reschedule_hook);

    // Transition to the one-shot TSC-deadline scheduler timer when the TSC
    // is invariant (stable across P/C states). The periodic LAPIC fallback
    // remains active otherwise; a forced flag is available for testing the
    // deadline path under QEMU/KVM where TSC is often already invariant.
    let force_deadline = core::option_env!("HUESOS_FORCE_TSC_DEADLINE").is_some();
    if huesos_arch::lapic::tsc_deadline_supported()
        && (huesos_arch::lapic::tsc_invariant() || force_deadline)
        && TSC_CLOCK.get().is_some()
    {
        TSC_DEADLINE_ACTIVE.store(true, Ordering::Relaxed);
        // Disarm the periodic count so the one-shot deadline owns the vector.
        huesos_arch::lapic::timer_stop();
        let clock = TSC_CLOCK.get().expect("TSC clock published");
        let now = huesos_arch::rdtsc();
        let deadline = now.saturating_add(clock.ns_to_cycles(TICK_NS));
        // SAFETY: LAPIC init completed before scheduler init.
        unsafe { huesos_arch::lapic::timer_arm_tsc_deadline(deadline, 0x20) };
    }

    // Publish the kernel Job accounting table exactly once (BSP or first AP;
    // content is the root Job with the whole machine's demand).
    JOB_TABLE.call_once(|| {
        RankedIrqSafeTicketLock::new(
            JobState::new(JobId::ROOT, 1024, 0).expect("root job weight"),
            LockRank::SCHEDULER,
        )
    });

    mark_cpu_online();
}

/// Called from the outermost PreemptionGuard drop when a reschedule was
/// deferred while preemption was disabled.
fn deferred_reschedule_hook() {
    run_current_cpu_scheduler_interrupt(false);
}

/// Yield the current task (cooperative).
pub fn yield_now() {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    CPU_INBOX[cpu].drain(|slot| process_inbox_task(cpu, slot));
    process_runqueue_token_mailbox(cpu);
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let switch_context = guard.tick();
    drop(guard); // Release the lock before performing context switch!

    if let Some(target) = switch_context {
        perform_context_switch(target);
    }
    huesos_arch::interrupts::enable();
}

/// Park the current task on a wait queue: mark blocked, drop from the
/// runqueue, and switch away. Returns when [`wake_task`] has cleared
/// `blocked` and requeued the task.
pub fn park_current() {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    process_runqueue_token_mailbox(cpu);
    {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let idx = guard.current;
        let mut should_park = true;
        let fair_key = if let Some(task) = guard.tasks.get_mut(idx) {
            // The scheduler lock makes the blocked flag and the pending wake
            // handshake atomic with respect to remote wake_task calls.
            task.blocked.store(true, Ordering::SeqCst);
            let fair_key = match task.sched_policy {
                SchedPolicy::Fair { vruntime, .. } => Some((vruntime, task.id)),
                SchedPolicy::Deadline { .. } => None,
            };
            let pending = task.wake_pending.swap(false, Ordering::SeqCst);
            if pending || !task.blocked.load(Ordering::SeqCst) {
                task.blocked.store(false, Ordering::SeqCst);
                should_park = false;
            }
            fair_key
        } else {
            None
        };
        if let Some((vruntime, task_id)) = fair_key {
            let _ = guard.fair_queue.remove(fair_key_of(vruntime, task_id));
        }
        // Prefer tick(); if it declines to switch (edge case), force idle.
        let switch_context = if should_park {
            guard.tick().or_else(|| {
                if guard.current == 0 || guard.tasks.len() <= 1 {
                    return None;
                }
                let old = guard.current;
                guard.current = 0;
                guard.apply_task_environment(0);
                let old_ptr = &raw mut guard.tasks[old].context;
                let new_ptr = &raw const guard.tasks[0].context;
                let new_guards = &raw mut guard.tasks[0].execution_guards;
                Some(SwitchTarget {
                    old: old_ptr,
                    new: new_ptr,
                    new_guards,
                })
            })
        } else {
            None
        };
        drop(guard);
        if let Some(target) = switch_context {
            perform_context_switch(target);
        }
    }
    huesos_arch::interrupts::enable();
}

/// Rebase a Deadline task's `(deadline, remaining_budget)` on unblock,
/// matching a standard Constant Bandwidth Server (CBS) replenishment.
///
/// Contract:
/// - `deadline` becomes `now + period` (saturating; a `period` of `u64::MAX`
///   just pins the deadline at `u64::MAX`, which prevents overflow rather
///   than wrapping to zero and creating a spurious "immediately due" task).
/// - `remaining_budget` is refilled to full `capacity`. A task that spent
///   any CPU time in the previous period is entitled to a fresh capacity
///   when its period is reset; leaving a partially consumed budget would
///   silently starve the task on wake.
///
/// Without this rebase, a task blocked for longer than one period wakes
/// with a stale deadline in the past, which makes EDF give it infinite
/// priority and starves every other Deadline task. Extracted into a
/// pure `pub(crate)` function so the property is exercised by host tests
/// without dragging in the per-CPU scheduler.
pub(crate) fn replenish_deadline_on_unblock(
    now: u64,
    capacity: u64,
    period: u64,
    remaining_budget: &mut u64,
    deadline: &mut u64,
) {
    *deadline = now.saturating_add(period);
    *remaining_budget = capacity;
}

/// Wake a previously parked task. Safe to call from IRQ context (port queue).
///
/// Always clears `blocked` and ensures the task is on the fair runqueue.
/// This closes the lost-wakeup race where `wake` arrived after enqueue but
/// before `park_current` set `blocked=true` (swap would early-return and the
/// subsequent park would sleep forever).
/// Apply the wake policy for a task confirmed on this CPU. The caller owns
/// the scheduler lock; `idx` has been validated by `task_matches`.
unsafe fn apply_local_wake(guard: &mut Scheduler, now: u64, task_id: u64, idx: usize) {
    let task = &mut guard.tasks[idx];
    debug_assert_eq!(task.id, task_id, "wake must target the validated identity");
    if task.finished.load(Ordering::Relaxed) {
        task.blocked.store(false, Ordering::SeqCst);
        task.wake_pending.store(false, Ordering::SeqCst);
        return;
    }
    let was_blocked = task.blocked.swap(false, Ordering::SeqCst);
    if !was_blocked {
        // The waiter has not completed its enqueue-to-park handshake yet.
        // Remember the wake so park_current will not put it to sleep.
        task.wake_pending.store(true, Ordering::SeqCst);
        return;
    }
    task.wake_pending.store(false, Ordering::SeqCst);
    let fair_reinsert = match &mut task.sched_policy {
        SchedPolicy::Fair { vruntime, .. } => Some((*vruntime, task.id)),
        SchedPolicy::Deadline {
            capacity,
            period,
            remaining_budget,
            deadline,
        } => {
            replenish_deadline_on_unblock(now, *capacity, *period, remaining_budget, deadline);
            None
        }
    };
    if let Some((vr, id)) = fair_reinsert {
        let _ = guard.fair_queue.remove(fair_key_of(vr, id));
        guard
            .fair_queue
            .insert(fair_key_of(vr, id), u128::from(vr))
            .expect("fair queue capacity");
    }
}

/// Process one pending remote operation for a Task owned by this CPU.
///
/// The operation flags are taken from the Task directory before the owner
/// lock is acquired, so the drain never double-applies a wake.
fn process_inbox_task(cpu: usize, slot: usize) {
    let Some(id) = TASK_DIRECTORY.published_id(slot) else {
        return;
    };
    let raw_id = id.raw();
    let operations = TASK_DIRECTORY.take_operations(id).unwrap_or(0);
    if operations == 0 {
        return;
    }
    let Some(location) = task_location(raw_id) else {
        return;
    };
    if location.owner.as_usize() != cpu {
        return;
    }
    let idx = location.local_index as usize;
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    if !guard.task_matches(raw_id) {
        return;
    }
    if operations & task_operations::WAKE != 0 {
        let now = guard.ticks;
        // SAFETY: the scheduler lock is held and `idx` was validated by
        // task_matches against the directory location.
        unsafe { apply_local_wake(&mut *guard, now, raw_id, idx) };
    }
    if operations & task_operations::POLICY != 0 {
        // Control-plane policy requests carry payload applied synchronously
        // by set_sched_policy under the owner lock. A flag-only POLICY bit
        // (possible if the publisher raced a migration) is consumed by
        // re-evaluating the task's current fair key.
        if let SchedPolicy::Fair { vruntime, .. } = guard.tasks[idx].sched_policy {
            let key = fair_key_of(vruntime, raw_id);
            let _ = guard.fair_queue.remove(key);
            guard
                .fair_queue
                .insert(key, u128::from(vruntime))
                .expect("fair queue capacity");
        }
    }
}

/// Wake a previously parked task. Safe to call from IRQ context (port queue).
///
/// Same-CPU wakes are applied directly under the local scheduler lock.
/// Remote wakes publish a WAKE operation into the target CPU's allocation-free
/// bitmap inbox and send at most one coalesced reschedule IPI; the owner CPU
/// applies the wake during its next scheduler drain. No remote runqueue lock
/// is ever taken, so the caller never waits on another CPU.
pub fn wake_task(task_id: u64) {
    let Some(location) = task_location(task_id) else {
        return;
    };
    let cpu = location.owner.as_usize();
    if cpu >= MAX_CPUS {
        return;
    }
    if cpu == cpu_id() {
        let idx = location.local_index as usize;
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        if guard.task_matches(task_id) {
            let now = guard.ticks;
            // SAFETY: local scheduler lock held and idx validated above.
            unsafe { apply_local_wake(&mut *guard, now, task_id, idx) };
        }
        return;
    }
    let Some(id) = V2TaskId::from_raw(task_id) else {
        return;
    };
    OBS_REMOTE_WAKES.fetch_add(1, Ordering::Relaxed);
    let _ = TASK_DIRECTORY.publish_operations(id, task_operations::WAKE);
    let Some(result) = CPU_INBOX[cpu].publish(id.slot()) else {
        return;
    };
    if result.send_ipi {
        OBS_RESCHED_IPIS.fetch_add(1, Ordering::Relaxed);
        if let Some(apic_id) = lapic_id_for_cpu_index(cpu) {
            huesos_arch::lapic::ipi_reschedule(apic_id);
        }
    }
}

/// Get current task id for debugging.
pub fn current_task_id() -> Option<u64> {
    let guard = PER_CPU_SCHEDULERS[cpu_id()].lock();
    guard.current_task().map(|t| t.id)
}

/// Mark a user task's first-entry metadata as consumed. After this point the
/// task may be migrated by opt-in token stealing because no rank-40 pending
/// startup record is keyed by its task id anymore.
pub(crate) fn mark_user_entry_consumed(task_id: u64) {
    let Some(location) = task_location(task_id) else {
        return;
    };
    let cpu = location.owner.as_usize();
    if cpu >= MAX_CPUS {
        return;
    }
    let idx = location.local_index as usize;
    let guard = PER_CPU_SCHEDULERS[cpu].lock();
    if guard.task_matches(task_id) {
        guard.tasks[idx]
            .startup_pending
            .store(false, Ordering::Release);
    }
}

/// Monotonic BSP-ish tick counter for wait timeouts (sum of local ticks is
/// fine; we use the current CPU's scheduler ticks).
pub fn global_ticks() -> u64 {
    MONOTONIC_TICKS.load(Ordering::SeqCst)
}

/// Monotonic time in nanoseconds derived from the invariant TSC.
///
/// Returns 0 before `scheduler::init` has calibrated the clock. Degraded
/// (approximate) when the TSC is not invariant.
pub fn monotonic_ns() -> u64 {
    let Some(clock) = TSC_CLOCK.get() else {
        return 0;
    };
    clock.cycles_to_ns(huesos_arch::rdtsc())
}

/// Whether the TSC clock is invariant (non-degraded).
pub fn tsc_clock_invariant() -> bool {
    huesos_arch::lapic::tsc_invariant()
}

/// Try to reserve CBS/IRQ CPU bandwidth on `cpu`.
///
/// Returns `Ok(())` when the reservation fits under the shared 80% ceiling;
/// `Err(())` when it would overcommit. Reservations are owned by the
/// scheduling-control capability layer; ordinary threads cannot create them.
/// A successful reservation must later be released with [`cbs_release`] or
/// the CPU admission budget will leak.
pub fn cbs_try_admit(cpu: usize, capacity_ns: u64, period_ns: u64) -> Result<(), ()> {
    if cpu >= MAX_CPUS {
        return Err(());
    }
    let Ok(reservation) = CbsReservation::new(capacity_ns, period_ns, period_ns) else {
        return Err(());
    };
    CBS_ADMISSION[cpu]
        .lock()
        .reserve(reservation)
        .map(|_| ())
        .map_err(|_| ())
}

/// Release previously admitted CBS/IRQ bandwidth on `cpu`.
pub fn cbs_release(cpu: usize, capacity_ns: u64, period_ns: u64) -> Result<(), ()> {
    if cpu >= MAX_CPUS {
        return Err(());
    }
    let Ok(reservation) = CbsReservation::new(capacity_ns, period_ns, period_ns) else {
        return Err(());
    };
    let ppm = reservation.utilization_ppm().map_err(|_| ())?;
    CBS_ADMISSION[cpu].lock().release_ppm(ppm).map_err(|_| ())
}

/// Current admitted utilization on `cpu` in ppm (0..1_000_000).
pub fn cbs_admitted_ppm(cpu: usize) -> u32 {
    if cpu >= MAX_CPUS {
        return 0;
    }
    CBS_ADMISSION[cpu].lock().admitted_ppm()
}

/// Scheduler observability snapshot (aggregate since boot).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SchedStats {
    pub context_switches: u64,
    pub remote_wakes: u64,
    pub resched_ipis: u64,
    pub inbox_drains: u64,
    pub irq_storm_masks: u64,
}

/// Read the scheduler observability counters.
pub fn sched_stats() -> SchedStats {
    SchedStats {
        context_switches: OBS_CTX_SWITCHES.load(Ordering::Relaxed),
        remote_wakes: OBS_REMOTE_WAKES.load(Ordering::Relaxed),
        resched_ipis: OBS_RESCHED_IPIS.load(Ordering::Relaxed),
        inbox_drains: OBS_INBOX_DRAINS.load(Ordering::Relaxed),
        irq_storm_masks: OBS_IRQ_STORM_MASKS.load(Ordering::Relaxed),
    }
}

/// Record that an IRQ source was masked due to a storm/budget violation.
/// Called by the IRQ layer when it quarantines a misbehaving source.
pub fn irq_storm_masked() {
    OBS_IRQ_STORM_MASKS.fetch_add(1, Ordering::Relaxed);
}

/// Set the scheduling policy for a task by its ID.
pub fn set_sched_policy(task_id: u64, policy: SchedPolicy) {
    huesos_arch::interrupts::disable();
    let Some(location) = task_location(task_id) else {
        huesos_arch::interrupts::enable();
        return;
    };
    let cpu = location.owner.as_usize();
    let idx = location.local_index as usize;
    if cpu >= MAX_CPUS {
        huesos_arch::interrupts::enable();
        return;
    }
    // Policy changes are control-plane operations: rare and allowed to
    // briefly take the owner scheduler lock so the mutation is applied
    // synchronously with correct payload semantics. The hot scheduling
    // path (wake/tick) never takes this path.
    let Some(_token) = acquire_runqueue_token(cpu) else {
        huesos_arch::interrupts::enable();
        return;
    };
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    if !guard.task_matches(task_id) {
        drop(guard);
        huesos_arch::interrupts::enable();
        return;
    }
    if let Some(SchedPolicy::Fair { vruntime, .. }) = Some(guard.tasks[idx].sched_policy) {
        let _ = guard.fair_queue.remove(fair_key_of(vruntime, task_id));
    }
    guard.tasks[idx].sched_policy = policy;
    if let SchedPolicy::Fair { vruntime, .. } = policy {
        guard
            .fair_queue
            .insert(fair_key_of(vruntime, task_id), u128::from(vruntime))
            .expect("fair queue capacity");
    }
    drop(guard);
    huesos_arch::interrupts::enable();
}

/// Spawn a new kernel thread. Returns `None` when the global Task capacity
/// is exhausted.
pub fn spawn_kernel_thread(name: &[u8; 32], entry: extern "C" fn() -> !) -> Option<u64> {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let id = guard.add_task(cpu, |id| Task::new_kernel(id, *name, entry));
    drop(guard);
    huesos_arch::interrupts::enable();
    id
}

/// Spawn a new userspace task bound to `process`, whose first execution
/// will jump to ring3 via `entry_trampoline`.
pub fn spawn_user_thread(
    name: &[u8; 32],
    process: Arc<Process>,
    entry_point: u64,
    user_rsp: u64,
    cr3: u64,
) -> u64 {
    spawn_user_thread_on_cpu(name, process, entry_point, user_rsp, cr3, cpu_id())
        .unwrap_or(u64::MAX)
}

/// Spawn a userspace task on an explicit dense CPU index. This is the only
/// cross-CPU task-placement path: no global load average or implicit balancing
/// is consulted. Remote runqueue mutation is guarded by the runqueue token.
pub fn spawn_user_thread_on_cpu(
    name: &[u8; 32],
    process: Arc<Process>,
    entry_point: u64,
    user_rsp: u64,
    cr3: u64,
    cpu: usize,
) -> Option<u64> {
    if cpu >= MAX_CPUS || !is_cpu_online(cpu) {
        return None;
    }
    huesos_arch::interrupts::disable();
    let Some(_token) = acquire_runqueue_token(cpu) else {
        huesos_arch::interrupts::enable();
        return None;
    };
    // Drive the policy transition before publishing the first runnable task.
    let _ = process.start();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let Some(id) = guard.add_task(cpu, |id| {
        Task::new_user(
            id,
            *name,
            process,
            crate::process::user_entry_trampoline,
            cr3,
        )
    }) else {
        drop(guard);
        huesos_arch::interrupts::enable();
        return None;
    };
    drop(guard);
    // Publish startup metadata only after releasing the rank-60 scheduler.
    // Interrupts remain disabled, so this CPU cannot run the new task before
    // its rank-40 process record is visible.
    crate::process::queue_user_entry(id, entry_point, user_rsp);
    huesos_arch::interrupts::enable();

    if cpu != cpu_id() {
        if let Some(apic_id) = lapic_id_for_cpu_index(cpu) {
            huesos_arch::lapic::ipi_reschedule(apic_id);
        }
    }
    Some(id)
}

/// Mark the currently running task as finished (won't be scheduled again)
/// and switch away from it. Never returns.
pub fn exit_current_task(code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let mut process_to_signal: Option<alloc::sync::Arc<huesos_object::Process>> = None;
    let mut reap_id: Option<u64> = None;
    {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let current_idx = guard.current;
        if let Some(task) = guard.tasks.get_mut(current_idx) {
            task.finished.store(true, Ordering::Relaxed);
            task.blocked.store(false, Ordering::Relaxed);
            reap_id = Some(task.id);
            if let crate::task::TaskKind::User { process } = &task.kind {
                process_to_signal = Some(alloc::sync::Arc::clone(process));
            }
            if let SchedPolicy::Fair { vruntime, .. } = task.sched_policy {
                let id = task.id;
                let _ = guard.fair_queue.remove(fair_key_of(vruntime, id));
            }
        }
    }
    if let Some(proc) = process_to_signal {
        if proc.set_exit_code(code) {
            record_process_exit(&proc, code);
        }
        huesos_object::collect_exited_process(proc.koid());
        PROCESS_TEARDOWN.lock().push(proc);
        REAP_PENDING.store(true, Ordering::Release);
    }
    if let Some(id) = reap_id {
        REAP_QUEUE.lock().push(id);
        REAP_PENDING.store(true, Ordering::Release);
    }
    loop {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let switch_context = guard.tick();
        drop(guard);

        if let Some(target) = switch_context {
            perform_context_switch(target);
        }
        huesos_arch::interrupts::enable();
        huesos_arch::hlt();
        huesos_arch::interrupts::disable();
    }
}

/// Terminate every thread belonging to the current userspace process and
/// switch away from the faulting thread. This is used for unhandled ring-3
/// exceptions: continuing sibling threads in a potentially corrupted address
/// space would violate process isolation.
pub fn terminate_current_process(code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let current_cpu = cpu_id();
    let process = {
        let guard = PER_CPU_SCHEDULERS[current_cpu].lock();
        guard.current_task().and_then(|task| match &task.kind {
            TaskKind::User { process } => Some(Arc::clone(process)),
            TaskKind::Kernel | TaskKind::Reaped => None,
        })
    };

    let Some(process) = process else {
        panic!("terminate_current_process called without a userspace process");
    };
    if process.set_exit_code(code) {
        record_process_exit(&process, code);
    }
    let process_koid = process.koid();
    huesos_object::collect_exited_process(process_koid);

    for scheduler in &PER_CPU_SCHEDULERS {
        let mut guard = scheduler.lock();
        for idx in 0..guard.tasks.len() {
            let matched = match &guard.tasks[idx].kind {
                TaskKind::User { process } => process.koid() == process_koid,
                TaskKind::Kernel | TaskKind::Reaped => false,
            };
            if !matched {
                continue;
            }
            let (id, fair_key) = {
                let task = &mut guard.tasks[idx];
                task.finished.store(true, Ordering::SeqCst);
                task.blocked.store(false, Ordering::SeqCst);
                let fair_key = match task.sched_policy {
                    SchedPolicy::Fair { vruntime, .. } => Some(vruntime),
                    SchedPolicy::Deadline { .. } => None,
                };
                (task.id, fair_key)
            };
            if let Some(vruntime) = fair_key {
                let _ = guard.fair_queue.remove(fair_key_of(vruntime, id));
            }
            REAP_QUEUE.lock().push(id);
            REAP_PENDING.store(true, Ordering::Release);
        }
    }

    PROCESS_TEARDOWN.lock().push(Arc::clone(&process));
    REAP_PENDING.store(true, Ordering::Release);
    for cpu in 0..MAX_CPUS {
        if cpu != current_cpu && is_cpu_online(cpu) {
            if let Some(apic_id) = lapic_id_for_cpu_index(cpu) {
                huesos_arch::lapic::ipi_reschedule(apic_id);
            }
        }
    }

    switch_away_from_finished(current_cpu)
}

fn switch_away_from_finished(cpu: usize) -> ! {
    loop {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let switch_context = guard.tick();
        drop(guard);

        if let Some(target) = switch_context {
            perform_context_switch(target);
        }
        huesos_arch::interrupts::enable();
        huesos_arch::hlt();
        huesos_arch::interrupts::disable();
    }
}

static TASK_GRAVEYARD: RankedIrqSafeTicketLock<Option<TaskGraveyard<256>>> =
    RankedIrqSafeTicketLock::new(None, LockRank::REAPER);
static TASK_GRAVEYARD_EVICTIONS: AtomicU64 = AtomicU64::new(0);

fn record_process_exit(process: &Process, code: i64) {
    let Some(info) = process.exit_info() else {
        return;
    };
    {
        let mut yard = TASK_GRAVEYARD.lock();
        let graveyard = yard.get_or_insert_with(TaskGraveyard::new);
        // ProcessLifecycle owns the generation in ExitInfo. Reusing it here keeps
        // the graveyard record and ProcessWait/reaper observations ABA-safe.
        let (_, outcome) =
            graveyard.record_exit_with_generation(info.koid, info.generation, code, global_ticks());
        if matches!(outcome, InsertOutcome::Evicted(_)) {
            TASK_GRAVEYARD_EVICTIONS.fetch_add(1, Ordering::Relaxed);
        }
    }
    // Critical-process fallback (Fuchsia-inspired "critical to root
    // job"). A process marked critical is one whose continued liveness
    // the system depends on; if it exits — for any reason — the kernel
    // atomically halts before the surrounding services can observe an
    // inconsistent partial-shutdown state. Runs *after* graveyard
    // record so a ProcessWait on the doomed process still sees the
    // real exit code before the machine stops. See
    // `docs/ARCHITECTURE_ROADMAP.md` §3.
    if process.is_critical() {
        // Snapshot the name so the halt banner can name the offender.
        let name = process.name();
        crate::shutdown::note_critical_exit(&name, code);
    }
}

fn reap_observed_process_exits() {
    let mut yard = TASK_GRAVEYARD.lock();
    let Some(graveyard) = yard.as_mut() else {
        return;
    };
    let _ = graveyard.reap_waited(|koid, generation| {
        match huesos_object::lookup_process(huesos_object::Koid(koid)) {
            Some(process) => process.observed_exit_generation(generation),
            None => true,
        }
    });
}

/// True while deferred task/process teardown needs process-context service.
static REAP_PENDING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Task ids waiting for kernel-stack reclamation.
static REAP_QUEUE: RankedIrqSafeTicketLock<alloc::vec::Vec<u64>> =
    RankedIrqSafeTicketLock::new(alloc::vec::Vec::new(), LockRank::REAPER);

/// Processes waiting for address-space / handle-table teardown.
static PROCESS_TEARDOWN: RankedIrqSafeTicketLock<
    alloc::vec::Vec<alloc::sync::Arc<huesos_object::Process>>,
> = RankedIrqSafeTicketLock::new(alloc::vec::Vec::new(), LockRank::REAPER);

/// Service deferred teardown after an ordinary syscall has released all
/// subsystem locks. The atomic fast path avoids touching queue mutexes on
/// syscalls that have no lifecycle work.
pub fn reap_if_pending() {
    if REAP_PENDING.swap(false, Ordering::AcqRel) {
        reap_finished_tasks();
    }
    huesos_object::flush_pending_quota_notifications();
}

/// Drain finished tasks' kernel stacks (frames stay until process Arc drops).
/// Safe to call from a low-priority path; currently invoked from the BSP
/// idle loop opportunistically.
pub fn reap_finished_tasks() {
    let batch = {
        let mut q = REAP_QUEUE.lock();
        core::mem::take(&mut *q)
    };
    for task_id in batch {
        // This lock is acquired before any scheduler lock, preventing a
        // scheduler -> pending-entry inversion during task-slot reclamation.
        crate::process::cancel_user_entry(task_id);
        let Some(location) = task_location(task_id) else {
            continue;
        };
        let cpu = location.owner.as_usize();
        let idx = location.local_index as usize;
        if cpu >= MAX_CPUS {
            continue;
        }
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        // Drop duplicate/stale queue entries before comparing indexes: a new
        // generation may legitimately be running in the same slot.
        if !guard.task_matches(task_id) {
            continue;
        }
        // Never reap the currently running generation (shouldn't be queued).
        if guard.current == idx {
            REAP_QUEUE.lock().push(task_id);
            REAP_PENDING.store(true, Ordering::Release);
            continue;
        }
        let reusable = {
            let slot = &mut guard.tasks[idx];
            if !slot.finished.load(Ordering::Acquire) || matches!(&slot.kind, TaskKind::Reaped) {
                false
            } else {
                // Release the stack and Process Arc before publishing the slot.
                slot.kernel_stack = alloc::vec::Vec::new();
                slot.kind = TaskKind::Reaped;
                true
            }
        };
        if reusable {
            guard.free_slots.push(idx);
            // Release the global slot so a later task reuses it under a fresh
            // generation. Generation overflow retires the slot permanently.
            if let Some(id) = V2TaskId::from_raw(task_id) {
                let _ = TASK_SLOTS.free(id.slot());
            }
        }
    }

    // Tear down exited processes (page tables, owned frames, handles).
    let procs = {
        let mut q = PROCESS_TEARDOWN.lock();
        core::mem::take(&mut *q)
    };
    for proc in procs {
        let koid = proc.koid();
        let still_current = (0..MAX_CPUS).any(|cpu| {
            let guard = PER_CPU_SCHEDULERS[cpu].lock();
            guard.current_task().is_some_and(|task| match &task.kind {
                TaskKind::User { process } => process.koid() == koid,
                TaskKind::Kernel | TaskKind::Reaped => false,
            })
        });
        if still_current {
            // A remote CPU has not yet taken its reschedule IPI. Never destroy
            // page tables while that CPU can still have the process CR3 live.
            PROCESS_TEARDOWN.lock().push(proc);
            REAP_PENDING.store(true, Ordering::Release);
        } else {
            crate::process::teardown_process(&proc);
        }
    }
    reap_observed_process_exits();
}

#[cfg(test)]
mod task_id_tests {
    use super::*;

    #[test]
    fn global_task_ids_do_not_encode_cpu_ownership() {
        // Two tasks created for different CPUs must remain distinct even when
        // the local queue index coincides: the global slot separates them.
        let first = V2TaskId::new(10, 1).and_then(|id| Some(id.raw()));
        let second = V2TaskId::new(11, 1).and_then(|id| Some(id.raw()));
        let (a, b) = (first.unwrap_or(0), second.unwrap_or(0));
        assert_ne!(a, b);
        assert_eq!(V2TaskId::from_raw(a).map(|id| id.slot()), Some(10));
        assert_eq!(V2TaskId::from_raw(a).map(|id| id.generation()), Some(1));
        assert!(
            task_location(a).is_none(),
            "unpublished id must not resolve"
        );
    }

    // --- EDF replenishment on unblock ---
    //
    // Regression for the bug where a Deadline task blocked for longer than
    // one period woke with a stale (past) deadline and gained infinite
    // priority under EDF, starving every other Deadline task.

    #[test]
    fn replenish_rebases_deadline_from_now_and_refills_budget() {
        let capacity = 40;
        let period = 100;
        let mut remaining_budget = 5; // partially consumed in previous period
        let mut deadline = 30; // stale — well before "now"
        replenish_deadline_on_unblock(500, capacity, period, &mut remaining_budget, &mut deadline);
        assert_eq!(deadline, 600, "new deadline must be now + period");
        assert_eq!(remaining_budget, capacity, "budget must be fully refilled");
    }

    #[test]
    fn replenish_never_makes_deadline_stale_relative_to_now() {
        // Sweep a range of (now, period) pairs. Post-replenish deadline
        // must always be >= now — EDF fairness relies on this.
        for now in [0u64, 1, 100, u64::MAX / 2, u64::MAX - 10] {
            for period in [1u64, 10, 1000, u64::MAX] {
                let mut remaining_budget = 0;
                let mut deadline = 0;
                replenish_deadline_on_unblock(
                    now,
                    10,
                    period,
                    &mut remaining_budget,
                    &mut deadline,
                );
                assert!(
                    deadline >= now,
                    "post-replenish deadline={deadline} must be >= now={now} (period={period})"
                );
            }
        }
    }

    #[test]
    fn replenish_saturates_deadline_on_overflow() {
        // A pathological period must not wrap deadline to zero (which would
        // make EDF think the task is immediately due).
        let mut remaining_budget = 0;
        let mut deadline = 100;
        replenish_deadline_on_unblock(u64::MAX, 10, 5, &mut remaining_budget, &mut deadline);
        assert_eq!(deadline, u64::MAX, "must saturate, not wrap");
    }
}
