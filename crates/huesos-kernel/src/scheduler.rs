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

#[path = "scheduler/wavl.rs"]
pub mod wavl;

use crate::task::{Task, TaskKind};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::Ordering;
use huesos_arch::{LockRank, RankedIrqSafeTicketLock};
use huesos_object::{KernelObject, Process};
use x86_64::VirtAddr;

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 64;

// Task IDs are opaque capabilities, not bare vector indexes. The high byte
// identifies a CPU, the next 24 bits identify a slot generation, and the low
// 32 bits identify the slot. A delayed wake carrying an older generation can
// therefore never wake an unrelated task after slot reuse.
const TASK_CPU_SHIFT: u32 = 56;
const TASK_GENERATION_SHIFT: u32 = 32;
const TASK_GENERATION_MASK: u32 = 0x00ff_ffff;
const TASK_INDEX_MASK: u64 = 0xffff_ffff;

const fn encode_task_id(cpu: usize, generation: u32, index: usize) -> u64 {
    ((cpu as u64) << TASK_CPU_SHIFT)
        | (((generation & TASK_GENERATION_MASK) as u64) << TASK_GENERATION_SHIFT)
        | (index as u64 & TASK_INDEX_MASK)
}

const fn task_cpu(id: u64) -> usize {
    (id >> TASK_CPU_SHIFT) as usize
}

const fn task_generation(id: u64) -> u32 {
    ((id >> TASK_GENERATION_SHIFT) as u32) & TASK_GENERATION_MASK
}

const fn task_index(id: u64) -> usize {
    (id & TASK_INDEX_MASK) as usize
}

const fn next_task_generation(previous: u32) -> Option<u32> {
    if previous >= TASK_GENERATION_MASK {
        None
    } else {
        Some(previous + 1)
    }
}

/// Bitmask of CPUs that have finished scheduler init and may receive tasks.
/// Bit N set => CPU with LAPIC-id N is online for load-balancing.
static ONLINE_CPUS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Hardware-timer-driven monotonic clock. Only CPU 0 advances it, so SMP does
/// not make time run faster. Cooperative yields never affect this clock.
static MONOTONIC_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
    (ONLINE_CPUS.load(Ordering::SeqCst) & (1u64 << cpu)) != 0
}

/// Saved CPU context for a task.
pub type SchedContext = huesos_arch::context_switch::Context;

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
    generation: u32,
    /// Permanently set before a generation could wrap and recreate an old ID.
    retired: bool,
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
    tasks: Vec<TaskSlot>,
    /// Reaped reusable indexes. Each index appears at most once.
    free_slots: Vec<usize>,
    current: usize,
    fair_queue: wavl::WavlTree,
    ticks: u64,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            free_slots: Vec::new(),
            current: 0,
            fair_queue: wavl::WavlTree::new(),
            ticks: 0,
        }
    }

    fn add_task(&mut self, cpu: usize, create: impl FnOnce(u64) -> Task) -> u64 {
        let reusable = loop {
            let Some(index) = self.free_slots.pop() else {
                break None;
            };
            let Some(slot) = self.tasks.get_mut(index) else {
                continue;
            };
            if slot.retired || !matches!(&slot.kind, TaskKind::Reaped) {
                continue;
            }
            if let Some(generation) = next_task_generation(slot.generation) {
                break Some((index, generation));
            }
            // Defensive retirement if a corrupted/stale free-list entry ever
            // names an exhausted slot. The task constructor is not consumed.
            slot.retired = true;
        };

        let (index, generation) = reusable.unwrap_or((self.tasks.len(), 0));

        let id = encode_task_id(cpu, generation, index);
        let task = create(id);
        let policy = task.sched_policy;
        if index == self.tasks.len() {
            self.tasks.push(TaskSlot {
                generation,
                retired: false,
                task: Box::new(task),
            });
        } else {
            let slot = &mut self.tasks[index];
            slot.generation = generation;
            slot.retired = false;
            *slot.task = task;
        }
        if index > 0 {
            if let SchedPolicy::Fair { vruntime, .. } = policy {
                self.fair_queue.insert(vruntime, id);
            }
        }
        id
    }

    fn task_matches(&self, id: u64) -> bool {
        self.tasks
            .get(task_index(id))
            .is_some_and(|slot| slot.generation == task_generation(id) && slot.id == id)
    }

    fn live_task_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|slot| !matches!(&slot.kind, TaskKind::Reaped))
            .count()
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

    fn tick(&mut self) -> Option<(*mut SchedContext, *const SchedContext)> {
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
            let task_id = self.tasks[self.current].id;
            let finished = self.tasks[self.current].finished.load(Ordering::Relaxed);
            let blocked = self.tasks[self.current].blocked.load(Ordering::Relaxed);

            match &mut self.tasks[self.current].sched_policy {
                SchedPolicy::Fair { weight, vruntime } => {
                    let delta = (1024 * 1000) / (*weight).max(1);
                    *vruntime += delta;
                    if !finished && !blocked {
                        self.fair_queue.insert(*vruntime, task_id);
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
            while let Some(task_id) = self.fair_queue.pop_min() {
                let idx = task_index(task_id);
                if self.task_matches(task_id) {
                    let task = &self.tasks[idx];
                    if task.finished.load(Ordering::Relaxed) || task.blocked.load(Ordering::Relaxed)
                    {
                        continue;
                    }
                    next_idx = idx;
                    break;
                }
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

        Some((old_ptr, new_ptr))
    }

    fn current_task(&self) -> Option<&Task> {
        self.tasks.get(self.current).map(|slot| &**slot)
    }
}

/// Return the LAPIC ID of the current CPU via GS_BASE, clamped to MAX_CPUS.
fn cpu_id() -> usize {
    (unsafe { huesos_arch::cpu_local::current_lapic_id() } as usize).min(MAX_CPUS - 1)
}

/// Register the current CPU's scheduler pointer in its `CpuLocal`.
///
/// # Safety
/// Must be called once per CPU after `cpu_local::init_gs_base`.
unsafe fn register_scheduler_ptr(sched: *mut Scheduler) {
    let ptr = huesos_arch::cpu_local::cpu_local_ptr();
    unsafe { (*ptr).scheduler = sched as *mut () };
}

/// Initialize the scheduler for the current CPU and register the timer callback.
/// Called once per CPU.
pub fn init() {
    let cpu = cpu_id();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    unsafe { register_scheduler_ptr(&mut *guard) };
    guard.add_task(cpu, |id| {
        Task::new_idle(
            id,
            *b"idle\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        )
    });
    drop(guard);

    huesos_arch::timer_callback::set_timer_callback(&|| {
        huesos_arch::interrupts::disable();
        let cpu = cpu_id();
        if cpu == 0 {
            MONOTONIC_TICKS.fetch_add(1, Ordering::SeqCst);
        }
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let switch_context = guard.tick();
        drop(guard); // Release the lock before performing context switch!

        // Wake any waiters whose timeout expired against hardware time.
        huesos_object::wait::notify_tick(MONOTONIC_TICKS.load(Ordering::SeqCst));

        if let Some((old_ptr, new_ptr)) = switch_context {
            // Safety: interrupts are disabled; pointers point to active Vec
            unsafe {
                huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
            }
        }
        huesos_arch::interrupts::enable();
    });

    mark_cpu_online();
}

/// Yield the current task (cooperative).
pub fn yield_now() {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let switch_context = guard.tick();
    drop(guard); // Release the lock before performing context switch!

    if let Some((old_ptr, new_ptr)) = switch_context {
        unsafe {
            huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
        }
    }
    huesos_arch::interrupts::enable();
}

/// Park the current task on a wait queue: mark blocked, drop from the
/// runqueue, and switch away. Returns when [`wake_task`] has cleared
/// `blocked` and requeued the task.
pub fn park_current() {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
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
            guard.fair_queue.remove(vruntime, task_id);
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
                Some((old_ptr, new_ptr))
            })
        } else {
            None
        };
        drop(guard);
        if let Some((old_ptr, new_ptr)) = switch_context {
            unsafe {
                huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
            }
        }
    }
    huesos_arch::interrupts::enable();
}

/// Wake a previously parked task. Safe to call from IRQ context (port queue).
///
/// Always clears `blocked` and ensures the task is on the fair runqueue.
/// This closes the lost-wakeup race where `wake` arrived after enqueue but
/// before `park_current` set `blocked=true` (swap would early-return and the
/// subsequent park would sleep forever).
pub fn wake_task(task_id: u64) {
    let cpu = task_cpu(task_id);
    if cpu >= MAX_CPUS {
        return;
    }
    let idx = task_index(task_id);
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    if !guard.task_matches(task_id) {
        return;
    }
    let task = &mut guard.tasks[idx];
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
    if let SchedPolicy::Fair { vruntime, .. } = task.sched_policy {
        // insert is idempotent enough if we remove first (wavl may allow dup — remove first)
        let id = task.id;
        let vr = vruntime;
        guard.fair_queue.remove(vr, id);
        guard.fair_queue.insert(vr, id);
    }
    drop(guard);
    if cpu != cpu_id() {
        huesos_arch::lapic::ipi_reschedule(cpu as u8);
    }
}

/// Get current task id for debugging.
pub fn current_task_id() -> Option<u64> {
    let guard = PER_CPU_SCHEDULERS[cpu_id()].lock();
    guard.current_task().map(|t| t.id)
}

/// Monotonic BSP-ish tick counter for wait timeouts (sum of local ticks is
/// fine; we use the current CPU's scheduler ticks).
pub fn global_ticks() -> u64 {
    MONOTONIC_TICKS.load(Ordering::SeqCst)
}

/// Find the best CPU to spawn a task on (online CPU with fewest tasks).
fn find_best_cpu() -> usize {
    let mut best_cpu = cpu_id();
    let mut min_tasks = usize::MAX;
    let mask = ONLINE_CPUS.load(Ordering::SeqCst);

    for (i, scheduler) in PER_CPU_SCHEDULERS.iter().enumerate() {
        if (mask & (1u64 << i)) == 0 {
            continue;
        }
        let guard = scheduler.lock();
        let count = guard.live_task_count();
        // Prefer the least-loaded online CPU that already has at least an idle task.
        if count >= 1 && count < min_tasks {
            min_tasks = count;
            best_cpu = i;
        }
    }
    best_cpu
}

/// Set the scheduling policy for a task by its ID.
pub fn set_sched_policy(task_id: u64, policy: SchedPolicy) {
    huesos_arch::interrupts::disable();
    let cpu = task_cpu(task_id);
    let idx = task_index(task_id);
    if cpu < MAX_CPUS {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();

        if !guard.task_matches(task_id) {
            drop(guard);
            huesos_arch::interrupts::enable();
            return;
        }
        let old_policy = Some(guard.tasks[idx].sched_policy);

        if let Some(SchedPolicy::Fair { vruntime, .. }) = old_policy {
            guard.fair_queue.remove(vruntime, task_id);
        }

        if let Some(task) = guard.tasks.get_mut(idx) {
            task.sched_policy = policy;
        }

        if let SchedPolicy::Fair { vruntime, .. } = policy {
            guard.fair_queue.insert(vruntime, task_id);
        }
    }
    huesos_arch::interrupts::enable();
}

/// Spawn a new kernel thread.
pub fn spawn_kernel_thread(name: &[u8; 32], entry: extern "C" fn() -> !) -> u64 {
    huesos_arch::interrupts::disable();
    let cpu = find_best_cpu();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let id = guard.add_task(cpu, |id| Task::new_kernel(id, *name, entry));
    drop(guard);
    huesos_arch::interrupts::enable();

    if cpu != cpu_id() {
        huesos_arch::lapic::ipi_reschedule(cpu as u8);
    }
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
    huesos_arch::interrupts::disable();
    // Prefer the caller's CPU for userspace launches. Early boot services
    // spawned by init must not be stranded on an AP that is still settling
    // under QEMU TCG (missing ready handshake). Kernel threads may still
    // use find_best_cpu for load balance.
    let cpu = cpu_id();
    let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
    let id = guard.add_task(cpu, |id| {
        Task::new_user(
            id,
            *name,
            process,
            crate::process::user_entry_trampoline,
            cr3,
        )
    });
    drop(guard);
    // Publish startup metadata only after releasing the rank-60 scheduler.
    // Interrupts remain disabled, so this CPU cannot run the new local task
    // before its rank-40 process record is visible.
    crate::process::queue_user_entry(id, entry_point, user_rsp);
    huesos_arch::interrupts::enable();

    if cpu != cpu_id() {
        huesos_arch::lapic::ipi_reschedule(cpu as u8);
    }
    id
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
                guard.fair_queue.remove(vruntime, id);
            }
        }
    }
    if let Some(proc) = process_to_signal {
        proc.set_exit_code(code);
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

        if let Some((old_ptr, new_ptr)) = switch_context {
            unsafe {
                huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
            }
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
    process.set_exit_code(code);
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
                guard.fair_queue.remove(vruntime, id);
            }
            REAP_QUEUE.lock().push(id);
            REAP_PENDING.store(true, Ordering::Release);
        }
    }

    PROCESS_TEARDOWN.lock().push(Arc::clone(&process));
    REAP_PENDING.store(true, Ordering::Release);
    for cpu in 0..MAX_CPUS {
        if cpu != current_cpu && is_cpu_online(cpu) {
            huesos_arch::lapic::ipi_reschedule(cpu as u8);
        }
    }

    switch_away_from_finished(current_cpu)
}

fn switch_away_from_finished(cpu: usize) -> ! {
    loop {
        let mut guard = PER_CPU_SCHEDULERS[cpu].lock();
        let switch_context = guard.tick();
        drop(guard);

        if let Some((old_ptr, new_ptr)) = switch_context {
            unsafe {
                huesos_arch::context_switch::context_switch(old_ptr, new_ptr);
            }
        }
        huesos_arch::interrupts::enable();
        huesos_arch::hlt();
        huesos_arch::interrupts::disable();
    }
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
        let cpu = task_cpu(task_id);
        let idx = task_index(task_id);
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
                if slot.generation >= TASK_GENERATION_MASK {
                    // Never permit generation wrap to recreate a historical ID.
                    slot.retired = true;
                    false
                } else {
                    true
                }
            }
        };
        if reusable {
            guard.free_slots.push(idx);
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
}

#[cfg(test)]
mod task_id_tests {
    use super::*;

    #[test]
    fn task_id_fields_round_trip_without_aliasing() {
        let id = encode_task_id(63, 0x00ab_cdef, 0xfedc_ba98);
        assert_eq!(task_cpu(id), 63);
        assert_eq!(task_generation(id), 0x00ab_cdef);
        assert_eq!(task_index(id), 0xfedc_ba98);

        let next_cpu = encode_task_id(62, 0x00ab_cdef, 0xfedc_ba98);
        let next_generation = encode_task_id(63, 0x00ab_cdf0, 0xfedc_ba98);
        assert_ne!(id, next_cpu);
        assert_ne!(id, next_generation);
    }

    #[test]
    fn generation_exhaustion_retires_instead_of_wrapping() {
        assert_eq!(next_task_generation(0), Some(1));
        assert_eq!(next_task_generation(41), Some(42));
        assert_eq!(next_task_generation(TASK_GENERATION_MASK), None);
    }
}
