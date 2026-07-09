//! Preemptive round-robin scheduler with real context switches, including
//! switching page tables (CR3) and the kernel stack used for interrupts /
//! syscalls (TSS.RSP0) when hopping between kernel and userspace tasks.
//!
//! SMP-aware: each CPU has its own scheduler instance accessed via LAPIC ID.
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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::Ordering;
use huesos_object::Process;
use x86_64::VirtAddr;

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 64;

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

/// Wrapper needed because `UnsafeCell<T>` is never `Sync` regardless of
/// `T`; we provide the `Sync` impl ourselves since all accesses to the
/// inner `Scheduler` happen with interrupts disabled.
struct SchedulerCell(UnsafeCell<Scheduler>);
unsafe impl Sync for SchedulerCell {}

static PER_CPU_SCHEDULERS: [SchedulerCell; MAX_CPUS] =
    [const { SchedulerCell(UnsafeCell::new(Scheduler::new())) }; MAX_CPUS];

struct Scheduler {
    tasks: Vec<Task>,
    current: usize,
    fair_queue: wavl::WavlTree,
    ticks: u64,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current: 0,
            fair_queue: wavl::WavlTree::new(),
            ticks: 0,
        }
    }

    fn add_task(&mut self, task: Task) -> u64 {
        let id = task.id;
        let idx = self.tasks.len();
        let policy = task.sched_policy;
        self.tasks.push(task);
        if idx > 0 {
            if let SchedPolicy::Fair { vruntime, .. } = policy {
                self.fair_queue.insert(vruntime, id);
            }
        }
        id
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

    fn tick(&mut self) {
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
            let curr_task = &mut self.tasks[self.current];
            let task_id = curr_task.id;
            let finished = curr_task.finished.load(Ordering::Relaxed);

            match &mut curr_task.sched_policy {
                SchedPolicy::Fair { weight, vruntime } => {
                    let delta = (1024 * 1000) / (*weight).max(1);
                    *vruntime += delta;
                    if !finished {
                        // Re-insert into Fair queue
                        self.fair_queue.insert(*vruntime, task_id);
                    }
                }
                SchedPolicy::Deadline { remaining_budget, .. } => {
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
            if t.finished.load(Ordering::Relaxed) {
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

        // If no Deadline task is ready, schedule from Fair queue
        if next_idx == 0 {
            if let Some(task_id) = self.fair_queue.pop_min() {
                next_idx = (task_id & 0xFFFFFFFF) as usize;
            }
        }

        let old_index = self.current;
        if next_idx == old_index {
            // Keep running the same task
            return;
        }

        self.current = next_idx;
        self.apply_task_environment(self.current);

        let (old_ptr, new_ptr): (*mut Task, *const Task) = {
            let old = &mut self.tasks[old_index] as *mut Task;
            let new = &self.tasks[self.current] as *const Task;
            (old, new)
        };

        // Safety: interrupts are disabled; pointers point to active Vec
        unsafe {
            huesos_arch::context_switch::context_switch(
                &mut (*old_ptr).context,
                &(*new_ptr).context,
            );
        }
    }

    fn current_task(&self) -> Option<&Task> {
        self.tasks.get(self.current)
    }
}

/// Return the LAPIC ID of the current CPU via GS_BASE, clamped to MAX_CPUS.
fn cpu_id() -> usize {
    (unsafe { huesos_arch::cpu_local::current_lapic_id() } as usize).min(MAX_CPUS - 1)
}

/// Get a mutable reference to the current CPU's scheduler.
///
/// # Safety
/// Interrupts must be disabled by the caller.
unsafe fn current_scheduler() -> &'static mut Scheduler {
    &mut *PER_CPU_SCHEDULERS[cpu_id()].0.get()
}

/// Register the current CPU's scheduler pointer in its `CpuLocal`.
///
/// # Safety
/// Must be called once per CPU after `cpu_local::init_gs_base`.
unsafe fn register_scheduler_ptr(sched: *mut Scheduler) {
    let ptr = huesos_arch::cpu_local::cpu_local_ptr();
    unsafe { (*ptr).scheduler = sched as *mut () };
}

/// RAII-ish helper: disable interrupts, run `f` with exclusive scheduler
/// access, re-enable interrupts.
fn with_scheduler<R>(f: impl FnOnce(&mut Scheduler) -> R) -> R {
    huesos_arch::interrupts::disable();
    let sched = unsafe { current_scheduler() };
    let r = f(sched);
    huesos_arch::interrupts::enable();
    r
}

/// Initialize the scheduler for the current CPU and register the timer callback.
/// Called once per CPU.
pub fn init() {
    let sched = unsafe { current_scheduler() };
    unsafe { register_scheduler_ptr(sched) };
    sched.add_task(Task::new_idle(
        0,
        *b"idle\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    ));

    huesos_arch::timer_callback::set_timer_callback(&|| {
        let sched = unsafe { current_scheduler() };
        sched.tick();
    });
}

/// Yield the current task (cooperative).
pub fn yield_now() {
    with_scheduler(|s| s.tick());
}

/// Get current task id for debugging.
pub fn current_task_id() -> Option<u64> {
    let sched = unsafe { &*PER_CPU_SCHEDULERS[cpu_id()].0.get() };
    sched.current_task().map(|t| t.id)
}

/// Find the best CPU to spawn a task on (online CPU with fewest tasks).
fn find_best_cpu() -> usize {
    let mut best_cpu = 0;
    let mut min_tasks = usize::MAX;

    for i in 0..MAX_CPUS {
        let sched = unsafe { &*PER_CPU_SCHEDULERS[i].0.get() };
        let count = sched.tasks.len();
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
    let cpu = (task_id >> 32) as usize;
    let idx = (task_id & 0xFFFFFFFF) as usize;
    if cpu < MAX_CPUS {
        let sched = unsafe { &mut *PER_CPU_SCHEDULERS[cpu].0.get() };
        if let Some(task) = sched.tasks.get_mut(idx) {
            // Remove from fair queue if it was there
            if let SchedPolicy::Fair { vruntime, .. } = task.sched_policy {
                sched.fair_queue.remove(vruntime, task_id);
            }

            task.sched_policy = policy;

            // Re-insert into fair queue if the new policy is Fair
            if let SchedPolicy::Fair { vruntime, .. } = policy {
                sched.fair_queue.insert(vruntime, task_id);
            }
        }
    }
    huesos_arch::interrupts::enable();
}

/// Spawn a new kernel thread.
pub fn spawn_kernel_thread(name: &[u8; 32], entry: extern "C" fn() -> !) -> u64 {
    huesos_arch::interrupts::disable();
    let cpu = find_best_cpu();
    let sched = unsafe { &mut *PER_CPU_SCHEDULERS[cpu].0.get() };
    let id = ((cpu as u64) << 32) | (sched.tasks.len() as u64);
    let task = Task::new_kernel(id, *name, entry);
    sched.add_task(task);
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
    let cpu = find_best_cpu();
    let sched = unsafe { &mut *PER_CPU_SCHEDULERS[cpu].0.get() };
    let id = ((cpu as u64) << 32) | (sched.tasks.len() as u64);
    crate::process::queue_user_entry(id, entry_point, user_rsp);
    let task = Task::new_user(
        id,
        *name,
        process,
        crate::process::user_entry_trampoline,
        cr3,
    );
    sched.add_task(task);
    huesos_arch::interrupts::enable();

    if cpu != cpu_id() {
        huesos_arch::lapic::ipi_reschedule(cpu as u8);
    }
    id
}

/// Mark the currently running task as finished (won't be scheduled again)
/// and switch away from it. Never returns.
pub fn exit_current_task(_code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let sched = unsafe { current_scheduler() };
    if let Some(task) = sched.tasks.get(sched.current) {
        task.finished.store(true, Ordering::Relaxed);
    }
    loop {
        sched.tick();
        huesos_arch::interrupts::enable();
        huesos_arch::hlt();
        huesos_arch::interrupts::disable();
    }
}
