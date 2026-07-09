//! Preemptive round-robin scheduler with real context switches, including
//! switching page tables (CR3) and the kernel stack used for interrupts /
//! syscalls (TSS.RSP0) when hopping between kernel and userspace tasks.
//!
//! SMP-aware: each CPU has its own scheduler instance accessed via LAPIC ID.

use crate::task::{Task, TaskKind};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::Ordering;
use huesos_object::Process;
use x86_64::VirtAddr;

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 64;

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
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current: 0,
        }
    }

    fn add_task(&mut self, task: Task) -> u64 {
        let id = task.id;
        self.tasks.push(task);
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

    /// Pick the next non-finished task in round-robin order. Always leaves
    /// task 0 (idle) as a fallback so we never run out of runnable tasks.
    fn next_runnable(&self) -> usize {
        let len = self.tasks.len();
        for step in 1..=len {
            let idx = (self.current + step) % len;
            if idx == 0 || !self.tasks[idx].finished.load(Ordering::Relaxed) {
                return idx;
            }
        }
        0
    }

    fn tick(&mut self) {
        let len = self.tasks.len();
        if len <= 1 {
            return;
        }
        let old_index = self.current;
        self.current = self.next_runnable();
        if self.current == old_index {
            return;
        }
        self.apply_task_environment(self.current);

        let (old_ptr, new_ptr): (*mut Task, *const Task) = {
            let old = &mut self.tasks[old_index] as *mut Task;
            let new = &self.tasks[self.current] as *const Task;
            (old, new)
        };

        // Safety: interrupts are disabled by the caller; pointers are into
        // a Vec that outlives this call.
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

/// Find a CPU that is currently idle (only the idle task is present).
fn find_idle_cpu() -> Option<u8> {
    for i in 0..MAX_CPUS {
        let sched = unsafe { &*PER_CPU_SCHEDULERS[i].0.get() };
        if sched.tasks.len() == 1 {
            // Only idle task — this CPU is idle.
            return Some(i as u8);
        }
    }
    None
}

/// If there is an idle CPU, send it a reschedule IPI so it picks up
/// the newly added task.
fn maybe_wake_idle_cpu() {
    if let Some(cpu) = find_idle_cpu() {
        huesos_arch::lapic::ipi_reschedule(cpu);
    }
}

/// Spawn a new kernel thread on the current CPU.
pub fn spawn_kernel_thread(name: &[u8; 32], entry: extern "C" fn() -> !) -> u64 {
    let id = with_scheduler(|s| {
        let id = s.tasks.len() as u64;
        let task = Task::new_kernel(id, *name, entry);
        s.add_task(task)
    });
    maybe_wake_idle_cpu();
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
    let id = with_scheduler(|s| {
        let id = s.tasks.len() as u64;
        crate::process::queue_user_entry(id, entry_point, user_rsp);
        let task = Task::new_user(
            id,
            *name,
            process,
            crate::process::user_entry_trampoline,
            cr3,
        );
        s.add_task(task)
    });
    maybe_wake_idle_cpu();
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
