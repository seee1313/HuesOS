//! Preemptive round-robin scheduler with real context switches, including
//! switching page tables (CR3) and the kernel stack used for interrupts /
//! syscalls (TSS.RSP0) when hopping between kernel and userspace tasks.

use crate::task::{Task, TaskKind};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::Ordering;
use huesos_object::Process;
use x86_64::VirtAddr;

/// Wrapper needed because `UnsafeCell<T>` is never `Sync` regardless of
/// `T`; we provide the `Sync` impl ourselves since all accesses to the
/// inner `Scheduler` happen with interrupts disabled (see `with_scheduler`).
struct SchedulerCell(UnsafeCell<Scheduler>);
unsafe impl Sync for SchedulerCell {}

static SCHEDULER: SchedulerCell = SchedulerCell(UnsafeCell::new(Scheduler::new()));

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

/// RAII-ish helper: disable interrupts, run `f` with exclusive scheduler
/// access, re-enable interrupts.
fn with_scheduler<R>(f: impl FnOnce(&mut Scheduler) -> R) -> R {
    huesos_arch::interrupts::disable();
    let sched = unsafe { &mut *SCHEDULER.0.get() };
    let r = f(sched);
    huesos_arch::interrupts::enable();
    r
}

/// Initialize the scheduler and register the timer callback.
pub fn init() {
    let sched = unsafe { &mut *SCHEDULER.0.get() };
    sched.add_task(Task::new_idle(
        0,
        *b"idle\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    ));

    huesos_arch::timer_callback::set_timer_callback(&|| {
        let sched = unsafe { &mut *SCHEDULER.0.get() };
        sched.tick();
    });
}

/// Yield the current task (cooperative).
pub fn yield_now() {
    with_scheduler(|s| s.tick());
}

/// Get current task id for debugging.
pub fn current_task_id() -> Option<u64> {
    let sched = unsafe { &*SCHEDULER.0.get() };
    sched.current_task().map(|t| t.id)
}

/// Spawn a new kernel thread.
pub fn spawn_kernel_thread(name: &[u8; 32], entry: extern "C" fn() -> !) -> u64 {
    with_scheduler(|s| {
        let id = s.tasks.len() as u64;
        let task = Task::new_kernel(id, *name, entry);
        s.add_task(task)
    })
}

/// Spawn a new userspace task bound to `process`, whose first execution
/// will jump to ring3 via `entry_trampoline`.
pub fn spawn_user_thread(
    name: &[u8; 32],
    process: Arc<Process>,
    entry_trampoline: extern "C" fn() -> !,
    cr3: u64,
) -> u64 {
    with_scheduler(|s| {
        let id = s.tasks.len() as u64;
        let task = Task::new_user(id, *name, process, entry_trampoline, cr3);
        s.add_task(task)
    })
}

/// Mark the currently running task as finished (won't be scheduled again)
/// and switch away from it. Never returns.
pub fn exit_current_task(_code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let sched = unsafe { &mut *SCHEDULER.0.get() };
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
