//! Task (thread) representation: kernel threads and userspace (ring3)
//! processes/threads.

use alloc::sync::Arc;
use alloc::vec::Vec;
use huesos_arch::context_switch::Context;
use huesos_arch::VirtAddr;
use huesos_object::Process;

/// Stack size for a kernel thread (64 KiB).
pub const KERNEL_STACK_SIZE: usize = 4096 * 16;
/// Stack size for a userspace thread's kernel-side stack (used for
/// interrupts/syscalls while running in ring0 on behalf of that thread).
pub const USER_KERNEL_STACK_SIZE: usize = 4096 * 16;

/// What kind of execution context this task represents.
pub enum TaskKind {
    /// A task that only ever runs in ring0 (kernel code).
    Kernel,
    /// A task that runs userspace code in ring3, associated with a
    /// [`Process`] and its own address space.
    User {
        /// Owning process (address space + handle table).
        process: Arc<Process>,
    },
}

/// A schedulable task — execution context with its own stack.
pub struct Task {
    /// Task id.
    pub id: u64,
    /// Task name.
    pub name: [u8; 32],
    /// CPU context (callee-saved + RIP/RSP/RFLAGS/CR3).
    pub context: Context,
    /// Kernel-side stack (always present; used directly for kernel tasks,
    /// used as RSP0/interrupt stack for user tasks).
    pub kernel_stack: Vec<u8>,
    /// What kind of task this is.
    pub kind: TaskKind,
    /// Set once the task has exited; the scheduler skips finished tasks.
    pub finished: core::sync::atomic::AtomicBool,
    /// Set while the task is parked on a wait queue (blocking syscall).
    pub blocked: core::sync::atomic::AtomicBool,
    /// Scheduling policy.
    pub sched_policy: crate::scheduler::SchedPolicy,
}

impl Task {
    /// Create the idle task (no real stack, never preempted away from).
    ///
    /// Uses the *current* CR3 (the kernel's own address space) rather than
    /// `Context::zero()`'s cr3=0: this task's context is only ever a
    /// placeholder until the first context switch overwrites it with the
    /// real suspended kmain state, but if a switch *back into* task 0 ever
    /// happened before that first switch (or if `cr3` were otherwise never
    /// updated — see the note on `context_switch` for why that's not
    /// actually guaranteed), loading `cr3=0` would immediately triple-fault
    /// the machine (there is no valid page table at physical address 0).
    pub fn new_idle(id: u64, name: [u8; 32]) -> Self {
        Self {
            id,
            name,
            context: Context::zero_with_cr3(current_cr3()),
            kernel_stack: Vec::new(),
            kind: TaskKind::Kernel,
            finished: core::sync::atomic::AtomicBool::new(false),
            blocked: core::sync::atomic::AtomicBool::new(false),
            sched_policy: crate::scheduler::SchedPolicy::Fair {
                weight: 1024,
                vruntime: 0,
            },
        }
    }

    /// Create a kernel task that starts executing `entry`.
    pub fn new_kernel(id: u64, name: [u8; 32], entry: extern "C" fn() -> !) -> Self {
        let mut stack = alloc::vec![0u8; KERNEL_STACK_SIZE];
        let stack_top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let cr3 = current_cr3();
        // Reserve 8 bytes at the very top for the return address when the
        // thread function eventually `ret`s.
        // SAFETY: `stack` owns USER_KERNEL_STACK_SIZE writable bytes and is
        // stored in the Task for the complete context lifetime. Reserving the
        // top word leaves room for the thread-return sentinel below.
        let context = unsafe { Context::new(entry, stack_top.sub(8), cr3) };
        unsafe {
            let ret_slot = (stack_top as *mut u64).sub(1);
            *ret_slot = thread_exit as *const () as u64;
        }
        Self {
            id,
            name,
            context,
            kernel_stack: stack,
            kind: TaskKind::Kernel,
            finished: core::sync::atomic::AtomicBool::new(false),
            blocked: core::sync::atomic::AtomicBool::new(false),
            sched_policy: crate::scheduler::SchedPolicy::Fair {
                weight: 1024,
                vruntime: 0,
            },
        }
    }

    /// Create a userspace task. `entry_trampoline` is a small kernel-side
    /// function that performs the ring0->ring3 jump (`enter_userspace`) the
    /// first time this task is scheduled; from then on, context switches
    /// resume it exactly like a kernel task (its saved context lives on its
    /// kernel stack, same as any other task, since interrupts/syscalls push
    /// state there).
    pub fn new_user(
        id: u64,
        name: [u8; 32],
        process: Arc<Process>,
        entry_trampoline: extern "C" fn() -> !,
        cr3: u64,
    ) -> Self {
        let mut stack = alloc::vec![0u8; USER_KERNEL_STACK_SIZE];
        let stack_top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        // SAFETY: the Task retains this writable stack for its full lifetime;
        // the top word is reserved for the return sentinel.
        let context = unsafe { Context::new(entry_trampoline, stack_top.sub(8), cr3) };
        unsafe {
            let ret_slot = (stack_top as *mut u64).sub(1);
            *ret_slot = thread_exit as *const () as u64;
        }
        Self {
            id,
            name,
            context,
            kernel_stack: stack,
            kind: TaskKind::User { process },
            finished: core::sync::atomic::AtomicBool::new(false),
            blocked: core::sync::atomic::AtomicBool::new(false),
            sched_policy: crate::scheduler::SchedPolicy::Fair {
                weight: 1024,
                vruntime: 0,
            },
        }
    }

    /// Top-of-stack address for this task's kernel stack (used to program
    /// TSS.RSP0 / the syscall kernel stack when this task is scheduled).
    ///
    /// Returns `0` for tasks with no real kernel stack (the idle task):
    /// `Vec::as_ptr()` on an empty, never-allocated `Vec` returns a
    /// dangling-but-well-aligned sentinel pointer (not a null pointer), so
    /// without this explicit check the scheduler would happily program
    /// TSS.RSP0 with that bogus, non-zero address whenever it switched to
    /// idle — a real kernel stack corruption bug waiting to be triggered
    /// the first time idle takes an interrupt/syscall from ring3-adjacent
    /// state before switching away again.
    pub fn kernel_stack_top(&self) -> u64 {
        if self.kernel_stack.is_empty() {
            return 0;
        }
        unsafe { self.kernel_stack.as_ptr().add(self.kernel_stack.len()) as u64 }
    }
}

fn current_cr3() -> u64 {
    use x86_64::registers::control::Cr3;
    Cr3::read().0.start_address().as_u64()
}

/// Default landing pad when a kernel thread returns.
extern "C" fn thread_exit() -> ! {
    loop {
        huesos_arch::hlt();
    }
}

/// Silence unused import warning when VirtAddr isn't otherwise referenced.
#[allow(dead_code)]
fn _assert_virtaddr_reexport(_: VirtAddr) {}
