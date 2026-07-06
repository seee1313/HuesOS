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
}

impl Task {
    /// Create the idle task (no real stack, never preempted away from).
    pub fn new_idle(id: u64, name: [u8; 32]) -> Self {
        Self {
            id,
            name,
            context: Context::zero(),
            kernel_stack: Vec::new(),
            kind: TaskKind::Kernel,
            finished: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a kernel task that starts executing `entry`.
    pub fn new_kernel(id: u64, name: [u8; 32], entry: extern "C" fn() -> !) -> Self {
        let mut stack = alloc::vec![0u8; KERNEL_STACK_SIZE];
        let stack_top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let cr3 = current_cr3();
        // Reserve 8 bytes at the very top for the return address when the
        // thread function eventually `ret`s.
        let context = Context::new(entry, unsafe { stack_top.sub(8) }, cr3);
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
        let context = Context::new(entry_trampoline, unsafe { stack_top.sub(8) }, cr3);
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
        }
    }

    /// Top-of-stack address for this task's kernel stack (used to program
    /// TSS.RSP0 / the syscall kernel stack when this task is scheduled).
    pub fn kernel_stack_top(&self) -> u64 {
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
