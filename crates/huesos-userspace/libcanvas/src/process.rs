//! Process/thread-level primitives: exiting and cooperative yielding.

use crate::raw;
use huesos_abi::Syscall;

/// Exit the current process with `code`. Never returns.
pub fn exit(code: i64) -> ! {
    unsafe {
        let _ = raw::syscall1(Syscall::ProcessExit, code as u64);
    }
    // The kernel's ProcessExit handler never returns control, but the
    // compiler doesn't know that about a syscall; park just in case.
    loop {
        core::hint::spin_loop();
    }
}

/// Yield the remainder of the current thread's scheduling quantum
/// cooperatively.
pub fn yield_now() {
    unsafe {
        let _ = raw::syscall0(Syscall::Yield);
    }
}
