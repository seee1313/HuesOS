//! Process lifecycle helpers.

use crate::raw;
use huesos_abi::Syscall;

/// Exit the current process with `code`. Never returns.
pub fn exit(code: i64) -> ! {
    let _ = raw::syscall1(Syscall::ProcessExit, code as u64);
    // The kernel's ProcessExit handler never returns control, but the
    // compiler doesn't know that about a syscall; park just in case.
    loop {
        core::hint::spin_loop();
    }
}

/// Yield the remainder of the current thread's scheduling quantum
/// cooperatively.
pub fn yield_now() {
    let _ = raw::syscall0(Syscall::Yield);
}

/// Set the calling thread's x86-64 `MSR_FS_BASE` (userspace TLS base).
///
/// The kernel rejects non-canonical or kernel-half addresses (`>= USER_ASPACE_END`)
/// with `ErrorCode::InvalidArgs`.
pub fn set_fs_base(fs_base: u64) -> crate::Result<()> {
    raw::decode(raw::syscall1(Syscall::ThreadSetFsBase, fs_base)).map(|_| ())
}
