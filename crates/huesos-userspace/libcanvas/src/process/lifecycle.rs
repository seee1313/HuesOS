//! Process lifecycle helpers.

use crate::raw;
use huesos_abi::Syscall;

/// Exit the current process with `code`, running registered finalisers when
/// linked dynamically or built as `libcanvas.so`. Never returns.
pub fn exit(code: i64) -> ! {
    #[cfg(feature = "c-abi")]
    crate::c_abi::run_process_fini_once();
    #[cfg(feature = "dyn-client")]
    {
        #[link(name = "canvas", kind = "dylib")]
        unsafe extern "C" {
            fn canvas_exit(code: i64) -> !;
        }
        // SAFETY: `canvas_exit` runs registered `__cxa_atexit`/`.fini_array`
        // handlers in `libcanvas.so` / `ld-huesos.so` and invokes `ProcessExit`.
        unsafe { canvas_exit(code) }
    }
    #[cfg(not(feature = "dyn-client"))]
    {
        let _ = raw::syscall1(Syscall::ProcessExit, code as u64);
        // The kernel's ProcessExit handler never returns control, but the
        // compiler doesn't know that about a syscall; park just in case.
        loop {
            core::hint::spin_loop();
        }
    }
}

/// Exit only the calling thread with `code`. If it is the last active thread
/// in the process, the kernel tears down the process as well. Never returns.
pub fn exit_thread(code: i64) -> ! {
    let _ = raw::syscall1(Syscall::ThreadExit, code as u64);
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
