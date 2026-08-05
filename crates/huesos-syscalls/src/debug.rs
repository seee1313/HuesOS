//! Debug output syscall.

use huesos_abi::ErrorCode;

use crate::{callbacks::DEBUG_WRITE_FN, user_memory, SyscallResult};

pub(crate) fn sys_debug_write(buf: *const u8, len: usize) -> SyscallResult {
    if len == 0 || len > 4096 {
        return Err(ErrorCode::InvalidArgs);
    }
    let bytes = user_memory::copy_from_user(buf, len)?;
    // Hold the callback lookup lock for the duration of the write. This
    // both pins the callback (so a concurrent `set_debug_write_fn` cannot
    // swap the function pointer mid-write) and serializes writers against
    // each other so two `DebugWrite` syscalls cannot interleave bytes.
    //
    // `debug_write` writes one byte at a time to the UART without its own
    // lock. Under release-mode LTO the scheduler can preempt a userspace
    // process between two bytes of the same write and dispatch another
    // `DebugWrite` syscall whose bytes interleave with the first,
    // producing a serial log that no longer matches the source-level
    // `\n`-bounded lines the boot smoke greps for. Holding this guard
    // for the duration of the write is safe because `debug_write` never
    // re-enters the syscall path.
    //
    // See `huesos_object::wait::park_current` for the related
    // callback-mutex-across-call pattern; this is the analogous
    // write-side application.
    let guard = DEBUG_WRITE_FN.lock();
    if let Some(f) = *guard {
        f(&bytes);
    }
    Ok(len as i64)
}
