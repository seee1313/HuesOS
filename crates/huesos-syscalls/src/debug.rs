//! Debug output syscall.

use huesos_abi::ErrorCode;

use crate::{callbacks::DEBUG_WRITE_FN, user_memory, SyscallResult};

pub(crate) fn sys_debug_write(buf: *const u8, len: usize) -> SyscallResult {
    if len == 0 || len > 4096 {
        return Err(ErrorCode::InvalidArgs);
    }
    let bytes = user_memory::copy_from_user(buf, len)?;
    // Drop the lock before calling the callback (see
    // `huesos_object::wait::park_current` for why holding a callback
    // mutex guard across the call is unsafe in general).
    let debug_write_fn = *DEBUG_WRITE_FN.lock();
    if let Some(f) = debug_write_fn {
        f(&bytes);
    }
    Ok(len as i64)
}
