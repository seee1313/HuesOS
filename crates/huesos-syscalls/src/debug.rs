//! Debug output syscall.

use huesos_abi::ErrorCode;

use crate::{callbacks::DEBUG_WRITE_FN, SyscallResult};

pub(crate) fn sys_debug_write(buf: *const u8, len: usize) -> SyscallResult {
    if buf.is_null() || len == 0 || len > 4096 {
        return Err(ErrorCode::InvalidArgs);
    }
    let slice = unsafe { core::slice::from_raw_parts(buf, len) };
    if let Some(f) = *DEBUG_WRITE_FN.lock() {
        f(slice);
    }
    Ok(len as i64)
}
