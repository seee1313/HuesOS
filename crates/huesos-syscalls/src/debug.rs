//! Debug output syscall.

use huesos_abi::ErrorCode;

use crate::{callbacks::DEBUG_WRITE_FN, user_memory, SyscallResult};

pub(crate) fn sys_debug_write(buf: *const u8, len: usize) -> SyscallResult {
    if len == 0 || len > 4096 {
        return Err(ErrorCode::InvalidArgs);
    }
    let bytes = user_memory::copy_from_user(buf, len)?;
    if let Some(f) = *DEBUG_WRITE_FN.lock() {
        f(&bytes);
    }
    Ok(len as i64)
}
