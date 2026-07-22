//! Shared syscall helpers.

use alloc::sync::Arc;
use huesos_abi::ErrorCode;

/// Return the current process or `BadHandle` if no userspace process is active.
pub(crate) fn current_proc() -> Result<Arc<huesos_object::Process>, ErrorCode> {
    huesos_object::current_process().ok_or(ErrorCode::BadHandle)
}

/// Map a handle-table admission failure to the syscall resource status.
pub(crate) fn map_handle_install_error(error: huesos_object::HandleTableError) -> ErrorCode {
    match error {
        huesos_object::HandleTableError::QuotaExceeded
        | huesos_object::HandleTableError::OutOfMemory => ErrorCode::NoMemory,
        huesos_object::HandleTableError::Missing
        | huesos_object::HandleTableError::Duplicate => ErrorCode::InvalidArgs,
    }
}
