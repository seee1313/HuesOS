//! Shared syscall helpers.

use alloc::sync::Arc;
use huesos_abi::ErrorCode;

/// Return the current process or `BadHandle` if no userspace process is active.
pub(crate) fn current_proc() -> Result<Arc<huesos_object::Process>, ErrorCode> {
    huesos_object::current_process().ok_or(ErrorCode::BadHandle)
}
