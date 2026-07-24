//! Shared syscall helpers.

use alloc::sync::Arc;
use huesos_abi::ErrorCode;

/// Return the current process or `BadHandle` if no userspace process is active.
pub(crate) fn current_proc() -> Result<Arc<huesos_object::Process>, ErrorCode> {
    huesos_object::current_process().ok_or(ErrorCode::BadHandle)
}

/// RAII guard that runs a cleanup closure when dropped without being committed.
///
/// Used for **syscall rollback**: after a syscall performs side effects (handle
/// table insertions, object registrations, channel creation, thread starts),
/// any subsequent failure (user-memory write fault, quota exhaustion) must
/// undo those effects to maintain the all-or-nothing syscall contract.
///
/// # Usage
///
/// ```ignore
/// let rollback = DeferGuard::new(|| { /* undo side effects */ });
/// // ... perform more operations that might fail ...
/// user_memory::write_value(out, &value)?;  // on error, Drop runs cleanup
/// rollback.commit();  // success — disarm the guard
/// ```
///
/// # Safety notes
///
/// The cleanup closure must be **infalible** (no panics, no error returns).
/// It runs in a context where the syscall has already decided to fail; a
/// panicking cleanup would leave the kernel in an inconsistent state.
pub(crate) struct DeferGuard<F: FnOnce()> {
    cleanup: Option<F>,
}

impl<F: FnOnce()> DeferGuard<F> {
    /// Create a guard that will run `cleanup` on drop unless [`commit`](Self::commit) is called.
    pub fn new(cleanup: F) -> Self {
        Self {
            cleanup: Some(cleanup),
        }
    }

    /// Disarm the guard — the operation succeeded, no rollback needed.
    pub fn commit(mut self) {
        self.cleanup = None;
        // Drop with cleanup = None is a no-op.
    }
}

impl<F: FnOnce()> Drop for DeferGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.cleanup.take() {
            f();
        }
    }
}
