//! Monotonic clock and privileged system-control syscalls.

use huesos_abi::ErrorCode;

use crate::callbacks::{CLOCK_FN, SHUTDOWN_FN};
use crate::SyscallResult;

pub(crate) fn sys_clock_get_monotonic() -> SyscallResult {
    let clock = (*CLOCK_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let ticks = clock();
    if ticks > i64::MAX as u64 {
        return Err(ErrorCode::Busy);
    }
    Ok(ticks as i64)
}

pub(crate) fn sys_system_shutdown() -> SyscallResult {
    let shutdown = (*SHUTDOWN_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    shutdown()?;
    // A successful shutdown never returns. Keep the ABI result defined for a
    // test implementation that elects to return instead.
    Ok(0)
}
