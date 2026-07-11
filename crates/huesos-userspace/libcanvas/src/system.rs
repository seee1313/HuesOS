//! Monotonic time and supervisor system-control wrappers.

use crate::raw;
use huesos_abi::Syscall;

/// Read the kernel monotonic clock in 100 Hz scheduler ticks.
pub fn monotonic_ticks() -> crate::Result<u64> {
    let value = raw::syscall0(Syscall::ClockGetMonotonic);
    raw::decode(value).map(|ticks| ticks as u64)
}

/// Request an orderly non-ACPI software shutdown.
///
/// Kernel policy accepts this only from the root init supervisor. On success
/// every CPU halts and this function does not return.
pub fn shutdown() -> crate::Result<()> {
    let value = raw::syscall0(Syscall::SystemShutdown);
    raw::decode(value).map(|_| ())
}
