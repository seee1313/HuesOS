//! Monotonic time and supervisor system-control wrappers.

use crate::raw;
use huesos_abi::Syscall;

/// Read the kernel monotonic clock in 100 Hz scheduler ticks.
pub fn monotonic_ticks() -> crate::Result<u64> {
    let value = raw::syscall0(Syscall::ClockGetMonotonic);
    raw::decode(value).map(|ticks| ticks as u64)
}

/// Number of online CPUs using HuesOS dense CPU indexes.
pub fn cpu_count() -> crate::Result<usize> {
    let value = raw::syscall0(Syscall::SystemCpuCount);
    raw::decode(value).map(|count| count as usize)
}

/// Dense CPU index of the caller.
pub fn current_cpu() -> crate::Result<usize> {
    let value = raw::syscall0(Syscall::SystemCurrentCpu);
    raw::decode(value).map(|cpu| cpu as usize)
}

/// Copy the bootloader volume key blob (Stage D key handoff).
///
/// `Ok(None)` when this kernel build has no key blob (plain-volume
/// deployments); an encrypted volume then cannot be mounted, which
/// is the Stage D security gate. The storage service passes the
/// key to `Hxfs::mount_with_keys`.
pub fn get_volume_key() -> crate::Result<Option<[u8; 32]>> {
    let mut key = [0u8; 32];
    let ret = raw::syscall1(Syscall::VolumeKeyGet, &mut key as *mut [u8; 32] as u64);
    match raw::decode(ret) {
        Ok(_) => Ok(Some(key)),
        Err(crate::ErrorCode::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Request an orderly non-ACPI software shutdown.
///
/// Kernel policy accepts this only from the root init supervisor. On success
/// every CPU halts and this function does not return.
pub fn shutdown() -> crate::Result<()> {
    let value = raw::syscall0(Syscall::SystemShutdown);
    raw::decode(value).map(|_| ())
}
