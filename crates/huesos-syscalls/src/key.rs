//! Stage D: `VolumeKeyGet` — bootloader volume key handoff.
//!
//! Copies the kernel's build-time volume key blob
//! (`huesos_object::boot_key::BOOT_VOLUME_KEY`) into the caller's
//! buffer. Returns `NotFound` when this build has no key blob
//! (plain-volume deployments). The storage service passes the key
//! to `Hxfs::mount_with_keys`, so an encrypted volume is
//! mountable exactly when the bootloader/kernel key path
//! delivered a key.

use crate::user_memory;
use crate::SyscallResult;
use huesos_abi::ErrorCode;

pub(crate) fn sys_volume_key_get(out: *mut [u8; 32]) -> SyscallResult {
    let key = match *huesos_object::boot_key::BOOT_VOLUME_KEY.lock() {
        Some(key) => key,
        None => return Err(ErrorCode::NotFound),
    };
    // SAFETY-free boundary: user_memory::copy_to_user validates
    // the destination against the caller's address space before
    // writing and returns the kernel error code on a fault.
    user_memory::copy_to_user(out as *mut u8, &key)?;
    Ok(0)
}
