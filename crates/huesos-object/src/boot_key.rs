//! Bootloader volume-key blob (Stage D bootloader KeyProvider).
//!
//! The kernel bakes a 32-byte volume key blob into the image at
//! build time (`HUESOS_VOLUME_KEY_HEX`, see
//! `huesos-kernel/build.rs`) and stores it here at boot; the
//! `VolumeKeyTake` syscall moves it to KeyBroker, which
//! passes it to `Hxfs::mount_with_keys`. On a build without the
//! blob (plain-volume deployments) the slot stays `None` and the
//! syscall returns `NotFound`; an encrypted volume then cannot be
//! mounted, which is the correct Stage D behaviour.
//!
//! This is the MVP "bootloader key" handoff. A real Stage D
//! implementation measures/seals the key with the TPM and
//! unseals it into this slot at boot; the ABI of the handoff
//! (kernel -> syscall -> service -> mount) does not change.

use crate::irq_guard::IrqSafeMutex;

/// The kernel-owned volume key blob. `None` when this build has no
/// key (only plain volumes can be mounted then).
pub static BOOT_VOLUME_KEY: IrqSafeMutex<Option<[u8; 32]>> = IrqSafeMutex::new(None);

/// Install the build-time key blob (called once during kernel
/// init, before KeyBroker can call `VolumeKeyTake`).
pub fn set_boot_volume_key(key: [u8; 32]) {
    *BOOT_VOLUME_KEY.lock() = Some(key);
}

/// Atomically remove the boot volume key from the kernel slot.
///
/// Only the capability-gated `VolumeKeyTake` syscall calls this. Returning
/// `None` after the first successful call is the one-shot contract.
pub fn take_boot_volume_key() -> Option<[u8; 32]> {
    BOOT_VOLUME_KEY.lock().take()
}

/// Restore a key when the final recoverable userspace copy failed.
///
/// The syscall validates the output before taking the key, but a page fault can
/// still occur during the recoverable copy. Restoration preserves the one-shot
/// contract without turning a bad pointer into permanent key loss.
pub fn restore_boot_volume_key(key: [u8; 32]) -> Result<(), [u8; 32]> {
    let mut slot = BOOT_VOLUME_KEY.lock();
    if slot.is_some() {
        return Err(key);
    }
    *slot = Some(key);
    Ok(())
}
