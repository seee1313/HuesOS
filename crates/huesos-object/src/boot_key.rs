//! Bootloader volume-key blob (Stage D bootloader KeyProvider).
//!
//! The kernel bakes a 32-byte volume key blob into the image at
//! build time (`HUESOS_VOLUME_KEY_HEX`, see
//! `huesos-kernel/build.rs`) and stores it here at boot; the
//! `VolumeKeyGet` syscall serves it to the storage service, which
//! passes it to `Hxfs::mount_with_keys`. On a build without the
//! blob (plain-volume deployments) the slot stays `None` and the
//! syscall returns `NotFound`; an encrypted volume then cannot be
//! mounted, which is the correct Stage D behaviour.
//!
//! This is the MVP "bootloader key" handoff. A real Stage D
//! implementation measures/seals the key with the TPM and
//! unseals it into this slot at boot; the ABI of the handoff
//! (kernel -> syscall -> service -> mount) does not change.

use spin::Mutex;

/// The kernel-owned volume key blob. `None` when this build has no
/// key (only plain volumes can be mounted then).
pub static BOOT_VOLUME_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// Install the build-time key blob (called once during kernel
/// init, before any userspace process can call `VolumeKeyGet`).
pub fn set_boot_volume_key(key: [u8; 32]) {
    *BOOT_VOLUME_KEY.lock() = Some(key);
}
