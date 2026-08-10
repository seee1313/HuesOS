//! Build-time bootloader volume key blob (Stage D).
//!
//! `huesos-kernel/build.rs` emits this module's body from the
//! `HUESOS_VOLUME_KEY_HEX` environment variable (64 hex chars);
//! the kernel stores it in `huesos_object::boot_key` at init and
//! the `VolumeKeyGet` syscall serves it to the storage service.
//! A build without the variable gets `None` (plain-volume
//! deployments; encrypted volumes then cannot mount, which is the
//! Stage D security gate).

include!(concat!(env!("OUT_DIR"), "/boot_key.rs"));
