//! Kernel-enforced PCI `DeviceLease` ABI (AP-20 / Stages G.2 + G.3).
//!
//! A `DeviceLease` binds hardware authority to a non-zero
//! `(device_id, generation, firmware_snapshot_id)` tuple so BDF reuse,
//! relocation, surprise removal, or stale capability requests cannot revive
//! authority across generations (preventing ABA races).

use crate::{HandleValue, ResourceKindAbi};

/// Lease lifecycle states visible across the syscall boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DeviceLeaseStateAbi {
    /// Plan committed; child resources may be minted for this generation.
    Configured = 1,
    /// Driver reported ready; lease is operational.
    Online = 2,
    /// Teardown or relocation in progress; minting disabled.
    Removing = 3,
    /// Lease ended normally or by surprise removal.
    Removed = 4,
    /// Lease failed closed and cannot return online.
    Failed = 5,
}

impl DeviceLeaseStateAbi {
    /// Decode a wire value.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            1 => Self::Configured,
            2 => Self::Online,
            3 => Self::Removing,
            4 => Self::Removed,
            5 => Self::Failed,
            _ => return None,
        })
    }
}

/// Revocation flags passed to [`crate::Syscall::DeviceLeaseRevoke`].
pub mod revoke_flags {
    /// Mark the revoked lease as failed-closed (`Failed`) instead of `Removed`.
    pub const FAILED: u32 = 1 << 0;
    /// All known revocation flags.
    pub const ALL: u32 = FAILED;
}

/// Pack `(segment, bus, device, function)` into a canonical `u64`.
/// Returns `None` if `device >= 32` or `function >= 8`.
pub const fn pack_pci_address(segment: u16, bus: u8, device: u8, function: u8) -> Option<u64> {
    if device >= 32 || function >= 8 {
        return None;
    }
    Some(
        ((segment as u64) << 16)
            | ((bus as u64) << 8)
            | (((device as u64) & 0x1F) << 3)
            | ((function as u64) & 0x07),
    )
}

/// Unpack a canonical `u64` PCI address into `(segment, bus, device, function)`.
/// Rejects reserved upper bits so callers cannot smuggle hidden tags.
pub const fn unpack_pci_address(packed: u64) -> Option<(u16, u8, u8, u8)> {
    if (packed >> 32) != 0 {
        return None;
    }
    let segment = (packed >> 16) as u16;
    let bus = ((packed >> 8) & 0xFF) as u8;
    let devfn = (packed & 0xFF) as u8;
    let device = (devfn >> 3) & 0x1F;
    let function = devfn & 0x07;
    Some((segment, bus, device, function))
}

/// Arguments for [`crate::Syscall::DeviceLeaseCreate`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceLeaseCreateArgs {
    /// Caller-owned `DeviceLeaseAuthority` capability handle.
    pub authority: HandleValue,
    /// Reserved creation flags. Must be zero.
    pub flags: u32,
    /// Non-zero stable device presence identity.
    pub device_id: u64,
    /// Non-zero firmware snapshot identity (`HMCF` / boot archive).
    pub firmware_snapshot_id: u64,
    /// Canonical packed PCI address from [`pack_pci_address`].
    pub pci_address_packed: u64,
}

impl DeviceLeaseCreateArgs {
    /// Validate structural fields before entering object creation.
    pub const fn validate(&self) -> bool {
        self.flags == 0
            && self.device_id != 0
            && self.firmware_snapshot_id != 0
            && unpack_pci_address(self.pci_address_packed).is_some()
    }
}

/// Arguments for [`crate::Syscall::DeviceLeaseMintResource`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceLeaseMintResourceArgs {
    /// Caller-owned `DeviceLease` handle with `WRITE` rights.
    pub lease: HandleValue,
    /// Resource kind tag (`IoPort`, `Mmio`, `Irq`, or `DmaPool`).
    pub kind: u32,
    /// Expected active lease generation (prevents ABA / stale mints).
    pub expected_generation: u64,
    /// Physical base / port / IRQ / DMA range start.
    pub base: u64,
    /// Range length in bytes or vectors (non-zero, no `u64` overflow).
    pub len: u64,
    /// Non-zero requests an exclusive resource range; zero requests shared.
    pub exclusive: u32,
    /// Reserved for future flags. Must be zero.
    pub reserved: u32,
}

impl DeviceLeaseMintResourceArgs {
    /// Validate structural fields and allowed per-device resource kinds.
    pub const fn validate(&self) -> bool {
        if self.reserved != 0 || self.expected_generation == 0 || self.len == 0 {
            return false;
        }
        if self.base.checked_add(self.len).is_none() {
            return false;
        }
        matches!(
            ResourceKindAbi::from_raw(self.kind),
            Some(
                ResourceKindAbi::IoPort
                    | ResourceKindAbi::Mmio
                    | ResourceKindAbi::Irq
                    | ResourceKindAbi::DmaPool
            )
        )
    }
}

/// Arguments for [`crate::Syscall::DeviceLeaseBindGonePort`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceLeaseBindPortArgs {
    /// Caller-owned `DeviceLease` handle with `READ` rights.
    pub lease: HandleValue,
    /// Caller-owned `Port` handle with `WRITE` rights.
    pub port: HandleValue,
    /// User-supplied key copied into the `PORT_PACKET_DEVICE_GONE` packet.
    pub key: u64,
    /// Reserved for future flags. Must be zero.
    pub flags: u32,
    /// Reserved padding word. Must be zero.
    pub reserved: u32,
}

impl DeviceLeaseBindPortArgs {
    /// Validate structural fields.
    pub const fn validate(&self) -> bool {
        self.flags == 0 && self.reserved == 0
    }
}

/// Snapshot returned by [`crate::Syscall::DeviceLeaseQuery`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceLeaseInfo {
    /// Stable device presence identity.
    pub device_id: u64,
    /// Current monotonic lease generation.
    pub generation: u64,
    /// Firmware snapshot identity bound at creation.
    pub firmware_snapshot_id: u64,
    /// Canonical packed PCI address.
    pub pci_address_packed: u64,
    /// Current [`DeviceLeaseStateAbi`] discriminant.
    pub state: u32,
    /// Non-zero when the lease has been revoked (`DeviceGone`).
    pub revoked: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_address_pack_unpack_roundtrip() {
        let packed = match pack_pci_address(0x0003, 0x12, 0x1f, 0x07) {
            Some(v) => v,
            None => {
                assert!(false, "valid PCI address must pack");
                return;
            }
        };
        assert_eq!(unpack_pci_address(packed), Some((0x0003, 0x12, 0x1f, 0x07)));
        assert_eq!(pack_pci_address(0, 0, 32, 0), None);
        assert_eq!(pack_pci_address(0, 0, 0, 8), None);
        assert_eq!(unpack_pci_address(1u64 << 32), None);
    }

    #[test]
    fn lease_args_layouts_match_kernel_user_record_expectations() {
        assert_eq!(core::mem::size_of::<DeviceLeaseCreateArgs>(), 32);
        assert_eq!(core::mem::size_of::<DeviceLeaseMintResourceArgs>(), 40);
        assert_eq!(core::mem::size_of::<DeviceLeaseBindPortArgs>(), 24);
        assert_eq!(core::mem::size_of::<DeviceLeaseInfo>(), 40);
    }

    #[test]
    fn lease_args_validation_rejects_zero_ids_and_non_device_kinds() {
        let valid_addr = pack_pci_address(0, 0, 1, 0).unwrap_or(0);
        let good = DeviceLeaseCreateArgs {
            authority: 9,
            flags: 0,
            device_id: 1,
            firmware_snapshot_id: 2,
            pci_address_packed: valid_addr,
        };
        assert!(good.validate());
        assert!(!DeviceLeaseCreateArgs {
            device_id: 0,
            ..good
        }
        .validate());
        assert!(!DeviceLeaseCreateArgs {
            firmware_snapshot_id: 0,
            ..good
        }
        .validate());
        assert!(!DeviceLeaseCreateArgs { flags: 1, ..good }.validate());

        let good_mint = DeviceLeaseMintResourceArgs {
            lease: 10,
            kind: ResourceKindAbi::Mmio as u32,
            expected_generation: 1,
            base: 0x8000_0000,
            len: 0x1000,
            exclusive: 1,
            reserved: 0,
        };
        assert!(good_mint.validate());
        assert!(!DeviceLeaseMintResourceArgs {
            kind: ResourceKindAbi::PowerControl as u32,
            ..good_mint
        }
        .validate());
        assert!(!DeviceLeaseMintResourceArgs {
            expected_generation: 0,
            ..good_mint
        }
        .validate());
        assert!(!DeviceLeaseMintResourceArgs {
            len: 0,
            ..good_mint
        }
        .validate());
    }
}
