//! Snapshot-bound PCI configuration capability mint (AP-8).
//!
//! The root userspace supervisor holds the unique `PciConfigMint`
//! [`Resource`](huesos_object::Resource) installed by the kernel at boot.
//! This module is the enforcement point for turning the firmware's
//! published config-window evidence into real capabilities.
//!
//! Design invariants, enforced here:
//!
//! * the mint never accepts a physical address from the caller — only a
//!   read-only `HMCF` VMO plus the identity fields the image itself carries;
//! * the kernel independently decodes the `HMCF` image and compares it
//!   against the window set it stashed from its own archive-v2 MCFG at
//!   boot (`install_config_authority`), never against anything the caller
//!   claims about the firmware;
//! * every claimed window must match exactly one stashed window (subset
//!   semantics) and must not overlap usable RAM;
//! * nothing is minted unless every check passes; on any failure the call
//!   is all-or-nothing (already-minted capabilities of this call are
//!   rolled back).
//!
//! `PciConfigMint` is not exposed through `sys_resource_create`, so no
//! other process can obtain mint authority; the kernel mints it exactly
//! once for the root supervisor at boot.

use crate::resource::require_resource_of_kind;
use crate::user_memory;
use crate::SyscallResult;

use huesos_abi::hmcf;
use huesos_abi::pci_config::{
    self, verify_hmcf_against_mcfg, EcamAllocation, MINT_KIND_ECAM_WINDOWS,
    MINT_KIND_LEGACY_CF8_CFC,
};
use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::{
    current_process, unregister_object, KernelObject, KernelObjectExt, Resource, ResourceError,
    ResourceKind, Rights,
};

/// Maximum ECAM windows retained from the boot-time MCFG decode.
/// Mirrors [`hmcf::MAX_RECORDS`].
pub const MAX_WINDOWS: usize = hmcf::MAX_RECORDS as usize;
/// Maximum usable-RAM regions retained from the boot memory map.
pub const MAX_RAM_REGIONS: usize = 128;

/// Boot-time config-window authority, installed once by the kernel from
/// its own archive-v2 build before any userspace process runs.
#[derive(Clone, Copy)]
pub struct ConfigAuthority {
    firmware_snapshot_id: u64,
    windows: [EcamAllocation; MAX_WINDOWS],
    window_count: usize,
    usable_ram: [(u64, u64); MAX_RAM_REGIONS],
    ram_count: usize,
}

const EMPTY_ALLOCATION: EcamAllocation = EcamAllocation {
    segment: 0,
    start_bus: 0,
    end_bus: 0,
    ecam_base: 0,
    span_bytes: 1 << 20,
};

impl ConfigAuthority {
    /// Construct the authority. `windows` and `usable_ram` are copied
    /// into fixed-capacity arrays; entries past capacity are dropped.
    pub fn new(
        firmware_snapshot_id: u64,
        windows: &[EcamAllocation],
        usable_ram: &[(u64, u64)],
    ) -> Self {
        let mut authority = Self {
            firmware_snapshot_id,
            windows: [EMPTY_ALLOCATION; MAX_WINDOWS],
            window_count: 0,
            usable_ram: [(0, 0); MAX_RAM_REGIONS],
            ram_count: 0,
        };
        for window in windows.iter().take(MAX_WINDOWS) {
            authority.windows[authority.window_count] = *window;
            authority.window_count += 1;
        }
        for region in usable_ram.iter().take(MAX_RAM_REGIONS) {
            authority.usable_ram[authority.ram_count] = *region;
            authority.ram_count += 1;
        }
        authority
    }

    fn windows(&self) -> &[EcamAllocation] {
        &self.windows[..self.window_count]
    }

    fn usable_ram(&self) -> &[(u64, u64)] {
        &self.usable_ram[..self.ram_count]
    }
}

static CONFIG_AUTHORITY: spin::Mutex<Option<ConfigAuthority>> = spin::Mutex::new(None);

/// Install the unique boot-time config authority. Called exactly once by
/// the kernel while building the initial process's environment; further
/// calls are rejected and change nothing. Returns whether this call
/// installed the authority.
pub fn install_config_authority(authority: ConfigAuthority) -> bool {
    let mut guard = CONFIG_AUTHORITY.lock();
    if guard.is_some() {
        return false;
    }
    *guard = Some(authority);
    true
}

/// `Syscall::PciConfigMint` handler.
///
/// `a1` is the `PciConfigMint` resource handle, `a2` a pointer to
/// [`pci_config::PciConfigMintRequest`], `a3` a `*mut HandleValue` output
/// array, and `a4` its capacity in handles. Returns the number of handles
/// written, or a negative error.
pub(crate) fn sys_pci_config_mint(
    authority_handle: HandleValue,
    request_ptr: *const pci_config::PciConfigMintRequest,
    out_handles: *mut HandleValue,
    capacity: u64,
) -> SyscallResult {
    let request = user_memory::read_value(request_ptr)?;
    request.validate().map_err(|_| ErrorCode::InvalidArgs)?;
    if capacity > hmcf::MAX_RECORDS as u64 {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_write_array(out_handles, capacity as usize)?;

    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    // The caller must present the unique `PciConfigMint` authority.
    let authority_object = require_resource_of_kind(authority_handle, ResourceKind::PciConfigMint)?;
    let _authority_resource = authority_object
        .downcast_ref::<Resource>()
        .ok_or(ErrorCode::WrongType)?;

    // Read the caller's read-only HMCF VMO and decode it independently.
    let vmo_handle = caller
        .handles
        .get(request.hmcf_vmo)
        .ok_or(ErrorCode::BadHandle)?;
    if !vmo_handle.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let vmo_object = huesos_object::lookup_object(vmo_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = vmo_object
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;

    let mut image = [0u8; hmcf::MAX_BYTES];
    let mut prefix = [0u8; hmcf::HEADER_BYTES];
    if vmo.read(0, &mut prefix) != hmcf::HEADER_BYTES {
        return Err(ErrorCode::InvalidArgs);
    }
    let total = hmcf::declared_size(&prefix).map_err(|_| ErrorCode::InvalidArgs)?;
    if vmo.size() != total {
        return Err(ErrorCode::InvalidArgs);
    }
    if vmo.read(0, &mut image[..total]) != total {
        return Err(ErrorCode::Internal);
    }
    let view = hmcf::decode(&image[..total]).map_err(|_| ErrorCode::InvalidArgs)?;
    view.check_binding(request.producer_generation, request.firmware_snapshot_id)
        .map_err(|_| ErrorCode::AccessDenied)?;

    // The kernel's independent view of the firmware: stash installed at
    // boot from the archive-v2 build. The critical section is bounded to
    // the checks; minting happens after it is dropped.
    let minted = {
        let guard = CONFIG_AUTHORITY.lock();
        let authority = guard.as_ref().ok_or(ErrorCode::NotSupported)?;
        if view.firmware_snapshot_id() != authority.firmware_snapshot_id {
            return Err(ErrorCode::AccessDenied);
        }
        verify_hmcf_against_mcfg(&view, authority.windows(), authority.usable_ram())
            .map_err(|_| ErrorCode::AccessDenied)?;

        let mut minted = [(0u64, 0u64); MAX_WINDOWS];
        let mut count = 0usize;
        match request.kind {
            MINT_KIND_ECAM_WINDOWS => {
                for record in view.records() {
                    minted[count] = (record.ecam_base, record.span_bytes);
                    count += 1;
                }
            }
            MINT_KIND_LEGACY_CF8_CFC => {
                let has_segment0 = view.records().any(|record| record.segment == 0);
                if !has_segment0 {
                    return Err(ErrorCode::NotFound);
                }
                minted[0] = (
                    pci_config::LEGACY_CF8_CFC_BASE,
                    pci_config::LEGACY_CF8_CFC_LEN,
                );
                count = 1;
            }
            _ => return Err(ErrorCode::InvalidArgs),
        }
        if capacity < count as u64 {
            return Err(ErrorCode::InvalidArgs);
        }
        (minted, count)
    };
    let (minted, count) = minted;

    // Phase A: create all resources before any handle is installed, so a
    // mid-way conflict rolls back a clean set.
    let mut created: [Option<alloc::sync::Arc<Resource>>; MAX_WINDOWS] =
        [const { None }; MAX_WINDOWS];
    for (index, (base, len)) in minted.iter().take(count).enumerate() {
        let kind = if request.kind == MINT_KIND_LEGACY_CF8_CFC {
            ResourceKind::IoPort
        } else {
            ResourceKind::Mmio
        };
        let result = Resource::try_create_exclusive(kind, *base, *len);
        let resource = match result {
            Ok(resource) => resource,
            Err(error) => {
                for slot in created.iter_mut().take(index) {
                    if let Some(resource) = slot.take() {
                        unregister_object(resource.koid());
                    }
                }
                return Err(match error {
                    ResourceError::InvalidRange => ErrorCode::InvalidArgs,
                    ResourceError::Conflict => ErrorCode::Busy,
                });
            }
        };
        created[index] = Some(resource);
    }

    // ECAM capabilities are read-only on purpose: they grant the right to
    // observe configuration space, never to write it. The legacy
    // CF8/CFC window carries READ|WRITE because configuration mechanism
    // #1 requires writing the address port even for a read; write
    // policy for AML config cycles is enforced one layer up (AP-10).
    let rights = if request.kind == MINT_KIND_LEGACY_CF8_CFC {
        Rights::READ | Rights::WRITE | Rights::TRANSFER
    } else {
        Rights::READ | Rights::TRANSFER
    };

    // Phase B: install handles into the caller's table. On any failure
    // the handles installed by this call are removed again (the koids
    // then collect) and every resource minted by this call is
    // unregistered.
    let mut installed = [0u32; MAX_WINDOWS];
    for index in 0..count {
        let Some(resource) = created[index].take() else {
            return Err(ErrorCode::Internal);
        };
        let koid = resource.koid();
        let inserted = caller
            .handles
            .add_with_commit(huesos_object::Handle::new(koid, rights), |handle_value| {
                user_memory::write_value(out_handles.wrapping_add(index), &handle_value)
            });
        match inserted {
            Ok((handle_value, _)) => installed[index] = handle_value,
            Err(write_error) => {
                for value in installed.iter().take(index) {
                    let _ = caller.handles.remove(*value);
                }
                unregister_object(koid);
                for slot in created.iter_mut().take(count) {
                    if let Some(resource) = slot.take() {
                        unregister_object(resource.koid());
                    }
                }
                return Err(write_error);
            }
        }
    }
    Ok(count as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation(base: u64) -> EcamAllocation {
        EcamAllocation {
            segment: 0,
            start_bus: 0,
            end_bus: 255,
            ecam_base: base,
            span_bytes: (256 - 0) * 1 << 20,
        }
    }

    #[test]
    fn authority_retains_bounded_windows_and_ram() {
        let mut windows = [allocation(0xE000_0000); MAX_WINDOWS + 5];
        for (index, window) in windows.iter_mut().enumerate() {
            window.ecam_base = 0xE000_0000 + index as u64 * (1 << 28);
        }
        let mut ram = [(0u64, 0u64); MAX_RAM_REGIONS + 5];
        for (index, region) in ram.iter_mut().enumerate() {
            *region = (0x1000_0000 + index as u64 * (1 << 24), 1 << 20);
        }
        let authority = ConfigAuthority::new(7, &windows, &ram);
        assert_eq!(authority.windows().len(), MAX_WINDOWS);
        assert_eq!(authority.usable_ram().len(), MAX_RAM_REGIONS);
        assert_eq!(
            authority.windows()[MAX_WINDOWS - 1].ecam_base,
            0xE000_0000 + (MAX_WINDOWS - 1) as u64 * (1 << 28)
        );
    }

    #[test]
    fn install_config_authority_is_one_shot() {
        // Only this test installs the global authority; the second
        // call must observe the existing install and refuse to
        // replace it.
        let authority = ConfigAuthority::new(42, &[allocation(0xE000_0000)], &[]);
        let first = install_config_authority(authority);
        let second = install_config_authority(ConfigAuthority::new(43, &[], &[]));
        assert!(first);
        assert!(!second);
        let guard = CONFIG_AUTHORITY.lock();
        let installed = match guard.as_ref() {
            Some(installed) => installed,
            None => return,
        };
        assert_eq!(installed.firmware_snapshot_id, 42);
        assert_eq!(installed.windows().len(), 1);
    }
}
