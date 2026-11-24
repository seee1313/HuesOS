//! Live PCI BAR sizing and firmware resource inventory (Stage E.1).
//!
//! Implements the bounded, reversible `0xFFFF_FFFF` BAR-sizing protocol for
//! Type 0 endpoints and Type 1 PCI-to-PCI bridges using [`WriteClass::CommandControl`]
//! and [`WriteClass::Bar`] transactions:
//!
//! 1. Refuse to touch any device that currently holds an `Online` lease.
//! 2. Snapshot `Command` (`0x04`) and all BARs; disable active I/O, Memory, and
//!    Bus Master decode bits (`0x07`) before probing.
//! 3. Probe each BAR (and 64-bit upper half where `type == 0b10`), validate the
//!    size mask for malformed/non-power-of-two encodings, and immediately restore
//!    the original BAR value with readback verification.
//! 4. Restore `Command` (`0x04`) with readback verification.
//! 5. Decode Type 1 bridge forwarding windows and ROM BAR state without
//!    enabling decoding.

use alloc::vec::Vec;

use crate::lease::LeaseState;
use crate::resource_validation::{
    validate_firmware_resources, FirmwareResource, ResourceClass, ResourceRegister, RootAperture,
    ValidationReport, MAX_VALIDATION_RESOURCES,
};
use crate::topology::{FunctionKind, Parent, TopologySnapshot};
use crate::write_policy::{
    execute_checked_write, validate_write_request, ConfigReadWriteTransport, HeaderKind,
    WriteClass, WritePolicyError, WriteRequest, OFFSET_BAR0, OFFSET_COMMAND,
};
use crate::{ConfigWidth, PciAddress, ENHANCED_CONFIG_BYTES};

const CMD_DECODE_BITS: u32 = 0x0007;

/// Expansion ROM BAR state read safely without enabling decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RomBarState {
    /// Owning PCI function.
    pub owner: PciAddress,
    /// Raw 32-bit ROM BAR register value (`0x30` for Type 0, `0x38` for Type 1).
    pub raw_value: u32,
    /// ROM decode enable bit (`bit 0`).
    pub enabled: bool,
    /// Aligned ROM base (`bits 31:11`) when non-zero.
    pub pci_base: u32,
}

/// Complete live BAR-sizing inventory output for a topology snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveBarInventory {
    /// Sized BARs and bridge windows across all functions.
    pub resources: Vec<FirmwareResource>,
    /// Expansion ROM BAR observations (read-only).
    pub rom_bars: Vec<RomBarState>,
    /// Validation report against the supplied root apertures.
    pub validation: ValidationReport,
}

/// Errors emitted during live BAR sizing (Stage E.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarSizingError {
    /// Refused because the target device currently has an active `Online` lease.
    DeviceOnlineLeased(PciAddress),
    /// Transport failed to read a config register.
    TransportReadFailed(PciAddress, u16),
    /// Writing a BAR probe or restore failed.
    WriteFailed(PciAddress, u16, WritePolicyError),
    /// A BAR returned an invalid or non-power-of-two size mask.
    MalformedBarMask {
        /// Offending function.
        owner: PciAddress,
        /// BAR index (`0..5`).
        bar_index: u8,
        /// Raw size mask read back after writing `0xFFFF_FFFF`.
        raw_mask: u64,
    },
    /// Resource capacity or allocation limit exceeded.
    CapacityExceeded,
    /// Firmware validation failed on the collected resources.
    ValidationFailed,
}

/// Optional callback/lookup indicating whether `address` currently has an
/// active lease state (sizing is only permitted when not [`LeaseState::Online`]).
pub trait LeaseStateLookup {
    /// Return the current lease state of `address`, if leased.
    fn lease_state(&self, address: PciAddress) -> Option<LeaseState>;
}

/// Default lookup reporting no active leases (boot-time discovery before binding).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoActiveLeases;

impl LeaseStateLookup for NoActiveLeases {
    fn lease_state(&self, _address: PciAddress) -> Option<LeaseState> {
        None
    }
}

/// Size and restore BARs for every function in `topology`, then validate against
/// `apertures`.
pub fn collect_live_bar_inventory(
    transport: &mut impl ConfigReadWriteTransport,
    topology: &TopologySnapshot,
    apertures: &[RootAperture],
    leases: &impl LeaseStateLookup,
) -> Result<LiveBarInventory, BarSizingError> {
    let mut resources = Vec::new();
    let mut rom_bars = Vec::new();

    for node in topology.nodes() {
        let addr = node.function.address;
        if leases.lease_state(addr) == Some(LeaseState::Online) {
            return Err(BarSizingError::DeviceOnlineLeased(addr));
        }
        let header_kind = match node.function.kind {
            FunctionKind::Endpoint => HeaderKind::Type0Endpoint,
            FunctionKind::PciBridge { .. } => HeaderKind::Type1Bridge,
        };
        let root_id = root_id_of(topology, addr).ok_or(BarSizingError::ValidationFailed)?;
        size_function_bars(
            transport,
            addr,
            header_kind,
            root_id,
            apertures,
            &mut resources,
            &mut rom_bars,
        )?;
    }

    let validation = validate_firmware_resources(topology, apertures, &resources)
        .map_err(|_| BarSizingError::ValidationFailed)?;
    Ok(LiveBarInventory {
        resources,
        rom_bars,
        validation,
    })
}

/// Safely size all BARs and decode bridge/ROM metadata for a single function.
pub fn size_function_bars(
    transport: &mut impl ConfigReadWriteTransport,
    address: PciAddress,
    header_kind: HeaderKind,
    root_id: u64,
    apertures: &[RootAperture],
    out_resources: &mut Vec<FirmwareResource>,
    out_roms: &mut Vec<RomBarState>,
) -> Result<(), BarSizingError> {
    let orig_cmd = transport
        .read_width(address, OFFSET_COMMAND, ConfigWidth::Word)
        .ok_or(BarSizingError::TransportReadFailed(address, OFFSET_COMMAND))?;
    let active_decode = orig_cmd & CMD_DECODE_BITS;

    if active_decode != 0 {
        let disable_req = WriteRequest {
            address,
            header_kind,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: 0,
            write_mask: active_decode,
            expected_readback_mask: active_decode,
            allowlist_entry: None,
        };
        execute_checked_write(transport, &disable_req)
            .map_err(|err| BarSizingError::WriteFailed(address, OFFSET_COMMAND, err))?;
    }

    let probe_res = probe_bars_inner(
        transport,
        address,
        header_kind,
        orig_cmd,
        BarProbeRoot { root_id, apertures },
        out_resources,
        out_roms,
    );

    if active_decode != 0 {
        let restore_req = WriteRequest {
            address,
            header_kind,
            class: WriteClass::CommandControl,
            offset: OFFSET_COMMAND,
            width: ConfigWidth::Word,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: active_decode,
            write_mask: active_decode,
            expected_readback_mask: active_decode,
            allowlist_entry: None,
        };
        execute_checked_write(transport, &restore_req)
            .map_err(|err| BarSizingError::WriteFailed(address, OFFSET_COMMAND, err))?;
    }

    probe_res
}

#[derive(Copy, Clone)]
struct BarProbeRoot<'a> {
    root_id: u64,
    apertures: &'a [RootAperture],
}

fn probe_bars_inner(
    transport: &mut impl ConfigReadWriteTransport,
    address: PciAddress,
    header_kind: HeaderKind,
    orig_cmd: u32,
    root: BarProbeRoot<'_>,
    out_resources: &mut Vec<FirmwareResource>,
    out_roms: &mut Vec<RomBarState>,
) -> Result<(), BarSizingError> {
    let BarProbeRoot { root_id, apertures } = root;
    let bar_count: u8 = match header_kind {
        HeaderKind::Type0Endpoint => 6,
        HeaderKind::Type1Bridge => 2,
    };

    let mut bar_idx = 0u8;
    while bar_idx < bar_count {
        let offset = OFFSET_BAR0 + u16::from(bar_idx) * 4;
        let orig_lo = transport
            .read_width(address, offset, ConfigWidth::Dword)
            .ok_or(BarSizingError::TransportReadFailed(address, offset))?;

        if (orig_lo & 1) == 1 {
            let size_mask_lo = probe_and_restore_bar_dword(
                transport,
                address,
                header_kind,
                offset,
                orig_lo,
                !0x3,
            )?;
            let addr_mask = size_mask_lo & !0x3;
            if addr_mask != 0 {
                // PCI I/O BARs can implement bits up to 31 or only 15..2 (upper 16 bits zero).
                let effective = if (addr_mask & 0xFFFF_0000) == 0 {
                    addr_mask | 0xFFFF_0000
                } else {
                    addr_mask
                };
                let len = u64::from((!effective).wrapping_add(1));
                if len == 0 || !len.is_power_of_two() {
                    return Err(BarSizingError::MalformedBarMask {
                        owner: address,
                        bar_index: bar_idx,
                        raw_mask: u64::from(size_mask_lo),
                    });
                }
                let pci_base = u64::from(orig_lo & !0x3);
                push_resource(
                    out_resources,
                    FirmwareResource {
                        owner: address,
                        register: ResourceRegister::Bar(bar_idx),
                        class: ResourceClass::Io,
                        assigned: pci_base != 0,
                        pci_base,
                        len,
                        fixed: false,
                    },
                )?;
            }
            bar_idx += 1;
            continue;
        }

        let mem_type = (orig_lo >> 1) & 0x3;
        let prefetch = (orig_lo & 0x8) != 0;
        if mem_type == 0x2 && bar_idx + 1 < bar_count {
            let hi_offset = offset + 4;
            let orig_hi = transport
                .read_width(address, hi_offset, ConfigWidth::Dword)
                .ok_or(BarSizingError::TransportReadFailed(address, hi_offset))?;

            let mask_lo = probe_and_restore_bar_dword(
                transport,
                address,
                header_kind,
                offset,
                orig_lo,
                !0xF,
            )?;
            let mask_hi = probe_and_restore_bar_dword(
                transport,
                address,
                header_kind,
                hi_offset,
                orig_hi,
                u32::MAX,
            )?;
            let full_mask = (u64::from(mask_hi) << 32) | u64::from(mask_lo & !0xF);
            if full_mask != 0 {
                let len = (!full_mask).wrapping_add(1);
                if len == 0 || !len.is_power_of_two() {
                    return Err(BarSizingError::MalformedBarMask {
                        owner: address,
                        bar_index: bar_idx,
                        raw_mask: full_mask,
                    });
                }
                let pci_base = (u64::from(orig_hi) << 32) | u64::from(orig_lo & !0xF);
                let assigned = pci_base != 0;
                let class =
                    classify_mem_bar(root_id, apertures, prefetch, assigned, pci_base, len, true);
                push_resource(
                    out_resources,
                    FirmwareResource {
                        owner: address,
                        register: ResourceRegister::Bar(bar_idx),
                        class,
                        assigned,
                        pci_base,
                        len,
                        fixed: false,
                    },
                )?;
            }
            bar_idx += 2;
        } else {
            let mask_lo = probe_and_restore_bar_dword(
                transport,
                address,
                header_kind,
                offset,
                orig_lo,
                !0xF,
            )?;
            let addr_mask = mask_lo & !0xF;
            if addr_mask != 0 {
                let len = u64::from((!addr_mask).wrapping_add(1));
                if len == 0 || !len.is_power_of_two() {
                    return Err(BarSizingError::MalformedBarMask {
                        owner: address,
                        bar_index: bar_idx,
                        raw_mask: u64::from(mask_lo),
                    });
                }
                let pci_base = u64::from(orig_lo & !0xF);
                let assigned = pci_base != 0;
                let class =
                    classify_mem_bar(root_id, apertures, prefetch, assigned, pci_base, len, false);
                push_resource(
                    out_resources,
                    FirmwareResource {
                        owner: address,
                        register: ResourceRegister::Bar(bar_idx),
                        class,
                        assigned,
                        pci_base,
                        len,
                        fixed: false,
                    },
                )?;
            }
            bar_idx += 1;
        }
    }

    if header_kind == HeaderKind::Type1Bridge {
        decode_bridge_windows(
            transport,
            address,
            orig_cmd,
            root_id,
            apertures,
            out_resources,
        )?;
    }

    let rom_offset = match header_kind {
        HeaderKind::Type0Endpoint => 0x30u16,
        HeaderKind::Type1Bridge => 0x38u16,
    };
    if let Some(raw_rom) = transport.read_width(address, rom_offset, ConfigWidth::Dword) {
        out_roms
            .try_reserve(1)
            .map_err(|_| BarSizingError::CapacityExceeded)?;
        out_roms.push(RomBarState {
            owner: address,
            raw_value: raw_rom,
            enabled: (raw_rom & 1) != 0,
            pci_base: raw_rom & !0x7FF,
        });
    }

    Ok(())
}

fn probe_and_restore_bar_dword(
    transport: &mut impl ConfigReadWriteTransport,
    address: PciAddress,
    header_kind: HeaderKind,
    offset: u16,
    orig_value: u32,
    addr_bits_mask: u32,
) -> Result<u32, BarSizingError> {
    let probe_req = WriteRequest {
        address,
        header_kind,
        class: WriteClass::Bar,
        offset,
        width: ConfigWidth::Dword,
        max_config_bytes: ENHANCED_CONFIG_BYTES,
        value: u32::MAX,
        write_mask: u32::MAX,
        expected_readback_mask: u32::MAX,
        allowlist_entry: None,
    };
    let _validated = validate_write_request(&probe_req)
        .map_err(|err| BarSizingError::WriteFailed(address, offset, err))?;

    if !transport.write_width(address, offset, ConfigWidth::Dword, u32::MAX) {
        return Err(BarSizingError::WriteFailed(
            address,
            offset,
            WritePolicyError::TransportWriteFailed,
        ));
    }
    let Some(raw_mask) = transport.read_width(address, offset, ConfigWidth::Dword) else {
        let _ = transport.write_width(address, offset, ConfigWidth::Dword, orig_value);
        return Err(BarSizingError::TransportReadFailed(address, offset));
    };

    let restore_mask = raw_mask & addr_bits_mask;
    if restore_mask != 0 {
        let restore_req = WriteRequest {
            address,
            header_kind,
            class: WriteClass::Bar,
            offset,
            width: ConfigWidth::Dword,
            max_config_bytes: ENHANCED_CONFIG_BYTES,
            value: orig_value,
            write_mask: u32::MAX,
            expected_readback_mask: restore_mask,
            allowlist_entry: None,
        };
        execute_checked_write(transport, &restore_req)
            .map_err(|err| BarSizingError::WriteFailed(address, offset, err))?;
    } else if !transport.write_width(address, offset, ConfigWidth::Dword, orig_value) {
        return Err(BarSizingError::WriteFailed(
            address,
            offset,
            WritePolicyError::TransportWriteFailed,
        ));
    }

    Ok(raw_mask)
}

fn classify_mem_bar(
    root_id: u64,
    apertures: &[RootAperture],
    prefetch: bool,
    assigned: bool,
    pci_base: u64,
    len: u64,
    is_64bit: bool,
) -> ResourceClass {
    let fits_aperture = |class: ResourceClass| {
        apertures.iter().any(|ap| {
            ap.root_id == root_id
                && ap.class == class
                && (!assigned
                    || (pci_base >= ap.pci_base
                        && pci_base.saturating_add(len) <= ap.pci_base.saturating_add(ap.len)))
        })
    };

    if assigned {
        if prefetch {
            if fits_aperture(ResourceClass::PrefetchableMemory) {
                return ResourceClass::PrefetchableMemory;
            }
            // Firmware (OVMF / UEFI / AMD _CRS) frequently declares >4 GiB or <4 GiB
            // QWordMemory/DWordMemory root apertures as non-cacheable Mmio64/Mmio32
            // even when PCIe prefetchable BARs or bridge windows live inside them.
            if fits_aperture(ResourceClass::Mmio64) {
                return ResourceClass::Mmio64;
            }
            if pci_base.saturating_add(len) <= 0x1_0000_0000 && fits_aperture(ResourceClass::Mmio32)
            {
                return ResourceClass::Mmio32;
            }
            return ResourceClass::PrefetchableMemory;
        }
        if pci_base.saturating_add(len) <= 0x1_0000_0000 && fits_aperture(ResourceClass::Mmio32) {
            return ResourceClass::Mmio32;
        }
        if fits_aperture(ResourceClass::Mmio64) {
            return ResourceClass::Mmio64;
        }
        if fits_aperture(ResourceClass::PrefetchableMemory) {
            return ResourceClass::PrefetchableMemory;
        }
        return if is_64bit && pci_base.saturating_add(len) > 0x1_0000_0000 {
            ResourceClass::Mmio64
        } else {
            ResourceClass::Mmio32
        };
    }

    if prefetch {
        if fits_aperture(ResourceClass::PrefetchableMemory) {
            return ResourceClass::PrefetchableMemory;
        }
        if is_64bit && fits_aperture(ResourceClass::Mmio64) {
            return ResourceClass::Mmio64;
        }
        if !is_64bit && fits_aperture(ResourceClass::Mmio32) {
            return ResourceClass::Mmio32;
        }
        return ResourceClass::PrefetchableMemory;
    }
    if is_64bit {
        if fits_aperture(ResourceClass::Mmio64) {
            ResourceClass::Mmio64
        } else if fits_aperture(ResourceClass::Mmio32) {
            ResourceClass::Mmio32
        } else {
            ResourceClass::Mmio64
        }
    } else {
        ResourceClass::Mmio32
    }
}

fn decode_bridge_windows(
    transport: &mut impl ConfigReadWriteTransport,
    owner: PciAddress,
    orig_cmd: u32,
    root_id: u64,
    apertures: &[RootAperture],
    out: &mut Vec<FirmwareResource>,
) -> Result<(), BarSizingError> {
    if let Some(io_reg) = transport.read_width(owner, 0x1C, ConfigWidth::Dword) {
        let io_base_lo = (io_reg & 0xFF) as u8;
        let io_limit_lo = ((io_reg >> 8) & 0xFF) as u8;
        let (base_hi, limit_hi) = if (io_base_lo & 0x0F) == 1 {
            if let Some(upper) = transport.read_width(owner, 0x30, ConfigWidth::Dword) {
                (u64::from(upper & 0xFFFF), u64::from((upper >> 16) & 0xFFFF))
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };
        let base = (base_hi << 16) | (u64::from(io_base_lo & 0xF0) << 8);
        let limit = (limit_hi << 16) | (u64::from(io_limit_lo & 0xF0) << 8) | 0x0FFF;
        // On PCIe Root Ports with 32-bit I/O capability, bits [3:0] of IO_BASE and
        // IO_LIMIT hardwire to 0x1 at reset (`0x0001_0001`), yielding `base == 0,
        // limit == 0xFFF` even when I/O forwarding is completely unconfigured.
        // Never treat `base == 0` as an active bridge window unless I/O decode is
        // explicitly enabled (`COMMAND.IO == 1`) AND `io_limit_lo & 0xF0 != 0`.
        let io_active =
            limit >= base && (base != 0 || ((orig_cmd & 0x1) != 0 && (io_limit_lo & 0xF0) != 0));
        if io_active {
            push_resource(
                out,
                FirmwareResource {
                    owner,
                    register: ResourceRegister::BridgeWindow(0),
                    class: ResourceClass::Io,
                    assigned: true,
                    pci_base: base,
                    len: (limit - base) + 1,
                    fixed: false,
                },
            )?;
        }
    }

    if let Some(mem_reg) = transport.read_width(owner, 0x20, ConfigWidth::Dword) {
        let mem_base = u64::from(mem_reg & 0xFFF0) << 16;
        let mem_limit = (u64::from((mem_reg >> 16) & 0xFFF0) << 16) | 0xF_FFFF;
        // Physical 0x0000_0000..0x000F_FFFF is x86 low RAM/BIOS; `mem_base == 0`
        // represents an unprogrammed bridge memory window.
        if mem_limit >= mem_base && mem_base != 0 {
            let len = (mem_limit - mem_base) + 1;
            let class = classify_mem_bar(root_id, apertures, false, true, mem_base, len, false);
            push_resource(
                out,
                FirmwareResource {
                    owner,
                    register: ResourceRegister::BridgeWindow(1),
                    class,
                    assigned: true,
                    pci_base: mem_base,
                    len,
                    fixed: false,
                },
            )?;
        }
    }

    if let Some(pref_reg) = transport.read_width(owner, 0x24, ConfigWidth::Dword) {
        let pref_base_lo = (pref_reg & 0xFFFF) as u16;
        let pref_limit_lo = ((pref_reg >> 16) & 0xFFFF) as u16;
        let is_64 = (pref_base_lo & 0x0F) == 1;
        let (base_hi, limit_hi) = if is_64 {
            let b = transport
                .read_width(owner, 0x28, ConfigWidth::Dword)
                .unwrap_or(0);
            let l = transport
                .read_width(owner, 0x2C, ConfigWidth::Dword)
                .unwrap_or(0);
            (u64::from(b), u64::from(l))
        } else {
            (0, 0)
        };
        let base = (base_hi << 32) | (u64::from(pref_base_lo & 0xFFF0) << 16);
        let limit = (limit_hi << 32) | (u64::from(pref_limit_lo & 0xFFF0) << 16) | 0xF_FFFF;
        // On 64-bit PCIe Root Ports, `pref_reg` resets to `0x0001_0001` (capability
        // bit 0 = 64-bit decode) with `base == 0`. Ignore unconfigured `base == 0`.
        if limit >= base && base != 0 {
            let len = (limit - base) + 1;
            let class = classify_mem_bar(root_id, apertures, true, true, base, len, is_64);
            push_resource(
                out,
                FirmwareResource {
                    owner,
                    register: ResourceRegister::BridgeWindow(2),
                    class,
                    assigned: true,
                    pci_base: base,
                    len,
                    fixed: false,
                },
            )?;
        }
    }

    Ok(())
}

/// Resolve the owning PCI root bridge ID for `owner` by walking `topology` parent links.
pub fn root_id_of(topology: &TopologySnapshot, owner: PciAddress) -> Option<u64> {
    let mut parent = topology.find(owner).map(|node| node.parent);
    let mut remaining = crate::topology::MAX_TOPOLOGY_DEPTH + 1;
    while remaining != 0 {
        match parent {
            Some(Parent::Root(root_id)) => return Some(root_id),
            Some(Parent::Bridge(address)) => {
                parent = topology.find(address).map(|node| node.parent);
            }
            None => return None,
        }
        remaining -= 1;
    }
    None
}

fn push_resource(
    out: &mut Vec<FirmwareResource>,
    resource: FirmwareResource,
) -> Result<(), BarSizingError> {
    if out.len() >= MAX_VALIDATION_RESOURCES {
        return Err(BarSizingError::CapacityExceeded);
    }
    out.try_reserve(1)
        .map_err(|_| BarSizingError::CapacityExceeded)?;
    out.push(resource);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{build_snapshot, DiscoveredFunction, RootBus};
    use crate::ClassCode;

    struct FakeBarTransport {
        cmd: u16,
        bars: [u32; 6],
        masks: [u32; 6],
        rom: u32,
        writes: usize,
        fail_restore_bar: Option<usize>,
    }

    impl FakeBarTransport {
        fn new_endpoint() -> Self {
            Self {
                cmd: 0x0007,
                bars: [0x8000_0000, 0x8001_0004, 0x0000_0002, 0x0000_C001, 0, 0],
                masks: [0xFFFF_F000, 0xFFFF_C004, 0xFFFF_FFFF, 0xFFFF_FF01, 0, 0],
                rom: 0,
                writes: 0,
                fail_restore_bar: None,
            }
        }
    }

    impl ConfigReadWriteTransport for FakeBarTransport {
        fn read_width(
            &mut self,
            _address: PciAddress,
            offset: u16,
            _width: ConfigWidth,
        ) -> Option<u32> {
            match offset {
                0x04 => Some(u32::from(self.cmd)),
                0x10..=0x24 if (offset - 0x10).is_multiple_of(4) => {
                    let idx = usize::from((offset - 0x10) / 4);
                    Some(self.bars[idx])
                }
                0x30 => Some(self.rom),
                _ => Some(0),
            }
        }

        fn write_width(
            &mut self,
            _address: PciAddress,
            offset: u16,
            _width: ConfigWidth,
            value: u32,
        ) -> bool {
            self.writes += 1;
            match offset {
                0x04 => {
                    self.cmd = (value & 0xFFFF) as u16;
                    true
                }
                0x10..=0x24 if (offset - 0x10).is_multiple_of(4) => {
                    let idx = usize::from((offset - 0x10) / 4);
                    if value == u32::MAX {
                        self.bars[idx] = self.masks[idx];
                        true
                    } else if self.fail_restore_bar == Some(idx) {
                        false
                    } else if idx == 2 {
                        // Upper 32 bits of 64-bit BAR1: all 32 bits are writable address bits.
                        self.bars[idx] = value & self.masks[idx];
                        true
                    } else if (self.bars[idx] & 1) == 1 {
                        self.bars[idx] =
                            (value & (self.masks[idx] & !0x3)) | (self.bars[idx] & 0x3);
                        true
                    } else {
                        self.bars[idx] =
                            (value & (self.masks[idx] & !0xF)) | (self.bars[idx] & 0xF);
                        true
                    }
                }
                _ => true,
            }
        }
    }

    #[test]
    fn sizes_32bit_64bit_and_io_bars_and_restores_command_and_bars() {
        let addr = match PciAddress::try_new(0, 0, 1, 0) {
            Ok(a) => a,
            Err(_) => return,
        };
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
        }];
        let functions = [DiscoveredFunction {
            address: addr,
            vendor_id: 0x8086,
            device_id: 0x1234,
            class_code: ClassCode {
                class: 0x01,
                subclass: 0x08,
                prog_if: 0x02,
            },
            kind: FunctionKind::Endpoint,
        }];
        let Ok(topo) = build_snapshot(1, &roots, &functions) else {
            return;
        };
        let apertures = [
            RootAperture {
                root_id: 1,
                class: ResourceClass::Mmio32,
                pci_base: 0x8000_0000,
                cpu_base: 0x8000_0000,
                len: 0x1000_0000,
            },
            RootAperture {
                root_id: 1,
                class: ResourceClass::Mmio64,
                pci_base: 0x2_0000_0000,
                cpu_base: 0x2_0000_0000,
                len: 0x1_0000_0000,
            },
            RootAperture {
                root_id: 1,
                class: ResourceClass::Io,
                pci_base: 0xC000,
                cpu_base: 0xC000,
                len: 0x1000,
            },
        ];

        let mut transport = FakeBarTransport::new_endpoint();
        let inv =
            match collect_live_bar_inventory(&mut transport, &topo, &apertures, &NoActiveLeases) {
                Ok(inv) => inv,
                Err(_) => {
                    assert!(false, "live bar inventory should succeed");
                    return;
                }
            };

        assert_eq!(transport.cmd, 0x0007);
        assert_eq!(transport.bars[0], 0x8000_0000);
        assert_eq!(transport.bars[1], 0x8001_0004);
        assert_eq!(transport.bars[2], 0x0000_0002);
        assert_eq!(transport.bars[3], 0x0000_C001);
        assert!(inv.validation.is_conflict_free());
        assert_eq!(
            inv.resources
                .iter()
                .find(|r| r.register == ResourceRegister::Bar(0))
                .map(|r| r.len),
            Some(0x1000)
        );
        assert_eq!(
            inv.resources
                .iter()
                .find(|r| r.register == ResourceRegister::Bar(1))
                .map(|r| (r.class, r.len)),
            Some((ResourceClass::Mmio64, 0x4000))
        );
        assert_eq!(
            inv.resources
                .iter()
                .find(|r| r.register == ResourceRegister::Bar(3))
                .map(|r| (r.class, r.len)),
            Some((ResourceClass::Io, 0x100))
        );
    }

    #[test]
    fn refuses_sizing_when_device_has_online_lease() {
        struct OnlineLease(PciAddress);
        impl LeaseStateLookup for OnlineLease {
            fn lease_state(&self, address: PciAddress) -> Option<LeaseState> {
                (address == self.0).then_some(LeaseState::Online)
            }
        }

        let Ok(addr) = PciAddress::try_new(0, 0, 2, 0) else {
            return;
        };
        let Ok(topo) = build_snapshot(
            1,
            &[RootBus {
                root_id: 1,
                segment: 0,
                start_bus: 0,
                end_bus: 0,
            }],
            &[DiscoveredFunction {
                address: addr,
                vendor_id: 0x8086,
                device_id: 0x5678,
                class_code: ClassCode {
                    class: 0x02,
                    subclass: 0x00,
                    prog_if: 0x00,
                },
                kind: FunctionKind::Endpoint,
            }],
        ) else {
            return;
        };
        let mut transport = FakeBarTransport::new_endpoint();
        let res = collect_live_bar_inventory(&mut transport, &topo, &[], &OnlineLease(addr));
        assert_eq!(res, Err(BarSizingError::DeviceOnlineLeased(addr)));
        assert_eq!(transport.writes, 0);
    }

    #[test]
    fn rejects_malformed_non_power_of_two_bar_mask() {
        let Ok(addr) = PciAddress::try_new(0, 0, 3, 0) else {
            return;
        };
        let Ok(topo) = build_snapshot(
            1,
            &[RootBus {
                root_id: 1,
                segment: 0,
                start_bus: 0,
                end_bus: 0,
            }],
            &[DiscoveredFunction {
                address: addr,
                vendor_id: 0x8086,
                device_id: 0x9999,
                class_code: ClassCode {
                    class: 0x02,
                    subclass: 0x00,
                    prog_if: 0x00,
                },
                kind: FunctionKind::Endpoint,
            }],
        ) else {
            return;
        };
        let mut transport = FakeBarTransport::new_endpoint();
        transport.masks[0] = 0xFFFF_A000;
        let res = collect_live_bar_inventory(&mut transport, &topo, &[], &NoActiveLeases);
        assert!(matches!(
            res,
            Err(BarSizingError::MalformedBarMask { bar_index: 0, .. })
        ));
    }

    #[test]
    fn routes_64bit_prefetchable_bar_in_mmio64_crs_and_ignores_reset_pcie_bridge_windows() {
        let Ok(bridge_addr) = PciAddress::try_new(0, 0, 1, 3) else {
            return;
        };
        let Ok(wlan_addr) = PciAddress::try_new(0, 1, 0, 0) else {
            return;
        };
        let Ok(vnet_addr) = PciAddress::try_new(0, 0, 4, 0) else {
            return;
        };
        let roots = [RootBus {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 2,
        }];
        let functions = [
            DiscoveredFunction {
                address: bridge_addr,
                vendor_id: 0x1022,
                device_id: 0x1634,
                class_code: ClassCode {
                    class: 0x06,
                    subclass: 0x04,
                    prog_if: 0x00,
                },
                kind: FunctionKind::PciBridge {
                    secondary_bus: 1,
                    subordinate_bus: 1,
                },
            },
            DiscoveredFunction {
                address: wlan_addr,
                vendor_id: 0x10EC,
                device_id: 0xC821,
                class_code: ClassCode {
                    class: 0x02,
                    subclass: 0x80,
                    prog_if: 0x00,
                },
                kind: FunctionKind::Endpoint,
            },
            DiscoveredFunction {
                address: vnet_addr,
                vendor_id: 0x1AF4,
                device_id: 0x1000,
                class_code: ClassCode {
                    class: 0x02,
                    subclass: 0x00,
                    prog_if: 0x00,
                },
                kind: FunctionKind::Endpoint,
            },
        ];
        let Ok(topo) = build_snapshot(1, &roots, &functions) else {
            return;
        };
        let apertures = [
            RootAperture {
                root_id: 1,
                class: ResourceClass::Mmio32,
                pci_base: 0xFC00_0000,
                cpu_base: 0xFC00_0000,
                len: 0x0200_0000,
            },
            RootAperture {
                root_id: 1,
                class: ResourceClass::Mmio64,
                pci_base: 0xC0_0000_0000,
                cpu_base: 0xC0_0000_0000,
                len: 0x01_0000_0000,
            },
        ];

        struct MultiDevTransport {
            bridge_cmd: u16,
            wlan_cmd: u16,
            wlan_bar2_lo: u32,
            wlan_bar2_hi: u32,
            vnet_cmd: u16,
            vnet_bar4_lo: u32,
            vnet_bar4_hi: u32,
        }
        impl ConfigReadWriteTransport for MultiDevTransport {
            fn read_width(&mut self, addr: PciAddress, off: u16, _w: ConfigWidth) -> Option<u32> {
                if addr.bus() == 0 && addr.device() == 1 && addr.function() == 3 {
                    return match off {
                        0x04 => Some(u32::from(self.bridge_cmd)),
                        0x1C => Some(0x0001_0001), // unconfigured 32-bit I/O cap reset value
                        0x20 => Some(0xFC80_FC80), // 0xFC80_0000..0xFC8F_FFFF
                        0x24 => Some(0x0001_0001), // unconfigured 64-bit pref cap reset value
                        _ => Some(0),
                    };
                }
                if addr.bus() == 1 {
                    return match off {
                        0x04 => Some(u32::from(self.wlan_cmd)),
                        0x18 => Some(self.wlan_bar2_lo),
                        0x1C => Some(self.wlan_bar2_hi),
                        _ => Some(0),
                    };
                }
                match off {
                    0x04 => Some(u32::from(self.vnet_cmd)),
                    0x20 => Some(self.vnet_bar4_lo),
                    0x24 => Some(self.vnet_bar4_hi),
                    _ => Some(0),
                }
            }
            fn write_width(
                &mut self,
                addr: PciAddress,
                off: u16,
                _w: ConfigWidth,
                val: u32,
            ) -> bool {
                if addr.bus() == 0 && addr.device() == 1 && addr.function() == 3 {
                    if off == 0x04 {
                        self.bridge_cmd = val as u16;
                    }
                    return true;
                }
                if addr.bus() == 1 {
                    match off {
                        0x04 => self.wlan_cmd = val as u16,
                        0x18 => {
                            self.wlan_bar2_lo = if val == u32::MAX {
                                0xFFFF_0004
                            } else {
                                (val & 0xFFFF_0000) | 0x4
                            };
                        }
                        0x1C => {
                            self.wlan_bar2_hi = if val == u32::MAX { u32::MAX } else { val };
                        }
                        _ => {}
                    }
                    return true;
                }
                match off {
                    0x04 => self.vnet_cmd = val as u16,
                    0x20 => {
                        self.vnet_bar4_lo = if val == u32::MAX {
                            0xFFFF_C00C
                        } else {
                            (val & 0xFFFF_C000) | 0xC
                        };
                    }
                    0x24 => {
                        self.vnet_bar4_hi = if val == u32::MAX { u32::MAX } else { val };
                    }
                    _ => {}
                }
                true
            }
        }

        let mut t = MultiDevTransport {
            bridge_cmd: 0x0006,
            wlan_cmd: 0x0006,
            wlan_bar2_lo: 0xFC80_0004,
            wlan_bar2_hi: 0x0000_0000,
            vnet_cmd: 0x0006,
            vnet_bar4_lo: 0x0000_000C,
            vnet_bar4_hi: 0x0000_00C0,
        };
        let live_res = collect_live_bar_inventory(&mut t, &topo, &apertures, &NoActiveLeases);
        assert!(live_res.is_ok(), "live BAR inventory must succeed");
        let Ok(live) = live_res else {
            return;
        };
        assert!(
            live.validation.is_conflict_free(),
            "validation must be conflict-free: {:?}",
            live.validation.resources()
        );
        let wlan_bar = live.validation.find(wlan_addr, ResourceRegister::Bar(2));
        assert_eq!(wlan_bar.and_then(|r| r.cpu_base), Some(0xFC80_0000));
        let vnet_bar = live.validation.find(vnet_addr, ResourceRegister::Bar(4));
        assert_eq!(vnet_bar.and_then(|r| r.cpu_base), Some(0xC0_0000_0000));
    }
}
