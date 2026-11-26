//! Firmware IOMMU (`DMAR` / `IVRS`) discovery and validation policy (Stage N.1 / N.3).
//!
//! Pure `no_std`, allocation-free (`default-features = false` compatible), and
//! `unsafe`-free parser and policy evaluator for:
//! - **Intel VT-d** `DMAR` (`DMA Remapping Reporting` ACPI table: `DRHD`,
//!   `RMRR`, Device Scope requester paths, Host Address Width, and `INTR_REMAP`).
//! - **AMD-Vi** `IVRS` (`I/O Virtualization Reporting Structure` ACPI table:
//!   `IVHD` types `0x10`/`0x11`/`0x40`, device entries, and `IVMD` exclusion /
//!   unity-mapped memory blocks).
//!
//! Stage N.1 & N.3 invariants enforced by construction:
//! 1. Absent, conflicting, truncated, bad-checksum, or structurally invalid
//!    firmware tables **never** synthesize a fake isolated domain; they select
//!    [`DmaIsolation::Trusted`] with an explicit [`FirmwareIommuStatus`] reason.
//! 2. Hardware interrupt-remapping support (`interrupt_remapping_supported`) is
//!    tracked separately from active interrupt remapping
//!    (`interrupt_remapping_active = false`), so HuesOS never claims active
//!    interrupt remapping merely because firmware tables exist.

use crate::lease::DmaIsolation;
use crate::PciAddress;

/// Standard ACPI System Description Table header size.
pub const ACPI_SDT_HEADER_BYTES: usize = 36;
/// Minimum Intel `DMAR` table length (`36` SDT + `12` DMAR header).
pub const DMAR_MIN_BYTES: usize = 48;
/// Minimum AMD `IVRS` table length (`36` SDT + `12` IVRS header).
pub const IVRS_MIN_BYTES: usize = 48;
/// Maximum raw `DMAR`/`IVRS` table size accepted by the bounded parser.
pub const MAX_IOMMU_TABLE_BYTES: usize = 4096;
/// Maximum IOMMU remapping hardware units (`DRHD`/`IVHD`) retained.
pub const MAX_DISCOVERED_UNITS: usize = 8;
/// Maximum reserved/unity DMA regions (`RMRR`/`IVMD`) retained.
pub const MAX_DISCOVERED_REGIONS: usize = 16;
/// Maximum explicit Device Scope BDFs retained per unit.
pub const MAX_UNIT_SCOPE_BDFS: usize = 32;

/// `DMAR` header flag bit 0: platform supports VT-d Interrupt Remapping.
pub const DMAR_FLAG_INTR_REMAP: u8 = 1 << 0;
/// `DMAR` header flag bit 1: firmware requests x2APIC opt-out.
pub const DMAR_FLAG_X2APIC_OPT_OUT: u8 = 1 << 1;
/// `DRHD` flag bit 0: unit covers all remaining PCI devices on its segment.
pub const DRHD_FLAG_INCLUDE_PCI_ALL: u8 = 1 << 0;

/// Platform IOMMU architecture discovered in firmware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareIommuKind {
    /// Neither `DMAR` nor `IVRS` was present in the ACPI archive.
    None,
    /// Intel VT-d `DMAR`.
    IntelVtd,
    /// AMD-Vi `IVRS`.
    AmdVi,
}

/// Validation outcome for firmware IOMMU discovery (Stage N.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareIommuStatus {
    /// No `DMAR` or `IVRS` table present; `Trusted` DMA mode selected.
    Absent,
    /// Firmware table decoded cleanly and passed all structural checks.
    Valid,
    /// Table failed checksum, length, alignment, or subtable validation;
    /// `Trusted` DMA mode selected fail-closed.
    MalformedFallbackTrusted,
    /// Both `DMAR` and `IVRS` were supplied simultaneously; `Trusted` selected.
    ConflictFallbackTrusted,
}

/// One validated hardware IOMMU engine (`DRHD` or `IVHD`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveredIommuUnit {
    /// PCI segment group served by this unit.
    pub segment: u16,
    /// `true` when this unit is a segment-wide catch-all (`INCLUDE_PCI_ALL` / `IVHD All`).
    pub include_pci_all: bool,
    /// 4 KiB-aligned MMIO register base physical address.
    pub register_base: u64,
    /// Number of explicit `(bus << 8) | (dev << 3) | func` scope targets.
    pub scope_bdf_count: u8,
    /// Packed `(bus << 8) | (dev << 3) | func` scope targets.
    pub scope_bdfs: [u16; MAX_UNIT_SCOPE_BDFS],
}

impl DiscoveredIommuUnit {
    /// Empty unit slot.
    pub const ZERO: Self = Self {
        segment: 0,
        include_pci_all: false,
        register_base: 0,
        scope_bdf_count: 0,
        scope_bdfs: [0; MAX_UNIT_SCOPE_BDFS],
    };

    /// Pack `(bus, device, function)` into a 16-bit requester ID.
    pub const fn pack_bdf(bus: u8, device: u8, function: u8) -> u16 {
        ((bus as u16) << 8) | (((device & 0x1F) as u16) << 3) | ((function & 0x07) as u16)
    }
}

/// One validated firmware reserved/unity-mapped DMA region (`RMRR` or `IVMD`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveredReservedRegion {
    /// PCI segment group.
    pub segment: u16,
    /// Packed `(bus << 8) | (dev << 3) | func` requester (or `0xFFFF` for all).
    pub requester_bdf: u16,
    /// Firmware permission/exclusion flags.
    pub flags: u32,
    /// Inclusive physical base address.
    pub base_address: u64,
    /// Inclusive physical limit address (`>= base_address`).
    pub limit_address: u64,
}

impl DiscoveredReservedRegion {
    /// Empty reserved-region slot.
    pub const ZERO: Self = Self {
        segment: 0,
        requester_bdf: 0,
        flags: 0,
        base_address: 0,
        limit_address: 0,
    };
}

/// Complete Stage N.1 / N.3 IOMMU discovery and policy evaluation report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IommuDiscoveryReport {
    /// Discovered firmware IOMMU architecture.
    pub kind: FirmwareIommuKind,
    /// Firmware table validation status.
    pub status: FirmwareIommuStatus,
    /// Effective DMA isolation profile (`Trusted` until per-device domains are active).
    pub active_dma_isolation: DmaIsolation,
    /// Hardware interrupt-remapping capability advertised by firmware.
    pub interrupt_remapping_supported: bool,
    /// Whether interrupt remapping is actively enabled by the kernel (`false` in N.1/N.3).
    pub interrupt_remapping_active: bool,
    /// Whether `DMAR` requested x2APIC opt-out.
    pub x2apic_opt_out: bool,
    /// Host physical address width in bits (`0` when unknown/absent).
    pub host_address_width: u8,
    /// Number of valid entries in [`Self::units`].
    pub unit_count: usize,
    /// Validated hardware IOMMU units.
    pub units: [DiscoveredIommuUnit; MAX_DISCOVERED_UNITS],
    /// Number of valid entries in [`Self::regions`].
    pub region_count: usize,
    /// Validated reserved DMA memory regions (`RMRR`/`IVMD`).
    pub regions: [DiscoveredReservedRegion; MAX_DISCOVERED_REGIONS],
}

impl IommuDiscoveryReport {
    /// Clean fail-closed report for platforms without `DMAR`/`IVRS`.
    pub const fn absent() -> Self {
        Self {
            kind: FirmwareIommuKind::None,
            status: FirmwareIommuStatus::Absent,
            active_dma_isolation: DmaIsolation::Trusted,
            interrupt_remapping_supported: false,
            interrupt_remapping_active: false,
            x2apic_opt_out: false,
            host_address_width: 0,
            unit_count: 0,
            units: [DiscoveredIommuUnit::ZERO; MAX_DISCOVERED_UNITS],
            region_count: 0,
            regions: [DiscoveredReservedRegion::ZERO; MAX_DISCOVERED_REGIONS],
        }
    }

    const fn malformed(kind: FirmwareIommuKind) -> Self {
        Self {
            kind,
            status: FirmwareIommuStatus::MalformedFallbackTrusted,
            ..Self::absent()
        }
    }

    /// Resolve the IOMMU hardware unit governing `address`, preferring explicit
    /// Device Scope matches over segment-wide `INCLUDE_PCI_ALL` units (VT-d §8.3.1).
    pub fn unit_for_requester(&self, address: PciAddress) -> Option<&DiscoveredIommuUnit> {
        if self.status != FirmwareIommuStatus::Valid {
            return None;
        }
        let target_bdf =
            DiscoveredIommuUnit::pack_bdf(address.bus(), address.device(), address.function());
        for idx in 0..self.unit_count {
            let unit = &self.units[idx];
            if unit.segment != address.segment() {
                continue;
            }
            for s in 0..usize::from(unit.scope_bdf_count) {
                if unit.scope_bdfs[s] == target_bdf {
                    return Some(unit);
                }
            }
        }
        for idx in 0..self.unit_count {
            let unit = &self.units[idx];
            if unit.segment == address.segment() && unit.include_pci_all {
                return Some(unit);
            }
        }
        None
    }
}

/// Evaluate optional archived `DMAR` and `IVRS` byte slices into a fail-closed
/// [`IommuDiscoveryReport`].
pub fn discover_from_acpi_tables(dmar: Option<&[u8]>, ivrs: Option<&[u8]>) -> IommuDiscoveryReport {
    match (dmar, ivrs) {
        (None, None) => IommuDiscoveryReport::absent(),
        (Some(_), Some(_)) => IommuDiscoveryReport {
            kind: FirmwareIommuKind::None,
            status: FirmwareIommuStatus::ConflictFallbackTrusted,
            ..IommuDiscoveryReport::absent()
        },
        (Some(bytes), None) => parse_dmar(bytes),
        (None, Some(bytes)) => parse_ivrs(bytes),
    }
}

/// Parse an Intel VT-d `DMAR` table. Any structural error returns `Trusted` fallback.
pub fn parse_dmar(bytes: &[u8]) -> IommuDiscoveryReport {
    let Some(table) = validate_sdt_header(bytes, *b"DMAR", DMAR_MIN_BYTES) else {
        return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
    };
    let haw_raw = table[36];
    if haw_raw == 0 || haw_raw >= 64 {
        return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
    }
    let host_address_width = haw_raw + 1;
    let dmar_flags = table[37];
    let intr_remap_hw = (dmar_flags & DMAR_FLAG_INTR_REMAP) != 0;
    let x2apic_opt_out = (dmar_flags & DMAR_FLAG_X2APIC_OPT_OUT) != 0;

    let mut units = [DiscoveredIommuUnit::ZERO; MAX_DISCOVERED_UNITS];
    let mut unit_count = 0usize;
    let mut regions = [DiscoveredReservedRegion::ZERO; MAX_DISCOVERED_REGIONS];
    let mut region_count = 0usize;

    let mut cursor = DMAR_MIN_BYTES;
    while cursor < table.len() {
        if table.len() - cursor < 4 {
            return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
        }
        let sub_type = u16::from_le_bytes([table[cursor], table[cursor + 1]]);
        let sub_len = u16::from_le_bytes([table[cursor + 2], table[cursor + 3]]) as usize;
        if sub_len < 4 || cursor + sub_len > table.len() {
            return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
        }
        let sub = &table[cursor..cursor + sub_len];
        match sub_type {
            0 => {
                // DRHD: DMA Remapping Hardware Unit Definition
                if sub_len < 16 || unit_count >= MAX_DISCOVERED_UNITS {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
                }
                let flags = sub[4];
                let segment = u16::from_le_bytes([sub[6], sub[7]]);
                let reg_base = u64::from_le_bytes([
                    sub[8], sub[9], sub[10], sub[11], sub[12], sub[13], sub[14], sub[15],
                ]);
                if reg_base == 0 || (reg_base & 0xFFF) != 0 {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
                }
                let mut scope_bdfs = [0u16; MAX_UNIT_SCOPE_BDFS];
                let Some(scope_count) = parse_vtd_device_scopes(&sub[16..], &mut scope_bdfs) else {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
                };
                // Duplicate register base across DRHDs is malformed firmware.
                for prev in units.iter().take(unit_count) {
                    if prev.register_base == reg_base {
                        return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
                    }
                }
                units[unit_count] = DiscoveredIommuUnit {
                    segment,
                    include_pci_all: (flags & DRHD_FLAG_INCLUDE_PCI_ALL) != 0,
                    register_base: reg_base,
                    scope_bdf_count: scope_count as u8,
                    scope_bdfs,
                };
                unit_count += 1;
            }
            1 => {
                // RMRR: Reserved Memory Region Reporting
                if sub_len < 24 || region_count >= MAX_DISCOVERED_REGIONS {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
                }
                let segment = u16::from_le_bytes([sub[6], sub[7]]);
                let base = u64::from_le_bytes([
                    sub[8], sub[9], sub[10], sub[11], sub[12], sub[13], sub[14], sub[15],
                ]);
                let limit = u64::from_le_bytes([
                    sub[16], sub[17], sub[18], sub[19], sub[20], sub[21], sub[22], sub[23],
                ]);
                if (base & 0xFFF) != 0 || limit < base {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
                }
                let mut scope_bdfs = [0u16; MAX_UNIT_SCOPE_BDFS];
                let Some(scope_count) = parse_vtd_device_scopes(&sub[24..], &mut scope_bdfs) else {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
                };
                let requester_bdf = if scope_count > 0 {
                    scope_bdfs[0]
                } else {
                    0xFFFF
                };
                regions[region_count] = DiscoveredReservedRegion {
                    segment,
                    requester_bdf,
                    flags: 0,
                    base_address: base,
                    limit_address: limit,
                };
                region_count += 1;
            }
            2..=6 => {
                // ATSR / RHSA / ANDD / SATC / SIDP: bounds already verified.
            }
            _ => {
                return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
            }
        }
        cursor += sub_len;
    }

    if unit_count == 0 {
        return IommuDiscoveryReport::malformed(FirmwareIommuKind::IntelVtd);
    }

    IommuDiscoveryReport {
        kind: FirmwareIommuKind::IntelVtd,
        status: FirmwareIommuStatus::Valid,
        // Stage N.1/N.3: firmware topology is valid, active DMA isolation stays
        // Trusted until Stage N.2 per-device kernel IOMMU page tables are wired.
        active_dma_isolation: DmaIsolation::Trusted,
        interrupt_remapping_supported: intr_remap_hw,
        interrupt_remapping_active: false,
        x2apic_opt_out,
        host_address_width,
        unit_count,
        units,
        region_count,
        regions,
    }
}

fn parse_vtd_device_scopes(
    bytes: &[u8],
    out_bdfs: &mut [u16; MAX_UNIT_SCOPE_BDFS],
) -> Option<usize> {
    let mut cursor = 0usize;
    let mut stored = 0usize;
    while cursor < bytes.len() {
        if bytes.len() - cursor < 8 {
            return None;
        }
        let scope_type = bytes[cursor];
        let scope_len = usize::from(bytes[cursor + 1]);
        if !(1..=5).contains(&scope_type)
            || scope_len < 8
            || !(scope_len - 6).is_multiple_of(2)
            || cursor + scope_len > bytes.len()
        {
            return None;
        }
        let mut bus = bytes[cursor + 5];
        let path_pairs = (scope_len - 6) / 2;
        let mut dev = 0u8;
        let mut func = 0u8;
        for step in 0..path_pairs {
            dev = bytes[cursor + 6 + step * 2];
            func = bytes[cursor + 6 + step * 2 + 1];
            if dev >= 32 || func >= 8 {
                return None;
            }
            // Multi-hop PCI bridge paths advance logically; single-hop uses start_bus.
            if step + 1 < path_pairs {
                bus = bus.saturating_add(1);
            }
        }
        if (scope_type == 1 || scope_type == 2) && stored < MAX_UNIT_SCOPE_BDFS {
            out_bdfs[stored] = DiscoveredIommuUnit::pack_bdf(bus, dev, func);
            stored += 1;
        }
        cursor += scope_len;
    }
    Some(stored)
}

/// Parse an AMD-Vi `IVRS` table. Any structural error returns `Trusted` fallback.
pub fn parse_ivrs(bytes: &[u8]) -> IommuDiscoveryReport {
    let Some(table) = validate_sdt_header(bytes, *b"IVRS", IVRS_MIN_BYTES) else {
        return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
    };
    let iv_info = u32::from_le_bytes([table[36], table[37], table[38], table[39]]);
    let pa_size = ((iv_info >> 8) & 0x7F) as u8;
    if pa_size == 0 || pa_size > 64 {
        return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
    }
    // AMD-Vi IVINFO bit 1 (`DMA_REMAP_SUPPORT` / `IntRemap` reported per IVHD).
    let mut intr_remap_hw = false;

    let mut units = [DiscoveredIommuUnit::ZERO; MAX_DISCOVERED_UNITS];
    let mut unit_count = 0usize;
    let mut regions = [DiscoveredReservedRegion::ZERO; MAX_DISCOVERED_REGIONS];
    let mut region_count = 0usize;

    let mut cursor = IVRS_MIN_BYTES;
    while cursor < table.len() {
        if table.len() - cursor < 4 {
            return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
        }
        let block_type = table[cursor];
        let block_flags = table[cursor + 1];
        let block_len = u16::from_le_bytes([table[cursor + 2], table[cursor + 3]]) as usize;
        if block_len < 4 || cursor + block_len > table.len() {
            return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
        }
        let blk = &table[cursor..cursor + block_len];
        match block_type {
            0x10 | 0x11 | 0x40 => {
                // IVHD: I/O Virtualization Hardware Definition
                let hdr_len = if block_type == 0x10 { 24usize } else { 40usize };
                if block_len < hdr_len {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
                }
                let reg_base = u64::from_le_bytes([
                    blk[8], blk[9], blk[10], blk[11], blk[12], blk[13], blk[14], blk[15],
                ]);
                let segment = u16::from_le_bytes([blk[16], blk[17]]);
                if reg_base == 0 || (reg_base & 0xFFF) != 0 {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
                }
                // IVHD flags bit 4 (`IotlbSup`) / feature bit 1 (`IntCap` / `GASup`);
                // bit 0 of `blk[20]` (`IntSup` in IVHD feature report) indicates IR support.
                let feat = u32::from_le_bytes([blk[20], blk[21], blk[22], blk[23]]);
                if (feat & (1 << 1)) != 0 || (block_flags & (1 << 1)) != 0 {
                    intr_remap_hw = true;
                }

                let mut include_all = false;
                let mut scope_bdfs = [0u16; MAX_UNIT_SCOPE_BDFS];
                let mut scope_count = 0usize;
                let mut range_start: Option<u16> = None;
                let mut dev_off = hdr_len;
                while dev_off < block_len {
                    let entry_type = blk[dev_off];
                    let entry_len = match entry_type {
                        0x00..=0x3F => 4usize,
                        0x40..=0x7F => 8usize,
                        0x80..=0xBF => 16usize,
                        0xF0 => {
                            if dev_off + 22 > block_len {
                                return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
                            }
                            22usize + usize::from(blk[dev_off + 21])
                        }
                        _ => return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi),
                    };
                    if dev_off + entry_len > block_len {
                        return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
                    }
                    let bdf = if entry_len >= 3 {
                        u16::from_le_bytes([blk[dev_off + 1], blk[dev_off + 2]])
                    } else {
                        0
                    };
                    match entry_type {
                        1 => {
                            include_all = true;
                            range_start = None;
                        }
                        2 | 0x42 | 0x46 => {
                            range_start = None;
                            if scope_count < MAX_UNIT_SCOPE_BDFS
                                && !scope_bdfs[..scope_count].contains(&bdf)
                            {
                                scope_bdfs[scope_count] = bdf;
                                scope_count += 1;
                            } else if scope_count >= MAX_UNIT_SCOPE_BDFS {
                                include_all = true;
                            }
                        }
                        3 | 0x43 | 0x47 => {
                            range_start = Some(bdf);
                        }
                        4 => {
                            if let Some(start_bdf) = range_start.take() {
                                if start_bdf == 0 && bdf >= 0x00FF {
                                    include_all = true;
                                } else if bdf >= start_bdf {
                                    let mut cur = start_bdf;
                                    loop {
                                        if scope_count < MAX_UNIT_SCOPE_BDFS
                                            && !scope_bdfs[..scope_count].contains(&cur)
                                        {
                                            scope_bdfs[scope_count] = cur;
                                            scope_count += 1;
                                        } else if scope_count >= MAX_UNIT_SCOPE_BDFS {
                                            break;
                                        }
                                        if cur == bdf {
                                            break;
                                        }
                                        cur += 1;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    dev_off += entry_len;
                }

                // AGESA and QEMU 8.x may publish multiple IVHD blocks (`0x10`, `0x11`, `0x40`)
                // describing the same physical `(segment, register_base)` hardware unit.
                let existing = units[..unit_count]
                    .iter_mut()
                    .find(|u| u.segment == segment && u.register_base == reg_base);
                if let Some(unit) = existing {
                    unit.include_pci_all |= include_all;
                    let mut s = 0usize;
                    while s < scope_count {
                        let cand = scope_bdfs[s];
                        let cur_n = usize::from(unit.scope_bdf_count);
                        if cur_n < MAX_UNIT_SCOPE_BDFS && !unit.scope_bdfs[..cur_n].contains(&cand)
                        {
                            unit.scope_bdfs[cur_n] = cand;
                            unit.scope_bdf_count += 1;
                        }
                        s += 1;
                    }
                } else {
                    if unit_count >= MAX_DISCOVERED_UNITS {
                        return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
                    }
                    units[unit_count] = DiscoveredIommuUnit {
                        segment,
                        include_pci_all: include_all,
                        register_base: reg_base,
                        scope_bdf_count: scope_count as u8,
                        scope_bdfs,
                    };
                    unit_count += 1;
                }
            }
            0x20..=0x22 => {
                // IVMD: I/O Virtualization Memory Definition
                if block_len < 32 || region_count >= MAX_DISCOVERED_REGIONS {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
                }
                let requester = if block_type == 0x20 {
                    0xFFFF
                } else {
                    u16::from_le_bytes([blk[4], blk[5]])
                };
                let start = u64::from_le_bytes([
                    blk[16], blk[17], blk[18], blk[19], blk[20], blk[21], blk[22], blk[23],
                ]);
                let length = u64::from_le_bytes([
                    blk[24], blk[25], blk[26], blk[27], blk[28], blk[29], blk[30], blk[31],
                ]);
                if length == 0 {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
                }
                let Some(limit) = start.checked_add(length - 1) else {
                    return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
                };
                regions[region_count] = DiscoveredReservedRegion {
                    segment: 0,
                    requester_bdf: requester,
                    flags: u32::from(block_flags),
                    base_address: start,
                    limit_address: limit,
                };
                region_count += 1;
            }
            _ => {
                return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
            }
        }
        cursor += block_len;
    }

    if unit_count == 0 {
        return IommuDiscoveryReport::malformed(FirmwareIommuKind::AmdVi);
    }

    IommuDiscoveryReport {
        kind: FirmwareIommuKind::AmdVi,
        status: FirmwareIommuStatus::Valid,
        active_dma_isolation: DmaIsolation::Trusted,
        interrupt_remapping_supported: intr_remap_hw,
        interrupt_remapping_active: false,
        x2apic_opt_out: false,
        host_address_width: pa_size,
        unit_count,
        units,
        region_count,
        regions,
    }
}

fn validate_sdt_header(bytes: &[u8], expected_sig: [u8; 4], min_len: usize) -> Option<&[u8]> {
    if bytes.len() < min_len {
        return None;
    }
    if bytes[0..4] != expected_sig {
        return None;
    }
    let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if declared < min_len || declared > bytes.len() || declared > MAX_IOMMU_TABLE_BYTES {
        return None;
    }
    let table = &bytes[..declared];
    let mut sum = 0u8;
    for &b in table {
        sum = sum.wrapping_add(b);
    }
    if sum != 0 {
        return None;
    }
    Some(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal_acpi_checksum(buf: &mut [u8]) {
        buf[9] = 0;
        let mut sum = 0u8;
        for &b in buf.iter() {
            sum = sum.wrapping_add(b);
        }
        buf[9] = 0u8.wrapping_sub(sum);
    }

    #[test]
    fn dmar_drhd_and_rmrr_parse_cleanly_while_keeping_trusted_mode_and_inactive_ir() {
        // 48B header + 24B DRHD (with 1 endpoint scope) + 32B RMRR (with 1 endpoint scope) = 104B
        let mut dmar = [0u8; 104];
        dmar[0..4].copy_from_slice(b"DMAR");
        dmar[4..8].copy_from_slice(&(104u32).to_le_bytes());
        dmar[8] = 1;
        dmar[36] = 38; // HAW = 39 bits
        dmar[37] = DMAR_FLAG_INTR_REMAP;

        // DRHD at 48..72 (24 bytes): explicit endpoint 01:00.0
        dmar[48..50].copy_from_slice(&0u16.to_le_bytes());
        dmar[50..52].copy_from_slice(&24u16.to_le_bytes());
        dmar[52] = DRHD_FLAG_INCLUDE_PCI_ALL;
        dmar[54..56].copy_from_slice(&0u16.to_le_bytes());
        dmar[56..64].copy_from_slice(&0xFED9_0000u64.to_le_bytes());
        dmar[64] = 1; // PCI Endpoint scope
        dmar[65] = 8; // scope length
        dmar[69] = 1; // start_bus = 1
        dmar[70] = 0; // dev = 0
        dmar[71] = 0; // fn = 0

        // RMRR at 72..104 (32 bytes)
        dmar[72..74].copy_from_slice(&1u16.to_le_bytes());
        dmar[74..76].copy_from_slice(&32u16.to_le_bytes());
        dmar[78..80].copy_from_slice(&0u16.to_le_bytes());
        dmar[80..88].copy_from_slice(&0x7E00_0000u64.to_le_bytes());
        dmar[88..96].copy_from_slice(&0x7E00_FFFFu64.to_le_bytes());
        dmar[96] = 1;
        dmar[97] = 8;
        dmar[101] = 0;
        dmar[102] = 0x14;
        dmar[103] = 0;

        seal_acpi_checksum(&mut dmar);

        let report = discover_from_acpi_tables(Some(&dmar), None);
        assert_eq!(report.kind, FirmwareIommuKind::IntelVtd);
        assert_eq!(report.status, FirmwareIommuStatus::Valid);
        assert_eq!(report.active_dma_isolation, DmaIsolation::Trusted);
        assert!(report.interrupt_remapping_supported);
        assert!(!report.interrupt_remapping_active);
        assert_eq!(report.host_address_width, 39);
        assert_eq!(report.unit_count, 1);
        assert_eq!(report.region_count, 1);

        let Ok(nvme_addr) = PciAddress::try_new(0, 1, 0, 0) else {
            assert!(false);
            return;
        };
        let Some(unit) = report.unit_for_requester(nvme_addr) else {
            assert!(false);
            return;
        };
        assert_eq!(unit.register_base, 0xFED9_0000);
    }

    #[test]
    fn ivrs_ivhd_and_ivmd_parse_and_malformed_tables_select_trusted_explicitly() {
        // 48B IVRS header + 28B IVHD (type 0x10 + 4B All entry) + 32B IVMD = 108B
        let mut ivrs = [0u8; 108];
        ivrs[0..4].copy_from_slice(b"IVRS");
        ivrs[4..8].copy_from_slice(&(108u32).to_le_bytes());
        ivrs[8] = 2;
        ivrs[36..40].copy_from_slice(&(48u32 << 8).to_le_bytes());

        // IVHD at 48..76 (28 bytes)
        ivrs[48] = 0x10;
        ivrs[49] = 0x02;
        ivrs[50..52].copy_from_slice(&28u16.to_le_bytes());
        ivrs[56..64].copy_from_slice(&0xFEB8_0000u64.to_le_bytes());
        ivrs[68..72].copy_from_slice(&(1u32 << 1).to_le_bytes());
        ivrs[72] = 1; // All devices on segment

        // IVMD at 76..108 (32 bytes)
        ivrs[76] = 0x20;
        ivrs[77] = 0x03;
        ivrs[78..80].copy_from_slice(&32u16.to_le_bytes());
        ivrs[92..100].copy_from_slice(&0x9000_0000u64.to_le_bytes());
        ivrs[100..108].copy_from_slice(&0x0001_0000u64.to_le_bytes());

        seal_acpi_checksum(&mut ivrs);

        let report = discover_from_acpi_tables(None, Some(&ivrs));
        assert_eq!(report.kind, FirmwareIommuKind::AmdVi);
        assert_eq!(report.status, FirmwareIommuStatus::Valid);
        assert_eq!(report.active_dma_isolation, DmaIsolation::Trusted);
        assert!(report.interrupt_remapping_supported);
        assert!(!report.interrupt_remapping_active);
        assert_eq!(report.unit_count, 1);
        assert_eq!(report.region_count, 1);
        assert_eq!(report.regions[0].limit_address, 0x9000_FFFF);

        // Corrupt checksum -> explicit MalformedFallbackTrusted, 0 units, Trusted mode
        ivrs[20] ^= 0x55;
        let bad = discover_from_acpi_tables(Some(&ivrs), None);
        assert_eq!(bad.status, FirmwareIommuStatus::MalformedFallbackTrusted);
        assert_eq!(bad.active_dma_isolation, DmaIsolation::Trusted);
        assert_eq!(bad.unit_count, 0);

        // Conflict (both DMAR and IVRS passed) -> ConflictFallbackTrusted
        let conflict = discover_from_acpi_tables(Some(&ivrs), Some(&ivrs));
        assert_eq!(
            conflict.status,
            FirmwareIommuStatus::ConflictFallbackTrusted
        );
        assert_eq!(conflict.active_dma_isolation, DmaIsolation::Trusted);
    }

    #[test]
    fn ivrs_qemu_range_and_duplicate_ivhd_blocks_deduplicate_into_single_unit() {
        // 48B IVRS hdr + 40B IVHD 0x10 (Start 0x0000, End 0xFFFF, Special 8B)
        // + 44B IVHD 0x11 (same reg_base 0xFED8_0000 + Select 0x0018) = 132B
        let mut ivrs = [0u8; 132];
        ivrs[0..4].copy_from_slice(b"IVRS");
        ivrs[4..8].copy_from_slice(&(132u32).to_le_bytes());
        ivrs[8] = 2;
        ivrs[36..40].copy_from_slice(&(40u32 << 8).to_le_bytes());

        // Block 1: IVHD type 0x10 at 48..88 (24B hdr + 4B start + 4B end + 8B special)
        ivrs[48] = 0x10;
        ivrs[50..52].copy_from_slice(&40u16.to_le_bytes());
        ivrs[56..64].copy_from_slice(&0xFED8_0000u64.to_le_bytes());
        ivrs[72] = 0x03; // Start of Range 0x0000
        ivrs[76] = 0x04; // End of Range 0xFFFF
        ivrs[77..79].copy_from_slice(&0xFFFFu16.to_le_bytes());
        ivrs[80] = 0x48; // Special device (IOAPIC, 8 bytes)

        // Block 2: IVHD type 0x11 at 88..132 (40B hdr + 4B Select 00:03.0)
        ivrs[88] = 0x11;
        ivrs[90..92].copy_from_slice(&44u16.to_le_bytes());
        ivrs[96..104].copy_from_slice(&0xFED8_0000u64.to_le_bytes());
        ivrs[128] = 0x02;
        ivrs[129..131].copy_from_slice(&0x0018u16.to_le_bytes());

        seal_acpi_checksum(&mut ivrs);
        let report = discover_from_acpi_tables(None, Some(&ivrs));
        assert_eq!(report.status, FirmwareIommuStatus::Valid);
        assert_eq!(report.unit_count, 1);
        assert!(report.units[0].include_pci_all);
        assert_eq!(report.units[0].register_base, 0xFED8_0000);
        assert_eq!(report.units[0].scope_bdf_count, 1);
        assert_eq!(report.units[0].scope_bdfs[0], 0x0018);
    }
}
