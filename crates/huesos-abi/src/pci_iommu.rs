//! Immutable IOMMU firmware discovery snapshot (`HIOM`, Stage N.1 / N.3).
//!
//! `acpi-manager` inspects archived `DMAR` (Intel VT-d) and `IVRS` (AMD-Vi)
//! tables and publishes one bounded, pointer-free `HIOM` VMO to `DriverManager`,
//! which retains it and forwards a read-only handle to `pci-manager`.
//!
//! Security and honesty invariants:
//! - Absent or malformed firmware tables explicitly report
//!   [`IommuMode::Trusted`] (never a fake isolated domain).
//! - Hardware interrupt-remapping capability (`FLAG_INTR_REMAP_HW_SUPPORTED`)
//!   is tracked separately from active interrupt remapping
//!   (`FLAG_INTR_REMAP_ACTIVE`) per Stage N.3.

/// Wire magic: ASCII `HIOM`.
pub const MAGIC: [u8; 4] = *b"HIOM";
/// Current wire format version.
pub const VERSION: u16 = 1;
/// Fixed header size in bytes.
pub const HEADER_BYTES: usize = 48;
/// Fixed per-IOMMU-unit record size in bytes.
pub const UNIT_BYTES: usize = 24;
/// Fixed per-reserved-memory-region (`RMRR`/`IVMD`) record size in bytes.
pub const REGION_BYTES: usize = 24;
/// Maximum IOMMU hardware units encoded in one snapshot.
pub const MAX_UNITS: usize = 8;
/// Maximum reserved DMA memory regions (`RMRR`/`IVMD`) encoded in one snapshot.
pub const MAX_REGIONS: usize = 16;
/// Maximum encoded `HIOM` byte length (`624` bytes).
pub const MAX_BYTES: usize = HEADER_BYTES + MAX_UNITS * UNIT_BYTES + MAX_REGIONS * REGION_BYTES;

/// Header flag: firmware advertises hardware interrupt-remapping support.
pub const FLAG_INTR_REMAP_HW_SUPPORTED: u8 = 1 << 0;
/// Header flag: kernel interrupt remapping is actively enabled.
pub const FLAG_INTR_REMAP_ACTIVE: u8 = 1 << 1;
/// Header flag: firmware requested x2APIC opt-out (`DMAR` bit 1).
pub const FLAG_X2APIC_OPT_OUT: u8 = 1 << 2;
/// Known header flags in v1.
pub const HEADER_FLAGS_V1: u8 =
    FLAG_INTR_REMAP_HW_SUPPORTED | FLAG_INTR_REMAP_ACTIVE | FLAG_X2APIC_OPT_OUT;

/// Unit flag: unit covers all PCI devices on its segment (`INCLUDE_PCI_ALL`).
pub const UNIT_FLAG_INCLUDE_PCI_ALL: u8 = 1 << 0;

const CHECKSUM_OFFSET: usize = 36;

/// Discovered platform IOMMU architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IommuHardwareKind {
    /// No IOMMU table (`DMAR`/`IVRS`) exists in the firmware archive.
    None = 0,
    /// Intel VT-d (`DMAR`).
    IntelVtd = 1,
    /// AMD-Vi / I/O Virtualization (`IVRS`).
    AmdVi = 2,
}

impl IommuHardwareKind {
    /// Convert raw wire byte to [`IommuHardwareKind`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::IntelVtd),
            2 => Some(Self::AmdVi),
            _ => None,
        }
    }

    /// Short canonical label for structured logs and operator queries.
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::IntelVtd => "intel-vtd",
            Self::AmdVi => "amd-vi",
        }
    }
}

/// Outcome of validating firmware IOMMU tables (Stage N.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IommuDiscoveryStatus {
    /// Neither `DMAR` nor `IVRS` is present; platform runs in `Trusted` mode.
    Absent = 0,
    /// Firmware table decoded cleanly and passed structural validation.
    Valid = 1,
    /// Firmware table was truncated, failed checksum, or had invalid descriptors;
    /// platform explicitly falls back to `Trusted` mode.
    MalformedFallbackTrusted = 2,
    /// Both `DMAR` and `IVRS` or duplicate tables appeared; platform falls back
    /// to `Trusted` mode.
    ConflictFallbackTrusted = 3,
}

impl IommuDiscoveryStatus {
    /// Convert raw wire byte to [`IommuDiscoveryStatus`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Absent),
            1 => Some(Self::Valid),
            2 => Some(Self::MalformedFallbackTrusted),
            3 => Some(Self::ConflictFallbackTrusted),
            _ => None,
        }
    }

    /// Short canonical status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Valid => "valid",
            Self::MalformedFallbackTrusted => "malformed-fallback-trusted",
            Self::ConflictFallbackTrusted => "conflict-fallback-trusted",
        }
    }
}

/// Effective DMA isolation profile enforced for PCI leases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IommuMode {
    /// DriverHosts with bus-mastering DMA are part of the trusted profile.
    Trusted = 0,
    /// Per-device IOMMU translation domains actively isolate DMA.
    Isolated = 1,
}

impl IommuMode {
    /// Convert raw wire byte to [`IommuMode`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Trusted),
            1 => Some(Self::Isolated),
            _ => None,
        }
    }

    /// Short canonical profile label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trusted => "Trusted",
            Self::Isolated => "Isolated",
        }
    }
}

/// One hardware IOMMU remapping engine (`DRHD` or `IVHD`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IommuUnitDesc {
    /// PCI segment group covered by this remapping hardware unit.
    pub segment: u16,
    /// Unit flags (`UNIT_FLAG_INCLUDE_PCI_ALL`).
    pub flags: u8,
    /// Number of explicit endpoint/bridge BDF entries in [`Self::scope_bdfs`].
    pub scope_bdf_count: u8,
    /// 4 KiB-aligned MMIO register base address of the IOMMU engine.
    pub register_base: u64,
    /// Up to four explicit `(bus << 8) | (dev << 3) | func` scope targets.
    pub scope_bdfs: [u16; 4],
}

impl IommuUnitDesc {
    /// Zeroed placeholder descriptor.
    pub const ZERO: Self = Self {
        segment: 0,
        flags: 0,
        scope_bdf_count: 0,
        register_base: 0,
        scope_bdfs: [0; 4],
    };
}

/// One firmware-declared reserved/unity-mapped DMA region (`RMRR` or `IVMD`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IommuReservedRegion {
    /// PCI segment group.
    pub segment: u16,
    /// Primary requester `(bus << 8) | (dev << 3) | func` (or `0xFFFF` for all).
    pub requester_bdf: u16,
    /// Firmware flags (e.g. unity/exclusion permissions).
    pub flags: u32,
    /// Inclusive physical start address.
    pub base_address: u64,
    /// Inclusive physical end address (`>= base_address`).
    pub limit_address: u64,
}

impl IommuReservedRegion {
    /// Zeroed placeholder region.
    pub const ZERO: Self = Self {
        segment: 0,
        requester_bdf: 0,
        flags: 0,
        base_address: 0,
        limit_address: 0,
    };
}

/// Complete decoded `HIOM` snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IommuSnapshot {
    /// Non-zero archive-v2 firmware snapshot identity.
    pub firmware_snapshot_id: u64,
    /// Non-zero `acpi-manager` generation that produced this image.
    pub producer_generation: u64,
    /// Hardware architecture discovered in firmware tables.
    pub hardware_kind: IommuHardwareKind,
    /// Validation outcome for firmware tables.
    pub discovery_status: IommuDiscoveryStatus,
    /// Active DMA isolation mode (never `Isolated` on absent/malformed tables).
    pub active_mode: IommuMode,
    /// Header capability/state flags (`FLAG_*`).
    pub flags: u8,
    /// Host physical address width (`HAW` + 1 on VT-d, or `0` when unknown).
    pub host_address_width: u8,
    /// Number of valid entries in [`Self::units`].
    pub unit_count: usize,
    /// Hardware IOMMU engine descriptors.
    pub units: [IommuUnitDesc; MAX_UNITS],
    /// Number of valid entries in [`Self::regions`].
    pub region_count: usize,
    /// Reserved memory regions (`RMRR`/`IVMD`).
    pub regions: [IommuReservedRegion; MAX_REGIONS],
}

impl IommuSnapshot {
    /// Construct a fail-closed `Trusted` snapshot with no active hardware units.
    pub const fn trusted_fallback(
        firmware_snapshot_id: u64,
        producer_generation: u64,
        hardware_kind: IommuHardwareKind,
        discovery_status: IommuDiscoveryStatus,
    ) -> Self {
        Self {
            firmware_snapshot_id,
            producer_generation,
            hardware_kind,
            discovery_status,
            active_mode: IommuMode::Trusted,
            flags: 0,
            host_address_width: 0,
            unit_count: 0,
            units: [IommuUnitDesc::ZERO; MAX_UNITS],
            region_count: 0,
            regions: [IommuReservedRegion::ZERO; MAX_REGIONS],
        }
    }

    /// True when firmware advertises hardware interrupt-remapping support.
    pub const fn interrupt_remapping_supported(&self) -> bool {
        (self.flags & FLAG_INTR_REMAP_HW_SUPPORTED) != 0
    }

    /// True when kernel interrupt remapping is actively enabled (Stage N.3).
    pub const fn interrupt_remapping_active(&self) -> bool {
        (self.flags & FLAG_INTR_REMAP_ACTIVE) != 0
    }

    /// Verify binding against expected producer generation and firmware snapshot.
    pub const fn check_binding(
        &self,
        expected_generation: u64,
        expected_snapshot: u64,
    ) -> Result<(), IommuWireError> {
        if self.producer_generation != expected_generation {
            return Err(IommuWireError::StaleGeneration);
        }
        if self.firmware_snapshot_id != expected_snapshot {
            return Err(IommuWireError::SnapshotMismatch);
        }
        Ok(())
    }
}

/// Wire encoding/decoding failure for `HIOM`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IommuWireError {
    /// Buffer shorter than required header or declared payload.
    BufferTooSmall,
    /// Magic bytes do not match `HIOM`.
    BadMagic,
    /// Unsupported format version.
    UnsupportedVersion,
    /// Header length, total size, or reserved fields are malformed.
    InvalidLayout,
    /// Wrapping checksum mismatch.
    BadChecksum,
    /// Snapshot or generation identity is zero.
    MissingIdentity,
    /// Invalid enum discriminant or flag combination (e.g. fake Isolated mode).
    InvalidPolicyState,
    /// Unit descriptor has unaligned/zero MMIO base or invalid scope count.
    InvalidUnit,
    /// Reserved memory region has `limit_address < base_address`.
    InvalidRegion,
    /// Producer generation did not match supervisor expectation.
    StaleGeneration,
    /// Firmware snapshot ID did not match retained archive/HMCF snapshot.
    SnapshotMismatch,
}

/// Validate semantic invariants of a snapshot prior to encode or after decode.
pub fn validate_snapshot(snap: &IommuSnapshot) -> Result<(), IommuWireError> {
    if snap.firmware_snapshot_id == 0 || snap.producer_generation == 0 {
        return Err(IommuWireError::MissingIdentity);
    }
    if snap.unit_count > MAX_UNITS || snap.region_count > MAX_REGIONS {
        return Err(IommuWireError::InvalidLayout);
    }
    if (snap.flags & !HEADER_FLAGS_V1) != 0 {
        return Err(IommuWireError::InvalidPolicyState);
    }
    // Stage N.3: cannot claim active interrupt remapping if hardware does not support it.
    if snap.interrupt_remapping_active() && !snap.interrupt_remapping_supported() {
        return Err(IommuWireError::InvalidPolicyState);
    }
    // Stage N.1: never allow Isolated mode on absent/malformed/unitless firmware tables.
    if snap.active_mode == IommuMode::Isolated
        && (snap.hardware_kind == IommuHardwareKind::None
            || snap.discovery_status != IommuDiscoveryStatus::Valid
            || snap.unit_count == 0)
    {
        return Err(IommuWireError::InvalidPolicyState);
    }
    if snap.discovery_status != IommuDiscoveryStatus::Valid
        && (snap.unit_count != 0 || snap.region_count != 0)
    {
        return Err(IommuWireError::InvalidPolicyState);
    }
    for idx in 0..snap.unit_count {
        let u = snap.units[idx];
        if u.register_base == 0
            || (u.register_base & 0xFFF) != 0
            || u.scope_bdf_count > 4
            || (u.flags & !UNIT_FLAG_INCLUDE_PCI_ALL) != 0
        {
            return Err(IommuWireError::InvalidUnit);
        }
    }
    for idx in 0..snap.region_count {
        let r = snap.regions[idx];
        if r.limit_address < r.base_address {
            return Err(IommuWireError::InvalidRegion);
        }
    }
    Ok(())
}

/// Return the declared byte length from a `HEADER_BYTES` prefix.
pub fn declared_size(header: &[u8]) -> Result<usize, IommuWireError> {
    if header.len() < HEADER_BYTES {
        return Err(IommuWireError::BufferTooSmall);
    }
    if header[0..4] != MAGIC {
        return Err(IommuWireError::BadMagic);
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != VERSION {
        return Err(IommuWireError::UnsupportedVersion);
    }
    let hdr_bytes = u16::from_le_bytes([header[6], header[7]]) as usize;
    if hdr_bytes != HEADER_BYTES {
        return Err(IommuWireError::InvalidLayout);
    }
    let total = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let units = usize::from(header[33]);
    let regions = usize::from(header[34]);
    if units > MAX_UNITS || regions > MAX_REGIONS {
        return Err(IommuWireError::InvalidLayout);
    }
    let expected = HEADER_BYTES + units * UNIT_BYTES + regions * REGION_BYTES;
    if total != expected || total > MAX_BYTES {
        return Err(IommuWireError::InvalidLayout);
    }
    Ok(total)
}

/// Encode `snap` into `out`, returning the encoded byte length.
pub fn encode(snap: &IommuSnapshot, out: &mut [u8]) -> Result<usize, IommuWireError> {
    validate_snapshot(snap)?;
    let total = HEADER_BYTES + snap.unit_count * UNIT_BYTES + snap.region_count * REGION_BYTES;
    if out.len() < total {
        return Err(IommuWireError::BufferTooSmall);
    }
    out[..total].fill(0);
    out[0..4].copy_from_slice(&MAGIC);
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    out[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    out[12..20].copy_from_slice(&snap.firmware_snapshot_id.to_le_bytes());
    out[20..28].copy_from_slice(&snap.producer_generation.to_le_bytes());
    out[28] = snap.hardware_kind as u8;
    out[29] = snap.discovery_status as u8;
    out[30] = snap.active_mode as u8;
    out[31] = snap.flags;
    out[32] = snap.host_address_width;
    out[33] = snap.unit_count as u8;
    out[34] = snap.region_count as u8;
    out[35] = 0;

    let mut cursor = HEADER_BYTES;
    for idx in 0..snap.unit_count {
        let u = snap.units[idx];
        out[cursor..cursor + 2].copy_from_slice(&u.segment.to_le_bytes());
        out[cursor + 2] = u.flags;
        out[cursor + 3] = u.scope_bdf_count;
        out[cursor + 4..cursor + 12].copy_from_slice(&u.register_base.to_le_bytes());
        for s in 0..usize::from(u.scope_bdf_count) {
            let off = cursor + 12 + s * 2;
            out[off..off + 2].copy_from_slice(&u.scope_bdfs[s].to_le_bytes());
        }
        cursor += UNIT_BYTES;
    }

    for idx in 0..snap.region_count {
        let r = snap.regions[idx];
        out[cursor..cursor + 2].copy_from_slice(&r.segment.to_le_bytes());
        out[cursor + 2..cursor + 4].copy_from_slice(&r.requester_bdf.to_le_bytes());
        out[cursor + 4..cursor + 8].copy_from_slice(&r.flags.to_le_bytes());
        out[cursor + 8..cursor + 16].copy_from_slice(&r.base_address.to_le_bytes());
        out[cursor + 16..cursor + 24].copy_from_slice(&r.limit_address.to_le_bytes());
        cursor += REGION_BYTES;
    }

    let csum = compute_checksum(&out[..total]);
    out[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&csum.to_le_bytes());
    Ok(total)
}

/// Decode and validate a complete `HIOM` image.
pub fn decode(bytes: &[u8]) -> Result<IommuSnapshot, IommuWireError> {
    let total = declared_size(bytes)?;
    if bytes.len() < total {
        return Err(IommuWireError::BufferTooSmall);
    }
    let slice = &bytes[..total];
    if slice[35] != 0 || slice[40..48] != [0u8; 8] {
        return Err(IommuWireError::InvalidLayout);
    }
    let stored_csum = u32::from_le_bytes([
        slice[CHECKSUM_OFFSET],
        slice[CHECKSUM_OFFSET + 1],
        slice[CHECKSUM_OFFSET + 2],
        slice[CHECKSUM_OFFSET + 3],
    ]);
    if stored_csum != compute_checksum(slice) {
        return Err(IommuWireError::BadChecksum);
    }

    let firmware_snapshot_id = u64::from_le_bytes([
        slice[12], slice[13], slice[14], slice[15], slice[16], slice[17], slice[18], slice[19],
    ]);
    let producer_generation = u64::from_le_bytes([
        slice[20], slice[21], slice[22], slice[23], slice[24], slice[25], slice[26], slice[27],
    ]);
    let hardware_kind =
        IommuHardwareKind::from_raw(slice[28]).ok_or(IommuWireError::InvalidPolicyState)?;
    let discovery_status =
        IommuDiscoveryStatus::from_raw(slice[29]).ok_or(IommuWireError::InvalidPolicyState)?;
    let active_mode = IommuMode::from_raw(slice[30]).ok_or(IommuWireError::InvalidPolicyState)?;
    let flags = slice[31];
    let host_address_width = slice[32];
    let unit_count = usize::from(slice[33]);
    let region_count = usize::from(slice[34]);

    let mut units = [IommuUnitDesc::ZERO; MAX_UNITS];
    let mut cursor = HEADER_BYTES;
    for slot in units.iter_mut().take(unit_count) {
        if slice[cursor + 20..cursor + 24] != [0u8; 4] {
            return Err(IommuWireError::InvalidLayout);
        }
        let segment = u16::from_le_bytes([slice[cursor], slice[cursor + 1]]);
        let uflags = slice[cursor + 2];
        let scope_count = slice[cursor + 3];
        let register_base = u64::from_le_bytes([
            slice[cursor + 4],
            slice[cursor + 5],
            slice[cursor + 6],
            slice[cursor + 7],
            slice[cursor + 8],
            slice[cursor + 9],
            slice[cursor + 10],
            slice[cursor + 11],
        ]);
        let mut scope_bdfs = [0u16; 4];
        for (s, dst) in scope_bdfs.iter_mut().enumerate() {
            let off = cursor + 12 + s * 2;
            *dst = u16::from_le_bytes([slice[off], slice[off + 1]]);
        }
        *slot = IommuUnitDesc {
            segment,
            flags: uflags,
            scope_bdf_count: scope_count,
            register_base,
            scope_bdfs,
        };
        cursor += UNIT_BYTES;
    }

    let mut regions = [IommuReservedRegion::ZERO; MAX_REGIONS];
    for slot in regions.iter_mut().take(region_count) {
        let segment = u16::from_le_bytes([slice[cursor], slice[cursor + 1]]);
        let requester_bdf = u16::from_le_bytes([slice[cursor + 2], slice[cursor + 3]]);
        let rflags = u32::from_le_bytes([
            slice[cursor + 4],
            slice[cursor + 5],
            slice[cursor + 6],
            slice[cursor + 7],
        ]);
        let base_address = u64::from_le_bytes([
            slice[cursor + 8],
            slice[cursor + 9],
            slice[cursor + 10],
            slice[cursor + 11],
            slice[cursor + 12],
            slice[cursor + 13],
            slice[cursor + 14],
            slice[cursor + 15],
        ]);
        let limit_address = u64::from_le_bytes([
            slice[cursor + 16],
            slice[cursor + 17],
            slice[cursor + 18],
            slice[cursor + 19],
            slice[cursor + 20],
            slice[cursor + 21],
            slice[cursor + 22],
            slice[cursor + 23],
        ]);
        *slot = IommuReservedRegion {
            segment,
            requester_bdf,
            flags: rflags,
            base_address,
            limit_address,
        };
        cursor += REGION_BYTES;
    }

    let snap = IommuSnapshot {
        firmware_snapshot_id,
        producer_generation,
        hardware_kind,
        discovery_status,
        active_mode,
        flags,
        host_address_width,
        unit_count,
        units,
        region_count,
        regions,
    };
    validate_snapshot(&snap)?;
    Ok(snap)
}

fn compute_checksum(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (idx, &b) in bytes.iter().enumerate() {
        if !(CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4).contains(&idx) {
            sum = sum.wrapping_add(u32::from(b));
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_valid_vtd_snapshot_preserves_units_and_separate_ir_flags() {
        let mut snap = IommuSnapshot::trusted_fallback(
            0xAABB_CCDD,
            3,
            IommuHardwareKind::IntelVtd,
            IommuDiscoveryStatus::Valid,
        );
        snap.flags = FLAG_INTR_REMAP_HW_SUPPORTED;
        snap.host_address_width = 39;
        snap.unit_count = 1;
        snap.units[0] = IommuUnitDesc {
            segment: 0,
            flags: UNIT_FLAG_INCLUDE_PCI_ALL,
            scope_bdf_count: 1,
            register_base: 0xFED9_0000,
            scope_bdfs: [0x0100, 0, 0, 0],
        };
        snap.region_count = 1;
        snap.regions[0] = IommuReservedRegion {
            segment: 0,
            requester_bdf: 0x00FA,
            flags: 1,
            base_address: 0x7F00_0000,
            limit_address: 0x7F00_FFFF,
        };

        let mut buf = [0u8; MAX_BYTES];
        let Ok(len) = encode(&snap, &mut buf) else {
            assert!(false, "encode failed");
            return;
        };
        let Ok(decoded) = decode(&buf[..len]) else {
            assert!(false, "decode failed");
            return;
        };
        assert_eq!(decoded, snap);
        assert!(decoded.interrupt_remapping_supported());
        assert!(!decoded.interrupt_remapping_active());
        assert_eq!(decoded.check_binding(3, 0xAABB_CCDD), Ok(()));
        assert_eq!(
            decoded.check_binding(2, 0xAABB_CCDD),
            Err(IommuWireError::StaleGeneration)
        );
    }

    #[test]
    fn fake_isolated_mode_or_active_ir_without_hw_support_is_rejected() {
        let mut fake = IommuSnapshot::trusted_fallback(
            1,
            1,
            IommuHardwareKind::IntelVtd,
            IommuDiscoveryStatus::MalformedFallbackTrusted,
        );
        fake.active_mode = IommuMode::Isolated;
        let mut buf = [0u8; MAX_BYTES];
        assert_eq!(
            encode(&fake, &mut buf),
            Err(IommuWireError::InvalidPolicyState)
        );

        let mut bad_ir = IommuSnapshot::trusted_fallback(
            1,
            1,
            IommuHardwareKind::IntelVtd,
            IommuDiscoveryStatus::Valid,
        );
        bad_ir.flags = FLAG_INTR_REMAP_ACTIVE;
        assert_eq!(
            encode(&bad_ir, &mut buf),
            Err(IommuWireError::InvalidPolicyState)
        );
    }
}
