//! PCI Manager root-bridge descriptor wire format (`HPCI`).
//!
//! The isolated ACPI service produces this bounded table for the
//! userspace PCI Manager. MCFG describes configuration windows; these records
//! additionally carry root bus ranges, `_CRS` I/O/MMIO apertures (including
//! explicit PCI-bus-to-CPU address translation), `_PRT` interrupt-routing
//! entries (including Link `_CRS`/`_STA` resolution), and per-root `_OSC`
//! query/ownership state (AP-15/AP-18).

/// Wire magic: ASCII `HPCI` in little endian.
pub const MAGIC: u32 = 0x4943_5048;
/// Initial version-1 format (roots + apertures only).
pub const VERSION_1: u16 = 1;
/// Current append-only format version (adds `_PRT` entries and `_OSC` metadata).
pub const VERSION: u16 = 2;
/// Fixed global header size.
pub const HEADER_BYTES: usize = 32;
/// Fixed version-1 root record size.
pub const ROOT_ENTRY_BYTES_V1: usize = 40;
/// Fixed version-2 root record size.
pub const ROOT_ENTRY_BYTES_V2: usize = 64;
/// Fixed current root record size.
pub const ROOT_ENTRY_BYTES: usize = ROOT_ENTRY_BYTES_V2;
/// Fixed aperture record size.
pub const APERTURE_ENTRY_BYTES: usize = 32;
/// Fixed `_PRT` entry record size.
pub const PRT_ENTRY_BYTES: usize = 16;
/// Maximum root bridges in one table.
pub const MAX_ROOTS: usize = 16;
/// Maximum apertures across all roots.
pub const MAX_APERTURES: usize = 64;
/// Maximum `_PRT` routing entries across all roots.
pub const MAX_PRT_ENTRIES: usize = 256;
/// Maximum encoded byte length.
pub const MAX_ENCODED_BYTES: usize = HEADER_BYTES
    + MAX_ROOTS * ROOT_ENTRY_BYTES_V2
    + MAX_APERTURES * APERTURE_ENTRY_BYTES
    + MAX_PRT_ENTRIES * PRT_ENTRY_BYTES;

/// Root supports firmware/native hotplug notification.
pub const ROOT_FLAG_HOTPLUG_CAPABLE: u32 = 1 << 0;
/// `_OSC` granted native PCIe hotplug control.
pub const ROOT_FLAG_NATIVE_HOTPLUG: u32 = 1 << 1;
/// A validated `_PRT` legacy interrupt-routing description is available.
pub const ROOT_FLAG_INTX_ROUTING: u32 = 1 << 2;
/// `_OSC` granted native AER control.
pub const ROOT_FLAG_NATIVE_AER: u32 = 1 << 3;
/// All root flags known by version 1/2.
pub const ROOT_FLAGS_V1: u32 = ROOT_FLAG_HOTPLUG_CAPABLE
    | ROOT_FLAG_NATIVE_HOTPLUG
    | ROOT_FLAG_INTX_ROUTING
    | ROOT_FLAG_NATIVE_AER;

/// `_OSC` DWORD 0 query flag (`1` = query mode without taking ownership).
pub const OSC_FLAG_QUERY: u32 = 1 << 0;
/// `_OSC` DWORD 0 error bit: generic failure.
pub const OSC_ERR_FAILURE: u32 = 1 << 1;
/// `_OSC` DWORD 0 error bit: unrecognized UUID.
pub const OSC_ERR_UNRECOGNIZED_UUID: u32 = 1 << 2;
/// `_OSC` DWORD 0 error bit: unrecognized revision.
pub const OSC_ERR_UNRECOGNIZED_REV: u32 = 1 << 3;
/// `_OSC` DWORD 0 error bit: capabilities masked by firmware.
pub const OSC_ERR_MASKED: u32 = 1 << 4;

/// `_OSC` Support DWORD 1 bit: Extended Configuration Space (ECAM) supported.
pub const OSC_SUPPORT_EXT_CFG: u32 = 1 << 0;
/// `_OSC` Support DWORD 1 bit: ASPM supported.
pub const OSC_SUPPORT_ASPM: u32 = 1 << 1;
/// `_OSC` Support DWORD 1 bit: Clock Power Management supported.
pub const OSC_SUPPORT_CLOCK_PM: u32 = 1 << 2;
/// `_OSC` Support DWORD 1 bit: PCI Segment Groups supported.
pub const OSC_SUPPORT_SEGMENT_GROUPS: u32 = 1 << 3;
/// `_OSC` Support DWORD 1 bit: MSI supported.
pub const OSC_SUPPORT_MSI: u32 = 1 << 4;

/// `_OSC` Control DWORD 2 bit: PCIe Native Hotplug control.
pub const OSC_CTRL_HOTPLUG: u32 = 1 << 0;
/// `_OSC` Control DWORD 2 bit: PCIe Native PME control.
pub const OSC_CTRL_PME: u32 = 1 << 2;
/// `_OSC` Control DWORD 2 bit: PCIe Native AER control.
pub const OSC_CTRL_AER: u32 = 1 << 3;
/// `_OSC` Control DWORD 2 bit: PCIe Capability Structure control.
pub const OSC_CTRL_CAPABILITY: u32 = 1 << 4;

/// Aperture contains space deliberately reserved for future hotplug.
pub const APERTURE_FLAG_HOTPLUG_RESERVE: u32 = 1 << 0;
/// Aperture assignment is fixed by the platform and cannot be relocated.
pub const APERTURE_FLAG_FIXED: u32 = 1 << 1;
/// All aperture flags known by version 1/2.
pub const APERTURE_FLAGS_V1: u32 = APERTURE_FLAG_HOTPLUG_RESERVE | APERTURE_FLAG_FIXED;

/// Result of evaluating `_OSC` on one PCI host bridge (C.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OscStatus {
    /// `_OSC` method is not present on this root bridge (or HPCI v1 input).
    NotPresent = 0,
    /// `_OSC` Query succeeded with all requested control bits permitted.
    Granted = 1,
    /// `_OSC` Query succeeded with firmware masking part/all of control bits.
    Masked = 2,
    /// `_OSC` evaluation failed or firmware returned a protocol error bit.
    Failed = 3,
}

impl OscStatus {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::NotPresent),
            1 => Some(Self::Granted),
            2 => Some(Self::Masked),
            3 => Some(Self::Failed),
            _ => None,
        }
    }

    /// Stable human-readable label for serial diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotPresent => "NotPresent",
            Self::Granted => "Granted",
            Self::Masked => "Masked",
            Self::Failed => "Failed",
        }
    }
}

/// How one `_PRT` entry resolves its target GSI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrtSourceKind {
    /// Hardwired GSI (`Source == NULL`, `SourceIndex` is GSI).
    DirectGsi = 1,
    /// Routed through a PCI Interrupt Link device whose `_STA`/`_CRS`
    /// resolved to a live GSI.
    PciLinkDevice = 2,
    /// Routed through a PCI Interrupt Link device that is currently
    /// disabled, absent, or has no active GSI in `_CRS`.
    UnresolvedLink = 3,
}

impl PrtSourceKind {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::DirectGsi),
            2 => Some(Self::PciLinkDevice),
            3 => Some(Self::UnresolvedLink),
            _ => None,
        }
    }
}

/// One resolved `_PRT` legacy PCI interrupt-routing entry (C.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrtEntry {
    /// Index of the owning root record.
    pub root_index: u16,
    /// PCI device number (`0..=31`, from `(Address >> 16) & 0x1F`).
    pub device: u8,
    /// PCI INTx pin (`0 = INTA# .. 3 = INTD#`).
    pub pin: u8,
    /// Resolved IOAPIC/platform GSI (`0` when [`PrtSourceKind::UnresolvedLink`]).
    pub gsi: u32,
    /// Resolution mechanism.
    pub source_kind: PrtSourceKind,
    /// Whether the target route / link device is currently active (`_STA`).
    pub link_active: bool,
    /// Interrupt triggering (`0` = edge, `1` = level).
    pub triggering: u8,
    /// Interrupt polarity (`0` = active-high, `1` = active-low).
    pub polarity: u8,
}

impl Default for PrtEntry {
    fn default() -> Self {
        Self {
            root_index: 0,
            device: 0,
            pin: 0,
            gsi: 0,
            source_kind: PrtSourceKind::DirectGsi,
            link_active: false,
            triggering: 1,
            polarity: 1,
        }
    }
}

/// Configuration transport selected for one root bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConfigBackend {
    /// PCI Configuration Mechanism #1 (`0xCF8/0xCFC`).
    LegacyIo = 1,
    /// PCI Express Enhanced Configuration Access Mechanism.
    Ecam = 2,
}

impl ConfigBackend {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::LegacyIo),
            2 => Some(Self::Ecam),
            _ => None,
        }
    }
}

/// Address-space class of one root aperture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApertureKind {
    /// PCI I/O-port space.
    Io = 1,
    /// Non-prefetchable memory constrained below 4 GiB.
    Mmio32 = 2,
    /// Non-prefetchable 64-bit memory.
    Mmio64 = 3,
    /// Prefetchable memory, normally allocated in 64-bit space.
    PrefetchableMemory = 4,
}

impl ApertureKind {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Io),
            2 => Some(Self::Mmio32),
            3 => Some(Self::Mmio64),
            4 => Some(Self::PrefetchableMemory),
            _ => None,
        }
    }
}

/// One PCI host/root bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootBridge {
    /// Stable identity assigned by the ACPI/root-bridge producer for this boot.
    pub root_id: u64,
    /// PCI segment group.
    pub segment: u16,
    /// First bus routed by this root.
    pub start_bus: u8,
    /// Last bus routed by this root, inclusive.
    pub end_bus: u8,
    /// Configuration transport.
    pub backend: ConfigBackend,
    /// Root capability/ownership flags.
    pub flags: u32,
    /// ECAM physical base, or zero for [`ConfigBackend::LegacyIo`].
    pub ecam_base: u64,
    /// Index of this root's first aperture in [`RootBridgeTable::apertures`].
    pub aperture_start: u16,
    /// Number of contiguous aperture records owned by this root.
    pub aperture_count: u16,
    /// Index of this root's first `_PRT` entry in [`RootBridgeTable::prt_entries`].
    pub prt_start: u16,
    /// Number of contiguous `_PRT` entries owned by this root.
    pub prt_count: u16,
    /// `_OSC` query/ownership evaluation status.
    pub osc_status: OscStatus,
    /// OS support bitmask passed in `_OSC` DWORD 1.
    pub osc_support: u32,
    /// Requested control bitmask passed in `_OSC` DWORD 2.
    pub osc_requested_control: u32,
    /// Platform-returned control bitmask from `_OSC` DWORD 2.
    pub osc_granted_control: u32,
    /// Platform-returned error/status bits from `_OSC` DWORD 0.
    pub osc_error_flags: u32,
}

impl Default for RootBridge {
    fn default() -> Self {
        Self {
            root_id: 0,
            segment: 0,
            start_bus: 0,
            end_bus: 0,
            backend: ConfigBackend::LegacyIo,
            flags: 0,
            ecam_base: 0,
            aperture_start: 0,
            aperture_count: 0,
            prt_start: 0,
            prt_count: 0,
            osc_status: OscStatus::NotPresent,
            osc_support: 0,
            osc_requested_control: 0,
            osc_granted_control: 0,
            osc_error_flags: 0,
        }
    }
}

/// One allocatable root-bridge address aperture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aperture {
    /// Index of the owning root record.
    pub root_index: u16,
    /// Address-space class.
    pub kind: ApertureKind,
    /// Versioned aperture flags.
    pub flags: u32,
    /// Base address programmed into PCI BARs/windows.
    pub pci_base: u64,
    /// CPU physical/I/O base corresponding to [`Self::pci_base`].
    pub cpu_base: u64,
    /// Aperture length in bytes or I/O-port units.
    pub len: u64,
}

impl Default for Aperture {
    fn default() -> Self {
        Self {
            root_index: 0,
            kind: ApertureKind::Io,
            flags: 0,
            pci_base: 0,
            cpu_base: 0,
            len: 0,
        }
    }
}

/// Bounded decoded root-bridge table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootBridgeTable {
    /// Number of valid root records.
    pub root_count: usize,
    /// Root records.
    pub roots: [RootBridge; MAX_ROOTS],
    /// Number of valid aperture records.
    pub aperture_count: usize,
    /// Aperture records, grouped contiguously by root.
    pub apertures: [Aperture; MAX_APERTURES],
    /// Number of valid `_PRT` routing entries.
    pub prt_count: usize,
    /// `_PRT` routing entries, grouped contiguously by root.
    pub prt_entries: [PrtEntry; MAX_PRT_ENTRIES],
}

impl RootBridgeTable {
    /// Construct an empty table.
    pub const fn empty() -> Self {
        Self {
            root_count: 0,
            roots: [const {
                RootBridge {
                    root_id: 0,
                    segment: 0,
                    start_bus: 0,
                    end_bus: 0,
                    backend: ConfigBackend::LegacyIo,
                    flags: 0,
                    ecam_base: 0,
                    aperture_start: 0,
                    aperture_count: 0,
                    prt_start: 0,
                    prt_count: 0,
                    osc_status: OscStatus::NotPresent,
                    osc_support: 0,
                    osc_requested_control: 0,
                    osc_granted_control: 0,
                    osc_error_flags: 0,
                }
            }; MAX_ROOTS],
            aperture_count: 0,
            apertures: [const {
                Aperture {
                    root_index: 0,
                    kind: ApertureKind::Io,
                    flags: 0,
                    pci_base: 0,
                    cpu_base: 0,
                    len: 0,
                }
            }; MAX_APERTURES],
            prt_count: 0,
            prt_entries: [const {
                PrtEntry {
                    root_index: 0,
                    device: 0,
                    pin: 0,
                    gsi: 0,
                    source_kind: PrtSourceKind::DirectGsi,
                    link_active: false,
                    triggering: 1,
                    polarity: 1,
                }
            }; MAX_PRT_ENTRIES],
        }
    }

    /// Append one root if capacity permits.
    pub fn push_root(&mut self, root: RootBridge) -> bool {
        if self.root_count >= MAX_ROOTS {
            return false;
        }
        self.roots[self.root_count] = root;
        self.root_count += 1;
        true
    }

    /// Append one aperture if capacity permits.
    pub fn push_aperture(&mut self, aperture: Aperture) -> bool {
        if self.aperture_count >= MAX_APERTURES {
            return false;
        }
        self.apertures[self.aperture_count] = aperture;
        self.aperture_count += 1;
        true
    }

    /// Append one `_PRT` entry if capacity permits.
    pub fn push_prt(&mut self, entry: PrtEntry) -> bool {
        if self.prt_count >= MAX_PRT_ENTRIES {
            return false;
        }
        self.prt_entries[self.prt_count] = entry;
        self.prt_count += 1;
        true
    }

    /// Return the `_PRT` slice belonging to `root_index`.
    pub fn root_prt(&self, root_index: usize) -> &[PrtEntry] {
        let Some(root) = self.roots[..self.root_count].get(root_index) else {
            return &[];
        };
        let start = root.prt_start as usize;
        let Some(end) = start.checked_add(root.prt_count as usize) else {
            return &[];
        };
        if end > self.prt_count {
            return &[];
        }
        &self.prt_entries[start..end]
    }
}

impl Default for RootBridgeTable {
    fn default() -> Self {
        Self::empty()
    }
}

/// Root-table encode/decode error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Magic or version does not match.
    BadHeader,
    /// Header/entry sizes, counts, or total byte length are inconsistent.
    BadLength,
    /// A reserved field is non-zero.
    ReservedNonZero,
    /// Unknown versioned flags are set.
    UnknownFlags,
    /// Backend or aperture kind is unknown.
    UnknownKind,
    /// Root bus/config geometry is invalid.
    InvalidRoot,
    /// Aperture ownership/range/translation is invalid.
    InvalidAperture,
    /// `_PRT` routing entry ownership/pin/device/trigger/polarity is invalid.
    InvalidPrt,
    /// `_OSC` metadata is inconsistent with its reported status.
    InvalidOsc,
    /// Caller-provided output buffer is too small.
    BufferTooSmall,
}

/// Cross-table validation error between `HPCI` and `HMCF`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyError {
    /// Standalone `HPCI` structural/range validation failed.
    RootTable(Error),
    /// Root table contains zero root bridges.
    EmptyRoots,
    /// Two roots share the same `root_id`.
    DuplicateRootId,
    /// Two roots in the same segment claim overlapping bus numbers.
    OverlappingRoots,
    /// Two apertures overlap in the same address space.
    OverlappingApertures,
    /// A root's `(segment, start_bus..=end_bus)` is not covered by `HMCF`.
    MissingHmcfCoverage,
    /// A root's `ecam_base` does not match the covering `HMCF` window.
    EcamMismatch,
    /// A root MMIO aperture overlaps an `HMCF` ECAM physical window.
    ApertureOverlapsEcam,
}

/// Validate `table` canonically (unique IDs, disjoint root bus ranges and
/// apertures) and verify consistency against a decoded `HMCF` snapshot.
pub fn validate_roots_and_hmcf(
    table: &RootBridgeTable,
    hmcf: &crate::hmcf::HmcfView<'_>,
) -> Result<(), ConsistencyError> {
    validate(table).map_err(ConsistencyError::RootTable)?;
    if table.root_count == 0 {
        return Err(ConsistencyError::EmptyRoots);
    }

    let roots = &table.roots[..table.root_count];
    for (i, a) in roots.iter().enumerate() {
        for b in &roots[i + 1..] {
            if a.root_id == b.root_id {
                return Err(ConsistencyError::DuplicateRootId);
            }
            if a.segment == b.segment && a.start_bus <= b.end_bus && b.start_bus <= a.end_bus {
                return Err(ConsistencyError::OverlappingRoots);
            }
        }

        let mut covered = false;
        for record in hmcf.records() {
            if record.segment == a.segment
                && a.start_bus >= record.start_bus
                && a.end_bus <= record.end_bus
            {
                if a.backend == ConfigBackend::Ecam {
                    let bus_offset = u64::from(a.start_bus - record.start_bus);
                    let expected_ecam = record
                        .ecam_base
                        .checked_add(bus_offset << 20)
                        .ok_or(ConsistencyError::EcamMismatch)?;
                    if a.ecam_base != expected_ecam {
                        return Err(ConsistencyError::EcamMismatch);
                    }
                }
                covered = true;
                break;
            }
        }
        if !covered {
            return Err(ConsistencyError::MissingHmcfCoverage);
        }
    }

    let apertures = &table.apertures[..table.aperture_count];
    for (i, a) in apertures.iter().enumerate() {
        let a_cpu_end = a.cpu_base + a.len;
        let a_pci_end = a.pci_base + a.len;
        let a_is_io = a.kind == ApertureKind::Io;

        if !a_is_io {
            for record in hmcf.records() {
                let rec_end = record.ecam_base.saturating_add(record.span_bytes);
                if a.cpu_base < rec_end && record.ecam_base < a_cpu_end {
                    return Err(ConsistencyError::ApertureOverlapsEcam);
                }
            }
        }

        for b in &apertures[i + 1..] {
            let b_is_io = b.kind == ApertureKind::Io;
            if a_is_io != b_is_io {
                continue;
            }
            let b_cpu_end = b.cpu_base + b.len;
            if a.cpu_base < b_cpu_end && b.cpu_base < a_cpu_end {
                return Err(ConsistencyError::OverlappingApertures);
            }
            if a.root_index == b.root_index {
                let b_pci_end = b.pci_base + b.len;
                if a.pci_base < b_pci_end && b.pci_base < a_pci_end {
                    return Err(ConsistencyError::OverlappingApertures);
                }
            }
        }
    }

    Ok(())
}

/// Encode a canonical version-2 root table (including `_PRT` and `_OSC`).
pub fn encode(table: &RootBridgeTable, out: &mut [u8]) -> Result<usize, Error> {
    validate(table)?;
    let roots_bytes = table
        .root_count
        .checked_mul(ROOT_ENTRY_BYTES_V2)
        .ok_or(Error::BadLength)?;
    let apertures_bytes = table
        .aperture_count
        .checked_mul(APERTURE_ENTRY_BYTES)
        .ok_or(Error::BadLength)?;
    let prt_bytes = table
        .prt_count
        .checked_mul(PRT_ENTRY_BYTES)
        .ok_or(Error::BadLength)?;
    let total = HEADER_BYTES
        .checked_add(roots_bytes)
        .and_then(|value| value.checked_add(apertures_bytes))
        .and_then(|value| value.checked_add(prt_bytes))
        .ok_or(Error::BadLength)?;
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    out[..total].fill(0);
    write_u32(out, 0, MAGIC)?;
    write_u16(out, 4, VERSION)?;
    write_u16(out, 6, HEADER_BYTES as u16)?;
    write_u16(out, 8, ROOT_ENTRY_BYTES_V2 as u16)?;
    write_u16(out, 10, APERTURE_ENTRY_BYTES as u16)?;
    write_u16(out, 12, table.root_count as u16)?;
    write_u16(out, 14, table.aperture_count as u16)?;
    write_u16(out, 16, PRT_ENTRY_BYTES as u16)?;
    write_u16(out, 18, table.prt_count as u16)?;

    for index in 0..table.root_count {
        encode_root_v2(
            &table.roots[index],
            out,
            HEADER_BYTES + index * ROOT_ENTRY_BYTES_V2,
        )?;
    }
    let aperture_base = HEADER_BYTES + roots_bytes;
    for index in 0..table.aperture_count {
        encode_aperture(
            &table.apertures[index],
            out,
            aperture_base + index * APERTURE_ENTRY_BYTES,
        )?;
    }
    let prt_base = aperture_base + apertures_bytes;
    for index in 0..table.prt_count {
        encode_prt(
            &table.prt_entries[index],
            out,
            prt_base + index * PRT_ENTRY_BYTES,
        )?;
    }
    Ok(total)
}

/// Encode a legacy version-1 root table (roots + apertures only, no `_PRT`/`_OSC`).
#[cfg(test)]
fn encode_v1(table: &RootBridgeTable, out: &mut [u8]) -> Result<usize, Error> {
    validate(table)?;
    let roots_bytes = table
        .root_count
        .checked_mul(ROOT_ENTRY_BYTES_V1)
        .ok_or(Error::BadLength)?;
    let apertures_bytes = table
        .aperture_count
        .checked_mul(APERTURE_ENTRY_BYTES)
        .ok_or(Error::BadLength)?;
    let total = HEADER_BYTES
        .checked_add(roots_bytes)
        .and_then(|value| value.checked_add(apertures_bytes))
        .ok_or(Error::BadLength)?;
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    out[..total].fill(0);
    write_u32(out, 0, MAGIC)?;
    write_u16(out, 4, VERSION_1)?;
    write_u16(out, 6, HEADER_BYTES as u16)?;
    write_u16(out, 8, ROOT_ENTRY_BYTES_V1 as u16)?;
    write_u16(out, 10, APERTURE_ENTRY_BYTES as u16)?;
    write_u16(out, 12, table.root_count as u16)?;
    write_u16(out, 14, table.aperture_count as u16)?;

    for index in 0..table.root_count {
        encode_root_v1(
            &table.roots[index],
            out,
            HEADER_BYTES + index * ROOT_ENTRY_BYTES_V1,
        )?;
    }
    let aperture_base = HEADER_BYTES + roots_bytes;
    for index in 0..table.aperture_count {
        encode_aperture(
            &table.apertures[index],
            out,
            aperture_base + index * APERTURE_ENTRY_BYTES,
        )?;
    }
    Ok(total)
}

/// Return the exact declared wire length of a `HPCI` header slice (v1 or v2).
pub fn declared_size(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::BadLength);
    }
    if read_u32(bytes, 0)? != MAGIC {
        return Err(Error::BadHeader);
    }
    let version = read_u16(bytes, 4)?;
    if version != VERSION_1 && version != VERSION {
        return Err(Error::BadHeader);
    }
    if read_u16(bytes, 6)? as usize != HEADER_BYTES
        || read_u16(bytes, 10)? as usize != APERTURE_ENTRY_BYTES
    {
        return Err(Error::BadLength);
    }
    let root_entry_bytes = read_u16(bytes, 8)? as usize;
    let root_count = read_u16(bytes, 12)? as usize;
    let aperture_count = read_u16(bytes, 14)? as usize;
    if root_count > MAX_ROOTS || aperture_count > MAX_APERTURES {
        return Err(Error::BadLength);
    }

    let (expected_root_bytes, prt_count) = if version == VERSION_1 {
        if root_entry_bytes != ROOT_ENTRY_BYTES_V1 {
            return Err(Error::BadLength);
        }
        if read_u32(bytes, 16)? != 0 || read_u32(bytes, 20)? != 0 || read_u64(bytes, 24)? != 0 {
            return Err(Error::ReservedNonZero);
        }
        (ROOT_ENTRY_BYTES_V1, 0usize)
    } else {
        if root_entry_bytes != ROOT_ENTRY_BYTES_V2
            || read_u16(bytes, 16)? as usize != PRT_ENTRY_BYTES
        {
            return Err(Error::BadLength);
        }
        let prt_count = read_u16(bytes, 18)? as usize;
        if prt_count > MAX_PRT_ENTRIES {
            return Err(Error::BadLength);
        }
        if read_u32(bytes, 20)? != 0 || read_u64(bytes, 24)? != 0 {
            return Err(Error::ReservedNonZero);
        }
        (ROOT_ENTRY_BYTES_V2, prt_count)
    };

    let roots_bytes = root_count
        .checked_mul(expected_root_bytes)
        .ok_or(Error::BadLength)?;
    let apertures_bytes = aperture_count
        .checked_mul(APERTURE_ENTRY_BYTES)
        .ok_or(Error::BadLength)?;
    let prt_bytes = prt_count
        .checked_mul(PRT_ENTRY_BYTES)
        .ok_or(Error::BadLength)?;
    HEADER_BYTES
        .checked_add(roots_bytes)
        .and_then(|value| value.checked_add(apertures_bytes))
        .and_then(|value| value.checked_add(prt_bytes))
        .ok_or(Error::BadLength)
}

/// Decode and validate one exact root-table blob (v1 or v2).
pub fn decode(bytes: &[u8]) -> Result<RootBridgeTable, Error> {
    let total = declared_size(bytes)?;
    if bytes.len() != total {
        return Err(Error::BadLength);
    }
    let version = read_u16(bytes, 4)?;
    let root_entry_bytes = read_u16(bytes, 8)? as usize;
    let root_count = read_u16(bytes, 12)? as usize;
    let aperture_count = read_u16(bytes, 14)? as usize;
    let prt_count = if version == VERSION_1 {
        0
    } else {
        read_u16(bytes, 18)? as usize
    };
    let roots_bytes = root_count * root_entry_bytes;

    let mut table = RootBridgeTable::empty();
    let aperture_base = HEADER_BYTES + roots_bytes;
    for index in 0..root_count {
        let base = HEADER_BYTES + index * root_entry_bytes;
        table.roots[index] = if version == VERSION_1 {
            decode_root_v1(bytes, base)?
        } else {
            decode_root_v2(bytes, base)?
        };
    }
    for index in 0..aperture_count {
        table.apertures[index] =
            decode_aperture(bytes, aperture_base + index * APERTURE_ENTRY_BYTES)?;
    }
    let prt_base = aperture_base + aperture_count * APERTURE_ENTRY_BYTES;
    for index in 0..prt_count {
        table.prt_entries[index] = decode_prt(bytes, prt_base + index * PRT_ENTRY_BYTES)?;
    }
    table.root_count = root_count;
    table.aperture_count = aperture_count;
    table.prt_count = prt_count;
    validate(&table)?;
    Ok(table)
}

/// Validate the canonical in-memory table.
pub fn validate(table: &RootBridgeTable) -> Result<(), Error> {
    if table.root_count > MAX_ROOTS
        || table.aperture_count > MAX_APERTURES
        || table.prt_count > MAX_PRT_ENTRIES
    {
        return Err(Error::BadLength);
    }
    let mut expected_aperture = 0usize;
    let mut expected_prt = 0usize;
    for root_index in 0..table.root_count {
        let root = table.roots[root_index];
        if root.root_id == 0 || root.start_bus > root.end_bus || root.flags & !ROOT_FLAGS_V1 != 0 {
            return Err(if root.flags & !ROOT_FLAGS_V1 != 0 {
                Error::UnknownFlags
            } else {
                Error::InvalidRoot
            });
        }
        match root.backend {
            ConfigBackend::LegacyIo => {
                if root.segment != 0 || root.ecam_base != 0 {
                    return Err(Error::InvalidRoot);
                }
            }
            ConfigBackend::Ecam => {
                if root.ecam_base == 0 || !root.ecam_base.is_multiple_of(1 << 20) {
                    return Err(Error::InvalidRoot);
                }
            }
        }
        if root.aperture_start as usize != expected_aperture {
            return Err(Error::InvalidAperture);
        }
        expected_aperture = expected_aperture
            .checked_add(root.aperture_count as usize)
            .ok_or(Error::InvalidAperture)?;
        if expected_aperture > table.aperture_count {
            return Err(Error::InvalidAperture);
        }

        if root.prt_start as usize != expected_prt {
            return Err(Error::InvalidPrt);
        }
        expected_prt = expected_prt
            .checked_add(root.prt_count as usize)
            .ok_or(Error::InvalidPrt)?;
        if expected_prt > table.prt_count {
            return Err(Error::InvalidPrt);
        }

        if root.osc_status == OscStatus::NotPresent
            && (root.osc_error_flags != 0 || root.osc_granted_control != 0)
        {
            return Err(Error::InvalidOsc);
        }
        if root.osc_status == OscStatus::Granted && root.osc_error_flags != 0 {
            return Err(Error::InvalidOsc);
        }
    }
    if expected_aperture != table.aperture_count {
        return Err(Error::InvalidAperture);
    }
    if expected_prt != table.prt_count {
        return Err(Error::InvalidPrt);
    }

    for aperture_index in 0..table.aperture_count {
        let aperture = table.apertures[aperture_index];
        if aperture.root_index as usize >= table.root_count {
            return Err(Error::InvalidAperture);
        }
        let root = table.roots[aperture.root_index as usize];
        let start = root.aperture_start as usize;
        let end = start + root.aperture_count as usize;
        if aperture_index < start || aperture_index >= end || aperture.len == 0 {
            return Err(Error::InvalidAperture);
        }
        if aperture.flags & !APERTURE_FLAGS_V1 != 0 {
            return Err(Error::UnknownFlags);
        }
        if aperture.pci_base.checked_add(aperture.len).is_none()
            || aperture.cpu_base.checked_add(aperture.len).is_none()
        {
            return Err(Error::InvalidAperture);
        }
        if aperture.kind == ApertureKind::Mmio32
            && aperture
                .pci_base
                .checked_add(aperture.len)
                .ok_or(Error::InvalidAperture)?
                > 1u64 << 32
        {
            return Err(Error::InvalidAperture);
        }
    }

    for prt_index in 0..table.prt_count {
        let prt = table.prt_entries[prt_index];
        if prt.root_index as usize >= table.root_count {
            return Err(Error::InvalidPrt);
        }
        let root = table.roots[prt.root_index as usize];
        let start = root.prt_start as usize;
        let end = start + root.prt_count as usize;
        if prt_index < start
            || prt_index >= end
            || prt.device >= 32
            || prt.pin >= 4
            || prt.triggering > 1
            || prt.polarity > 1
        {
            return Err(Error::InvalidPrt);
        }
        if prt.source_kind == PrtSourceKind::UnresolvedLink && (prt.gsi != 0 || prt.link_active) {
            return Err(Error::InvalidPrt);
        }
    }
    Ok(())
}

#[cfg(test)]
fn encode_root_v1(root: &RootBridge, out: &mut [u8], base: usize) -> Result<(), Error> {
    write_u64(out, base, root.root_id)?;
    write_u16(out, base + 8, root.segment)?;
    write_u8(out, base + 10, root.start_bus)?;
    write_u8(out, base + 11, root.end_bus)?;
    write_u8(out, base + 12, root.backend as u8)?;
    write_u16(out, base + 14, root.aperture_start)?;
    write_u16(out, base + 16, root.aperture_count)?;
    write_u32(out, base + 20, root.flags)?;
    write_u64(out, base + 24, root.ecam_base)?;
    Ok(())
}

fn encode_root_v2(root: &RootBridge, out: &mut [u8], base: usize) -> Result<(), Error> {
    write_u64(out, base, root.root_id)?;
    write_u16(out, base + 8, root.segment)?;
    write_u8(out, base + 10, root.start_bus)?;
    write_u8(out, base + 11, root.end_bus)?;
    write_u8(out, base + 12, root.backend as u8)?;
    write_u16(out, base + 14, root.aperture_start)?;
    write_u16(out, base + 16, root.aperture_count)?;
    write_u32(out, base + 20, root.flags)?;
    write_u64(out, base + 24, root.ecam_base)?;
    write_u16(out, base + 40, root.prt_start)?;
    write_u16(out, base + 42, root.prt_count)?;
    write_u8(out, base + 44, root.osc_status as u8)?;
    write_u32(out, base + 48, root.osc_support)?;
    write_u32(out, base + 52, root.osc_requested_control)?;
    write_u32(out, base + 56, root.osc_granted_control)?;
    write_u32(out, base + 60, root.osc_error_flags)?;
    Ok(())
}

fn decode_root_v1(bytes: &[u8], base: usize) -> Result<RootBridge, Error> {
    let backend = ConfigBackend::from_raw(read_u8(bytes, base + 12)?).ok_or(Error::UnknownKind)?;
    if read_u8(bytes, base + 13)? != 0
        || read_u16(bytes, base + 18)? != 0
        || read_u64(bytes, base + 32)? != 0
    {
        return Err(Error::ReservedNonZero);
    }
    Ok(RootBridge {
        root_id: read_u64(bytes, base)?,
        segment: read_u16(bytes, base + 8)?,
        start_bus: read_u8(bytes, base + 10)?,
        end_bus: read_u8(bytes, base + 11)?,
        backend,
        flags: read_u32(bytes, base + 20)?,
        ecam_base: read_u64(bytes, base + 24)?,
        aperture_start: read_u16(bytes, base + 14)?,
        aperture_count: read_u16(bytes, base + 16)?,
        ..Default::default()
    })
}

fn decode_root_v2(bytes: &[u8], base: usize) -> Result<RootBridge, Error> {
    let backend = ConfigBackend::from_raw(read_u8(bytes, base + 12)?).ok_or(Error::UnknownKind)?;
    let osc_status = OscStatus::from_raw(read_u8(bytes, base + 44)?).ok_or(Error::UnknownKind)?;
    if read_u8(bytes, base + 13)? != 0
        || read_u16(bytes, base + 18)? != 0
        || read_u64(bytes, base + 32)? != 0
        || read_u8(bytes, base + 45)? != 0
        || read_u16(bytes, base + 46)? != 0
    {
        return Err(Error::ReservedNonZero);
    }
    Ok(RootBridge {
        root_id: read_u64(bytes, base)?,
        segment: read_u16(bytes, base + 8)?,
        start_bus: read_u8(bytes, base + 10)?,
        end_bus: read_u8(bytes, base + 11)?,
        backend,
        flags: read_u32(bytes, base + 20)?,
        ecam_base: read_u64(bytes, base + 24)?,
        aperture_start: read_u16(bytes, base + 14)?,
        aperture_count: read_u16(bytes, base + 16)?,
        prt_start: read_u16(bytes, base + 40)?,
        prt_count: read_u16(bytes, base + 42)?,
        osc_status,
        osc_support: read_u32(bytes, base + 48)?,
        osc_requested_control: read_u32(bytes, base + 52)?,
        osc_granted_control: read_u32(bytes, base + 56)?,
        osc_error_flags: read_u32(bytes, base + 60)?,
    })
}

fn encode_prt(entry: &PrtEntry, out: &mut [u8], base: usize) -> Result<(), Error> {
    write_u16(out, base, entry.root_index)?;
    write_u8(out, base + 2, entry.device)?;
    write_u8(out, base + 3, entry.pin)?;
    write_u32(out, base + 4, entry.gsi)?;
    write_u8(out, base + 8, entry.source_kind as u8)?;
    write_u8(out, base + 9, u8::from(entry.link_active))?;
    write_u8(out, base + 10, entry.triggering)?;
    write_u8(out, base + 11, entry.polarity)?;
    write_u32(out, base + 12, 0)?;
    Ok(())
}

fn decode_prt(bytes: &[u8], base: usize) -> Result<PrtEntry, Error> {
    let source_kind =
        PrtSourceKind::from_raw(read_u8(bytes, base + 8)?).ok_or(Error::UnknownKind)?;
    let link_active_raw = read_u8(bytes, base + 9)?;
    if link_active_raw > 1 || read_u32(bytes, base + 12)? != 0 {
        return Err(if link_active_raw > 1 {
            Error::InvalidPrt
        } else {
            Error::ReservedNonZero
        });
    }
    Ok(PrtEntry {
        root_index: read_u16(bytes, base)?,
        device: read_u8(bytes, base + 2)?,
        pin: read_u8(bytes, base + 3)?,
        gsi: read_u32(bytes, base + 4)?,
        source_kind,
        link_active: link_active_raw == 1,
        triggering: read_u8(bytes, base + 10)?,
        polarity: read_u8(bytes, base + 11)?,
    })
}

fn encode_aperture(aperture: &Aperture, out: &mut [u8], base: usize) -> Result<(), Error> {
    write_u16(out, base, aperture.root_index)?;
    write_u8(out, base + 2, aperture.kind as u8)?;
    write_u32(out, base + 4, aperture.flags)?;
    write_u64(out, base + 8, aperture.pci_base)?;
    write_u64(out, base + 16, aperture.cpu_base)?;
    write_u64(out, base + 24, aperture.len)?;
    Ok(())
}

fn decode_aperture(bytes: &[u8], base: usize) -> Result<Aperture, Error> {
    let kind = ApertureKind::from_raw(read_u8(bytes, base + 2)?).ok_or(Error::UnknownKind)?;
    if read_u8(bytes, base + 3)? != 0 {
        return Err(Error::ReservedNonZero);
    }
    Ok(Aperture {
        root_index: read_u16(bytes, base)?,
        kind,
        flags: read_u32(bytes, base + 4)?,
        pci_base: read_u64(bytes, base + 8)?,
        cpu_base: read_u64(bytes, base + 16)?,
        len: read_u64(bytes, base + 24)?,
    })
}

fn write_u8(out: &mut [u8], offset: usize, value: u8) -> Result<(), Error> {
    *out.get_mut(offset).ok_or(Error::BufferTooSmall)? = value;
    Ok(())
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) -> Result<(), Error> {
    out.get_mut(offset..offset + 2)
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) -> Result<(), Error> {
    out.get_mut(offset..offset + 4)
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) -> Result<(), Error> {
    out.get_mut(offset..offset + 8)
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, Error> {
    bytes.get(offset).copied().ok_or(Error::BadLength)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let slice = bytes.get(offset..offset + 2).ok_or(Error::BadLength)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let slice = bytes.get(offset..offset + 4).ok_or(Error::BadLength)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let slice = bytes.get(offset..offset + 8).ok_or(Error::BadLength)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RootBridgeTable {
        let mut table = RootBridgeTable::empty();
        assert!(table.push_root(RootBridge {
            root_id: 1,
            segment: 0,
            start_bus: 0,
            end_bus: 63,
            backend: ConfigBackend::Ecam,
            flags: ROOT_FLAG_HOTPLUG_CAPABLE | ROOT_FLAG_INTX_ROUTING,
            ecam_base: 0x8000_0000,
            aperture_start: 0,
            aperture_count: 2,
            prt_start: 0,
            prt_count: 2,
            osc_status: OscStatus::Granted,
            osc_support: OSC_SUPPORT_EXT_CFG | OSC_SUPPORT_MSI,
            osc_requested_control: OSC_CTRL_HOTPLUG | OSC_CTRL_AER,
            osc_granted_control: OSC_CTRL_HOTPLUG | OSC_CTRL_AER,
            osc_error_flags: 0,
        }));
        assert!(table.push_root(RootBridge {
            root_id: 2,
            segment: 0,
            start_bus: 64,
            end_bus: 127,
            backend: ConfigBackend::LegacyIo,
            flags: 0,
            ecam_base: 0,
            aperture_start: 2,
            aperture_count: 1,
            prt_start: 2,
            prt_count: 1,
            osc_status: OscStatus::NotPresent,
            ..Default::default()
        }));
        assert!(table.push_aperture(Aperture {
            root_index: 0,
            kind: ApertureKind::Mmio32,
            flags: 0,
            pci_base: 0x8000_0000,
            cpu_base: 0x8000_0000,
            len: 0x1000_0000,
        }));
        assert!(table.push_aperture(Aperture {
            root_index: 0,
            kind: ApertureKind::PrefetchableMemory,
            flags: APERTURE_FLAG_HOTPLUG_RESERVE,
            pci_base: 0x1_0000_0000,
            cpu_base: 0x2_0000_0000,
            len: 0x4000_0000,
        }));
        assert!(table.push_aperture(Aperture {
            root_index: 1,
            kind: ApertureKind::Io,
            flags: APERTURE_FLAG_FIXED,
            pci_base: 0x1000,
            cpu_base: 0x1000,
            len: 0x1000,
        }));
        assert!(table.push_prt(PrtEntry {
            root_index: 0,
            device: 1,
            pin: 0,
            gsi: 16,
            source_kind: PrtSourceKind::DirectGsi,
            link_active: true,
            triggering: 1,
            polarity: 1,
        }));
        assert!(table.push_prt(PrtEntry {
            root_index: 0,
            device: 2,
            pin: 1,
            gsi: 11,
            source_kind: PrtSourceKind::PciLinkDevice,
            link_active: true,
            triggering: 1,
            polarity: 1,
        }));
        assert!(table.push_prt(PrtEntry {
            root_index: 1,
            device: 0,
            pin: 0,
            gsi: 0,
            source_kind: PrtSourceKind::UnresolvedLink,
            link_active: false,
            triggering: 1,
            polarity: 1,
        }));
        table
    }

    fn encoded_sample() -> (RootBridgeTable, [u8; MAX_ENCODED_BYTES], usize) {
        let table = sample();
        let mut bytes = [0u8; MAX_ENCODED_BYTES];
        let len = match encode(&table, &mut bytes) {
            Ok(len) => len,
            Err(_) => 0,
        };
        (table, bytes, len)
    }

    #[test]
    fn root_table_round_trips_translation_and_backend() {
        let (table, bytes, len) = encoded_sample();
        assert!(len > HEADER_BYTES);
        assert_eq!(decode(&bytes[..len]), Ok(table));
        assert_eq!(table.apertures[1].pci_base, 0x1_0000_0000);
        assert_eq!(table.apertures[1].cpu_base, 0x2_0000_0000);
    }

    #[test]
    fn encode_rejects_small_output() {
        let table = sample();
        let mut bytes = [0u8; HEADER_BYTES];
        assert_eq!(encode(&table, &mut bytes), Err(Error::BufferTooSmall));
    }

    #[test]
    fn decode_rejects_header_size_count_and_reserved_errors() {
        let (_, bytes, len) = encoded_sample();

        let mut bad_magic = bytes;
        bad_magic[0] = 0;
        assert_eq!(decode(&bad_magic[..len]), Err(Error::BadHeader));

        let mut bad_size = bytes;
        bad_size[8..10].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode(&bad_size[..len]), Err(Error::BadLength));

        assert_eq!(decode(&bytes[..len - 1]), Err(Error::BadLength));

        let mut reserved = bytes;
        reserved[20] = 1;
        assert_eq!(decode(&reserved[..len]), Err(Error::ReservedNonZero));
    }

    #[test]
    fn validate_rejects_noncanonical_aperture_ownership() {
        let mut table = sample();
        table.roots[1].aperture_start = 1;
        assert_eq!(validate(&table), Err(Error::InvalidAperture));

        let mut table = sample();
        table.apertures[2].root_index = 0;
        assert_eq!(validate(&table), Err(Error::InvalidAperture));
    }

    #[test]
    fn validate_rejects_invalid_root_backend_geometry() {
        let mut table = sample();
        table.roots[1].segment = 1;
        assert_eq!(validate(&table), Err(Error::InvalidRoot));

        let mut table = sample();
        table.roots[0].ecam_base = 0x8000_1000;
        assert_eq!(validate(&table), Err(Error::InvalidRoot));
    }

    #[test]
    fn validate_rejects_aperture_wrap_and_mmio32_above_four_gib() {
        let mut table = sample();
        table.apertures[0].pci_base = u64::MAX;
        assert_eq!(validate(&table), Err(Error::InvalidAperture));

        let mut table = sample();
        table.apertures[0].pci_base = 0xffff_f000;
        table.apertures[0].cpu_base = 0xffff_f000;
        table.apertures[0].len = 0x2000;
        assert_eq!(validate(&table), Err(Error::InvalidAperture));
    }

    #[test]
    fn decode_rejects_unknown_kinds_and_flags() {
        let (_, bytes, len) = encoded_sample();
        let mut backend = bytes;
        backend[HEADER_BYTES + 12] = 0xff;
        assert_eq!(decode(&backend[..len]), Err(Error::UnknownKind));

        let roots_bytes = 2 * ROOT_ENTRY_BYTES;
        let aperture_base = HEADER_BYTES + roots_bytes;
        let mut kind = bytes;
        kind[aperture_base + 2] = 0xff;
        assert_eq!(decode(&kind[..len]), Err(Error::UnknownKind));

        let mut flags = bytes;
        flags[aperture_base + 4..aperture_base + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&flags[..len]), Err(Error::UnknownFlags));
    }

    fn encode_test_hmcf(
        records: &[crate::hmcf::HmcfRecord],
    ) -> ([u8; crate::hmcf::MAX_BYTES], usize) {
        let mut buf = [0u8; crate::hmcf::MAX_BYTES];
        let ok = crate::hmcf::encode(1, 1, records, &mut buf).is_ok();
        assert!(ok);
        let declared = match crate::hmcf::declared_size(&buf) {
            Ok(sz) => sz,
            Err(_) => 0,
        };
        assert!(declared > 0);
        (buf, declared)
    }

    #[test]
    fn validate_roots_and_hmcf_checks_coverage_overlaps_and_ecam() {
        let rec_res = crate::hmcf::HmcfRecord::new(0, 0, 255, 0xb000_0000);
        assert!(rec_res.is_ok());
        let Ok(rec) = rec_res else {
            return;
        };
        let (buf, declared) = encode_test_hmcf(&[rec]);
        let hmcf_res = crate::hmcf::decode(&buf[..declared]);
        assert!(hmcf_res.is_ok());
        let Ok(hmcf) = hmcf_res else {
            return;
        };

        let mut table = RootBridgeTable::empty();
        assert!(table.push_root(RootBridge {
            root_id: 10,
            segment: 0,
            start_bus: 0,
            end_bus: 63,
            backend: ConfigBackend::Ecam,
            flags: 0,
            ecam_base: 0xb000_0000,
            aperture_start: 0,
            aperture_count: 1,
            ..Default::default()
        }));
        assert!(table.push_root(RootBridge {
            root_id: 20,
            segment: 0,
            start_bus: 64,
            end_bus: 127,
            backend: ConfigBackend::Ecam,
            flags: 0,
            ecam_base: 0xb000_0000 + (64u64 << 20),
            aperture_start: 1,
            aperture_count: 1,
            ..Default::default()
        }));
        assert!(table.push_aperture(Aperture {
            root_index: 0,
            kind: ApertureKind::Mmio32,
            flags: 0,
            pci_base: 0x8000_0000,
            cpu_base: 0x8000_0000,
            len: 0x1000_0000,
        }));
        assert!(table.push_aperture(Aperture {
            root_index: 1,
            kind: ApertureKind::Io,
            flags: 0,
            pci_base: 0xc000,
            cpu_base: 0xc000,
            len: 0x1000,
        }));
        assert_eq!(validate_roots_and_hmcf(&table, &hmcf), Ok(()));

        // Overlapping root bus range fails.
        let mut overlap = table;
        overlap.roots[1].start_bus = 63;
        overlap.roots[1].ecam_base = 0xb000_0000 + (63u64 << 20);
        assert_eq!(
            validate_roots_and_hmcf(&overlap, &hmcf),
            Err(ConsistencyError::OverlappingRoots)
        );

        // ECAM mismatch fails.
        let mut mismatch = table;
        mismatch.roots[1].ecam_base = 0xb000_0000;
        assert_eq!(
            validate_roots_and_hmcf(&mismatch, &hmcf),
            Err(ConsistencyError::EcamMismatch)
        );

        // Root outside HMCF fails.
        let mut uncovered = table;
        uncovered.roots[1].segment = 1;
        assert_eq!(
            validate_roots_and_hmcf(&uncovered, &hmcf),
            Err(ConsistencyError::MissingHmcfCoverage)
        );

        // Aperture overlapping MCFG/HMCF ECAM window fails.
        let mut ecam_overlap = table;
        ecam_overlap.apertures[0].cpu_base = 0xb000_0000;
        ecam_overlap.apertures[0].pci_base = 0xb000_0000;
        assert_eq!(
            validate_roots_and_hmcf(&ecam_overlap, &hmcf),
            Err(ConsistencyError::ApertureOverlapsEcam)
        );

        // Crossing/overlapping apertures across roots fail.
        let mut ap_overlap = table;
        ap_overlap.apertures[1].kind = ApertureKind::Mmio32;
        ap_overlap.apertures[1].pci_base = 0x8800_0000;
        ap_overlap.apertures[1].cpu_base = 0x8800_0000;
        assert_eq!(
            validate_roots_and_hmcf(&ap_overlap, &hmcf),
            Err(ConsistencyError::OverlappingApertures)
        );
    }

    #[test]
    fn v1_backward_decode_and_v2_prt_osc_validation() {
        let mut v1_table = RootBridgeTable::empty();
        assert!(v1_table.push_root(RootBridge {
            root_id: 7,
            segment: 0,
            start_bus: 0,
            end_bus: 31,
            backend: ConfigBackend::Ecam,
            flags: ROOT_FLAG_INTX_ROUTING,
            ecam_base: 0xb000_0000,
            aperture_start: 0,
            aperture_count: 1,
            ..Default::default()
        }));
        assert!(v1_table.push_aperture(Aperture {
            root_index: 0,
            kind: ApertureKind::Io,
            flags: 0,
            pci_base: 0xc000,
            cpu_base: 0xc000,
            len: 0x1000,
        }));
        let mut buf = [0u8; MAX_ENCODED_BYTES];
        let v1_len = match encode_v1(&v1_table, &mut buf) {
            Ok(len) => len,
            Err(_) => 0,
        };
        assert_eq!(decode(&buf[..v1_len]), Ok(v1_table));

        let mut bad_prt = sample();
        bad_prt.prt_entries[0].pin = 4;
        assert_eq!(validate(&bad_prt), Err(Error::InvalidPrt));

        let mut bad_unresolved = sample();
        bad_unresolved.prt_entries[2].gsi = 9;
        assert_eq!(validate(&bad_unresolved), Err(Error::InvalidPrt));

        let mut bad_osc = sample();
        bad_osc.roots[1].osc_status = OscStatus::NotPresent;
        bad_osc.roots[1].osc_error_flags = OSC_ERR_MASKED;
        assert_eq!(validate(&bad_osc), Err(Error::InvalidOsc));
    }
}
