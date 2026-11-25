//! Immutable zero-bus-traffic PCI inventory snapshot (`HPIN`, Stage D.3).
//!
//! `pci-manager` encodes its discovered PCI topology, function identities,
//! capability flags, BAR/window assignments, validation statuses, interrupt
//! selections, DMA isolation profiles, lease states, and IOMMU summary into a
//! read-only `HPIN` VMO and transfers a handle to `DriverManager`.
//!
//! Inventory consumers (`DriverManager` `query:pci` and `/bin/pci.elf`) read
//! only this immutable VMO and generate **zero** PCI configuration-bus traffic.

use crate::pci::ConfigBackend;
use crate::pci_iommu::{IommuDiscoveryStatus, IommuHardwareKind, IommuMode};

/// Wire magic: ASCII `HPIN`.
pub const MAGIC: [u8; 4] = *b"HPIN";
/// Current wire format version.
pub const VERSION: u16 = 1;
/// Fixed header size in bytes.
pub const HEADER_BYTES: usize = 56;
/// Fixed per-BAR/window slot size in bytes.
pub const BAR_SLOT_BYTES: usize = 20;
/// Number of BAR/window slots stored per function record (`BAR0..BAR5` or bridge windows).
pub const BAR_SLOTS_PER_FUNCTION: usize = 6;
/// Fixed per-function record size in bytes (`48 + 6 * 20 = 168`).
pub const RECORD_BYTES: usize = 48 + BAR_SLOTS_PER_FUNCTION * BAR_SLOT_BYTES;
/// Maximum PCI functions stored in one `HPIN` snapshot.
pub const MAX_FUNCTIONS: usize = 64;
/// Maximum encoded `HPIN` byte length (`56 + 64 * 168 = 10,808` bytes).
pub const MAX_BYTES: usize = HEADER_BYTES + MAX_FUNCTIONS * RECORD_BYTES;

/// Snapshot flag: live BAR sizing and firmware resource validation have run.
pub const INVENTORY_FLAG_LIVE_SIZED: u32 = 1 << 0;
/// Snapshot flag: driver binding and lease resource handoff have run.
pub const INVENTORY_FLAG_BINDING_COMPLETE: u32 = 1 << 1;
/// Snapshot flag: ACPI runtime is frozen; snapshot is retained last-good state.
pub const INVENTORY_FLAG_FROZEN: u32 = 1 << 2;
/// Known snapshot flags in v1.
pub const INVENTORY_FLAGS_V1: u32 =
    INVENTORY_FLAG_LIVE_SIZED | INVENTORY_FLAG_BINDING_COMPLETE | INVENTORY_FLAG_FROZEN;

/// Capability bit: PCI Express capability (`0x10`).
pub const CAP_FLAG_PCIE: u16 = 1 << 0;
/// Capability bit: MSI capability (`0x05`).
pub const CAP_FLAG_MSI: u16 = 1 << 1;
/// Capability bit: MSI-X capability (`0x11`).
pub const CAP_FLAG_MSIX: u16 = 1 << 2;
/// Capability bit: PCI Power Management capability (`0x01`).
pub const CAP_FLAG_PM: u16 = 1 << 3;
/// Capability bit: Vendor-specific capability (`0x09`, e.g. VirtIO modern).
pub const CAP_FLAG_VENDOR: u16 = 1 << 4;
/// Capability bit: PCIe Advanced Error Reporting extended capability (`0x0001`).
pub const CAP_FLAG_AER: u16 = 1 << 5;
/// Capability bit: PCIe Slot / Bridge hotplug capable.
pub const CAP_FLAG_HOTPLUG: u16 = 1 << 6;

const CHECKSUM_OFFSET: usize = 48;

/// Topology parent kind for one discovered function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InventoryParentKind {
    /// Direct child of an ACPI `HPCI` host bridge root.
    Root = 0,
    /// Downstream child of a Type-1 PCI-to-PCI bridge.
    Bridge = 1,
}

impl InventoryParentKind {
    /// Convert raw byte to [`InventoryParentKind`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Root),
            1 => Some(Self::Bridge),
            _ => None,
        }
    }
}

/// Selected interrupt delivery mode recorded in the inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InventoryIrqMode {
    /// Unbound or no interrupt configured.
    None = 0,
    /// ACPI `_PRT` legacy INTx GSI.
    Intx = 1,
    /// Message Signaled Interrupts (MSI).
    Msi = 2,
    /// Extended Message Signaled Interrupts (MSI-X).
    Msix = 3,
    /// Approved timer/completion polling mode.
    Polling = 4,
}

impl InventoryIrqMode {
    /// Convert raw byte to [`InventoryIrqMode`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Intx),
            2 => Some(Self::Msi),
            3 => Some(Self::Msix),
            4 => Some(Self::Polling),
            _ => None,
        }
    }

    /// Short canonical label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Intx => "intx",
            Self::Msi => "msi",
            Self::Msix => "msix",
            Self::Polling => "polling",
        }
    }
}

/// Per-function kernel/policy lease state in the published inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InventoryLeaseState {
    /// Visible diagnostically, no lease minted.
    Unbound = 0,
    /// Kernel `DeviceLease` minted, no driver bound.
    Leased = 1,
    /// Bound to a DriverHost / service with narrow resources handed off.
    BoundOnline = 2,
    /// Lease generation explicitly revoked.
    Revoked = 3,
    /// Function failed validation, commit, or recovery.
    Failed = 4,
}

impl InventoryLeaseState {
    /// Convert raw byte to [`InventoryLeaseState`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unbound),
            1 => Some(Self::Leased),
            2 => Some(Self::BoundOnline),
            3 => Some(Self::Revoked),
            4 => Some(Self::Failed),
            _ => None,
        }
    }

    /// Short canonical label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unbound => "unbound",
            Self::Leased => "leased",
            Self::BoundOnline => "bound-online",
            Self::Revoked => "revoked",
            Self::Failed => "failed",
        }
    }
}

/// Relocation policy class advertised for a function (Stage L.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InventoryRelocationClass {
    /// Never moved while system is running (default; mandatory for system NVMe).
    Fixed = 0,
    /// Relocatable only through transactional DriverHost stop/revoke/restart.
    Restart = 1,
    /// Relocatable through deadline-bounded `QuiesceRemap` protocol.
    QuiesceRemap = 2,
}

impl InventoryRelocationClass {
    /// Convert raw byte to [`InventoryRelocationClass`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Fixed),
            1 => Some(Self::Restart),
            2 => Some(Self::QuiesceRemap),
            _ => None,
        }
    }

    /// Short canonical label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Restart => "restart",
            Self::QuiesceRemap => "quiesce-remap",
        }
    }
}

/// Address-space kind of one BAR/bridge-window slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InventoryBarClass {
    /// Unused / unimplemented BAR slot.
    Unused = 0,
    /// Legacy 16/32-bit I/O port BAR or bridge I/O window.
    Io = 1,
    /// Non-prefetchable 32-bit MMIO BAR or bridge memory window.
    Mmio32 = 2,
    /// Non-prefetchable 64-bit MMIO BAR.
    Mmio64 = 3,
    /// Prefetchable 32/64-bit MMIO BAR or bridge prefetchable window.
    Prefetchable = 4,
}

impl InventoryBarClass {
    /// Convert raw byte to [`InventoryBarClass`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unused),
            1 => Some(Self::Io),
            2 => Some(Self::Mmio32),
            3 => Some(Self::Mmio64),
            4 => Some(Self::Prefetchable),
            _ => None,
        }
    }

    /// Short canonical label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unused => "-",
            Self::Io => "io",
            Self::Mmio32 => "mmio32",
            Self::Mmio64 => "mmio64",
            Self::Prefetchable => "pref64",
        }
    }
}

/// Firmware/planner validation finding for one BAR/window slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InventoryBarStatus {
    /// Slot is unused.
    None = 0,
    /// Valid firmware/planned assignment within root/bridge apertures.
    Valid = 1,
    /// Valid fixed assignment that must never move.
    Fixed = 2,
    /// Implemented BAR/window that is currently unassigned (`base == 0`).
    Unassigned = 3,
    /// Overlaps a sibling resource or reserved region.
    Conflicting = 4,
    /// Lies outside declared root/parent apertures.
    Unrouteable = 5,
    /// Malformed or unsupported register encoding.
    Unsupported = 6,
}

impl InventoryBarStatus {
    /// Convert raw byte to [`InventoryBarStatus`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Valid),
            2 => Some(Self::Fixed),
            3 => Some(Self::Unassigned),
            4 => Some(Self::Conflicting),
            5 => Some(Self::Unrouteable),
            6 => Some(Self::Unsupported),
            _ => None,
        }
    }

    /// Short canonical label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Valid => "valid",
            Self::Fixed => "fixed",
            Self::Unassigned => "unassigned",
            Self::Conflicting => "conflicting",
            Self::Unrouteable => "unrouteable",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One BAR or bridge-window slot recorded on a function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciInventoryBar {
    /// CPU-translated base address (or raw PCI address when unrouteable).
    pub base: u64,
    /// Size in bytes (`0` when unused).
    pub len: u64,
    /// Resource address-space class.
    pub class: InventoryBarClass,
    /// Validation finding.
    pub status: InventoryBarStatus,
}

impl PciInventoryBar {
    /// Unused empty BAR slot.
    pub const EMPTY: Self = Self {
        base: 0,
        len: 0,
        class: InventoryBarClass::Unused,
        status: InventoryBarStatus::None,
    };
}

/// Decoded header of an `HPIN` PCI inventory snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciInventoryHeader {
    /// Non-zero archive-v2 firmware snapshot ID.
    pub firmware_snapshot_id: u64,
    /// Non-zero `pci-manager` generation that produced this image.
    pub manager_generation: u64,
    /// Non-zero topology snapshot generation.
    pub topology_generation: u64,
    /// Active PCI configuration transport backend.
    pub backend: ConfigBackend,
    /// Discovered IOMMU hardware kind.
    pub iommu_hw: IommuHardwareKind,
    /// Firmware IOMMU table validation status.
    pub iommu_status: IommuDiscoveryStatus,
    /// Active DMA isolation mode across leases.
    pub active_dma_isolation: IommuMode,
    /// Number of validated hardware IOMMU units.
    pub iommu_unit_count: u8,
    /// `pci_iommu::FLAG_*` interrupt-remapping / opt-out summary bits.
    pub iommu_flags: u8,
    /// Number of function records in the image (`0..=MAX_FUNCTIONS`).
    pub function_count: u16,
    /// `INVENTORY_FLAG_*` bitmask.
    pub flags: u32,
}

/// One discovered PCI function in an `HPIN` snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciInventoryRecord {
    /// PCI segment group.
    pub segment: u16,
    /// PCI bus number.
    pub bus: u8,
    /// PCI device number (`0..32`).
    pub device: u8,
    /// PCI function number (`0..8`).
    pub function: u8,
    /// Bridge hierarchy depth (`0` for root-bus devices).
    pub depth: u8,
    /// Direct parent kind (`Root` or `Bridge`).
    pub parent_kind: InventoryParentKind,
    /// Parent bridge bus (`0` if `Root`).
    pub parent_bus: u8,
    /// Parent bridge device (`0` if `Root`).
    pub parent_device: u8,
    /// Parent bridge function (`0` if `Root`).
    pub parent_function: u8,
    /// PCI Vendor ID.
    pub vendor_id: u16,
    /// PCI Device ID.
    pub device_id: u16,
    /// Base class code.
    pub class_code: u8,
    /// Sub-class code.
    pub subclass: u8,
    /// Programming interface byte.
    pub prog_if: u8,
    /// Silicon revision ID.
    pub revision_id: u8,
    /// Header layout (`0` = endpoint, `1` = PCI-to-PCI bridge).
    pub header_type: u8,
    /// Bridge secondary bus (`0` for endpoints).
    pub secondary_bus: u8,
    /// Bridge subordinate bus (`0` for endpoints).
    pub subordinate_bus: u8,
    /// `true` when firmware root apertures cover this function.
    pub firmware_available: bool,
    /// Selected interrupt mode.
    pub irq_mode: InventoryIrqMode,
    /// Effective per-lease DMA isolation mode.
    pub dma_isolation: IommuMode,
    /// Allocated CPU vector base or legacy GSI (`0` if `None`/`Polling`).
    pub irq_vector_or_gsi: u16,
    /// Current lease/binding state.
    pub lease_state: InventoryLeaseState,
    /// Relocation classification.
    pub relocation_class: InventoryRelocationClass,
    /// `CAP_FLAG_*` summary bitmask.
    pub cap_flags: u16,
    /// Owning `HPCI` host-bridge `root_id`.
    pub root_id: u64,
    /// Decoded BARs (`0..6`) or bridge windows (`0..3`).
    pub bars: [PciInventoryBar; BAR_SLOTS_PER_FUNCTION],
}

/// Wire format error for `HPIN`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryWireError {
    /// Input or output slice shorter than required.
    BufferTooSmall,
    /// Magic bytes do not match `HPIN`.
    BadMagic,
    /// Unsupported wire format version.
    UnsupportedVersion,
    /// Header/record layout, counts, or reserved bytes invalid.
    InvalidLayout,
    /// Wrapping checksum mismatch.
    BadChecksum,
    /// Zero snapshot/generation identity.
    MissingIdentity,
    /// Invalid field value or BDF out of range.
    InvalidRecord,
}

/// Human-readable short PCI class description for CLI and diagnostics.
pub const fn class_short_name(class_code: u8, subclass: u8, prog_if: u8) -> &'static str {
    match (class_code, subclass, prog_if) {
        (0x01, 0x08, _) => "nvme",
        (0x01, 0x06, _) => "sata-ahci",
        (0x01, _, _) => "storage",
        (0x02, 0x00, _) => "ethernet",
        (0x02, 0x80, _) => "wlan-net",
        (0x02, _, _) => "network",
        (0x03, 0x00, _) => "vga",
        (0x03, _, _) => "display",
        (0x04, 0x03, _) => "hda-audio",
        (0x06, 0x00, _) => "host-bridge",
        (0x06, 0x01, _) => "isa-bridge",
        (0x06, 0x04, _) => "pci-bridge",
        (0x06, _, _) => "bridge",
        (0x0c, 0x03, 0x30) => "xhci-usb",
        (0x0c, 0x03, _) => "usb",
        (0x0c, 0x05, _) => "smbus",
        _ => "pci-dev",
    }
}

/// Return declared total byte length from an `HPIN` header prefix.
pub fn declared_size(header: &[u8]) -> Result<usize, InventoryWireError> {
    if header.len() < HEADER_BYTES {
        return Err(InventoryWireError::BufferTooSmall);
    }
    if header[0..4] != MAGIC {
        return Err(InventoryWireError::BadMagic);
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != VERSION {
        return Err(InventoryWireError::UnsupportedVersion);
    }
    let hdr_len = u16::from_le_bytes([header[6], header[7]]) as usize;
    if hdr_len != HEADER_BYTES {
        return Err(InventoryWireError::InvalidLayout);
    }
    let total = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let fn_count = u16::from_le_bytes([header[42], header[43]]) as usize;
    if fn_count > MAX_FUNCTIONS {
        return Err(InventoryWireError::InvalidLayout);
    }
    let expected = HEADER_BYTES + fn_count * RECORD_BYTES;
    if total != expected || total > MAX_BYTES {
        return Err(InventoryWireError::InvalidLayout);
    }
    Ok(total)
}

/// Encode `header` and `records` into `out`, returning total encoded bytes.
pub fn encode(
    header: &PciInventoryHeader,
    records: &[PciInventoryRecord],
    out: &mut [u8],
) -> Result<usize, InventoryWireError> {
    if header.firmware_snapshot_id == 0
        || header.manager_generation == 0
        || header.topology_generation == 0
    {
        return Err(InventoryWireError::MissingIdentity);
    }
    if records.len() > MAX_FUNCTIONS || usize::from(header.function_count) != records.len() {
        return Err(InventoryWireError::InvalidLayout);
    }
    if (header.flags & !INVENTORY_FLAGS_V1) != 0 {
        return Err(InventoryWireError::InvalidLayout);
    }
    let total = HEADER_BYTES + records.len() * RECORD_BYTES;
    if out.len() < total {
        return Err(InventoryWireError::BufferTooSmall);
    }
    out[..total].fill(0);
    out[0..4].copy_from_slice(&MAGIC);
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    out[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    out[12..20].copy_from_slice(&header.firmware_snapshot_id.to_le_bytes());
    out[20..28].copy_from_slice(&header.manager_generation.to_le_bytes());
    out[28..36].copy_from_slice(&header.topology_generation.to_le_bytes());
    out[36] = match header.backend {
        ConfigBackend::Ecam => 1,
        ConfigBackend::LegacyIo => 2,
    };
    out[37] = header.iommu_hw as u8;
    out[38] = header.iommu_status as u8;
    out[39] = header.active_dma_isolation as u8;
    out[40] = header.iommu_unit_count;
    out[41] = header.iommu_flags;
    out[42..44].copy_from_slice(&header.function_count.to_le_bytes());
    out[44..48].copy_from_slice(&header.flags.to_le_bytes());

    let mut cursor = HEADER_BYTES;
    for rec in records {
        if rec.device >= 32
            || rec.function >= 8
            || rec.parent_device >= 32
            || rec.parent_function >= 8
            || rec.header_type > 1
        {
            return Err(InventoryWireError::InvalidRecord);
        }
        out[cursor..cursor + 2].copy_from_slice(&rec.segment.to_le_bytes());
        out[cursor + 2] = rec.bus;
        out[cursor + 3] = rec.device;
        out[cursor + 4] = rec.function;
        out[cursor + 5] = rec.depth;
        out[cursor + 6] = rec.parent_kind as u8;
        out[cursor + 7] = rec.parent_bus;
        out[cursor + 8] = rec.parent_device;
        out[cursor + 9] = rec.parent_function;
        out[cursor + 10..cursor + 12].copy_from_slice(&rec.vendor_id.to_le_bytes());
        out[cursor + 12..cursor + 14].copy_from_slice(&rec.device_id.to_le_bytes());
        out[cursor + 14] = rec.class_code;
        out[cursor + 15] = rec.subclass;
        out[cursor + 16] = rec.prog_if;
        out[cursor + 17] = rec.revision_id;
        out[cursor + 18] = rec.header_type;
        out[cursor + 19] = rec.secondary_bus;
        out[cursor + 20] = rec.subordinate_bus;
        out[cursor + 21] = u8::from(rec.firmware_available);
        out[cursor + 22] = rec.irq_mode as u8;
        out[cursor + 23] = rec.dma_isolation as u8;
        out[cursor + 24..cursor + 26].copy_from_slice(&rec.irq_vector_or_gsi.to_le_bytes());
        out[cursor + 26] = rec.lease_state as u8;
        out[cursor + 27] = rec.relocation_class as u8;
        out[cursor + 28..cursor + 30].copy_from_slice(&rec.cap_flags.to_le_bytes());
        out[cursor + 32..cursor + 40].copy_from_slice(&rec.root_id.to_le_bytes());

        let mut bar_off = cursor + 48;
        for bar in &rec.bars {
            out[bar_off..bar_off + 8].copy_from_slice(&bar.base.to_le_bytes());
            out[bar_off + 8..bar_off + 16].copy_from_slice(&bar.len.to_le_bytes());
            out[bar_off + 16] = bar.class as u8;
            out[bar_off + 17] = bar.status as u8;
            bar_off += BAR_SLOT_BYTES;
        }
        cursor += RECORD_BYTES;
    }

    let csum = compute_checksum(&out[..total]);
    out[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&csum.to_le_bytes());
    Ok(total)
}

/// Validate a complete `HPIN` image and return its decoded header.
pub fn validate_and_decode_header(bytes: &[u8]) -> Result<PciInventoryHeader, InventoryWireError> {
    let total = declared_size(bytes)?;
    if bytes.len() < total {
        return Err(InventoryWireError::BufferTooSmall);
    }
    let slice = &bytes[..total];
    if slice[52..56] != [0u8; 4] {
        return Err(InventoryWireError::InvalidLayout);
    }
    let stored_csum = u32::from_le_bytes([
        slice[CHECKSUM_OFFSET],
        slice[CHECKSUM_OFFSET + 1],
        slice[CHECKSUM_OFFSET + 2],
        slice[CHECKSUM_OFFSET + 3],
    ]);
    if stored_csum != compute_checksum(slice) {
        return Err(InventoryWireError::BadChecksum);
    }

    let firmware_snapshot_id = u64::from_le_bytes([
        slice[12], slice[13], slice[14], slice[15], slice[16], slice[17], slice[18], slice[19],
    ]);
    let manager_generation = u64::from_le_bytes([
        slice[20], slice[21], slice[22], slice[23], slice[24], slice[25], slice[26], slice[27],
    ]);
    let topology_generation = u64::from_le_bytes([
        slice[28], slice[29], slice[30], slice[31], slice[32], slice[33], slice[34], slice[35],
    ]);
    if firmware_snapshot_id == 0 || manager_generation == 0 || topology_generation == 0 {
        return Err(InventoryWireError::MissingIdentity);
    }
    let backend = match slice[36] {
        1 => ConfigBackend::Ecam,
        2 => ConfigBackend::LegacyIo,
        _ => return Err(InventoryWireError::InvalidLayout),
    };
    let iommu_hw =
        IommuHardwareKind::from_raw(slice[37]).ok_or(InventoryWireError::InvalidLayout)?;
    let iommu_status =
        IommuDiscoveryStatus::from_raw(slice[38]).ok_or(InventoryWireError::InvalidLayout)?;
    let active_dma_isolation =
        IommuMode::from_raw(slice[39]).ok_or(InventoryWireError::InvalidLayout)?;
    let iommu_unit_count = slice[40];
    let iommu_flags = slice[41];
    let function_count = u16::from_le_bytes([slice[42], slice[43]]);
    let flags = u32::from_le_bytes([slice[44], slice[45], slice[46], slice[47]]);
    if (flags & !INVENTORY_FLAGS_V1) != 0 {
        return Err(InventoryWireError::InvalidLayout);
    }

    for idx in 0..usize::from(function_count) {
        let _ = decode_record(slice, idx)?;
    }

    Ok(PciInventoryHeader {
        firmware_snapshot_id,
        manager_generation,
        topology_generation,
        backend,
        iommu_hw,
        iommu_status,
        active_dma_isolation,
        iommu_unit_count,
        iommu_flags,
        function_count,
        flags,
    })
}

/// Decode the `index`-th function record from a validated `HPIN` image.
pub fn decode_record(bytes: &[u8], index: usize) -> Result<PciInventoryRecord, InventoryWireError> {
    let total = declared_size(bytes)?;
    if bytes.len() < total {
        return Err(InventoryWireError::BufferTooSmall);
    }
    let fn_count = u16::from_le_bytes([bytes[42], bytes[43]]) as usize;
    if index >= fn_count {
        return Err(InventoryWireError::InvalidLayout);
    }
    let cursor = HEADER_BYTES + index * RECORD_BYTES;
    let rec = &bytes[cursor..cursor + RECORD_BYTES];
    if rec[30..32] != [0u8; 2] || rec[40..48] != [0u8; 8] {
        return Err(InventoryWireError::InvalidLayout);
    }

    let segment = u16::from_le_bytes([rec[0], rec[1]]);
    let bus = rec[2];
    let device = rec[3];
    let function = rec[4];
    let depth = rec[5];
    let parent_kind =
        InventoryParentKind::from_raw(rec[6]).ok_or(InventoryWireError::InvalidRecord)?;
    let parent_bus = rec[7];
    let parent_device = rec[8];
    let parent_function = rec[9];
    if device >= 32 || function >= 8 || parent_device >= 32 || parent_function >= 8 {
        return Err(InventoryWireError::InvalidRecord);
    }
    let vendor_id = u16::from_le_bytes([rec[10], rec[11]]);
    let device_id = u16::from_le_bytes([rec[12], rec[13]]);
    let class_code = rec[14];
    let subclass = rec[15];
    let prog_if = rec[16];
    let revision_id = rec[17];
    let header_type = rec[18];
    if header_type > 1 {
        return Err(InventoryWireError::InvalidRecord);
    }
    let secondary_bus = rec[19];
    let subordinate_bus = rec[20];
    let firmware_available = match rec[21] {
        0 => false,
        1 => true,
        _ => return Err(InventoryWireError::InvalidRecord),
    };
    let irq_mode = InventoryIrqMode::from_raw(rec[22]).ok_or(InventoryWireError::InvalidRecord)?;
    let dma_isolation = IommuMode::from_raw(rec[23]).ok_or(InventoryWireError::InvalidRecord)?;
    let irq_vector_or_gsi = u16::from_le_bytes([rec[24], rec[25]]);
    let lease_state =
        InventoryLeaseState::from_raw(rec[26]).ok_or(InventoryWireError::InvalidRecord)?;
    let relocation_class =
        InventoryRelocationClass::from_raw(rec[27]).ok_or(InventoryWireError::InvalidRecord)?;
    let cap_flags = u16::from_le_bytes([rec[28], rec[29]]);
    let root_id = u64::from_le_bytes([
        rec[32], rec[33], rec[34], rec[35], rec[36], rec[37], rec[38], rec[39],
    ]);

    let mut bars = [PciInventoryBar::EMPTY; BAR_SLOTS_PER_FUNCTION];
    for (b_idx, slot) in bars.iter_mut().enumerate() {
        let boff = 48 + b_idx * BAR_SLOT_BYTES;
        if rec[boff + 18..boff + 20] != [0u8; 2] {
            return Err(InventoryWireError::InvalidLayout);
        }
        let base = u64::from_le_bytes([
            rec[boff],
            rec[boff + 1],
            rec[boff + 2],
            rec[boff + 3],
            rec[boff + 4],
            rec[boff + 5],
            rec[boff + 6],
            rec[boff + 7],
        ]);
        let len = u64::from_le_bytes([
            rec[boff + 8],
            rec[boff + 9],
            rec[boff + 10],
            rec[boff + 11],
            rec[boff + 12],
            rec[boff + 13],
            rec[boff + 14],
            rec[boff + 15],
        ]);
        let class =
            InventoryBarClass::from_raw(rec[boff + 16]).ok_or(InventoryWireError::InvalidRecord)?;
        let status = InventoryBarStatus::from_raw(rec[boff + 17])
            .ok_or(InventoryWireError::InvalidRecord)?;
        *slot = PciInventoryBar {
            base,
            len,
            class,
            status,
        };
    }

    Ok(PciInventoryRecord {
        segment,
        bus,
        device,
        function,
        depth,
        parent_kind,
        parent_bus,
        parent_device,
        parent_function,
        vendor_id,
        device_id,
        class_code,
        subclass,
        prog_if,
        revision_id,
        header_type,
        secondary_bus,
        subordinate_bus,
        firmware_available,
        irq_mode,
        dma_isolation,
        irq_vector_or_gsi,
        lease_state,
        relocation_class,
        cap_flags,
        root_id,
        bars,
    })
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
    fn encode_decode_hpin_roundtrip_and_checksum_tamper_rejection() {
        let hdr = PciInventoryHeader {
            firmware_snapshot_id: 0x1234,
            manager_generation: 2,
            topology_generation: 1,
            backend: ConfigBackend::Ecam,
            iommu_hw: IommuHardwareKind::None,
            iommu_status: IommuDiscoveryStatus::Absent,
            active_dma_isolation: IommuMode::Trusted,
            iommu_unit_count: 0,
            iommu_flags: 0,
            function_count: 1,
            flags: INVENTORY_FLAG_LIVE_SIZED | INVENTORY_FLAG_BINDING_COMPLETE,
        };
        let mut bars = [PciInventoryBar::EMPTY; BAR_SLOTS_PER_FUNCTION];
        bars[0] = PciInventoryBar {
            base: 0xFEBF_0000,
            len: 0x4000,
            class: InventoryBarClass::Mmio64,
            status: InventoryBarStatus::Fixed,
        };
        let rec = PciInventoryRecord {
            segment: 0,
            bus: 1,
            device: 0,
            function: 0,
            depth: 1,
            parent_kind: InventoryParentKind::Bridge,
            parent_bus: 0,
            parent_device: 1,
            parent_function: 0,
            vendor_id: 0x1B36,
            device_id: 0x0010,
            class_code: 0x01,
            subclass: 0x08,
            prog_if: 0x02,
            revision_id: 0x02,
            header_type: 0,
            secondary_bus: 0,
            subordinate_bus: 0,
            firmware_available: true,
            irq_mode: InventoryIrqMode::Msix,
            dma_isolation: IommuMode::Trusted,
            irq_vector_or_gsi: 0x50,
            lease_state: InventoryLeaseState::BoundOnline,
            relocation_class: InventoryRelocationClass::Fixed,
            cap_flags: CAP_FLAG_PCIE | CAP_FLAG_MSIX,
            root_id: 1,
            bars,
        };

        let mut buf = [0u8; HEADER_BYTES + RECORD_BYTES];
        let Ok(written) = encode(&hdr, &[rec], &mut buf) else {
            assert!(false, "encode failed");
            return;
        };
        let Ok(decoded_hdr) = validate_and_decode_header(&buf[..written]) else {
            assert!(false, "header decode failed");
            return;
        };
        assert_eq!(decoded_hdr, hdr);
        let Ok(decoded_rec) = decode_record(&buf[..written], 0) else {
            assert!(false, "record decode failed");
            return;
        };
        assert_eq!(decoded_rec, rec);
        assert_eq!(
            class_short_name(rec.class_code, rec.subclass, rec.prog_if),
            "nvme"
        );

        buf[HEADER_BYTES + 10] ^= 0xFF;
        assert_eq!(
            validate_and_decode_header(&buf[..written]),
            Err(InventoryWireError::BadChecksum)
        );
    }
}
