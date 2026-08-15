//! PCI Manager root-bridge descriptor wire format.
//!
//! The isolated ACPI service produces this bounded table for the future
//! userspace PCI Manager. MCFG describes configuration windows; these records
//! additionally carry root bus ranges and `_CRS` I/O/MMIO apertures, including
//! explicit PCI-bus-to-CPU address translation.

/// Wire magic: ASCII `HPCI` in little endian.
pub const MAGIC: u32 = 0x4943_5048;
/// Current append-only format version.
pub const VERSION: u16 = 1;
/// Fixed global header size.
pub const HEADER_BYTES: usize = 32;
/// Fixed root record size.
pub const ROOT_ENTRY_BYTES: usize = 40;
/// Fixed aperture record size.
pub const APERTURE_ENTRY_BYTES: usize = 32;
/// Maximum root bridges in one table.
pub const MAX_ROOTS: usize = 16;
/// Maximum apertures across all roots.
pub const MAX_APERTURES: usize = 64;
/// Maximum encoded byte length.
pub const MAX_ENCODED_BYTES: usize =
    HEADER_BYTES + MAX_ROOTS * ROOT_ENTRY_BYTES + MAX_APERTURES * APERTURE_ENTRY_BYTES;

/// Root supports firmware/native hotplug notification.
pub const ROOT_FLAG_HOTPLUG_CAPABLE: u32 = 1 << 0;
/// `_OSC` granted native PCIe hotplug control.
pub const ROOT_FLAG_NATIVE_HOTPLUG: u32 = 1 << 1;
/// A validated `_PRT` legacy interrupt-routing description is available.
pub const ROOT_FLAG_INTX_ROUTING: u32 = 1 << 2;
/// `_OSC` granted native AER control.
pub const ROOT_FLAG_NATIVE_AER: u32 = 1 << 3;
/// All root flags known by version 1.
pub const ROOT_FLAGS_V1: u32 = ROOT_FLAG_HOTPLUG_CAPABLE
    | ROOT_FLAG_NATIVE_HOTPLUG
    | ROOT_FLAG_INTX_ROUTING
    | ROOT_FLAG_NATIVE_AER;

/// Aperture contains space deliberately reserved for future hotplug.
pub const APERTURE_FLAG_HOTPLUG_RESERVE: u32 = 1 << 0;
/// Aperture assignment is fixed by the platform and cannot be relocated.
pub const APERTURE_FLAG_FIXED: u32 = 1 << 1;
/// All aperture flags known by version 1.
pub const APERTURE_FLAGS_V1: u32 = APERTURE_FLAG_HOTPLUG_RESERVE | APERTURE_FLAG_FIXED;

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
    /// Caller-provided output buffer is too small.
    BufferTooSmall,
}

/// Encode a canonical version-1 root table.
pub fn encode(table: &RootBridgeTable, out: &mut [u8]) -> Result<usize, Error> {
    validate(table)?;
    let roots_bytes = table
        .root_count
        .checked_mul(ROOT_ENTRY_BYTES)
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
    write_u16(out, 4, VERSION)?;
    write_u16(out, 6, HEADER_BYTES as u16)?;
    write_u16(out, 8, ROOT_ENTRY_BYTES as u16)?;
    write_u16(out, 10, APERTURE_ENTRY_BYTES as u16)?;
    write_u16(out, 12, table.root_count as u16)?;
    write_u16(out, 14, table.aperture_count as u16)?;

    for index in 0..table.root_count {
        encode_root(
            &table.roots[index],
            out,
            HEADER_BYTES + index * ROOT_ENTRY_BYTES,
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

/// Decode and validate one exact root-table blob.
pub fn decode(bytes: &[u8]) -> Result<RootBridgeTable, Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::BadLength);
    }
    if read_u32(bytes, 0)? != MAGIC || read_u16(bytes, 4)? != VERSION {
        return Err(Error::BadHeader);
    }
    if read_u16(bytes, 6)? as usize != HEADER_BYTES
        || read_u16(bytes, 8)? as usize != ROOT_ENTRY_BYTES
        || read_u16(bytes, 10)? as usize != APERTURE_ENTRY_BYTES
    {
        return Err(Error::BadLength);
    }
    let root_count = read_u16(bytes, 12)? as usize;
    let aperture_count = read_u16(bytes, 14)? as usize;
    if root_count > MAX_ROOTS || aperture_count > MAX_APERTURES {
        return Err(Error::BadLength);
    }
    if read_u32(bytes, 16)? != 0 || read_u32(bytes, 20)? != 0 || read_u64(bytes, 24)? != 0 {
        return Err(Error::ReservedNonZero);
    }
    let roots_bytes = root_count
        .checked_mul(ROOT_ENTRY_BYTES)
        .ok_or(Error::BadLength)?;
    let apertures_bytes = aperture_count
        .checked_mul(APERTURE_ENTRY_BYTES)
        .ok_or(Error::BadLength)?;
    let total = HEADER_BYTES
        .checked_add(roots_bytes)
        .and_then(|value| value.checked_add(apertures_bytes))
        .ok_or(Error::BadLength)?;
    if bytes.len() != total {
        return Err(Error::BadLength);
    }

    let mut table = RootBridgeTable::empty();
    let aperture_base = HEADER_BYTES + roots_bytes;
    for index in 0..root_count {
        table.roots[index] = decode_root(bytes, HEADER_BYTES + index * ROOT_ENTRY_BYTES)?;
    }
    for index in 0..aperture_count {
        table.apertures[index] =
            decode_aperture(bytes, aperture_base + index * APERTURE_ENTRY_BYTES)?;
    }
    table.root_count = root_count;
    table.aperture_count = aperture_count;
    validate(&table)?;
    Ok(table)
}

/// Validate the canonical in-memory table.
pub fn validate(table: &RootBridgeTable) -> Result<(), Error> {
    if table.root_count > MAX_ROOTS || table.aperture_count > MAX_APERTURES {
        return Err(Error::BadLength);
    }
    let mut expected_aperture = 0usize;
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
    }
    if expected_aperture != table.aperture_count {
        return Err(Error::InvalidAperture);
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
    Ok(())
}

fn encode_root(root: &RootBridge, out: &mut [u8], base: usize) -> Result<(), Error> {
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

fn decode_root(bytes: &[u8], base: usize) -> Result<RootBridge, Error> {
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
}
