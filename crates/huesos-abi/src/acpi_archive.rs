//! Immutable ACPI table-archive decoding and physical-address translation.
//!
//! Version 1 contains a table directory and copied SDT bytes. Version 2 adds a
//! copied RSDP, a non-zero firmware snapshot identity, and a complete bounded
//! physical-to-VMO translation directory suitable for a future Ring-3 uACPI
//! table-map callback. Archive and ACPI-broker protocol versions are separate.
//!
//! The streaming validator reads through [`ArchiveReader`], so a userspace
//! service can validate a read-only VMO without first copying the complete
//! (up to 64 MiB) archive. Version-2 table bodies and the RSDP are checked as
//! part of validation; accepted physical mappings are canonical, non-overlapping
//! and referenced exactly once.

use crate::acpi_broker::{
    ArchiveError, TableArchiveEntry, TableArchiveHeader, ARCHIVE_V1_VERSION, MAX_ARCHIVE_BYTES,
    MAX_TABLES, MAX_TABLE_BYTES, TABLE_ARCHIVE_ENTRY_BYTES, TABLE_ARCHIVE_HEADER_BYTES,
    TABLE_ARCHIVE_MAGIC,
};

/// Current immutable table-archive version.
pub const VERSION: u16 = 2;
/// Version-2 fixed header bytes.
pub const HEADER_BYTES: usize = 96;
/// Version-2 table directory entry bytes.
pub const TABLE_ENTRY_BYTES: usize = 40;
/// Version-2 physical translation entry bytes.
pub const MAPPING_ENTRY_BYTES: usize = 32;
/// One RSDP mapping plus at most one mapping for every archived table.
pub const MAX_PHYSICAL_MAPPINGS: u32 = MAX_TABLES + 1;
/// A version-2 table has no physical translation record.
pub const NO_MAPPING_INDEX: u32 = u32::MAX;
/// Version-2 table entry represents the non-SDT FACS structure.
pub const TABLE_FLAG_FACS: u16 = 1 << 0;
/// All version-2 table flags currently understood.
pub const TABLE_FLAGS_V2: u16 = TABLE_FLAG_FACS;
/// Physical translation contains the RSDP.
pub const MAPPING_KIND_RSDP: u8 = 1;
/// Physical translation contains one archived table/FACS object.
pub const MAPPING_KIND_TABLE: u8 = 2;
/// Maximum bytes used while checksumming a table through a streaming reader.
const CHECKSUM_CHUNK_BYTES: usize = 1024;
/// Fixed bitmap words needed to account for all mapping entries.
const MAPPING_BITMAP_WORDS: usize = (MAX_PHYSICAL_MAPPINGS as usize).div_ceil(64);

/// Maximum number of distinct firmware physical ranges tracked by the legacy
/// version-1 in-memory index.
///
/// Version 2 does not use this small fixed array. A version-1 archive that
/// exceeds this capacity now fails explicitly instead of silently dropping
/// mappings.
pub const MAX_PHYSICAL_RANGES: usize = 64;

/// One firmware physical range present in the immutable archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    /// Start of the range in firmware physical address space.
    pub address: u64,
    /// Length of the range in bytes.
    pub length: u64,
}

/// Immutable legacy version-1 physical-address index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalIndex {
    ranges: [PhysicalRange; MAX_PHYSICAL_RANGES],
    count: usize,
}

impl PhysicalIndex {
    /// Empty, deny-by-default index.
    pub const fn empty() -> Self {
        Self {
            ranges: [PhysicalRange {
                address: 0,
                length: 0,
            }; MAX_PHYSICAL_RANGES],
            count: 0,
        }
    }

    /// Number of tracked ranges.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether no physical range is tracked.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate the tracked ranges in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &PhysicalRange> {
        self.ranges.iter().take(self.count)
    }

    /// Returns `true` iff `[address, address + length)` lies inside one range.
    pub fn contains_range(&self, address: u64, length: u64) -> bool {
        if length == 0 {
            return false;
        }
        let end = match address.checked_add(length) {
            Some(end) => end,
            None => return false,
        };
        self.iter().any(|range| {
            let range_end = match range.address.checked_add(range.length) {
                Some(range_end) => range_end,
                None => return false,
            };
            address >= range.address && end <= range_end
        })
    }

    /// Insert a range if space remains.
    pub fn insert(&mut self, address: u64, length: u64) -> bool {
        if self.count >= MAX_PHYSICAL_RANGES {
            return false;
        }
        self.ranges[self.count] = PhysicalRange { address, length };
        self.count += 1;
        true
    }
}

/// A validated, decoded legacy version-1 archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedArchive {
    /// Version-1 archive header.
    pub header: TableArchiveHeader,
    /// Complete legacy index, or decoding fails with [`ArchiveError::Capacity`].
    pub index: PhysicalIndex,
}

/// Version-2 RSDP descriptor embedded in the fixed header.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RsdpDescriptor {
    /// Original firmware physical address.
    pub physical_address: u64,
    /// Offset of copied RSDP bytes in the archive VMO.
    pub offset: u64,
    /// Exact copied length: 20 bytes for revision 0, 36 for revision 2+.
    pub length: u32,
    /// Index of the matching physical translation record.
    pub mapping_index: u32,
    /// ACPI RSDP revision byte.
    pub revision: u8,
}

/// Canonical version-2 fixed header.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArchiveV2Header {
    /// Aggregate bytes covered by the archive.
    pub total_size: u64,
    /// Non-zero identity of this immutable firmware snapshot.
    pub firmware_snapshot_id: u64,
    /// Number of following table directory records.
    pub table_count: u32,
    /// Number of physical translation records.
    pub mapping_count: u32,
    /// Offset of the table directory; canonical value is [`HEADER_BYTES`].
    pub table_entries_offset: u64,
    /// Offset of the physical translation directory.
    pub mappings_offset: u64,
    /// First byte available for copied firmware payloads.
    pub payload_offset: u64,
    /// Copied RSDP descriptor.
    pub rsdp: RsdpDescriptor,
}

/// One version-2 table directory record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArchiveV2TableEntry {
    /// Four-byte SDT signature or `FACS`.
    pub signature: [u8; 4],
    /// SDT revision, or FACS version byte for a FACS record.
    pub revision: u8,
    /// Versioned table flags.
    pub flags: u16,
    /// Original physical address, or zero for a virtual table.
    pub physical_address: u64,
    /// Offset of copied bytes in the archive VMO.
    pub offset: u64,
    /// Copied object length.
    pub length: u32,
    /// Stable duplicate index for repeated signatures such as SSDT.
    pub instance: u32,
    /// Matching translation record, or [`NO_MAPPING_INDEX`].
    pub mapping_index: u32,
}

/// One version-2 physical-to-VMO translation record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PhysicalMappingEntry {
    /// Original firmware physical address.
    pub physical_address: u64,
    /// Offset of copied bytes in the archive VMO.
    pub offset: u64,
    /// Mapping length.
    pub length: u64,
    /// [`MAPPING_KIND_RSDP`] or [`MAPPING_KIND_TABLE`].
    pub kind: u8,
}

/// Summary returned by the dual-version streaming validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveSummary {
    /// Validated archive version (1 or 2).
    pub version: u16,
    /// Aggregate archive bytes.
    pub total_size: u64,
    /// Number of table records.
    pub table_count: u32,
    /// Number of represented physical ranges.
    pub mapping_count: u32,
    /// Zero for legacy v1, non-zero for v2.
    pub firmware_snapshot_id: u64,
    /// Present only for version 2.
    pub rsdp: Option<RsdpDescriptor>,
}

/// Backing storage could not return a complete requested archive range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveReadError;

/// Minimal random-access reader used to validate slices and read-only VMOs.
pub trait ArchiveReader {
    /// Copy exactly `output.len()` bytes beginning at `offset`.
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ArchiveReadError>;
}

impl ArchiveReader for [u8] {
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ArchiveReadError> {
        let start = usize::try_from(offset).map_err(|_| ArchiveReadError)?;
        let end = start.checked_add(output.len()).ok_or(ArchiveReadError)?;
        let bytes = self.get(start..end).ok_or(ArchiveReadError)?;
        output.copy_from_slice(bytes);
        Ok(())
    }
}

/// Decode the legacy version-1 archive and materialize its fixed index.
///
/// This compatibility API remains for existing host policy tests. New runtime
/// consumers should use [`validate`] so version 2 is accepted without copying
/// the complete archive.
pub fn decode(bytes: &[u8]) -> Result<DecodedArchive, ArchiveError> {
    if bytes.len() < TABLE_ARCHIVE_HEADER_BYTES as usize {
        return Err(ArchiveError::Metadata);
    }
    // SAFETY: the legacy header is repr(C) POD with the locked 24-byte wire
    // layout. read_unaligned is required because a byte slice need not be
    // naturally aligned.
    let header: TableArchiveHeader =
        unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<TableArchiveHeader>()) };
    if header.magic != TABLE_ARCHIVE_MAGIC || header.version != ARCHIVE_V1_VERSION {
        return Err(ArchiveError::Format);
    }
    if header.header_size != TABLE_ARCHIVE_HEADER_BYTES
        || header.table_count > MAX_TABLES
        || header.total_size > MAX_ARCHIVE_BYTES
        || (bytes.len() as u64) < header.total_size
    {
        return Err(ArchiveError::Metadata);
    }

    let entries_bytes = (header.table_count as usize)
        .checked_mul(TABLE_ARCHIVE_ENTRY_BYTES)
        .ok_or(ArchiveError::Metadata)?;
    let metadata_end = (header.header_size as usize)
        .checked_add(entries_bytes)
        .ok_or(ArchiveError::Metadata)?;
    if metadata_end > header.total_size as usize {
        return Err(ArchiveError::Metadata);
    }

    let mut index = PhysicalIndex::empty();
    let mut previous_end = metadata_end as u64;
    for index_in_archive in 0..header.table_count as usize {
        let offset = header.header_size as usize + index_in_archive * TABLE_ARCHIVE_ENTRY_BYTES;
        if offset + TABLE_ARCHIVE_ENTRY_BYTES > bytes.len() {
            return Err(ArchiveError::Metadata);
        }
        // SAFETY: same locked repr(C) POD contract as the legacy header.
        let entry: TableArchiveEntry = unsafe {
            core::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<TableArchiveEntry>())
        };
        validate_v1_entry(&entry, metadata_end as u64, previous_end, header.total_size)?;
        previous_end = entry
            .offset
            .checked_add(entry.length as u64)
            .ok_or(ArchiveError::Range)?;
        if entry.physical_address != 0 && !index.insert(entry.physical_address, entry.length as u64)
        {
            return Err(ArchiveError::Capacity);
        }
    }

    Ok(DecodedArchive { header, index })
}

/// Validate a version-1 or version-2 archive through a bounded reader.
///
/// `available_bytes` is the immutable VMO/slice length visible to the caller.
/// The archive's declared total size must fit inside it.
pub fn validate<R: ArchiveReader + ?Sized>(
    reader: &R,
    available_bytes: u64,
) -> Result<ArchiveSummary, ArchiveError> {
    let mut prefix = [0u8; TABLE_ARCHIVE_HEADER_BYTES as usize];
    read(reader, 0, &mut prefix)?;
    if prefix[..8] != TABLE_ARCHIVE_MAGIC {
        return Err(ArchiveError::Format);
    }
    match u16_at(&prefix, 8)? {
        ARCHIVE_V1_VERSION => validate_v1(reader, available_bytes, &prefix),
        VERSION => validate_v2(reader, available_bytes),
        _ => Err(ArchiveError::UnsupportedVersion),
    }
}

/// Encode a canonical version-2 fixed header.
pub fn encode_v2_header(header: &ArchiveV2Header, output: &mut [u8]) -> Result<(), ArchiveError> {
    if output.len() != HEADER_BYTES {
        return Err(ArchiveError::Metadata);
    }
    output.fill(0);
    output[..8].copy_from_slice(&TABLE_ARCHIVE_MAGIC);
    put_u16(output, 8, VERSION)?;
    put_u16(output, 10, HEADER_BYTES as u16)?;
    put_u32(output, 12, 0)?;
    put_u64(output, 16, header.total_size)?;
    put_u64(output, 24, header.firmware_snapshot_id)?;
    put_u32(output, 32, header.table_count)?;
    put_u32(output, 36, header.mapping_count)?;
    put_u64(output, 40, header.table_entries_offset)?;
    put_u64(output, 48, header.mappings_offset)?;
    put_u64(output, 56, header.payload_offset)?;
    put_u64(output, 64, header.rsdp.physical_address)?;
    put_u64(output, 72, header.rsdp.offset)?;
    put_u32(output, 80, header.rsdp.length)?;
    put_u32(output, 84, header.rsdp.mapping_index)?;
    output[88] = header.rsdp.revision;
    Ok(())
}

/// Decode one canonical version-2 fixed header from exact bytes.
pub fn decode_v2_header(bytes: &[u8]) -> Result<ArchiveV2Header, ArchiveError> {
    if bytes.len() != HEADER_BYTES
        || bytes[..8] != TABLE_ARCHIVE_MAGIC
        || u16_at(bytes, 8)? != VERSION
        || u16_at(bytes, 10)? as usize != HEADER_BYTES
        || u32_at(bytes, 12)? != 0
        || bytes[89..96].iter().any(|byte| *byte != 0)
    {
        return Err(ArchiveError::Format);
    }
    Ok(ArchiveV2Header {
        total_size: u64_at(bytes, 16)?,
        firmware_snapshot_id: u64_at(bytes, 24)?,
        table_count: u32_at(bytes, 32)?,
        mapping_count: u32_at(bytes, 36)?,
        table_entries_offset: u64_at(bytes, 40)?,
        mappings_offset: u64_at(bytes, 48)?,
        payload_offset: u64_at(bytes, 56)?,
        rsdp: RsdpDescriptor {
            physical_address: u64_at(bytes, 64)?,
            offset: u64_at(bytes, 72)?,
            length: u32_at(bytes, 80)?,
            mapping_index: u32_at(bytes, 84)?,
            revision: bytes[88],
        },
    })
}

/// Encode one canonical version-2 table directory entry.
pub fn encode_v2_table_entry(
    entry: &ArchiveV2TableEntry,
    output: &mut [u8],
) -> Result<(), ArchiveError> {
    if output.len() != TABLE_ENTRY_BYTES || entry.flags & !TABLE_FLAGS_V2 != 0 {
        return Err(ArchiveError::Metadata);
    }
    output.fill(0);
    output[..4].copy_from_slice(&entry.signature);
    output[4] = entry.revision;
    put_u16(output, 6, entry.flags)?;
    put_u64(output, 8, entry.physical_address)?;
    put_u64(output, 16, entry.offset)?;
    put_u32(output, 24, entry.length)?;
    put_u32(output, 28, entry.instance)?;
    put_u32(output, 32, entry.mapping_index)?;
    Ok(())
}

/// Decode one exact version-2 table directory entry.
pub fn decode_v2_table_entry(bytes: &[u8]) -> Result<ArchiveV2TableEntry, ArchiveError> {
    if bytes.len() != TABLE_ENTRY_BYTES
        || bytes[5] != 0
        || u16_at(bytes, 38)? != 0
        || u16_at(bytes, 6)? & !TABLE_FLAGS_V2 != 0
    {
        return Err(ArchiveError::Reserved);
    }
    Ok(ArchiveV2TableEntry {
        signature: [bytes[0], bytes[1], bytes[2], bytes[3]],
        revision: bytes[4],
        flags: u16_at(bytes, 6)?,
        physical_address: u64_at(bytes, 8)?,
        offset: u64_at(bytes, 16)?,
        length: u32_at(bytes, 24)?,
        instance: u32_at(bytes, 28)?,
        mapping_index: u32_at(bytes, 32)?,
    })
}

/// Encode one canonical version-2 physical translation entry.
pub fn encode_v2_mapping(
    mapping: &PhysicalMappingEntry,
    output: &mut [u8],
) -> Result<(), ArchiveError> {
    if output.len() != MAPPING_ENTRY_BYTES
        || !matches!(mapping.kind, MAPPING_KIND_RSDP | MAPPING_KIND_TABLE)
    {
        return Err(ArchiveError::Metadata);
    }
    output.fill(0);
    put_u64(output, 0, mapping.physical_address)?;
    put_u64(output, 8, mapping.offset)?;
    put_u64(output, 16, mapping.length)?;
    output[24] = mapping.kind;
    Ok(())
}

/// Decode one exact version-2 physical translation entry.
pub fn decode_v2_mapping(bytes: &[u8]) -> Result<PhysicalMappingEntry, ArchiveError> {
    if bytes.len() != MAPPING_ENTRY_BYTES
        || bytes[25..32].iter().any(|byte| *byte != 0)
        || !matches!(bytes[24], MAPPING_KIND_RSDP | MAPPING_KIND_TABLE)
    {
        return Err(ArchiveError::Reserved);
    }
    Ok(PhysicalMappingEntry {
        physical_address: u64_at(bytes, 0)?,
        offset: u64_at(bytes, 8)?,
        length: u64_at(bytes, 16)?,
        kind: bytes[24],
    })
}

fn validate_v1<R: ArchiveReader + ?Sized>(
    reader: &R,
    available_bytes: u64,
    prefix: &[u8],
) -> Result<ArchiveSummary, ArchiveError> {
    let header_size = u16_at(prefix, 10)?;
    let table_count = u32_at(prefix, 12)?;
    let total_size = u64_at(prefix, 16)?;
    if header_size != TABLE_ARCHIVE_HEADER_BYTES
        || table_count > MAX_TABLES
        || total_size > MAX_ARCHIVE_BYTES
        || total_size > available_bytes
    {
        return Err(ArchiveError::Metadata);
    }
    let entries_bytes = u64::from(table_count)
        .checked_mul(TABLE_ARCHIVE_ENTRY_BYTES as u64)
        .ok_or(ArchiveError::Metadata)?;
    let metadata_end = u64::from(header_size)
        .checked_add(entries_bytes)
        .ok_or(ArchiveError::Metadata)?;
    if metadata_end > total_size {
        return Err(ArchiveError::Metadata);
    }

    let mut previous_end = metadata_end;
    let mut mapping_count = 0u32;
    let mut raw = [0u8; TABLE_ARCHIVE_ENTRY_BYTES];
    for index in 0..table_count {
        let offset = u64::from(header_size)
            .checked_add(u64::from(index) * TABLE_ARCHIVE_ENTRY_BYTES as u64)
            .ok_or(ArchiveError::Metadata)?;
        read(reader, offset, &mut raw)?;
        let entry = decode_v1_entry(&raw)?;
        validate_v1_entry(&entry, metadata_end, previous_end, total_size)?;
        previous_end = entry
            .offset
            .checked_add(entry.length as u64)
            .ok_or(ArchiveError::Range)?;
        if entry.physical_address != 0 {
            mapping_count = mapping_count.checked_add(1).ok_or(ArchiveError::Capacity)?;
        }
    }
    if total_size != 0 {
        let mut probe = [0u8; 1];
        read(reader, total_size - 1, &mut probe)?;
    }
    Ok(ArchiveSummary {
        version: ARCHIVE_V1_VERSION,
        total_size,
        table_count,
        mapping_count,
        firmware_snapshot_id: 0,
        rsdp: None,
    })
}

fn validate_v2<R: ArchiveReader + ?Sized>(
    reader: &R,
    available_bytes: u64,
) -> Result<ArchiveSummary, ArchiveError> {
    let mut raw_header = [0u8; HEADER_BYTES];
    read(reader, 0, &mut raw_header)?;
    let header = decode_v2_header(&raw_header)?;
    validate_v2_geometry(&header, available_bytes)?;

    let mut seen_mappings = [0u64; MAPPING_BITMAP_WORDS];
    let rsdp_mapping = read_mapping(reader, &header, header.rsdp.mapping_index)?;
    if rsdp_mapping.kind != MAPPING_KIND_RSDP
        || rsdp_mapping.physical_address != header.rsdp.physical_address
        || rsdp_mapping.offset != header.rsdp.offset
        || rsdp_mapping.length != u64::from(header.rsdp.length)
    {
        return Err(ArchiveError::Translation);
    }
    mark_mapping(&mut seen_mappings, header.rsdp.mapping_index)?;
    validate_rsdp(reader, &header.rsdp)?;

    let mut previous_payload_end = header
        .rsdp
        .offset
        .checked_add(u64::from(header.rsdp.length))
        .ok_or(ArchiveError::Range)?;
    let mut raw_table = [0u8; TABLE_ENTRY_BYTES];
    for index in 0..header.table_count {
        let offset = header
            .table_entries_offset
            .checked_add(u64::from(index) * TABLE_ENTRY_BYTES as u64)
            .ok_or(ArchiveError::Metadata)?;
        read(reader, offset, &mut raw_table)?;
        let entry = decode_v2_table_entry(&raw_table)?;
        validate_v2_table(reader, &header, &entry, previous_payload_end)?;
        previous_payload_end = entry
            .offset
            .checked_add(u64::from(entry.length))
            .ok_or(ArchiveError::Range)?;
        if entry.physical_address == 0 {
            if entry.mapping_index != NO_MAPPING_INDEX {
                return Err(ArchiveError::Translation);
            }
        } else {
            if entry.mapping_index == NO_MAPPING_INDEX
                || entry.mapping_index >= header.mapping_count
            {
                return Err(ArchiveError::Translation);
            }
            let mapping = read_mapping(reader, &header, entry.mapping_index)?;
            if mapping.kind != MAPPING_KIND_TABLE
                || mapping.physical_address != entry.physical_address
                || mapping.offset != entry.offset
                || mapping.length != u64::from(entry.length)
            {
                return Err(ArchiveError::Translation);
            }
            mark_mapping(&mut seen_mappings, entry.mapping_index)?;
        }
    }
    if previous_payload_end != header.total_size {
        return Err(ArchiveError::Metadata);
    }

    validate_mapping_directory(reader, &header, &seen_mappings)?;
    Ok(ArchiveSummary {
        version: VERSION,
        total_size: header.total_size,
        table_count: header.table_count,
        mapping_count: header.mapping_count,
        firmware_snapshot_id: header.firmware_snapshot_id,
        rsdp: Some(header.rsdp),
    })
}

fn validate_v2_geometry(
    header: &ArchiveV2Header,
    available_bytes: u64,
) -> Result<(), ArchiveError> {
    if header.firmware_snapshot_id == 0
        || header.table_count > MAX_TABLES
        || header.mapping_count == 0
        || header.mapping_count > MAX_PHYSICAL_MAPPINGS
        || header.total_size > MAX_ARCHIVE_BYTES
        || header.total_size > available_bytes
        || header.table_entries_offset != HEADER_BYTES as u64
    {
        return Err(ArchiveError::Metadata);
    }
    let table_bytes = u64::from(header.table_count)
        .checked_mul(TABLE_ENTRY_BYTES as u64)
        .ok_or(ArchiveError::Metadata)?;
    let expected_mappings = header
        .table_entries_offset
        .checked_add(table_bytes)
        .ok_or(ArchiveError::Metadata)?;
    let mapping_bytes = u64::from(header.mapping_count)
        .checked_mul(MAPPING_ENTRY_BYTES as u64)
        .ok_or(ArchiveError::Metadata)?;
    let expected_payload = expected_mappings
        .checked_add(mapping_bytes)
        .ok_or(ArchiveError::Metadata)?;
    if header.mappings_offset != expected_mappings
        || header.payload_offset != expected_payload
        || header.rsdp.offset != header.payload_offset
        || header.rsdp.physical_address == 0
        || header.rsdp.mapping_index >= header.mapping_count
        || !valid_rsdp_length(header.rsdp.revision, header.rsdp.length)
    {
        return Err(ArchiveError::Metadata);
    }
    let rsdp_end = header
        .rsdp
        .offset
        .checked_add(u64::from(header.rsdp.length))
        .ok_or(ArchiveError::Range)?;
    if rsdp_end > header.total_size {
        return Err(ArchiveError::Range);
    }
    Ok(())
}

fn validate_v2_table<R: ArchiveReader + ?Sized>(
    reader: &R,
    header: &ArchiveV2Header,
    entry: &ArchiveV2TableEntry,
    previous_end: u64,
) -> Result<(), ArchiveError> {
    if entry.flags & !TABLE_FLAGS_V2 != 0 || entry.offset != previous_end {
        return Err(ArchiveError::Metadata);
    }
    let facs = entry.flags & TABLE_FLAG_FACS != 0;
    if facs {
        if entry.signature != *b"FACS" || entry.length < 64 {
            return Err(ArchiveError::Format);
        }
    } else if entry.signature == *b"FACS" || !(36..=MAX_TABLE_BYTES).contains(&entry.length) {
        return Err(ArchiveError::Range);
    }
    if entry.length > MAX_TABLE_BYTES {
        return Err(ArchiveError::Range);
    }
    let end = entry
        .offset
        .checked_add(u64::from(entry.length))
        .ok_or(ArchiveError::Range)?;
    if entry.offset < header.payload_offset || end > header.total_size {
        return Err(ArchiveError::Range);
    }
    if entry.physical_address != 0
        && entry
            .physical_address
            .checked_add(u64::from(entry.length))
            .is_none()
    {
        return Err(ArchiveError::Range);
    }

    let mut fixed = [0u8; 36];
    read(reader, entry.offset, &mut fixed)?;
    if fixed[..4] != entry.signature || u32_at(&fixed, 4)? != entry.length {
        return Err(ArchiveError::Format);
    }
    if facs {
        if fixed[32] != entry.revision {
            return Err(ArchiveError::Format);
        }
    } else {
        if fixed[8] != entry.revision || checksum(reader, entry.offset, entry.length)? != 0 {
            return Err(ArchiveError::Checksum);
        }
    }
    Ok(())
}

fn validate_rsdp<R: ArchiveReader + ?Sized>(
    reader: &R,
    descriptor: &RsdpDescriptor,
) -> Result<(), ArchiveError> {
    let mut bytes = [0u8; 36];
    let length = descriptor.length as usize;
    read(reader, descriptor.offset, &mut bytes[..length])?;
    if bytes[..8] != *b"RSD PTR " || bytes[15] != descriptor.revision || byte_sum(&bytes[..20]) != 0
    {
        return Err(ArchiveError::Checksum);
    }
    if descriptor.revision >= 2
        && (u32_at(&bytes, 20)? != descriptor.length || byte_sum(&bytes[..length]) != 0)
    {
        return Err(ArchiveError::Checksum);
    }
    Ok(())
}

fn validate_mapping_directory<R: ArchiveReader + ?Sized>(
    reader: &R,
    header: &ArchiveV2Header,
    seen: &[u64; MAPPING_BITMAP_WORDS],
) -> Result<(), ArchiveError> {
    let mut previous_end = 0u64;
    for index in 0..header.mapping_count {
        if !mapping_marked(seen, index) {
            return Err(ArchiveError::Translation);
        }
        let mapping = read_mapping(reader, header, index)?;
        if mapping.physical_address == 0
            || mapping.length == 0
            || mapping.offset < header.payload_offset
            || mapping
                .offset
                .checked_add(mapping.length)
                .is_none_or(|end| end > header.total_size)
            || mapping
                .physical_address
                .checked_add(mapping.length)
                .is_none()
        {
            return Err(ArchiveError::Range);
        }
        if index != 0 && mapping.physical_address < previous_end {
            return Err(ArchiveError::Overlap);
        }
        previous_end = mapping
            .physical_address
            .checked_add(mapping.length)
            .ok_or(ArchiveError::Range)?;
    }
    Ok(())
}

fn read_mapping<R: ArchiveReader + ?Sized>(
    reader: &R,
    header: &ArchiveV2Header,
    index: u32,
) -> Result<PhysicalMappingEntry, ArchiveError> {
    if index >= header.mapping_count {
        return Err(ArchiveError::Translation);
    }
    let offset = header
        .mappings_offset
        .checked_add(u64::from(index) * MAPPING_ENTRY_BYTES as u64)
        .ok_or(ArchiveError::Metadata)?;
    let mut raw = [0u8; MAPPING_ENTRY_BYTES];
    read(reader, offset, &mut raw)?;
    decode_v2_mapping(&raw)
}

fn mark_mapping(seen: &mut [u64; MAPPING_BITMAP_WORDS], index: u32) -> Result<(), ArchiveError> {
    if index >= MAX_PHYSICAL_MAPPINGS {
        return Err(ArchiveError::Capacity);
    }
    let word = index as usize / 64;
    let bit = 1u64 << (index % 64);
    if seen[word] & bit != 0 {
        return Err(ArchiveError::Translation);
    }
    seen[word] |= bit;
    Ok(())
}

fn mapping_marked(seen: &[u64; MAPPING_BITMAP_WORDS], index: u32) -> bool {
    let word = index as usize / 64;
    let bit = 1u64 << (index % 64);
    seen.get(word).is_some_and(|value| value & bit != 0)
}

fn validate_v1_entry(
    entry: &TableArchiveEntry,
    metadata_end: u64,
    previous_end: u64,
    total_size: u64,
) -> Result<(), ArchiveError> {
    if entry.reserved != [0; 3] {
        return Err(ArchiveError::Reserved);
    }
    if !(36..=MAX_TABLE_BYTES).contains(&entry.length) || entry.offset < metadata_end {
        return Err(ArchiveError::Range);
    }
    if entry.physical_address != 0
        && entry
            .physical_address
            .checked_add(u64::from(entry.length))
            .is_none()
    {
        return Err(ArchiveError::Range);
    }
    if entry.offset < previous_end {
        return Err(ArchiveError::Overlap);
    }
    let end = entry
        .offset
        .checked_add(u64::from(entry.length))
        .ok_or(ArchiveError::Range)?;
    if end > total_size {
        return Err(ArchiveError::Range);
    }
    Ok(())
}

fn decode_v1_entry(bytes: &[u8]) -> Result<TableArchiveEntry, ArchiveError> {
    if bytes.len() != TABLE_ARCHIVE_ENTRY_BYTES {
        return Err(ArchiveError::Metadata);
    }
    Ok(TableArchiveEntry {
        signature: [bytes[0], bytes[1], bytes[2], bytes[3]],
        revision: bytes[4],
        reserved: [bytes[5], bytes[6], bytes[7]],
        physical_address: u64_at(bytes, 8)?,
        offset: u64_at(bytes, 16)?,
        length: u32_at(bytes, 24)?,
        instance: u32_at(bytes, 28)?,
    })
}

fn valid_rsdp_length(revision: u8, length: u32) -> bool {
    match revision {
        0 => length == 20,
        2.. => length == 36,
        _ => false,
    }
}

fn checksum<R: ArchiveReader + ?Sized>(
    reader: &R,
    offset: u64,
    length: u32,
) -> Result<u8, ArchiveError> {
    let mut sum = 0u8;
    let mut done = 0u64;
    let mut chunk = [0u8; CHECKSUM_CHUNK_BYTES];
    while done < u64::from(length) {
        let remaining = u64::from(length) - done;
        let take = core::cmp::min(remaining, CHECKSUM_CHUNK_BYTES as u64) as usize;
        read(reader, offset + done, &mut chunk[..take])?;
        sum = chunk[..take]
            .iter()
            .fold(sum, |accumulator, byte| accumulator.wrapping_add(*byte));
        done += take as u64;
    }
    Ok(sum)
}

fn byte_sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

fn read<R: ArchiveReader + ?Sized>(
    reader: &R,
    offset: u64,
    output: &mut [u8],
) -> Result<(), ArchiveError> {
    reader
        .read_exact_at(offset, output)
        .map_err(|_| ArchiveError::Read)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ArchiveError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ArchiveError::Metadata)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ArchiveError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ArchiveError::Metadata)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ArchiveError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(ArchiveError::Metadata)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), ArchiveError> {
    output
        .get_mut(offset..offset + 2)
        .ok_or(ArchiveError::Metadata)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), ArchiveError> {
    output
        .get_mut(offset..offset + 4)
        .ok_or(ArchiveError::Metadata)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), ArchiveError> {
    output
        .get_mut(offset..offset + 8)
        .ok_or(ArchiveError::Metadata)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acpi_broker::{TABLE_ARCHIVE_ENTRY_BYTES, TABLE_ARCHIVE_HEADER_BYTES};

    const TEST_BUF: usize = 8192;

    fn encode_v1(entries: &[(Option<u64>, u32)]) -> [u8; TEST_BUF] {
        let mut out = [0u8; TEST_BUF];
        let metadata_end =
            TABLE_ARCHIVE_HEADER_BYTES as usize + entries.len() * TABLE_ARCHIVE_ENTRY_BYTES;
        let mut total = metadata_end as u64;
        for (_, len) in entries {
            total += u64::from(*len);
        }
        assert!((total as usize) <= TEST_BUF, "test buffer too small");
        out[..8].copy_from_slice(&TABLE_ARCHIVE_MAGIC);
        out[8..10].copy_from_slice(&ARCHIVE_V1_VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&TABLE_ARCHIVE_HEADER_BYTES.to_le_bytes());
        out[12..16].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        out[16..24].copy_from_slice(&total.to_le_bytes());
        let mut cursor = metadata_end as u64;
        for (index, (physical, len)) in entries.iter().enumerate() {
            let start = TABLE_ARCHIVE_HEADER_BYTES as usize + index * TABLE_ARCHIVE_ENTRY_BYTES;
            let encoded = &mut out[start..start + TABLE_ARCHIVE_ENTRY_BYTES];
            encoded[..4].copy_from_slice(b"FACP");
            encoded[8..16].copy_from_slice(&physical.unwrap_or(0).to_le_bytes());
            encoded[16..24].copy_from_slice(&cursor.to_le_bytes());
            encoded[24..28].copy_from_slice(&len.to_le_bytes());
            encoded[28..32].copy_from_slice(&(index as u32).to_le_bytes());
            cursor += u64::from(*len);
        }
        out
    }

    fn finalize_checksum(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        let sum = byte_sum(bytes);
        bytes[checksum_offset] = 0u8.wrapping_sub(sum);
    }

    fn encode_v2() -> ([u8; TEST_BUF], usize) {
        let mut out = [0u8; TEST_BUF];
        let table_count = 1u32;
        let mapping_count = 2u32;
        let mappings_offset = HEADER_BYTES + TABLE_ENTRY_BYTES;
        let payload_offset = mappings_offset + mapping_count as usize * MAPPING_ENTRY_BYTES;
        let rsdp_offset = payload_offset;
        let table_offset = rsdp_offset + 36;
        let total_size = table_offset + 36;
        let header = ArchiveV2Header {
            total_size: total_size as u64,
            firmware_snapshot_id: 7,
            table_count,
            mapping_count,
            table_entries_offset: HEADER_BYTES as u64,
            mappings_offset: mappings_offset as u64,
            payload_offset: payload_offset as u64,
            rsdp: RsdpDescriptor {
                physical_address: 0x1000,
                offset: rsdp_offset as u64,
                length: 36,
                mapping_index: 0,
                revision: 2,
            },
        };
        assert_eq!(encode_v2_header(&header, &mut out[..HEADER_BYTES]), Ok(()));
        let table = ArchiveV2TableEntry {
            signature: *b"FACP",
            revision: 6,
            flags: 0,
            physical_address: 0x2000,
            offset: table_offset as u64,
            length: 36,
            instance: 0,
            mapping_index: 1,
        };
        assert_eq!(
            encode_v2_table_entry(
                &table,
                &mut out[HEADER_BYTES..HEADER_BYTES + TABLE_ENTRY_BYTES]
            ),
            Ok(())
        );
        let rsdp_mapping = PhysicalMappingEntry {
            physical_address: 0x1000,
            offset: rsdp_offset as u64,
            length: 36,
            kind: MAPPING_KIND_RSDP,
        };
        let table_mapping = PhysicalMappingEntry {
            physical_address: 0x2000,
            offset: table_offset as u64,
            length: 36,
            kind: MAPPING_KIND_TABLE,
        };
        assert_eq!(
            encode_v2_mapping(
                &rsdp_mapping,
                &mut out[mappings_offset..mappings_offset + MAPPING_ENTRY_BYTES]
            ),
            Ok(())
        );
        assert_eq!(
            encode_v2_mapping(
                &table_mapping,
                &mut out[mappings_offset + MAPPING_ENTRY_BYTES..payload_offset]
            ),
            Ok(())
        );

        let rsdp = &mut out[rsdp_offset..rsdp_offset + 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        finalize_checksum(&mut rsdp[..20], 8);
        finalize_checksum(rsdp, 32);

        let sdt = &mut out[table_offset..table_offset + 36];
        sdt[..4].copy_from_slice(b"FACP");
        sdt[4..8].copy_from_slice(&36u32.to_le_bytes());
        sdt[8] = 6;
        finalize_checksum(sdt, 9);
        (out, total_size)
    }

    #[test]
    fn legacy_decode_builds_complete_small_index() {
        let bytes = encode_v1(&[(Some(0x1000), 64), (Some(0x2000), 128)]);
        let decoded = decode(&bytes);
        assert!(decoded.as_ref().is_ok_and(|value| {
            value.header.table_count == 2
                && value.index.len() == 2
                && value.index.contains_range(0x1020, 16)
                && !value.index.contains_range(0x1000, 100)
                && !value.index.contains_range(u64::MAX - 8, 16)
        }));
    }

    #[test]
    fn legacy_decode_rejects_mapping_truncation() {
        let entries = [(Some(0x1000), 36); MAX_PHYSICAL_RANGES + 1];
        let bytes = encode_v1(&entries);
        assert_eq!(decode(&bytes), Err(ArchiveError::Capacity));
        let summary = validate(&bytes[..], bytes.len() as u64);
        assert!(summary.is_ok_and(|value| {
            value.version == ARCHIVE_V1_VERSION
                && value.mapping_count == (MAX_PHYSICAL_RANGES + 1) as u32
        }));
    }

    #[test]
    fn legacy_virtual_tables_do_not_enter_index() {
        let bytes = encode_v1(&[(None, 64), (Some(0x2000), 128)]);
        let decoded = decode(&bytes);
        assert!(decoded.as_ref().is_ok_and(|value| {
            value.index.len() == 1 && value.index.contains_range(0x2000, 128)
        }));
    }

    #[test]
    fn legacy_rejects_bad_metadata_and_overlap() {
        let mut bytes = encode_v1(&[(Some(0x1000), 128), (Some(0x2000), 64)]);
        bytes[0] = b'X';
        assert_eq!(decode(&bytes), Err(ArchiveError::Format));
        let mut bytes = encode_v1(&[(Some(0x1000), 128), (Some(0x2000), 64)]);
        let metadata_end = TABLE_ARCHIVE_HEADER_BYTES as usize + 2 * TABLE_ARCHIVE_ENTRY_BYTES;
        let second = TABLE_ARCHIVE_HEADER_BYTES as usize + TABLE_ARCHIVE_ENTRY_BYTES;
        bytes[second + 16..second + 24]
            .copy_from_slice(&((metadata_end + 32) as u64).to_le_bytes());
        assert_eq!(decode(&bytes), Err(ArchiveError::Overlap));
    }

    #[test]
    fn version_two_round_trips_and_validates_bodies() {
        let (bytes, len) = encode_v2();
        let summary = validate(&bytes[..], len as u64);
        assert!(summary.is_ok_and(|value| {
            value.version == VERSION
                && value.table_count == 1
                && value.mapping_count == 2
                && value.firmware_snapshot_id == 7
                && value
                    .rsdp
                    .is_some_and(|rsdp| rsdp.physical_address == 0x1000)
        }));
        let header = decode_v2_header(&bytes[..HEADER_BYTES]);
        assert!(header.is_ok_and(|value| value.total_size == len as u64));
    }

    #[test]
    fn version_two_rejects_bad_rsdp_and_table_checksums() {
        let (mut bytes, len) = encode_v2();
        let payload = u64_at(&bytes[..HEADER_BYTES], 56).unwrap_or(0) as usize;
        bytes[payload + 1] ^= 1;
        assert_eq!(
            validate(&bytes[..], len as u64),
            Err(ArchiveError::Checksum)
        );

        let (mut bytes, len) = encode_v2();
        bytes[len - 1] ^= 1;
        assert_eq!(
            validate(&bytes[..], len as u64),
            Err(ArchiveError::Checksum)
        );
    }

    #[test]
    fn version_two_rejects_missing_duplicate_and_widened_mappings() {
        let (mut bytes, len) = encode_v2();
        let table = HEADER_BYTES;
        bytes[table + 32..table + 36].copy_from_slice(&NO_MAPPING_INDEX.to_le_bytes());
        assert_eq!(
            validate(&bytes[..], len as u64),
            Err(ArchiveError::Translation)
        );

        let (mut bytes, len) = encode_v2();
        bytes[table + 32..table + 36].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            validate(&bytes[..], len as u64),
            Err(ArchiveError::Translation)
        );

        let (mut bytes, len) = encode_v2();
        let mappings = HEADER_BYTES + TABLE_ENTRY_BYTES;
        bytes[mappings + MAPPING_ENTRY_BYTES + 16..mappings + MAPPING_ENTRY_BYTES + 24]
            .copy_from_slice(&37u64.to_le_bytes());
        assert_eq!(
            validate(&bytes[..], len as u64),
            Err(ArchiveError::Translation)
        );
    }

    #[test]
    fn version_two_rejects_physical_overlap_and_unknown_version() {
        let (mut bytes, len) = encode_v2();
        let mappings = HEADER_BYTES + TABLE_ENTRY_BYTES;
        bytes[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&0x1010u64.to_le_bytes());
        bytes[mappings + MAPPING_ENTRY_BYTES..mappings + MAPPING_ENTRY_BYTES + 8]
            .copy_from_slice(&0x1010u64.to_le_bytes());
        assert_eq!(validate(&bytes[..], len as u64), Err(ArchiveError::Overlap));

        let (mut bytes, len) = encode_v2();
        bytes[8..10].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            validate(&bytes[..], len as u64),
            Err(ArchiveError::UnsupportedVersion)
        );
    }

    struct ShortReader;

    impl ArchiveReader for ShortReader {
        fn read_exact_at(&self, _offset: u64, _output: &mut [u8]) -> Result<(), ArchiveReadError> {
            Err(ArchiveReadError)
        }
    }

    #[test]
    fn streaming_read_failures_are_explicit() {
        assert_eq!(validate(&ShortReader, 4096), Err(ArchiveError::Read));
    }
}
