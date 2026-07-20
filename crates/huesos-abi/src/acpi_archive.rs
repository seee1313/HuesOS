//! Immutable ACPI table-archive decoding and physical-address index.
//!
//! The kernel publishes validated ACPI tables in a read-only VMO. This module
//! turns the raw VMO bytes into a typed [`TableArchiveHeader`] and builds an
//! immutable *physical-address index*: the only firmware physical ranges a
//! future Ring-3 uACPI `map` callback is permitted to resolve.
//!
//! The index is **deny-by-default**. A mapping request that does not fall
//! entirely inside one archived physical range is rejected, which removes
//! arbitrary physical memory access from the AML process. This is the
//! prerequisite called out by `docs/ACPI_RING3.md`: a userspace map callback
//! "may resolve only ranges present in this immutable physical-address index".
//!
//! The decoder performs no table-body reads; it inspects only the bounded
//! metadata region (header + entry array) and is fully exercisable on the
//! host, so the layout and the index predicate are covered by unit tests.

use crate::acpi_broker::{
    ArchiveError, TableArchiveEntry, TableArchiveHeader, TABLE_ARCHIVE_ENTRY_BYTES,
    TABLE_ARCHIVE_HEADER_BYTES, TABLE_ARCHIVE_MAGIC, VERSION,
};

/// Maximum number of distinct firmware physical ranges tracked by the index.
///
/// Real x86_64 firmwares export well under this many physical-backed tables
/// (FACP, APIC, HPET, MADT, DSDT, FACS, a handful of SSDTs, DMAR/IVRS, ...).
/// Extra ranges past the cap are simply not tracked and therefore denied,
/// which is the safe failure direction for a deny-by-default index.
pub const MAX_PHYSICAL_RANGES: usize = 64;

/// One firmware physical range present in the immutable archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalRange {
    /// Start of the range in firmware physical address space.
    pub address: u64,
    /// Length of the range in bytes.
    pub length: u64,
}

/// Immutable index of firmware physical ranges exported by the archive.
///
/// Constructed once from a validated archive and consulted by the Ring-3
/// uACPI `map` callback. It never grants access to ranges absent from the
/// index.
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

    /// Number of tracked physical ranges.
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

    /// Returns `true` iff the half-open `[address, address + length)` is fully
    /// contained within exactly one archived physical range.
    ///
    /// A zero-length probe and any range that overflows the address space or
    /// spans more than one archived range are rejected.
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

    /// Insert a range if space remains. Returns `false` once the cap is hit.
    pub fn insert(&mut self, address: u64, length: u64) -> bool {
        if self.count >= MAX_PHYSICAL_RANGES {
            return false;
        }
        self.ranges[self.count] = PhysicalRange { address, length };
        self.count += 1;
        true
    }
}

/// A validated, decoded ACPI table archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedArchive {
    /// Archive header (magic, version, counts, total size).
    pub header: TableArchiveHeader,
    /// Immutable index of firmware physical ranges exported by the archive.
    pub index: PhysicalIndex,
}

/// Decode and validate the raw archive VMO bytes.
///
/// Inspects only the bounded metadata region (the header plus the entry
/// array). Table bodies are never read. On success returns the typed header
/// and the immutable [`PhysicalIndex`] of firmware physical ranges.
///
/// # Errors
/// Returns the specific [`ArchiveError`] for any malformed layout: bad magic or
/// version, inconsistent metadata, an out-of-bounds or zero-length table, an
/// out-of-order/overlapping entry, or a nonzero reserved field.
pub fn decode(bytes: &[u8]) -> Result<DecodedArchive, ArchiveError> {
    if bytes.len() < TABLE_ARCHIVE_HEADER_BYTES as usize {
        return Err(ArchiveError::Metadata);
    }
    // SAFETY: the archive header is exactly TABLE_ARCHIVE_HEADER_BYTES and the
    // struct is repr(C) POD matching the on-wire layout. read_unaligned is used
    // because the VMO slice need not be 8-byte aligned.
    let header: TableArchiveHeader = unsafe {
        core::ptr::read_unaligned(bytes.as_ptr().cast::<TableArchiveHeader>())
    };
    if header.magic != TABLE_ARCHIVE_MAGIC || header.version != VERSION {
        return Err(ArchiveError::Format);
    }
    if header.header_size != TABLE_ARCHIVE_HEADER_BYTES
        || header.table_count > crate::acpi_broker::MAX_TABLES
        || header.total_size > crate::acpi_broker::MAX_ARCHIVE_BYTES
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
        // Entries begin immediately after the header; `metadata_end` is the
        // end of the entry array and the offset where table bodies start.
        let offset = header.header_size as usize + index_in_archive * TABLE_ARCHIVE_ENTRY_BYTES;
        if offset + TABLE_ARCHIVE_ENTRY_BYTES > bytes.len() {
            return Err(ArchiveError::Metadata);
        }
        // SAFETY: same POD / repr(C) reasoning as the header read above.
        let entry: TableArchiveEntry = unsafe {
            core::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<TableArchiveEntry>())
        };
        if entry.reserved != [0; 3] {
            return Err(ArchiveError::Reserved);
        }
        if !(36..=crate::acpi_broker::MAX_TABLE_BYTES).contains(&entry.length)
            || entry.offset < metadata_end as u64
        {
            return Err(ArchiveError::Range);
        }
        if entry.physical_address != 0
            && entry
                .physical_address
                .checked_add(entry.length as u64)
                .is_none()
        {
            return Err(ArchiveError::Range);
        }
        if entry.offset < previous_end {
            return Err(ArchiveError::Overlap);
        }
        let end = entry
            .offset
            .checked_add(entry.length as u64)
            .ok_or(ArchiveError::Range)?;
        if end > header.total_size {
            return Err(ArchiveError::Range);
        }
        // Only firmware physical ranges back the map index; virtual tables
        // contribute no mappable physical address.
        if entry.physical_address != 0 {
            let _ = index.insert(entry.physical_address, entry.length as u64);
        }
        previous_end = end;
    }

    Ok(DecodedArchive { header, index })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acpi_broker::{
        MAX_TABLE_BYTES, TABLE_ARCHIVE_ENTRY_BYTES, TABLE_ARCHIVE_HEADER_BYTES,
        TABLE_ARCHIVE_MAGIC, VERSION,
    };

    /// Generous stack buffer for the small synthetic archives used below.
    const TEST_BUF: usize = 8192;

    /// Mirror the kernel encoder layout (`huesos-kernel::boot::acpi_archive`)
    /// so the decoder is proven against the exact on-wire bytes the kernel
    /// produces. Returns the full buffer; trailing zeros beyond `total_size`
    /// are ignored by [`decode`].
    fn encode_archive(entries: &[(Option<u64>, u32)]) -> [u8; TEST_BUF] {
        let mut out = [0u8; TEST_BUF];
        let metadata_end =
            TABLE_ARCHIVE_HEADER_BYTES as usize + entries.len() * TABLE_ARCHIVE_ENTRY_BYTES;
        let mut total = metadata_end as u64;
        for (_, len) in entries {
            total += *len as u64;
        }
        assert!((total as usize) <= TEST_BUF, "test buffer too small");

        out[..8].copy_from_slice(&TABLE_ARCHIVE_MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&TABLE_ARCHIVE_HEADER_BYTES.to_le_bytes());
        out[12..16].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        out[16..24].copy_from_slice(&total.to_le_bytes());

        let mut cursor = metadata_end as u64;
        for (i, (phys, len)) in entries.iter().enumerate() {
            let start = TABLE_ARCHIVE_HEADER_BYTES as usize + i * TABLE_ARCHIVE_ENTRY_BYTES;
            let encoded = &mut out[start..start + TABLE_ARCHIVE_ENTRY_BYTES];
            encoded[..4].copy_from_slice(b"FACP");
            let phys = phys.unwrap_or(0);
            encoded[8..16].copy_from_slice(&phys.to_le_bytes());
            encoded[16..24].copy_from_slice(&cursor.to_le_bytes());
            encoded[24..28].copy_from_slice(&len.to_le_bytes());
            encoded[28..32].copy_from_slice(&(i as u32).to_le_bytes());
            cursor += *len as u64;
        }
        out
    }

    #[test]
    fn decodes_header_and_physical_index() {
        let bytes = encode_archive(&[(Some(0x1000u64), 64), (Some(0x2000u64), 128)]);
        let decoded = decode(&bytes).expect("archive should decode");
        assert_eq!(decoded.header.table_count, 2);
        assert_eq!(decoded.index.len(), 2);
    }

    #[test]
    fn index_contains_only_archived_ranges() {
        let bytes = encode_archive(&[(Some(0x1000u64), 64), (Some(0x2000u64), 128)]);
        let decoded = decode(&bytes).unwrap();
        // Exact fit inside the first range.
        assert!(decoded.index.contains_range(0x1000, 64));
        // Sub-range inside the first range.
        assert!(decoded.index.contains_range(0x1020, 16));
        // Exceeds the first range length.
        assert!(!decoded.index.contains_range(0x1000, 100));
        // Address not inside any archived range.
        assert!(!decoded.index.contains_range(0x1500, 16));
        // Second archived range.
        assert!(decoded.index.contains_range(0x2000, 128));
        // Zero-length probe is rejected.
        assert!(!decoded.index.contains_range(0x1000, 0));
        // Overflowing address space is rejected.
        assert!(!decoded.index.contains_range(u64::MAX - 8, 16));
    }

    #[test]
    fn virtual_tables_contribute_no_index_entry() {
        let bytes = encode_archive(&[(None, 64), (Some(0x2000u64), 128)]);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.index.len(), 1);
        assert!(decoded.index.contains_range(0x2000, 128));
        assert!(!decoded.index.contains_range(0x1000, 64));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = encode_archive(&[(Some(0x1000u64), 64)]);
        bytes[0] = b'X';
        assert_eq!(decode(&bytes), Err(ArchiveError::Format));
    }

    #[test]
    fn rejects_zero_length_table() {
        let bytes = encode_archive(&[(Some(0x1000u64), 0)]);
        assert_eq!(decode(&bytes), Err(ArchiveError::Range));
    }

    #[test]
    fn rejects_oversized_table() {
        // A table longer than MAX_TABLE_BYTES is rejected before any body read,
        // so the archive need only carry the header and one entry.
        let metadata_end =
            TABLE_ARCHIVE_HEADER_BYTES as usize + TABLE_ARCHIVE_ENTRY_BYTES;
        let mut bytes = [0u8; 64];
        bytes[..8].copy_from_slice(&TABLE_ARCHIVE_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&TABLE_ARCHIVE_HEADER_BYTES.to_le_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[16..24].copy_from_slice(&(metadata_end as u64).to_le_bytes());
        let encoded = &mut bytes[TABLE_ARCHIVE_HEADER_BYTES as usize..metadata_end];
        encoded[..4].copy_from_slice(b"FACP");
        encoded[16..24].copy_from_slice(&(metadata_end as u64).to_le_bytes());
        encoded[24..28].copy_from_slice(&(MAX_TABLE_BYTES + 1).to_le_bytes());
        assert_eq!(decode(&bytes[..metadata_end]), Err(ArchiveError::Range));
    }

    #[test]
    fn rejects_overlapping_entries() {
        // Two entries; move the second entry's VMO offset inside the first
        // entry's body so the per-entry ranges overlap.
        let mut bytes = encode_archive(&[(Some(0x1000u64), 128), (Some(0x2000u64), 64)]);
        let metadata_end =
            TABLE_ARCHIVE_HEADER_BYTES as usize + 2 * TABLE_ARCHIVE_ENTRY_BYTES;
        let second = TABLE_ARCHIVE_HEADER_BYTES as usize + TABLE_ARCHIVE_ENTRY_BYTES;
        // metadata_end (88) .. first entry end (216): an in-body offset.
        let overlap_offset = (metadata_end + 32) as u64;
        bytes[second + 16..second + 24].copy_from_slice(&overlap_offset.to_le_bytes());
        assert_eq!(decode(&bytes), Err(ArchiveError::Overlap));
    }

    #[test]
    fn rejects_nonzero_reserved_entry_field() {
        let mut bytes = encode_archive(&[(Some(0x1000u64), 64)]);
        let entry = TABLE_ARCHIVE_HEADER_BYTES as usize;
        bytes[entry + 5] = 1; // reserved[0]
        assert_eq!(decode(&bytes), Err(ArchiveError::Reserved));
    }
}
