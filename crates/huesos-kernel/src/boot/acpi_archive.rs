//! Immutable ACPI table archive exported to the Ring-3 ACPI manager.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use huesos_abi::acpi_broker::{
    MAX_ARCHIVE_BYTES, MAX_TABLE_BYTES, MAX_TABLES, TABLE_ARCHIVE_ENTRY_BYTES,
    TABLE_ARCHIVE_HEADER_BYTES, TABLE_ARCHIVE_MAGIC, VERSION,
};

/// Failure while snapshotting uACPI's validated table set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveBuildError {
    /// uACPI reported too many installed tables.
    TooManyTables,
    /// A referenced table disappeared or had an invalid SDT length.
    InvalidTable,
    /// Aggregate size exceeded the bounded archive format.
    TooLarge,
    /// Kernel allocation failed.
    OutOfMemory,
}

#[derive(Clone, Copy)]
struct Entry {
    index: usize,
    signature: [u8; 4],
    revision: u8,
    physical_address: u64,
    offset: u64,
    length: u32,
    instance: u32,
}

/// Copy every installed uACPI table into a self-contained immutable archive.
///
/// Table references are reacquired by stable index for the copy pass. This
/// runs during single-threaded early boot, before namespace/AML support can
/// dynamically install or unload tables.
pub fn build() -> Result<Vec<u8>, ArchiveBuildError> {
    let count = huesos_uacpi::table_count();
    if count > MAX_TABLES as usize {
        return Err(ArchiveBuildError::TooManyTables);
    }
    let metadata_bytes = (TABLE_ARCHIVE_HEADER_BYTES as usize)
        .checked_add(
            count
                .checked_mul(TABLE_ARCHIVE_ENTRY_BYTES)
                .ok_or(ArchiveBuildError::TooLarge)?,
        )
        .ok_or(ArchiveBuildError::TooLarge)?;
    let mut next_offset = metadata_bytes as u64;
    let mut instances = BTreeMap::<[u8; 4], u32>::new();
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| ArchiveBuildError::OutOfMemory)?;

    for index in 0..count {
        let metadata =
            huesos_uacpi::table_metadata(index).map_err(|_| ArchiveBuildError::InvalidTable)?;
        if metadata.checksum_bad {
            return Err(ArchiveBuildError::InvalidTable);
        }
        let table = huesos_uacpi::Table::get(index).map_err(|_| ArchiveBuildError::InvalidTable)?;
        let bytes = table.bytes().map_err(|_| ArchiveBuildError::InvalidTable)?;
        let length = u32::try_from(bytes.len()).map_err(|_| ArchiveBuildError::TooLarge)?;
        if !(36..=MAX_TABLE_BYTES).contains(&length) {
            return Err(ArchiveBuildError::InvalidTable);
        }
        let signature = table
            .signature()
            .map_err(|_| ArchiveBuildError::InvalidTable)?;
        let revision = table
            .revision()
            .map_err(|_| ArchiveBuildError::InvalidTable)?;
        if metadata.length != bytes.len() || metadata.signature != signature {
            return Err(ArchiveBuildError::InvalidTable);
        }
        let instance = instances.entry(signature).or_insert(0);
        entries.push(Entry {
            index,
            signature,
            revision,
            physical_address: metadata.physical_address.unwrap_or(0),
            offset: next_offset,
            length,
            instance: *instance,
        });
        *instance = instance
            .checked_add(1)
            .ok_or(ArchiveBuildError::TooManyTables)?;
        next_offset = next_offset
            .checked_add(length as u64)
            .ok_or(ArchiveBuildError::TooLarge)?;
        if next_offset > MAX_ARCHIVE_BYTES {
            return Err(ArchiveBuildError::TooLarge);
        }
    }

    let total_size = usize::try_from(next_offset).map_err(|_| ArchiveBuildError::TooLarge)?;
    let mut archive = Vec::new();
    archive
        .try_reserve_exact(total_size)
        .map_err(|_| ArchiveBuildError::OutOfMemory)?;
    archive.resize(total_size, 0);
    encode_header(&mut archive, count as u32, next_offset);
    for (position, entry) in entries.iter().enumerate() {
        encode_entry(&mut archive, position, entry);
        let table = huesos_uacpi::Table::get(entry.index)
            .map_err(|_| ArchiveBuildError::InvalidTable)?;
        let bytes = table.bytes().map_err(|_| ArchiveBuildError::InvalidTable)?;
        if bytes.len() != entry.length as usize {
            return Err(ArchiveBuildError::InvalidTable);
        }
        let start = entry.offset as usize;
        let end = start
            .checked_add(bytes.len())
            .ok_or(ArchiveBuildError::TooLarge)?;
        archive[start..end].copy_from_slice(bytes);
    }
    Ok(archive)
}

fn encode_header(output: &mut [u8], count: u32, total_size: u64) {
    output[..8].copy_from_slice(&TABLE_ARCHIVE_MAGIC);
    output[8..10].copy_from_slice(&VERSION.to_le_bytes());
    output[10..12].copy_from_slice(&TABLE_ARCHIVE_HEADER_BYTES.to_le_bytes());
    output[12..16].copy_from_slice(&count.to_le_bytes());
    output[16..24].copy_from_slice(&total_size.to_le_bytes());
}

fn encode_entry(output: &mut [u8], position: usize, entry: &Entry) {
    let start = TABLE_ARCHIVE_HEADER_BYTES as usize + position * TABLE_ARCHIVE_ENTRY_BYTES;
    let encoded = &mut output[start..start + TABLE_ARCHIVE_ENTRY_BYTES];
    encoded[..4].copy_from_slice(&entry.signature);
    encoded[4] = entry.revision;
    encoded[8..16].copy_from_slice(&entry.physical_address.to_le_bytes());
    encoded[16..24].copy_from_slice(&entry.offset.to_le_bytes());
    encoded[24..28].copy_from_slice(&entry.length.to_le_bytes());
    encoded[28..32].copy_from_slice(&entry.instance.to_le_bytes());
}
