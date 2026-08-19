//! Immutable ACPI archive-v2 producer for the isolated Ring-3 runtime.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use huesos_abi::acpi_archive::{
    self, ArchiveV2Header, ArchiveV2TableEntry, PhysicalMappingEntry, RsdpDescriptor, HEADER_BYTES,
    MAPPING_ENTRY_BYTES, MAPPING_KIND_RSDP, MAPPING_KIND_TABLE, NO_MAPPING_INDEX,
    TABLE_ENTRY_BYTES, TABLE_FLAG_FACS,
};
use huesos_abi::acpi_broker::{MAX_ARCHIVE_BYTES, MAX_TABLES, MAX_TABLE_BYTES};

static NEXT_FIRMWARE_SNAPSHOT_ID: AtomicU64 = AtomicU64::new(1);

/// Failure while snapshotting uACPI's validated table graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveBuildError {
    /// uACPI reported too many installed tables.
    TooManyTables,
    /// A referenced SDT disappeared or had inconsistent metadata.
    InvalidTable,
    /// The boot RSDP could not be copied and validated.
    InvalidRsdp,
    /// The FADT-referenced FACS could not be copied and validated.
    InvalidFacs,
    /// Aggregate size or address arithmetic exceeded the bounded format.
    TooLarge,
    /// Kernel allocation failed.
    OutOfMemory,
    /// The assembled snapshot failed canonical archive-v2 validation.
    InvalidSnapshot,
}

#[derive(Clone, Copy)]
enum EntrySource<'a> {
    Installed(usize),
    Borrowed(&'a [u8]),
}

#[derive(Clone, Copy)]
struct Entry<'a> {
    source: EntrySource<'a>,
    signature: [u8; 4],
    revision: u8,
    flags: u16,
    physical_address: u64,
    offset: u64,
    length: u32,
    instance: u32,
    mapping_index: u32,
}

#[derive(Clone, Copy)]
struct MappingBuild {
    owner: Option<usize>,
    mapping: PhysicalMappingEntry,
}

/// Copy the complete barebones-uACPI table graph into a canonical version-2
/// archive, including the boot RSDP and FADT-selected FACS.
///
/// The function runs during single-threaded BSP bootstrap. Installed tables are
/// reacquired by stable index for the copy pass, and the final bytes are
/// validated by the same streaming decoder used by Ring 3 before publication.
pub fn build(rsdp_physical: u64) -> Result<Vec<u8>, ArchiveBuildError> {
    let rsdp =
        huesos_uacpi::rsdp_snapshot(rsdp_physical).map_err(|_| ArchiveBuildError::InvalidRsdp)?;
    let facs = huesos_uacpi::facs_snapshot().map_err(|_| ArchiveBuildError::InvalidFacs)?;
    let installed_count = huesos_uacpi::table_count();
    let total_entries = installed_count
        .checked_add(usize::from(facs.is_some()))
        .ok_or(ArchiveBuildError::TooManyTables)?;
    if total_entries > MAX_TABLES as usize {
        return Err(ArchiveBuildError::TooManyTables);
    }

    let mut entries = Vec::new();
    entries
        .try_reserve_exact(total_entries)
        .map_err(|_| ArchiveBuildError::OutOfMemory)?;
    let mut instances = BTreeMap::<[u8; 4], u32>::new();

    for index in 0..installed_count {
        let metadata =
            huesos_uacpi::table_metadata(index).map_err(|_| ArchiveBuildError::InvalidTable)?;
        if metadata.checksum_bad {
            return Err(ArchiveBuildError::InvalidTable);
        }
        let table = huesos_uacpi::Table::get(index).map_err(|_| ArchiveBuildError::InvalidTable)?;
        let bytes = table.bytes().map_err(|_| ArchiveBuildError::InvalidTable)?;
        let signature = table
            .signature()
            .map_err(|_| ArchiveBuildError::InvalidTable)?;
        let revision = table
            .revision()
            .map_err(|_| ArchiveBuildError::InvalidTable)?;
        let length = u32::try_from(bytes.len()).map_err(|_| ArchiveBuildError::TooLarge)?;
        if !(36..=MAX_TABLE_BYTES).contains(&length)
            || metadata.length != bytes.len()
            || metadata.signature != signature
            || signature == *b"FACS"
        {
            return Err(ArchiveBuildError::InvalidTable);
        }
        let instance = next_instance(&mut instances, signature)?;
        entries.push(Entry {
            source: EntrySource::Installed(index),
            signature,
            revision,
            flags: 0,
            physical_address: metadata.physical_address.unwrap_or(0),
            offset: 0,
            length,
            instance,
            mapping_index: NO_MAPPING_INDEX,
        });
    }

    if let Some(facs) = facs {
        let length = u32::try_from(facs.bytes.len()).map_err(|_| ArchiveBuildError::TooLarge)?;
        if !(64..=MAX_TABLE_BYTES).contains(&length) {
            return Err(ArchiveBuildError::InvalidFacs);
        }
        let instance = next_instance(&mut instances, *b"FACS")?;
        entries.push(Entry {
            source: EntrySource::Borrowed(facs.bytes),
            signature: *b"FACS",
            revision: facs.version,
            flags: TABLE_FLAG_FACS,
            physical_address: facs.physical_address,
            offset: 0,
            length,
            instance,
            mapping_index: NO_MAPPING_INDEX,
        });
    }

    let snapshot_id = NEXT_FIRMWARE_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed);
    if snapshot_id == 0 || snapshot_id == u64::MAX {
        return Err(ArchiveBuildError::TooLarge);
    }
    encode_snapshot(
        rsdp.physical_address,
        rsdp.revision,
        rsdp.bytes,
        snapshot_id,
        &mut entries,
    )
}

fn next_instance(
    instances: &mut BTreeMap<[u8; 4], u32>,
    signature: [u8; 4],
) -> Result<u32, ArchiveBuildError> {
    let value = instances.entry(signature).or_insert(0);
    let current = *value;
    *value = value
        .checked_add(1)
        .ok_or(ArchiveBuildError::TooManyTables)?;
    Ok(current)
}

fn encode_snapshot(
    rsdp_physical: u64,
    rsdp_revision: u8,
    rsdp_bytes: &[u8],
    snapshot_id: u64,
    entries: &mut [Entry<'_>],
) -> Result<Vec<u8>, ArchiveBuildError> {
    if snapshot_id == 0
        || rsdp_physical == 0
        || !matches!((rsdp_revision, rsdp_bytes.len()), (0, 20) | (2.., 36))
        || entries.len() > MAX_TABLES as usize
    {
        return Err(ArchiveBuildError::InvalidSnapshot);
    }
    let physical_table_count = entries
        .iter()
        .filter(|entry| entry.physical_address != 0)
        .count();
    let mapping_count = 1usize
        .checked_add(physical_table_count)
        .ok_or(ArchiveBuildError::TooLarge)?;
    if mapping_count > acpi_archive::MAX_PHYSICAL_MAPPINGS as usize {
        return Err(ArchiveBuildError::TooManyTables);
    }

    let table_entries_offset = HEADER_BYTES;
    let mappings_offset = table_entries_offset
        .checked_add(
            entries
                .len()
                .checked_mul(TABLE_ENTRY_BYTES)
                .ok_or(ArchiveBuildError::TooLarge)?,
        )
        .ok_or(ArchiveBuildError::TooLarge)?;
    let payload_offset = mappings_offset
        .checked_add(
            mapping_count
                .checked_mul(MAPPING_ENTRY_BYTES)
                .ok_or(ArchiveBuildError::TooLarge)?,
        )
        .ok_or(ArchiveBuildError::TooLarge)?;
    let rsdp_offset = payload_offset;
    let mut cursor = rsdp_offset
        .checked_add(rsdp_bytes.len())
        .ok_or(ArchiveBuildError::TooLarge)?;
    for entry in entries.iter_mut() {
        entry.offset = cursor as u64;
        cursor = cursor
            .checked_add(entry.length as usize)
            .ok_or(ArchiveBuildError::TooLarge)?;
    }
    if cursor as u64 > MAX_ARCHIVE_BYTES {
        return Err(ArchiveBuildError::TooLarge);
    }

    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(mapping_count)
        .map_err(|_| ArchiveBuildError::OutOfMemory)?;
    mappings.push(MappingBuild {
        owner: None,
        mapping: PhysicalMappingEntry {
            physical_address: rsdp_physical,
            offset: rsdp_offset as u64,
            length: rsdp_bytes.len() as u64,
            kind: MAPPING_KIND_RSDP,
        },
    });
    for (index, entry) in entries.iter().enumerate() {
        if entry.physical_address != 0 {
            mappings.push(MappingBuild {
                owner: Some(index),
                mapping: PhysicalMappingEntry {
                    physical_address: entry.physical_address,
                    offset: entry.offset,
                    length: u64::from(entry.length),
                    kind: MAPPING_KIND_TABLE,
                },
            });
        }
    }
    mappings.sort_unstable_by_key(|entry| entry.mapping.physical_address);

    let mut rsdp_mapping_index = None;
    let mut previous_physical_end = 0u64;
    for (index, mapping) in mappings.iter().enumerate() {
        if mapping.mapping.physical_address == 0 || mapping.mapping.length == 0 {
            return Err(ArchiveBuildError::InvalidSnapshot);
        }
        if index != 0 && mapping.mapping.physical_address < previous_physical_end {
            return Err(ArchiveBuildError::InvalidSnapshot);
        }
        previous_physical_end = mapping
            .mapping
            .physical_address
            .checked_add(mapping.mapping.length)
            .ok_or(ArchiveBuildError::TooLarge)?;
        let index = u32::try_from(index).map_err(|_| ArchiveBuildError::TooManyTables)?;
        match mapping.owner {
            Some(owner) => entries[owner].mapping_index = index,
            None => rsdp_mapping_index = Some(index),
        }
    }
    let Some(rsdp_mapping_index) = rsdp_mapping_index else {
        return Err(ArchiveBuildError::InvalidSnapshot);
    };

    let mut archive = Vec::new();
    archive
        .try_reserve_exact(cursor)
        .map_err(|_| ArchiveBuildError::OutOfMemory)?;
    archive.resize(cursor, 0);
    let header = ArchiveV2Header {
        total_size: cursor as u64,
        firmware_snapshot_id: snapshot_id,
        table_count: entries.len() as u32,
        mapping_count: mappings.len() as u32,
        table_entries_offset: table_entries_offset as u64,
        mappings_offset: mappings_offset as u64,
        payload_offset: payload_offset as u64,
        rsdp: RsdpDescriptor {
            physical_address: rsdp_physical,
            offset: rsdp_offset as u64,
            length: rsdp_bytes.len() as u32,
            mapping_index: rsdp_mapping_index,
            revision: rsdp_revision,
        },
    };
    acpi_archive::encode_v2_header(&header, &mut archive[..HEADER_BYTES])
        .map_err(|_| ArchiveBuildError::InvalidSnapshot)?;
    for (index, entry) in entries.iter().enumerate() {
        let start = table_entries_offset + index * TABLE_ENTRY_BYTES;
        let wire = ArchiveV2TableEntry {
            signature: entry.signature,
            revision: entry.revision,
            flags: entry.flags,
            physical_address: entry.physical_address,
            offset: entry.offset,
            length: entry.length,
            instance: entry.instance,
            mapping_index: entry.mapping_index,
        };
        acpi_archive::encode_v2_table_entry(&wire, &mut archive[start..start + TABLE_ENTRY_BYTES])
            .map_err(|_| ArchiveBuildError::InvalidSnapshot)?;
    }
    for (index, mapping) in mappings.iter().enumerate() {
        let start = mappings_offset + index * MAPPING_ENTRY_BYTES;
        acpi_archive::encode_v2_mapping(
            &mapping.mapping,
            &mut archive[start..start + MAPPING_ENTRY_BYTES],
        )
        .map_err(|_| ArchiveBuildError::InvalidSnapshot)?;
    }
    archive[rsdp_offset..rsdp_offset + rsdp_bytes.len()].copy_from_slice(rsdp_bytes);
    for entry in entries.iter() {
        let start = entry.offset as usize;
        let end = start
            .checked_add(entry.length as usize)
            .ok_or(ArchiveBuildError::TooLarge)?;
        match entry.source {
            EntrySource::Installed(index) => {
                let table =
                    huesos_uacpi::Table::get(index).map_err(|_| ArchiveBuildError::InvalidTable)?;
                let bytes = table.bytes().map_err(|_| ArchiveBuildError::InvalidTable)?;
                if bytes.len() != entry.length as usize
                    || bytes.get(..4) != Some(entry.signature.as_slice())
                    || bytes.get(8).copied() != Some(entry.revision)
                {
                    return Err(ArchiveBuildError::InvalidTable);
                }
                archive[start..end].copy_from_slice(bytes);
            }
            EntrySource::Borrowed(bytes) => {
                if bytes.len() != entry.length as usize {
                    return Err(ArchiveBuildError::InvalidTable);
                }
                archive[start..end].copy_from_slice(bytes);
            }
        }
    }

    acpi_archive::validate(&archive[..], archive.len() as u64)
        .map_err(|_| ArchiveBuildError::InvalidSnapshot)?;
    Ok(archive)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
    }

    fn finalize_checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset] = 0u8.wrapping_sub(checksum(bytes));
    }

    fn rsdp() -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[..8].copy_from_slice(b"RSD PTR ");
        bytes[15] = 2;
        bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
        finalize_checksum(&mut bytes[..20], 8);
        finalize_checksum(&mut bytes, 32);
        bytes
    }

    fn sdt(signature: [u8; 4], revision: u8) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[..4].copy_from_slice(&signature);
        bytes[4..8].copy_from_slice(&36u32.to_le_bytes());
        bytes[8] = revision;
        finalize_checksum(&mut bytes, 9);
        bytes
    }

    fn facs() -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..4].copy_from_slice(b"FACS");
        bytes[4..8].copy_from_slice(&64u32.to_le_bytes());
        bytes[32] = 2;
        bytes
    }

    #[test]
    fn pure_encoder_sorts_mappings_and_round_trips() {
        let rsdp = rsdp();
        let table = sdt(*b"FACP", 6);
        let facs = facs();
        let mut entries = [
            Entry {
                source: EntrySource::Borrowed(&table),
                signature: *b"FACP",
                revision: 6,
                flags: 0,
                physical_address: 0x3000,
                offset: 0,
                length: table.len() as u32,
                instance: 0,
                mapping_index: NO_MAPPING_INDEX,
            },
            Entry {
                source: EntrySource::Borrowed(&facs),
                signature: *b"FACS",
                revision: 2,
                flags: TABLE_FLAG_FACS,
                physical_address: 0x2000,
                offset: 0,
                length: facs.len() as u32,
                instance: 0,
                mapping_index: NO_MAPPING_INDEX,
            },
        ];
        let encoded = encode_snapshot(0x1000, 2, &rsdp, 9, &mut entries);
        assert!(encoded.as_ref().is_ok_and(|bytes| {
            acpi_archive::validate(&bytes[..], bytes.len() as u64).is_ok_and(|summary| {
                summary.version == acpi_archive::VERSION
                    && summary.table_count == 2
                    && summary.mapping_count == 3
                    && summary.firmware_snapshot_id == 9
            })
        }));
        assert_eq!(entries[1].mapping_index, 1);
        assert_eq!(entries[0].mapping_index, 2);
    }

    #[test]
    fn pure_encoder_rejects_overlapping_physical_objects() {
        let rsdp = rsdp();
        let table = sdt(*b"SSDT", 2);
        let mut entries = [Entry {
            source: EntrySource::Borrowed(&table),
            signature: *b"SSDT",
            revision: 2,
            flags: 0,
            physical_address: 0x1010,
            offset: 0,
            length: table.len() as u32,
            instance: 0,
            mapping_index: NO_MAPPING_INDEX,
        }];
        assert_eq!(
            encode_snapshot(0x1000, 2, &rsdp, 1, &mut entries),
            Err(ArchiveBuildError::InvalidSnapshot)
        );
    }

    #[test]
    fn pure_encoder_rejects_zero_snapshot_identity() {
        let rsdp = rsdp();
        let mut entries = [];
        assert_eq!(
            encode_snapshot(0x1000, 2, &rsdp, 0, &mut entries),
            Err(ArchiveBuildError::InvalidSnapshot)
        );
    }
}
