//! GPT cooperation policy core for Hxfs/VolumeManager.
//!
//! Hxfs does not replace GPT. Stage T adds a small no-heap GPT parser core so
//! installers and VolumeManager can validate candidate partitions before handing
//! the selected block range to Hxfs.

use crate::format::Uuid;

/// GPT header signature bytes (`EFI PART`).
pub const GPT_SIGNATURE: u64 = 0x5452_4150_2049_4645;
/// Minimum GPT header bytes parsed by this core.
pub const GPT_HEADER_BYTES: usize = 92;
/// GPT partition entry bytes for the UEFI baseline.
pub const GPT_ENTRY_BYTES: usize = 128;

/// GPT parse/validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GptError {
    /// Header signature is not GPT.
    BadSignature,
    /// Header size/version/entry size is unsupported.
    Unsupported,
    /// A range overflows or violates LBA ordering.
    BadRange,
    /// Partition entry is empty or not found.
    NotFound,
}

/// Decoded GPT header summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptHeader {
    /// Header revision.
    pub revision: u32,
    /// Header byte size.
    pub header_size: u32,
    /// Current header LBA.
    pub current_lba: u64,
    /// Backup header LBA.
    pub backup_lba: u64,
    /// First usable LBA.
    pub first_usable_lba: u64,
    /// Last usable LBA.
    pub last_usable_lba: u64,
    /// Disk GUID.
    pub disk_guid: Uuid,
    /// Partition-entry array starting LBA.
    pub partition_entries_lba: u64,
    /// Number of partition entries.
    pub partition_entry_count: u32,
    /// Partition-entry byte size.
    pub partition_entry_size: u32,
    /// Partition-entry array CRC32 from the header.
    pub partition_entries_crc32: u32,
}

/// Decoded GPT partition entry summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptPartitionEntry {
    /// Partition type GUID.
    pub type_guid: Uuid,
    /// Unique partition GUID.
    pub unique_guid: Uuid,
    /// First LBA inclusive.
    pub first_lba: u64,
    /// Last LBA inclusive.
    pub last_lba: u64,
    /// Attribute bits.
    pub attributes: u64,
}

impl GptPartitionEntry {
    /// Whether this entry is empty.
    pub fn is_empty(self) -> bool {
        self.type_guid == [0; 16]
    }

    /// Number of LBAs covered by this partition.
    pub fn block_count(self) -> Result<u64, GptError> {
        if self.is_empty() || self.last_lba < self.first_lba {
            return Err(GptError::BadRange);
        }
        self.last_lba
            .checked_sub(self.first_lba)
            .and_then(|blocks| blocks.checked_add(1))
            .ok_or(GptError::BadRange)
    }
}

/// Parse a GPT header sector.
pub fn parse_gpt_header(bytes: &[u8]) -> Result<GptHeader, GptError> {
    if bytes.len() < GPT_HEADER_BYTES {
        return Err(GptError::Unsupported);
    }
    let signature = read_u64(bytes, 0)?;
    if signature != GPT_SIGNATURE {
        return Err(GptError::BadSignature);
    }
    let revision = read_u32(bytes, 8)?;
    let header_size = read_u32(bytes, 12)?;
    if header_size < GPT_HEADER_BYTES as u32 || header_size as usize > bytes.len() {
        return Err(GptError::Unsupported);
    }
    let current_lba = read_u64(bytes, 24)?;
    let backup_lba = read_u64(bytes, 32)?;
    let first_usable_lba = read_u64(bytes, 40)?;
    let last_usable_lba = read_u64(bytes, 48)?;
    if first_usable_lba > last_usable_lba {
        return Err(GptError::BadRange);
    }
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(bytes.get(56..72).ok_or(GptError::Unsupported)?);
    let partition_entries_lba = read_u64(bytes, 72)?;
    let partition_entry_count = read_u32(bytes, 80)?;
    let partition_entry_size = read_u32(bytes, 84)?;
    let partition_entries_crc32 = read_u32(bytes, 88)?;
    if partition_entry_count == 0 || partition_entry_size < GPT_ENTRY_BYTES as u32 {
        return Err(GptError::Unsupported);
    }
    Ok(GptHeader {
        revision,
        header_size,
        current_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid,
        partition_entries_lba,
        partition_entry_count,
        partition_entry_size,
        partition_entries_crc32,
    })
}

/// Parse one GPT partition entry.
pub fn parse_partition_entry(bytes: &[u8]) -> Result<GptPartitionEntry, GptError> {
    if bytes.len() < GPT_ENTRY_BYTES {
        return Err(GptError::Unsupported);
    }
    let mut type_guid = [0u8; 16];
    let mut unique_guid = [0u8; 16];
    type_guid.copy_from_slice(bytes.get(0..16).ok_or(GptError::Unsupported)?);
    unique_guid.copy_from_slice(bytes.get(16..32).ok_or(GptError::Unsupported)?);
    let first_lba = read_u64(bytes, 32)?;
    let last_lba = read_u64(bytes, 40)?;
    let attributes = read_u64(bytes, 48)?;
    let entry = GptPartitionEntry {
        type_guid,
        unique_guid,
        first_lba,
        last_lba,
        attributes,
    };
    if !entry.is_empty() {
        let _ = entry.block_count()?;
    }
    Ok(entry)
}

/// Find a partition by unique GUID in a fixed entry buffer.
pub fn find_partition_by_guid(
    entries: &[u8],
    entry_size: u32,
    entry_count: u32,
    unique_guid: Uuid,
) -> Result<GptPartitionEntry, GptError> {
    if entry_size < GPT_ENTRY_BYTES as u32 {
        return Err(GptError::Unsupported);
    }
    let entry_size = entry_size as usize;
    let count = entry_count as usize;
    let mut index = 0usize;
    while index < count {
        let offset = index.checked_mul(entry_size).ok_or(GptError::BadRange)?;
        let end = offset.checked_add(entry_size).ok_or(GptError::BadRange)?;
        if end > entries.len() {
            return Err(GptError::BadRange);
        }
        let entry = parse_partition_entry(&entries[offset..end])?;
        if !entry.is_empty() && entry.unique_guid == unique_guid {
            return Ok(entry);
        }
        index += 1;
    }
    Err(GptError::NotFound)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GptError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(GptError::Unsupported)?
            .try_into()
            .map_err(|_| GptError::Unsupported)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, GptError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(GptError::Unsupported)?
            .try_into()
            .map_err(|_| GptError::Unsupported)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_and_partition_entry() {
        let mut header = [0u8; 512];
        header[0..8].copy_from_slice(&GPT_SIGNATURE.to_le_bytes());
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&(GPT_HEADER_BYTES as u32).to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes());
        header[32..40].copy_from_slice(&99u64.to_le_bytes());
        header[40..48].copy_from_slice(&34u64.to_le_bytes());
        header[48..56].copy_from_slice(&90u64.to_le_bytes());
        header[56..72].copy_from_slice(&[7; 16]);
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&4u32.to_le_bytes());
        header[84..88].copy_from_slice(&(GPT_ENTRY_BYTES as u32).to_le_bytes());
        let parsed = parse_gpt_header(&header);
        assert!(parsed.is_ok());
        let Ok(parsed) = parsed else { return };
        assert_eq!(parsed.first_usable_lba, 34);

        let mut entry = [0u8; GPT_ENTRY_BYTES];
        entry[0..16].copy_from_slice(&[1; 16]);
        entry[16..32].copy_from_slice(&[2; 16]);
        entry[32..40].copy_from_slice(&40u64.to_le_bytes());
        entry[40..48].copy_from_slice(&49u64.to_le_bytes());
        let entry = parse_partition_entry(&entry);
        assert!(entry.is_ok());
        let Ok(entry) = entry else { return };
        assert_eq!(entry.block_count(), Ok(10));
    }

    #[test]
    fn finds_partition_by_unique_guid() {
        let mut entries = [0u8; GPT_ENTRY_BYTES * 2];
        entries[0..16].copy_from_slice(&[1; 16]);
        entries[16..32].copy_from_slice(&[9; 16]);
        entries[32..40].copy_from_slice(&10u64.to_le_bytes());
        entries[40..48].copy_from_slice(&20u64.to_le_bytes());
        assert_eq!(
            find_partition_by_guid(&entries, GPT_ENTRY_BYTES as u32, 2, [9; 16])
                .map(|entry| entry.first_lba),
            Ok(10)
        );
        assert_eq!(
            find_partition_by_guid(&entries, GPT_ENTRY_BYTES as u32, 2, [8; 16]),
            Err(GptError::NotFound)
        );
    }
}
