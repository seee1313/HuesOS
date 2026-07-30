//! Persistent no-heap Hxblob index and Merkle metadata trees.
//!
//! Stage R keeps Hxblob write-once state in fixed-capacity sorted root-leaf
//! trees. The actual blob bytes live as immutable Hxfs file objects; the index
//! maps `hash(content) -> ObjectId`, while Merkle descriptors point at metadata
//! needed for chunk verification.

use crate::hxblob::{BlobHash, HxblobError};

/// Hxblob tree operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HxblobTreeError {
    /// Index is full.
    Full,
    /// Same hash already exists with different metadata.
    DuplicateHash,
    /// Entry was not found.
    NotFound,
    /// Record shape is invalid.
    BadRecord,
}

impl From<HxblobTreeError> for HxblobError {
    fn from(error: HxblobTreeError) -> Self {
        match error {
            HxblobTreeError::Full => Self::Full,
            HxblobTreeError::DuplicateHash => Self::DuplicateHash,
            HxblobTreeError::NotFound | HxblobTreeError::BadRecord => Self::NotFound,
        }
    }
}

/// Persistent Hxblob index record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HxblobIndexRecord {
    /// Content hash.
    pub hash: BlobHash,
    /// Backing immutable Hxfs object id.
    pub object_id: u64,
    /// Blob size in bytes.
    pub size: u64,
    /// Merkle root hash.
    pub merkle_root: BlobHash,
    /// Merkle metadata tree LBA, or zero for single-chunk blobs.
    pub merkle_tree_lba: u64,
    /// Write-once flags. Reserved bits must be zero.
    pub flags: u32,
}

/// Persistent Hxblob Merkle descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HxblobMerkleRecord {
    /// Content hash this Merkle descriptor belongs to.
    pub hash: BlobHash,
    /// Merkle root hash.
    pub merkle_root: BlobHash,
    /// Chunk size in bytes.
    pub chunk_bytes: u32,
    /// Number of leaf chunks.
    pub leaves: u64,
    /// Total nodes including root.
    pub total_nodes: u64,
    /// Tree level count.
    pub levels: u32,
    /// Metadata payload LBA, or zero if stored inline/future.
    pub metadata_lba: u64,
}

/// Fixed-capacity Hxblob hash -> object index tree.
pub struct HxblobIndexTree<const N: usize> {
    records: [Option<HxblobIndexRecord>; N],
}

impl<const N: usize> Default for HxblobIndexTree<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HxblobIndexTree<N> {
    /// Create an empty Hxblob index tree.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
        }
    }

    /// Immutable record array.
    pub const fn records(&self) -> &[Option<HxblobIndexRecord>; N] {
        &self.records
    }

    /// Number of live records.
    pub fn record_count(&self) -> usize {
        count_options(&self.records)
    }

    /// Insert one write-once Hxblob mapping. Identical records are idempotent
    /// dedup hits; same hash with different metadata is rejected.
    pub fn insert(&mut self, record: HxblobIndexRecord) -> Result<(), HxblobTreeError> {
        validate_index_record(record)?;
        let mut free = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(existing) = self.records[index] {
                if existing.hash == record.hash {
                    return if existing == record {
                        Ok(())
                    } else {
                        Err(HxblobTreeError::DuplicateHash)
                    };
                }
            } else if free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(HxblobTreeError::Full)?;
        self.records[slot] = Some(record);
        self.sort();
        Ok(())
    }

    /// Lookup by content hash.
    pub fn lookup(&self, hash: &BlobHash) -> Result<HxblobIndexRecord, HxblobTreeError> {
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if &record.hash == hash {
                    return Ok(record);
                }
            }
            index += 1;
        }
        Err(HxblobTreeError::NotFound)
    }

    /// Validate sorted write-once index invariants.
    pub fn validate(&self) -> Result<(), HxblobTreeError> {
        let mut previous: Option<BlobHash> = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                validate_index_record(record)?;
                if let Some(prev) = previous {
                    if prev >= record.hash {
                        return Err(HxblobTreeError::DuplicateHash);
                    }
                }
                previous = Some(record.hash);
            }
            index += 1;
        }
        Ok(())
    }

    fn sort(&mut self) {
        sort_index_records(&mut self.records);
    }
}

/// Fixed-capacity Hxblob Merkle descriptor tree.
pub struct HxblobMerkleTree<const N: usize> {
    records: [Option<HxblobMerkleRecord>; N],
}

impl<const N: usize> Default for HxblobMerkleTree<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HxblobMerkleTree<N> {
    /// Create an empty Merkle metadata tree.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
        }
    }

    /// Immutable record array.
    pub const fn records(&self) -> &[Option<HxblobMerkleRecord>; N] {
        &self.records
    }

    /// Number of live records.
    pub fn record_count(&self) -> usize {
        count_options(&self.records)
    }

    /// Insert one Merkle descriptor.
    pub fn insert(&mut self, record: HxblobMerkleRecord) -> Result<(), HxblobTreeError> {
        validate_merkle_record(record)?;
        let mut free = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(existing) = self.records[index] {
                if existing.hash == record.hash {
                    return if existing == record {
                        Ok(())
                    } else {
                        Err(HxblobTreeError::DuplicateHash)
                    };
                }
            } else if free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(HxblobTreeError::Full)?;
        self.records[slot] = Some(record);
        self.sort();
        Ok(())
    }

    /// Lookup Merkle descriptor by content hash.
    pub fn lookup(&self, hash: &BlobHash) -> Result<HxblobMerkleRecord, HxblobTreeError> {
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if &record.hash == hash {
                    return Ok(record);
                }
            }
            index += 1;
        }
        Err(HxblobTreeError::NotFound)
    }

    /// Validate sorted Merkle descriptor invariants.
    pub fn validate(&self) -> Result<(), HxblobTreeError> {
        let mut previous: Option<BlobHash> = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                validate_merkle_record(record)?;
                if let Some(prev) = previous {
                    if prev >= record.hash {
                        return Err(HxblobTreeError::DuplicateHash);
                    }
                }
                previous = Some(record.hash);
            }
            index += 1;
        }
        Ok(())
    }

    fn sort(&mut self) {
        sort_merkle_records(&mut self.records);
    }
}

fn validate_index_record(record: HxblobIndexRecord) -> Result<(), HxblobTreeError> {
    if record.object_id == 0 || record.size == 0 || record.flags != 0 {
        return Err(HxblobTreeError::BadRecord);
    }
    Ok(())
}

fn validate_merkle_record(record: HxblobMerkleRecord) -> Result<(), HxblobTreeError> {
    if record.chunk_bytes == 0
        || record.leaves == 0
        || record.total_nodes == 0
        || record.levels == 0
    {
        return Err(HxblobTreeError::BadRecord);
    }
    Ok(())
}

fn count_options<T: Copy, const N: usize>(records: &[Option<T>; N]) -> usize {
    let mut count = 0usize;
    let mut index = 0usize;
    while index < records.len() {
        if records[index].is_some() {
            count += 1;
        }
        index += 1;
    }
    count
}

fn sort_index_records<const N: usize>(records: &mut [Option<HxblobIndexRecord>; N]) {
    let mut i = 0usize;
    while i < records.len() {
        let mut j = i + 1;
        while j < records.len() {
            if should_swap_index(records[i], records[j]) {
                records.swap(i, j);
            }
            j += 1;
        }
        i += 1;
    }
}

fn sort_merkle_records<const N: usize>(records: &mut [Option<HxblobMerkleRecord>; N]) {
    let mut i = 0usize;
    while i < records.len() {
        let mut j = i + 1;
        while j < records.len() {
            if should_swap_merkle(records[i], records[j]) {
                records.swap(i, j);
            }
            j += 1;
        }
        i += 1;
    }
}

fn should_swap_index(left: Option<HxblobIndexRecord>, right: Option<HxblobIndexRecord>) -> bool {
    match (left, right) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => a.hash > b.hash,
        _ => false,
    }
}

fn should_swap_merkle(left: Option<HxblobMerkleRecord>, right: Option<HxblobMerkleRecord>) -> bool {
    match (left, right) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => a.hash > b.hash,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> BlobHash {
        [byte; 32]
    }

    fn entry(byte: u8, object_id: u64) -> HxblobIndexRecord {
        HxblobIndexRecord {
            hash: hash(byte),
            object_id,
            size: 4096,
            merkle_root: hash(byte.wrapping_add(1)),
            merkle_tree_lba: 100 + object_id,
            flags: 0,
        }
    }

    #[test]
    fn persistent_index_is_write_once_and_sorted() {
        let mut tree = HxblobIndexTree::<4>::new();
        assert!(tree.insert(entry(9, 9)).is_ok());
        assert!(tree.insert(entry(1, 1)).is_ok());
        assert!(tree.insert(entry(1, 1)).is_ok());
        assert_eq!(tree.records()[0].map(|record| record.hash), Some(hash(1)));
        assert_eq!(tree.lookup(&hash(9)).map(|record| record.object_id), Ok(9));
        assert_eq!(tree.validate(), Ok(()));
        assert_eq!(
            tree.insert(entry(1, 2)),
            Err(HxblobTreeError::DuplicateHash)
        );
    }

    #[test]
    fn merkle_descriptors_are_write_once() {
        let mut tree = HxblobMerkleTree::<2>::new();
        let record = HxblobMerkleRecord {
            hash: hash(1),
            merkle_root: hash(2),
            chunk_bytes: 4096,
            leaves: 4,
            total_nodes: 7,
            levels: 3,
            metadata_lba: 55,
        };
        assert!(tree.insert(record).is_ok());
        assert!(tree.insert(record).is_ok());
        assert_eq!(tree.lookup(&hash(1)), Ok(record));
        assert_eq!(tree.validate(), Ok(()));
    }
}
