//! Hxblob immutable package-view primitives.
//!
//! Hxblob is Hxfs's BlobFS-compatible per-volume subsystem: immutable
//! content-addressed objects with a `hash -> ObjectId` index. This module is a
//! fixed-capacity, no-heap policy model for Stage I.

/// Content hash bytes. SHA-256 for v1 compatibility with current BlobFS work.
pub type BlobHash = [u8; 32];

/// One Hxblob index entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HxblobEntry {
    /// Content hash.
    pub hash: BlobHash,
    /// Backing Hxfs object id.
    pub object_id: u64,
    /// Blob size in bytes.
    pub size: u64,
}

/// Hxblob index operation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HxblobError {
    /// Index is full.
    Full,
    /// Same hash already exists with a different object id/size.
    DuplicateHash,
    /// Blob was not found.
    NotFound,
}

/// Fixed-capacity Hxblob index.
pub struct HxblobIndex<const N: usize> {
    entries: [Option<HxblobEntry>; N],
}

impl<const N: usize> Default for HxblobIndex<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HxblobIndex<N> {
    /// Empty index.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; N],
        }
    }

    /// Insert a write-once blob mapping. Duplicate identical mappings are
    /// accepted as idempotent dedup hits.
    pub fn insert(&mut self, entry: HxblobEntry) -> Result<(), HxblobError> {
        for existing in self.entries.iter().flatten() {
            if existing.hash == entry.hash {
                return if *existing == entry {
                    Ok(())
                } else {
                    Err(HxblobError::DuplicateHash)
                };
            }
        }
        let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) else {
            return Err(HxblobError::Full);
        };
        *slot = Some(entry);
        Ok(())
    }

    /// Lookup by hash.
    pub fn lookup(&self, hash: &BlobHash) -> Result<HxblobEntry, HxblobError> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| &entry.hash == hash)
            .copied()
            .ok_or(HxblobError::NotFound)
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Merkle tree sizing for immutable package verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MerklePlan {
    /// Leaf count.
    pub leaves: u64,
    /// Total hash nodes including root.
    pub total_nodes: u64,
    /// Number of tree levels including leaf level and root.
    pub levels: u32,
}

/// Plan a binary Merkle tree for `payload_bytes` and `chunk_bytes`.
pub fn plan_merkle(payload_bytes: u64, chunk_bytes: u32) -> Option<MerklePlan> {
    if chunk_bytes == 0 || !chunk_bytes.is_power_of_two() {
        return None;
    }
    let mut level_nodes = payload_bytes.div_ceil(u64::from(chunk_bytes)).max(1);
    let leaves = level_nodes;
    let mut total = 0u64;
    let mut levels = 0u32;
    loop {
        total = total.checked_add(level_nodes)?;
        levels = levels.checked_add(1)?;
        if level_nodes == 1 {
            break;
        }
        level_nodes = level_nodes.div_ceil(2);
    }
    Some(MerklePlan {
        leaves,
        total_nodes: total,
        levels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> BlobHash {
        [byte; 32]
    }

    #[test]
    fn insert_lookup_and_dedup() {
        let mut index = HxblobIndex::<2>::new();
        let entry = HxblobEntry {
            hash: hash(1),
            object_id: 42,
            size: 7,
        };
        assert_eq!(index.insert(entry), Ok(()));
        assert_eq!(index.insert(entry), Ok(()));
        assert_eq!(index.lookup(&hash(1)), Ok(entry));
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn rejects_duplicate_hash_with_different_object() {
        let mut index = HxblobIndex::<2>::new();
        assert_eq!(
            index.insert(HxblobEntry {
                hash: hash(1),
                object_id: 1,
                size: 1,
            }),
            Ok(())
        );
        assert_eq!(
            index.insert(HxblobEntry {
                hash: hash(1),
                object_id: 2,
                size: 1,
            }),
            Err(HxblobError::DuplicateHash)
        );
    }

    #[test]
    fn merkle_plan_counts_levels() {
        assert_eq!(
            plan_merkle(8192, 4096),
            Some(MerklePlan {
                leaves: 2,
                total_nodes: 3,
                levels: 2,
            })
        );
    }
}
