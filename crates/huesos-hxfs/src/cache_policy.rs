//! No-heap cache, writeback, mmap, and direct-I/O policy core.
//!
//! Stage S keeps runtime policy decisions host-testable and independent of the
//! service implementation. The structures here are fixed-capacity and suitable
//! for `hxfs-service` without a heap.

use crate::format::{Uuid, BLOCK_SIZE, BLOCK_SIZE_U64};
use crate::io_policy::direct_io_aligned;

/// Cache policy operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CachePolicyError {
    /// The fixed cache/queue is full and no eviction is possible.
    Full,
    /// Requested entry was not found.
    NotFound,
    /// Dirty entries must be written back before eviction.
    Dirty,
    /// Invalid mmap/direct-I/O request shape.
    Invalid,
}

/// File-cache key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheKey {
    /// Virtual volume UUID.
    pub volume_uuid: Uuid,
    /// Object id.
    pub object_id: u64,
    /// Logical 4 KiB block inside the object.
    pub logical_block: u64,
}

/// One fixed cache entry descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheEntry {
    /// Cache key.
    pub key: CacheKey,
    /// Backing physical block currently cached.
    pub physical_block: u64,
    /// Last access tick for LRU-style eviction.
    pub last_access_tick: u64,
    /// Whether data is dirty and must be written back before eviction.
    pub dirty: bool,
}

/// Fixed-capacity file-cache metadata.
pub struct FixedCache<const N: usize> {
    entries: [Option<CacheEntry>; N],
}

impl<const N: usize> Default for FixedCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FixedCache<N> {
    /// Empty cache metadata table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; N],
        }
    }

    /// Immutable entries for diagnostics/tests.
    pub const fn entries(&self) -> &[Option<CacheEntry>; N] {
        &self.entries
    }

    /// Find a cache entry.
    pub fn lookup(&mut self, key: CacheKey, tick: u64) -> Result<CacheEntry, CachePolicyError> {
        let mut index = 0usize;
        while index < self.entries.len() {
            if let Some(mut entry) = self.entries[index] {
                if entry.key == key {
                    entry.last_access_tick = tick;
                    self.entries[index] = Some(entry);
                    return Ok(entry);
                }
            }
            index += 1;
        }
        Err(CachePolicyError::NotFound)
    }

    /// Insert or update a clean cache entry. If full, evicts the clean least
    /// recently used entry.
    pub fn admit_clean(
        &mut self,
        key: CacheKey,
        physical_block: u64,
        tick: u64,
    ) -> Result<Option<CacheEntry>, CachePolicyError> {
        if let Ok(existing) = self.lookup(key, tick) {
            let index = self.index_of(key).ok_or(CachePolicyError::NotFound)?;
            self.entries[index] = Some(CacheEntry {
                physical_block,
                dirty: existing.dirty,
                ..existing
            });
            return Ok(None);
        }
        if let Some(index) = self.free_slot() {
            self.entries[index] = Some(CacheEntry {
                key,
                physical_block,
                last_access_tick: tick,
                dirty: false,
            });
            return Ok(None);
        }
        let evict = self.clean_lru_index().ok_or(CachePolicyError::Dirty)?;
        let victim = self.entries[evict];
        self.entries[evict] = Some(CacheEntry {
            key,
            physical_block,
            last_access_tick: tick,
            dirty: false,
        });
        Ok(victim)
    }

    /// Mark an entry dirty.
    pub fn mark_dirty(&mut self, key: CacheKey, tick: u64) -> Result<(), CachePolicyError> {
        let index = self.index_of(key).ok_or(CachePolicyError::NotFound)?;
        let Some(mut entry) = self.entries[index] else {
            return Err(CachePolicyError::NotFound);
        };
        entry.dirty = true;
        entry.last_access_tick = tick;
        self.entries[index] = Some(entry);
        Ok(())
    }

    /// Mark one entry clean after writeback.
    pub fn mark_clean(&mut self, key: CacheKey) -> Result<(), CachePolicyError> {
        let index = self.index_of(key).ok_or(CachePolicyError::NotFound)?;
        let Some(mut entry) = self.entries[index] else {
            return Err(CachePolicyError::NotFound);
        };
        entry.dirty = false;
        self.entries[index] = Some(entry);
        Ok(())
    }

    /// Count dirty cache entries.
    pub fn dirty_count(&self) -> usize {
        let mut count = 0usize;
        let mut index = 0usize;
        while index < self.entries.len() {
            if self.entries[index]
                .map(|entry| entry.dirty)
                .unwrap_or(false)
            {
                count += 1;
            }
            index += 1;
        }
        count
    }

    fn free_slot(&self) -> Option<usize> {
        let mut index = 0usize;
        while index < self.entries.len() {
            if self.entries[index].is_none() {
                return Some(index);
            }
            index += 1;
        }
        None
    }

    fn clean_lru_index(&self) -> Option<usize> {
        let mut best: Option<(usize, u64)> = None;
        let mut index = 0usize;
        while index < self.entries.len() {
            if let Some(entry) = self.entries[index] {
                if !entry.dirty {
                    match best {
                        Some((_, tick)) if tick <= entry.last_access_tick => {}
                        _ => best = Some((index, entry.last_access_tick)),
                    }
                }
            }
            index += 1;
        }
        best.map(|(index, _)| index)
    }

    fn index_of(&self, key: CacheKey) -> Option<usize> {
        let mut index = 0usize;
        while index < self.entries.len() {
            if self.entries[index]
                .map(|entry| entry.key == key)
                .unwrap_or(false)
            {
                return Some(index);
            }
            index += 1;
        }
        None
    }
}

/// One dirty writeback record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritebackRecord {
    /// Cache key.
    pub key: CacheKey,
    /// Transaction/checkpoint generation that dirtied this block.
    pub generation: u64,
}

/// Fixed-capacity writeback queue.
pub struct WritebackQueue<const N: usize> {
    records: [Option<WritebackRecord>; N],
}

impl<const N: usize> Default for WritebackQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> WritebackQueue<N> {
    /// Create an empty writeback queue.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
        }
    }

    /// Enqueue a dirty block if it is not already queued.
    pub fn enqueue(&mut self, record: WritebackRecord) -> Result<(), CachePolicyError> {
        let mut free = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(existing) = self.records[index] {
                if existing.key == record.key {
                    self.records[index] = Some(record);
                    return Ok(());
                }
            } else if free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(CachePolicyError::Full)?;
        self.records[slot] = Some(record);
        Ok(())
    }

    /// Pop the oldest generation first.
    pub fn pop_oldest(&mut self) -> Option<WritebackRecord> {
        let mut best: Option<(usize, u64)> = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                match best {
                    Some((_, generation)) if generation <= record.generation => {}
                    _ => best = Some((index, record.generation)),
                }
            }
            index += 1;
        }
        let (index, _) = best?;
        let record = self.records[index];
        self.records[index] = None;
        record
    }

    /// Number of queued records.
    pub fn len(&self) -> usize {
        let mut count = 0usize;
        let mut index = 0usize;
        while index < self.records.len() {
            if self.records[index].is_some() {
                count += 1;
            }
            index += 1;
        }
        count
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// File mmap permission request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmapRequest {
    /// Byte offset.
    pub offset: u64,
    /// Byte length.
    pub length: u64,
    /// Writable mapping requested.
    pub writable: bool,
    /// Volume is encrypted.
    pub encrypted: bool,
    /// Object has compressed extents.
    pub compressed: bool,
}

/// Mmap policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmapDecision {
    /// Mapping may be served by a read-only VMO snapshot.
    ReadOnlySnapshot,
    /// Writable mmap is deferred until coherent writeback is implemented.
    DenyWritable,
    /// Mapping cannot be direct because encrypted/compressed transform is needed.
    DenyTransformed,
}

/// Decide mmap handling for a file request.
pub fn decide_mmap(request: MmapRequest) -> Result<MmapDecision, CachePolicyError> {
    if request.length == 0 || !request.offset.is_multiple_of(BLOCK_SIZE_U64) {
        return Err(CachePolicyError::Invalid);
    }
    if request.encrypted || request.compressed {
        return Ok(MmapDecision::DenyTransformed);
    }
    if request.writable {
        return Ok(MmapDecision::DenyWritable);
    }
    Ok(MmapDecision::ReadOnlySnapshot)
}

/// Direct-I/O coherency action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectIoDecision {
    /// Direct I/O may proceed without cache interaction.
    Proceed,
    /// Dirty cache for the range must be flushed first.
    FlushDirtyRange,
    /// Request alignment is invalid.
    RejectUnaligned,
}

/// Decide direct-I/O behavior.
pub fn decide_direct_io(offset: u64, bytes: u64, has_dirty_overlap: bool) -> DirectIoDecision {
    if !direct_io_aligned(offset, bytes, BLOCK_SIZE as u32) {
        return DirectIoDecision::RejectUnaligned;
    }
    if has_dirty_overlap {
        DirectIoDecision::FlushDirtyRange
    } else {
        DirectIoDecision::Proceed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VOLUME: Uuid = [1; 16];

    fn key(block: u64) -> CacheKey {
        CacheKey {
            volume_uuid: VOLUME,
            object_id: 7,
            logical_block: block,
        }
    }

    #[test]
    fn cache_evicts_clean_lru_and_preserves_dirty() {
        let mut cache = FixedCache::<2>::new();
        assert_eq!(cache.admit_clean(key(1), 10, 1), Ok(None));
        assert_eq!(cache.admit_clean(key(2), 11, 2), Ok(None));
        assert!(cache.mark_dirty(key(1), 3).is_ok());
        let evicted = cache.admit_clean(key(3), 12, 4);
        assert_eq!(
            evicted.map(|entry| entry.map(|entry| entry.key)),
            Ok(Some(key(2)))
        );
        assert_eq!(cache.dirty_count(), 1);
    }

    #[test]
    fn writeback_queue_pops_oldest_generation() {
        let mut queue = WritebackQueue::<4>::new();
        assert!(queue
            .enqueue(WritebackRecord {
                key: key(1),
                generation: 4,
            })
            .is_ok());
        assert!(queue
            .enqueue(WritebackRecord {
                key: key(2),
                generation: 2,
            })
            .is_ok());
        assert_eq!(queue.pop_oldest().map(|record| record.key), Some(key(2)));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn mmap_policy_denies_writable_and_transformed() {
        assert_eq!(
            decide_mmap(MmapRequest {
                offset: 0,
                length: 4096,
                writable: false,
                encrypted: false,
                compressed: false,
            }),
            Ok(MmapDecision::ReadOnlySnapshot)
        );
        assert_eq!(
            decide_mmap(MmapRequest {
                offset: 0,
                length: 4096,
                writable: true,
                encrypted: false,
                compressed: false,
            }),
            Ok(MmapDecision::DenyWritable)
        );
        assert_eq!(
            decide_mmap(MmapRequest {
                offset: 0,
                length: 4096,
                writable: false,
                encrypted: true,
                compressed: false,
            }),
            Ok(MmapDecision::DenyTransformed)
        );
    }

    #[test]
    fn direct_io_policy_flushes_dirty_overlap() {
        assert_eq!(
            decide_direct_io(1, 4096, false),
            DirectIoDecision::RejectUnaligned
        );
        assert_eq!(
            decide_direct_io(0, 4096, true),
            DirectIoDecision::FlushDirtyRange
        );
        assert_eq!(decide_direct_io(0, 4096, false), DirectIoDecision::Proceed);
    }
}
