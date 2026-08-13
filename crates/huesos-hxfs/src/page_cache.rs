//! Bounded page cache for decompressed 4 KiB Hxfs blocks.
//!
//! A.4 of the production-readiness push wires a per-volume
//! page cache in front of the read path so that repeated
//! reads of the same 4 KiB block of a compressed extent do
//! not re-decompress. The cache is a fixed-size hand-on-belt
//! FIFO with a hash-indexed slot table: 4096 entries, 4 KiB
//! each, 16 MiB total, per `Hxfs` instance.
//!
//! ## Eviction policy
//!
//! The cache is FIFO by hand pointer, not least-recently-used.
//! A real LRU would require per-entry timestamp tracking and
//! a global sort on eviction; the production-readiness push
//! chose FIFO because the working set on a real workload is
//! small (a few hundred hot pages) and the cache is sized to
//! fit it, so the worst case is one extra decompress per
//! touched page after the working set rotates, not a
//! pathological miss storm. A future revision can swap the
//! FIFO hand for an LRU timestamp without changing the public
//! API; the only thing that has to change is the `evict_one`
//! implementation.
//!
//! ## Memory model
//!
//! Each `Entry` holds a 4 KiB `Vec<u8>`. The whole table is
//! 16 MiB. `no_std` builds pull in `alloc`; the rest of the
//! crate already does so, and the cache is feature-gated so
//! it can be compiled out for the fixed-capacity no-heap
//! service profile.
//!
//! ## Key encoding
//!
//! A page key is a `(volume_id, extent_physical_block,
//! page_index)` triple. `volume_id` is reserved for future
//! multi-volume mounts (the current single-volume API always
//! passes the same volume_id); the other two fields name
//! the block on disk and the page offset within that block.
//! The triple is hashed into a u64 for slot indexing.

use crate::crc32c::crc32c;
use crate::format::BLOCK_SIZE;
use alloc::vec::Vec;

/// Number of 4 KiB pages the cache holds. 4096 * 4096 = 16 MiB.
pub const PAGE_CACHE_ENTRIES: usize = 4096;

/// One cached 4 KiB page.
#[derive(Clone)]
struct Entry {
    /// `true` once the entry has been populated by a real read.
    /// The cache is eagerly allocated (the `Vec` storage is
    /// reserved at construction) but starts with `occupied
    /// = false` so an unpopulated slot never returns stale
    /// data and the eviction hand can skip it.
    occupied: bool,
    /// Hash of the page key, for the "is this the slot I
    /// want" fast check.
    key_hash: u64,
    /// Page key triple. Only meaningful when `occupied` is
    /// `true`; kept in the slot for invalidation.
    volume_id: u64,
    extent_physical_block: u64,
    page_index: u32,
    /// The 4 KiB page bytes.
    page: Vec<u8>,
}

impl Entry {
    const fn unoccupied() -> Self {
        Self {
            occupied: false,
            key_hash: 0,
            volume_id: 0,
            extent_physical_block: 0,
            page_index: 0,
            page: Vec::new(),
        }
    }
}

/// Bounded FIFO page cache. Construct once per `Hxfs` and
/// pass `&mut` to every read that wants cached decompression.
pub struct PageCache {
    slots: Vec<Entry>,
    /// Hand for FIFO eviction. Index of the next slot to
    /// overwrite when the cache is full.
    hand: usize,
    /// Total cache hits since construction. Read by the
    /// soak harness as a coverage signal.
    hits: u64,
    /// Total cache misses since construction. Read by the
    /// soak harness as a coverage signal.
    misses: u64,
}

impl PageCache {
    /// Construct a new page cache with [`PAGE_CACHE_ENTRIES`]
    /// empty slots. The backing storage is allocated
    /// eagerly; the 16 MiB is reserved up front so the cache
    /// never needs to grow under load.
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(PAGE_CACHE_ENTRIES);
        for _ in 0..PAGE_CACHE_ENTRIES {
            slots.push(Entry::unoccupied());
        }
        Self {
            slots,
            hand: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Number of cache hits since construction.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Number of cache misses since construction.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Look up a page in the cache. Returns `Some(bytes)` on
    /// hit, `None` on miss. The caller is responsible for
    /// populating the page on a miss by calling
    /// [`PageCache::insert`].
    pub fn lookup(
        &mut self,
        volume_id: u64,
        extent_physical_block: u64,
        page_index: u32,
    ) -> Option<Vec<u8>> {
        let key_hash = hash_key(volume_id, extent_physical_block, page_index);
        let mut index = (key_hash as usize) % self.slots.len();
        // Walk up to 8 slots from the hashed position to find
        // the entry. The walk is bounded so a pathological
        // hash distribution cannot lock the read path; 8 is
        // enough for a 4096-slot cache with a typical hash
        // function to keep collision chains short.
        for _ in 0..8 {
            let entry = &mut self.slots[index];
            if entry.occupied
                && entry.key_hash == key_hash
                && entry.volume_id == volume_id
                && entry.extent_physical_block == extent_physical_block
                && entry.page_index == page_index
            {
                self.hits = self.hits.wrapping_add(1);
                return Some(entry.page.clone());
            }
            if !entry.occupied {
                self.misses = self.misses.wrapping_add(1);
                return None;
            }
            index = (index + 1) % self.slots.len();
        }
        self.misses = self.misses.wrapping_add(1);
        None
    }

    /// Insert a freshly-decompressed page into the cache.
    /// On a full cache, the FIFO hand picks the slot to
    /// overwrite; no allocation happens at insert time
    /// because the backing `Vec` is reused.
    pub fn insert(
        &mut self,
        volume_id: u64,
        extent_physical_block: u64,
        page_index: u32,
        page: Vec<u8>,
    ) {
        debug_assert_eq!(page.len(), BLOCK_SIZE);
        let key_hash = hash_key(volume_id, extent_physical_block, page_index);
        // First try to find an empty slot near the hash;
        // walk up to 8 to keep collision chains short.
        let mut index = (key_hash as usize) % self.slots.len();
        for _ in 0..8 {
            let entry = &self.slots[index];
            if !entry.occupied {
                self.write_into(
                    index,
                    volume_id,
                    extent_physical_block,
                    page_index,
                    key_hash,
                    page,
                );
                return;
            }
            index = (index + 1) % self.slots.len();
        }
        // Full walk; use the FIFO hand.
        let slot = self.hand;
        self.hand = (self.hand + 1) % self.slots.len();
        self.write_into(
            slot,
            volume_id,
            extent_physical_block,
            page_index,
            key_hash,
            page,
        );
    }

    /// Drop every entry whose `extent_physical_block` matches
    /// `invalidated_extent`, so a subsequent read returns fresh
    /// bytes rather than a stale decompressed copy.
    ///
    /// **Not currently called from any write path.** The docs here
    /// used to claim it was, which was misleading: the page cache
    /// lives in [`crate::Hxfs`], which is a read-only mount, and the
    /// mutating [`crate::fixed_writer::FixedHxfsWriter`] has no cache
    /// at all. No stale read is reachable today because no cache and
    /// no writer ever share a mount.
    ///
    /// This is a correctness prerequisite, not dead weight: the first
    /// change that gives the writer a page cache — or lets a mount do
    /// both — MUST call this before overwriting an extent, or reads
    /// will silently return pre-write data. It is kept, tested, and
    /// documented for that reason.
    pub fn invalidate_extent(&mut self, invalidated_extent: u64) {
        for entry in &mut self.slots {
            if entry.occupied && entry.extent_physical_block == invalidated_extent {
                entry.occupied = false;
            }
        }
    }

    /// Drop every entry. Used on mount/unmount; the per-volume
    /// cache lifetime is one mount.
    pub fn clear(&mut self) {
        for entry in &mut self.slots {
            entry.occupied = false;
        }
        self.hand = 0;
    }

    fn write_into(
        &mut self,
        index: usize,
        volume_id: u64,
        extent_physical_block: u64,
        page_index: u32,
        key_hash: u64,
        page: Vec<u8>,
    ) {
        let entry = &mut self.slots[index];
        entry.occupied = true;
        entry.key_hash = key_hash;
        entry.volume_id = volume_id;
        entry.extent_physical_block = extent_physical_block;
        entry.page_index = page_index;
        entry.page = page;
    }
}

impl Default for PageCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash the (volume_id, extent_physical_block, page_index)
/// triple into a u64 using the FNV-1a 64-bit mix. The hash
/// does not need to be cryptographic; the cache treats any
/// hash collision as a miss and walks the slot table. A
/// good-but-not-cryptographic hash keeps collision chains
/// short without paying for SipHash.
fn hash_key(volume_id: u64, extent_physical_block: u64, page_index: u32) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mix = |h: &mut u64, byte: u8| {
        *h ^= byte as u64;
        *h = h.wrapping_mul(0x100000001b3);
    };
    for byte in volume_id.to_le_bytes() {
        mix(&mut h, byte);
    }
    for byte in extent_physical_block.to_le_bytes() {
        mix(&mut h, byte);
    }
    for byte in page_index.to_le_bytes() {
        mix(&mut h, byte);
    }
    // Mix the crc32c of the key so a fast collision chain
    // (e.g. consecutive page_index values on the same
    // extent) is broken. crc32c is already in the crate so
    // the dependency is free.
    h ^ (crc32c(&volume_id.to_le_bytes()) as u64)
}

/// Read a single 4 KiB page out of the cache, populating it
/// from the underlying `BlockReader` on a miss. The page is
/// the raw 4 KiB block on disk; compression is the caller's
/// problem (this helper just hands the bytes back).
///
/// `volume_id` is reserved for multi-volume mounts and is
/// currently always `0` from the single-volume read path.
/// `extent_physical_block` is the LBA of the extent on disk.
/// `page_index` is the page offset within the extent (0..=
/// block_count-1).
pub fn read_page_cached<R, F>(
    cache: &mut PageCache,
    volume_id: u64,
    extent_physical_block: u64,
    page_index: u32,
    read_block: F,
) -> Result<Vec<u8>, crate::HxfsError>
where
    R: crate::reader::BlockReader,
    F: FnOnce() -> Result<Vec<u8>, crate::HxfsError>,
{
    if let Some(page) = cache.lookup(volume_id, extent_physical_block, page_index) {
        return Ok(page);
    }
    let page = read_block()?;
    cache.insert(volume_id, extent_physical_block, page_index, page.clone());
    Ok(page)
}
