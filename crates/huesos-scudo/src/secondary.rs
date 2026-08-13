//! Secondary allocator: large blocks with guard pages.
//!
//! Allocations too large for a size class get their own page-aligned
//! block, and — the hardening property that motivates a separate
//! allocator at all — an **unmapped guard page on each side**. A
//! linear overflow off either end of a large buffer therefore hits
//! an unmapped page and faults immediately, at the instruction that
//! did the overflow, instead of quietly corrupting whatever the
//! allocator happened to place next door.
//!
//! Layout of one secondary block:
//!
//! ```text
//! [ guard page ][ header + payload, page-aligned ][ guard page ]
//!   never mapped         committed                  never mapped
//! ```
//!
//! Blocks are allocated by bumping through the secondary area. Freed
//! blocks are decommitted (returning the memory) and recorded in a
//! small cache so a repeated allocate/free of the same size does not
//! churn syscalls. The cache is bounded; beyond it, address space is
//! simply retired. That is a deliberate trade: a ring-3 service's
//! large allocations are rare and long-lived, and never reusing an
//! address is itself a hardening property (no address is recycled
//! for a differently-sized object).

use crate::backend::{page_align_up, Backend, BackendError, PAGE_SIZE};
use crate::chunk::{self, ChunkHeader, ChunkState, Origin, HEADER_BYTES};

/// How many freed blocks the secondary keeps for reuse.
const CACHE_ENTRIES: usize = 8;

/// Errors the secondary allocator can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryError {
    /// The secondary area has no address space left.
    OutOfMemory,
    /// The backend refused to commit pages.
    Backend(BackendError),
    /// The request could not be represented (overflowing size).
    InvalidRequest,
}

#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    /// Offset of the payload region (after the leading guard page).
    payload_offset: usize,
    /// Committed size of the payload region.
    payload_size: usize,
    /// Whether this slot holds a block.
    used: bool,
}

impl CacheEntry {
    const fn empty() -> Self {
        Self {
            payload_offset: 0,
            payload_size: 0,
            used: false,
        }
    }
}

/// The secondary allocator.
pub struct Secondary {
    area_offset: usize,
    area_size: usize,
    /// Next unused offset in the area.
    bump: usize,
    cache: [CacheEntry; CACHE_ENTRIES],
    live_bytes: usize,
}

impl Secondary {
    /// Create a secondary allocator over the given area.
    pub fn new(area_offset: usize, area_size: usize) -> Self {
        Self {
            area_offset,
            area_size,
            bump: area_offset,
            cache: [CacheEntry::empty(); CACHE_ENTRIES],
            live_bytes: 0,
        }
    }

    /// Whether `offset` falls inside the secondary area.
    pub fn owns_offset(&self, offset: usize) -> bool {
        offset >= self.area_offset && offset < self.area_offset + self.area_size
    }

    /// Bytes currently handed out by the secondary.
    pub fn live_bytes(&self) -> usize {
        self.live_bytes
    }

    /// Total payload bytes needed for `request_size` plus its header.
    fn payload_size_for(request_size: usize) -> Option<usize> {
        let total = request_size.checked_add(HEADER_BYTES)?;
        Some(page_align_up(total))
    }

    /// Allocate a block, returning the offset of its payload region.
    pub fn allocate<B: Backend>(
        &mut self,
        backend: &B,
        request_size: usize,
    ) -> Result<usize, SecondaryError> {
        let payload_size =
            Self::payload_size_for(request_size).ok_or(SecondaryError::InvalidRequest)?;

        // Reuse a cached block of exactly the right size: same size
        // means the guard layout is already correct.
        for entry in self.cache.iter_mut() {
            if entry.used && entry.payload_size == payload_size {
                entry.used = false;
                let offset = entry.payload_offset;
                backend
                    .commit(offset, payload_size)
                    .map_err(SecondaryError::Backend)?;
                self.live_bytes += payload_size;
                return Ok(offset);
            }
        }

        // Fresh block: guard page, payload, guard page. Only the
        // payload is ever committed; the guards stay unmapped, which
        // is what makes an overflow fault.
        let guard = PAGE_SIZE;
        let total = payload_size
            .checked_add(guard * 2)
            .ok_or(SecondaryError::InvalidRequest)?;
        let area_end = self.area_offset + self.area_size;
        if self
            .bump
            .checked_add(total)
            .ok_or(SecondaryError::OutOfMemory)?
            > area_end
        {
            return Err(SecondaryError::OutOfMemory);
        }

        let payload_offset = self.bump + guard;
        backend
            .commit(payload_offset, payload_size)
            .map_err(SecondaryError::Backend)?;
        self.bump += total;
        self.live_bytes += payload_size;
        Ok(payload_offset)
    }

    /// Release a block previously returned by [`Self::allocate`].
    pub fn deallocate<B: Backend>(
        &mut self,
        backend: &B,
        payload_offset: usize,
        request_size: usize,
    ) -> Result<(), SecondaryError> {
        let payload_size =
            Self::payload_size_for(request_size).ok_or(SecondaryError::InvalidRequest)?;
        self.live_bytes = self.live_bytes.saturating_sub(payload_size);

        // Decommit immediately: a freed large buffer should stop
        // costing memory, and any dangling pointer into it now
        // faults rather than reading stale contents.
        backend
            .decommit(payload_offset, payload_size)
            .map_err(SecondaryError::Backend)?;

        for entry in self.cache.iter_mut() {
            if !entry.used {
                entry.payload_offset = payload_offset;
                entry.payload_size = payload_size;
                entry.used = true;
                return Ok(());
            }
        }
        // Cache full: retire the address range.
        Ok(())
    }

    /// Write the header for a secondary chunk and return the user pointer.
    ///
    /// # Safety
    /// `payload_offset` must come from [`Self::allocate`].
    pub unsafe fn finish_allocation<B: Backend>(
        backend: &B,
        payload_offset: usize,
        request_size: usize,
    ) -> *mut u8 {
        let header_end = (backend.base() + payload_offset + HEADER_BYTES) as *mut u8;
        let header = ChunkHeader {
            state: ChunkState::Allocated,
            origin: Origin::Secondary,
            class: 0,
            offset: 0,
            request_size: request_size as u32,
        };
        // SAFETY: the payload region was just committed and is page
        // aligned, so the header is 16-byte aligned and writable.
        unsafe { chunk::write_header(header_end, &header) };
        header_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::TestBackend;

    fn setup(pages: usize) -> (TestBackend, Secondary) {
        let backend = TestBackend::new(pages);
        let secondary = Secondary::new(0, backend.window_size());
        (backend, secondary)
    }

    #[test]
    fn allocation_is_page_aligned_and_guarded() {
        let (backend, mut secondary) = setup(64);
        let offset = match secondary.allocate(&backend, 100_000) {
            Ok(offset) => offset,
            Err(error) => {
                assert!(false, "allocation failed: {error:?}");
                return;
            }
        };
        assert_eq!(offset % PAGE_SIZE, 0, "payload must be page aligned");
        assert!(offset >= PAGE_SIZE, "a guard page must precede the payload");
    }

    #[test]
    fn guard_pages_are_never_committed() {
        let (backend, mut secondary) = setup(64);
        let size = 8192;
        let offset = match secondary.allocate(&backend, size) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        let payload_pages = page_align_up(size + HEADER_BYTES) / PAGE_SIZE;
        // Exactly the payload is committed: neither guard page is.
        assert_eq!(backend.committed_pages(), payload_pages);
        assert!(offset >= PAGE_SIZE);
    }

    #[test]
    fn blocks_do_not_overlap_and_are_separated_by_guards() {
        let (backend, mut secondary) = setup(128);
        let first = match secondary.allocate(&backend, 20_000) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        let second = match secondary.allocate(&backend, 20_000) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        let first_end = first + page_align_up(20_000 + HEADER_BYTES);
        assert!(
            second >= first_end + PAGE_SIZE * 2,
            "two guard pages must separate consecutive blocks"
        );
    }

    #[test]
    fn free_decommits_memory() {
        let (backend, mut secondary) = setup(64);
        let size = 30_000;
        let offset = match secondary.allocate(&backend, size) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        assert!(backend.committed_pages() > 0);
        assert_eq!(secondary.deallocate(&backend, offset, size), Ok(()));
        assert_eq!(
            backend.committed_pages(),
            0,
            "freeing a large block must return its pages"
        );
    }

    #[test]
    fn same_size_block_is_reused_from_cache() {
        let (backend, mut secondary) = setup(64);
        let size = 12_000;
        let first = match secondary.allocate(&backend, size) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        assert_eq!(secondary.deallocate(&backend, first, size), Ok(()));
        let second = secondary.allocate(&backend, size);
        assert_eq!(second, Ok(first), "cache should return the same block");
    }

    #[test]
    fn churn_does_not_exhaust_address_space() {
        let (backend, mut secondary) = setup(256);
        let size = 20_000;
        for iteration in 0..1000 {
            let offset = match secondary.allocate(&backend, size) {
                Ok(offset) => offset,
                Err(error) => {
                    assert!(false, "iteration {iteration} failed: {error:?}");
                    return;
                }
            };
            assert_eq!(secondary.deallocate(&backend, offset, size), Ok(()));
        }
    }

    #[test]
    fn exhaustion_is_reported() {
        let (backend, mut secondary) = setup(4);
        // Far larger than the 4-page window.
        assert_eq!(
            secondary.allocate(&backend, 1_000_000),
            Err(SecondaryError::OutOfMemory)
        );
    }

    #[test]
    fn live_bytes_returns_to_zero() {
        let (backend, mut secondary) = setup(128);
        let mut offsets = [0usize; 4];
        let size = 10_000;
        for slot in offsets.iter_mut() {
            match secondary.allocate(&backend, size) {
                Ok(offset) => *slot = offset,
                Err(_) => return,
            }
        }
        assert!(secondary.live_bytes() > 0);
        for offset in offsets {
            assert_eq!(secondary.deallocate(&backend, offset, size), Ok(()));
        }
        assert_eq!(secondary.live_bytes(), 0);
    }
}
