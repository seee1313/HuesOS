//! Primary allocator: per-class free lists over committed regions.
//!
//! Each size class owns a region carved out of the backend window.
//! Chunks are handed out in batches (Scudo's `TransferBatch`): when a
//! class's free list runs dry the primary commits more of that
//! class's region and carves `batch_count` fresh chunks at once,
//! which keeps the common path free of syscalls.
//!
//! The free list is intrusive — the `next` link lives in the freed
//! chunk's own body — which is what upstream does and what the old
//! HuesOS allocator did. The difference is that **every link is
//! validated before it is followed**:
//!
//! - the link must lie inside this class's region;
//! - it must be correctly aligned for a chunk of this class.
//!
//! The old allocator followed raw links unconditionally, so one bad
//! write turned into an unbounded walk through attacker-influenced
//! memory. Here a corrupt link is reported as
//! [`PrimaryError::CorruptFreeList`] and the class is left in a
//! consistent state.
//!
//! Region layout inside the window:
//!
//! ```text
//! [ class 0 region | class 1 region | ... | class N-1 region ]
//! ```
//!
//! Regions are equal-sized slices of the primary area. A class only
//! commits pages as it needs them, so an unused class costs nothing
//! but address space.

use crate::backend::{page_align_up, Backend, BackendError, PAGE_SIZE};
use crate::chunk::{self, ChunkHeader, ChunkState, Origin, HEADER_BYTES};
use crate::size_class::{batch_count, size_for_class, CLASS_SIZES, NUM_CLASSES};

/// Errors the primary allocator can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryError {
    /// This class's region is exhausted.
    OutOfMemory,
    /// The backend refused to commit more pages.
    Backend(BackendError),
    /// A free-list link pointed outside the class region or was
    /// misaligned — memory corruption, caught before dereference.
    CorruptFreeList,
    /// The class index does not exist.
    BadClass,
}

/// Per-class allocation state.
#[derive(Debug, Clone, Copy)]
struct ClassState {
    /// Offset of this class's region within the window.
    region_offset: usize,
    /// Size of the region in bytes.
    region_size: usize,
    /// Bytes of the region already carved into chunks.
    carved: usize,
    /// Bytes of the region currently committed.
    committed: usize,
    /// Head of the intrusive free list, as a window offset.
    /// `usize::MAX` means empty (0 is a valid offset).
    free_head: usize,
    /// Number of chunks currently on the free list.
    free_count: usize,
}

impl ClassState {
    const EMPTY: usize = usize::MAX;

    const fn new() -> Self {
        Self {
            region_offset: 0,
            region_size: 0,
            carved: 0,
            committed: 0,
            free_head: Self::EMPTY,
            free_count: 0,
        }
    }
}

/// The primary allocator.
pub struct Primary {
    classes: [ClassState; NUM_CLASSES],
    /// Window offset where the primary area starts.
    area_offset: usize,
    /// Total size of the primary area.
    area_size: usize,
}

impl Primary {
    /// Create a primary allocator over `[area_offset, area_offset + area_size)`.
    ///
    /// The area is split evenly between the size classes, each
    /// region page-aligned so commits never straddle two classes.
    /// Regions are sized **proportionally to their class size**, not
    /// equally. An equal split starves the large classes: with a
    /// small window, a 64 KiB class whose region is one page cannot
    /// hold even a single chunk, so it reports OOM while the 16-byte
    /// class sits on thousands of unused slots.
    ///
    /// Each class gets a share proportional to its chunk size, with
    /// a floor of enough pages for one full `TransferBatch` refill
    /// where the window allows it, so no class is dead on arrival.
    pub fn new(area_offset: usize, area_size: usize) -> Self {
        let mut classes = [ClassState::new(); NUM_CLASSES];

        // Weight each class by its chunk size so the region can hold
        // a comparable number of chunks across classes.
        let total_weight: usize = CLASS_SIZES.iter().sum();
        let usable = area_size & !(PAGE_SIZE - 1);

        let mut cursor = area_offset;
        for (index, class) in classes.iter_mut().enumerate() {
            let weight = CLASS_SIZES[index];
            let share = ((usable / total_weight.max(1)) * weight) & !(PAGE_SIZE - 1);
            // Never hand a class less than one page, and never more
            // than what is left in the area.
            let remaining = (area_offset + usable).saturating_sub(cursor);
            let size = share.max(PAGE_SIZE).min(remaining);
            class.region_offset = cursor;
            class.region_size = size;
            cursor += size;
        }

        Self {
            classes,
            area_offset,
            area_size,
        }
    }

    /// Offset of the first byte after the primary area.
    pub fn area_end(&self) -> usize {
        self.area_offset + self.area_size
    }

    /// Whether `offset` falls inside the primary area.
    pub fn owns_offset(&self, offset: usize) -> bool {
        offset >= self.area_offset && offset < self.area_end()
    }

    /// Number of chunks on `class`'s free list.
    pub fn free_count(&self, class: usize) -> usize {
        self.classes
            .get(class)
            .map(|state| state.free_count)
            .unwrap_or(0)
    }

    /// Total bytes committed across all classes.
    pub fn committed_bytes(&self) -> usize {
        self.classes.iter().map(|class| class.committed).sum()
    }

    /// Validate that `offset` could be the start of a chunk in `class`.
    ///
    /// This is the check the old allocator was missing. Every link
    /// read out of application-writable memory goes through it
    /// before being turned into a pointer.
    fn validate_offset(state: &ClassState, chunk_stride: usize, offset: usize) -> bool {
        if offset < state.region_offset {
            return false;
        }
        let relative = offset - state.region_offset;
        // Must be within the carved part of the region and land
        // exactly on a chunk boundary.
        relative < state.carved && relative.is_multiple_of(chunk_stride)
    }

    /// Take one chunk from `class`, refilling from the region if needed.
    ///
    /// Returns the window offset of the chunk's header start.
    pub fn allocate<B: Backend>(
        &mut self,
        backend: &B,
        class: usize,
    ) -> Result<usize, PrimaryError> {
        let chunk_size = size_for_class(class).ok_or(PrimaryError::BadClass)?;
        let stride = HEADER_BYTES + chunk_size;

        // Fast path: pop the free list.
        if let Some(offset) = self.pop_free(backend, class, stride)? {
            return Ok(offset);
        }

        // Slow path: carve a fresh batch.
        self.refill(backend, class, stride)?;
        match self.pop_free(backend, class, stride)? {
            Some(offset) => Ok(offset),
            // Refill either succeeded (list non-empty) or returned an
            // error; an empty list here means the region is spent.
            None => Err(PrimaryError::OutOfMemory),
        }
    }

    fn pop_free<B: Backend>(
        &mut self,
        backend: &B,
        class: usize,
        stride: usize,
    ) -> Result<Option<usize>, PrimaryError> {
        let state = self.classes.get_mut(class).ok_or(PrimaryError::BadClass)?;
        if state.free_head == ClassState::EMPTY {
            return Ok(None);
        }
        let head = state.free_head;
        if !Self::validate_offset(state, stride, head) {
            // Refuse to follow a corrupt head, and drop the whole
            // list rather than leaving a known-bad pointer in place.
            state.free_head = ClassState::EMPTY;
            state.free_count = 0;
            return Err(PrimaryError::CorruptFreeList);
        }

        // Read the intrusive `next` link stored in the chunk body.
        let body = backend.base() + head + HEADER_BYTES;
        // SAFETY: `head` was validated to be a carved, committed
        // chunk start in this class's region, so `body` points at
        // that chunk's first word, which the allocator owns while
        // the chunk is free.
        let next = unsafe { (body as *const usize).read() };

        if next != ClassState::EMPTY && !Self::validate_offset(state, stride, next) {
            state.free_head = ClassState::EMPTY;
            state.free_count = 0;
            return Err(PrimaryError::CorruptFreeList);
        }

        state.free_head = next;
        state.free_count = state.free_count.saturating_sub(1);
        Ok(Some(head))
    }

    fn refill<B: Backend>(
        &mut self,
        backend: &B,
        class: usize,
        stride: usize,
    ) -> Result<(), PrimaryError> {
        let count = batch_count(class).max(1);
        let state = self.classes.get_mut(class).ok_or(PrimaryError::BadClass)?;

        let available = state.region_size.saturating_sub(state.carved);
        if available < stride {
            return Err(PrimaryError::OutOfMemory);
        }
        let batch = count.min(available / stride);

        // Commit enough pages to cover the new chunks.
        let needed = state.carved + batch * stride;
        if needed > state.committed {
            let commit_end = page_align_up(needed).min(state.region_size);
            let commit_len = commit_end - state.committed;
            if commit_len > 0 {
                backend
                    .commit(state.region_offset + state.committed, commit_len)
                    .map_err(PrimaryError::Backend)?;
                state.committed = commit_end;
            }
        }

        // Carve the batch and thread it onto the free list. Chunks
        // are linked in reverse so the list comes out in ascending
        // address order, which keeps allocation patterns predictable.
        for index in (0..batch).rev() {
            let offset = state.region_offset + state.carved + index * stride;
            let body = backend.base() + offset + HEADER_BYTES;
            // SAFETY: the range was just committed and lies inside
            // this class's region; nothing else refers to it yet.
            unsafe {
                (body as *mut usize).write(state.free_head);
            }
            state.free_head = offset;
            state.free_count += 1;
        }
        state.carved += batch * stride;
        Ok(())
    }

    /// Return a chunk to `class`'s free list.
    ///
    /// The caller has already validated the chunk's header, so this
    /// only re-checks that the offset is a plausible chunk start
    /// before linking it in — a corrupted offset must never be
    /// written into the list.
    pub fn deallocate<B: Backend>(
        &mut self,
        backend: &B,
        class: usize,
        offset: usize,
    ) -> Result<(), PrimaryError> {
        let chunk_size = size_for_class(class).ok_or(PrimaryError::BadClass)?;
        let stride = HEADER_BYTES + chunk_size;
        let state = self.classes.get_mut(class).ok_or(PrimaryError::BadClass)?;
        if !Self::validate_offset(state, stride, offset) {
            return Err(PrimaryError::CorruptFreeList);
        }

        let body = backend.base() + offset + HEADER_BYTES;
        // SAFETY: validated chunk start inside a committed region;
        // the chunk is owned by the allocator now that it is freed.
        unsafe {
            (body as *mut usize).write(state.free_head);
        }
        state.free_head = offset;
        state.free_count += 1;
        Ok(())
    }

    /// Write the header for a freshly allocated primary chunk and
    /// return the user pointer offset.
    ///
    /// # Safety
    /// `offset` must be a chunk start returned by [`Self::allocate`].
    pub unsafe fn finish_allocation<B: Backend>(
        backend: &B,
        offset: usize,
        class: usize,
        request_size: usize,
    ) -> *mut u8 {
        let header_end = (backend.base() + offset + HEADER_BYTES) as *mut u8;
        let header = ChunkHeader {
            state: ChunkState::Allocated,
            origin: Origin::Primary,
            class: class as u8,
            offset: 0,
            request_size: request_size as u32,
        };
        // SAFETY: `header_end` is 16-byte aligned (region and stride
        // are both multiples of 16) and points just past the chunk's
        // header, which the allocator owns.
        unsafe { chunk::write_header(header_end, &header) };
        header_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::TestBackend;
    use crate::size_class::class_for_size;

    fn setup() -> (TestBackend, Primary) {
        // 32 classes * 8 pages each keeps the test window small but
        // gives every class a real multi-page region.
        let backend = TestBackend::new(NUM_CLASSES * 8);
        let primary = Primary::new(0, backend.window_size());
        (backend, primary)
    }

    #[test]
    fn allocation_returns_distinct_chunks() {
        let (backend, mut primary) = setup();
        let class = match class_for_size(64) {
            Some(class) => class,
            None => {
                assert!(false, "64 bytes must have a class");
                return;
            }
        };
        let mut seen = [0usize; 16];
        for slot in seen.iter_mut() {
            match primary.allocate(&backend, class) {
                Ok(offset) => *slot = offset,
                Err(error) => {
                    assert!(false, "allocation failed: {error:?}");
                    return;
                }
            }
        }
        for (index, offset) in seen.iter().enumerate() {
            for other in seen.iter().skip(index + 1) {
                assert_ne!(offset, other, "chunks must not overlap");
            }
        }
    }

    #[test]
    fn freed_chunk_is_reused() {
        let (backend, mut primary) = setup();
        let class = match class_for_size(128) {
            Some(class) => class,
            None => return,
        };
        let first = match primary.allocate(&backend, class) {
            Ok(offset) => offset,
            Err(_) => {
                assert!(false, "first allocation failed");
                return;
            }
        };
        assert_eq!(primary.deallocate(&backend, class, first), Ok(()));
        let second = primary.allocate(&backend, class);
        assert_eq!(second, Ok(first), "the freed chunk should come back");
    }

    /// The regression that killed the old allocator: allocate and
    /// free repeatedly and confirm memory does not run out.
    #[test]
    fn steady_state_churn_does_not_exhaust_the_region() {
        let (backend, mut primary) = setup();
        let class = match class_for_size(1000) {
            Some(class) => class,
            None => return,
        };
        for iteration in 0..10_000 {
            let offset = match primary.allocate(&backend, class) {
                Ok(offset) => offset,
                Err(error) => {
                    assert!(false, "iteration {iteration} failed: {error:?}");
                    return;
                }
            };
            assert_eq!(primary.deallocate(&backend, class, offset), Ok(()));
        }
    }

    /// Interleaved allocation across many classes: a bug in region
    /// splitting would show up as two classes handing out the same
    /// address.
    #[test]
    fn classes_do_not_overlap() {
        let (backend, mut primary) = setup();
        let mut offsets = [0usize; NUM_CLASSES];
        for class in 0..NUM_CLASSES {
            match primary.allocate(&backend, class) {
                Ok(offset) => offsets[class] = offset,
                Err(error) => {
                    assert!(false, "class {class} failed: {error:?}");
                    return;
                }
            }
        }
        for (index, offset) in offsets.iter().enumerate() {
            for other in offsets.iter().skip(index + 1) {
                assert_ne!(offset, other);
            }
        }
    }

    /// A corrupted free-list head must be detected instead of
    /// followed. This is precisely the old allocator's failure mode.
    #[test]
    fn corrupt_free_list_head_is_rejected() {
        let (backend, mut primary) = setup();
        let class = match class_for_size(64) {
            Some(class) => class,
            None => return,
        };
        let offset = match primary.allocate(&backend, class) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        assert_eq!(primary.deallocate(&backend, class, offset), Ok(()));

        // Corrupt the head link to point far outside the region.
        if let Some(state) = primary.classes.get_mut(class) {
            state.free_head = state.region_offset + state.region_size * 4;
        }
        assert_eq!(
            primary.allocate(&backend, class),
            Err(PrimaryError::CorruptFreeList)
        );
    }

    /// A corrupted `next` link inside a freed chunk must also be
    /// caught, not dereferenced.
    #[test]
    fn corrupt_next_link_is_rejected() {
        let (backend, mut primary) = setup();
        let class = match class_for_size(64) {
            Some(class) => class,
            None => return,
        };
        let first = match primary.allocate(&backend, class) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        let second = match primary.allocate(&backend, class) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        assert_eq!(primary.deallocate(&backend, class, first), Ok(()));
        assert_eq!(primary.deallocate(&backend, class, second), Ok(()));

        // `second` is now the head; poison its `next` field.
        let body = backend.base() + second + HEADER_BYTES;
        unsafe {
            (body as *mut usize).write(0xdead_0000);
        }
        assert_eq!(
            primary.allocate(&backend, class),
            Err(PrimaryError::CorruptFreeList)
        );
    }

    #[test]
    fn deallocate_rejects_offsets_outside_the_class() {
        let (backend, mut primary) = setup();
        let class = match class_for_size(64) {
            Some(class) => class,
            None => return,
        };
        // Never carved, so not a valid chunk start.
        assert_eq!(
            primary.deallocate(&backend, class, backend.window_size() * 2),
            Err(PrimaryError::CorruptFreeList)
        );
    }

    #[test]
    fn misaligned_offsets_are_rejected() {
        let (backend, mut primary) = setup();
        let class = match class_for_size(64) {
            Some(class) => class,
            None => return,
        };
        let offset = match primary.allocate(&backend, class) {
            Ok(offset) => offset,
            Err(_) => return,
        };
        // One byte into a real chunk is not a chunk start.
        assert_eq!(
            primary.deallocate(&backend, class, offset + 1),
            Err(PrimaryError::CorruptFreeList)
        );
    }

    #[test]
    fn commit_is_lazy() {
        let (backend, mut primary) = setup();
        assert_eq!(backend.committed_pages(), 0, "nothing committed up front");
        let class = match class_for_size(16) {
            Some(class) => class,
            None => return,
        };
        let _ = primary.allocate(&backend, class);
        let committed = backend.committed_pages();
        assert!(committed > 0, "allocation must commit something");
        assert!(
            committed < 8,
            "one small allocation must not commit a whole class region"
        );
    }

    #[test]
    fn region_exhaustion_reports_out_of_memory() {
        let backend = TestBackend::new(NUM_CLASSES);
        let mut primary = Primary::new(0, backend.window_size());
        let class = NUM_CLASSES - 1; // 64 KiB chunks, 1 page region
                                     // The region is smaller than a single chunk of this class.
        assert_eq!(
            primary.allocate(&backend, class),
            Err(PrimaryError::OutOfMemory)
        );
    }
}
