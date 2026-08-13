//! Platform memory backend.
//!
//! Upstream Scudo talks to `mmap`/`munmap` directly. HuesOS ring-3
//! processes have no such call — they own a pre-reserved heap window
//! and grow it with `VmarHeapExtend`. This trait is the seam between
//! the two: the allocator core is written against it, `libcanvas`
//! implements it on top of the real syscalls, and the host tests
//! implement it over a plain buffer so every layer is testable
//! without a kernel.
//!
//! The address space handed out is a single contiguous window, which
//! matches how the kernel reserves it and keeps the allocator's
//! pointer-ownership test a simple range check.

/// Why a backend request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    /// The window has no more address space to hand out.
    OutOfAddressSpace,
    /// The kernel refused to commit the pages (out of frames).
    CommitFailed,
    /// The request was malformed (unaligned or zero-length).
    InvalidRequest,
}

/// Page granularity every backend works in.
pub const PAGE_SIZE: usize = 4096;

/// Round `value` up to a whole number of pages.
pub const fn page_align_up(value: usize) -> usize {
    value.div_ceil(PAGE_SIZE) * PAGE_SIZE
}

/// A source of committed, writable memory for the allocator.
///
/// # Safety
/// Implementations must guarantee that:
///
/// - [`Self::base`] and [`Self::window_size`] describe a range that
///   stays reserved for the allocator's whole lifetime;
/// - a successful [`Self::commit`] leaves every byte of the
///   requested range readable and writable, and zeroed;
/// - [`Self::decommit`] only ever affects memory previously handed
///   out by this backend.
///
/// The allocator relies on these to turn raw offsets into pointers
/// it dereferences.
pub unsafe trait Backend {
    /// Base address of the reserved window.
    fn base(&self) -> usize;

    /// Total size of the reserved window in bytes.
    fn window_size(&self) -> usize;

    /// Make `[offset, offset + len)` readable and writable.
    ///
    /// `offset` and `len` are page-aligned and the range lies inside
    /// the window. Committing an already-committed range succeeds.
    fn commit(&self, offset: usize, len: usize) -> Result<(), BackendError>;

    /// Release `[offset, offset + len)`, returning the memory to the
    /// system. The address space stays reserved.
    fn decommit(&self, offset: usize, len: usize) -> Result<(), BackendError>;
}

#[cfg(any(test, feature = "test-backend"))]
pub use test_backend::TestBackend;

#[cfg(any(test, feature = "test-backend"))]
mod test_backend {
    use super::{Backend, BackendError, PAGE_SIZE};
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;

    /// A [`Backend`] over one heap-allocated buffer, for host tests.
    ///
    /// Commit tracking is real: the backend records which pages are
    /// committed and zeroes them on commit, so tests exercise the
    /// same commit/decommit logic the kernel backend does, and a
    /// use-after-decommit shows up as zeroed memory rather than
    /// stale data.
    pub struct TestBackend {
        memory: UnsafeCell<Vec<u8>>,
        committed: UnsafeCell<Vec<bool>>,
    }

    impl TestBackend {
        /// Create a backend with a `pages`-page window.
        pub fn new(pages: usize) -> Self {
            Self {
                memory: UnsafeCell::new(vec![0u8; pages * PAGE_SIZE]),
                committed: UnsafeCell::new(vec![false; pages]),
            }
        }

        /// How many pages are currently committed.
        pub fn committed_pages(&self) -> usize {
            // SAFETY: single-threaded test use; no other borrow is
            // live across this call.
            let committed = unsafe { &*self.committed.get() };
            committed.iter().filter(|page| **page).count()
        }
    }

    // SAFETY: the window is a stable heap buffer that lives as long
    // as the backend; commit zeroes and marks pages; decommit only
    // touches pages inside the window.
    unsafe impl Backend for TestBackend {
        fn base(&self) -> usize {
            // SAFETY: read-only access to the buffer's address.
            let memory = unsafe { &*self.memory.get() };
            memory.as_ptr() as usize
        }

        fn window_size(&self) -> usize {
            // SAFETY: read-only length access.
            let memory = unsafe { &*self.memory.get() };
            memory.len()
        }

        fn commit(&self, offset: usize, len: usize) -> Result<(), BackendError> {
            if len == 0 || !offset.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE) {
                return Err(BackendError::InvalidRequest);
            }
            let end = offset
                .checked_add(len)
                .ok_or(BackendError::InvalidRequest)?;
            if end > self.window_size() {
                return Err(BackendError::OutOfAddressSpace);
            }
            // SAFETY: single-threaded test use.
            let memory = unsafe { &mut *self.memory.get() };
            let committed = unsafe { &mut *self.committed.get() };
            let first_page = offset / PAGE_SIZE;
            for (index, page_committed) in committed[first_page..(end / PAGE_SIZE)]
                .iter_mut()
                .enumerate()
            {
                if !*page_committed {
                    let start = (first_page + index) * PAGE_SIZE;
                    memory[start..start + PAGE_SIZE].fill(0);
                    *page_committed = true;
                }
            }
            Ok(())
        }

        fn decommit(&self, offset: usize, len: usize) -> Result<(), BackendError> {
            if len == 0 || !offset.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE) {
                return Err(BackendError::InvalidRequest);
            }
            let end = offset
                .checked_add(len)
                .ok_or(BackendError::InvalidRequest)?;
            if end > self.window_size() {
                return Err(BackendError::OutOfAddressSpace);
            }
            // SAFETY: single-threaded test use.
            let memory = unsafe { &mut *self.memory.get() };
            let committed = unsafe { &mut *self.committed.get() };
            let first_page = offset / PAGE_SIZE;
            for (index, page_committed) in committed[first_page..(end / PAGE_SIZE)]
                .iter_mut()
                .enumerate()
            {
                if *page_committed {
                    let start = (first_page + index) * PAGE_SIZE;
                    // Poison rather than zero: a use-after-decommit
                    // is then visible in tests instead of looking
                    // like a fresh zeroed page.
                    memory[start..start + PAGE_SIZE].fill(0xdd);
                    *page_committed = false;
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_align_up_rounds_to_pages() {
        assert_eq!(page_align_up(0), 0);
        assert_eq!(page_align_up(1), PAGE_SIZE);
        assert_eq!(page_align_up(PAGE_SIZE), PAGE_SIZE);
        assert_eq!(page_align_up(PAGE_SIZE + 1), PAGE_SIZE * 2);
    }

    #[test]
    fn test_backend_tracks_commit_state() {
        let backend = TestBackend::new(4);
        assert_eq!(backend.committed_pages(), 0);
        assert_eq!(backend.commit(0, PAGE_SIZE * 2), Ok(()));
        assert_eq!(backend.committed_pages(), 2);
        // Re-committing is idempotent.
        assert_eq!(backend.commit(0, PAGE_SIZE), Ok(()));
        assert_eq!(backend.committed_pages(), 2);
        assert_eq!(backend.decommit(0, PAGE_SIZE * 2), Ok(()));
        assert_eq!(backend.committed_pages(), 0);
    }

    #[test]
    fn test_backend_rejects_bad_requests() {
        let backend = TestBackend::new(2);
        assert_eq!(backend.commit(0, 0), Err(BackendError::InvalidRequest));
        assert_eq!(
            backend.commit(1, PAGE_SIZE),
            Err(BackendError::InvalidRequest)
        );
        assert_eq!(
            backend.commit(0, PAGE_SIZE * 8),
            Err(BackendError::OutOfAddressSpace)
        );
    }
}
