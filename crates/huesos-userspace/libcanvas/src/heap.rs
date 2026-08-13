//! `GlobalAlloc` adapter binding `huesos-scudo` to the ring-3 heap.
//!
//! This is the piece that turns the platform-independent allocator
//! core into the process's `#[global_allocator]`:
//!
//! - [`HeapWindow`] implements `huesos_scudo::backend::Backend` over
//!   the kernel's `VmarHeapExtend` syscall, so the allocator commits
//!   and decommits real pages inside the process's reserved window;
//! - [`ScudoHeap`] wraps the allocator in the interior mutability
//!   `GlobalAlloc` requires and enforces the "initialise before
//!   first allocation" contract.
//!
//! ## Threading
//!
//! HuesOS ring-3 programs are single-threaded: `ThreadCreate` is
//! issued only by the process launcher and there is no TLS. The
//! `Sync` impl below rests on that. When userspace threads arrive,
//! this type — not the allocator core — is where a lock or a
//! per-thread cache registry belongs.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

use huesos_scudo::backend::{Backend, BackendError};
use huesos_scudo::Allocator;

use crate::memory;

/// A [`Backend`] over this process's kernel-reserved heap window.
pub struct HeapWindow {
    base: usize,
    size: usize,
}

impl HeapWindow {
    /// Describe the process's full heap window.
    pub const fn new() -> Self {
        Self {
            base: memory::HEAP_BASE,
            size: memory::HEAP_SIZE,
        }
    }
}

impl Default for HeapWindow {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: the kernel reserves `[USER_HEAP_BASE, +USER_HEAP_SIZE)`
// for the lifetime of every process (`huesos-kernel/src/process.rs`),
// `heap_commit` returns only after the range is mapped RW and zeroed,
// and `heap_decommit` unmaps exactly the range it is given inside
// that same window.
unsafe impl Backend for HeapWindow {
    fn base(&self) -> usize {
        self.base
    }

    fn window_size(&self) -> usize {
        self.size
    }

    fn commit(&self, offset: usize, len: usize) -> Result<(), BackendError> {
        match memory::heap_commit(offset, len) {
            Ok(_) => Ok(()),
            Err(huesos_abi::ErrorCode::InvalidArgs) => Err(BackendError::InvalidRequest),
            Err(_) => Err(BackendError::CommitFailed),
        }
    }

    fn decommit(&self, offset: usize, len: usize) -> Result<(), BackendError> {
        match memory::heap_decommit(offset, len) {
            Ok(_) => Ok(()),
            Err(huesos_abi::ErrorCode::InvalidArgs) => Err(BackendError::InvalidRequest),
            Err(_) => Err(BackendError::CommitFailed),
        }
    }
}

/// The process-wide hardened heap.
///
/// Declare one as the `#[global_allocator]` and call
/// [`ScudoHeap::init`] once, early in `main`, before the first
/// allocation.
pub struct ScudoHeap {
    inner: UnsafeCell<Option<Allocator<HeapWindow>>>,
}

impl ScudoHeap {
    /// Create an uninitialised heap.
    pub const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(None),
        }
    }

    /// Initialise the allocator, seeding its header cookie from
    /// kernel entropy.
    ///
    /// Returns `false` if entropy was unavailable or the allocator
    /// refused the cookie. The caller must treat that as fatal: an
    /// allocator with a predictable cookie provides no integrity
    /// guarantee, and every later allocation would return null
    /// anyway.
    ///
    /// # Safety
    /// Must be called at most once, before any allocation, and
    /// before any additional thread exists.
    pub unsafe fn init(&self) -> bool {
        let cookie = match memory::random_u64() {
            Ok(value) if value != 0 => value,
            _ => return false,
        };
        let allocator = match Allocator::new(HeapWindow::new(), cookie) {
            Ok(allocator) => allocator,
            Err(_) => return false,
        };
        // SAFETY: called once before any other access, per the
        // function's contract.
        unsafe {
            *self.inner.get() = Some(allocator);
        }
        true
    }

    /// Whether [`Self::init`] has run successfully.
    pub fn is_initialised(&self) -> bool {
        // SAFETY: single-threaded process; no mutable borrow is live.
        unsafe { (*self.inner.get()).is_some() }
    }

    /// Runtime counters, or `None` before initialisation.
    pub fn stats(&self) -> Option<huesos_scudo::Stats> {
        // SAFETY: single-threaded process; read-only access.
        unsafe { (*self.inner.get()).as_ref().map(|inner| inner.stats()) }
    }
}

impl Default for ScudoHeap {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: HuesOS ring-3 processes are single-threaded (see the
// module docs). The `UnsafeCell` is never accessed concurrently
// because no second thread exists to access it.
unsafe impl Sync for ScudoHeap {}

// SAFETY: `alloc`/`dealloc` uphold the GlobalAlloc contract: they
// return either null or a pointer to `layout.size()` writable bytes
// aligned to `layout.align()`, and `dealloc` is only ever called
// with a pointer this allocator returned.
unsafe impl GlobalAlloc for ScudoHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: single-threaded; the mutable borrow does not
        // escape this call.
        let slot = unsafe { &mut *self.inner.get() };
        match slot {
            Some(allocator) => match allocator.allocate(layout.size(), layout.align()) {
                Ok(ptr) => ptr,
                // GlobalAlloc signals failure with null; the typed
                // error is available through `stats()` for
                // diagnostics.
                Err(_) => core::ptr::null_mut(),
            },
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: single-threaded; borrow does not escape.
        let slot = unsafe { &mut *self.inner.get() };
        if let Some(allocator) = slot {
            // The Rust language contract makes an invalid pointer
            // here caller UB, and `dealloc` cannot report an error.
            // The allocator still validates the header and refuses
            // to act on a corrupt one, so a bad free is contained
            // (counted in `stats()`) rather than corrupting the
            // heap — which is the whole point of the port.
            // SAFETY: `GlobalAlloc::dealloc` requires the caller to
            // pass a pointer from this allocator, which is exactly
            // `deallocate`'s contract.
            let _ = unsafe { allocator.deallocate(ptr) };
        }
    }
}
