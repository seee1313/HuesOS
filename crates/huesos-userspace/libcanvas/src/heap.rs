//! `GlobalAlloc` adapter binding `huesos-scudo` to the ring-3 heap.
//!
//! This is the piece that turns the platform-independent allocator
//! core into the process's `#[global_allocator]`:
//!
//! - In `local-heap` mode (static services and `libcanvas.so`),
//!   [`HeapWindow`] implements `huesos_scudo::backend::Backend` over
//!   `VmarHeapExtend` and [`ScudoHeap`] embeds the `Allocator`.
//! - In `dyn-client` mode, [`ScudoHeap`] is a thin zero-sized proxy
//!   forwarding allocations to `libcanvas.so` (`canvas_alloc` / `canvas_free`),
//!   where `libcanvas.so`'s `.init_array` constructor initialises the single
//!   process-wide Scudo instance once before `_start`.

use core::alloc::{GlobalAlloc, Layout};

#[cfg(feature = "local-heap")]
use core::cell::UnsafeCell;
#[cfg(feature = "local-heap")]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(feature = "local-heap")]
use huesos_scudo::backend::{Backend, BackendError};
#[cfg(feature = "local-heap")]
use huesos_scudo::Allocator;

#[cfg(feature = "local-heap")]
use crate::memory;

#[cfg(feature = "local-heap")]
struct HeapLock<T> {
    state: AtomicU32,
    data: UnsafeCell<T>,
}

#[cfg(feature = "local-heap")]
impl<T> HeapLock<T> {
    const fn new(data: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }

    #[inline]
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.state.swap(2, Ordering::Acquire) != 0 {
                let _ = crate::futex::wait(&self.state, 2, 0);
            }
        }
        struct Unlock<'a>(&'a AtomicU32);
        impl Drop for Unlock<'_> {
            #[inline]
            fn drop(&mut self) {
                if self.0.swap(0, Ordering::Release) == 2 {
                    let _ = crate::futex::wake(self.0, 1);
                }
            }
        }
        let _guard = Unlock(&self.state);
        // SAFETY: `self.state` was acquired via 3-state futex protocol and is
        // released only when `_guard` drops.
        f(unsafe { &mut *self.data.get() })
    }
}

// SAFETY: `HeapLock` enforces mutual exclusion via `AtomicBool` Acquire/Release.
#[cfg(feature = "local-heap")]
unsafe impl<T: Send> Sync for HeapLock<T> {}

/// A [`Backend`] over this process's kernel-reserved heap window.
#[cfg(feature = "local-heap")]
pub struct HeapWindow {
    base: usize,
    size: usize,
}

#[cfg(feature = "local-heap")]
impl HeapWindow {
    /// Describe the process's full heap window.
    pub const fn new() -> Self {
        Self {
            base: memory::HEAP_BASE,
            size: memory::HEAP_SIZE,
        }
    }
}

#[cfg(feature = "local-heap")]
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
#[cfg(feature = "local-heap")]
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
/// allocation (for dynamic binaries linked against `libcanvas.so`, the shared
/// library's `.init_array` constructor runs `init` automatically before `_start`).
#[cfg(feature = "local-heap")]
pub struct ScudoHeap {
    inner: HeapLock<Option<Allocator<HeapWindow>>>,
}

#[cfg(feature = "local-heap")]
impl ScudoHeap {
    /// Create an uninitialised heap.
    pub const fn new() -> Self {
        Self {
            inner: HeapLock::new(None),
        }
    }

    /// Initialise the allocator, seeding its header cookie from
    /// kernel entropy. Idempotent if already initialised.
    ///
    /// Returns `false` if entropy was unavailable or the allocator
    /// refused the cookie. The caller must treat that as fatal: an
    /// allocator with a predictable cookie provides no integrity
    /// guarantee, and every later allocation would return null
    /// anyway.
    ///
    /// # Safety
    /// Must be called before concurrent use if no synchronisation barrier
    /// exists yet; thread-safe under internal `HeapLock` once constructed.
    pub unsafe fn init(&self) -> bool {
        if self.is_initialised() {
            return true;
        }
        let cookie = match memory::random_u64() {
            Ok(value) if value != 0 => value,
            _ => return false,
        };
        self.inner.with(|slot| {
            if slot.is_some() {
                return true;
            }
            match Allocator::new(HeapWindow::new(), cookie) {
                Ok(allocator) => {
                    *slot = Some(allocator);
                    true
                }
                Err(_) => false,
            }
        })
    }

    /// Safely initialise the single process-wide [`ScudoHeap`] instance.
    ///
    /// Enforces via a one-shot atomic claim that at most one `'static ScudoHeap`
    /// in the address space can own [`HeapWindow`], while [`HeapLock`] serialises
    /// concurrent callers.
    pub fn init_process_heap(&'static self) -> bool {
        static CLAIMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        if self.is_initialised() {
            return true;
        }
        if CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return self.is_initialised();
        }
        let cookie = match memory::random_u64() {
            Ok(value) if value != 0 => value,
            _ => return false,
        };
        self.inner.with(|slot| {
            if slot.is_some() {
                return true;
            }
            match Allocator::new(HeapWindow::new(), cookie) {
                Ok(allocator) => {
                    *slot = Some(allocator);
                    true
                }
                Err(_) => false,
            }
        })
    }

    /// Whether [`Self::init`] has run successfully.
    pub fn is_initialised(&self) -> bool {
        self.inner.with(|slot| slot.is_some())
    }

    /// Query usable bytes for a live allocation returned by this heap.
    ///
    /// # Safety
    /// `ptr` must be a live non-null pointer previously returned by this heap.
    #[cfg(feature = "c-abi")]
    pub(crate) unsafe fn usable_size(&self, ptr: *mut u8) -> Option<usize> {
        self.inner.with(|slot| {
            slot.as_mut()
                .and_then(|allocator| unsafe { allocator.usable_size(ptr) }.ok())
        })
    }

    /// Runtime counters, or `None` before initialisation.
    pub fn stats(&self) -> Option<huesos_scudo::Stats> {
        self.inner
            .with(|slot| slot.as_ref().map(|inner| inner.stats()))
    }
}

#[cfg(feature = "local-heap")]
impl Default for ScudoHeap {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: `alloc`/`dealloc` uphold the GlobalAlloc contract: they
// return either null or a pointer to `layout.size()` writable bytes
// aligned to `layout.align()`, and `dealloc` is only ever called
// with a pointer this allocator returned.
#[cfg(feature = "local-heap")]
unsafe impl GlobalAlloc for ScudoHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.inner.with(|slot| match slot {
            Some(allocator) => match allocator.allocate(layout.size(), layout.align()) {
                Ok(ptr) => ptr,
                // GlobalAlloc signals failure with null; the typed
                // error is available through `stats()` for
                // diagnostics.
                Err(_) => core::ptr::null_mut(),
            },
            None => core::ptr::null_mut(),
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        self.inner.with(|slot| {
            if let Some(allocator) = slot {
                // SAFETY: `GlobalAlloc::dealloc` requires the caller to
                // pass a pointer from this allocator, which is exactly
                // `deallocate`'s contract.
                let _ = unsafe { allocator.deallocate(ptr) };
            }
        });
    }
}

#[cfg(not(feature = "local-heap"))]
#[link(name = "canvas", kind = "dylib")]
unsafe extern "C" {
    fn canvas_heap_init() -> i64;
    fn canvas_heap_is_initialised() -> u8;
    fn canvas_alloc(size: usize, align: usize) -> *mut u8;
    fn canvas_free(ptr: *mut u8);
}

/// Thin proxy to `libcanvas.so`'s single process-wide Scudo heap.
#[cfg(not(feature = "local-heap"))]
pub struct ScudoHeap;

#[cfg(not(feature = "local-heap"))]
impl ScudoHeap {
    /// Create a proxy handle to `libcanvas.so`'s global heap.
    pub const fn new() -> Self {
        Self
    }

    /// Ensure `libcanvas.so`'s Scudo heap is initialised (idempotent).
    ///
    /// # Safety
    /// Same single-threaded initialisation contract as the embedded heap.
    pub unsafe fn init(&self) -> bool {
        // SAFETY: C ABI call into `libcanvas.so`.
        unsafe { canvas_heap_init() == 0 }
    }

    /// Whether `libcanvas.so`'s Scudo heap is initialised.
    pub fn is_initialised(&self) -> bool {
        // SAFETY: C ABI call into `libcanvas.so`.
        unsafe { canvas_heap_is_initialised() != 0 }
    }
}

#[cfg(not(feature = "local-heap"))]
impl Default for ScudoHeap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "local-heap"))]
unsafe impl GlobalAlloc for ScudoHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegates to `libcanvas.so`'s GlobalAlloc-compatible allocator.
        unsafe { canvas_alloc(layout.size(), layout.align()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: `ptr` came from `canvas_alloc` in `libcanvas.so`.
        unsafe { canvas_free(ptr) }
    }
}
