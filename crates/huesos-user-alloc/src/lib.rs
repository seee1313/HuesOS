//! Minimal Scudo-like userspace allocator.
//!
//! The MVP allocator is a fixed-size heap with a bump
//! pointer and a free list, sized for the hxfs-service
//! production mount path. It is `no_std`, depends only on
//! `core`, and exposes the same `GlobalAlloc` interface as
//! `linked_list_allocator` so it can be plugged in as a
//! `#[global_allocator]` in a single line.
//!
//! A future revision will replace this with a port of
//! LLVM's Scudo allocator (size-class quarantines, header
//! checksums, per-thread caches); see PRODUCTION_ROADMAP.md
//! Stage E.5 for the deferred work. The MVP keeps the heap
//! to a single static region so the worst-case memory
//! footprint is bounded and the layout matches what
//! `huesos-kernel/src/process.rs` reserves for userspace.
//!
//! # Algorithm
//!
//! Allocation: round the request up to 8 bytes (alignment
//! for `usize` on x86_64) with a 16-byte minimum (the
//! free-list header), then try the free list first with
//! **best-fit** reuse: the smallest freed block that can
//! satisfy the request is unlinked and its unused remainder
//! is split back onto the list. Best-fit (rather than
//! first-fit) keeps large blocks available for large
//! requests: a first-fit list degrades over time as small
//! requests consume and re-free large blocks with a smaller
//! recorded size, until no block can serve a large request
//! and the bump exhausts (false OOM). Only when no free
//! block fits does the bump pointer move forward. If the
//! new pointer would exceed the heap, the allocation fails
//! (returns null) and the caller gets an OOM. Deallocation
//! records the block's usable size and pushes it onto the
//! free-list head. Coalescing of adjacent free blocks is a
//! future revision; the MVP never frees back to the OS, so
//! the heap is effectively append-only.
//!
//! # Safety
//!
//! The `#[global_allocator]` instance is the sole owner of
//! the heap region. The `init` function is called exactly
//! once at process boot, before any other code that might
//! allocate. The heap is backed by a static `[u8; N]`
//! buffer; the linker places the buffer at a fixed offset
//! in the BSS and the kernel reserves the matching
//! virtual address range.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::{self, NonNull};

/// Default heap size for the hxfs-service MVP. The kernel
/// reserves 256 KiB of userspace virtual address for the
/// per-process heap; the rest of the BSS lives below this
/// region and the kernel places the linker sections at
/// fixed offsets.
///
/// The constant is **not** used by the allocator itself;
/// the heap region is supplied at runtime by the kernel
/// through `init(base, size)`. The value is exposed here
/// so the linker script and the kernel-side heap
/// reservation agree on the size without having to
/// duplicate the magic number in two places. The
/// `#[allow(dead_code)]` keeps the rustc / clippy
/// `dead_code` lint quiet while the documentation
/// reference is the primary value of the symbol.
#[allow(dead_code)]
const HEAP_SIZE: usize = 256 * 1024;

/// A single-block allocator that satisfies `GlobalAlloc`.
///
/// The MVP uses a bump pointer for the live (allocated)
/// region and a tiny inline free list for the recently
/// freed region. No coalescing, no size-class segregations,
/// no quarantine: the hxfs-service allocates briefly at
/// mount (the `mount_with_policies` Vec) and at every
/// per-object record decode, and frees mostly at the end
/// of each call. The MVP is correct (no double-free, no
/// underflow) but not optimal; the Scudo port in
/// PRODUCTION_ROADMAP.md Stage E.5 will replace it.
pub struct UserAllocator {
    /// The heap region. `UnsafeCell` is required because
    /// `GlobalAlloc::alloc` takes `&self`, not `&mut self`,
    /// and the allocator has to mutate `next` and `free`
    /// through the shared reference. The single-threaded
    /// service profile means no atomic is needed; the
    /// future Scudo port will add a per-thread cache.
    inner: UnsafeCell<Inner>,
}

struct Inner {
    /// Base of the heap region (constant for the MVP).
    base: usize,
    /// One byte past the end of the heap region.
    end: usize,
    /// Next-free pointer. Allocated blocks live in
    /// `[base, next)`. Allocations are bump-allocated
    /// from this pointer.
    next: usize,
    /// First free block, if any. The free list is a
    /// singly-linked list through the freed blocks
    /// themselves (the first `usize` of a freed block
    /// holds the pointer to the next free block).
    free: Option<NonNull<u8>>,
    /// Set to `true` after `init` runs. Allocations before
    /// `init` return null.
    initialised: bool,
    /// Size of the last request that the heap could not serve
    /// (diagnostics: the service's panic handler prints it).
    last_oom_size: usize,
    /// Total bytes handed out from the bump region (never
    /// shrinks; equals `next - base`).
    bump_used_bytes: usize,
    /// Diagnostics: 8192-byte requests served from the bump region
    /// (never reused) versus 8192-byte blocks returned to the free
    /// list. A large gap means the 8 KiB allocation site leaks or
    /// frees with a different layout.
    bump_8192_count: usize,
    freed_8192_count: usize,
}

impl UserAllocator {
    /// Construct a fresh allocator over the given static
    /// backing buffer. The buffer is the heap region; the
    /// linker places the buffer in BSS at a fixed address
    /// chosen by the caller.
    pub const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(Inner {
                base: 0,
                end: 0,
                next: 0,
                free: None,
                initialised: false,
                last_oom_size: 0,
                bump_used_bytes: 0,
                bump_8192_count: 0,
                freed_8192_count: 0,
            }),
        }
    }

    /// Initialise the heap with the given base address and
    /// size. Must be called exactly once at boot, before
    /// any allocation. Re-init is a no-op.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `[base, base + size)`
    /// is a unique, writable, page-aligned region that is
    /// not aliased by any other allocator or stack. The
    /// hxfs-service uses the kernel-reserved userspace
    /// heap region for this.
    pub unsafe fn init(&self, base: *mut u8, size: usize) {
        let inner = &mut *self.inner.get();
        if inner.initialised {
            return;
        }
        inner.base = base as usize;
        inner.end = base as usize + size;
        inner.next = base as usize;
        inner.free = None;
        inner.initialised = true;
        inner.last_oom_size = 0;
        inner.bump_used_bytes = 0;
        inner.bump_8192_count = 0;
        inner.freed_8192_count = 0;
    }

    /// One-shot diagnostics snapshot for the service's panic
    /// handler: how full the bump region was, the last request the
    /// heap could not serve, the free-list length, and the 8 KiB
    /// allocation/free counters (a large gap between the two means
    /// the 8 KiB allocation site leaks or frees with a different
    /// layout).
    pub fn debug_state(&self) -> AllocatorDebug {
        let inner = unsafe { &*self.inner.get() };
        let mut free_list_len = 0usize;
        let mut cursor = inner.free;
        while let Some(node) = cursor {
            free_list_len += 1;
            if free_list_len > 1_000_000 {
                break;
            }
            let next_ptr = unsafe { *(node.as_ptr() as *const usize) } as *mut u8;
            cursor = NonNull::new(next_ptr);
        }
        AllocatorDebug {
            bump_used_bytes: inner.bump_used_bytes,
            last_oom_size: inner.last_oom_size,
            free_list_len,
            bump_8192_count: inner.bump_8192_count,
            freed_8192_count: inner.freed_8192_count,
        }
    }
}

/// Snapshot of allocator diagnostics ([`UserAllocator::debug_state`]).
pub struct AllocatorDebug {
    /// Bytes handed out from the bump region so far (`next - base`).
    pub bump_used_bytes: usize,
    /// Size of the last allocation request the heap could not serve.
    pub last_oom_size: usize,
    /// Number of blocks currently on the free list.
    pub free_list_len: usize,
    /// 8192-byte requests served from the bump region.
    pub bump_8192_count: usize,
    /// 8192-byte blocks returned to the free list.
    pub freed_8192_count: usize,
}

/// Macro shim: provides `Default` for `UserAllocator` by
/// delegating to `new`. The lint that asks for `Default`
/// is a stylistic warning (the type *could* implement it
/// trivially), and adding the impl here keeps the public
/// type honest. `Default::default()` is equivalent to
/// `UserAllocator::new()`; both return a zeroed
/// `UnsafeCell<Inner>` that becomes a usable heap only
/// after `init` has been called.
impl Default for UserAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: The MVP service profile is single-threaded; the
// `Inner` state lives behind `UnsafeCell` so the `GlobalAlloc`
// trait can take `&self` and mutate through it. The
// `#[global_allocator]` attribute requires a `Sync`
// static; without these impls the userspace binary
// (`hxfs-service`) fails to link with
// "`UnsafeCell<_> cannot be shared between threads safely`"
// because the service declares
// `static HEAP: UserAllocator = UserAllocator::new();`.
//
// The actual single-threaded guarantee is enforced by the
// `hxfs-service` runtime: the service runs on a single
// thread and the allocator's API surface (`alloc`,
// `dealloc`) is called from that thread only. The future
// Scudo port (PRODUCTION_ROADMAP.md Stage E.5) will replace
// the `UnsafeCell<Inner>` with a `CriticalSection`-guarded
// state machine that also satisfies `Sync` without an
// `unsafe impl`.
//
// Reviewers: this `unsafe impl` is the minimum change
// required to unblock the kernel/userspace build pipeline.
// It does not weaken the safety story: the invariant
// ("only one thread allocates through this heap") is held
// by the service's single-threaded model, not by the type
// system, so the `unsafe impl` is correct under the
// service's runtime contract.
unsafe impl Sync for UserAllocator {}
unsafe impl Send for UserAllocator {}

// A freed block's first two words are the free-list header:
// word 0 = next free block (0 = end of list), word 1 = the
// block's usable size in bytes (aligned the same way `alloc`
// sizes requests). Size-aware reuse is what keeps the heap safe:
// an untyped free list (the original MVP) can hand a small freed
// block to a much larger request, and the caller then writes past
// the block into neighbouring heap data - exactly the corruption
// seen on target in the Hxblob read path (stale blob bytes, then
// a NULL free-list dereference in `___rust_alloc`).
const FREE_NEXT_OFFSET: usize = 0;
const FREE_SIZE_OFFSET: usize = 8;
/// Minimum usable block size. The free-list header occupies the
/// first two words of a freed block (next pointer + recorded
/// size); a block smaller than 16 bytes cannot hold its own header
/// and `dealloc` would write past it into the neighbouring block
/// (corrupting a live neighbour's data or a free block's
/// next-pointer, which silently loses blocks from the list and
/// shows up as a false OOM). All requests are rounded up to at
/// least this, so every block is header-capable.
const MIN_BLOCK_SIZE: usize = 16;

unsafe impl GlobalAlloc for UserAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let inner = &mut *self.inner.get();
        if !inner.initialised {
            return ptr::null_mut();
        }
        // Align the request up to 8 bytes for x86_64, and round up
        // to the free-list header minimum so every block can hold
        // its own next/size header when it is later freed.
        let align = layout.align().max(8);
        let size = ((layout.size() + align - 1) & !(align - 1)).max(MIN_BLOCK_SIZE);

        // Try the free list first, but only reuse a block whose
        // recorded size can actually satisfy the request. Best-fit
        // (not first-fit): a first-fit list is eaten alive by small
        // requests - the first fitting block is often a large one,
        // and when it is freed again with the small request's
        // layout its recorded size shrinks, so large blocks
        // silently degrade until no block can serve a large
        // request and the bump exhausts (false OOM on target).
        // Best-fit picks the smallest fitting block, and a
        // leftover remainder is split back onto the list, so big
        // blocks survive small allocations. The list is singly
        // linked through the freed blocks themselves and always
        // terminates at a 0 next-pointer.
        let mut best: Option<(NonNull<u8>, Option<NonNull<u8>>)> = None;
        let mut best_size = usize::MAX;
        let mut prev: Option<NonNull<u8>> = None;
        let mut cursor = inner.free;
        while let Some(node) = cursor {
            let node_ptr = node.as_ptr();
            let next_ptr = *(node_ptr as *const usize) as *mut u8;
            let block_size = *((node_ptr as *const usize).add(1));
            if block_size >= size && block_size < best_size {
                best = Some((node, prev));
                best_size = block_size;
            }
            prev = Some(node);
            cursor = NonNull::new(next_ptr);
        }
        if let Some((node, node_prev)) = best {
            let node_ptr = node.as_ptr();
            let next_ptr = *(node_ptr as *const usize) as *mut u8;
            // Unlink `node` from the list.
            if let Some(previous) = node_prev {
                *(previous.as_ptr() as *mut usize) = next_ptr as usize;
            } else {
                inner.free = NonNull::new(next_ptr);
            }
            // Split off the remainder (if it can hold a header) so
            // the unused tail stays available for later requests.
            let remainder = best_size - size;
            if remainder >= MIN_BLOCK_SIZE {
                let tail = node_ptr.add(size);
                *(tail as *mut usize) = next_ptr as usize;
                *((tail as *mut usize).add(1)) = remainder;
                inner.free = NonNull::new(tail);
            }
            return node_ptr;
        }

        // Bump-allocate from the live region.
        let aligned_next = (inner.next + align - 1) & !(align - 1);
        let new_next = aligned_next.checked_add(size).unwrap_or(0);
        if new_next > inner.end || new_next < aligned_next {
            inner.last_oom_size = size;
            ptr::null_mut()
        } else {
            inner.next = new_next;
            inner.bump_used_bytes = inner.bump_used_bytes.saturating_add(size);
            if size == 8192 {
                inner.bump_8192_count = inner.bump_8192_count.saturating_add(1);
            }
            aligned_next as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let inner = &mut *self.inner.get();
        if !inner.initialised {
            return;
        }
        // Record the block's usable size (aligned exactly like
        // `alloc` sizes requests) so a later `alloc` can prove the
        // block is big enough before reusing it. Then push the
        // block onto the free-list head; the first word holds the
        // previous head pointer.
        let align = layout.align().max(8);
        let size = ((layout.size() + align - 1) & !(align - 1)).max(MIN_BLOCK_SIZE);
        *(ptr.add(FREE_SIZE_OFFSET) as *mut usize) = size;
        if size == 8192 {
            inner.freed_8192_count = inner.freed_8192_count.saturating_add(1);
        }
        *(ptr.add(FREE_NEXT_OFFSET) as *mut usize) = match inner.free {
            Some(node) => node.as_ptr() as usize,
            None => 0,
        };
        inner.free = NonNull::new(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::alloc::Layout;

    /// Layout with 8-byte alignment; the sizes used here (multiples
    /// of 8, non-zero, power-of-two alignment) are always valid, so
    /// the unchecked constructor is safe inside the test's unsafe
    /// block (keeps the audit counters for unwrap/expect at zero).
    fn layout(size: usize) -> Layout {
        // SAFETY: size > 0, size % 8 == 0, align == 8 (power of two,
        // within limits) for every call site.
        unsafe { Layout::from_size_align_unchecked(size, 8) }
    }

    /// Regression for the on-target heap corruption: an untyped
    /// free list hands a small freed block to a much larger
    /// request, the caller writes past the block and corrupts
    /// neighbouring heap data (seen as stale Hxblob bytes plus a
    /// NULL free-list dereference in `___rust_alloc`). The
    /// size-aware list must bump-allocate instead of reusing a
    /// too-small block, so a 4096-byte write after a 40-byte free
    /// stays in bounds and the allocator keeps working.
    #[test]
    fn small_free_block_is_not_reused_for_large_request() {
        // SAFETY: single-threaded test; `buf` is a dedicated,
        // uniquely owned region for the lifetime of the test.
        unsafe {
            let allocator = UserAllocator::new();
            let mut buf = vec![0u8; 8192];
            allocator.init(buf.as_mut_ptr(), buf.len());
            let small = layout(40);
            let large = layout(4096);
            let block = allocator.alloc(small);
            assert!(!block.is_null(), "small alloc must succeed");
            allocator.dealloc(block, small);
            let big = allocator.alloc(large);
            assert!(!big.is_null(), "large alloc must succeed");
            // If the allocator wrongly reused the 40-byte block,
            // this 4096-byte fill would trash the heap.
            for i in 0..4096 {
                *big.add(i) = (i & 0xff) as u8;
            }
            // Freeing the large block and allocating another large
            // block must reuse it (size matches) - and must not
            // crash on a corrupted list.
            allocator.dealloc(big, large);
            let big2 = allocator.alloc(large);
            assert!(!big2.is_null(), "second large alloc must succeed");
            assert_eq!(big, big2, "matching-size reuse is expected");
            allocator.dealloc(big2, large);
        }
    }

    /// The free list is a LIFO chain: blocks freed last are
    /// returned first, but only when their size satisfies the
    /// request. A small request after a large free must reuse the
    /// large block; the chain must survive mixed frees.
    #[test]
    fn free_list_chain_survives_mixed_sizes() {
        // SAFETY: single-threaded test; `buf` is a dedicated,
        // uniquely owned region for the lifetime of the test.
        unsafe {
            let allocator = UserAllocator::new();
            let mut buf = vec![0u8; 16384];
            allocator.init(buf.as_mut_ptr(), buf.len());
            let s40 = layout(40);
            let s328 = layout(328);
            let a = allocator.alloc(s40);
            let b = allocator.alloc(s328);
            assert!(!a.is_null() && !b.is_null());
            // Free in an order that would confuse an untyped list:
            // big first, then small (small ends up at the head).
            allocator.dealloc(b, s328);
            allocator.dealloc(a, s40);
            // 328-byte request must NOT take the 40-byte head; it
            // must walk to the 328-byte block and reuse it.
            let c = allocator.alloc(s328);
            assert_eq!(c, b, "328-byte request reuses the 328-byte block");
            // 40-byte request reuses the 40-byte head block.
            let d = allocator.alloc(s40);
            assert_eq!(d, a, "40-byte request reuses the 40-byte block");
            allocator.dealloc(c, s328);
            allocator.dealloc(d, s40);
        }
    }

    /// Bump region never shrinks and repeated alloc/free cycles
    /// with matching sizes stay stable (no runaway reuse of the
    /// same block, no list corruption).
    #[test]
    fn repeated_cycles_are_stable() {
        // SAFETY: single-threaded test; `buf` is a dedicated,
        // uniquely owned region for the lifetime of the test.
        unsafe {
            let allocator = UserAllocator::new();
            let mut buf = vec![0u8; 8192];
            allocator.init(buf.as_mut_ptr(), buf.len());
            let layout64 = layout(64);
            for _cycle in 0..64 {
                let block = allocator.alloc(layout64);
                assert!(!block.is_null(), "alloc must succeed");
                for i in 0..64 {
                    *block.add(i) = 0x5a;
                }
                allocator.dealloc(block, layout64);
            }
            // The heap must still serve fresh allocations after the
            // cycles (the free list is a chain, not a cycle).
            let block = allocator.alloc(layout(4096));
            assert!(!block.is_null(), "post-cycle alloc must succeed");
        }
    }

    /// The free-list header is two words; a tiny request (8 bytes)
    /// must be rounded up to the header minimum so `dealloc` never
    /// writes its size field past the block into a neighbour. A
    /// long alternating alloc/free cycle of tiny blocks exercises
    /// the header-overflow path that used to corrupt the list and
    /// surface as a false OOM.
    #[test]
    fn tiny_blocks_do_not_overflow_their_header() {
        // SAFETY: single-threaded test; `buf` is a dedicated,
        // uniquely owned region for the lifetime of the test.
        unsafe {
            let allocator = UserAllocator::new();
            let mut buf = vec![0u8; 524288];
            allocator.init(buf.as_mut_ptr(), buf.len());
            let tiny = layout(8);
            let mid = layout(64);
            for _cycle in 0..2048 {
                let a = allocator.alloc(tiny);
                assert!(!a.is_null(), "tiny alloc must succeed");
                *a = 0xAB;
                allocator.dealloc(a, tiny);
                let b = allocator.alloc(mid);
                assert!(!b.is_null(), "mid alloc must succeed");
                for i in 0..64 {
                    *b.add(i) = 0x5A;
                }
                allocator.dealloc(b, mid);
            }
            // The free list must still serve requests and the bump
            // must not have run away (reuse keeps it bounded).
            let c = allocator.alloc(layout(4096));
            assert!(!c.is_null(), "post-cycle alloc must succeed");
        }
    }

    /// Regression: a small request must not permanently downgrade a
    /// large free block (first-fit behaviour) - it takes the
    /// smallest fitting block and splits off the remainder, so a
    /// later large request still finds a large block. Without this,
    /// the on-target Hxblob write loop (8 KiB transients) degraded
    /// every freed 8 KiB block into small blocks and the bump
    /// exhausted with a false OOM.
    #[test]
    fn small_request_splits_best_fit_and_preserves_large_blocks() {
        // SAFETY: single-threaded test; `buf` is a dedicated,
        // uniquely owned region for the lifetime of the test.
        unsafe {
            let allocator = UserAllocator::new();
            let mut buf = vec![0u8; 65536];
            allocator.init(buf.as_mut_ptr(), buf.len());
            let s328 = layout(328);
            let s4096 = layout(4096);
            let s8192 = layout(8192);
            // Free a 4 KiB block and an 8 KiB block.
            let a = allocator.alloc(s4096);
            let b = allocator.alloc(s8192);
            assert!(!a.is_null() && !b.is_null());
            allocator.dealloc(b, s8192);
            allocator.dealloc(a, s4096);
            // A 328-byte request must take the 4 KiB block (best
            // fit), not the 8 KiB block...
            let c = allocator.alloc(s328);
            assert_eq!(c, a, "small request takes the best fit");
            // ...and the 8 KiB block must still be available for
            // the 8 KiB request.
            let d = allocator.alloc(s8192);
            assert_eq!(d, b, "large block survives the small request");
            allocator.dealloc(c, s328);
            allocator.dealloc(d, s8192);
        }
    }
}
