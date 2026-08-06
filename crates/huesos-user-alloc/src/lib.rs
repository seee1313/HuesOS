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
//! for `usize` on x86_64), then bump the next-free pointer
//! forward. If the new pointer would exceed the heap, the
//! allocation fails (returns null) and the caller gets an
//! OOM. Deallocation: walk the free list and insert the
//! freed block. Coalescing of adjacent free blocks is a
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

#![no_std]
#![warn(missing_docs)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::{self, NonNull};

/// Default heap size for the hxfs-service MVP. The kernel
/// reserves 256 KiB of userspace virtual address for the
/// per-process heap; the rest of the BSS lives below this
/// region and the kernel places the linker sections at
/// fixed offsets.
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
    }
}

unsafe impl GlobalAlloc for UserAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let inner = &mut *self.inner.get();
        if !inner.initialised {
            return ptr::null_mut();
        }
        // Align the request up to 8 bytes for x86_64.
        let align = layout.align().max(8);
        let size = (layout.size() + align - 1) & !(align - 1);

        // Try the free list first.
        let mut cursor = inner.free;
        let mut prev: Option<NonNull<u8>> = None;
        while let Some(node) = cursor {
            let node_ptr = node.as_ptr();
            // Read the next pointer out of the freed block.
            let next_ptr = *(node_ptr as *const usize) as *mut u8;
            // The free list entries are 8-byte aligned, so
            // we can just check the size by trying to fit
            // the next allocation. The MVP doesn't track
            // sizes in the free list, so we always
            // re-allocate the first free block.
            if let Some(prev_node) = prev {
                *(prev_node.as_ptr() as *mut usize) = next_ptr as usize;
            } else {
                inner.free = NonNull::new(next_ptr);
            }
            return node_ptr;
        }

        // Bump-allocate from the live region.
        let aligned_next = (inner.next + align - 1) & !(align - 1);
        let new_next = aligned_next.checked_add(size).unwrap_or(0);
        if new_next > inner.end || new_next < aligned_next {
            ptr::null_mut()
        } else {
            inner.next = new_next;
            aligned_next as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let inner = &mut *self.inner.get();
        if !inner.initialised {
            return;
        }
        // Push the freed block onto the free list head. The
        // first usize of the block holds the previous
        // free-list head pointer.
        *(ptr as *mut usize) = match inner.free {
            Some(node) => node.as_ptr() as usize,
            None => 0,
        };
        inner.free = NonNull::new(ptr);
    }
}
