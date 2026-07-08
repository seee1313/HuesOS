//! Kernel Global Allocator.
//! Implements kmalloc and kfree using a combination of Buddy and Slab allocation.

use huesos_alloc::{BuddyAllocator, SlabAllocator, BuddyProvider, AllocError};
use spin::Mutex;

/// The global allocator instance.
pub struct KernelAllocator {
    buddy: BuddyAllocator<10>,
    slab: SlabAllocator,
}

impl KernelAllocator {
    /// Initialize the kernel allocator with a region of memory.
    pub unsafe fn new(base_addr: usize, total_pages: usize) -> Self {
        Self {
            buddy: BuddyAllocator::new(base_addr, total_pages, 4096),
            slab: SlabAllocator::new(),
        }
    }

    /// Allocate memory of given size.
    pub fn kmalloc(&mut self, size: usize) -> Result<usize, AllocError> {
        if size == 0 {
            return Err(AllocError::InvalidSize);
        }

        if size <= 2048 {
            let mut buddy_wrapper = BuddyWrapper { buddy: &mut self.buddy };
            self.slab.allocate(size, &mut buddy_wrapper)
        } else {
            let pages = (size + 4095) / 4096;
            self.buddy.allocate(pages)
        }
    }

    /// Free memory previously allocated by kmalloc.
    pub unsafe fn kfree(&mut self, ptr: usize, size: usize) {
        if size == 0 { return; }

        if size <= 2048 {
            self.slab.deallocate(ptr, size);
        } else {
            let pages = (size + 4095) / 4096;
            self.buddy.deallocate(ptr, pages);
        }
    }
}

struct BuddyWrapper<'a> {
    buddy: &'a mut BuddyAllocator<10>,
}

impl<'a> BuddyProvider for BuddyWrapper<'a> {
    fn allocate_page(&mut self) -> Result<usize, AllocError> {
        self.buddy.allocate(1)
    }
}

impl BuddyProvider for KernelAllocator {
    fn allocate_page(&mut self) -> Result<usize, AllocError> {
        self.buddy.allocate(1)
    }
}

/// Global singleton for the kernel allocator.
pub static GLOBAL_ALLOCATOR: Mutex<Option<KernelAllocator>> = Mutex::new(None);

/// Public API for kernel allocation.
/// Returns 0 on failure (caller must handle).
pub fn kmalloc(size: usize) -> usize {
    let mut lock = GLOBAL_ALLOCATOR.lock();
    if let Some(alloc) = lock.as_mut() {
        alloc.kmalloc(size).unwrap_or(0)
    } else {
        0
    }
}

pub unsafe fn kfree(ptr: usize, size: usize) {
    let mut lock = GLOBAL_ALLOCATOR.lock();
    if let Some(alloc) = lock.as_mut() {
        alloc.kfree(ptr, size);
    }
}
