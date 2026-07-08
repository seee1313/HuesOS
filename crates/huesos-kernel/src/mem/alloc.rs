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

        // If the size is small enough, use the Slab allocator.
        if size <= 2048 {
            self.slab.allocate(size, &mut self)
        } else {
            // Otherwise, use Buddy allocator.
            // Calculate pages needed.
            let pages = (size + 4095) / 4096;
            let addr = self.buddy.allocate(pages)?;
            Ok(addr)
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

/// Implement BuddyProvider so SlabAllocator can request pages from the Buddy system.
impl BuddyProvider for KernelAllocator {
    fn allocate_page(&mut self) -> Result<usize, AllocError> {
        self.buddy.allocate(1)
    }
}

/// Global singleton for the kernel allocator.
pub static GLOBAL_ALLOCATOR: Mutex<Option<KernelAllocator>> = Mutex::new(None);

/// Public API for kernel allocation.
pub fn kmalloc(size: usize) -> usize {
    let mut lock = GLOBAL_ALLOCATOR.lock();
    let alloc = lock.as_mut().expect("Kernel allocator not initialized");
    alloc.kmalloc(size).expect("Kernel out of memory during kmalloc")
}

pub unsafe fn kfree(ptr: usize, size: usize) {
    let mut lock = GLOBAL_ALLOCATOR.lock();
    let alloc = lock.as_mut().expect("Kernel allocator not initialized");
    alloc.kfree(ptr, size);
}
