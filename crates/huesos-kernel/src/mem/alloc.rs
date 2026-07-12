#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};
use huesos_arch::IrqSafeTicketLock;

use huesos_alloc::{AllocError, BuddyAllocator, BuddyProvider, SlabAllocator};

pub const BUDDY_ORDER: usize = 20;

pub struct KernelAllocator {
    buddy: BuddyAllocator<BUDDY_ORDER>,
    slab: SlabAllocator,
}

impl KernelAllocator {
    /// Create the kernel heap allocator over pre-mapped pages.
    ///
    /// # Safety
    /// The range must be page-aligned, writable, exclusively owned by this
    /// allocator, and remain mapped for the kernel lifetime.
    pub unsafe fn new(base_addr: usize, total_pages: usize) -> Self {
        Self {
            buddy: unsafe { BuddyAllocator::new(base_addr, total_pages, 4096) },
            slab: SlabAllocator::new(),
        }
    }

    pub fn kmalloc(&mut self, size: usize) -> Result<usize, AllocError> {
        if size == 0 {
            return Err(AllocError::InvalidSize);
        }
        if size <= 2048 {
            let mut w = BuddyWrapper {
                buddy: &mut self.buddy,
            };
            self.slab.allocate(size, &mut w)
        } else {
            let pages = size.div_ceil(4096);
            self.buddy.allocate(pages)
        }
    }

    /// Free one allocation returned by [`Self::kmalloc`].
    ///
    /// # Safety
    /// `ptr` must be live, allocated by this instance, and paired with the
    /// original allocation size. It must not be freed twice.
    pub unsafe fn kfree(&mut self, ptr: usize, size: usize) -> Result<(), AllocError> {
        if size == 0 {
            return Err(AllocError::InvalidSize);
        }
        if size <= 2048 {
            let mut provider = BuddyWrapper {
                buddy: &mut self.buddy,
            };
            unsafe { self.slab.deallocate(ptr, size, &mut provider) }
        } else {
            let pages = size.div_ceil(4096);
            unsafe { self.buddy.deallocate(ptr, pages) }
        }
    }
}

struct BuddyWrapper<'a> {
    buddy: &'a mut BuddyAllocator<BUDDY_ORDER>,
}

impl BuddyProvider for BuddyWrapper<'_> {
    fn allocate_page(&mut self) -> Result<usize, AllocError> {
        self.buddy.allocate(1)
    }

    fn deallocate_page(&mut self, page: usize) -> Result<(), AllocError> {
        // SAFETY: SlabCache returns only complete pages previously supplied by
        // this exact buddy allocator.
        unsafe { self.buddy.deallocate(page, 1) }
    }
}

impl BuddyProvider for KernelAllocator {
    fn allocate_page(&mut self) -> Result<usize, AllocError> {
        self.buddy.allocate(1)
    }

    fn deallocate_page(&mut self, page: usize) -> Result<(), AllocError> {
        // SAFETY: BuddyProvider contract pairs this with allocate_page.
        unsafe { self.buddy.deallocate(page, 1) }
    }
}

pub fn kmalloc(size: usize) -> usize {
    let mut lock = GLOBAL_ALLOCATOR.lock();
    if let Some(a) = lock.as_mut() {
        a.kmalloc(size).unwrap_or(0)
    } else {
        0
    }
}

/// Free one kernel-heap allocation.
///
/// # Safety
/// `ptr` and `size` must satisfy [`KernelAllocator::kfree`]'s contract.
pub unsafe fn kfree(ptr: usize, size: usize) {
    let mut lock = GLOBAL_ALLOCATOR.lock();
    if let Some(allocator) = lock.as_mut() {
        let _ = unsafe { allocator.kfree(ptr, size) };
    }
}

pub static GLOBAL_ALLOCATOR: IrqSafeTicketLock<Option<KernelAllocator>> =
    IrqSafeTicketLock::new(None);

pub struct KernelGlobalAlloc;

unsafe impl GlobalAlloc for KernelGlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let sz = layout.size().max(layout.align());
        let addr = kmalloc(sz);
        if addr == 0 {
            core::ptr::null_mut()
        } else {
            addr as *mut u8
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let sz = layout.size().max(layout.align());
        kfree(ptr as usize, sz);
    }
}

#[cfg(not(test))]
#[global_allocator]
pub static ALLOCATOR: KernelGlobalAlloc = KernelGlobalAlloc;
