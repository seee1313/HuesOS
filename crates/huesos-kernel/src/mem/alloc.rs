#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};
use huesos_arch::{LockRank, RankedIrqSafeTicketLock};

use huesos_alloc::{AllocError, BuddyAllocator, BuddyProvider, SlabAllocator};

pub const BUDDY_ORDER: usize = 20;

pub struct KernelAllocator {
    buddy: Option<BuddyAllocator<BUDDY_ORDER>>,
    slab: SlabAllocator,
}

impl KernelAllocator {
    /// Construct an uninitialized kernel allocator whose large slab arrays live
    /// directly in `.bss` rather than on the boot stack.
    pub const fn uninit() -> Self {
        Self {
            buddy: None,
            slab: SlabAllocator::new(),
        }
    }

    /// Initialize the kernel heap allocator over pre-mapped pages.
    ///
    /// # Safety
    /// The range must be page-aligned, writable, exclusively owned by this
    /// allocator, and remain mapped for the kernel lifetime.
    pub unsafe fn init(&mut self, base_addr: usize, total_pages: usize) {
        self.buddy = Some(unsafe { BuddyAllocator::new(base_addr, total_pages, 4096) });
    }

    pub fn kmalloc(&mut self, size: usize) -> Result<usize, AllocError> {
        if size == 0 {
            return Err(AllocError::InvalidSize);
        }
        let buddy = self.buddy.as_mut().ok_or(AllocError::OutOfMemory)?;
        if size <= 2048 {
            let mut w = BuddyWrapper { buddy };
            self.slab.allocate(size, &mut w)
        } else {
            let pages = size.div_ceil(4096);
            buddy.allocate(pages)
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
        let buddy = self.buddy.as_mut().ok_or(AllocError::OutOfMemory)?;
        if size <= 2048 {
            let mut provider = BuddyWrapper { buddy };
            unsafe { self.slab.deallocate(ptr, size, &mut provider) }
        } else {
            let pages = size.div_ceil(4096);
            unsafe { buddy.deallocate(ptr, pages) }
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
        self.deallocate_pages(page, 1)
    }

    fn allocate_pages(&mut self, pages: usize) -> Result<usize, AllocError> {
        self.buddy.allocate(pages)
    }

    fn deallocate_pages(&mut self, page: usize, pages: usize) -> Result<(), AllocError> {
        // SAFETY: SlabCache returns only complete page blocks previously
        // supplied by this exact buddy allocator.
        unsafe { self.buddy.deallocate(page, pages) }
    }
}

pub fn kmalloc(size: usize) -> usize {
    GLOBAL_ALLOCATOR.lock().kmalloc(size).unwrap_or(0)
}

/// Free one kernel-heap allocation.
///
/// # Safety
/// `ptr` and `size` must satisfy [`KernelAllocator::kfree`]'s contract.
pub unsafe fn kfree(ptr: usize, size: usize) {
    let _ = unsafe { GLOBAL_ALLOCATOR.lock().kfree(ptr, size) };
}

pub static GLOBAL_ALLOCATOR: RankedIrqSafeTicketLock<KernelAllocator> =
    RankedIrqSafeTicketLock::new(KernelAllocator::uninit(), LockRank::ALLOCATOR);

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
