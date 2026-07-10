#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};
use huesos_arch::IrqSafeTicketLock;

use huesos_alloc::{BuddyAllocator, SlabAllocator, BuddyProvider, AllocError};

pub const BUDDY_ORDER: usize = 20;

pub struct KernelAllocator {
    buddy: BuddyAllocator<BUDDY_ORDER>,
    slab: SlabAllocator,
}

impl KernelAllocator {
    pub unsafe fn new(base_addr: usize, total_pages: usize) -> Self {
        Self {
            buddy: BuddyAllocator::new(base_addr, total_pages, 4096),
            slab: SlabAllocator::new(),
        }
    }

    pub fn kmalloc(&mut self, size: usize) -> Result<usize, AllocError> {
        if size == 0 { return Err(AllocError::InvalidSize); }
        if size <= 2048 {
            let mut w = BuddyWrapper { buddy: &mut self.buddy };
            self.slab.allocate(size, &mut w)
        } else {
            let pages = (size + 4095) / 4096;
            self.buddy.allocate(pages)
        }
    }

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

struct BuddyWrapper<'a> { buddy: &'a mut BuddyAllocator<BUDDY_ORDER> }

impl<'a> BuddyProvider for BuddyWrapper<'a> {
    fn allocate_page(&mut self) -> Result<usize, AllocError> { self.buddy.allocate(1) }
}

impl BuddyProvider for KernelAllocator {
    fn allocate_page(&mut self) -> Result<usize, AllocError> { self.buddy.allocate(1) }
}

pub fn kmalloc(size: usize) -> usize {
    let mut lock = GLOBAL_ALLOCATOR.lock();
    if let Some(a) = lock.as_mut() { a.kmalloc(size).unwrap_or(0) } else { 0 }
}

pub unsafe fn kfree(ptr: usize, size: usize) {
    let mut lock = GLOBAL_ALLOCATOR.lock();
    if let Some(a) = lock.as_mut() { a.kfree(ptr, size); }
}

pub static GLOBAL_ALLOCATOR: IrqSafeTicketLock<Option<KernelAllocator>> = IrqSafeTicketLock::new(None);

pub struct KernelGlobalAlloc;

unsafe impl GlobalAlloc for KernelGlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let sz = layout.size().max(layout.align());
        let addr = kmalloc(sz);
        if addr == 0 { core::ptr::null_mut() } else { addr as *mut u8 }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let sz = layout.size().max(layout.align());
        kfree(ptr as usize, sz);
    }
}

#[cfg(not(test))]
#[global_allocator]
pub static ALLOCATOR: KernelGlobalAlloc = KernelGlobalAlloc;
