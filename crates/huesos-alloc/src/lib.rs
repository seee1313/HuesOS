//! HuesOS Memory Allocation Crate.
//! Buddy + Slab allocator for no_std kernels.

#![no_std]

use core::option::Option;
use core::result::Result;

#[derive(Debug, PartialEq, Eq)]
pub enum AllocError {
    OutOfMemory,
    InvalidSize,
}

pub struct BuddyAllocator<const ORDER: usize> {
    free_lists: [Option<*mut FreeBlock>; ORDER],
    base_addr: usize,
    #[allow(dead_code)]
    total_pages: usize,
}

#[repr(C)]
struct FreeBlock {
    next: Option<*mut FreeBlock>,
}

impl<const ORDER: usize> BuddyAllocator<ORDER> {
    pub unsafe fn new(base_addr: usize, total_pages: usize, page_size: usize) -> Self {
        let mut allocator = Self {
            free_lists: [None; ORDER],
            base_addr,
            total_pages,
        };

        let mut current_offset = 0;
        let mut remaining_pages = total_pages;

        while remaining_pages > 0 {
            let mut order = ORDER - 1;
            while order > 0 && (remaining_pages < (1 << order) || (current_offset / page_size) % (1 << order) != 0) {
                order -= 1;
            }

            let block_ptr = (base_addr + current_offset * page_size) as *mut FreeBlock;
            allocator.push_free_block(order, block_ptr);

            current_offset += 1 << order;
            remaining_pages -= 1 << order;
        }

        allocator
    }

    fn push_free_block(&mut self, order: usize, ptr: *mut FreeBlock) {
        unsafe {
            (*ptr).next = self.free_lists[order];
            self.free_lists[order] = Some(ptr);
        }
    }

    fn pop_free_block(&mut self, order: usize) -> Option<*mut FreeBlock> {
        let ptr = self.free_lists[order]?;
        unsafe { self.free_lists[order] = (*ptr).next; }
        Some(ptr)
    }

    pub fn allocate(&mut self, pages: usize) -> Result<usize, AllocError> {
        if pages == 0 { return Err(AllocError::InvalidSize); }
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        if order >= ORDER { return Err(AllocError::OutOfMemory); }

        for i in order..ORDER {
            if let Some(block) = self.pop_free_block(i) {
                for j in (order..i).rev() {
                    let size = (1 << j) * 4096;
                    let buddy = (block as usize + size) as *mut FreeBlock;
                    self.push_free_block(j, buddy);
                }
                return Ok(block as usize);
            }
        }
        Err(AllocError::OutOfMemory)
    }

    pub unsafe fn deallocate(&mut self, ptr: usize, pages: usize) {
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        if order >= ORDER { return; }

        let mut current_ptr = ptr as *mut FreeBlock;
        let mut current_order = order;

        while current_order < ORDER - 1 {
            let block_size = (1 << current_order) * 4096;
            let buddy_offset = (current_ptr as usize - self.base_addr) ^ block_size;
            let buddy_ptr = (self.base_addr + buddy_offset) as *mut FreeBlock;

            if self.is_block_free(current_order, buddy_ptr) {
                self.remove_free_block(current_order, buddy_ptr);
                current_ptr = if (current_ptr as usize) < (buddy_ptr as usize) { current_ptr } else { buddy_ptr };
                current_order += 1;
            } else {
                break;
            }
        }
        self.push_free_block(current_order, current_ptr);
    }

    fn is_block_free(&self, order: usize, ptr: *mut FreeBlock) -> bool {
        let mut curr = self.free_lists[order];
        while let Some(node) = curr {
            if node == ptr { return true; }
            unsafe { curr = (*node).next; }
        }
        false
    }

    fn remove_free_block(&mut self, order: usize, ptr: *mut FreeBlock) {
        let mut curr = &mut self.free_lists[order];
        while let Some(node) = *curr {
            if node == ptr {
                unsafe { *curr = (*node).next; }
                return;
            }
            unsafe { curr = &mut (*node).next; }
        }
    }
}

// Slab allocator (simplified, no .expect in hot paths)
pub struct Slab {
    pub page_start: usize,
    pub slot_size: usize,
    pub free_list: Option<*mut SlabSlot>,
    pub used_slots: usize,
    pub total_slots: usize,
}

#[repr(C)]
pub struct SlabSlot { pub next: Option<*mut SlabSlot> }

impl Slab {
    pub unsafe fn new(page_start: usize, slot_size: usize, total_pages: usize) -> Self {
        let total_slots = (total_pages * 4096) / slot_size;
        let mut slab = Self { page_start, slot_size, free_list: None, used_slots: 0, total_slots };
        for i in 0..total_slots {
            let p = (page_start + i * slot_size) as *mut SlabSlot;
            slab.push_slot(p);
        }
        slab
    }
    pub fn push_slot(&mut self, slot: *mut SlabSlot) {
        unsafe { (*slot).next = self.free_list; self.free_list = Some(slot); }
    }
    pub fn pop_slot(&mut self) -> Option<usize> {
        let slot = self.free_list?;
        unsafe { self.free_list = (*slot).next; }
        self.used_slots += 1;
        Some(slot as usize)
    }
    pub unsafe fn free_slot(&mut self, ptr: usize) {
        let p = ptr as *mut SlabSlot;
        self.push_slot(p);
        self.used_slots -= 1;
    }
    pub fn is_full(&self) -> bool { self.used_slots == self.total_slots }
}

pub struct SlabCache {
    pub slot_size: usize,
    pub slabs: [Option<Slab>; 16],
}

impl SlabCache {
    pub fn new(slot_size: usize) -> Self {
        Self { slot_size, slabs: [const { None }; 16] }
    }
    pub fn allocate<B: BuddyProvider>(&mut self, buddy: &mut B) -> Result<usize, AllocError> {
        for s in &mut self.slabs {
            if let Some(slab) = s {
                if !slab.is_full() {
                    if let Some(p) = slab.pop_slot() { return Ok(p); }
                }
            }
        }
        let page = buddy.allocate_page()?;
        unsafe {
            let mut ns = Slab::new(page, self.slot_size, 1);
            if let Some(p) = ns.pop_slot() {
                if let Some(idx) = self.slabs.iter().position(|x| x.is_none()) {
                    self.slabs[idx] = Some(ns);
                    return Ok(p);
                }
            }
        }
        Err(AllocError::OutOfMemory)
    }
    pub unsafe fn deallocate(&mut self, ptr: usize) {
        for s in &mut self.slabs {
            if let Some(slab) = s {
                let end = slab.page_start + slab.total_slots * slab.slot_size;
                if ptr >= slab.page_start && ptr < end {
                    slab.free_slot(ptr);
                    return;
                }
            }
        }
    }
}

pub trait BuddyProvider {
    fn allocate_page(&mut self) -> Result<usize, AllocError>;
}

pub struct SlabAllocator {
    pub caches: [SlabCache; 8],
}

impl SlabAllocator {
    pub fn new() -> Self {
        let sizes = [16, 32, 64, 128, 256, 512, 1024, 2048];
        Self { caches: sizes.map(SlabCache::new) }
    }
    fn get_cache_idx(size: usize) -> Option<usize> {
        [16,32,64,128,256,512,1024,2048].iter().position(|&s| s >= size)
    }
    pub fn allocate<B: BuddyProvider>(&mut self, size: usize, buddy: &mut B) -> Result<usize, AllocError> {
        let idx = Self::get_cache_idx(size).ok_or(AllocError::InvalidSize)?;
        self.caches[idx].allocate(buddy)
    }
    pub unsafe fn deallocate(&mut self, ptr: usize, size: usize) {
        if let Some(idx) = Self::get_cache_idx(size) {
            self.caches[idx].deallocate(ptr);
        }
    }
}

unsafe impl<const ORDER: usize> Send for BuddyAllocator<ORDER> {}
unsafe impl<const ORDER: usize> Sync for BuddyAllocator<ORDER> {}
unsafe impl Send for Slab {}
unsafe impl Sync for Slab {}
unsafe impl Send for SlabCache {}
unsafe impl Sync for SlabCache {}
unsafe impl Send for SlabAllocator {}
unsafe impl Sync for SlabAllocator {}
