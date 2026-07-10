//! HuesOS Memory Allocation Crate.
//! Buddy + Slab allocator for no_std kernels.

#![no_std]

extern crate alloc;

use core::option::Option;
use core::result::Result;

#[derive(Debug, PartialEq, Eq)]
pub enum AllocError {
    OutOfMemory,
    InvalidSize,
}

pub struct BuddyAllocator<const ORDER: usize> {
    // Raw pointer to head of free list. null = empty.
    free_lists: [*mut FreeBlock; ORDER],
    base_addr: usize,
    page_size: usize,
    #[allow(dead_code)]
    total_pages: usize,
}

#[repr(C)]
struct FreeBlock {
    next: *mut FreeBlock,
}

impl<const ORDER: usize> BuddyAllocator<ORDER> {
    pub unsafe fn new(base_addr: usize, total_pages: usize, page_size: usize) -> Self {
        let mut allocator = Self {
            free_lists: [core::ptr::null_mut(); ORDER],
            base_addr,
            page_size,
            total_pages,
        };

        let mut current_offset = 0;
        let mut remaining_pages = total_pages;

        while remaining_pages > 0 {
            let mut order = ORDER - 1;
            while order > 0 && (remaining_pages < (1 << order) || current_offset % (1 << order) != 0) {
                order -= 1;
            }

            let block_ptr = (base_addr + current_offset * page_size) as *mut FreeBlock;
            debug_assert_eq!(block_ptr as usize % (1 << order), 0, "block not aligned to its order");
            allocator.push_free_block(order, block_ptr);

            current_offset += 1 << order;
            remaining_pages -= 1 << order;
        }

        allocator
    }

    #[inline]
    fn order_bytes(&self, order: usize) -> usize {
        (1usize << order) * self.page_size
    }

    fn push_free_block(&mut self, order: usize, ptr: *mut FreeBlock) {
        let end = self.base_addr + self.total_pages * self.page_size;
        debug_assert!((ptr as usize) >= self.base_addr, "ptr below base");
        debug_assert!((ptr as usize) < end, "ptr above end");
        debug_assert_eq!((ptr as usize) % self.page_size, 0, "ptr not page-aligned");
        debug_assert_eq!((ptr as usize) % (1 << order), 0, "ptr not aligned to order {}", order);
        unsafe {
            (*ptr).next = self.free_lists[order];
            self.free_lists[order] = ptr;
        }
    }

    fn pop_free_block(&mut self, order: usize) -> Option<*mut FreeBlock> {
        let ptr = self.free_lists[order];
        if ptr.is_null() {
            return None;
        }
        let end = self.base_addr + self.total_pages * self.page_size;
        debug_assert!((ptr as usize) >= self.base_addr, "popped ptr below base");
        debug_assert!((ptr as usize) < end, "popped ptr above end");
        debug_assert_eq!((ptr as usize) % (1 << order), 0, "popped ptr not aligned to order {}", order);
        unsafe { self.free_lists[order] = (*ptr).next; }
        Some(ptr)
    }

    pub fn allocate(&mut self, pages: usize) -> Result<usize, AllocError> {
        if pages == 0 { return Err(AllocError::InvalidSize); }
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        if order >= ORDER { return Err(AllocError::OutOfMemory); }

        for i in order..ORDER {
            if let Some(block) = self.pop_free_block(i) {
                // Standard buddy split: push LOWER buddy, continue with UPPER buddy.
                let mut current = block;
                for j in (order..i).rev() {
                    let size = self.order_bytes(j);
                    // Lower buddy is at `current`, upper buddy is at `current + size`.
                    let upper = (current as usize + size) as *mut FreeBlock;
                    debug_assert!((upper as usize) >= self.base_addr, "upper buddy below base at order {}", j);
                    debug_assert!((upper as usize) < self.base_addr + self.total_pages * self.page_size, "upper buddy above end at order {}", j);
                    debug_assert_eq!((upper as usize) % (1 << j), 0, "upper buddy not aligned to order {}", j);
                    // Push LOWER buddy (current) onto free list
                    self.push_free_block(j, current);
                    // Continue splitting the UPPER buddy
                    current = upper;
                }
                let result = current as usize;
                debug_assert_eq!(result % (1 << order), 0, "result not aligned to requested order");
                return Ok(result);
            }
        }
        Err(AllocError::OutOfMemory)
    }

    pub unsafe fn deallocate(&mut self, ptr: usize, pages: usize) {
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        if order >= ORDER { return; }

        debug_assert!(ptr >= self.base_addr, "dealloc ptr below base");
        debug_assert!(ptr < self.base_addr + self.total_pages * self.page_size, "dealloc ptr above end");
        debug_assert_eq!(ptr % (1 << order), 0, "dealloc ptr not aligned to order {}", order);

        let mut current_ptr = ptr as *mut FreeBlock;
        let mut current_order = order;

        while current_order < ORDER - 1 {
            let block_size = self.order_bytes(current_order);
            let buddy_offset = (current_ptr as usize - self.base_addr) ^ block_size;
            let buddy_ptr = (self.base_addr + buddy_offset) as *mut FreeBlock;

            debug_assert!((buddy_ptr as usize) >= self.base_addr, "dealloc buddy below base at order {}", current_order);
            debug_assert!((buddy_ptr as usize) < self.base_addr + self.total_pages * self.page_size, "dealloc buddy above end at order {}", current_order);
            debug_assert_eq!((buddy_ptr as usize) % (1 << current_order), 0, "dealloc buddy not aligned");

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
        while !curr.is_null() {
            if curr == ptr { return true; }
            unsafe { curr = (*curr).next; }
        }
        false
    }

    fn remove_free_block(&mut self, order: usize, ptr: *mut FreeBlock) {
        let mut curr = &mut self.free_lists[order] as *mut *mut FreeBlock;
        while unsafe { !(*curr).is_null() } {
            let node = unsafe { *curr };
            if node == ptr {
                unsafe { *curr = (*node).next; }
                return;
            }
            unsafe { curr = &mut (*node).next as *mut *mut FreeBlock; }
        }
        debug_assert!(false, "remove_free_block: buddy not found in free list at order {}", order);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buddy_allocate_deallocate() {
        let mut mem = alloc::vec![0u8; 8 * 4096];
        let base = mem.as_mut_ptr() as usize;
        let mut allocator = unsafe { BuddyAllocator::<4>::new(base, 8, 4096) };
        let a = allocator.allocate(1).unwrap();
        let b = allocator.allocate(2).unwrap();
        let c = allocator.allocate(4).unwrap();
        assert!(a != 0);
        assert!(b != 0);
        assert!(c != 0);
        unsafe {
            allocator.deallocate(a, 1);
            allocator.deallocate(b, 2);
            allocator.deallocate(c, 4);
        }
        let d = allocator.allocate(8).unwrap();
        assert_eq!(d, base);
    }

    #[test]
    fn test_buddy_non_power_of_two_pages() {
        let mut mem = alloc::vec![0u8; 5 * 4096];
        let base = mem.as_mut_ptr() as usize;
        let mut allocator = unsafe { BuddyAllocator::<4>::new(base, 5, 4096) };
        let a = allocator.allocate(4).unwrap();
        assert_eq!(a, base);
        let b = allocator.allocate(1).unwrap();
        assert_eq!(b, base + 4 * 4096);
        assert!(allocator.allocate(1).is_err());
    }
}
