#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
use core::{cmp::max, option::Option, result::Result, iter::Iterator};

#[cfg(test)]
use std::{cmp::max, option::Option, result::Result, iter::Iterator};

#[derive(Debug, PartialEq, Eq)]
pub enum AllocError {
    OutOfMemory,
    InvalidSize,
}

/// A simple Buddy Allocator implementation.
pub struct BuddyAllocator<const ORDER: usize> {
    free_lists: [Option<*mut FreeBlock>; ORDER],
    base_addr: usize,
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
        unsafe {
            self.free_lists[order] = (*ptr).next;
        }
        Some(ptr)
    }

    pub fn allocate(&mut self, pages: usize) -> Result<usize, AllocError> {
        if pages == 0 {
            return Err(AllocError::InvalidSize);
        }

        let order = pages.next_power_of_two().trailing_zeros() as usize;
        if order >= ORDER {
            return Err(AllocError::OutOfMemory);
        }

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
            let page_size = 4096;
            let block_size = (1 << current_order) * page_size;
            let relative_offset = current_ptr as usize - self.base_addr;
            let buddy_offset = relative_offset ^ block_size;
            let buddy_ptr = (self.base_addr + buddy_offset) as *mut FreeBlock;

            if self.is_block_free(current_order, buddy_ptr) {
                self.remove_free_block(current_order, buddy_ptr);
                current_ptr = if (current_ptr as usize) < (buddy_ptr as usize) {
                    current_ptr
                } else {
                    buddy_ptr
                };
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
            if node == ptr {
                return true;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_alloc_dealloc() {
        let mem = Box::leak(vec![0u8; 1024 * 1024].into_boxed_slice());
        let base = mem.as_ptr() as usize;
        
        let mut alloc = unsafe { BuddyAllocator::<10>::new(base, 256, 4096) };
        
        let p1 = alloc.allocate(1).expect("Alloc 1 page");
        let p2 = alloc.allocate(1).expect("Alloc 2 page");
        
        assert_ne!(p1, p2);
        
        unsafe {
            alloc.deallocate(p1, 1);
            alloc.deallocate(p2, 1);
        }
        
        let p3 = alloc.allocate(2).expect("Alloc 2 pages merged");
        assert_eq!(p3, p1);
    }

    #[test]
    fn test_oom() {
        let mem = Box::leak(vec![0u8; 4096 * 4].into_boxed_slice());
        let base = mem.as_ptr() as usize;
        let mut alloc = unsafe { BuddyAllocator::<10>::new(base, 4, 4096) };
        
        let _p1 = alloc.allocate(4).unwrap();
        assert_eq!(alloc.allocate(1), Err(AllocError::OutOfMemory));
    }
}
