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
    InvalidPointer,
    DoubleFree,
    CorruptedFreeList,
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
    /// Construct a buddy allocator over caller-owned memory.
    ///
    /// # Safety
    /// The complete range must be writable, page-aligned, exclusively owned by
    /// this allocator, and remain valid until all allocations are released.
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
            while order > 0
                && (remaining_pages < (1 << order) || current_offset % (1 << order) != 0)
            {
                order -= 1;
            }

            let block_ptr = (base_addr + current_offset * page_size) as *mut FreeBlock;
            debug_assert_eq!(
                block_ptr as usize % (1 << order),
                0,
                "block not aligned to its order"
            );
            allocator
                .push_free_block_checked(order, block_ptr)
                .expect("constructor generated an invalid buddy block");

            current_offset += 1 << order;
            remaining_pages -= 1 << order;
        }

        allocator
    }

    #[inline]
    fn order_bytes(&self, order: usize) -> usize {
        (1usize << order) * self.page_size
    }

    fn pop_free_block(&mut self, order: usize) -> Result<Option<*mut FreeBlock>, AllocError> {
        let pointer = self.free_lists[order];
        if pointer.is_null() {
            return Ok(None);
        }
        if !self.valid_free_node(order, pointer) {
            return Err(AllocError::CorruptedFreeList);
        }
        // SAFETY: pointer is a validated free-list node.
        self.free_lists[order] = unsafe { (*pointer).next };
        Ok(Some(pointer))
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
            if let Some(block) = self.pop_free_block(i)? {
                // Standard buddy split: push LOWER buddy, continue with UPPER buddy.
                let mut current = block;
                for j in (order..i).rev() {
                    let size = self.order_bytes(j);
                    // Lower buddy is at `current`, upper buddy is at `current + size`.
                    let upper = (current as usize + size) as *mut FreeBlock;
                    debug_assert!(
                        (upper as usize) >= self.base_addr,
                        "upper buddy below base at order {}",
                        j
                    );
                    debug_assert!(
                        (upper as usize) < self.base_addr + self.total_pages * self.page_size,
                        "upper buddy above end at order {}",
                        j
                    );
                    debug_assert_eq!(
                        (upper as usize) % (1 << j),
                        0,
                        "upper buddy not aligned to order {}",
                        j
                    );
                    // Push LOWER buddy (current) onto free list
                    self.push_free_block_checked(j, current)?;
                    // Continue splitting the UPPER buddy
                    current = upper;
                }
                let result = current as usize;
                debug_assert_eq!(
                    result % (1 << order),
                    0,
                    "result not aligned to requested order"
                );
                return Ok(result);
            }
        }
        Err(AllocError::OutOfMemory)
    }

    /// Return a block previously produced by [`Self::allocate`].
    ///
    /// # Safety
    /// `ptr` must be a live allocation from this instance and `pages` must
    /// match the original request. Unlike the old implementation, malformed
    /// input is rejected in release builds before any free-list write.
    pub unsafe fn deallocate(&mut self, ptr: usize, pages: usize) -> Result<(), AllocError> {
        if pages == 0 {
            return Err(AllocError::InvalidSize);
        }
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        if order >= ORDER {
            return Err(AllocError::InvalidSize);
        }
        let heap_end = self
            .base_addr
            .checked_add(
                self.total_pages
                    .checked_mul(self.page_size)
                    .ok_or(AllocError::InvalidSize)?,
            )
            .ok_or(AllocError::InvalidSize)?;
        let block_bytes = self.order_bytes(order);
        let allocation_end = ptr
            .checked_add(block_bytes)
            .ok_or(AllocError::InvalidPointer)?;
        if ptr < self.base_addr
            || allocation_end > heap_end
            || !(ptr - self.base_addr).is_multiple_of(block_bytes)
        {
            return Err(AllocError::InvalidPointer);
        }
        if self.range_is_free(ptr, block_bytes)? {
            return Err(AllocError::DoubleFree);
        }

        let mut current_ptr = ptr as *mut FreeBlock;
        let mut current_order = order;
        while current_order < ORDER - 1 {
            let block_size = self.order_bytes(current_order);
            let buddy_offset = (current_ptr as usize - self.base_addr) ^ block_size;
            let buddy_ptr = (self.base_addr + buddy_offset) as *mut FreeBlock;
            if self.is_block_free(current_order, buddy_ptr)? {
                self.remove_free_block(current_order, buddy_ptr)?;
                current_ptr = if (current_ptr as usize) < buddy_ptr as usize {
                    current_ptr
                } else {
                    buddy_ptr
                };
                current_order += 1;
            } else {
                break;
            }
        }
        self.push_free_block_checked(current_order, current_ptr)?;
        Ok(())
    }

    fn valid_free_node(&self, order: usize, pointer: *mut FreeBlock) -> bool {
        if pointer.is_null() || order >= ORDER {
            return false;
        }
        let address = pointer as usize;
        let Some(heap_bytes) = self.total_pages.checked_mul(self.page_size) else {
            return false;
        };
        let Some(heap_end) = self.base_addr.checked_add(heap_bytes) else {
            return false;
        };
        address >= self.base_addr
            && address < heap_end
            && (address - self.base_addr).is_multiple_of(self.order_bytes(order))
            && address.is_multiple_of(core::mem::align_of::<FreeBlock>())
    }

    fn range_is_free(&self, ptr: usize, bytes: usize) -> Result<bool, AllocError> {
        let end = ptr.checked_add(bytes).ok_or(AllocError::InvalidPointer)?;
        for order in 0..ORDER {
            let mut current = self.free_lists[order];
            while !current.is_null() {
                if !self.valid_free_node(order, current) {
                    return Err(AllocError::CorruptedFreeList);
                }
                let block_start = current as usize;
                let block_end = block_start + self.order_bytes(order);
                if ptr >= block_start && end <= block_end {
                    return Ok(true);
                }
                // SAFETY: node range/alignment was validated above and free
                // memory stores a FreeBlock header by allocator invariant.
                current = unsafe { (*current).next };
            }
        }
        Ok(false)
    }

    fn is_block_free(&self, order: usize, ptr: *mut FreeBlock) -> Result<bool, AllocError> {
        let mut current = self.free_lists[order];
        while !current.is_null() {
            if !self.valid_free_node(order, current) {
                return Err(AllocError::CorruptedFreeList);
            }
            if current == ptr {
                return Ok(true);
            }
            // SAFETY: validated free-list node.
            current = unsafe { (*current).next };
        }
        Ok(false)
    }

    fn remove_free_block(&mut self, order: usize, ptr: *mut FreeBlock) -> Result<(), AllocError> {
        let mut link = &mut self.free_lists[order] as *mut *mut FreeBlock;
        loop {
            // SAFETY: link starts in the free-list head array and advances only
            // through validated node `next` fields.
            let node = unsafe { *link };
            if node.is_null() {
                return Err(AllocError::CorruptedFreeList);
            }
            if !self.valid_free_node(order, node) {
                return Err(AllocError::CorruptedFreeList);
            }
            if node == ptr {
                // SAFETY: node was validated and link is its owning list link.
                unsafe { *link = (*node).next };
                return Ok(());
            }
            // SAFETY: validated node contains a writable next field.
            link = unsafe { &mut (*node).next };
        }
    }

    fn push_free_block_checked(
        &mut self,
        order: usize,
        pointer: *mut FreeBlock,
    ) -> Result<(), AllocError> {
        if !self.valid_free_node(order, pointer) {
            return Err(AllocError::InvalidPointer);
        }
        // SAFETY: pointer is a validated block head in exclusively free memory.
        unsafe {
            (*pointer).next = self.free_lists[order];
            self.free_lists[order] = pointer;
        }
        Ok(())
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
pub struct SlabSlot {
    pub next: Option<*mut SlabSlot>,
}

impl Slab {
    /// Build a slab over freshly allocated pages.
    ///
    /// # Safety
    /// The page range must be writable, exclusively owned, page-aligned, and
    /// remain valid until the slab is returned to its buddy provider.
    pub unsafe fn new(page_start: usize, slot_size: usize, total_pages: usize) -> Self {
        let total_slots = (total_pages * 4096) / slot_size;
        let mut slab = Self {
            page_start,
            slot_size,
            free_list: None,
            used_slots: 0,
            total_slots,
        };
        for index in 0..total_slots {
            let pointer = (page_start + index * slot_size) as *mut SlabSlot;
            // SAFETY: constructor generates each in-range slot exactly once.
            unsafe { slab.push_slot(pointer) };
        }
        slab
    }

    fn end(&self) -> Option<usize> {
        self.page_start
            .checked_add(self.total_slots.checked_mul(self.slot_size)?)
    }

    fn valid_slot(&self, pointer: usize) -> bool {
        let Some(end) = self.end() else { return false };
        pointer >= self.page_start
            && pointer < end
            && (pointer - self.page_start).is_multiple_of(self.slot_size)
            && pointer.is_multiple_of(core::mem::align_of::<SlabSlot>())
    }

    fn free_list_contains(&self, pointer: usize) -> Result<bool, AllocError> {
        let mut current = self.free_list;
        while let Some(node) = current {
            if !self.valid_slot(node as usize) {
                return Err(AllocError::CorruptedFreeList);
            }
            if node as usize == pointer {
                return Ok(true);
            }
            // SAFETY: node was validated as an aligned in-slab slot.
            current = unsafe { (*node).next };
        }
        Ok(false)
    }

    /// Link one validated free slot.
    ///
    /// # Safety
    /// `slot` must be a unique, writable slot in this slab and not already
    /// present in the free list.
    unsafe fn push_slot(&mut self, slot: *mut SlabSlot) {
        // SAFETY: delegated to the caller contract.
        unsafe {
            (*slot).next = self.free_list;
            self.free_list = Some(slot);
        }
    }

    pub fn pop_slot(&mut self) -> Result<Option<usize>, AllocError> {
        let Some(slot) = self.free_list else {
            return Ok(None);
        };
        if !self.valid_slot(slot as usize) {
            return Err(AllocError::CorruptedFreeList);
        }
        // SAFETY: slot is an aligned in-slab free-list node.
        self.free_list = unsafe { (*slot).next };
        self.used_slots = self
            .used_slots
            .checked_add(1)
            .ok_or(AllocError::CorruptedFreeList)?;
        Ok(Some(slot as usize))
    }

    /// Return one live slot to this slab.
    ///
    /// # Safety
    /// The caller must own `ptr` as an allocated slot from this slab.
    pub unsafe fn free_slot(&mut self, ptr: usize) -> Result<(), AllocError> {
        if !self.valid_slot(ptr) {
            return Err(AllocError::InvalidPointer);
        }
        if self.free_list_contains(ptr)? {
            return Err(AllocError::DoubleFree);
        }
        if self.used_slots == 0 {
            return Err(AllocError::DoubleFree);
        }
        // SAFETY: validation above proves a unique in-range allocated slot.
        unsafe { self.push_slot(ptr as *mut SlabSlot) };
        self.used_slots -= 1;
        Ok(())
    }

    pub fn is_full(&self) -> bool {
        self.used_slots == self.total_slots
    }
}

pub struct SlabCache {
    pub slot_size: usize,
    pub slabs: [Option<Slab>; 16],
}

impl SlabCache {
    pub fn new(slot_size: usize) -> Self {
        Self {
            slot_size,
            slabs: [const { None }; 16],
        }
    }

    pub fn allocate<B: BuddyProvider>(&mut self, buddy: &mut B) -> Result<usize, AllocError> {
        for slab in self.slabs.iter_mut().flatten() {
            if !slab.is_full() {
                if let Some(pointer) = slab.pop_slot()? {
                    return Ok(pointer);
                }
            }
        }
        let index = self
            .slabs
            .iter()
            .position(Option::is_none)
            .ok_or(AllocError::OutOfMemory)?;
        let page = buddy.allocate_page()?;
        // SAFETY: BuddyProvider returned one exclusive writable page.
        let mut slab = unsafe { Slab::new(page, self.slot_size, 1) };
        let pointer = slab.pop_slot()?.ok_or(AllocError::CorruptedFreeList)?;
        self.slabs[index] = Some(slab);
        Ok(pointer)
    }

    /// Return a slot and give a completely empty slab page back to buddy.
    ///
    /// # Safety
    /// `ptr` must be a live slot allocated by this cache.
    pub unsafe fn deallocate<B: BuddyProvider>(
        &mut self,
        ptr: usize,
        buddy: &mut B,
    ) -> Result<(), AllocError> {
        let index = self
            .slabs
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|slab| slab.valid_slot(ptr)))
            .ok_or(AllocError::InvalidPointer)?;
        let slab = self.slabs[index]
            .as_mut()
            .ok_or(AllocError::InvalidPointer)?;
        // SAFETY: cache ownership lookup above found the unique slab.
        unsafe { slab.free_slot(ptr) }?;
        if slab.used_slots == 0 {
            let page = slab.page_start;
            self.slabs[index] = None;
            buddy.deallocate_page(page)?;
        }
        Ok(())
    }
}

pub trait BuddyProvider {
    fn allocate_page(&mut self) -> Result<usize, AllocError>;
    fn deallocate_page(&mut self, page: usize) -> Result<(), AllocError>;
}

pub struct SlabAllocator {
    pub caches: [SlabCache; 8],
}

impl Default for SlabAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl SlabAllocator {
    pub fn new() -> Self {
        let sizes = [16, 32, 64, 128, 256, 512, 1024, 2048];
        Self {
            caches: sizes.map(SlabCache::new),
        }
    }
    fn get_cache_idx(size: usize) -> Option<usize> {
        [16, 32, 64, 128, 256, 512, 1024, 2048]
            .iter()
            .position(|&s| s >= size)
    }
    pub fn allocate<B: BuddyProvider>(
        &mut self,
        size: usize,
        buddy: &mut B,
    ) -> Result<usize, AllocError> {
        let idx = Self::get_cache_idx(size).ok_or(AllocError::InvalidSize)?;
        self.caches[idx].allocate(buddy)
    }
    /// Return an allocation to its size-class cache.
    ///
    /// # Safety
    /// `ptr` must be live and `size` must select the same cache used during
    /// allocation. The pointer must not be freed more than once.
    pub unsafe fn deallocate<B: BuddyProvider>(
        &mut self,
        ptr: usize,
        size: usize,
        buddy: &mut B,
    ) -> Result<(), AllocError> {
        let index = Self::get_cache_idx(size).ok_or(AllocError::InvalidSize)?;
        // SAFETY: caller contract guarantees this allocation belongs to the
        // selected size class; the cache performs range/double-free checks.
        unsafe { self.caches[index].deallocate(ptr, buddy) }
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

    struct TestBuddy<'a> {
        allocator: &'a mut BuddyAllocator<4>,
    }

    impl BuddyProvider for TestBuddy<'_> {
        fn allocate_page(&mut self) -> Result<usize, AllocError> {
            self.allocator.allocate(1)
        }

        fn deallocate_page(&mut self, page: usize) -> Result<(), AllocError> {
            unsafe { self.allocator.deallocate(page, 1) }
        }
    }

    #[test]
    fn test_buddy_allocate_deallocate() {
        // Vec only guarantees byte alignment. The production heap is page
        // aligned, so over-allocate and align the host-test backing explicitly.
        let mut mem = alloc::vec![0u8; 9 * 4096];
        let base = (mem.as_mut_ptr() as usize + 4095) & !4095;
        let mut allocator = unsafe { BuddyAllocator::<4>::new(base, 8, 4096) };
        let a = allocator.allocate(1).unwrap();
        let b = allocator.allocate(2).unwrap();
        let c = allocator.allocate(4).unwrap();
        assert!(a != 0);
        assert!(b != 0);
        assert!(c != 0);
        unsafe {
            allocator.deallocate(a, 1).unwrap();
            allocator.deallocate(b, 2).unwrap();
            allocator.deallocate(c, 4).unwrap();
        }
        let d = allocator.allocate(8).unwrap();
        assert_eq!(d, base);
    }

    #[test]
    fn buddy_rejects_double_free_and_invalid_pointer() {
        let mut memory = alloc::vec![0u8; 9 * 4096];
        let base = (memory.as_mut_ptr() as usize + 4095) & !4095;
        let mut allocator = unsafe { BuddyAllocator::<4>::new(base, 8, 4096) };
        let allocation = allocator.allocate(1).unwrap();
        unsafe { allocator.deallocate(allocation, 1).unwrap() };
        assert_eq!(
            unsafe { allocator.deallocate(allocation, 1) },
            Err(AllocError::DoubleFree)
        );
        assert_eq!(
            unsafe { allocator.deallocate(base - 4096, 1) },
            Err(AllocError::InvalidPointer)
        );
    }

    #[test]
    fn slab_rejects_double_free_and_returns_empty_page() {
        let mut memory = alloc::vec![0u8; 3 * 4096];
        let base = (memory.as_mut_ptr() as usize + 4095) & !4095;
        let mut buddy_allocator = unsafe { BuddyAllocator::<4>::new(base, 2, 4096) };
        let mut provider = TestBuddy {
            allocator: &mut buddy_allocator,
        };
        let mut slabs = SlabAllocator::new();
        let pointer = slabs.allocate(32, &mut provider).unwrap();
        unsafe { slabs.deallocate(pointer, 32, &mut provider).unwrap() };
        assert_eq!(
            unsafe { slabs.deallocate(pointer, 32, &mut provider) },
            Err(AllocError::InvalidPointer)
        );
        // The empty slab page was returned, so both pages can coalesce and be
        // allocated as one order-1 block.
        assert!(provider.allocator.allocate(2).is_ok());
    }

    #[test]
    fn test_buddy_non_power_of_two_pages() {
        let mut mem = alloc::vec![0u8; 6 * 4096];
        let base = (mem.as_mut_ptr() as usize + 4095) & !4095;
        let mut allocator = unsafe { BuddyAllocator::<4>::new(base, 5, 4096) };
        let a = allocator.allocate(4).unwrap();
        assert_eq!(a, base);
        let b = allocator.allocate(1).unwrap();
        assert_eq!(b, base + 4 * 4096);
        assert!(allocator.allocate(1).is_err());
    }
}
