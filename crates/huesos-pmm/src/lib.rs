//! # HuesOS Physical Memory Manager
//!
//! A bitmap-based frame allocator that consumes a firmware/bootloader memory
//! map (Limine's, in practice) and hands out 4 KiB physical frames.
//!
//! This replaces the old "bump allocator over a hardcoded 4MiB..16MiB range"
//! placeholder: it actually understands how much RAM the machine has and
//! which parts of it are safe to use.

#![no_std]
#![warn(missing_docs)]

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

/// Frame size (4 KiB pages only, for MVP simplicity).
pub const FRAME_SIZE: u64 = 4096;

/// A single memory-map entry, architecture/bootloader agnostic.
#[derive(Clone, Copy, Debug)]
pub struct MemoryRegion {
    /// Physical base address.
    pub base: u64,
    /// Length in bytes.
    pub length: u64,
    /// Whether this region is usable general-purpose RAM.
    pub usable: bool,
}

/// Errors returned by the PMM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmmError {
    /// No physical memory left.
    OutOfMemory,
    /// PMM has not been initialized yet.
    NotInitialized,
}

struct BitmapAllocator {
    /// Higher-half direct map offset, used to turn physical bitmap addresses
    /// into addresses the CPU can actually dereference.
    hhdm_offset: u64,
    /// Physical address of the bitmap itself.
    bitmap_phys: u64,
    /// Number of bits (== number of frames == highest_addr / FRAME_SIZE).
    frame_count: usize,
    /// Next-fit search cursor, purely a performance heuristic.
    cursor: usize,
}

// Safety: all mutation happens through the Mutex below.
unsafe impl Send for BitmapAllocator {}

static ALLOCATOR: Mutex<Option<BitmapAllocator>> = Mutex::new(None);
static FREE_FRAMES: AtomicUsize = AtomicUsize::new(0);
static TOTAL_FRAMES: AtomicUsize = AtomicUsize::new(0);

impl BitmapAllocator {
    fn bitmap(&self) -> &'static mut [u8] {
        let len = self.frame_count.div_ceil(8);
        let virt = self.hhdm_offset + self.bitmap_phys;
        unsafe { core::slice::from_raw_parts_mut(virt as *mut u8, len) }
    }

    #[inline]
    fn set_used(&mut self, frame_idx: usize) {
        let bitmap = self.bitmap();
        bitmap[frame_idx / 8] |= 1 << (frame_idx % 8);
    }

    #[inline]
    fn set_free(&mut self, frame_idx: usize) {
        let bitmap = self.bitmap();
        bitmap[frame_idx / 8] &= !(1 << (frame_idx % 8));
    }

    #[inline]
    fn is_used(&self, frame_idx: usize) -> bool {
        let bitmap_len = self.frame_count.div_ceil(8);
        let virt = self.hhdm_offset + self.bitmap_phys;
        let bitmap = unsafe { core::slice::from_raw_parts(virt as *const u8, bitmap_len) };
        bitmap[frame_idx / 8] & (1 << (frame_idx % 8)) != 0
    }

    fn allocate(&mut self) -> Option<u64> {
        let start = self.cursor;
        for offset in 0..self.frame_count {
            let idx = (start + offset) % self.frame_count;
            if !self.is_used(idx) {
                self.set_used(idx);
                self.cursor = (idx + 1) % self.frame_count;
                FREE_FRAMES.fetch_sub(1, Ordering::Relaxed);
                return Some(idx as u64 * FRAME_SIZE);
            }
        }
        None
    }

    fn deallocate(&mut self, phys_addr: u64) {
        let idx = (phys_addr / FRAME_SIZE) as usize;
        if idx < self.frame_count && self.is_used(idx) {
            self.set_free(idx);
            FREE_FRAMES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Initialize the PMM from a bootloader-supplied memory map.
///
/// `hhdm_offset` must be the higher-half direct map offset (physical address
/// `p` is accessible at virtual address `hhdm_offset + p`) and must already
/// cover all usable RAM (true for Limine's default HHDM before we build our
/// own page tables).
///
/// # Safety
/// Must be called exactly once, early in boot, before any other PMM function
/// and while the HHDM mapping supplied by the bootloader is still active.
pub unsafe fn init(regions: &[MemoryRegion], hhdm_offset: u64) {
    // 1. Determine how many frames we need to track.
    let highest = regions
        .iter()
        .map(|r| r.base + r.length)
        .max()
        .unwrap_or(0);
    let frame_count = (highest.div_ceil(FRAME_SIZE)) as usize;
    let bitmap_bytes = frame_count.div_ceil(8);
    let bitmap_frames = (bitmap_bytes as u64).div_ceil(FRAME_SIZE);

    // 2. Find a usable region large enough to hold the bitmap.
    let mut bitmap_phys = 0u64;
    let mut found = false;
    for r in regions {
        if r.usable && r.length >= bitmap_frames * FRAME_SIZE {
            bitmap_phys = r.base;
            found = true;
            break;
        }
    }
    assert!(found, "PMM: no usable region large enough for bitmap");

    // 3. Zero the bitmap via the HHDM, then mark it fully "used"; we'll clear
    //    bits for usable regions next.
    let bitmap_virt = (hhdm_offset + bitmap_phys) as *mut u8;
    core::ptr::write_bytes(bitmap_virt, 0xFF, bitmap_bytes);

    let mut alloc = BitmapAllocator {
        hhdm_offset,
        bitmap_phys,
        frame_count,
        cursor: 0,
    };

    let mut free_count = 0usize;
    for r in regions {
        if !r.usable {
            continue;
        }
        let start_frame = r.base / FRAME_SIZE;
        let end_frame = (r.base + r.length) / FRAME_SIZE;
        for f in start_frame..end_frame {
            alloc.set_free(f as usize);
            free_count += 1;
        }
    }

    // 4. Re-reserve the frames the bitmap itself lives in.
    let bmp_start = bitmap_phys / FRAME_SIZE;
    for f in bmp_start..(bmp_start + bitmap_frames) {
        if !alloc.is_used(f as usize) {
            free_count -= 1;
        }
        alloc.set_used(f as usize);
    }

    TOTAL_FRAMES.store(frame_count, Ordering::Relaxed);
    FREE_FRAMES.store(free_count, Ordering::Relaxed);
    *ALLOCATOR.lock() = Some(alloc);

    log::info!(
        "PMM initialized: {} total frames, {} free ({} MiB)",
        frame_count,
        free_count,
        (free_count as u64 * FRAME_SIZE) / (1024 * 1024)
    );
}

/// Reserve (mark used) an arbitrary physical range without allocating it
/// through the normal path. Used to protect the kernel image, boot modules,
/// and other regions the bootloader marked specially.
pub fn reserve_range(base: u64, length: u64) {
    let mut guard = ALLOCATOR.lock();
    if let Some(alloc) = guard.as_mut() {
        let start_frame = base / FRAME_SIZE;
        let end_frame = (base + length).div_ceil(FRAME_SIZE);
        for f in start_frame..end_frame {
            if (f as usize) < alloc.frame_count && !alloc.is_used(f as usize) {
                alloc.set_used(f as usize);
                FREE_FRAMES.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

/// Allocate a single 4 KiB physical frame. Returns the physical address.
pub fn alloc_frame() -> Result<u64, PmmError> {
    let mut guard = ALLOCATOR.lock();
    let alloc = guard.as_mut().ok_or(PmmError::NotInitialized)?;
    alloc.allocate().ok_or(PmmError::OutOfMemory)
}

/// Free a previously allocated frame.
pub fn free_frame(phys_addr: u64) {
    let mut guard = ALLOCATOR.lock();
    if let Some(alloc) = guard.as_mut() {
        alloc.deallocate(phys_addr);
    }
}

/// Total number of 4 KiB frames tracked by the PMM.
pub fn total_frames() -> usize {
    TOTAL_FRAMES.load(Ordering::Relaxed)
}

/// Number of frames currently free.
pub fn free_frames() -> usize {
    FREE_FRAMES.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    // The PMM keeps its state in process-wide globals (`ALLOCATOR`, etc.),
    // matching how a real single-address-space kernel works. To test it
    // safely on the host we serialize all tests with a lock and back the
    // "physical memory" with a real heap buffer, using it as if address 0
    // were `buffer.as_ptr()` (hhdm_offset = buffer's address).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_fresh_pmm<R>(total_bytes: u64, f: impl FnOnce() -> R) -> R {
        let _guard = TEST_LOCK.lock();
        let mut backing = vec![0u8; total_bytes as usize];
        let hhdm_offset = backing.as_mut_ptr() as u64;
        let regions = [MemoryRegion {
            base: 0,
            length: total_bytes,
            usable: true,
        }];
        unsafe {
            init(&regions, hhdm_offset);
        }
        f()
    }

    #[test]
    fn allocates_and_frees_frames() {
        with_fresh_pmm(1024 * 1024, || {
            let total_before = total_frames();
            let free_before = free_frames();
            assert!(total_before > 0);
            assert!(free_before > 0);

            let f1 = alloc_frame().expect("first alloc should succeed");
            let f2 = alloc_frame().expect("second alloc should succeed");
            assert_ne!(f1, f2, "two allocations must not return the same frame");
            assert_eq!(free_frames(), free_before - 2);

            free_frame(f1);
            assert_eq!(free_frames(), free_before - 1);

            // This is a next-fit allocator (search continues from where the
            // last allocation left off), so a freed frame behind the cursor
            // isn't necessarily the very next one handed out — but it must
            // eventually be reachable once the cursor wraps around, and the
            // free count must reflect the free() immediately.
            let total = total_frames();
            let mut reused = false;
            let mut allocated = std::vec::Vec::new();
            for _ in 0..total {
                match alloc_frame() {
                    Ok(f) => {
                        if f == f1 {
                            reused = true;
                            break;
                        }
                        allocated.push(f);
                    }
                    Err(_) => break,
                }
            }
            assert!(reused, "freed frame {f1:#x} was never handed back out by the allocator");
            let _ = f2;
        });
    }

    #[test]
    fn exhausts_and_reports_out_of_memory() {
        with_fresh_pmm(FRAME_SIZE * 4, || {
            let mut allocated = std::vec::Vec::new();
            loop {
                match alloc_frame() {
                    Ok(f) => allocated.push(f),
                    Err(PmmError::OutOfMemory) => break,
                    Err(e) => panic!("unexpected error: {:?}", e),
                }
            }
            assert!(!allocated.is_empty());
            assert_eq!(free_frames(), 0);
        });
    }

    #[test]
    fn reserve_range_marks_frames_used() {
        // Use a large enough pool that the bitmap itself only occupies the
        // very first frame, leaving the range we reserve untouched by setup.
        with_fresh_pmm(FRAME_SIZE * 64, || {
            let free_before = free_frames();
            // Reserve frames well past the bitmap's own storage.
            reserve_range(FRAME_SIZE * 10, FRAME_SIZE * 2);
            assert_eq!(free_frames(), free_before - 2);
        });
    }
}
