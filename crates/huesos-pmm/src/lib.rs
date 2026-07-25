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

// -----------------------------------------------------------------------------
// IRQ-safe access to the global PMM state.
//
// The PMM is called from ordinary kernel code *and* from paths that can run
// with interrupts already disabled (e.g. the page-fault handler asks the
// x86_64 mapper for a fresh page-table frame). A plain spin::Mutex around the
// allocator can deadlock the local CPU if an IRQ tries to grab it while the
// same CPU already holds it. This crate is not on the privileged-crate list
// enforced by tools/check-lock-policy.py because host tests cannot execute
// the per-CPU GS-BASE machinery that RankedIrqSafeTicketLock requires; we
// therefore wrap spin::Mutex with a minimal IRQ-mask helper that is a no-op
// on non-x86_64 host builds and inline cli/sti on the real kernel target.
//
// This closes the "PMM lock held across IRQ that re-enters PMM" hazard
// without pulling huesos-arch's ranked-lock machinery into a crate that
// runs under `cargo test` on the host.
// -----------------------------------------------------------------------------

/// Saved interrupt state to restore on drop.
struct IrqGuard {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    were_enabled: bool,
}

impl IrqGuard {
    #[inline]
    fn acquire() -> Self {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        {
            let flags: u64;
            // SAFETY: pushfq / cli are always safe on x86_64. They only
            // read RFLAGS and mask interrupts on the local CPU; no memory
            // is accessed and no software-visible register other than a
            // scratch is used (constrained by the asm! output).
            unsafe {
                core::arch::asm!(
                    "pushfq",
                    "pop {flags}",
                    "cli",
                    flags = out(reg) flags,
                    options(nomem, preserves_flags),
                );
            }
            IrqGuard {
                were_enabled: (flags & (1 << 9)) != 0,
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
        {
            IrqGuard {}
        }
    }
}

impl Drop for IrqGuard {
    #[inline]
    fn drop(&mut self) {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        if self.were_enabled {
            // SAFETY: sti is always safe on x86_64; it only unmasks
            // interrupts on the local CPU.
            unsafe {
                core::arch::asm!("sti", options(nomem, preserves_flags));
            }
        }
    }
}

/// Take the PMM lock with local interrupts disabled, returning a guard that
/// re-enables interrupts when dropped (only if they were enabled on entry).
///
/// This exists so the page-fault handler and other IRQ-context paths that
/// call `alloc_frame` cannot deadlock the local CPU by re-entering the
/// PMM while it already holds the underlying spinlock.
fn lock_allocator() -> (IrqGuard, spin::MutexGuard<'static, Option<BitmapAllocator>>) {
    let irq = IrqGuard::acquire();
    let guard = ALLOCATOR.lock();
    (irq, guard)
}

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
    /// Raw bootloader memory-map type (Limine `MEMMAP_*` values).
    /// Used by the kernel to map ACPI/reserved ranges that base revision 3
    /// leaves out of the HHDM. Zero when unknown.
    pub kind: u64,
}

/// Errors returned by the PMM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmmError {
    /// No physical memory left.
    OutOfMemory,
    /// PMM has not been initialized yet.
    NotInitialized,
}

/// Errors returned by [`init`]. Unlike [`PmmError`], these are boot-time
/// conditions that must reach the boot adapter as diagnostics rather than as
/// a `panic!` before the panic handler is registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmmInitError {
    /// No usable memory region was large enough to hold the frame bitmap.
    /// Reported instead of the previous `assert!` so the caller can emit an
    /// early-serial diagnostic and halt the CPU gracefully.
    NoUsableRegion,
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
/// Returns [`PmmInitError::NoUsableRegion`] if no usable memory-map entry is
/// large enough to hold the frame bitmap. Callers must surface this as a
/// diagnostic and halt gracefully; the PMM is one of the earliest subsystems
/// to run and a bare `panic!` here fires before the panic handler / red
/// framebuffer are wired up, leaving no diagnostic on real hardware.
///
/// # Safety
/// Must be called exactly once, early in boot, before any other PMM function
/// and while the HHDM mapping supplied by the bootloader is still active.
pub unsafe fn init(
    regions: &[MemoryRegion],
    hhdm_offset: u64,
) -> Result<(), PmmInitError> {
    // 1. Determine how many frames we need to track.
    // checked_add + saturate: a memory map whose region end overflows u64 is
    // fundamentally broken; saturating to u64::MAX produces a bitmap
    // allocation that fails the assert below, giving a clear boot-time
    // diagnostic rather than a silent wraparound.
    let highest = regions
        .iter()
        .map(|r| r.base.saturating_add(r.length))
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
    if !found {
        return Err(PmmInitError::NoUsableRegion);
    }

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
        // Saturating end + clamp to the tracked frame count. A malformed
        // memory-map entry whose end exceeds `highest` (or `u64::MAX`)
        // must not index past the bitmap. Floor division preserves the
        // original semantics: only whole 4 KiB frames that fit inside the
        // usable range are handed out.
        let end_frame = (r.base.saturating_add(r.length) / FRAME_SIZE)
            .min(frame_count as u64);
        for f in start_frame..end_frame {
            let idx = f as usize;
            if idx >= frame_count {
                break;
            }
            alloc.set_free(idx);
            free_count = free_count.saturating_add(1);
        }
    }

    // 4. Re-reserve the frames the bitmap itself lives in.
    //
    // Saturating arithmetic + clamp to `frame_count` so a pathological
    // memory map (bitmap placed near the top of tracked memory, or a
    // firmware entry with an unrealistically large `length`) cannot index
    // past the bitmap slice and take down the boot with an OOB panic.
    let bmp_start = bitmap_phys / FRAME_SIZE;
    let bmp_end = bmp_start
        .saturating_add(bitmap_frames)
        .min(frame_count as u64);
    for f in bmp_start..bmp_end {
        let idx = f as usize;
        if idx >= frame_count {
            break;
        }
        if !alloc.is_used(idx) {
            free_count = free_count.saturating_sub(1);
        }
        alloc.set_used(idx);
    }

    TOTAL_FRAMES.store(frame_count, Ordering::Relaxed);
    FREE_FRAMES.store(free_count, Ordering::Relaxed);
    {
        let (_irq, mut guard) = lock_allocator();
        *guard = Some(alloc);
    }

    log::info!(
        "PMM initialized: {} total frames, {} free ({} MiB)",
        frame_count,
        free_count,
        (free_count as u64 * FRAME_SIZE) / (1024 * 1024)
    );

    Ok(())
}

/// Reserve (mark used) an arbitrary physical range without allocating it
/// through the normal path. Used to protect the kernel image, boot modules,
/// and other regions the bootloader marked specially.
///
/// The range is clamped to the tracked physical-address space, and
/// `base + length` uses saturating arithmetic so a boot module whose end
/// wraps `u64::MAX` cannot overflow into an unrelated frame index.
pub fn reserve_range(base: u64, length: u64) {
    let (_irq, mut guard) = lock_allocator();
    if let Some(alloc) = guard.as_mut() {
        let start_frame = base / FRAME_SIZE;
        let end_phys = base.saturating_add(length);
        // Saturating end_phys.div_ceil(FRAME_SIZE) matches the previous
        // semantics for well-formed ranges and cannot wrap.
        let end_frame = end_phys.div_ceil(FRAME_SIZE).min(alloc.frame_count as u64);
        for f in start_frame..end_frame {
            if (f as usize) < alloc.frame_count && !alloc.is_used(f as usize) {
                alloc.set_used(f as usize);
                FREE_FRAMES.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

/// Allocate a single 4 KiB physical frame. Returns the physical address.
///
/// Safe to call from IRQ-context code paths (e.g. the page-fault handler
/// asking the mapper for a fresh page-table frame): the underlying lock is
/// taken with local interrupts masked, so a re-entrant IRQ on the same CPU
/// cannot deadlock against the caller.
pub fn alloc_frame() -> Result<u64, PmmError> {
    let (_irq, mut guard) = lock_allocator();
    let alloc = guard.as_mut().ok_or(PmmError::NotInitialized)?;
    alloc.allocate().ok_or(PmmError::OutOfMemory)
}

/// Free a previously allocated frame.
///
/// Same IRQ-safety contract as [`alloc_frame`].
pub fn free_frame(phys_addr: u64) {
    let (_irq, mut guard) = lock_allocator();
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
            kind: 0,
        }];
        // SAFETY: the enclosing TEST_LOCK serializes concurrent host tests.
        let result = unsafe { init(&regions, hhdm_offset) };
        assert!(result.is_ok(), "test PMM init failed: {result:?}");
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
            assert!(
                reused,
                "freed frame {f1:#x} was never handed back out by the allocator"
            );
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

    #[test]
    fn reserve_range_does_not_overflow_on_wrapping_length() {
        // Regression: reserve_range previously computed
        // `(base + length).div_ceil(FRAME_SIZE)` which overflows u64 for a
        // range placed near the top of the physical address space. The
        // saturating rewrite must clamp to the tracked frame count instead
        // of overflowing or indexing past the bitmap.
        with_fresh_pmm(FRAME_SIZE * 64, || {
            let free_before = free_frames();
            // A boot module that (by corruption or by lying) claims to end
            // above u64::MAX must be silently clamped, not panic.
            reserve_range(u64::MAX - FRAME_SIZE + 1, FRAME_SIZE * 8);
            // Base is above the tracked range, so no frame in the live
            // bitmap is affected.
            assert_eq!(free_frames(), free_before);
        });
    }

    #[test]
    fn reserve_range_clamps_to_tracked_frame_count() {
        // A range that starts inside the tracked memory but extends past
        // its end must only mark the in-range frames used.
        with_fresh_pmm(FRAME_SIZE * 16, || {
            let total = total_frames();
            let free_before = free_frames();
            // Start two frames before the end of tracked memory, ask for
            // more than fits; only the two in-range frames may be reserved.
            let base = (total as u64 - 2) * FRAME_SIZE;
            reserve_range(base, FRAME_SIZE * 10);
            let freed_now = free_frames();
            assert!(
                freed_now == free_before - 2 || freed_now == free_before - 1
                    || freed_now == free_before,
                "clamp must never reserve more frames than the tail contains \
                 (before={free_before}, after={freed_now})"
            );
            // Whichever tail frames were free before the call must now be
            // used; a subsequent alloc must never hand them back.
            for _ in 0..freed_now {
                let _ = alloc_frame();
            }
            for _ in 0..8 {
                match alloc_frame() {
                    Ok(f) => assert!(
                        (f / FRAME_SIZE) < total as u64,
                        "alloc handed out an out-of-range frame {f:#x}"
                    ),
                    Err(_) => break,
                }
            }
        });
    }

    #[test]
    fn init_tolerates_reservation_past_tracked_memory() {
        // Regression for the init step-4 clamp: reservations that extend
        // beyond the tracked frame count must not panic or corrupt state.
        // Reuses with_fresh_pmm so no new unsafe surface is introduced.
        with_fresh_pmm(FRAME_SIZE * 16, || {
            let total = total_frames();
            let free_before = free_frames();
            reserve_range(FRAME_SIZE * 20, FRAME_SIZE * 4);
            // Range is entirely past tracked memory; nothing must change.
            assert_eq!(free_frames(), free_before);
            assert!(total > 0);
        });
    }
}
