//! Bounds-checked volatile MMIO and DMA window accessors for `driver-host-xhci`.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};
use huesos_usb::xhci::{EnqueuedTrb, Trb};

/// Mapped virtual memory window (BAR0 MMIO or 4 MiB DMA pool).
#[derive(Clone, Copy)]
pub struct MappedWin {
    pub base: usize,
    pub len: usize,
}

impl MappedWin {
    pub const fn new(base: usize, len: usize) -> Self {
        Self { base, len }
    }

    pub fn read32(&self, off: usize) -> u32 {
        if off.saturating_add(4) <= self.len && off.is_multiple_of(4) {
            // SAFETY: `off + 4 <= self.len` and 4-byte aligned inside mapped VMAR window.
            unsafe { read_volatile((self.base + off) as *const u32) }
        } else {
            0
        }
    }

    pub fn write32(&self, off: usize, v: u32) {
        if off.saturating_add(4) <= self.len && off.is_multiple_of(4) {
            // SAFETY: `off + 4 <= self.len` and 4-byte aligned inside mapped VMAR window.
            unsafe { write_volatile((self.base + off) as *mut u32, v) }
        }
    }

    /// Write a 64-bit xHCI register (`DCBAAP`, `CRCR`, `ERSTBA`, `ERDP`) as two
    /// ordered 32-bit writes (`lo` then `hi`) so both `AC64=0` and `AC64=1`
    /// controllers accept it cleanly.
    pub fn write64_split(&self, off: usize, v: u64) {
        self.write32(off, v as u32);
        self.write32(off.saturating_add(4), (v >> 32) as u32);
    }

    /// Write a 64-bit value into normal DMA RAM (`DCBAA` / Scratchpad Array).
    pub fn write64_dma(&self, off: usize, v: u64) {
        self.write32(off, v as u32);
        self.write32(off.saturating_add(4), (v >> 32) as u32);
    }

    pub fn zero_range(&self, off: usize, len: usize) {
        if len > 0 && off.saturating_add(len) <= self.len {
            // SAFETY: `[off .. off + len)` is within the mapped DMA VMAR window.
            unsafe {
                core::ptr::write_bytes((self.base + off) as *mut u8, 0, len);
            }
            fence(Ordering::Release);
        }
    }

    pub fn copy_in(&self, off: usize, src: &[u8]) {
        if !src.is_empty() && off.saturating_add(src.len()) <= self.len {
            // SAFETY: `[off .. off + src.len())` is within the mapped DMA VMAR window,
            // and `src` is a disjoint stack/static slice.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    (self.base + off) as *mut u8,
                    src.len(),
                );
            }
            fence(Ordering::Release);
        }
    }

    pub fn copy_out(&self, off: usize, dst: &mut [u8]) {
        if !dst.is_empty() && off.saturating_add(dst.len()) <= self.len {
            fence(Ordering::Acquire);
            // SAFETY: `[off .. off + dst.len())` is within the mapped DMA VMAR window,
            // and `dst` is a disjoint stack/static slice.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.base + off) as *const u8,
                    dst.as_mut_ptr(),
                    dst.len(),
                );
            }
        }
    }

    /// Read a single 16-byte `Trb` from DMA memory using volatile 32-bit loads,
    /// reading `d3` (carrying the Cycle bit) first followed by an `Acquire` fence.
    pub fn read_trb(&self, ring_off: usize, index: usize) -> Trb {
        let off = ring_off.saturating_add(index.saturating_mul(16));
        let d3 = self.read32(off.saturating_add(12));
        fence(Ordering::Acquire);
        let d0 = self.read32(off);
        let d1 = self.read32(off.saturating_add(4));
        let d2 = self.read32(off.saturating_add(8));
        Trb { d0, d1, d2, d3 }
    }

    /// Commit a 16-byte `Trb` to a producer ring in DMA memory, writing `d0..d2`
    /// first, issuing a `Release` fence, and publishing `d3` (Producer Cycle bit)
    /// last so xHCI never observes a torn TRB.
    pub fn write_trb(&self, ring_off: usize, index: usize, trb: Trb) {
        let off = ring_off.saturating_add(index.saturating_mul(16));
        self.write32(off, trb.d0);
        self.write32(off.saturating_add(4), trb.d1);
        self.write32(off.saturating_add(8), trb.d2);
        fence(Ordering::Release);
        self.write32(off.saturating_add(12), trb.d3);
        fence(Ordering::SeqCst);
    }

    /// Commit an [`EnqueuedTrb`] step (including an optional wrap `Link` TRB) into
    /// DMA memory in hardware-safe order (`payload` at slot 0 first on wrap, then
    /// the `Link` TRB at `cap - 1` so xHCI only follows the wrap after slot 0 is ready).
    pub fn commit_enqueued(&self, ring_off: usize, step: EnqueuedTrb) -> u64 {
        self.write_trb(ring_off, step.slot_index, step.trb);
        if let Some((link_idx, link_trb)) = step.wrap_link {
            self.write_trb(ring_off, link_idx, link_trb);
        }
        step.trb_iova
    }
}
