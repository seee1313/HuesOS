//! PCI MMIO transport for real NVMe hardware.
//!
//! [`PciMmioTransport`] implements [`NvmeTransport`] by accessing the NVMe
//! controller's BAR0 (MMIO, uncacheable) and DMA-coherent memory. This is
//! the on-target transport for ring-3 DriverHost processes.
//!
//! ## Kernel plumbing requirements
//!
//! The kernel must grant two capabilities to the DriverHost:
//!
//! 1. **BAR mapping**: map the NVMe controller's BAR0 into the DriverHost's
//!    address space as uncacheable MMIO. This extends the existing deny-by-default
//!    MMIO capability (used by the ACPI broker) into a general device-MMIO grant
//!    authorized by the device manager.
//!
//! 2. **Coherent DMA buffers**: provide physically-contiguous (or IOMMU-mapped)
//!    pages to the DriverHost as VMOs for the queues and data buffers. The driver
//!    programs their physical addresses into ASQ/ACQ/PRP entries. With no IOMMU,
//!    buffers must be physically contiguous; the identity between the DriverHost's
//!    virtual mapping and the device-visible physical address is established by
//!    the kernel.
//!
//! ## Memory ordering
//!
//! NVMe requires specific memory ordering for register accesses and DMA:
//!
//! - **MMIO writes** (doorbells, CC.EN) must be visible to the device before
//!   subsequent operations. Use volatile writes with appropriate barriers.
//! - **DMA writes** (SQEs, data buffers) must be visible to the device before
//!   the doorbell write. Use flush/invalidate as needed.
//! - **DMA reads** (CQEs) must see device writes. Use invalidate before reading.
//!
//! This transport uses `core::ptr::read_volatile` / `write_volatile` for MMIO
//! and relies on the kernel's DMA API for cache coherency.

use crate::device::DeviceResources;
use crate::transport::NvmeTransport;

/// PCI MMIO transport for real NVMe hardware.
///
/// Accesses the controller's BAR0 (MMIO) and DMA-coherent memory. The kernel
/// provides [`DeviceResources`] (BAR + DMA window) during DriverHost setup.
pub struct PciMmioTransport {
    /// BAR0 virtual address (mapped uncacheable by kernel).
    bar_virt: u64,
    /// BAR0 physical address (for diagnostics).
    bar_phys: u64,
    /// BAR0 size in bytes.
    bar_size: u64,
    /// DMA window virtual address (mapped by kernel).
    dma_virt: u64,
    /// DMA window physical address (device-visible).
    dma_phys: u64,
    /// DMA window size in bytes.
    dma_size: u64,
}

impl PciMmioTransport {
    /// Create a PCI MMIO transport from kernel-provided device resources.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `resources.reg_bar` is a valid NVMe controller BAR0 mapped uncacheable.
    /// - `resources.dma` is a valid DMA-coherent memory region.
    /// - The kernel has established the identity between virtual and physical
    ///   addresses for the DMA region.
    pub unsafe fn new(resources: DeviceResources) -> Self {
        Self {
            bar_virt: resources.reg_bar.base,
            bar_phys: resources.reg_bar.base,
            bar_size: resources.reg_bar.size,
            dma_virt: resources.dma.virt,
            dma_phys: resources.dma.phys,
            dma_size: resources.dma.size,
        }
    }

    /// BAR0 physical address (for diagnostics).
    pub fn bar_phys(&self) -> u64 {
        self.bar_phys
    }

    /// DMA window physical address (for diagnostics).
    pub fn dma_phys(&self) -> u64 {
        self.dma_phys
    }

    /// DMA window size in bytes.
    pub fn dma_size(&self) -> u64 {
        self.dma_size
    }

    /// Validate that a register offset is within BAR0 bounds.
    fn validate_reg_offset(&self, off: u32) -> bool {
        (off as u64) < self.bar_size
    }

    /// Validate that a DMA offset + size is within the DMA window.
    fn validate_dma_range(&self, off: u64, size: u64) -> bool {
        off.checked_add(size)
            .is_some_and(|end| end <= self.dma_size)
    }
}

impl NvmeTransport for PciMmioTransport {
    fn read64(&mut self, off: u32) -> u64 {
        debug_assert!(self.validate_reg_offset(off));
        let addr = self.bar_virt + off as u64;
        // Safety: addr is a valid MMIO address within BAR0, mapped uncacheable.
        // Volatile read ensures the access is not optimized away and observes
        // device-visible ordering.
        unsafe { core::ptr::read_volatile(addr as *const u64) }
    }

    fn write64(&mut self, off: u32, val: u64) {
        debug_assert!(self.validate_reg_offset(off));
        let addr = self.bar_virt + off as u64;
        // Safety: addr is a valid MMIO address within BAR0, mapped uncacheable.
        // Volatile write ensures the access is not optimized away and is visible
        // to the device before subsequent operations.
        unsafe { core::ptr::write_volatile(addr as *mut u64, val) }
    }

    fn read32(&mut self, off: u32) -> u32 {
        debug_assert!(self.validate_reg_offset(off));
        let addr = self.bar_virt + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    fn write32(&mut self, off: u32, val: u32) {
        debug_assert!(self.validate_reg_offset(off));
        let addr = self.bar_virt + off as u64;
        unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
    }

    fn dma_read(&mut self, addr: u64, buf: &mut [u8]) {
        // addr is a DMA-window offset, not an absolute physical address.
        let off = addr - self.dma_phys;
        debug_assert!(self.validate_dma_range(off, buf.len() as u64));
        let virt = self.dma_virt + off;
        // Safety: virt is a valid DMA address within the DMA window, mapped
        // by the kernel. The kernel ensures cache coherency (invalidate before
        // device read, flush after device write).
        unsafe {
            core::ptr::copy_nonoverlapping(virt as *const u8, buf.as_mut_ptr(), buf.len());
        }
    }

    fn dma_write(&mut self, addr: u64, buf: &[u8]) {
        let off = addr - self.dma_phys;
        debug_assert!(self.validate_dma_range(off, buf.len() as u64));
        let virt = self.dma_virt + off;
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), virt as *mut u8, buf.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{BarRegion, DmaRegion};

    #[test]
    fn pci_transport_validates_bounds() {
        // This test validates the bounds-checking logic without real MMIO.
        // Real MMIO testing requires QEMU -device nvme and on-target verification.
        let resources = DeviceResources {
            reg_bar: BarRegion {
                index: 0,
                base: 0xFE00_0000,
                size: 0x4000,
                is_memory: true,
                prefetchable: false,
            },
            dma: DmaRegion {
                phys: 0x100_0000,
                virt: 0x7000_0000_0000,
                size: 0x10_0000,
            },
        };
        let transport = unsafe { PciMmioTransport::new(resources) };
        assert!(transport.validate_reg_offset(0));
        assert!(transport.validate_reg_offset(0x3FFF));
        assert!(!transport.validate_reg_offset(0x4000));
        assert!(transport.validate_dma_range(0, 0x10_0000));
        assert!(!transport.validate_dma_range(1, 0x10_0000));
        assert!(!transport.validate_dma_range(u64::MAX, 1));
    }
}
