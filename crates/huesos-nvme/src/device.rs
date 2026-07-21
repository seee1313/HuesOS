//! Shared device-resource descriptors for the kernel <-> DriverHost boundary.
//!
//! A userspace NVMe driver needs two things from the kernel: the controller's
//! register BAR (MMIO, mapped uncacheable into the process) and DMA-coherent
//! memory for the queues and data buffers. These descriptors name those
//! resources; the kernel populates them when it sets up a DriverHost, and the
//! driver uses them to build an [`NvmeTransport`](crate::transport::NvmeTransport).
//!
//! The descriptors themselves are pure data (host-tested). The kernel-side
//! population -- discovering the device, mapping the BAR, and allocating
//! DMA-coherent pages as VMOs -- is on-target; see
//! `docs/NVME_KERNEL_PLUMBING.md`.

/// A PCI Base Address Region (BAR) granted to a driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarRegion {
    /// BAR index (0-5).
    pub index: u8,
    /// Physical base address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Memory (true) vs I/O-port (false) BAR.
    pub is_memory: bool,
    /// Prefetchable.
    pub prefetchable: bool,
}

impl BarRegion {
    /// True when `off` (a register offset) lies within this BAR.
    pub fn contains(&self, off: u64) -> bool {
        off < self.size
    }
    /// The physical address of a register at `off` within this BAR.
    pub fn phys_of(&self, off: u64) -> u64 {
        self.base + off
    }
}

/// A DMA-coherent memory region granted to a driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaRegion {
    /// Device-visible physical address.
    pub phys: u64,
    /// Address in the driver's virtual address space (mapped via a VMO).
    pub virt: u64,
    /// Size in bytes.
    pub size: u64,
}

impl DmaRegion {
    /// True when a `size`-byte allocation at offset `off` fits.
    pub fn fits(&self, off: u64, size: u64) -> bool {
        off.checked_add(size).is_some_and(|end| end <= self.size)
    }
    /// Translate a DMA-window offset to the device-visible physical address.
    pub fn phys_of(&self, off: u64) -> u64 {
        self.phys + off
    }
    /// Translate a DMA-window offset to the driver's virtual address.
    pub fn virt_of(&self, off: u64) -> u64 {
        self.virt + off
    }
}

/// Resources granted to a driver for one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceResources {
    /// The NVMe register BAR (BAR0).
    pub reg_bar: BarRegion,
    /// DMA window for queues and data buffers.
    pub dma: DmaRegion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_contains_and_phys() {
        let bar = BarRegion { index: 0, base: 0xFE00_0000, size: 0x4000, is_memory: true, prefetchable: false };
        assert!(bar.contains(0));
        assert!(bar.contains(0x3FFF));
        assert!(!bar.contains(0x4000));
        assert_eq!(bar.phys_of(0x14), 0xFE00_0014);
    }

    #[test]
    fn dma_fits_and_translate() {
        let dma = DmaRegion { phys: 0x100_0000, virt: 0x7000_0000_0000, size: 0x10_0000 };
        assert!(dma.fits(0, 0x10_0000));
        assert!(!dma.fits(1, 0x10_0000)); // would exceed
        assert!(!dma.fits(u64::MAX, 1)); // overflow-safe
        assert_eq!(dma.phys_of(0x1000), 0x100_1000);
        assert_eq!(dma.virt_of(0x1000), 0x7000_0000_1000);
    }

    #[test]
    fn device_resources_compose() {
        let res = DeviceResources {
            reg_bar: BarRegion { index: 0, base: 0xFE00_0000, size: 0x4000, is_memory: true, prefetchable: false },
            dma: DmaRegion { phys: 0x100_0000, virt: 0x7000_0000_0000, size: 0x10_0000 },
        };
        // The driver maps register offset 0x14 (CC) to BAR phys, and DMA offset
        // 0 to the DMA window phys/virt.
        assert_eq!(res.reg_bar.phys_of(0x14), 0xFE00_0014);
        assert_eq!(res.dma.phys_of(0), 0x100_0000);
    }
}
