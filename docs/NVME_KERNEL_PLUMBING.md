# NVMe Kernel Plumbing: BAR Mapping + Coherent DMA

Status: **designed; on-target implementation pending.** The shared descriptors
live in `crates/huesos-nvme/src/device.rs` (host-tested). The kernel-side work
below requires QEMU (`-device nvme`) / bare-metal verification.

A userspace NVMe DriverHost needs the kernel to grant two resources, described
by `DeviceResources`:

1. **Register BAR (MMIO)** — the controller's BAR0, mapped *uncacheable* into
   the DriverHost's address space so register accesses reach the device.
2. **DMA-coherent memory** — physically-addressable pages for the submission/
   completion queues, PRP-list pages, and data buffers, mapped into the
   DriverHost so it can both touch them and hand their physical addresses to the
   device.

## Device discovery (kernel)

- Enumerate PCI (the kernel today has no PCI bus driver; this is the first
  consumer). Find the NVMe controller (class 0x01, subclass 0x08, prog-if 0x02),
  read its BAR0 (memory BAR, base + size from the BAR register and the PCI
  config space), and enable bus-mastering + memory-space in the command register.
- Populate a `BarRegion { index: 0, base, size, is_memory: true, .. }`.

## BAR mapping into the DriverHost (kernel, paging)

- Map the BAR0 physical range into the DriverHost's page tables with
  `PRESENT | WRITABLE | USER_ACCESSIBLE | NO_CACHE` (and `NO_EXECUTE`). This is
  the same uncached MMIO mapping the kernel already does for the LAPIC, extended
  to a userspace mapping authorized by a device grant.
- The driver receives the BAR's virtual base; register offset `off` is at
  `virt_base + off` (`BarRegion::phys_of` gives the physical address for
  documentation/diagnostics).
- Authorization model: extend the existing deny-by-default MMIO capability (used
  by the ACPI broker) into a per-device grant issued by the device manager when
  it spawns the DriverHost. The driver cannot map arbitrary MMIO; only the
  granted BAR.

## Coherent DMA buffers (kernel)

- Allocate physically-contiguous pages (or program the IOMMU if present) for the
  driver's DMA window, and map them into the DriverHost as a VMO. The driver
  receives both the physical base (device-visible, programmed into ASQ/ACQ/PRP)
  and the virtual base (driver-accessible) — `DmaRegion { phys, virt, size }`.
- Without an IOMMU, the DMA window must be physically contiguous and is reserved
  from the PMM (like the HBI image reservation). With an IOMMU, the kernel can
  map arbitrary pages and return their IOVA as `phys`.
- The driver's bump allocator (`Controller::dma_alloc`) carves queues, PRP-list
  pages, and data buffers from this window; PRP entries use the *physical*
  addresses (`DmaRegion::phys_of`).

## Building the transport in the driver

Given `DeviceResources`, the driver constructs an `NvmeTransport`:

- `read32/write32/read64/write64(off)` access the BAR mapping at
  `bar_virt_base + off` (volatile, uncached).
- `dma_read/dma_write(addr, buf)` copy between the driver's buffers and the DMA
  window (or, since the DMA window is mapped, the driver reads/writes the
  virtual addresses directly and `addr` is the physical address used only for
  PRP/queue programming).

`MockNvme` implements the same trait in memory, so the controller and block
service are exercised end-to-end on the host; the on-target transport swaps in
the real BAR/DMA accesses.

## On-target verification checklist

- PCI enumeration finds the NVMe controller; BAR0 base/size read correctly.
- BAR0 mapped uncached into the DriverHost; register reads (CAP/VS) return sane
  values; CC.EN -> CSTS.RDY.
- DMA window allocated and mapped; ASQ/ACQ/PRP physical addresses are honored
  by the device (data integrity on a Read/Write round-trip).
- MSI-X delivery through the HuesOS Port (or polled completion as a first step).
- The deny-by-default MMIO grant rejects unauthorized BAR access from other
  processes.

## Incremental path

A pragmatic first on-target step is a *polled* single-queue driver (no MSI-X):
map BAR0 + DMA, run the existing `Controller` against a real-transport
`NvmeTransport`, and verify a Read/Write round-trip in QEMU (`-device nvme`).
MSI-X, multiple queues, and multiple namespaces follow.
