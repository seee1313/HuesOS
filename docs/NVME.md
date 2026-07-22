# NVMe Driver (ring-3 DriverHost)

Status: **protocol foundation, async controller, block wire validation, and
host tests landed.** Request bounds and DMA arithmetic are checked; real
DriverHost MMIO/DMA plumbing remains the next on-target slice.
This is ROADMAP Short-Term #7 (real VFS + drivers in userspace), first device.

## Goal

A userspace NVMe driver running as a ring-3 DriverHost process, built on
`hues-async`. Scope (agreed): full-featured — multiple I/O queues, MSI-X per
queue, multiple namespaces, full Identify/Set Features — exposing a simple
block protocol (read/write by LBA) over a Channel, with VFS mounting later.

## Layering

```
+------------------------------------------------------------+
|  Block service (read_blocks / write_blocks by LBA, Channel) |  <- later slice
+------------------------------------------------------------+
|  Async Controller (hues-async): submit -> CQE -> wake task  |  <- next slice
+------------------------------------------------------------+
|  Protocol foundation (this slice, host-tested):             |
|   regs  - controller register map + bitfields (CAP/CC/...)  |
|   cmd   - SQE/CQE, opcodes, status, Identify/Features,      |
|           admin + NVM I/O command builders                  |
|   prp   - PRP (Physical Region Page) layout                 |
+------------------------------------------------------------+
|  Transport abstraction: NvmeRegs (MMIO) + DmaMemory         |  <- with controller
+------------------------------------------------------------+
|  Kernel plumbing: map BAR into DriverHost + coherent DMA    |  <- on-target slice
+------------------------------------------------------------+
```

## Protocol foundation (`crates/huesos-nvme`, this slice)

Pure `no_std` + `core`, host-unit-tested (29 tests):

- `regs`: BAR0 register offsets and bitfield helpers — CAP (MQES, doorbell
  stride, timeout, page-size range), CC (enable with MPS/IOSQES/IOCQES/CSS),
  CSTS (RDY/CFS/SHST), AQA (admin queue depths), and doorbell offset
  computation from `CAP.DSTRD`.
- `cmd`: SQE (16 LE dwords = 64 B) and CQE (4 dwords = 16 B) as explicit dword
  arrays with accessors; admin and NVM I/O opcodes; completion status decoding
  (phase / SCT / SC / DNR / More); Identify CNS and Set-Features FID constants;
  builders for Identify, Create I/O CQ/SQ, Set Number of Queues, Read, Write,
  Flush.
- `prp`: PRP1 (offset-carrying first address), page-count, PRP-list detection,
  and per-page rest-entry computation for Read/Write.

No `unsafe`, no `unwrap`/`expect`/`panic!` (budget-neutral). The controller
rejects zero-block, namespace-out-of-range, short-buffer, DMA-window overflow,
and malformed block-wire requests before touching queues or device memory.

## Async Controller (next slice)

Built on `hues-async`. The controller owns the admin queue and one-or-more I/O
queue pairs (SQ/CQ in DMA memory). Model:

- `submit(sqe)` writes the SQE to the SQ tail, assigns a command id (CID) tied
  to a `hues-async` task/waker, advances the tail, and rings the SQ doorbell.
- The completion loop (hybrid: a short CQ poll window after a submit, then
  waiting on the MSI-X interrupt delivered via a HuesOS `Port`) reads CQEs,
  matches the CID, and wakes the corresponding task. The CQ phase bit tracks
  wraparound; the CQ head doorbell is rung after processing.
- An I/O operation is a future that resolves with the CQE result once its
  completion arrives.

The whole submit -> CQE -> wake path is host-testable against an in-memory mock
controller (a `NvmeTransport` implementation that responds to register writes
and processes the queues), so the async logic is verified without hardware.

## Transport abstraction + kernel plumbing (on-target slice)

The driver accesses the device through two abstractions:

- `NvmeRegs`: 64/32-bit register reads/writes on BAR0.
- `DmaMemory`: physically-addressable memory for the SQ/CQ and data buffers
  (and PRP-list pages).

On-target, these are backed by kernel-provided capabilities:

- **BAR mapping**: the kernel maps the NVMe controller's BAR0 (MMIO,
  uncacheable) into the DriverHost's address space. This extends the existing
  deny-by-default MMIO capability (used by the ACPI broker) into a general
  device-MMIO grant authorized by the device manager.
- **Coherent DMA buffers**: the kernel provides physically-contiguous (or
  IOMMU-mapped) pages to the DriverHost as VMOs for the queues and data buffers,
  and the driver programs their physical addresses into ASQ/ACQ/PRP entries.
  With no IOMMU, buffers must be physically contiguous; the identity between the
  DriverHost's virtual mapping and the device-visible physical address is
  established by the kernel.

This plumbing requires QEMU (`-device nvme`) / bare-metal verification and is a
separate slice.

## Block protocol (later slice)

The DriverHost exposes `read_blocks(lba, count) -> data` and
`write_blocks(lba, data)` over a Channel (a small block protocol), consumed by a
future FileSystemService / VFS mount (the broader #7 goal). Namespace size and
LBA size come from Identify Namespace (NSZE/LBAF).

## On-target verification checklist

- Controller enable: CC.EN -> wait CSTS.RDY within CAP.TO; AQA/ASQ/ACQ set up.
- Identify Controller + Namespace; Set Features (Number of Queues); Create I/O
  CQ/SQ (MSI-X vector per queue).
- Read/Write a namespace via PRP; data integrity round-trip.
- MSI-X completion delivery through the HuesOS Port; hybrid poll/IRQ behavior.
- Multiple I/O queues across CPUs; multiple namespaces.
