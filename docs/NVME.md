# NVMe Driver (ring-3 DriverHost)

Status: **Stage A hardware plumbing landed.** The repository now has:
`DmaPool` resource capability, a userspace `driver-host-nvme` skeleton, Identify
Controller/Namespace parsers, per-CPU queue/DMA planning, an async BlockDevice
Channel+Port wire protocol, a 64 MiB boot DMA pool reservation, kernel PCI NVMe
BAR/IRQ metadata discovery, HBI boot-driver packaging, and DriverManager launch
of `driver-host-nvme` from BOOTFS when NVMe hardware is discovered. Real BAR
userspace mapping, MSI-X/MSI programming, controller admin-queue bring-up, and
on-target I/O remain the next slices. This is ROADMAP Short-Term #7 (real VFS +
drivers in userspace), first device.

## Goal

A userspace NVMe driver running as a ring-3 DriverHost process, built on
`hues-async`. Scope (agreed): userspace DriverHost loaded from HBI `.img`, preallocated
64 MiB DMA pool, no heap allocation after initialization, interrupt-first I/O
(MSI-X → MSI → polling fallback), per-CPU I/O queues with depth 256, 1 MiB max
request size, and async BlockDevice protocol over Channel submissions plus Port
completions. BlobFS/Hxfs/VFS mounting comes later.

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
invalid MDTS values, and malformed block-wire requests before touching queues or
device memory. The first controller slice uses one reusable bounded DMA data
buffer plus one PRP-list page for I/O, so repeated reads/writes no longer consume
the DMA window monotonically; transfers that would require chained PRP-list pages
are rejected until chaining is implemented.

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

- **BAR metadata Resource**: Stage A discovers NVMe PCI functions using legacy
  config-space access, validates BAR0 as a memory BAR, sizes it, and forwards an
  exclusive `Mmio` Resource label to `driver-host-nvme`. The actual userspace
  MMIO mapping syscall/VMAR path is deliberately left for Stage B before any
  register access from ring 3.
- **Interrupt metadata Resource**: Stage A records INTx line/pin and MSI/MSI-X
  capability metadata, then forwards an `Irq` Resource label. MSI-X → MSI →
  polling programming and Port delivery remain the next hardware slice.
- **Coherent DMA buffers**: boot reserves a preallocated `DmaPool` resource for
  the DriverHost. The first production target is a 64 MiB pool, physically
  contiguous, pinned, below 4 GiB when available, and device-visible. The driver
  can identify `base/len` and later carve admin queues, per-CPU I/O queues,
  PRP-list pages, request descriptors, and bounce buffers from that pool without
  heap allocation after initialization.

The ABI side has a `ResourceKindAbi::DmaPool` / object `ResourceKind::DmaPool`
capability and a storage boot-info VMO (`huesos_abi::storage_boot`) so init can
mint dynamic resources while DriverManager remains the launch/registry owner.

## Block protocol / DriverManager registry

The async BlockDevice control protocol is a fixed request record over a Channel
and Port completions keyed by `request_id`. DriverManager reserves the registry
request:

```text
open:block:nvme
```

with the success response:

```text
service:block:nvme:channel
```

Stage A can launch the real NVMe DriverHost and mark the hardware resources as
present, but there is still no async BlockDevice server channel. DriverManager
therefore continues to return `err:block:nvme-unavailable` for `open:block:nvme`
until Stage C wires a real service channel. This keeps clients and future
BlobFS/Hxfs code on a stable discovery contract without pretending that storage
I/O is already online.

## On-target verification checklist

Stage A completed in code:

- Boot reserves/logs the 64 MiB DMA pool.
- Kernel storage boot-info logs discovered NVMe PCI function(s), BAR0, IRQ line,
  and MSI/MSI-X metadata.
- Init forwards `Mmio`, `Irq`, and `DmaPool` Resource handles with deterministic
  labels to DriverManager.
- DriverManager enumerates `/storage/boot-drivers.manifest` and launches
  `/drivers/driver-host-nvme.elf` from HBI BOOTFS when hardware is present.
- `driver-host-nvme` logs `resources: mmio OK, irq OK, dma OK` or the exact
  missing resource kind.

Remaining Stage B/C work:

- Controller enable: CC.EN -> wait CSTS.RDY within CAP.TO; AQA/ASQ/ACQ set up.
- Identify Controller + Namespace; Set Features (Number of Queues); Create I/O
  CQ/SQ (MSI-X vector per queue).
- Read/Write a namespace via PRP; data integrity round-trip.
- MSI-X completion delivery through the HuesOS Port; hybrid poll/IRQ behavior.
- Multiple I/O queues across CPUs; multiple namespaces. The host-side
  `QueueManager` now tracks exact active queue IDs and rejects deletion of a
  non-existent queue; the remaining on-target work is submitting the matching
  Create/Delete I/O CQ/SQ admin commands and wiring MSI-X vectors.
