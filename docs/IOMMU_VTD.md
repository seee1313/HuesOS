# Intel VT-d Hardware IOMMU Isolation (`huesos-iommu` & Stage N.2)

HuesOS enforces hardware DMA isolation (**PCI Isolated Profile**, Stage N.2 of
[`PCI_PRODUCTION_ROADMAP.md`](PCI_PRODUCTION_ROADMAP.md)) using **Intel VT-d**
second-stage address translation when firmware publishes a valid ACPI `DMAR`
table.

## Trust & Privilege Boundary

Following the microkernel policy-crate split enforced by
`tools/check-policy-crates.py`:

1. **`crates/huesos-iommu` (`#![no_std]`, `#![forbid(unsafe_code)]`)** owns all
   pure bit-level codecs and policy state machines:
   - `VtdCapabilities::parse`: validates `VER_REG`, `CAP_REG`, and `ECAP_REG`,
     selecting 48-bit (4-level) or 39-bit (3-level) second-stage page tables,
     detecting Caching Mode (`CAP.CM == 1`), Page-Walk Coherency (`ECAP.C`),
     `DRD`/`DWD` drain flags, and bounded register offsets (`IOTLB_REG`,
     `FRCD_REG`).
   - `RootEntry`, `ContextEntry`, and `SlPte`: encode 128-bit Root/Context
     descriptors and 64-bit 4 KiB Second-Stage PTEs (`R`/`W`, `TT=00`),
     permanently reserving `DomainId 0` for `CM=1` compliance.
   - `build_gcmd`, `ccmd_*`, and `iotlb_*`: construct invalidation and global
     command words while masking one-shot `GSTS_REG` status bits (`0x96FF_FFFF`).
   - `FaultRecord`: decodes 128-bit Primary Fault Recording entries (`FRCD_REG`)
     into PCI Source-ID (`BDF`), 4 KiB faulting IOVA, access direction, and
     classified `FaultKind`.
   - `DomainTable`: fixed-capacity (`MAX_ACTIVE_DOMAINS = 64`) per-lease domain
     allocator tracking `(lease_koid, lease_generation) -> DomainId`, enforcing
     isolation-group exclusivity (`derive_isolation_group`), and accounting
     mapped `DmaPool` pages and completed teardowns.

2. **`crates/huesos-arch/src/x86_64/vtd.rs` (Ring-0 hardware adapter)** owns
   the minimal privileged integration boundary:
   - Maps each `DRHD` MMIO window uncached (`PRESENT | WRITABLE | NO_CACHE | NO_EXECUTE`)
     after `huesos-kernel` verifies that `DRHD` bases in `DMAR` do not alias
     usable RAM.
   - Allocates 4 KiB physical frames for the Root Table, per-bus Context Tables,
     and per-domain Second-Stage Page Tables from `huesos-pmm`, executing
     `clflush` on modified cache lines whenever `ECAP.C == 0`.
   - Pre-populates firmware `RMRR` reserved unity regions (`IOVA == HPA`) before
     setting `GCMD.TE = 1` and polling `GSTS.TES == 1`.
   - Exposes `bind_lease_dma` and synchronous `teardown_lease` under
     `RankedIrqSafeTicketLock` (`LockRank::ARCHITECTURE`).

## Capability Lifecycle (`DeviceLease` ↔ `DmaPool`)

- **Default-deny DMA:** Once `GCMD.TE = 1` is enabled at boot, every PCIe
  requester covered by a `DRHD` unit has `ContextEntry.Present = 0` (except
  firmware-mandated `RMRR` scopes) and cannot DMA to any physical RAM page.
- **Least-privilege attachment (`Syscall::DeviceLeaseAttachDma = 96` & `DeviceLeaseMintResource`):**
  Only `DriverManager` and `pci-manager` hold `WRITE` rights on a `DeviceLease`
  handle; Ring-3 drivers (`driver-host-nvme`, `net-service`, `wlan-service`)
  receive read-only `DeviceLease` duplicates (`READ | TRANSFER`) and cannot
  widen their own IOMMU mappings. Before forwarding a `DmaPool` `Resource`
  handle to a child driver, `DriverManager` calls `DeviceLeaseAttachDma`, which
  maps strictly `[base, base + len)` (`IOVA == HPA`, `R | W`) into that
  device's dedicated VT-d `DomainId` and flushes Context Cache + IOTLB.
- **Synchronous revocation (`DeviceLease::revoke` & `Drop`):** Revoking a
  `DeviceLease` (or dropping its last kernel reference) synchronously clears
  `ContextEntry[devfn]`, flushes the `DRHD` Context Cache and Domain IOTLB, and
  frees all second-stage page-table frames **before** `revoke()` returns or
  delivers `PORT_PACKET_DEVICE_GONE`.
- **Honest telemetry (`Syscall::SystemIommuStatus = 97`):** `acpi-manager` and
  `pci-manager` report `IommuMode::Isolated` in `HIOM` v1, `HPIN` v1, and
  `pci -v --iommu` **if and only if** kernel hardware translation (`GSTS.TES == 1`)
  is genuinely active; platforms without an active hardware IOMMU honestly
  report `Trusted`.

## Verification

- **Host unit tests:** `cargo test -p huesos-iommu` exercises capability
  parsing (`39-bit` / `48-bit`, `CM=1`, malformed offsets), `GCMD` persistent
  masking, Root/Context/SLPT codecs, `FRCD` fault decoding, isolation-group
  conflict rejection, and domain teardown reuse.
- **Live QEMU hardware smoke (`scripts/ci-qemu-iommu-vtd-smoke.sh`):** Boots
  QEMU Q35 with `-device intel-iommu,intremap=off,caching-mode=on`, a PCI `edu`
  DMA engine, an encrypted `HxFS v7` NVMe drive, and `virtio-net-pci,iommu_platform=on`,
  proving authorized DMA read/write success, hardware blocking + `FRCD` fault
  capture on out-of-bounds canary DMA, synchronous post-`revoke()` DMA blocking,
  and full Ring-3 storage/network bring-up under `mode=Isolated`.
