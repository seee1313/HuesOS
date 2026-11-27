# Hardware IOMMU Isolation: Intel VT-d & AMD-Vi (`huesos-iommu` & Stage N.2)

HuesOS enforces hardware DMA isolation (**PCI Isolated Profile**, Stage N.2 of
[`PCI_PRODUCTION_ROADMAP.md`](PCI_PRODUCTION_ROADMAP.md)) across both **Intel
VT-d** (ACPI `DMAR`) and **AMD-Vi** (ACPI `IVRS`) platforms using per-lease
4 KiB IO page tables.

## Trust & Privilege Boundary

Following the microkernel policy-crate split enforced by
`tools/check-policy-crates.py`:

1. **`crates/huesos-iommu` (`#![no_std]`, `#![forbid(unsafe_code)]`)** owns all
   pure bit-level codecs and policy state machines:
   - **Intel VT-d codecs:** `VtdCapabilities::parse` (`VER_REG`/`CAP_REG`/`ECAP_REG`,
     39-bit / 48-bit SLPTs, `CM=1`, `ECAP.C`, `IOTLB_REG`/`FRCD_REG`),
     `RootEntry`/`ContextEntry`/`SlPte`, `build_gcmd`/`ccmd_*`/`iotlb_*`, and
     `FaultRecord::decode_frcd`.
   - **AMD-Vi codecs (`amd_vi` module):**
     - `AmdViDte`: 256-bit Device Table Entries (`AmdViDte::blocked` sets
       `V = 1, TV = 1, Mode = 4, IR = 0, IW = 0` on `DomainId 1` because `V = 0`
       in AMD-Vi is pass-through; `AmdViDte::translated` binds `DomainId >= 2`).
     - `AmdViPte`: 64-bit 4-level (`48`-bit IOVA) IO Page Table entries with
       `NextLevel` (`3`, `2`, `1` on directories; `0` on 4 KiB leaves) and
       `IR`/`IW` bits.
     - `AmdViCommand`: 128-bit ring commands (`COMPLETION_WAIT` store-fence,
       `INVALIDATE_DEVTAB_ENTRY`, `INVALIDATE_IOMMU_PAGES` full-domain `S = 1, PDE = 1`).
     - `decode_amd_vi_event`: decodes 128-bit Event Log entries (`IO_PAGE_FAULT`
       and hardware/table faults) into `FaultRecord`.
   - `DomainTable`: fixed-capacity (`MAX_ACTIVE_DOMAINS = 64`) per-lease domain
     allocator (`allocate_domain` / `allocate_domain_min`) tracking
     `(lease_koid, lease_generation) -> DomainId`, enforcing isolation-group
     exclusivity (`derive_isolation_group`), and accounting mapped `DmaPool`
     pages and completed teardowns.

2. **`crates/huesos-arch/src/x86_64/{vtd.rs, amd_vi.rs, iommu.rs}` (Ring-0 hardware adapters)**
   own the minimal privileged integration boundary:
   - Map each `DRHD` (`4 KiB`) or `IVHD` (`16 KiB`) MMIO window uncached
     (`PRESENT | WRITABLE | NO_CACHE | NO_EXECUTE`) after `huesos-kernel`
     verifies that firmware register bases do not alias usable RAM.
   - **VT-d (`vtd.rs`):** allocates 4 KiB Root, per-bus Context, and SLPT frames
     from `huesos-pmm`, pre-populates `RMRR` unity regions (`IOVA == HPA`), and
     sets `GCMD.TE = 1` (`GSTS.TES == 1`).
   - **AMD-Vi (`amd_vi.rs`, 0 `unsafe` blocks):** allocates a contiguous 2 MiB
     (`65,536`-entry) Device Table pre-filled with `AmdViDte::blocked`, 4 KiB
     Command Buffer and Event Log rings, pre-populates `IVMD` unity regions,
     enables `CmdBufEn | EventLogEn | IommuEn`, and synchronizes every DTE/IOTLB
     invalidation with a hardware `COMPLETION_WAIT` memory store fence.
   - **`huesos_arch::iommu`:** unified Ring-0 facade dispatching `bind_lease_dma`,
     `teardown_lease`, `status_snapshot`, and `drain_faults` to the active
     backend under `RankedIrqSafeTicketLock` (`LockRank::ARCHITECTURE`).

## Capability Lifecycle (`DeviceLease` ↔ `DmaPool`)

- **Default-deny DMA:** Once hardware translation is enabled at boot (`GCMD.TE = 1`
  on VT-d or `IommuEn = 1` with `AmdViDte::blocked` on AMD-Vi), every PCIe
  requester covered by an active IOMMU unit is blocked by default (except
  firmware-mandated `RMRR`/`IVMD` scopes) and cannot DMA to any physical RAM page.
- **Least-privilege attachment (`Syscall::DeviceLeaseAttachDma = 96` & `DeviceLeaseMintResource`):**
  Only `DriverManager` and `pci-manager` hold `WRITE` rights on a `DeviceLease`
  handle; Ring-3 drivers (`driver-host-nvme`, `driver-host-xhci`, `net-service`,
  `wlan-service`) receive read-only `DeviceLease` duplicates (`READ | TRANSFER`)
  and cannot widen their own IOMMU mappings. Before forwarding a `DmaPool`
  `Resource` handle to a child driver (from the static `[0..76 MiB)` boot slices
  or the four `[76..92 MiB)` `(lease_koid, generation)`-claimed live hotplug
  slices inside `BOOT_DMA_POOL_LEN = 92 MiB`), `DriverManager` calls
  `DeviceLeaseAttachDma`, which maps strictly `[base, base + len)`
  (`IOVA == HPA`, `R | W`) into that device's dedicated VT-d/AMD-Vi `DomainId`
  and flushes the hardware Context/Device-Table cache and IOTLB.
- **Synchronous revocation (`DeviceLease::revoke` & `Drop`):** Revoking a
  `DeviceLease` (or dropping its last kernel reference) synchronously clears the
  VT-d `ContextEntry[devfn]` or resets the AMD-Vi `DTE` to `AmdViDte::blocked`,
  flushes the hardware Context/DTE cache and Domain IOTLB (`COMPLETION_WAIT` on
  AMD-Vi), releases any dynamic hotplug DMA slot, and frees all IO page-table
  frames **before** `revoke()` returns or delivers `PORT_PACKET_DEVICE_GONE`.
- **Honest telemetry (`Syscall::SystemIommuStatus = 97`):** `acpi-manager` and
  `pci-manager` report `IommuMode::Isolated` in `HIOM` v1, `HPIN` v1, and
  `pci -v --iommu` **if and only if** kernel hardware translation is genuinely
  active; platforms without an active hardware IOMMU honestly report `Trusted`.

## Verification

- **Host unit tests:** `cargo test -p huesos-iommu` exercises VT-d capability
  parsing (`39-bit` / `48-bit`, `CM=1`, malformed offsets), `GCMD` persistent
  masking, Root/Context/SLPT codecs, `FRCD` fault decoding, AMD-Vi DTE/PTE/Command
  and Event Log codecs (`amd_vi`), isolation-group conflict rejection, and
  domain teardown reuse.
- **Live QEMU hardware smoke (`scripts/ci-qemu-iommu-vtd-smoke.sh`):** Boots the
  same HBI ISO across three Q35 legs: (1) `intel-iommu,intremap=off,caching-mode=on`,
  (2) `amd-iommu,intremap=off`, and (3) no-IOMMU `Trusted` fallback — proving
  authorized `edu` DMA read/write success, hardware blocking on out-of-bounds
  canary DMA, synchronous post-`revoke()` DMA blocking + fault capture, and full
  Ring-3 NVMe + `HxFS v7` + `virtio-net-pci,iommu_platform=on` bring-up under
  `mode=Isolated` on both Intel VT-d and AMD-Vi.
