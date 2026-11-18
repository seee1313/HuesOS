# HuesOS Roadmap

**Snapshot baseline:** `main` at `ba1f439` (2026-11-18).

The MVP boot-to-userspace pipeline (Limine → PMM → paging → SMP-aware
scheduler → ring3 → syscalls → VMO/Channel IPC) is working and verified in
QEMU (`-smp 1` and `-smp 2`). This roadmap organizes active work by subsystem
and keeps a compact ledger of recently completed milestones.

Authoritative status and evidence boundaries live in [STATUS.md](STATUS.md).
Storage details live in [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md) and
[STORAGE_PRODUCTION_GATE.md](STORAGE_PRODUCTION_GATE.md); mutable HxFS v7
exists, while `storage production-ready` and format freeze remain `false`.

PCI/PCIe and Ring-3 ACPI modernization are specified in
[PCI Manager Architecture](PCI_MANAGER_ARCHITECTURE.md),
[Ring-3 ACPI Architecture](ACPI_RING3.md),
[PCI Production Roadmap](PCI_PRODUCTION_ROADMAP.md), and
[ACPI → PCI Implementation PR Plan](ACPI_PCI_IMPLEMENTATION_PLAN.md). The
kernel CF8/CFC NVMe bootstrap (`crates/huesos-kernel/src/boot/storage.rs`)
remains a migration shim and `PCI production-ready` remains `false`.

---

## Active Subsystems Roadmap

### 1. PCI / PCIe & Ring-3 ACPI (AP-17+ — Stages B.4…O)

AP-0 through AP-16 established the isolated Ring-3 `uacpi-runtime`, `acpi-manager`
supervision, `HMCF` config-window snapshots, `PciConfigMint` capability minting,
mediated `PCI_Config`/`SystemIO`/`SystemMemory` reads, generation-safe ACPI IRQ
grants, namespace load/init, `HPCI` root-bridge discovery, and root-bound
read-only diagnostic PCI inventory. The next ordered stages turn read-only
discovery into active device ownership:

- **AP-17 (`B.4` — Audited config write policy & transactions):** bounded
  config-space write policy and write/readback verification transactions
  (Command register, BAR sizing/enable, bridge windows) owned solely by
  `pci-manager`; AML config writes remain denied unless explicitly justified.
- **AP-18 (`C.3` — `_PRT` and `_OSC` ownership):** evaluate ACPI `_PRT`
  (PCI interrupt routing tables) and `_OSC` (host/OS control negotiation) in
  Ring-3 `uacpi-runtime` and carry validated routing/control metadata to
  `pci-manager`.
- **AP-19 (`E.1` + `F.2` — Live BAR inventory & rollback-verified planner):**
  live BAR sizing/validation integrated with `huesos-pci::resource_planner`
  for deterministic firmware-preserving allocation and explicit rollback plans.
- **AP-20 (`G.2` + `G.3` — Kernel `DeviceLease` & `DeviceGone`):** kernel-enforced
  per-device lease object bound to `(DeviceId, LeaseGeneration, FirmwareSnapshotId)`,
  preventing BDF-reuse / stale-resource ABA and delivering `DeviceGone` revocation
  signals.
- **AP-21 (`H.3` + `I` — Driver binding & narrow BAR/IRQ/DMA handoff):**
  `pci-manager` + `driver-manager` driver binding that mints narrow per-device
  BAR MMIO, MSI-X/MSI/INTx IRQ, and bounded DMA pool handles strictly through
  active `DeviceLease` grants.
- **AP-22 (`J` — NVMe migration & kernel PCI shim removal):** migrate system
  NVMe boot/binding completely to `pci-manager` + `driver-host-nvme` and delete
  the legacy kernel CF8/CFC scan in `crates/huesos-kernel/src/boot/storage.rs`.
- **Later (`Stages K–O`):** reserved-space hotplug and surprise-removal
  fail-stop (`K`), restart-based and opt-in `QuiesceRemap` rebalance (`L`–`M`),
  IOMMU isolated DMA domains (VT-d / AMD-Vi, `N`), and multi-machine
  bare-metal production qualification (`O`).

### 2. Storage & HxFS (`PRODUCTION_ROADMAP.md` / `STORAGE_PRODUCTION_GATE.md`)

HxFS v7 read/write/checkpoint foundations, encrypted metadata/filenames/extents
(Stage B), runtime knobs/structured observation/reproducible benchmarks
(Stages E.1/E.2/E.4), and Hxblob/service foundations (Stage F) have landed,
while `v7 format freeze` and `storage production-ready` remain deliberately
`false`. Remaining work to close the storage track:

- **Stage E.3 — 24-hour long-haul soak & run-to-run comparison:** extend the
  bounded ~2 h `scripts/soak-long.sh` pass to a full 24 h endurance run with
  automated throughput/error/recovery delta checks against a prior baseline.
- **Stage C — Full reliability closure:** complete end-to-end fault-injection
  and recovery verification for media error handling, online `fsck`, and
  online `scrub` across power-loss and LBA-corruption matrices.
- **Stage D — Hardware security closure:** execute the owner-gated physical
  TPM PCR sealing and Secure Boot verification matrix on real hardware (beyond
  QEMU OVMF + `swtpm` smoke gates).
- **Multi-vendor NVMe qualification & format freeze:** sustain persistent
  `hxfs-service` workloads across at least two distinct NVMe controller/SSD
  vendors before approving an irreversible on-disk HxFS v7 format freeze.

### 3. Networking (Medium Term #9)

No network driver or TCP/IP stack exists yet. Planned incremental delivery:

- **Userspace `virtio-net` DriverHost:** implement a capability-scoped network
  device driver host (`driver-host-net`) using bounded DMA descriptor rings,
  `WaitSet` / `Port` completion notifications, and `DeviceLease`-mediated
  BAR/IRQ grants once AP-20/AP-21 land (or manifest-scoped MMIO/IRQ in a
  staging harness).
- **Userspace TCP/IP stack:** isolated, quota-bounded protocol service
  (Ethernet, ARP, IPv4, ICMP, UDP, TCP) communicating with clients over
  Channel/VMO IPC without adding protocol parsing to Ring-0.
- **QEMU & real-NIC follow-ups:** automated QEMU user-net / tap smoke tests
  (DHCP/ARP/ICMP/UDP/TCP echo), followed later by real hardware NIC drivers
  (e.g., Intel `e1000e`/`igc`) under the IOMMU isolated profile.

### 4. Platform, Userspace & Long-Term Hardening

- **VFS-backed process execution:** replace build-time `include_bytes!` BOOTFS
  ELF embedding for non-bootstrap applications with dynamic loading from
  persistent HxFS / BlobFS volumes.
- **Userspace environment & toolchain:** expand `libcanvas`, freestanding C/POSIX
  compatibility surfaces, interactive shell utilities, and work toward a
  self-hosting toolchain.
- **Additional device classes (post PCI/Storage/Net):** USB xHCI host controller
  driver host and audio output (PC Speaker SFX / HD Audio).
- **Kernel & CPU security hardening:** KASLR, full physical-CPU SMEP/SMAP
  verification matrices, and IOMMU (VT-d / AMD-Vi) DMA isolation.

---

## Done (recent)

### ACPI→PCI Bring-Up Series (AP-4…AP-16)
- **AP-4 / AP-5 / AP-6 (uACPI primitives, archive-v2, supervision):** isolated
  Ring-3 `uacpi-runtime` extended with process-local primitives and archive-v2
  read-only table maps; `acpi-manager` supervision enforces generation-safe
  retained archive/broker handles, bounded backoff, and last-good freeze
  (`scripts/ci-qemu-acpi-restart-smoke.sh restart|budget`).
- **AP-7 (`huesos-dev/ap7-hmcf-wire`):** validated `HMCF` ECAM config-window
  snapshot produced by `acpi-manager` and retained by `driver-manager` under the
  active ACPI generation.
- **AP-8 (`d100388`, PR #245):** kernel `PciConfigMint` one-shot root
  capability (`init` only), bounded mint requests bound to HMCF + archive-v2
  MCFG with canonical-subset and usable-RAM-alias checks, minting read-only,
  non-executable, `NO_CACHE` ECAM mappings.
- **AP-9 (`b66895d`, PR #246):** `init` delegates `PciConfigMint` to
  `driver-manager`, which mints generation-bound read-only ECAM capabilities per
  `pci-manager` generation and transitions readiness from fail-closed to
  `read-only config authority ready`.
- **AP-10 (`6ad1f78`, PR #247; `3050c5c`, PR #248):** dedicated ACPI→PCI
  `PCI_Config` read mediation channel served by `pci-manager`; all config
  writes denied; legacy broker PCI opcodes permanently unauthorizable;
  scenario-aware ECAM/forced-legacy QEMU smoke gates.
- **AP-11 (`9fc854c`, PR #249; `18242b3`, PR #250):** Gate B range policy and
  kernel-broker mediation for ACPI `SystemIO` and `SystemMemory`
  `OperationRegion` accesses (`huesos_abi::acpi_region_policy`,
  `acpi_policy.rs`), preserving sacred denies and snapshot bindings.
- **AP-12 (`f007150`, PR #251):** generation-safe ACPI IRQ grants and CPU0
  deferred-work queue (`uacpi-runtime::work`), keeping AML interrupt/work
  dispatch bounded and generation-checked.
- **AP-13 / AP-14 (`92e7be9`, PR #252; `9c9c625`, PR #254):** isolated Ring-3
  uACPI AML namespace load (`_PIC(IOAPIC)`), bounded `uacpi_namespace_initialize`,
  writable FACS shadow in `uacpi_shim.c`, and host ASan/UBSan namespace corpus
  tests (`scripts/test-uacpi-runtime.sh`).
- **AP-15 (`a192cfe`, PR #255):** Ring-3 uACPI root-bridge discovery (`_HID`
  `PNP0A03`/`PNP0A08`, `_CRS`, `_BBN`/`_SEG`) producing validated `HPCI`
  `RootBridgeTable` VMOs (`acpi-manager` → `driver-manager` → `pci-manager`)
  with HMCF cross-checks and ECAM/forced-legacy QEMU parity.
- **AP-16 (`ba1f439`, PR #256):** `huesos-pci::inventory` and `pci-manager`
  read-only diagnostic PCI inventory enumeration bound to validated `HPCI` roots
  with `FirmwareResourceAvailability` status, zero config writes/BAR sizing
  mutations, crash-freeze inventory retention, and CI stabilization for
  `tools/storage-bench.py` (`--self-compare` warmup/median) and
  `extable::tests` (`SORTED_PTR` host-test serialization).

### Core Kernel, Security, Scheduler & Quotas (Immediate #1–#4, Short-Term #5–#6, Medium-Term #8 & #10 — COMPLETE ✅)
- **Immediate #1 — Recoverable copies, VMAR splits & SMEP/SMAP:** `huesos-extable`,
  `.ex_table` asm primitives for bulk & typed user copies, `VmarCreateChild` /
  split `VmarUnmap` / `VmarProtect`, and `qemu-extable-smoke` (`extable_test=1`).
- **Immediate #2 — IOAPIC routing:** `huesos-ioapic` policy crate, masked-first
  multi-controller GSI routing, dynamic IDT bridge, and kernel `edu` level-IRQ
  probe (`scripts/ci-qemu-irq-level-smoke.sh`); userspace raw-GSI path and
  `_PRT` integration remain open under AP-18/AP-21.
- **Immediate #3 & Short-Term #5 — Process/object lifecycle & dynamic processes:**
  `huesos-lifecycle` `RefAccount` registry, `huesos-proclife` state machine,
  `ProcessBindExitPort`, `TaskDirectory::retire` drain, bounded graveyard, and
  32-exit repeated-observation init tests ([PROCESS_LIFECYCLE_REGRESSIONS.md](PROCESS_LIFECYCLE_REGRESSIONS.md)).
- **Immediate #4 & Short-Term #6 — Wait primitives & handle transfer:**
  `huesos-waitset` + `Syscall::WaitSetWait`, level-triggered `Signal` objects,
  and transactional all-or-nothing `huesos-handlemove` handle transfer in
  `ChannelWrite`.
- **Medium-Term #8 & #10 — Job quotas & scheduler polish (+ 16-item stabilization):**
  hierarchical `Job` tree (`JobDefault`/`JobCreate`/`JobSetLimits`/`JobBindQuotaPort`
  /`ProcessCreateInJob`), panic-free `huesos-sched` EEVDF (`?`-threaded internals),
  EDF replenish-on-unblock, opt-in token-based Fair task stealing, dedicated
  non-timer reschedule IPI, and deferred quota-exhaustion packets.
- **Locking & static safety gates:** type-enforced `IrqSafeMutex<T>` across
  `huesos-object` + `tools/check-huesos-object-lock-policy.py`, `hues-async`
  alloc-free CI gate, ranked privileged locks, sealed typed syscall allowlists,
  and zero runtime `unwrap`/`expect`/`panic` policy (`safety-budget.json`).

### Userspace Platform, Terminal, Input & Storage Foundation (Short-Term #7 foundation)
- **Userspace drivers, terminal & shutdown (PR-C…PR-G):** manifest-driven
  `Resource` capability grants (`IoPort`/`Mmio`/`Irq`/`PowerControl`), full
  migration of PS/2 input to event-driven `driver-host-input`, deletion of
  `huesos-arch::x86_64::keyboard`, userspace `shutdown-broker` + `Syscall::HardHalt`,
  Cozette 6×13 TTY font + buffered 16 MiB shadow terminal renderer, monotonic
  Snake, and Freedoom/DoomGeneric port.
- **NVMe & HxFS v7 foundation (Stages A–F foundation):** `driver-host-nvme`
  (64 MiB boot DMA pool, MSI-X→MSI→polling, per-CPU queues, async BlockDevice
  Channel+Port, VolumeManager), read-only BlobFS & DevFS handle namespace, and
  `hxfs-service` / `huesos-hxfs` v7 COW + encrypted/compressed pipeline +
  journaled crash-consistency harness (`scripts/ci-qemu-powerfail.sh`).

---

## Explicitly Out of Scope for the Original MVP

Tracked for historical context from the initial MVP boundary:

- ~~SMP / IOAPIC routing~~ → SMP core and generic IOAPIC route manager landed;
  userspace raw-GSI validation and ACPI `_PRT` integration continue under
  PCI/ACPI AP-18+.
- ~~Any filesystem on real block devices~~ → `driver-host-nvme` + HxFS v7
  foundation landed; storage production gate closure tracked in §2 above.
- Networking → tracked in §3 above.
- ~~Full process teardown / wait~~ → closed under Immediate #3/#4 and
  Short-Term #5.
