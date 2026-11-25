# HuesOS status and evidence map

Status reviewed against `main` at `6ad199e` (2026-11-23; through PR #287 plus
AP-23 PCI Manager completion on `arena/83195ede-huesos`). This is a versioned
snapshot, not a live dashboard and not a claim that every current CI job passed.
Docs-only follow-ups do not change implementation status.

## Read this first

Implementation, host tests, QEMU evidence and physical hardware evidence are
separate dimensions. A workflow definition is a configured gate, not its result.
A checked box in an old roadmap is not a current release approval.

| Area | Implemented boundary | Host coverage / QEMU gate | Physical evidence / remaining boundary |
| --- | --- | --- | --- |
| Boot and ring3 | Limine UEFI, independent address spaces, ELF launch and syscalls | Host ELF/PMM/object suites; `scripts/ci-qemu-smoke.sh` checks ring3, VMO, IPC and terminal markers | One MSI Modern 15 B5M smoke report; not a compatibility certification |
| Signed boot image | HBI v2.2 signature verification; development keys are not release keys | `scripts/ci-qemu-hbi-signature-smoke.sh`, secure-boot/TPM scripts are configured gates | Physical Secure Boot/TPM security matrix remains required |
| User-copy | Bounds/page-table validation, process memory lock, extable copies; sealed typed record allowlist and zeroed output padding | Syscall host suite; default user-pointer diagnostics; `scripts/ci-qemu-smep-smap-smoke.sh` on CPU max | Real CPU feature evidence must distinguish enabled controls from degraded mode |
| Objects and processes | Registry uses RefAccount; ProcessLifecycle, exit status, counted waiters, port notifications, deferred teardown and bounded graveyard wired | Object/policy host suites, actual-object exit/wait regressions, 4096-exit bounded-graveyard tests and 32-exit init probe with repeated observation; inspect run logs, not marker wording alone | Full-system baseline return, cancellations and longer concurrent storms need separate evidence |
| Task identities and SMP | Global TaskSlotAllocator/TaskDirectory; stable generation-bearing TaskId; owner-local scheduling and token-mediated remote operations; retire-at-reap drains and counts pending remote operations | `huesos-sched` host tests are selected by `make test`; generation-helper regressions cover sequential reuse, stale operations, atomic drain at retire, and replacement-generation isolation. Kernel and QEMU boot tests are complementary | SMP termination/reschedule-IPI race behavior still requires on-target evidence; directory-level carry-over is closed. CPU ownership is not encoded in TaskId. EEVDF/CBS/SMP v2 target design is only partially integrated |
| IRQ routing | Multi-controller route manager, dynamic vectors, typed IRQ/GSI objects, level ACK | IOAPIC host tests; keyboard QMP userspace test; edu level/raw-GSI kernel probe | Kernel-Port probe is not proof of raw-GSI userspace syscall path or real-device coverage |
| Job quotas | Hierarchical Job tree, VMO memory/CPU tick charging and bounded IPC queues; public Job controls | Quota/object host suites; integration stress still required | Per-handle hard caps and page-table metadata accounting are not complete |
| ACPI / PCI | Kernel immutable ACPI archive and broker; isolated userspace `uacpi-runtime` and generation-safe `acpi-manager` supervision (`HMCF`, `HPCI` v2 `_SEG`/`_BBN`/`_CRS`/`_PRT`/`_OSC`, and `HIOM` `DMAR`/`IVRS` snapshots retained by `driver-manager`); `PciConfigMint` RO→RW ECAM authority + named `B.4` write policy (`AP-17`); live BAR sizing, bottom-up bridge window synthesis, hotplug reserves, and rollback-verified commit plans (`E.1`, `F.1`–`F.3`, `AP-19`/`AP-23`); kernel `DeviceLease` revocation and `PORT_PACKET_DEVICE_GONE` (`G.2`/`G.3`, `AP-20`); manifest driver binding, MSI-X/MSI/INTx transactions, and `DmaPoolGrant` (`H.3`, `I.1`/`I.2`, `AP-21`) driving `driver-host-nvme`, `net-service`, and `wlan-service` with kernel PCI scan removed and guarded by `tools/check-kernel-no-pci.py` (`J.1`–`J.3`, `AP-22`); zero-bus-traffic `HPIN` inventory VMO + `pci -v` (`D.3`), reserved-space hotplug policy (`K.1`–`K.3`), restart rebalance + rollback (`L.1`–`L.3`), `QuiesceRemap` protocol (`M.1`), and fail-closed `Trusted` IOMMU discovery (`N.1`/`N.3`, `AP-23`) | Host suites (`huesos-abi`, `huesos-pci` including 10,000-event hotplug storm, 1,000-cycle add/remove leak/ABA, exhaustive rebalance fault injection, and `DMAR`/`IVRS` corpus, `huesos-syscalls`, `huesos-object`, `huesos-kernel`) + ASan/UBSan `scripts/test-uacpi-runtime.sh`; QEMU Q35/OVMF SMP2 (`scripts/ci-qemu-smoke.sh` ECAM and forced-legacy, `scripts/ci-qemu-pci-mediation-smoke.sh`, `scripts/ci-qemu-acpi-restart-smoke.sh`, `scripts/ci-qemu-storage-off-smoke.sh`, `scripts/ci-qemu-nvme-soak.sh`) | Hardware IOMMU per-device DMA page-table domains (`N.2`), live `QuiesceRemap` driver (`M.2`), and multi-platform physical bare-metal qualification matrix (`O.3`) remain open; `PCI production-ready = false` |
| NVMe / HxFS | Userspace driver and mutable HxFS v7 foundation; read-only v6 compatibility with explicit migration; versioned policies and recovery paths; production status remains false | Host/storage feature gates and QEMU fault/soak scripts; inspect per-commit results | Dedicated two-vendor NVMe, v7 format approval and independent security review remain open; no physical storage verification inferred from the laptop report |
| Framebuffer / terminal | Capability-gated drawing remains in kernel; userspace Canvas, terminal and games | Host framebuffer tests; terminal boot gate; visual/game tests have separate procedures | No Unicode shaping, GPU acceleration or desktop compositor claimed |

## Which documents are authoritative?

- **Current status overview:** this file. Detailed contracts still govern their
  subsystem; resolve contradictions against code and evidence before editing.
- **Current implementation:** [ARCHITECTURE.md](ARCHITECTURE.md),
  [USER_MEMORY.md](USER_MEMORY.md), [OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md),
  [DYNAMIC_PROCESSES.md](DYNAMIC_PROCESSES.md), [TASK_GENERATIONS.md](TASK_GENERATIONS.md),
  [IOAPIC_ROUTING.md](IOAPIC_ROUTING.md), [QUOTAS.md](QUOTAS.md), [UACPI.md](UACPI.md).
- **Verification procedures:** [TESTING.md](TESTING.md); actual evidence requires
  a commit, exact command/result and retained serial/test logs.
- **Physical reports:** [HARDWARE.md](HARDWARE.md). The report lists host hardware;
  listing an NVMe, network or Bluetooth device does not imply HuesOS tested it.
- **Release blockers:** [STORAGE_PRODUCTION_GATE.md](STORAGE_PRODUCTION_GATE.md),
  [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md). Bare-metal /
  physical-hardware evidence for Secure Boot, TPM and storage remains
  owner-gated; there is no public evidence checklist in the tree.
- **Target designs:** [SCHEDULER_V2.md](SCHEDULER_V2.md), [SMP_V2.md](SMP_V2.md),
  [ACPI_RING3.md](ACPI_RING3.md), [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md).
  Design acceptance is not implementation completion.
- **Current work queues:** [ROADMAP.md](ROADMAP.md),
  [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md),
  [ACPI_PCI_IMPLEMENTATION_PLAN.md](ACPI_PCI_IMPLEMENTATION_PLAN.md).
- **History:** archived/closed material (the v1 storage roadmap, the
  microkernel migration plan, the early architectural-weaknesses analysis,
  closed stage plans) was removed in the 2026-11 docs-hygiene pass. Migration
  and storage history lives in git; current design intent lives in the
  target designs listed above — not in the removed files.

See [INDEX.md](INDEX.md) for a newcomer reading order.

## Maintenance contract

When changing a boundary, update the subsystem contract and this snapshot in the
same PR. Record implementation and verification separately. State the observed
CPU/profile/commit and limitations; never turn a configured gate into a pass.
Do not erase still-open failure modes merely because ordinary boot succeeds.
Update the reviewed base above when reviewing code, not automatically for a
spelling change. Full green GitHub CI, independent review and hardware evidence
must not be inferred from a local docs-only verification.
