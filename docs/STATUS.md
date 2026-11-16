# HuesOS status and evidence map

Status reviewed against `main` at `d100388` (2026-11-16; AP-8 merged via
PR #245); the ACPI/PCI row additionally reflects the AP-9 branch under
review. This is a versioned
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
| ACPI / PCI | Kernel immutable ACPI archive and broker; isolated userspace uACPI runtime (host tests extended to the plan's required cases); ACPI Manager supervision on main: generation-safe retained archive/broker duplicates, structured control protocol, bounded backoff, last-good freeze policy; HMCF config-window snapshot produced from the archived MCFG and retained by DriverManager (envelope/size/generation validation, immutable VMO, no ECAM mapping); snapshot-bound config-mint authority (AP-8, on `huesos-dev/ap8-config-mint`): unique boot-minted `PciConfigMint` capability for the root supervisor, bounded mint request (HMCF VMO + generation metadata, never a physical range), independent kernel re-decode of HMCF and the bound archive-v2 MCFG with canonical-subset and usable-RAM-alias checks, read-only/non-executable/uncached ECAM capabilities; generation-bound read-only authority handed to PCI Manager (AP-9, on `huesos-dev/ap9-config-authority-handoff`): `init` delegates the unique mint authority to DriverManager, fresh minted ECAM capability set per PCI Manager generation (canonical HMCF order, snapshot/generation-bound), two-phase readiness (fail-closed at startup, upgrade after the burst validates and maps read-only), degraded paths settle into `no firmware snapshot`; AML reads and any topology publication remain disabled; PCI bootstrap remains the migration shim | Host decoders/ABI suites (huesos-abi 104 incl. 10 PciConfigMint cross-check tests; huesos-syscalls 30 incl. 2 authority tests; huesos-object 100 incl. binary `PciConfigMint` kind; ABI extensions append-only and 24 B layout unchanged; libcanvas mint wrapper adds no unsafe); QEMU Q35/OVMF SMP2: full boot gate (`[acpi-manager] published HMCF` / `[driver-manager] retained HMCF` plus new `[acpi] config mint authority installed: snapshot` / `[init] installed PciConfigMint capability (handle 8)` required markers), injected restart cascade, restart-budget exhaustion into degraded mode (release; cascade also debug); AP-8/AP-9 on-target evidence requires the CI `qemu-smoke` job (AP-9 adds `[init] delegated unique PciConfigMint authority to DriverManager`, `[driver-manager] PCI manager ready (read-only config authority` and `[pci-manager] read-only config authority ready` as required markers) | Full AML/PCI-manager production stages remain separate release blockers; bare-metal firmware corpus not claimed; AP-8/AP-9 QEMU evidence pending CI |
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
