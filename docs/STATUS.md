# HuesOS status and evidence map

Status reviewed against `main` at `71776eb` (2026-10-09). This is a versioned
snapshot, not a live dashboard and not a claim that every current CI job passed.
The later lifecycle-regression branch is deliberately not assumed merged here.

## Read this first

Implementation, host tests, QEMU evidence and physical hardware evidence are
separate dimensions. A workflow definition is a configured gate, not its result.
A checked box in an old roadmap is not a current release approval.

| Area | Implemented boundary | Host coverage / QEMU gate | Physical evidence / remaining boundary |
| --- | --- | --- | --- |
| Boot and ring3 | Limine UEFI, independent address spaces, ELF launch and syscalls | Host ELF/PMM/object suites; `scripts/ci-qemu-smoke.sh` checks ring3, VMO, IPC and terminal markers | One MSI Modern 15 B5M smoke report; not a compatibility certification |
| Signed boot image | HBI v2.2 signature verification; development keys are not release keys | `scripts/ci-qemu-hbi-signature-smoke.sh`, secure-boot/TPM scripts are configured gates | Physical Secure Boot/TPM security matrix remains required |
| User-copy | Bounds/page-table validation, process memory lock, extable copies; sealed typed record allowlist and zeroed output padding | Syscall host suite; default user-pointer diagnostics; `scripts/ci-qemu-smep-smap-smoke.sh` on CPU max | Real CPU feature evidence must distinguish enabled controls from degraded mode |
| Objects and processes | Registry uses RefAccount; ProcessLifecycle, exit status, counted waiters, port notifications, deferred teardown and bounded graveyard wired | Object/policy host suites and 32-exit init probe; inspect run logs, not marker wording alone | Full-system baseline return, cancellations and longer concurrent storms need separate evidence |
| Task identities and SMP | Global TaskSlotAllocator/TaskDirectory; stable generation-bearing TaskId; owner-local scheduling and token-mediated remote operations | `huesos-sched` host tests exist; base make test does not explicitly select this package. Kernel and QEMU boot tests are complementary | Known pending-operation carry-over in the current reaper-style reuse sequence; see TASK_GENERATIONS. CPU ownership is not encoded in TaskId. EEVDF/CBS/SMP v2 target design is only partially integrated |
| IRQ routing | Multi-controller route manager, dynamic vectors, typed IRQ/GSI objects, level ACK | IOAPIC host tests; keyboard QMP userspace test; edu level/raw-GSI kernel probe | Kernel-Port probe is not proof of raw-GSI userspace syscall path or real-device coverage |
| Job quotas | Hierarchical Job tree, VMO memory/CPU tick charging and bounded IPC queues; public Job controls | Quota/object host suites; integration stress still required | Per-handle hard caps and page-table metadata accounting are not complete |
| ACPI / PCI | Kernel immutable ACPI archive and broker; isolated userspace uACPI runtime; current PCI bootstrap/migration shim | Host decoders; ACPI restart/boot gates | Full AML/PCI-manager production stages remain separate release blockers |
| NVMe / HxFS | Userspace driver and mutable filesystem foundation, versioned policies and recovery paths; production status remains false | Host/storage feature gates and QEMU fault/soak scripts; no new storage test result asserted by this docs change | Dedicated two-vendor NVMe, format approval and independent security review remain open; no physical storage verification inferred from the laptop report |
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
  [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md),
  [BARE_METAL_SECURITY_EVIDENCE.md](BARE_METAL_SECURITY_EVIDENCE.md).
- **Target designs:** [SCHEDULER_V2.md](SCHEDULER_V2.md), [SMP_V2.md](SMP_V2.md),
  [ACPI_RING3.md](ACPI_RING3.md), [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md).
  Design acceptance is not implementation completion.
- **Current work queues:** [ROADMAP.md](ROADMAP.md),
  [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md),
  [ACPI_PCI_IMPLEMENTATION_PLAN.md](ACPI_PCI_IMPLEMENTATION_PLAN.md).
- **History:** [STORAGE_NVME_FS_ROADMAP_v1.md](STORAGE_NVME_FS_ROADMAP_v1.md) is
  explicitly archived; [design/ARCHITECTURAL_ANALYSIS.md](design/ARCHITECTURAL_ANALYSIS.md)
  and [MICROKERNEL_MIGRATION.md](MICROKERNEL_MIGRATION.md) contain historical findings
  and decisions, not an up-to-date feature checklist.

See [INDEX.md](INDEX.md) for a newcomer reading order. Historical files keep their
paths so existing links and PR references remain usable.

## Maintenance contract

When changing a boundary, update the subsystem contract and this snapshot in the
same PR. Record implementation and verification separately. State the observed
CPU/profile/commit and limitations; never turn a configured gate into a pass.
Do not erase still-open failure modes merely because ordinary boot succeeds.
Update the reviewed base above when reviewing code, not automatically for a
spelling change. Full green GitHub CI, independent review and hardware evidence
must not be inferred from a local docs-only verification.
