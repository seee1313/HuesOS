# Documentation reading guide

Start with [STATUS.md](STATUS.md): implementation, configured tests and physical
reports are separate. Then choose a reading path rather than treating every
roadmap as a current feature list.

## Build and use

1. [BUILD.md](BUILD.md) — pinned toolchain, ISO and QEMU.
2. [OPERATIONS.md](OPERATIONS.md) — runtime knobs, observation and storage off.
3. [USERSPACE.md](USERSPACE.md) — safe libcanvas API and userspace programs.
4. [TESTING.md](TESTING.md) — host, static, QEMU and hardware procedures.
5. [HARDWARE.md](HARDWARE.md) — reported physical results and coverage limits.

## Kernel boundaries

- [ARCHITECTURE.md](ARCHITECTURE.md), [SMP.md](SMP.md).
- [USER_MEMORY.md](USER_MEMORY.md), [RECOVERABLE_COPIES.md](RECOVERABLE_COPIES.md),
  [MEMORY_PROTECTION.md](MEMORY_PROTECTION.md), [FAULTS_AND_PANIC.md](FAULTS_AND_PANIC.md).
- [OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md), [DYNAMIC_PROCESSES.md](DYNAMIC_PROCESSES.md),
  [TASK_GENERATIONS.md](TASK_GENERATIONS.md), [HANDLE_TRANSFER.md](HANDLE_TRANSFER.md),
  [MULTI_OBJECT_WAIT.md](MULTI_OBJECT_WAIT.md), [VMAR_TRANSACTIONS.md](VMAR_TRANSACTIONS.md).
- [LOCK_ORDER.md](LOCK_ORDER.md), [UNSAFE_AUDIT.md](UNSAFE_AUDIT.md),
  [ALLOCATOR_HARDENING.md](ALLOCATOR_HARDENING.md), [QUOTAS.md](QUOTAS.md).

## Services, firmware and storage

- [UACPI.md](UACPI.md), [IOAPIC_ROUTING.md](IOAPIC_ROUTING.md).
- [NVME.md](NVME.md), [HXFS_V6.md](HXFS_V6.md), [KEY_BROKER.md](KEY_BROKER.md),
  [VERIFIED_BOOT_TPM.md](VERIFIED_BOOT_TPM.md).
- [STORAGE_PRODUCTION_GATE.md](STORAGE_PRODUCTION_GATE.md) is the storage release
  decision, not a claim that every design feature is ready.
- [FRAMEBUFFER_POLICY.md](FRAMEBUFFER_POLICY.md), [TERMINAL_RENDERING.md](TERMINAL_RENDERING.md),
  [DOOM.md](DOOM.md), [SHUTDOWN.md](SHUTDOWN.md).

## Future design and delivery

- [ROADMAP.md](ROADMAP.md), [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md).
- [SCHEDULER_RESEARCH.md](SCHEDULER_RESEARCH.md), [SCHEDULER_V2.md](SCHEDULER_V2.md),
  [SMP_V2.md](SMP_V2.md).
- [ACPI_RING3.md](ACPI_RING3.md), [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md),
  [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md),
  [ACPI_PCI_IMPLEMENTATION_PLAN.md](ACPI_PCI_IMPLEMENTATION_PLAN.md).
- `design/ADR_*.md` documents rejected alternatives and reopening criteria.

## Historical material

[STORAGE_NVME_FS_ROADMAP_v1.md](STORAGE_NVME_FS_ROADMAP_v1.md) is archived.
[design/ARCHITECTURAL_ANALYSIS.md](design/ARCHITECTURAL_ANALYSIS.md) retains earlier
findings; [MICROKERNEL_MIGRATION.md](MICROKERNEL_MIGRATION.md) retains migration
choices. Read them for rationale, not current verification status.

This is a curated entry point, not an exhaustive list of every file. Existing
subsystem documents and cross-links retain their original paths.
