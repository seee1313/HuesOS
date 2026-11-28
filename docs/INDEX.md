# Documentation reading guide

Start with [STATUS.md](STATUS.md): implementation, configured tests, and physical
hardware reports are tracked separately. Choose a reading path below rather than
treating roadmaps as current feature claims.

## Build, operate, and develop userspace

1. [BUILD.md](BUILD.md) — pinned toolchain, build profiles, ISO, and QEMU.
2. [OPERATIONS.md](OPERATIONS.md) — runtime knobs, structured observations, and `STORAGE_OFF=1`.
3. [USERSPACE.md](USERSPACE.md) — `huesos-std` vs `libcanvas` and capability rules.
4. [SHELL_AND_STD.md](SHELL_AND_STD.md) — `hsh`, `@caps` attenuation, `huesos-std`, and the 46 `coreutils` binaries & TUIs.
5. [EXECUTABLE_LOADERS.md](EXECUTABLE_LOADERS.md) — static ELF64, `/lib/ld-huesos.so` dynamic linking, and native Win64 PE32+ (`/lib/ld-pe.so` + system DLLs).
6. [TESTING.md](TESTING.md) — host, static-safety, sanitizer, QEMU, and hardware test gates.
7. [HARDWARE.md](HARDWARE.md) — reported bare-metal smoke results and coverage limits.

## Kernel, SMP, and safety boundaries

- [ARCHITECTURE.md](ARCHITECTURE.md), [SCHEDULER_V2.md](SCHEDULER_V2.md), [SMP_V2.md](SMP_V2.md), [SCHEDULER_BENCHMARK.md](SCHEDULER_BENCHMARK.md).
- [USER_MEMORY.md](USER_MEMORY.md), [RECOVERABLE_COPIES.md](RECOVERABLE_COPIES.md),
  [MEMORY_PROTECTION.md](MEMORY_PROTECTION.md), [FAULTS_AND_PANIC.md](FAULTS_AND_PANIC.md).
- [OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md), [OBJECT_LIFECYCLE_POLICY.md](OBJECT_LIFECYCLE_POLICY.md),
  [DYNAMIC_PROCESSES.md](DYNAMIC_PROCESSES.md), [PROCESS_LIFECYCLE_REGRESSIONS.md](PROCESS_LIFECYCLE_REGRESSIONS.md),
  [TASK_GENERATIONS.md](TASK_GENERATIONS.md), [HANDLE_TRANSFER.md](HANDLE_TRANSFER.md),
  [MULTI_OBJECT_WAIT.md](MULTI_OBJECT_WAIT.md), [VMAR_TRANSACTIONS.md](VMAR_TRANSACTIONS.md).
- [LOCK_ORDER.md](LOCK_ORDER.md), [UNSAFE_AUDIT.md](UNSAFE_AUDIT.md),
  [ALLOCATOR_HARDENING.md](ALLOCATOR_HARDENING.md), [QUOTAS.md](QUOTAS.md), [FUZZING.md](FUZZING.md).

## Firmware, PCI, storage, networking, and display

- [ACPI_RING3.md](ACPI_RING3.md), [UACPI.md](UACPI.md), [IOAPIC_ROUTING.md](IOAPIC_ROUTING.md), [IOMMU_VTD.md](IOMMU_VTD.md).
- [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md), [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md), [USB_XHCI.md](USB_XHCI.md).
- [NVME.md](NVME.md), [HXFS_DESIGN.md](HXFS_DESIGN.md), [HXFS_V6.md](HXFS_V6.md),
  [KEY_BROKER.md](KEY_BROKER.md), [VERIFIED_BOOT_TPM.md](VERIFIED_BOOT_TPM.md),
  [BOOTFS.md](BOOTFS.md), [ASYNC_RUNTIME.md](ASYNC_RUNTIME.md).
- [STORAGE_PRODUCTION_GATE.md](STORAGE_PRODUCTION_GATE.md) — Stage-Z release checklist (storage remains not production-ready).
- [NETWORKING.md](NETWORKING.md) — `net-service` (VirtIO TCP/IP), `wlan-service` (`rtw88` 802.11 WPA2-CCMP), and `huesos-tls` (TLS 1.3).
- [AUDIO_AND_BTL.md](AUDIO_AND_BTL.md) — `/net/btl` Bluetooth Classic (`RTL8821CE` `btrtl` USB-HCI, SSP, L2CAP, SDP, `btsnoop`, PTA coex) and `audio-service` (`VirtIO-Sound` PCIe, `HARB` SPSC VMO mixer, A2DP `SBC` + `AVRCP`, Doom SFX & OPL2).
- [FRAMEBUFFER_POLICY.md](FRAMEBUFFER_POLICY.md), [TERMINAL_RENDERING.md](TERMINAL_RENDERING.md),
  [SNAKE.md](SNAKE.md), [DOOM.md](DOOM.md), [SHUTDOWN.md](SHUTDOWN.md).

## Roadmaps and Architecture Decision Records

- [ROADMAP.md](ROADMAP.md), [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md), [ARCHITECTURE_ROADMAP.md](ARCHITECTURE_ROADMAP.md).
- `design/` — [ADR_WRITABLE_MMAP.md](design/ADR_WRITABLE_MMAP.md),
  [ADR_ZSTD_BACKEND.md](design/ADR_ZSTD_BACKEND.md),
  [EXTENT_GENERATION_NONCE.md](design/EXTENT_GENERATION_NONCE.md),
  [HXFS_REPAIR_POLICY.md](design/HXFS_REPAIR_POLICY.md),
  [INIT_BOOT_UX.md](design/INIT_BOOT_UX.md).

## Historical material

Closed execution plans, superseded pre-v2 notes, and single-PR migration drafts
(including the closed `AP-0..AP-23` PR plan, pre-v2 `SMP.md`, `SCUDO_PORT_PLAN`,
`ACPI_GATE_B_POLICY`, `MODULARITY`, `BOOTFS_DOOM`, `DIRTY_RENDERING`, `TTY_FONT`,
`PANIC_FREE_PROCESS_LAUNCH`, and `SCHEDULER_RESEARCH`) were consolidated into
their authoritative subsystem documents in the 2026-11 documentation audit.
Consult git history for historical staging details.
