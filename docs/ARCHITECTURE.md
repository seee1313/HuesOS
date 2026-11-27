# HuesOS Architecture

## Overview

For the reviewed implementation/evidence snapshot and document authority, see
[STATUS.md](STATUS.md).

HuesOS is a capability-based **microkernel** for `x86_64`, inspired by Google
Zircon (Fuchsia). It boots exclusively via **UEFI**, loaded by **Limine** (base
revision 3) as a higher-half ELF64 executable (`0xffffffff80000000`+) alongside
an Ed25519-signed **HBI v2.2** boot image module.

## Design Principles

1. **Minimal Kernel** — Firmware AML execution (`acpi-manager`), PCI/PCIe
   enumeration and BAR/IRQ allocation (`pci-manager`), storage (`driver-host-nvme`,
   `hxfs-service`, `key-broker`), USB 3.x (`driver-host-xhci`), networking
   (`net-service`, `wlan-service`), dynamic linkers (`ld-huesos`, `ld-pe`), and
   the shell (`hsh`) all run in isolated Ring-3 processes. Only memory
   management, scheduling, IPC, IRQ/GSI routing, hardware IOMMU page tables,
   capability enforcement, and the bounds-checked framebuffer/panic blitter live
   in Ring 0.
2. **Capability-Based Security** — Kernel objects are named only through
   per-process handles carrying monotonic `Rights`. There is no global kernel
   VFS or ambient root UID.
3. **Message-Passing & Shared-VMO IPC** — Processes communicate via `Channel`,
   `Port`, `Signal`, `WaitSet`, and page-backed `Vmo` handles.
4. **One Sanctioned Syscall Boundary** — Userspace code never issues raw
   `syscall` instructions directly; `libcanvas::raw` is the sole audited Ring-3
   entry point (with `huesos-std` layered safely on top for `/bin` utilities,
   and `PeHostApi` inside `ld-pe` bridging native Win64 DLLs).
5. **Policy Crates Forbidding `unsafe`** — Complex decision engines (`huesos-sched`,
   `huesos-pci`, `huesos-iommu`, `huesos-usb`, `huesos-fat`, `huesos-lifecycle`,
   `huesos-proclife`, `huesos-handlemove`, `huesos-waitset`, `huesos-extable`,
   `huesos-ioapic`, `huesos-quota`, `huesos-net`, `huesos-tls`,
   `huesos-ieee80211`, `huesos-wpa`, `huesos-rtw88`, `huesos-pe`, `huesos-hsh`)
   are standalone `#![no_std]`, `#![forbid(unsafe_code)]` host-tested crates.

## Crate Structure

```text
boot/kernel:   huesos-boot, huesos-kernel, huesos-arch, huesos-hal,
               huesos-pmm, huesos-alloc, huesos-object, huesos-syscalls,
               huesos-abi, huesos-sync, huesos-fb, huesos-bootux
sched/policy:  huesos-sched, huesos-lifecycle, huesos-proclife,
               huesos-handlemove, huesos-waitset, huesos-extable,
               huesos-ioapic, huesos-iommu, huesos-quota, hues-async
acpi/pci/hw:   huesos-uacpi, huesos-pci, huesos-usb, huesos-tpm, huesos-nvme
storage:       huesos-hxfs, huesos-hxfs-proto, huesos-blobfs,
               huesos-gpt, huesos-fat
net/wlan/tls:  huesos-net, huesos-tls, huesos-ieee80211,
               huesos-wpa, huesos-rtw88
loaders/shell: huesos-elf, huesos-pe, huesos-scudo, huesos-hsh
fuzzing:       huesos-decoder-fuzz, huesos-scudo-fuzz
userspace:     libcanvas, huesos-std, init, driver-manager,
               acpi-manager, uacpi-runtime, pci-manager, pci-hotplug-test,
               driver-host-input, driver-host-nvme, driver-host-xhci,
               hxfs-service, key-broker, shutdown-broker,
               net-service, wlan-service, ld-huesos, ld-pe, win64-runtime,
               terminal, hsh-bin, coreutils (46 binaries), fdisk, doom,
               fault-probe
```

## Boot Flow

1. **Limine** maps `huesos-boot` into the higher half, sets up long mode, and
   enters `kmain_entry` with the memory map, framebuffer, RSDP, and HBI v2.2
   module.
2. `huesos_arch::init_early()` initializes serial diagnostics, `EFER.NXE`, BSP
   GDT/TSS, IDT, `CpuLocal` (`GS_BASE`), SMEP/SMAP/UMIP, and `XSAVE`/`FXSAVE`
   SIMD state.
3. `huesos-pmm` initializes the physical frame bitmap and reserves the HBI
   module, kernel image, and page tables.
4. Explicit HHDM mappings are installed for ACPI reclaimable/NVS/RSDP tables and
   uncached/NX LAPIC/IOAPIC MMIO (Limine base revision 3 does not map reserved or
   ACPI ranges into the HHDM).
5. `huesos-alloc` initializes the 64 MiB buddy + slab kernel heap;
   `huesos-object` initializes the KOID/handle/object registries.
6. **SMP v2 bring-up** ([SMP_V2.md](SMP_V2.md)): parses CPUID `0x1F`/`0x0B`
   topology and uACPI barebones MADT (`xAPIC` and `x2APIC` 32-bit APIC IDs),
   allocates permanent 16 KiB unmapped-guard-paged `NX` stacks (`PML4[509]`
   arena), boots APs via phys `0x8000`, syncs BSP `IA32_PAT` (`WC` framebuffer
   parity), initializes per-CPU GDT/TSS/IDT/`STAR`/`LSTAR`/`SFMASK`/SIMD/scheduler,
   and gates AP execution on `APS_MAY_RUN`.
7. Verifies the HBI v2.2 Ed25519 signature, builds the immutable ACPI archive v2,
   initializes Intel VT-d (`DMAR`) or AMD-Vi (`IVRS`) hardware DMA translation
   ([IOMMU_VTD.md](IOMMU_VTD.md)) when firmware publishes a valid IOMMU table
   (falling back fail-closed to `Trusted` mode otherwise), creates `init`'s
   bootstrap handles (`BOOTFS` VMO, `FrameDraw`, `SystemControl`, `AcpiBroker`,
   `PciConfigMint`, `DeviceLeaseAuthority`, FADT SCI `Irq`, `VolumeKey`),
   releases APs, and enters Ring 3 `huesos-init`.
8. **`init` → `driver-manager` cascade**:
   - `driver-manager` supervises `acpi-manager` (`HMCF`, `HPCI` v2, `HIOM` v1,
     `SCI -> GPE -> Notify` hotplug events), `pci-manager` (sole PCI config
     executor + `HPIN` v1 inventory), `key-broker`, `driver-host-input`,
     `driver-host-nvme`, `driver-host-xhci`, `hxfs-service`, `net-service`, and
     `wlan-service`.
   - `init` launches `shutdown-broker` and `/bin/terminal.elf`, which spawns
     `/bin/hsh.elf` ([SHELL_AND_STD.md](SHELL_AND_STD.md)).

## SMP v2 & Scheduler v2

Specified and tracked in [SCHEDULER_V2.md](SCHEDULER_V2.md) and
[SMP_V2.md](SMP_V2.md):

- **Capacities & identity:** up to `MAX_CPUS = 256` dense CPU indices (mapped to
  32-bit hardware APIC IDs) and `MAX_TASKS = 8192` generation-tagged `TaskId`
  slots (`TaskSlotAllocator` + `TaskDirectory`).
- **Single-writer runqueues:** only the owner CPU mutates its `Scheduler`;
  cross-CPU wake, kill, policy, spawn, and reap operations publish into the
  target CPU's two-level atomic bitmap `TaskInbox` and send a directed
  reschedule IPI when needed.
- **Policies:** two-level request-based **EEVDF** (`Job` tree → per-Job `Thread`
  tree, `O(1)` virtual-time rollover, `yield_now()` slice forfeiture) preempted
  by admission-controlled **CBS** (`Deadline`) reservations charged in
  nanoseconds from `TscClock`.
- **Placement & TLB:** topology-aware spawn placement and idle pull (preferring
  completely idle physical cores before busy SMT siblings), plus per-`CR3`
  active-CPU tracking for targeted TLB shootdowns (`shootdown_range_for_cr3`).

## Kernel Object System

Every kernel resource implements `KernelObject` with a unique 64-bit `Koid` and
two-counter `RefAccount` lifecycle ([OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md)):

| `ObjectType` | Purpose |
|---|---|
| `Vmo` | Page-backed Virtual Memory Object (anonymous, physical MMIO, or DMA pool) |
| `Vmar` | Hierarchical Virtual Memory Address Region with transactional map/split-unmap/protect |
| `Process` | Isolated PML4 address space, handle table, `ProcessAbi` (`Elf64` / `Pe64`), exit waiters/ports |
| `Thread` | Execution context (kernel stack, saved GPRs, `XSAVE`/`FXSAVE` buffer, Ring-3 `FS_BASE`/`GS_BASE`) |
| `Job` | Hierarchical process container with VMO byte, CPU tick, and IPC queue quotas ([QUOTAS.md](QUOTAS.md)) |
| `Channel` | Bidirectional message-passing pipe (inline fast path for ≤64 B / ≤2 handles; transactional handle move) |
| `Port` | Asynchronous packet queue for interrupts, process exits, quota alerts, and `PORT_PACKET_DEVICE_GONE` |
| `Interrupt` | Capability-bound GSI / MSI / MSI-X bridge waking a `Port` |
| `Signal` | Level-triggered waitable user synchronization object |
| `Resource` | Ranged (`IoPort`, `Mmio`, `Irq`, `DmaPool`) or binary (`FrameDraw`, `SystemControl`, `VolumeKey`, `PciConfigMint`, `DeviceLeaseAuthority`) authority |
| `AcpiBroker` | Snapshot-bound Gate B `SystemIO`/`SystemMemory`/IRQ broker for `acpi-manager` ([ACPI_RING3.md](ACPI_RING3.md)) |
| `DeviceLease` | Generation-checked per-PCI-function authority (`DeviceId`, `LeaseGeneration`) revocable on removal/rebalance ([PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md)) |

## Syscall Boundary

Canonical syscall numbers (`..=98`) live in `huesos_abi::Syscall`. Major groups:

- **Memory & address spaces:** `VmoCreate`, `VmoRead`, `VmoWrite`, `VmoSetSize`,
  `VmarMap`, `VmarUnmap`, `VmarProtect`, `VmarCreateChild`, `VmarHeapExtend`.
- **IPC & synchronization:** `ChannelCreate`, `ChannelWrite`, `ChannelRead`,
  `PortCreate`, `PortQueue`, `PortWait`, `SignalCreate`, `SignalUpdate`,
  `WaitSetWait`, `FutexWait`, `FutexWake`.
- **Processes, threads, jobs & ABIs:** `ProcessCreate`, `ProcessCreateInJob`,
  `ProcessStart`, `ProcessWait`, `ProcessTerminate`, `ProcessBindExitPort`,
  `ProcessSetAffinityMask256`, `ProcessGetAffinityMask256`, `ProcessSetAbi`,
  `ThreadCreate`, `ThreadStart`, `ThreadSetGsBase`, `ThreadGetGsBase`,
  `SchedSetPolicy`, `JobDefault`, `JobCreate`, `JobSetLimits`, `JobBindQuotaPort`.
- **Hardware & platform capabilities:** `ResourceCreate`, `PciConfigMint`,
  `DeviceLeaseCreate`, `DeviceLeaseAttachDma`, `DeviceLeaseRevoke`,
  `PciHotplugTrigger`, `AcpiBrokerOp`, `InterruptCreate`, `InterruptBind`,
  `InterruptAck`, `FramebufferInfo`, `FramebufferBlit`.
- **Observability & clocks:** `ClockGetMonotonic`, `ClockGetMonotonicNs`,
  `SystemCpuCount`, `SystemSchedStats`, `SystemTaskQuery`, `SystemIommuStatus`,
  `HandleGetKoid`, `ObserveRead`, `KnobGet`/`KnobSet`, `HardHalt`.

Every pointer-bearing syscall validates lower-half bounds and page-table flags
under the process memory lock and copies via recoverable `.ex_table` routines
([USER_MEMORY.md](USER_MEMORY.md), [RECOVERABLE_COPIES.md](RECOVERABLE_COPIES.md)).

## Subsystems in Ring 3

- **ACPI, PCI/PCIe & IOMMU:** [ACPI_RING3.md](ACPI_RING3.md),
  [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md),
  [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md),
  [IOMMU_VTD.md](IOMMU_VTD.md).
- **USB 3.x (`xHCI`) & Storage (`NVMe`, `HxFS v7`):** [USB_XHCI.md](USB_XHCI.md),
  [NVME.md](NVME.md), [HXFS_DESIGN.md](HXFS_DESIGN.md),
  [KEY_BROKER.md](KEY_BROKER.md), [STORAGE_PRODUCTION_GATE.md](STORAGE_PRODUCTION_GATE.md).
- **Networking, 802.11 Wi-Fi & TLS 1.3:** [NETWORKING.md](NETWORKING.md).
- **Static/Dynamic ELF & Win64 PE32+ Loaders:** [EXECUTABLE_LOADERS.md](EXECUTABLE_LOADERS.md).
- **Shell (`hsh`), `huesos-std` & Coreutils:** [SHELL_AND_STD.md](SHELL_AND_STD.md).
- **Framebuffer, Terminal & Games:** [FRAMEBUFFER_POLICY.md](FRAMEBUFFER_POLICY.md),
  [TERMINAL_RENDERING.md](TERMINAL_RENDERING.md), [SNAKE.md](SNAKE.md),
  [DOOM.md](DOOM.md), [SHUTDOWN.md](SHUTDOWN.md).
