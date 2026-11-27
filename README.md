# HuesOS

**HuesOS** is an x86_64 capability-based microkernel operating system written in
Rust, inspired by Google Zircon (Fuchsia). It boots exclusively via UEFI
(Limine base revision 3) and runs isolated Ring-3 services, drivers, dynamic
ELF64 and native Win64 PE32+ executables, an interactive shell (`hsh`), storage
(`HxFS v7` over NVMe and `FAT16/FAT32` over USB 3.x `xHCI`), and networking
(`TCP/IPv4`, `802.11 WPA2-CCMP`, `TLS 1.3`) strictly over capability-checked IPC
and hardware IOMMU DMA domains.

## Status: Active Development (Not Production-Ready)

Current implementation/evidence map: [docs/STATUS.md](docs/STATUS.md).
Reading guide: [docs/INDEX.md](docs/INDEX.md). Workflow definitions and roadmap
ledgers are not substitutes for verification on a specific commit or physical
machine.

## Verified Working (Host Suites + QEMU CI Matrix)

- ✅ **UEFI + Signed HBI v2.2 boot**: Limine protocol 0.6.5 (base revision 3),
  Ed25519-verified HBI packaging (`tools/hbi-gen`), TPM-sealed/KeyBroker volume
  key handoff, and bitmap PMM over the real Limine memory map.
- ✅ **Paging & supervisor memory protection**: independent per-process PML4s,
  W^X user mappings, SMEP/SMAP/UMIP where supported, HHDM base-rev-3 explicit
  ACPI/MMIO mappings, and recoverable `.ex_table` user copies (`huesos-extable`).
- ✅ **SMP v2 & Scheduler v2 (`MAX_CPUS = 256`, `MAX_TASKS = 8192`)**: MADT
  `xAPIC`/`x2APIC` 32-bit APIC IDs, `CPUID 0x1F/0x0B` topology discovery, AP
  `IA32_PAT` sync (`WC` framebuffer parity on all cores), per-task `XSAVE`/`FXSAVE`
  SIMD state, 16 KiB unmapped-guard-paged `NX` kernel stacks, per-`CR3` targeted
  TLB shootdowns, `IA32_TSC_DEADLINE` / periodic LAPIC timer, two-level
  request-based **EEVDF** (`Job` + `Thread`) + **CBS** deadline reservations,
  single-writer per-CPU runqueues with lock-free bitmap remote inboxes, and
  topology-aware idle pull/placement.
- ✅ **Ring-3 ACPI, Userspace PCI Manager, Hardware IOMMU & Hotplug (`AP-0..AP-24`, `Stage N.2`)**:
  immutable kernel ACPI archive v2, isolated Ring-3 `uacpi-runtime`
  (`acpi-manager` publishing `HMCF`, `HPCI` v2 `_SEG`/`_BBN`/`_CRS`/`_PRT`/`_OSC`,
  `HIOM` `DMAR`/`IVRS`, and `SCI -> GPE -> Notify` hotplug events), sole
  config-space ownership in `pci-manager` (ECAM + forced-legacy `CF8/CFC`), live
  BAR/bridge window planning with rollback and hotplug reserves, kernel
  `DeviceLease` revocation (`PORT_PACKET_DEVICE_GONE`), hardware **Intel VT-d**
  (`DMAR`) & **AMD-Vi** (`IVRS`) second-stage DMA domains (`huesos-iommu` +
  `Syscall::DeviceLeaseAttachDma = 96`, synchronous teardown on `revoke`/`Drop`),
  bounded live PCI hotplug (`HPHG` v1 + `[76..92 MiB)` dynamic DMA slots inside
  `BOOT_DMA_POOL_LEN = 92 MiB` + `Syscall::PciHotplugTrigger = 98`), MSI-X/MSI/INTx
  + `DmaPoolGrant` handoff, and zero-bus-traffic `HPIN` v1 inventory (`pci -v`,
  `pci --iommu`). Zero PCI enumeration remains in the kernel
  (`tools/check-kernel-no-pci.py`).
- ✅ **Userspace NVMe & mutable `HxFS v7`**: Ring-3 `driver-host-nvme` +
  `hxfs-service` with CoW checkpoints, 64-bit AES-GCM extent nonces, LZ4
  compression, Hxblob, random-offset RMW writes & `truncate`, symlinks
  (`O_NOFOLLOW`), POSIX modes (`chmod`), `StatFs`, persistent named snapshots,
  journal replay, power-fail recovery, online `scrub`/`fsck`, and explicit
  `v6 → v7` migration (`tools/hxfs-migrate`).
- ✅ **Zero-Heap Ring-3 USB 3.x (`xHCI`) & FAT32 `/mnt/usb0`**: `#![forbid(unsafe_code)]`
  `huesos-usb` (xHCI 1.x rings/contexts, USB 2.0/3.x Hub, HID Boot Keyboard/Mouse,
  BOT SCSI, `TrbCompletionTable` futures) + zero-heap `driver-host-xhci` under
  hardware IOMMU isolation, PS/2 + USB keyboard multiplexing in `driver-manager`,
  zero-bus-traffic `HUSB` v1 inventory (`lsusb`), and `#![forbid(unsafe_code)]`
  `huesos-fat` (FAT16/FAT32 + VFAT LFN R/W) transparently mounted at `/mnt/usb0`.
- ✅ **Dynamic ELF64 & Native Win64 PE32+ loaders**: `/lib/ld-huesos.so`
  (`BIND_NOW`, full `RELRO`, TLS, `canvas_dlopen_*`, shared `/lib/libcanvas.so`)
  and `/lib/ld-pe.so` + native `x86_64-huesos-pe64` system DLLs (`ntdll.dll`,
  `kernel32.dll`, `ucrtbase.dll`, `msvcrt.dll`, `ws2_32.dll`, `bcrypt.dll`,
  `advapi32.dll`) with Ring-3 `GS_BASE` (`TEB`/`PEB`) and `.pdata`/`.xdata` SEH
  unwinding (`huesos-pe`).
- ✅ **Userspace Networking, Wi-Fi & TLS 1.3**: `#![forbid(unsafe_code)]`
  `huesos-net` (`Ethernet`/`ARP`/`IPv4`/`ICMP`/`UDP`/`DHCP`/`DNS`/`TCP`) inside
  `net-service` (VirtIO 1.0 Modern PCIe NIC + `wlan-service` dual-uplink),
  `huesos-ieee80211` + `huesos-wpa` (`WPA2-PSK` / `AES-128-CCMP`) + `huesos-rtw88`
  (`RTL8821CE` PCIe HAL), and pure-Rust `huesos-tls` (TLS 1.3 + X.509v3 CA
  verification powering `/bin/curl.elf`).
- ✅ **Interactive userland (`terminal`, `hsh`, `huesos-std`, 46 `coreutils` binaries)**:
  buffered dirty-row truecolor terminal (`Cozette 6×13` default), `hsh` with
  Fish-style highlighting/completion, scripting, N-stage streaming Channel
  pipelines, job control/`Ctrl-C` (`ProcessTerminate`), `@caps(...)` capability
  attenuation, Scudo-hardened `huesos-std`, full-screen truecolor `btop` and
  `fdisk`/`cfdisk` TUI studios, `nano`, Snake, and Freedoom (`doomgeneric`).

## Known Limitations & Open Gates

- **Storage & PCI production gates remain `false`:** `HxFS v7` format freeze,
  independent cryptographic review, 24-hour hardware soak, and multi-vendor
  bare-metal matrices remain open ([docs/STORAGE_PRODUCTION_GATE.md](docs/STORAGE_PRODUCTION_GATE.md),
  [docs/PCI_PRODUCTION_ROADMAP.md](docs/PCI_PRODUCTION_ROADMAP.md)). Bare-metal
  first boots should still use `STORAGE_OFF=1` unless testing disposable media.
- **PCI / IOMMU remaining tracks (`Stages M.2, N.3, O`):** per-lease Intel VT-d
  (`DMAR`) and AMD-Vi (`IVRS`) second-stage DMA page tables are active in Ring 0
  ([docs/IOMMU_VTD.md](docs/IOMMU_VTD.md), falling back fail-closed to `Trusted`
  when absent), while hardware interrupt remapping (`Stage N.3`), the first live
  `QuiesceRemap` driver (`Stage M.2`), 1,000-cycle QMP Root-Port hotplug soak
  (`Stage O.2`), and bare-metal qualification (`Stage O.3`) remain open.
- **USB class coverage:** USB 2.0/3.x Hubs, HID Boot Keyboard/Mouse, and BOT
  mass-storage drives work end-to-end ([docs/USB_XHCI.md](docs/USB_XHCI.md));
  isochronous endpoints, arbitrary HID Report Descriptors beyond Boot Protocol,
  and UASP remain open.
- **Scheduler/CPU hardware features:** `PcidTable` and `SmtCoreGate` policy
  models live in `huesos-sched`, while hardware `CR3` PCID/`INVPCID` activation
  and cross-SMT core-scheduling barriers remain future work.
- **Networking scope:** IPv4 client networking (`DHCP`/`DNS`/`ICMP`/`UDP`/`TCP`/
  `TLS 1.3`) is implemented; IPv6 and broad physical Ethernet/Wi-Fi chipset
  coverage remain open.
- **Quotas & lifecycle:** Job memory/CPU/IPC queue accounting and generation-safe
  process/task reaping are wired; per-handle hard caps, page-table metadata
  charging, and long-haul cancellation stress remain open ([docs/QUOTAS.md](docs/QUOTAS.md),
  [docs/OBJECT_LIFECYCLE.md](docs/OBJECT_LIFECYCLE.md)).
- **Framebuffer text:** bitmap ASCII/box-drawing glyphs only (no Unicode
  complex-script shaping or GPU 3D acceleration).

## Quick Start

```bash
# Restore pinned Rust toolchain, QEMU, swtpm, cargo-audit/cargo-fuzz on Ubuntu/Debian
bash scripts/restore-dev-env.sh
source "$HOME/.cargo/env"

# Enforce safety budget, lock ranks, policy crates, doc links, and formatting
make audit-check

# Run host unit tests across hardware-independent and policy crates
make test

# Build + package a bootable UEFI ISO + boot in QEMU (SMP 2)
make run
make run PROFILE=release
```

See [docs/BUILD.md](docs/BUILD.md) for full build profiles (`iso-release` vs
`boot-selftest`) and [docs/TESTING.md](docs/TESTING.md) for QEMU smoke/soak and
sanitizer suites.

## Documentation Map

Start at [docs/INDEX.md](docs/INDEX.md) and [docs/STATUS.md](docs/STATUS.md):

- **Core kernel & SMP:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
  [docs/SCHEDULER_V2.md](docs/SCHEDULER_V2.md), [docs/SMP_V2.md](docs/SMP_V2.md),
  [docs/USER_MEMORY.md](docs/USER_MEMORY.md), [docs/FAULTS_AND_PANIC.md](docs/FAULTS_AND_PANIC.md),
  [docs/LOCK_ORDER.md](docs/LOCK_ORDER.md), [docs/UNSAFE_AUDIT.md](docs/UNSAFE_AUDIT.md).
- **ACPI, PCI, IOMMU, USB & storage:** [docs/ACPI_RING3.md](docs/ACPI_RING3.md),
  [docs/PCI_MANAGER_ARCHITECTURE.md](docs/PCI_MANAGER_ARCHITECTURE.md),
  [docs/PCI_PRODUCTION_ROADMAP.md](docs/PCI_PRODUCTION_ROADMAP.md),
  [docs/IOMMU_VTD.md](docs/IOMMU_VTD.md),
  [docs/USB_XHCI.md](docs/USB_XHCI.md),
  [docs/NVME.md](docs/NVME.md), [docs/HXFS_DESIGN.md](docs/HXFS_DESIGN.md),
  [docs/STORAGE_PRODUCTION_GATE.md](docs/STORAGE_PRODUCTION_GATE.md).
- **Userspace, loaders & networking:** [docs/USERSPACE.md](docs/USERSPACE.md),
  [docs/SHELL_AND_STD.md](docs/SHELL_AND_STD.md),
  [docs/EXECUTABLE_LOADERS.md](docs/EXECUTABLE_LOADERS.md),
  [docs/NETWORKING.md](docs/NETWORKING.md), [docs/OPERATIONS.md](docs/OPERATIONS.md).
- **Hardware & roadmap:** [docs/HARDWARE.md](docs/HARDWARE.md),
  [docs/ROADMAP.md](docs/ROADMAP.md), [docs/PRODUCTION_ROADMAP.md](docs/PRODUCTION_ROADMAP.md).

## Project Structure

```text
HuesOS/
├── crates/
│   ├── huesos-boot, huesos-kernel, huesos-arch, huesos-hal, huesos-pmm, huesos-alloc
│   ├── huesos-object, huesos-syscalls, huesos-abi, huesos-sync, huesos-fb, huesos-bootux
│   ├── huesos-sched, huesos-lifecycle, huesos-proclife, huesos-handlemove,
│   │   huesos-waitset, huesos-extable, huesos-ioapic, huesos-iommu, huesos-quota, hues-async
│   ├── huesos-uacpi, huesos-pci, huesos-usb, huesos-tpm, huesos-nvme, huesos-gpt, huesos-fat
│   ├── huesos-hxfs, huesos-hxfs-proto, huesos-blobfs
│   ├── huesos-net, huesos-tls, huesos-ieee80211, huesos-wpa, huesos-rtw88
│   ├── huesos-elf, huesos-pe, huesos-scudo, huesos-hsh
│   ├── huesos-decoder-fuzz, huesos-scudo-fuzz
│   └── huesos-userspace/
│       ├── libcanvas, huesos-std
│       ├── init, driver-manager, acpi-manager, pci-manager, uacpi-runtime
│       ├── driver-host-input, driver-host-nvme, driver-host-xhci,
│       │   hxfs-service, key-broker, shutdown-broker, pci-hotplug-test
│       ├── net-service, wlan-service
│       ├── ld-huesos, ld-pe, win64-runtime (ntdll, kernel32, ucrtbase, msvcrt, ws2_32, ...)
│       └── terminal, hsh-bin, coreutils (46 binaries), fdisk, doom, fault-probe
├── scripts/               # QEMU CI gates, ISO/HBI builders, dev-env bootstrap
├── tools/                 # Safety/lock/policy gates, hbi-gen, hxfs-migrate, benchmarks
├── third_party/           # Vendored Limine, OVMF, uACPI, DoomGeneric, Freedoom, CA bundle
├── docs/                  # Subsystem contracts, status map, and production gates
└── Makefile
```

## Contributing & Licensing

See [CONTRIBUTING.md](CONTRIBUTING.md) for strict safety-budget, lock-ordering,
and verification rules (`make audit-check` must never regress).

First-party HuesOS Rust code is MIT-licensed (`LICENSE`). Third-party vendored
components retain their upstream licenses: DoomGeneric (`GPL-2.0-only`, isolated
userspace binary), Freedoom (`BSD-3-Clause`), Limine (`BSD-2-Clause`), OVMF/edk2
(`BSD-2-Clause-Patent`), uACPI (`MIT`), and Mozilla root certificates (`MPL-2.0`).
