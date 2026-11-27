# HuesOS Roadmap

**Snapshot baseline:** `main` at `fdf41e3` (2026-11-27; through PR #293).

Authoritative implementation and evidence boundaries live in [STATUS.md](STATUS.md).
Storage release gates live in [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md) and
[STORAGE_PRODUCTION_GATE.md](STORAGE_PRODUCTION_GATE.md); PCI production gates
live in [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md). Both
`storage production-ready` and `PCI production-ready` remain deliberately `false`
until bare-metal and hardware-isolation gates close.

---

## Active Subsystems Roadmap

### 1. PCI / PCIe Production Qualification (`PCI_PRODUCTION_ROADMAP.md` Stages M.2, N.3, O)

Stages `A` through `J`, `K` (`AP-23` policy + `AP-24` live SCI/`Notify` →
`pci-hotplug-events` runtime handoff, `[76..92 MiB)` dynamic DMA slots, and
`Syscall::PciHotplugTrigger = 98`), `L`, `M.1`, `N.1`, `N.2` (Intel VT-d &
AMD-Vi hardware DMA domains, [IOMMU_VTD.md](IOMMU_VTD.md)), and `N.3`
(`AP-0..AP-24`) are implemented, and the legacy kernel PCI scan is permanently
removed (`tools/check-kernel-no-pci.py`). Remaining tracks before
`PCI production-ready = true`:

- **Stage O.1/O.2 (QMP hotplug soak) & Stage M.2 (`QuiesceRemap` driver):**
  exercise 1,000-cycle QEMU QMP Root-Port `device_add`/`device_del` hotplug
  storms and migrate a first non-storage driver onto live `QuiesceRemap` BAR
  relocation.
- **Stage O.3 — Multi-platform bare-metal qualification:** execute the documented
  Intel/AMD multi-generation chipset, PCIe switch/bridge, NVMe, and integrated
  xHCI bare-metal matrix.

### 2. Storage & `HxFS v7` Closure (`PRODUCTION_ROADMAP.md` / `STORAGE_PRODUCTION_GATE.md`)

Mutable `HxFS v7` (AES-GCM 64-bit extent nonces, LZ4, Hxblob, random-offset RMW,
`truncate`, symlinks, `chmod`, `StatFs`, persistent named snapshots, journal
replay, `scrub`/`fsck`, and `v6 → v7` migration) runs end-to-end over
`pci-manager` + `driver-host-nvme`. Remaining blockers before format freeze:

- **Stage E.3 — Full 24-hour endurance soak:** extend the automated soak gate
  from bounded CI windows to a 24-hour mixed workload with baseline delta checks.
- **Stage D — Physical Secure Boot & TPM PCR matrix:** record owner-verified
  bare-metal Secure Boot + hardware TPM 2.0 PCR sealing/mismatch runs.
- **Independent review & multi-vendor NVMe matrix:** complete external
  cryptographic/fsck review of `KeyBroker` + `HxFS v7` and qualify at least two
  physical NVMe controller families before freezing the v7 on-disk layout.

### 3. Networking & Wireless Expansion (`NETWORKING.md`)

Userspace `net-service` (VirtIO 1.0 Modern + `huesos-net` IPv4/DHCP/DNS/ICMP/UDP/TCP),
`wlan-service` (`huesos-ieee80211` + `huesos-wpa` WPA2-CCMP + `huesos-rtw88`
`RTL8821CE`), and `huesos-tls` (TLS 1.3 HTTPS) are operational. Next steps:

- **Bare-metal RF & Ethernet qualification:** multi-AP interoperability soak on
  physical `RTL8821CE` hardware plus wired PCIe Ethernet DriverHosts (e.g.,
  Intel `e1000e`/`igc`, Realtek `r8169`).
- **Protocol surface:** IPv6 dual-stack (`NDP`/`SLAAC`/TCP6/UDP6), passive/active
  listening socket readiness for userspace daemons, and hardware checksum/TSO
  offload negotiation.

### 4. Scheduler, CPU Hardening & New Device Classes

- **Hardware `CR3` PCID/`INVPCID` & SMT core-scheduling:** wire the host-tested
  `huesos_sched::hw::PcidTable` and `SmtCoreGate` policy engines into `huesos-arch`
  page-table switching and cross-sibling IPI barriers, and record bare-metal
  latency thresholds ([SCHEDULER_BENCHMARK.md](SCHEDULER_BENCHMARK.md)).
- **Audio DriverHosts & USB class expansion:** isolated userspace audio output
  (`Intel HDA` / `VirtIO-Sound`) over `DeviceLease`, plus full HID Report
  Descriptor parsing (beyond Boot Protocol), UASP, and isochronous endpoints on
  top of `huesos-usb` / `driver-host-xhci` ([USB_XHCI.md](USB_XHCI.md)).
- **Lifecycle & quota completion:** per-handle hard caps, page-table frame
  charging in `Job` quotas ([QUOTAS.md](QUOTAS.md)), and sustained concurrent
  cancellation stress ([OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md)).

---

## Completed Milestones Summary

- **AP-0…AP-24 — Ring-3 ACPI, Userspace PCI Manager, IOMMU & Hotplug (PRs #240–#262, #283, #288, #290, #292, #293):**
  immutable ACPI archive v2, isolated Ring-3 `uacpi-runtime` (`HMCF`, `HPCI` v2
  `_SEG`/`_BBN`/`_CRS`/`_PRT`/`_OSC`, `HIOM` v1 `DMAR`/`IVRS`, FADT SCI → GPE →
  `Notify` hotplug forwarding), `PciConfigMint` RO→RW ECAM + `B.4` write policy,
  live Type-0/Type-1 BAR & 64-bit bridge window sizing/planning with rollback
  and hotplug reserves, kernel `DeviceLease` + `PORT_PACKET_DEVICE_GONE`,
  hardware Intel VT-d & AMD-Vi second-stage DMA domains (`huesos-iommu` +
  `vtd.rs`/`amd_vi.rs`), `[76..92 MiB)` dynamic hotplug DMA slots +
  `Syscall::PciHotplugTrigger = 98`, MSI-X/MSI/INTx + `DmaPoolGrant` binding for
  NVMe / `xHCI` / VirtIO-Net / `rtw88`, deletion of kernel PCI bootstrap scan,
  zero-bus-traffic `HPIN` v1 inventory (`pci -v`, `pci --iommu`), and
  `HotplugCoordinator` / `Rebalance` / `QuiesceRemap` engines.
- **Ring-3 USB 3.x (`xHCI`) & `#![forbid(unsafe_code)]` FAT32 `/mnt/usb0` (PRs #291, #292):**
  `#![forbid(unsafe_code)]` `huesos-usb` (xHCI 1.x rings/contexts, Ch9, USB
  2.0/3.x Hub, HID Boot Keyboard/Mouse, BOT SCSI, `TrbCompletionTable` futures),
  zero-heap Ring-3 `driver-host-xhci` under IOMMU isolation, PS/2 + USB keyboard
  multiplexing, `HUSB` v1 `lsusb`, and `#![forbid(unsafe_code)]` `huesos-fat`
  (FAT16/FAT32 + VFAT LFN R/W) mounted transparently at `/mnt/usb0`.
- **Scheduler v2 & SMP v2 (PRs #280, #281, #287):** `MAX_CPUS = 256`,
  `MAX_TASKS = 8192`, single-writer per-CPU runqueues + bitmap `TaskInbox`,
  two-level `Job`→`Thread` EEVDF (`O(1)` rollover, `yield_now()` forfeiture) +
  CBS reservations over `TscClock`, `x2APIC`/`xAPIC` 32-bit APIC IDs, CPUID
  `0x1F`/`0x0B` topology, AP `IA32_PAT` sync (`WC`), `XSAVE`/`FXSAVE`, 16 KiB
  guard-paged `NX` stacks, per-`CR3` targeted TLB shootdowns, `TSC-deadline`
  timer, and futexes.
- **Networking, 802.11 WPA2-CCMP & TLS 1.3 (PRs #282–#286):** `huesos-net`,
  `net-service`, `huesos-ieee80211`, `huesos-wpa`, `huesos-rtw88`, `wlan-service`,
  `huesos-tls`, and `netctl`/`wlanctl`/`ping`/`curl`.
- **Dynamic ELF64 & Native Win64 PE32+ (PRs #263, #264, #282, #283):**
  `/lib/ld-huesos.so` (`BIND_NOW`, `RELRO`, TLS, `canvas_dlopen_*`, `libcanvas.so`)
  and `huesos-pe` + `/lib/ld-pe.so` + native `ntdll`/`kernel32`/`ucrtbase`/
  `msvcrt`/`ws2_32`/`bcrypt`/`advapi32` DLLs with `GS_BASE` `SwapGsGuard` and SEH
  virtual unwind.
- **`HxFS v7`, `huesos-std`, Scripting `hsh` & Truecolor TUIs (PRs #265–#281):**
  `HxFS v7` symlinks/snapshots/`StatFs`/random-offset RMW/`truncate`, Scudo-backed
  `huesos-std`, Fish-UX scripting `hsh` with N-stage streaming pipes, job
  control/`Ctrl-C` (`ProcessTerminate`), `@caps` attenuation, 46 `coreutils`
  binaries, and full-screen truecolor `btop` and `fdisk`/`cfdisk` TUI studios.
