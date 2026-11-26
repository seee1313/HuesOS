# HuesOS Roadmap

**Snapshot baseline:** `main` at `52be571` (2026-11-23; through PR #288).

Authoritative implementation and evidence boundaries live in [STATUS.md](STATUS.md).
Storage release gates live in [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md) and
[STORAGE_PRODUCTION_GATE.md](STORAGE_PRODUCTION_GATE.md); PCI production gates
live in [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md). Both
`storage production-ready` and `PCI production-ready` remain deliberately `false`
until bare-metal and hardware-isolation gates close.

---

## Active Subsystems Roadmap

### 1. PCI / PCIe Production Qualification (`PCI_PRODUCTION_ROADMAP.md` Stages M.2, N.2, O)

Stages `A` through `J`, `K` (policy + boot self-check), `L`, `M.1`, and
`N.1`/`N.3` (`AP-0..AP-23`) are merged on `main`, and the legacy kernel PCI scan
is permanently removed (`tools/check-kernel-no-pci.py`). Remaining tracks before
`PCI production-ready = true`:

- **Stage N.2 — Hardware IOMMU DMA isolation (`PCI Isolated Profile`):** program
  Intel VT-d (`DMAR`) and AMD-Vi (`IVRS`) second-stage DMA translation tables in
  the kernel, bind `DeviceLease` lifetimes to per-device IOMMU domains, and pass
  negative unauthorized-DMA fault tests (replacing `dma_isolation=trusted` on
  capable platforms).
- **Stage K.2 (live runtime) & Stage M.2 (`QuiesceRemap` driver):** wire live
  PCIe Root Port hotplug interrupts to runtime `DriverHost` spawn/teardown in
  QEMU and migrate a first non-storage driver onto live `QuiesceRemap` BAR
  relocation.
- **Stage O — Multi-platform bare-metal qualification:** execute the documented
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
- **USB xHCI & Audio DriverHosts:** Ring-3 USB 3.x (`xHCI`) controller/HID/mass-storage
  driver host over `DeviceLease` and isolated userspace audio output (Intel HDA /
  VirtIO-Sound).
- **Lifecycle & quota completion:** per-handle hard caps, page-table frame
  charging in `Job` quotas ([QUOTAS.md](QUOTAS.md)), and sustained concurrent
  cancellation stress ([OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md)).

---

## Completed Milestones Summary

- **AP-0…AP-23 — Ring-3 ACPI & Userspace PCI Manager (PRs #240–#262, #283, #288):**
  immutable ACPI archive v2, isolated Ring-3 `uacpi-runtime` (`HMCF`, `HPCI` v2
  `_SEG`/`_BBN`/`_CRS`/`_PRT`/`_OSC`, `HIOM` v1 `DMAR`/`IVRS`), `PciConfigMint`
  RO→RW ECAM + `B.4` write policy, live Type-0/Type-1 BAR & 64-bit bridge window
  sizing/planning with rollback and hotplug reserves, kernel `DeviceLease` +
  `PORT_PACKET_DEVICE_GONE`, MSI-X/MSI/INTx + `DmaPoolGrant` binding for NVMe /
  VirtIO-Net / `rtw88`, deletion of kernel PCI bootstrap scan, zero-bus-traffic
  `HPIN` v1 inventory (`pci -v`), and `HotplugCoordinator` / `Rebalance` /
  `QuiesceRemap` engines.
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
  control/`Ctrl-C` (`ProcessTerminate`), `@caps` attenuation, 45 `coreutils`, and
  full-screen truecolor `btop` and `fdisk`/`cfdisk` TUI studios.
