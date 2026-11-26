# HuesOS status and evidence map

Status reviewed against `main` at `52be571` (2026-11-23; through PR #288). This
is a versioned snapshot, not a live dashboard and not a claim that every current
CI job passed. Docs-only follow-ups do not change implementation status.

## Read this first

Implementation, host tests, QEMU evidence, and physical hardware evidence are
separate dimensions. A workflow definition is a configured gate, not its result.
A checked box in a roadmap is not a release approval.

| Area | Implemented boundary | Host coverage / QEMU gate | Physical evidence / remaining boundary |
| --- | --- | --- | --- |
| Boot and ring3 | Limine UEFI base-rev-3, independent PML4s, W^X ELF/PE launch, capability syscalls, Scudo userspace heap (`huesos-scudo`) | Host ELF/PMM/Scudo/object suites; `scripts/ci-qemu-smoke.sh` checks ring3, VMO, IPC, `std-smoke`, and `hsh` startup smokes | One MSI Modern 15 B5M smoke report; not a broad compatibility certification |
| Signed boot image | HBI v2.2 Ed25519 verification, KeyBroker one-shot volume key handoff, TPM unseal path | `scripts/ci-qemu-hbi-signature-smoke.sh`, `ci-qemu-secure-boot-smoke.sh`, `ci-qemu-tpm-sealed-key-smoke.sh`, `ci-qemu-key-broker-fail-smoke.sh` | Physical Secure Boot/TPM PCR matrix and production key ceremony remain required |
| User-copy & CPU hardening | Bounds/page-table validation, process memory lock, `.ex_table` recoverable copies, sealed `UserRecord` allowlist, SMEP/SMAP/UMIP enablement | Syscall/extable host suites; `scripts/ci-qemu-extable-smoke.sh` and `scripts/ci-qemu-smep-smap-smoke.sh` | Real-CPU feature evidence must distinguish enabled hardware controls from degraded mode |
| Objects, processes & quotas | `RefAccount` registry, `ProcessLifecycle`, exit ports, foreign `ProcessTerminate`, deferred teardown, bounded graveyard, hierarchical `Job` VMO/CPU/IPC quotas | Policy/object host suites (`huesos-lifecycle`, `huesos-proclife`, `huesos-quota`, `huesos-handlemove`, `huesos-waitset`), 4096-exit graveyard tests, 32-exit init probe | Per-handle hard caps, page-table metadata charging, and long-haul cancellation storms remain open |
| Scheduler v2 & SMP v2 | `MAX_CPUS = 256`, `MAX_TASKS = 8192`, generation-tagged `TaskId`/`TaskDirectory`, single-writer per-CPU runqueues + bitmap `TaskInbox`, two-level `Job`→`Thread` EEVDF + CBS reservations over `TscClock`, `x2APIC`/`xAPIC` 32-bit APIC IDs, `CPUID 0x1F/0x0B` topology, AP `IA32_PAT` sync (`WC`), `XSAVE`/`FXSAVE` SIMD, 16 KiB guard-paged `NX` stacks, per-`CR3` targeted TLB shootdowns, `IA32_TSC_DEADLINE`/LAPIC timer, futexes, and topology-aware idle pull | `huesos-sched` host suite (EEVDF, CBS, `TaskDirectory`, `PcidTable`, `SmtCoreGate`); QEMU debug/release SMP 1/2/4/8 boot and soak gates | Hardware `CR3` PCID/`INVPCID` activation, cross-SMT core-scheduling barriers, and multi-platform bare-metal latency benchmarks remain open |
| IRQ routing | Multi-controller IOAPIC route manager, dynamic vectors, typed IRQ/GSI objects, level ACK | `huesos-ioapic` host suite; `scripts/ci-qemu-ioapic-delivery.sh`; `scripts/ci-qemu-irq-level-smoke.sh` | Bare-metal multi-IOAPIC and non-QEMU device GSI coverage remain open |
| ACPI, PCI Manager & VT-d IOMMU (`AP-0..AP-23`, `N.2`) | Immutable ACPI archive v2 + broker; Ring-3 `uacpi-runtime` & `acpi-manager` (`HMCF`, `HPCI` v2 `_SEG`/`_BBN`/`_CRS`/`_PRT`/`_OSC`, `HIOM` `DMAR`/`IVRS`); sole config executor `pci-manager` (ECAM + forced-legacy, `B.4` write policy, live BAR/bridge planner with rollback & hotplug reserves, `HPIN` v1 `pci -v`), kernel `DeviceLease` + `PORT_PACKET_DEVICE_GONE`, Intel VT-d second-stage DMA domains (`huesos-iommu` + `vtd.rs`, synchronous teardown on `revoke`/`Drop`, `RMRR`, `FRCD` fault drain, `pci --iommu`), MSI-X/MSI/INTx + `DmaPoolGrant` driving `driver-host-nvme`/`net-service` (`VIRTIO_F_ACCESS_PLATFORM`)/`wlan-service`; kernel PCI scan removed (`tools/check-kernel-no-pci.py`) | `huesos-abi`, `huesos-pci`, & `huesos-iommu` host suites (hotplug storms, rebalance fault injection, `DMAR`/`IVRS`, VT-d codecs/domains); ASan `test-uacpi-runtime.sh`; QEMU `ci-qemu-pci-mediation-smoke.sh`, `ci-qemu-acpi-restart-smoke.sh`, & `ci-qemu-iommu-vtd-smoke.sh` (`edu` negative DMA + revoke + NVMe + VirtIO 1.0) | AMD-Vi (`IVRS`) hardware tables, live `QuiesceRemap` driver (`M.2`), and bare-metal qualification (`O.3`) remain open; `PCI production-ready = false` |
| NVMe & `HxFS v7` | Ring-3 `driver-host-nvme` + mutable `HxFS v7` (`AES-GCM` 64-bit extent nonces, `LZ4`, `Hxblob`, random-offset RMW, `truncate`, symlinks, `chmod`, `StatFs`, persistent named snapshots, journal replay, `scrub`/`fsck`, explicit `v6 → v7` migration) | Host `huesos-nvme`/`huesos-hxfs`/GPT suites, `migration-check`, benchmark gate, and QEMU `gcm-inject`/`crc-inject`/`no-tpm`/`powerfail`/`shutdown-cycle`/`stress`/`long-soak` | Independent security review, `HxFS v7` format freeze, 24h endurance soak, and two-vendor disposable-NVMe bare-metal matrix remain open; `storage production-ready = false` |
| Loaders & Win64 PE32+ | Static `huesos-elf`, dynamic `/lib/ld-huesos.so` (`BIND_NOW`, `RELRO`, TLS, `canvas_dlopen_*`, `libcanvas.so`), and native Win64 PE32+ (`huesos-pe` + `/lib/ld-pe.so` + `ntdll`/`kernel32`/`ucrtbase`/`msvcrt`/`ws2_32`/`bcrypt`/`advapi32`, `GS_BASE` `SwapGsGuard`, `.pdata`/`.xdata` SEH unwind) | `huesos-elf` & `huesos-pe` host suites; QEMU dynamic ELF (`dyn-rust-smoke`, `dyn-c-smoke`, `smoke-plugin`) and Win64 PE32+ selftest gates | Subset of Win32/NT console, file, sync, CRT, and Winsock APIs; GUI/Win32k/COM subsystems are not claimed |
| Networking, Wi-Fi & TLS 1.3 | `#![forbid(unsafe_code)]` `huesos-net` (`Eth`/`ARP`/`IPv4`/`ICMP`/`UDP`/`DHCP`/`DNS`/`TCP`), `net-service` (VirtIO 1.0 + dual-uplink), `huesos-ieee80211` + `huesos-wpa` (`WPA2-CCMP`) + `huesos-rtw88` (`RTL8821CE`) in `wlan-service`, pure-Rust `huesos-tls` (TLS 1.3 + X.509v3 CA validation) | Host suites across `huesos-net`, `huesos-ieee80211`, `huesos-wpa`, `huesos-rtw88`, and `huesos-tls`; QEMU boot-selftest exercises VirtIO + simulated 802.11 WPA2 + TLS | IPv4 client focus (no IPv6); `RTL8821CE` targets initial laptop silicon while multi-NIC/RF bare-metal qualification remains open |
| USB 3.x (`xHCI`) | `#![forbid(unsafe_code)]` `huesos-usb` (xHCI 1.x rings/contexts, Ch9, Hub, HID Boot Keyboard/Mouse, BOT SCSI, `TrbCompletionTable` futures), zero-heap Ring-3 `driver-host-xhci` (`[72..76 MiB)` VT-d-isolated `DmaPool`, MSI-X `0xE0`), `driver-manager` PS/2+USB keyboard mux + `/dev/block/usb0` + `HUSB` v1 VMO (`lsusb`) | `huesos-abi::usb` & `huesos-usb` host + ASan suites; `scripts/ci-qemu-usb-xhci-smoke.sh` (Q35 `intel-iommu` + `qemu-xhci` + `usb-hub` + QMP `usb-kbd` + `usb-mouse` + `usb-storage` LBA read) | Isochronous endpoints, HID Report Descriptor parser (beyond Boot Protocol), UASP, and multi-controller bare-metal qualification remain open |
| Display, `hsh` & userland | Kernel capability-gated `huesos-fb` (`src_stride` dirty blits), buffered truecolor `terminal`, `hsh` (`@caps`, N-stage pipes, scripting, job control), `huesos-std`, 45 `coreutils`, `btop`/`fdisk` TUIs, Snake, Freedoom | `huesos-fb` & `huesos-hsh` host suites; QEMU smoke checks `std-smoke`, `hsh` pipes, `pci -v`, and terminal readiness | ASCII/box-drawing bitmap fonts only; no GPU acceleration or window compositor claimed |

## Which documents are authoritative?

- **Current status overview:** this file ([STATUS.md](STATUS.md)).
- **Core kernel, scheduler & SMP:** [ARCHITECTURE.md](ARCHITECTURE.md),
  [SCHEDULER_V2.md](SCHEDULER_V2.md), [SMP_V2.md](SMP_V2.md),
  [USER_MEMORY.md](USER_MEMORY.md), [OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md),
  [DYNAMIC_PROCESSES.md](DYNAMIC_PROCESSES.md), [TASK_GENERATIONS.md](TASK_GENERATIONS.md),
  [IOAPIC_ROUTING.md](IOAPIC_ROUTING.md), [QUOTAS.md](QUOTAS.md).
- **ACPI, PCI, storage & networking:** [ACPI_RING3.md](ACPI_RING3.md),
  [UACPI.md](UACPI.md), [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md),
  [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md), [NVME.md](NVME.md),
  [HXFS_DESIGN.md](HXFS_DESIGN.md), [STORAGE_PRODUCTION_GATE.md](STORAGE_PRODUCTION_GATE.md),
  [NETWORKING.md](NETWORKING.md).
- **Userspace, loaders & tools:** [USERSPACE.md](USERSPACE.md),
  [SHELL_AND_STD.md](SHELL_AND_STD.md), [EXECUTABLE_LOADERS.md](EXECUTABLE_LOADERS.md),
  [OPERATIONS.md](OPERATIONS.md).
- **Verification & physical hardware:** [TESTING.md](TESTING.md),
  [HARDWARE.md](HARDWARE.md). Listing host hardware in `HARDWARE.md` never
  implies HuesOS exercised every device on that board.
- **Active work queues:** [ROADMAP.md](ROADMAP.md),
  [PRODUCTION_ROADMAP.md](PRODUCTION_ROADMAP.md),
  [ARCHITECTURE_ROADMAP.md](ARCHITECTURE_ROADMAP.md).

See [INDEX.md](INDEX.md) for a newcomer reading order.

## Maintenance contract

When changing a subsystem boundary, update both its contract document and this
snapshot in the same PR. Record implementation, host tests, QEMU gates, and
bare-metal evidence separately; never turn a configured gate into a pass or
claim production readiness while release blockers remain open.
