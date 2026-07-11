# HuesOS

**HuesOS** is an x86_64 microkernel operating system written in Rust,
inspired by Google Zircon (Fuchsia). It boots exclusively via UEFI (via
Limine) and has a **real, verified boot-to-userspace pipeline**: it loads
via Limine, sets up paging/heap/SMP-aware scheduler, loads a ring3 ELF
process, and that process performs actual `syscall` instructions to
exercise VMOs and Channel IPC — including multi-core bring-up under QEMU
`-smp 2`.

## Status: MVP + SMP

This is still a minimum viable microkernel, not a production OS. It proves
out the full pipeline end-to-end with no stubs in the paths it exercises.
SMP (INIT-SIPI-SIPI, per-CPU GDT/TSS/IDT/scheduler, LAPIC timer, load
balance) is now verified in QEMU. Scope remains intentionally narrow —
see [Known Limitations](#known-limitations) and
[docs/ROADMAP.md](docs/ROADMAP.md) for what's next.

## Verified Working

- ✅ UEFI boot via Limine (protocol 0.6.5, **base revision 3**)
- ✅ **HBI v2.1** boot image packaging (`tools/hbi-gen` + `scripts/mkhbi.sh`)
  loaded as a Limine module; kernel parser in `huesos-kernel::boot::hbi`
- ✅ Physical memory manager: bitmap frame allocator over the real Limine
  memory map (not a hardcoded range); HBI image protected via `reserve_range`
- ✅ Paging: per-process address spaces (independent PML4, shared kernel
  upper half), kernel heap mapped through real page tables
- ✅ **HHDM base-rev-3 awareness**: ACPI/firmware tables and low AP trampoline
  pages are explicitly mapped (rev 3 does not put reserved/ACPI/MMIO into
  the HHDM and dropped the unconditional low 4 GiB identity map)
- ✅ GDT/TSS with real ring0/ring3 segments, IDT with page fault / GPF /
  double fault handlers
- ✅ Real `syscall`/`sysret` fast path (STAR/LSTAR/SFMASK), programmed
  **per logical CPU** (critical for user tasks migrated to APs)
- ✅ Hardened userspace-copy boundary: full lower-half range and active
  page-table permission validation on every pointer-bearing syscall; no direct
  caller-pointer dereferences in syscall handlers; bounded temporary transfers
- ✅ Privilege-aware fault isolation: unhandled Ring 3 exceptions terminate the
  complete process while Ring 0 faults enter a non-returning SMP kernel panic
  (white diagnostics on a red framebuffer plus emergency serial output)
- ✅ **SMP**: MADT parse, INIT-SIPI-SIPI, per-CPU GDT/TSS/IDT/CpuLocal
  (GS_BASE), per-CPU scheduler with idle task, shared LAPIC timer
  calibration, LAPIC EOI on vector 0x20, online-CPU load balancing, IPI
  reschedule on remote spawn
- ✅ Scheduler: Fair (CFS-like WAVL-tree) + Deadline (EDF) policies, not
  just plain round-robin
- ✅ Buddy + slab kernel heap (`huesos-alloc`, 128 MiB heap, `page_size`-aware)
- ✅ FAT16/32 driver crate (`huesos-fat`) with correct on-disk BPB layout
  and FAT16-aware end-of-chain
- ✅ ELF64 loader (`huesos-elf`) that maps `PT_LOAD` segments into a fresh
  address space
- ✅ Real ring3 userspace process (`huesos-init`) launched via `iretq`,
  built as a separate target and embedded at build time
- ✅ Dynamic userspace launch: init embeds child ELF images, creates
  processes/root VMARs, maps VMOs, creates threads, starts them, and
  receives bootstrap channels
- ✅ VMOs backed by real physical page frames
- ✅ Channel IPC with real connected pairs (`Channel::pair()`)
- ✅ PS/2 keyboard IRQ bridge to userspace via Interrupt objects + Ports
- ✅ Real framebuffer driver (`huesos-fb`) + `libcanvas` (safe syscall lib;
  userspace never maps raw video memory)
- ✅ Privileged non-ACPI `shutdown`: terminal → init IPC, PS/2 quiesce,
  shutdown-stop IPI, permanent CPU halt, and a final safe-to-power-off screen
- ✅ Full-screen Snake paced by the kernel monotonic clock (no RDTSC/device-
  frequency dependency), with resolution-adaptive layout and refreshed visuals
- ✅ TTY-style 8×16 default terminal font with the original 8×8 font retained
  as `font compact`
- ✅ DoomGeneric userspace port with Freedoom Phase 1, custom non-POSIX libc,
  Canvas video, Channel keyboard input, and monotonic timing (silent first cut)

All of the above is exercised live by `huesos-init` on every boot — built
against `libcanvas` — which creates a VMO, does a channel round-trip,
mirrors logs to the framebuffer, then launches DriverManager and the
framebuffer terminal. DriverManager starts an `input-host` DriverHost,
registers the keyboard service, mounts a RAM BOOTFS image as
FileSystemService, and monitors heartbeats. The terminal paints via
`Canvas` and runs a built-in mini shell.

### QEMU multi-core smoke (expected)

```text
[HuesOS] Bootloader handed over control
[PMM] Reserved HBI image: ...
[SMP] MADT parsed 2 CPUs found
[SMP] LAPIC timer count=...
[SMP] Booting AP 1
[SMP] AP 1 online (waiting for release)
[SMP] AP 1 ready
[SMP] bringup done, APs ready=1
HBI v2.1 parsed. Entries: 0x4
[SMP] APs released to run
[SMP] AP 1 scheduling
HuesOS v0.1.0 on CPU 0
[init] hello from ring3 userspace, via libcanvas
[init] VMO read/write round-trip OK
[init] channel IPC round-trip OK
... driver-manager / terminal ready ...
```

Default `scripts/run.sh` uses `-smp 2`.

## Known Limitations

- No IOAPIC routing yet (LAPIC timer + legacy PIC keyboard path only)
- No filesystem on real block devices yet (BOOTFS is RAM; FAT crate is
  library-ready, not wired as the production VFS backend)
- Exited-process address spaces and kernel stacks are reaped, but finished task
  metadata is retained and the global object registry still needs a complete
  strong/weak-reference lifecycle (ordinary last-handle close does not yet
  unregister every object)
- Dynamic process launch and blocking `ProcessWait` work, but supervision,
  cancellation, and multi-object waits remain MVP-level
- No dynamic loading / relocations (static ELF only)
- Capability rights are enforced on current handle syscalls, but object
  lifetime/resource quota enforcement is not yet complete
- Framebuffer text is ASCII-only (no Unicode shaping, by design)

## Hardware Compatibility

See [docs/HARDWARE.md](docs/HARDWARE.md) for real-machine smoke-test notes.
Current reported bare-metal success includes an MSI Modern 15 B5M laptop.

## Quick Start

```bash
# Build the kernel (also builds and embeds the userspace init binary)
make build

# Build + package a bootable ISO + run in QEMU (UEFI/OVMF, 2 CPUs)
make run

# Release build
make run PROFILE=release

# Host-side unit tests (crates with hardware-independent logic)
make test
```

## Writing Your Own Userspace Program

See [docs/USERSPACE.md](docs/USERSPACE.md) — the short version: depend on
`libcanvas`, never call `syscall` yourself, and look at
`crates/huesos-userspace/init/src/main.rs` for a complete working example
(VMOs, channels, and framebuffer drawing).

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed design
(including SMP, HBI, HHDM base-rev-3 mapping rules, and allocators). The
security contract for every pointer-bearing syscall is documented separately
in [docs/USER_MEMORY.md](docs/USER_MEMORY.md). Exception containment and the
non-rebooting red panic screen are specified in
[docs/FAULTS_AND_PANIC.md](docs/FAULTS_AND_PANIC.md). See
[docs/SHUTDOWN.md](docs/SHUTDOWN.md) for the non-ACPI halt protocol,
[docs/SNAKE.md](docs/SNAKE.md) for deterministic game timing/fullscreen layout,
[docs/TTY_FONT.md](docs/TTY_FONT.md) for terminal font modes, and
[docs/DOOM.md](docs/DOOM.md) for the GPL userspace game port. The ongoing
hardening effort is tracked in
[docs/OPTIMIZATION_SAFETY_PROGRAM.md](docs/OPTIMIZATION_SAFETY_PROGRAM.md) and
[docs/UNSAFE_AUDIT.md](docs/UNSAFE_AUDIT.md).

## Building

See [docs/BUILD.md](docs/BUILD.md) for prerequisites and build instructions.

## Testing

See [docs/TESTING.md](docs/TESTING.md) for unit tests, multi-core QEMU
expectations, and CI setup.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for planned improvements.

## Project Structure

```
HuesOS/
├── crates/
│   ├── huesos-boot        # Limine ELF entry point, memmap / modules / HBI handoff
│   ├── huesos-arch        # x86_64: GDT/TSS, IDT, paging, SMP, LAPIC, syscall, serial
│   ├── huesos-hal         # Hardware abstraction (thin, grows with drivers)
│   ├── huesos-pmm         # Physical memory manager (bitmap frame allocator)
│   ├── huesos-alloc       # Buddy + slab kernel allocator
│   ├── huesos-fat         # FAT16/32 filesystem library (no_std)
│   ├── huesos-object      # Kernel objects: VMO, Channel, Process, Job, handles/rights
│   ├── huesos-abi         # Shared kernel<->userspace ABI: syscall numbers, error codes
│   ├── huesos-fb          # Framebuffer driver: pixel/rect/text/blit primitives
│   ├── huesos-syscalls    # Syscall dispatch table
│   ├── huesos-elf         # ELF64 loader
│   ├── huesos-kernel      # Scheduler (Fair/Deadline), SMP, process/thread, HBI parse
│   └── huesos-userspace/
│       ├── libcanvas      # Safe userspace syscall library (the only sanctioned way in)
│       ├── init           # Real ring3 userspace init
│       ├── driver-manager # Userspace driver supervisor + BOOTFS FS service
│       └── ...            # driver hosts / terminal
├── scripts/               # QEMU runner, ISO builder, HBI packager, Limine config
├── tools/
│   ├── hbi-gen            # HBI v2.1 image generator
│   └── fontgen/           # 8x8 bitmap font generator
├── third_party/           # Vendored Limine + OVMF binaries
├── docs/                  # Documentation
├── x86_64-huesos.json     # Kernel target spec (ELF, higher-half)
└── Makefile
```

## License

HuesOS kernel and native Rust crates are MIT. The separately built DoomGeneric
userspace program is GPL-2.0-only; Freedoom Phase 1 assets are BSD 3-Clause.
See `third_party/doomgeneric/LICENSE`, `third_party/freedoom/LICENSE.txt`, and
[docs/DOOM.md](docs/DOOM.md).
