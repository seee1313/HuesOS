# HuesOS

**HuesOS** is an x86_64 microkernel operating system written in Rust,
inspired by Google Zircon (Fuchsia). It boots exclusively via UEFI (via
Limine) and has a **real, verified boot-to-userspace pipeline**: it loads
via Limine, sets up paging/heap/scheduler, loads a ring3 ELF process, and
that process performs actual `syscall` instructions to exercise VMOs and
Channel IPC.

## Status: MVP

This is a minimum viable microkernel, not a production OS. It proves out
the full pipeline end-to-end with no stubs in the paths it exercises, but
scope is intentionally narrow — see [Known Limitations](#known-limitations)
and [docs/ROADMAP.md](docs/ROADMAP.md) for what's next.

## Verified Working

- ✅ UEFI boot via Limine (real Limine protocol 0.6.5, base revision 3)
- ✅ Physical memory manager: bitmap frame allocator over the real Limine
  memory map (not a hardcoded range)
- ✅ Paging: per-process address spaces (independent PML4, shared kernel
  upper half), kernel heap mapped through real page tables
- ✅ GDT/TSS with real ring0/ring3 segments, IDT with page fault / GPF /
  double fault handlers
- ✅ Real `syscall`/`sysret` fast path (STAR/LSTAR/SFMASK), not a software
  interrupt gate
- ✅ Preemptive round-robin scheduler (PIT-driven, 100 Hz) that context
  switches address spaces (CR3) and kernel stacks (TSS.RSP0) correctly
  between kernel and userspace tasks
- ✅ ELF64 loader (`huesos-elf`) that maps `PT_LOAD` segments into a fresh
  address space
- ✅ A real ring3 userspace process (`huesos-init`) launched via `iretq`,
  built as a genuinely separate target/executable and embedded into the
  kernel image at build time
- ✅ VMOs backed by real physical page frames (not a `Vec<u8>` placeholder)
- ✅ Channel IPC with real connected pairs (`Channel::pair()`)
- ✅ PS/2 keyboard driver (scancode set 1 → ASCII) and PIT timer driver

All of the above is exercised live by `huesos-init` on every boot: it
performs real `syscall` instructions from ring3 to create a VMO, write to
it, read it back, create a channel pair, send/receive a message, and exit
cleanly — verified in QEMU/OVMF in both debug and release builds.

## Known Limitations

- Single core only (no SMP / APIC — see roadmap)
- No filesystem, no drivers beyond keyboard/serial/PIT
- Exited process address spaces / kernel task stacks are not yet reclaimed
  (a "zombie reaper" is future work)
- No dynamic loading, no relocations (static ELF executables only)
- Rights enforcement exists but isn't exhaustively audited

## Quick Start

```bash
# Build the kernel (also builds and embeds the userspace init binary)
make build

# Build + package a bootable ISO + run in QEMU (UEFI/OVMF)
make run

# Release build
make run PROFILE=release

# Host-side unit tests (crates with hardware-independent logic)
make test
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed design.

## Building

See [docs/BUILD.md](docs/BUILD.md) for prerequisites and build instructions.

## Testing

See [docs/TESTING.md](docs/TESTING.md) for unit tests, integration tests, and CI setup.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for planned improvements.

## Project Structure

```
HuesOS/
├── crates/
│   ├── huesos-boot        # Limine ELF entry point
│   ├── huesos-arch        # x86_64 primitives: GDT/TSS, IDT, paging, syscall, PIT, PS/2
│   ├── huesos-hal         # Hardware abstraction (thin, grows with drivers)
│   ├── huesos-pmm         # Physical memory manager (bitmap frame allocator)
│   ├── huesos-object      # Kernel objects: VMO, Channel, Process, Job, handles/rights
│   ├── huesos-syscalls    # Syscall dispatch table
│   ├── huesos-elf         # ELF64 loader
│   ├── huesos-kernel      # Scheduler, process/thread mgmt, init sequence
│   └── huesos-userspace/
│       └── init           # Real ring3 userspace program (separate target)
├── scripts/               # QEMU runner, ISO builder, Limine config
├── docs/                  # Documentation
├── x86_64-huesos.json     # Kernel target spec (ELF, higher-half)
└── Makefile
```

## License

MIT
