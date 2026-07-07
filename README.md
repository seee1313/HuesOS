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
- ✅ MVP dynamic userspace launch path: init embeds child ELF images,
  creates processes/root VMARs, maps VMOs, creates threads, starts them,
  and receives bootstrap channels
- ✅ VMOs backed by real physical page frames (not a `Vec<u8>` placeholder)
- ✅ Channel IPC with real connected pairs (`Channel::pair()`)
- ✅ PS/2 keyboard IRQ bridge to userspace via Interrupt objects + Ports
  (DriverManager can receive raw scancode packets)
- ✅ PS/2 keyboard driver (scancode set 1 → ASCII) and PIT timer driver
- ✅ Real framebuffer driver (`huesos-fb`): pixel/rect/text/blit
  primitives, bounds-checked against untrusted userspace input
- ✅ `libcanvas`: a safe, `ntdll`/`libc`-style userspace syscall library —
  application code never writes `asm!("syscall")` directly; every syscall
  is a typed, `Result`-returning wrapper with RAII handle lifetimes.
  Userspace draws to the screen via a VMO-backed `Canvas` + a
  bounds-checked `FramebufferBlit` syscall — it never gets a mapping of
  real video memory.

All of the above is exercised live by `huesos-init` on every boot — now
built entirely against `libcanvas`, not raw syscalls — which creates a
VMO, writes to it, reads it back, creates a channel pair, sends/receives a
message, mirrors init progress logs to the framebuffer until handing the
screen to the terminal, then launches the userspace DriverManager and
framebuffer terminal as child processes. DriverManager now starts an
`input-host` DriverHost, registers the keyboard service from its readiness
messages, and monitors heartbeat messages. The terminal paints the
framebuffer from userspace via `Canvas` and runs a built-in mini shell
with internal commands only. Historical framebuffer test output is shown
in `tools/fontgen/qemu_screenshot.png`.

## Known Limitations

- Single core only (no SMP / APIC — see roadmap)
- No filesystem, no drivers beyond keyboard/serial/PIT/framebuffer
- Exited process address spaces / kernel task stacks are not yet reclaimed
  (a "zombie reaper" is future work)
- Dynamic process launch exists as an MVP (`ProcessCreate`/`VmarMap`/
  `ThreadCreate`/`ThreadStart`), but there is still no filesystem/initrd
  program namespace and no process teardown/wait-based supervision yet
- No dynamic loading, no relocations (static ELF executables only)
- Rights enforcement exists but isn't exhaustively audited
- Framebuffer text is ASCII-only (no Unicode shaping, by design)


## Hardware Compatibility

See [docs/HARDWARE.md](docs/HARDWARE.md) for real-machine smoke-test notes.
Current reported bare-metal success includes an MSI Modern 15 B5M laptop.

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

## Writing Your Own Userspace Program

See [docs/USERSPACE.md](docs/USERSPACE.md) — the short version: depend on
`libcanvas`, never call `syscall` yourself, and look at
`crates/huesos-userspace/init/src/main.rs` for a complete working example
(VMOs, channels, and framebuffer drawing).

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
│   ├── huesos-abi         # Shared kernel<->userspace ABI: syscall numbers, error codes
│   ├── huesos-fb          # Framebuffer driver: pixel/rect/text/blit primitives
│   ├── huesos-syscalls    # Syscall dispatch table
│   ├── huesos-elf         # ELF64 loader
│   ├── huesos-kernel      # Scheduler, process/thread mgmt, init sequence
│   └── huesos-userspace/
│       ├── libcanvas      # Safe userspace syscall library (the only sanctioned way in)
│       └── init           # Real ring3 userspace program (separate target)
├── scripts/               # QEMU runner, ISO builder, Limine config
├── tools/fontgen/         # 8x8 bitmap font generator for huesos-fb/libcanvas
├── third_party/           # Vendored Limine + OVMF binaries (see their READMEs)
├── docs/                  # Documentation
├── x86_64-huesos.json     # Kernel target spec (ELF, higher-half)
└── Makefile
```

## License

MIT
