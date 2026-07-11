# Doom on HuesOS

## Components and licensing

The Doom port is a separate userspace program:

- Engine: `doomgeneric`, GPL-2.0-only, vendored under
  `third_party/doomgeneric` with its license.
- Game data: Freedoom Phase 1 v0.13.0, BSD 3-Clause, vendored as
  `third_party/freedoom/freedoom1.wad`.
- WAD SHA-256:
  `7323bcc168c5a45ff10749b339960e98314740a734c30d4b9f3337001f9e703d`.
- HuesOS kernel, ABI, libcanvas, terminal, and other crates retain their
  existing MIT licensing. The GPL engine remains a distinct process/binary.

No commercial Doom IWAD is distributed.

## Launch architecture

The terminal command is:

```text
doom
```

Terminal duplicates its keyboard service Channel and transfers it to init with
`system:launch-doom`. Init owns the embedded Doom ELF, creates the process,
maps its segments in bounded 1 MiB VMO transfers, starts its initial thread,
and forwards the keyboard handle through the child bootstrap channel.

Terminal then remains quiescent so it neither consumes Doom keyboard events nor
overwrites Doom frames.

## Freestanding libc compatibility layer

DoomGeneric is C, but HuesOS does not emulate Linux or claim POSIX compliance.
The port provides a small purpose-built compatibility layer containing only
what this engine needs:

- fixed userspace heap (`malloc`, `calloc`, `realloc`, `free`);
- memory and string routines;
- bounded printf-family formatting;
- in-memory `FILE` implementation for the embedded WAD;
- minimal configuration/save sinks;
- `atan`, `fabs`, integer parsers, assertions, and process exit.

The WAD reader calls into Rust and reads the compile-time Freedoom byte slice.
There are no host file descriptors or Linux syscalls.

## Video

DoomGeneric produces a 640×400 packed 32-bit buffer. The HuesOS adapter writes
it to a Canvas VMO and presents it centered on the physical framebuffer. Timing
uses `ClockGetMonotonic`; no POSIX clocks are involved.

Large child address spaces are created without flushing the current process TLB
for every page. A fresh child CR3 cannot have stale entries, and eliminating
those redundant flushes makes Doom startup practical.

## Input

The first port maps:

| HuesOS key | Doom action |
|---|---|
| W/A/S/D | Arrow movement/turning |
| F | Fire |
| E | Use/open |
| Enter | Confirm |
| Escape | Menu |

The early keyboard service publishes press events only. The Doom adapter emits
a matching synthetic release on the following poll, preventing permanently
stuck keys while preserving keyboard repeat.

## SIMD and stack ABI

Doom's C compiler uses the x86_64 SysV SSE ABI. HuesOS now enables CR0.MP and
CR4.OSFXSR/OSXMMEXCPT on every logical CPU. Initial userspace RSP is aligned as
a SysV function entry (`RSP % 16 == 8`), which is required by aligned XMM stack
moves.

Kernel Rust remains soft-float and does not touch SIMD registers. The current
scheduler pins userspace launch work to one CPU, so the single Doom SIMD task
retains state across switches. Full lazy/eager FXSAVE/FXRSTOR ownership is a
required follow-up before multiple independent SIMD userspace tasks share one
CPU.

## Memory requirement

The initial self-contained binary embeds the 28 MiB Freedoom IWAD and has a
20 MiB BSS heap. The standard QEMU profile is therefore 512 MiB. A 256 MiB
profile correctly reports OOM during the large process setup.

A future storage iteration should place Doom and the WAD in BOOTFS/VFS and map
or stream them without embedding/copying the payload through init. That will
reduce the minimum memory requirement.

## Sound

The first stable port is intentionally silent (`-nosound`). PC Speaker effects
are the next isolated phase. They require a privileged userspace-facing tone
service or driver and must not grant Doom arbitrary I/O-port access. Music is
out of scope for the PC Speaker backend.

## Test expectations

A successful serial boot includes:

```text
[init] launching DoomGeneric/Freedoom
[doom-launch] thread started
[doom] HuesOS DoomGeneric starting (Freedoom Phase 1)
W_Init: Init WADfiles.
I_InitGraphics: DOOM screen size: 320 x 200
```

A QEMU PPM screenshot must contain a centered multicolor game image rather than
the two-color terminal background, and the serial log must contain no Doom
user-fault or kernel panic. The release soak test captured title, gameplay, and
late gameplay frames with 156/164/149 distinct colors and byte differences of
622,930 and 532,728 respectively, while repeatedly injecting movement/fire
input.
