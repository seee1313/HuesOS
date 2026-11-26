# Doom on HuesOS

## Components and licensing

The Doom port is a separate Ring-3 userspace program (`/bin/doom.elf`):

- Engine: `doomgeneric`, GPL-2.0-only, vendored under `third_party/doomgeneric`
  with its upstream license.
- Game data: Freedoom Phase 1 v0.13.0, BSD 3-Clause, vendored as
  `third_party/freedoom/freedoom1.wad` (packaged in HBI BOOTFS at
  `/data/freedoom1.wad`, SHA-256
  `7323bcc168c5a45ff10749b339960e98314740a734c30d4b9f3337001f9e703d`).
- HuesOS kernel, ABI, `libcanvas`, `huesos-std`, `terminal`, `hsh`, and other
  first-party crates retain MIT licensing; the GPL engine remains an isolated
  executable in `BOOTFS`.

No commercial Doom IWAD is distributed.

## BOOTFS VMO launch architecture

Neither `init` nor `/bin/doom.elf` embeds the 28 MiB Freedoom WAD in `.rodata`:

1. `hbi-gen` packages `/bin/doom.elf` and `/data/freedoom1.wad` once inside the
   HBI `BOOTFS` module.
2. At boot the kernel copies `BOOTFS` into one immutable VMO (`READ | DUPLICATE | TRANSFER`)
   shared by `init` and `driver-manager`.
3. When the user runs `doom`, `terminal` transfers a duplicate of its keyboard
   `Channel` to `init` (`system:launch-doom`) and parks until `doom:exited`.
4. `init` locates `/bin/doom.elf` and `/data/freedoom1.wad` in the bounded
   `BOOTFS` directory, spawns `/bin/doom.elf` via `spawn_elf_from_vmo` (with
   strict entry-bounds and W^X segment checks), and transfers a read-only
   duplicate of the `BOOTFS` VMO plus the validated `(wad_offset, wad_len)`
   slice.
5. Doom's narrow C FFI streams WAD ranges out of that read-only VMO without
   holding write, map, or ambient filesystem authority. If `BOOTFS` lacks Doom or
   the WAD, `init` returns `doom:error` cleanly without panicking.

## Freestanding C shim

DoomGeneric is C, compiled against a minimal non-POSIX compatibility layer:

- userspace heap (`malloc`, `calloc`, `realloc`, `free`);
- string/memory/printf/math (`atan`, `fabs`) helpers;
- read-only VMO-backed `FILE` stream for `/data/freedoom1.wad`;
- monotonic millisecond timing via `ClockGetMonotonic` / `ClockGetMonotonicNs`.

## Adaptive viewport and write-combining (`WC`) video

DoomGeneric renders internally at 640×400 (16:10). Rather than stretching across
ultra-high-resolution panels and copying millions of pixels per frame, the
adapter:

- preserves 16:10 aspect ratio, capping the game viewport at **960×600** centered
  on the physical display (and scaling down cleanly on smaller modes such as
  800×600 → 800×500);
- clears the outer border once and uploads/presents only the bounded game canvas
  on subsequent frames.

During SMP bring-up ([SMP_V2.md](SMP_V2.md)), every AP clones the BSP's
`IA32_PAT` (`MSR 0x277`) so write-combining (`WC`) framebuffer pages maintain
full throughput regardless of which CPU core schedules Doom.

## Input, SIMD, and stack ABI

| HuesOS key | Doom action |
|---|---|
| W / A / S / D or Arrows | Movement / turning |
| F | Fire |
| E | Use / open |
| Enter / Escape | Confirm / Menu |
| Q | Immediate clean exit back to `terminal` |

Every logical CPU enables `CR0.MP`, `CR4.OSFXSR`/`OSXMMEXCPT`, and per-task
64-byte-aligned `XSAVEOPT64`/`XSAVE64`/`XRSTOR64` (with `FXSAVE64`/`FXRSTOR64`
fallback), so multiple preempted Ring-3 SIMD tasks can share CPUs safely. Sound
remains intentionally disabled (`-nosound`) until a dedicated userspace audio
DriverHost lands.
