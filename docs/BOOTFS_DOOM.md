# Doom and Freedoom from HBI BOOTFS

## Motivation

The first Doom port embedded the Doom ELF in init and the Freedoom WAD in the Doom ELF. Init also embedded a complete BOOTFS archive. At boot this produced several independent copies of a roughly 28 MiB asset and made the trusted supervisor unnecessarily large.

The current design keeps optional applications and assets in one place: the HBI BOOTFS module.

## Boot ownership flow

1. The HBI generator stores `/bin/doom.elf` and `/data/freedoom1.wad` in BOOTFS.
2. The kernel validates the HBI directory and obtains the BOOTFS module slice.
3. Before init is scheduled, the kernel creates one VMO, copies the module into it, registers it, and installs handle `INIT_BOOTFS_HANDLE` in init.
4. Init receives only `READ | DUPLICATE | TRANSFER`; it cannot modify the archive.
5. Init duplicates the same VMO for DriverManager's filesystem service.
6. On a Doom request, init parses only the bounded BOOTFS header/directory, then launches `/bin/doom.elf` with `spawn_elf_from_vmo`.
7. Init transfers Doom a read-only duplicate of the archive plus the validated WAD entry offset and length.
8. Doom's narrow C FFI reads WAD bytes through the safe VMO wrapper. Doom never receives write, map, duplicate, or arbitrary filesystem authority.

The HBI image remains reserved until boot-resource reclamation is implemented. The VMO copy is currently intentional: it gives the object subsystem normal frame ownership and capability lifetime without aliasing bootloader-owned physical pages. A future immutable physical VMO can eliminate this final copy after page-aligned HBI ownership is specified.

## VMO-backed ELF validation

`spawn_elf_from_vmo` now treats the BOOTFS entry length as a security boundary. It rejects:

- zero or overflowing entry ranges;
- short header reads;
- a `PT_LOAD` file range outside the selected entry;
- offset arithmetic overflow;
- short source reads or destination writes.

Each segment is copied in bounded 4 KiB chunks into a dedicated VMO and mapped with W^X policy inherited from the ELF flags.

## Memory impact

Removed:

- complete BOOTFS bytes from init ELF;
- Doom ELF bytes from init ELF;
- complete Freedoom WAD from Doom ELF.

Remaining large storage at runtime:

- reserved HBI module;
- one read-only BOOTFS VMO shared by handles;
- Doom engine data allocated as needed by the C port.

This is intended to make the 256 MiB QEMU profile viable again. Exact peak-frame accounting remains part of the CI lifecycle soak.

## Adaptive viewport

DoomGeneric renders internally at 640×400. Scaling that buffer to every framebuffer pixel made pixels unnecessarily large on modern displays and copied the full screen every frame.

The output policy is now:

- preserve the 16:10 aspect ratio;
- cap the game viewport at 960×600;
- center it on the physical framebuffer;
- fit down on displays smaller than 960×600;
- clear the surrounding area once with a dark border;
- present only the bounded game canvas on later frames.

Examples:

| Framebuffer | Doom viewport | Destination |
| --- | --- | --- |
| 1280×800 | 960×600 | 160,100 |
| 1920×1080 | 960×600 | 480,240 |
| 2560×1440 | 960×600 | 800,420 |
| 800×600 | 800×500 | 0,50 |

The cap reduces per-frame output from 1,024,000 pixels at 1280×800 to 576,000 pixels and prevents scaling from worsening as display resolution increases.

## Failure behavior

If BOOTFS is absent, malformed, cannot be copied, or lacks either Doom file, core init/DriverManager/Terminal boot continues. A Doom launch request receives `doom:error`; no kernel panic occurs. If the WAD capability is missing, the FFI reports zero length/read rather than dereferencing invalid memory.
