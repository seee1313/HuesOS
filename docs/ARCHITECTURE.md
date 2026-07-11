# HuesOS Architecture

## Overview

HuesOS is a **microkernel** for x86_64, inspired by Google Zircon (Fuchsia).
It boots exclusively via **UEFI**, loaded directly by the **Limine**
bootloader as a higher-half ELF64 executable (not a legacy multiboot image,
and not a standalone UEFI PE application — Limine handles all firmware
interaction and hands off a fully set up long-mode environment).

## Design Principles

1. **Minimal Kernel** — Drivers, filesystems, and network stack are meant to
   live in userspace (only bootstrap keyboard/serial/timer paths live
   in-kernel today).
2. **Capability-Based Security** — Resources are accessed through handles
   with rights (`huesos-object::Rights`).
3. **Message-Passing IPC** — Channels are the primary IPC primitive.
4. **Real ring3 userspace** — Processes genuinely run at CPL=3 with their own
   page tables and reach the kernel exclusively via the `syscall`
   instruction.
5. **One sanctioned syscall entry point in userspace** — application code
   never issues `syscall` itself; it goes through `libcanvas`. See
   [docs/USERSPACE.md](USERSPACE.md).
6. **SMP-aware from the kernel up** — every CPU has its own GDT/TSS,
   scheduler, and syscall MSRs; work is only placed on online CPUs.

## Crate Structure

```
crates/
├── huesos-boot        # Limine ELF entry point, memmap / HHDM / modules handoff
├── huesos-arch        # x86_64: GDT/TSS, IDT, paging, SMP, LAPIC, syscall, serial
├── huesos-hal         # Thin hardware abstraction layer
├── huesos-pmm         # Physical memory manager (bitmap frame allocator)
├── huesos-alloc       # Buddy + slab kernel allocator (no_std)
├── huesos-fat         # FAT16/32 library (no_std; not yet the production VFS)
├── huesos-object      # Kernel objects: Vmo, Channel, Process, Thread, Job, Handle/Rights
├── huesos-abi         # Shared kernel<->userspace ABI (syscall numbers, errors)
├── huesos-fb          # Framebuffer driver (bounds-checked blit)
├── huesos-syscalls    # Syscall dispatch
├── huesos-elf         # ELF64 loader
├── huesos-kernel      # Scheduler (Fair/Deadline), SMP, process/thread, HBI parse
└── huesos-userspace/
    ├── libcanvas      # Safe userspace syscall library
    ├── init           # ring3 init
    ├── driver-manager # userspace driver supervisor + BOOTFS FS service
    └── ...            # driver hosts / terminal
```

Tools (outside the no_std workspace): `tools/hbi-gen` builds HBI v2.1 images.

## Boot Flow

1. **Limine** maps `huesos-boot` into the higher half (`0xffffffff80000000`+),
   sets up long mode + a stack (1 MiB requested), and jumps to `kmain_entry`.
   Optional **HBI** image is loaded as a Limine module.
2. `kmain_entry` validates base revision **3**, reads HHDM offset, memory
   map (including raw `kind` types), framebuffer, RSDP, and HBI module.
3. `huesos_arch::init_early()`: serial, `EFER.NXE`, BSP GDT/TSS, IDT,
   `CpuLocal` + `GS_BASE`.
4. PMM init from the memory map; **HBI physical range reserved**.
5. Paging init over Limine's tables via the HHDM.
6. **`map_firmware_tables`**: map ACPI reclaimable/NVS/table regions (and a
   window around the RSDP) into the HHDM — base rev 3 does *not* map these
   by default. General RESERVED is intentionally **not** bulk-mapped (would
   WB-map LAPIC/MMIO).
7. Heap init (128 MiB buddy+slab at `0xffff_ff00_0000_0000`).
8. Object subsystem init; phys-to-virt + CPU-id callbacks.
9. **SMP bring-up** (if RSDP/MADT present):
   - Program LAPIC base (HHDM + **NO_CACHE**); calibrate timer once on BSP.
   - INIT-SIPI-SIPI; AP trampoline at phys `0x8000` with identity+HHDM maps
     for low memory; AP sets stack, enables LME|NXE, jumps to `ap_entry`.
   - APs: per-CPU GDT/TSS, IDT load, **syscall MSR init**, scheduler init,
     signal ready, wait on `APS_MAY_RUN`.
10. Parse HBI (if present); framebuffer / HAL / **syscall_init** (BSP MSRs +
    global handler); **BSP scheduler::init** (marks CPU online).
11. `init_late`: PIC setup, LAPIC timer start (shared calibrated count), STI.
12. **`smp::release_aps`**: APs start their LAPIC timers, STI, HLT idle.
13. Spawn `huesos-init`; BSP and APs idle on `hlt` while timer IRQs drive
    per-CPU scheduling.

## SMP Model

| Piece | Location / notes |
|-------|------------------|
| CpuLocal | `huesos-arch::cpu_local`, GS_BASE |
| Per-CPU GDT/TSS | `PerCpuGdt` (APs); BSP uses static GDT early |
| Per-CPU scheduler | `PER_CPU_SCHEDULERS[lapic_id]`, spinlock |
| Online mask | `ONLINE_CPUS` — spawn only onto online CPUs |
| Timer | LAPIC periodic vector `0x20`; EOI LAPIC (+ PIC for legacy) |
| IPI | `ipi_reschedule` wakes remote idle CPUs on spawn |
| Syscall | STAR/LSTAR/SFMASK **per CPU** |

### Limine base revision 3 mapping rules (important)

For base revision ≥ 3, HHDM covers only certain memmap types (usable,
bootloader-reclaimable, executable+modules, framebuffer) — **not** general
reserved/ACPI/MMIO — and there is **no** unconditional low 4 GiB identity
map. The kernel therefore:

- Maps ACPI-related ranges + RSDP window via `map_hhdm_range`
- Maps LAPIC MMIO with `PRESENT|WRITABLE|NO_CACHE` (and `update_flags` if a
  page was already present)
- Identity-maps the first 64 KiB for the AP trampoline / `ApBootInfo`

## Memory Model

- **Physical Memory**: `huesos-pmm` bitmap; `reserve_range` protects HBI,
  bitmap storage, etc.
- **HHDM**: `hhdm_offset + phys` for kernel access where mapped.
- **Per-process address spaces**: fresh PML4, kernel upper half cloned
  (indices 256..512).
- **Kernel heap**: buddy (`huesos-alloc::BuddyAllocator`, stores `page_size`)
  + slab; exposed as `GlobalAlloc` after `heap_init`.
- **VMOs**: real 4 KiB physical frames.

## HBI (HuesOS Boot Image) v2.1

On-disk layout (generator: `tools/hbi-gen`, parser:
`huesos-kernel::boot::hbi`):

- Global header (`HUESOS_H`, version `0x0002_0001`)
- Directory entries (`type_id`, `offset`, `length`, `flags`)
- Per-module `EntryHeader` (**24 bytes** = 6×`u32`) + payload + 8-byte pad

`hbi-gen` must advance the payload cursor by `size_of::<EntryHeader>()`, not
a hardcoded 16 — otherwise every module after the first is mis-sliced.

## Object System

Every kernel resource is an **object** with a unique `Koid`:

| Type      | Purpose                          |
|-----------|----------------------------------|
| Vmo       | Physical memory pages            |
| Process   | Address space + handle table     |
| Thread    | Execution context                |
| Job       | Group of processes (hierarchy)   |
| Channel   | IPC endpoint (message passing)   |
| Port      | Waitset (multiplex waiting)      |
| Interrupt | Userspace IRQ bridge             |

Objects implement `KernelObject: Any`, live in a global registry, and are
referenced by **handles** with **rights**.

## Syscalls

Invoked via real `syscall` (not a software interrupt). Canonical numbers
live in `huesos-abi::Syscall`. Current surface includes VMO/Channel/handle
ops, process/thread/VMAR launch, Port/Interrupt, framebuffer info/blit,
yield/exit/debug write.

Raw caller pointers are never dereferenced by individual syscall handlers.
`huesos-syscalls::user_memory` validates ABI bounds plus every active
page-table level (`PRESENT`, `USER_ACCESSIBLE`, and `WRITABLE` for outputs),
then performs the only audited raw copies. Argument records are snapshotted
once, and blocking/dequeueing calls preflight outputs before side effects.
See [USER_MEMORY.md](USER_MEMORY.md) for the complete contract, limits, review
checklist, and the required upgrade before VMAR unmap/protect is introduced.

`ClockGetMonotonic` exposes a hardware-tick clock independent of yields and SMP
CPU count. `SystemShutdown` is restricted to the init KOID; terminal requests
it through init-owned IPC rather than receiving global power authority. See
[SHUTDOWN.md](SHUTDOWN.md).

## Scheduler

- **Fair**: CFS-like virtual runtime in a rank-balanced WAVL tree
- **Deadline**: capacity/period with EDF priority over Fair
- Preemption from LAPIC timer (~100 Hz after Div16 calibration)
- Cross-core spawn uses online-CPU least-loaded placement + reschedule IPI

## Framebuffer & Graphics

`huesos-fb` owns Limine's framebuffer. Userspace draws into a VMO-backed
`Canvas` and presents via bounds-checked `FramebufferBlit`. No raw video
mapping is given to userspace.

## Monotonic Time

Each per-CPU scheduler still tracks local scheduling ticks, but public
monotonic time is a separate atomic counter advanced only by CPU 0's calibrated
LAPIC interrupt. Cooperative scheduling operations never update it. This keeps
time stable under different workloads and prevents an SMP system from running
clocks N times faster with N CPUs.

## Large Userspace Programs and Doom

The process launcher copies large ELF segments to VMOs in bounded 1 MiB
transfers. Child page-table construction does not flush the current process TLB
for each mapping because the child CR3 has never been active. Initial RSP uses
SysV post-call alignment, and every CPU enables x87/SSE execution for the
separate GPL DoomGeneric process. See [DOOM.md](DOOM.md).

## Orderly Shutdown

Shutdown is a root-supervisor operation. Terminal sends an IPC request to init;
the kernel verifies init's recorded KOID, renders the final screen, disables
both PS/2 interfaces with 8042 commands, broadcasts vector `0xF2`, and halts
all CPUs permanently. It intentionally performs neither ACPI poweroff nor
8042 reset. Physical power remains on.

## Fault Containment

The saved CS privilege level determines exception policy. Page faults, GPF,
invalid opcodes, divide errors, and alignment checks from Ring 3 terminate the
entire owning process and report a stable negative status through
`ProcessWait`. Ring 0 exceptions and double faults enter the SMP panic path:
one CPU emits emergency serial diagnostics and a white-on-red framebuffer
report, other CPUs receive a panic-stop IPI, and no CPU reboots. See
[FAULTS_AND_PANIC.md](FAULTS_AND_PANIC.md).

## Security Model

- No global namespaces — capabilities via handles.
- Rights checked on handle-touching syscalls; handle duplication can only
  preserve or reduce rights, never add rights absent from the source.
- W^X on user pages (`NO_EXECUTE` requires `EFER.NXE` on **every** CPU).
- Syscall user pointers are range-checked and page-table-checked before an
  audited copy; kernel-half pointers and supervisor-only mappings are rejected.
- Per-call transfer limits bound attacker-controlled temporary allocations.
- Jobs exist but do not yet enforce aggregate quotas.
- SMEP/SMAP and fault-recoverable copies remain future hardening.
