# HuesOS Architecture

## Overview

HuesOS is a **microkernel** for x86_64, inspired by Google Zircon (Fuchsia).
It boots exclusively via **UEFI**, loaded directly by the **Limine**
bootloader as a higher-half ELF64 executable (not a legacy multiboot image,
and not a standalone UEFI PE application — Limine handles all firmware
interaction and hands off a fully set up long-mode environment).

## Design Principles

1. **Minimal Kernel** — Drivers, filesystems, and network stack are meant to
   live in userspace (only a keyboard/serial/PIT driver live in-kernel today,
   as a bootstrap necessity).
2. **Capability-Based Security** — Resources are accessed through handles
   with rights (`huesos-object::Rights`).
3. **Message-Passing IPC** — Channels are the primary IPC primitive.
4. **Real ring3 userspace** — Processes genuinely run at CPL=3 with their own
   page tables and reach the kernel exclusively via the `syscall`
   instruction.

## Crate Structure

```
crates/
├── huesos-boot        # Limine ELF entry point, memory map / HHDM handoff
├── huesos-arch        # x86_64: GDT/TSS, IDT, paging, syscall trampoline, PIT, PS/2, serial
├── huesos-hal         # Thin hardware abstraction layer
├── huesos-pmm         # Physical memory manager (bitmap frame allocator)
├── huesos-object      # Kernel objects: Vmo, Channel, Process, Thread, Job, Handle/Rights
├── huesos-syscalls    # Syscall number table + dispatch
├── huesos-elf         # ELF64 loader (PT_LOAD segment mapping)
├── huesos-kernel      # Scheduler, process/thread management, init sequence
└── huesos-userspace/
    └── init           # Real ring3 userspace program (own target + linker script)
```

## Boot Flow

1. **Limine** parses `huesos-boot`'s ELF headers, maps it into the higher
   half (`0xffffffff80000000`+), sets up long mode + a stack, and jumps to
   `kmain_entry` (the linker script's `ENTRY`).
2. `kmain_entry` validates the Limine base revision, reads the HHDM offset
   and physical memory map from Limine's request/response protocol, and
   calls into `huesos_kernel::kmain` with an architecture-agnostic
   `BootInfo`.
3. `huesos_arch::init_early()`: serial console, `EFER.NXE` (required before
   any `NO_EXECUTE` page table flag is used), GDT/TSS, IDT.
4. PMM init: bitmap allocator built from the real memory map.
5. Paging init: kernel `OffsetPageTable` wired up over the bootloader's page
   tables via the HHDM.
6. Heap init: kernel heap is mapped through *real* page tables (not assumed
   pre-mapped), then handed to `linked_list_allocator`.
7. Object subsystem init: root job created, phys-to-virt translator wired up
   for VMOs.
8. Syscall init: STAR/LSTAR/SFMASK MSRs programmed, `syscall`/`sysret`
   enabled, dispatcher registered.
9. Scheduler init: idle task created, timer callback registered.
10. `huesos_arch::init_late()`: PIC unmasked, PIT programmed to 100 Hz,
    interrupts enabled.
11. `huesos-init` (embedded via `include_bytes!` at kernel build time) is
    loaded through the ELF loader into a fresh address space, and a user
    task is spawned.
12. On its first scheduling, the user task's trampoline performs a real
    `iretq` into ring3 at the loaded entry point.
13. Kernel idle-loops (`hlt`) while the scheduler preempts between the idle
    task and any live user/kernel tasks.

## Memory Model

- **Physical Memory**: tracked by `huesos-pmm`'s bitmap allocator, built
  from Limine's memory map. `reserve_range` protects regions (e.g. the
  bitmap's own storage) from being handed out.
- **Higher Half Direct Map (HHDM)**: all physical memory is accessible at
  `hhdm_offset + phys_addr` for kernel-side access (e.g. VMO page contents).
- **Per-process address spaces** (`huesos_arch::paging::AddressSpace`): each
  process gets a fresh PML4 that clones the kernel's upper-half entries
  (256..512) so kernel code/interrupts/syscalls keep working after a CR3
  switch, with an independent, isolated lower half for user mappings.
- **VMOs**: backed by real 4 KiB physical frames (`huesos_object::Vmo`), not
  a `Vec<u8>` — can be mapped directly into a process's page tables.

## Object System

Every kernel resource is an **object** with a unique `Koid`:

| Type      | Purpose                          |
|-----------|-----------------------------------|
| Vmo       | Physical memory pages            |
| Process   | Address space + handle table     |
| Thread    | Execution context                |
| Job       | Group of processes (hierarchy)   |
| Channel   | IPC endpoint (message passing)   |
| Port      | Waitset (multiplex waiting)      |

Objects implement `KernelObject: Any`, registered in a global
`Koid -> Arc<dyn KernelObject>` map, and downcast safely to their concrete
type via `KernelObjectExt::downcast_ref::<T>()`.

Objects are referenced by **handles** with **rights** (read, write, map,
transfer, destroy, etc.), stored per-process in a `HandleTable`.

## Syscalls

Invoked via the real `syscall` instruction (not a software interrupt):

- `rax` — syscall number (in), return value (out)
- `rdi`, `rsi`, `rdx`, `r10`, `r8` — arguments (`r10` instead of `rcx`,
  since `syscall` clobbers `rcx`/`r11`)

The asm trampoline (`huesos_arch::syscall::syscall_entry`) swaps to a
per-task kernel stack, marshals registers into a `SyscallFrame`, calls the
architecture-independent `huesos_syscalls::dispatch`, and `sysret`s back.

Current syscalls: `Nop`, `VmoCreate`, `HandleClose`, `HandleDuplicate`,
`Yield`, `VmoRead`, `VmoWrite`, `ChannelCreate`, `ChannelWrite`,
`ChannelRead`, `ProcessExit`, `DebugWrite`.

## Security Model

- **No global namespaces** — processes acquire resources via handles from
  parents or channels.
- **Rights are checked** on every syscall that touches a handle (see
  `huesos-syscalls`).
- **W^X on user pages**: code pages are mapped without `WRITABLE`, data/stack
  pages are mapped without executable permission (`NO_EXECUTE`, which
  requires `EFER.NXE` — see boot flow above).
- **Jobs** exist as a container concept but don't yet enforce quotas
  (roadmap item).
