# HuesOS Roadmap

The MVP boot-to-userspace pipeline (Limine → PMM → paging → SMP-aware
scheduler → ring3 → syscalls → VMO/Channel IPC) is working and verified in
QEMU (`-smp 1` and `-smp 2`). This roadmap covers what's next, roughly in
priority order.

## Done (recent)

### SMP / LAPIC (core path) — verified in QEMU
- MADT parse, INIT-SIPI-SIPI trampoline (stack + far jmp into long mode,
  `EFER.NXE`)
- Per-CPU GDT/TSS/IDT, `CpuLocal` via `GS_BASE`, per-CPU scheduler + idle
- Shared LAPIC timer calibration (BSP vs PIT); APs reuse the count
- LAPIC EOI on vector 0x20; PIC EOI retained for keyboard path
- Online-CPU load balancing; IPI reschedule on remote spawn
- Per-CPU STAR/LSTAR/SFMASK (user tasks may run on APs without `#UD`)
- HHDM base-rev-3 fixes: map ACPI tables; identity-map low trampoline
  pages; LAPIC MMIO mapped uncached

### HBI / FAT / alloc hardening
- HBI v2.1 gen/parser `EntryHeader` stride alignment (24 bytes)
- FAT BPB field widths + FAT16 EOC thresholds
- Buddy allocator stores and uses `page_size`

### Blocking waits + reaper (feature/wait-reaper-stability)
- Wait queues + `park`/`wake` hooks from the scheduler
- Blocking `ChannelRead` / `PortRead` (flag arg) and blocking `ProcessWait`
- Handle transfer-on-write already landed earlier; documented
- `Vmo` Drop frees physical frames; exit path frees kernel stacks via reaper
- `AddressSpace::destroy` frees owned user frames + private page tables
- Process teardown clears handle table; driver-host input uses blocking Port

## Immediate

### 1. IOAPIC interrupt routing
- **Current**: LAPIC timer on all CPUs; keyboard still via legacy PIC path.
- **Needed**: full IOAPIC programming, IRQ remapping for multi-core IRQs,
  drop reliance on 8259 for anything that can go through IOAPIC.

### 2. Process/task teardown (partial)
- **Current**: kernel stacks reaped; VMO frames on Drop; address space
  destroy + handle clear on exit. Still no full object-refcount GC for
  every koid still held only by the global registry.
- **Needed**: a "zombie" list + reaper task (or reference-counted teardown
  triggered once nothing can reference the task anymore) that frees the
  process's `AddressSpace` (walking all 4 page table levels and returning
  frames to `huesos-pmm`) and the task's kernel stack.

### 3. Blocking syscalls / wait primitives (partial)
- **Current**: Channel/Port can block via flag; ProcessWait blocks on exit.
- **Needed**: multiplexed multi-object wait, timeouts, interruptible cancels.

## Short Term

### 4. Multiple/dynamic userspace processes
- **Current**: MVP split launch exists (`ProcessCreate`, `VmarMap`,
  `ThreadCreate`, `ThreadStart`) and init can launch embedded child ELF
  images through `libcanvas::process::spawn_elf`.
- **Needed**: finish the process lifecycle around this path: blocking waits
  or port signals for exit, teardown/reaping, richer handle-transfer
  semantics, and eventually loading ELF images from a VFS instead of
  build-time `include_bytes!`.

### 5. Handle transfer semantics
- **Current**: `ChannelWrite` copies `Handle` values into the message but
  doesn't remove them from the sender's handle table (so a "transferred"
  handle remains usable by both processes — a capability leak).
- **Needed**: proper move semantics matching the `TRANSFER` right.

### 6. Real VFS + drivers in userspace
- BOOTFS is live as a RAM archive; `huesos-fat` exists as a library.
- **Needed**: virtio-block (or similar) + FAT/other backends behind
  FileSystemService; load DriverHosts from FS instead of build embeds.

## Medium Term

### 7. Capabilities & resource quotas
- Job-based CPU time / memory / handle-count quotas (the `Job` object
  exists as a container concept but enforces nothing yet).

### 8. Networking
- virtio-net driver + a userspace TCP/IP stack.

### 9. Scheduler polish
- Work-stealing, better AP timer calibration without PIT races, fair
  migration, and serial-log interleaving cleanup under SMP.

## Long Term

- KASLR, SMAP/SMEP, other hardening.
- Self-hosting toolchain.

## Explicitly Out of Scope for the Original MVP

These were deliberately excluded to keep the first MVP's surface area
achievable — several are now partially landed (SMP, BOOTFS, FAT lib):

- ~~SMP~~ → core path done; IOAPIC still open
- Any filesystem on real block devices
- Networking
- Full process teardown / wait
