# HuesOS Roadmap

The MVP boot-to-userspace pipeline (Limine → PMM → paging → SMP-aware
scheduler → ring3 → syscalls → VMO/Channel IPC) is working and verified in
QEMU (`-smp 1` and `-smp 2`). This roadmap covers what's next, roughly in
priority order.

## Done (recent)

### Syscall user-memory boundary
- Central validated user-copy layer; syscall handlers no longer directly
  dereference caller pointers
- Full ABI-bound and active page-table walk (`PRESENT`, `USER_ACCESSIBLE`,
  `WRITABLE` for outputs), including multi-page ranges and huge-page leaves
- Single-fetch ABI records and output preflight before blocking/side effects
- Bounded VMO/Channel/debug/framebuffer temporary transfers with fallible
  allocation
- Handle duplication restricted to equal or reduced rights
- Detailed contract and review checklist in `docs/USER_MEMORY.md`

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
- `Vmo` Drop returns physical frames when the object is explicitly released;
  exit path frees kernel stacks via reaper
- `AddressSpace::destroy` frees owned user frames + private page tables
- Process teardown clears handle table; driver-host input uses blocking Port
- Handle counts track table and in-flight ownership, but the registry
  intentionally does not yet auto-unregister on the ordinary last close
- Timed waits: `ChannelRead`/`PortRead` mode `>=2` = timeout in ticks + `TimedOut`

## Immediate

### 1. User-fault isolation and recoverable copies
- **Current**: syscall copies reject invalid ranges before access; mappings
  cannot yet be removed concurrently because no unmap/protect syscall exists.
- **Needed**: classify CPL3 page faults and terminate only the offending
  process; add exception-table/fixup recovery (or address-space locking) before
  exposing VMAR unmap/protect; add SMEP/SMAP after the copy path is prepared.

### 2. IOAPIC interrupt routing
- **Current**: LAPIC timer on all CPUs; keyboard still via legacy PIC path.
- **Needed**: full IOAPIC programming, IRQ remapping for multi-core IRQs,
  drop reliance on 8259 for anything that can go through IOAPIC.

### 3. Process/task and object teardown (mostly done)
- **Current**: exited-process stacks, private page tables, and address-space-
  owned frames are reaped; process teardown clears its handle table. The
  global object registry still holds strong `Arc`s and does not automatically
  unregister an object on ordinary last-handle close.
- **Needed**: formalize handle, mapping, in-flight Channel, scheduler, and
  kernel-internal ownership; use weak registry entries or equivalent lifecycle
  accounting so VMOs and their physical frames are reclaimed without freeing
  an object that is still mapped or in flight. Finished task metadata also
  needs bounded zombie reclamation.

### 4. Blocking syscalls / wait primitives (mostly done)
- **Current**: Channel/Port block + tick timeouts (`TimedOut`); ProcessWait.
- **Needed**: multiplexed multi-object wait / cancel.

## Short Term

### 5. Multiple/dynamic userspace processes
- **Current**: MVP split launch exists (`ProcessCreate`, `VmarMap`,
  `ThreadCreate`, `ThreadStart`) and init can launch embedded child ELF
  images through `libcanvas::process::spawn_elf`.
- **Needed**: finish the process lifecycle around this path: blocking waits
  or port signals for exit, teardown/reaping, richer handle-transfer
  semantics, and eventually loading ELF images from a VFS instead of
  build-time `include_bytes!`.

### 6. Handle transfer semantics
- **Current**: `ChannelWrite` validates all handles, requires `TRANSFER`, then
  removes them from the sender before enqueueing; in-flight messages retain
  handle-count ownership until receipt or drop.
- **Needed**: transactional rollback when peer closure/send failure becomes
  observable, richer typed handle dispositions, and stress tests for concurrent
  close/transfer.

### 7. Real VFS + drivers in userspace
- BOOTFS is live as a RAM archive; `huesos-fat` exists as a library.
- **Needed**: virtio-block (or similar) + FAT/other backends behind
  FileSystemService; load DriverHosts from FS instead of build embeds.

## Medium Term

### 8. Capabilities & resource quotas
- Job-based CPU time / memory / handle-count quotas (the `Job` object
  exists as a container concept but enforces nothing yet).

### 9. Networking
- virtio-net driver + a userspace TCP/IP stack.

### 10. Scheduler polish
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
