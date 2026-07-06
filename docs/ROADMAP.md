# HuesOS Roadmap

The MVP boot-to-userspace pipeline (Limine → PMM → paging → scheduler →
ring3 → syscalls → VMO/Channel IPC) is working and verified in QEMU. This
roadmap covers what's next, roughly in priority order.

## Immediate

### 1. SMP / LAPIC / IOAPIC
- **Current**: single core, legacy PIC + PIT only.
- **Needed**: parse MADT, start APs via INIT-SIPI-SIPI, per-CPU
  GDT/TSS/IDT, LAPIC timer, IOAPIC interrupt routing.
- **Why deferred**: the MVP scope explicitly kept PIC/single-core to focus
  effort on getting a real, correct ring3 pipeline working first — adding
  SMP before that was solid would have multiplied debugging surface area.

### 2. Process/task teardown
- **Current**: `ProcessExit` marks a task "finished" so the scheduler skips
  it, but its kernel stack, user address space (PML4 + all mapped frames),
  and handle table are never freed.
- **Needed**: a "zombie" list + reaper task (or reference-counted teardown
  triggered once nothing can reference the task anymore) that frees the
  process's `AddressSpace` (walking all 4 page table levels and returning
  frames to `huesos-pmm`) and the task's kernel stack.

### 3. Blocking syscalls / wait primitives
- **Current**: `ChannelRead` returns `ShouldWait` immediately if empty;
  there's no way for a thread to actually block until data arrives.
- **Needed**: real blocking (park the task, wake it from the IRQ/syscall
  path that delivers the awaited event) plus `Port`-based multiplexed
  waiting (the `Port` object exists but isn't wired to anything yet).

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
- A VFS server process handling `open`/`read`/`write` via IPC, with
  filesystem and device drivers (starting with something like a virtio
  block device under QEMU) living in userspace processes rather than the
  kernel.

## Medium Term

### 7. Capabilities & resource quotas
- Job-based CPU time / memory / handle-count quotas (the `Job` object
  exists as a container concept but enforces nothing yet).

### 8. Networking
- virtio-net driver + a userspace TCP/IP stack.

### 9. Userspace runtime
- A `no_std` runtime/libc-equivalent for userspace programs (the current
  `huesos-init` hand-rolls raw `syscall` asm; anything beyond a proof of
  concept needs a proper syscall wrapper library).

## Long Term

- KASLR, SMAP/SMEP, other hardening.
- Self-hosting toolchain.

## Explicitly Out of Scope for This MVP

These were deliberately excluded to keep the MVP's surface area
achievable and verifiable in one pass — see the "Known Limitations"
section of the README:

- Any filesystem or persistent storage
- Networking
- More than a keyboard/serial/PIT driver
- SMP
