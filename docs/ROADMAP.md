# HuesOS Roadmap

The MVP boot-to-userspace pipeline (Limine → PMM → paging → SMP-aware
scheduler → ring3 → syscalls → VMO/Channel IPC) is working and verified in
QEMU (`-smp 1` and `-smp 2`). This roadmap covers what's next, roughly in
priority order.

## Done (recent)

### Host-testable policy cores + contribution rules + safety audit
- Seven `no_std`, dependency-free, host-unit-tested **policy crates** extracted
  from the privileged paths, each with a `docs/` design page describing its
  intended kernel integration and what still needs on-target verification:
  - `huesos-lifecycle` — bounded zombie reclamation + two-counter collection
    model (Immediate #3).
  - `huesos-ioapic` — I/O APIC redirection-entry codec, MADT Interrupt Source
    Override parsing, device-vector allocation, GSI→I/O APIC routing (#2).
  - `huesos-extable` — exception/fixup table for recoverable user-copies (#1).
  - `huesos-waitset` — multi-object wait/cancel/timeout dispatch (#4).
  - `huesos-proclife` — per-process lifecycle state machine and exit/wait/reap
    coordination (Short-Term #5).
  - `huesos-handlemove` — rights monotonicity + all-or-nothing transactional
    handle transfer (Short-Term #6).
  - `huesos-quota` — flat and hierarchical resource admission for memory,
    handles, and CPU ticks (Medium-Term #8).
- These model decisions/encodings remain host-testable; bounded Channel/Port
  queue admission now uses the quota core, while the I/O APIC MMIO writes,
  fault-handler fixup, multi-wait syscall, full Job accounting, and complete
  policy-crate replacement of object-specific paths still need on-target
  verification.
- `CONTRIBUTING.md` with strict rules (safety budget, ranked-lock policy,
  Conventional Commits, host-test requirement, Definition of Done).
- Panicking-surface audit (`docs/UNSAFE_AUDIT.md`): every `unwrap`/`expect`/
  `panic!` site categorized (build scripts, budgeted tests, Ring-0 invariants);
  the one Ring-3 runtime unwrap (terminal parser) replaced with a defensive
  `let-else`; safety budget tightened (`unwrap_calls` 26 → 25) and the baseline
  regenerated.

### Buffered terminal renderer / post-game stall fix
- Root cause isolated to per-pixel/per-scanline VMO syscalls during Terminal repaint
- Static 16 MiB userspace shadow framebuffer; no per-frame heap allocation
- Local glyph rasterization + bounded 1 MiB uploads + one present
- Removed duplicate post-Snake terminal render
- Doom Q-exit regression restores Terminal in 60–80 ms under QEMU TCG

### TTY font + DoomGeneric/Freedoom userspace port
- Custom TTY-style 8×16 default font; original 8×8 retained as compact mode
- GPL-2.0 DoomGeneric isolated as a separate process; MIT kernel unchanged
- BSD-licensed Freedoom Phase 1 with pinned SHA-256
- Purpose-built freestanding C compatibility layer, no Linux/POSIX syscall ABI
- Canvas video, monotonic game timing, transferred keyboard service Channel
- Bounded large-ELF VMO copies, inactive-child page-table mapping optimization,
  SysV entry-stack alignment, and per-CPU SSE enablement
- First stable release is silent; privileged PC Speaker SFX remains next

### Monotonic clock, full-screen Snake, and orderly shutdown
- Hardware-timer monotonic syscall unaffected by yields or online CPU count
- Snake pacing moved entirely off RDTSC to 100 Hz monotonic deadlines
- Resolution-adaptive full-screen board, refreshed HUD/grid/object visuals
- Terminal `shutdown` request routed through init supervisor IPC
- Init-KOID authorization for `SystemShutdown`; unprivileged callers denied
- Non-ACPI halt: PS/2 interfaces quiesced, LAPIC timer stopped, peer CPUs
  stopped by IPI, final safe-to-power-off screen retained
- QEMU keyboard-injection and framebuffer screenshot tests

### Ring-3 fault isolation + SMP kernel panic
- CPL-aware dispatch for #PF, #GP, #UD, #DE, and #AC; #DF is always fatal
- Unhandled userspace exceptions terminate the complete process with stable
  `ProcessWait` codes while unrelated services continue
- Cross-CPU process termination, reschedule IPI, and CR3-safe deferred teardown
- Single-owner kernel panic, panic-stop IPI, lock-free emergency serial path
- Allocation-free white-on-red framebuffer diagnostics; no automatic reboot
- Embedded faulting child plus debug/SMP QEMU containment smoke test
- Trusted `panic_test=1` HBI hook and screenshot-based panic renderer test

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
- Handle transfer-on-write validates batches before removal and restores moved
  handles when bounded queue admission fails; the normative policy crate is
  not yet the direct implementation of the privileged table operations
- `Vmo` Drop returns physical frames when the object is explicitly released;
  exit path frees kernel stacks via reaper
- `AddressSpace::destroy` frees owned user frames + private page tables
- Process teardown clears handle table; driver-host input uses blocking Port
- Registry VMAR mapping acquires the VMO kernel lifetime reference atomically
  with object lookup
- Channel and Port queues use bounded per-object quota admission; overflow is
  observable as a normal error/drop counter rather than an unbounded allocation
- Timed waits: `ChannelRead`/`PortRead` mode `>=2` = timeout in ticks + `TimedOut`
- The scheduler uses a pending-wake handshake to close the enqueue-to-park SMP
  lost-wakeup window

## Immediate

### 1. Recoverable copies, VMAR unmap/protect, and SMEP/SMAP
- **Current**: `VmarUnmap` and `VmarProtect` operate on exact mappings under
  Process user-copy locking and a global mutation lock; cross-CPU TLB shootdown
  is required before returning to ring 3. `huesos-extable` remains the
  host-tested long-term recovery policy for faults that occur despite
  validation or future pageable copies.
- **Policy core landed**: `huesos-extable` — host-tested fixup-table data
  structure and lookup (see [RECOVERABLE_COPIES.md](RECOVERABLE_COPIES.md)).
- **Needed (on-target)**: install the actual fault-handler fixup path, add
  adversarial unmap/protect race tests, then complete SMEP/SMAP copy-window
  hardening and support mapping splits/child VMARs.

### 2. IOAPIC interrupt routing
- **Current**: LAPIC timer on all CPUs; keyboard IRQ1 is routed through an
  integrated masked-first I/O APIC path with PIC fallback.
- **Policy core landed**: `huesos-ioapic` — host-tested redirection-entry codec,
  MADT Interrupt Source Override parsing, vector allocation, and GSI→I/O APIC
  routing (see [IOAPIC_ROUTING.md](IOAPIC_ROUTING.md)).
- **Needed (on-target)**: deliberate vector/IRQ assertions, x2APIC and real
  source-override coverage, broader device routing, level-triggered EOI tests,
  and removal of PIC fallback where safe.

### 3. Process/task and object teardown (mostly done)
- **Current**: exited-process stacks, private page tables, and address-space-
  owned frames are reaped; process teardown clears its handle table. The
  global object registry still holds strong `Arc`s and does not automatically
  unregister an object on ordinary last-handle close.
- **Policy core landed**: `huesos-lifecycle` — host-tested bounded zombie
  reclamation and the two-counter (handle/kernel refs) collection model (see
  [OBJECT_LIFECYCLE_POLICY.md](OBJECT_LIFECYCLE_POLICY.md)).
- **Needed (on-target)**: wire the policy into the registry — weak registry
  entries / lifecycle accounting so VMOs and their physical frames are reclaimed
  without freeing an object still mapped or in flight, and feed finished-task
  records into the bounded graveyard.

### 4. Blocking syscalls / wait primitives (mostly done)
- **Current**: Channel/Port block + tick timeouts (`TimedOut`); ProcessWait.
- **Policy core landed**: `huesos-waitset` — host-tested multi-object wait
  dispatch (Any/All, cancel, deadline) (see
  [MULTI_OBJECT_WAIT.md](MULTI_OBJECT_WAIT.md)).
- **Needed (on-target)**: a multiplexed multi-object wait / cancel syscall wired
  to the scheduler park/wake hooks using the policy crate.

## Short Term

### 5. Multiple/dynamic userspace processes
- **Current**: MVP split launch exists (`ProcessCreate`, `VmarMap`,
  `ThreadCreate`, `ThreadStart`) and init can launch embedded child ELF
  images through `libcanvas::process::spawn_elf`.
- **Policy core landed**: `huesos-proclife` — host-tested per-process lifecycle
  state machine (Created→Running→Exited→Reaped) with exit/wait/reap
  coordination and an exit-info payload for port signals (see
  [DYNAMIC_PROCESSES.md](DYNAMIC_PROCESSES.md)).
- **Needed (on-target)**: drive the state machine from the scheduler/process
  subsystem (blocking waits / port signals for exit, teardown/reaping), richer
  handle-transfer semantics, and eventually loading ELF images from a VFS
  instead of build-time `include_bytes!`.

### 6. Handle transfer semantics
- **Current**: `ChannelWrite` validates distinct handles and `TRANSFER`, removes
  them as one handle-table batch, and restores the original slots when bounded
  queue admission fails; in-flight messages retain handle-count ownership until
  receipt or drop.
- **Policy core landed**: `huesos-handlemove` — host-tested rights monotonicity
  (transfer can preserve/reduce, never add rights), typed Move/Duplicate
  dispositions, and all-or-nothing transactional transfer (see
  [HANDLE_TRANSFER.md](HANDLE_TRANSFER.md)).
- **Needed (on-target)**: replace the object-specific batch path with the policy
  crate's dispositions and stress concurrent handle allocation, close, transfer,
  and queue rejection.

### 7. Real VFS + drivers in userspace
- BOOTFS is live as a RAM archive; `huesos-fat` exists as a library.
- **Needed**: virtio-block (or similar) + FAT/other backends behind
  FileSystemService; load DriverHosts from FS instead of build embeds.

## Medium Term

### 8. Capabilities & resource quotas
- **Current**: `Job` owns a shared hierarchical quota tree, Processes attach to
  Jobs, VMO physical-frame allocation is charged/released, and bounded
  Channel/Port queues use local quota admission (see [QUOTAS.md](QUOTAS.md)).
- **Current**: scheduler CPU ticks are charged to the owning Job; exhaustion is
  recorded but not yet converted into throttling or termination.
- **Needed**: charge handle references and page-table mappings, expose
  controlled child-Job creation, define exhaustion supervision, and verify
  release during SMP teardown.

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

- ~~SMP~~ → core path done; IOAPIC keyboard path done, general routing still open
- Any filesystem on real block devices
- Networking
- Full process teardown / wait
