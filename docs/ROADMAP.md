# HuesOS Roadmap

The MVP boot-to-userspace pipeline (Limine → PMM → paging → SMP-aware
scheduler → ring3 → syscalls → VMO/Channel IPC) is working and verified in
QEMU (`-smp 1` and `-smp 2`). This roadmap covers what's next, roughly in
priority order.

## Done (recent)

### NVMe host-test unwraps retired; `unwrap_calls` back to 25
- The five `.unwrap()` calls introduced by NVMe `buffer_pool` host tests
  (previously tracked as Immediate #0b) have been rewritten around an
  `expect_some!` `match`-based helper. CONTRIBUTING §1 is again satisfied
  100%: no `.unwrap()` / `.expect()` / `panic!()` outside the historical
  Ring-0 invariants explicitly documented in `docs/UNSAFE_AUDIT.md`.
- `safety-budget.json` tightened `unwrap_calls: 30 → 25` in the same commit.

### `hues-async` alloc-free rule enforced in CI
- New gate `tools/check-hues-async-noalloc.py` rejects any use of the
  `alloc` crate or any heap-backed collection / smart-pointer under
  `crates/hues-async/**` (production and tests). Wired into
  `make audit-check` and therefore into the `static-safety` CI job.
- Rationale and full list of banned identifiers documented in
  [ASYNC_RUNTIME.md](ASYNC_RUNTIME.md#project-rule-no-allocations-ever) and
  cross-linked from `CONTRIBUTING.md § 1a`.
- Current `crates/hues-async/` code passes the gate with zero changes.

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
  `let-else`. `unwrap_calls` was tightened `26 → 25` at that point, then later
  raised to **30** (+5) by the NVMe `PciMmioTransport` host tests; see
  `docs/UNSAFE_AUDIT.md § "NVMe PciMmioTransport MMIO/DMA boundary"` for the
  retroactive dedicated-review record. Retiring those five NVMe test unwraps
  and returning to `unwrap_calls = 25` is tracked as follow-up cleanup.

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
- Single-fetch ABI records and output preflight before blocking/side effects;
  RAII `DeferGuard` rollback undoes handle-table insertions and object
  registrations when user-memory delivery fails after side effects
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
- HBI parser validates image_size vs buffer length, caps num_entries at 256,
  checks per-directory-entry offset/length bounds, and cross-checks
  DirectoryEntry ↔ EntryHeader type_id consistency
- ELF loader and PMM use checked/saturating arithmetic for segment-end and
  region-end computations; paging map_phys_range rejects overflow ranges
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
- Process lifecycle owns exit generation; the scheduler records that exact
  `(koid, generation)` identity in its bounded task graveyard, avoiding a
  second, mismatched ABA identifier during deferred reaping
- Channel and Port queues use bounded per-object quota admission; overflow is
  observable as a normal error/drop counter rather than an unbounded allocation
- Timed waits: `ChannelRead`/`PortRead` mode `>=2` = timeout in ticks + `TimedOut`
- The scheduler uses a pending-wake handshake to close the enqueue-to-park SMP
  lost-wakeup window; `WaitQueue::prepare` / `PreparedWait::park` / `cancel`
  closes the remaining check-to-enqueue gap in every blocking path (Channel
  recv, Port read, ProcessWait). `hues-async` is integrated as a ring-0
  allocation-free primitive for the early-boot ProcessWait path; async primitives
  (Recv, Sleep, ProcessWait) use the WaitQueue ↔ Waker bridge; sys_waitset_wait
  multiplexes across objects; keyboard IRQ → reactor wake bridge;
  QEMU init now
  also exercises a blocking `ProcessWait` wake after a yielding child exit in
  the debug/release, SMP 1/2 smoke matrix

### Async architecture (ring 0 + ring 3 universal async)
- `hues-async` Executor generic over `Backend` trait: `KernelBackend`
  (ring 0, SMP-ready) and `UserBackend` (ring 3, single-threaded)
- `scope_on(fut, &backend)` drives non-'static futures; `spawn` requires
  `'static` futures in executor slots. Clear separation.
- Reactor = scheduler: timer callback drains events and wakes tasks.
  No separate reactor thread. `async_rt::run_sync(fut)` is the kernel
  async entry point.
- Completion model: inline metadata (PortPacket), shared ring/CQ
  (NVMe I/O), peek & claim (Channel IPC with cookie-gated consume)
- Lock rules: never hold a ranked lock across `.await`. Capacity
  errors are policy, not bugs.
- Full design doc: `docs/design/ASYNC_ARCHITECTURE.md`

## Immediate

### 1. Recoverable copies, VMAR unmap/protect, and SMEP/SMAP
- **Current**: `VmarUnmap` and `VmarProtect` operate on exact mappings under
  Process user-copy locking and a global mutation lock; cross-CPU TLB shootdown
  is required before returning to ring 3.
- **Policy core landed**: `huesos-extable` — host-tested fixup-table data
  structure and lookup (see [RECOVERABLE_COPIES.md](RECOVERABLE_COPIES.md)).
- **Plumbing landed (H1)**: kernel-side `crate::extable` module + arch-side
  `set_kernel_recover_hook` + IDT `#PF` re-entry that redirects RIP to a
  `fixup_rip` when the extable covers the fault.
- **Macro infrastructure landed (H2 follow-up, part 1 of 3)**:
  `huesos-syscalls::user_access::recoverable_copy_{from,to}_user` are
  `asm!`-based user-copy primitives that emit their own `.ex_table`
  entries via `.pushsection`. `crate::extable::install` now reads the
  linker-emitted `[__huesos_ex_table_start, __huesos_ex_table_end)`
  range, sorts it, validates the non-overlap invariant via
  `Extable::new_sorted`, and publishes the sorted snapshot behind a
  lock-free `AtomicPtr`. Kernel boots log
  `[extable] installed N recoverable-copy entries`. See
  `docs/UNSAFE_AUDIT.md § "Extable macro infrastructure"` for the
  safety-budget review.
- **Wire-up landed (H2 follow-up, part 2 of 3)**: `copy_from_user` /
  `copy_to_user` in `huesos-syscalls::user_memory` now go through
  `user_access::recoverable_copy_{from,to}_user`. `readelf .ex_table`
  reports 2 entries × 24 bytes, each pointing at the exact 2-byte
  `rep movsb` opcode in the corresponding copy helper. VMO reads and
  Channel messages (the paths that dominate bulk userspace byte
  traffic) are now covered.
- **Smoke probe landed (H2 follow-up, part 3 of 3)**: kernel-side
  `huesos_syscalls::user_access::synthetic_recoverable_copy_probe`,
  gated by HBI cmdline `extable_test=1` and dispatched from `kmain`.
  New CI job `qemu-extable-smoke` in `.github/workflows/hardening.yml`
  runs in matrix `{debug, release}` (both profiles so a release/LTO
  regression — the historical failure mode of `651cc1c revert` —
  surfaces even if the debug boot smoke is green) and requires the
  positive `[extable-test] recovered synthetic user-copy fault OK`
  serial-log marker plus absence of `KERNEL PANIC` and
  `[extable-test] FAILED`. See `docs/UNSAFE_AUDIT.md § "Extable smoke
  probe"` for the design rationale (kernel-side synthetic vs.
  userspace race).
- **Needed (on-target)**: (a) wire `read_value` / `read_array` /
  `write_value` / `write_array` through a new
  `recoverable_read_at::<T>` helper (deferred: the race window on a
  single small ABI record is microscopic vs. a 1 MiB VMO copy); (b)
  complete SMEP/SMAP copy-window hardening and support mapping
  splits / child VMARs; (c) once intra-process threading lands in
  userspace, add a real cross-CPU race probe alongside the synthetic
  one.

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
  global object registry now backs each object with a
  `huesos_lifecycle::RefAccount` (host-tested two-counter model), and
  `note_handle_close` / `note_kernel_ref_close` invoke `try_collect` — the
  registry `Arc` is dropped on last-handle close for ordinary objects.
- **Policy core landed**: `huesos-lifecycle` — host-tested bounded zombie
  reclamation and the two-counter (handle/kernel refs) collection model (see
  [OBJECT_LIFECYCLE_POLICY.md](OBJECT_LIFECYCLE_POLICY.md)).
- **Landed**: registry migration from split `handle_counts` + `kernel_refs`
  maps to one `BTreeMap<Koid, RefAccount>`; ABA-style stale-koid resurrection
  is impossible because `open_*` on a collected account is a no-op. New
  regression test `once_collected_object_stays_gone_and_ignores_stale_notes`.
- **Needed (on-target)**: (a) feed finished-task metadata into the
  `TaskGraveyard` (already used by scheduler for `TaskWait`, needs uniform
  policy call); (b) use `huesos-proclife` for the process lifecycle state
  machine instead of ad-hoc bool flags.

### 4. Blocking syscalls / wait primitives (mostly done)
- **Current**: Channel/Port block + tick timeouts (`TimedOut`); ProcessWait.
- **Policy core landed**: `huesos-waitset` — host-tested multi-object wait
  dispatch (Any/All, cancel, deadline) (see
  [MULTI_OBJECT_WAIT.md](MULTI_OBJECT_WAIT.md)).
- **Landed**: `Syscall::WaitSetWait` (#33) in `huesos-syscalls::waitset`
  plus the `libcanvas::wait_any` / `wait_all` typed wrappers in userspace.
  ABI signal constants (`huesos_abi::signals::{READABLE, WRITABLE,
  CANCELED, PEER_CLOSED, SIGNALED}`) live in `huesos-abi` with a host test
  that pins their numeric layout to `huesos_waitset::Signals`.
- **Needed (on-target)**: cancellation smoke tests (a canceled handle
  wakes a pending waiter); explicit level-triggered signal-object type
  (currently only Channel/Port/Process report signals via `update_waitset_signals`).

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
- **PS/2 driver ownership (fully migrated as of PR-E)**: the scancode
  decoder, shift-state machine, and key-event dispatch live only in the
  userspace `driver-host:input` process. The kernel keeps a
  two-instruction IRQ1 shim in the IDT that reads port 0x60 and
  forwards the raw byte via `irq_callback::emit(1, byte)`. **The
  `huesos-arch::x86_64::keyboard` module has been deleted**; the 8042
  quiesce sequence executed on the shutdown path is now driven by the
  userspace `shutdown-broker` component through its IoPort resource.
  The legacy `SystemShutdown` kernel path no longer touches PS/2 at
  all — `interrupts::disable()` already masks IRQ delivery before the
  LAPIC halt sequence, so no spurious event can reach a dead handler.
- **Manifest-driven resource grants (landed as PR-C)**: `Resource`
  capability objects (`ObjectType::Resource`, kinds
  `IoPort`/`Mmio`/`Irq`, shared/exclusive semantics) are minted
  kernel-side by the root supervisor via `Syscall::ResourceCreate`;
  driver manifests declare fine-grained `resource=<kind>:<base>:<len>:<mode>`
  and `critical=true` lines that init reads out of BOOTFS and turns
  into per-driver handle grants transferred through DriverManager. See
  `docs/ARCHITECTURE_ROADMAP.md` §2/§4.
- **Userspace shutdown-broker + `sys_hard_halt` + critical-process
  fallback (landed as PR-D)**: capability-gated atomic halt via a new
  `PowerControl` resource kind, `Syscall::HardHalt = 36`, and safe
  8042 quiesce through `Syscall::IoPortWrite8`/`IoPortRead8`. The
  userspace `shutdown-broker` component holds an IoPort(0x64) grant
  and a PowerControl grant; init marks it critical, and the terminal
  `system:shutdown` command now routes through it. If the broker
  crashes before delivering the halt, the kernel's critical-exit
  hook forces `hard_halt` itself (Fuchsia's "critical to root job"
  analogue). DriverManager forward layer + input-host verification
  close the PR-C limitation end-to-end: manifest-minted resource
  handles now reach the driver process they were declared for.
  `keyboard::prepare_shutdown` is deleted in PR-E; see the item
  above.
- **`huesos-arch::x86_64::keyboard` module deletion (landed as PR-E)**:
  the last kernel-side PS/2 code is gone. The module file is removed
  and `mod.rs` no longer declares it. Legacy `SystemShutdown`
  continues to work as a broker-unavailable fallback but skips the
  historical `out 0x64, 0xAD/0xA7` sequence entirely.
- **Input UX quality: Cozette 6x13 font + event-driven PS/2 driver
  (landed as PR-F)**: replaces the 8x8-upscaled-to-8x16 pixelated
  terminal text with the Cozette bitmap font (6×13, MIT), doubling
  usable terminal cells from 44×96 to 54×168. The input-host
  driver loop is rewritten around `wait_any([bootstrap, port])` so
  it spends zero CPU when the keyboard is idle and dispatches
  key events at IPI-plus-context-switch latency instead of at
  scheduler-yield granularity. `tools/fontgen/bdf2rs.py` is the
  new regenerator for the font tables from an upstream `.bdf`
  release; both `libcanvas::font6x13` and `huesos_fb::font6x13`
  ship the same glyph data.

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
- **Landed**: EDF replenish-on-unblock. A Deadline task blocked for
  longer than one period would previously wake with a stale (past)
  deadline and be given infinite priority by EDF, starving every other
  Deadline task. `wake_task` now rebases `deadline = now + period` and
  refills `remaining_budget` — matching a standard Constant Bandwidth
  Server. Pure helper `replenish_deadline_on_unblock` covered by three
  host tests including overflow saturation.

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
