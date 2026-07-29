# HuesOS Roadmap

The MVP boot-to-userspace pipeline (Limine → PMM → paging → SMP-aware
scheduler → ring3 → syscalls → VMO/Channel IPC) is working and verified in
QEMU (`-smp 1` and `-smp 2`). This roadmap covers what's next, roughly in
priority order.

## Done (recent)

### Type-enforced `IrqSafeMutex` for all of `huesos-object`, replacing the ad-hoc `IrqGuard` fix
- Field verification of the previous "IRQ-safe guards" fix (see below) found
  the keyboard self-deadlock still occurred, just less often — the manually
  curated set of guarded locks missed `wait::PARK_FN`/`WAKE_FN` (called from
  `WaitQueue::wake_one`, which the keyboard IRQ1 bridge reaches through
  `Interrupt::signal` -> `Port::queue`), proving the fix approach itself
  (convention over enforcement) was the real gap.
- Replaced every `spin::Mutex` in `huesos-object` with a new
  `crate::irq_guard::IrqSafeMutex<T>` (Zircon `Guard<SpinLock, IrqSave>`
  style): the type makes it impossible to `.lock()` without disabling local
  interrupts, so a future call site cannot reintroduce this bug by omission.
  New CI gate `tools/check-huesos-object-lock-policy.py` (in `make
  audit-check`) rejects any bare `spin::Mutex` in the crate going forward.
- Also applied a seL4-inspired secondary hardening: `Interrupt::signal` (the
  actual IRQ handler body) no longer looks anything up in the global object
  registry — `InterruptBinding` now caches the bound `Port`'s `Arc` at
  `bind_port` time instead of re-resolving a `Koid` on every interrupt.
  Needed a new safe `KernelObjectExt::downcast_arc` (zero `unsafe`, via a
  blanket `AsAnyArc` trait and `alloc`'s own `Arc::downcast`).
- Zero new safety-budget surface: mechanical lock-type migration, no new
  `unsafe`. Full writeup in `docs/UNSAFE_AUDIT.md` § "huesos-object
  migration to type-enforced `IrqSafeMutex`".
- Verified: `cargo test -p huesos-object` (39/39, including updated
  `interrupt_signal_queues_port_packet`), `cargo build -p huesos-boot
  --release` (full kernel + every embedded userspace ELF), `make
  audit-check` (6/6 gates), `clippy -D warnings`, `make test` (full host
  suite) all green locally. A fresh QEMU soak-with-continuous-typing test
  is still the authoritative signal that this closes the hazard completely
  (see docs/TESTING.md); not run in this sandbox.

### Fixed keyboard self-deadlock: IRQ-safe guards for `huesos-object` registry/Port/Interrupt/WaitQueue locks
- Root cause: the keyboard IRQ1 bridge (`Interrupt::signal` -> `Port::queue`
  -> `WaitQueue::wake_one`) and the timer IRQ (`wait::notify_tick`) share
  several plain `spin::Mutex` locks (`REGISTRY`, `Port::packets`/`quota`,
  `Interrupt::binding`, `WaitQueue::waiters`/`async_wakers`, the wait-timeout
  table) with ordinary syscall-context code that runs with interrupts
  enabled (`PortRead`, `InterruptBindPort`, `WaitSetWait`'s poll loop,
  `ProcessWait`'s timeout path). A keystroke or timer tick landing on the
  same CPU while syscall-context code already holds one of these locks
  self-deadlocks that CPU: the IRQ handler cannot get the lock, and the
  lock holder cannot resume because it is preempted inside the IRQ handler
  that is spinning on it. This reproduced as "keyboard input works for a
  few seconds, then the terminal or the entire system freezes solid", with
  the local CPU's timer tick stopping and no panic message — a single-CPU
  hazard, not an SMP race, so it did not require `-smp 2` to trigger.
- Fixed with a new crate-local `huesos_object::irq_guard::IrqGuard`, a
  verbatim reuse of `huesos-pmm`'s existing IRQ-mask-around-`lock()` pattern
  (see `docs/UNSAFE_AUDIT.md` "PMM IRQ-guard boundary"), applied to every
  affected lock. `huesos-object` still cannot depend on
  `huesos-arch::RankedIrqSafeTicketLock` without losing host-testability, so
  this closes the gap `docs/LOCK_ORDER.md` had flagged as outstanding
  ("Legacy `spin::Mutex` instances remain in the platform-neutral object
  and syscall crates... must move to a host-testable shared ranked-lock
  core") without requiring that larger migration.
- Safety-budget delta: `unsafe_blocks` 245 -> 247 (+2; the same two `cli`/
  `sti` `asm!` sites as the PMM guard, gated to real kernel builds and a
  no-op under host tests). Full writeup and verification log in
  `docs/UNSAFE_AUDIT.md` § "huesos-object IRQ-guard boundary".
- Verified: `cargo test -p huesos-object` (all 39 tests, unchanged
  behavior on host target), `cargo build -p huesos-boot --release`,
  `cargo clippy -D warnings` / `scripts/clippy.sh`, `make test` (full host
  suite), `make audit-check` (5/5 gates) all green locally. QEMU boot/
  keyboard-under-load verification is via CI's `qemu-boot` matrix per
  `docs/TESTING.md`.

### Fixed flaky `qemu-boot (release, 1)` CI hang: callback-mutex guard held across `park_current`
- Root cause: `huesos_object::wait::park_current` (and five other, lower-risk
  call sites) called `f()` while still holding the `MutexGuard` from
  `*PARK_FN.lock()`, because `if let Some(f) = *MUTEX.lock() { f() }` extends
  the lock's temporary lifetime across the whole body. `park_current` performs
  a real context switch and may not return for an arbitrary time, so any
  other task/CPU calling `park_current`/`wake_task` before the first one was
  woken spun forever on the mutex with interrupts disabled — stopping the
  timer tick permanently and hanging the system with no panic message. This
  is the actual cause of the `qemu-boot (release, 1)` CI flakiness (not a bug
  in the `sys_waitset_wait`/shutdown-broker fixes from PR #127, which remain
  correct and necessary on their own).
- Fixed by copying the `Option<fn>` out of the lock into a local before
  calling it, matching the pattern already used (and commented) in
  `huesos_syscalls::process::sys_yield`. Applied to
  `huesos_object::wait::{park_current, wake_task, current_task_id,
  now_ticks}`, `huesos_object::registry::current_cpu`,
  `huesos_syscalls::waitset::current_tick`, and
  `huesos_syscalls::debug::sys_debug_write`.
- Zero safety-budget impact (pure safe-Rust lock-scope fix, no new
  `unsafe`). Full writeup in `docs/UNSAFE_AUDIT.md`.
- Verified: `bash scripts/ci-qemu-smoke.sh release 1 120` green 5/5 under
  artificial host CPU load that previously reproduced the hang; `debug 1`,
  `debug 2`, `release 2`, and both `ci-qemu-extable-smoke.sh` profiles also
  re-verified green.

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

## Immediate — COMPLETE ✅

**Status:** CLOSED. All four Immediate tracks are implemented in `main`:
recoverable user copies + child/splitting VMARs, production-safe IOAPIC routing,
`huesos-proclife`-backed process lifecycle/reaper integration, and public
level-triggered Signal objects integrated with `WaitSetWait`.

Notes remaining under this section are explicitly future-facing validation or
next-stage expansion items; they are not blockers for the Immediate milestone.

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
- **Smoke probe landed (H2 follow-up, part 3 of 4)**: kernel-side
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
- **Typed ABI wire-up landed (H2 follow-up, part 4 of 4)**:
  `read_value` / `read_array` / `write_value` / `write_array` now
  route through typed helpers built on the same recoverable
  `rep movsb` user-access primitive. Small syscall records and
  handle/wait result arrays now share the same post-validation fault
  recovery as bulk VMO/Channel byte copies.
- **Child VMAR hierarchy + split ops landed**: `VmarCreateChild` reserves
  nested VMAR ranges append-only in the ABI; mappings may be installed into
  child VMARs; partial `VmarUnmap` / `VmarProtect` split mapping metadata
  transactionally while preserving VMO lifetime refs. Existing exact-range
  callers keep working unchanged.
- **Immediate status**: complete for the current userspace threading model.
  A real cross-CPU unmap-vs-copy race probe remains gated on future
  intra-process threading; the current CI probe is the kernel-side synthetic
  extable fault-recovery proof.

### 2. IOAPIC interrupt routing
- **Current**: LAPIC timer on all CPUs; keyboard IRQ1 is routed through an
  integrated masked-first I/O APIC path with PIC fallback.
- **Policy core landed**: `huesos-ioapic` — host-tested redirection-entry codec,
  MADT Interrupt Source Override parsing, vector allocation, and GSI→I/O APIC
  routing (see [IOAPIC_ROUTING.md](IOAPIC_ROUTING.md)).
- **Route verification landed**: the policy helper refuses non-device vectors
  and skips reserved vectors in misconfigured ranges; host tests cover
  non-identity IRQ1 source overrides and level-triggered LAPIC
  EOI requirements, and the privileged keyboard route now reads back the I/O
  APIC redirection entry after unmasking. A mismatch masks the entry again and
  leaves the PIC fallback active.
- **Production-safe x2APIC/route foundation landed**: I/O APIC destination
  construction is x2APIC-aware and refuses APIC IDs that cannot be represented
  in the classic 8-bit redirection-entry destination field, preventing silent
  truncation. The privileged route core is generic over legacy IRQ/vector and
  records routed IRQs in a bitmap; IRQ1 remains the only enabled route until
  matching IDT handlers and device drivers are installed. PIC fallback is
  intentionally retained for production hardware until broader coverage proves
  it safe to remove.
- **Immediate status**: complete for the current hardware matrix. Future work is
  additive: interrupt remapping/x2APIC logical destination support, multi-device
  route enablement as drivers appear, and eventual PIC fallback removal after
  bare-metal validation.

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
- **Process lifecycle replacement landed**: `Process.lifecycle` is now a
  private `huesos-proclife::ProcessLifecycle` policy object reached only
  through typed methods; scheduler/reaper code no longer inspects process
  `ProcState` directly. Finished-task metadata is recorded through
  `TaskGraveyard::record_exit_with_generation`, and overflow eviction outcome
  is accounted explicitly.
- **Immediate status**: complete. Remaining lifecycle work is future-facing
  observability/stress coverage, not a missing Immediate architecture piece.

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
- **Signal object landed**: append-only public ABI `SignalCreate` /
  `SignalSet` / `SignalClear`, `ObjectType::Signal`, `libcanvas::Signal`, and
  `WaitSetWait` `SIGNALED` support. Signal state is level-triggered: `set`
  stays active until `clear`, and handle close wakes pending waiters so they can
  report `CANCELED`.
- **Immediate status**: complete. Future work is richer wait diagnostics and
  higher-level userspace event abstractions built on `Signal`.

## Short Term

### 5. Multiple/dynamic userspace processes — COMPLETE ✅
- **Current**: split launch exists (`ProcessCreate`, `VmarMap`,
  `ThreadCreate`, `ThreadStart`) and init can launch embedded child ELF
  images through `libcanvas::process::spawn_elf`.
- **Policy core landed**: `huesos-proclife` — host-tested per-process lifecycle
  state machine (Created→Running→Exited→Reaped) with exit/wait/reap
  coordination and an exit-info payload (see
  [DYNAMIC_PROCESSES.md](DYNAMIC_PROCESSES.md)).
- **Exit notifications landed**: `ProcessBindExitPort` lets a supervisor bind a
  Port to a process. On exit, the kernel queues a `PORT_PACKET_PROCESS_EXIT`
  packet carrying `(koid, generation, exit_code)` plus the user key; late binds
  to an already-exited process queue immediately.
- **Short-Term #5 status**: complete for the current launch model. Loading ELF
  images from VFS instead of build-time `include_bytes!` is tracked under
  Short-Term #7 (real VFS + userspace drivers), not as a blocker for #5.

### 6. Handle transfer semantics — COMPLETE ✅
- **Current**: `ChannelWrite` validates moved handles through the
  `huesos-handlemove` policy model, removes them as one handle-table batch, and
  restores the original slots when bounded queue admission fails; in-flight
  messages retain handle-count ownership until receipt or drop.
- **Policy core integrated**: the syscall path builds internal
  `Disposition { op: Move }` entries for the existing handle-array ABI and runs
  the host-tested all-or-nothing policy before touching the real handle table.
  Missing handles, missing `TRANSFER`, repeated handles, and capacity failures
  map to stable syscall errors without partial mutation.
- **Short-Term #6 status**: complete for the current public ABI. A future
  `ChannelWriteEtc`-style API with public Duplicate/reduced-right dispositions
  can be added append-only when userspace needs it.

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
- **Init service integration ordering + CI happy-path markers
  (landed as PR-G)**: explicit
  `manifest:grants-complete:<driver>` barrier on the init → DM
  bootstrap channel so DriverManager cannot spawn an input host
  before init has finished minting its Resource grants; tightened
  8042 port ownership so `input-host` owns only 0x60 and
  `shutdown-broker` owns only 0x64, removing the exclusive-mint
  collision that used to leave the broker unspawned; and a
  significantly expanded `scripts/ci-qemu-smoke.sh` marker set
  covering every step of the healthy boot chain up to
  `[terminal] keyboard service online, starting shell` plus an
  anti-marker set that fails CI on any known "silent stall"
  line. Closes the class of bug where a userspace regression
  leaves the terminal wedged waiting for a service that never
  came up while CI stays green because early-boot self-tests
  still print.

## Medium Term

### 8. Capabilities & resource quotas — COMPLETE ✅
- **Current**: `Job` owns a shared hierarchical quota tree, Processes attach to
  Jobs, VMO physical-frame allocation is charged/released, scheduler CPU ticks
  are charged to the owning Job, and bounded Channel/Port queues use local quota
  admission (see [QUOTAS.md](QUOTAS.md)).
- **Public Job API landed**: append-only `JobDefault`, `JobCreate`,
  `JobSetLimits`, `JobBindQuotaPort`, and `ProcessCreateInJob` expose controlled
  child-Job creation, per-Job limit replacement, and process creation inside a
  selected child Job.
- **Exhaustion supervision landed**: failed Job charges queue
  `PORT_PACKET_QUOTA_EXHAUSTED` to bound supervisor Ports instead of killing the
  process automatically. Packet payload carries `(job_koid, resource_id,
  attempted_amount)`.
- **Medium-Term #8 status**: complete for active quota resources. Future work is
  finer-grained accounting classes (for example separate page-table metadata
  counters) and QEMU/SMP stress coverage for charge/release races.

### 9. Networking
- virtio-net driver + a userspace TCP/IP stack.

### 10. Scheduler polish — COMPLETE ✅
- **Landed**: EDF replenish-on-unblock. A Deadline task blocked for
  longer than one period would previously wake with a stale (past)
  deadline and be given infinite priority by EDF, starving every other
  Deadline task. `wake_task` now rebases `deadline = now + period` and
  refills `remaining_budget` — matching a standard Constant Bandwidth
  Server. Pure helper `replenish_deadline_on_unblock` covered by three
  host tests including overflow saturation.
- **Landed**: token-based opt-in Fair task stealing. A process must set
  `scheduler_flags::STEAL_OPT_IN` before its initial thread starts; idle CPUs
  may then request a victim runqueue token and steal only ready Fair user tasks
  whose affinity mask includes the target CPU. The scheduler keeps no global
  load average and does not perform global balancing.
- **Safety invariant**: migrated tasks receive a fresh task id on the target CPU
  and an old→new alias is retained for stale references. Tasks that have not yet
  consumed their initial user-entry record are not stealable, preserving startup
  lookup correctness.
- **Medium-Term #10 status**: complete for the approved per-CPU/token SMP model.
  Future polish is diagnostic/telemetry work rather than a missing scheduler
  architecture item.

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
