# `hues-async` — Async Runtime for Fast Drivers

Status: **executor + host tests landed.** Used by the in-progress NVMe driver
(ROADMAP Short-Term #7). The on-target DriverHost integration (MMIO/DMA) is a
separate follow-up.

## Purpose

HuesOS drivers run as ring-3 DriverHost processes. Device I/O (the first target
is NVMe) is queue-based and latency-sensitive, so drivers need async/await
ergonomics **without** a heavyweight runtime. `hues-async` is a deliberately
tiny executor tuned for that: maximum speed, minimal/absent runtime, no
allocation on the hot path.

## Design

- **Futures-based.** Tasks are `core::future::Future`s. An I/O operation is a
  future that completes when the device signals completion.
- **Allocation-free, fixed capacity.** `Executor<TASKS, F>` stores up to `TASKS`
  futures *inline* (each up to `F` bytes) in a static slot table. Spawning a too-
  large future is a checked error (`SpawnError::TooLarge`); nothing is ever
  heap-allocated. `TASKS <= 64`.
- **`u64` ready bitmask.** Waking is a single bit-set; the run loop is a tight
  `trailing_zeros` scan. No queues, no lists.
- **No-alloc waker.** The `Waker` given to a future points at its stable slot;
  waking sets the slot's ready bit. For *external* completions the driver calls
  `Executor::wake(task_id)` with the id returned by `spawn` — this path is
  generation-guarded against stale ids.
- **Run-to-completion.** `poll()` drains ready tasks until quiescent; `run(park)`
  loops, calling `park` whenever the ready set is empty.
- **Owns its futures.** The executor drops any still-live futures when it is
  itself dropped (no leaks). Futures must be `'static`.

### Hybrid completion (driver policy, not runtime)

The executor only polls *ready* tasks. The **driver** implements the hybrid wait
the architecture calls for: after submitting I/O it polls the device completion
queue for a short window (lowest latency), then falls back to waiting on the
HuesOS `Port`/`Interrupt` for the completion IRQ (no busy CPU). When a completion
arrives, the driver maps it to a `TaskId` (e.g. the NVMe command id) and calls
`Executor::wake`. This keeps `hues-async` mechanism-only and the policy in the
driver.

## Project rule: no allocations, ever

`crates/hues-async/**` is **strictly allocation-free**. This is not a
performance suggestion; it is a hard project rule enforced by CI:

- The crate is `#![cfg_attr(not(test), no_std)]` and must not import the
  `alloc` crate anywhere (production **or** tests).
- The following identifiers are forbidden anywhere in a `.rs` file under
  `crates/hues-async/`: `use alloc`, `extern crate alloc`, `alloc::`,
  `Box<`, `Vec<`, `Vec::`, `String`, `Arc<`, `Rc<`, `Weak<`, `BTreeMap`,
  `BTreeSet`, `HashMap`, `HashSet`, `VecDeque`, `LinkedList`, `BinaryHeap`.
- Tests that need collections must use fixed-size arrays, or live in a
  downstream crate that consumes `hues-async` and is allowed to allocate.

Enforcement: `tools/check-hues-async-noalloc.py`, wired into
`make audit-check` and the `static-safety` CI job. Run it locally at any
time:

```bash
python3 tools/check-hues-async-noalloc.py
```

The gate reports every offending line and exits non-zero on any hit. It is
intentionally a raw-text scan (no AST parsing) so it runs on a fresh
checkout with only Python 3 available, matches the style of the three
existing safety gates, and cannot be bypassed with clever type aliases: the
banned identifiers cover the imports that would introduce them.

Rationale: the executor stores futures inline in a fixed-capacity table and
tracks readiness in a single `u64`. Any heap-backed container defeats that
design and re-introduces the runtime overhead the crate exists to avoid.
Growth beyond the fixed capacity should surface as `SpawnError::TooLarge`
at compile-time-visible sites, not as a silent `Vec::push`.

## Contracts

- **Single-threaded.** One executor per driver core; waking and polling happen on
  one thread (the completion handler wakes tasks from that same thread).
- **Stable address.** Do not move the executor after the first `spawn` (wakers
  hold interior pointers).
- **Progress.** A task that unconditionally re-wakes itself without progressing
  will spin; tasks must make progress.

## API sketch

```rust
let ex: Executor<16, 128> = Executor::new();        // 16 tasks, <=128 B each
let id = ex.spawn(io_operation(/* ... */))?;        // TaskId for completion
ex.run(|| {                                          // event loop
    nvme.poll_completions(|cmd_id| ex.wake(cmd_id)); // hybrid: poll CQ ...
    port.wait_briefly();                             // ... then await IRQ
});
```

## Safety

The executor contains a small, deliberate amount of `unsafe` (type-erased inline
futures + a no-alloc waker). Each site is documented with a `SAFETY:` comment and
the surface is reviewed in [`UNSAFE_AUDIT.md`](UNSAFE_AUDIT.md)
("hues-async executor boundary") and bounded by `safety-budget.json`. There are
no `unwrap`/`expect`/`panic!` outside a compile-time capacity assertion.

## Tests (host)

`make test` includes `-p hues-async`. The suite (9 tests) covers spawn/complete,
waker self-reschedule (`yield_now`), multiple tasks, external `wake(task_id)`,
capacity (`Full`), the size guard (`TooLarge`), generation-guarded stale-id
rejection, `run(park)`, and that dropping the executor drops live futures.

## Next: NVMe DriverHost (on-target)

The NVMe driver is the first consumer. The host-testable protocol/queue layer
(registers, SQE/CQE, phase bit, admin commands, PRP-based Read/Write) and the
DriverHost event loop are the next deliverables; the privileged plumbing —
mapping the controller BAR (MMIO) into the DriverHost and providing coherent DMA
buffers via VMOs — is a separate kernel-side step that requires QEMU
(`-device nvme`) / bare-metal verification.
