# Object / Task Lifecycle Policy (`huesos-lifecycle`)

Status: **policy + host tests landed; kernel integration not yet landed and not
yet verified on-target.**

This document describes the host-testable policy crate `huesos-lifecycle` and
how it is intended to plug into the kernel. It supports the remaining work in
[OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md) and
[ROADMAP.md](ROADMAP.md) (Immediate #3: process/task and object teardown,
specifically *"bounded zombie reclamation"* of finished-task metadata).

## Why a separate crate

The registry's *decision logic* — when an object may be collected, and how
finished-task metadata may be bounded and reclaimed — is pure and
hardware-independent. Per the project's hardening pattern (compare
`huesos-abi::broker_policy` and `huesos-decoder-fuzz`), we extract that logic
into a dependency-free, `no_std`, host-testable crate so it can be unit-tested
without QEMU, an allocator, or `unsafe`, and so the privileged code can be held
to a written specification.

The crate is **budget-neutral**: it adds no `unsafe`, no `unwrap`/`expect`
calls, and no panicking macros (tests included), so
`tools/check-safety-budget.py` is unaffected.

## Contents

### `BoundedZombieStore<M, N>`

A fixed-capacity, order-preserving FIFO with explicit eviction and reclamation
accounting. Backed by an inline `[Option<M>; N]` (no allocator, no `unsafe`).

- `insert` admits a record; when full it evicts and returns the **oldest**
  (`InsertOutcome::Evicted`), so retention is bounded no matter how many tasks
  finish.
- `reap_oldest` / `retain` remove records explicitly (e.g. once a waiter has
  observed them).
- `alloc_generation` hands out strictly monotonic generations (saturating),
  used to distinguish a fresh exit of a reused identity from a stale one.
- Accounting invariant, asserted by tests:
  `total_inserted == total_evicted + total_reaped + len`.
- `N == 0` is a supported degenerate capacity (every insert evicts itself).

### `TaskGraveyard<N>`

Concrete wrapper for [`FinishedTask`] records: assigns a generation on
`record_exit`, supports `find(koid, generation)`, `find_latest(koid)`, and
waiter-driven `reap_waited(predicate)`.

### `RefAccount`

A specification model of the registry's two-counter collection decision:
collection is permitted iff the object is registered, not yet collected, and
**both** `handle_refs` and `kernel_refs` are zero. Tests pin the invariants
described in [OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md):

- handle refs (table + in-flight) block collection;
- kernel refs (e.g. a VMAR mapping) block collection independently;
- the in-flight handle-transfer window never exposes a transient zero while a
  capability is queued (`remove_keep_alive` semantics);
- counters saturate and never underflow.

## Intended kernel integration (NOT yet implemented here)

This crate changes no privileged behavior yet. The planned integration:

1. In the scheduler/task layer, replace unbounded retention of finished-task
   metadata with a `TaskGraveyard<N>` (capacity chosen to bound memory while
   covering the realistic number of concurrently-waited exits; suggested start
   `N = 64`).
2. On task exit, `record_exit(koid, exit_code, exit_tick)` stores the record;
   the returned generation is what `ProcessWait` reports so a waiter can pin a
   specific exit.
3. When a `ProcessWait` is satisfied (or a wait handle is closed), call
   `reap_waited` so observed records are reclaimed promptly; the FIFO bound is
   the safety net for unobserved ones.
4. `RefAccount` is a reference model for the registry's existing collection
   path; it is intended to be used in host tests that mirror the kernel's
   open/close call sequence, not called from the hot path.

## What still requires on-target verification

The following are **not** verified by this change and must be confirmed in QEMU
(`-smp 1` and `-smp 2`) and, ideally, a bare-metal soak before the integration
is considered done:

- Free-frame and object-count return exactly to baseline across a
  create/map/close/exit storm (extends the existing
  [OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md) integration matrix).
- The graveyard bound holds under many rapid exits with no waiters, and evicted
  records do not strand kernel references.
- No regression in `ProcessWait`/blocking behavior under SMP.

These need the full toolchain (pinned nightly + `build-std`, QEMU/OVMF) and were
not runnable in the environment where this crate was authored.

## Tests (host)

`make test` now includes `-p huesos-lifecycle`. The suite (23 tests) covers
FIFO eviction and wraparound, `retain` compaction across a wrapped layout, the
accounting invariant, the `N == 0` degenerate case, generation monotonicity and
saturation, koid-reuse disambiguation, waiter-driven reaping, and every
`RefAccount` collection invariant above.
