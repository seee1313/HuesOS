# Object / Task Lifecycle Policy (`huesos-lifecycle`)

Status: **registry accounting and bounded task-graveyard integration landed; host
policy tests cover the decision model. SMP on-target lifecycle stress remains
required before this is considered fully verified.**

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

Concrete wrapper for [`FinishedTask`] records. `record_exit` assigns a local
generation for standalone policy callers. Kernel process-exit integration uses
`record_exit_with_generation`: the `ProcessLifecycle`-owned generation in
`ExitInfo` is recorded verbatim, so a graveyard record and a waiter identify
the same `(koid, generation)` exit. The store supports `find(koid,
generation)`, `find_latest(koid)`, and waiter-driven `reap_waited(predicate)`.

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

## Current kernel integration

The kernel uses the policy in the following bounded, reviewable ways:

1. The scheduler owns a `TaskGraveyard<256>` under its reaper-ranked lock.
2. On process exit, it snapshots lifecycle-owned `ExitInfo` and records the
   same `koid`, `generation`, exit code, and tick through
   `record_exit_with_generation`. The graveyard never invents a second
   identity for a lifecycle-managed exit.
3. Deferred reaping compares the process lifecycle payload with the stored
   `(koid, generation)` pair and reaps records that have been observed or whose
   typed process record is gone. The FIFO bound remains the safety net for
   unobserved exits.
4. `RefAccount` remains a reference model for the registry's collection path;
   it documents and host-tests the accounting invariants rather than running in
   the hot path.

## What still requires on-target verification

The following are **not** verified by this change and must be confirmed in QEMU
(`-smp 1` and `-smp 2`) and, ideally, a bare-metal soak before the integration
is considered done:

- Free-frame and object-count return exactly to baseline across a
  create/map/close/exit storm (extends the existing
  [OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md) integration matrix).
- The graveyard bound holds under many rapid exits with no waiters, and evicted
  records do not strand kernel references.
- A process exit observed through `ProcessWait` has the same generation as its
  graveyard record under concurrent teardown.
- No regression in `ProcessWait`/blocking behavior under SMP.

These need the full toolchain (pinned nightly + `build-std`, QEMU/OVMF) and were
not runnable in the environment where this crate was authored.

## Tests (host)

`make test` now includes `-p huesos-lifecycle`. The suite (25 tests) covers
FIFO eviction and wraparound, `retain` compaction across a wrapped layout, the
accounting invariant, the `N == 0` degenerate case, generation monotonicity and
saturation, koid-reuse disambiguation, waiter-driven reaping, externally
lifecycle-owned generation preservation, and every `RefAccount` collection
invariant above.
