# Multi-Object Wait Policy (`huesos-waitset`)

Status: **policy + host tests landed; privileged blocking-syscall integration
and on-target behavior not yet implemented or verified.**

This document describes the host-testable crate `huesos-waitset` and how it is
intended to plug into the kernel. It supports
[ROADMAP.md](ROADMAP.md) Immediate #4 (*Blocking syscalls / wait primitives —
multiplexed multi-object wait / cancel*).

## Why this matters

The kernel already has blocking `ChannelRead` / `PortRead` (with tick timeouts)
and `ProcessWait`, plus a `WaitQueue` with scheduler park/wake hooks. The
remaining work is a **multiplexed multi-object wait with cancellation**: block
on several objects at once and return when a condition over the set holds (any
satisfied, or all satisfied), honoring cancellation and a deadline. This crate
models that dispatch logic so it can be tested without the scheduler.

## Why a separate crate

The wait *dispatch decisions* — signal-set algebra, per-item satisfaction,
Any/All completion, cancellation precedence, and deadline handling — are pure
and hardware-independent. Following the project's hardening pattern
(`huesos-lifecycle`, `huesos-ioapic`, `huesos-extable`), we extract them into a
dependency-free, `no_std`, host-testable crate so the logic is unit-tested
without the scheduler, QEMU, or `unsafe`, and the privileged syscalls are held
to a written, tested specification.

The crate is **budget-neutral**: no `unsafe`, no `unwrap`/`expect` calls, and no
panicking macros (tests included), so `tools/check-safety-budget.py` is
unaffected.

## Contents

### `Signals`

A 32-bit signal bitset with the common object signals (`READABLE`, `WRITABLE`,
`CANCELED`, `PEER_CLOSED`, `SIGNALED`) and set operations (`contains`,
`intersects`, `union`, `intersection`, `difference`), all `const fn`.

### `WaitItem`

One waited-on object: a user `key`, the `awaited` signals, and the currently
`active` signals. `is_satisfied` is `active ∩ awaited ≠ ∅`; `satisfied_signals`
returns that intersection.

### `WaitSet<N>`

A bounded, key-identified, compactly stored set of wait items. `add` rejects a
full set or a duplicate key; `remove` keeps the occupied prefix contiguous via a
`rotate_left`. `signal` / `set_active` / `clear_signal` mutate an item's active
set by key; `cancel` marks the whole wait canceled. Queries: `any_satisfied`,
`all_satisfied` (vacuously true when empty), `satisfied_count`, and a
`satisfied()` iterator.

### `WaitMode`, `WaitOutcome`, `poll`, `poll_at`

- `WaitMode::Any` completes when at least one item is satisfied; `WaitMode::All`
  when every item is satisfied (vacuously true when empty).
- `WaitOutcome` ∈ {`Pending`, `Signaled`, `Canceled`, `TimedOut`}.
- `poll(mode)`: cancellation takes precedence; then the mode condition decides
  `Signaled` vs `Pending`.
- `poll_at(mode, now, deadline)`: if the result would be `Pending` and
  `now >= deadline`, returns `TimedOut`; a `None` deadline never times out.
  `Signaled`/`Canceled` are returned regardless of the deadline.

## Intended kernel integration (NOT yet implemented here)

This crate changes no privileged behavior. The planned integration:

1. A multi-wait syscall builds a `WaitSet` from the caller's (handle, awaited,
   key) array, validated through the user-memory copy layer.
2. The syscall parks the thread on the existing `WaitQueue`/scheduler hooks and
   re-evaluates `poll(WaitMode::Any)` (the Zircon-style multi-wait semantic) on
   each signal, cancel, and tick, returning the satisfied items' keys and active
   signals.
3. `poll_at` provides the deadline (`TimedOut`), and handle closure / explicit
   cancel drives `Canceled`.
4. All-of-many and per-object single waits are the same machinery with `All`
   mode or a one-item set.

## What still requires on-target verification

The following are **not** verified by this change and must be confirmed in QEMU
(`-smp 1`/`-smp 2`) before the integration is done:

- The actual blocking syscall wired to the scheduler park/wake hooks.
- Wake-on-signal across cores, cancel propagation, and deadline (`TimedOut`)
  behavior under the monotonic tick.
- Correct return of satisfied keys/active signals to userspace via the
  user-memory copy layer.

These need the full toolchain (pinned nightly + `build-std`, QEMU/OVMF) and were
not runnable where this crate was authored.

## Tests (host)

`make test` includes `-p huesos-waitset`. The suite (15 tests) covers signal-set
algebra and bit round-trip, item satisfaction, membership (capacity/duplicate
rejection, compaction on remove), signal/clear effects, the satisfied iterator,
`poll` Any/All (including the vacuous empty-`All` case), cancellation precedence
over satisfaction and over timeout, and `poll_at` deadline semantics (pending
before, timed out at/after, no-deadline waits forever, signaled ignores
deadline), plus awaiting the `CANCELED` signal as a satisfier.
