# Dynamic Processes: Process Lifecycle Policy (`huesos-proclife`)

Status: **policy + host tests landed; the kernel Process object now owns the
policy state machine and `ProcessWait` accounts waiters. Full graveyard/reap
integration and on-target lifecycle stress remain.**

This document describes the host-testable crate `huesos-proclife` and how it is
intended to plug into the kernel. It supports
[ROADMAP.md](ROADMAP.md) Short-Term #5 (*multiple/dynamic userspace processes*:
finish the process lifecycle around the spawn path — blocking waits or port
signals for exit, teardown/reaping).

## Scope

An MVP split launch already exists (`ProcessCreate`, `VmarMap`, `ThreadCreate`,
`ThreadStart`, and `libcanvas::process::spawn_elf`). The remaining work is the
lifecycle *around* that path: observing exit via blocking waits / port signals,
and reaping. This crate models the **per-process state machine** that governs
those decisions so the logic can be tested without the scheduler.

## Relationship to `huesos-lifecycle`

- `huesos-lifecycle` (Immediate #3): **registry-level** concerns — the bounded
  zombie graveyard and the two-counter object-collection decision.
- `huesos-proclife` (this crate, Short-Term #5): the **per-process** state
  machine — when a process has exited, when its exit is observable, and when it
  may be reaped. The per-process `Reaped` transition is what feeds a record into
  the registry's bounded graveyard.

## Contents

### `ProcState` and `can_transition`

Lifecycle states `Created -> Running -> Exited -> Reaped`, with the valid
transition relation:

```text
Created -> Running   (first thread started)
Created -> Exited    (spawn failure / killed before start)
Running -> Exited    (normal exit or killed)
Exited  -> Reaped    (observed and reaped)
```

`Reaped` is terminal. A process exits at most once.

### `ExitInfo`

The exit payload (`koid`, `generation`, `exit_code`) delivered to a supervisor
through a blocking `ProcessWait` or a port packet. The `generation`
disambiguates a reused `koid` (ABA defense), consistent with the graveyard in
`huesos-lifecycle`.

### `ProcessLifecycle`

A stateful per-process record:

- `start()`: `Created -> Running`.
- `exit(code)`: `Created/Running -> Exited`, capturing the exit code.
- `add_waiter()` / `remove_waiter()`: account blocked exit waiters (saturating).
- `can_reap()`: `Exited` **and** zero waiters.
- `reap()`: `Exited -> Reaped` only when `can_reap()`.
- `exit_info()`: the `ExitInfo`, available once exited (and still after reap).

## Current kernel integration boundary

The kernel `Process` object now owns a `Mutex<ProcessLifecycle>` rather than a
second independent exit-code state. The first userspace task publication drives
`Created -> Running`; process exit drives the policy's `exit(code)` transition
and wakes the existing wait queue. `ProcessWait` calls `add_waiter()` before
parking and releases the waiter when the exit status is observed, so waits
arriving after exit do not park unnecessarily.

The remaining integration work is:

1. emit a generation-bearing exit packet to subscribed Port supervisors;
2. drive `Exited -> Reaped` from the object/reaper lifecycle;
3. hand `FinishedTask` records to the bounded `huesos-lifecycle` graveyard;
4. release address-space, kernel-stack, handle, and quota resources only after
   the policy transition permits it.

## What still requires on-target verification

- Driving transitions from the real scheduler/process subsystem.
- Waking `ProcessWait` and emitting port packets on exit under `-smp 1/2`.
- Reap gating with concurrent waiters, and koid/generation reuse behavior.
- Loading ELF images from a VFS instead of build-time `include_bytes!` (the
  broader #5 goal; the VFS itself is Short-Term #7).

These need the full toolchain (pinned nightly + `build-std`, QEMU/OVMF) and were
not runnable where this crate was authored.

## Tests (host)

`make test` includes `-p huesos-proclife`. The suite (13 tests) covers the
valid/invalid transition relation and terminal state, start/exit (including
spawn-failure exit from `Created` and exit-once), waiter accounting (waiters
block reaping, saturating removal), reap eligibility and rejection while
running or while waiters remain, the stability of the `Reaped` state, and
`exit_info` availability before/after exit and after reap.
