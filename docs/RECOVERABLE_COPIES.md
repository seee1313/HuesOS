# Recoverable Copies: Exception / Fixup Table (`huesos-extable`)

Status: **policy + host tests landed; privileged fault-handler integration and
on-target behavior not yet implemented or verified.**

This document describes the host-testable crate `huesos-extable` and how it is
intended to plug into the kernel. It supports
[ROADMAP.md](ROADMAP.md) Immediate #1 (*Recoverable copies, VMAR unmap/protect,
and SMEP/SMAP*).

## Why this matters

Today every pointer-bearing syscall copies through the validated user-copy layer
(`crates/huesos-syscalls/src/user_memory.rs`), which pre-validates the active
page tables before copying. That is safe as long as no userspace `unmap` /
`protect` can race a copy. The roadmap's next step is to make copies
**recoverable**: if a kernel-mode copy faults (e.g. because a mapping changed),
the page-fault handler redirects execution to a *fixup* address that returns an
error, instead of panicking the kernel. This is a prerequisite for safely
exposing VMAR `unmap`/`protect`, and for enabling SMEP/SMAP with explicit copy
access windows.

## Why a separate crate

The fixup table's *data structure and lookup* — a sorted, non-overlapping set of
`[start_rip, end_rip) -> fixup_rip` ranges searched by binary search — are pure
and hardware-independent. Following the project's hardening pattern
(`huesos-lifecycle`, `huesos-ioapic`), we extract them into a dependency-free,
`no_std`, host-testable crate so the lookup logic is unit-tested without QEMU or
`unsafe`, and the privileged fault handler is held to a written, tested
specification.

The crate is **budget-neutral**: no `unsafe`, no `unwrap`/`expect` calls, and no
panicking macros (tests included), so `tools/check-safety-budget.py` is
unaffected.

## Contents

### `FixupRange`

One entry: faults at any instruction pointer in the half-open range
`[start_rip, end_rip)` recover at `fixup_rip`. A single instruction is the
degenerate range `[rip, rip + 1)` (`FixupRange::point`). `contains` and
`is_valid` are provided. `point(u64::MAX)` is not representable and is rejected
by table validation.

### `Extable`

A sorted, non-overlapping table borrowed from a static slice. In the kernel the
table is emitted by the linker as a sorted section; `Extable::new_sorted`
re-validates the invariants (every range well-formed, strictly increasing
`start_rip`, no overlaps: `a.end_rip <= b.start_rip`). `find(fault_rip)` binary
searches for the rightmost entry with `start_rip <= fault_rip`, then confirms
`fault_rip < end_rip`. `is_recoverable` is the boolean form.

### `sort_ranges`

Allocation-free in-place sort by `start_rip` (core's unstable sort), for host
tooling/tests to build a valid table from arbitrary entries. Sorting does not
repair overlaps or duplicates; `new_sorted` still rejects them.

### `FaultResolution` and `resolve_kernel_fault`

The decision the privileged handler makes: `Recover { fixup_rip }` when the
faulting RIP is covered, else `Fatal` (the kernel panic path).

## Intended kernel integration (NOT yet implemented here)

This crate changes no privileged behavior. The planned integration in
`huesos-arch`:

1. The linker emits a sorted `.extable`-style section of `(fault_rip, fixup_rip)`
   entries around each recoverable copy site; each copy site's faulting
   instruction(s) map to a fixup that returns an error code.
2. Wrap that section in an `Extable` (validated once at boot).
3. In the kernel-mode `#PF`/`#GP` handler, when a fault occurs in the copy
   window, call `resolve_kernel_fault(fault_rip, &EXTABLE)`; on `Recover`, set
   the saved `RIP` to `fixup_rip` and return from the exception (the copy
   returns an error); on `Fatal`, take the existing SMP kernel panic path.
4. Add the address-space locking / copy-window guard that prevents a VMAR
   `unmap`/`protect` from racing an in-flight copy, *before* exposing those
   operations; then enable SMEP/SMAP with explicit copy access windows.

## What still requires on-target verification

The following are **not** verified by this change and must be confirmed in QEMU
(`-smp 1`/`-smp 2`) and on hardware before the integration is done:

- The linker-section emission and the fault handler reading this table.
- An actual recoverable copy: a fault during a user-copy is redirected to the
  fixup and returns an error without panicking (and without killing unrelated
  services).
- The copy-window / address-space locking that makes VMAR `unmap`/`protect`
  race-free, and SMEP/SMAP enablement.

These need the full toolchain (pinned nightly + `build-std`, QEMU/OVMF) and were
not runnable where this crate was authored.

## Tests (host)

`make test` includes `-p huesos-extable`. The suite (19 tests) covers
single-instruction and multi-instruction ranges, half-open boundary semantics,
table validation (empty, unsorted, duplicate start, overlapping, empty/inverted
range, adjacent-non-overlapping), binary-search lookup across points/ranges/gaps
and below/above/between misses, `is_recoverable`, `sort_ranges` (and that sorting
does not fix overlaps), and the `resolve_kernel_fault` Recover/Fatal decisions.
