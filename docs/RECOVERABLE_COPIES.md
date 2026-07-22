# Recoverable Copies: Exception / Fixup Table (`huesos-extable`)

Status: **policy + privileged copy/fault integration landed as an opt-in
extable test path; normal boot remains on the existing fatal fault policy until
the release linker-table smoke is promoted.**

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

## Current privileged integration

The kernel now emits four `(fault range, fixup)` entries from the assembly
user-copy primitives into a linker `.ex_table` section. An opt-in HBI test
image installs the `huesos-extable` lookup callback; the page-fault handler then
redirects a kernel-mode RIP to the fixup when it falls inside one of the copy
ranges. The fixup returns `-1`, which the validated user-copy layer maps to
`InvalidArgs`. Normal images keep the established fatal kernel-fault policy
until release-mode linker-table validation is promoted.

Process user-memory locking and VMAR mutation locking prevent the normal
validation/copy race; the cross-CPU TLB shootdown handles stale translations.
The copy primitives remain bounded and execute only while `UserAccessGuard` has
opened the SMAP window.

## What still requires on-target verification

The remaining on-target work is:

- deliberate fault injection during each load/store fixup range;
- validation that a recoverable kernel copy does not kill unrelated services;
- coverage for recoverable faults from additional copy helpers;
- full SMEP/SMAP and STAC/CLAC stress under IRQ and SMP pressure;
- eventual removal of the address-space lock once all required copies are
  proven fault-recoverable.

## Tests (host)

`make test` includes `-p huesos-extable`. The suite (19 tests) covers
single-instruction and multi-instruction ranges, half-open boundary semantics,
table validation (empty, unsorted, duplicate start, overlapping, empty/inverted
range, adjacent-non-overlapping), binary-search lookup across points/ranges/gaps
and below/above/between misses, `is_recoverable`, `sort_ranges` (and that sorting
does not fix overlaps), and the `resolve_kernel_fault` Recover/Fatal decisions.
