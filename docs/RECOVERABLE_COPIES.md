# Recoverable Copies: Exception / Fixup Table (`huesos-extable`)

Status: **policy core, privileged fault-handler hook, recoverable user-copy
primitives, bulk/typed `user_memory` wire-up, and synthetic QEMU smoke coverage
landed.** Remaining work is SMEP/SMAP copy-window hardening, mapping
splits/child VMAR support, and a real cross-CPU race probe once intra-process
threading exists.

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

## Kernel integration status

The kernel integration is now live for validated user-copy sites:

1. Recoverable copy helpers emit `.ex_table` entries around the exact
   `rep movsb` instruction that may fault.
2. Boot-time extable installation reads the linker-emitted section, validates
   and sorts it, and publishes a kernel-lifetime snapshot.
3. The ring-0 `#PF` path consults the extable and redirects recoverable faults
   to the emitted fixup address; non-covered faults still take the fatal panic
   path.
4. `huesos-syscalls::user_memory::{copy_from_user, copy_to_user,
   read_value, read_array, write_value, write_array}` route through those
   recoverable primitives after bounds and page-table validation.

Still pending: complete the SMEP/SMAP copy-window hardening and mapping
split/child-VMAR support before exposing broader concurrent mapping mutation.

## What still requires on-target verification

The following still require QEMU (`-smp 1`/`-smp 2`) and hardware coverage:

- A real userspace race between validated copy and concurrent mapping mutation;
  the current CI probe is synthetic because userspace does not yet expose
  intra-process threading.
- The copy-window / address-space locking that makes broader VMAR
  `unmap`/`protect` race-free, including mapping splits and child VMARs.
- Hardware SMEP/SMAP coverage across CPUs and supported/unsupported feature
  combinations.

## Tests (host)

`make test` includes `-p huesos-extable`. The suite (19 tests) covers
single-instruction and multi-instruction ranges, half-open boundary semantics,
table validation (empty, unsorted, duplicate start, overlapping, empty/inverted
range, adjacent-non-overlapping), binary-search lookup across points/ranges/gaps
and below/above/between misses, `is_recoverable`, `sort_ranges` (and that sorting
does not fix overlaps), and the `resolve_kernel_fault` Recover/Fatal decisions.
