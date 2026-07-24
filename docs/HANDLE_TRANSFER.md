# Handle-Transfer Semantics (`huesos-handlemove`)

Status: **policy + host tests landed; bounded queue admission and rollback on
queue rejection are now integrated, but the policy crate is not yet the single
implementation used by the privileged channel path and concurrent close/send
behavior still requires on-target verification.**

This document describes the host-testable crate `huesos-handlemove` and how it
is intended to plug into the kernel. It supports
[ROADMAP.md](ROADMAP.md) Short-Term #6 (*handle transfer semantics*:
transactional rollback when peer closure/send failure becomes observable,
richer typed handle dispositions, stress on concurrent close/transfer).

## Why this matters

Channels move capabilities between processes by transferring handles. Two
invariants must hold:

1. **Rights monotonicity** — a transferred/duplicated handle may keep or
   *reduce* the source's rights, never *add* rights the source lacks.
2. **Atomicity** — a message carrying several handles transfers all of them or
   none. A validation failure (missing handle, missing right, repeated handle,
   full destination) must leave both the sender's and receiver's tables
   unchanged, so a failed send cannot partially drain a process's handles.

## Why a separate crate

The rights computation, the typed dispositions, and the all-or-nothing transfer
algorithm are pure and hardware-independent. Following the project's hardening
pattern (`huesos-lifecycle`, `huesos-ioapic`, `huesos-extable`,
`huesos-waitset`, `huesos-proclife`), we extract them into a dependency-free,
`no_std`, host-testable crate so the invariants are unit-tested without
channels, the scheduler, or `unsafe`, and the privileged send path is held to a
written, tested specification.

The crate is **budget-neutral**: no `unsafe`, no `unwrap`/`expect` calls, and no
panicking macros (tests included), so `tools/check-safety-budget.py` is
unaffected.

## Contents

### `Rights` and `transfer_rights`

A rights bitset (`DUPLICATE`, `TRANSFER`, `READ`, `WRITE`, `SIGNAL`) with set
operations. `transfer_rights(source, requested)` is the intersection — it can
reduce rights (request fewer) but never add rights the source lacks.

### `HandleTable<N>`

A bounded handle→rights table (dense indices). `insert`/`get`/`remove`/
`contains`/`available` model one process's handle table in transfer tests.

### `DispOp` and `Disposition`

A typed disposition: a source `handle`, an operation (`Move` removes the source
handle and requires `TRANSFER`; `Duplicate` keeps it, creates a new handle with
reduced rights, and requires `DUPLICATE`), and the `rights` requested for the
destination handle.

### `transfer` (all-or-nothing)

`transfer(src, dst, disps) -> Result<usize, TransferError>`:

- **Phase 1 (validate, no mutation):** every handle exists; each has the right
  required by its operation; no handle is staged twice (`AlreadyStaged`); and
  `dst` has capacity for one new handle per disposition (`DestinationFull`).
  Any failure returns an error and leaves both tables unchanged.
- **Phase 2 (apply, total given phase 1):** Move removes the source handle,
  Duplicate keeps it; each destination handle receives
  `transfer_rights(source, requested)`.

`TransferError` ∈ {`NoSuchHandle`, `MissingRight`, `AlreadyStaged`,
`DestinationFull`}.

## Current privileged integration boundary

The syscall channel path now validates the complete handle list before removal,
removes it as one handle-table batch, and restores the original handle slots if
bounded queue admission fails. In-flight messages still hold the global handle
count until receipt or drop. Queue admission is quota-bound and therefore
returns a normal resource error instead of growing without limit.

The userspace `libcanvas::Channel::write_handle` wrapper consumes an owned
`Handle` before issuing `ChannelWrite`. If the syscall fails, the kernel's
all-or-nothing contract leaves the raw handle value in the sender's table (or a
close on that value is harmless if a future kernel path consumed it despite
returning an error). The wrapper therefore closes the raw value on failure so
ordinary `?` error paths do not leak a capability.

The pure `transfer` function remains the normative policy model, but the kernel
has not yet replaced its object-specific handle representation with the policy
crate's `Disposition` table. That is an intentional next step so the model can
be wired without duplicating rollback semantics.

## What still requires on-target verification

- Rights enforcement end-to-end across processes, including the `DUPLICATE`
  right and per-permission VMO mappings.
- Transactional rollback under concurrent handle-table allocation and queue
  rejection races.
- QEMU/SMP stress testing of concurrent close, transfer, receive, and object
  collection; the peer-close state and `PeerClosed` ABI status are now wired.

## Tests (host)

`make test` includes `-p huesos-handlemove`. The suite (13 tests) covers rights
operations and the monotonic `transfer_rights` (never adds, can reduce), table
insert/get/remove/full/out-of-range, Move (removes source, reduces rights),
Duplicate (keeps source, reduces rights), empty-disposition no-op, and —
critically — atomicity: `NoSuchHandle`, `MissingRight` (including
`Duplicate` requiring `DUPLICATE`), `AlreadyStaged`, and `DestinationFull` each
leave **both** tables unchanged.
