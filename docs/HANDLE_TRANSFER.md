# Handle-Transfer Semantics (`huesos-handlemove`)

Status: **policy + host tests landed; privileged channel-send integration and
on-target behavior not yet implemented or verified.**

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

## Intended kernel integration (NOT yet implemented here)

This crate changes no privileged behavior. The planned integration:

1. The channel send path builds `Disposition`s from the caller's handle list
   (validated through the user-memory copy layer), each with its requested
   rights and Move/Duplicate operation.
2. `transfer` runs against the sender's handle table and a staging area for the
   message; on `Err`, the send fails cleanly with no partial drain (the
   transactional rollback the roadmap calls for).
3. In-flight messages hold the transferred handle counts until receipt or drop
   (already the case via `remove_keep_alive`), consistent with the registry
   collection model in `huesos-lifecycle`.

## What still requires on-target verification

- Wiring `transfer` into the actual channel send/receive path.
- Transactional rollback under concurrent close/transfer races and peer
  closure mid-send.
- Rights enforcement end-to-end across processes, and stress testing
  concurrent close/transfer.

These need the full toolchain (pinned nightly + `build-std`, QEMU/OVMF) and were
not runnable where this crate was authored.

## Tests (host)

`make test` includes `-p huesos-handlemove`. The suite (13 tests) covers rights
operations and the monotonic `transfer_rights` (never adds, can reduce), table
insert/get/remove/full/out-of-range, Move (removes source, reduces rights),
Duplicate (keeps source, reduces rights), empty-disposition no-op, and —
critically — atomicity: `NoSuchHandle`, `MissingRight` (including
`Duplicate` requiring `DUPLICATE`), `AlreadyStaged`, and `DestinationFull` each
leave **both** tables unchanged.
