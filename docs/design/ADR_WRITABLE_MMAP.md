# ADR: writable mmap stays disabled on Hxfs

Status: **accepted** (owner-approved). Closes the production-gate item
"coherent writable mmap or explicit decision to keep writable mmap
disabled" by taking the second option.

## Context

The gate offers a choice: implement writable mmap coherently, or
decide, explicitly and in writing, not to offer it. This ADR records
the decision and the criteria that would reopen it.

Hxfs already refuses writable mappings in `cache_policy::decide_mmap`,
which returns `MmapDecision::DenyWritable`. Until now that was an
implementation state, not a decision — nothing said whether it was a
deliberate boundary or an unfinished feature. This document makes it
the former.

## Decision

Hxfs serves **read-only** mappings (`ReadOnlySnapshot`) and refuses
writable ones. `MAP_SHARED`-style writable file mappings are not part
of the v5 contract.

Two independent reasons, either one sufficient.

### 1. Coherence would need a second writeback path

A writable mapping makes the MMU a writer. Pages go dirty without the
filesystem being told, so the dirty set lives in the page tables, not
in Hxfs's own structures. Making that coherent means:

- discovering dirty pages (scanning PTE dirty bits, or taking a fault
  on first write to keep an explicit set);
- ordering those writebacks against `write()`, checkpoints and
  `fsync`, so a checkpoint never captures half a mapped region;
- invalidating mappings when reclaim hands the underlying block to
  another file, in lockstep with the extent table.

That is a second, parallel write path into the same extents as
`write_file_at`, with its own ordering rules against the checkpoint.
Two write paths into one CoW filesystem is precisely the shape of bug
that does not show up in tests and does show up as silent corruption
in the field — and this codebase has already been bitten twice this
cycle by exactly that class of aliasing (the retired metadata region
overlapping live extents; the LBA-only AEAD nonce).

### 2. The encrypted/compressed path cannot be mapped at all

`decide_mmap` returns `DenyTransformed` before it even considers
writability, because an encrypted or compressed extent has no
byte-for-byte on-disk image that a mapping could expose. The bytes on
disk are a GCM envelope or an LZ4 frame; the plaintext exists only in
a decode buffer.

So a writable mmap could only ever be offered on plain, uncompressed
volumes — the configuration a production deployment is *least* likely
to run, since the same gate list requires encryption via a real
KeyProvider. Building a second write path that is unavailable in the
recommended configuration is a poor use of the risk budget.

## Consequences

- `decide_mmap` keeps returning `DenyWritable`, now as a documented
  contract with a test that pins it.
- Callers that need shared mutable state between processes use a VMO
  directly; a VMO is anonymous memory with explicit handles, not a
  file mapping, so no filesystem coherence question arises.
- Read-only mappings of plain files stay available and are unaffected.

## What would reopen this

Any one of:

1. a workload that demonstrably needs writable file mappings and
   cannot use a VMO — a POSIX-compatibility target, or a database
   engine ported to HuesOS;
2. the kernel gaining a general dirty-page tracking facility for other
   reasons, which would remove the largest part of the cost;
3. Hxfs gaining a unified writeback path that `write()` also goes
   through, so mmap writeback would be one more producer into an
   existing queue rather than a second path.

Absent those, this stays closed.
