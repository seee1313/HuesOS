# Transactional VMAR Mapping and Task Reaping

## Mapping failure model

A userspace `VmarMap` request touches three independently managed resources:

1. VMAR overlap metadata;
2. page-table entries and intermediate table frames;
3. a kernel reference keeping the backing VMO frames alive.

Previously pages were installed first and metadata was recorded last. Two
threads could both pass the overlap check, and a later `map_to(...).expect()`
could panic the kernel. Any mid-operation failure also left a partially mapped
range with no matching VMAR record.

## Transaction order

The mapping path now performs:

1. pure argument/permission/range validation;
2. validation of every requested VMO frame;
3. atomic VMAR check-and-reserve under the mapping lock;
4. acquisition of one VMAR-owned VMO kernel reference;
5. fallible page installation;
6. commit by returning success.

If page installation fails, already installed pages are unmapped in reverse
order, the exact metadata reservation is removed, and the VMO kernel reference
is released. The caller receives `NoMemory`, `Busy`, or `InvalidArgs`; ordinary
resource pressure no longer reaches `expect` in this syscall path.

## Inactive address-space API

`AddressSpace::try_map_user_page` maps a non-owned VMO frame and returns typed
errors for intermediate-frame OOM, existing mappings, and huge parents.
`unmap_user_page` supports rollback and reports not-mapped, huge-parent, and
invalid-frame cases. Both ignore TLB flush tokens because the child CR3 is
inactive; the first CR3 activation starts without stale translations.

Empty intermediate tables created by a failed transaction remain owned by the
address space and are reclaimed by its normal recursive destruction. Data
frames remain VMO-owned throughout rollback.

## Finished task ownership

Task IDs encode a stable vector index, so physically removing vector elements
would invalidate IDs held by wait queues and reaper queues. Finished slots are
therefore converted to `TaskKind::Reaped`:

- kernel stack storage is released;
- the `Arc<Process>` in `TaskKind::User` is dropped;
- scheduling policy/context metadata remains as a small tombstone;
- the finished flag permanently excludes the slot from scheduling.

This removes the large/process-owning resources without renumbering historical
tasks. A future generation-based slot allocator can safely reuse tombstones.

## Tests and invariants

- exact VMAR reservation removal is unit-tested through mapping bookkeeping;
- object lifecycle tests verify mapping references retain VMO frames;
- Clippy runs with warnings denied;
- host/kernel tests and SMP QEMU boot must pass;
- no rollback path may free a VMO-owned data frame;
- no active/current task may be reaped.
