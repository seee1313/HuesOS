# Generation-safe scheduler task slots

## Problem

Scheduler task IDs are retained by wait queues, timeout tables, interrupt delivery paths, and process/thread metadata. A plain `(cpu, vector_index)` ID cannot safely be reused: a delayed wake for a terminated task could unblock a new, unrelated task that inherited the same vector index. Keeping every tombstone forever avoided that ABA bug but made task metadata grow without bound.

## Current ID layout

The supported runtime uses `huesos_sched::TaskId`, not the historical
CPU/24-bit-generation/vector-index encoding. CPU ownership lives in
`TaskDirectory` and can change without changing identity.

| Bits | Meaning |
| --- | --- |
| 63..13 | 51-bit nonzero slot generation |
| 12..0 | Global slot index (8192 slots) |

`TaskId::new` rejects generation zero and generations above
`MAX_TASK_GENERATION = u64::MAX >> 13`. `TaskId::next_generation` returns None
at that bound. Kernel creation uses `TaskSlotAllocator`; if its returned
counter cannot be encoded, the kernel frees the slot and returns a failed
allocation without publishing an identity. Permanent retirement at the 51-bit
TaskId bound is not implemented by that failure path; do not infer it from
`TaskId::next_generation`. The allocator has a separate u64 counter limit.

## Lifecycle and ownership

1. Global allocation obtains a slot and nonzero generation, then TaskDirectory
   publishes its owner CPU and owner-local index.
2. A runnable Task remains boxed at a stable address inside a per-CPU TaskSlot.
3. Exit marks it finished and queues the full identity for deferred reaping.
4. Reaping resolves the directory and validates the complete task identity;
   stale/duplicate entries are discarded before the current-task check.
5. Current reaping releases the global allocation after marking the owner-local
   occupant Reaped; a replacement publishes a fresh generation. Reaping drains
   remote operations at retire time: `TaskDirectory::retire` atomically reports
   the pending operation mask in the same publication step that discards it, so
   no pending bit can leak into the replacement generation. The kernel counts
   drained bits and affected tasks in observability counters
   (`sched_stats().reap_discarded_op_flags` / `reap_tasks_with_discarded_ops`).
   Pending remote operations on a dying identity are dropped, never applied.
   Do not substitute the directory `clear` contract (which fails while
   operations are pending) for `retire` here.
6. CPU ownership is separate from identity; any remote operation must validate
   the published full identity and obey owner/runqueue-token contracts.

A Process ExitInfo generation is a different domain from TaskId generation.
See [OBJECT_LIFECYCLE.md](OBJECT_LIFECYCLE.md) for graveyard exit identity.

## Concurrency and lock ordering

The runtime combines atomic TaskDirectory/TaskSlotAllocator state with the
owner CPU's `PER_CPU_SCHEDULERS[cpu]` lock. Occupants are protected by the
owner scheduler lock. No caller may cache a `Task` pointer after dropping the mutex. Owner-local wake processing validates the live occupant under this lock.
Remote publishers use atomic directory operations instead; do not extend the
local lock guarantee to concurrent publication/reuse. In particular,
`publish_operations` checks identity before its atomic OR, rather than updating
identity and pending bits as one generation-tagged transaction.

Exit paths set an atomic `REAP_PENDING` flag. After an ordinary syscall returns with subsystem locks released, the kernel services pending teardown in process context; the BSP idle loop remains a fallback for a quiescent system. This avoids both dependence on idle scheduling and the timeout/wakeup interference caused by an earlier periodic reaper-thread design. Expensive address-space/Object drops never run in timer IRQ context. Queue entries are moved into a private batch before scheduler locks are acquired. If the target is still current, the ID is requeued and pending remains armed. Stale duplicate entries are discarded before the current-index check so they cannot keep requeuing after a slot has been reused. Startup records for tasks killed before first schedule are cancelled by their full generation-bearing ID.

Existing global ordering remains:

1. scheduler mutex;
2. never acquire `REAP_QUEUE` while retaining a scheduler mutex except for the bounded current-task requeue path;
3. process teardown occurs after scheduler scans establish that no CPU still runs the process CR3.

A future lock-order audit will remove the remaining scheduler-to-reaper exception by using a per-CPU deferred list.

## Performance

Global allocation scans a bounded bitmap; directory lookup and owner-local
identity validation are bounded. Do not describe global allocation as an O(1)
free-index stack. Current placement is owner-local/token-mediated, not an
automatic global load-average balancer. Deferred reaping keeps task resources
separate from the bounded process-exit graveyard.

## Tests

Host tests (`crates/huesos-sched/src/generation_regressions.rs`) cover ID
field isolation, the non-wrapping generation increment, checked `clear`,
forced retirement, generation-tagged CAS interleavings, concurrent
publication, and the reuse sequence including the kernel release order
(retire → mark Reaped → free global slot → allocate → publish → take).
The pending-operation carry-over at reap is closed at the directory and
integration level:

- `retire_reports_pending_remote_operations_atomically` — retire returns
  exactly the pending WAKE|MIGRATION mask, one-shot; the identity is
  unpublished and later operations fail with `StaleIdentity`.
- `retire_reports_empty_mask_when_no_operations_pending` — clean retire
  reports zero.
- `replacement_generation_never_inherits_discarded_remote_operations` — the
  exact kernel release order; the replacement generation's take reports
  `Ok(0)`.
- `publish_replacement_discards_stale_flags_even_without_retire` —
  defense-in-depth: even if the global slot were freed without retiring,
  `publish` replaces the generation-tagged word on reuse, so stale flags
  never reach the replacement.
- `stale_producers_and_consumers_cannot_cross_concurrent_slot_churn` —
  concurrent publishers/consumers across a retire and repeated reuse.
- `reaper_retirement_recycles_more_than_global_capacity_without_carry_over` —
  2×-capacity recycle with the retire-before-free order.

Drain-at-retire is an intentional drop: remote operations on a dying identity
are not applied, forwarded, or retried. They are only counted, for boot/CI
evidence and future soak tooling. If a dying identity shows a non-zero
`reap_discarded_op_flags`, that is a signal about the remote publisher, not a
scheduling invariant violation.

Kernel validation additionally requires:

- repeated process launch/exit beyond the previous maximum slot count;
- a delayed timeout wake for generation N after generation N+1 occupies the slot;
- duplicate reaper entries while the replacement task is current;
- SMP process termination and reschedule IPI races;
- Clippy with warnings denied and release QEMU SMP boot.

The directory/integration level is host-tested; the on-target items above
are not closed by host tests. Ordinary QEMU boot does not close them either.
