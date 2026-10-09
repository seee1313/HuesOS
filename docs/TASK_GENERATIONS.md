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
   occupant Reaped; a replacement publishes a fresh generation. The current
   kernel reaper does not call TaskDirectory::clear or drain its operation bits
   here. Do not attribute the directory helper's stronger clear contract to
   this integration without a separate change and verification.
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

Host tests cover ID field isolation and the helper's non-wrapping increment
contract. This does not prove kernel retirement at the 51-bit boundary.
A deterministic host probe of the current reaper-style helper sequence
(old WAKE → free/reallocate without clear → publish replacement → take) returns
the old WAKE bit for the replacement, rather than zero. This is a known
integration gap; a full kernel reproduction and a synchronized publication/
reclamation fix remain open. Ordinary QEMU boot does not close it.

Kernel validation additionally requires:

- repeated process launch/exit beyond the previous maximum slot count;
- a delayed timeout wake for generation N after generation N+1 occupies the slot;
- duplicate reaper entries while the replacement task is current;
- SMP process termination and reschedule IPI races;
- Clippy with warnings denied and release QEMU SMP boot.
