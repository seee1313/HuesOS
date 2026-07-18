# Generation-safe scheduler task slots

## Problem

Scheduler task IDs are retained by wait queues, timeout tables, interrupt delivery paths, and process/thread metadata. A plain `(cpu, vector_index)` ID cannot safely be reused: a delayed wake for a terminated task could unblock a new, unrelated task that inherited the same vector index. Keeping every tombstone forever avoided that ABA bug but made task metadata grow without bound.

## ID layout

Task IDs are opaque 64-bit values:

| Bits | Meaning |
| --- | --- |
| 63..56 | CPU/LAPIC scheduler index |
| 55..32 | 24-bit slot generation |
| 31..0 | slot index |

Generation zero denotes a slot that has never been reused. Reuse increments the generation and skips zero after wraparound. At 100,000 process launches per second, exhausting all 24-bit generations for one specific slot would still take about 168 seconds; wraparound is therefore not treated as a cryptographic guarantee. The scheduler's memory-safety guarantee is that stale IDs are rejected except after a complete 24-bit reuse cycle. Expanding IDs or retiring wrapped slots is required before HuesOS supports hostile workloads capable of forcing that cycle.

## Lifecycle and ownership

1. A task occupies a stable heap allocation inside `TaskSlot`.
2. Exit marks it finished, removes its fair-runqueue key, and queues its full ID for reaping.
3. Reaping validates CPU, index **and generation**, then releases the kernel stack and process `Arc` and changes the task to `TaskKind::Reaped`.
4. A spawn may replace a reaped tombstone in place. It increments the slot generation before publishing the new runqueue key.
5. Old wait, timeout, policy, runqueue, and duplicate reaper entries fail generation validation and have no effect.

The idle slot (index zero) is never reused. Context addresses remain stable while runnable because the `Task` stays boxed; replacement is allowed only after reaping proves the old task is neither current nor schedulable.

## Concurrency and lock ordering

Generation and occupant are protected by that CPU's `PER_CPU_SCHEDULERS[cpu]` mutex. No caller may cache a `Task` pointer after dropping the mutex. A wake validates and mutates the slot under one lock acquisition, closing the check/use race.

Reaper queue entries are moved into a private batch before scheduler locks are acquired. If the target is still current, the ID is requeued. Stale duplicate entries are discarded before the current-index check so they cannot keep requeuing after a slot has been reused.

Existing global ordering remains:

1. scheduler mutex;
2. never acquire `REAP_QUEUE` while retaining a scheduler mutex except for the bounded current-task requeue path;
3. process teardown occurs after scheduler scans establish that no CPU still runs the process CR3.

A future lock-order audit will remove the remaining scheduler-to-reaper exception by using a per-CPU deferred list.

## Performance

Spawning searches reaped slots linearly. This bounds persistent metadata but is O(number of slots). The current process count is small; if profiling shows launch-heavy workloads, replace the scan with a generation-tagged free-index stack under the same scheduler mutex. Scheduling and waking remain O(1) for slot validation.

Load balancing counts live tasks, not tombstones, so a CPU with historical churn is not incorrectly considered overloaded.

## Tests

Host tests cover ID field isolation and generation wrap/zero skipping. Kernel validation additionally requires:

- repeated process launch/exit beyond the previous maximum slot count;
- a delayed timeout wake for generation N after generation N+1 occupies the slot;
- duplicate reaper entries while the replacement task is current;
- SMP process termination and reschedule IPI races;
- Clippy with warnings denied and release QEMU SMP boot.
