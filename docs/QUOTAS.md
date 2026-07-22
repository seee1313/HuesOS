# Resource Quotas

`huesos-quota` is the host-testable policy core for hierarchical Job resource
accounting. It is intentionally independent of locks, scheduler state, page
tables, and handles so its admission decisions can be tested on the host.

## Resources

The model tracks:

- `Memory` — bytes;
- `Handles` — capability/handle count;
- `CpuTicks` — scheduler ticks.

`UNLIMITED` disables a limit. Accounting uses saturating arithmetic so malformed
release paths cannot underflow and overflow cannot turn a denied acquisition
into an allowed one.

## Hierarchical policy

`QuotaTree` models the Job hierarchy. A charge to a child is checked against:

1. the child's own limit; and
2. every ancestor's aggregate subtree usage.

This makes sibling Jobs share their parent's budget. Node identifiers are tagged
to their originating tree; cross-tree and invalid identifiers return a normal
error/result rather than indexing and panicking.

## Current kernel use

The bounded Channel and Port queues use `huesos-quota::Quota` for their local
byte/packet admission budgets. This prevents unbounded IPC retention and avoids
allocating from the keyboard IRQ path after a Port is created.

`huesos-object::Job` now owns a shared hierarchical `QuotaTree`, and every
Process is attached to a Job. VMO physical-frame allocation is charged to the
owning Job before frames are allocated and released from the same Job on VMO
Drop. The root Job remains unlimited by default, preserving the existing MVP
behavior.

CPU tick accounting is now charged from the scheduler to the owning Job. The
current MVP records budget exhaustion but does not yet throttle or terminate a
process because the supervisor policy is not finalized.

Handle-count accounting is now charged to the Process Job for locally installed
handles. A transferred capability keeps its sender Job charge while in flight
and moves the charge to the receiving Job on successful receipt; failed queue
admission and failed destination admission preserve the original ownership.
Page-table accounting and user-visible Job creation/limits remain outstanding.
Until those charges are integrated, queue, VMO, CPU, and handle accounting are
active but the complete system-wide resource budget is not yet enforced.

## Required privileged integration

Before exposing user-configurable quotas, the kernel must:

- attach every Process to a Job node; (implemented with unlimited root default)
- charge VMO physical frames; (implemented)
- charge address-space mappings;
- charge process and in-flight handle references; (handle path implemented)
- charge CPU time from scheduler accounting; (accounting implemented)
- release charges only after the corresponding object/task lifecycle reaches a
  terminal state;
- make charge/release operations atomic with object registry and reaper state;
- add QEMU SMP tests for concurrent charge, release, and process exit.

The policy crate's host tests cover flat quotas, parent/child budgets, sibling
sharing, release, saturation, and invalid/cross-tree node rejection. They do
not prove the privileged integration.
