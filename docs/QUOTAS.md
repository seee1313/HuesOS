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

The full `Job` integration is deliberately still separate: `huesos-object::Job`
does not yet own a `QuotaTree`, and process memory/handle/CPU usage is not yet
charged to a hierarchical Job. Until that integration lands, queue limits are
per-object bounded quotas, not system-wide parent Job quotas.

## Required privileged integration

Before exposing user-configurable quotas, the kernel must:

- attach every Process to a Job node;
- charge VMO physical frames and address-space mappings;
- charge process and in-flight handle references;
- charge CPU time from scheduler accounting;
- release charges only after the corresponding object/task lifecycle reaches a
  terminal state;
- make charge/release operations atomic with object registry and reaper state;
- add QEMU SMP tests for concurrent charge, release, and process exit.

The policy crate's host tests cover flat quotas, parent/child budgets, sibling
sharing, release, saturation, and invalid/cross-tree node rejection. They do
not prove the privileged integration.
