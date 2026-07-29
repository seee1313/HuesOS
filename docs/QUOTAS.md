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

CPU tick accounting is charged from the scheduler to the owning Job. When a
Job charge fails, the kernel does not kill the process automatically; it queues a
`PORT_PACKET_QUOTA_EXHAUSTED` packet to every Port bound with
`JobBindQuotaPort`. Supervisors can decide whether to throttle, terminate, or
raise limits.

Userspace quota control is append-only in the ABI:

- `JobDefault` returns a handle to the caller's current Job;
- `JobCreate` creates a bounded child Job;
- `JobSetLimits` replaces a Job's limits;
- `JobBindQuotaPort` subscribes a Port to exhaustion notifications;
- `ProcessCreateInJob` creates a suspended process owned by an explicit Job.

The active enforcement points are VMO frame allocation, scheduler CPU ticks, and
bounded Channel/Port queues. Finer-grained classes such as page-table metadata
and per-process handle-table hard caps can be added as separate counters without
changing the Job hierarchy API.

## Required privileged integration

The policy crate's host tests cover flat quotas, parent/child budgets, sibling
sharing, release, saturation, and invalid/cross-tree node rejection. Privileged
integration must continue to be validated by QEMU/SMP stress tests for
concurrent charge, release, process exit, and quota-port delivery.
