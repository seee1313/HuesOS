# Kernel Object Lifecycle and Registry Collection

## Problem

The original global registry held a strong `Arc<dyn KernelObject>` forever.
Closing the final VMO handle only decremented a diagnostic counter; the registry
Arc kept the VMO alive, so its `Drop` implementation never returned physical
frames. A process could repeatedly create and close VMOs until physical memory
was exhausted. Channels, ports, VMARs, and interrupt objects accumulated in the
same way.

Simply deleting an object when its handle count reaches zero is unsafe. A VMO
may still back a VMAR mapping, a transferred handle may be queued inside a
Channel message, and scheduler/IRQ registries may own typed references.

## Unified registry state

Object discovery, handle counts, kernel reference counts, process indexes, and
IRQ fanout now live behind one mutex. This provides an atomic collection
decision and one lock order instead of independent locks acquired in different
orders.

The registry owns one strong Arc while an object is discoverable. Two counters
determine whether that Arc can be removed:

- **handle references** — handles installed in process tables and handles in
  flight inside Channel messages;
- **kernel references** — non-handle ownership such as a VMAR mapping keeping
  its backing VMO frames alive.

Collection requires both counters to be zero.

## Handle transfer

Channel transfer removes a handle from the sender with
`remove_keep_alive`: the global handle count does not change while the handle is
inside the message. Receiving installs the existing counted handle. Dropping an
unread message releases the count. Thus a transient zero process-table handle
count cannot free an in-flight capability.

## VMO mapping ownership

After a VMO mapping is successfully recorded, the VMAR opens one kernel
reference to the VMO. Closing every VMO handle does not free its frames while
the mapping exists. `Vmar::drop` takes its mapping vector, releases every
reference without holding the VMAR lock, and permits final VMO collection.

The reference is opened only after page-table mapping and metadata recording
succeed, so rejected mapping requests do not leak counts.

## Drop outside the registry lock

Removing an Arc and dropping it are separate phases. The mutex is released
before the removed Arc is dropped. This is mandatory for Channels: dropping a
Channel may drop queued messages, which release transferred handle counts and
re-enter registry collection. Dropping while holding the mutex would deadlock.

## Processes and typed registries

A running process can outlive all userspace process handles because scheduler
tasks own `Arc<Process>`. Its object-discovery entry may disappear, while the
typed process index remains until the process exits. Setting the exit status
re-runs collection; if no wait handle remains, the typed index is removed.
Scheduler/task Arcs then determine the final Rust lifetime.

Interrupt fanout exists only to deliver events to live userspace capabilities.
Final handle collection removes the corresponding typed IRQ entries.

## Tests

Host tests verify:

1. create/register a one-page VMO;
2. install and close its final handle;
3. confirm object lookup fails and the PMM free-frame count returns exactly to
   its starting value;
4. repeat with a kernel mapping reference;
5. confirm final handle close does not free the VMO;
6. release the mapping reference and confirm exact frame reclamation.

The broader integration matrix repeatedly creates, maps, closes, and exits
processes while monitoring free-frame and object counts.

## Remaining work

- Add public diagnostic counters for QEMU/bare-metal soak tests.
- Make VMAR page-table mutation and mapping-reference recording one rollback-
  capable transaction.
- Reclaim finished Task metadata, not only stacks.
- Replace remaining object-specific explicit unregister calls with typed RAII
  ownership where practical.
- Add per-Job handle/memory quotas to bound intentional retention.
