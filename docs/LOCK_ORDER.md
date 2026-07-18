# Kernel lock ordering

## Rule

A thread may acquire locks only from lower rank to higher rank. It must not context-switch, enter userspace, perform an unbounded allocation, or execute object destructors while retaining a scheduler/registry lock. IRQ paths may acquire only locks explicitly marked IRQ-safe.

## Current rank model

| Rank | Domain | Representative locks |
| ---: | --- | --- |
| 10 | immutable boot/architecture state | HHDM offset, paging initialization |
| 20 | object registry indexes | `REGISTRY`, process and interrupt indexes |
| 30 | object-local state | HandleTable, Channel, Port, Interrupt, VMO, VMAR |
| 40 | process runtime | `Process::address_space`, Thread task ID |
| 50 | wait metadata | WaitQueue waiter vectors, timeout table |
| 60 | scheduler instance | `PER_CPU_SCHEDULERS[cpu]`, fair queue |
| 70 | deferred teardown queues | `REAP_QUEUE`, `PROCESS_TEARDOWN` |
| 80 | allocator internals | slab and buddy metadata |

Allocator calls are forbidden while ranks 20–70 are held unless the operation is proven allocation-free. Dropping an `Arc<dyn KernelObject>` is treated as potentially acquiring ranks 20–80 and must happen after registry locks are released.

## Scheduler and reaper

Context-switch pointers are selected under one per-CPU scheduler mutex, but the mutex is dropped before assembly switches contexts. Reaper and process teardown queues are drained into private batches before scheduler locks are taken. Startup-entry cancellation happens before scheduler acquisition.

Deferred teardown executes after ordinary syscall dispatch has released subsystem locks, with the BSP idle loop as a fallback. It may free page tables, handles, VMOs, and allocator memory; none of this occurs in timer IRQ context. The atomic pending flag provides a lock-free fast path when no lifecycle work exists. A currently executing generation is requeued under the present bounded scheduler-to-reaper exception, which remains scheduled for removal when deferred queues become per-CPU.

## Registry

The unified registry atomically updates object ownership counts and indexes. Removed `Arc`s are returned from the critical section and dropped afterward. Channel destruction may recursively close transferred handles, which is why dropping under `REGISTRY` is forbidden.

## VMAR and process runtime

The order is process runtime → VMAR-local metadata → registry reference accounting. VMAR mapping is transactional: reserve metadata and kernel VMO reference, install pages, then publish success. Rollback removes pages in reverse order and releases registry ownership after metadata removal.

## IRQ constraints

Timer IRQ may:

- lock the current CPU scheduler;
- move runnable state;
- scan timeout metadata after releasing the scheduler;
- perform the assembly context switch after all Rust guards are dropped.

Timer IRQ must not tear down processes, drop object graphs, parse firmware, or allocate framebuffer-sized buffers. Device IRQ paths may enqueue bounded Port packets and wake a task but may not wait on process-runtime or filesystem locks.

## Runtime enforcement status

`RankedIrqSafeTicketLock` enforces non-decreasing rank order in **all builds**. Each CPU owns a fixed-capacity rank stack selected through GS-based `CpuLocal` state; acquiring a ranked lock disables local interrupts before touching that stack. The implementation rejects rank inversions, recursive acquisition, excessive nesting, and non-LIFO guard release. Contract violations use lock-independent emergency serial output and fail-stop rather than entering the ordinary panic path while synchronization state may be corrupt.

The context-switch and ring0→ring3 assembly boundaries call `assert_no_ranked_locks_held`, so a ranked guard cannot silently survive a task switch or userspace entry. The allocator, per-CPU scheduler, task reaper, and process-teardown queues have been migrated. Legacy `spin::Mutex` instances remain in object-local and callback-registration code; those locks are still governed by this table but do not yet provide runtime evidence. They must be migrated before runtime enforcement is considered complete.

Rank tracking starts after `init_gs_base`. HuesOS deliberately keeps pre-GS serial/GDT bootstrap locks unranked; AP and BSP initialization install their unique tracker index before allocator, scheduler, object, or firmware runtime work begins.

## Review checklist

For every new lock or acquisition:

1. assign a rank and document whether IRQ-safe;
2. list every lock already held at acquisition;
3. prove no destructor or allocator call occurs in the critical section;
4. prove all guards are dropped before park/yield/context switch/user entry;
5. add an SMP stress case for cross-CPU paths;
6. update this document and the machine-readable lock inventory when introduced.
