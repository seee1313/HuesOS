# Scheduler and SMP research record

Status: architecture research, no implementation claim.

This document records the operating-system schedulers examined before the
HuesOS Scheduler/SMP v2 design was approved. It exists to preserve rationale:
future changes must not copy a mechanism without also understanding the
trade-off that caused another system to use it.

The target is a high-throughput, security-oriented x86-64 microkernel without
NUMA support in this phase. "Production-grade" is an exit criterion backed by
model tests, stress tests, measurements, and physical Intel/AMD evidence. It is
not a property conferred by resemblance to Linux or another kernel.

## Current HuesOS findings

The pre-v2 scheduler already has per-CPU schedulers, weighted fair and
EDF-like policies, generation-bearing task IDs, affinity, ranked IRQ-safe
locks, and a separate reschedule IPI. The audit found blockers:

- `Scheduler::tick()` scans the complete task table for deadline release and
  selection on each tick;
- the fair queue uses `BTreeSet` mutations in hard scheduling context;
- remote wake waits synchronously for a runqueue token and can return without
  publishing the wake;
- work stealing is compiled but not called;
- migration changes Task ID and relies on a bounded alias table;
- deadline policy has no admission control and is not a Constant Bandwidth
  Server;
- accounting is in BSP-derived periodic ticks, not elapsed time;
- MADT and IPI paths assume 8-bit APIC IDs;
- userspace SIMD is disabled because xstate is not switched;
- syscall execution keeps interrupts masked;
- most kernel locks mask local interrupts, preventing a genuinely preemptible
  kernel.

These findings require a scheduler foundation replacement, not incremental
heuristic tuning.

## Linux

Studied mechanisms:

- EEVDF eligibility, lag, virtual requests, and wakeup preemption;
- per-CPU runqueues;
- remote `ttwu` wake lists;
- scheduler domains and deferred balancing;
- preemption counters and `need_resched`;
- NO_HZ and high-resolution timer integration;
- cgroup group scheduling and bandwidth control;
- SMT core-scheduling cookies;
- eager xstate switching and PCID/INVPCID.

Adopt:

- EEVDF principles;
- owner-applied remote wake operation;
- separate preemption and IRQ nesting state;
- deferred load balancing;
- explicit group weight and hard bandwidth as different controls;
- trust-domain concept for SMT.

Do not adopt in this phase:

- NUMA domain hierarchy;
- cgroup ABI and full recursive controller machinery;
- PELT in its complete form;
- energy-aware scheduling;
- legacy scheduler-class compatibility;
- direct remote runqueue locking.

Important warning: Linux EEVDF sleeper placement and entity reweighting have
continued to receive corrections. HuesOS will use an independently testable
request-based model rather than translating `fair.c` line for line.

References:

- https://www.kernel.org/doc/html/latest/scheduler/sched-eevdf.html
- https://www.kernel.org/doc/html/latest/scheduler/sched-domains.html
- https://www.kernel.org/doc/html/latest/timers/no_hz.html
- https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/core-scheduling.html
- https://github.com/torvalds/linux/commit/dd960a0ddd43b5f7c7e53b55ac17e

## Zircon

Studied mechanisms:

- hybrid Fair and Deadline disciplines;
- per-CPU scheduler instances;
- virtual start/finish timeline;
- augmented WAVL ready queues;
- last-CPU and affinity-aware placement;
- idle work stealing;
- eager x86 extended-register switching.

Adopt:

- augmented ordered-queue invariants;
- virtual start/finish representation;
- separate fair, deadline-ready, and replenishment queues;
- affinity/cache-aware placement.

Defer:

- DVFS and energy models;
- heterogeneous processing-rate accounting;
- critical-deadline class separate from ordinary reservations.

References:

- https://fuchsia.dev/fuchsia-src/concepts/kernel/kernel_scheduling
- https://fuchsia.dev/fuchsia-src/concepts/kernel/fair_scheduler
- https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/kernel/scheduler.cc

## FreeBSD ULE

Studied mechanisms:

- per-CPU queues and fine-grained queue locks;
- topology-aware CPU selection;
- cache-affinity windows;
- idle pull and periodic push balancing;
- critical nesting and deferred kernel preemption;
- thread pinning separate from preemption.

Adopt:

- pull plus push balancing;
- migration hysteresis;
- physical-core topology;
- nested preemption-disable and migration-disable semantics.

Reject:

- pair-locking source and destination runqueues;
- interactive-class absolute preference, which can starve batch work.

References:

- https://man.freebsd.org/cgi/man.cgi?query=sched_ule
- https://docs.freebsd.org/en/books/arch-handbook/smp/
- https://www.usenix.org/legacy/event/bsdcon03/tech/full_papers/roberson/roberson.pdf

## DragonFlyBSD

DragonFly is the closest precedent for HuesOS single-writer runqueue
ownership. Each CPU owns a self-contained LWKT scheduler. Foreign scheduling
operations execute on the target CPU through asynchronous IPI messages.

Adopt:

- only the owner CPU mutates a local runqueue;
- remote operation is explicit message publication;
- IPI batching/coalescing;
- CPU-local critical sections instead of remote queue locks;
- kernel-context migration requires explicit CPU-local safety.

Reject:

- an IPI FIFO that can fill and force the producer to wait/process incoming
  queues;
- automatic token release/reacquisition semantics;
- a second independent user scheduler layer.

The HuesOS task bitmap has no queue-full condition for coalescible scheduler
operations.

References:

- https://www.dragonflybsd.org/features/
- https://raw.githubusercontent.com/DragonFlyBSD/DragonFlyBSD/master/sys/kern/lwkt_thread.c
- https://raw.githubusercontent.com/DragonFlyBSD/DragonFlyBSD/master/sys/kern/lwkt_ipiq.c
- https://raw.githubusercontent.com/DragonFlyBSD/DragonFlyBSD/master/sys/kern/usched_dfly.c

## NetBSD and OpenBSD

NetBSD uses per-CPU queues, periodic balancing, and idle stealing. It is useful
as confirmation that cache-affinity thresholds are required, but its classic
priority policies are not the HuesOS fair-policy target.

OpenBSD uses a deliberately conservative scheduler and has historically
favoured disabling SMT when security cannot be established. This supports an
explicit strict `smt=off` policy rather than claiming that trust cookies solve
all cross-HT risks.

References:

- https://mail-index.netbsd.org/current-users/2011/02/01/msg015577.html
- https://www.openbsd.org/papers/asiabsdcon2010_smp_for_sgi_paper.pdf

## XNU Clutch/Edge

Studied mechanisms:

- hierarchical bucket, thread-group, and thread scheduling;
- workload-level fairness rather than only per-thread priority;
- per-cluster queues and migration edges;
- EDF-like bucket selection and starvation windows.

Adopt:

- resource-domain/Job grouping above threads;
- explicit workload identity to prevent thread-count amplification.

Reject/defer:

- QoS bucket ABI;
- asymmetric P/E cluster policy;
- thermal/performance-controller integration.

Reference:

- https://github.com/apple-oss-distributions/xnu/blob/main/doc/scheduler/sched_clutch_edge.md

## Windows NT

Studied mechanisms from public architecture material:

- per-processor ready queues and summaries;
- DeferredReady state;
- ideal and previous processor;
- preference for a fully idle physical core over an SMT sibling;
- DPC deferred interrupt work.

Adopt:

- deferred placement as an explicit state;
- physical-core-first placement;
- owner CPU finalizes ready-queue insertion.

Do not adopt:

- fixed-priority dynamic-boost policy as the ordinary Fair scheduler.

Reference:

- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadidealprocessor

## illumos/Solaris

Studied mechanisms:

- pluggable scheduling classes;
- per-CPU dispatch queues;
- bound-thread semantics;
- deferred dispatch and tracing probes.

Adopt:

- trace points around enqueue, dequeue, wake, migrate, and context switch;
- explicit distinction between pinned and migratable tasks.

Do not adopt:

- priority-class policy as the general-purpose Fair policy.

References:

- https://illumos.org/books/dtrace/chp-sched.html
- https://illumos.org/books/dev/layout.html

## QNX Neutrino

Studied mechanisms:

- strict-priority scheduling;
- adaptive CPU partitions;
- system-wide CPU budgets;
- client budget inheritance by servers;
- run masks and affinity;
- interrupt-event delivery to threads.

Adopt:

- resource-domain hard caps distinct from fair weights;
- privileged control of CPU reservations;
- IRQ work as a schedulable, budgeted entity;
- eventual client-accounted server execution as a future extension.

Important warning: system-wide budgets interact badly with restricted CPU
masks unless admission accounts for usable capacity. HuesOS admission must
consider affinity and topology.

References:

- https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_sys_arch/adaptive.html
- https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.adaptive_partitioning_en_user_guide/aps_details.html

## seL4 MCS and Fiasco.OC

Studied mechanisms:

- scheduling contexts separate from threads;
- budget, period, and bounded refill queues;
- passive server/budget donation;
- per-core scheduling-control authority;
- home-core mutation and cross-core IPI.

Adopt:

- CBS/sporadic-server refill semantics;
- capability-authorized reservations;
- conservative refill merging;
- migration as transfer of a scheduling context, not only a thread pointer.

Defer:

- IPC scheduling-context donation until HuesOS has an explicit synchronous
  call/budget-token contract.

References:

- https://docs.sel4.systems/Tutorials/mcs.html
- https://docs.sel4.systems/projects/sel4/api-doc.html
- https://people.mpi-sws.org/~bbb/events/ospert15/pdf/ospert15-p19.pdf

## Haiku

Studied mechanisms:

- logical-CPU, core, thread, and IRQ load tracking;
- topology-aware placement;
- scheduler-directed IRQ affinity;
- ordered priority structures.

Adopt:

- include IRQ runtime in published CPU load;
- avoid treating an IRQ-saturated CPU as idle merely because its task queue is
  short;
- make IRQ affinity part of SMP scheduling evidence.

References:

- https://www.haiku-os.org/blog/pawe%C5%82_dziepak/2014-02-18_new_scheduler_merged/
- https://www.haiku-os.org/blog/pawe%C5%82_dziepak/2013-12-20_haiku_meets_9th_processor/

## RTEMS and Zephyr

These RTOS designs emphasize bounded structures and explicit scheduler/CPU
assignments. They also demonstrate that arbitrary affinity filtering can turn
selection into an `O(n)` scan.

Adopt:

- bounded capacities;
- admission failure rather than unbounded allocation;
- ready queues contain only tasks already eligible for that CPU;
- directed rather than broadcast reschedule IPIs.

Do not adopt:

- global priority queues as the ordinary SMP Fair scheduler;
- affinity implementations requiring full ready-list traversal.

References:

- https://docs.rtems.org/docs/main/c-user/scheduling-concepts/smp-schedulers.html
- https://docs.zephyrproject.org/latest/kernel/services/smp/smp.html

## Barrelfish and Akaros

Barrelfish treats inter-core state as a distributed system and performs
cross-core work by explicit message passing. Akaros separates coarse core
allocation from user-level thread scheduling.

Adopt:

- explicit split-phase cross-core control;
- replicated read-mostly load snapshots;
- no implicit remote writes to owner-local state.

Do not adopt:

- a full multikernel with replicated memory-management state;
- application-owned core provisioning/gang scheduling as the default process
  model.

References:

- https://people.inf.ethz.ch/troscoe/pubs/sosp09-barrelfish.pdf
- https://www2.eecs.berkeley.edu/Pubs/TechRpts/2014/EECS-2014-223.pdf

## Xen

Studied mechanisms:

- credit-based proportional scheduling;
- runqueue topology choices;
- idle stealing;
- separate masks for CPUs that actually have transferable work;
- SMT-aware tickling.

Adopt:

- publish transferable count separately from running/runnable count;
- do not probe victims from which no work can be moved;
- stagger victim search to avoid lower-ID lock/cache pressure.

Reference:

- https://www.mail-archive.com/xen-devel@lists.xen.org/msg98838.html

## MINIX, Redox, and Serenity

These systems were reviewed but are not production policy references for this
work:

- MINIX uses a deliberately simple userspace priority/round-robin policy;
- Redox is transitioning from a primitive scheduler to DWRR;
- Serenity SMP still exposes scheduler/lock integration defects.

The useful lesson is negative: policy flexibility is not a substitute for a
correct kernel scheduling mechanism and fallback.

## Resulting HuesOS synthesis

The approved HuesOS design combines:

- EEVDF policy from the Linux/original research lineage;
- virtual timeline and augmented ordered queues from Zircon;
- owner-only CPU state and asynchronous commands from DragonFly/Barrelfish;
- idle pull plus deferred push from ULE;
- workload grouping from XNU;
- physical-core-first placement from Windows and BSD schedulers;
- IRQ-load accounting from Haiku;
- budget/refill mechanics from seL4;
- resource-domain caps and IRQ-thread concepts from QNX;
- bounded capacities from RTOS practice;
- explicit SMT trust modes informed by Linux/OpenBSD security trade-offs.

Mechanisms are adopted only where their invariants fit HuesOS. Source code is
not copied.
