# Scheduler v2 production design

Status: approved target architecture; implementation not yet present.

This document is normative for the Scheduler/SMP v2 implementation. It
separates fixed architecture decisions from tunable values that still require
measurement. Existing code must not claim these properties until the exit
gates in this document pass.

Related documents:

- `docs/SCHEDULER_RESEARCH.md` — comparative rationale;
- `docs/SMP_V2.md` — APIC, topology, timer, IPI, and IRQ architecture;
- `docs/SMP.md` — currently implemented SMP path.

## 1. Goals

Scheduler v2 must provide:

- weighted, starvation-free general-purpose scheduling;
- low wake latency without heuristic interactive priority classes;
- Job/resource-domain isolation against thread-count amplification;
- capability-controlled CPU bandwidth reservations;
- bounded and accounting-correct threaded IRQ execution;
- scalable SMP without remote runqueue locks;
- fully preemptible kernel support;
- kernel-context and userspace-context migration;
- x86 extended-state isolation and fast address-space switching;
- explicit SMT security policies;
- allocation-free, bounded hard scheduling paths;
- deterministic host models and physical Intel/AMD evidence.

NUMA and CPU hotplug/offline are not part of this phase.

## 2. Fixed capacities

The v2 ABI and internal masks support:

```text
MAX_CPUS  = 256 logical CPUs
MAX_TASKS = 8192 live/published Task slots
```

APIC IDs are `u32` and may be sparse. Dense CPU indexes are in
`0..MAX_CPUS` and are never inferred from APIC IDs.

Task-slot exhaustion is an explicit `OutOfResources` result. Scheduler paths
must not allocate opportunistically to exceed these limits.

## 3. Stable Task identity

Task identity is independent of CPU ownership:

```text
TaskId = (global slot index, slot generation)
```

A generation never wraps into an old live identity. An exhausted slot is
retired.

Migration changes `owner_cpu`, never Task ID. The following remain valid over
migration:

- wait registrations;
- timeout records;
- process/thread object references;
- observation records;
- pending wake operations;
- CBS scheduling contexts.

No alias table is permitted.

## 4. Task state machine

The lifecycle is explicit:

```text
Embryo
  -> DeferredReady(target)
  -> Ready(cpu)
  -> Running(cpu)

Running(cpu)
  -> Ready(cpu)               preemption/yield
  -> Blocking(epoch)
  -> Dying

Blocking(epoch)
  -> Blocked(cpu, epoch)
  -> Waking(target, epoch)    wake races with block

Blocked(cpu, epoch)
  -> Waking(target, epoch)

Ready/Blocked
  -> Migrating(source,target,generation)
  -> Ready(target)

Running/Ready/Blocked
  -> Dying
  -> Dead
  -> Reaped
```

Required invariants:

1. A Task is present in at most one ready queue.
2. A Running Task is not a ready-tree node.
3. A Blocked Task is not ready.
4. A successful wake transition always leaves a pending inbox bit until an
   owner CPU consumes it.
5. Duplicate wakes cannot create duplicate queue membership.
6. Task storage is not reclaimed while Running, Migrating, pending in an
   inbox, or referenced by an IRQ/CBS context.
7. Migration preserves Task ID and generation.
8. Affinity is checked before publishing the target CPU.
9. No acknowledged wake may be dropped due to contention or capacity.

The atomic transition model must be exercised under `loom` or an equivalent
interleaving checker.

## 5. Single-writer per-CPU runqueues

Each CPU is the only writer of its runqueue state:

- root Job EEVDF tree;
- per-Job Thread EEVDF trees;
- CBS eligible tree;
- CBS replenishment tree;
- current Task;
- local virtual time;
- timer-programming state;
- local service accounting.

Remote CPUs never lock or mutate these trees. Local mutation occurs with
preemption disabled and the required interrupt state. A debug owner assertion
must fail-stop on foreign access.

The old per-CPU scheduler ticket locks and synchronous runqueue-token mailbox
are removed after the v2 owner protocol is proven.

## 6. Remote operation inbox

Every CPU owns a hierarchical bitmap for Task-slot operations.

For 8192 Tasks:

```text
128 atomic 64-bit task words per CPU
2 atomic 64-bit first-level summary words
1 top-level summary/armed state
```

Operation details are stored in atomic Task metadata. The bitmap answers
which Tasks require owner attention.

Producer protocol:

1. validate TaskId generation;
2. atomically publish/merge the requested operation;
3. set the Task bit;
4. set the summary bit;
5. send a reschedule IPI only on the required empty-to-nonempty transition.

Consumer protocol:

1. atomically detach dirty summary words;
2. atomically detach only named Task words;
3. validate generation and state;
4. apply operations locally;
5. repeat if producers published work during drain.

Properties:

- no dynamic allocation;
- no bounded-ring overflow;
- duplicate operations coalesce;
- no waiting for a remote CPU;
- one IPI may service many operations;
- stale generation bits are harmless and observable.

Remote wake, kill, affinity change, policy update, throttle, and migration
control use this mechanism.

## 7. Scheduling-class order

At a scheduling point:

1. non-threadable hard-IRQ/NMI work has already run outside Task scheduling;
2. choose an eligible CBS/IRQ reservation by earliest absolute deadline;
3. otherwise choose a Job through root EEVDF;
4. choose a Thread through that Job's EEVDF;
5. otherwise run the CPU idle Task.

There is no ordinary fixed-priority class that can indefinitely starve Fair
work.

## 8. Request-based EEVDF

HuesOS uses request-based Earliest Eligible Virtual Deadline First.

Each EEVDF entity has:

```text
weight
request duration
virtual start / eligible time
virtual finish / virtual deadline
preserved lag
actual execution start
accumulated service
```

For a request of cost `r` and weight `w`:

```text
virtual_finish = virtual_start + scale(r, w)
eligible        = virtual_start <= queue_virtual_time
```

The eligible entity with the earliest virtual finish is selected. If no entity
is eligible while runnable work exists, the queue virtual time advances to the
smallest virtual start.

The implementation uses saturating/fixed-point integer arithmetic. Floating
point is forbidden in scheduler policy.

### 8.1 Data structure

The ready queue is an index-based augmented WAVL tree:

- links are Task/Job slot indexes, not raw pointers;
- ordering key is `(virtual_start, stable_id)`;
- each subtree caches minimum virtual finish;
- insert, remove, reweight, and selection are `O(log n)`;
- no allocator call occurs in enqueue, dequeue, account, or pick-next;
- randomized tests verify ordering, ranks, augmentation, uniqueness, and
  generation validity after every operation.

### 8.2 Current entity

A running entity is represented explicitly in queue accounting even if it is
not an ordinary tree node. Weighted virtual-time calculations must include its
service and weight.

### 8.3 Wake and sleep placement

Fixed rules:

- migration preserves bounded lag, not source-CPU absolute virtual time;
- explicit yield does not create positive service credit;
- a short sleep does not erase negative lag;
- long sleep decays lag toward zero;
- sleeper credit is bounded by request-size-derived limits;
- a waking earlier-deadline eligible Task may preempt after minimum
  granularity;
- Task creation cannot start arbitrarily far ahead of existing entities.

Exact decay constants, base request size, and minimum granularity are tunables
that must be chosen from benchmark/model results and recorded with their
baseline.

### 8.4 Weight changes

A weight change is:

1. dequeue;
2. account elapsed execution;
3. preserve bounded service lag under the old weight;
4. convert lag/request under the new weight;
5. reinsert.

A direct field overwrite while queued is forbidden.

## 9. Job/ResourceDomain hierarchy

Fair scheduling has two levels:

```text
Root per-CPU EEVDF
  -> Job/ResourceDomain entity
       -> Thread EEVDF for that Job on that CPU
```

A Job with many threads competes as one root entity on a CPU. Threads divide
only that Job's local service.

### 9.1 System-wide fairness

Exact global virtual time is intentionally rejected because it would put a
shared cache line/lock in every context-switch path.

System-wide fairness is obtained by:

- per-CPU Job service counters;
- published runnable demand and transferable count;
- deferred service-deficit balancing;
- Job-aware wake placement;
- migration hysteresis;
- strict aggregate Job hard caps.

This is a measurable approximation. The implementation must report maximum
and percentile service error under adversarial thread-count and affinity
workloads.

### 9.2 Work-conserving behavior

Unused capacity is available to other Jobs. Job weights determine relative
service under contention. A separate hard cap limits maximum aggregate use.

### 9.3 Hard cap

A Job cap is expressed as aggregate CPU nanoseconds per period. A quota may be
larger than one period to represent parallel use across CPUs.

The global period pool hands bounded runtime slices to CPU-local Job accounts.
Local execution consumes reserved slices without shared-cache writes. Atomic
reservation ensures total issued runtime never exceeds the cap.

On exhaustion:

- local Job entities become throttled;
- owner CPUs are notified through coalesced inbox operations;
- the next period publishes a new generation;
- stale-period runtime cannot be consumed.

Unused local reservations should be returned when profitable, but security
must never depend on their return. A smaller reservation slice reduces
stranding at the cost of more global atomics.

## 10. Constant Bandwidth Server

CBS is represented by a capability-controlled SchedulingContext separate from
Task identity.

Parameters:

```text
capacity C
period T
relative deadline D (D = T in the initial implementation)
remaining budget
absolute deadline
bounded refill ring
admission generation
owner CPU
```

Validation requires:

```text
0 < C <= D <= T
```

Additional configured lower/upper period and capacity bounds prevent timer
and arithmetic abuse.

### 10.1 Admission

CBS Tasks and CBS-backed IRQ work share a maximum initial admitted utilization
of 80% on each CPU:

```text
sum(C/T) <= 0.80
```

The remaining 20% is not sold as a hard guarantee; it covers hard IRQs,
Scheduler/IPI work, migration, Fair work, and kernel overhead.

Admission considers:

- allowed CPU mask;
- Job hard cap;
- existing CBS/IRQ reservations;
- SMT mode and TrustDomain constraints;
- timer precision and common clock availability;
- migration overhead margin.

Only privileged scheduling-control capabilities may create or change a
reservation.

### 10.2 Runtime

Elapsed CPU time, not ticks, consumes budget. An exhausted Task leaves the
eligible tree and enters the replenishment tree until budget is legally
available.

The refill ring is fixed-size. If it fills, entries are merged
conservatively: service may be delayed or forfeited, but budget is never made
available earlier than permitted.

### 10.3 Automatic migration

CBS migration is automatic when it improves schedulability and passes
admission, affinity, cooldown, and TrustDomain checks.

Two-phase protocol:

1. target reserves utilization under a migration generation;
2. source accounts runtime and dequeues the Task;
3. source transfers Task and SchedulingContext state;
4. target validates generation and commits enqueue;
5. source releases old admission only after target acknowledgement.

Target-first reservation temporarily double-counts utilization, which is safe.
Source-first release is forbidden because it can lose the reservation.

Transferred state includes remaining budget, refill ring, absolute deadline,
next eligible time, context, and policy generation. Failure rolls back to the
source without changing Task ID.

Migration execution time is charged to the migrating Task's budget. Cooldown
and minimum-benefit thresholds prevent ping-pong.

Automatic CBS migration is disabled with an explicit degraded marker if the
platform lacks a sufficiently common monotonic time domain.

### 10.4 Guarantee terminology

Until priority inheritance/budget donation and bounded IRQ/preemption latency
are proven, CBS is described as temporal bandwidth isolation/soft real-time.
The implementation must not claim hard real-time guarantees prematurely.

## 11. Kernel preemption profiles

One binary supports:

### `preempt=full`

- ordinary kernel process context is preemptible;
- pending reschedule is served at interrupt return and outermost
  `preempt_enable`;
- a Task may resume kernel execution on a different CPU if migration is
  enabled and safe;
- hard IRQ/NMI remains non-preemptible.

### `preempt=lazy`

- the same lock and state correctness applies;
- ordinary Fair preemption may wait for syscall/user return, explicit
  block/yield, or a safe lazy point;
- eligible CBS/IRQ urgency remains immediate;
- intended for throughput-oriented trusted/server workloads.

Both profiles are mandatory CI configurations.

## 12. Preemption and migration counters

Task state contains nested:

```text
preempt_disable_depth
migration_disable_depth
```

CPU state contains:

```text
hardirq_depth
nmi_depth
need_resched
lazy_need_resched
```

Rules:

- spinlock acquisition disables preemption;
- safe CPU-local access holds a MigrationGuard;
- sleeping with preemption disabled is fatal;
- sleeping while a temporary CPU-local borrow is live is fatal;
- migration requires both depths zero, no held spinlock, and no IRQ/NMI
  context;
- outermost enable/drop checks deferred reschedule;
- Task-local counters survive migration; CPU IRQ counters do not migrate.

## 13. CPU-local API

Ordinary safe code must not receive a `'static` mutable CPU-local reference.
Access uses a closure or guard whose lifetime also holds migration-disable.

Unsafe raw CPU-local pointers are restricted to:

- entry/exit assembly;
- context switch;
- AP initialization;
- scheduler owner internals.

The safety audit rejects new unguarded CPU-local access.

## 14. Lock classes

Kernel synchronization is classified:

1. **Raw IRQ spinlock** — masks IRQ and preemption; hard-context-safe;
2. **Preempt spinlock** — disables preemption, leaves IRQ enabled;
3. **PI/sleeping mutex** — process context, waiter blocks;
4. **owner-only state** — no inter-CPU lock;
5. **immutable/seqlock snapshot** — read-mostly data.

Current universal IRQ-masking locks must be inventoried and assigned a class.
Long process-context work is not permitted under an IRQ spinlock.

Scheduler context switch asserts:

- no ranked/spin lock held;
- preemption and migration state valid for the switch type;
- owner/runqueue state consistent;
- AC/SMAP user-access window closed.

## 15. Threaded IRQ work

Threadable device IRQ execution is a schedulable CBS-backed activity.

For userspace-owned devices, the DriverHost Task is the IRQ thread:

```text
hard top half -> Interrupt object/event count -> bitmap wake -> DriverHost
```

A redundant kernel IRQ Task is not inserted before DriverHost.

Kernel IRQ Tasks exist only for kernel-owned device work. Non-threadable CPU
exceptions, timer, reschedule, TLB, panic/stop, NMI, and machine-check paths
remain hard context.

Hard top halves are bounded to mask/ack, publish event state, EOI, and return.
Level-triggered sources remain masked until the thread acknowledges handling.
MSI/edge events use a saturating pending counter so coalescing cannot erase all
knowledge of multiple arrivals.

IRQ storm policy:

- bounded pending count and telemetry;
- CBS budget and 80% shared admission ceiling;
- source masking/quarantine after budget/rate violation when possible;
- health event to DriverManager/root supervisor;
- no unbounded loop in hard context.

IRQ runtime contributes to CPU load placement.

## 16. SMT TrustDomain

Fairness Jobs and SMT trust are separate concepts.

Every Process starts with a distinct TrustDomain cookie. Threads inherit it.
A capability authorizes controlled sharing or reassignment of a TrustDomain;
ordinary userspace cannot guess or forge cookies.

Boot policies:

### `smt=off`

Only one logical CPU per physical core is online. This is the strict
cross-thread policy.

### `smt=isolated`

SMT siblings may simultaneously return to userspace only with compatible
TrustDomain cookies. An atomic physical-core gate coordinates active cookies
and may force a sibling idle. This mitigates but does not claim to eliminate
all cross-HT leakage.

### `smt=trusted`

No TrustDomain co-scheduling restriction. Maximum throughput; an explicit
security-degraded marker is required.

## 17. Extended state

Userspace SIMD remains disabled until eager context switching is complete.

Required sequence:

- enumerate x87/SSE/AVX state with CPUID/XCR0;
- require a compatible xstate contract on every online CPU;
- allocate aligned per-Task state;
- initialize clean architectural state;
- eagerly save with XSAVE/XSAVEOPT and restore with XRSTOR;
- use FXSAVE/FXRSTOR fallback where supported;
- never use lazy `#NM` ownership as the security model;
- zero state before reclamation.

After target tests pass, SSE2 may become the userspace baseline. Wider SIMD is
runtime/target controlled.

FS base and any enabled user-visible extended/supervisor state must also be
switched.

## 18. PCID and address-space switching

PCID/INVPCID is implemented only after the ordinary CR3/TLB path is proven
under v2 migration.

Required model:

- address-space generation;
- per-CPU loaded generation/PCID state;
- active-address-space CPU mask;
- targeted TLB shootdown with acknowledgement;
- safe PCID reuse only after invalidation/generation change;
- unsupported/degraded fallback to flushing CR3 switch.

A performance regression may disable PCID. A stale-translation risk may not.

## 19. Reaping

Task storage is reclaimed only after:

- Task is not current on any CPU;
- owner state is Dead;
- no pending bitmap operation exists;
- migration generation is committed/rolled back;
- wait/timeout records no longer reference the generation;
- xstate and kernel stack are no longer active;
- address-space active masks are updated.

Reaping is deferred process-context work and never runs in hard IRQ.

## 20. Observability

Per CPU counters include:

- context switches by reason;
- EEVDF preemptions and request completions;
- runnable/transferable count;
- remote wake publications and coalesced IPIs;
- inbox drain batches;
- migration requests/commits/rollbacks/cooldown rejects;
- CBS admission rejects, exhaustion, refill merge, deadline miss;
- IRQ top-half and IRQ-thread runtime;
- forced SMT idle time;
- scheduler and preemption-disabled latency maxima;
- PCID/xstate switch counts.

Per Task/Job diagnostics include service, lag, virtual start/finish, wait
latency, migrations, throttled time, and reservation state. Secret/capability
values are not logged.

Tracing uses bounded per-CPU rings. Serial output is not emitted from the
scheduler hot path except fatal emergency diagnostics.

## 21. Correctness gates

Host/model gates:

- state-machine interleavings for block/wake/migrate/exit;
- zero dropped acknowledged wakes;
- zero duplicate queue membership;
- WAVL invariants after randomized operations;
- EEVDF weight/share and starvation properties;
- sleeper/yield gaming tests;
- Job thread-amplification isolation;
- hard-cap aggregate accounting;
- CBS sliding-window budget property;
- two-phase migration rollback at every transition;
- affinity and TrustDomain safety;
- timer/arithmetic saturation and wrap tests.

Target gates:

- SMP 1/2/4/8/16/32, debug and release;
- 8192-task bounded-capacity stress in host model and practical target subset;
- simultaneous remote wake/exit/migrate storms;
- full and lazy preemption;
- syscall/page-fault kernel-context migration;
- IRQ storm containment;
- CBS overload and automatic migration;
- SMT off/isolated/trusted;
- TSC-deadline and forced fallback;
- xAPIC/x2APIC;
- PCID on/off and shootdown stress;
- eager xstate cross-process leakage/corruption tests.

## 22. Performance gates

QEMU proves behavior, not physical latency.

Physical Intel and AMD measurements include:

- context-switch p50/p95/p99/max, same and different address spaces;
- local and remote wake latency;
- scheduler decision time at 1/16/256/4096 runnable entities;
- preemption-disabled and hard-IRQ maximum duration;
- context switches and IPIs per second;
- EEVDF weighted-share error;
- Job global service error;
- load-balance convergence and migration rate;
- CBS budget error/deadline misses/migration cost;
- IRQ latency and storm behavior;
- SMT throughput and forced-idle cost;
- PCID and XSAVE impact.

Baselines and accepted thresholds are committed before calling the scheduler
production-grade.

## 23. Documentation obligations during implementation

Every implementation PR must keep this design synchronized and add:

- actual state/transition table;
- memory-ordering proof for the bitmap inbox;
- EEVDF fixed-point formulas and overflow bounds;
- WAVL invariant description;
- CBS refill and migration proof;
- preemption/locking inventory;
- IRQ vector ownership table;
- APIC/timer fallback matrix;
- SMT threat-model limitations;
- test commands and evidence locations;
- benchmark baseline and hardware identity.

Any architectural deviation requires explicit owner approval before code.

## 24. Implementation ledger (v2 branch)

This ledger records partial integration without turning target properties into
claims about the whole kernel.

- `7e080fc`: added the `huesos-sched` no-unsafe policy crate with stable
  8192-slot Task IDs, 256-bit CPU masks, lifecycle/guard oracles, a two-level
  atomic Task inbox, request-based EEVDF oracle, and 80% CBS admission model.
- `073bdac`: MADT parsing now validates Local x2APIC records, wide ACPI UIDs,
  duplicate identities, and 64-bit LAPIC address overrides. The existing
  xAPIC startup backend refuses rather than truncates wide destinations.
- `c0ea92f`: added strict distributed Job-cap accounting, conservative fixed
  refill rings, CBS runtime accounting, and target-first migration protocol
  models.
- `3a019d7`: Task-owned preemption/migration guard storage is installed at
  every context switch, with CpuLocal bootstrap guards before Scheduler init;
  the audited unsafe switch boundary is centralized and SMP4 QEMU passed.
- `b428099`: added pure three-mode SMT TrustDomain gate and bounded IRQ
  event/storm models.
- `04dd8d4`: added a fixed 8192-slot Task directory model with coherent
  owner/local-index publication, generation validation, and coalesced pending
  operations.
- `30439e4`: kernel Scheduler transitioned to `huesos_sched::TaskId` (global
  slot + generation). Migration keeps the ID and republishes the owner; the
  128-entry alias table and CPU-encoded ID layout were removed. A global
  8192-slot allocator advances generations on reuse and retires slots only on
  generation overflow. `make test`, safety/policy gates, and QEMU debug SMP4
  pass with this layout.
- `a871025`: preemption guards (`ExecutionGuards`) are connected to the
  reschedule hook so the outermost guard release runs a deferred scheduler
  tick when a task was rescheduled while preemption-disabled. This is the
  first building block for fully preemptible kernel context switching.
- `2118719`: added `TaskDirectory::published_id(slot)` so inbox-drain paths
  can recover the full TaskId from a slot number without a prior locate call.

- `scripts/restore-arena-env.sh` is kept OUT of the repository per owner
  request; the copy used in this workspace lives at
  `~/workspace-tools/restore-arena-env.sh` and restores rustup, cargo tools,
  system packages, git metadata, executable bits, and the persistent SSH key
  from `$HOME/.ssh/huesos_deploy`.

- Remote operation inbox integration (replacing the synchronous token protocol
  with allocation-free async bitmap wake/kill/policy operations).
- Owner-only runqueue mutation (eliminating per-CPU scheduler ticket locks).
- Request-based EEVDF selection replacing `tick()` linear scan and BTreeSet.
- Job/ResourceDomain hierarchy integration.
- Monotonic clock, TSC-deadline/one-shot timer, and cross-CPU skew report.
- CBS, hard caps, and automatic migration.
- Threaded IRQ, kernel IRQ thread, storm containment.
- Topology-aware CPU selection, xAPIC/x2APIC backend.
- SMT off/isolated/rusted gates with trust capabilities.
- Eager XSAVE and SIMD enablement.
- PCID/INVPCID/active address-space management.
- Stress tests, benchmark harness, and bare-metal evidence collection.

## 25. Implementation ledger (scheduler-smp-production-v2)

- `41e1ed3` Job hierarchy: `JobId`, per-CPU `JobState` (runnable/demand/
  service), hard cap oracle, fixed Job table with generation-safe slot reuse.
- `bafa106` Kernel: Task carries a `JobId`; per-tick service is charged to the
  task's Job through a kernel `JobState` table (root Job by default).
- `b807bfd` Kernel CBS admission API: per-CPU `AdmissionControl` at the shared
  80% ceiling with `cbs_try_admit`/`cbs_release`/`cbs_admitted_ppm`.
- `b9c9f25` Tickless scheduler timer: transitions to one-shot TSC-deadline
  when CPUID 0x1F/invtsc and a calibrated clock are available, with periodic
  LAPIC fallback; verified under QEMU `-cpu max`.
- `7352cb0` Observability: `SchedStats` counters (context switches, remote
  wakes, reschedule IPIs, inbox drains, IRQ storm masks) + `irq_storm_masked`.
- `6fb547e` Hardware models: `XsaveModel` (CPUID 0xD layout), `PcidTable`
  (generation-safe ASID allocation), `CpuTopology` (leaf 0x1F parsing).
- `SCHEDULER_BENCHMARK.md` + `scripts/sched-bench-host.sh`: deterministic host
  harness; physical thresholds to be committed from real hardware.

Still explicit non-goals of this phase: runtime CPU hotplug, NUMA, and
enabling userspace SIMD / CR4.PCIDE in the boot path (models are ready; the
switches themselves require the full physical gate).
