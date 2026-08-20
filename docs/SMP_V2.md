# SMP v2 production design

Status: approved target architecture; implementation not yet present.

This document specifies x86-64 SMP behavior supporting Scheduler v2. It does
not describe NUMA or runtime CPU hotplug, which are excluded from this phase.
The currently implemented AP path remains documented in `docs/SMP.md`.

## 1. Scope and fixed limits

- Up to 256 logical CPUs.
- Dense `CpuIndex` in `0..256` for arrays and masks.
- Sparse `ApicId(u32)` for hardware routing.
- xAPIC and x2APIC local-controller backends.
- SMT/core/package topology; no NUMA scheduling level.
- Boot-time CPU discovery/online/failure states.
- No runtime CPU online/offline API.

No APIC ID is truncated to `u8` outside a hardware interface explicitly proven
to have an 8-bit destination.

## 2. CPU state machine

```text
Absent
Present
  -> Starting
  -> Online
  -> Failed(reason)
  -> ParkedByPolicy        SMT off or explicit boot policy
```

Only Online CPUs may:

- own runnable Tasks;
- receive Scheduler placement;
- hold CBS admission;
- receive ordinary IRQ affinity;
- appear in userspace CPU masks.

A Failed or Parked CPU is permanently excluded until reboot in this phase.
Failure is logged structurally and boot continues if the BSP and required
minimum CPU policy remain satisfied.

## 3. Firmware and topology discovery

The MADT parser supports:

- Processor Local APIC (type 0);
- Local x2APIC (type 9);
- Local APIC address override;
- IOAPIC records;
- interrupt source overrides;
- enabled/online-capable flags with explicit policy.

Duplicate ACPI processor/APIC identities, malformed lengths, and conflicting
records are rejected. Enumeration never trusts MADT count before validating
record bounds.

Topology uses:

1. CPUID leaf `0x1f` when valid;
2. CPUID leaf `0x0b` fallback;
3. conservative one-thread-per-core fallback when topology cannot be trusted.

Published topology identifies:

```text
logical CPU
SMT sibling set
physical core ID
package ID
```

NUMA node is intentionally absent from Scheduler policy in this phase.

All CPU masks are scalable 256-bit structures, not a single `u64`.

## 4. APIC backend

A common interface covers:

- local APIC enable/init;
- APIC ID read;
- EOI;
- local timer programming;
- directed fixed IPI;
- INIT/SIPI startup;
- broadcast panic/stop operations;
- delivery-status/error reporting.

### 4.1 xAPIC

Uses uncached MMIO and supports representable 8-bit physical destinations.
Every delivery-status wait is bounded.

### 4.2 x2APIC

Uses APIC MSRs and 32-bit destination IDs. Mode is enabled only when CPUID,
firmware, and platform state allow it. Initialization failure falls back to
xAPIC only when every required APIC ID and operation remains representable;
otherwise affected CPUs stay Failed/Parked.

The backend and chosen mode are logged once without hot-path serial output.

## 5. External interrupt destination limitation

x2APIC support does not make the legacy IOAPIC destination field wider.
Without VT-d/AMD-IOMMU interrupt remapping, some external IRQ formats cannot
target APIC IDs above 255.

Until interrupt remapping is separately implemented:

- high-ID CPUs may schedule Tasks and receive local timers/IPIs;
- external IOAPIC/MSI/MSI-X IRQs are assigned only to CPUs supported by the
  exact interrupt format;
- the affinity planner records a degraded limitation rather than truncating
  the destination;
- no interrupt is silently routed to the wrong CPU.

IOMMU interrupt remapping is not implied by this design.

## 6. AP bring-up

The BSP:

1. validates firmware CPU/topology records;
2. initializes the selected APIC backend;
3. establishes the monotonic clock source;
4. allocates guarded AP bootstrap/kernel stacks;
5. prepares immutable per-CPU descriptors;
6. starts APs through INIT/SIPI with bounded waits;
7. records Online/Failed/Parked state;
8. releases only fully initialized APs into scheduling.

Each AP initializes before Online publication:

- GS/per-CPU state;
- GDT/TSS;
- IDT;
- syscall MSRs;
- CR0/CR4/EFER protection state;
- SMEP/SMAP marker;
- xstate/XCR0 contract;
- APIC timer backend;
- scheduler owner state and idle Task;
- lock/preemption/IRQ nesting state.

Online publication uses Release ordering; placement observes it with Acquire.

AP startup may remain sequential initially for simpler failure attribution.
Parallel startup is a benchmark-driven optimization, not a correctness
requirement.

## 7. Guarded stacks

AP bootstrap and Task kernel stacks use virtual mappings with unmapped guard
pages. A plain heap `Vec` without a guard is not accepted for the v2
production path.

Required properties:

- architecture-required alignment;
- non-executable stack pages;
- unmapped lower guard;
- optional upper guard where layout permits;
- zero before reuse;
- deferred reclamation after Task/CPU ownership ends.

IST stacks are separate for designated fatal exceptions.

## 8. Monotonic clock

Scheduler accounting uses monotonic nanoseconds derived from a validated
clocksource.

Preferred path:

- invariant TSC capability;
- frequency calibration against HPET or ACPI PM timer;
- PIT only as a last fallback;
- cross-CPU skew measurement during AP startup;
- serialized TSC reads and fixed multiplier/shift conversion.

The clock layer publishes:

```text
clocksource kind
frequency/conversion
cross-CPU synchronization status
precision/error bound
generation
```

If TSC is not sufficiently common across CPUs:

- ordinary Fair scheduling continues with a safe fallback;
- automatic CBS migration is disabled or constrained to compatible CPUs;
- a degraded marker is mandatory;
- temporal guarantees are not claimed beyond measured error.

## 9. One-shot local timers

Preferred timer order:

1. TSC-deadline local APIC mode;
2. calibrated one-shot LAPIC;
3. periodic LAPIC degraded fallback.

The next interrupt is programmed for the earliest of:

```text
current EEVDF request end
current CBS/IRQ budget exhaustion
nearest CBS refill
nearest timeout
balance/housekeeping deadline
```

Idle CPUs and CPUs with no upcoming preemption do not receive an unnecessary
100 Hz scheduler tick. At least one housekeeping time source maintains any
legacy coarse-clock ABI until it is converted to monotonic time.

Timer programming is local-owner state. A remote CPU publishes a changed
deadline through the inbox and directed reschedule IPI.

## 10. IPI vectors and contracts

Dedicated vectors exist for:

- reschedule/inbox drain;
- TLB shootdown;
- panic stop;
- shutdown stop;
- any bounded generic SMP call facility explicitly introduced later.

Reschedule IPI:

- does not advance time;
- EOIs before expensive scheduler work;
- drains owner inbox in bounded batches;
- coalesces repeated publications;
- never waits for the sender.

TLB shootdown:

- carries generation/range through separately synchronized state;
- targets only CPUs that can hold the address space when active masks are
  proven;
- acknowledges completion with bounded failure policy;
- never relies on APIC ID as an array index.

No hard IPI callback may sleep or allocate.

## 11. Single-writer Scheduler integration

Every CPU mutates only its own ordered scheduling structures. Cross-CPU
operations publish Task bits/metadata and send an IPI.

Published per-CPU snapshots are cacheline-separated and include:

```text
online/idle state
running Task class/Job/TrustDomain summary
runnable count
transferable count
Fair weighted demand
CBS admitted utilization and nearest deadline
IRQ runtime/load
recent utilization
load epoch
```

Snapshots are hints. Owners revalidate all decisions before mutation.
Staleness may reduce optimality but must not violate affinity, admission,
identity, or trust.

## 12. CPU placement

Fair Task placement order:

1. intersect affinity with Online mask;
2. apply SMT policy and TrustDomain constraints;
3. keep previous CPU when load/cooldown permits;
4. prefer an idle physical core;
5. prefer an allowed idle SMT sibling;
6. choose the CPU with lowest normalized Job-aware load;
7. use stable rotating tie-breaking, not permanent low-ID bias.

CPU selection accounts for task demand, CBS load, IRQ runtime, and current
power/idle state where available. It does not use NUMA distance.

Kernel-context migration additionally requires zero migration-disable depth and
no CPU-local borrow.

## 13. Load balancing

### 13.1 Idle pull

An idle CPU reads published snapshots and sends a `StealRequest` to a nearby
victim with transferable work. It does not read or lock the victim tree.

The victim owner:

- revalidates load epoch;
- selects a non-running, affinity-compatible, cooldown-safe entity;
- performs source dequeue locally;
- sends a transfer to target;
- rolls back safely if target rejects.

Search order is SMT/core/package aware. Victim rotation avoids repeated
pressure on low CPU IDs.

### 13.2 Deferred push

An overloaded owner periodically compares service/load snapshots and may push
one entity to an underloaded CPU. Balance intervals are staggered and include
hysteresis.

Heavy balancing never runs in hard timer IRQ. A hard event only marks deferred
work/need-reschedule.

### 13.3 Migration suppression

- minimum residency;
- per-Task cooldown;
- minimum load/service benefit;
- one in-flight migration generation;
- no migration of pinned/ineligible Tasks;
- no cache-destroying attempt solely to improve an insignificant imbalance.

## 14. Job-aware global approximation

Per-CPU EEVDF remains local. Global Job fairness is approximated through
service-deficit balancing and strict hard caps rather than a global runqueue.

The balancer considers:

- Job weight;
- runnable parallelism;
- service received per CPU;
- affinity-constrained capacity;
- hard cap remaining;
- CPU/IRQ load.

A Job with one runnable thread may receive at most one CPU of parallel service,
while spare CPUs remain work-conserving for other Jobs.

Fairness error is measured; it is not hidden behind the word "approximately."

## 15. CBS automatic migration

A CBS target must reserve admitted utilization before the source releases its
reservation. Migration uses a generation-bearing reserve/commit/rollback
protocol specified in `docs/SCHEDULER_V2.md`.

Target choice considers:

- admitted slack under the 80% ceiling;
- absolute deadlines;
- affinity;
- common clock domain;
- Job cap;
- SMT TrustDomain;
- migration cost/cooldown.

Migration overhead is charged to the Task budget.

## 16. Kernel preemption and migration

Both `preempt=full` and `preempt=lazy` use the same correctness machinery.

A kernel Task may migrate after preemption only when:

```text
preempt_disable_depth == 0
migration_disable_depth == 0
hardirq_depth == 0
nmi_depth == 0
no spinlock held
no CPU-local borrow live
```

Per-CPU safe access pins migration for its guard lifetime. Spinlocks prevent
preemption. Sleeping in atomic/CPU-local context is fatal.

Scheduler entry points include:

- user return from IRQ;
- kernel return from IRQ when profile/policy permits;
- syscall exit;
- outermost preempt-enable;
- explicit block/yield/exit;
- idle loop.

Context switch is never performed with a ranked/spin lock held.

## 17. Threaded IRQ model

### 17.1 Non-threadable hard vectors

Remain hard context:

- NMI and machine check;
- CPU faults/exceptions;
- local scheduler timer;
- reschedule and TLB IPIs;
- panic/shutdown stop IPIs;
- minimal APIC control paths.

### 17.2 Userspace device IRQ

For userspace-owned hardware, DriverHost is the IRQ thread:

```text
hard top half
  -> mask/ack and saturating pending count
  -> Interrupt object/task bitmap wake
  -> EOI
  -> DriverHost Task under CBS reservation
  -> completion/unmask
```

No redundant kernel IRQ Task is inserted.

### 17.3 Kernel-owned device IRQ

Only kernel-owned device bottom halves use kernel IRQ Tasks. They are
preemptible, affinity-bound, observable, and CBS-budgeted.

### 17.4 Storm containment

- top-half operation bound;
- coalesced wake/IPI;
- saturating pending count;
- source mask/quarantine on rate/budget violation;
- health notification;
- IRQ runtime in CPU load;
- no infinite interrupt-context retry.

CBS and IRQ reservations share an initial per-CPU admission ceiling of 80%.

## 18. IRQ affinity

Boot-time affinity planner distributes representable vectors using:

- Online mask;
- APIC/MSI destination limits;
- queue ownership;
- DriverHost affinity;
- physical core topology;
- CBS admission;
- existing IRQ load.

NVMe MSI-X queues prefer the CPU that owns the associated DriverHost work.
Legacy keyboard/low-rate IRQs may remain on a designated housekeeping CPU.

Dynamic IRQ migration is allowed only through mask/drain/reprogram/unmask with
generation validation. The first implementation may retain static boot-time
affinity while collecting evidence.

## 19. SMT policies

Topology identifies siblings before scheduling begins.

### `smt=off`

One logical CPU per physical core is Online; siblings are ParkedByPolicy.

### `smt=isolated`

All siblings may be Online. A physical-core atomic gate allows simultaneous
userspace execution only for compatible explicit TrustDomain cookies.
Incompatible work may force a sibling idle and trigger directed reschedule.
This is mitigation, not a complete cross-HT security claim.

### `smt=trusted`

No trust restriction; core-first placement still prefers physical cores before
siblings. A security-degraded boot marker is mandatory.

TrustDomain is a capability-backed object distinct from Job/resource fairness.
Processes receive distinct domains unless authorized sharing occurs.

## 20. Extended state and migration

All Online CPUs must satisfy the selected xstate contract. The scheduler uses
eager XSAVE/XSAVEOPT and XRSTOR, with FXSAVE fallback where applicable.

Migration includes:

- extended register state;
- FS/user GS state;
- CR3/PCID generation;
- kernel stack context;
- scheduling counters/state.

No Task runs on a CPU unable to restore its enabled state components.

## 21. PCID and TLB

PCID is an optional performance layer over a correct generation-based TLB
model.

On context migration:

- source clears address-space active membership after switch-out ordering;
- target installs/checks local PCID generation before execution;
- stale PCID reuse forces invalidation;
- shootdowns target active/potential holders and await required acknowledgement;
- unsupported PCID falls back to CR3 flushing.

A stale translation is a security failure. Performance never overrides the
fallback.

## 22. Failure handling

- malformed MADT/topology: fail closed for affected CPU records;
- AP startup timeout: CPU Failed, never scheduled;
- unsupported x2APIC destination: fallback only if representable;
- timer capability failure: explicit timer fallback/degraded state;
- unsynchronized clock: restrict CBS migration/claims;
- IRQ route failure: device/route unavailable, never guessed;
- inbox stale generation: discard and count;
- migration commit failure: rollback source;
- CBS over-admission: reject control operation;
- IPI delivery timeout: structured fatal/degraded policy according to operation;
- no silent CPU-mask truncation.

## 23. Security invariants

- only Online allowed CPUs execute a Task;
- owner-only ordered queue mutation;
- no acknowledged wake/event loss;
- no simultaneous Task execution on two CPUs;
- no Task ID change on migration;
- no kernel migration with CPU-local borrow;
- no cross-TrustDomain user coexecution in `smt=isolated` according to the
  documented gate model;
- no unvalidated IRQ destination;
- no xstate leakage;
- no stale TLB/PCID reuse;
- IRQ storms cannot consume unbounded thread budget;
- hard cap and CBS admission cannot exceed validated capacity.

## 24. Test matrix

Host tests:

- MADT type 0/type 9, malformed and duplicate records;
- topology leaf 0x1f/0x0b/fallback;
- scalable CPU masks and sparse APIC IDs;
- APIC command encoding;
- timer conversion/overflow;
- inbox memory ordering/state model;
- load-placement/steal invariants;
- IRQ affinity format restrictions;
- SMT gate interleavings;
- TLB/PCID generation model.

QEMU gates:

- SMP 1/2/4/8/16/32;
- xAPIC and x2APIC;
- sparse/high APIC-ID topology where supported;
- AP startup failure injection;
- full/lazy preemption;
- TSC-deadline and one-shot/periodic fallback;
- remote wake/migration/IPI storms;
- threaded IRQ and storm masking;
- NVMe MSI-X affinity;
- SMT policy modes;
- eager xstate and PCID on/off;
- TLB shootdown under migrating address spaces.

Bare-metal gates:

- Intel and AMD;
- SMT on/off topology;
- xAPIC/x2APIC mode;
- invariant-TSC/skew report;
- AP Online/Failed masks;
- physical wake and scheduling latency;
- IRQ distribution under NVMe load;
- CBS migration and budget error;
- PCID/xstate isolation;
- complete unedited serial/performance evidence.

QEMU is not bare-metal evidence.

## 25. Implementation sequencing

This is one implementation PR, but commits remain independently reviewable:

1. pure model, IDs, masks, state machine, and observability;
2. preemption/migration guards and lock classification;
3. owner-only runqueues and bitmap inbox;
4. request-based EEVDF and Job hierarchy;
5. monotonic clock and one-shot timer;
6. CBS, hard caps, and automatic migration;
7. threaded IRQ and affinity;
8. topology, x2APIC, and SMT policies;
9. eager xstate and SIMD enablement;
10. PCID/INVPCID and active-address-space masks;
11. stress, benchmark, docs, and physical-evidence harness.

No commit may bypass the prior layer's invariant tests.

## 26. Documentation requirement

The implementation must update this document with exact constants, memory
orderings, vector assignments, fallback behavior, measurements, and evidence.
Architectural deviation requires owner approval before code.
