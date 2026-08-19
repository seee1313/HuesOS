# ACPI → PCI implementation PR plan

- **Status:** approved execution plan; implementation has not started
- **Owners:** HuesOS project owner + implementation agent
- **Architecture:** [ACPI_RING3.md](ACPI_RING3.md) and
  [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md)
- **Related roadmap:** [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md)

This document is the shared working agreement for delivering the Ring-3 uACPI
runtime, immutable firmware snapshots, mediated AML PCI reads, and HPCI root
publication without weakening the HuesOS microkernel trust model.

It deliberately defines small PR boundaries. A later PR may be split further
when review reveals an independent risk, but adjacent stages must not be merged
into one large implementation diff merely for speed.

---

## 1. Collaboration contract

### 1.1 Project owner responsibilities

The project owner:

- approves changes to trust boundaries, failure policy, and wire ABI;
- selects an option at every architecture checkpoint before dependent code is
  written;
- creates/merges PRs in the documented order after required CI is green;
- uses **Create a merge commit** for staged branches;
- provides or approves bare-metal runs when a gate requires physical hardware;
- decides whether a documented compatibility exception is acceptable;
- does not need to manually rewrite agent-produced implementation to count as
  the architecture owner.

### 1.2 Implementation agent responsibilities

The implementation agent:

- starts every batch from the verified current `origin/main`;
- asks before changing an approved authority or lifecycle decision;
- keeps policy logic safe, `no_std`, bounded, and host-testable where possible;
- isolates and documents every new Rust/C `unsafe` boundary;
- writes focused commits with Conventional Commit messages, motivation,
  root-cause/context, and actual verification evidence;
- runs the required gates and never reports a skipped gate as passing;
- pushes review branches and supplies exact compare/PR links and merge order;
- updates architecture, roadmap, progress ledger, and testing documentation in
  the PR that changes behavior.

### 1.3 Shared review rules

Both participants treat the following as stop conditions:

- a PR contains an undeclared raw physical-memory, ECAM, CF8/CFC, or port-I/O
  grant;
- an AML declaration is used as its own authorization without an approved
  independent policy source;
- a config write lacks a named policy class, readback mask, and rollback path;
- a generation/snapshot mismatch is logged but accepted;
- a capacity overflow silently drops firmware data;
- a test or QEMU marker claims a path that did not execute;
- a stacked PR shows changes from more than its named stage after retargeting.

---

## 2. Branch and merge workflow

Implementation is delivered in stacks of at most three PRs. This limits review
size and avoids maintaining one long fragile stack.

For each batch:

1. fetch and verify `origin/main`;
2. branch PR N from `main`;
3. branch PR N+1 from PR N only when the dependency is real;
4. branch PR N+2 from PR N+1 only when required;
5. push all branches and create PRs with their correct temporary bases;
6. merge PR N with **Create a merge commit**;
7. retarget PR N+1 to `main` and confirm its diff contains only stage N+1;
8. do not delete a parent branch before retargeting the child;
9. if GitHub shows duplicate history after retargeting, stop, rebase the
   remaining stack onto `main`, verify, and force-push with lease;
10. start the next batch only after the previous batch is in `main` and green.

Every PR description includes:

```text
Architecture/roadmap stages
Why this boundary exists
Authority added or deliberately not added
Failure/rollback behavior
Files and ABI affected
Tests actually run
Tests not run and why
Next dependent PR
```

---

## 3. Standard verification gates

Unless a PR documents a narrower policy-only exception, run:

```bash
source /home/user/huesos-toolchain-env.sh
make audit-check
make clippy
make test
CARGO_BUILD_JOBS=1 make build-release
git diff --check origin/main...HEAD
```

Additionally:

- run the relevant standalone userspace crate build/Clippy commands;
- run all feature matrices touched by the PR;
- run host sanitizer and malformed-input corpora when the C runtime or AML
  boundary changes;
- run QEMU for any on-target bootstrap, capability, mapping, process,
  interrupt, or hardware-access change;
- preserve the kernel NVMe bootstrap and its smoke markers until Stage J;
- attach serial markers and seed/replay data for failures;
- record unavailable local dependencies such as QEMU instead of claiming the
  corresponding verification.

No implementation stage closes solely because it compiles.

---

## 4. Architecture checkpoints

### Gate A — fixed by the architecture PR

Approved:

- separate kernel barebones and userspace full-uACPI crates;
- ACPI archive v2 with RSDP and complete physical translation;
- HMCF separate from HPCI;
- DriverManager snapshot retention and supervision;
- dynamic kernel config-capability mint request;
- `pci-manager` as sole PCI config executor;
- first AML PCI path is mediated read-only;
- old ACPI broker PCI opcodes are reserved and hard-denied;
- incomplete devices are diagnostic/read-only/unbound;
- last-good snapshot is retained after ACPI failure while new lifecycle work is
  frozen.

### Gate B — SystemMemory/SystemIO grant derivation

**Must be approved before AP-11 begins.** The first fixed FADT SystemIO policy
is already bounded, but general AML OperationRegions need an independent grant
source. The decision must specify:

- which UEFI/E820 memory types may back SystemMemory;
- how RAM, kernel image, page tables, DMA buffers, ECAM, BARs, and other live
  capabilities are excluded;
- whether only platform-reserved ranges or also board policy may grant access;
- initial read/write direction per range;
- how dynamic AML offsets/lengths are checked;
- whether unsupported firmware degrades one root or the complete ACPI runtime.

An AML `OperationRegion` declaration alone is not sufficient authority.

### Gate C — PCI config writes

**Outside the read-only root-discovery sequence.** No PCI config write is
implemented until B.4 defines write classes, expected readback masks,
transaction ownership, audit records, and rollback. Firmware requiring a write
in the first runtime receives a structured denial.

### Gate D — `_OSC`, hotplug, and runtime root changes

Deferred until static HMCF/HPCI publication is proven. The owner must approve
native-control claims, last-good snapshot replacement, and root hotplug policy
before `_OSC` grants or dynamic root insertion are enabled.

---

## 5. PR sequence overview

| PR | Working title | Main result | Runtime authority added? |
|---|---|---|---|
| **AP-0** | Reconcile ACPI/PCI authority documentation | Normative architecture + this plan | No |
| **AP-1** | Define ACPI archive v2 | RSDP-complete bounded ABI and dual-version decoder | No |
| **AP-2** | Produce sealed archive-v2 snapshots | Kernel builder emits complete immutable snapshot | Read-only snapshot only |
| **AP-3** | Isolate full userspace uACPI build | Separate runtime crate with denied callbacks | No |
| **AP-4** | Add bounded runtime primitives | alloc/time/mutex/event/dispatch contracts | No hardware authority |
| **AP-5** | Map uACPI tables from archive only | physical→VMO translation; no raw physical map | Archive read only |
| **AP-6** | Supervise ACPI manager generations | restart/backoff, retained archive/broker duplicate | Existing ACPI broker only |
| **AP-7** | Define and publish HMCF | validated config-window snapshot | No config access |
| **AP-8** | Add dynamic config mint authority | kernel cross-check and exact capability creation | Mint mechanism, no consumer yet |
| **AP-9** | Deliver config authority to PCI Manager | generation-safe HMCF/capability handoff | Read-only transport to PCI Manager |
| **AP-10** | Mediate AML PCI reads | dedicated ACPI→PCI protocol; writes denied | Bounded config reads |
| **AP-11** | Mediate AML OperationRegions | approved SystemIO/SystemMemory handlers | Gate-B ranges only |
| **AP-12** | Complete IRQ/work teardown boundary | CPU0 work, IRQ install/remove, drain ordering | Narrow IRQ authority |
| **AP-13** | Load the userspace AML namespace | full uACPI initialize/load with corpus tests | No new authority |
| **AP-14** | Initialize namespace and `_PIC` | `_STA`/`_INI`/`_REG`, explicit degradation | No PCI writes |
| **AP-15** | Publish HPCI root descriptors | `_SEG`/`_BBN`/`_CRS` → immutable roots | Data publication only |
| **AP-16** | Publish read-only PCI inventory | HMCF/HPCI consistency + visible unbound devices | Read-only inventory |

AP-0 is the documentation PR containing this plan. AP-1 is the first
implementation PR and must not begin until AP-0 is merged.

---

# Batch 1 — Snapshot ABI and isolated runtime build

## AP-1 — ACPI archive v2 ABI

**Proposed commit:**

```text
feat(acpi-abi): define RSDP-complete archive v2
```

Scope:

- separate broker protocol version from archive format version;
- define archive-v2 header and RSDP descriptor;
- define complete physical-range-to-VMO translation records;
- bind records to a non-zero `firmware_snapshot_id`;
- add bounded streaming/metadata decoder suitable for a VMO reader;
- keep v1 decoding only for controlled transition and diagnostics;
- make index-capacity failure explicit;
- update current `acpi-manager` validation to understand v1 and v2 without
  enabling AML.

Required tests:

- RSDP revision 0/2 checksum and length;
- truncated, duplicate, overlapping, unsorted, and reserved fields;
- table/physical/VMO arithmetic overflow;
- duplicate signatures and stable instance numbers;
- translation containment and boundary requests;
- too many physical ranges fails instead of truncating;
- v1 compatibility does not invent an RSDP.

Not in scope:

- kernel archive-v2 production;
- full uACPI linking;
- hardware access.

## AP-2 — Kernel archive-v2 producer

**Proposed commit:**

```text
feat(acpi): publish sealed RSDP-complete firmware snapshots
```

Scope:

- copy the boot RSDP and every accepted installed table object;
- cross-check barebones uACPI metadata and copied bytes;
- emit a complete physical translation index;
- reject unrepresentable FACS/DSDT/table graph rather than publishing a partial
  snapshot;
- install the archive VMO read-only with duplicate/transfer rights;
- preserve v1 consumer compatibility only for the AP-1 transition;
- expose structured boot diagnostics including snapshot ID and counts.

Required evidence:

- host encoder/decoder round trips;
- injected RSDP/table/index failures;
- `make audit-check`, Clippy, tests, release build;
- QEMU Q35/OVMF marker proving the v2 snapshot reached current
  `acpi-manager`;
- no namespace/AML execution.

Rollback:

- archive construction failure leaves Ring-3 ACPI unavailable and retains the
  existing early barebones/SMP failure policy; it never publishes a partial v2
  handle.

## AP-3 — Separate full userspace uACPI crate

**Proposed commit:**

```text
feat(uacpi-runtime): add isolated fail-closed userspace build
```

Scope:

- add a separate `no_std` userspace runtime crate;
- compile the pinned full uACPI C source set without changing the kernel crate;
- provide explicit stubs for the complete host callback surface;
- allow logging and non-hardware initialization scaffolding only;
- all mapping, SystemIO, SystemMemory, PCI, IRQ, reset, and power callbacks fail
  closed;
- add the standalone crate to formatting/Clippy tooling;
- document every FFI type/layout and callback contract.

Required evidence:

- kernel `huesos-uacpi` still compiles with `UACPI_BAREBONES_MODE`;
- userspace full runtime links independently;
- missing callback symbols are a build failure, not weak/default behavior;
- host ASan/UBSan smoke for the C runtime;
- no on-target manager behavior change.

---

# Batch 2 — Runtime primitives, archive mapping, and supervision

## AP-4 — Userspace uACPI primitives

**Proposed commits:**

```text
feat(uacpi-runtime): add bounded allocation and time callbacks
feat(uacpi-runtime): implement mutex event and dispatch contracts
```

Scope:

- allocation/free/zeroed allocation with failure reporting;
- monotonic nanoseconds, bounded stall, scheduler sleep;
- non-recursive mutexes with exact timeout semantics;
- counted events with saturation/teardown rules;
- stable thread IDs;
- process-local interrupt-dispatch suppression and restoration;
- spin/dispatch guards that do not execute privileged `cli`/`sti`.

Required tests:

- zero, finite, and infinite timeout behavior;
- recursion rejection;
- signal-before-wait, multiple signals, reset, saturation, and teardown races;
- monotonicity and overflow boundaries;
- allocation failure at each uACPI-visible allocation point;
- no callback blocks while holding an IRQ-delivery or allocator-internal lock.

## AP-5 — Archive-only uACPI table map

**Proposed commit:**

```text
feat(uacpi-runtime): resolve firmware tables from archive v2
```

Scope:

- map the archive VMO read-only once;
- return the archived original RSDP address;
- translate `uacpi_kernel_map` requests into archive offsets;
- reject cross-record, zero-length, overflow, stale snapshot, and unindexed
  ranges;
- make unmap bookkeeping deterministic;
- prove that no physical-map syscall is reachable from the table callback.

Required tests:

- RSDP → XSDT/RSDT → FADT/DSDT/FACS graph over synthetic snapshots;
- misaligned header/full-table requests;
- page-boundary ranges contained in one record;
- attempts to map RAM, MMIO, ECAM, adjacent gaps, or two records fail;
- fuzz decoder/translator under ASan/UBSan.

## AP-6 — ACPI Manager supervision and generations

**Proposed commit:**

```text
feat(driver-manager): supervise generation-safe ACPI runtime
```

Scope:

- DriverManager retains a master archive duplicate;
- the parent retains or can duplicate the immutable ACPI broker capability for
  each child generation;
- replace text-only lifecycle markers with a bounded versioned control protocol;
- non-zero generation, hello, ready stage, heartbeat, structured failure;
- bounded restart backoff and explicit degraded state;
- last-good snapshot/freeze policy state machine, initially with no HMCF/HPCI
  payload;
- stale replies cannot mark a new generation ready.

Required QEMU cases:

- successful current archive-validation startup;
- crash before archive acceptance;
- crash after readiness;
- stale heartbeat/control bytes;
- restart budget exhaustion;
- existing unrelated DriverHosts continue.

No full AML or PCI authority is enabled.

---

# Batch 3 — HMCF and dynamic config capability

## AP-7 — HMCF wire format and producer

**Proposed commits:**

```text
feat(acpi-abi): define validated config-window snapshots
feat(acpi-manager): publish HMCF from archived MCFG
```

Scope:

- add a pointer-free, bounded, versioned `HMCF` wire format;
- records contain segment, start/end bus, ECAM physical base, flags, snapshot
  ID, and producer generation;
- use the existing checked `huesos-pci` MCFG parser;
- publish through DriverManager, not directly to `pci-manager`;
- DriverManager validates only envelope/size/generation and retains the
  immutable VMO; semantic validation remains in the producer/consumer;
- no ECAM mapping or enumeration.

Required tests:

- multiple segments, adjacent/overlapping windows, non-zero start bus;
- reserved fields, count, checksum provenance, physical span overflow;
- stale generation/snapshot and malformed VMO rejection;
- deterministic canonical encoding.

## AP-8 — Dynamic kernel config mint authority

**Proposed commits:**

```text
feat(pci): add snapshot-bound config mint authority
feat(syscalls): cross-check HMCF before minting config resources
```

Scope:

- add one unique `PciConfigMint` authority for the root supervisor;
- add a bounded mint request accepting HMCF VMO/generation metadata, never a
  naked physical range;
- kernel independently decodes HMCF and the bound archive-v2 MCFG;
- exact equality/canonical-subset checks for every ECAM record;
- reject RAM aliases, overlap, overflow, stale archive, widened range, unknown
  record, and duplicate request;
- create initial read-only, uncached, NX ECAM capabilities;
- support only the fixed exact segment-0 CF8/CFC authority request;
- return a handle whose DriverManager rights are transfer-only where the object
  model permits it.

Security tests:

- arbitrary physical address cannot be minted;
- HMCF signed/bound to another snapshot fails;
- one-bus and one-byte widening fails;
- removed/replayed generation fails;
- ordinary processes and `acpi-manager` cannot invoke mint;
- overlapping authority cannot be minted twice;
- no write-capable ECAM mapping exists in this PR.

QEMU must prove capability creation but not device enumeration.

## AP-9 — DriverManager → PCI Manager authority handoff

**Proposed commit:**

```text
feat(pci-manager): accept generation-bound HMCF config authority
```

Scope:

- order PCI Manager readiness on HMCF validation and capability receipt;
- transfer HMCF plus exact config handles to the matching manager generation;
- `pci-manager` independently validates metadata and mapping geometry;
- malformed/missing/stale authority remains fail-closed;
- restart replays the retained HMCF through a fresh validated mint/handoff;
- no public topology and no DriverHost binding.

Required QEMU markers distinguish:

```text
no firmware snapshot
HMCF rejected
config capability mint rejected
read-only config authority ready
```

---

# Batch 4 — Mediated PCI reads and ACPI hardware boundary

## AP-10 — Dedicated ACPI → PCI read protocol

**Proposed commits:**

```text
feat(pci-abi): define ACPI config mediation protocol
feat(pci-manager): serve bounded AML config reads
feat(acpi): permanently deny legacy broker PCI opcodes
```

Scope:

- dedicated private channel created/transferred by DriverManager;
- request includes both manager generations, snapshot ID, segment:BDF, offset,
  width, correlation ID, and read operation;
- PCI Manager performs the physical ECAM/CF8 access;
- every write variant is absent or explicitly rejected as `AccessDenied`;
- uACPI open/read/close callbacks use opaque userspace handles with no raw
  config pointer;
- old ACPI broker PCI opcodes remain decodable append-only values but cannot be
  authorized or executed;
- structured latency, denial, absent-function, timeout, and backend observations.

Required tests:

- conventional/extended offset and width boundaries;
- absent function returns the uACPI-compatible result without fabricating a
  present device;
- stale generation, channel reconnect, timeout, and manager crash;
- all write attempts denied before hardware access;
- QEMU Q35 ECAM reads and forced legacy common-subset reads.

No inventory is published.

## AP-11 — SystemIO/SystemMemory OperationRegion handlers

**Blocked by architecture Gate B.**

**Proposed commits after approval:**

```text
feat(acpi-broker): enforce approved firmware OperationRegion grants
feat(uacpi-runtime): mediate SystemIO and SystemMemory regions
```

Scope:

- keep archive table mapping separate from SystemMemory;
- install explicit uACPI address-space handlers;
- exact width/alignment/range/direction checks;
- approved independent grant derivation only;
- deny RAM, kernel, page tables, DMA, ECAM, PCI BAR, and unreserved ranges unless
  a later explicit policy says otherwise;
- no raw MMIO mapping in `acpi-manager`;
- bounded broker calls and teardown.

Required tests include malicious AML declarations targeting RAM, kernel text,
ECAM, CF8/CFC, wraparound, and adjacent-but-ungranted ranges.

## AP-12 — IRQ and deferred-work lifecycle

**Proposed commits:**

```text
feat(acpi-broker): add generation-safe IRQ handler lifecycle
feat(uacpi-runtime): add CPU0 work queue and completion barrier
```

Scope:

- exact granted IRQ installation/removal;
- userspace interrupt channel and bounded dispatch queue;
- CPU0-affine GPE work;
- notification work ordering;
- completion waits drain interrupt callbacks before work;
- crash/restart revokes old handlers and stale packets;
- no full GPE enablement until namespace behavior is proven.

Required tests:

- interrupt during teardown;
- queued work during manager crash;
- duplicate install/remove;
- queue overflow and deadline;
- stale generation packet;
- QEMU synthetic SCI delivery without enabling hotplug policy.

---

# Batch 5 — Namespace execution and root publication

## AP-13 — Full userspace namespace load

**Proposed commit:**

```text
feat(acpi-manager): load AML namespace in isolated runtime
```

Scope:

- call full uACPI initialization against archive v2;
- delay ACPI mode until fixed broker readiness;
- load DSDT/SSDT namespace;
- install only handlers completed in AP-10 through AP-12;
- unsupported address spaces return explicit `NoHandler`/degraded status;
- no namespace initialization and no `_INI` yet;
- synthetic AML and captured-firmware corpus harness.

Required evidence:

- host ASan/UBSan full corpus;
- allocation and callback fault injection;
- namespace bytecode/while limits and process watchdog;
- Q35/OVMF namespace-load marker;
- malformed AML kills only `acpi-manager`, followed by supervised restart.

Deferred address spaces such as EmbeddedController, GPIO, GenericSerialBus,
SMBus, PCC, battery/thermal policy, and suspend are not silently claimed as
supported.

## AP-14 — Namespace initialize and `_PIC`

**Proposed commit:**

```text
feat(acpi-manager): initialize bounded AML namespace
```

Scope:

- select the IOAPIC interrupt model through `_PIC` after namespace load and
  before namespace initialization when available;
- execute required `_STA`, `_INI`, and `_REG` initialization through uACPI;
- enforce per-method deadline and aggregate bootstrap watchdog;
- mediated PCI reads allowed; writes denied;
- record which denied/unsupported handler caused degradation;
- no HPCI publication on partial or inconsistent root evaluation.

Required QEMU cases:

- normal Q35 initialization;
- missing `_PIC` allowed when specification permits it;
- PCI-write-required firmware path is visibly degraded;
- handler timeout, malformed return, manager crash, and restart;
- kernel and unrelated services remain alive.

## AP-15 — HPCI root descriptor producer

**Proposed commits:**

```text
feat(acpi-manager): publish validated PCI root descriptors
feat(pci-manager): validate HMCF and HPCI consistency
```

Scope:

- find `PNP0A03`/`PNP0A08` roots;
- evaluate bounded `_SEG`, `_BBN`, and `_CRS`;
- decode bus, I/O, MMIO32, MMIO64, prefetchable, translation, and fixed flags;
- canonical root IDs stable for one firmware snapshot;
- encode existing HPCI ABI or revise it append-only if review requires;
- DriverManager retains and forwards immutable generation-bound HPCI;
- PCI Manager independently validates roots and matches HMCF config windows;
- MCFG never supplies allocatable BAR apertures.

Required tests:

- multiple roots/segments;
- absent optional `_SEG`/`_BBN` defaults;
- translated apertures and overflow;
- producer/consumer descriptor semantics;
- root bus outside HMCF;
- overlapping/crossing roots and apertures;
- malformed AML package/resource buffers;
- Q35 root reaches PCI Manager through the complete userspace path.

`_PRT`, `_OSC`, `_CBA` hotplug, and native-control grants remain later Gate-D
work unless a root cannot be represented safely without them.

## AP-16 — Diagnostic read-only PCI inventory

**Proposed commit:**

```text
feat(pci-manager): publish root-bound read-only inventory
```

Scope:

- enumerate only validated HPCI roots through accepted HMCF/capabilities;
- build the existing immutable bridge-aware topology snapshot;
- attach firmware-resource availability status;
- devices without complete roots remain visible only as
  `FirmwareResourcesUnavailable`;
- no config write, BAR sizing mutation, lease, IRQ allocation, DMA, bus-master
  enable, or DriverHost launch;
- ACPI crash freezes new inventory generations while preserving the last-good
  diagnostic snapshot.

Required evidence:

- Q35 ECAM and forced legacy common-subset inventory comparison;
- multifunction and nested bridge fixtures;
- malformed capabilities/topology remain bounded;
- PCI/ACPI manager crash/restart and stale-generation rejection;
- explicit proof that no config write occurred;
- roadmap marks only read-only discovery gates complete.

---

## 6. Work intentionally after AP-16

AP-16 does **not** make PCI production-ready. The next approved architecture
work remains:

```text
B.4  config write policy and audited write/readback transactions
C.3  _PRT and _OSC ownership
G.2  kernel DeviceLease object and revocation enforcement
G.3  DeviceGone delivery
E.1  live BAR inventory
F.2  plan verification/rollback data
H.3  driver binding
I    interrupt and DMA handoff
J    NVMe migration and kernel bootstrap removal
K+   hotplug, rebalance, IOMMU, production qualification
```

No AP-series PR removes `crates/huesos-kernel/src/boot/storage.rs` or claims
that NVMe is managed by the production PCI path.

---

## 7. Progress ledger template

Each PR adds one row or updates the corresponding row in the live PCI roadmap:

| PR | State | Merge commit | Host evidence | QEMU evidence | Hardware evidence | Blocker |
|---|---|---|---|---|---|---|
| AP-0 | complete | `fea733f` | repository gates green | n/a | n/a | — |
| AP-1 | complete | `0c45f00` | archive-v2 ABI/61 ABI tests | n/a | n/a | — |
| AP-2 | complete | `8d7fc8c` | pure encoder + repository gates | Q35/OVMF release SMP2: 8 tables/9 mappings | n/a | — |
| AP-3 | complete | `57d8203` | target build + fail-closed ASan/UBSan smoke | n/a | n/a | — |
| AP-4 | in review | pending | 4 primitive host tests + target build | n/a | n/a | merge |
| AP-5…AP-16 | not started | — | — | — | — | ordered dependencies |

A row says `Complete` only after its exit criteria and actual verification logs
are named in the merged PR. Policy-only completion never closes an on-target
runtime gate.
