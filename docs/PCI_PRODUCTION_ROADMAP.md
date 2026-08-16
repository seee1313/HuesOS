# HuesOS PCI/PCIe Production Roadmap

- **Status:** active roadmap; PCI production-ready = false
- **Target:** x86_64 UEFI/ACPI systems with PCI/PCIe, NVMe, xHCI, and
  future network and graphics DriverHosts
- **Architecture:**
  [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md)

This roadmap turns the approved HuesOS userspace PCI Manager architecture into
small, reviewable delivery stages. It is intentionally stricter than a feature
checklist: a stage closes only when the behavior is exercised through the
production path and its negative cases are observable.

The roadmap does not promise broad hardware support merely because PCI is a
standard. It defines the evidence required before HuesOS may claim that support.

---

## 1. Production definition

HuesOS PCI/PCIe is production-ready only when all of the following are true:

- PCI roots are discovered from validated ACPI data, including multiple
  segments where present.
- ECAM and legacy CF8/CFC common-subset paths are independently tested.
- bridge-aware enumeration replaces the flat all-BDF boot scan.
- one userspace `pci-manager` is the only configuration writer.
- individual drivers receive only per-device MMIO/IRQ/DMA authority.
- valid firmware assignments are preserved and conflicts are rejected.
- DeviceLease generation/revocation prevents BDF-reuse and stale-resource ABA.
- NVMe boots entirely through `pci-manager`; the kernel storage PCI shim is
  removed.
- insertion, orderly removal, and fail-stop surprise removal have deterministic
  lifecycle tests.
- resource planning and relocation have exhaustive host fault injection.
- trusted-DMA and IOMMU-isolated modes are reported accurately.
- a documented QEMU matrix and a multi-machine bare-metal matrix are green.
- operational topology/resource/lease records are sufficient to reproduce a
  field failure.

Passing host unit tests alone does not close the production gate.

---

## 2. Delivery rules

Every stage PR must:

1. state the stage and track identifiers;
2. name the invariant it establishes;
3. include host tests for hardware-independent logic;
4. include QEMU evidence for on-target behavior, or explicitly state that the
   stage is policy-only and cannot close a runtime gate;
5. update this roadmap and the architecture document when behavior changes;
6. keep config-space writes bounded and observable;
7. add no unreviewed `unsafe`, panic surface, or privileged unranked lock;
8. preserve the current NVMe boot path until its replacement is proven;
9. avoid combining policy, kernel mechanism, userspace orchestration, and
   driver migration into one unreviewable diff;
10. identify rollback behavior before mutating hardware.

A stage may contain several PRs. "Code exists" and "production path uses it"
are separate states.

---

## 3. Profile model

### 3.1 PCI Compatibility Profile

```text
Boot:              UEFI + ACPI
Config transport:  ECAM or segment-0 CF8/CFC
DMA:               trusted driver, bounded pool, no hardware isolation claim
Interrupts:        MSI-X / MSI / INTx / allowed polling fallback
Hotplug:           reserved-space insertion + orderly/fail-stop removal
```

Drivers controlling bus-mastering devices are part of the machine-wide TCB in
this profile.

### 3.2 PCI Isolated Profile

```text
Boot:              UEFI + ACPI
Config transport:  ECAM preferred
DMA:               per-device VT-d/AMD-Vi domain
Interrupts:        same as compatibility profile; interrupt remapping reported
Hotplug:           lease revocation includes DMA-domain teardown
```

Only this profile may claim that a malicious/compromised DriverHost cannot DMA
outside its granted buffers.

---

## 4. Stage index

| Stage | Theme | Exit signal |
|---|---|---|
| **A** | Architecture and contracts | Approved normative docs; no unresolved ownership or identity ambiguity |
| **B** | Config transport policy core | Host-tested ECAM/legacy plans and checked `PciAddress` model |
| **C** | Firmware/root-bridge discovery | Validated MCFG + ACPI root descriptors reach userspace |
| **D** | Topology and capabilities | Deterministic multi-segment bridge graph and bounded capability traversal |
| **E** | Firmware resource validation | BAR/window inventory is conflict-free or explicitly rejected |
| **F** | Resource planner | Deterministic firmware-preserving allocation with rollback plan |
| **G** | DeviceLease and revocation | Generation-safe per-device authority; stale handles fail |
| **H** | Userspace PCI Manager | One userspace service owns config access and publishes inventory |
| **I** | Interrupt and DMA handoff | Drivers receive narrow BAR/IRQ/DMA resources through leases |
| **J** | NVMe migration | System NVMe boots through PCI Manager; kernel PCI shim deleted |
| **K** | Reserved-space hotplug | Insert/orderly remove/surprise fail-stop work without moving active devices |
| **L** | Restart-based rebalance | Restartable drivers relocate transactionally; fixed devices never move |
| **M** | Opt-in live relocation | `QuiesceRemap` drivers survive verified BAR/window changes |
| **N** | IOMMU isolated profile | Per-device DMA domains and negative unauthorized-DMA tests pass |
| **O** | Production qualification | Long-haul, fault, hotplug, performance, and bare-metal matrices pass |

---

# Stage A — Architecture and contracts

Status: **IN PROGRESS**

## A.1 Normative architecture

Deliver:

- `docs/PCI_MANAGER_ARCHITECTURE.md`;
- authority and trust boundaries;
- config backend semantics;
- address vs identity model;
- DeviceLease lifecycle;
- relocation classes;
- DMA security profiles;
- hotplug and rollback behavior.

Exit criterion:

- project owner approves the architecture;
- all implementation documents link to it instead of duplicating conflicting
  PCI policy;
- unresolved questions are listed explicitly, not hidden in code comments.

## A.2 Initial ABI vocabulary

Specify, without necessarily implementing:

```text
PciAddress
DeviceId
LeaseGeneration
PciRootBridgeDescriptor
PciDeviceInfo
PciBarInfo
DmaIsolation
RelocationClass
DeviceGone
TopologyGeneration
```

Exit criterion:

- each identity has one meaning and stable-width representation;
- BDF is explicitly non-stable;
- config errors, absence, unsupported transport, revocation, and device removal
  are distinguishable.

## A.3 Migration map

Document every current bootstrap responsibility and its final owner:

| Current responsibility | Current owner | Target owner |
|---|---|---|
| CF8/CFC scan | kernel `boot/storage.rs` | `pci-manager` transport |
| NVMe class match | kernel | userspace topology/binding |
| BAR0 sizing | kernel | resource inventory/planner |
| MSI-X/MSI programming | kernel | `pci-manager` + kernel IRQ allocator |
| DMA pool reservation | kernel init | lease/DMA allocator |
| resource minting | init | root supervisor/lease authority |
| DriverHost launch | DriverManager | component/driver manager from PCI event |

Exit criterion:

- no current function can be deleted without a named later-stage replacement.

---

# Stage B — Configuration transport policy core

Status: **IN PROGRESS**

## B.1 Address and width model

Implementation status: complete across PCI-1/PCI-2. Checked vocabulary landed
first; PCI-2 removes the current kernel bootstrap shim's ad-hoc CF8 encoding in
favor of the shared planner.

Extend `huesos-pci` with checked, safe types:

```text
PciAddress { segment, bus, device, function }
ConfigOffset
ConfigWidth
ConfigError
```

Required tests:

- device/function limits;
- width alignment and end crossing;
- offset 255/256/4095/4096 boundaries;
- arithmetic overflow;
- absent-function semantics.

Exit criterion:

- no caller constructs config addresses through ad-hoc shifts.

## B.2 ECAM access planning

Implementation status: **complete (policy core) in PCI-2**; physical ECAM
mapping/execution remains Stage H.

Implement pure checked ECAM address calculation from a validated MCFG window.
No physical pointer dereference belongs in this track.

Required tests:

- start/end bus boundaries;
- multiple segments;
- non-zero start bus;
- overlapping and adjacent windows;
- physical end overflow;
- malformed MCFG records;
- exact 4 KiB function stride.

Exit criterion:

- a host test can generate every physical access address used by the future
  on-target backend.

## B.3 Legacy access planning

Implementation status: **complete in PCI-2**, including migration of the
current kernel NVMe bootstrap shim to checked plans.

Implement a pure CF8 address planner for the common subset:

```text
segment 0
bus 0..255
function 0..7
offset 0..255
dword transport with bounded sub-dword read-modify-write
```

Required tests:

- reject non-zero segment and extended offset;
- preserve unrelated bytes on write8/write16 plans;
- serialize access requirements explicitly.

Exit criterion:

- ECAM and legacy backends pass the same common-subset conformance vectors.

## B.4 Config write policy

Classify writes:

```text
ReadOnlyIdentity
CommandControl
BAR
BridgeBusNumbers
BridgeWindow
CapabilityControl
VendorAllowlisted
Forbidden
```

Exit criterion:

- every target-stage config write names a policy class and expected readback
  mask; no unrestricted generic write reaches an ordinary DriverHost.

---

# Stage C — Firmware and root-bridge discovery

Status: **IN PROGRESS**

## C.1 MCFG archive path

Implementation status: PCI-3 lands the bounded checksum/reserved/range/overlap
parser and multi-segment ECAM records. Transport from the live ACPI service and
QEMU evidence remain open.

ACPI manager exports validated MCFG entries to the PCI Manager bootstrap.

Required behavior:

- checksum and SDT length already validated by the ACPI archive;
- MCFG reserved field zero;
- record count bounded;
- segment and bus ranges validated;
- physical config span checked against overflow;
- conflicts reported per entry.

Exit criterion:

- QEMU Q35 reports one ECAM root through the userspace bootstrap path;
- malformed synthetic MCFG inputs fail without kernel fault.

## C.2 Root bridge descriptors

Implementation status: PCI-3 lands the versioned bounded ABI for roots and
translated apertures. Producing it from `_SEG`/`_BBN`/`_CRS` remains open.

Resolve `_SEG`, `_BBN`, and `_CRS` into immutable root descriptors. MCFG is not
used as an MMIO/BAR aperture source.

Required tests:

- separate I/O, MMIO32, MMIO64, and prefetchable apertures;
- non-zero PCI-bus-to-CPU translation offsets and overflow rejection;
- multiple roots and segments;
- overlapping firmware apertures;
- absent optional methods;
- bus range outside MCFG;
- bounded AML response sizes/timeouts.

Exit criterion:

- planner input contains explicit allocatable apertures for each root.

## C.3 Legacy routing and ownership

Export `_PRT` routing and `_OSC` native-control results.

Exit criterion:

- legacy interrupt availability and native hotplug/AER ownership are reported,
  never guessed.

---

# Stage D — Topology and capability enumeration

Status: **IN PROGRESS**

## D.1 Read-only userspace enumeration

Implementation status: PCI-5 lands the immutable generation-tagged topology
policy, including multi-segment roots, bridge parent resolution, deterministic
ordering, and malformed-graph rejection. Feeding it from live userspace config
reads and publishing the inventory remain open.

Build immutable topology snapshots without programming devices.

Required coverage:

- endpoints and Type 1 bridges;
- multifunction functions;
- nested bridges;
- multiple roots/segments;
- empty functions;
- duplicate/looping/invalid bus ranges;
- global node/depth/read budgets.

Exit criterion:

- QEMU and synthetic topology dumps are deterministic and generation tagged.

## D.2 Capability parsing

Implementation status: **complete (policy core) in PCI-4**. Conventional and
PCIe extended lists share bounded checked decoders; the current NVMe bootstrap
now rejects malformed or duplicate interrupt capabilities rather than using a
partial view. Live ECAM inventory integration remains part of D.1/H.2.

Extend current MSI/MSI-X parsing to conventional and ECAM-only extended
capabilities.

Required malformed-input tests:

- self-cycle and multi-node cycle;
- unaligned pointer;
- backward/overlapping pointers;
- truncated capability;
- unknown capability preservation;
- extended pointer beyond 4095.

Exit criterion:

- no malformed function can hang enumeration or make it read another
  function's page.

## D.3 Inventory publication

Publish a read-only topology snapshot to DriverManager/component manager and
operator tooling.

Exit criterion:

- inventory clients generate no config-bus traffic;
- snapshot includes backend, generation, segment:BDF, topology path, IDs,
  capabilities, BAR values, and validation findings.

---

# Stage E — Firmware resource validation

Status: **IN PROGRESS**

## E.1 BAR inventory

Decode all Type 0/Type 1 BARs, including 64-bit pairs, prefetchability, I/O
BARs, ROM BAR state, and malformed masks.

Safe sizing protocol:

- device is not owned by an active driver;
- memory/I/O decoding and bus mastering are disabled;
- original command/BAR values are snapshotted;
- all-ones sizing is bounded and restored;
- readback verifies restoration.

Exit criterion:

- sizing cannot run on an Online lease.

## E.2 Firmware assignment validator

Implementation status: PCI-6 lands the pure validator and canonical status
report, including explicit bus-to-CPU translation, collision checks, and
parent-window forwarding. Supplying BAR/window inventory from live enumeration
remains E.1/D.1 work.

Validate that:

- every BAR lies in a matching root/bridge aperture;
- every child BAR is forwarded by every parent window;
- sibling resources do not overlap;
- RAM/ECAM/reserved regions do not overlap assigned MMIO;
- 32-bit constraints are honored;
- bridge bus ranges are nested and non-conflicting.

Exit criterion:

- each resource is `Valid`, `Unassigned`, `Conflicting`, `Unrouteable`,
  `Unsupported`, or `Fixed`; invalid values are never silently accepted.

---

# Stage F — Firmware-preserving resource planner

Status: **NOT STARTED**

## F.1 Pure allocation model

Input is a topology snapshot, root apertures, resource requirements, and fixed
assignments. Output is an immutable plan; hardware is never touched.

Allocator order:

1. claim fixed/valid firmware ranges;
2. allocate unassigned endpoint BARs;
3. size bridge requirements bottom-up;
4. allocate windows top-down;
5. preserve hotplug reserves;
6. fail new/unassigned devices before stealing working resources.

Exit criterion:

- same input yields byte-identical plan;
- property tests prove no overlap/out-of-aperture assignment.

## F.2 Plan verification and rollback data

Each plan includes old/new values, write order, readback masks, and rollback
writes.

Exit criterion:

- fault injection before every planned write leaves the old plan recoverable or
  marks affected devices failed; no partial plan is considered committed.

## F.3 Reserved hotplug capacity

Policy reserves configurable bus numbers and MMIO/I/O space below capable
ports.

Exit criterion:

- synthetic insertion fits without moving active devices when reserve policy
  advertised enough capacity.

---

# Stage G — DeviceLease and revocation

Status: **NOT STARTED**

## G.1 Lease policy core

Implement a safe host-testable state machine:

```text
Discovered → Configured → DriverStarting → Online
Online → Quiescing → Rebalancing → Configured/Online
Online → Removing → Removed
any operational state → Failed
```

Exit criterion:

- invalid transitions, stale generations, double revoke, and BDF reuse are
  rejected in host tests.

## G.2 Kernel lease object

Add generation-safe authority for child MMIO/IRQ/DMA grants.

Initial restart-based revocation may terminate the DriverHost and rely on
process teardown. The kernel must still prevent new grants from a revoked
lease.

Exit criterion:

- stale lease handles cannot create mappings/interrupts/resources;
- resource address reuse does not revive old authority.

## G.3 DeviceGone delivery

Clients and supervisors receive stable removal/failure notifications.

Exit criterion:

- after removal no new operation reports success;
- service registry withdraws the device before address reuse.

---

# Stage H — Userspace PCI Manager

Status: **NOT STARTED**

## H.1 Component bootstrap

Launch `pci-manager` from BOOTFS with the unique config/root authority and ACPI
root descriptors.

Exit criterion:

- a second process cannot acquire overlapping config authority;
- manager crash is visible to the root supervisor;
- boot does not silently fall back without a status marker.

## H.2 Config backend execution

Wire policy plans to audited privileged boundaries:

- uncached/NX ECAM mapping;
- exclusive CF8/CFC dword access;
- one serialized writer;
- bounded read/write operations;
- structured write/readback observations.

Exit criterion:

- QEMU ECAM and forced-legacy runs enumerate the same segment-0 common
  inventory.

## H.3 Driver binding

Match manifests by class/vendor/device/subsystem/revision/capabilities and
launch one DriverHost per assigned device or approved group.

Exit criterion:

- unknown devices remain visible and unbound;
- no driver receives authority before lease and plan commit.

---

# Stage I — Interrupt and DMA resource handoff

Status: **NOT STARTED**

## I.1 Interrupt transaction

Manager selects MSI-X, MSI, INTx, or approved polling; kernel allocates vectors;
manager programs capabilities/tables; driver receives Interrupt handles.

Required tests:

- MSI-X table bounds/BIR/readback;
- vector exhaustion;
- x2APIC destination refusal without remapping;
- MSI fallback;
- shared INTx acknowledge;
- revoke while interrupt pending.

Exit criterion:

- no DriverHost programs MSI/MSI-X through raw config access.

## I.2 Unified DMA allocator

Expose one driver API returning device-visible addresses in both trusted and
IOMMU modes.

Exit criterion:

- driver code does not assume DMA address equals physical address;
- boot log and topology inventory identify actual isolation mode.

---

# Stage J — NVMe migration

Status: **NOT STARTED**

## J.1 Dual-path equivalence

Temporarily run kernel bootstrap inventory and userspace PCI inventory in
comparison mode without configuring the same function twice.

Compare:

- segment:BDF;
- vendor/device/class;
- BAR base/size/type;
- MSI/MSI-X metadata;
- selected vectors;
- DMA mode.

Exit criterion:

- mismatch fails a dedicated CI image with both inventories attached.

## J.2 PCI Manager boot path

PCI Manager configures and leases NVMe; DriverManager starts
`driver-host-nvme`; BlockDevice/Volume/Hxfs markers match the existing path.

Exit criterion:

- debug/release, SMP 1/2, plain/encrypted/no-TPM/power-fail/high-queue-depth
  matrices pass through PCI Manager.

## J.3 Remove bootstrap shim

Delete kernel CF8 flat scan, BAR sizing, and MSI/MSI-X programming from
`huesos-kernel::boot::storage`. Retain only generic kernel mechanisms still
needed by userspace.

Exit criterion:

- source/CI gate rejects reintroduction of direct kernel PCI policy;
- no storage boot-info NVMe descriptor remains in the public boot ABI.

---

# Stage K — Reserved-space hotplug

Status: **NOT STARTED**

## K.1 Event ingestion

Consume ACPI/native hotplug events through a bounded queue and rescan only the
affected root/subtree.

Exit criterion:

- event storms are coalesced/bounded;
- no enumeration occurs in IRQ callback context.

## K.2 Insertion without relocation

Use pre-reserved bus numbers/windows and allocate only the new subtree.

Exit criterion:

- repeated QEMU insertion reaches DriverHost ready without moving an Online
  lease.

## K.3 Removal

Orderly removal drains and revokes. Surprise removal terminates the DriverHost,
revokes generation, withdraws services, and reports `DeviceGone`.

Exit criterion:

- 1,000 synthetic add/remove cycles have no handle/resource leak;
- stale handle negative tests pass after every cycle.

---

# Stage L — Restart-based rebalance

Status: **NOT STARTED**

## L.1 Relocation classification

Manifests declare `Fixed`, `Restart`, or `QuiesceRemap`; default is `Fixed`.
System NVMe remains fixed.

Exit criterion:

- planner never moves a fixed device;
- unsupported devices fail allocation instead of forcing unsafe relocation.

## L.2 Transactional restart relocation

For `Restart` devices:

1. stop new opens;
2. stop DriverHost;
3. revoke old lease;
4. disable bus mastering/decoding;
5. apply and verify plan;
6. mint new generation/resources;
7. start new DriverHost;
8. publish service after readiness.

Exit criterion:

- exhaustive fault injection before every transition/write produces complete
  old layout, complete new layout, or explicit Failed devices — never partial
  Online state.

## L.3 Rollback

Exit criterion:

- previous plan is restored byte-for-byte when hardware readback permits;
- rollback failure is fail-stop and observable, not represented as success.

---

# Stage M — Opt-in live relocation

Status: **DEFERRED**

## M.1 QuiesceRemap protocol

Implement deadline-bounded `PrepareRelocation`, `Quiesced`, `NewLease`, and
`Resume` messages.

Exit criterion:

- stale/late replies are generation rejected;
- no mapping or IRQ from the previous lease remains usable before address
  reassignment.

## M.2 First supported driver

Start with a disposable/non-storage device. NVMe is not the first live
relocation target.

Exit criterion:

- sustained workload survives repeated relocations with no data corruption,
  stale MMIO, IRQ leak, or client-visible false success.

---

# Stage N — IOMMU isolated profile

Status: **NOT STARTED**

## N.1 DMAR/IVRS discovery

Validate Intel DMAR and AMD IVRS topology, reserved regions, and requester IDs.

Exit criterion:

- unsupported/malformed firmware selects Trusted mode explicitly; it never
  creates a fake isolated domain.

## N.2 Per-device DMA domains

Bind DeviceLease to an IOMMU domain and map only lease-owned buffers.

Exit criterion:

- negative test DMA outside mapped buffers faults/is blocked;
- domain teardown completes before resource/BDF reuse;
- devices sharing an isolation group are treated as one trust unit.

## N.3 Interrupt remapping

Deferred unless required by the platform/profile. Status is visible separately
from DMA translation.

Exit criterion:

- HuesOS does not claim interrupt remapping merely because DMA translation is
  active.

---

# Stage O — Production qualification

Status: **BLOCKED ON A–N**

## O.1 CI matrix

Mandatory:

```text
QEMU Q35 ECAM debug/release SMP 1/2
forced legacy CF8/CFC common-subset run
nested bridge and multifunction synthetic topology
NVMe MSI-X/MSI/polling fallbacks
xHCI discovery and lease handoff
hot-add/orderly-remove/surprise-remove
resource exhaustion/no-space
manager/driver crash during each lifecycle stage
IOMMU isolated negative DMA (when emulation supports it)
```

## O.2 Long-haul and repetition gates

Minimum initial gates:

- 24-hour mixed NVMe/xHCI/PCI-manager workload;
- 1,000 add/remove cycles in QEMU;
- 1,000 DriverHost restart cycles;
- exhaustive policy fault injection for every rebalance operation;
- repeated suspend/resume only after PCI power management is in scope;
- zero unexplained lease/resource/IRQ/DMA leak;
- throughput regression comparison against committed machine-local baseline.

## O.3 Bare-metal matrix

Record exact commit, firmware, CPU/chipset, IOMMU state, root bridges, backend,
devices, interrupt modes, and workload.

Required before broad "modern PC" claim:

- at least two Intel platform generations;
- at least two AMD platform generations;
- at least three NVMe controller families;
- integrated xHCI on Intel and AMD;
- one real bridge/switch topology;
- one ECAM multi-root or multi-segment platform if available;
- one no-IOMMU compatibility run;
- one VT-d and one AMD-Vi isolated run;
- repeated cold/warm boots.

## O.4 Release blockers

PCI production-ready remains false while any of these are true:

- kernel boot/storage PCI policy is still required;
- config writes can originate outside PCI Manager;
- root apertures are guessed rather than firmware/controller declared;
- stale DeviceLease generations can create resources;
- an Online device has unverified BAR/bridge routing;
- trusted DMA is reported as isolated;
- hotplug/rebalance can publish partial topology;
- the system NVMe can be moved while mounted without a verified storage freeze
  and reconnect protocol;
- a mandatory CI or hardware matrix cell is skipped.

---

## 5. Immediate next PR sequence

The first implementation cascade after this documentation lands is:

```text
PCI-1  PciAddress / ConfigOffset / ConfigWidth / ConfigError
PCI-2  checked ECAM + CF8/CFC access planners and conformance vectors
PCI-3  MCFG parser/root-descriptor wire format
PCI-4  conventional + extended capability parsing hardening
PCI-5  bridge-aware immutable topology snapshots
PCI-6  firmware BAR/window validator
PCI-7  pure firmware-preserving allocator
```

No on-target configuration write is added before PCI-1 through PCI-3 are
host-tested. No kernel bootstrap code is removed before Stage J closes.

---

## 6. Progress ledger

| Track | Status | Evidence |
|---|---|---|
| A.1 Normative architecture | Complete | merged architecture document |
| A.2 ABI vocabulary | Complete (design) | architecture §§6, 12–14 |
| A.3 Migration map | Complete | architecture §2 + roadmap A.3 |
| B.1 Checked address vocabulary | Complete | PCI-1 types + PCI-2 bootstrap adoption |
| B.2 ECAM access planner | Complete (policy) | checked region-relative plans and boundary tests |
| B.3 Legacy access planner | Complete | common-subset plans; kernel shim migrated |
| C.1 MCFG decoding | In progress | policy parser complete; live ACPI handoff/QEMU open |
| C.2 Root descriptor ABI | In progress | bounded wire format complete; AML producer open |
| D.1 Topology snapshots | In progress | policy graph complete; live enumeration/publication open |
| D.2 Capability parsing | Complete (policy) | bounded conventional/extended decoders; NVMe bootstrap hardened |
| E.2 Firmware assignment validator | Complete (policy) | translated status report + overlap/forwarding checks |
| B.4, C.3, D.3, E.1, F–O | Not started | no production claim |

Update this table in every PCI stage PR. A track may be marked complete only
with its exit criterion and verification command/log named in the PR.
