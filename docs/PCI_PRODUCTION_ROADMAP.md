# HuesOS PCI/PCIe Production Roadmap

- **Status:** active roadmap; PCI production-ready = false
- **Target:** x86_64 UEFI/ACPI systems with PCI/PCIe, NVMe, xHCI, and
  future network and graphics DriverHosts
- **Architecture:**
  [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md) and
  [ACPI_RING3.md](ACPI_RING3.md)
- **Status overview:** [STATUS.md](STATUS.md)

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
- one userspace `pci-manager` is the only physical configuration executor;
- AML config reads are mediated through it and first-phase writes are denied;
- HMCF config windows and HPCI root resources are bound to one immutable ACPI
  snapshot and independently validated;
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
10. identify rollback behavior before mutating hardware;
11. bind ACPI/PCI payloads and capabilities to explicit process and firmware
    snapshot generations;
12. never add a raw physical/ECAM/CF8 grant as a temporary shortcut around the
    approved dynamic mint and mediation paths.

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
| **C** | Firmware/root-bridge discovery | Snapshot-bound HMCF + AML-produced HPCI reach PCI Manager |
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

Status: **DONE (AP-0, AP-22, AP-23)**

## A.1 Normative architecture

Deliver:

- `docs/PCI_MANAGER_ARCHITECTURE.md`;
- `docs/ACPI_RING3.md`;
- `docs/PCI_PRODUCTION_ROADMAP.md`;
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
FirmwareSnapshotId
ManagerGeneration
HmcfConfigWindow
PciConfigMint
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

Status: **DONE (PCI-1, PCI-2, AP-17)**

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

Status: **DONE (AP-1..AP-15, AP-18)**

## C.1 Archive v2 and HMCF config windows

Implementation status: PCI-3 lands the bounded MCFG parser and multi-segment
ECAM policy records. The live path still lacks archive-v2 RSDP publication,
HMCF ABI/producer, dynamic capability mint, and QEMU evidence.

`acpi-manager` exports validated MCFG entries as an immutable, pointer-free
HMCF snapshot through DriverManager. HMCF identifies config transports only;
it is not a root bridge or BAR-aperture description.

Required behavior:

- archive v2 includes validated RSDP and a complete physical-to-VMO index;
- checksum and SDT length already validated by the ACPI archive;
- MCFG reserved field zero;
- record count bounded;
- segment and bus ranges validated;
- physical config span checked against overflow;
- HMCF carries firmware snapshot and producer generations;
- DriverManager retains/forwards but does not semantically interpret HMCF;
- kernel dynamic mint independently cross-checks HMCF against archive MCFG;
- arbitrary, widened, stale, overlapping, RAM-aliasing, or overflowing ranges
  are rejected;
- initial ECAM capability is read-only, uncached, and NX;
- conflicts are reported per entry/domain.

Exit criterion:

- QEMU Q35 reports one accepted HMCF config domain and exact ECAM capability
  through the userspace bootstrap path;
- malformed synthetic MCFG/HMCF and stale mint inputs fail without kernel fault;
- no public device binding or config write occurs.

## C.2 Root bridge descriptors

Implementation status: PCI-3 lands the versioned bounded HPCI ABI for roots and
translated apertures. Archive-v2 startup, isolated full uACPI runtime,
mediated OperationRegions, namespace initialization, and the AML producer
remain open.

The separately built Ring-3 uACPI runtime resolves `_SEG`, `_BBN`, and `_CRS`
into immutable HPCI root descriptors. HPCI is bound to the same firmware
snapshot as HMCF. MCFG is not used as an MMIO/BAR aperture source.

Required tests:

- separate I/O, MMIO32, MMIO64, and prefetchable apertures;
- non-zero PCI-bus-to-CPU translation offsets and overflow rejection;
- multiple roots and segments;
- overlapping firmware apertures;
- absent optional methods;
- bus range outside HMCF;
- HMCF/HPCI snapshot-generation mismatch;
- bounded AML response sizes/timeouts;
- manager crash/restart and last-good snapshot freeze semantics.

Exit criterion:

- planner input contains explicit allocatable apertures for each root;
- Q35 root descriptors travel `acpi-manager → DriverManager → pci-manager`;
- incomplete roots may be visible diagnostically but remain unbound and receive
  no lease.

## C.3 Legacy routing and ownership

Export `_PRT` routing and `_OSC` native-control results.

Exit criterion:

- legacy interrupt availability and native hotplug/AER ownership are reported,
  never guessed.

---

# Stage D — Topology and capability enumeration

Status: **DONE (PCI-4, PCI-5, AP-16, AP-23)**

## D.1 Read-only userspace enumeration

Implementation status: PCI-5 lands the immutable generation-tagged topology
policy, including multi-segment roots, bridge parent resolution, deterministic
ordering, and malformed-graph rejection. Feeding it from live userspace config
reads and publishing the inventory remain open.

Build immutable topology snapshots without programming devices. Functions
seen before complete HPCI may be published only as
`FirmwareResourcesUnavailable`, read-only and unbound.

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

Implementation status: **complete in AP-23**. `pci-manager` encodes and
publishes an immutable read-only `HPIN` v1 inventory VMO
(`huesos_abi::pci_inventory`) retained by `driver-manager`, serving default TSV
`query:pci` (`pci | count`) and `query:pci:vmo` (`pci -v`, `--bars`, `--iommu`)
with zero PCI config-bus traffic.

Publish a read-only topology snapshot to DriverManager/component manager and
operator tooling.

Exit criterion:

- inventory clients generate no config-bus traffic;
- snapshot includes backend, generation, segment:BDF, topology path, IDs,
  capabilities, BAR values, and validation findings.

---

# Stage E — Firmware resource validation

Status: **DONE (PCI-6, AP-19)**

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

Status: **DONE (PCI-7, AP-19, AP-23)**

## F.1 Pure allocation model

Implementation status: **complete across PCI-7 and AP-23**. Deterministic
firmware-preserving allocation, bottom-up nested bridge window synthesis,
top-down window placement, fixed-resource preservation, and no-space refusal
are implemented and host-tested in `huesos-pci::resource_planner`.

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

Status: **DONE (PCI-8, AP-20)**

## G.1 Lease policy core

Implementation status: **complete (policy) in PCI-8**. Device identity,
generation, relocation class, DMA isolation mode, resource-mint/I/O gates, and
fail-closed lifecycle transitions are host-tested. Kernel object enforcement
remains G.2.

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

Status: **DONE (PCI-9, AP-9..AP-22)**

## H.1 Component bootstrap

Implementation status: PCI-9 lands the separately built BOOTFS service,
versioned binary hello/ready/heartbeat protocol, DriverManager supervision,
bounded restart backoff, and explicit no-root fail-closed readiness. HMCF/HPCI,
dynamic config mint, ACPI mediation, and root/config authority remain open.

DriverManager launches `pci-manager`, retains immutable firmware snapshots,
requests exact config capabilities with its unique snapshot-bound mint
authority, and transfers HMCF/HPCI plus capabilities to matching manager
generations. DriverManager does not map those capabilities or own PCI policy.

Exit criterion:

- a second process cannot acquire overlapping config authority;
- arbitrary physical ranges cannot be minted;
- HMCF/HPCI and capabilities reject stale manager/snapshot generations;
- manager crash is visible to the root supervisor;
- boot does not silently fall back without a status marker.

## H.2 Config backend execution

Wire policy plans to audited privileged boundaries in two sub-phases:

1. read-only AML/bootstrap and inventory:
   - snapshot-bound read-only uncached/NX ECAM mapping;
   - exclusive CF8/CFC dword access held only by `pci-manager`;
   - dedicated bounded ACPI→PCI read mediation;
   - every write denied and observed;
2. later B.4-approved mutation:
   - one serialized writer;
   - named write classes and expected readback masks;
   - rollback data and structured write/readback observations.

Exit criterion:

- QEMU ECAM and forced-legacy runs enumerate the same segment-0 common
  inventory;
- first-phase logs prove no config write occurred;
- no write path activates before B.4 exit criteria are met.

## H.3 Driver binding

Match manifests by class/vendor/device/subsystem/revision/capabilities and
launch one DriverHost per assigned device or approved group.

Exit criterion:

- unknown devices remain visible and unbound;
- no driver receives authority before lease and plan commit.

---

# Stage I — Interrupt and DMA resource handoff

Status: **DONE (AP-21)**

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

Status: **DONE (AP-22)**

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

Status: **COMPLETE (POLICY IN AP-23 + LIVE SCI/NOTIFY/HANDOFF RUNTIME IN AP-24; 1,000-CYCLE QMP SOAK TRACKED IN STAGE O)**

## K.1 Event ingestion

Consume ACPI/native hotplug events through a bounded queue and rescan only the
affected root/subtree.

Implemented in `AP-23`/`AP-24` (PRs #288, #293):
- `INIT_ACPI_SCI_IRQ_HANDLE = 10` binds the FADT SCI GSI to Ring-3
  `acpi-manager` (`SCI -> GPE -> Notify` bridge), forwarding 40-byte `HPHG` v1
  wire events (`crates/huesos-abi/src/pci_hotplug.rs`) over the private
  `pci-hotplug-events` channel into `pci-manager`'s `HotplugEventQueue`;
- `Syscall::PciHotplugTrigger = 98` + `/services/pci-hotplug-test.elf` exercise
  the live Ring-3 event path in `scripts/ci-qemu-smoke.sh`.

Exit criterion:

- event storms are coalesced/bounded;
- no enumeration occurs in IRQ callback context.

## K.2 Insertion without relocation

Use pre-reserved bus numbers/windows and allocate only the new subtree.

Implemented in `AP-24` (PR #293): generation-bound live `DriverHost` handoff,
rollback, restart cleanup, and kernel-owned `[76..92 MiB)` dynamic 4×4 MiB DMA
slots inside `BOOT_DMA_POOL_LEN = 92 MiB` (`crates/huesos-object/src/dma_pool.rs`).

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

Status: **DONE (POLICY + EXHAUSTIVE FAULT INJECTION IN AP-23)**

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

Status: **M.1 PROTOCOL COMPLETE (AP-23); M.2 LIVE DRIVER DEFERRED**

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

Status: **N.1, N.2 (Intel VT-d & AMD-Vi), & N.3 COMPLETE**

## N.1 DMAR/IVRS discovery

Validate Intel DMAR and AMD IVRS topology, reserved regions, and requester IDs.

Exit criterion:

- unsupported/malformed firmware selects Trusted mode explicitly; it never
  creates a fake isolated domain.

## N.2 Per-device DMA domains

Bind DeviceLease to an IOMMU domain and map only lease-owned buffers.

Implemented for both Intel VT-d (`DMAR`) and AMD-Vi (`IVRS`, [IOMMU_VTD.md](IOMMU_VTD.md)):
- pure `#![forbid(unsafe_code)]` codec/policy crate `crates/huesos-iommu`
  (VT-d 39-bit / 48-bit SLPTs + `RMRR` + `CM=1` + `FRCD`, AMD-Vi DTE + 4-level
  IO page tables + Command Buffer / Event Log + `IVMD`, per-lease `DomainTable`);
- Ring-0 backends `huesos_arch::x86_64::{vtd, amd_vi, iommu}` wired to
  `DeviceLease` (`Syscall::DeviceLeaseAttachDma = 96`,
  `Syscall::SystemIommuStatus = 97`, synchronous `revoke()`/`Drop` teardown
  before BDF or physical frame reuse);
- `acpi-manager` `HIOM` `active_mode=Isolated` gated on `SystemIommuStatus`,
  `pci-manager` `IommuDomain` binding, `driver-manager` `:dma:` grant binding,
  `net-service` `VIRTIO_F_ACCESS_PLATFORM` negotiation, and `pci --iommu`
  `IOMMU-KERNEL` telemetry;
- verified in CI by the 3-leg `scripts/ci-qemu-iommu-vtd-smoke.sh` (`intel-iommu`,
  `amd-iommu`, and no-IOMMU `Trusted` fallback).

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

## 5. Completed `AP-0..AP-24` bring-up cascade

`PCI-1` through `PCI-9`, the `AP-0..AP-24` Ring-3 ACPI → PCI Manager + live
hotplug implementation series, and `Stage N.2` Intel VT-d & AMD-Vi hardware DMA
isolation are implemented. The remaining open work before
`PCI production-ready = true` consists strictly of `Stage M.2` (first live
`QuiesceRemap` DriverHost), `Stage N.3` (interrupt remapping when required by a
platform profile), and `Stage O` (1,000-cycle QMP Root-Port hotplug soak,
24-hour mixed endurance, and multi-platform bare-metal qualification).

---

## 6. Progress ledger

| Track | Status | Evidence |
|---|---|---|
| A.1 Normative architecture | Complete | PCI + Ring-3 ACPI authority docs; AP execution plan |
| A.2 ABI vocabulary | Complete | `HPCI` v2, `HMCF`, `HIOM`, `HPIN`, `HPHG` v1, `pci_config`, `pci_mediation`, `pci_lease`, `pci_hotplug` ABIs + unit tests |
| A.3 Migration map | Complete | Kernel PCI scan removed (`tools/check-kernel-no-pci.py`, AP-22) |
| ACPI archive v2 | Complete | AP-1/AP-2 merged; Q35 v2 snapshot accepted in Ring 3 |
| Full Ring-3 uACPI | Complete | AP-3..AP-15 + AP-18 + AP-24 (`_SEG`, `_BBN`, `_CRS`, `_PRT`, `_OSC`, `_PIC(IOAPIC)`, `SCI -> GPE -> Notify`) |
| ACPI supervision | Complete | AP-6 restart/backoff/freeze + stale-snapshot drop (`HMCF`/`HPCI`/`HIOM`) |
| B.1–B.4 Config transport & write policy | Complete | ECAM + forced CF8/CFC + RO→RW ECAM upgrade + named write classes/readback (`AP-17`) |
| C.1–C.3 HMCF / HPCI / `_PRT` / `_OSC` | Complete | `AP-7`..`AP-15`, `AP-18` verified on QEMU Q35 ECAM & legacy |
| D.1–D.3 Topology, capabilities & `HPIN` VMO | Complete | `PCI-4`, `PCI-5`, `AP-16`, `AP-23` (`pci` + `pci -v` zero-bus-traffic VMO) |
| E.1–E.2 Live BAR sizing & validator | Complete | `PCI-6` + `AP-19` non-Online decode-disabled BAR sizing & restoration |
| F.1–F.3 Planner, rollback & hotplug reserves | Complete | `PCI-7`, `AP-19`, `AP-23` bottom-up bridge synthesis + `HotplugReservePolicy` |
| G.1–G.3 `DeviceLease` & `DeviceGone` | Complete | `PCI-8` + `AP-20` kernel `DeviceLease` revocation & `PORT_PACKET_DEVICE_GONE` |
| H.1–H.3 PCI Manager & driver binding | Complete | `AP-9`..`AP-22`, PRs #282/#283/#291 (`nvme-host`, `xhci-host`, `net-service`, `wlan-service`) |
| I.1–I.2 Interrupt transaction & DMA pools | Complete | `AP-21` + `AP-24` MSI-X/MSI/INTx programming + `DmaPoolGrant` (`BOOT_DMA_POOL_LEN = 92 MiB`) |
| J.1–J.3 NVMe migration & shim removal | Complete | `AP-22` (`1f83e29`); `tools/check-kernel-no-pci.py` CI gate |
| K.1–K.3 Reserved-space hotplug | Complete (policy + runtime SCI/Notify/handoff) | `huesos_pci::hotplug` 10,000-storm coalescing + 1,000-cycle suite (`AP-23`) + live `HPHG` v1 / dynamic DMA slots / syscall-98 smoke (`AP-24`, PR #293) |
| L.1–L.3 Restart rebalance & rollback | Complete (policy + fault injection) | `huesos_pci::rebalance` NVMe `Fixed` enforcement + 8-step rollback fault-injection suite (`AP-23`) |
| M.1–M.2 Live `QuiesceRemap` | M.1 protocol complete; M.2 deferred | `QuiesceRemapSession` deadline-bounded state machine + 1,000-cycle suite (`AP-23`) |
| N.1–N.3 IOMMU profile | Complete (Intel VT-d & AMD-Vi) | `huesos-iommu` + `vtd.rs`/`amd_vi.rs` per-lease IO page-table domains + 3-leg `scripts/ci-qemu-iommu-vtd-smoke.sh` (`intel-iommu` + `amd-iommu` + `Trusted` fallback) |
| O.1–O.4 Production qualification | Open | QEMU matrix (VT-d & AMD-Vi isolated DMA) green; multi-platform physical bare-metal matrix required |

Update this table in every PCI stage PR. A track may be marked complete only
with its exit criterion and verification command/log named in the PR.
