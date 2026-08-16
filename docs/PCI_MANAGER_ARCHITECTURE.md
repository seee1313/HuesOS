# HuesOS PCI/PCIe Manager Architecture

- **Status:** approved target architecture; implementation is incomplete
- **Audience:** kernel, platform, DriverManager, and DriverHost maintainers
- **Scope:** x86_64 PCI/PCIe discovery, configuration, resource ownership,
  DMA, interrupts, hotplug, and relocation

This document defines the target PCI/PCIe architecture for HuesOS. It is a
normative design document: implementation PRs may refine details, but they must
not silently change the trust boundaries, ownership model, or lifecycle
invariants described here.

The staged delivery plan and production exit criteria are tracked separately in
[PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md). The firmware/AML trust
boundary is normative in [ACPI_RING3.md](ACPI_RING3.md), and the shared
owner/agent PR sequence is maintained in
[ACPI_PCI_IMPLEMENTATION_PLAN.md](ACPI_PCI_IMPLEMENTATION_PLAN.md).

---

## 1. Executive summary

HuesOS uses one privileged **userspace PCI Manager** as the authority for PCI
configuration and topology policy. The kernel supplies protection mechanisms:
it maps narrowly authorized physical ranges, delivers interrupts, owns handle
rights, and will eventually enforce per-device DMA domains. Individual device
drivers run in separate userspace processes and receive only the resources of
one assigned device.

```text
kernel barebones ACPI → immutable archive v2
        │
        ▼
DriverManager (snapshot cache, generations, capability transport)
        │
        ├── acpi-manager
        │     ├── MCFG → HMCF config-window snapshot
        │     └── _SEG/_BBN/_CRS → HPCI root snapshot
        │
        ├── HMCF + unique mint authority → kernel cross-check
        │     └── exact ECAM/CF8 capabilities
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│ pci-manager (privileged userspace component)                 │
│                                                              │
│ config transports ─ topology ─ resource planner ─ lifecycle  │
│ ECAM / CF8-CFC      graph      BAR/windows       hotplug      │
└───────────────┬──────────────────────────┬───────────────────┘
                │ DeviceLease + resources  │ topology/events
                ▼                          ▼
       ┌─────────────────┐        DriverManager/component_manager
       │ DriverHost      │
       │ NVMe/xHCI/NIC…  │
       └───────┬─────────┘
               │ device-independent IPC service
               ▼
       block / USB / network clients

Kernel mechanisms:
  Process + Handle rights + Resource + Interrupt + VMO/VMAR
  snapshot-bound config mint + future DeviceLease/DmaDomain/IOMMU
```

The architecture intentionally combines lessons from several systems:

- QNX's central userspace PCI server and single-writer configuration policy;
- Genode's platform resource broker and per-device DMA protection domains;
- Barrelfish's userspace device management, capability grants, and pure
  resource-planning approach;
- Fuchsia's userspace PCI bus driver, driver-host isolation, BAR/IRQ/DMA
  handles, and protocol-mediated device access;
- seL4's capability and IOMMU mechanisms;
- Linux's mature PCI topology, resource, hotplug, and error-recovery model.

HuesOS does not copy any wire ABI from those systems.

---

## 2. Current state and migration boundary

The current production path is a bootstrap shim, not the target architecture:

- `huesos-kernel::boot::storage` scans all segment-0 BDFs through PCI
  Configuration Mechanism #1 (`0xCF8/0xCFC`).
- It identifies up to four NVMe functions, sizes BAR0, programs MSI-X/MSI,
  enables bus mastering, and serializes `StorageBootInfo` for init.
- Init mints `Mmio`, `Irq`, and `DmaPool` Resources from that descriptor.
- DriverManager launches `driver-host-nvme`, which is already a real ring-3
  hardware driver.
- `huesos-pci` currently parses a conventional 256-byte configuration image,
  BAR encodings, class codes, and MSI/MSI-X capabilities. It does not yet own
  on-target configuration access, root-bridge discovery, bridge topology,
  resource allocation, or hotplug.

The bootstrap shim remains in place until the userspace PCI Manager boots the
same NVMe service reliably. It must not be removed merely because an ECAM
parser compiles.

Migration is complete only when:

```text
pci-manager discovers/configures NVMe
→ DeviceLease/resources reach driver-host-nvme
→ the ordinary BlockDevice/Volume/Hxfs path is green
→ QEMU and bare-metal fallback tests are green
→ kernel boot/storage PCI scanning is deleted
```

---

## 3. Design goals

1. **Userspace policy, kernel enforcement.** Enumeration policy, driver
   binding, topology, BAR planning, and hotplug orchestration live in
   userspace. The kernel enforces capabilities, mappings, interrupts, process
   teardown, and DMA isolation where hardware permits it.
2. **One configuration executor.** Only `pci-manager` performs physical PCI
   configuration reads or writes. ACPI and DriverHosts use bounded mediated
   operations and never receive an ECAM window or CF8/CFC authority.
3. **Fine-grained driver authority.** A DriverHost receives only one device's
   approved MMIO/I/O ranges, interrupt handles, DMA domain/pool, and service
   channels.
4. **Identity is not BDF.** Segment:BDF is a mutable address. Device identity
   and lease generation remain safe across hotplug and bus-number changes.
5. **Firmware-preserving first.** Valid firmware assignments are claimed and
   verified before HuesOS attempts relocation.
6. **Planning before mutation.** Enumeration and resource allocation produce
   immutable plans. No hardware register is changed while a plan is still
   being calculated.
7. **Transactional relocation.** Reconfiguration either publishes a complete
   verified layout or restores the previous layout/fails the affected devices.
8. **No silent degradation.** Lack of ECAM, IOMMU, interrupt remapping, bridge
   aperture space, or relocation support is exposed explicitly in topology and
   operational records.
9. **Host-testable policy.** Address calculations, topology traversal,
   allocation, rebalance, and lifecycle state machines are safe `no_std` code
   tested without hardware.
10. **Bounded privileged work.** Config walks, capability traversal, retries,
    and hotplug queues have explicit limits and timeouts.

---

## 4. Non-goals of the first production profile

The following are not required for the first production PCI profile:

- PCI Express Advanced Error Reporting recovery beyond reporting and fail-stop;
- SR-IOV VF lifecycle and VF BAR allocation;
- Alternative Routing-ID Interpretation (ARI);
- PCIe peer-to-peer DMA;
- ATS, PRI, and PASID;
- CXL enumeration and HDM decoder configuration;
- live relocation of every driver;
- physical PCI/PCIe surprise hotplug on hardware that provides no ACPI/native
  hotplug indication;
- preserving a driver process after an unannounced device disappearance;
- arbitrary config-space writes by ordinary applications or DriverHosts.

These may be added append-only after the base authority and lifecycle model is
proven.

---

## 5. Trust model and authorities

### 5.1 Trusted computing base

The initial PCI TCB contains:

- the kernel's capability, mapping, dynamic config-mint, interrupt, and process
  teardown paths;
- barebones ACPI table validation and sealed archive construction;
- the isolated `acpi-manager` root-bridge descriptor producer;
- `pci-manager`;
- the component/root supervisor that retains immutable snapshots and launches
  both managers with generation-bound authority.

`acpi-manager` is in the firmware-policy TCB but outside the kernel
memory-safety TCB. It receives no raw physical-memory or PCI-config authority.
DriverManager is trusted to transport handles and enforce lifecycle ordering,
but it does not interpret HMCF/HPCI semantically or perform configuration
access.

Individual DriverHosts are outside the memory-safety TCB when an IOMMU domain
is active. Without an IOMMU, any bus-mastering driver remains part of the
machine-wide TCB because it can program its device to DMA outside the intended
pool.

### 5.2 Configuration authority

`pci-manager` is the sole holder of PCI configuration authority. The authority
is transport-specific but exposed to the manager through one internal
`ConfigAccess` abstraction.

Target grants are minted dynamically from immutable firmware data rather than
from caller-supplied physical ranges:

```text
DriverManager:
  unique PciConfigMint authority bound to firmware_snapshot_id
  may request and transfer exact config capabilities
  may not map or execute them

Initial ECAM root:
  read-only uncached/NX mapping exactly matching one accepted HMCF/MCFG window

Later write-capable ECAM root:
  separate authority upgrade after HPCI + B.4 write-policy gates

Legacy root:
  exact exclusive dword I/O authority for 0xCF8/0xCFC
  segment 0 only, conventional 256-byte space only
  transferred only to pci-manager
```

The mint syscall independently decodes HMCF and cross-checks it against MCFG in
the bound sealed ACPI archive. Unknown, widened, stale, overflowing, overlapping,
or RAM-aliasing records fail closed. HPCI alone never mints config authority.

A future kernel `PciConfig` execution object may replace direct ECAM/port grants
only through a separately approved architecture change if audit evidence shows
that mediation materially reduces risk. The userspace ownership rule does not
depend on the physical transport mechanism.

### 5.3 ACPI-facing mediation

Full Ring-3 uACPI may require PCI Config OperationRegion access while loading or
initializing the namespace. `acpi-manager` does not receive ECAM/CF8 authority
and does not use the kernel ACPI broker for PCI.

DriverManager connects it to `pci-manager` through a private, versioned channel.
The first phase supports bounded reads only and carries both manager
generations, `firmware_snapshot_id`, segment:BDF, offset, width, and correlation
ID. `pci-manager` performs the physical read. Every write is rejected and
observed until B.4 lands.

The existing append-only ACPI broker opcode numbers `PciRead` and `PciWrite`
remain reserved but permanently hard-denied; no kernel backend or PCI grant is
implemented for them.

### 5.4 Driver-facing mediation

Drivers do not receive raw configuration authority. They use a per-device IPC
protocol offered by `pci-manager`, with operations such as:

```text
GetDeviceInfo
GetBar
AllocateInterrupts
SetBusMastering
ResetFunction
ReadCapability
ReadConfigRange
WriteConfigRange (manifest/policy allowlisted)
PrepareRelocation / Quiesced / Resume
```

Standard operations are strongly typed. Vendor-specific config access is
bounded to explicit ranges and widths in the driver manifest or device policy;
the manager remains the process that performs the physical write.

---

## 6. Addressing and identity

### 6.1 PCI address

```rust
struct PciAddress {
    segment:  u16,
    bus:      u8,
    device:   u8, // 0..31
    function: u8, // 0..7 in the base profile
}
```

`PciAddress` names the function's current routing address. It is not a stable
identity and must never be used as the sole key for stale-handle protection.

### 6.2 Stable presence identity

```text
DeviceId      = unique kernel/object identity for one observed presence
Generation    = monotonically increasing lease generation
PciAddress    = current mutable segment:BDF
TopologyPath  = root bridge / downstream ports / slot
```

A device that disappears and later returns receives a new presence identity or
new generation even if it reuses the same BDF. Old handles cannot gain access
to the replacement.

### 6.3 DeviceLease

`DeviceLease` is the revocable authority that binds one device presence to one
driver instance.

Conceptual fields:

```rust
struct DeviceLease {
    koid:          Koid,
    device_id:     DeviceId,
    generation:    u64,
    address:       PciAddress,
    state:         LeaseState,
    relocation:    RelocationClass,
    dma_isolation: DmaIsolation,
}
```

A lease is minted only from parent authorities for the relevant root bridge.
The kernel validates that every child range is contained in a parent aperture
and that exclusive ranges do not overlap; `pci-manager` cannot invent a
physical range by placing it in a plan. This requires the parent/child resource
split mechanism already anticipated by the component-framework architecture.

Child grants derive from a live lease:

- BAR `Mmio`/`IoPort` handles;
- `Interrupt` handles;
- DMA domain/pool handles;
- reset/power/config RPC endpoint;
- driver-service bootstrap channels.

A lease is not interchangeable with today's immutable `Resource`. Existing
Resources validate creation-time authority but do not revoke objects already
created through them. Restart-based relocation can initially revoke by killing
the DriverHost and relying on process teardown. Live relocation requires
lease-aware mappings and IRQ bindings that reject stale generations.

---

## 7. Configuration transports

### 7.1 Common interface

The PCI policy core consumes a transport-independent interface:

```rust
trait ConfigAccess {
    fn read8(address, offset)  -> Result<u8, ConfigError>;
    fn read16(address, offset) -> Result<u16, ConfigError>;
    fn read32(address, offset) -> Result<u32, ConfigError>;
    fn write8(address, offset, value)  -> Result<(), ConfigError>;
    fn write16(address, offset, value) -> Result<(), ConfigError>;
    fn write32(address, offset, value) -> Result<(), ConfigError>;
    fn max_offset(address) -> u16;
}
```

Production code may use a different Rust shape, but these semantics are
normative:

- widths are 1, 2, or 4 bytes;
- accesses cannot cross their natural width boundary;
- offsets are checked before arithmetic;
- a missing function returns `NotPresent`, not all-ones data disguised as a
  valid response;
- physical access failures are distinct from malformed topology;
- writes are serialized by `pci-manager`;
- all write classes are observable.

### 7.2 ECAM backend

MCFG supplies one or more enhanced configuration windows. `acpi-manager`
publishes their validated pointer-free representation as a bounded HMCF
snapshot. HMCF is transported and retained by DriverManager, independently
validated by `pci-manager`, and cross-checked by the kernel before any exact
mapping capability is minted. HMCF does not describe allocatable BAR apertures.

Address calculation uses checked arithmetic:

```text
ecam = base
     + ((bus - start_bus) << 20)
     + (device << 15)
     + (function << 12)
     + offset
```

Validation requirements:

- `start_bus <= end_bus`;
- bus lies inside exactly one applicable segment window;
- physical `base + span` does not overflow;
- windows do not overlap inconsistently;
- HMCF snapshot and manager generations match the bound archive/mint request;
- kernel cross-check finds an exact canonical MCFG record, never a userspace
  physical-range assertion;
- the initial region is mapped read-only, uncached, and NX;
- offset is within `[0, 4096)`;
- firmware-reserved and RAM ranges cannot alias the ECAM mapping;
- malformed MCFG/HMCF disables only the affected config domain and emits an
  observation record.

### 7.3 Legacy CF8/CFC backend

The legacy backend supports only:

```text
segment = 0
bus 0..255
device 0..31
function 0..7
offset 0..255
```

All accesses use aligned dword cycles internally. Sub-dword writes are
read-modify-write operations performed by the sole manager. CF8/CFC is a global
address/data pair, so no other process may hold overlapping I/O authority.

ECAM and CF8/CFC are equal on the common subset. ECAM additionally supports
multiple segments and PCIe extended configuration space. The public inventory
records which backend and feature level served each root bridge.

---

## 8. Firmware and root bridges

MCFG identifies ECAM windows but does not define allocatable MMIO/I/O apertures.
Production resource allocation also needs ACPI host-bridge information:

- `_SEG` — segment group;
- `_BBN` — base bus number where supplied;
- `_CRS` — bus-number, I/O, non-prefetchable memory, and prefetchable memory
  apertures;
- `_PRT` — legacy INTx routing;
- `_OSC` — native PCIe control negotiation;
- hotplug notifications and slot metadata where firmware exposes them.

The ACPI service publishes immutable, validated `PciRootBridgeDescriptor`
(HPCI) records through DriverManager. HPCI is generation-bound to the same
`firmware_snapshot_id` as HMCF. DriverManager validates only the envelope and
retains a last-good read-only VMO; `pci-manager` independently validates record
semantics and HMCF/HPCI segment/bus consistency.

`pci-manager` does not evaluate arbitrary AML while holding the configuration
transaction lock. ACPI requests required by hotplug are issued as bounded
asynchronous operations outside the planner. An ACPI manager crash retains the
last-good static snapshots for existing devices but freezes new leases,
binding, hotplug, rebalance, BDF reuse, and topology-generation advancement
until restart and revalidation.

A root descriptor includes at least:

```text
root_id
segment
bus_start / bus_end
config_backend
ECAM physical window (if any)
I/O aperture(s), each with PCI-bus base, CPU base/translation, and length
MMIO32 aperture(s), each with PCI-bus base, CPU physical base, and length
MMIO64/prefetchable aperture(s) with the same translation metadata
legacy routing reference
native-control flags
hotplug capability flags
```

---

## 9. Enumeration and topology

Enumeration builds a generation-tagged immutable snapshot. It is separate from
resource mutation and driver launch.

Required behavior:

- enumerate every validated root bridge and segment;
- function 0 controls conventional multifunction probing;
- decode Type 0 endpoints and Type 1 PCI-to-PCI bridges;
- follow secondary/subordinate bus ranges without global flat scanning;
- bound recursion depth, node count, and config reads;
- reject bridge loops, duplicate addresses, invalid bus ranges, and malformed
  capability chains;
- parse conventional capabilities and PCIe extended capabilities when ECAM is
  available;
- retain unknown devices and unknown capabilities in the inventory rather than
  dropping them;
- a function observed through HMCF before complete HPCI may appear only with
  `FirmwareResourcesUnavailable`; it is read-only, unbound, and receives no
  lease;
- publish a deterministic topology ordering;
- record config backend, ACPI/PCI manager generations, and firmware snapshot
  generation.

Only a snapshot rooted in accepted HPCI is a source for driver matching and
planning. A hotplug event
creates a new snapshot; it never mutates a graph while clients iterate it.

---

## 10. Resource model

The resource planner handles distinct address classes:

```text
Bus numbers
I/O port space
32-bit non-prefetchable MMIO
64-bit non-prefetchable MMIO
64-bit prefetchable MMIO
Expansion ROM space (disabled by default)
```

Each BAR requirement records:

- size and alignment;
- I/O vs memory;
- 32-bit vs 64-bit constraints;
- prefetchability;
- fixed/firmware assignment;
- resizable-BAR capabilities when available;
- owning function and parent bridge path.

Bridge windows must contain all matching child windows and BARs. The planner
computes size requirements bottom-up and assigns windows/addresses top-down.
Sibling ranges never overlap and every assignment stays inside the root
bridge's ACPI aperture.

BARs and bridge windows contain PCI bus addresses. Driver MMIO Resources name
CPU physical addresses. Each root aperture therefore carries an explicit
PCI-bus-to-CPU translation; the planner validates in bus space and the lease
materializer translates with checked arithmetic. HuesOS must not assume an
identity translation merely because that is common on x86 PCs.

### 10.1 Firmware-preserving policy

The first strategy is conservative:

1. Validate firmware BARs and bridge windows.
2. Claim non-conflicting valid assignments.
3. Mark invalid, overlapping, unrouteable, or out-of-aperture assignments.
4. Allocate only unassigned/invalid resources from known free apertures.
5. Prefer leaving working devices untouched.
6. Preserve spare bus numbers and bridge-window capacity for hotplug.

The planner must never invent an MMIO aperture from a convenient-looking gap in
physical address space. It uses firmware/root-controller declarations.

### 10.2 Planning output

A plan is immutable and complete:

```text
input topology generation
input lease generations
new BAR values
new bridge bus numbers/windows
config write set with old and new values
quiesce/restart set
fixed devices that constrain the plan
resource handles to mint after commit
rollback write set
expected readback masks
```

No hardware writes occur if any required device cannot fit or any affected
lease cannot satisfy its relocation policy.

---

## 11. Interrupt model

Preference order:

```text
MSI-X → MSI → legacy INTx → polling only when driver policy permits it
```

`pci-manager` owns capability discovery and config-space programming. The
kernel owns interrupt-vector allocation and delivery objects. Drivers receive
only the resulting Interrupt/Port handles.

Rules:

- MSI/MSI-X table and capability bounds are validated against the owning BAR;
- entries are masked before programming and read back before publication;
- bus mastering and INTx disable are changed only as part of a device
  activation transaction;
- shared legacy INTx is brokered and acknowledged explicitly;
- lease revocation masks MSI/MSI-X and disconnects IRQ delivery before driver
  teardown completes;
- x2APIC destinations that cannot be represented without interrupt remapping
  are rejected rather than truncated;
- interrupt-remapping support is a later security enhancement, not silently
  assumed.

---

## 12. DMA and IOMMU model

### 12.1 Compatibility mode

```text
DmaIsolation::Trusted
```

On systems without an active IOMMU, the driver receives a bounded DMA pool, but
that pool is not an enforcement boundary. Any process able to control a
bus-mastering device is trusted with all physical memory. Logs, system status,
and security documentation must say so explicitly.

### 12.2 Isolated mode

```text
DmaIsolation::IommuDomain(domain_id)
```

Each lease owns a per-device DMA address space. The driver requests DMA buffers
through the lease; the kernel/IOMMU maps only those buffers. Revocation:

1. manager asks the driver to quiesce;
2. manager clears bus mastering;
3. outstanding commands are drained or timed out;
4. IOMMU mappings are removed;
5. DMA buffers are released;
6. lease generation is invalidated.

The driver-facing DMA API should not require different code for trusted and
IOMMU modes. It receives device-visible addresses from one allocator and never
assumes `DMA address == physical address`.

Production compatibility may permit trusted mode for signed built-in drivers.
A claim of malicious-driver isolation requires IOMMU mode.

---

## 13. Driver binding and relocation classes

Driver manifests match on:

- PCI class/subclass/programming interface;
- vendor/device and subsystem IDs;
- revision range where required;
- required capabilities;
- optional topology/slot constraints.

Each driver declares one relocation class:

```text
Fixed
  The device cannot move while the driver is active.

Restart
  Stop the DriverHost, revoke the old lease, move resources, and start a new
  DriverHost with a new generation.

QuiesceRemap
  The running DriverHost implements PrepareRelocation/Resume and can replace
  its mappings and interrupt handles without process restart.
```

Unknown and legacy drivers default to `Fixed`, never `QuiesceRemap`.

The mounted system NVMe device starts as `Fixed`. It may become restartable only
after storage service reconnection, in-flight I/O cancellation, filesystem
freeze, and recovery behavior have dedicated end-to-end tests.

---

## 14. Hotplug lifecycle

Lease/device states:

```text
Discovered
Unconfigured
Configured
DriverStarting
Online
Quiescing
Rebalancing
Removing
Removed
Failed
```

All transitions are generation checked and journaled in the observation ring.

### 14.1 Insertion

1. Receive ACPI/native hotplug event.
2. Debounce and snapshot the affected root/subtree.
3. Discover the new function/bridge without binding a driver.
4. Attempt allocation inside pre-reserved bus numbers/windows.
5. If that fails, calculate a restart/live relocation plan.
6. Apply the plan transactionally.
7. Mint a new DeviceLease and narrow resources.
8. Launch the matching DriverHost.
9. Publish the device/service only after driver readiness.

### 14.2 Orderly removal

1. Mark lease `Removing`; reject new client opens.
2. Ask services and driver to quiesce with a bounded deadline.
3. Stop bus mastering and mask interrupts.
4. Revoke resources and terminate/restart the driver as policy requires.
5. Remove topology nodes and free planner resources.
6. Notify clients with `DeviceGone`.

### 14.3 Surprise removal

The first production policy is fail-stop:

- IRQ delivery is masked/disconnected;
- the DriverHost is terminated;
- process teardown removes mappings and handles;
- the lease generation is revoked;
- outstanding clients receive `DeviceGone`;
- no attempt is made to preserve the old driver process;
- the topology is rescanned before BDF/resource reuse.

---

## 15. Rebalance transactions

Full rebalance is a target capability, delivered in stages. The normal path
uses firmware assignments and reserved hotplug capacity. Rebalance is a
fallback, not a routine boot operation.

### 15.1 Plan phase

- take topology and lease-generation snapshots;
- calculate all resource moves without hardware writes;
- classify fixed, restartable, and live-relocatable devices;
- reject plans that move fixed resources;
- compute bridge windows bottom-up and addresses top-down;
- include bus-number changes and their identity consequences;
- produce exact forward, readback, and rollback write sets.

### 15.2 Prepare phase

- prevent new driver/client binding in the affected subtree;
- quiesce or stop every affected driver;
- wait for bounded I/O drain;
- mask interrupts;
- clear bus mastering and decode bits;
- revoke old DeviceLease generations before old MMIO can be reassigned.

### 15.3 Apply phase

- program bus numbers/windows in dependency-safe order;
- program endpoint BARs;
- program MSI/MSI-X state only after BAR placement;
- read back every writable field with architecturally read-only bits masked;
- keep devices disabled until the complete topology verifies.

### 15.4 Commit phase

- publish the new topology generation atomically;
- mint new lease generations and resource handles;
- restart/resume drivers;
- publish services after readiness;
- release the old resource-plan snapshot.

### 15.5 Failure and rollback

If any write/readback fails:

- apply the complete rollback set where hardware remains accessible;
- verify the restored layout;
- restore old lease generations only if their resources are exactly restored;
- otherwise mark affected devices `Failed`, terminate drivers, and report
  `DeviceGone`;
- never leave a partially moved device `Online`.

Every plan and operation index must be reproducible in a synthetic topology
test. Fault injection stops before every write/ack/timeout boundary and permits
only the complete old or complete new topology.

---

## 16. Driver/service protocol boundary

PCI services are management-plane IPC and are not placed in the I/O data path.
After setup, an NVMe request travels directly through the NVMe DriverHost's
queues and BlockDevice protocol; it does not call `pci-manager` per command.

The manager-to-driver bootstrap transfers:

```text
DeviceLease handle + generation
immutable device identity/config summary
BAR handles
Interrupt handles or allocation endpoint
DMA allocator/domain endpoint
reset/config-management endpoint
lifecycle channel
```

Driver readiness includes proof that required BARs mapped, interrupts bound,
DMA mode accepted, and the hardware reached an operational state.

---

## 17. Concurrency and lock rules

- `pci-manager` serializes config writes per root bridge; legacy CF8/CFC is
  globally serialized.
- topology snapshots are immutable and generation tagged;
- no config or topology lock is held while waiting for a DriverHost response;
- no manager lock is held across ACPI IPC;
- AML PCI requests carry both process generations and a snapshot ID; stale
  requests/replies are rejected;
- DriverManager never replaces a last-good HMCF/HPCI snapshot implicitly after
  ACPI restart;
- while ACPI is unavailable, existing non-ACPI-dependent operations may
  continue but new lifecycle/topology work remains frozen;
- rebalance uses explicit transaction state, not lock ownership, to span
  asynchronous quiesce/resume operations;
- IRQ/hotplug callbacks enqueue bounded events and do not perform enumeration
  inline;
- stale replies carrying an old transaction or lease generation are ignored;
- all waits have a deadline and a recorded failure code.

---

## 18. Observability and operations

Required structured records include:

```text
ACPI archive/snapshot generation accepted/rejected
HMCF accepted/rejected
config capability mint accepted/rejected
ACPI mediated config read/denied write/timeout
ACPI manager crash/restart/frozen-snapshot state
root bridge accepted/rejected
config backend selected
function discovered/removed
malformed capability/topology rejection
firmware resource conflict
allocation plan accepted/rejected
lease mint/revoke/generation
interrupt mode and vector count
DMA isolation mode
hotplug event and debounce outcome
rebalance begin/prepare/apply/commit/rollback/fail
config read/write timeout/readback mismatch
driver quiesce/restart timeout
```

A topology snapshot and resource plan must be exportable in deterministic text
or JSON form so field failures can be reproduced in host tests.

---

## 19. Security invariants

The following are release-blocking invariants:

1. Only `pci-manager` can execute PCI configuration reads or writes; the first
   AML mediation phase permits reads only.
2. Dynamic ECAM/CF8 minting accepts no naked physical range and succeeds only
   after HMCF matches MCFG in the bound immutable ACPI snapshot.
3. `acpi-manager` and the kernel ACPI broker never receive ECAM/CF8 authority;
   legacy ACPI broker PCI opcodes remain hard-denied.
4. A DriverHost cannot map another device's BAR.
5. Numeric overlap checks are atomic and use half-open checked ranges.
6. BDF reuse cannot revive an old handle or lease.
7. No BAR/window lies outside a declared root aperture.
8. No two live exclusive resources overlap.
9. No device is marked Online before BAR/IRQ/DMA setup and readback succeed.
10. Bus mastering is off while resources are moved or revoked.
11. Old MMIO/IRQ/DMA authority is invalid before an address is reassigned.
12. Surprise removal cannot leave a driver serving successful I/O.
13. Trusted DMA mode is never represented as IOMMU isolation.
14. Config, capability, and topology walks are bounded on malformed hardware.
15. A failed rebalance publishes neither a partial topology nor partially
    restored leases.
16. The boot NVMe shim and `pci-manager` never configure the same live function
    concurrently during migration.

---

## 20. Verification strategy

### Host tests

- archive-v2 RSDP/SDT/physical-translation completeness and overflow rejection;
- MCFG/HMCF/root descriptor validation and overlap rejection;
- snapshot-bound config mint rejection for stale, widened, unknown, and
  RAM-aliasing records;
- ACPI mediated config reads and unconditional first-phase write denial;
- ECAM/legacy access planning and overflow/alignment boundaries;
- conventional and extended capability cycles/truncation;
- bridge topology loops, duplicate BDFs, depth/node limits;
- BAR sizing/typing including 64-bit pairs and malformed masks;
- root aperture and bridge-window allocation;
- fixed/restart/live relocation constraints;
- deterministic plan generation;
- DeviceLease state/generation transitions;
- exhaustive rebalance fault injection and rollback;
- hotplug insertion/removal event ordering;
- stale generation and BDF-reuse rejection.

### QEMU tests

- Q35/OVMF archive-v2, HMCF, dynamic ECAM mint, and HPCI bootstrap markers;
- full Ring-3 namespace load before public PCI inventory;
- mediated AML config reads with all first-phase writes denied;
- ACPI manager crash/restart with last-good snapshot freeze semantics;
- Q35/OVMF ECAM enumeration;
- forced legacy backend on segment 0;
- multifunction and nested bridge synthetic topologies;
- MSI-X, MSI, legacy INTx, and polling fallbacks;
- NVMe/xHCI discovery through `pci-manager`;
- device add/remove through QEMU monitor;
- insufficient-window allocation failure;
- DriverHost crash during quiesce/restart;
- IOMMU-enabled negative DMA tests when VT-d emulation is available.

### Bare-metal tests

At minimum:

- Intel and AMD systems;
- multiple NVMe controller vendors;
- integrated and discrete xHCI;
- a real downstream bridge/switch where available;
- ECAM and legacy common-subset comparison;
- cold/warm boot and repeated driver restart;
- IOMMU present/absent status validation;
- hotplug-capable platform if available.

No test may claim a path it skipped. Logs include backend, segment, topology
generation, lease generation, interrupt mode, and DMA isolation mode.

---

## 21. Prior-art references

These references informed the architecture; HuesOS remains independently
specified.

- Fuchsia PCI protocol:
  <https://fuchsia.dev/reference/fidl/fuchsia.hardware.pci>
- Fuchsia PCI hardware-resource tutorial:
  <https://fuchsia.dev/fuchsia-src/development/drivers/tutorials/sdk_build_driver/hardware-resources>
- Fuchsia uPCI legacy-interrupt RFC:
  <https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0070_pci_protocol_legacy_interrupt_changes>
- QNX 8 PCI Server overview:
  <https://www.qnx.com/developers/docs/8.0/com.qnx.doc.pci_server/topic/overview.html>
- Genode platform-driver / PCI decode design:
  <https://genode.org/documentation/release-notes/22.05>
- Genode IOMMU/device-PD design:
  <https://genode.org/documentation/genode-foundations/25.05/under_the_hood/Execution_on_the_NOVA_microhypervisor_(base-nova).html>
- Barrelfish architecture overview, SKB/Kaluga/device capabilities:
  <https://barrelfish.org/publications/TN-000-Overview.pdf>
- Barrelfish ACPI root publication and PCI-domain bootstrap:
  <https://barrelfish.org/publications/TN-019-DeviceDriver.pdf>
- uACPI host API and userspace-runtime examples:
  <https://uacpi.github.io/>
- ACPI PCI host-bridge requirements:
  <https://docs.kernel.org/PCI/acpi-info.html>
- seL4 capDL hardware capability model:
  <https://docs.sel4.systems/projects/capdl/lang-spec.html>
- Linux PCI API documentation:
  <https://docs.kernel.org/driver-api/pci/pci.html>
- Linux movable-BAR/hotplug design discussion:
  <https://patchwork.ozlabs.org/project/linux-pci/cover/20201218174011.340514-1-s.miroshnichenko@yadro.com/>
- Redox userspace PCI daemon (`pcid`):
  <https://github.com/redox-os/drivers/tree/master/pcid>

---

## 22. Architecture decisions fixed by this document

- PCI enumeration and binding policy belongs to a privileged userspace
  `pci-manager`.
- Only `pci-manager` executes configuration-space reads or writes; ACPI and
  drivers use mediated protocols.
- HMCF config windows and HPCI root resources are separate immutable ABIs bound
  to one firmware snapshot.
- DriverManager retains snapshots and generations but owns no AML or PCI
  policy.
- ECAM/CF8 capabilities are minted dynamically only after kernel cross-check of
  HMCF against MCFG in the bound sealed archive.
- The first AML PCI phase permits mediated reads only; writes fail closed.
- Legacy ACPI broker PCI opcodes remain reserved and permanently hard-denied.
- ACPI manager failure retains last-good snapshots for existing devices while
  freezing new PCI lifecycle operations until revalidation.
- Individual DriverHosts receive narrow device resources and mediated control
  operations, not ECAM/CF8 authority.
- ECAM and CF8/CFC are equal on their common segment-0 conventional-config
  subset; ECAM exposes additional segments and extended config.
- PCI v1 is multi-root, multi-segment, bridge-aware, and hotplug-ready.
- Orderly removal is supported; surprise removal is fail-stop.
- Valid firmware assignments are preserved first.
- Full rebalance remains a production target but is staged after reserved-space
  hotplug and restart-based relocation.
- Drivers explicitly declare `Fixed`, `Restart`, or `QuiesceRemap` relocation.
- The boot/system NVMe device is initially fixed.
- Device identity is generation-safe and distinct from BDF.
- IOMMU is optional for compatibility but mandatory for a claim of malicious
  DMA isolation.
- The kernel never parses driver manifests or owns PCI driver-selection policy.
