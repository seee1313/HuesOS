# Ring-3 ACPI architecture

- **Status:** approved target architecture; full AML runtime is not implemented
- **Audience:** kernel, ACPI, PCI, DriverManager, and platform maintainers
- **Scope:** x86_64 ACPI table ownership, AML execution, OperationRegions,
  PCI-root discovery, supervision, and failure containment

This document is normative. It defines the ACPI trust boundary and its
interaction with the userspace PCI Manager. The PCI ownership model is defined
in [PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md); the ordered
implementation PRs are defined in
[ACPI_PCI_IMPLEMENTATION_PLAN.md](ACPI_PCI_IMPLEMENTATION_PLAN.md).

Implementation may refine data structures, but it must not silently change the
authorities, boot ordering, or failure policy below.

---

## 1. Trust split

HuesOS does not execute firmware AML in the kernel. The final architecture is
split into four authorities:

1. **Kernel bootstrap** — barebones uACPI table discovery and MADT consumption
   needed to initialize APIC/SMP; immutable snapshot construction; capability
   enforcement.
2. **`acpi-manager` in Ring 3** — full uACPI namespace loading, AML execution,
   `_INI`, `_STA`, `_CRS`, `_PRT`, notifications, and power methods.
3. **ACPI capability broker** — exact-width SystemIO, approved SystemMemory,
   interrupt, reset, and power operations requested by `acpi-manager`.
4. **`pci-manager` in Ring 3** — the sole PCI configuration authority and the
   only component that executes PCI configuration reads or writes.

`DriverManager` supervises and connects these components. It retains immutable
snapshot handles and transfers capabilities, but it does not interpret AML,
select config addresses, enumerate PCI, allocate BARs, or perform hardware I/O.

AML is firmware-controlled input and is outside the kernel memory-safety TCB.
A malformed namespace may terminate `acpi-manager`, but it must not give that
process arbitrary physical-memory, port-I/O, PCI-config, or interrupt authority.

### 1.1 Authority matrix

| Operation | Kernel | DriverManager | `acpi-manager` | ACPI broker | `pci-manager` |
|---|---:|---:|---:|---:|---:|
| Early RSDP/SDT/MADT bootstrap | owns | no | no | no | no |
| Retain canonical ACPI snapshot | mechanism | coordinates | read-only copy | no | no |
| Execute AML | no | no | owns | no | no |
| Exact SystemIO/SystemMemory | enforces | no | requests | executes | no |
| PCI config read/write | protects grants | no | requests reads | **never** | executes |
| Interpret MCFG / publish HMCF | cross-checks mint input | transports | produces | no | validates/consumes |
| Interpret `_SEG`/`_BBN`/`_CRS` | no | transports | produces HPCI | no | validates/consumes |
| Mint ECAM/CF8 authority | dynamic syscall | holds unique mint authority | no | no | receives result |
| Driver binding/BAR policy | no | launches on approved event | no | no | owns |

No component gains authority merely by supplying an integer physical address.

---

## 2. Target data and control flow

```text
kernel barebones uACPI
  └─ ACPI archive v2 (RSDP + SDTs + physical→VMO translation)
          │ read-only duplicate + ACPI broker
          ▼
     DriverManager
          │
          ├─ launch/supervise acpi-manager
          │      ├─ static MCFG validation → HMCF snapshot
          │      ├─ full uACPI namespace/AML
          │      └─ _SEG/_BBN/_CRS → HPCI root snapshot
          │
          ├─ HMCF + unique mint authority → kernel validation syscall
          │      └─ exact ECAM/CF8 capabilities
          │
          └─ snapshots + config capabilities → pci-manager
                  ├─ mediated AML config reads
                  ├─ HMCF/HPCI consistency validation
                  └─ read-only/unbound inventory until roots are complete
```

HMCF and HPCI are different contracts:

- **HMCF** describes validated configuration transports: ECAM physical base,
  segment, and bus range. It does not claim that any BAR aperture is
  allocatable.
- **HPCI** describes ACPI PCI host bridges and their bus, I/O, MMIO,
  translation, routing, native-control, and hotplug properties.

An MCFG allocation must never be reinterpreted as a root `_CRS` aperture.

---

## 3. Immutable ACPI archive v2

The kernel exports one sealed read-only VMO containing an atomic firmware table
snapshot. Version 2 adds the RSDP and enough translation metadata for full
userspace uACPI startup.

The archive contains:

```text
versioned header
RSDP descriptor: original physical address, VMO offset, length, revision
bounded table-entry array
copied RSDP bytes
copied SDT/FACS/DSDT bytes installed by barebones uACPI
original-physical-range → archive-offset translation records
```

Required invariants:

- RSDP v1/v2 checksums, revision, and exact 20/36-byte length are validated;
- SDT signature, declared length, checksum status, revision, and uACPI metadata
  agree before publication;
- all offset, length, count, physical-end, and aggregate-size calculations use
  checked arithmetic;
- archive ranges do not overlap metadata or each other;
- physical translation ranges are complete for every accepted physical-backed
  object;
- a capacity limit is a visible archive-construction error, never silent index
  truncation;
- duplicate SDT signatures use monotonically increasing instance numbers;
- consumers receive `READ | DUPLICATE | TRANSFER`, never write authority;
- a `firmware_snapshot_id` binds derived HMCF/HPCI data and dynamic capability
  mint requests to this exact archive generation.

The current v1 mismatch between `MAX_TABLES = 4096` and a 64-entry physical
index must not be carried into v2. If the bounded v2 translation index cannot
represent every accepted physical range, archive creation fails closed.

### 3.1 Table mapping is not hardware mapping

The full userspace runtime maps the archive VMO once as non-writable data.
`uacpi_kernel_map(original_physical, length)` performs only:

```text
validate request against one archive translation record
→ translate to archive VMO offset
→ return a pointer into the read-only archive mapping
```

It never maps arbitrary machine physical memory. `uacpi_kernel_unmap` releases
only runtime bookkeeping; it cannot change physical mappings outside the
archive.

AML `SystemMemory OperationRegion` access is a separate privileged operation
and must not be smuggled through this table-map callback.

---

## 4. OperationRegion mediation

### 4.1 SystemIO and SystemMemory

SystemIO and approved SystemMemory requests go through the ACPI broker. The
request structure is validated before policy lookup:

- exact protocol version and known opcode;
- zero reserved fields;
- width from the supported exact-width set;
- natural alignment and checked end address;
- no value bits outside the write width;
- zero write value on reads;
- operation-specific capability and direction checks.

The first non-empty SystemIO policy remains the bounded fixed FADT policy: SMI
command, PM1 event/control, PM2 control, PM timer, and GPE blocks. PM timer is
read-only. Reset and power-off remain separate capabilities.

General AML-derived SystemIO/SystemMemory authority is **not yet specified as
implemented**. Before the corresponding implementation PR, the project owner
and implementation agent must approve the independent source from which safe
ranges are derived. An AML `OperationRegion` declaration alone cannot
self-authorize arbitrary ports, RAM, kernel memory, or MMIO.

Full uACPI uses explicit address-space handlers so table translation and
hardware OperationRegions remain distinct.

### 4.2 PCI configuration OperationRegions

`acpi-manager` never receives ECAM, CF8/CFC, or a kernel PCI broker backend.
Its uACPI PCI callbacks use a dedicated versioned capability channel to
`pci-manager`.

The first runtime phase supports mediated reads only:

- address, offset, and width are checked by both peers;
- the request carries ACPI and PCI manager generations;
- `pci-manager` performs the physical access;
- every write request returns `AccessDenied` and emits an observation;
- firmware that requires a PCI config write during initialization is reported
  as degraded/fail-closed rather than silently granted broader authority.

Write support requires a later dedicated B.4 policy PR with named write class,
readback mask, rollback behavior, and QEMU/bare-metal evidence.

The append-only `huesos_abi::acpi_broker` opcode values `PciRead` and
`PciWrite` remain reserved for compatibility, but they are permanently
hard-denied. No kernel execution backend or PCI grants are added for them.

### 4.3 Interrupts and deferred work

The ACPI process receives interrupt events through capability IPC; it never
executes privileged interrupt instructions. The userspace runtime implements
uACPI interrupt masking as dispatch suppression for its own event loop, not as
Ring-3 `cli`/`sti`.

Deferred GPE work runs on a CPU-0-affine worker as required by the uACPI host
contract. Notification work may use another bounded worker only after ordering
and teardown tests pass. Work completion drains installed interrupt callbacks
before deferred work.

---

## 5. HMCF and dynamic configuration-capability minting

The kernel does not accept arbitrary ECAM physical ranges from userspace.
DriverManager holds a unique, non-mappable configuration-mint authority tied to
the canonical ACPI archive object and its `firmware_snapshot_id`.

Mint flow:

1. `acpi-manager` validates static MCFG and publishes a bounded HMCF VMO.
2. DriverManager submits HMCF plus the unique mint authority to a kernel
   request.
3. The kernel independently decodes HMCF and cross-checks every ECAM record
   against MCFG bytes in the bound immutable archive.
4. Unknown, missing, overlapping, overflowing, RAM-aliasing, stale-generation,
   or widened records are rejected.
5. The kernel creates exact transport capabilities. DriverManager receives only
   rights needed to transfer them to the current `pci-manager` generation.
6. `pci-manager` validates capability metadata against HMCF before mapping or
   accessing the transport.

Initial ECAM mappings are read-only, uncached, and NX. Later write-capable ECAM
mappings require a separate authority upgrade after HPCI and B.4 policy gates.

Legacy CF8/CFC is not described by HMCF. The same unique mint authority may
request only the architecturally fixed segment-0 conventional backend. The
kernel may grant the exact exclusive port resource only to `pci-manager`.
Because a legacy read writes the CF8 address selector, semantic read-only policy
is enforced by the trusted manager and audited protocol; no ordinary driver
receives the port capability.

---

## 6. AML-first bootstrap state machine

"AML first" means no public PCI inventory or driver authority precedes a
validated AML root description. It does not mean full namespace initialization
can occur without the minimal config transport needed by PCI Config
OperationRegions.

```text
ArchiveReady
  → AcpiRuntimeStarted
  → McfgValidated
  → HmcfPublished
  → ReadOnlyConfigAuthorityReady
  → NamespaceLoaded
  → OperationRegionHandlersReady
  → InterruptModelSelected
  → NamespaceInitialized
  → RootDescriptorsPublished
  → PciReadOnlyInventory
```

Rules:

- no namespace initialization starts before the archive, broker, runtime
  primitives, required mediated handlers, and interrupt-model selection are
  ready;
- `_PIC` is selected after namespace load and before namespace initialization
  when firmware provides it;
- entering ACPI mode is delayed until the fixed FADT broker policy is ready;
- HMCF enables only internal mediated PCI reads during AML bootstrap;
- no public device lease, BAR mutation, bus-master enable, interrupt
  allocation, or DriverHost launch occurs before HPCI validation;
- devices found through HMCF before complete HPCI may appear only in a
  diagnostic inventory as `FirmwareResourcesUnavailable`, read-only and
  unbound;
- the current kernel NVMe bootstrap remains authoritative until the Stage-J
  migration gate closes.

---

## 7. HPCI root publication

After successful namespace loading and the required initialization phase,
`acpi-manager` finds PCI/PCIe root bridge devices (`PNP0A03`/`PNP0A08`) and
produces immutable HPCI records from:

- `_SEG` — segment group;
- `_BBN` — base bus number when present;
- `_CRS` — bus-number, I/O, non-prefetchable memory, and prefetchable memory
  windows with translation;
- `_PRT` — legacy INTx routing reference;
- `_OSC` — native PCIe control results;
- `_CBA` where a hot-pluggable host bridge supplies config base dynamically;
- hotplug/slot metadata where firmware exposes it.

`pci-manager` validates HPCI independently and rejects inconsistent HMCF/HPCI
segment or bus geometry. HPCI does not grant config authority by itself; it
makes firmware resources eligible for validation and planning.

---

## 8. Supervision, generations, and failure policy

DriverManager is the parent of both managers. It retains a read-only master
archive handle and enough broker/mint authority to create a new process
generation without asking a failed child to return handles.

Every ACPI and PCI bootstrap/control message carries a non-zero process
generation. Snapshot publication additionally carries the bound
`firmware_snapshot_id`.

### 8.1 ACPI manager failure

On `acpi-manager` death:

- the ACPI broker rejects new calls and removes installed interrupt handlers;
- deferred work is drained or cancelled in the documented order;
- ACPI-dependent reset, power, hotplug, and firmware-method operations stop;
- DriverManager retains the last validated HMCF/HPCI snapshots;
- existing drivers and leases continue when their operations do not require
  new AML evaluation;
- new leases, binding, hotplug, BAR allocation, rebalance, BDF reuse, and
  topology-generation advancement are frozen;
- DriverManager applies bounded restart backoff;
- restart-budget exhaustion enters an explicit degraded mode, never a silent
  fallback.

A restarted manager publishes a new producer generation. DriverManager does not
replace the last-good snapshots until the new HMCF/HPCI set is validated.
Static-root identity or aperture changes require controlled PCI reconciliation;
they are not applied as an implicit live update.

### 8.2 PCI manager failure

The separately defined PCI policy remains:

- restartable and fail-closed;
- existing DriverHosts continue with already granted resources;
- new PCI operations are disabled until the manager returns;
- stale ACPI mediation replies and stale config capabilities are rejected by
  generation.

---

## 9. Power operations

Reset and power-off are separate broker opcodes and require dedicated
power-management capability. Generic AML evaluation cannot directly request
them. The broker records the initiating process and operation, DriverManager
coordinates driver quiescence, and the existing non-ACPI soft-halt path remains
the fallback.

Suspend/resume is outside the first root-discovery batch. It requires a separate
transaction covering AML preparation, device freeze, interrupt teardown,
resume-time config validation, and driver restart.

---

## 10. Concurrency and lock rules

- no kernel lock is held while waiting for userspace;
- no ACPI manager lock is held across synchronous PCI Manager IPC unless the
  lock is explicitly proven non-recursive and the call has a deadline;
- `pci-manager` never holds its topology or config transaction lock while
  waiting for AML;
- every broker/config request has a correlation ID, process generation, and
  bounded response deadline;
- one worker serializes firmware control operations in the first profile;
- IRQ callbacks enqueue bounded work and do not evaluate AML inline;
- stale replies, snapshots, and capabilities fail closed;
- manager teardown drains interrupt callbacks before deferred work and broker
  authority release.

---

## 11. Verification and release blockers

Required host evidence includes:

- archive-v2 RSDP/SDT decode, checksum, overlap, overflow, count, and translation
  tests;
- proof that every accepted physical-backed entry is indexed or construction
  fails explicitly;
- table-map requests cannot escape the archive VMO;
- SystemIO/SystemMemory and PCI mediation use distinct authorities;
- HMCF decode and kernel cross-check reject widened/stale/configured ranges;
- old ACPI broker PCI opcodes remain denied;
- generation, restart, last-good-snapshot, and freeze-state transitions;
- uACPI mutex/event/work-queue timeout and teardown semantics;
- malformed AML/resource/package output bounds.

Required QEMU evidence includes:

- Q35/OVMF archive-v2 and full userspace namespace startup;
- HMCF publication and exact ECAM capability mint;
- mediated PCI reads with all writes rejected;
- `_SEG`/`_BBN`/`_CRS` HPCI publication;
- manager crash/restart while existing non-ACPI-dependent drivers continue;
- explicit degraded markers when AML or firmware resources are unavailable.

No production claim is permitted while `acpi-manager` has raw physical-memory,
unrestricted I/O-port, raw ECAM, or CF8/CFC authority.

---

## 12. Prior-art references and applied lessons

HuesOS remains independently specified, but the split was checked against:

- Genode ACPI discovery → `pci_decode` report → platform-driver resource
  mediation:
  <https://genode.org/documentation/release-notes/22.05>
- Barrelfish ACPI root-bridge publication → Octopus/Kaluga orchestration → PCI
  domain startup:
  <https://barrelfish.org/publications/TN-019-DeviceDriver.pdf>
- QNX central PCI server and all-writes-through-server policy:
  <https://www.qnx.com/developers/docs/8.0/com.qnx.doc.pci_server/topic/overview.html>
- Fuchsia ACPI root publication and ACPI+PCI composite-device model:
  <https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0112_acpi_support_on_x86>
- uACPI host API, operation-region handlers, and userspace microkernel examples:
  <https://uacpi.github.io/>
- ACPI PCI host-bridge/config/resource requirements:
  <https://docs.kernel.org/PCI/acpi-info.html>
- MINIX's documented warning that an unrestricted userspace ACPI process can
  access arbitrary memory and I/O:
  <https://wiki.minix3.org/doku.php?id=acpi>

The applied lesson is not merely "put ACPI in userspace." The production
boundary also requires narrow authority, immutable publication, one PCI config
executor, generation-safe restart, and explicit degradation.

---

## 13. Architecture decisions fixed by this document

- Full AML runs only in a separate Ring-3 `acpi-manager` runtime.
- Kernel `huesos-uacpi` remains permanently barebones; full userspace uACPI is
  built as a separate crate.
- Archive v2 contains RSDP and a complete bounded physical-to-VMO translation.
- `uacpi_kernel_map` maps only immutable archive copies, never arbitrary machine
  physical memory.
- AML SystemIO/SystemMemory/IRQ operations use the ACPI broker.
- Only `pci-manager` executes PCI config reads or writes.
- ACPI broker `PciRead`/`PciWrite` opcode numbers remain reserved and
  permanently hard-denied.
- HMCF config transports and HPCI root resources are separate ABIs.
- DriverManager retains snapshots and transports handles but owns no PCI or AML
  policy.
- Exact ECAM/CF8 capabilities are minted dynamically by a kernel request that
  cross-checks HMCF against the bound immutable archive.
- The first AML PCI path permits mediated reads only; writes fail closed.
- Before valid HPCI, discovered devices may be visible for diagnostics but are
  unbound and receive no lease.
- ACPI manager failure retains the last-good snapshot for existing devices but
  freezes new PCI lifecycle operations until restart/revalidation.

The implementation sequence and owner/agent review points are maintained in
[ACPI_PCI_IMPLEMENTATION_PLAN.md](ACPI_PCI_IMPLEMENTATION_PLAN.md).
