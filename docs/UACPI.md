# uACPI integration

- **Status:** kernel barebones table subsystem implemented; Ring-3 full AML
  runtime not implemented
- **Architecture:** [ACPI_RING3.md](ACPI_RING3.md)
- **Delivery plan:**
  [ACPI_PCI_IMPLEMENTATION_PLAN.md](ACPI_PCI_IMPLEMENTATION_PLAN.md)

## 1. Decision and pinned source

HuesOS uses **uACPI**, not ACPICA, for standards-complete ACPI and AML support.
The vendored code is pinned to:

```text
repository: https://github.com/uACPI/uACPI
commit:     9c9b26d6291a1cdd9014cc5bb6b03e596697cbfd
license:    MIT
```

The upstream license, README, headers, sources, and exact revision are stored
under `third_party/uacpi/`. Updating the revision requires a dedicated PR,
review of the complete Rust/C boundary, host ASan/UBSan runs, firmware/AML
corpus runs, and safety-budget update. A uACPI update is not combined with the
first Ring-3 runtime enablement.

---

## 2. Permanent two-runtime split

HuesOS deliberately uses two separately built uACPI integrations.

### 2.1 Kernel bootstrap crate

`huesos-uacpi` remains permanently compiled with `UACPI_BAREBONES_MODE`.
It owns only:

- bootloader RSDP handoff;
- RSDP/XSDT/RSDT traversal;
- SDT mapping, checksums, references, and metadata;
- table lookup needed by early platform bootstrap;
- MADT access for APIC/SMP initialization;
- immutable ACPI archive construction inputs.

The kernel crate never loads the AML namespace, executes methods, handles GPEs,
or exposes full-operation-region callbacks.

### 2.2 Userspace runtime crate

A separate future `huesos-uacpi-runtime` crate is linked only into
`acpi-manager`. It compiles the full uACPI source set without barebones mode and
provides the audited Ring-3 host boundary.

The separation is physical, not just a Cargo feature selected on one shared
kernel crate. This prevents feature unification or a build-configuration error
from silently linking AML execution into the kernel.

The userspace runtime initially links with every privileged callback
fail-closed. Individual callback families become active only in their own PR
after the corresponding capability protocol and negative tests exist.

---

## 3. Current kernel boundary

The implemented foreign boundary in `huesos-uacpi` includes table-subsystem C
APIs such as:

- `uacpi_setup_early_table_access`;
- `uacpi_table_subsystem_available`;
- table count, metadata, lookup, get, and unref calls.

The implemented early host callbacks are:

- `uacpi_kernel_get_rsdp`;
- `uacpi_kernel_map`;
- `uacpi_kernel_unmap`;
- `uacpi_kernel_log`.

Every unsafe operation has a local contract. Foreign strings are bounded,
table lengths are capped, null pointers are rejected, and early firmware
mappings go through the fallible HHDM page-table API. The descriptor scratch
buffer is static, aligned, and serialized without `static mut`.

Barebones failure is not a kernel panic. Invalid table initialization or MADT
lookup emits a serial diagnostic and retains the existing degraded/uniprocessor
policy.

---

## 4. Userspace runtime host boundary

The Ring-3 host callbacks are grouped by authority and land incrementally.

### 4.1 Process-local runtime primitives

Implemented inside the userspace runtime/libcanvas boundary:

- sized allocation/free and zeroed allocation;
- strictly monotonic nanoseconds;
- bounded microsecond stall;
- scheduler-backed millisecond sleep;
- non-recursive mutexes with exact uACPI timeout semantics;
- semaphore-like counted events;
- process-local spin/dispatch guards;
- stable userspace thread identity;
- bounded deferred work queues and completion barriers;
- firmware fatal/breakpoint policy.

Ring-3 code cannot execute privileged interrupt-disable instructions. uACPI's
interrupt-state callbacks are represented as suppression/restoration of ACPI
interrupt dispatch in the manager event loop. Hardware interrupt masking and
routing remain kernel mechanisms.

### 4.2 Immutable table mapping

The full runtime maps ACPI archive v2 read-only. Its
`uacpi_kernel_get_rsdp()` returns the original physical RSDP address recorded in
the archive, and `uacpi_kernel_map()` translates only ranges represented by the
archive's physical-to-VMO index.

This callback never performs a physical-map syscall and never maps AML-selected
SystemMemory. A request outside one complete archive translation record returns
`UACPI_MAP_FAILED`.

### 4.3 Privileged hardware callbacks

| uACPI operation | HuesOS authority |
|---|---|
| SystemIO | exact-width ACPI broker request |
| SystemMemory OperationRegion | explicit address-space handler → ACPI broker |
| PCI config | dedicated mediated request → `pci-manager` |
| interrupt install/uninstall | IRQ capability/broker protocol |
| reset/poweroff | dedicated power capability and DriverManager coordination |
| table map | read-only archive translation, not a broker |

The legacy ACPI broker `PciRead`/`PciWrite` opcodes remain hard-denied. Full
runtime code must not call a kernel PCI execution backend.

---

## 5. Full runtime initialization order

The normative startup sequence is:

```text
receive archive-v2 duplicate, broker, generation, and snapshot ID
→ validate and map the complete archive read-only
→ construct all process-local synchronization/work primitives
→ initialize uACPI without exposing unready hardware handlers
→ validate MCFG and publish HMCF
→ wait for pci-manager read-only config authority
→ load AML namespace
→ install SystemIO/SystemMemory/PCI/IRQ handlers
→ set the interrupt model (_PIC) when available
→ initialize namespace (_STA/_INI/_REG)
→ publish HPCI root descriptors
→ enable only the GPE/notification classes with complete teardown support
```

Entering ACPI mode must not occur before the fixed FADT broker policy and
required runtime primitives are ready. If the pinned uACPI API uses
`UACPI_FLAG_NO_ACPI_MODE`, the manager delays the explicit mode transition
until that point.

MCFG/HMCF bootstrap does not authorize public PCI enumeration or driver launch.
It exists so PCI Config OperationRegions can be served by the sole PCI Manager
during namespace initialization.

The first PCI callback phase is read-only. Any write request returns a
structured denial. A platform whose root discovery requires a config write is
reported as degraded until a separate reviewed B.4 write-policy PR supports
that operation.

---

## 6. Namespace and resource extraction

After successful load/initialization, the runtime uses public uACPI APIs to:

- find `PNP0A03` and `PNP0A08` root devices;
- evaluate bounded `_SEG`, `_BBN`, `_CRS`, and later `_PRT`/`_OSC` results;
- decode resources through uACPI's public resource representation;
- preserve PCI-to-CPU translation and producer/consumer semantics;
- reject malformed packages, duplicate roots, crossing bus ranges, overflows,
  and unsupported resource descriptors;
- encode immutable HPCI rather than exporting uACPI object pointers.

No pointer, namespace node, or uACPI-owned object crosses the process boundary.
All IPC payloads are bounded, versioned, pointer-free wire formats.

---

## 7. Failure and teardown

Every initialization level has an explicit failure state. Failure does not
cause the kernel to fall back to executing AML.

On `acpi-manager` termination:

1. stop accepting new broker and PCI mediation calls;
2. remove or mask installed interrupt handlers;
3. drain in-flight interrupt callbacks;
4. drain/cancel deferred work;
5. disconnect address-space handlers;
6. release runtime objects and archive mappings;
7. report a structured reason and generation to DriverManager.

DriverManager retains the canonical archive and last-good HMCF/HPCI snapshots,
applies restart backoff, and freezes new PCI lifecycle operations while the
runtime is unavailable. Existing drivers may continue only with already
granted resources and operations that do not need new AML evaluation.

A fatal AML request, namespace timeout, work-queue overflow, malformed result,
or broker denial is observable. It is never translated into silent success.

---

## 8. Lock and execution rules

- uACPI mutexes are non-recursive and implement timeout `0`, finite
  milliseconds, and `0xFFFF` infinite wait exactly;
- callbacks do not hold Rust allocator internals across IPC;
- no ACPI lock is held while waiting for DriverManager;
- synchronous PCI mediation has a bounded deadline and does not run while
  `pci-manager` holds topology/config transaction locks across ACPI IPC;
- GPE work is CPU-0-affine in the first profile;
- IRQ delivery only queues work; AML is not evaluated inline in the interrupt
  receive path;
- completion waits drain interrupt callbacks before deferred work;
- shutdown cannot free callback context while a worker or interrupt references
  it.

Lock ranks and callback reentrancy are documented alongside each activated
host callback family.

---

## 9. Verification gates

Before full namespace initialization reaches the production boot path:

- the complete userspace C/Rust boundary is listed and reviewed;
- every callback has success, denial, timeout, teardown, and malformed-input
  tests;
- host ASan/UBSan runs cover the full C runtime and synthetic AML corpus;
- archive translation cannot escape the read-only VMO;
- physical-index capacity errors are explicit;
- SystemMemory and PCI config cannot bypass their brokers;
- writes are denied and observed in the first PCI phase;
- manager crash/restart and stale-generation tests pass;
- Q35/OVMF namespace load and HPCI publication pass in QEMU;
- at least one Intel and one AMD bare-metal firmware corpus is archived and
  replayable before broad hardware claims.

The kernel `huesos-uacpi` safety budget and userspace
`huesos-uacpi-runtime` safety budget are tracked separately. No new `unsafe`,
`unsafe impl`, `unwrap`, `expect`, `panic!`, or `static mut` is accepted outside
a dedicated review with machine-readable budget updates where applicable.

---

## 10. Delivery plan

The full sequence, PR boundaries, owner/agent responsibilities, merge order,
and verification commands are maintained in
[ACPI_PCI_IMPLEMENTATION_PLAN.md](ACPI_PCI_IMPLEMENTATION_PLAN.md). No
implementation PR may skip its architecture checkpoint by adding a permissive
stub or temporary raw hardware grant.
