# Ring-3 ACPI architecture

## Trust split

HuesOS does not execute firmware AML in the kernel. The final architecture is split into:

1. **Kernel bootstrap** — uACPI barebones table discovery and MADT consumption needed to initialize APIC/SMP.
2. **`acpi-manager` in Ring 3** — uACPI namespace loading, AML execution, `_INI`, `_STA`, `_CRS`, `_PRT`, notifications and power methods.
3. **Capability broker** — the only component permitted to perform exact-width SystemIO, PCI configuration and IRQ operations requested by `acpi-manager`.

AML is firmware-controlled input and therefore outside the kernel TCB. A crash terminates and restarts only `acpi-manager`; malformed AML cannot directly dereference kernel memory or execute port I/O.

## Immutable table archive

The kernel exports validated ACPI tables in a read-only VMO. The VMO begins with `TableArchiveHeader`, followed by bounded `TableArchiveEntry` records and copied table bytes. Requirements:

- archive magic and version must match;
- at most 4096 tables;
- each table is between the ACPI header size and 16 MiB;
- every offset/length calculation is checked;
- table data begins after the complete entry array;
- ranges may not overlap metadata;
- duplicate signatures use monotonically increasing instance numbers;
- consumers receive only `READ | DUPLICATE | TRANSFER`, never write rights.

The archive removes arbitrary physical mapping from the AML process. uACPI's userspace map callback resolves firmware physical addresses only through a broker-created immutable address map associated with this VMO.

## Broker channel

The bootstrap channel passed to `acpi-manager` is the authority. Requests use `huesos_abi::acpi_broker::Request`; the broker validates structure before consulting its per-channel allowlist.

Structural validation includes:

- exact protocol version and known opcode;
- zero reserved fields;
- exact widths of 1, 2 or 4 bytes;
- natural alignment;
- no value bits beyond the requested write width;
- zero write value on reads;
- zero width/value on control operations.

Authorization is independent of structural validity. The broker checks every request against capabilities derived from validated firmware resources and platform policy. It never accepts a caller-provided raw kernel pointer, MMIO virtual address or unrestricted PCI segment.

The first non-empty policy is derived only from fixed legacy FADT SystemIO descriptors: SMI command, PM1 event/control, PM2 control, PM timer and GPE blocks. Zero-length blocks, arithmetic overflow and addresses outside the 16-bit port space are discarded. PM timer is read-only; reset, power-off, Generic Address Structures, MMIO, PCI and interrupts remain denied until dedicated validators exist.

## Concurrency and lifecycle

Requests carry a 64-bit correlation ID. One broker worker serializes firmware control operations; read-only requests may later be parallelized only after uACPI locking and device semantics are proven. Deferred GPE work is queued to CPU 0 as required by common firmware assumptions.

On manager death, the broker:

- rejects new messages;
- removes installed interrupt handlers;
- drains deferred work;
- revokes port/PCI grants;
- releases archive handles;
- reports a structured exit reason to DriverManager.

DriverManager applies restart throttling. Repeated namespace/AML failure enters a degraded mode with SMP retained but runtime ACPI events and firmware power methods disabled.

## Power operations

Reset and power-off are separate broker opcodes and require a dedicated power-management capability. Generic AML evaluation cannot directly request them. The broker records the initiating process and operation, quiesces drivers, and uses existing soft-halt behavior as fallback.

## Migration sequence

1. Stabilize the broker ABI and archive parser with host tests.
2. Build the read-only table archive in the kernel.
3. Add the capability broker and deny-by-default allowlists.
4. Build `acpi-manager` with full uACPI in Ring 3.
5. Load and initialize the namespace, then evaluate `_PIC`.
6. Route `_PRT`, `_CRS`, events and power operations through the broker.
7. Add malformed archive/AML fuzzing and manager crash/restart tests.
8. Remove any temporary Ring-0 AML implementation; only barebones bootstrap remains.
