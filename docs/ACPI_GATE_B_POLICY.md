# Gate B: proposed subtractive firmware OperationRegion policy

Status: owner-proposed direction, 2026-11-17; **not yet implemented or verified
end to end**. This document records the owner's stated choices and identifies
implementation prerequisites. It is not a claim that the existing broker
already enforces these rules, nor does it grant hardware access.

## Authority sources and exclusions

Only independently validated sources may propose a grant: FADT registers,
ACPI NVS entries in the boot memory map, and optionally an explicit static
board policy. An AML OperationRegion is never an authority source. Each grant
must be bound to the firmware snapshot identity. ACPI reclaimable memory is
accessible for tables through the archive only, not as a raw SystemMemory
grant. Reserved/MMIO is denied by default, unless covered by validated FADT or
an explicit board policy. Usable RAM, bootloader/kernel/modules and framebuffer
are denied.

The sacred deny set always wins: managed RAM, kernel image/heap/page tables,
HBI, DMA pools, ECAM, active and discovered PCI BARs, LAPIC, all IOAPICs and
HPET; in I/O space CF8-CFF, 60 and 64, 3F8-3FF, 20-21, A0-A1, 40-43 and ports
already delegated to DriverHosts. Dynamic identities and lifetimes must be
accounted for; an incomplete or unprovable deny set must not result in a grant.
A candidate intersecting a deny range even by one byte is rejected; no silent
truncation or joining of adjacent grants. The policy's use of 'subtraction'
does not itself authorize splitting an intersecting candidate.

ACPI NVS is a *candidate* for read/write, not proof that it is safe: it must
pass the complete deny set and snapshot binding. PM timer is read-only; FADT
PM1 and GPE status/control regions may be read/write within validated bounds.
SMI_CMD and RESET_REG are denied. Board-policy records default to read-only;
any writes require a specified class and mask. No board profile, port, mask or
write class is enabled merely by mentioning an example.

For each access use checked arithmetic for base+offset and end, natural
alignment, one-grant containment, and exact widths: 1/2/4/8 for memory and
1/2/4 for I/O. Direction must be authorized; write values must fit width, and
read requests carry no write value. Invalid records, zero-length ranges,
overflows and stale or zero snapshot IDs fail closed.

## Failure isolation and scope

A denied operation during side-device initialization is reported and marks the
runtime degraded, but PCI root discovery may continue only when the failure can
be attributed safely to that device. A denial during evaluation of a root
excludes that root; a global failure before attribution blocks the HPCI snapshot
and preserves last-good state. Cross-root inconsistencies, incomplete exclusion
evidence and malformed shared data must not be silently accepted.

Gate C remains closed: PCI config writes remain denied. Gate D remains closed:
no native-control grants, hotplug or dynamic roots. AP-16 inventory remains
read-only and unbound. Unsupported address spaces remain explicit failures. This
policy does not claim safe real-hardware operation or PCI production readiness.

## Implementation status

`huesos_abi::acpi_region_policy` supplies preliminary pure range and snapshot
checks, with no hardware side effects. **It is not connected to the broker**.
The legacy FADT SystemIO grant derivation rejects SMI_CMD and fixed deny-list
port overlaps, including an overlapping SystemIO RESET_REG; it does not yet
account for dynamic DriverHost grants. The syscall backend only executes
SystemIO, the complete deny set and NVS derivation are not wired, and the full
uACPI runtime is not active in `acpi-manager`. No AP-11 through AP-16 exit criterion
is closed by this document or by the policy helper alone. Implementation must
resolve resource tracking and races before granting access, enforce write-value
rules and masks in the broker, and provide the required negative and on-target
checks. Until then the existing boot policy must not be described as conforming
to this Gate B proposal.
