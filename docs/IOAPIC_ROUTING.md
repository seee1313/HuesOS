# I/O APIC Routing Policy (`huesos-ioapic`)

Status: **policy + host tests landed; IRQ1 now has an integrated masked-first
MMIO route with readback verification and PIC fallback. The route core is
x2APIC-aware (no APIC-ID truncation) and generic over legacy IRQ/vector, but only
IRQ1 is enabled until matching handlers/drivers exist.**

This document describes the host-testable crate `huesos-ioapic` and how it is
intended to plug into the kernel's interrupt handling. It supports
[ROADMAP.md](ROADMAP.md) Immediate #2 (I/O APIC interrupt routing, dropping
reliance on the legacy 8259 PIC).

## Current state (why this matters)

The kernel routes the LAPIC timer through the local APIC and attempts to route
PS/2 keyboard IRQ1 through the I/O APIC before interrupts are enabled. If MADT,
MMIO mapping, vector allocation, or GSI selection fails, the 8259 keyboard path
remains enabled as a deliberate fallback. The MADT parser extracts Local APICs
(entry type 0) and I/O APIC descriptors (entry type 1); the policy consumer now
also parses Interrupt Source Overrides (entry type 2).

## Why a separate crate

The routing *decisions and encodings* — the redirection-entry bit layout,
source-override resolution, vector allocation, and GSI→I/O-APIC selection — are
pure and hardware-independent. Following the project's hardening pattern
(`huesos-abi::broker_policy`, `huesos-decoder-fuzz`, `huesos-lifecycle`), we
extract them into a dependency-free, `no_std`, host-testable crate so they can
be unit-tested without MMIO or QEMU, and so the privileged driver is held to a
written, tested specification.

The crate is **budget-neutral**: no `unsafe`, no `unwrap`/`expect` calls, and
no panicking macros (tests included), so `tools/check-safety-budget.py` is
unaffected.

## Contents

### `RedirectionEntry`

A faithful codec for the 64-bit I/O APIC redirection table entry
(Intel 82093AA §3.2.4):

```text
 7:0   vector
 10:8  delivery mode (Fixed/LowestPriority/SMI/NMI/INIT/ExtInt)
 11    destination mode (Physical/Logical)
 12    delivery status (read-only)
 13    pin polarity (ActiveHigh/ActiveLow)
 14    remote IRR (read-only)
 15    trigger mode (Edge/Level)
 16    mask (1 = disabled)
 63:56 destination (physical APIC ID or logical destination)
```

`to_bits`/`from_bits` round-trip the full register; `low()`/`high()` split it
into the two 32-bit halves the driver writes (low half first). Reserved
delivery-mode encodings decode to `Fixed`. `RedirectionEntry::masked()` starts
masked so a partially programmed entry never fires; `unmasked()` enables it.
`writable_fields_match()` lets the privileged driver verify MMIO readback while
ignoring read-only delivery-status / remote-IRR bits, and
`level_requires_lapic_eoi()` documents the level-triggered remote-IRR EOI rule.

### `SourceOverride` and `parse_source_overrides`

`SourceOverride` models a MADT Interrupt Source Override (type 2): `bus`,
`source` (legacy IRQ), `gsi`, and `flags`, with `polarity()`/`trigger()`
decoding the flags (conforming/reserved treated as the ISA defaults: active
high / edge).

`parse_source_overrides(&[u8]) -> Option<SourceOverrideTable>` scans a MADT
byte slice for type-2 entries, mirroring the defensive style of
`parse_madt_bytes`: every length and boundary is re-checked, malformed firmware
yields `None` (bad header) or skips unknown entries, and no raw pointer is
dereferenced. `SourceOverrideTable::resolve_gsi`/`find` apply the overrides
(identity when none match).

### `VectorAllocator`

Hands out distinct device-IRQ vectors from an inclusive range (default
`0x30..=0xEF`), deliberately avoiding the CPU exceptions (`0x00-0x1F`), the
LAPIC timer vector (`0x20`), the panic-stop (`0xF1`) and shutdown-stop (`0xF2`)
IPIs, and the spurious vector (`0xFF`). `is_device_vector()` and
`entry_for_legacy_irq` refuse vectors outside this external-device range even if
a caller accidentally configures a bad allocator range; reserved vectors are
freed and skipped until a valid device vector appears or the range is exhausted.
Backed by a 256-entry occupancy map (no allocator); allocation is a circular
scan, with `reserve`/`free` for explicit management.

### `IoApicDescriptor` and `route_gsi`

`route_gsi(io_apics, gsi) -> Option<(ioapic_id, redirection_index)>` selects the
I/O APIC owning a GSI. When descriptors declare a `pin_count`, the explicit
`[gsi_base, gsi_base + pin_count)` ranges are authoritative and a GSI outside
all ranges has no owner (`None`); when no pin counts are known, it falls back to
the descriptor with the largest `gsi_base <= gsi`.

### `entry_for_legacy_irq`

Ties the pieces together: resolves the GSI and polarity/trigger via source
overrides (ISA defaults otherwise), allocates a vector, and builds a masked,
fixed-delivery entry targeting a given APIC ID. The caller unmasks it only
after installing it.

The helper is x2APIC-aware in the production-safe sense: without interrupt
remapping, the I/O APIC redirection entry exposes only an 8-bit physical
destination field. `ioapic_physical_destination` therefore rejects APIC IDs above
255 instead of silently truncating them and routing interrupts to the wrong CPU.

## Current privileged integration

`huesos-arch::ioapic::init_keyboard` now performs the first integrated route
through a generic internal `init_legacy_irq(madt, irq, vector)` helper:

1. parse MADT and source overrides;
2. map each I/O APIC MMIO window uncached;
3. read the pin count from the version register;
4. use `route_gsi` and `entry_for_legacy_irq` for the requested ISA IRQ;
5. reject unrepresentable x2APIC destinations instead of truncating;
6. program the high and low redirection halves masked-first;
7. unmask the entry only after both writes;
8. read the redirection entry back and compare every writable field;
9. mark the legacy IRQ as routed in a bitmap.

The keyboard handler is the only current external-IRQ IDT consumer, so only IRQ1
is enabled today. `interrupts::init` masks the 8259 keyboard path only after this
route succeeds. If any step fails, including readback mismatch or unsupported
APIC destination, the driver masks the candidate I/O APIC entry again and the
existing PIC handler remains active.
## What still requires on-target verification

The QEMU debug/release × SMP1/SMP2 serial smoke matrix verifies that the
integrated boot path remains healthy. The following still require additional
coverage before claiming a complete interrupt subsystem:

- keyboard-injection CI assertions that prove the `0x31` vector, rather than
  the PIC vector, delivered the event;
- enabling additional routed IRQs only alongside their IDT handlers and userspace
  drivers;
- interrupt-remapping or logical-destination support for machines whose x2APIC
  IDs exceed the classic I/O APIC's 8-bit physical destination field;
- real source overrides such as IRQ0→GSI2 on hardware, not only synthetic host
  tables;
- bare-metal firmware variation;
- eventual PIC fallback removal once the I/O APIC path is proven on enough
  machines.

## Tests (host)

`make test` includes `-p huesos-ioapic`. The suite covers redirection-entry
round-trip and bit placement, readback comparison of writable fields,
level-triggered LAPIC EOI policy, reserved-delivery-mode fallback, override flag
decoding, GSI resolution (identity and override), defensive MADT source-override
parsing (valid, empty, bad signature, truncated, oversized declared length,
zero-length entry), device-vector range assertions, vector
allocation/exhaustion/free/reserve and the empty-range and underflow edge cases,
GSI→I/O-APIC selection (explicit range, fallback, no owner), non-identity IRQ1
source overrides, x2APIC APIC-ID rejection, and the `entry_for_legacy_irq`
integration helper.
