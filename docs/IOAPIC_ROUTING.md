# I/O APIC Routing Policy (`huesos-ioapic`)

Status: **policy + host tests landed; privileged MMIO driver and on-target
behavior not yet implemented or verified.**

This document describes the host-testable crate `huesos-ioapic` and how it is
intended to plug into the kernel's interrupt handling. It supports
[ROADMAP.md](ROADMAP.md) Immediate #2 (I/O APIC interrupt routing, dropping
reliance on the legacy 8259 PIC).

## Current state (why this matters)

Today the kernel routes the LAPIC timer through the local APIC and still
delivers the PS/2 keyboard via the **legacy 8259 PIC** path. The MADT parser
(`crates/huesos-arch/src/x86_64/acpi.rs`, `parse_madt_bytes`) extracts Local
APICs (entry type 0) and I/O APIC descriptors (entry type 1) but does **not**
consume **Interrupt Source Overrides** (entry type 2). Source overrides are
common on real firmware (e.g. ISA IRQ0 remapped to GSI2) and are required for
correct I/O APIC routing.

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
IPIs, and the spurious vector (`0xFF`). Backed by a 256-entry occupancy map
(no allocator); allocation is a circular scan, with `reserve`/`free` for
explicit management.

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

## Intended kernel integration (NOT yet implemented here)

This crate changes no privileged behavior. The planned integration in
`huesos-arch`:

1. Consume `parse_source_overrides` alongside `parse_madt_bytes` (or fold
   source-override collection into `MadtInfo`).
2. Map the I/O APIC MMIO base (uncached) from the existing `IoApicInfo.address`.
3. For each routable IRQ, use `route_gsi` + `entry_for_legacy_irq` to build a
   `RedirectionEntry`, then write its `low()`/`high()` halves to the I/O APIC
   redirection registers (index register `0x10`, data register `0x11`; entry
   `n` at index `0x10 + 2*n`), masked first, then unmasked.
4. Re-point the keyboard (IRQ1) from the 8259 to the I/O APIC and retire the
   PIC path where every consumer can go through the I/O APIC.
5. EOI via the LAPIC (already done for the timer); level-triggered lines need
   EOI after the device is serviced.

## What still requires on-target verification

The following are **not** verified by this change and must be confirmed in QEMU
(`-smp 1`/`-smp 2`) and on real hardware before the integration is done:

- Actual I/O APIC MMIO programming and the index/data register-pair writes.
- Keyboard IRQ delivery via the I/O APIC instead of the 8259 (and full removal
  of the PIC path).
- Correct handling of real source overrides (e.g. IRQ0→GSI2) from firmware.
- SMP IRQ affinity / destination selection and level-triggered EOI semantics.

These need the full toolchain (pinned nightly + `build-std`, QEMU/OVMF) and were
not runnable where this crate was authored.

## Tests (host)

`make test` includes `-p huesos-ioapic`. The suite (31 tests) covers
redirection-entry round-trip and bit placement, reserved-delivery-mode fallback,
override flag decoding, GSI resolution (identity and override), defensive MADT
source-override parsing (valid, empty, bad signature, truncated, oversized
declared length, zero-length entry), vector allocation/exhaustion/free/reserve
and the empty-range and underflow edge cases, GSI→I/O-APIC selection (explicit
range, fallback, no owner), and the `entry_for_legacy_irq` integration helper.
