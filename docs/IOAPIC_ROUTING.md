# I/O APIC Routing (`huesos-ioapic`)

Status: **policy tests and the multi-controller hardware route manager are
implemented.** The kernel can mask every discovered I/O APIC pin, route legacy
IRQs or explicitly typed GSIs through dynamically installed IDT vectors, bridge
interrupts to bound userspace ports, and release routes with their object
lifecycle. Level-triggered routes are masked before LAPIC EOI and require a
userspace acknowledgement after device service. A QEMU SMP2 test now injects a
PS/2 key through QMP and observes its IOAPIC-delivered IRQ packet arrive at the
userspace keyboard Port. A separate QEMU edu kernel-Port probe covers raw GSI
and level ACK/re-enable (see below); the corresponding userspace syscall path
and physical verification remain pending.

The implementation supports Immediate #2 in [ROADMAP.md](ROADMAP.md), while
retaining the 8259 as a boot-time fallback. It does not add interrupt
remapping, x2APIC destinations wider than the I/O APIC's 8-bit destination
field, or ACPI `_PRT`/link-device enumeration.

## Policy crate

`huesos-ioapic` contains the pure, `no_std`, host-testable routing policy. It
has no MMIO or `unsafe` code and is budget-neutral for
`tools/check-safety-budget.py`.

### Redirection entries and electrical configuration

`RedirectionEntry` encodes the 64-bit I/O APIC entry and exposes writable-field
readback comparison that ignores the read-only delivery-status and Remote IRR
bits. Routes use fixed delivery in physical destination mode. Destination IDs
that cannot fit the hardware's 8-bit field are rejected, never truncated.

`RouteConfig::isa_default()` is active-high/edge; `RouteConfig::pci_intx_default()`
is active-low/level. MADT Interrupt Source Overrides (type 2) take precedence
for their ISA source. The parser accepts only bus 0 (ISA), rejects reserved
polarity/trigger encodings, duplicate sources or GSIs, truncated entries, and
over-capacity tables. The privileged initializer also verifies that every
override GSI belongs to a discovered controller's pin range. Unsupported or
invalid routing information fails closed rather than being silently remapped.

### Controller ranges and vectors

The hardware initializer reads each controller's redirection count from its
version register, rejects duplicate IDs, overflowing or overlapping GSI ranges,
and resolves each GSI against the complete controller set. The vector policy is
`0x30..=0xCF`. Vector `0x31` is reserved for the PS/2 keyboard handler;
`0xD0..=0xDF` remains dedicated to the existing NVMe MSI/MSI-X handlers, and
scheduler/IPI vectors remain outside the allocator's range. Allocation and
release are bounded and require no allocator.

## Hardware and kernel integration

`huesos-arch::ioapic::initialize` maps all MADT controllers uncached, reads
hardware pin counts, validates controller/override ranges, and masks every
redirection entry with a mask-bit readback before publishing the controller
set. `IOAPIC_STATE` serializes the IOREGSEL/IOWIN selector-window transaction
across CPUs and disables local interrupts while held.

For a new route, the manager:

1. validates the GSI owner, electrical configuration, online destination, and
   available vector;
2. masks the old low word and verifies that the pin is masked before changing
   vector/destination fields;
3. writes the high and low words while masked, reads the entry back, and checks
   all writable fields;
4. publishes the vector-to-event mapping and route metadata before unmasking;
5. verifies the final unmasked state. If masking cannot be proven on an error
   path, the vector is retained rather than recycled.

The IDT has static `x86-interrupt` stubs for the dynamic range. For a generic
external vector, the stub masks a level-triggered route before LAPIC EOI, then
emits the event key(s) to the common IRQ callback. A MADT ISA override can
therefore deliver both its legacy source key and its raw GSI key. The callback
key is a typed `u64` namespace/number pair (`InterruptEventKey`), so a raw GSI
cannot collide with an equal-number MSI vector or legacy IRQ. The keyboard
continues to use its dedicated `0x31` handler and retains PIC fallback if its
I/O APIC route cannot be verified.

IRQ objects acquire their hardware route when bound to a port and release it
when the final object reference is dropped. Other than the permanent kernel
keyboard route, a level-triggered route allows a single active userspace owner;
this prevents one listener from re-enabling a line while another is still
servicing it. The handler masks a level route before EOI. After clearing or
servicing the device, userspace calls `Interrupt::acknowledge()` to unmask it.
Edge-triggered routes and the pre-routed NVMe MSI vectors need no IOAPIC ACK.
If a level event cannot be queued, the route stays masked (fail-safe); closing
the owning interrupt object releases the route.

`InterruptCreateGsiForResource` (syscall 66) creates an explicitly typed raw-GSI
interrupt from an `Irq` Resource, so a numeric value is never ambiguously
interpreted as a legacy IRQ, GSI, or MSI vector. `InterruptAcknowledge` (syscall
67) implements the level-route ACK; `Syscall::COUNT` is 68. The current raw-GSI
convenience path uses MADT override flags for ISA aliases and PCI INTx
active-low/level defaults for other GSIs. It must only be used for PCI INTx when
no more specific electrical-routing data is available; ACPI `_PRT`/link-device
resolution is not implemented yet.

Affinity changes mask the input, wait a bounded time for level Remote IRR to
clear, write/verify the new destination while masked, and restore its prior
mask state. Destinations above 255 and APIC IDs that are not scheduler-online
are rejected. The kernel supplies the online-CPU validator; before it is
installed, only the current CPU is accepted.

## Remaining verification and scope limits

- **Done (kernel-side)**: `irq_test=1` boot probe
  (`crates/huesos-kernel/src/boot/irq_probe.rs`, gated by
  `scripts/ci-qemu-irq-level-smoke.sh`) drives QEMU's `edu` PCI device, a real
  level-triggered INTx source. It proves on target that a non-keyboard raw GSI
  (GSI 11 under the CI Q35 machine) is acquired, delivered to a bound Port, kept
  masked while asserted and unacknowledged, and redelivered after deassert plus
  `Interrupt::acknowledge`. The probe uses a kernel Port, so the
  userspace syscall path (`InterruptCreateGsiForResource`, `InterruptAcknowledge`,
  `libcanvas`) is still unverified on target.
- Extend the QEMU test to the userspace path: a Resource-minted raw-GSI Interrupt
  created through syscall 66, read from a userspace Port, and acknowledged
  through syscall 67.
- Route drop/release after the probe, conflicting routes, and online/offline
  affinity rejection are not yet exercised in an integration test. Level ACK and
  re-enable on an asserted device are now covered by the kernel-side probe.
- Supply PCI `_PRT`/link-device electrical data instead of relying on the
  documented PCI INTx default for non-ISA GSIs.
- Add interrupt remapping or logical destination support before routing to
  physical APIC IDs above 255; those requests currently fail closed.
- Keep the PIC fallback until the new route paths have been verified across
  firmware and physical machines.

## Host tests

`make test` includes `-p huesos-ioapic`. Tests cover redirection encoding and
readback, edge/level policy, override polarity/trigger decoding and strict MADT
parsing, multiple-controller GSI ownership, overlap/overflow/duplicate checks,
vector bounds/reservation/exhaustion/reuse, and x2APIC destination rejection.
The hardware MMIO path itself must be checked with QEMU and real hardware.
