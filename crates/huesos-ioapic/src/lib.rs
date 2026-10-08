//! # HuesOS I/O APIC Routing Policy
//!
//! Host-testable, dependency-free policy and data-plane primitives for routing
//! external interrupts through the I/O APIC. This crate isolates the *decisions
//! and encodings* the kernel's privileged I/O APIC driver relies on, so they can
//! be unit-tested on the host without MMIO, QEMU, or `unsafe`. It advances
//! [ROADMAP.md](../../docs/ROADMAP.md) Immediate #2 (I/O APIC interrupt routing,
//! dropping reliance on the legacy 8259 PIC).
//!
//! ## What lives here
//!
//! - [`RedirectionEntry`]: a faithful codec for the 64-bit I/O APIC redirection
//!   table entry (Intel 82093AA §3.2.4), with the delivery-mode / polarity /
//!   trigger / mask / destination fields as typed values.
//! - [`SourceOverride`] and [`parse_source_overrides`]: the MADT *Interrupt
//!   Source Override* (entry type 2) that remaps a legacy bus IRQ to a Global
//!   System Interrupt with explicit polarity/trigger flags — the entry the
//!   existing privileged MADT parser (`huesos-arch::x86_64::acpi`) does not yet
//!   consume.
//! - [`VectorAllocator`]: hands out device-IRQ vectors from the reserved
//!   I/O-APIC range, excluding vectors owned by keyboard/MSI/IPI handlers.
//! - [`IoApicDescriptor`], [`validate_ioapic_descriptors`], and [`route_gsi`]:
//!   validate non-overlapping controller ranges and choose the I/O APIC that
//!   owns a GSI and its redirection pin.
//! - [`RouteConfig`], [`route_config_for_legacy_irq`], and
//!   [`entry_for_gsi`]: construct redirection entries for both legacy ISA
//!   sources and arbitrary GSI routes.
//!
//! ## What does NOT live here
//!
//! No MMIO, no register writes, no EOI, no locks. The privileged driver in
//! `huesos-arch` performs the actual 32-bit register-pair writes to the I/O APIC
//! and is verified on-target. See `docs/IOAPIC_ROUTING.md` for the integration
//! plan and the explicit list of not-yet-verified on-target behavior.
//!
//! ## Safety budget
//!
//! This crate is intentionally **budget-neutral**: it contains no `unsafe`
//! blocks, no `unwrap` or `expect` calls, and no panicking macros anywhere —
//! including its tests — so it adds nothing to the surface tracked by
//! `tools/check-safety-budget.py`.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Redirection table entry
// ---------------------------------------------------------------------------

/// I/O APIC delivery mode (redirection entry bits [10:8]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMode {
    /// Deliver to the vector field on the destination LAPIC.
    Fixed = 0b000,
    /// Deliver to the lowest-priority CPU among the destination set.
    LowestPriority = 0b001,
    /// System Management Interrupt.
    Smi = 0b010,
    /// Non-maskable interrupt.
    Nmi = 0b100,
    /// INIT IPI.
    Init = 0b101,
    /// External interrupt (legacy INTR pin).
    ExtInt = 0b111,
}

impl DeliveryMode {
    /// Decode the 3-bit field. Reserved encodings (0b011, 0b110) yield `None`.
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b111 {
            0b000 => Some(Self::Fixed),
            0b001 => Some(Self::LowestPriority),
            0b010 => Some(Self::Smi),
            0b100 => Some(Self::Nmi),
            0b101 => Some(Self::Init),
            0b111 => Some(Self::ExtInt),
            _ => None,
        }
    }

    /// Encode to the 3-bit field.
    pub fn to_bits(self) -> u8 {
        self as u8
    }
}

/// Destination mode (redirection entry bit 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DestinationMode {
    /// Destination field is a physical APIC ID.
    Physical = 0,
    /// Destination field is a logical destination register value.
    Logical = 1,
}

impl DestinationMode {
    /// Decode the single bit.
    pub fn from_bit(bit: bool) -> Self {
        if bit {
            Self::Logical
        } else {
            Self::Physical
        }
    }

    /// Encode to a single bit.
    pub fn to_bit(self) -> bool {
        matches!(self, Self::Logical)
    }
}

/// Pin polarity (redirection entry bit 13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PinPolarity {
    /// Signal is active high.
    ActiveHigh = 0,
    /// Signal is active low.
    ActiveLow = 1,
}

impl PinPolarity {
    /// Decode the single bit.
    pub fn from_bit(bit: bool) -> Self {
        if bit {
            Self::ActiveLow
        } else {
            Self::ActiveHigh
        }
    }

    /// Encode to a single bit.
    pub fn to_bit(self) -> bool {
        matches!(self, Self::ActiveLow)
    }
}

/// Trigger mode (redirection entry bit 15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TriggerMode {
    /// Edge-sensitive interrupt.
    Edge = 0,
    /// Level-sensitive interrupt.
    Level = 1,
}

impl TriggerMode {
    /// Decode the single bit.
    pub fn from_bit(bit: bool) -> Self {
        if bit {
            Self::Level
        } else {
            Self::Edge
        }
    }

    /// Encode to a single bit.
    pub fn to_bit(self) -> bool {
        matches!(self, Self::Level)
    }
}

/// Electrical/trigger configuration for one I/O-APIC input pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteConfig {
    /// Active signal polarity.
    pub polarity: PinPolarity,
    /// Edge- or level-sensitive delivery.
    pub trigger: TriggerMode,
}

impl RouteConfig {
    /// ISA bus defaults for a legacy source without a MADT override.
    pub const fn isa_default() -> Self {
        Self {
            polarity: PinPolarity::ActiveHigh,
            trigger: TriggerMode::Edge,
        }
    }

    /// PCI INTx defaults when no firmware `_PRT`/link information is
    /// available: active-low, level-triggered.
    pub const fn pci_intx_default() -> Self {
        Self {
            polarity: PinPolarity::ActiveLow,
            trigger: TriggerMode::Level,
        }
    }
}

/// A 64-bit I/O APIC redirection table entry (Intel 82093AA §3.2.4).
///
/// Bit layout:
///
/// ```text
///  7:0   vector
///  10:8  delivery mode
///  11    destination mode
///  12    delivery status (read-only)
///  13    pin polarity
///  14    remote IRR (read-only)
///  15    trigger mode
///  16    mask (1 = masked / disabled)
///  55:17 reserved
///  63:56 destination (physical APIC ID or logical destination)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedirectionEntry {
    /// Interrupt vector delivered to the destination LAPIC.
    pub vector: u8,
    /// Delivery mode.
    pub delivery_mode: DeliveryMode,
    /// Physical vs logical destination.
    pub destination_mode: DestinationMode,
    /// Delivery status (read-only; true while a delivery is pending).
    pub delivery_status: bool,
    /// Pin polarity.
    pub pin_polarity: PinPolarity,
    /// Remote IRR (read-only; for level-triggered, set while the interrupt is
    /// accepted and awaiting EOI).
    pub remote_irr: bool,
    /// Trigger mode.
    pub trigger_mode: TriggerMode,
    /// True when the entry is masked (interrupts from this pin disabled).
    pub masked: bool,
    /// Destination APIC ID (physical mode) or logical destination value.
    pub destination: u8,
}

impl RedirectionEntry {
    /// Mask bit position.
    pub const MASK_BIT: u64 = 1 << 16;

    /// A masked, fixed-delivery, edge-triggered, active-high entry with a zero
    /// vector and destination. Masked by default so a partially programmed
    /// entry never fires.
    pub fn masked() -> Self {
        Self {
            vector: 0,
            delivery_mode: DeliveryMode::Fixed,
            destination_mode: DestinationMode::Physical,
            delivery_status: false,
            pin_polarity: PinPolarity::ActiveHigh,
            remote_irr: false,
            trigger_mode: TriggerMode::Edge,
            masked: true,
            destination: 0,
        }
    }

    /// Encode to the 64-bit register value.
    pub fn to_bits(&self) -> u64 {
        let mut bits: u64 = self.vector as u64;
        bits |= (self.delivery_mode.to_bits() as u64) << 8;
        bits |= (self.destination_mode.to_bit() as u64) << 11;
        bits |= (self.delivery_status as u64) << 12;
        bits |= (self.pin_polarity.to_bit() as u64) << 13;
        bits |= (self.remote_irr as u64) << 14;
        bits |= (self.trigger_mode.to_bit() as u64) << 15;
        bits |= (self.masked as u64) << 16;
        bits |= (self.destination as u64) << 56;
        bits
    }

    /// Decode from the 64-bit register value. Reserved delivery-mode encodings
    /// fall back to [`DeliveryMode::Fixed`].
    pub fn from_bits(bits: u64) -> Self {
        let delivery_mode = match DeliveryMode::from_bits((bits >> 8) as u8) {
            Some(mode) => mode,
            None => DeliveryMode::Fixed,
        };
        Self {
            vector: (bits & 0xFF) as u8,
            delivery_mode,
            destination_mode: DestinationMode::from_bit((bits >> 11) & 1 == 1),
            delivery_status: (bits >> 12) & 1 == 1,
            pin_polarity: PinPolarity::from_bit((bits >> 13) & 1 == 1),
            remote_irr: (bits >> 14) & 1 == 1,
            trigger_mode: TriggerMode::from_bit((bits >> 15) & 1 == 1),
            masked: (bits >> 16) & 1 == 1,
            destination: (bits >> 56) as u8,
        }
    }

    /// The low 32 bits of the register pair (written to the I/O APIC data
    /// register first).
    pub fn low(&self) -> u32 {
        (self.to_bits() & 0xFFFF_FFFF) as u32
    }

    /// The high 32 bits of the register pair (destination).
    pub fn high(&self) -> u32 {
        (self.to_bits() >> 32) as u32
    }

    /// Whether every writable field matches `observed`.
    ///
    /// I/O APIC readback may report the read-only delivery-status and remote-IRR
    /// bits changing underneath us, so privileged verification compares only
    /// the fields software actually programs.
    pub fn writable_fields_match(&self, observed: &Self) -> bool {
        self.vector == observed.vector
            && self.delivery_mode == observed.delivery_mode
            && self.destination_mode == observed.destination_mode
            && self.pin_polarity == observed.pin_polarity
            && self.trigger_mode == observed.trigger_mode
            && self.masked == observed.masked
            && self.destination == observed.destination
    }

    /// Whether a level-triggered fixed-delivery entry needs a LAPIC EOI to let
    /// the I/O APIC clear remote-IRR and reassert future interrupts.
    pub fn level_requires_lapic_eoi(&self) -> bool {
        !self.masked
            && self.delivery_mode == DeliveryMode::Fixed
            && self.trigger_mode == TriggerMode::Level
    }

    /// Builder: set the vector.
    pub fn with_vector(mut self, vector: u8) -> Self {
        self.vector = vector;
        self
    }

    /// Builder: set the destination (physical APIC ID by default).
    pub fn with_destination(mut self, destination: u8) -> Self {
        self.destination = destination;
        self
    }

    /// Builder: set the trigger mode.
    pub fn with_trigger(mut self, trigger: TriggerMode) -> Self {
        self.trigger_mode = trigger;
        self
    }

    /// Builder: set the pin polarity.
    pub fn with_polarity(mut self, polarity: PinPolarity) -> Self {
        self.pin_polarity = polarity;
        self
    }

    /// Builder: unmask the entry (enable delivery).
    pub fn unmasked(mut self) -> Self {
        self.masked = false;
        self
    }
}

// ---------------------------------------------------------------------------
// MADT Interrupt Source Override (entry type 2)
// ---------------------------------------------------------------------------

/// A MADT Interrupt Source Override (entry type 2).
///
/// Maps a bus-relative legacy interrupt `source` (e.g. an ISA IRQ) to a Global
/// System Interrupt `gsi`, carrying explicit polarity/trigger `flags` that may
/// override the bus default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceOverride {
    /// Bus source (0 = ISA).
    pub bus: u8,
    /// Bus-relative interrupt source (the legacy IRQ number).
    pub source: u8,
    /// Global System Interrupt this source maps to.
    pub gsi: u32,
    /// Polarity/trigger flags (MADT layout: bits [1:0] polarity, [3:2] trigger).
    pub flags: u16,
}

impl SourceOverride {
    /// Decode pin polarity from the flags, treating "conforming"/reserved as the
    /// ISA default (active high).
    pub fn polarity(&self) -> PinPolarity {
        match self.flags & 0b11 {
            0b11 => PinPolarity::ActiveLow,
            _ => PinPolarity::ActiveHigh,
        }
    }

    /// Decode trigger mode from the flags, treating "conforming"/reserved as the
    /// ISA default (edge).
    pub fn trigger(&self) -> TriggerMode {
        match (self.flags >> 2) & 0b11 {
            0b11 => TriggerMode::Level,
            _ => TriggerMode::Edge,
        }
    }

    /// Decode the MADT flags while rejecting reserved encodings. `None` means
    /// the firmware supplied polarity or trigger value `0b10`, which must not
    /// be guessed when programming a live interrupt route.
    pub fn config(&self) -> Option<RouteConfig> {
        let polarity = match self.flags & 0b11 {
            0b00 | 0b01 => PinPolarity::ActiveHigh,
            0b11 => PinPolarity::ActiveLow,
            _ => return None,
        };
        let trigger = match (self.flags >> 2) & 0b11 {
            0b00 | 0b01 => TriggerMode::Edge,
            0b11 => TriggerMode::Level,
            _ => return None,
        };
        Some(RouteConfig { polarity, trigger })
    }
}

/// Maximum source overrides retained by [`SourceOverrideTable`].
pub const MAX_SOURCE_OVERRIDES: usize = 16;

/// A bounded table of [`SourceOverride`] entries parsed from a MADT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceOverrideTable {
    /// Storage; only the first [`count`](Self::count) entries are valid.
    pub entries: [Option<SourceOverride>; MAX_SOURCE_OVERRIDES],
    /// Number of valid entries.
    pub count: usize,
}

impl SourceOverrideTable {
    /// An empty table.
    pub const fn empty() -> Self {
        Self {
            entries: [None; MAX_SOURCE_OVERRIDES],
            count: 0,
        }
    }

    /// Number of valid entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True when there are no overrides.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate the valid overrides.
    pub fn iter(&self) -> impl Iterator<Item = &SourceOverride> {
        self.entries[..self.count]
            .iter()
            .filter_map(|slot| slot.as_ref())
    }

    /// Resolve a legacy bus IRQ to a GSI: the override whose `source` matches,
    /// else the identity mapping (`legacy_irq` as the GSI).
    pub fn resolve_gsi(&self, legacy_irq: u8) -> u32 {
        for override_entry in self.iter() {
            if override_entry.bus == 0 && override_entry.source == legacy_irq {
                return override_entry.gsi;
            }
        }
        legacy_irq as u32
    }

    /// Look up the override for a legacy IRQ, if any.
    pub fn find(&self, legacy_irq: u8) -> Option<SourceOverride> {
        for override_entry in self.iter() {
            if override_entry.bus == 0 && override_entry.source == legacy_irq {
                return Some(*override_entry);
            }
        }
        None
    }

    /// Look up the ISA source alias for a GSI, if firmware defines one.
    pub fn find_gsi(&self, gsi: u32) -> Option<SourceOverride> {
        for override_entry in self.iter() {
            if override_entry.bus == 0 && override_entry.gsi == gsi {
                return Some(*override_entry);
            }
        }
        None
    }

    /// Resolve the electrical configuration for a legacy source, validating
    /// reserved MADT encodings. Sources without an override use ISA defaults.
    pub fn config_for_legacy_irq(&self, legacy_irq: u8) -> Option<RouteConfig> {
        match self.find(legacy_irq) {
            Some(override_entry) => override_entry.config(),
            None => Some(RouteConfig::isa_default()),
        }
    }

    /// Resolve a GSI's electrical configuration from an ISA source override.
    /// Non-ISA GSIs have no configuration in MADT and must be configured by
    /// their bus/device policy instead.
    pub fn config_for_gsi(&self, gsi: u32) -> Option<RouteConfig> {
        self.find_gsi(gsi)
            .filter(|override_entry| override_entry.bus == 0)
            .and_then(|override_entry| override_entry.config())
    }
}

/// Parse MADT Interrupt Source Override (type 2) entries from a MADT byte
/// slice, mirroring the defensive style of the privileged
/// `parse_madt_bytes`: every length and boundary is re-checked, malformed
/// firmware yields `None` (bad header) or simply skips unknown entries, and no
/// raw pointer is dereferenced.
///
/// Returns `None` if the slice is not a structurally valid MADT; returns an
/// empty table when the MADT has no source overrides (the common case on simple
/// firmware).
pub fn parse_source_overrides(table: &[u8]) -> Option<SourceOverrideTable> {
    const HEADER_BYTES: usize = 36;
    const FIXED: usize = HEADER_BYTES + 8;

    if table.len() < FIXED || table.get(..4)? != b"APIC" {
        return None;
    }
    let declared = u32::from_le_bytes(table.get(4..8)?.try_into().ok()?) as usize;
    if !(FIXED..=table.len()).contains(&declared) {
        return None;
    }

    let mut out = SourceOverrideTable::empty();
    let mut cursor = FIXED;
    while cursor < declared {
        let prefix = table.get(cursor..cursor.checked_add(2)?)?;
        let entry_type = prefix[0];
        let entry_len = prefix[1] as usize;
        if entry_len < 2 {
            return None;
        }
        let next = cursor.checked_add(entry_len)?;
        if next > declared {
            return None;
        }
        let entry = table.get(cursor..next)?;
        if entry_type == 2 {
            if entry_len < 10 || out.count == out.entries.len() {
                return None;
            }
            let override_entry = SourceOverride {
                bus: entry[2],
                source: entry[3],
                gsi: u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?),
                flags: u16::from_le_bytes(entry.get(8..10)?.try_into().ok()?),
            };
            if override_entry.bus != 0
                || override_entry.config().is_none()
                || out.iter().any(|known| {
                    known.bus == override_entry.bus
                        && (known.source == override_entry.source
                            || known.gsi == override_entry.gsi)
                })
            {
                return None;
            }
            out.entries[out.count] = Some(override_entry);
            out.count += 1;
        }
        cursor = next;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Device-vector allocation
// ---------------------------------------------------------------------------

/// First vector in the dynamically allocated I/O-APIC IRQ range. Vectors
/// below this are exceptions, the LAPIC timer, or reserved compatibility
/// vectors.
pub const DEVICE_VECTOR_START: u8 = 0x30;

/// Last dynamically allocated I/O-APIC vector. `0xD0..=0xDF` is reserved for
/// the statically installed NVMe MSI/MSI-X handlers; `0xF0..=0xF3` is reserved
/// for scheduler, stop, and TLB-shootdown IPIs.
pub const DEVICE_VECTOR_END: u8 = 0xCF;

/// Whether `vector` is in the HuesOS external-device IRQ vector range.
pub fn is_device_vector(vector: u8) -> bool {
    (DEVICE_VECTOR_START..=DEVICE_VECTOR_END).contains(&vector)
}

/// Allocates distinct interrupt vectors from a configured inclusive range.
///
/// Backed by a 256-bit occupancy map (no allocator). Allocation is a circular
/// scan so recently freed vectors are not immediately reused.
pub struct VectorAllocator {
    used: [bool; 256],
    start: u8,
    end: u8,
    next: u16,
    count: usize,
}

impl VectorAllocator {
    /// An allocator over the inclusive range `[start, end]`. If `start > end`
    /// the range is empty and every allocation fails.
    pub const fn new(start: u8, end: u8) -> Self {
        Self {
            used: [false; 256],
            start,
            end,
            next: start as u16,
            count: 0,
        }
    }

    /// An allocator over the default device-IRQ range
    /// ([`DEVICE_VECTOR_START`], [`DEVICE_VECTOR_END`]).
    pub const fn device_default() -> Self {
        Self::new(DEVICE_VECTOR_START, DEVICE_VECTOR_END)
    }

    /// Number of vectors in the configured range.
    pub fn capacity(&self) -> usize {
        if self.end < self.start {
            return 0;
        }
        (self.end as usize) - (self.start as usize) + 1
    }

    /// Number of vectors currently allocated.
    pub fn used_count(&self) -> usize {
        self.count
    }

    /// Whether `vector` is currently allocated.
    pub fn is_used(&self, vector: u8) -> bool {
        self.used[vector as usize]
    }

    /// Allocate the next free vector, if any.
    pub fn allocate(&mut self) -> Option<u8> {
        if self.end < self.start {
            return None;
        }
        let cap = self.capacity();
        for offset in 0..cap {
            let idx =
                ((self.next as usize - self.start as usize + offset) % cap) + self.start as usize;
            if !self.used[idx] {
                self.used[idx] = true;
                self.count += 1;
                let mut advance = (idx + 1) as u16;
                if advance > self.end as u16 {
                    advance = self.start as u16;
                }
                self.next = advance;
                return Some(idx as u8);
            }
        }
        None
    }

    /// Reserve a specific vector if it is in range and free. Returns whether it
    /// was reserved.
    pub fn reserve(&mut self, vector: u8) -> bool {
        let v = vector as usize;
        if v < self.start as usize || v > self.end as usize || self.used[v] {
            return false;
        }
        self.used[v] = true;
        self.count += 1;
        true
    }

    /// Free a previously allocated/reserved vector. Returns whether it was
    /// actually freed.
    pub fn free(&mut self, vector: u8) -> bool {
        let v = vector as usize;
        if v < self.start as usize || v > self.end as usize || !self.used[v] {
            return false;
        }
        self.used[v] = false;
        self.count = self.count.saturating_sub(1);
        true
    }
}

impl Default for VectorAllocator {
    fn default() -> Self {
        Self::device_default()
    }
}

// ---------------------------------------------------------------------------
// GSI -> I/O APIC selection
// ---------------------------------------------------------------------------

/// Routing-relevant descriptor of an I/O APIC (mirrors the MADT I/O APIC entry
/// plus a pin count).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApicDescriptor {
    /// I/O APIC id.
    pub id: u8,
    /// First Global System Interrupt handled by this I/O APIC.
    pub gsi_base: u32,
    /// Number of redirection entries (pins) exposed; typically 24. Use 0 if
    /// unknown to fall back to `gsi_base`-only selection.
    pub pin_count: u32,
}

/// Why a discovered I/O-APIC GSI range set is unsafe to route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoApicDescriptorError {
    /// A discovered controller has no redirection entries.
    EmptyRange,
    /// `gsi_base + pin_count` extends beyond the GSI address space.
    RangeOverflow,
    /// Two records advertise the same controller ID.
    DuplicateId,
    /// Two controllers claim at least one common GSI.
    OverlappingRanges,
}

/// Validate controller identifiers and the half-open GSI ranges reported by
/// the hardware. The privileged driver calls this after reading each
/// controller's redirection-table size and before accepting any route.
pub fn validate_ioapic_descriptors(
    io_apics: &[IoApicDescriptor],
) -> Result<(), IoApicDescriptorError> {
    let mut i = 0usize;
    while i < io_apics.len() {
        let current = io_apics[i];
        if current.pin_count == 0 {
            return Err(IoApicDescriptorError::EmptyRange);
        }
        let end = u64::from(current.gsi_base) + u64::from(current.pin_count);
        if end > u64::from(u32::MAX) + 1 {
            return Err(IoApicDescriptorError::RangeOverflow);
        }
        let mut j = i + 1;
        while j < io_apics.len() {
            let other = io_apics[j];
            if current.id == other.id {
                return Err(IoApicDescriptorError::DuplicateId);
            }
            let other_end = u64::from(other.gsi_base) + u64::from(other.pin_count);
            if other.pin_count != 0
                && u64::from(current.gsi_base) < other_end
                && u64::from(other.gsi_base) < end
            {
                return Err(IoApicDescriptorError::OverlappingRanges);
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}

/// Select the I/O APIC that owns `gsi` and the redirection index (pin) within
/// it, returning `(ioapic_id, redirection_index)`.
///
/// Prefers an explicit `[gsi_base, gsi_base + pin_count)` range match; if no
/// descriptor declares a pin count, falls back to the descriptor with the
/// largest `gsi_base <= gsi`. Returns `None` if no descriptor can own the GSI.
pub fn route_gsi(io_apics: &[IoApicDescriptor], gsi: u32) -> Option<(u8, u32)> {
    let mut known_pins = false;
    for apic in io_apics {
        if apic.pin_count > 0 {
            known_pins = true;
            let end = u64::from(apic.gsi_base) + u64::from(apic.pin_count);
            if gsi >= apic.gsi_base && u64::from(gsi) < end {
                return Some((apic.id, gsi - apic.gsi_base));
            }
        }
    }
    // If any descriptor declares a pin count, the explicit ranges are
    // authoritative: a GSI outside every declared range has no owner.
    if known_pins {
        return None;
    }
    // No pin counts known: fall back to the descriptor with the largest
    // gsi_base <= gsi.
    let mut best: Option<IoApicDescriptor> = None;
    for apic in io_apics {
        if apic.gsi_base <= gsi {
            match best {
                Some(current) if current.gsi_base >= apic.gsi_base => {}
                _ => best = Some(*apic),
            }
        }
    }
    best.map(|apic| (apic.id, gsi - apic.gsi_base))
}

// ---------------------------------------------------------------------------
// Integration helper
// ---------------------------------------------------------------------------

fn allocate_device_vector(vectors: &mut VectorAllocator) -> Option<u8> {
    let capacity = vectors.capacity();
    for _ in 0..capacity {
        let vector = vectors.allocate()?;
        if is_device_vector(vector) {
            return Some(vector);
        }
        let _ = vectors.free(vector);
    }
    None
}

/// Convert a LAPIC/x2APIC physical ID into the 8-bit I/O APIC redirection
/// destination field.
///
/// Without interrupt remapping, the classic I/O APIC redirection entry can only
/// name an 8-bit physical APIC destination. Returning `None` for larger x2APIC
/// IDs is deliberate production-safe behavior: do not silently truncate and
/// route an interrupt to the wrong CPU.
pub fn ioapic_physical_destination(apic_id: u32) -> Option<u8> {
    if apic_id <= u8::MAX as u32 {
        Some(apic_id as u8)
    } else {
        None
    }
}

/// Build a redirection entry for a legacy ISA IRQ.
///
/// Applies source overrides for the GSI and polarity/trigger, allocates a
/// device vector, and targets `destination_apic_id` with fixed delivery. The
/// returned entry is left **masked**; the caller unmasks it (via
/// [`RedirectionEntry::unmasked`]) only after it has been installed.
///
/// Returns `(gsi, entry)`, or `None` if no vector or 8-bit physical destination
/// is available.
pub fn entry_for_legacy_irq(
    legacy_irq: u8,
    overrides: &SourceOverrideTable,
    vectors: &mut VectorAllocator,
    destination_apic_id: u32,
) -> Option<(u32, RedirectionEntry)> {
    let destination = ioapic_physical_destination(destination_apic_id)?;
    let gsi = overrides.resolve_gsi(legacy_irq);
    let config = overrides.config_for_legacy_irq(legacy_irq)?;
    let vector = allocate_device_vector(vectors)?;
    let entry = RedirectionEntry::masked()
        .with_vector(vector)
        .with_destination(destination)
        .with_polarity(config.polarity)
        .with_trigger(config.trigger);
    Some((gsi, entry))
}

/// Build a masked redirection entry for an arbitrary GSI using explicit
/// electrical configuration and an already selected vector. This is the
/// primitive used by PCI/ACPI interrupt routing; unlike
/// [`entry_for_legacy_irq`], it never guesses how an un-described GSI is wired.
pub fn entry_for_gsi(
    config: RouteConfig,
    vector: u8,
    destination_apic_id: u32,
) -> Option<RedirectionEntry> {
    if !is_device_vector(vector) {
        return None;
    }
    let destination = ioapic_physical_destination(destination_apic_id)?;
    Some(
        RedirectionEntry::masked()
            .with_vector(vector)
            .with_destination(destination)
            .with_polarity(config.polarity)
            .with_trigger(config.trigger),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Host tests. Kept free of `unwrap`, `expect`, and panicking macros
    //! (asserts expand to a panic at runtime but do not match the budget's
    //! textual panic-macro pattern), keeping this crate budget-neutral.

    use super::*;
    use std::vec;
    use std::vec::Vec;

    // --- RedirectionEntry codec ---

    #[test]
    fn masked_default_is_masked_and_zero() {
        let entry = RedirectionEntry::masked();
        assert!(entry.masked);
        assert_eq!(entry.vector, 0);
        assert_eq!(entry.delivery_mode, DeliveryMode::Fixed);
        assert_eq!(entry.destination_mode, DestinationMode::Physical);
        assert_eq!(entry.pin_polarity, PinPolarity::ActiveHigh);
        assert_eq!(entry.trigger_mode, TriggerMode::Edge);
        // Mask bit must be set in the encoded value.
        assert_eq!(
            entry.to_bits() & RedirectionEntry::MASK_BIT,
            RedirectionEntry::MASK_BIT
        );
    }

    #[test]
    fn round_trip_full_entry() {
        let entry = RedirectionEntry {
            vector: 0x41,
            delivery_mode: DeliveryMode::LowestPriority,
            destination_mode: DestinationMode::Logical,
            delivery_status: true,
            pin_polarity: PinPolarity::ActiveLow,
            remote_irr: true,
            trigger_mode: TriggerMode::Level,
            masked: false,
            destination: 0x0F,
        };
        let bits = entry.to_bits();
        let decoded = RedirectionEntry::from_bits(bits);
        assert_eq!(decoded, entry);
    }

    #[test]
    fn vector_occupies_low_byte() {
        let entry = RedirectionEntry::masked().with_vector(0xAB);
        assert_eq!(entry.to_bits() & 0xFF, 0xAB);
    }

    #[test]
    fn destination_occupies_top_byte() {
        let entry = RedirectionEntry::masked().with_destination(0x05);
        assert_eq!(entry.to_bits() >> 56, 0x05);
        assert_eq!(entry.high() >> 24, 0x05);
    }

    #[test]
    fn low_high_split_matches_bits() {
        let entry = RedirectionEntry {
            vector: 0x77,
            delivery_mode: DeliveryMode::Nmi,
            destination_mode: DestinationMode::Physical,
            delivery_status: false,
            pin_polarity: PinPolarity::ActiveLow,
            remote_irr: false,
            trigger_mode: TriggerMode::Level,
            masked: true,
            destination: 0x02,
        };
        let bits = entry.to_bits();
        assert_eq!(entry.low() as u64, bits & 0xFFFF_FFFF);
        assert_eq!(entry.high() as u64, bits >> 32);
    }

    #[test]
    fn reserved_delivery_mode_falls_back_to_fixed() {
        // 0b011 in bits [10:8] is reserved.
        let bits: u64 = 0b011 << 8;
        let decoded = RedirectionEntry::from_bits(bits);
        assert_eq!(decoded.delivery_mode, DeliveryMode::Fixed);
    }

    #[test]
    fn delivery_mode_rejects_reserved_encodings() {
        assert_eq!(DeliveryMode::from_bits(0b011), None);
        assert_eq!(DeliveryMode::from_bits(0b110), None);
        assert_eq!(DeliveryMode::from_bits(0b000), Some(DeliveryMode::Fixed));
        assert_eq!(DeliveryMode::from_bits(0b111), Some(DeliveryMode::ExtInt));
    }

    #[test]
    fn builders_configure_entry() {
        let entry = RedirectionEntry::masked()
            .with_vector(0x50)
            .with_destination(0x03)
            .with_polarity(PinPolarity::ActiveLow)
            .with_trigger(TriggerMode::Level)
            .unmasked();
        assert_eq!(entry.vector, 0x50);
        assert_eq!(entry.destination, 0x03);
        assert_eq!(entry.pin_polarity, PinPolarity::ActiveLow);
        assert_eq!(entry.trigger_mode, TriggerMode::Level);
        assert!(!entry.masked);
    }

    #[test]
    fn writable_field_match_ignores_read_only_status_bits() {
        let expected = RedirectionEntry::masked()
            .with_vector(0x50)
            .with_destination(0x03)
            .with_trigger(TriggerMode::Level)
            .unmasked();
        let mut observed = expected;
        observed.delivery_status = true;
        observed.remote_irr = true;
        assert!(expected.writable_fields_match(&observed));
        observed.vector = 0x51;
        assert!(!expected.writable_fields_match(&observed));
    }

    #[test]
    fn level_fixed_entries_require_lapic_eoi() {
        let level = RedirectionEntry::masked()
            .with_vector(0x50)
            .with_trigger(TriggerMode::Level)
            .unmasked();
        assert!(level.level_requires_lapic_eoi());
        let edge = RedirectionEntry::masked()
            .with_vector(0x51)
            .with_trigger(TriggerMode::Edge)
            .unmasked();
        assert!(!edge.level_requires_lapic_eoi());
        let masked = level;
        assert!(!RedirectionEntry {
            masked: true,
            ..masked
        }
        .level_requires_lapic_eoi());
    }

    // --- SourceOverride flag decoding ---

    #[test]
    fn override_flag_polarity() {
        let active_low = SourceOverride {
            bus: 0,
            source: 9,
            gsi: 9,
            flags: 0b11,
        };
        assert_eq!(active_low.polarity(), PinPolarity::ActiveLow);
        let active_high = SourceOverride {
            bus: 0,
            source: 1,
            gsi: 1,
            flags: 0b01,
        };
        assert_eq!(active_high.polarity(), PinPolarity::ActiveHigh);
        // Conforming (0b00) maps to the ISA default (active high).
        let conforming = SourceOverride {
            bus: 0,
            source: 0,
            gsi: 2,
            flags: 0b00,
        };
        assert_eq!(conforming.polarity(), PinPolarity::ActiveHigh);
    }

    #[test]
    fn override_flag_trigger() {
        let level = SourceOverride {
            bus: 0,
            source: 9,
            gsi: 9,
            flags: 0b1100,
        };
        assert_eq!(level.trigger(), TriggerMode::Level);
        let edge = SourceOverride {
            bus: 0,
            source: 1,
            gsi: 1,
            flags: 0b0100,
        };
        assert_eq!(edge.trigger(), TriggerMode::Edge);
        // Conforming (0b00) maps to the ISA default (edge).
        let conforming = SourceOverride {
            bus: 0,
            source: 0,
            gsi: 2,
            flags: 0b0000,
        };
        assert_eq!(conforming.trigger(), TriggerMode::Edge);
    }

    // --- SourceOverrideTable resolution ---

    fn table_with(overrides: &[SourceOverride]) -> SourceOverrideTable {
        let mut table = SourceOverrideTable::empty();
        for (i, o) in overrides.iter().enumerate() {
            if i < table.entries.len() {
                table.entries[i] = Some(*o);
                table.count += 1;
            }
        }
        table
    }

    #[test]
    fn resolve_gsi_identity_without_override() {
        let table = SourceOverrideTable::empty();
        assert!(table.is_empty());
        assert_eq!(table.resolve_gsi(1), 1);
        assert_eq!(table.resolve_gsi(4), 4);
    }

    #[test]
    fn resolve_gsi_applies_override() {
        // The classic ISA IRQ0 -> GSI2 source override.
        let table = table_with(&[SourceOverride {
            bus: 0,
            source: 0,
            gsi: 2,
            flags: 0,
        }]);
        assert_eq!(table.resolve_gsi(0), 2);
        // Unrelated IRQs are unaffected.
        assert_eq!(table.resolve_gsi(1), 1);
    }

    #[test]
    fn find_returns_matching_override() {
        let table = table_with(&[
            SourceOverride {
                bus: 0,
                source: 0,
                gsi: 2,
                flags: 0,
            },
            SourceOverride {
                bus: 0,
                source: 9,
                gsi: 9,
                flags: 0b1111,
            },
        ]);
        assert_eq!(table.len(), 2);
        let found = table.find(9);
        assert!(found.is_some(), "expected an override for IRQ9");
        if let Some(o) = found {
            assert_eq!(o.gsi, 9);
            assert_eq!(o.polarity(), PinPolarity::ActiveLow);
            assert_eq!(o.trigger(), TriggerMode::Level);
        }
        assert_eq!(table.find(5), None);
    }

    // --- parse_source_overrides ---

    fn madt_with_iso(source: u8, gsi: u32, flags: u16) -> Vec<u8> {
        // 36-byte SDT header + 8 bytes MADT fixed (local APIC addr + flags)
        // + one 10-byte Interrupt Source Override entry. Total 54.
        let mut table = vec![0u8; 54];
        table[..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&54u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        // Entry at offset 44.
        table[44] = 2; // type = Interrupt Source Override
        table[45] = 10; // length
        table[46] = 0; // bus = ISA
        table[47] = source;
        table[48..52].copy_from_slice(&gsi.to_le_bytes());
        table[52..54].copy_from_slice(&flags.to_le_bytes());
        table
    }

    #[test]
    fn parses_a_single_source_override() {
        let table = madt_with_iso(0, 2, 0);
        let parsed = parse_source_overrides(&table);
        assert!(parsed.is_some(), "expected a valid MADT");
        if let Some(t) = parsed {
            assert_eq!(t.len(), 1);
            assert_eq!(t.resolve_gsi(0), 2);
        }
    }

    #[test]
    fn rejects_reserved_override_flags_and_duplicate_sources() {
        let invalid_flags = madt_with_iso(1, 1, 0b0010);
        assert_eq!(parse_source_overrides(&invalid_flags), None);
        let mut unsupported_bus = madt_with_iso(1, 1, 0);
        unsupported_bus[46] = 1;
        assert_eq!(parse_source_overrides(&unsupported_bus), None);

        let mut duplicate = madt_with_iso(1, 1, 0);
        duplicate.resize(64, 0);
        duplicate[4..8].copy_from_slice(&64u32.to_le_bytes());
        duplicate[54] = 2;
        duplicate[55] = 10;
        duplicate[56] = 0;
        duplicate[57] = 1;
        duplicate[58..62].copy_from_slice(&2u32.to_le_bytes());
        duplicate[62..64].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(parse_source_overrides(&duplicate), None);

        duplicate[57] = 2;
        duplicate[58..62].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(parse_source_overrides(&duplicate), None);
    }

    #[test]
    fn rejects_no_space_for_additional_source_overrides() {
        let mut table = vec![0u8; 44 + 17 * 10];
        table[..4].copy_from_slice(b"APIC");
        let table_len = table.len() as u32;
        table[4..8].copy_from_slice(&table_len.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        for index in 0..17 {
            let at = 44 + index * 10;
            table[at] = 2;
            table[at + 1] = 10;
            table[at + 2] = 0;
            table[at + 3] = index as u8;
            table[at + 4..at + 8].copy_from_slice(&(index as u32).to_le_bytes());
            table[at + 8..at + 10].copy_from_slice(&0u16.to_le_bytes());
        }
        assert_eq!(parse_source_overrides(&table), None);
    }

    #[test]
    fn parses_no_overrides_as_empty_table() {
        // A MADT with a Local APIC entry (type 0), no ISOs.
        let mut table = vec![0u8; 52];
        table[..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&52u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44] = 0; // type 0 (Local APIC)
        table[45] = 8; // length
        let parsed = parse_source_overrides(&table);
        assert!(parsed.is_some(), "header was valid");
        if let Some(t) = parsed {
            assert!(t.is_empty());
        }
    }

    #[test]
    fn rejects_bad_signature() {
        let mut table = madt_with_iso(0, 2, 0);
        table[0] = b'X';
        assert_eq!(parse_source_overrides(&table), None);
    }

    #[test]
    fn rejects_truncated_table() {
        let table = madt_with_iso(0, 2, 0);
        let short = &table[..40];
        assert_eq!(parse_source_overrides(short), None);
    }

    #[test]
    fn rejects_declared_length_beyond_slice() {
        let mut table = madt_with_iso(0, 2, 0);
        table[4..8].copy_from_slice(&200u32.to_le_bytes());
        assert_eq!(parse_source_overrides(&table), None);
    }

    #[test]
    fn rejects_zero_length_entry() {
        let mut table = madt_with_iso(0, 2, 0);
        table[45] = 0; // entry length 0 is invalid
        assert_eq!(parse_source_overrides(&table), None);
    }

    // --- VectorAllocator ---

    #[test]
    fn default_range_capacity_and_bounds() {
        let alloc = VectorAllocator::device_default();
        assert_eq!(alloc.capacity(), (0xCF - 0x30 + 1) as usize);
        assert_eq!(alloc.used_count(), 0);
        assert!(!is_device_vector(0x20));
        assert!(is_device_vector(DEVICE_VECTOR_START));
        assert!(is_device_vector(DEVICE_VECTOR_END));
        assert!(!is_device_vector(0xF0));
    }

    #[test]
    fn allocates_distinct_vectors() {
        let mut alloc = VectorAllocator::new(0x30, 0x33); // 4 vectors
        let mut seen = Vec::new();
        for _ in 0..4 {
            let v = alloc.allocate();
            assert!(v.is_some(), "expected a free vector");
            if let Some(vector) = v {
                assert!(!seen.contains(&vector));
                seen.push(vector);
            }
        }
        assert_eq!(alloc.used_count(), 4);
        // Fifth allocation must fail (range exhausted).
        assert_eq!(alloc.allocate(), None);
    }

    #[test]
    fn free_makes_vector_reusable() {
        let mut alloc = VectorAllocator::new(0x30, 0x31);
        let a = alloc.allocate();
        let b = alloc.allocate();
        assert_eq!(alloc.allocate(), None);
        assert!(a.is_some(), "first allocation should succeed");
        if let Some(va) = a {
            assert!(alloc.free(va));
        }
        // Freeing again is a no-op returning false.
        if let Some(va) = a {
            assert!(!alloc.free(va));
        }
        // Now one more can be allocated.
        let c = alloc.allocate();
        assert_ne!(c, None);
        assert_ne!(b, None);
    }

    #[test]
    fn reserve_specific_vector() {
        let mut alloc = VectorAllocator::new(0x30, 0x3F);
        assert!(alloc.reserve(0x35));
        assert!(alloc.is_used(0x35));
        // Reserving the same vector again fails.
        assert!(!alloc.reserve(0x35));
        // Reserving out-of-range fails.
        assert!(!alloc.reserve(0x20));
        // Subsequent allocations never hand out the reserved vector.
        for _ in 0..15 {
            match alloc.allocate() {
                Some(v) => assert_ne!(v, 0x35),
                None => break,
            }
        }
    }

    #[test]
    fn empty_range_allocates_nothing() {
        let mut alloc = VectorAllocator::new(0x40, 0x30); // start > end
        assert_eq!(alloc.capacity(), 0);
        assert_eq!(alloc.allocate(), None);
    }

    #[test]
    fn used_count_never_underflows() {
        let mut alloc = VectorAllocator::new(0x30, 0x33);
        // Freeing without any allocation must not underflow.
        assert!(!alloc.free(0x30));
        assert_eq!(alloc.used_count(), 0);
        let v = alloc.allocate();
        assert!(v.is_some(), "should allocate");
        if let Some(x) = v {
            assert!(alloc.free(x));
        }
        assert_eq!(alloc.used_count(), 0);
    }

    // --- controller-range validation and GSI selection ---

    #[test]
    fn accepts_adjacent_non_overlapping_ioapic_ranges() {
        let apics = [
            IoApicDescriptor {
                id: 0,
                gsi_base: 0,
                pin_count: 24,
            },
            IoApicDescriptor {
                id: 1,
                gsi_base: 24,
                pin_count: 24,
            },
        ];
        assert_eq!(validate_ioapic_descriptors(&apics), Ok(()));
    }

    #[test]
    fn rejects_empty_overlapping_duplicate_and_overflow_ranges() {
        assert_eq!(
            validate_ioapic_descriptors(&[IoApicDescriptor {
                id: 0,
                gsi_base: 0,
                pin_count: 0,
            }]),
            Err(IoApicDescriptorError::EmptyRange)
        );
        assert_eq!(
            validate_ioapic_descriptors(&[
                IoApicDescriptor {
                    id: 0,
                    gsi_base: 0,
                    pin_count: 24,
                },
                IoApicDescriptor {
                    id: 1,
                    gsi_base: 23,
                    pin_count: 24,
                },
            ]),
            Err(IoApicDescriptorError::OverlappingRanges)
        );
        assert_eq!(
            validate_ioapic_descriptors(&[
                IoApicDescriptor {
                    id: 7,
                    gsi_base: 0,
                    pin_count: 24,
                },
                IoApicDescriptor {
                    id: 7,
                    gsi_base: 24,
                    pin_count: 24,
                },
            ]),
            Err(IoApicDescriptorError::DuplicateId)
        );
        assert_eq!(
            validate_ioapic_descriptors(&[IoApicDescriptor {
                id: 0,
                gsi_base: u32::MAX,
                pin_count: 2,
            }]),
            Err(IoApicDescriptorError::RangeOverflow)
        );
    }

    #[test]
    fn route_gsi_by_explicit_range() {
        let apics = [
            IoApicDescriptor {
                id: 0,
                gsi_base: 0,
                pin_count: 24,
            },
            IoApicDescriptor {
                id: 1,
                gsi_base: 24,
                pin_count: 24,
            },
        ];
        assert_eq!(route_gsi(&apics, 0), Some((0, 0)));
        assert_eq!(route_gsi(&apics, 23), Some((0, 23)));
        assert_eq!(route_gsi(&apics, 24), Some((1, 0)));
        assert_eq!(route_gsi(&apics, 47), Some((1, 23)));
        // Beyond all declared ranges.
        assert_eq!(route_gsi(&apics, 48), None);
    }

    #[test]
    fn route_gsi_fallback_by_base() {
        // Unknown pin counts (0): fall back to largest gsi_base <= gsi.
        let apics = [
            IoApicDescriptor {
                id: 2,
                gsi_base: 0,
                pin_count: 0,
            },
            IoApicDescriptor {
                id: 3,
                gsi_base: 16,
                pin_count: 0,
            },
        ];
        assert_eq!(route_gsi(&apics, 5), Some((2, 5)));
        assert_eq!(route_gsi(&apics, 16), Some((3, 0)));
        assert_eq!(route_gsi(&apics, 100), Some((3, 84)));
    }

    #[test]
    fn route_gsi_no_owner() {
        let apics = [IoApicDescriptor {
            id: 0,
            gsi_base: 10,
            pin_count: 24,
        }];
        // GSI below the lowest base has no owner.
        assert_eq!(route_gsi(&apics, 5), None);
        assert!(route_gsi(&[], 0).is_none());
    }

    // --- entry_for_legacy_irq ---

    #[test]
    fn physical_destination_rejects_unrepresentable_x2apic_ids() {
        assert_eq!(ioapic_physical_destination(0), Some(0));
        assert_eq!(ioapic_physical_destination(255), Some(255));
        assert_eq!(ioapic_physical_destination(256), None);
        assert_eq!(ioapic_physical_destination(u32::MAX), None);
    }

    #[test]
    fn legacy_irq_rejects_unrepresentable_x2apic_destination() {
        let overrides = SourceOverrideTable::empty();
        let mut vectors = VectorAllocator::new(0x30, 0x30);
        assert_eq!(entry_for_legacy_irq(1, &overrides, &mut vectors, 256), None);
        assert_eq!(vectors.used_count(), 0);
    }

    #[test]
    fn legacy_irq_without_override_uses_isa_defaults() {
        let overrides = SourceOverrideTable::empty();
        let mut vectors = VectorAllocator::new(0x30, 0x3F);
        let built = entry_for_legacy_irq(1, &overrides, &mut vectors, 0x00);
        assert!(built.is_some(), "expected a built entry");
        if let Some((gsi, entry)) = built {
            assert_eq!(gsi, 1);
            assert_eq!(entry.pin_polarity, PinPolarity::ActiveHigh);
            assert_eq!(entry.trigger_mode, TriggerMode::Edge);
            assert_eq!(entry.destination, 0x00);
            assert!(entry.masked, "must stay masked until installed");
            assert!(entry.vector >= 0x30 && entry.vector <= 0x3F);
        }
    }

    #[test]
    fn legacy_irq_with_override_uses_override_flags() {
        // IRQ0 -> GSI2, active low / level.
        let overrides = table_with(&[SourceOverride {
            bus: 0,
            source: 0,
            gsi: 2,
            flags: 0b1111,
        }]);
        let mut vectors = VectorAllocator::new(0x30, 0x3F);
        let built = entry_for_legacy_irq(0, &overrides, &mut vectors, 0x01);
        assert!(built.is_some(), "expected a built entry");
        if let Some((gsi, entry)) = built {
            assert_eq!(gsi, 2);
            assert_eq!(entry.pin_polarity, PinPolarity::ActiveLow);
            assert_eq!(entry.trigger_mode, TriggerMode::Level);
            assert_eq!(entry.destination, 0x01);
        }
    }

    #[test]
    fn legacy_irq_fails_when_no_vector_available() {
        let overrides = SourceOverrideTable::empty();
        let mut vectors = VectorAllocator::new(0x30, 0x30); // single vector
        let first = entry_for_legacy_irq(1, &overrides, &mut vectors, 0x00);
        assert_ne!(first, None);
        // Range now exhausted.
        let second = entry_for_legacy_irq(2, &overrides, &mut vectors, 0x00);
        assert_eq!(second, None);
    }

    #[test]
    fn arbitrary_gsi_entry_uses_explicit_pci_intx_configuration() {
        let entry = entry_for_gsi(RouteConfig::pci_intx_default(), 0x42, 3);
        assert!(entry.is_some(), "valid GSI route should build");
        if let Some(entry) = entry {
            assert_eq!(entry.vector, 0x42);
            assert_eq!(entry.destination, 3);
            assert_eq!(entry.pin_polarity, PinPolarity::ActiveLow);
            assert_eq!(entry.trigger_mode, TriggerMode::Level);
            assert!(entry.masked);
        }
        assert_eq!(entry_for_gsi(RouteConfig::isa_default(), 0xD0, 0), None);
        assert_eq!(entry_for_gsi(RouteConfig::isa_default(), 0x42, 256), None);
    }

    #[test]
    fn invalid_reserved_override_flags_refuse_a_legacy_route() {
        let overrides = table_with(&[SourceOverride {
            bus: 0,
            source: 5,
            gsi: 5,
            flags: 0b0010,
        }]);
        let mut vectors = VectorAllocator::new(0x40, 0x40);
        assert_eq!(entry_for_legacy_irq(5, &overrides, &mut vectors, 0), None);
        assert_eq!(vectors.used_count(), 0);
    }

    #[test]
    fn legacy_irq_rejects_non_device_vector() {
        let overrides = SourceOverrideTable::empty();
        let mut vectors = VectorAllocator::new(0x20, 0x20);
        assert_eq!(
            entry_for_legacy_irq(1, &overrides, &mut vectors, 0x00),
            None
        );
        assert_eq!(vectors.used_count(), 0);
    }

    #[test]
    fn legacy_irq_skips_reserved_vector_before_device_range() {
        let overrides = SourceOverrideTable::empty();
        let mut vectors = VectorAllocator::new(0x20, DEVICE_VECTOR_START);
        let built = entry_for_legacy_irq(1, &overrides, &mut vectors, 0x00);
        assert!(
            built.is_some(),
            "expected device vector after reserved range"
        );
        if let Some((_gsi, entry)) = built {
            assert_eq!(entry.vector, DEVICE_VECTOR_START);
        }
        assert_eq!(vectors.used_count(), 1);
    }

    #[test]
    fn keyboard_override_can_route_to_non_identity_gsi() {
        let overrides = table_with(&[SourceOverride {
            bus: 0,
            source: 1,
            gsi: 17,
            flags: 0b1111,
        }]);
        let mut vectors = VectorAllocator::new(0x31, 0x31);
        let built = entry_for_legacy_irq(1, &overrides, &mut vectors, 0x02);
        assert!(built.is_some(), "expected keyboard route");
        if let Some((gsi, entry)) = built {
            assert_eq!(gsi, 17);
            assert_eq!(entry.vector, 0x31);
            assert_eq!(entry.pin_polarity, PinPolarity::ActiveLow);
            assert_eq!(entry.trigger_mode, TriggerMode::Level);
            assert_eq!(entry.destination, 0x02);
        }
    }

    #[test]
    fn non_isa_source_override_does_not_remap_legacy_irq() {
        let table = table_with(&[SourceOverride {
            bus: 1,
            source: 1,
            gsi: 99,
            flags: 0,
        }]);
        assert_eq!(table.resolve_gsi(1), 1);
        assert_eq!(table.find(1), None);
    }
}
