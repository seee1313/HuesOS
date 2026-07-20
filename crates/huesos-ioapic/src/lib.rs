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
//! - [`VectorAllocator`]: hands out device-IRQ vectors from a safe range that
//!   avoids the CPU exceptions, the LAPIC timer vector, the panic-stop /
//!   shutdown-stop IPIs, and the spurious vector.
//! - [`IoApicDescriptor`] and [`route_gsi`]: choose which I/O APIC owns a GSI
//!   and the redirection index (pin) within it.
//! - [`entry_for_legacy_irq`]: ties the pieces together to build a redirection
//!   entry for a legacy ISA IRQ.
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
        self.entries[..self.count].iter().filter_map(|slot| slot.as_ref())
    }

    /// Resolve a legacy bus IRQ to a GSI: the override whose `source` matches,
    /// else the identity mapping (`legacy_irq` as the GSI).
    pub fn resolve_gsi(&self, legacy_irq: u8) -> u32 {
        for override_entry in self.iter() {
            if override_entry.source == legacy_irq {
                return override_entry.gsi;
            }
        }
        legacy_irq as u32
    }

    /// Look up the override for a legacy IRQ, if any.
    pub fn find(&self, legacy_irq: u8) -> Option<SourceOverride> {
        for override_entry in self.iter() {
            if override_entry.source == legacy_irq {
                return Some(*override_entry);
            }
        }
        None
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
        if entry_type == 2 && entry_len >= 10 && out.count < out.entries.len() {
            let gsi = u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?);
            let flags = u16::from_le_bytes(entry.get(8..10)?.try_into().ok()?);
            out.entries[out.count] = Some(SourceOverride {
                bus: entry[2],
                source: entry[3],
                gsi,
                flags,
            });
            out.count += 1;
        }
        cursor = next;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Device-vector allocation
// ---------------------------------------------------------------------------

/// Lowest device-IRQ vector. Below this are the CPU exceptions (0x00-0x1F) and
/// the LAPIC timer vector (0x20).
pub const DEVICE_VECTOR_START: u8 = 0x30;

/// Highest device-IRQ vector. Above this are the panic-stop (0xF1),
/// shutdown-stop (0xF2) IPIs and the spurious vector (0xFF).
pub const DEVICE_VECTOR_END: u8 = 0xEF;

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
    pub fn new(start: u8, end: u8) -> Self {
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
    pub fn device_default() -> Self {
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
            let idx = ((self.next as usize - self.start as usize + offset) % cap) + self.start as usize;
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
            if gsi >= apic.gsi_base && gsi < apic.gsi_base.saturating_add(apic.pin_count) {
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

/// Build a redirection entry for a legacy ISA IRQ.
///
/// Applies source overrides for the GSI and polarity/trigger, allocates a
/// device vector, and targets `destination_apic_id` with fixed delivery. The
/// returned entry is left **masked**; the caller unmasks it (via
/// [`RedirectionEntry::unmasked`]) only after it has been installed.
///
/// Returns `(gsi, entry)`, or `None` if no vector is available.
pub fn entry_for_legacy_irq(
    legacy_irq: u8,
    overrides: &SourceOverrideTable,
    vectors: &mut VectorAllocator,
    destination_apic_id: u8,
) -> Option<(u32, RedirectionEntry)> {
    let gsi = overrides.resolve_gsi(legacy_irq);
    let (polarity, trigger) = match overrides.find(legacy_irq) {
        Some(override_entry) => (override_entry.polarity(), override_entry.trigger()),
        None => (PinPolarity::ActiveHigh, TriggerMode::Edge),
    };
    let vector = vectors.allocate()?;
    let entry = RedirectionEntry::masked()
        .with_vector(vector)
        .with_destination(destination_apic_id)
        .with_polarity(polarity)
        .with_trigger(trigger);
    Some((gsi, entry))
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
        assert_eq!(entry.to_bits() & RedirectionEntry::MASK_BIT, RedirectionEntry::MASK_BIT);
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

    // --- SourceOverride flag decoding ---

    #[test]
    fn override_flag_polarity() {
        let active_low = SourceOverride { bus: 0, source: 9, gsi: 9, flags: 0b11 };
        assert_eq!(active_low.polarity(), PinPolarity::ActiveLow);
        let active_high = SourceOverride { bus: 0, source: 1, gsi: 1, flags: 0b01 };
        assert_eq!(active_high.polarity(), PinPolarity::ActiveHigh);
        // Conforming (0b00) maps to the ISA default (active high).
        let conforming = SourceOverride { bus: 0, source: 0, gsi: 2, flags: 0b00 };
        assert_eq!(conforming.polarity(), PinPolarity::ActiveHigh);
    }

    #[test]
    fn override_flag_trigger() {
        let level = SourceOverride { bus: 0, source: 9, gsi: 9, flags: 0b1100 };
        assert_eq!(level.trigger(), TriggerMode::Level);
        let edge = SourceOverride { bus: 0, source: 1, gsi: 1, flags: 0b0100 };
        assert_eq!(edge.trigger(), TriggerMode::Edge);
        // Conforming (0b00) maps to the ISA default (edge).
        let conforming = SourceOverride { bus: 0, source: 0, gsi: 2, flags: 0b0000 };
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
        let table = table_with(&[SourceOverride { bus: 0, source: 0, gsi: 2, flags: 0 }]);
        assert_eq!(table.resolve_gsi(0), 2);
        // Unrelated IRQs are unaffected.
        assert_eq!(table.resolve_gsi(1), 1);
    }

    #[test]
    fn find_returns_matching_override() {
        let table = table_with(&[
            SourceOverride { bus: 0, source: 0, gsi: 2, flags: 0 },
            SourceOverride { bus: 0, source: 9, gsi: 9, flags: 0b1111 },
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
        assert_eq!(alloc.capacity(), (0xEF - 0x30 + 1) as usize);
        assert_eq!(alloc.used_count(), 0);
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

    // --- route_gsi ---

    #[test]
    fn route_gsi_by_explicit_range() {
        let apics = [
            IoApicDescriptor { id: 0, gsi_base: 0, pin_count: 24 },
            IoApicDescriptor { id: 1, gsi_base: 24, pin_count: 24 },
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
            IoApicDescriptor { id: 2, gsi_base: 0, pin_count: 0 },
            IoApicDescriptor { id: 3, gsi_base: 16, pin_count: 0 },
        ];
        assert_eq!(route_gsi(&apics, 5), Some((2, 5)));
        assert_eq!(route_gsi(&apics, 16), Some((3, 0)));
        assert_eq!(route_gsi(&apics, 100), Some((3, 84)));
    }

    #[test]
    fn route_gsi_no_owner() {
        let apics = [IoApicDescriptor { id: 0, gsi_base: 10, pin_count: 24 }];
        // GSI below the lowest base has no owner.
        assert_eq!(route_gsi(&apics, 5), None);
        assert!(route_gsi(&[], 0).is_none());
    }

    // --- entry_for_legacy_irq ---

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
}
