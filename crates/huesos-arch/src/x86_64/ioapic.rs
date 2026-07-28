//! Minimal I/O APIC routing for the legacy keyboard IRQ.
//!
//! Policy decisions and codecs live in `huesos-ioapic`; this module owns only
//! the privileged MMIO mapping and register-pair writes. The first integrated
//! device is ISA IRQ1, routed to a fixed vector before interrupts are enabled.

use core::sync::atomic::{AtomicU32, Ordering};
use huesos_ioapic::{
    entry_for_legacy_irq, is_device_vector, parse_source_overrides, route_gsi, IoApicDescriptor,
    RedirectionEntry, VectorAllocator,
};
use x86_64::structures::paging::PageTableFlags;

/// Vector used for the I/O APIC keyboard route.
pub const KEYBOARD_VECTOR: u8 = 0x31;

static ROUTED_LEGACY_IRQS: AtomicU32 = AtomicU32::new(0);

/// Failure while configuring the integrated I/O APIC keyboard route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoApicError {
    /// No usable I/O APIC was described by MADT.
    NoController,
    /// Firmware table structure was malformed.
    InvalidMadt,
    /// The I/O APIC MMIO range could not be mapped.
    Mapping,
    /// The configured vector is not in the external-device range.
    InvalidVector,
    /// No vector or GSI route was available.
    NoRoute,
    /// The current LAPIC/x2APIC destination cannot be encoded safely.
    UnsupportedDestination,
    /// MMIO readback did not match the programmed redirection entry.
    Verification,
}

/// Whether a legacy ISA IRQ was successfully routed through an I/O APIC.
pub fn legacy_irq_routed(irq: u8) -> bool {
    if irq >= 32 {
        return false;
    }
    ROUTED_LEGACY_IRQS.load(Ordering::Acquire) & (1u32 << irq) != 0
}

/// Whether IRQ1 was successfully routed through an I/O APIC.
pub fn keyboard_routed() -> bool {
    legacy_irq_routed(1)
}

/// Configure the I/O APIC redirection entry for ISA IRQ1.
///
/// The entry is programmed masked-first and is unmasked only after both
/// 32-bit halves have been written. The function runs once on the BSP before
/// `STI`; all later keyboard events use the existing userspace IRQ bridge.
pub fn init_keyboard(madt_bytes: &[u8]) -> Result<(), IoApicError> {
    init_legacy_irq(madt_bytes, 1, KEYBOARD_VECTOR)
}

fn init_legacy_irq(madt_bytes: &[u8], legacy_irq: u8, vector: u8) -> Result<(), IoApicError> {
    if legacy_irq >= 32 {
        return Err(IoApicError::NoRoute);
    }
    if !is_device_vector(vector) {
        return Err(IoApicError::InvalidVector);
    }
    let madt = super::acpi::parse_madt_bytes(madt_bytes).ok_or(IoApicError::InvalidMadt)?;
    let overrides = parse_source_overrides(madt_bytes).ok_or(IoApicError::InvalidMadt)?;

    let mut descriptors = [IoApicDescriptor {
        id: 0,
        gsi_base: 0,
        pin_count: 0,
    }; 8];
    let mut bases = [0u64; 8];
    let mut count = 0usize;
    for slot in madt.io_apics.iter().take(madt.io_apic_count) {
        let Some(apic) = slot else {
            continue;
        };
        if count >= descriptors.len() {
            break;
        }
        let base = apic.address as u64;
        map_mmio(base)?;
        let version = read_register(base, 1);
        let pin_count = ((version >> 16) & 0xff).saturating_add(1);
        descriptors[count] = IoApicDescriptor {
            id: apic.id,
            gsi_base: apic.gsi_base,
            pin_count,
        };
        bases[count] = base;
        count += 1;
    }
    if count == 0 {
        return Err(IoApicError::NoController);
    }

    let destination = super::lapic::id();
    let mut vectors = VectorAllocator::new(vector, vector);
    let destination_error = if destination > u8::MAX as u32 {
        IoApicError::UnsupportedDestination
    } else {
        IoApicError::NoRoute
    };
    let (gsi, entry) = entry_for_legacy_irq(legacy_irq, &overrides, &mut vectors, destination)
        .ok_or(destination_error)?;
    let (ioapic_id, pin) = route_gsi(&descriptors[..count], gsi).ok_or(IoApicError::NoRoute)?;
    let index = descriptors[..count]
        .iter()
        .position(|descriptor| descriptor.id == ioapic_id)
        .ok_or(IoApicError::NoRoute)?;

    let masked = entry;
    let unmasked = masked.unmasked();
    write_redirection(bases[index], pin, masked);
    write_redirection(bases[index], pin, unmasked);
    let observed = read_redirection(bases[index], pin);
    if !unmasked.writable_fields_match(&observed) {
        write_redirection(bases[index], pin, masked);
        return Err(IoApicError::Verification);
    }
    ROUTED_LEGACY_IRQS.fetch_or(1u32 << legacy_irq, Ordering::AcqRel);
    Ok(())
}

fn map_mmio(base: u64) -> Result<(), IoApicError> {
    super::paging::map_hhdm_range_flags(
        base,
        0x20,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::NO_EXECUTE,
    )
    .map_err(|_| IoApicError::Mapping)
}

fn read_register(base: u64, register: u32) -> u32 {
    write_index(base, register);
    read_data(base)
}

fn read_redirection(base: u64, pin: u32) -> RedirectionEntry {
    let register = 0x10 + pin.saturating_mul(2);
    let low = read_register(base, register) as u64;
    let high = read_register(base, register + 1) as u64;
    RedirectionEntry::from_bits(low | (high << 32))
}

fn write_redirection(base: u64, pin: u32, entry: RedirectionEntry) {
    let register = 0x10 + pin.saturating_mul(2);
    // Program the high destination half first, while the entry is masked.
    write_index(base, register + 1);
    write_data(base, entry.high());
    write_index(base, register);
    write_data(base, entry.low());
}

fn write_index(base: u64, register: u32) {
    let pointer = (super::paging::phys_to_virt(base).as_u64()) as *mut u32;
    // SAFETY: init mapped the I/O APIC's two-register MMIO window as uncached;
    // the pointer is derived from that fixed physical base and the register
    // offset is the architecturally defined IOREGSEL location.
    unsafe { core::ptr::write_volatile(pointer, register) };
}

fn read_data(base: u64) -> u32 {
    let pointer = (super::paging::phys_to_virt(base + 0x10).as_u64()) as *const u32;
    // SAFETY: init mapped the I/O APIC's IOWIN register as uncached MMIO.
    unsafe { core::ptr::read_volatile(pointer) }
}

fn write_data(base: u64, value: u32) {
    let pointer = (super::paging::phys_to_virt(base + 0x10).as_u64()) as *mut u32;
    // SAFETY: init mapped the I/O APIC's IOWIN register as uncached MMIO.
    unsafe { core::ptr::write_volatile(pointer, value) };
}
