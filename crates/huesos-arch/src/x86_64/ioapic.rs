//! Minimal I/O APIC routing for the legacy keyboard IRQ.
//!
//! Policy decisions and codecs live in `huesos-ioapic`; this module owns only
//! the privileged MMIO mapping and register-pair writes. The first integrated
//! device is ISA IRQ1, routed to a fixed vector before interrupts are enabled.

use core::sync::atomic::{AtomicBool, Ordering};
use huesos_ioapic::{
    entry_for_legacy_irq, parse_source_overrides, route_gsi, IoApicDescriptor,
    RedirectionEntry, VectorAllocator,
};
use x86_64::structures::paging::PageTableFlags;

/// Vector used for the I/O APIC keyboard route.
pub const KEYBOARD_VECTOR: u8 = 0x31;

static KEYBOARD_ROUTED: AtomicBool = AtomicBool::new(false);

/// Failure while configuring the integrated I/O APIC keyboard route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoApicError {
    /// No usable I/O APIC was described by MADT.
    NoController,
    /// Firmware table structure was malformed.
    InvalidMadt,
    /// The I/O APIC MMIO range could not be mapped.
    Mapping,
    /// No vector or GSI route was available.
    NoRoute,
}

/// Whether IRQ1 was successfully routed through an I/O APIC.
pub fn keyboard_routed() -> bool {
    KEYBOARD_ROUTED.load(Ordering::Acquire)
}

/// Configure the I/O APIC redirection entry for ISA IRQ1.
///
/// The entry is programmed masked-first and is unmasked only after both
/// 32-bit halves have been written. The function runs once on the BSP before
/// `STI`; all later keyboard events use the existing userspace IRQ bridge.
pub fn init_keyboard(madt_bytes: &[u8]) -> Result<(), IoApicError> {
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

    let overrides = overrides;
    let mut vectors = VectorAllocator::new(KEYBOARD_VECTOR, KEYBOARD_VECTOR);
    let (gsi, entry) = entry_for_legacy_irq(
        1,
        &overrides,
        &mut vectors,
        super::lapic::id() as u8,
    )
    .ok_or(IoApicError::NoRoute)?;
    let (ioapic_id, pin) = route_gsi(&descriptors[..count], gsi).ok_or(IoApicError::NoRoute)?;
    let index = descriptors[..count]
        .iter()
        .position(|descriptor| descriptor.id == ioapic_id)
        .ok_or(IoApicError::NoRoute)?;

    let masked = entry;
    write_redirection(bases[index], pin, masked);
    write_redirection(bases[index], pin, masked.unmasked());
    KEYBOARD_ROUTED.store(true, Ordering::Release);
    Ok(())
}

fn map_mmio(base: u64) -> Result<(), IoApicError> {
    super::paging::map_hhdm_range_flags(
        base,
        0x20,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE,
    )
    .map_err(|_| IoApicError::Mapping)
}

fn read_register(base: u64, register: u32) -> u32 {
    write_index(base, register);
    read_data(base)
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

