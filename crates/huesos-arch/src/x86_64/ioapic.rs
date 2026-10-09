//! I/O APIC driver and GSI route manager for x86_64.
//!
//! [`huesos_ioapic`] contains the host-tested encodings and routing policy;
//! this module owns privileged MMIO access, controller discovery, route
//! lifetime, vector dispatch, masking, and single-CPU affinity changes. Every
//! redirection entry is masked at initialization. New routes are programmed
//! masked-first, read back, and only then unmasked.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use huesos_abi::{InterruptEventKey, InterruptEventKind};
use huesos_ioapic::{
    entry_for_gsi, is_device_vector, parse_source_overrides,
    route_gsi as select_controller_for_gsi, validate_ioapic_descriptors, DeliveryMode,
    DestinationMode, IoApicDescriptor, PinPolarity, RedirectionEntry, RouteConfig,
    SourceOverrideTable, TriggerMode, VectorAllocator, DEVICE_VECTOR_END, DEVICE_VECTOR_START,
};
use x86_64::structures::paging::PageTableFlags;

use crate::{LockRank, RankedIrqSafeTicketLock};

/// Vector used for the PS/2 keyboard IRQ1 compatibility handler.
///
/// The vector is reserved from the general route allocator because this
/// handler reads port `0x60` and carries the scancode as event data.
pub const KEYBOARD_VECTOR: u8 = 0x31;

const MAX_IOAPICS: usize = 8;
const MAX_ROUTES: usize = (DEVICE_VECTOR_END - DEVICE_VECTOR_START + 1) as usize;
const NO_EVENT: u64 = u64::MAX;
const REDIRECTION_BASE: u32 = 0x10;
const MASK_BIT: u32 = 1 << 16;
const REMOTE_IRR_POLLS: usize = 128;

const fn legacy_event_key(number: u32) -> u64 {
    InterruptEventKey::new(InterruptEventKind::LegacyOrVector, number).raw()
}

const fn gsi_event_key(number: u32) -> u64 {
    InterruptEventKey::new(InterruptEventKind::Gsi, number).raw()
}

static ROUTED_LEGACY_IRQS: AtomicU32 = AtomicU32::new(0);
static KEYBOARD_GSI: AtomicU32 = AtomicU32::new(u32::MAX);
static VECTOR_PRIMARY_EVENT: [AtomicU64; 256] = [const { AtomicU64::new(NO_EVENT) }; 256];
static VECTOR_ALIAS_EVENT: [AtomicU64; 256] = [const { AtomicU64::new(NO_EVENT) }; 256];

/// Failure while discovering or programming an I/O APIC route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoApicError {
    /// No usable I/O APIC was described by MADT.
    NoController,
    /// Firmware table structure or an I/O APIC address was malformed.
    InvalidMadt,
    /// The I/O APIC MMIO range could not be mapped.
    Mapping,
    /// The configured vector is outside the dynamic I/O-APIC range.
    InvalidVector,
    /// No controller owns the requested GSI.
    NoRoute,
    /// The LAPIC destination cannot be represented in the classic 8-bit field.
    UnsupportedDestination,
    /// MMIO readback did not match the programmed redirection entry.
    Verification,
    /// The firmware describes more controllers than the bounded driver can
    /// safely retain.
    TooManyControllers,
    /// Controller GSI ranges overlap, overflow, or reuse an APIC ID.
    InvalidControllerRange,
    /// MADT source-override flags contain reserved encodings.
    InvalidOverrideFlags,
    /// No dynamic interrupt vector or route slot is available.
    NoVector,
    /// The controller manager was initialized more than once.
    AlreadyInitialized,
    /// Routing was requested before controller initialization.
    NotInitialized,
    /// A GSI is already configured with an incompatible route or alias set.
    RouteConflict,
    /// No active route exists for the requested GSI.
    RouteNotFound,
    /// The level-triggered route still has Remote IRR set during affinity change.
    Busy,
    /// The requested destination is not an online CPU.
    DestinationOffline,
    /// A MADT ISA source override names a GSI with no owning I/O APIC pin.
    InvalidSourceOverrideGsi,
}

/// Summary of the I/O APIC controllers initialized from the MADT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoApicSummary {
    /// Number of discovered controllers.
    pub controller_count: usize,
    /// Total number of redirection entries masked at initialization.
    pub pin_count: u32,
}

/// A live I/O APIC route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoApicRoute {
    /// Global System Interrupt number.
    pub gsi: u32,
    /// CPU interrupt vector programmed in the redirection entry.
    pub vector: u8,
    /// Firmware I/O APIC identifier.
    pub controller_id: u8,
    /// Redirection-table input number on `controller_id`.
    pub pin: u32,
    /// Physical destination Local APIC ID.
    pub destination_apic_id: u32,
    /// Signal polarity programmed for the pin.
    pub polarity: PinPolarity,
    /// Trigger mode programmed for the pin.
    pub trigger: TriggerMode,
    /// Whether this route is currently masked.
    pub masked: bool,
}

#[derive(Clone, Copy)]
struct Controller {
    valid: bool,
    id: u8,
    base: u64,
    gsi_base: u32,
    pin_count: u32,
}

impl Controller {
    const EMPTY: Self = Self {
        valid: false,
        id: 0,
        base: 0,
        gsi_base: 0,
        pin_count: 0,
    };
}

#[derive(Clone, Copy)]
struct RouteRecord {
    valid: bool,
    gsi: u32,
    primary_event: u64,
    alias_event: u64,
    vector: u8,
    controller: u8,
    pin: u32,
    entry: RedirectionEntry,
    references: u32,
    permanent: bool,
    in_service: bool,
    pending_acks: u32,
    manually_masked: bool,
}

impl RouteRecord {
    const EMPTY_ENTRY: RedirectionEntry = RedirectionEntry {
        vector: 0,
        delivery_mode: DeliveryMode::Fixed,
        destination_mode: DestinationMode::Physical,
        delivery_status: false,
        pin_polarity: PinPolarity::ActiveHigh,
        remote_irr: false,
        trigger_mode: TriggerMode::Edge,
        masked: true,
        destination: 0,
    };

    const EMPTY: Self = Self {
        valid: false,
        gsi: 0,
        primary_event: NO_EVENT,
        alias_event: NO_EVENT,
        vector: 0,
        controller: 0,
        pin: 0,
        entry: Self::EMPTY_ENTRY,
        references: 0,
        permanent: false,
        in_service: false,
        pending_acks: 0,
        manually_masked: false,
    };
}

#[derive(Clone, Copy)]
struct RouteRequest {
    gsi: u32,
    primary_event: u64,
    alias_event: Option<u64>,
    config: RouteConfig,
    destination_apic_id: u32,
    forced_vector: Option<u8>,
    permanent: bool,
}

struct IoApicState {
    initialized: bool,
    controllers: [Controller; MAX_IOAPICS],
    controller_count: usize,
    pin_count: u32,
    routes: [RouteRecord; MAX_ROUTES],
    overrides: SourceOverrideTable,
    vectors: VectorAllocator,
}

impl IoApicState {
    const fn new() -> Self {
        Self {
            initialized: false,
            controllers: [Controller::EMPTY; MAX_IOAPICS],
            controller_count: 0,
            pin_count: 0,
            routes: [RouteRecord::EMPTY; MAX_ROUTES],
            overrides: SourceOverrideTable::empty(),
            vectors: VectorAllocator::device_default(),
        }
    }
}

type AffinityValidator = fn(u32) -> bool;

static IOAPIC_STATE: RankedIrqSafeTicketLock<IoApicState> =
    RankedIrqSafeTicketLock::new(IoApicState::new(), LockRank::ARCHITECTURE);
static AFFINITY_VALIDATOR: RankedIrqSafeTicketLock<Option<AffinityValidator>> =
    RankedIrqSafeTicketLock::new(None, LockRank::ARCHITECTURE);

/// Install a kernel callback that accepts only APIC IDs of scheduler-online
/// CPUs. Until installed, route changes may target only the current CPU.
pub fn set_affinity_validator(validator: fn(u32) -> bool) {
    *AFFINITY_VALIDATOR.lock() = Some(validator);
}

fn destination_is_online(apic_id: u32) -> bool {
    let validator = *AFFINITY_VALIDATOR.lock();
    match validator {
        Some(validator) => validator(apic_id),
        None => apic_id == super::lapic::id(),
    }
}

/// Whether a legacy PIC IRQ was successfully represented by an I/O APIC route.
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

/// Discover every MADT I/O APIC, map its MMIO window, validate the GSI ranges,
/// and mask every redirection entry before publishing the controller set.
///
/// The call is idempotence-protected and must run on the BSP before device
/// interrupts are enabled. If it fails after masking some entries, all such
/// entries remain masked and the caller may safely retain the PIC fallback.
pub fn initialize(madt_bytes: &[u8]) -> Result<IoApicSummary, IoApicError> {
    let madt = super::acpi::parse_madt_bytes(madt_bytes).ok_or(IoApicError::InvalidMadt)?;
    let overrides = parse_source_overrides(madt_bytes).ok_or(IoApicError::InvalidMadt)?;
    if madt.io_apic_count == 0 {
        return Err(IoApicError::NoController);
    }
    if madt.io_apic_count > MAX_IOAPICS {
        return Err(IoApicError::TooManyControllers);
    }

    // Map first: the page-table lock is also architecture-ranked, so never
    // acquire it while holding IOAPIC_STATE. All later selector/window
    // transactions are serialized by IOAPIC_STATE.
    for apic in madt.io_apics[..madt.io_apic_count].iter().flatten() {
        let base = u64::from(apic.address);
        if base == 0 || base & 0xfff != 0 {
            return Err(IoApicError::InvalidMadt);
        }
        map_mmio(base)?;
    }

    let mut state = IOAPIC_STATE.lock();
    if state.initialized {
        return Err(IoApicError::AlreadyInitialized);
    }

    let mut controllers = [Controller::EMPTY; MAX_IOAPICS];
    let mut descriptors = [IoApicDescriptor {
        id: 0,
        gsi_base: 0,
        pin_count: 0,
    }; MAX_IOAPICS];
    let mut count = 0usize;
    let mut total_pins = 0u32;

    for apic in madt.io_apics[..madt.io_apic_count].iter().flatten() {
        let base = u64::from(apic.address);
        let version = read_register(base, 1);
        let pin_count = ((version >> 16) & 0xff) + 1;
        if count >= MAX_IOAPICS {
            return Err(IoApicError::TooManyControllers);
        }
        controllers[count] = Controller {
            valid: true,
            id: apic.id,
            base,
            gsi_base: apic.gsi_base,
            pin_count,
        };
        descriptors[count] = IoApicDescriptor {
            id: apic.id,
            gsi_base: apic.gsi_base,
            pin_count,
        };
        count += 1;
        total_pins = total_pins.saturating_add(pin_count);
    }

    validate_ioapic_descriptors(&descriptors[..count])
        .map_err(|_| IoApicError::InvalidControllerRange)?;
    if overrides
        .iter()
        .any(|entry| huesos_ioapic::route_gsi(&descriptors[..count], entry.gsi).is_none())
    {
        return Err(IoApicError::InvalidSourceOverrideGsi);
    }

    // Mask before publishing. Read the existing low word and only set the
    // mask bit, preserving firmware's remaining fields until the route is
    // explicitly replaced. Never trust firmware to have left pins disabled.
    for controller in controllers[..count].iter().copied() {
        let mut pin = 0u32;
        while pin < controller.pin_count {
            let low_reg = redirection_low_register(pin)?;
            let low = read_register(controller.base, low_reg);
            write_register(controller.base, low_reg, low | MASK_BIT);
            if read_register(controller.base, low_reg) & MASK_BIT == 0 {
                return Err(IoApicError::Verification);
            }
            pin += 1;
        }
    }

    let mut vectors = VectorAllocator::device_default();
    if !vectors.reserve(KEYBOARD_VECTOR) {
        return Err(IoApicError::InvalidVector);
    }

    state.controllers = controllers;
    state.controller_count = count;
    state.pin_count = total_pins;
    state.routes = [RouteRecord::EMPTY; MAX_ROUTES];
    state.overrides = overrides;
    state.vectors = vectors;
    state.initialized = true;

    Ok(IoApicSummary {
        controller_count: count,
        pin_count: total_pins,
    })
}

/// Initialize the complete I/O APIC controller set and install the PS/2
/// keyboard's fixed-vector compatibility route. The 8259 PIC remains available
/// until [`keyboard_routed`] confirms readback of this route.
pub fn init_keyboard(madt_bytes: &[u8]) -> Result<(), IoApicError> {
    let _summary = initialize(madt_bytes)?;
    let mut state = IOAPIC_STATE.lock();
    let irq = 1u8;
    let gsi = state.overrides.resolve_gsi(irq);
    let config = state
        .overrides
        .config_for_legacy_irq(irq)
        .ok_or(IoApicError::InvalidOverrideFlags)?;
    let alias = (gsi != u32::from(irq)).then_some(gsi_event_key(gsi));
    let destination = super::lapic::id();
    let route = route_locked(
        &mut state,
        RouteRequest {
            gsi,
            primary_event: legacy_event_key(u32::from(irq)),
            alias_event: alias,
            config,
            destination_apic_id: destination,
            forced_vector: Some(KEYBOARD_VECTOR),
            permanent: true,
        },
    )?;
    KEYBOARD_GSI.store(route.gsi, Ordering::Release);
    ROUTED_LEGACY_IRQS.fetch_or(1u32 << irq, Ordering::AcqRel);
    Ok(())
}

/// Acquire and unmask a legacy ISA route, applying any MADT source override.
/// The returned route is reference-counted and is masked/released when its last
/// interrupt object is dropped.
pub fn route_legacy_irq(irq: u8) -> Result<IoApicRoute, IoApicError> {
    if irq >= 16 {
        return Err(IoApicError::NoRoute);
    }
    let mut state = IOAPIC_STATE.lock();
    if !state.initialized {
        return Err(IoApicError::NotInitialized);
    }
    let gsi = state.overrides.resolve_gsi(irq);
    let config = state
        .overrides
        .config_for_legacy_irq(irq)
        .ok_or(IoApicError::InvalidOverrideFlags)?;
    let alias = (gsi != u32::from(irq)).then_some(gsi_event_key(gsi));
    route_locked(
        &mut state,
        RouteRequest {
            gsi,
            primary_event: legacy_event_key(u32::from(irq)),
            alias_event: alias,
            config,
            destination_apic_id: super::lapic::id(),
            forced_vector: None,
            permanent: false,
        },
    )
}

/// Acquire and unmask a route for an arbitrary GSI with explicitly supplied
/// polarity and trigger mode. Use [`RouteConfig::pci_intx_default`] only when
/// firmware/PCI routing data does not provide a more precise configuration.
pub fn route_gsi(
    gsi: u32,
    config: RouteConfig,
    destination_apic_id: u32,
) -> Result<IoApicRoute, IoApicError> {
    let mut state = IOAPIC_STATE.lock();
    if !state.initialized {
        return Err(IoApicError::NotInitialized);
    }
    let alias = state
        .overrides
        .find_gsi(gsi)
        .filter(|entry| entry.bus == 0)
        .map(|entry| legacy_event_key(u32::from(entry.source)));
    if let Some(override_entry) = state
        .overrides
        .find_gsi(gsi)
        .filter(|override_entry| override_entry.bus == 0)
    {
        let firmware_config = override_entry
            .config()
            .ok_or(IoApicError::InvalidOverrideFlags)?;
        if firmware_config != config {
            return Err(IoApicError::RouteConflict);
        }
    }
    route_locked(
        &mut state,
        RouteRequest {
            gsi,
            primary_event: gsi_event_key(gsi),
            alias_event: alias,
            config,
            destination_apic_id,
            forced_vector: None,
            permanent: false,
        },
    )
}

/// Acquire a legacy IRQ or already-routed MSI vector for an interrupt object.
/// ISA IRQs `0..15` use MADT overrides. The MSI-X/MSI vector range
/// (`0xD0..=0xDF`) is already wired by the PCI path and needs no I/O APIC route.
/// Other numeric values are rejected; raw GSIs must use the explicitly typed
/// [`acquire_gsi_interrupt_route`] path.
pub fn acquire_interrupt_route(irq_or_vector: u32) -> Option<bool> {
    if (0xD0..=0xDF).contains(&irq_or_vector) {
        return Some(false);
    }
    if irq_or_vector >= 16 {
        return None;
    }
    route_legacy_irq(irq_or_vector as u8)
        .ok()
        .map(|route| route.trigger == TriggerMode::Level && route.vector != KEYBOARD_VECTOR)
}

/// Acquire an explicitly typed raw GSI route for an interrupt object. MADT
/// source-override flags are used when the GSI is an ISA alias; otherwise PCI
/// INTx electrical defaults are used until ACPI `_PRT`/link routing is wired.
pub fn acquire_gsi_interrupt_route(gsi: u32) -> Option<bool> {
    let config = {
        let state = IOAPIC_STATE.lock();
        if !state.initialized {
            return None;
        }
        match state.overrides.find_gsi(gsi).filter(|entry| entry.bus == 0) {
            Some(entry) => entry.config()?,
            None if gsi < 16 => RouteConfig::isa_default(),
            None => RouteConfig::pci_intx_default(),
        }
    };
    route_gsi(gsi, config, super::lapic::id())
        .ok()
        .map(|route| route.trigger == TriggerMode::Level && route.vector != KEYBOARD_VECTOR)
}

/// Release one interrupt-object reference to a legacy/GSI route. MSI vectors
/// do not own an I/O APIC route and are ignored.
pub fn release_interrupt_route(irq_or_vector: u32) {
    if irq_or_vector < 16 {
        release_route_key(irq_or_vector, true);
    }
}

/// Release one interrupt-object reference to an explicitly typed raw GSI.
pub fn release_gsi_interrupt_route(gsi: u32) {
    release_route_key(gsi, false);
}

/// Complete one userspace service cycle for a legacy IRQ or MSI vector. Edge
/// routes and MSI vectors need no I/O-APIC unmask operation.
pub fn acknowledge_interrupt_route(irq_or_vector: u32) -> Result<(), IoApicError> {
    if (0xD0..=0xDF).contains(&irq_or_vector) {
        return Ok(());
    }
    if irq_or_vector >= 16 {
        return Err(IoApicError::RouteNotFound);
    }
    acknowledge_route_key(irq_or_vector, true)
}

/// Complete one userspace service cycle for an explicitly typed GSI.
pub fn acknowledge_gsi_interrupt_route(gsi: u32) -> Result<(), IoApicError> {
    acknowledge_route_key(gsi, false)
}

fn acknowledge_route_key(key: u32, legacy_source: bool) -> Result<(), IoApicError> {
    let mut state = IOAPIC_STATE.lock();
    if !state.initialized {
        return Err(IoApicError::NotInitialized);
    }
    let gsi = if legacy_source {
        state.overrides.resolve_gsi(key as u8)
    } else {
        key
    };
    let route_index = find_route_index(&state, gsi).ok_or(IoApicError::RouteNotFound)?;
    let mut route = state.routes[route_index];
    if route.permanent || route.entry.trigger_mode != TriggerMode::Level || !route.in_service {
        return Ok(());
    }
    if route.pending_acks == 0 {
        return Ok(());
    }
    route.pending_acks -= 1;
    if route.pending_acks != 0 {
        state.routes[route_index] = route;
        return Ok(());
    }
    if route.manually_masked {
        route.in_service = false;
        state.routes[route_index] = route;
        return Ok(());
    }

    route.entry.masked = false;
    if let Err(error) = write_low_word(&state, route, route.entry.low()) {
        route.entry.masked = true;
        route.pending_acks = 1;
        let _ = mask_record(&state, route);
        state.routes[route_index] = route;
        return Err(error);
    }
    let observed = match read_route(&state, route) {
        Ok(observed) => observed,
        Err(error) => {
            route.entry.masked = true;
            route.pending_acks = 1;
            let _ = mask_record(&state, route);
            state.routes[route_index] = route;
            return Err(error);
        }
    };
    if !route.entry.writable_fields_match(&observed) || observed.masked {
        route.entry.masked = true;
        route.pending_acks = 1;
        let _ = mask_record(&state, route);
        state.routes[route_index] = route;
        return Err(IoApicError::Verification);
    }
    route.in_service = false;
    state.routes[route_index] = route;
    Ok(())
}

fn release_route_key(key: u32, legacy_source: bool) {
    let mut state = IOAPIC_STATE.lock();
    if !state.initialized {
        return;
    }
    let gsi = if legacy_source {
        state.overrides.resolve_gsi(key as u8)
    } else {
        key
    };
    let Some(route_index) = state.routes[..MAX_ROUTES]
        .iter()
        .position(|route| route.valid && route.gsi == gsi)
    else {
        return;
    };
    let mut route = state.routes[route_index];
    if route.permanent {
        return;
    }
    if route.references > 1 {
        state.routes[route_index].references -= 1;
        return;
    }

    if mask_record(&state, route).is_err() {
        // Leaking a masked-policy decision (and its vector) is safer than
        // reusing a vector whose hardware entry we could not prove disabled.
        route.entry.masked = true;
        route.manually_masked = true;
        route.references = 1;
        state.routes[route_index] = route;
        return;
    }
    clear_vector_events(route.vector);
    let _ = state.vectors.free(route.vector);
    state.routes[route_index] = RouteRecord::EMPTY;
}

/// Mask an active GSI route without releasing its vector or route lease.
pub fn mask_gsi(gsi: u32) -> Result<(), IoApicError> {
    let mut state = IOAPIC_STATE.lock();
    if !state.initialized {
        return Err(IoApicError::NotInitialized);
    }
    let route_index = find_route_index(&state, gsi).ok_or(IoApicError::RouteNotFound)?;
    let mut route = state.routes[route_index];
    route.manually_masked = true;
    route.entry.masked = true;
    state.routes[route_index] = route;
    write_low_word(&state, route, route.entry.low())?;
    let observed = read_route(&state, route)?;
    if !route.entry.writable_fields_match(&observed) || !observed.masked {
        return Err(IoApicError::Verification);
    }
    Ok(())
}

/// Unmask an already configured GSI route.
pub fn unmask_gsi(gsi: u32) -> Result<(), IoApicError> {
    let mut state = IOAPIC_STATE.lock();
    if !state.initialized {
        return Err(IoApicError::NotInitialized);
    }
    let route_index = find_route_index(&state, gsi).ok_or(IoApicError::RouteNotFound)?;
    let original = state.routes[route_index];
    if original.in_service && original.entry.trigger_mode == TriggerMode::Level {
        return Err(IoApicError::Busy);
    }
    let mut route = original;
    route.manually_masked = false;
    route.entry.masked = false;
    if let Err(error) = write_low_word(&state, route, route.entry.low()) {
        let mut safe = original;
        safe.manually_masked = true;
        safe.entry.masked = true;
        let _ = mask_record(&state, safe);
        state.routes[route_index] = safe;
        return Err(error);
    }
    let observed = match read_route(&state, route) {
        Ok(observed) => observed,
        Err(error) => {
            let mut safe = original;
            safe.manually_masked = true;
            safe.entry.masked = true;
            let _ = mask_record(&state, safe);
            state.routes[route_index] = safe;
            return Err(error);
        }
    };
    if !route.entry.writable_fields_match(&observed) || observed.masked {
        let mut safe = original;
        safe.manually_masked = true;
        safe.entry.masked = true;
        let _ = mask_record(&state, safe);
        state.routes[route_index] = safe;
        return Err(IoApicError::Verification);
    }
    state.routes[route_index] = route;
    Ok(())
}

/// Move a GSI to another physical Local APIC destination. This operation
/// masks the input first, waits a bounded time for level-triggered Remote IRR
/// to clear, changes the destination while masked, verifies readback, then
/// restores the previous mask state. Destinations above 255 are rejected; I/O
/// APIC interrupt remapping is not implemented.
pub fn set_affinity(gsi: u32, destination_apic_id: u32) -> Result<(), IoApicError> {
    let destination = huesos_ioapic::ioapic_physical_destination(destination_apic_id)
        .ok_or(IoApicError::UnsupportedDestination)?;
    if !destination_is_online(destination_apic_id) {
        return Err(IoApicError::DestinationOffline);
    }
    let mut state = IOAPIC_STATE.lock();
    if !state.initialized {
        return Err(IoApicError::NotInitialized);
    }
    let route_index = find_route_index(&state, gsi).ok_or(IoApicError::RouteNotFound)?;
    let mut route = state.routes[route_index];
    let was_masked = route.entry.masked;
    route.entry.masked = true;
    state.routes[route_index] = route;
    write_low_word(&state, route, route.entry.low())?;
    let masked_observed = read_route(&state, route)?;
    if !route.entry.writable_fields_match(&masked_observed) || !masked_observed.masked {
        return Err(IoApicError::Verification);
    }

    if route.entry.trigger_mode == TriggerMode::Level {
        let mut clear = false;
        for _ in 0..REMOTE_IRR_POLLS {
            if !read_route(&state, route)?.remote_irr {
                clear = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !clear {
            if !was_masked && !route.manually_masked {
                let mut restore = route;
                restore.entry.masked = false;
                if write_low_word(&state, restore, restore.entry.low()).is_ok()
                    && read_route(&state, restore).is_ok_and(|observed| {
                        restore.entry.writable_fields_match(&observed) && !observed.masked
                    })
                {
                    state.routes[route_index] = restore;
                } else {
                    route.manually_masked = true;
                    let _ = mask_record(&state, route);
                    state.routes[route_index] = route;
                }
            }
            return Err(IoApicError::Busy);
        }
    }

    route.entry.destination = destination;
    route.entry.masked = true;
    state.routes[route_index] = route;
    if let Err(error) = install_redirection_masked(&state, route, route.entry) {
        let _ = mask_record(&state, route);
        state.routes[route_index] = route;
        return Err(error);
    }
    let masked_observed = match read_route(&state, route) {
        Ok(observed) => observed,
        Err(error) => {
            let _ = mask_record(&state, route);
            state.routes[route_index] = route;
            return Err(error);
        }
    };
    if !route.entry.writable_fields_match(&masked_observed) || !masked_observed.masked {
        let _ = mask_record(&state, route);
        state.routes[route_index] = route;
        return Err(IoApicError::Verification);
    }

    route.entry.masked = was_masked || route.manually_masked;
    if let Err(error) = write_low_word(&state, route, route.entry.low()) {
        route.entry.masked = true;
        let _ = mask_record(&state, route);
        state.routes[route_index] = route;
        return Err(error);
    }
    let observed = match read_route(&state, route) {
        Ok(observed) => observed,
        Err(error) => {
            route.entry.masked = true;
            let _ = mask_record(&state, route);
            state.routes[route_index] = route;
            return Err(error);
        }
    };
    if !route.entry.writable_fields_match(&observed) {
        route.entry.masked = true;
        let _ = mask_record(&state, route);
        state.routes[route_index] = route;
        return Err(IoApicError::Verification);
    }
    state.routes[route_index] = route;
    Ok(())
}

/// Return the current route for `gsi`, if one is installed.
pub fn route_info(gsi: u32) -> Option<IoApicRoute> {
    let state = IOAPIC_STATE.lock();
    let route_index = find_route_index(&state, gsi)?;
    Some(public_route(&state, state.routes[route_index]))
}

/// Mask an arriving level-triggered route before local-APIC EOI and mark it
/// as awaiting one userspace acknowledgement. Permanent kernel-owned routes
/// (currently the PS/2 keyboard) are serviced by their dedicated handler.
pub fn begin_interrupt(vector: u8) -> Result<(), IoApicError> {
    let mut state = IOAPIC_STATE.lock();
    if !state.initialized {
        return Err(IoApicError::NotInitialized);
    }
    let Some(route_index) = state.routes[..MAX_ROUTES]
        .iter()
        .position(|route| route.valid && route.vector == vector)
    else {
        return Ok(());
    };
    let mut route = state.routes[route_index];
    if route.permanent || route.entry.trigger_mode != TriggerMode::Level || route.in_service {
        return Ok(());
    }
    route.entry.masked = true;
    if let Err(error) = mask_record(&state, route) {
        route.in_service = true;
        route.pending_acks = route.references;
        state.routes[route_index] = route;
        return Err(error);
    }
    route.in_service = true;
    route.pending_acks = route.references;
    state.routes[route_index] = route;
    Ok(())
}

/// Dispatch an external interrupt vector to its registered event key(s).
/// The generic IDT stub calls this only after level routes were masked and LAPIC
/// EOI completed; event publication itself is lock-free.
pub fn dispatch_vector(vector: u8) {
    dispatch_vector_with_data(vector, 0);
}

/// Dispatch an external interrupt vector with device event data.
/// The keyboard IDT shim uses this to preserve its scancode payload while also
/// supporting the GSI alias declared by MADT.
pub fn dispatch_vector_with_data(vector: u8, data: u64) {
    let primary = VECTOR_PRIMARY_EVENT[vector as usize].load(Ordering::Acquire);
    if primary == NO_EVENT {
        return;
    }
    crate::x86_64::irq_callback::emit(primary, data);
    let alias = VECTOR_ALIAS_EVENT[vector as usize].load(Ordering::Acquire);
    if alias != NO_EVENT && alias != primary {
        crate::x86_64::irq_callback::emit(alias, data);
    }
}

fn route_locked(
    state: &mut IoApicState,
    request: RouteRequest,
) -> Result<IoApicRoute, IoApicError> {
    let RouteRequest {
        gsi,
        primary_event,
        alias_event,
        config,
        destination_apic_id,
        forced_vector,
        permanent,
    } = request;
    if !state.initialized {
        return Err(IoApicError::NotInitialized);
    }
    let destination = huesos_ioapic::ioapic_physical_destination(destination_apic_id)
        .ok_or(IoApicError::UnsupportedDestination)?;
    if !destination_is_online(destination_apic_id) {
        return Err(IoApicError::DestinationOffline);
    }
    let (controller_index, pin) = controller_for_gsi(state, gsi).ok_or(IoApicError::NoRoute)?;

    if let Some(existing_index) = find_route_index(state, gsi) {
        let mut existing = state.routes[existing_index];
        if existing.entry.pin_polarity != config.polarity
            || existing.entry.trigger_mode != config.trigger
            || existing.entry.destination != destination
        {
            return Err(IoApicError::RouteConflict);
        }
        if !existing.permanent
            && !permanent
            && config.trigger == TriggerMode::Level
            && existing.references != 0
        {
            // A level-triggered route needs one unambiguous userspace owner so
            // one ACK cannot re-enable the line while another driver is still
            // servicing the same device.
            return Err(IoApicError::RouteConflict);
        }
        let observed = read_route(state, existing)?;
        if !existing.entry.writable_fields_match(&observed) {
            return Err(IoApicError::Verification);
        }
        add_event_key(&mut existing, primary_event)?;
        if let Some(alias) = alias_event {
            add_event_key(&mut existing, alias)?;
        }
        if !existing.permanent && !permanent {
            existing.references = existing
                .references
                .checked_add(1)
                .ok_or(IoApicError::RouteConflict)?;
        }
        publish_vector_events(
            existing.vector,
            existing.primary_event,
            existing.alias_event,
        );
        state.routes[existing_index] = existing;
        return Ok(public_route(state, existing));
    }

    let route_index = state
        .routes
        .iter()
        .position(|route| !route.valid)
        .ok_or(IoApicError::NoVector)?;
    let vector = if let Some(vector) = forced_vector {
        if !is_device_vector(vector)
            || state
                .routes
                .iter()
                .any(|route| route.valid && route.vector == vector)
        {
            return Err(IoApicError::InvalidVector);
        }
        vector
    } else {
        state.vectors.allocate().ok_or(IoApicError::NoVector)?
    };

    let entry = match entry_for_gsi(config, vector, destination_apic_id) {
        Some(entry) => entry,
        None => {
            if forced_vector.is_none() {
                let _ = state.vectors.free(vector);
            }
            return Err(if !is_device_vector(vector) {
                IoApicError::InvalidVector
            } else {
                IoApicError::UnsupportedDestination
            });
        }
    };
    let mut record = RouteRecord {
        valid: true,
        gsi,
        primary_event,
        alias_event: alias_event.unwrap_or(NO_EVENT),
        vector,
        controller: controller_index as u8,
        pin,
        entry,
        references: if permanent { 0 } else { 1 },
        permanent,
        in_service: false,
        pending_acks: 0,
        manually_masked: false,
    };

    publish_vector_events(record.vector, record.primary_event, record.alias_event);
    if let Err(error) = install_redirection_masked(state, record, record.entry) {
        if mask_record(state, record).is_ok() {
            clear_vector_events(record.vector);
            if forced_vector.is_none() {
                let _ = state.vectors.free(record.vector);
            }
        } else {
            // Do not recycle a vector while the hardware's mask state is
            // uncertain. Retain the mapping so a stray delivery remains safe.
            state.routes[route_index] = record;
        }
        return Err(error);
    }
    let masked_observed = match read_route(state, record) {
        Ok(observed) => observed,
        Err(error) => {
            if mask_record(state, record).is_ok() {
                clear_vector_events(record.vector);
                if forced_vector.is_none() {
                    let _ = state.vectors.free(record.vector);
                }
            } else {
                state.routes[route_index] = record;
            }
            return Err(error);
        }
    };
    if !record.entry.writable_fields_match(&masked_observed) || !masked_observed.masked {
        if mask_record(state, record).is_ok() {
            clear_vector_events(record.vector);
            if forced_vector.is_none() {
                let _ = state.vectors.free(record.vector);
            }
        } else {
            state.routes[route_index] = record;
        }
        return Err(IoApicError::Verification);
    }

    // Publish route metadata before unmasking. The vector stub needs only the
    // atomic event mapping, but this ordering keeps every management query
    // coherent if the destination CPU takes the interrupt immediately.
    state.routes[route_index] = record;
    record.entry.masked = false;
    if let Err(error) = write_low_word(state, record, record.entry.low()) {
        let mut masked_record = record;
        masked_record.entry.masked = true;
        if mask_record(state, masked_record).is_ok() {
            clear_vector_events(record.vector);
            state.routes[route_index] = RouteRecord::EMPTY;
            if forced_vector.is_none() {
                let _ = state.vectors.free(record.vector);
            }
        } else {
            state.routes[route_index] = masked_record;
        }
        return Err(error);
    }
    let observed = match read_route(state, record) {
        Ok(observed) => observed,
        Err(error) => {
            let mut masked_record = record;
            masked_record.entry.masked = true;
            if mask_record(state, masked_record).is_ok() {
                clear_vector_events(record.vector);
                state.routes[route_index] = RouteRecord::EMPTY;
                if forced_vector.is_none() {
                    let _ = state.vectors.free(record.vector);
                }
            } else {
                state.routes[route_index] = masked_record;
            }
            return Err(error);
        }
    };
    if !record.entry.writable_fields_match(&observed) || observed.masked {
        let mut masked_record = record;
        masked_record.entry.masked = true;
        if mask_record(state, masked_record).is_ok() {
            clear_vector_events(record.vector);
            state.routes[route_index] = RouteRecord::EMPTY;
            if forced_vector.is_none() {
                let _ = state.vectors.free(record.vector);
            }
        } else {
            state.routes[route_index] = masked_record;
        }
        return Err(IoApicError::Verification);
    }
    state.routes[route_index] = record;
    Ok(public_route(state, record))
}

fn add_event_key(route: &mut RouteRecord, event: u64) -> Result<(), IoApicError> {
    if event == route.primary_event || event == route.alias_event {
        return Ok(());
    }
    if route.alias_event == NO_EVENT {
        route.alias_event = event;
        return Ok(());
    }
    Err(IoApicError::RouteConflict)
}

fn controller_for_gsi(state: &IoApicState, gsi: u32) -> Option<(usize, u32)> {
    let mut descriptors = [IoApicDescriptor {
        id: 0,
        gsi_base: 0,
        pin_count: 0,
    }; MAX_IOAPICS];
    for (index, controller) in state.controllers[..state.controller_count]
        .iter()
        .copied()
        .enumerate()
    {
        descriptors[index] = IoApicDescriptor {
            id: controller.id,
            gsi_base: controller.gsi_base,
            pin_count: controller.pin_count,
        };
    }
    let (id, pin) = select_controller_for_gsi(&descriptors[..state.controller_count], gsi)?;
    let index = state.controllers[..state.controller_count]
        .iter()
        .position(|controller| controller.valid && controller.id == id)?;
    Some((index, pin))
}

fn find_route_index(state: &IoApicState, gsi: u32) -> Option<usize> {
    state
        .routes
        .iter()
        .position(|route| route.valid && route.gsi == gsi)
}

fn public_route(state: &IoApicState, route: RouteRecord) -> IoApicRoute {
    let controller = state.controllers[route.controller as usize];
    IoApicRoute {
        gsi: route.gsi,
        vector: route.vector,
        controller_id: controller.id,
        pin: route.pin,
        destination_apic_id: u32::from(route.entry.destination),
        polarity: route.entry.pin_polarity,
        trigger: route.entry.trigger_mode,
        masked: route.entry.masked,
    }
}

fn publish_vector_events(vector: u8, primary: u64, alias: u64) {
    VECTOR_ALIAS_EVENT[vector as usize].store(alias, Ordering::Relaxed);
    VECTOR_PRIMARY_EVENT[vector as usize].store(primary, Ordering::Release);
}

fn clear_vector_events(vector: u8) {
    VECTOR_PRIMARY_EVENT[vector as usize].store(NO_EVENT, Ordering::Release);
    VECTOR_ALIAS_EVENT[vector as usize].store(NO_EVENT, Ordering::Relaxed);
}

fn redirection_low_register(pin: u32) -> Result<u32, IoApicError> {
    pin.checked_mul(2)
        .and_then(|offset| REDIRECTION_BASE.checked_add(offset))
        .ok_or(IoApicError::InvalidMadt)
}

fn controller_for_route(
    state: &IoApicState,
    route: RouteRecord,
) -> Result<Controller, IoApicError> {
    state
        .controllers
        .get(route.controller as usize)
        .copied()
        .filter(|controller| controller.valid)
        .ok_or(IoApicError::RouteNotFound)
}

fn read_route(state: &IoApicState, route: RouteRecord) -> Result<RedirectionEntry, IoApicError> {
    let controller = controller_for_route(state, route)?;
    Ok(read_redirection(controller.base, route.pin))
}

fn write_low_word(state: &IoApicState, route: RouteRecord, low: u32) -> Result<(), IoApicError> {
    let controller = controller_for_route(state, route)?;
    write_register(controller.base, redirection_low_register(route.pin)?, low);
    Ok(())
}

fn install_redirection_masked(
    state: &IoApicState,
    route: RouteRecord,
    entry: RedirectionEntry,
) -> Result<(), IoApicError> {
    if !entry.masked {
        return Err(IoApicError::InvalidVector);
    }
    let controller = controller_for_route(state, route)?;
    let low_reg = redirection_low_register(route.pin)?;
    let high_reg = low_reg.checked_add(1).ok_or(IoApicError::InvalidMadt)?;

    // First mask the old route using its current low word. Only while the
    // input is known masked do we change destination/vector/polarity/trigger.
    let old_low = read_register(controller.base, low_reg);
    write_register(controller.base, low_reg, old_low | MASK_BIT);
    if read_register(controller.base, low_reg) & MASK_BIT == 0 {
        return Err(IoApicError::Verification);
    }
    write_register(controller.base, high_reg, entry.high());
    write_register(controller.base, low_reg, entry.low() | MASK_BIT);
    Ok(())
}

fn mask_record(state: &IoApicState, mut route: RouteRecord) -> Result<(), IoApicError> {
    route.entry.masked = true;
    let low_reg = redirection_low_register(route.pin)?;
    let controller = controller_for_route(state, route)?;
    let low = read_register(controller.base, low_reg);
    write_register(controller.base, low_reg, low | MASK_BIT);
    let observed = read_redirection(controller.base, route.pin);
    if !route.entry.writable_fields_match(&observed) || !observed.masked {
        return Err(IoApicError::Verification);
    }
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

fn write_register(base: u64, register: u32, value: u32) {
    write_index(base, register);
    write_data(base, value);
}

fn read_redirection(base: u64, pin: u32) -> RedirectionEntry {
    let register = REDIRECTION_BASE + pin * 2;
    let low = read_register(base, register) as u64;
    let high = read_register(base, register + 1) as u64;
    RedirectionEntry::from_bits(low | (high << 32))
}

fn write_index(base: u64, register: u32) {
    let pointer = (super::paging::phys_to_virt(base).as_u64()) as *mut u32;
    // SAFETY: `initialize` mapped the I/O APIC's IOREGSEL MMIO word as
    // uncached. The pointer is derived from the MADT physical base and the
    // register is serialized by `IOAPIC_STATE`.
    unsafe { core::ptr::write_volatile(pointer, register) };
}

fn read_data(base: u64) -> u32 {
    let pointer = (super::paging::phys_to_virt(base + 0x10).as_u64()) as *const u32;
    // SAFETY: `initialize` mapped IOWIN as uncached and the selector/window
    // transaction is serialized by `IOAPIC_STATE`.
    unsafe { core::ptr::read_volatile(pointer) }
}

fn write_data(base: u64, value: u32) {
    let pointer = (super::paging::phys_to_virt(base + 0x10).as_u64()) as *mut u32;
    // SAFETY: `initialize` mapped IOWIN as uncached and the selector/window
    // transaction is serialized by `IOAPIC_STATE`.
    unsafe { core::ptr::write_volatile(pointer, value) };
}
