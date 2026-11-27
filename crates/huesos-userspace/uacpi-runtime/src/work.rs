//! Userspace SCI delivery, uACPI work-generation state, and hotplug forwarding.
//!
//! The kernel IRQ bridge queues an SCI packet on a userspace `Port`; this
//! module never executes firmware code from interrupt context. The ACPI manager
//! drains the port, calls the C uACPI SCI dispatcher, and acknowledges the
//! level-triggered interrupt only after uACPI has cleared/enabled the GPE.
//! Deferred GPE and Notify callbacks are drained by the pinned C host shim so
//! Rust does not need to call an opaque C function pointer.

use core::ffi::c_void;
use spin::Mutex;

use crate::primitives::store_scalar;
use huesos_abi::pci_hotplug::{acpi_notify_kind, HotplugWireEvent};
use huesos_abi::{PortPacket, PORT_PACKET_INTERRUPT};
use libcanvas::{Channel, Handle, Interrupt, Port};

const UACPI_STATUS_OK: i32 = 0;
const UACPI_STATUS_INVALID_ARGUMENT: i32 = 7;
const UACPI_STATUS_DENIED: i32 = 20;
const UACPI_STATUS_INTERNAL_ERROR: i32 = 10;
const MAX_IRQ_HANDLERS: usize = 8;
const SCI_PORT_KEY: u64 = 0x5343_4900;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IrqSlot {
    gsi: u32,
    generation: u64,
}

struct WorkState {
    generation: u64,
    irqs: [Option<IrqSlot>; MAX_IRQ_HANDLERS],
}

impl WorkState {
    const fn new() -> Self {
        Self {
            generation: 1,
            irqs: [None; MAX_IRQ_HANDLERS],
        }
    }
}

struct SciEndpoint {
    resource: Handle,
    port: Port,
    interrupt: Option<Interrupt>,
    gsi: Option<u32>,
}

/// Fixed-layout identity produced by the C uACPI namespace walker.
///
/// The record crosses only the C ABI; the Rust side still validates every
/// range and Notify classification before constructing the 40-byte channel
/// event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AcpiHotplugTarget {
    /// Root, bridge-port, or function discriminator.
    pub kind: u32,
    /// Segment of the target and root.
    pub segment: u16,
    /// Target bus.
    pub bus: u8,
    /// Target device.
    pub device: u8,
    /// Target function.
    pub function: u8,
    /// C-side mapping success marker.
    pub valid: u8,
    /// Segment from the resolved PNP0A03/08 ancestor.
    pub root_segment: u16,
    /// Root bus range from `_BBN`/`_CRS`.
    pub root_start_bus: u8,
    /// Root bus range end from `_CRS`.
    pub root_end_bus: u8,
}

struct HotplugEndpoint {
    channel: Channel,
    snapshot_id: u64,
}

static WORK_STATE: Mutex<WorkState> = Mutex::new(WorkState::new());
static SCI_ENDPOINT: Mutex<Option<SciEndpoint>> = Mutex::new(None);
static HOTPLUG_CHANNEL: Mutex<Option<HotplugEndpoint>> = Mutex::new(None);

/// Install the kernel-minted FADT SCI resource and create the private Port
/// that will receive the real interrupt packets.
pub fn install_sci_irq(resource: Handle) -> bool {
    let Ok(port) = Port::create() else {
        return false;
    };
    let mut state = SCI_ENDPOINT.lock();
    if state.is_some() {
        return false;
    }
    *state = Some(SciEndpoint {
        resource,
        port,
        interrupt: None,
        gsi: None,
    });
    true
}

/// Install the private ACPI-manager to PCI-manager event endpoint and bind it
/// to the immutable ACPI archive snapshot used for root identity derivation.
pub fn install_hotplug_channel(channel: Channel, snapshot_id: u64) -> bool {
    if snapshot_id == 0 {
        return false;
    }
    let mut state = HOTPLUG_CHANNEL.lock();
    if state.is_some() {
        return false;
    }
    *state = Some(HotplugEndpoint {
        channel,
        snapshot_id,
    });
    true
}

/// Return the Port handle to include in the ACPI manager's wait set.
pub fn sci_port_handle() -> Option<huesos_abi::HandleValue> {
    SCI_ENDPOINT
        .lock()
        .as_ref()
        .map(|state| state.port.raw_handle())
}

/// Consume one SCI packet, if the kernel delivered one.
pub fn poll_sci_packet() -> bool {
    let state = SCI_ENDPOINT.lock();
    let Some(endpoint) = state.as_ref() else {
        return false;
    };
    match endpoint.port.read() {
        Ok(packet) => is_sci_packet(packet),
        Err(_) => false,
    }
}

/// Acknowledge the level-triggered SCI after the uACPI dispatcher returns.
pub fn acknowledge_sci() {
    let state = SCI_ENDPOINT.lock();
    if let Some(endpoint) = state.as_ref() {
        if let Some(interrupt) = endpoint.interrupt.as_ref() {
            let _ = interrupt.acknowledge();
        }
    }
}

/// Advance the generation and forget stale IRQ bookkeeping.
pub fn reset_generation(new_generation: u64) {
    let mut state = WORK_STATE.lock();
    state.generation = new_generation.max(1);
    state.irqs = [None; MAX_IRQ_HANDLERS];
}

/// Install the actual kernel Interrupt object for the SCI callback invoked by
/// uACPI. Authorization is checked through the immutable ACPI broker first.
#[allow(clippy::result_unit_err)]
pub fn install_irq(gsi: u32) -> Result<(), ()> {
    // Keep the lock order identical to `uninstall_irq` (work state first,
    // SCI endpoint second). The uACPI callback is normally serialized, but
    // preserving one order prevents a teardown callback from deadlocking a
    // concurrent generation install.
    let mut work = WORK_STATE.lock();
    let generation = work.generation;
    let mut endpoint = SCI_ENDPOINT.lock();
    let state = endpoint.as_mut().ok_or(())?;
    if state.gsi.is_some() {
        return Err(());
    }
    let interrupt = Interrupt::create_gsi_from_resource(&state.resource, gsi).map_err(|_| ())?;
    interrupt
        .bind_port(&state.port, SCI_PORT_KEY)
        .map_err(|_| ())?;

    if work
        .irqs
        .iter()
        .flatten()
        .any(|slot| slot.gsi == gsi && slot.generation == generation)
    {
        return Err(());
    }
    let Some(slot) = work.irqs.iter_mut().find(|slot| slot.is_none()) else {
        return Err(());
    };
    *slot = Some(IrqSlot { gsi, generation });
    state.interrupt = Some(interrupt);
    state.gsi = Some(gsi);
    Ok(())
}

/// Remove the actual SCI Interrupt object and its generation bookkeeping.
#[allow(clippy::result_unit_err)]
pub fn uninstall_irq(gsi: u32) -> Result<(), ()> {
    let mut work = WORK_STATE.lock();
    let generation = work.generation;
    let Some(slot) = work.irqs.iter_mut().find(|slot| {
        slot.as_ref()
            .is_some_and(|entry| entry.gsi == gsi && entry.generation == generation)
    }) else {
        return Err(());
    };
    *slot = None;
    drop(work);

    let mut endpoint = SCI_ENDPOINT.lock();
    let Some(state) = endpoint.as_mut() else {
        return Err(());
    };
    if state.gsi != Some(gsi) {
        return Err(());
    }
    state.interrupt = None;
    state.gsi = None;
    Ok(())
}

/// Rust half of the C `uacpi_kernel_install_interrupt_handler` bridge.
#[unsafe(no_mangle)]
pub extern "C" fn hues_uacpi_irq_install(
    irq: u32,
    out_irq_handle: *mut *mut c_void,
) -> i32 {
    if out_irq_handle.is_null() {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
    if crate::broker::authorize_install_interrupt(irq).is_err() {
        store_scalar(out_irq_handle, core::ptr::null_mut());
        return UACPI_STATUS_DENIED;
    }
    if install_irq(irq).is_err() {
        let _ = crate::broker::authorize_remove_interrupt(irq);
        store_scalar(out_irq_handle, core::ptr::null_mut());
        return UACPI_STATUS_DENIED;
    }
    let Some(token) = usize::try_from(irq).ok().and_then(|value| value.checked_add(1)) else {
        let _ = uninstall_irq(irq);
        let _ = crate::broker::authorize_remove_interrupt(irq);
        store_scalar(out_irq_handle, core::ptr::null_mut());
        return UACPI_STATUS_INVALID_ARGUMENT;
    };
    store_scalar(out_irq_handle, token as *mut c_void);
    UACPI_STATUS_OK
}

/// Rust half of the C `uacpi_kernel_uninstall_interrupt_handler` bridge.
#[unsafe(no_mangle)]
pub extern "C" fn hues_uacpi_irq_uninstall(irq_handle: *mut c_void) -> i32 {
    let Some(raw) = (irq_handle as usize).checked_sub(1) else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };
    let Ok(irq) = u32::try_from(raw) else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };
    if uninstall_irq(irq).is_err() {
        return UACPI_STATUS_INTERNAL_ERROR;
    }
    let _ = crate::broker::authorize_remove_interrupt(irq);
    UACPI_STATUS_OK
}

/// Forward one mapped ACPI Notify value over the private K.2 event channel.
///
/// The C callback supplies an identity record, not an opaque namespace pointer.
/// Root IDs are derived from the same `(snapshot, segment, bus range)` tuple
/// used by `roots.rs`, so PCI Manager can reject a stale or cross-root event.
#[unsafe(no_mangle)]
pub extern "C" fn hues_uacpi_notify_event(target: AcpiHotplugTarget, value: u64) {
    const TARGET_ROOT: u32 = 1;
    const TARGET_BRIDGE: u32 = 2;
    const TARGET_FUNCTION: u32 = 3;

    let Ok(notify_value) = u32::try_from(value) else {
        return;
    };
    let Some(notify_kind) = acpi_notify_kind(notify_value) else {
        return;
    };
    if target.valid == 0
        || target.device > 31
        || target.function > 7
        || target.root_start_bus > target.root_end_bus
        || target.segment != target.root_segment
    {
        return;
    }

    let mut endpoint = HOTPLUG_CHANNEL.lock();
    let Some(endpoint) = endpoint.as_mut() else {
        return;
    };
    let event = match (target.kind, notify_kind) {
        (TARGET_ROOT, huesos_abi::pci_hotplug::HotplugNotifyKind::RescanSubtree) => {
            let root_id = crate::roots::canonical_root_id(
                endpoint.snapshot_id,
                target.root_segment,
                target.root_start_bus,
                target.root_end_bus,
            );
            HotplugWireEvent::root_rescan(root_id, notify_value)
        }
        (TARGET_ROOT, huesos_abi::pci_hotplug::HotplugNotifyKind::OrderlyEject) => {
            let root_id = crate::roots::canonical_root_id(
                endpoint.snapshot_id,
                target.root_segment,
                target.root_start_bus,
                target.root_end_bus,
            );
            HotplugWireEvent::root_eject(root_id, notify_value)
        }
        (TARGET_ROOT, huesos_abi::pci_hotplug::HotplugNotifyKind::SurpriseLinkDown) => {
            let root_id = crate::roots::canonical_root_id(
                endpoint.snapshot_id,
                target.root_segment,
                target.root_start_bus,
                target.root_end_bus,
            );
            HotplugWireEvent::root_surprise_removal(root_id, notify_value)
        }
        (TARGET_BRIDGE, huesos_abi::pci_hotplug::HotplugNotifyKind::RescanSubtree) => {
            HotplugWireEvent::bridge_port_rescan(
                target.segment,
                target.bus,
                target.device,
                target.function,
                notify_value,
            )
        }
        (TARGET_BRIDGE, huesos_abi::pci_hotplug::HotplugNotifyKind::OrderlyEject) => {
            HotplugWireEvent::bridge_port_eject(
                target.segment,
                target.bus,
                target.device,
                target.function,
                notify_value,
            )
        }
        (TARGET_BRIDGE, huesos_abi::pci_hotplug::HotplugNotifyKind::SurpriseLinkDown) => {
            HotplugWireEvent::bridge_port_surprise_removal(
                target.segment,
                target.bus,
                target.device,
                target.function,
                notify_value,
            )
        }
        (TARGET_FUNCTION, huesos_abi::pci_hotplug::HotplugNotifyKind::RescanSubtree) => {
            HotplugWireEvent::function_rescan(
                target.segment,
                target.bus,
                target.device,
                target.function,
                notify_value,
            )
        }
        (TARGET_FUNCTION, huesos_abi::pci_hotplug::HotplugNotifyKind::OrderlyEject) => {
            HotplugWireEvent::function_eject(
                target.segment,
                target.bus,
                target.device,
                target.function,
                notify_value,
            )
        }
        (TARGET_FUNCTION, huesos_abi::pci_hotplug::HotplugNotifyKind::SurpriseLinkDown) => {
            HotplugWireEvent::function_surprise_removal(
                target.segment,
                target.bus,
                target.device,
                target.function,
                notify_value,
            )
        }
        _ => return,
    };
    let bytes = event.encode();
    let _ = endpoint.channel.write(&bytes);
}

/// Host-side packet shape used by tests to keep the event bridge observable.
#[allow(dead_code)]
fn is_sci_packet(packet: PortPacket) -> bool {
    packet.packet_type == PORT_PACKET_INTERRUPT && packet.key == SCI_PORT_KEY
}
