//! PCI configuration region callbacks (AP-10).
//!
//! The pinned interpreter's `default_handlers.c` implements the
//! `PCI_CONFIG` operation region against this file's callbacks once
//! `HUESOS_UACPI_RUST_PCI` is defined: ATTACH opens an opaque region
//! handle (a small integer — never a pointer), READ performs one
//! mediated configuration read through the private ACPI ↔ PCI channel,
//! DETACH closes the handle. Every write variant is answered
//! `UACPI_STATUS_DENIED` before any hardware access.
//!
//! Authority discipline mirrors the rest of the AP series: the channel
//! is installed exactly once per process (`install_pci_mediation`), the
//! handle table is fixed-size and allocation-free, and stale handles
//! are rejected by a per-slot generation counter. No raw configuration
//! pointer is ever stored, minted, or derived.

use core::ffi::c_void;
use spin::Mutex;

use huesos_abi::pci_mediation::{PciConfigRegions, RegionBinding};
use libcanvas::pci_mediation::{AccessError, MediationRequester};
use libcanvas::Channel;

const UACPI_STATUS_OK: i32 = 0;
const UACPI_STATUS_NOT_FOUND: i32 = 6;
const UACPI_STATUS_INVALID_ARGUMENT: i32 = 7;
const UACPI_STATUS_INTERNAL_ERROR: i32 = 10;
const UACPI_STATUS_TIMEOUT: i32 = 18;
const UACPI_STATUS_DENIED: i32 = 20;

/// Full extended configuration space exposed by every opened region.
const CONFIG_SPACE_BYTES: u16 = 4096;

static REGIONS: Mutex<PciConfigRegions> = Mutex::new(PciConfigRegions::new());
static MEDIATION: Mutex<Option<MediationRequester>> = Mutex::new(None);

/// One-shot process-local installation of the mediation endpoint.
///
/// `channel` is the ACPI-manager end of the private pair created by
/// DriverManager (label `pci-config-read`); the generations are the
/// ones announced by DriverManager at hand-off.
/// Returns `false` when already installed or any argument is zero —
/// callers must treat either as fatal for the mediation path.
pub fn install_pci_mediation(
    channel: Channel,
    acpi_generation: u64,
    pci_generation: u64,
    firmware_snapshot_id: u64,
) -> bool {
    if acpi_generation == 0 || pci_generation == 0 || firmware_snapshot_id == 0 {
        return false;
    }
    let mut mediation = MEDIATION.lock();
    if mediation.is_some() {
        return false;
    }
    let mut requester = MediationRequester::new(channel, acpi_generation, firmware_snapshot_id);
    requester.set_pci_generation(pci_generation);
    *mediation = Some(requester);
    true
}

/// Whether the mediation endpoint was installed in this process.
pub fn pci_mediation_installed() -> bool {
    MEDIATION.lock().is_some()
}

/// Layout-compatible mirror of `uacpi_pci_address` in
/// `include/uacpi/types.h`.
#[repr(C)]
pub struct UacpiPciAddress {
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
}

use crate::primitives::store_scalar;

fn handle_to_region(handle: *mut c_void) -> Option<u32> {
    u32::try_from(handle as usize).ok().filter(|raw| *raw != 0)
}

fn resolve_binding(handle: *mut c_void) -> Result<RegionBinding, i32> {
    let raw = handle_to_region(handle).ok_or(UACPI_STATUS_INVALID_ARGUMENT)?;
    REGIONS.lock().resolve(raw).ok_or(UACPI_STATUS_DENIED)
}

fn checked_region_offset(offset: u64, width: u8) -> Result<u16, i32> {
    let end = offset
        .checked_add(u64::from(width))
        .ok_or(UACPI_STATUS_INVALID_ARGUMENT)?;
    if end > u64::from(CONFIG_SPACE_BYTES) {
        return Err(UACPI_STATUS_INVALID_ARGUMENT);
    }
    u16::try_from(offset).map_err(|_| UACPI_STATUS_INVALID_ARGUMENT)
}

fn access_error_to_status(error: AccessError) -> i32 {
    match error {
        AccessError::NotReady => UACPI_STATUS_DENIED,
        AccessError::NotAuthorized => UACPI_STATUS_DENIED,
        AccessError::Timeout => UACPI_STATUS_TIMEOUT,
        AccessError::PeerClosed => UACPI_STATUS_DENIED,
        AccessError::InvalidRequest => UACPI_STATUS_INVALID_ARGUMENT,
        AccessError::Denied => UACPI_STATUS_DENIED,
        AccessError::NotFound => UACPI_STATUS_NOT_FOUND,
        AccessError::StaleGeneration => UACPI_STATUS_DENIED,
        AccessError::SnapshotMismatch => UACPI_STATUS_DENIED,
        AccessError::Internal => UACPI_STATUS_INTERNAL_ERROR,
    }
}

fn pci_read(handle: *mut c_void, offset: u64, width: u8) -> Result<u64, i32> {
    let binding = resolve_binding(handle)?;
    let absolute = u64::from(binding.base_offset)
        .checked_add(offset)
        .ok_or(UACPI_STATUS_INVALID_ARGUMENT)?;
    let absolute = checked_region_offset(absolute, width)?;
    let mediation = MEDIATION.lock();
    let Some(requester) = mediation.as_ref() else {
        return Err(UACPI_STATUS_DENIED);
    };
    requester
        .read(
            binding.segment,
            binding.bus,
            binding.device,
            binding.function,
            absolute,
            width,
        )
        .map_err(access_error_to_status)
}

fn pci_region_attach(address: UacpiPciAddress) -> Result<u32, i32> {
    let binding = RegionBinding {
        segment: address.segment,
        bus: address.bus,
        device: address.device,
        function: address.function,
        base_offset: 0,
        length: CONFIG_SPACE_BYTES,
    };
    if MEDIATION.lock().is_none() {
        // No mediation endpoint: harder failure than "device absent",
        // never a fabricated present device.
        return Err(UACPI_STATUS_DENIED);
    }
    REGIONS.lock().attach(binding).ok_or(UACPI_STATUS_DENIED)
}

/// uACPI host callback: open one PCI function for the PCI_CONFIG
/// operation region. On success `*out_handle` receives the opaque
/// region handle (small integer, never a pointer).
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_pci_device_open(
    address: UacpiPciAddress,
    out_handle: *mut *mut c_void,
) -> i32 {
    if out_handle.is_null() {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
    let (status, region) = match pci_region_attach(address) {
        Ok(region) => (UACPI_STATUS_OK, region),
        Err(status) => (status, 0),
    };
    // The handle is a small table index+generation value, never a real
    // pointer; zero signals failure, matching the uACPI contract.
    store_scalar(out_handle, region as usize as *mut c_void);
    status
}

/// uACPI host callback: close one region handle. Stale, doubled or
/// foreign handles are ignored.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_pci_device_close(handle: *mut c_void) {
    if let Some(raw) = handle_to_region(handle) {
        REGIONS.lock().detach(raw);
    }
}

macro_rules! pci_read_handler {
    ($name:ident, $ty:ty, $width:expr, $doc:literal) => {
        #[doc = $doc]
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(handle: *mut c_void, offset: usize, value: *mut $ty) -> i32 {
            if value.is_null() {
                return UACPI_STATUS_INVALID_ARGUMENT;
            }
            match pci_read(handle, offset as u64, $width) {
                Ok(read) => {
                    store_scalar(value, read as $ty);
                    UACPI_STATUS_OK
                }
                Err(status) => status,
            }
        }
    };
}

pci_read_handler!(
    uacpi_kernel_pci_read8,
    u8,
    1,
    "uACPI host callback: one mediated configuration read, width 1."
);
pci_read_handler!(
    uacpi_kernel_pci_read16,
    u16,
    2,
    "uACPI host callback: one mediated configuration read, width 2."
);
pci_read_handler!(
    uacpi_kernel_pci_read32,
    u32,
    4,
    "uACPI host callback: one mediated configuration read, width 4."
);

/// uACPI host callback: configuration writes are never executed.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_pci_write8(_handle: *mut c_void, _offset: usize, _value: u8) -> i32 {
    UACPI_STATUS_DENIED
}

/// uACPI host callback: configuration writes are never executed.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_pci_write16(
    _handle: *mut c_void,
    _offset: usize,
    _value: u16,
) -> i32 {
    UACPI_STATUS_DENIED
}

/// uACPI host callback: configuration writes are never executed.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_pci_write32(
    _handle: *mut c_void,
    _offset: usize,
    _value: u32,
) -> i32 {
    UACPI_STATUS_DENIED
}
