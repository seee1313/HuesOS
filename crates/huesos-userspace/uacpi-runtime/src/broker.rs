//! Mediated SystemIO, SystemMemory, interrupt, and log callbacks backed by
//! the kernel's immutable `AcpiBroker` capability (AP-11 / AP-12 / AP-13).
//!
//! Zero `unsafe` in this module: pointer writes go through
//! [`crate::primitives::store_scalar`] and C strings are packed by value in
//! `uacpi_shim.c`.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use crate::primitives::store_scalar;
use huesos_abi::acpi_broker::Status as BrokerStatus;
use huesos_abi::acpi_manager::{
    INIT_DETAIL_AML_ERROR, INIT_DETAIL_DENIED_OPREGION, INIT_DETAIL_DENIED_PCI_WRITE,
};
use libcanvas::acpi_broker::AcpiBroker;

const UACPI_STATUS_OK: i32 = 0;
const UACPI_STATUS_NOT_FOUND: i32 = 6;
const UACPI_STATUS_INVALID_ARGUMENT: i32 = 7;
const UACPI_STATUS_INTERNAL_ERROR: i32 = 10;
const UACPI_STATUS_DENIED: i32 = 20;

const MAX_IO_REGIONS: usize = 32;
const IO_SPACE_LIMIT: u64 = 0x1_0000;

struct BrokerState {
    broker: AcpiBroker,
    snapshot_id: u64,
}

#[derive(Clone, Copy)]
struct IoRegionSlot {
    occupied: bool,
    generation: u16,
    base: u32,
    length: u32,
}

impl IoRegionSlot {
    const EMPTY: Self = Self {
        occupied: false,
        generation: 1,
        base: 0,
        length: 0,
    };
}

struct IoRegionTable {
    slots: [IoRegionSlot; MAX_IO_REGIONS],
}

impl IoRegionTable {
    const fn new() -> Self {
        Self {
            slots: [IoRegionSlot::EMPTY; MAX_IO_REGIONS],
        }
    }

    fn map(&mut self, base: u32, length: u32) -> Option<u32> {
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if !slot.occupied {
                let gen = slot.generation.max(1);
                slot.occupied = true;
                slot.generation = gen;
                slot.base = base;
                slot.length = length;
                return Some(((idx as u32) + 1) | (u32::from(gen) << 16));
            }
        }
        None
    }

    fn resolve(&self, raw: u32) -> Option<(u32, u32)> {
        let index = ((raw & 0xffff) as usize).checked_sub(1)?;
        let gen = (raw >> 16) as u16;
        let slot = self.slots.get(index)?;
        if slot.occupied && slot.generation == gen {
            Some((slot.base, slot.length))
        } else {
            None
        }
    }

    fn unmap(&mut self, raw: u32) {
        let Some(index) = ((raw & 0xffff) as usize).checked_sub(1) else {
            return;
        };
        let gen = (raw >> 16) as u16;
        if let Some(slot) = self.slots.get_mut(index) {
            if slot.occupied && slot.generation == gen {
                slot.occupied = false;
                slot.generation = slot.generation.wrapping_add(1).max(1);
                slot.base = 0;
                slot.length = 0;
            }
        }
    }
}

static BROKER: Mutex<Option<BrokerState>> = Mutex::new(None);
static IO_REGIONS: Mutex<IoRegionTable> = Mutex::new(IoRegionTable::new());
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static DEGRADED_OPREGIONS: AtomicBool = AtomicBool::new(false);
static LOGGED_AML_ERROR: AtomicBool = AtomicBool::new(false);
static DEGRADATION_BITS: AtomicU32 = AtomicU32::new(0);

/// One-shot process-local installation of the kernel `AcpiBroker` handle.
///
/// Returns `false` if a broker is already installed or `snapshot_id == 0`.
pub fn install_broker(broker: AcpiBroker, snapshot_id: u64) -> bool {
    if snapshot_id == 0 {
        return false;
    }
    let mut guard = BROKER.lock();
    if guard.is_some() {
        return false;
    }
    *guard = Some(BrokerState {
        broker,
        snapshot_id,
    });
    true
}

/// Whether an `AcpiBroker` has been installed for this process generation.
pub fn broker_installed() -> bool {
    BROKER.lock().is_some()
}

/// Whether any mediated OpRegion / broker access was denied in this generation.
pub fn had_degraded_opregion() -> bool {
    DEGRADED_OPREGIONS.load(Ordering::Acquire)
}

/// Reset the degraded OpRegion flag (primarily for host tests).
pub fn clear_degraded_opregion() {
    DEGRADED_OPREGIONS.store(false, Ordering::Release);
    DEGRADATION_BITS.store(0, Ordering::Release);
}

/// Whether uACPI logged a critical error (`UACPI_LOG_ERROR`) in this phase.
pub fn had_logged_aml_error() -> bool {
    LOGGED_AML_ERROR.load(Ordering::Acquire)
}

/// Reset the logged AML error flag before a lifecycle phase.
pub fn clear_logged_aml_error() {
    LOGGED_AML_ERROR.store(false, Ordering::Release);
}

/// Bitmask of AP-14 degradation causes recorded in the current phase.
pub fn degradation_bits() -> u32 {
    DEGRADATION_BITS.load(Ordering::Acquire)
}

pub(crate) fn note_denied_opregion() {
    DEGRADED_OPREGIONS.store(true, Ordering::Release);
    DEGRADATION_BITS.fetch_or(INIT_DETAIL_DENIED_OPREGION, Ordering::AcqRel);
}

pub(crate) fn note_denied_pci_write() {
    DEGRADED_OPREGIONS.store(true, Ordering::Release);
    DEGRADATION_BITS.fetch_or(INIT_DETAIL_DENIED_PCI_WRITE, Ordering::AcqRel);
}

fn note_aml_error() {
    LOGGED_AML_ERROR.store(true, Ordering::Release);
    DEGRADATION_BITS.fetch_or(INIT_DETAIL_AML_ERROR, Ordering::AcqRel);
}

fn next_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

fn broker_status_to_uacpi(status: i32) -> i32 {
    if status == BrokerStatus::Ok as i32 {
        UACPI_STATUS_OK
    } else if status == BrokerStatus::InvalidRequest as i32 {
        UACPI_STATUS_INVALID_ARGUMENT
    } else if status == BrokerStatus::NotFound as i32 {
        note_denied_opregion();
        UACPI_STATUS_NOT_FOUND
    } else if status == BrokerStatus::AccessDenied as i32 {
        note_denied_opregion();
        UACPI_STATUS_DENIED
    } else {
        UACPI_STATUS_INTERNAL_ERROR
    }
}

/// Request broker authorization to install an ACPI interrupt (e.g. `SCI_INT`).
pub(crate) fn authorize_install_interrupt(irq: u32) -> Result<(), i32> {
    let req_id = next_request_id();
    let guard = BROKER.lock();
    let Some(state) = guard.as_ref() else {
        return Err(UACPI_STATUS_DENIED);
    };
    let response = state
        .broker
        .install_interrupt(irq, req_id)
        .map_err(|_| UACPI_STATUS_INTERNAL_ERROR)?;
    if response.request_id != req_id {
        return Err(UACPI_STATUS_INTERNAL_ERROR);
    }
    let st = broker_status_to_uacpi(response.status);
    if st == UACPI_STATUS_OK {
        Ok(())
    } else {
        Err(st)
    }
}

/// Request broker authorization to remove an ACPI interrupt.
pub(crate) fn authorize_remove_interrupt(irq: u32) -> Result<(), i32> {
    let req_id = next_request_id();
    let guard = BROKER.lock();
    let Some(state) = guard.as_ref() else {
        return Err(UACPI_STATUS_DENIED);
    };
    let response = state
        .broker
        .remove_interrupt(irq, req_id)
        .map_err(|_| UACPI_STATUS_INTERNAL_ERROR)?;
    if response.request_id != req_id {
        return Err(UACPI_STATUS_INTERNAL_ERROR);
    }
    let st = broker_status_to_uacpi(response.status);
    if st == UACPI_STATUS_OK {
        Ok(())
    } else {
        Err(st)
    }
}

fn io_resolve(handle: *mut c_void, offset: usize, width: u8) -> Result<u16, i32> {
    let raw = u32::try_from(handle as usize).map_err(|_| UACPI_STATUS_INVALID_ARGUMENT)?;
    if raw == 0 {
        return Err(UACPI_STATUS_INVALID_ARGUMENT);
    }
    let (base, length) = IO_REGIONS.lock().resolve(raw).ok_or(UACPI_STATUS_DENIED)?;
    let off = u32::try_from(offset).map_err(|_| UACPI_STATUS_INVALID_ARGUMENT)?;
    let end = off
        .checked_add(u32::from(width))
        .ok_or(UACPI_STATUS_INVALID_ARGUMENT)?;
    if end > length {
        return Err(UACPI_STATUS_INVALID_ARGUMENT);
    }
    let port = base.checked_add(off).ok_or(UACPI_STATUS_INVALID_ARGUMENT)?;
    u16::try_from(port).map_err(|_| UACPI_STATUS_INVALID_ARGUMENT)
}

fn io_read(handle: *mut c_void, offset: usize, width: u8) -> Result<u64, i32> {
    let port = io_resolve(handle, offset, width)?;
    let req_id = next_request_id();
    let guard = BROKER.lock();
    let Some(state) = guard.as_ref() else {
        return Err(UACPI_STATUS_DENIED);
    };
    let response = state
        .broker
        .system_io_read(port, width, state.snapshot_id, req_id)
        .map_err(|_| UACPI_STATUS_INTERNAL_ERROR)?;
    if response.request_id != req_id {
        return Err(UACPI_STATUS_INTERNAL_ERROR);
    }
    let st = broker_status_to_uacpi(response.status);
    if st == UACPI_STATUS_OK {
        Ok(response.value)
    } else {
        Err(st)
    }
}

fn io_write(handle: *mut c_void, offset: usize, width: u8, value: u64) -> i32 {
    let port = match io_resolve(handle, offset, width) {
        Ok(port) => port,
        Err(status) => return status,
    };
    let req_id = next_request_id();
    let guard = BROKER.lock();
    let Some(state) = guard.as_ref() else {
        return UACPI_STATUS_DENIED;
    };
    let Ok(response) = state
        .broker
        .system_io_write(port, width, value, state.snapshot_id, req_id)
    else {
        return UACPI_STATUS_INTERNAL_ERROR;
    };
    if response.request_id != req_id {
        return UACPI_STATUS_INTERNAL_ERROR;
    }
    broker_status_to_uacpi(response.status)
}

/// uACPI host callback: open a bounded SystemIO handle.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_io_map(
    base: u64,
    length: usize,
    out_handle: *mut *mut c_void,
) -> i32 {
    if out_handle.is_null() {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
    if !broker_installed() {
        store_scalar(out_handle, core::ptr::null_mut());
        return UACPI_STATUS_DENIED;
    }
    let Ok(len64) = u64::try_from(length) else {
        store_scalar(out_handle, core::ptr::null_mut());
        return UACPI_STATUS_INVALID_ARGUMENT;
    };
    let Some(end) = base.checked_add(len64) else {
        store_scalar(out_handle, core::ptr::null_mut());
        return UACPI_STATUS_INVALID_ARGUMENT;
    };
    if len64 == 0 || end > IO_SPACE_LIMIT {
        store_scalar(out_handle, core::ptr::null_mut());
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
    let (Ok(base32), Ok(len32)) = (u32::try_from(base), u32::try_from(len64)) else {
        store_scalar(out_handle, core::ptr::null_mut());
        return UACPI_STATUS_INVALID_ARGUMENT;
    };
    match IO_REGIONS.lock().map(base32, len32) {
        Some(handle) => {
            store_scalar(out_handle, handle as usize as *mut c_void);
            UACPI_STATUS_OK
        }
        None => {
            store_scalar(out_handle, core::ptr::null_mut());
            UACPI_STATUS_DENIED
        }
    }
}

/// uACPI host callback: close a SystemIO region handle.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_io_unmap(handle: *mut c_void) {
    if let Ok(raw) = u32::try_from(handle as usize) {
        if raw != 0 {
            IO_REGIONS.lock().unmap(raw);
        }
    }
}

macro_rules! io_read_handler {
    ($name:ident, $ty:ty, $width:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(handle: *mut c_void, offset: usize, value: *mut $ty) -> i32 {
            if value.is_null() {
                return UACPI_STATUS_INVALID_ARGUMENT;
            }
            match io_read(handle, offset, $width) {
                Ok(read) => {
                    store_scalar(value, read as $ty);
                    UACPI_STATUS_OK
                }
                Err(status) => status,
            }
        }
    };
}

macro_rules! io_write_handler {
    ($name:ident, $ty:ty, $width:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name(handle: *mut c_void, offset: usize, value: $ty) -> i32 {
            io_write(handle, offset, $width, u64::from(value))
        }
    };
}

io_read_handler!(uacpi_kernel_io_read8, u8, 1);
io_read_handler!(uacpi_kernel_io_read16, u16, 2);
io_read_handler!(uacpi_kernel_io_read32, u32, 4);
io_write_handler!(uacpi_kernel_io_write8, u8, 1);
io_write_handler!(uacpi_kernel_io_write16, u16, 2);
io_write_handler!(uacpi_kernel_io_write32, u32, 4);

/// Mediated `SystemMemory` OperationRegion read invoked from `uacpi_shim.c`.
#[unsafe(no_mangle)]
pub extern "C" fn hues_mmio_region_read(address: u64, width: u8, out_value: *mut u64) -> i32 {
    if out_value.is_null() {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
    let req_id = next_request_id();
    let guard = BROKER.lock();
    let Some(state) = guard.as_ref() else {
        DEGRADED_OPREGIONS.store(true, Ordering::Release);
        return UACPI_STATUS_DENIED;
    };
    let Ok(response) = state
        .broker
        .mmio_read(address, width, state.snapshot_id, req_id)
    else {
        return UACPI_STATUS_INTERNAL_ERROR;
    };
    if response.request_id != req_id {
        return UACPI_STATUS_INTERNAL_ERROR;
    }
    let st = broker_status_to_uacpi(response.status);
    if st == UACPI_STATUS_OK {
        store_scalar(out_value, response.value);
    }
    st
}

/// Mediated `SystemMemory` OperationRegion write invoked from `uacpi_shim.c`.
#[unsafe(no_mangle)]
pub extern "C" fn hues_mmio_region_write(address: u64, width: u8, value: u64) -> i32 {
    let req_id = next_request_id();
    let guard = BROKER.lock();
    let Some(state) = guard.as_ref() else {
        DEGRADED_OPREGIONS.store(true, Ordering::Release);
        return UACPI_STATUS_DENIED;
    };
    let Ok(response) = state
        .broker
        .mmio_write(address, width, value, state.snapshot_id, req_id)
    else {
        return UACPI_STATUS_INTERNAL_ERROR;
    };
    if response.request_id != req_id {
        return UACPI_STATUS_INTERNAL_ERROR;
    }
    broker_status_to_uacpi(response.status)
}

/// uACPI firmware request callback: always fail-closed in userspace.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_handle_firmware_request(_request: *mut c_void) -> i32 {
    UACPI_STATUS_DENIED
}

/// Value-passed bounded log line from `uacpi_shim.c` (`uacpi_kernel_log`).
#[repr(C)]
pub struct LogLine {
    /// uACPI log level (`1..=5`).
    pub level: u32,
    /// Number of valid UTF-8/ASCII bytes in `bytes`.
    pub len: u8,
    /// Packed log message bytes (newlines stripped by caller).
    pub bytes: [u8; 251],
}

/// Forward bounded uACPI log messages (errors/warnings/info) to serial debug.
#[unsafe(no_mangle)]
pub extern "C" fn hues_uacpi_log(line: LogLine) {
    let len = usize::from(line.len).min(line.bytes.len());
    let text = core::str::from_utf8(&line.bytes[..len]).unwrap_or("<non-utf8>");
    if line.level == 1 {
        note_aml_error();
    }
    if text.contains("no handler")
        || text.contains("EmbeddedControl")
        || text.contains("GeneralPurposeIO")
        || text.contains("GenericSerialBus")
        || text.contains("SMBus")
        || text.contains("PCC")
    {
        note_denied_opregion();
        #[cfg(not(test))]
        libcanvas::println!("[uacpi-rt] unsupported OpRegion degraded: {}", text);
    }
    // Log ERROR (1), WARN (2), and INFO (3); suppress TRACE/DEBUG noise.
    if line.level == 0 || line.level > 3 {
        return;
    }
    #[cfg(not(test))]
    libcanvas::println!("[uacpi] {}", text);
    #[cfg(test)]
    let _ = text;
}
