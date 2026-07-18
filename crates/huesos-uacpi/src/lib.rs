//! Audited Rust host boundary for the vendored uACPI table subsystem.
//!
//! This first integration deliberately enables uACPI's barebones mode: uACPI
//! validates and owns ACPI table discovery while HuesOS retains its existing
//! MADT consumer. Full AML/namespace support is enabled only after mutex,
//! event, work-queue, PCI, SystemIO, and interrupt host contracts exist.

#![no_std]
#![warn(missing_docs)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicU64, Ordering};

const STATUS_OK: i32 = 0;
const MAX_LOG_BYTES: usize = 4096;
const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;

static RSDP_PHYSICAL: AtomicU64 = AtomicU64::new(0);
static INITIALIZE_LOCK: huesos_arch::RankedIrqSafeTicketLock<()> =
    huesos_arch::RankedIrqSafeTicketLock::new((), huesos_arch::LockRank::ARCHITECTURE);

#[repr(align(16))]
struct Scratch(UnsafeCell<[u8; 8192]>);

// SAFETY: uACPI initialization is serialized by INITIALIZE_LOCK and the
// scratch array is never accessed after initialization publishes success.
unsafe impl Sync for Scratch {}

static TABLE_SCRATCH: Scratch = Scratch(UnsafeCell::new([0; 8192]));

/// Error returned by the uACPI host boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied RSDP address was zero.
    MissingRsdp,
    /// uACPI rejected the firmware table graph.
    Firmware(i32),
    /// A requested table was absent.
    NotFound,
    /// A mapped SDT reported an invalid length.
    InvalidTableLength,
    /// uACPI returned inconsistent table metadata.
    InvalidTableMetadata,
}

#[repr(C)]
struct UacpiTable {
    ptr: *mut c_void,
    index: usize,
}

#[repr(C)]
struct UacpiTableInfo {
    index: usize,
    size: usize,
    address: u64,
    signature: [c_char; 4],
    origin: u8,
    flags: u8,
    reference_count: u16,
}

unsafe extern "C" {
    fn uacpi_setup_early_table_access(buffer: *mut c_void, size: usize) -> i32;
    fn uacpi_table_subsystem_available() -> u8;
    fn uacpi_table_find_by_signature(signature: *const c_char, table: *mut UacpiTable) -> i32;
    fn uacpi_table_count() -> usize;
    fn uacpi_table_get_by_index(index: usize, table: *mut UacpiTable) -> i32;
    fn uacpi_table_info_get_by_index(index: usize, info: *mut UacpiTableInfo) -> i32;
    fn uacpi_table_unref(table: *mut UacpiTable);
}

/// Initialize uACPI table discovery from the bootloader-validated physical
/// RSDP address. Repeated calls are serialized and return the current state.
pub fn initialize_tables(rsdp_physical: u64) -> Result<(), Error> {
    if rsdp_physical == 0 {
        return Err(Error::MissingRsdp);
    }
    let _guard = INITIALIZE_LOCK.lock();
    RSDP_PHYSICAL.store(rsdp_physical, Ordering::Release);

    // SAFETY: INITIALIZE_LOCK gives unique scratch access; the buffer is
    // aligned to 16 bytes and remains static for the subsystem lifetime.
    let status = unsafe {
        let scratch = &mut *TABLE_SCRATCH.0.get();
        uacpi_setup_early_table_access(scratch.as_mut_ptr().cast(), scratch.len())
    };
    if status != STATUS_OK {
        return Err(Error::Firmware(status));
    }
    // SAFETY: a successful setup call initializes uACPI's global table state.
    if unsafe { uacpi_table_subsystem_available() } == 0 {
        return Err(Error::Firmware(status));
    }
    Ok(())
}

/// Number of tables installed by uACPI after successful initialization.
pub fn table_count() -> usize {
    // SAFETY: callers reach this after initialize_tables; the function only
    // reads uACPI's serialized table-array length.
    unsafe { uacpi_table_count() }
}

/// Validated metadata for one installed uACPI table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableMetadata {
    /// Stable table-array index.
    pub index: usize,
    /// Table length reported by uACPI.
    pub length: usize,
    /// Original physical address for firmware/host physical tables.
    pub physical_address: Option<u64>,
    /// Four-byte SDT signature.
    pub signature: [u8; 4],
    /// Whether uACPI detected a bad checksum.
    pub checksum_bad: bool,
}

/// Read bounded metadata for an installed table without mapping it.
pub fn table_metadata(index: usize) -> Result<TableMetadata, Error> {
    let mut info = UacpiTableInfo {
        index: 0,
        size: 0,
        address: 0,
        signature: [0; 4],
        origin: 0,
        flags: 0,
        reference_count: 0,
    };
    // SAFETY: info is writable for the complete C structure and uACPI checks
    // the supplied index before initializing it.
    let status = unsafe { uacpi_table_info_get_by_index(index, &mut info) };
    if status != STATUS_OK
        || info.index != index
        || !(36..=MAX_TABLE_BYTES).contains(&info.size)
    {
        return Err(Error::InvalidTableMetadata);
    }
    let mut signature = [0u8; 4];
    for (output, input) in signature.iter_mut().zip(info.signature) {
        *output = input as u8;
    }
    let physical = info.origin & ((1 << 0) | (1 << 2)) != 0;
    Ok(TableMetadata {
        index,
        length: info.size,
        physical_address: physical.then_some(info.address),
        signature,
        checksum_bad: info.flags & (1 << 2) != 0,
    })
}

/// A referenced, mapped ACPI system-description table.
pub struct Table {
    inner: UacpiTable,
}

impl Table {
    /// Reference an installed table by its stable uACPI index.
    pub fn get(index: usize) -> Result<Self, Error> {
        let mut inner = UacpiTable {
            ptr: core::ptr::null_mut(),
            index: 0,
        };
        // SAFETY: inner is writable and receives exactly one referenced table
        // descriptor on success. uACPI validates index against its table array.
        let status = unsafe { uacpi_table_get_by_index(index, &mut inner) };
        if status != STATUS_OK || inner.ptr.is_null() {
            return Err(Error::NotFound);
        }
        Ok(Self { inner })
    }

    /// Find a table by its four-byte ACPI signature.
    pub fn find(signature: &[u8; 4]) -> Result<Self, Error> {
        let mut inner = UacpiTable {
            ptr: core::ptr::null_mut(),
            index: 0,
        };
        // SAFETY: signature is readable for four bytes as required by uACPI;
        // inner is writable and receives one owned table reference on success.
        let status =
            unsafe { uacpi_table_find_by_signature(signature.as_ptr().cast(), &mut inner) };
        if status != STATUS_OK || inner.ptr.is_null() {
            return Err(Error::NotFound);
        }
        Ok(Self { inner })
    }

    /// Return the table's four-byte ACPI signature.
    pub fn signature(&self) -> Result<[u8; 4], Error> {
        let bytes = self.bytes()?;
        let mut signature = [0; 4];
        signature.copy_from_slice(&bytes[..4]);
        Ok(signature)
    }

    /// Return the revision byte from the standard SDT header.
    pub fn revision(&self) -> Result<u8, Error> {
        Ok(self.bytes()?[8])
    }

    /// Borrow the complete mapped SDT after validating its standard length
    /// field. The slice cannot outlive this table reference.
    pub fn bytes(&self) -> Result<&[u8], Error> {
        // ACPI SDT header: signature[4], length u32 at offset 4.
        // SAFETY: uACPI returned a mapped SDT pointer after checksum/header
        // validation; reading the unaligned length field is within its header.
        let length = unsafe {
            core::ptr::read_unaligned((self.inner.ptr as *const u8).add(4).cast::<u32>())
        } as usize;
        if !(36..=MAX_TABLE_BYTES).contains(&length) {
            return Err(Error::InvalidTableLength);
        }
        // SAFETY: uACPI keeps the complete table mapped while this reference is
        // held, and the validated SDT length defines the mapping extent.
        Ok(unsafe { core::slice::from_raw_parts(self.inner.ptr.cast(), length) })
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        // SAFETY: find returned exactly one reference represented by inner;
        // Drop runs once and uACPI accepts the same descriptor for unref.
        unsafe { uacpi_table_unref(&mut self.inner) };
    }
}

/// Return the pinned upstream uACPI revision.
pub const fn upstream_revision() -> &'static str {
    "9c9b26d6291a1cdd9014cc5bb6b03e596697cbfd"
}

/// uACPI host callback returning the physical RSDP.
///
/// # Safety
/// `out` must be null or writable for one `u64` as required by uACPI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_get_rsdp(out: *mut u64) -> i32 {
    if out.is_null() {
        return 3;
    }
    let rsdp = RSDP_PHYSICAL.load(Ordering::Acquire);
    if rsdp == 0 {
        return 14;
    }
    // SAFETY: required from the foreign caller and null-checked above.
    unsafe { out.write(rsdp) };
    STATUS_OK
}

/// uACPI physical mapping callback backed by the kernel HHDM.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_map(address: u64, length: usize) -> *mut c_void {
    if length == 0 || huesos_arch::paging::map_hhdm_range(address, length as u64).is_err() {
        return usize::MAX as *mut c_void;
    }
    huesos_arch::paging::phys_to_virt(address).as_mut_ptr()
}

/// HHDM mappings are shared boot mappings and are intentionally retained.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_unmap(_address: *mut c_void, _length: usize) {}

/// Forward a bounded, preformatted uACPI log line to emergency serial output.
///
/// # Safety
/// `message` must be null or point to a NUL-terminated uACPI-owned string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_log(_level: i32, message: *const c_char) {
    if message.is_null() {
        return;
    }
    use core::fmt::Write;
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writer.write_str("[uACPI] ");
    for index in 0..MAX_LOG_BYTES {
        // SAFETY: uACPI promises a NUL-terminated string. The hard cap limits
        // damage if a foreign-code bug violates that contract.
        let byte = unsafe { message.add(index).read() } as u8;
        if byte == 0 {
            break;
        }
        let _ = writer.write_char(byte as char);
    }
}
