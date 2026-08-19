//! Read-only archive-v2 installation and physical-table translation.

use core::ffi::c_void;
use huesos_abi::acpi_archive::{
    self, ArchiveReadError, ArchiveReader, ArchiveSummary, ArchiveV2Header, MAPPING_ENTRY_BYTES,
};
use huesos_abi::acpi_broker::{ArchiveError, MAX_ARCHIVE_BYTES};
use libcanvas::{ErrorCode, Vmar, Vmo};
use spin::Mutex;

/// Fixed read-only mapping window below the userspace heap.
pub const ARCHIVE_MAP_BASE: u64 = 0x0000_0000_6000_0000;
const PAGE_BYTES: u64 = 4096;
const UACPI_STATUS_OK: i32 = 0;
const UACPI_STATUS_INVALID_ARGUMENT: i32 = 7;
const UACPI_STATUS_DENIED: i32 = 20;

struct ArchiveState {
    bytes: &'static [u8],
    header: ArchiveV2Header,
    _vmo: Vmo,
    _vmar: Vmar,
}

static ARCHIVE: Mutex<Option<ArchiveState>> = Mutex::new(None);

/// Successful installed archive identity and mapping geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveMappingInfo {
    /// Firmware snapshot identity from archive v2.
    pub firmware_snapshot_id: u64,
    /// Number of archived tables.
    pub table_count: u32,
    /// Number of physical translation records.
    pub mapping_count: u32,
    /// Fixed userspace virtual mapping base.
    pub base: u64,
    /// Page-rounded VMO mapping length.
    pub mapped_length: u64,
}

/// Archive installation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveInstallError {
    /// One archive is already installed for this process generation.
    AlreadyInstalled,
    /// The VMO did not contain a valid canonical archive v2.
    InvalidArchive(ArchiveError),
    /// Only archive version 2 can back the full runtime.
    UnsupportedVersion,
    /// Mapping geometry overflowed or exceeded the bounded archive window.
    InvalidGeometry,
    /// The kernel rejected the read-only VMO mapping.
    Map(ErrorCode),
}

struct VmoReader<'a> {
    vmo: &'a Vmo,
}

impl ArchiveReader for VmoReader<'_> {
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ArchiveReadError> {
        match self.vmo.read(offset, output) {
            Ok(length) if length == output.len() => Ok(()),
            Ok(_) | Err(_) => Err(ArchiveReadError),
        }
    }
}

/// Validate and install a sealed archive-v2 VMO as a read-only mapping.
///
/// The caller must provide this process's root VMAR capability. The VMO needs
/// `READ | MAP` rights but no write or execute right. Both handles are retained
/// so the mapping cannot outlive its backing objects.
pub fn install_archive(
    vmo: Vmo,
    root_vmar: Vmar,
) -> Result<ArchiveMappingInfo, ArchiveInstallError> {
    if ARCHIVE.lock().is_some() {
        return Err(ArchiveInstallError::AlreadyInstalled);
    }
    let summary = acpi_archive::validate(&VmoReader { vmo: &vmo }, MAX_ARCHIVE_BYTES)
        .map_err(ArchiveInstallError::InvalidArchive)?;
    if summary.version != acpi_archive::VERSION {
        return Err(ArchiveInstallError::UnsupportedVersion);
    }
    let mapped_length = page_round_up(summary.total_size)?;
    if mapped_length > MAX_ARCHIVE_BYTES {
        return Err(ArchiveInstallError::InvalidGeometry);
    }
    let flags = huesos_abi::vmar_flags::READ
        | huesos_abi::vmar_flags::USER
        | huesos_abi::vmar_flags::SPECIFIC;
    let mapped = root_vmar
        .map(&vmo, 0, ARCHIVE_MAP_BASE, mapped_length, flags)
        .map_err(ArchiveInstallError::Map)?;
    if mapped != ARCHIVE_MAP_BASE {
        return Err(ArchiveInstallError::InvalidGeometry);
    }
    let total_size =
        usize::try_from(summary.total_size).map_err(|_| ArchiveInstallError::InvalidGeometry)?;
    // SAFETY: the kernel mapped the sealed VMO read-only at the exact fixed
    // address for at least total_size bytes. The retained VMO and VMAR handles
    // keep the backing frames and mapping alive for the process lifetime.
    let bytes = unsafe { core::slice::from_raw_parts(ARCHIVE_MAP_BASE as *const u8, total_size) };
    let mapped_summary = acpi_archive::validate(bytes, summary.total_size)
        .map_err(ArchiveInstallError::InvalidArchive)?;
    if mapped_summary != summary {
        return Err(ArchiveInstallError::InvalidGeometry);
    }
    let header = acpi_archive::decode_v2_header(
        bytes
            .get(..acpi_archive::HEADER_BYTES)
            .ok_or(ArchiveInstallError::InvalidGeometry)?,
    )
    .map_err(ArchiveInstallError::InvalidArchive)?;
    let info = info(summary, mapped_length);
    *ARCHIVE.lock() = Some(ArchiveState {
        bytes,
        header,
        _vmo: vmo,
        _vmar: root_vmar,
    });
    Ok(info)
}

fn info(summary: ArchiveSummary, mapped_length: u64) -> ArchiveMappingInfo {
    ArchiveMappingInfo {
        firmware_snapshot_id: summary.firmware_snapshot_id,
        table_count: summary.table_count,
        mapping_count: summary.mapping_count,
        base: ARCHIVE_MAP_BASE,
        mapped_length,
    }
}

fn page_round_up(length: u64) -> Result<u64, ArchiveInstallError> {
    if length == 0 {
        return Err(ArchiveInstallError::InvalidGeometry);
    }
    length
        .checked_add(PAGE_BYTES - 1)
        .map(|value| value & !(PAGE_BYTES - 1))
        .ok_or(ArchiveInstallError::InvalidGeometry)
}

/// Return the archived original RSDP address after successful installation.
///
/// # Safety
/// `output` must be null or writable for one `u64` according to uACPI's host
/// callback contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_get_rsdp(output: *mut u64) -> i32 {
    if output.is_null() {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
    let archive = ARCHIVE.lock();
    let Some(state) = archive.as_ref() else {
        return UACPI_STATUS_DENIED;
    };
    // SAFETY: required from the foreign caller and null-checked above.
    unsafe { output.write(state.header.rsdp.physical_address) };
    UACPI_STATUS_OK
}

/// Translate one firmware physical table range into the sealed archive mapping.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_map(address: u64, length: usize) -> *mut c_void {
    let Ok(length) = u64::try_from(length) else {
        return usize::MAX as *mut c_void;
    };
    let archive = ARCHIVE.lock();
    let Some(state) = archive.as_ref() else {
        return usize::MAX as *mut c_void;
    };
    let Some(offset) = translate_archive(state.bytes, &state.header, address, length) else {
        return usize::MAX as *mut c_void;
    };
    state.bytes.as_ptr().wrapping_add(offset).cast_mut().cast()
}

/// Archive mappings are process-lifetime mappings; individual uACPI unmaps are
/// bookkeeping no-ops and cannot release or widen the sealed VMO mapping.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_unmap(_address: *mut c_void, _length: usize) {}

fn translate_archive(
    bytes: &[u8],
    header: &ArchiveV2Header,
    physical_address: u64,
    length: u64,
) -> Option<usize> {
    if length == 0 {
        return None;
    }
    let physical_end = physical_address.checked_add(length)?;
    for index in 0..header.mapping_count {
        let offset = header
            .mappings_offset
            .checked_add(u64::from(index) * MAPPING_ENTRY_BYTES as u64)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(MAPPING_ENTRY_BYTES)?;
        let mapping = acpi_archive::decode_v2_mapping(bytes.get(start..end)?).ok()?;
        let mapping_end = mapping.physical_address.checked_add(mapping.length)?;
        if physical_address >= mapping.physical_address && physical_end <= mapping_end {
            let delta = physical_address - mapping.physical_address;
            let archive_offset = mapping.offset.checked_add(delta)?;
            let archive_end = archive_offset.checked_add(length)?;
            if archive_end > header.total_size {
                return None;
            }
            return usize::try_from(archive_offset).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_abi::acpi_archive::{
        encode_v2_mapping, PhysicalMappingEntry, MAPPING_KIND_RSDP, MAPPING_KIND_TABLE,
    };

    #[test]
    fn translation_accepts_only_contained_indexed_ranges() {
        let mappings_offset = acpi_archive::HEADER_BYTES as u64;
        let total_size = mappings_offset + 2 * MAPPING_ENTRY_BYTES as u64 + 128;
        let header = ArchiveV2Header {
            total_size,
            mapping_count: 2,
            mappings_offset,
            ..ArchiveV2Header::default()
        };
        let mut bytes = [0u8; acpi_archive::HEADER_BYTES + 2 * MAPPING_ENTRY_BYTES + 128];
        let first = PhysicalMappingEntry {
            physical_address: 0x1000,
            offset: mappings_offset + 2 * MAPPING_ENTRY_BYTES as u64,
            length: 36,
            kind: MAPPING_KIND_RSDP,
        };
        let second = PhysicalMappingEntry {
            physical_address: 0x3000,
            offset: mappings_offset + 2 * MAPPING_ENTRY_BYTES as u64 + 36,
            length: 64,
            kind: MAPPING_KIND_TABLE,
        };
        let mapping_start = mappings_offset as usize;
        assert_eq!(
            encode_v2_mapping(
                &first,
                &mut bytes[mapping_start..mapping_start + MAPPING_ENTRY_BYTES]
            ),
            Ok(())
        );
        assert_eq!(
            encode_v2_mapping(
                &second,
                &mut bytes
                    [mapping_start + MAPPING_ENTRY_BYTES..mapping_start + 2 * MAPPING_ENTRY_BYTES]
            ),
            Ok(())
        );

        assert_eq!(
            translate_archive(&bytes, &header, 0x1004, 8),
            Some(first.offset as usize + 4)
        );
        assert_eq!(
            translate_archive(&bytes, &header, 0x3000, 64),
            Some(second.offset as usize)
        );
        assert_eq!(translate_archive(&bytes, &header, 0x1010, 32), None);
        assert_eq!(translate_archive(&bytes, &header, 0x2000, 1), None);
        assert_eq!(translate_archive(&bytes, &header, 0x3000, 0), None);
        assert_eq!(translate_archive(&bytes, &header, u64::MAX - 1, 8), None);
    }

    #[test]
    fn mapping_geometry_rounds_without_wrap() {
        assert_eq!(page_round_up(1), Ok(4096));
        assert_eq!(page_round_up(4096), Ok(4096));
        assert_eq!(page_round_up(4097), Ok(8192));
        assert_eq!(page_round_up(0), Err(ArchiveInstallError::InvalidGeometry));
        assert_eq!(
            page_round_up(u64::MAX),
            Err(ArchiveInstallError::InvalidGeometry)
        );
    }
}
