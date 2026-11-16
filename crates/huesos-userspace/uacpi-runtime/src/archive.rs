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
    extern crate std;

    use super::*;
    use huesos_abi::acpi_archive::{
        encode_v2_mapping, PhysicalMappingEntry, RsdpDescriptor, MAPPING_KIND_RSDP,
        MAPPING_KIND_TABLE,
    };
    use std::vec;
    use std::vec::Vec;

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

    // Synthetic firmware graph matching the failing-closed archive shape:
    // RSDP -> XSDT -> FADT/DSDT/FACS with adjacent physical ranges. PHYS
    // addresses are laid out back-to-back so "start in one record, end in
    // the next" is a real geometry, not an artificial gap.
    struct GraphFixture {
        bytes: Vec<u8>,
        header: ArchiveV2Header,
        rsdp_phys: u64,
        xsdt_phys: u64,
        fadt_phys: u64,
        dsdt_phys: u64,
        facs_phys: u64,
        rsdp_off: u64,
        xsdt_off: u64,
        fadt_off: u64,
        dsdt_off: u64,
        facs_off: u64,
        dsdt_len: u64,
    }

    fn graph_archive() -> GraphFixture {
        const RSDP_LEN: u64 = 36;
        const XSDT_LEN: u64 = 128;
        const FADT_LEN: u64 = 244;
        const DSDT_LEN: u64 = 4100;
        const FACS_LEN: u64 = 64;

        let rsdp_phys = 0xE0000u64;
        let xsdt_phys = rsdp_phys + RSDP_LEN; // 0xE0024
        let fadt_phys = xsdt_phys + XSDT_LEN; // 0xE00A4
        let dsdt_phys = 0xE1000u64; // unindexed gap between FADT end and DSDT
        let facs_phys = dsdt_phys + DSDT_LEN; // adjacent to DSDT

        let mappings_offset = acpi_archive::HEADER_BYTES as u64;
        let payload_offset = mappings_offset + 5 * MAPPING_ENTRY_BYTES as u64; // 256
        let rsdp_off = payload_offset;
        let xsdt_off = rsdp_off + RSDP_LEN; // 292
        let fadt_off = xsdt_off + XSDT_LEN; // 420
        let dsdt_off = fadt_off + FADT_LEN; // 664, crosses the 4 KiB archive boundary
        let facs_off = dsdt_off + DSDT_LEN; // 4764
        let total_size = facs_off + FACS_LEN; // 4828

        let entries = [
            (rsdp_phys, rsdp_off, RSDP_LEN, MAPPING_KIND_RSDP),
            (xsdt_phys, xsdt_off, XSDT_LEN, MAPPING_KIND_TABLE),
            (fadt_phys, fadt_off, FADT_LEN, MAPPING_KIND_TABLE),
            (dsdt_phys, dsdt_off, DSDT_LEN, MAPPING_KIND_TABLE),
            (facs_phys, facs_off, FACS_LEN, MAPPING_KIND_TABLE),
        ];

        let mut bytes = vec![0u8; total_size as usize];
        for (index, &(physical_address, offset, length, kind)) in entries.iter().enumerate() {
            let entry = PhysicalMappingEntry {
                physical_address,
                offset,
                length,
                kind,
            };
            let start = acpi_archive::HEADER_BYTES + index * MAPPING_ENTRY_BYTES;
            assert_eq!(
                encode_v2_mapping(&entry, &mut bytes[start..start + MAPPING_ENTRY_BYTES]),
                Ok(())
            );
        }

        let header = ArchiveV2Header {
            total_size,
            firmware_snapshot_id: 7,
            table_count: 5,
            mapping_count: 5,
            table_entries_offset: mappings_offset,
            mappings_offset,
            payload_offset,
            rsdp: RsdpDescriptor {
                physical_address: rsdp_phys,
                offset: rsdp_off,
                length: RSDP_LEN as u32,
                mapping_index: 0,
                revision: 2,
            },
        };

        GraphFixture {
            bytes,
            header,
            rsdp_phys,
            xsdt_phys,
            fadt_phys,
            dsdt_phys,
            facs_phys,
            rsdp_off,
            xsdt_off,
            fadt_off,
            dsdt_off,
            facs_off,
            dsdt_len: DSDT_LEN,
        }
    }

    #[test]
    fn synthetic_rsdp_xsdt_fadt_dsdt_facs_graph_translates() {
        let fixture = graph_archive();
        let header = &fixture.header;
        let bytes = fixture.bytes.as_slice();
        for (phys, offset, length) in [
            (fixture.rsdp_phys, fixture.rsdp_off, 36u64),
            (fixture.xsdt_phys, fixture.xsdt_off, 128),
            (fixture.fadt_phys, fixture.fadt_off, 244),
            (fixture.dsdt_phys, fixture.dsdt_off, fixture.dsdt_len),
            (fixture.facs_phys, fixture.facs_off, 64),
        ] {
            assert_eq!(
                translate_archive(bytes, header, phys, length),
                usize::try_from(offset).ok(),
                "phys {phys:#x} len {length}"
            );
        }
        // Full-table sized requests: exact length succeeds, one byte more fails.
        assert_eq!(
            translate_archive(bytes, header, fixture.xsdt_phys, 129),
            None
        );
        assert_eq!(
            translate_archive(bytes, header, fixture.dsdt_phys, fixture.dsdt_len),
            Some(fixture.dsdt_off as usize)
        );
        assert_eq!(
            translate_archive(bytes, header, fixture.dsdt_phys, fixture.dsdt_len + 1),
            None
        );
        // Sub-range inside a record, including an unaligned start, is arithmetic.
        assert_eq!(
            translate_archive(bytes, header, fixture.xsdt_phys + 3, 8),
            Some(fixture.xsdt_off as usize + 3)
        );
        // Released original RSDP is serviceable from the translated archive.
        assert_eq!(
            translate_archive(bytes, header, fixture.rsdp_phys, 8),
            Some(fixture.rsdp_off as usize)
        );
    }

    #[test]
    fn adjacent_records_gaps_and_ecam_ranges_are_rejected() {
        let fixture = graph_archive();
        let header = &fixture.header;
        let bytes = fixture.bytes.as_slice();
        // One range covering the tail of RSDP and the head of XSDT spans two
        // adjacent records; it must not be silently merged.
        assert_eq!(
            translate_archive(bytes, header, fixture.rsdp_phys + 32, 16),
            None
        );
        // Back-to-back DSDT/FACS: a range may not straddle the boundary.
        let dsdt_end = fixture.dsdt_phys + fixture.dsdt_len;
        assert_eq!(translate_archive(bytes, header, dsdt_end - 4, 8), None);
        // Unindexed RAM gap between FADT end and DSDT start.
        assert_eq!(translate_archive(bytes, header, 0xE0600, 8), None);
        // ECAM-like and IOAPIC-like MMIO addresses are not indexed either.
        assert_eq!(translate_archive(bytes, header, 0x8000_0000, 0x1000), None);
        assert_eq!(translate_archive(bytes, header, 0xFEC0_0000, 4), None);
        // Zero-length requests are rejected even at a valid record start.
        assert_eq!(translate_archive(bytes, header, fixture.rsdp_phys, 0), None);
    }

    #[test]
    fn page_boundary_range_inside_one_record_is_accepted() {
        let fixture = graph_archive();
        let header = &fixture.header;
        let bytes = fixture.bytes.as_slice();
        // The DSDT record straddles the 4 KiB archive page boundary (file
        // offsets 664..4764). Ask for the range that crosses file offset 4096.
        let file_offset = 4090u64;
        let phys = fixture.dsdt_phys + (file_offset - fixture.dsdt_off);
        assert_eq!(
            translate_archive(bytes, header, phys, 16),
            Some(file_offset as usize)
        );
        // The full remainder of the record, ending exactly at its end.
        let remainder = fixture.dsdt_off + fixture.dsdt_len - file_offset;
        assert_eq!(
            translate_archive(bytes, header, phys, remainder),
            Some(file_offset as usize)
        );
        // One byte past the record end is a two-records (or overflow) request.
        assert_eq!(translate_archive(bytes, header, phys, remainder + 1), None);
    }

    #[test]
    fn unmap_is_a_process_lifetime_bookkeeping_noop() {
        // The full uACPI unmap entry point must never try to release the
        // sealed VMO mapping; it is bookkeeping only, for any pointer/length.
        uacpi_kernel_unmap(core::ptr::null_mut(), 0);
        uacpi_kernel_unmap(ARCHIVE_MAP_BASE as *mut c_void, 4096);
    }

    // Deterministic LCG so the decode/translate fuzz runs are reproducible
    // across machines without pulling in a random dependency.
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn byte(&mut self) -> u8 {
            (self.next() & 0xff) as u8
        }

        fn word(&mut self) -> u16 {
            (self.next() & 0xffff) as u16
        }
    }

    #[test]
    fn translator_never_panics_on_random_archives() {
        let mut rng = Lcg::new(0x853c49e6748fea9b);
        let total = (acpi_archive::HEADER_BYTES + 4 * MAPPING_ENTRY_BYTES + 64) as u64;
        let payload_base = (acpi_archive::HEADER_BYTES + 4 * MAPPING_ENTRY_BYTES) as u64;
        for _ in 0..2_000u32 {
            let mut bytes = vec![0u8; total as usize];
            let mapping_count = rng.byte() % 4;
            for index in 0..mapping_count {
                let entry = PhysicalMappingEntry {
                    physical_address: rng.next() % 0x0010_0000,
                    offset: payload_base + u64::from(rng.word()) % 64,
                    length: u64::from(rng.word()) % 512,
                    kind: 1 + (rng.byte() & 1),
                };
                let start = acpi_archive::HEADER_BYTES + usize::from(index) * MAPPING_ENTRY_BYTES;
                assert_eq!(
                    encode_v2_mapping(&entry, &mut bytes[start..start + MAPPING_ENTRY_BYTES]),
                    Ok(())
                );
            }
            let header = ArchiveV2Header {
                total_size: total,
                firmware_snapshot_id: 1 + u64::from(rng.word()),
                table_count: 0,
                mapping_count: u32::from(mapping_count),
                table_entries_offset: acpi_archive::HEADER_BYTES as u64,
                mappings_offset: acpi_archive::HEADER_BYTES as u64,
                payload_offset: payload_base,
                rsdp: RsdpDescriptor::default(),
            };
            let query_address = rng.next() % 0x0012_0000;
            let query_length = u64::from(rng.next() % 1024);
            // The valuable property: no panic, and any success stays in bounds.
            if let Some(offset) = translate_archive(&bytes, &header, query_address, query_length) {
                assert!(query_length != 0);
                assert!(offset as u64 + query_length <= header.total_size);
            }
        }
    }
}
