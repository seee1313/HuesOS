//! Safe `#![no_std]`, `#![forbid(unsafe_code)]` PE32+ (`x86_64`) parser and
//! relocation/import/export engine for the HuesOS native PE64 subsystem.
//!
//! Every slice read in this crate is bounds-checked and integer-overflow-safe;
//! malformed or truncated `.exe` / `.dll` inputs produce a typed [`PeError`]
//! rather than panicking or invoking undefined behaviour.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

pub mod unwind;
pub mod win64_abi;

pub use unwind::{
    lookup_runtime_function, resolve_apiset_dll, virtual_unwind, RuntimeFunction,
    UnwindStepOutcome, Win64UnwindRegs, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_NHANDLER,
    UNW_FLAG_UHANDLER,
};

/// `MZ` magic at offset `0` of the MS-DOS header.
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
/// `PE\0\0` signature at `e_lfanew`.
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
/// COFF machine ID for `x86_64` / AMD64.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// Optional header magic for 64-bit PE32+ images.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

/// COFF characteristic: image is executable (no unresolved externals).
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
/// COFF characteristic: image can handle >2 GiB addresses.
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
/// COFF characteristic: image is a DLL rather than a standalone `.exe`.
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// Subsystem: native / driver.
pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
/// Subsystem: Windows GUI.
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
/// Subsystem: Windows character-mode console (`CUI`).
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

/// Section characteristic: contains executable code.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// Section characteristic: contains initialized data.
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
/// Section characteristic: contains uninitialized data.
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
/// Section characteristic: discardable after load.
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
/// Section characteristic: executable.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Section characteristic: readable.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// Section characteristic: writable.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Data directory index: Export Table (`.edata`).
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
/// Data directory index: Import Table (`.idata`).
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
/// Data directory index: Resource Table (`.rsrc`).
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
/// Data directory index: Exception Table (`.pdata`).
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
/// Data directory index: Base Relocation Table (`.reloc`).
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
/// Data directory index: Thread Local Storage Table (`.tls`).
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
/// Data directory index: Import Address Table (`IAT`).
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
/// Maximum number of PE data directories.
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/// Base relocation type: padding no-op.
pub const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
/// Base relocation type: 64-bit pointer delta (`*target += delta`).
pub const IMAGE_REL_BASED_DIR64: u8 = 10;

/// Ordinal import flag in a 64-bit `IMAGE_THUNK_DATA64`.
pub const IMAGE_SNAP_BY_ORDINAL64: u64 = 1u64 << 63;

/// Maximum sections accepted in a single PE32+ image.
pub const MAX_PE_SECTIONS: usize = 96;
/// Maximum virtual image span accepted by the loader (256 MiB).
pub const MAX_PE_IMAGE_SIZE: u32 = 256 * 1024 * 1024;

/// Errors returned when validating, parsing, or relocating a PE32+ image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    /// Input buffer is too short to hold the MS-DOS header.
    BufferTooShort,
    /// First two bytes are not `MZ` (`0x5A4D`).
    InvalidDosMagic,
    /// `e_lfanew` is negative, misaligned, or outside the file buffer.
    InvalidNtHeaderOffset,
    /// Signature at `e_lfanew` is not `PE\0\0`.
    InvalidPeSignature,
    /// COFF `Machine` is not `IMAGE_FILE_MACHINE_AMD64` (`0x8664`).
    UnsupportedMachine(u16),
    /// Optional header magic is not PE32+ (`0x020B`).
    UnsupportedOptionalMagic(u16),
    /// Optional header is smaller than the minimum PE32+ header.
    OptionalHeaderTooSmall,
    /// `NumberOfSections` is zero or exceeds [`MAX_PE_SECTIONS`].
    InvalidSectionCount(u16),
    /// Section table extends past the input file buffer.
    SectionTableTruncated,
    /// `SectionAlignment` or `FileAlignment` is invalid or non-power-of-two.
    InvalidAlignment,
    /// `SizeOfImage` or `SizeOfHeaders` is zero, unaligned, or exceeds [`MAX_PE_IMAGE_SIZE`].
    InvalidImageSize,
    /// A section's raw data or virtual span overflows or exceeds image bounds.
    InvalidSectionBounds,
    /// A section requests simultaneous write and execute permissions (`W^X` violation).
    WriteExecuteSection,
    /// An RVA could not be mapped into the loaded image or file buffer.
    RvaOutOfBounds(u32),
    /// Base relocation directory is missing on an image relocated away from `ImageBase`.
    MissingRelocations,
    /// A base relocation block is truncated or uses an unsupported relocation type.
    MalformedRelocationBlock,
    /// Export directory is missing or structurally invalid.
    MalformedExportDirectory,
    /// Requested export symbol or ordinal was not found.
    ExportNotFound,
    /// Import directory or thunk table is truncated or structurally invalid.
    MalformedImportDirectory,
    /// A C string inside an import/export table has no NUL terminator or invalid ASCII.
    UnterminatedString,
}

/// Quick check whether `bytes` begins with `MZ` and a valid `PE\0\0` signature.
///
/// Used by `libcanvas` and `hsh` to distinguish PE64 `.exe` binaries from ELF64
/// binaries before committing to an interpreter.
pub fn has_pe64_magic(bytes: &[u8]) -> bool {
    if bytes.len() < 64 {
        return false;
    }
    if read_u16_le(bytes, 0) != Some(IMAGE_DOS_SIGNATURE) {
        return false;
    }
    let Some(lfanew_u32) = read_u32_le(bytes, 0x3C) else {
        return false;
    };
    let lfanew = lfanew_u32 as usize;
    if read_u32_le(bytes, lfanew) != Some(IMAGE_NT_SIGNATURE) {
        return false;
    }
    if read_u16_le(bytes, lfanew.saturating_add(4)) != Some(IMAGE_FILE_MACHINE_AMD64) {
        return false;
    }
    read_u16_le(bytes, lfanew.saturating_add(24)) == Some(IMAGE_NT_OPTIONAL_HDR64_MAGIC)
}

/// Parsed COFF header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl CoffHeader {
    /// True when `IMAGE_FILE_DLL` is set.
    pub const fn is_dll(&self) -> bool {
        (self.characteristics & IMAGE_FILE_DLL) != 0
    }
}

/// One `(virtual_address, size)` entry in the PE32+ Optional Header data directories.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub const fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// Parsed 64-bit PE32+ Optional Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalHeader64 {
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: [DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

/// Parsed 40-byte `IMAGE_SECTION_HEADER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    /// Trimmed UTF-8/ASCII section name (e.g. `".text"`).
    pub fn name_str(&self) -> &str {
        let len = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub const fn is_readable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_READ) != 0
    }

    pub const fn is_writable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_WRITE) != 0
    }

    pub const fn is_executable(&self) -> bool {
        (self.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) != 0
    }

    pub const fn is_discardable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0
    }

    /// Effective virtual span occupied by this section before alignment rounding.
    pub const fn mapped_len(&self) -> u32 {
        if self.virtual_size != 0 {
            self.virtual_size
        } else {
            self.size_of_raw_data
        }
    }
}

/// Validated view over a raw PE32+ file buffer.
#[derive(Debug, Clone, Copy)]
pub struct PeImage<'a> {
    raw: &'a [u8],
    coff: CoffHeader,
    optional: OptionalHeader64,
    section_table_offset: usize,
}

impl<'a> PeImage<'a> {
    /// Parse and validate a complete PE32+ file buffer.
    pub fn parse(raw: &'a [u8]) -> Result<Self, PeError> {
        Self::parse_internal(raw, true)
    }

    /// Parse and validate only the headers + section table (for example from the
    /// first 4 KiB header window of a VMO before reading the full image).
    pub fn parse_headers(header_window: &'a [u8]) -> Result<Self, PeError> {
        Self::parse_internal(header_window, false)
    }

    fn parse_internal(raw: &'a [u8], check_raw_sections: bool) -> Result<Self, PeError> {
        if raw.len() < 64 {
            return Err(PeError::BufferTooShort);
        }
        if read_u16_le(raw, 0) != Some(IMAGE_DOS_SIGNATURE) {
            return Err(PeError::InvalidDosMagic);
        }
        let lfanew = read_u32_le(raw, 0x3C).ok_or(PeError::InvalidNtHeaderOffset)? as usize;
        if lfanew < 0x40 || (lfanew & 0x3) != 0 {
            return Err(PeError::InvalidNtHeaderOffset);
        }
        if read_u32_le(raw, lfanew) != Some(IMAGE_NT_SIGNATURE) {
            return Err(PeError::InvalidPeSignature);
        }

        let coff_off = lfanew
            .checked_add(4)
            .ok_or(PeError::InvalidNtHeaderOffset)?;
        if coff_off.checked_add(20).is_none_or(|end| end > raw.len()) {
            return Err(PeError::InvalidNtHeaderOffset);
        }

        let machine = read_u16_le(raw, coff_off).ok_or(PeError::InvalidNtHeaderOffset)?;
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(PeError::UnsupportedMachine(machine));
        }
        let number_of_sections =
            read_u16_le(raw, coff_off + 2).ok_or(PeError::InvalidNtHeaderOffset)?;
        if number_of_sections == 0 || (number_of_sections as usize) > MAX_PE_SECTIONS {
            return Err(PeError::InvalidSectionCount(number_of_sections));
        }
        let time_date_stamp =
            read_u32_le(raw, coff_off + 4).ok_or(PeError::InvalidNtHeaderOffset)?;
        let size_of_optional_header =
            read_u16_le(raw, coff_off + 16).ok_or(PeError::InvalidNtHeaderOffset)?;
        let characteristics =
            read_u16_le(raw, coff_off + 18).ok_or(PeError::InvalidNtHeaderOffset)?;

        let coff = CoffHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            size_of_optional_header,
            characteristics,
        };

        if (size_of_optional_header as usize) < 112 {
            return Err(PeError::OptionalHeaderTooSmall);
        }
        let opt_off = coff_off + 20;
        let opt_end = opt_off
            .checked_add(size_of_optional_header as usize)
            .ok_or(PeError::OptionalHeaderTooSmall)?;
        if opt_end > raw.len() {
            return Err(PeError::OptionalHeaderTooSmall);
        }

        let opt_magic = read_u16_le(raw, opt_off).ok_or(PeError::OptionalHeaderTooSmall)?;
        if opt_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(PeError::UnsupportedOptionalMagic(opt_magic));
        }

        let address_of_entry_point =
            read_u32_le(raw, opt_off + 16).ok_or(PeError::OptionalHeaderTooSmall)?;
        let image_base = read_u64_le(raw, opt_off + 24).ok_or(PeError::OptionalHeaderTooSmall)?;
        let section_alignment =
            read_u32_le(raw, opt_off + 32).ok_or(PeError::OptionalHeaderTooSmall)?;
        let file_alignment =
            read_u32_le(raw, opt_off + 36).ok_or(PeError::OptionalHeaderTooSmall)?;
        let size_of_image =
            read_u32_le(raw, opt_off + 56).ok_or(PeError::OptionalHeaderTooSmall)?;
        let size_of_headers =
            read_u32_le(raw, opt_off + 60).ok_or(PeError::OptionalHeaderTooSmall)?;
        let checksum = read_u32_le(raw, opt_off + 64).ok_or(PeError::OptionalHeaderTooSmall)?;
        let subsystem = read_u16_le(raw, opt_off + 68).ok_or(PeError::OptionalHeaderTooSmall)?;
        let dll_characteristics =
            read_u16_le(raw, opt_off + 70).ok_or(PeError::OptionalHeaderTooSmall)?;
        let size_of_stack_reserve =
            read_u64_le(raw, opt_off + 72).ok_or(PeError::OptionalHeaderTooSmall)?;
        let size_of_stack_commit =
            read_u64_le(raw, opt_off + 80).ok_or(PeError::OptionalHeaderTooSmall)?;
        let size_of_heap_reserve =
            read_u64_le(raw, opt_off + 88).ok_or(PeError::OptionalHeaderTooSmall)?;
        let size_of_heap_commit =
            read_u64_le(raw, opt_off + 96).ok_or(PeError::OptionalHeaderTooSmall)?;
        let number_of_rva_and_sizes =
            read_u32_le(raw, opt_off + 108).ok_or(PeError::OptionalHeaderTooSmall)?;

        if !section_alignment.is_power_of_two()
            || section_alignment < 4096
            || !file_alignment.is_power_of_two()
            || file_alignment < 512
            || section_alignment < file_alignment
        {
            return Err(PeError::InvalidAlignment);
        }

        if size_of_image == 0
            || size_of_image > MAX_PE_IMAGE_SIZE
            || size_of_headers == 0
            || size_of_headers > size_of_image
        {
            return Err(PeError::InvalidImageSize);
        }

        let mut data_directories = [DataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        let dir_count = (number_of_rva_and_sizes as usize).min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for (idx, slot) in data_directories.iter_mut().enumerate().take(dir_count) {
            let dir_off = opt_off + 112 + idx * 8;
            if dir_off + 8 <= opt_end {
                let va = read_u32_le(raw, dir_off).unwrap_or(0);
                let sz = read_u32_le(raw, dir_off + 4).unwrap_or(0);
                *slot = DataDirectory {
                    virtual_address: va,
                    size: sz,
                };
            }
        }

        let section_table_offset = opt_end;
        let section_table_bytes = (number_of_sections as usize)
            .checked_mul(40)
            .ok_or(PeError::SectionTableTruncated)?;
        let section_table_end = section_table_offset
            .checked_add(section_table_bytes)
            .ok_or(PeError::SectionTableTruncated)?;
        if section_table_end > raw.len() {
            return Err(PeError::SectionTableTruncated);
        }

        let optional = OptionalHeader64 {
            address_of_entry_point,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            number_of_rva_and_sizes,
            data_directories,
        };

        let image = Self {
            raw,
            coff,
            optional,
            section_table_offset,
        };

        for idx in 0..(number_of_sections as usize) {
            let sec = image.section(idx).ok_or(PeError::SectionTableTruncated)?;
            if sec.is_writable() && (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 {
                return Err(PeError::WriteExecuteSection);
            }
            let vend = sec
                .virtual_address
                .checked_add(sec.mapped_len())
                .ok_or(PeError::InvalidSectionBounds)?;
            if vend > size_of_image {
                return Err(PeError::InvalidSectionBounds);
            }
            if check_raw_sections && sec.size_of_raw_data != 0 {
                let raw_end = (sec.pointer_to_raw_data as usize)
                    .checked_add(sec.size_of_raw_data as usize)
                    .ok_or(PeError::InvalidSectionBounds)?;
                if raw_end > raw.len() {
                    return Err(PeError::InvalidSectionBounds);
                }
            }
        }

        if address_of_entry_point != 0 && address_of_entry_point >= size_of_image {
            return Err(PeError::RvaOutOfBounds(address_of_entry_point));
        }

        Ok(image)
    }

    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub const fn coff(&self) -> &CoffHeader {
        &self.coff
    }

    pub const fn optional(&self) -> &OptionalHeader64 {
        &self.optional
    }

    pub const fn is_dll(&self) -> bool {
        self.coff.is_dll()
    }

    pub const fn section_count(&self) -> usize {
        self.coff.number_of_sections as usize
    }

    pub fn data_directory(&self, index: usize) -> DataDirectory {
        self.optional
            .data_directories
            .get(index)
            .copied()
            .unwrap_or_default()
    }

    /// Read the `index`-th section header (`0..section_count()`).
    pub fn section(&self, index: usize) -> Option<SectionHeader> {
        if index >= self.section_count() {
            return None;
        }
        let off = self.section_table_offset + index * 40;
        let mut name = [0u8; 8];
        name.copy_from_slice(self.raw.get(off..off + 8)?);
        Some(SectionHeader {
            name,
            virtual_size: read_u32_le(self.raw, off + 8)?,
            virtual_address: read_u32_le(self.raw, off + 12)?,
            size_of_raw_data: read_u32_le(self.raw, off + 16)?,
            pointer_to_raw_data: read_u32_le(self.raw, off + 20)?,
            characteristics: read_u32_le(self.raw, off + 36)?,
        })
    }

    /// Iterate over all validated section headers.
    pub fn sections(&self) -> SectionIter<'a> {
        SectionIter {
            image: *self,
            index: 0,
        }
    }

    /// Materialize headers and all non-discardable sections into a zero-initialized
    /// destination slice of length `>= self.optional.size_of_image as usize`.
    pub fn materialize_into(&self, mapped_image: &mut [u8]) -> Result<(), PeError> {
        let img_len = self.optional.size_of_image as usize;
        if mapped_image.len() < img_len {
            return Err(PeError::InvalidImageSize);
        }
        mapped_image[..img_len].fill(0);
        let hdr_copy = (self.optional.size_of_headers as usize).min(self.raw.len());
        mapped_image[..hdr_copy].copy_from_slice(&self.raw[..hdr_copy]);

        for sec in self.sections() {
            if sec.size_of_raw_data == 0 {
                continue;
            }
            let copy_len = if sec.virtual_size != 0 {
                (sec.size_of_raw_data.min(sec.virtual_size)) as usize
            } else {
                sec.size_of_raw_data as usize
            };
            let src_start = sec.pointer_to_raw_data as usize;
            let src_end = src_start
                .checked_add(copy_len)
                .ok_or(PeError::InvalidSectionBounds)?;
            let dst_start = sec.virtual_address as usize;
            let dst_end = dst_start
                .checked_add(copy_len)
                .ok_or(PeError::InvalidSectionBounds)?;
            let src = self
                .raw
                .get(src_start..src_end)
                .ok_or(PeError::InvalidSectionBounds)?;
            let dst = mapped_image
                .get_mut(dst_start..dst_end)
                .ok_or(PeError::InvalidSectionBounds)?;
            dst.copy_from_slice(src);
        }
        Ok(())
    }
}

/// Iterator over [`SectionHeader`]s in a [`PeImage`].
pub struct SectionIter<'a> {
    image: PeImage<'a>,
    index: usize,
}

impl<'a> Iterator for SectionIter<'a> {
    type Item = SectionHeader;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.image.section(self.index)?;
        self.index += 1;
        Some(item)
    }
}

/// Apply `IMAGE_DIRECTORY_ENTRY_BASERELOC` fixups to an already-materialized
/// image buffer loaded at `actual_base` instead of `preferred_base`.
///
/// Returns the number of `DIR64` slots patched.
pub fn apply_base_relocations(
    mapped_image: &mut [u8],
    reloc_dir: DataDirectory,
    preferred_base: u64,
    actual_base: u64,
) -> Result<usize, PeError> {
    let delta = actual_base.wrapping_sub(preferred_base);
    if delta == 0 {
        return Ok(0);
    }
    if !reloc_dir.is_present() {
        return Err(PeError::MissingRelocations);
    }

    let dir_start = reloc_dir.virtual_address as usize;
    let dir_end = dir_start
        .checked_add(reloc_dir.size as usize)
        .ok_or(PeError::MalformedRelocationBlock)?;
    if dir_end > mapped_image.len() {
        return Err(PeError::RvaOutOfBounds(reloc_dir.virtual_address));
    }

    // Collect relocation targets in a two-step bounded walk without aliasing
    // `mapped_image` mutably while reading the `.reloc` directory inside it.
    let mut cursor = dir_start;
    let mut patched = 0usize;
    while cursor < dir_end {
        if cursor + 8 > dir_end {
            return Err(PeError::MalformedRelocationBlock);
        }
        let page_rva =
            read_u32_le(mapped_image, cursor).ok_or(PeError::MalformedRelocationBlock)?;
        let block_size = read_u32_le(mapped_image, cursor + 4)
            .ok_or(PeError::MalformedRelocationBlock)? as usize;
        if block_size == 0 {
            break;
        }
        if block_size < 8 || (block_size & 1) != 0 || cursor + block_size > dir_end {
            return Err(PeError::MalformedRelocationBlock);
        }
        let entries = (block_size - 8) / 2;
        for idx in 0..entries {
            let entry = read_u16_le(mapped_image, cursor + 8 + idx * 2)
                .ok_or(PeError::MalformedRelocationBlock)?;
            let rel_type = (entry >> 12) as u8;
            let offset = (entry & 0x0FFF) as u32;
            match rel_type {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 => {
                    let target_rva = page_rva
                        .checked_add(offset)
                        .ok_or(PeError::MalformedRelocationBlock)?
                        as usize;
                    let orig = read_u64_le(mapped_image, target_rva)
                        .ok_or(PeError::RvaOutOfBounds(target_rva as u32))?;
                    let updated = orig.wrapping_add(delta);
                    write_u64_le(mapped_image, target_rva, updated)
                        .ok_or(PeError::RvaOutOfBounds(target_rva as u32))?;
                    patched += 1;
                }
                _ => return Err(PeError::MalformedRelocationBlock),
            }
        }
        cursor += block_size;
    }

    Ok(patched)
}

/// Resolution result from an Export Address Table (`EAT`) lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportTarget<'a> {
    /// Direct RVA inside this module (`actual_va = module_base + rva`).
    CodeOrDataRva(u32),
    /// Forwarder string inside `.edata` (e.g. `"NTDLL.RtlAllocateHeap"`).
    Forwarded(&'a str),
}

/// Resolve an exported symbol by exact ASCII name from a materialized PE32+ image.
pub fn resolve_export_by_name<'a>(
    mapped_image: &'a [u8],
    export_dir: DataDirectory,
    symbol_name: &str,
) -> Result<ExportTarget<'a>, PeError> {
    if !export_dir.is_present() {
        return Err(PeError::ExportNotFound);
    }
    let dir_off = export_dir.virtual_address as usize;
    let dir_end = dir_off
        .checked_add(export_dir.size as usize)
        .ok_or(PeError::MalformedExportDirectory)?;
    if dir_off
        .checked_add(40)
        .is_none_or(|end| end > mapped_image.len())
        || dir_end > mapped_image.len()
    {
        return Err(PeError::MalformedExportDirectory);
    }

    let number_of_functions =
        read_u32_le(mapped_image, dir_off + 20).ok_or(PeError::MalformedExportDirectory)? as usize;
    let number_of_names =
        read_u32_le(mapped_image, dir_off + 24).ok_or(PeError::MalformedExportDirectory)? as usize;
    let addr_of_functions =
        read_u32_le(mapped_image, dir_off + 28).ok_or(PeError::MalformedExportDirectory)? as usize;
    let addr_of_names =
        read_u32_le(mapped_image, dir_off + 32).ok_or(PeError::MalformedExportDirectory)? as usize;
    let addr_of_name_ordinals =
        read_u32_le(mapped_image, dir_off + 36).ok_or(PeError::MalformedExportDirectory)? as usize;

    if number_of_names == 0 || number_of_functions == 0 {
        return Err(PeError::ExportNotFound);
    }

    // Binary search first (standard sorted PE EAT); fall back to linear scan if needed.
    let mut lo = 0usize;
    let mut hi = number_of_names;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let name_rva_off = addr_of_names
            .checked_add(
                mid.checked_mul(4)
                    .ok_or(PeError::MalformedExportDirectory)?,
            )
            .ok_or(PeError::MalformedExportDirectory)?;
        let name_rva =
            read_u32_le(mapped_image, name_rva_off).ok_or(PeError::MalformedExportDirectory)?;
        let candidate = read_cstr(mapped_image, name_rva as usize)?;
        match candidate.as_bytes().cmp(symbol_name.as_bytes()) {
            core::cmp::Ordering::Equal => {
                return finish_export_index(
                    mapped_image,
                    export_dir,
                    number_of_functions,
                    addr_of_functions,
                    addr_of_name_ordinals,
                    mid,
                );
            }
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
        }
    }

    for idx in 0..number_of_names {
        let name_rva_off = addr_of_names
            .checked_add(
                idx.checked_mul(4)
                    .ok_or(PeError::MalformedExportDirectory)?,
            )
            .ok_or(PeError::MalformedExportDirectory)?;
        let name_rva =
            read_u32_le(mapped_image, name_rva_off).ok_or(PeError::MalformedExportDirectory)?;
        let candidate = read_cstr(mapped_image, name_rva as usize)?;
        if candidate == symbol_name {
            return finish_export_index(
                mapped_image,
                export_dir,
                number_of_functions,
                addr_of_functions,
                addr_of_name_ordinals,
                idx,
            );
        }
    }

    Err(PeError::ExportNotFound)
}

fn finish_export_index<'a>(
    mapped_image: &'a [u8],
    export_dir: DataDirectory,
    number_of_functions: usize,
    addr_of_functions: usize,
    addr_of_name_ordinals: usize,
    name_index: usize,
) -> Result<ExportTarget<'a>, PeError> {
    let ord_off = addr_of_name_ordinals
        .checked_add(
            name_index
                .checked_mul(2)
                .ok_or(PeError::MalformedExportDirectory)?,
        )
        .ok_or(PeError::MalformedExportDirectory)?;
    let func_idx =
        read_u16_le(mapped_image, ord_off).ok_or(PeError::MalformedExportDirectory)? as usize;
    resolve_export_function_index(
        mapped_image,
        export_dir,
        number_of_functions,
        addr_of_functions,
        func_idx,
    )
}

/// Resolve an exported symbol by biased ordinal (`ordinal >= Base`) from a
/// materialized PE32+ image.
pub fn resolve_export_by_ordinal<'a>(
    mapped_image: &'a [u8],
    export_dir: DataDirectory,
    ordinal: u16,
) -> Result<ExportTarget<'a>, PeError> {
    if !export_dir.is_present() {
        return Err(PeError::ExportNotFound);
    }
    let dir_off = export_dir.virtual_address as usize;
    if dir_off
        .checked_add(40)
        .is_none_or(|end| end > mapped_image.len())
    {
        return Err(PeError::MalformedExportDirectory);
    }
    let ordinal_base =
        read_u32_le(mapped_image, dir_off + 16).ok_or(PeError::MalformedExportDirectory)?;
    let number_of_functions =
        read_u32_le(mapped_image, dir_off + 20).ok_or(PeError::MalformedExportDirectory)? as usize;
    let addr_of_functions =
        read_u32_le(mapped_image, dir_off + 28).ok_or(PeError::MalformedExportDirectory)? as usize;

    let ord_u32 = ordinal as u32;
    if ord_u32 < ordinal_base {
        return Err(PeError::ExportNotFound);
    }
    let func_idx = (ord_u32 - ordinal_base) as usize;
    resolve_export_function_index(
        mapped_image,
        export_dir,
        number_of_functions,
        addr_of_functions,
        func_idx,
    )
}

fn resolve_export_function_index<'a>(
    mapped_image: &'a [u8],
    export_dir: DataDirectory,
    number_of_functions: usize,
    addr_of_functions: usize,
    func_idx: usize,
) -> Result<ExportTarget<'a>, PeError> {
    if func_idx >= number_of_functions {
        return Err(PeError::ExportNotFound);
    }
    let fn_off = addr_of_functions
        .checked_add(
            func_idx
                .checked_mul(4)
                .ok_or(PeError::MalformedExportDirectory)?,
        )
        .ok_or(PeError::MalformedExportDirectory)?;
    let target_rva = read_u32_le(mapped_image, fn_off).ok_or(PeError::MalformedExportDirectory)?;
    if target_rva == 0 {
        return Err(PeError::ExportNotFound);
    }

    let dir_end = export_dir.virtual_address.saturating_add(export_dir.size);
    if target_rva >= export_dir.virtual_address && target_rva < dir_end {
        let forwarder = read_cstr(mapped_image, target_rva as usize)?;
        Ok(ExportTarget::Forwarded(forwarder))
    } else {
        Ok(ExportTarget::CodeOrDataRva(target_rva))
    }
}

/// One parsed `IMAGE_IMPORT_DESCRIPTOR` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportDescriptor<'a> {
    pub dll_name: &'a str,
    /// RVA of the Import Lookup Table (`OriginalFirstThunk`, or `FirstThunk` if `0`).
    pub lookup_thunk_rva: u32,
    /// RVA of the Import Address Table (`FirstThunk`) to overwrite with resolved VAs.
    pub iat_rva: u32,
}

/// One symbol reference inside an `ImportDescriptor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportSymbol<'a> {
    ByName { hint: u16, name: &'a str },
    ByOrdinal(u16),
}

/// One import slot to resolve and write back to `iat_slot_rva`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportBinding<'a> {
    pub iat_slot_rva: u32,
    pub symbol: ImportSymbol<'a>,
}

/// Parse the `index`-th `IMAGE_IMPORT_DESCRIPTOR` (`0..`), returning `Ok(None)`
/// at the all-zero terminating descriptor.
pub fn parse_import_descriptor<'a>(
    mapped_image: &'a [u8],
    import_dir: DataDirectory,
    index: usize,
) -> Result<Option<ImportDescriptor<'a>>, PeError> {
    if !import_dir.is_present() {
        return Ok(None);
    }
    let off = (import_dir.virtual_address as usize)
        .checked_add(
            index
                .checked_mul(20)
                .ok_or(PeError::MalformedImportDirectory)?,
        )
        .ok_or(PeError::MalformedImportDirectory)?;
    let dir_end = (import_dir.virtual_address as usize)
        .checked_add(import_dir.size as usize)
        .ok_or(PeError::MalformedImportDirectory)?;
    if off + 20 > dir_end || off + 20 > mapped_image.len() {
        return Ok(None);
    }

    let original_first_thunk =
        read_u32_le(mapped_image, off).ok_or(PeError::MalformedImportDirectory)?;
    let name_rva = read_u32_le(mapped_image, off + 12).ok_or(PeError::MalformedImportDirectory)?;
    let first_thunk =
        read_u32_le(mapped_image, off + 16).ok_or(PeError::MalformedImportDirectory)?;

    if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
        return Ok(None);
    }
    if name_rva == 0 || first_thunk == 0 {
        return Err(PeError::MalformedImportDirectory);
    }

    let dll_name = read_cstr(mapped_image, name_rva as usize)?;
    let lookup_thunk_rva = if original_first_thunk != 0 {
        original_first_thunk
    } else {
        first_thunk
    };
    Ok(Some(ImportDescriptor {
        dll_name,
        lookup_thunk_rva,
        iat_rva: first_thunk,
    }))
}

/// Parse the `thunk_index`-th 64-bit thunk inside `desc`, returning `Ok(None)` at
/// the zero-terminated end of the thunk array.
pub fn parse_import_binding<'a>(
    mapped_image: &'a [u8],
    desc: &ImportDescriptor<'a>,
    thunk_index: usize,
) -> Result<Option<ImportBinding<'a>>, PeError> {
    let byte_off = thunk_index
        .checked_mul(8)
        .ok_or(PeError::MalformedImportDirectory)?;
    let ilt_off = (desc.lookup_thunk_rva as usize)
        .checked_add(byte_off)
        .ok_or(PeError::MalformedImportDirectory)?;
    let iat_rva = desc
        .iat_rva
        .checked_add(byte_off as u32)
        .ok_or(PeError::MalformedImportDirectory)?;
    if (iat_rva as usize)
        .checked_add(8)
        .is_none_or(|end| end > mapped_image.len())
    {
        return Err(PeError::MalformedImportDirectory);
    }

    let thunk = read_u64_le(mapped_image, ilt_off).ok_or(PeError::MalformedImportDirectory)?;
    if thunk == 0 {
        return Ok(None);
    }

    let symbol = if (thunk & IMAGE_SNAP_BY_ORDINAL64) != 0 {
        ImportSymbol::ByOrdinal((thunk & 0xFFFF) as u16)
    } else {
        let ibn_rva = (thunk & 0x7FFF_FFFF) as usize;
        let hint = read_u16_le(mapped_image, ibn_rva).ok_or(PeError::MalformedImportDirectory)?;
        let name = read_cstr(mapped_image, ibn_rva + 2)?;
        ImportSymbol::ByName { hint, name }
    };

    Ok(Some(ImportBinding {
        iat_slot_rva: iat_rva,
        symbol,
    }))
}

/// Write a resolved 64-bit virtual address into an IAT slot inside `mapped_image`.
pub fn write_iat_slot(
    mapped_image: &mut [u8],
    iat_slot_rva: u32,
    resolved_va: u64,
) -> Result<(), PeError> {
    write_u64_le(mapped_image, iat_slot_rva as usize, resolved_va)
        .ok_or(PeError::RvaOutOfBounds(iat_slot_rva))
}

/// Parsed 64-bit `IMAGE_TLS_DIRECTORY64` (if `IMAGE_DIRECTORY_ENTRY_TLS` is present).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsDirectory64 {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

/// Parse `IMAGE_TLS_DIRECTORY64` from a materialized PE32+ image.
pub fn parse_tls_directory(
    mapped_image: &[u8],
    tls_dir: DataDirectory,
) -> Result<Option<TlsDirectory64>, PeError> {
    if !tls_dir.is_present() {
        return Ok(None);
    }
    let off = tls_dir.virtual_address as usize;
    if off
        .checked_add(40)
        .is_none_or(|end| end > mapped_image.len())
    {
        return Err(PeError::RvaOutOfBounds(tls_dir.virtual_address));
    }
    Ok(Some(TlsDirectory64 {
        start_address_of_raw_data: read_u64_le(mapped_image, off).unwrap_or(0),
        end_address_of_raw_data: read_u64_le(mapped_image, off + 8).unwrap_or(0),
        address_of_index: read_u64_le(mapped_image, off + 16).unwrap_or(0),
        address_of_callbacks: read_u64_le(mapped_image, off + 24).unwrap_or(0),
        size_of_zero_fill: read_u32_le(mapped_image, off + 32).unwrap_or(0),
        characteristics: read_u32_le(mapped_image, off + 36).unwrap_or(0),
    }))
}

/// Case-insensitive ASCII comparison for DLL names (e.g. `"KERNEL32.dll"` == `"kernel32.dll"`).
pub fn eq_dll_name_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn read_cstr(buf: &[u8], offset: usize) -> Result<&str, PeError> {
    let tail = buf
        .get(offset..)
        .ok_or(PeError::RvaOutOfBounds(offset as u32))?;
    let max_scan = tail.len().min(512);
    let nul_pos = tail[..max_scan]
        .iter()
        .position(|&b| b == 0)
        .ok_or(PeError::UnterminatedString)?;
    core::str::from_utf8(&tail[..nul_pos]).map_err(|_| PeError::UnterminatedString)
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let bytes = buf.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn write_u64_le(buf: &mut [u8], off: usize, val: u64) -> Option<()> {
    let dst = buf.get_mut(off..off.checked_add(8)?)?;
    dst.copy_from_slice(&val.to_le_bytes());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn build_synthetic_pe64(is_dll: bool, wx_violation: bool) -> Vec<u8> {
        let mut file = vec![0u8; 0x1000];
        // DOS header
        file[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        file[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // NT signature
        let nt = 0x80usize;
        file[nt..nt + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
        // COFF header (20 bytes)
        let coff = nt + 4;
        file[coff..coff + 2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        file[coff + 2..coff + 4].copy_from_slice(&3u16.to_le_bytes()); // .text, .rdata, .reloc
        file[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        let chars = IMAGE_FILE_EXECUTABLE_IMAGE
            | IMAGE_FILE_LARGE_ADDRESS_AWARE
            | if is_dll { IMAGE_FILE_DLL } else { 0 };
        file[coff + 18..coff + 20].copy_from_slice(&chars.to_le_bytes());

        // OptionalHeader64 (240 bytes)
        let opt = coff + 20;
        file[opt..opt + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        file[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EntryPoint
        file[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        file[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        file[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        file[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
        file[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        file[opt + 68..opt + 70].copy_from_slice(&IMAGE_SUBSYSTEM_WINDOWS_CUI.to_le_bytes());
        file[opt + 72..opt + 80].copy_from_slice(&0x10_0000u64.to_le_bytes()); // StackReserve
        file[opt + 80..opt + 88].copy_from_slice(&0x4000u64.to_le_bytes()); // StackCommit
        file[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // DataDirectory[EXPORT] at RVA 0x2000, size 0x80
        let dd = opt + 112;
        file[dd..dd + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        file[dd + 4..dd + 8].copy_from_slice(&0x80u32.to_le_bytes());
        // DataDirectory[IMPORT] at RVA 0x2100, size 40
        file[dd + 8..dd + 12].copy_from_slice(&0x2100u32.to_le_bytes());
        file[dd + 12..dd + 16].copy_from_slice(&40u32.to_le_bytes());
        // DataDirectory[BASERELOC] at RVA 0x3000, size 12
        file[dd + 5 * 8..dd + 5 * 8 + 4].copy_from_slice(&0x3000u32.to_le_bytes());
        file[dd + 5 * 8 + 4..dd + 5 * 8 + 8].copy_from_slice(&12u32.to_le_bytes());

        // Section headers (3 * 40 bytes)
        let sec0 = opt + 240;
        file[sec0..sec0 + 5].copy_from_slice(b".text");
        file[sec0 + 8..sec0 + 12].copy_from_slice(&0x200u32.to_le_bytes());
        file[sec0 + 12..sec0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        file[sec0 + 16..sec0 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        file[sec0 + 20..sec0 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        let text_chars = IMAGE_SCN_CNT_CODE
            | IMAGE_SCN_MEM_EXECUTE
            | IMAGE_SCN_MEM_READ
            | if wx_violation { IMAGE_SCN_MEM_WRITE } else { 0 };
        file[sec0 + 36..sec0 + 40].copy_from_slice(&text_chars.to_le_bytes());

        let sec1 = sec0 + 40;
        file[sec1..sec1 + 6].copy_from_slice(b".rdata");
        file[sec1 + 8..sec1 + 12].copy_from_slice(&0x400u32.to_le_bytes());
        file[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        file[sec1 + 16..sec1 + 20].copy_from_slice(&0x400u32.to_le_bytes());
        file[sec1 + 20..sec1 + 24].copy_from_slice(&0x600u32.to_le_bytes());
        file[sec1 + 36..sec1 + 40]
            .copy_from_slice(&(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ).to_le_bytes());

        let sec2 = sec1 + 40;
        file[sec2..sec2 + 6].copy_from_slice(b".reloc");
        file[sec2 + 8..sec2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
        file[sec2 + 12..sec2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        file[sec2 + 16..sec2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        file[sec2 + 20..sec2 + 24].copy_from_slice(&0xA00u32.to_le_bytes());
        file[sec2 + 36..sec2 + 40].copy_from_slice(
            &(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE)
                .to_le_bytes(),
        );

        // .text raw @ 0x400 -> RVA 0x1000: put a 64-bit pointer at RVA 0x1010
        file[0x400] = 0xC3; // ret
        file[0x410..0x418].copy_from_slice(&0x0000_0001_4000_2000u64.to_le_bytes());

        // .rdata raw @ 0x600 -> RVA 0x2000:
        // Export directory with 1 exported function "NtDelayExecution" -> RVA 0x1000
        let ed = 0x600usize;
        file[ed + 16..ed + 20].copy_from_slice(&1u32.to_le_bytes()); // Base = 1
        file[ed + 20..ed + 24].copy_from_slice(&1u32.to_le_bytes()); // NumberOfFunctions = 1
        file[ed + 24..ed + 28].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames = 1
        file[ed + 28..ed + 32].copy_from_slice(&0x2030u32.to_le_bytes()); // AddressOfFunctions
        file[ed + 32..ed + 36].copy_from_slice(&0x2034u32.to_le_bytes()); // AddressOfNames
        file[ed + 36..ed + 40].copy_from_slice(&0x2038u32.to_le_bytes()); // AddressOfNameOrdinals
        file[0x630..0x634].copy_from_slice(&0x1000u32.to_le_bytes()); // fn[0] = 0x1000
        file[0x634..0x638].copy_from_slice(&0x2040u32.to_le_bytes()); // name[0] = 0x2040
        file[0x638..0x63A].copy_from_slice(&0u16.to_le_bytes()); // ord[0] = 0
        file[0x640..0x640 + 17].copy_from_slice(b"NtDelayExecution\0");

        // Import directory @ 0x700 -> RVA 0x2100: imports "WriteFile" from "KERNEL32.dll"
        let id = 0x700usize;
        file[id..id + 4].copy_from_slice(&0x2140u32.to_le_bytes()); // ILT
        file[id + 12..id + 16].copy_from_slice(&0x2160u32.to_le_bytes()); // Name RVA
        file[id + 16..id + 20].copy_from_slice(&0x2180u32.to_le_bytes()); // IAT RVA
                                                                          // ILT[0] @ 0x740 (RVA 0x2140) -> IMAGE_IMPORT_BY_NAME @ RVA 0x21A0
        file[0x740..0x748].copy_from_slice(&0x21A0u64.to_le_bytes());
        file[0x760..0x760 + 13].copy_from_slice(b"KERNEL32.dll\0");
        file[0x780..0x788].copy_from_slice(&0x21A0u64.to_le_bytes());
        file[0x7A0..0x7A2].copy_from_slice(&7u16.to_le_bytes()); // Hint = 7
        file[0x7A2..0x7A2 + 10].copy_from_slice(b"WriteFile\0");

        // .reloc raw @ 0xA00 -> RVA 0x3000: patch RVA 0x1010 (DIR64) + padding ABSOLUTE
        file[0xA00..0xA04].copy_from_slice(&0x1000u32.to_le_bytes()); // PageRVA
        file[0xA04..0xA08].copy_from_slice(&12u32.to_le_bytes()); // SizeOfBlock
        let rel_entry = ((IMAGE_REL_BASED_DIR64 as u16) << 12) | 0x0010;
        file[0xA08..0xA0A].copy_from_slice(&rel_entry.to_le_bytes());
        file[0xA0A..0xA0C].copy_from_slice(&0u16.to_le_bytes()); // ABSOLUTE padding

        file
    }

    #[test]
    fn parses_materializes_relocates_and_resolves_pe64() {
        let raw = build_synthetic_pe64(true, false);
        assert!(has_pe64_magic(&raw));

        let pe = PeImage::parse(&raw).unwrap_or_else(|_| loop {});
        assert!(pe.is_dll());
        assert_eq!(pe.section_count(), 3);
        assert_eq!(pe.optional().image_base, 0x0000_0001_4000_0000);

        let mut mapped = vec![0u8; pe.optional().size_of_image as usize];
        assert_eq!(pe.materialize_into(&mut mapped), Ok(()));
        assert_eq!(mapped[0x1000], 0xC3);

        // Relocate by +0x20_0000
        let new_base = 0x0000_0001_4020_0000u64;
        let reloc_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        let patched =
            apply_base_relocations(&mut mapped, reloc_dir, pe.optional().image_base, new_base);
        assert_eq!(patched, Ok(1));
        assert_eq!(read_u64_le(&mapped, 0x1010), Some(0x0000_0001_4020_2000));

        // Resolve export by name and by ordinal
        let exp_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
        assert_eq!(
            resolve_export_by_name(&mapped, exp_dir, "NtDelayExecution"),
            Ok(ExportTarget::CodeOrDataRva(0x1000))
        );
        assert_eq!(
            resolve_export_by_ordinal(&mapped, exp_dir, 1),
            Ok(ExportTarget::CodeOrDataRva(0x1000))
        );
        assert_eq!(
            resolve_export_by_name(&mapped, exp_dir, "DoesNotExist"),
            Err(PeError::ExportNotFound)
        );

        // Parse import descriptor & binding, then patch IAT
        let imp_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        let desc = parse_import_descriptor(&mapped, imp_dir, 0)
            .unwrap_or(None)
            .unwrap_or(ImportDescriptor {
                dll_name: "",
                lookup_thunk_rva: 0,
                iat_rva: 0,
            });
        assert!(eq_dll_name_ignore_ascii_case(desc.dll_name, "kernel32.dll"));
        let binding = parse_import_binding(&mapped, &desc, 0).unwrap_or(None);
        assert_eq!(
            binding,
            Some(ImportBinding {
                iat_slot_rva: 0x2180,
                symbol: ImportSymbol::ByName {
                    hint: 7,
                    name: "WriteFile",
                },
            })
        );
        assert_eq!(parse_import_binding(&mapped, &desc, 1), Ok(None));
        assert_eq!(parse_import_descriptor(&mapped, imp_dir, 1), Ok(None));
        assert_eq!(
            write_iat_slot(&mut mapped, 0x2180, 0x0000_7FF0_1234_5678),
            Ok(())
        );
        assert_eq!(read_u64_le(&mapped, 0x2180), Some(0x0000_7FF0_1234_5678));
    }

    #[test]
    fn rejects_wx_section_and_non_pe_inputs() {
        let wx = build_synthetic_pe64(false, true);
        assert_eq!(
            PeImage::parse(&wx).err(),
            Some(PeError::WriteExecuteSection)
        );

        let elf_stub = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0";
        assert!(!has_pe64_magic(elf_stub));
        assert_eq!(
            PeImage::parse(elf_stub).err(),
            Some(PeError::BufferTooShort)
        );
    }

    #[test]
    fn resolves_apiset_and_unwinds_x64_pdata_xdata() {
        assert_eq!(
            resolve_apiset_dll("api-ms-win-crt-stdio-l1-1-0.dll"),
            Some("ucrtbase.dll")
        );
        assert_eq!(
            resolve_apiset_dll("VCRUNTIME140_1.DLL"),
            Some("ucrtbase.dll")
        );
        assert_eq!(
            resolve_apiset_dll("api-ms-win-core-synch-l1-2-0.dll"),
            Some("kernel32.dll")
        );
        assert_eq!(
            resolve_apiset_dll("api-ms-win-security-base-l1-1-0.dll"),
            Some("advapi32.dll")
        );
        assert_eq!(resolve_apiset_dll("ws2_32.dll"), None);

        // Synthetic mapped image with:
        // - `.text` at 0x1000..0x1020 (`push rbx; sub rsp, 0x20; ...; add rsp, 0x20; pop rbx; ret`)
        // - `.xdata` at 0x2000 (version 1 | UNW_FLAG_EHANDLER, prolog=5, codes=2:
        //    [offset=5, UWOP_ALLOC_SMALL (info=3 => 32B)], [offset=1, UWOP_PUSH_NONVOL (info=3 => rbx)],
        //    handler_rva = 0x1500)
        // - `.pdata` at 0x3000: [begin=0x1000, end=0x1020, unwind=0x2000]
        let mut img = alloc::vec![0u8; 0x4000];
        img[0x1000..0x1005].copy_from_slice(&[0x53, 0x48, 0x83, 0xEC, 0x20]);
        img[0x101A..0x1020].copy_from_slice(&[0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3]);

        // UNWIND_INFO at 0x2000
        img[0x2000] = 0x01 | (UNW_FLAG_EHANDLER << 3);
        img[0x2001] = 5; // size_of_prolog
        img[0x2002] = 2; // count_of_codes
        img[0x2003] = 0; // no frame reg
                         // Code 0: offset 5, UWOP_ALLOC_SMALL (2), op_info = 3 (3*8 + 8 = 32 bytes)
        img[0x2004] = 5;
        img[0x2005] = (3 << 4) | 2;
        // Code 1: offset 1, UWOP_PUSH_NONVOL (0), op_info = 3 (rbx)
        img[0x2006] = 1;
        img[0x2007] = (3 << 4) | 0;
        // ExceptionHandler RVA at 0x2008 = 0x1500
        img[0x2008..0x200C].copy_from_slice(&0x1500u32.to_le_bytes());

        // RUNTIME_FUNCTION at 0x3000
        img[0x3000..0x3004].copy_from_slice(&0x1000u32.to_le_bytes());
        img[0x3004..0x3008].copy_from_slice(&0x1020u32.to_le_bytes());
        img[0x3008..0x300C].copy_from_slice(&0x2000u32.to_le_bytes());

        let pdata = DataDirectory {
            virtual_address: 0x3000,
            size: 12,
        };
        let rf = lookup_runtime_function(&img, pdata, 0x100A);
        assert_eq!(
            rf,
            Some(RuntimeFunction {
                begin_address: 0x1000,
                end_address: 0x1020,
                unwind_info_rva: 0x2000,
            })
        );
        let rf_val = match rf {
            Some(v) => v,
            None => return,
        };

        // Stack frame at RSP = 0x7000:
        // [0x7000..0x7020] = 32B local alloc
        // [0x7020] = saved rbx (0xCAFE_BABE_1122_3344)
        // [0x7028] = caller return RIP (0x0000_0001_4000_0999)
        let mut regs = Win64UnwindRegs {
            gpr: [0; 16],
            rip: 0x0000_0001_4000_100A,
        };
        regs.set_rsp(0x7000);

        let step = virtual_unwind(
            &img,
            0x0000_0001_4000_0000,
            rf_val,
            &mut regs,
            UNW_FLAG_EHANDLER,
            |addr| match addr {
                0x7020 => Some(0xCAFE_BABE_1122_3344),
                0x7028 => Some(0x0000_0001_4000_0999),
                _ => Some(0),
            },
        );
        assert_eq!(
            step,
            Some(UnwindStepOutcome {
                establisher_frame: 0x7000,
                handler_rva: Some(0x1500),
                handler_data_rva: 0x200C,
            })
        );
        assert_eq!(regs.gpr[3], 0xCAFE_BABE_1122_3344);
        assert_eq!(regs.rsp(), 0x7030);
        assert_eq!(regs.rip, 0x0000_0001_4000_0999);
    }
}
