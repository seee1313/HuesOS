//! HBI v2.1 Parser for HuesOS.
//! Safe parser with no unsafe pointer casts outside of very narrow validated regions.

/// Types of modules that can be present in an HBI image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ModuleType {
    /// The kernel ELF binary.
    Kernel = 1,
    /// Boot filesystem image.
    Bootfs = 2,
    /// Kernel command line.
    Cmdline = 3,
    /// Platform-specific data (device tree like).
    Platform = 4,
    /// Unknown module type.
    Unknown,
}

impl From<u32> for ModuleType {
    fn from(val: u32) -> Self {
        match val {
            1 => ModuleType::Kernel,
            2 => ModuleType::Bootfs,
            3 => ModuleType::Cmdline,
            4 => ModuleType::Platform,
            _ => ModuleType::Unknown,
        }
    }
}

/// Global header of an HBI image.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GlobalHeader {
    /// Magic bytes: "HUESOS_H".
    pub magic: [u8; 8],
    /// Version of the HBI format (currently 0x0002_0001).
    pub version: u32,
    /// Flags (reserved for future use).
    pub flags: u32,
    /// Number of directory entries that follow the header.
    pub num_entries: u32,
    /// Total size of the header section (including this header).
    pub header_size: u32,
    /// Total size of the entire HBI image.
    pub image_size: u64,
    /// Architecture identifier.
    pub arch_id: u32,
    /// Reserved for future use.
    pub reserved: [u8; 36],
}

/// Directory entry describing one module inside the HBI image.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryEntry {
    /// Module type (see [`ModuleType`]).
    pub type_id: u32,
    /// Offset from the start of the image to the module data.
    pub offset: u32,
    /// Length of the module data (after the per-module EntryHeader).
    pub length: u32,
    /// Flags for this entry.
    pub flags: u32,
}

/// Per-module header that immediately precedes the payload.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EntryHeader {
    pub type_id: u32,
    pub flags: u32,
    pub length: u32,
    pub extra: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// Parsed HBI image.
pub struct HbiImage<'a> {
    data: &'a [u8],
    header: GlobalHeader,
    entries: alloc::vec::Vec<DirectoryEntry>,
}

/// Errors that can occur while parsing an HBI image.
#[derive(Debug)]
pub enum HbiError {
    /// Magic bytes did not match.
    InvalidMagic,
    /// Unsupported HBI version.
    UnsupportedVersion,
    /// Input buffer too small for the declared header.
    BufferTooSmall,
    /// Requested module was not present.
    ModuleNotFound,
    /// Offset/length in directory entry was invalid.
    InvalidOffset,
    /// Generic parse error (e.g. arithmetic overflow).
    ParseError,
    /// The declared image_size does not match the actual buffer length.
    ImageSizeMismatch,
    /// The number of directory entries exceeds the sanity bound.
    TooManyEntries,
    /// A directory entry's type_id/length is inconsistent with its per-module
    /// EntryHeader.
    EntryMismatch,
    /// A module payload failed its recorded CRC32 check.
    ChecksumMismatch,
}

impl<'a> HbiImage<'a> {
    /// Parse an HBI image from a byte slice.
    ///
    /// This function is safe and performs all necessary size checks:
    /// - Magic and version validation.
    /// - `image_size` consistency with the actual buffer length.
    /// - `num_entries` sanity bound (max 256 directory entries).
    /// - Checked arithmetic for all offset/length computations.
    /// - Directory entry offset/length bounds against the buffer.
    /// - Directory entry ↔ EntryHeader type_id consistency.
    pub fn parse(data: &'a [u8]) -> Result<Self, HbiError> {
        const HEADER_SIZE: usize = core::mem::size_of::<GlobalHeader>();
        /// Sanity upper bound on directory entries. The boot image generator
        /// produces a handful of entries (kernel, bootfs, cmdline, platform);
        /// anything above this is either corrupted or a malicious image.
        const MAX_ENTRIES: usize = 256;

        if data.len() < HEADER_SIZE {
            return Err(HbiError::BufferTooSmall);
        }

        // Read header via unaligned read to avoid UB on arbitrary byte slices.
        let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const GlobalHeader) };

        if &header.magic != b"HUESOS_H" {
            return Err(HbiError::InvalidMagic);
        }

        if header.version != 0x0002_0001 {
            return Err(HbiError::UnsupportedVersion);
        }

        // Validate image_size: if non-zero, it must match the actual buffer.
        // A zero image_size is tolerated for forward-compatibility with
        // pre-release tooling that did not populate the field.
        if header.image_size != 0 && header.image_size as usize != data.len() {
            return Err(HbiError::ImageSizeMismatch);
        }

        let num_entries = header.num_entries as usize;
        if num_entries > MAX_ENTRIES {
            return Err(HbiError::TooManyEntries);
        }

        let header_size = header.header_size as usize;
        if header_size < HEADER_SIZE || data.len() < header_size {
            return Err(HbiError::BufferTooSmall);
        }

        let entries_byte_len = num_entries
            .checked_mul(core::mem::size_of::<DirectoryEntry>())
            .ok_or(HbiError::ParseError)?;

        let entries_start = HEADER_SIZE;
        let entries_end = entries_start
            .checked_add(entries_byte_len)
            .ok_or(HbiError::ParseError)?;

        if entries_end > data.len() || entries_end > header_size {
            return Err(HbiError::BufferTooSmall);
        }

        // Read each directory entry with an unaligned read.
        let mut entries: alloc::vec::Vec<DirectoryEntry> =
            alloc::vec::Vec::with_capacity(num_entries);
        let entry_size = core::mem::size_of::<DirectoryEntry>();
        for i in 0..num_entries {
            let off = entries_start
                .checked_add(i.checked_mul(entry_size).ok_or(HbiError::ParseError)?)
                .ok_or(HbiError::ParseError)?;
            let entry = unsafe {
                core::ptr::read_unaligned(data.as_ptr().add(off) as *const DirectoryEntry)
            };

            // Validate each entry's offset/length bounds before accepting it.
            let eh_offset = entry.offset as usize;
            if eh_offset < header_size {
                return Err(HbiError::InvalidOffset);
            }
            let entry_header_end = eh_offset
                .checked_add(core::mem::size_of::<EntryHeader>())
                .ok_or(HbiError::InvalidOffset)?;
            if entry_header_end > data.len() {
                return Err(HbiError::InvalidOffset);
            }
            let payload_start = entry_header_end;
            let payload_end = payload_start
                .checked_add(entry.length as usize)
                .ok_or(HbiError::InvalidOffset)?;
            if payload_end > data.len() {
                return Err(HbiError::InvalidOffset);
            }

            let header = unsafe {
                core::ptr::read_unaligned(data.as_ptr().add(eh_offset) as *const EntryHeader)
            };
            if header.type_id != entry.type_id || header.length != entry.length {
                return Err(HbiError::EntryMismatch);
            }
            if crc32(&data[payload_start..payload_end]) != header.crc32 {
                return Err(HbiError::ChecksumMismatch);
            }

            for existing in &entries {
                let existing_start = existing.offset as usize;
                let existing_payload_start = existing_start
                    .checked_add(core::mem::size_of::<EntryHeader>())
                    .ok_or(HbiError::InvalidOffset)?;
                let existing_payload_end = existing_payload_start
                    .checked_add(existing.length as usize)
                    .ok_or(HbiError::InvalidOffset)?;
                if ranges_overlap(
                    eh_offset,
                    payload_end.saturating_sub(eh_offset),
                    existing_start,
                    existing_payload_end.saturating_sub(existing_start),
                ) {
                    return Err(HbiError::InvalidOffset);
                }
            }

            entries.push(entry);
        }

        Ok(Self {
            data,
            header,
            entries,
        })
    }

    /// Get the raw payload of a module by type.
    ///
    /// The directory entry bounds were already validated during [`parse`];
    /// this re-validates for defense-in-depth in case entries are ever
    /// constructed by another path.
    pub fn get_module(&self, module_type: ModuleType) -> Result<&'a [u8], HbiError> {
        let type_id = module_type as u32;

        let entry = self
            .entries
            .iter()
            .find(|e| e.type_id == type_id)
            .ok_or(HbiError::ModuleNotFound)?;

        let offset = entry.offset as usize;
        let length = entry.length as usize;

        let payload_start = offset
            .checked_add(core::mem::size_of::<EntryHeader>())
            .ok_or(HbiError::InvalidOffset)?;

        let payload_end = payload_start
            .checked_add(length)
            .ok_or(HbiError::InvalidOffset)?;

        if payload_end > self.data.len() {
            return Err(HbiError::InvalidOffset);
        }

        Ok(&self.data[payload_start..payload_end])
    }

    /// Number of directory entries in this image.
    pub fn get_num_entries(&self) -> u32 {
        self.header.num_entries
    }

    /// Reference to the parsed global header.
    pub fn header(&self) -> &GlobalHeader {
        &self.header
    }
}

fn ranges_overlap(a_base: usize, a_size: usize, b_base: usize, b_size: usize) -> bool {
    let Some(a_end) = a_base.checked_add(a_size) else {
        return true;
    };
    let Some(b_end) = b_base.checked_add(b_size) else {
        return true;
    };
    a_size == 0 || b_size == 0 || (a_base < b_end && b_base < a_end)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= byte as u32;
        let mut bit = 0;
        while bit < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            bit += 1;
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_hbi_parse_invalid_magic() {
        let data = [0u8; 128];
        let result = HbiImage::parse(&data);
        assert!(matches!(result, Err(HbiError::InvalidMagic)));
    }

    #[test]
    fn test_hbi_parse_too_small() {
        let data = [0u8; 10];
        let result = HbiImage::parse(&data);
        assert!(matches!(result, Err(HbiError::BufferTooSmall)));
    }

    #[test]
    fn test_hbi_parse_valid_header() {
        let mut data = vec![0u8; 128];
        let header = GlobalHeader {
            magic: *b"HUESOS_H",
            version: 0x0002_0001,
            flags: 0,
            num_entries: 0,
            header_size: core::mem::size_of::<GlobalHeader>() as u32,
            image_size: 128,
            arch_id: 0,
            reserved: [0; 36],
        };

        let header_bytes = unsafe {
            core::slice::from_raw_parts(
                &header as *const GlobalHeader as *const u8,
                core::mem::size_of::<GlobalHeader>(),
            )
        };
        data[..core::mem::size_of::<GlobalHeader>()].copy_from_slice(header_bytes);

        let result = HbiImage::parse(&data);
        assert!(result.is_ok());
        let hbi = result.unwrap();
        assert_eq!(hbi.get_num_entries(), 0);
    }

    /// Build the first 32 bytes of an HBI global header directly (no unsafe
    /// transmute), filling the rest of `data` with zeroes.
    fn write_minimal_header(data: &mut [u8], num_entries: u32, image_size: u64) {
        data[..8].copy_from_slice(b"HUESOS_H");
        data[8..12].copy_from_slice(&0x0002_0001u32.to_le_bytes()); // version
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // flags
        data[16..20].copy_from_slice(&num_entries.to_le_bytes());
        data[20..24].copy_from_slice(&(core::mem::size_of::<GlobalHeader>() as u32).to_le_bytes()); // header_size
        data[24..32].copy_from_slice(&image_size.to_le_bytes());
    }

    #[test]
    fn test_hbi_parse_image_size_mismatch() {
        let mut data = vec![0u8; 128];
        write_minimal_header(&mut data, 0, 999); // wrong image_size
        let result = HbiImage::parse(&data);
        assert!(matches!(result, Err(HbiError::ImageSizeMismatch)));
    }

    #[test]
    fn test_hbi_parse_too_many_entries() {
        let mut data = vec![0u8; 128];
        write_minimal_header(&mut data, 257, 0); // above MAX_ENTRIES
        let result = HbiImage::parse(&data);
        assert!(matches!(result, Err(HbiError::TooManyEntries)));
    }
}
