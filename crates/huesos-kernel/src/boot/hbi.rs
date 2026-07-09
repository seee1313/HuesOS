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
}

impl<'a> HbiImage<'a> {
    /// Parse an HBI image from a byte slice.
    ///
    /// This function is safe and performs all necessary size checks.
    pub fn parse(data: &'a [u8]) -> Result<Self, HbiError> {
        const HEADER_SIZE: usize = core::mem::size_of::<GlobalHeader>();

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

        let num_entries = header.num_entries as usize;

        let header_size = header.header_size as usize;
        if header_size < HEADER_SIZE || data.len() < header_size {
            return Err(HbiError::BufferTooSmall);
        }

        let entries_byte_len = num_entries
            .checked_mul(core::mem::size_of::<DirectoryEntry>())
            .ok_or(HbiError::ParseError)?;

        let entries_start = HEADER_SIZE;
        let entries_end = entries_start + entries_byte_len;

        if entries_end > data.len() {
            return Err(HbiError::BufferTooSmall);
        }

        // Read each directory entry with an unaligned read.
        let mut entries = alloc::vec::Vec::with_capacity(num_entries);
        let entry_size = core::mem::size_of::<DirectoryEntry>();
        for i in 0..num_entries {
            let off = entries_start + i * entry_size;
            let entry = unsafe {
                core::ptr::read_unaligned(data.as_ptr().add(off) as *const DirectoryEntry)
            };
            entries.push(entry);
        }

        Ok(Self {
            data,
            header,
            entries,
        })
    }

    /// Get the raw payload of a module by type.
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
            image_size: core::mem::size_of::<GlobalHeader>() as u64,
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
}
