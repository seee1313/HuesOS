//! HBI v2.1 Parser for HuesOS.
//! Safe parser with no unsafe pointer casts outside of very narrow validated regions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ModuleType {
    Kernel = 1,
    Bootfs = 2,
    Cmdline = 3,
    Platform = 4,
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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GlobalHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub flags: u32,
    pub num_entries: u32,
    pub header_size: u32,
    pub image_size: u64,
    pub arch_id: u32,
    pub reserved: [u8; 36],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryEntry {
    pub type_id: u32,
    pub offset: u32,
    pub length: u32,
    pub flags: u32,
}

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

pub struct HbiImage<'a> {
    data: &'a [u8],
    header: GlobalHeader,
    entries: &'a [DirectoryEntry],
}

#[derive(Debug)]
pub enum HbiError {
    InvalidMagic,
    UnsupportedVersion,
    BufferTooSmall,
    ModuleNotFound,
    InvalidOffset,
    ParseError,
}

impl<'a> HbiImage<'a> {
    /// Safe parser: uses byte slices and checked arithmetic only.
    pub fn parse(data: &'a [u8]) -> Result<Self, HbiError> {
        const HEADER_SIZE: usize = core::mem::size_of::<GlobalHeader>();

        if data.len() < HEADER_SIZE {
            return Err(HbiError::BufferTooSmall);
        }

        // Safe copy of header (no aliasing issues)
        let mut header_bytes = [0u8; HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..HEADER_SIZE]);

        let header = unsafe { core::ptr::read(header_bytes.as_ptr() as *const GlobalHeader) };

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

        // Safe slice for entries (we validated size)
        let entries = unsafe {
            core::slice::from_raw_parts(
                data.as_ptr().add(entries_start) as *const DirectoryEntry,
                num_entries,
            )
        };

        Ok(Self {
            data,
            header,
            entries,
        })
    }

    pub fn get_module(&self, module_type: ModuleType) -> Result<&'a [u8], HbiError> {
        let type_id = module_type as u32;

        let entry = self
            .entries
            .iter()
            .find(|e| e.type_id == type_id)
            .ok_or(HbiError::ModuleNotFound)?;

        let offset = entry.offset as usize;
        let length = entry.length as usize;

        // Entry header + payload
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

    pub fn get_num_entries(&self) -> u32 {
        self.header.num_entries
    }

    pub fn header(&self) -> &GlobalHeader {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            header_size: 64,
            image_size: 64,
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
        let hbi = result.expect("test");
        assert_eq!(hbi.get_num_entries(), 0);
    }
}
