//! HBI v2.1 Parser for HuesOS.
//! This module provides functionality to parse the HuesOS Boot Image (HBI) format.

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
    header: &'a GlobalHeader,
    entries: &'a [DirectoryEntry],
}

#[derive(Debug)]
pub enum HbiError {
    InvalidMagic,
    UnsupportedVersion,
    BufferTooSmall,
    ModuleNotFound,
    InvalidOffset,
}

impl<'a> HbiImage<'a> {
    /// Parse an HBI image from a byte slice.
    pub unsafe fn parse(data: &'a [u8]) -> Result<Self, HbiError> {
        if data.len() < core::mem::size_of::<GlobalHeader>() {
            return Err(HbiError::BufferTooSmall);
        }

        let header = &*(data.as_ptr() as *const GlobalHeader);

        if &header.magic != b"HUESOS_H" {
            return Err(HbiError::InvalidMagic);
        }

        if header.version != 0x0002_0001 {
            return Err(HbiError::UnsupportedVersion);
        }

        let num_entries = header.num_entries as usize;
        let entries_size = num_entries * core::mem::size_of::<DirectoryEntry>();
        
        if data.len() < (header.header_size as usize) {
            return Err(HbiError::BufferTooSmall);
        }

        let entries_ptr = data.as_ptr().add(core::mem::size_of::<GlobalHeader>());
        let entries = core::slice::from_raw_parts(entries_ptr as *const DirectoryEntry, num_entries);

        Ok(Self {
            data,
            header,
            entries,
        })
    }

    /// Get a specific module's data by its type.
    pub fn get_module(&self, module_type: ModuleType) -> Result<&'a [u8], HbiError> {
        let type_id = module_type as u32;
        
        let entry = self.entries.iter()
            .find(|e| e.type_id == type_id)
            .ok_or(HbiError::ModuleNotFound)?;

        let offset = entry.offset as usize;
        let length = entry.length as usize;

        if offset + core::mem::size_of::<EntryHeader>() + length > self.data.len() {
            return Err(HbiError::InvalidOffset);
        }

        // The payload starts after the EntryHeader
        let payload_offset = offset + core::mem::size_of::<EntryHeader>();
        Ok(&self.data[payload_offset..payload_offset + length])
    }

// ... (previous content) ...

    pub fn get_num_entries(&self) -> u32 {
        self.header.num_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hbi_parse_invalid_magic() {
        let data = [0u8; 128];
        let result = unsafe { HbiImage::parse(&data) };
        assert!(matches!(result, Err(HbiError::InvalidMagic)));
    }

    #[test]
    fn test_hbi_parse_too_small() {
        let data = [0u8; 10];
        let result = unsafe { HbiImage::parse(&data) };
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
        unsafe {
            std::ptr::copy_nonoverlapping(
                &header as *const GlobalHeader as *const u8,
                data.as_mut_ptr(),
                core::mem::size_of::<GlobalHeader>(),
            );
        }
        let result = unsafe { HbiImage::parse(&data) };
        assert!(result.is_ok());
        assert_eq!(result.unwrap().get_num_entries(), 0);
    }
}
