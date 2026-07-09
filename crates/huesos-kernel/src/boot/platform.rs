//! Platform data parser (simple key-value style).
//!
//! Used to extract information such as CPU count from the bootloader-provided
//! platform data blob.

use core::str;

/// Well-known platform properties that can be queried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformProperty {
    /// Number of CPUs.
    CpuCount,
    /// Total memory size in bytes.
    MemorySize,
    /// Base address of the serial port.
    SerialPortBase,
    /// Base address of the interrupt controller.
    InterruptControllerBase,
    /// Unknown property.
    Unknown,
}

impl From<u32> for PlatformProperty {
    fn from(val: u32) -> Self {
        match val {
            0x100 => PlatformProperty::CpuCount,
            0x200 => PlatformProperty::MemorySize,
            0x300 => PlatformProperty::SerialPortBase,
            0x400 => PlatformProperty::InterruptControllerBase,
            _ => PlatformProperty::Unknown,
        }
    }
}

/// Parsed platform data blob.
pub struct PlatformData<'a> {
    data: &'a [u8],
}

impl<'a> PlatformData<'a> {
    /// Create a new platform data parser from a byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Get a property value by its ID.
    pub fn get_property(&self, property: PlatformProperty) -> Option<&[u8]> {
        let prop_id = match property {
            PlatformProperty::CpuCount => 0x100,
            PlatformProperty::MemorySize => 0x200,
            PlatformProperty::SerialPortBase => 0x300,
            PlatformProperty::InterruptControllerBase => 0x400,
            PlatformProperty::Unknown => return None,
        };

        let mut offset = 0;
        while offset + 8 <= self.data.len() {
            let id = u32::from_le_bytes(self.data[offset..offset+4].try_into().ok()?);
            let len = u32::from_le_bytes(self.data[offset+4..offset+8].try_into().ok()?);

            if id == prop_id {
                let start = offset + 8;
                let end = start + len as usize;
                if end <= self.data.len() {
                    return Some(&self.data[start..end]);
                }
            }
            offset += 8 + len as usize;
        }
        None
    }

    /// Get a property as u64.
    pub fn get_u64(&self, property: PlatformProperty) -> Option<u64> {
        let data = self.get_property(property)?;
        if data.len() == 8 {
            Some(u64::from_le_bytes(data.try_into().ok()?))
        } else {
            None
        }
    }

    /// Get a property as &str.
    pub fn get_str(&self, property: PlatformProperty) -> Option<&str> {
        let data = self.get_property(property)?;
        str::from_utf8(data).ok()
    }
}
