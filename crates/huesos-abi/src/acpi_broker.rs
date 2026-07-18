//! Versioned messages shared by the Ring-3 ACPI manager and its privileged
//! broker. The channel carrying these messages is itself the capability;
//! untrusted processes never receive it.

/// Current ACPI broker protocol version.
pub const VERSION: u16 = 1;
/// Maximum exact-width access accepted by the protocol.
pub const MAX_ACCESS_WIDTH: u8 = 4;
/// Magic at the start of a read-only ACPI table archive VMO.
pub const TABLE_ARCHIVE_MAGIC: [u8; 8] = *b"HUEACPI\0";
/// Maximum tables accepted from one archive.
pub const MAX_TABLES: u32 = 4096;
/// Maximum size of one archived table.
pub const MAX_TABLE_BYTES: u32 = 16 * 1024 * 1024;
/// Maximum aggregate immutable archive size.
pub const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
/// Encoded archive-header size, including alignment padding before `total_size`.
pub const TABLE_ARCHIVE_HEADER_BYTES: u16 = 24;
/// Encoded table-entry size.
pub const TABLE_ARCHIVE_ENTRY_BYTES: usize = 32;

/// Privileged operation requested by the ACPI manager.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    /// Exact-width SystemIO read from a granted range.
    SystemIoRead = 1,
    /// Exact-width SystemIO write to a granted range.
    SystemIoWrite = 2,
    /// PCI configuration-space read from a granted function.
    PciRead = 3,
    /// PCI configuration-space write to a granted function.
    PciWrite = 4,
    /// Install an ACPI interrupt handler through an existing IRQ capability.
    InstallInterrupt = 5,
    /// Remove a previously installed ACPI interrupt handler.
    RemoveInterrupt = 6,
    /// Request the firmware reset path after policy authorization.
    Reset = 7,
    /// Request the firmware S5 power-off path after policy authorization.
    PowerOff = 8,
}

impl Opcode {
    /// Decode a wire value without constructing an invalid Rust enum.
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::SystemIoRead),
            2 => Some(Self::SystemIoWrite),
            3 => Some(Self::PciRead),
            4 => Some(Self::PciWrite),
            5 => Some(Self::InstallInterrupt),
            6 => Some(Self::RemoveInterrupt),
            7 => Some(Self::Reset),
            8 => Some(Self::PowerOff),
            _ => None,
        }
    }

    const fn uses_width(self) -> bool {
        matches!(
            self,
            Self::SystemIoRead | Self::SystemIoWrite | Self::PciRead | Self::PciWrite
        )
    }
}

/// Fixed-size request. Integer fields are little-endian native values because
/// HuesOS currently supports only little-endian x86_64 peers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Request {
    /// Must equal [`VERSION`].
    pub version: u16,
    /// Raw [`Opcode`] value; decoded explicitly by [`Request::validate`].
    pub opcode: u16,
    /// Exact access width in bytes: 1, 2, or 4 for I/O operations.
    pub width: u8,
    /// Must be zero to permit compatible future extension.
    pub reserved: [u8; 3],
    /// Caller-selected ID copied into the response.
    pub request_id: u64,
    /// Operation-specific address or packed PCI address.
    pub address: u64,
    /// Write value; must be zero for reads and non-I/O operations.
    pub value: u64,
    /// Operation-specific capability key or interrupt identifier.
    pub argument: u64,
}

/// A structurally validated request. Authorization against the channel's
/// capability allowlist is a separate broker responsibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidRequest {
    /// Decoded operation.
    pub opcode: Opcode,
    /// Exact access width.
    pub width: u8,
    /// Correlation identifier.
    pub request_id: u64,
    /// Operation address.
    pub address: u64,
    /// Write value.
    pub value: u64,
    /// Additional operation argument.
    pub argument: u64,
}

/// Structural protocol validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// Unsupported protocol version.
    Version,
    /// Unknown operation number.
    Opcode,
    /// Reserved bytes were nonzero.
    Reserved,
    /// Access width was invalid for this operation.
    Width,
    /// Address was not naturally aligned to the exact access width.
    Alignment,
    /// A value contained bits wider than the requested write width.
    Value,
}

impl Request {
    /// Validate wire structure without performing privileged I/O.
    pub fn validate(self) -> Result<ValidRequest, ValidationError> {
        if self.version != VERSION {
            return Err(ValidationError::Version);
        }
        let Some(opcode) = Opcode::from_raw(self.opcode) else {
            return Err(ValidationError::Opcode);
        };
        if self.reserved != [0; 3] {
            return Err(ValidationError::Reserved);
        }
        if opcode.uses_width() {
            if !(self.width == 1 || self.width == 2 || self.width == MAX_ACCESS_WIDTH) {
                return Err(ValidationError::Width);
            }
            if self.address & (self.width as u64 - 1) != 0 {
                return Err(ValidationError::Alignment);
            }
            let max_value = if self.width == 4 {
                u32::MAX as u64
            } else {
                (1u64 << (self.width as u32 * 8)) - 1
            };
            if matches!(opcode, Opcode::SystemIoWrite | Opcode::PciWrite)
                && self.value > max_value
            {
                return Err(ValidationError::Value);
            }
            if matches!(opcode, Opcode::SystemIoRead | Opcode::PciRead) && self.value != 0 {
                return Err(ValidationError::Value);
            }
        } else if self.width != 0 || self.value != 0 {
            return Err(ValidationError::Width);
        }
        Ok(ValidRequest {
            opcode,
            width: self.width,
            request_id: self.request_id,
            address: self.address,
            value: self.value,
            argument: self.argument,
        })
    }
}

/// Broker response status.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// Operation completed successfully.
    Ok = 0,
    /// Request encoding was malformed.
    InvalidRequest = -1,
    /// Channel capability does not authorize the target.
    AccessDenied = -2,
    /// Target device or interrupt does not exist.
    NotFound = -3,
    /// Broker could not complete the operation.
    Internal = -4,
}

/// Fixed-size response paired by `request_id`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Response {
    /// Protocol version.
    pub version: u16,
    /// Reserved and required to be zero.
    pub reserved: u16,
    /// Raw [`Status`] value.
    pub status: i32,
    /// Correlation identifier copied from the request.
    pub request_id: u64,
    /// Read value or operation-specific result.
    pub value: u64,
}

/// Header of the immutable ACPI table archive passed as a read-only VMO.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableArchiveHeader {
    /// [`TABLE_ARCHIVE_MAGIC`].
    pub magic: [u8; 8],
    /// Archive format version, currently 1.
    pub version: u16,
    /// Size of this header in bytes.
    pub header_size: u16,
    /// Number of following [`TableArchiveEntry`] records.
    pub table_count: u32,
    /// Total VMO byte size covered by this archive.
    pub total_size: u64,
}

/// One validated table range in the immutable archive VMO.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TableArchiveEntry {
    /// Four-byte ACPI SDT signature.
    pub signature: [u8; 4],
    /// ACPI table revision.
    pub revision: u8,
    /// Reserved and required to be zero.
    pub reserved: [u8; 3],
    /// Original firmware physical address, or zero for virtual tables.
    pub physical_address: u64,
    /// Byte offset from the start of the archive.
    pub offset: u64,
    /// Table length in bytes.
    pub length: u32,
    /// Stable duplicate index for repeated signatures such as SSDT.
    pub instance: u32,
}

/// Invalid immutable table-archive layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveError {
    /// Magic or archive version does not match this ABI.
    Format,
    /// Header or entry count is inconsistent.
    Metadata,
    /// A table has an invalid length or offset.
    Range,
    /// Entries are not ordered or their byte ranges overlap.
    Overlap,
    /// Reserved entry fields were nonzero.
    Reserved,
}

/// Validate archive metadata before a consumer reads any table bytes.
///
/// Entries must be sorted by offset. This makes overlap detection linear and
/// prevents attacker-controlled archives from forcing quadratic kernel work.
pub fn validate_archive_layout(
    header: &TableArchiveHeader,
    entries: &[TableArchiveEntry],
) -> Result<(), ArchiveError> {
    if header.magic != TABLE_ARCHIVE_MAGIC || header.version != VERSION {
        return Err(ArchiveError::Format);
    }
    if header.header_size != TABLE_ARCHIVE_HEADER_BYTES
        || header.table_count > MAX_TABLES
        || header.table_count as usize != entries.len()
    {
        return Err(ArchiveError::Metadata);
    }
    let entries_bytes = entries
        .len()
        .checked_mul(TABLE_ARCHIVE_ENTRY_BYTES)
        .ok_or(ArchiveError::Metadata)?;
    let metadata_end = (header.header_size as usize)
        .checked_add(entries_bytes)
        .ok_or(ArchiveError::Metadata)? as u64;
    if metadata_end > header.total_size || header.total_size > MAX_ARCHIVE_BYTES {
        return Err(ArchiveError::Metadata);
    }

    let mut previous_end = metadata_end;
    for entry in entries {
        if entry.reserved != [0; 3] {
            return Err(ArchiveError::Reserved);
        }
        if !(36..=MAX_TABLE_BYTES).contains(&entry.length) || entry.offset < metadata_end {
            return Err(ArchiveError::Range);
        }
        if entry.physical_address != 0
            && entry
                .physical_address
                .checked_add(entry.length as u64)
                .is_none()
        {
            return Err(ArchiveError::Range);
        }
        if entry.offset < previous_end {
            return Err(ArchiveError::Overlap);
        }
        let end = entry
            .offset
            .checked_add(entry.length as u64)
            .ok_or(ArchiveError::Range)?;
        if end > header.total_size {
            return Err(ArchiveError::Range);
        }
        previous_end = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(opcode: Opcode, width: u8, address: u64, value: u64) -> Request {
        Request {
            version: VERSION,
            opcode: opcode as u16,
            width,
            address,
            value,
            ..Request::default()
        }
    }

    #[test]
    fn accepts_exact_width_aligned_io() {
        assert!(request(Opcode::SystemIoRead, 2, 0x404, 0).validate().is_ok());
        assert!(request(Opcode::PciWrite, 4, 0x10, 0xffff_ffff).validate().is_ok());
    }

    #[test]
    fn rejects_unknown_unaligned_and_wide_requests() {
        let mut unknown = request(Opcode::SystemIoRead, 1, 0, 0);
        unknown.opcode = 0xffff;
        assert_eq!(unknown.validate(), Err(ValidationError::Opcode));
        assert_eq!(
            request(Opcode::SystemIoRead, 4, 2, 0).validate(),
            Err(ValidationError::Alignment)
        );
        assert_eq!(
            request(Opcode::SystemIoWrite, 1, 0x80, 0x100).validate(),
            Err(ValidationError::Value)
        );
    }

    #[test]
    fn non_io_operations_forbid_width_and_value() {
        assert!(request(Opcode::Reset, 0, 0, 0).validate().is_ok());
        assert_eq!(
            request(Opcode::Reset, 1, 0, 0).validate(),
            Err(ValidationError::Width)
        );
    }

    #[test]
    fn validates_sorted_non_overlapping_archive() {
        let metadata = (TABLE_ARCHIVE_HEADER_BYTES as usize + TABLE_ARCHIVE_ENTRY_BYTES) as u64;
        let header = TableArchiveHeader {
            magic: TABLE_ARCHIVE_MAGIC,
            version: VERSION,
            header_size: TABLE_ARCHIVE_HEADER_BYTES,
            table_count: 1,
            total_size: metadata + 64,
        };
        let entry = TableArchiveEntry {
            signature: *b"DSDT",
            offset: metadata,
            length: 64,
            ..TableArchiveEntry::default()
        };
        assert_eq!(validate_archive_layout(&header, &[entry]), Ok(()));
    }

    #[test]
    fn rejects_archive_metadata_overlap() {
        let header = TableArchiveHeader {
            magic: TABLE_ARCHIVE_MAGIC,
            version: VERSION,
            header_size: TABLE_ARCHIVE_HEADER_BYTES,
            table_count: 1,
            total_size: 4096,
        };
        let entry = TableArchiveEntry {
            signature: *b"FACP",
            offset: 0,
            length: 64,
            ..TableArchiveEntry::default()
        };
        assert_eq!(
            validate_archive_layout(&header, &[entry]),
            Err(ArchiveError::Range)
        );
    }
}
