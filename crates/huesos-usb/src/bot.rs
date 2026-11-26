//! USB Mass Storage Bulk-Only Transport (`BOT` / `BBB`) `CBW`/`CSW` wire codecs
//! and SCSI Transparent Command Set (`SPC`/`SBC`) CDB builders.

/// 31-byte Command Block Wrapper (`CBW`) signature (`"USBC"`, `0x43425355`).
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// 13-byte Command Status Wrapper (`CSW`) signature (`"USBS"`, `0x53425355`).
pub const CSW_SIGNATURE: u32 = 0x5342_5355;
/// Exact byte length of a `CBW`.
pub const CBW_BYTES: usize = 31;
/// Exact byte length of a `CSW`.
pub const CSW_BYTES: usize = 13;

/// `bmCBWFlags` direction bit: Data-In (device to host, `0x80`).
pub const CBW_FLAG_DATA_IN: u8 = 0x80;
/// `bmCBWFlags` direction bit: Data-Out (host to device, `0x00`).
pub const CBW_FLAG_DATA_OUT: u8 = 0x00;

/// Decoded `bCSWStatus` from a 13-byte Command Status Wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CswStatus {
    /// `0x00`: Command Passed ("good status").
    Passed = 0x00,
    /// `0x01`: Command Failed (host should issue `REQUEST SENSE`).
    Failed = 0x01,
    /// `0x02`: Phase Error (host must perform Bulk-Only Reset Recovery).
    PhaseError = 0x02,
}

/// 31-byte Bulk-Only Transport Command Block Wrapper (`CBW`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandBlockWrapper {
    /// Host-chosen transaction tag echoed back in `dCSWTag`.
    pub tag: u32,
    /// Expected data-phase byte transfer length (`dCBWDataTransferLength`).
    pub data_transfer_len: u32,
    /// `CBW_FLAG_DATA_IN` (`0x80`) or `CBW_FLAG_DATA_OUT` (`0x00`).
    pub flags: u8,
    /// Target Logical Unit Number (`0..=15`).
    pub lun: u8,
    /// Valid CDB byte length (`1..=16`).
    pub cb_len: u8,
    /// Command Block (`CDB`) bytes.
    pub cb: [u8; 16],
}

impl CommandBlockWrapper {
    /// Encode into the wire 31-byte little-endian `CBW` packet.
    pub fn to_bytes(&self) -> [u8; CBW_BYTES] {
        let mut out = [0u8; CBW_BYTES];
        out[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        out[4..8].copy_from_slice(&self.tag.to_le_bytes());
        out[8..12].copy_from_slice(&self.data_transfer_len.to_le_bytes());
        out[12] = self.flags;
        out[13] = self.lun & 0x0F;
        out[14] = self.cb_len.clamp(1, 16);
        out[15..31].copy_from_slice(&self.cb);
        out
    }

    /// Build `TEST UNIT READY` (`0x00`, 6-byte CDB, no data stage).
    pub const fn scsi_test_unit_ready(tag: u32, lun: u8) -> Self {
        Self {
            tag,
            data_transfer_len: 0,
            flags: CBW_FLAG_DATA_OUT,
            lun,
            cb_len: 6,
            cb: [0; 16],
        }
    }

    /// Build `INQUIRY` (`0x12`, 6-byte CDB, 36-byte standard response).
    pub const fn scsi_inquiry(tag: u32, lun: u8, alloc_len: u8) -> Self {
        let mut cb = [0u8; 16];
        cb[0] = 0x12;
        cb[4] = alloc_len;
        Self {
            tag,
            data_transfer_len: alloc_len as u32,
            flags: CBW_FLAG_DATA_IN,
            lun,
            cb_len: 6,
            cb,
        }
    }

    /// Build `REQUEST SENSE` (`0x03`, 6-byte CDB, typically 18 bytes).
    pub const fn scsi_request_sense(tag: u32, lun: u8, alloc_len: u8) -> Self {
        let mut cb = [0u8; 16];
        cb[0] = 0x03;
        cb[4] = alloc_len;
        Self {
            tag,
            data_transfer_len: alloc_len as u32,
            flags: CBW_FLAG_DATA_IN,
            lun,
            cb_len: 6,
            cb,
        }
    }

    /// Build `READ CAPACITY (10)` (`0x25`, 10-byte CDB, 8-byte response).
    pub const fn scsi_read_capacity10(tag: u32, lun: u8) -> Self {
        let mut cb = [0u8; 16];
        cb[0] = 0x25;
        Self {
            tag,
            data_transfer_len: 8,
            flags: CBW_FLAG_DATA_IN,
            lun,
            cb_len: 10,
            cb,
        }
    }

    /// Build `READ CAPACITY (16)` (`0x9E / 0x10`, 16-byte CDB, 32-byte response)
    /// used when `READ CAPACITY (10)` returns `0xFFFF_FFFF`.
    pub const fn scsi_read_capacity16(tag: u32, lun: u8) -> Self {
        let mut cb = [0u8; 16];
        cb[0] = 0x9E;
        cb[1] = 0x10;
        cb[13] = 32;
        Self {
            tag,
            data_transfer_len: 32,
            flags: CBW_FLAG_DATA_IN,
            lun,
            cb_len: 16,
            cb,
        }
    }

    /// Build `READ (10)` (`0x28`) for 32-bit LBA ranges.
    pub const fn scsi_read10(
        tag: u32,
        lun: u8,
        lba: u32,
        blocks: u16,
        block_size: u32,
    ) -> Option<Self> {
        let Some(bytes) = (blocks as u32).checked_mul(block_size) else {
            return None;
        };
        let lba_be = lba.to_be_bytes();
        let cnt_be = blocks.to_be_bytes();
        let mut cb = [0u8; 16];
        cb[0] = 0x28;
        cb[2] = lba_be[0];
        cb[3] = lba_be[1];
        cb[4] = lba_be[2];
        cb[5] = lba_be[3];
        cb[7] = cnt_be[0];
        cb[8] = cnt_be[1];
        Some(Self {
            tag,
            data_transfer_len: bytes,
            flags: CBW_FLAG_DATA_IN,
            lun,
            cb_len: 10,
            cb,
        })
    }

    /// Build `WRITE (10)` (`0x2A`) for 32-bit LBA ranges.
    pub const fn scsi_write10(
        tag: u32,
        lun: u8,
        lba: u32,
        blocks: u16,
        block_size: u32,
    ) -> Option<Self> {
        let Some(bytes) = (blocks as u32).checked_mul(block_size) else {
            return None;
        };
        let lba_be = lba.to_be_bytes();
        let cnt_be = blocks.to_be_bytes();
        let mut cb = [0u8; 16];
        cb[0] = 0x2A;
        cb[2] = lba_be[0];
        cb[3] = lba_be[1];
        cb[4] = lba_be[2];
        cb[5] = lba_be[3];
        cb[7] = cnt_be[0];
        cb[8] = cnt_be[1];
        Some(Self {
            tag,
            data_transfer_len: bytes,
            flags: CBW_FLAG_DATA_OUT,
            lun,
            cb_len: 10,
            cb,
        })
    }

    /// Build `SYNCHRONIZE CACHE (10)` (`0x35`) for `OP_FLUSH`.
    pub const fn scsi_sync_cache10(tag: u32, lun: u8) -> Self {
        let mut cb = [0u8; 16];
        cb[0] = 0x35;
        Self {
            tag,
            data_transfer_len: 0,
            flags: CBW_FLAG_DATA_OUT,
            lun,
            cb_len: 10,
            cb,
        }
    }
}

/// Decoded 13-byte Command Status Wrapper (`CSW`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandStatusWrapper {
    /// Echoed `dCSWTag`.
    pub tag: u32,
    /// `dCSWDataResidue`.
    pub data_residue: u32,
    /// `bCSWStatus`.
    pub status: CswStatus,
}

impl CommandStatusWrapper {
    /// Parse and validate a 13-byte `CSW` against `expected_tag`.
    pub fn decode(bytes: &[u8], expected_tag: u32) -> Option<Self> {
        if bytes.len() < CSW_BYTES {
            return None;
        }
        let sig = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if sig != CSW_SIGNATURE {
            return None;
        }
        let tag = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if tag != expected_tag {
            return None;
        }
        let residue = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let status = match bytes[12] {
            0x00 => CswStatus::Passed,
            0x01 => CswStatus::Failed,
            0x02 => CswStatus::PhaseError,
            _ => return None,
        };
        Some(Self {
            tag,
            data_residue: residue,
            status,
        })
    }
}

/// Decoded block geometry from `READ CAPACITY (10)` or `READ CAPACITY (16)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScsiCapacity {
    /// Total logical block count (`last_lba + 1`).
    pub total_blocks: u64,
    /// Logical block size in bytes (typically `512` or `4096`).
    pub block_size: u32,
}

impl ScsiCapacity {
    /// Decode 8-byte `READ CAPACITY (10)` payload (`None` if `last_lba == 0xFFFF_FFFF`
    /// indicating `READ CAPACITY (16)` is required, or if `block_size == 0`).
    pub fn from_read_capacity10(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let last_lba = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let block_size = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if last_lba == u32::MAX || block_size == 0 || !block_size.is_power_of_two() {
            return None;
        }
        Some(Self {
            total_blocks: (last_lba as u64) + 1,
            block_size,
        })
    }

    /// Decode 32-byte `READ CAPACITY (16)` payload.
    pub fn from_read_capacity16(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let last_lba = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let block_size = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let total = last_lba.checked_add(1)?;
        if block_size == 0 || !block_size.is_power_of_two() {
            return None;
        }
        Some(Self {
            total_blocks: total,
            block_size,
        })
    }
}
