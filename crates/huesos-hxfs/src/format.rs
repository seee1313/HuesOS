//! Hxfs v1 on-disk constants and stable decoded records.

/// Hxfs format GUID. Not an ASCII magic string; this is the stable format type
/// identity used by mount validation.
pub const FORMAT_GUID: [u8; 16] = [
    0x48, 0x78, 0x66, 0x73, 0x2d, 0x48, 0x75, 0x65, 0x73, 0x4f, 0x53, 0x2d, 0x76, 0x31, 0x00, 0x01,
];

/// Hxfs v1 linear format version.
pub const FORMAT_VERSION: u32 = 1;
/// Hxfs v1 metadata type-system version.
pub const TYPE_SYSTEM_VERSION: u32 = 1;
/// Hxfs v1 block size.
pub const BLOCK_SIZE: usize = 4096;
/// Hxfs v1 block size as u64.
pub const BLOCK_SIZE_U64: u64 = BLOCK_SIZE as u64;
/// Maximum UTF-8 directory entry name length.
pub const MAX_NAME_BYTES: usize = 255;
/// Inline file data threshold from the design.
pub const INLINE_DATA_BYTES: usize = 1024;

/// Metadata block type: superblock/root-store record.
pub const BLOCK_TYPE_SUPERBLOCK: u32 = 1;
/// Metadata block type: checkpoint root.
pub const BLOCK_TYPE_CHECKPOINT: u32 = 2;
/// Metadata block type: volume table.
pub const BLOCK_TYPE_VOLUME_TABLE: u32 = 3;
/// Metadata block type: object table.
pub const BLOCK_TYPE_OBJECT_TABLE: u32 = 4;
/// Metadata block type: directory entries.
pub const BLOCK_TYPE_DIRECTORY: u32 = 5;
/// Metadata block type: file extent table.
pub const BLOCK_TYPE_EXTENT_TABLE: u32 = 6;

/// Object type: regular file.
pub const OBJECT_TYPE_FILE: u32 = 1;
/// Object type: directory.
pub const OBJECT_TYPE_DIRECTORY: u32 = 2;
/// Object type: path-level symbolic link.
pub const OBJECT_TYPE_SYMLINK: u32 = 3;
/// Object type: BlobFS-compatible Hxblob view root.
pub const OBJECT_TYPE_BLOB_VIEW: u32 = 4;

/// Volume flag: system/boot-selected volume.
pub const VOLUME_FLAG_SYSTEM: u32 = 1 << 0;
/// Volume flag: encrypted volume. Stage G parser rejects it after parsing the
/// policy id because actual key handling is out of scope.
pub const VOLUME_FLAG_ENCRYPTED: u32 = 1 << 1;
/// Volume flag: Hxblob immutable package volume.
pub const VOLUME_FLAG_HXBLOB: u32 = 1 << 2;

/// File extent flag: sparse hole.
pub const EXTENT_FLAG_HOLE: u32 = 1 << 0;
/// File extent flag: preallocated/reserved extent.
pub const EXTENT_FLAG_PREALLOCATED: u32 = 1 << 1;

/// Stable UUID/GUID bytes.
pub type Uuid = [u8; 16];

/// Every metadata block starts with this fixed header. The checksum field is a
/// CRC32C over the whole 4 KiB block with bytes `32..36` zeroed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    /// Block type id.
    pub block_type: u32,
    /// On-disk type version.
    pub type_version: u16,
    /// Header size in bytes.
    pub header_bytes: u16,
    /// Transaction/checkpoint generation.
    pub generation: u64,
    /// Owner id (volume/object/tree specific).
    pub owner_id: u64,
    /// Logical block address this metadata block expects to occupy.
    pub self_lba: u64,
    /// CRC32C checksum over the whole block with this field zeroed.
    pub crc32c: u32,
    /// Payload bytes after the header.
    pub payload_bytes: u32,
}

/// Decoded superblock/root-store record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    /// Hxfs format GUID.
    pub format_guid: Uuid,
    /// Linear format version.
    pub format_version: u32,
    /// Stable type system version.
    pub type_system_version: u32,
    /// Filesystem instance UUID.
    pub instance_uuid: Uuid,
    /// Published sequence number.
    pub sequence_number: u64,
    /// Block size.
    pub block_size: u32,
    /// Primary checkpoint LBA.
    pub checkpoint_lba: u64,
    /// Backup checkpoint LBA, if known.
    pub backup_checkpoint_lba: u64,
    /// Journal start LBA (`0` means clean/no replay needed for Stage G).
    pub journal_start_lba: u64,
    /// Journal end LBA.
    pub journal_end_lba: u64,
}

/// Decoded checkpoint record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Checkpoint sequence number.
    pub sequence_number: u64,
    /// Volume table root LBA.
    pub volume_table_lba: u64,
    /// Number of volume descriptors in the table.
    pub volume_count: u32,
    /// Boot/system volume UUID found by boot metadata.
    pub system_volume_uuid: Uuid,
}

/// Decoded volume descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeDescriptor {
    /// Volume UUID.
    pub uuid: Uuid,
    /// Root object id.
    pub root_object_id: u64,
    /// Object table root LBA.
    pub object_table_lba: u64,
    /// Number of object descriptors.
    pub object_count: u32,
    /// Volume flags.
    pub flags: u32,
    /// Encryption policy id.
    pub encryption_policy_id: u32,
    /// Compression policy id.
    pub compression_policy_id: u32,
    /// Physical-byte quota.
    pub quota_physical_bytes: u64,
    /// Object-count quota.
    pub quota_objects: u64,
}

/// Decoded object descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectDescriptor {
    /// Object id.
    pub object_id: u64,
    /// Stable object type id.
    pub object_type: u32,
    /// Object type schema version.
    pub type_version: u32,
    /// File/directory logical size in bytes.
    pub size: u64,
    /// Modified time, Unix nanoseconds.
    pub modified_unix_ns: i64,
    /// Encryption policy id.
    pub encryption_policy_id: u32,
    /// Compression policy id.
    pub compression_policy_id: u32,
    /// Tree/inline-data LBA. Meaning depends on object type.
    pub tree_lba: u64,
    /// Entry or extent count.
    pub record_count: u32,
    /// Object flags.
    pub flags: u32,
}

/// Decoded directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntry<'a> {
    /// Target object id.
    pub object_id: u64,
    /// UTF-8 name bytes.
    pub name: &'a str,
}

/// Decoded file extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentRecord {
    /// Logical file block.
    pub logical_block: u64,
    /// Physical filesystem block.
    pub physical_block: u64,
    /// Number of 4 KiB blocks.
    pub block_count: u32,
    /// Extent flags.
    pub flags: u32,
}

/// Lightweight directory handle for the read-only prototype.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryHandle {
    /// Directory object id.
    pub object_id: u64,
}

/// Lightweight file handle for the read-only prototype.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileHandle {
    /// File object id.
    pub object_id: u64,
    /// File size in bytes.
    pub size: u64,
}
