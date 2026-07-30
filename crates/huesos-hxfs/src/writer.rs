//! Host-testable Hxfs COW writer prototype.
//!
//! This module implements the Stage-H mutation model over an append-only image:
//! data and metadata are written to fresh 4 KiB blocks, then a new checkpoint is
//! published through the superblock/root-store record. Existing images/snapshots
//! remain readable. Encryption is intentionally rejected for Stage H MVP.

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::crc32c::metadata_crc32c;
use crate::format::*;
use crate::reader::SliceBlockReader;
use crate::{Hxfs, HxfsError};

/// Mutation failure for the Stage-H writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HxfsWriteError {
    /// Path syntax or name is invalid.
    BadPath,
    /// Object was not found.
    NotFound,
    /// Object already exists.
    AlreadyExists,
    /// Object type does not match the requested operation.
    WrongType,
    /// Directory is not empty.
    DirectoryNotEmpty,
    /// The encrypted-volume path is rejected in Stage H.
    EncryptedVolume,
    /// The image grew beyond supported bounds.
    OutOfSpace,
    /// Snapshot was not found.
    SnapshotNotFound,
}

/// Snapshot descriptor retained by the writer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotInfo {
    /// Snapshot id.
    pub snapshot_id: u64,
    /// Checkpoint LBA captured by the snapshot.
    pub checkpoint_lba: u64,
    /// Sequence number captured by the snapshot.
    pub sequence_number: u64,
    /// Snapshot name.
    pub name: String,
}

#[derive(Clone)]
enum NodeKind {
    Directory { entries: Vec<DirEntry> },
    File { data: Vec<u8>, logical_size: u64 },
    Symlink { target: String },
}

#[derive(Clone)]
struct Node {
    object_id: u64,
    modified_unix_ns: i64,
    encryption_policy_id: u32,
    compression_policy_id: u32,
    kind: NodeKind,
}

#[derive(Clone)]
struct DirEntry {
    name: String,
    object_id: u64,
}

/// Append-only Hxfs image writer.
pub struct HxfsWriter {
    instance_uuid: Uuid,
    volume_uuid: Uuid,
    image: Vec<u8>,
    sequence_number: u64,
    checkpoint_lba: u64,
    next_object_id: u64,
    next_snapshot_id: u64,
    nodes: Vec<Node>,
    snapshots: Vec<SnapshotInfo>,
    encrypted: bool,
}

impl HxfsWriter {
    /// Create an empty unencrypted Hxfs image with a root directory.
    pub fn new(instance_uuid: Uuid, volume_uuid: Uuid) -> Result<Self, HxfsWriteError> {
        let mut writer = Self {
            instance_uuid,
            volume_uuid,
            image: vec![0u8; BLOCK_SIZE],
            sequence_number: 0,
            checkpoint_lba: 0,
            next_object_id: 2,
            next_snapshot_id: 1,
            nodes: Vec::new(),
            snapshots: Vec::new(),
            encrypted: false,
        };
        writer.nodes.push(Node {
            object_id: 1,
            modified_unix_ns: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            kind: NodeKind::Directory {
                entries: Vec::new(),
            },
        });
        writer.commit()?;
        Ok(writer)
    }

    /// Current image bytes.
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// Clone the current image.
    pub fn image_vec(&self) -> Vec<u8> {
        self.image.clone()
    }

    /// Snapshot metadata table.
    pub fn snapshots(&self) -> &[SnapshotInfo] {
        &self.snapshots
    }

    /// Mark this writer encrypted. Stage-H mutation APIs reject encrypted
    /// volumes until the AES-XTS policy/key layer is implemented.
    pub fn mark_encrypted_for_test(&mut self) {
        self.encrypted = true;
    }

    /// Create a directory.
    pub fn mkdir(&mut self, path: &str) -> Result<u64, HxfsWriteError> {
        self.reject_encrypted()?;
        let (parent, name) = self.parent_and_name(path)?;
        if self.lookup_child(parent, name).is_some() {
            return Err(HxfsWriteError::AlreadyExists);
        }
        let object_id = self.alloc_object_id();
        self.nodes.push(Node {
            object_id,
            modified_unix_ns: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            kind: NodeKind::Directory {
                entries: Vec::new(),
            },
        });
        self.insert_child(parent, name, object_id)?;
        Ok(object_id)
    }

    /// Create a path-level symlink.
    pub fn create_symlink(&mut self, path: &str, target: &str) -> Result<u64, HxfsWriteError> {
        self.reject_encrypted()?;
        let (parent, name) = self.parent_and_name(path)?;
        if self.lookup_child(parent, name).is_some() {
            return Err(HxfsWriteError::AlreadyExists);
        }
        let object_id = self.alloc_object_id();
        self.nodes.push(Node {
            object_id,
            modified_unix_ns: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            kind: NodeKind::Symlink {
                target: String::from(target),
            },
        });
        self.insert_child(parent, name, object_id)?;
        Ok(object_id)
    }

    /// Create a new file with `data`.
    pub fn create_file(&mut self, path: &str, data: &[u8]) -> Result<u64, HxfsWriteError> {
        self.reject_encrypted()?;
        let (parent, name) = self.parent_and_name(path)?;
        if self.lookup_child(parent, name).is_some() {
            return Err(HxfsWriteError::AlreadyExists);
        }
        let object_id = self.alloc_object_id();
        self.nodes.push(Node {
            object_id,
            modified_unix_ns: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            kind: NodeKind::File {
                data: data.to_vec(),
                logical_size: data.len() as u64,
            },
        });
        self.insert_child(parent, name, object_id)?;
        Ok(object_id)
    }

    /// Overwrite an existing file using COW on next commit.
    pub fn overwrite_file(&mut self, path: &str, data: &[u8]) -> Result<(), HxfsWriteError> {
        self.reject_encrypted()?;
        let object_id = self.resolve_path(path)?;
        let node = self.node_mut(object_id).ok_or(HxfsWriteError::NotFound)?;
        let NodeKind::File {
            data: existing,
            logical_size,
        } = &mut node.kind
        else {
            return Err(HxfsWriteError::WrongType);
        };
        existing.clear();
        existing.extend_from_slice(data);
        *logical_size = data.len() as u64;
        Ok(())
    }

    /// Truncate or extend a file. Extending creates a sparse tail.
    pub fn truncate_file(&mut self, path: &str, new_size: u64) -> Result<(), HxfsWriteError> {
        self.reject_encrypted()?;
        let object_id = self.resolve_path(path)?;
        let node = self.node_mut(object_id).ok_or(HxfsWriteError::NotFound)?;
        let NodeKind::File { data, logical_size } = &mut node.kind else {
            return Err(HxfsWriteError::WrongType);
        };
        if new_size < data.len() as u64 {
            data.truncate(new_size as usize);
        }
        *logical_size = new_size;
        Ok(())
    }

    /// Rename/move a file or empty directory.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), HxfsWriteError> {
        self.reject_encrypted()?;
        let (old_parent, old_name) = self.parent_and_name(from)?;
        let object_id = self
            .lookup_child(old_parent, old_name)
            .ok_or(HxfsWriteError::NotFound)?;
        let (new_parent, new_name) = self.parent_and_name(to)?;
        if self.lookup_child(new_parent, new_name).is_some() {
            return Err(HxfsWriteError::AlreadyExists);
        }
        self.remove_child(old_parent, old_name)?;
        self.insert_child(new_parent, new_name, object_id)?;
        Ok(())
    }

    /// Unlink a file or empty directory.
    pub fn unlink(&mut self, path: &str) -> Result<(), HxfsWriteError> {
        self.reject_encrypted()?;
        let (parent, name) = self.parent_and_name(path)?;
        let object_id = self
            .lookup_child(parent, name)
            .ok_or(HxfsWriteError::NotFound)?;
        if let Some(node) = self.node(object_id) {
            if let NodeKind::Directory { entries } = &node.kind {
                if !entries.is_empty() {
                    return Err(HxfsWriteError::DirectoryNotEmpty);
                }
            }
        }
        self.remove_child(parent, name)?;
        let Some(index) = self
            .nodes
            .iter()
            .position(|node| node.object_id == object_id)
        else {
            return Err(HxfsWriteError::NotFound);
        };
        self.nodes.remove(index);
        Ok(())
    }

    /// Create a read-only snapshot of the current committed state. If uncommitted
    /// mutations are pending, they are first committed as a new checkpoint.
    pub fn create_snapshot(&mut self, name: &str) -> Result<u64, HxfsWriteError> {
        self.reject_encrypted()?;
        self.commit()?;
        let id = self.next_snapshot_id;
        self.next_snapshot_id = self.next_snapshot_id.saturating_add(1).max(1);
        self.snapshots.push(SnapshotInfo {
            snapshot_id: id,
            checkpoint_lba: self.checkpoint_lba,
            sequence_number: self.sequence_number,
            name: String::from(name),
        });
        Ok(id)
    }

    /// Delete a snapshot descriptor. Stage H does not reclaim old COW blocks yet.
    pub fn delete_snapshot(&mut self, snapshot_id: u64) -> Result<(), HxfsWriteError> {
        self.reject_encrypted()?;
        let Some(index) = self
            .snapshots
            .iter()
            .position(|snapshot| snapshot.snapshot_id == snapshot_id)
        else {
            return Err(HxfsWriteError::SnapshotNotFound);
        };
        self.snapshots.remove(index);
        Ok(())
    }

    /// Return an image view whose superblock points at the snapshot checkpoint.
    pub fn snapshot_image(&self, snapshot_id: u64) -> Result<Vec<u8>, HxfsWriteError> {
        let snapshot = self
            .snapshots
            .iter()
            .find(|snapshot| snapshot.snapshot_id == snapshot_id)
            .ok_or(HxfsWriteError::SnapshotNotFound)?;
        let mut image = self.image.clone();
        write_superblock(
            &mut image[0..BLOCK_SIZE],
            self.instance_uuid,
            snapshot.sequence_number,
            snapshot.checkpoint_lba,
        );
        Ok(image)
    }

    /// Publish a new checkpoint using copy-on-write metadata/data blocks.
    pub fn commit(&mut self) -> Result<u64, HxfsWriteError> {
        self.reject_encrypted()?;
        self.sequence_number = self.sequence_number.saturating_add(1).max(1);

        let mut plans: Vec<NodePlan> = Vec::new();
        let nodes_snapshot = self.nodes.clone();
        for node in &nodes_snapshot {
            let tree_lba = match &node.kind {
                NodeKind::Directory { entries } => {
                    let block = build_directory_block(node.object_id, entries, self.next_lba())?;
                    self.push_block(&block)?
                }
                NodeKind::File { data, logical_size } => {
                    let extents = self.write_file_data(data, *logical_size)?;
                    let block = build_extent_block(node.object_id, &extents, self.next_lba())?;
                    self.push_block(&block)?
                }
                NodeKind::Symlink { target } => {
                    let mut data = target.as_bytes().to_vec();
                    let logical_size = data.len() as u64;
                    let extents = self.write_file_data(&data, logical_size)?;
                    data.clear();
                    let block = build_extent_block(node.object_id, &extents, self.next_lba())?;
                    self.push_block(&block)?
                }
            };
            plans.push(NodePlan {
                object_id: node.object_id,
                tree_lba,
                record_count: record_count_for(&node.kind),
            });
        }

        let object_table_lba = self.next_lba();
        let object_block = build_object_table_block(&nodes_snapshot, &plans, object_table_lba)?;
        self.push_block(&object_block)?;

        let volume_table_lba = self.next_lba();
        let volume_block = build_volume_table_block(
            self.volume_uuid,
            object_table_lba,
            nodes_snapshot.len() as u32,
            volume_table_lba,
        )?;
        self.push_block(&volume_block)?;

        let checkpoint_lba = self.next_lba();
        let checkpoint_block = build_checkpoint_block(
            self.sequence_number,
            volume_table_lba,
            self.volume_uuid,
            checkpoint_lba,
        )?;
        self.push_block(&checkpoint_block)?;

        self.checkpoint_lba = checkpoint_lba;
        write_superblock(
            &mut self.image[0..BLOCK_SIZE],
            self.instance_uuid,
            self.sequence_number,
            checkpoint_lba,
        );
        Ok(checkpoint_lba)
    }

    /// Mount current image through the read-only parser.
    pub fn mount_current(&self) -> Result<Hxfs<SliceBlockReader<'_>>, HxfsError> {
        Hxfs::mount(SliceBlockReader::new(&self.image))
    }

    fn reject_encrypted(&self) -> Result<(), HxfsWriteError> {
        if self.encrypted {
            Err(HxfsWriteError::EncryptedVolume)
        } else {
            Ok(())
        }
    }

    fn alloc_object_id(&mut self) -> u64 {
        let id = self.next_object_id;
        self.next_object_id = self.next_object_id.saturating_add(1).max(2);
        id
    }

    fn next_lba(&self) -> u64 {
        (self.image.len() / BLOCK_SIZE) as u64
    }

    fn push_block(&mut self, block: &[u8; BLOCK_SIZE]) -> Result<u64, HxfsWriteError> {
        let lba = self.next_lba();
        self.image.extend_from_slice(block);
        Ok(lba)
    }

    fn write_file_data(
        &mut self,
        data: &[u8],
        logical_size: u64,
    ) -> Result<Vec<ExtentRecord>, HxfsWriteError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let start_lba = self.next_lba();
        let mut written = 0usize;
        while written < data.len() {
            let mut block = [0u8; BLOCK_SIZE];
            let chunk = (data.len() - written).min(BLOCK_SIZE);
            block[..chunk].copy_from_slice(&data[written..written + chunk]);
            self.push_block(&block)?;
            written += chunk;
        }
        let blocks = data.len().div_ceil(BLOCK_SIZE) as u32;
        let mut extents = Vec::new();
        extents.push(ExtentRecord {
            logical_block: 0,
            physical_block: start_lba,
            block_count: blocks,
            flags: 0,
        });
        let covered = u64::from(blocks) * BLOCK_SIZE_U64;
        if logical_size > covered {
            extents.push(ExtentRecord {
                logical_block: u64::from(blocks),
                physical_block: 0,
                block_count: ((logical_size - covered).div_ceil(BLOCK_SIZE_U64)) as u32,
                flags: EXTENT_FLAG_HOLE,
            });
        }
        Ok(extents)
    }

    fn parent_and_name<'a>(&self, path: &'a str) -> Result<(u64, &'a str), HxfsWriteError> {
        if path == "/" || !path.as_bytes().starts_with(b"/") {
            return Err(HxfsWriteError::BadPath);
        }
        let bytes = path.as_bytes();
        let Some(pos) = bytes.iter().rposition(|&byte| byte == b'/') else {
            return Err(HxfsWriteError::BadPath);
        };
        let name = core::str::from_utf8(&bytes[pos + 1..]).map_err(|_| HxfsWriteError::BadPath)?;
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(HxfsWriteError::BadPath);
        }
        let parent_path = if pos == 0 { "/" } else { &path[..pos] };
        let parent = self.resolve_directory(parent_path)?;
        Ok((parent, name))
    }

    fn resolve_directory(&self, path: &str) -> Result<u64, HxfsWriteError> {
        if path == "/" {
            return Ok(1);
        }
        let object_id = self.resolve_path(path)?;
        let node = self.node(object_id).ok_or(HxfsWriteError::NotFound)?;
        if matches!(node.kind, NodeKind::Directory { .. }) {
            Ok(object_id)
        } else {
            Err(HxfsWriteError::WrongType)
        }
    }

    fn resolve_path(&self, path: &str) -> Result<u64, HxfsWriteError> {
        if !path.as_bytes().starts_with(b"/") {
            return Err(HxfsWriteError::BadPath);
        }
        let mut current = 1u64;
        for component in path[1..].split('/') {
            if component.is_empty() {
                return Err(HxfsWriteError::BadPath);
            }
            current = self
                .lookup_child(current, component)
                .ok_or(HxfsWriteError::NotFound)?;
        }
        Ok(current)
    }

    fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        let node = self.node(parent)?;
        let NodeKind::Directory { entries } = &node.kind else {
            return None;
        };
        entries
            .iter()
            .find(|entry| entry.name.as_bytes() == name.as_bytes())
            .map(|entry| entry.object_id)
    }

    fn insert_child(
        &mut self,
        parent: u64,
        name: &str,
        object_id: u64,
    ) -> Result<(), HxfsWriteError> {
        let node = self.node_mut(parent).ok_or(HxfsWriteError::NotFound)?;
        let NodeKind::Directory { entries } = &mut node.kind else {
            return Err(HxfsWriteError::WrongType);
        };
        entries.push(DirEntry {
            name: String::from(name),
            object_id,
        });
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        Ok(())
    }

    fn remove_child(&mut self, parent: u64, name: &str) -> Result<(), HxfsWriteError> {
        let node = self.node_mut(parent).ok_or(HxfsWriteError::NotFound)?;
        let NodeKind::Directory { entries } = &mut node.kind else {
            return Err(HxfsWriteError::WrongType);
        };
        let Some(index) = entries
            .iter()
            .position(|entry| entry.name.as_bytes() == name.as_bytes())
        else {
            return Err(HxfsWriteError::NotFound);
        };
        entries.remove(index);
        Ok(())
    }

    fn node(&self, object_id: u64) -> Option<&Node> {
        self.nodes.iter().find(|node| node.object_id == object_id)
    }

    fn node_mut(&mut self, object_id: u64) -> Option<&mut Node> {
        self.nodes
            .iter_mut()
            .find(|node| node.object_id == object_id)
    }
}

struct NodePlan {
    object_id: u64,
    tree_lba: u64,
    record_count: u32,
}

fn record_count_for(kind: &NodeKind) -> u32 {
    match kind {
        NodeKind::Directory { entries } => entries.len() as u32,
        NodeKind::File { data, logical_size } => {
            if data.is_empty() {
                0
            } else if *logical_size > (data.len().div_ceil(BLOCK_SIZE) as u64) * BLOCK_SIZE_U64 {
                2
            } else {
                1
            }
        }
        NodeKind::Symlink { target } => usize::from(!target.is_empty()) as u32,
    }
}

fn build_directory_block(
    owner: u64,
    entries: &[DirEntry],
    lba: u64,
) -> Result<[u8; BLOCK_SIZE], HxfsWriteError> {
    let mut payload = [0u8; BLOCK_SIZE - 40];
    payload[0..8].copy_from_slice(&owner.to_le_bytes());
    payload[8..12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (index, entry) in entries.iter().enumerate() {
        let offset = 16 + index * 272;
        if offset + 272 > payload.len() || entry.name.len() > MAX_NAME_BYTES {
            return Err(HxfsWriteError::OutOfSpace);
        }
        payload[offset..offset + 8].copy_from_slice(&entry.object_id.to_le_bytes());
        payload[offset + 8..offset + 10].copy_from_slice(&(entry.name.len() as u16).to_le_bytes());
        payload[offset + 10..offset + 10 + entry.name.len()].copy_from_slice(entry.name.as_bytes());
    }
    Ok(make_metadata_block(
        BLOCK_TYPE_DIRECTORY,
        owner,
        lba,
        &payload[..16 + entries.len() * 272],
    ))
}

fn build_extent_block(
    owner: u64,
    extents: &[ExtentRecord],
    lba: u64,
) -> Result<[u8; BLOCK_SIZE], HxfsWriteError> {
    let mut payload = [0u8; BLOCK_SIZE - 40];
    payload[0..8].copy_from_slice(&owner.to_le_bytes());
    payload[8..12].copy_from_slice(&(extents.len() as u32).to_le_bytes());
    for (index, extent) in extents.iter().enumerate() {
        let offset = 16 + index * 32;
        if offset + 32 > payload.len() {
            return Err(HxfsWriteError::OutOfSpace);
        }
        payload[offset..offset + 8].copy_from_slice(&extent.logical_block.to_le_bytes());
        payload[offset + 8..offset + 16].copy_from_slice(&extent.physical_block.to_le_bytes());
        payload[offset + 16..offset + 20].copy_from_slice(&extent.block_count.to_le_bytes());
        payload[offset + 20..offset + 24].copy_from_slice(&extent.flags.to_le_bytes());
    }
    Ok(make_metadata_block(
        BLOCK_TYPE_EXTENT_TABLE,
        owner,
        lba,
        &payload[..16 + extents.len() * 32],
    ))
}

fn build_object_table_block(
    nodes: &[Node],
    plans: &[NodePlan],
    lba: u64,
) -> Result<[u8; BLOCK_SIZE], HxfsWriteError> {
    let mut payload = [0u8; BLOCK_SIZE - 40];
    payload[0..4].copy_from_slice(&(nodes.len() as u32).to_le_bytes());
    for (index, node) in nodes.iter().enumerate() {
        let offset = 16 + index * 64;
        if offset + 64 > payload.len() {
            return Err(HxfsWriteError::OutOfSpace);
        }
        let Some(plan) = plans.iter().find(|plan| plan.object_id == node.object_id) else {
            return Err(HxfsWriteError::OutOfSpace);
        };
        let (object_type, size) = match &node.kind {
            NodeKind::Directory { .. } => (OBJECT_TYPE_DIRECTORY, 0),
            NodeKind::File { logical_size, .. } => (OBJECT_TYPE_FILE, *logical_size),
            NodeKind::Symlink { target } => (OBJECT_TYPE_SYMLINK, target.len() as u64),
        };
        payload[offset..offset + 8].copy_from_slice(&node.object_id.to_le_bytes());
        payload[offset + 8..offset + 12].copy_from_slice(&object_type.to_le_bytes());
        payload[offset + 12..offset + 16].copy_from_slice(&1u32.to_le_bytes());
        payload[offset + 16..offset + 24].copy_from_slice(&size.to_le_bytes());
        payload[offset + 24..offset + 32].copy_from_slice(&node.modified_unix_ns.to_le_bytes());
        payload[offset + 32..offset + 36].copy_from_slice(&node.encryption_policy_id.to_le_bytes());
        payload[offset + 36..offset + 40]
            .copy_from_slice(&node.compression_policy_id.to_le_bytes());
        payload[offset + 40..offset + 48].copy_from_slice(&plan.tree_lba.to_le_bytes());
        payload[offset + 48..offset + 52].copy_from_slice(&plan.record_count.to_le_bytes());
    }
    Ok(make_metadata_block(
        BLOCK_TYPE_OBJECT_TABLE,
        1,
        lba,
        &payload[..16 + nodes.len() * 64],
    ))
}

fn build_volume_table_block(
    volume_uuid: Uuid,
    object_table_lba: u64,
    object_count: u32,
    lba: u64,
) -> Result<[u8; BLOCK_SIZE], HxfsWriteError> {
    let mut payload = [0u8; 16 + 96];
    payload[0..4].copy_from_slice(&1u32.to_le_bytes());
    let offset = 16;
    payload[offset..offset + 16].copy_from_slice(&volume_uuid);
    payload[offset + 16..offset + 24].copy_from_slice(&1u64.to_le_bytes());
    payload[offset + 24..offset + 32].copy_from_slice(&object_table_lba.to_le_bytes());
    payload[offset + 32..offset + 36].copy_from_slice(&object_count.to_le_bytes());
    payload[offset + 36..offset + 40].copy_from_slice(&VOLUME_FLAG_SYSTEM.to_le_bytes());
    Ok(make_metadata_block(
        BLOCK_TYPE_VOLUME_TABLE,
        0,
        lba,
        &payload,
    ))
}

fn build_checkpoint_block(
    sequence: u64,
    volume_table_lba: u64,
    volume_uuid: Uuid,
    lba: u64,
) -> Result<[u8; BLOCK_SIZE], HxfsWriteError> {
    let mut payload = [0u8; 40];
    payload[0..8].copy_from_slice(&sequence.to_le_bytes());
    payload[8..16].copy_from_slice(&volume_table_lba.to_le_bytes());
    payload[16..20].copy_from_slice(&1u32.to_le_bytes());
    payload[24..40].copy_from_slice(&volume_uuid);
    Ok(make_metadata_block(BLOCK_TYPE_CHECKPOINT, 0, lba, &payload))
}

fn write_superblock(block: &mut [u8], instance_uuid: Uuid, sequence: u64, checkpoint_lba: u64) {
    let mut payload = [0u8; 88];
    payload[0..16].copy_from_slice(&FORMAT_GUID);
    payload[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    payload[20..24].copy_from_slice(&TYPE_SYSTEM_VERSION.to_le_bytes());
    payload[24..40].copy_from_slice(&instance_uuid);
    payload[40..48].copy_from_slice(&sequence.to_le_bytes());
    payload[48..52].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
    payload[56..64].copy_from_slice(&checkpoint_lba.to_le_bytes());
    let new_block = make_metadata_block(BLOCK_TYPE_SUPERBLOCK, 0, 0, &payload);
    block.copy_from_slice(&new_block);
}

fn make_metadata_block(block_type: u32, owner: u64, lba: u64, payload: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    block[0..4].copy_from_slice(&block_type.to_le_bytes());
    block[4..6].copy_from_slice(&1u16.to_le_bytes());
    block[6..8].copy_from_slice(&(40u16).to_le_bytes());
    block[8..16].copy_from_slice(&1u64.to_le_bytes());
    block[16..24].copy_from_slice(&owner.to_le_bytes());
    block[24..32].copy_from_slice(&lba.to_le_bytes());
    block[36..40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    block[40..40 + payload.len()].copy_from_slice(payload);
    let crc = metadata_crc32c(&block);
    block[32..36].copy_from_slice(&crc.to_le_bytes());
    block
}

#[cfg(test)]
mod write_tests {
    use super::*;

    const INSTANCE: Uuid = [0x33; 16];
    const VOLUME: Uuid = [0x44; 16];

    #[test]
    fn create_overwrite_rename_truncate_unlink_flow() {
        let Ok(mut writer) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "writer should initialize");
            return;
        };
        assert!(writer.mkdir("/home").is_ok());
        assert!(writer.create_file("/home/a.txt", b"abcdef").is_ok());
        assert!(writer.create_symlink("/home/link", "/home/a.txt").is_ok());
        assert!(writer.commit().is_ok());
        let image1 = writer.image_vec();
        assert!(writer.overwrite_file("/home/a.txt", b"replacement").is_ok());
        assert!(writer.rename("/home/a.txt", "/home/b.txt").is_ok());
        assert!(writer.truncate_file("/home/b.txt", 4).is_ok());
        assert!(writer.create_file("/home/sparse.bin", b"").is_ok());
        assert!(writer.truncate_file("/home/sparse.bin", 8192).is_ok());
        assert!(writer.unlink("/home/b.txt").is_ok());
        assert!(writer.commit().is_ok());

        let old = Hxfs::mount(SliceBlockReader::new(&image1));
        assert!(old.is_ok());
        let Ok(mut old) = old else { return };
        let file = old.open_path("/home/a.txt");
        assert!(file.is_ok());

        let current = writer.mount_current();
        assert!(current.is_ok());
        let Ok(mut current) = current else { return };
        assert!(current.open_path("/home/b.txt").is_err());
        let sparse = current.open_path("/home/sparse.bin");
        assert!(sparse.is_ok());
        let Ok(sparse) = sparse else { return };
        let mut out = [1u8; 8192];
        assert_eq!(current.read_file(sparse, &mut out), Ok(8192));
        assert!(out.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn snapshots_preserve_old_checkpoint_and_can_delete() {
        let Ok(mut writer) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "writer should initialize");
            return;
        };
        assert!(writer.create_file("/pkg", b"old").is_ok());
        let snapshot = writer.create_snapshot("before-update");
        assert!(snapshot.is_ok());
        let Ok(snapshot) = snapshot else { return };
        assert!(writer.overwrite_file("/pkg", b"new").is_ok());
        assert!(writer.commit().is_ok());

        let snapshot_image = writer.snapshot_image(snapshot);
        assert!(snapshot_image.is_ok());
        let Ok(snapshot_image) = snapshot_image else {
            return;
        };
        let snap_mount = Hxfs::mount(SliceBlockReader::new(&snapshot_image));
        assert!(snap_mount.is_ok());
        let Ok(mut snap_mount) = snap_mount else {
            return;
        };
        let file = snap_mount.open_path("/pkg");
        assert!(file.is_ok());
        let Ok(file) = file else { return };
        let mut out = [0u8; 8];
        assert_eq!(snap_mount.read_file(file, &mut out), Ok(3));
        assert_eq!(&out[..3], b"old");

        assert!(writer.delete_snapshot(snapshot).is_ok());
        assert_eq!(
            writer.snapshot_image(snapshot),
            Err(HxfsWriteError::SnapshotNotFound)
        );
    }

    #[test]
    fn encrypted_writer_rejects_mutation() {
        let Ok(mut writer) = HxfsWriter::new(INSTANCE, VOLUME) else {
            assert!(false, "writer should initialize");
            return;
        };
        writer.mark_encrypted_for_test();
        assert_eq!(
            writer.create_file("/secret", b"x"),
            Err(HxfsWriteError::EncryptedVolume)
        );
        assert_eq!(writer.commit(), Err(HxfsWriteError::EncryptedVolume));
    }
}
