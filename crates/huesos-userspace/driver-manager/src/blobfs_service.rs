//! Read-only BlobFS service over the system Volume.
//!
//! Stage E mounts an immutable content-addressed BlobFS image from the
//! NVMe/SSD-optimized system volume. The service is intentionally read-only:
//! clients can list hashes and open a blob by hash, receiving a VMO handle.

use crate::protocol;
use crate::volume_service::VolumeManagerService;
use huesos_abi::rights;
use huesos_blobfs::{
    parse_entry_record, parse_hash_hex, parse_superblock_prefix, BlobEntry, BlobFsError, BlobHash,
    Sha256, Superblock, ENTRY_BYTES, SUPERBLOCK_BYTES,
};
use libcanvas::{println, Channel, ErrorCode, Vmo};

const MAX_BLOBFS_CLIENTS: usize = 4;
const MAX_BLOB_LIST_RESPONSE: usize = 1024;
const MAX_BLOCK_BYTES: usize = 4096;
/// Largest blob this service will materialise into a VMO.
///
/// `entry.length` comes from the on-disk table, which is untrusted
/// input, and it decides the size of the `Vmo::create` below. Without
/// a ceiling a corrupted or hostile table could name a multi-gigabyte
/// blob and have the service try to allocate it before a single byte
/// is hash-checked. 64 MiB is far above any blob the bootfs carries.
const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// DriverManager-owned BlobFS read-only service.
pub struct BlobFsService {
    mount: Option<BlobFsMount>,
    clients: [Option<Channel>; MAX_BLOBFS_CLIENTS],
}

struct BlobFsMount {
    device: libcanvas::block::BlockDevice,
    superblock: Superblock,
    block_size: u32,
}

impl BlobFsService {
    /// Empty BlobFS service.
    pub const fn new() -> Self {
        Self {
            mount: None,
            clients: [const { None }; MAX_BLOBFS_CLIENTS],
        }
    }

    /// Open BlobFS through the DriverManager registry.
    pub fn open_for_registry(
        &mut self,
        registry: &Channel,
        volume: &mut VolumeManagerService,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
    ) {
        if self
            .ensure_mounted(volume, nvme_bootstrap, nvme_online)
            .is_err()
        {
            let _ = registry.write(protocol::BLOBFS_UNAVAILABLE.as_bytes());
            return;
        }
        let Some(slot) = self.clients.iter_mut().find(|slot| slot.is_none()) else {
            let _ = registry.write(protocol::BLOBFS_UNAVAILABLE.as_bytes());
            println!("[driver-manager] BlobFS client table full");
            return;
        };
        match Channel::pair() {
            Ok((client_end, server_end)) => {
                if let Err((error, _handle)) = registry.write_handle(
                    protocol::BLOBFS_CHANNEL.as_bytes(),
                    client_end.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to return BlobFS channel: {}",
                        error.as_str()
                    );
                    return;
                }
                *slot = Some(server_end);
                println!("[driver-manager] opened BlobFS service channel");
            }
            Err(error) => {
                println!(
                    "[driver-manager] failed to create BlobFS channel: {}",
                    error.as_str()
                );
                let _ = registry.write(protocol::BLOBFS_UNAVAILABLE.as_bytes());
            }
        }
    }

    /// Poll BlobFS clients.
    pub fn poll(
        &mut self,
        _volume: &mut VolumeManagerService,
        _nvme_bootstrap: Option<&Channel>,
        _nvme_online: bool,
    ) {
        let mut index = 0usize;
        while index < self.clients.len() {
            self.poll_client(index);
            index += 1;
        }
    }

    fn ensure_mounted(
        &mut self,
        volume: &mut VolumeManagerService,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
    ) -> Result<(), ErrorCode> {
        if self.mount.is_some() {
            return Ok(());
        }
        if !nvme_online {
            return Err(ErrorCode::ShouldWait);
        }
        let Some(nvme_bootstrap) = nvme_bootstrap else {
            return Err(ErrorCode::ShouldWait);
        };
        let channel = volume.open_fs_candidate_channel(nvme_bootstrap, nvme_online)?;
        let mut device = libcanvas::block::BlockDevice::from_channel(channel)?;
        let info = device.info()?;
        if info.block_size == 0 || info.block_size as usize > MAX_BLOCK_BYTES {
            return Err(ErrorCode::InvalidArgs);
        }
        let mut first = [0u8; MAX_BLOCK_BYTES];
        device.read_blocks(0, 1, &mut first[..info.block_size as usize])?;
        let superblock = parse_superblock_prefix(&first[..SUPERBLOCK_BYTES]).map_err(blob_error)?;
        self.validate_table(&mut device, superblock, info.block_size)?;
        self.mount = Some(BlobFsMount {
            device,
            superblock,
            block_size: info.block_size,
        });
        println!(
            "[driver-manager] BlobFS mounted: blobs={} image_size={}",
            superblock.blob_count, superblock.image_size
        );
        Ok(())
    }

    fn validate_table(
        &self,
        device: &mut libcanvas::block::BlockDevice,
        superblock: Superblock,
        block_size: u32,
    ) -> Result<(), ErrorCode> {
        let mut previous_end = superblock.data_offset;
        let mut index = 0u32;
        while index < superblock.blob_count {
            let entry = read_entry(device, block_size, superblock, index).map_err(blob_error)?;
            validate_entry(superblock, entry, previous_end).map_err(blob_error)?;
            previous_end = entry.offset.saturating_add(entry.length);
            index += 1;
        }
        Ok(())
    }

    fn poll_client(&mut self, index: usize) {
        let mut request = [0u8; 96];
        loop {
            let Some(client) = self.clients[index].as_ref() else {
                return;
            };
            match client.read_into(&mut request) {
                Ok(n) => self.handle_request(index, &request[..n]),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.clients[index] = None;
                    return;
                }
                Err(error) => {
                    println!("[driver-manager] BlobFS read failed: {}", error.as_str());
                    return;
                }
            }
        }
    }

    fn handle_request(&mut self, index: usize, request: &[u8]) {
        if request == b"LIST" {
            self.list(index);
            return;
        }
        if let Some(hash_hex) = strip_prefix(request, b"OPEN ") {
            if let Some(hash) = parse_hash_hex(hash_hex) {
                self.open_blob(index, hash);
            } else {
                self.write(index, b"err:blobfs-bad-hash");
            }
            return;
        }
        self.write(index, b"err:blobfs-invalid");
    }

    fn list(&mut self, index: usize) {
        let Some(mount) = self.mount.as_mut() else {
            self.write(index, b"err:blobfs-not-mounted");
            return;
        };
        let mut out = [0u8; MAX_BLOB_LIST_RESPONSE];
        let len = {
            let mut writer = HexListWriter::new(&mut out);
            let mut blob_index = 0u32;
            while blob_index < mount.superblock.blob_count {
                if let Ok(entry) = read_entry(
                    &mut mount.device,
                    mount.block_size,
                    mount.superblock,
                    blob_index,
                ) {
                    writer.write_hash(&entry.hash);
                    writer.write_byte(b'\n');
                }
                blob_index += 1;
            }
            writer.len()
        };
        self.write(index, &out[..len]);
    }

    fn open_blob(&mut self, index: usize, hash: BlobHash) {
        let result = self.read_blob_to_vmo(hash);
        match result {
            Ok(vmo) => {
                let Some(client) = self.clients[index].as_ref() else {
                    return;
                };
                let duplicate = match vmo.duplicate(rights::READ | rights::TRANSFER) {
                    Ok(duplicate) => duplicate,
                    Err(_) => {
                        self.write(index, b"err:blobfs-vmo");
                        return;
                    }
                };
                if let Err((error, _handle)) = client.write_handle(
                    protocol::BLOBFS_BLOB_VMO.as_bytes(),
                    duplicate.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to return BlobFS blob VMO: {}",
                        error.as_str()
                    );
                }
            }
            Err(BlobFsError::NotFound) => self.write(index, b"err:blobfs-not-found"),
            Err(_) => self.write(index, b"err:blobfs"),
        }
    }

    fn read_blob_to_vmo(&mut self, hash: BlobHash) -> Result<Vmo, BlobFsError> {
        let Some(mount) = self.mount.as_mut() else {
            return Err(BlobFsError::BadLayout);
        };
        // Re-validate with the SAME accumulated `previous_end` the
        // mount-time check uses. Passing `data_offset` here instead
        // made the anti-overlap rule vacuous on the read path: every
        // entry was compared against the start of the data region
        // rather than the end of its predecessor, so a table that
        // mount would reject could still be read from.
        let mut previous_end = mount.superblock.data_offset;
        let mut blob_index = 0u32;
        while blob_index < mount.superblock.blob_count {
            let entry = read_entry(
                &mut mount.device,
                mount.block_size,
                mount.superblock,
                blob_index,
            )?;
            validate_entry(mount.superblock, entry, previous_end)?;
            if entry.hash == hash {
                return read_payload_to_vmo(&mut mount.device, mount.block_size, entry);
            }
            previous_end = entry
                .offset
                .saturating_add(entry.length)
                .max(entry.offset.saturating_add(1));
            blob_index += 1;
        }
        Err(BlobFsError::NotFound)
    }

    fn write(&self, index: usize, bytes: &[u8]) {
        if let Some(client) = self.clients[index].as_ref() {
            let _ = client.write(bytes);
        }
    }
}

fn read_payload_to_vmo(
    device: &mut libcanvas::block::BlockDevice,
    block_size: u32,
    entry: BlobEntry,
) -> Result<Vmo, BlobFsError> {
    // Bound the allocation before trusting the table: `entry.length`
    // is attacker-influenced and is only proven honest once the
    // payload hashes correctly, which cannot happen until after the
    // VMO exists.
    if entry.length > MAX_BLOB_BYTES {
        return Err(BlobFsError::BadLayout);
    }
    let vmo = Vmo::create(entry.length).map_err(|_| BlobFsError::BadLayout)?;
    let mut scratch = [0u8; MAX_BLOCK_BYTES];
    let mut hasher = Sha256::new();
    let mut copied = 0u64;
    while copied < entry.length {
        let absolute = entry.offset + copied;
        let block = absolute / u64::from(block_size);
        let within = (absolute % u64::from(block_size)) as usize;
        let chunk = (entry.length - copied)
            .min(u64::from(block_size) - within as u64)
            .min(MAX_BLOCK_BYTES as u64) as usize;
        device
            .read_blocks(block, 1, &mut scratch[..block_size as usize])
            .map_err(|_| BlobFsError::BadLayout)?;
        let data = &scratch[within..within + chunk];
        hasher = hasher.update(data);
        if vmo
            .write(copied, data)
            .map_err(|_| BlobFsError::BadLayout)?
            != data.len()
        {
            return Err(BlobFsError::BadLayout);
        }
        copied += chunk as u64;
    }
    if hasher.finish() != entry.hash {
        return Err(BlobFsError::HashMismatch);
    }
    Ok(vmo)
}

fn read_entry(
    device: &mut libcanvas::block::BlockDevice,
    block_size: u32,
    superblock: Superblock,
    index: u32,
) -> Result<BlobEntry, BlobFsError> {
    let offset = superblock
        .table_offset
        .checked_add(u64::from(index) * ENTRY_BYTES as u64)
        .ok_or(BlobFsError::BadLayout)?;
    let mut record = [0u8; ENTRY_BYTES];
    read_exact(device, block_size, offset, &mut record)?;
    parse_entry_record(&record)
}

fn read_exact(
    device: &mut libcanvas::block::BlockDevice,
    block_size: u32,
    offset: u64,
    out: &mut [u8],
) -> Result<(), BlobFsError> {
    let mut scratch = [0u8; MAX_BLOCK_BYTES];
    let mut copied = 0usize;
    while copied < out.len() {
        let absolute = offset + copied as u64;
        let block = absolute / u64::from(block_size);
        let within = (absolute % u64::from(block_size)) as usize;
        let chunk = (out.len() - copied).min(block_size as usize - within);
        device
            .read_blocks(block, 1, &mut scratch[..block_size as usize])
            .map_err(|_| BlobFsError::BadLayout)?;
        out[copied..copied + chunk].copy_from_slice(&scratch[within..within + chunk]);
        copied += chunk;
    }
    Ok(())
}

fn validate_entry(
    superblock: Superblock,
    entry: BlobEntry,
    previous_end: u64,
) -> Result<(), BlobFsError> {
    if entry.flags != 0 || entry.offset < superblock.data_offset {
        return Err(BlobFsError::BadLayout);
    }
    let end = entry
        .offset
        .checked_add(entry.length)
        .ok_or(BlobFsError::BadLayout)?;
    if end > superblock.image_size || entry.offset < previous_end {
        return Err(BlobFsError::Overlap);
    }
    Ok(())
}

fn blob_error(error: BlobFsError) -> ErrorCode {
    match error {
        BlobFsError::NotFound => ErrorCode::NotFound,
        BlobFsError::TooSmall
        | BlobFsError::BadMagic
        | BlobFsError::BadVersion
        | BlobFsError::BadLayout
        | BlobFsError::Overlap
        | BlobFsError::ReservedNonZero
        | BlobFsError::HashMismatch => ErrorCode::InvalidArgs,
    }
}

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.starts_with(prefix) {
        Some(&bytes[prefix.len()..])
    } else {
        None
    }
}

struct HexListWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> HexListWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_byte(&mut self, byte: u8) {
        if self.len < self.out.len() {
            self.out[self.len] = byte;
            self.len += 1;
        }
    }

    fn write_hash(&mut self, hash: &BlobHash) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &byte in hash {
            self.write_byte(HEX[(byte >> 4) as usize]);
            self.write_byte(HEX[(byte & 0x0f) as usize]);
        }
    }
}
