//! HxFS v6 versioned on-disk encryption and compression policy tables.
//!
//! The checkpoint points at one metadata block for each policy family. Mount
//! resolves volume/object policy ids only from these authenticated metadata
//! blocks; test/build configuration is not a policy source.

use alloc::vec::Vec;

use crate::compression::{self, CompressionPolicy};
use crate::crypto::{self, EncryptionPolicy, KeyProvider};
use crate::format::{
    BLOCK_SIZE, BLOCK_TYPE_COMPRESSION_POLICY_TREE, BLOCK_TYPE_ENCRYPTION_POLICY_TREE,
};
use crate::reader::BlockReader;
use crate::{validate_metadata_block, HxfsError};

/// Policy-table schema version.
pub const POLICY_TABLE_VERSION: u16 = 1;
/// Maximum descriptors in one v6 policy block.
pub const MAX_POLICY_RECORDS: usize = 32;
/// Common table prefix bytes.
pub const POLICY_HEADER_BYTES: usize = 16;
/// Encryption descriptor bytes.
pub const ENCRYPTION_RECORD_BYTES: usize = 24;
/// Compression descriptor bytes.
pub const COMPRESSION_RECORD_BYTES: usize = 16;

const ENCRYPTION_MAGIC: u32 = 0x4550_4f4c; // "EPOL"
const COMPRESSION_MAGIC: u32 = 0x4350_4f4c; // "CPOL"
const PROVIDER_TPM_OR_BOOTLOADER: u32 = 1;

/// Read and validate the v6 encryption-policy table.
pub fn read_encryption_policies<R: BlockReader>(
    reader: &mut R,
    lba: u64,
) -> Result<Vec<EncryptionPolicy>, HxfsError> {
    if lba == 0 {
        return Ok(Vec::new());
    }
    let mut block = [0u8; BLOCK_SIZE];
    reader.read_blocks(lba, 1, &mut block)?;
    let header = validate_metadata_block(&block, lba, BLOCK_TYPE_ENCRYPTION_POLICY_TREE, 0)?;
    let base = header.header_bytes as usize;
    let count = parse_table_header(&block, base, ENCRYPTION_MAGIC, ENCRYPTION_RECORD_BYTES)?;
    let mut policies: Vec<EncryptionPolicy> = Vec::new();
    policies
        .try_reserve_exact(count)
        .map_err(|_| HxfsError::NoSpace)?;
    let mut index = 0usize;
    while index < count {
        let offset = base + POLICY_HEADER_BYTES + index * ENCRYPTION_RECORD_BYTES;
        let policy_id = read_u32(&block, offset)?;
        let algorithm = read_u32(&block, offset + 4)?;
        let data_unit_bytes = read_u32(&block, offset + 8)?;
        let provider = match read_u32(&block, offset + 12)? {
            PROVIDER_TPM_OR_BOOTLOADER => KeyProvider::TpmOrBootloader,
            _ => return Err(HxfsError::EncryptedPolicyInvalid),
        };
        if policy_id == 0
            || read_u32(&block, offset + 16)? != 0
            || read_u32(&block, offset + 20)? != 0
            || policies.iter().any(|policy| policy.policy_id == policy_id)
        {
            return Err(HxfsError::EncryptedPolicyInvalid);
        }
        let policy = EncryptionPolicy {
            policy_id,
            algorithm,
            data_unit_bytes,
            provider,
        };
        crypto::validate_for_mount(policy, true).map_err(|_| HxfsError::EncryptedPolicyInvalid)?;
        policies.push(policy);
        index += 1;
    }
    Ok(policies)
}

/// Read and validate the v6 compression-policy table.
pub fn read_compression_policies<R: BlockReader>(
    reader: &mut R,
    lba: u64,
) -> Result<Vec<CompressionPolicy>, HxfsError> {
    if lba == 0 {
        return Ok(Vec::new());
    }
    let mut block = [0u8; BLOCK_SIZE];
    reader.read_blocks(lba, 1, &mut block)?;
    let header = validate_metadata_block(&block, lba, BLOCK_TYPE_COMPRESSION_POLICY_TREE, 0)?;
    let base = header.header_bytes as usize;
    let count = parse_table_header(&block, base, COMPRESSION_MAGIC, COMPRESSION_RECORD_BYTES)?;
    let mut policies: Vec<CompressionPolicy> = Vec::new();
    policies
        .try_reserve_exact(count)
        .map_err(|_| HxfsError::NoSpace)?;
    let mut index = 0usize;
    while index < count {
        let offset = base + POLICY_HEADER_BYTES + index * COMPRESSION_RECORD_BYTES;
        let policy_id = read_u32(&block, offset)?;
        let policy = CompressionPolicy {
            policy_id,
            algorithm: read_u32(&block, offset + 4)?,
            min_size_bytes: read_u32(&block, offset + 8)?,
        };
        if policy_id == 0
            || read_u32(&block, offset + 12)? != 0
            || policies.iter().any(|entry| entry.policy_id == policy_id)
        {
            return Err(HxfsError::CompressionPolicyInvalid);
        }
        compression::validate_policy(policy).map_err(|_| HxfsError::CompressionPolicyInvalid)?;
        policies.push(policy);
        index += 1;
    }
    Ok(policies)
}

/// Encode an encryption table payload for a metadata-block builder.
pub fn encode_encryption_payload(
    policies: &[EncryptionPolicy],
    out: &mut [u8],
) -> Result<usize, HxfsError> {
    if policies.len() > MAX_POLICY_RECORDS {
        return Err(HxfsError::NoSpace);
    }
    let required = POLICY_HEADER_BYTES
        .checked_add(
            policies
                .len()
                .checked_mul(ENCRYPTION_RECORD_BYTES)
                .ok_or(HxfsError::NoSpace)?,
        )
        .ok_or(HxfsError::NoSpace)?;
    if out.len() < required {
        return Err(HxfsError::BufferTooSmall);
    }
    write_header(
        out,
        ENCRYPTION_MAGIC,
        ENCRYPTION_RECORD_BYTES,
        policies.len(),
    );
    for (index, policy) in policies.iter().copied().enumerate() {
        if policy.policy_id == 0
            || policies[..index]
                .iter()
                .any(|entry| entry.policy_id == policy.policy_id)
        {
            return Err(HxfsError::EncryptedPolicyInvalid);
        }
        crypto::validate_for_mount(policy, true).map_err(|_| HxfsError::EncryptedPolicyInvalid)?;
        let offset = POLICY_HEADER_BYTES + index * ENCRYPTION_RECORD_BYTES;
        out[offset..offset + 4].copy_from_slice(&policy.policy_id.to_le_bytes());
        out[offset + 4..offset + 8].copy_from_slice(&policy.algorithm.to_le_bytes());
        out[offset + 8..offset + 12].copy_from_slice(&policy.data_unit_bytes.to_le_bytes());
        out[offset + 12..offset + 16].copy_from_slice(&PROVIDER_TPM_OR_BOOTLOADER.to_le_bytes());
    }
    Ok(required)
}

/// Encode a compression table payload for a metadata-block builder.
pub fn encode_compression_payload(
    policies: &[CompressionPolicy],
    out: &mut [u8],
) -> Result<usize, HxfsError> {
    if policies.len() > MAX_POLICY_RECORDS {
        return Err(HxfsError::NoSpace);
    }
    let required = POLICY_HEADER_BYTES
        .checked_add(
            policies
                .len()
                .checked_mul(COMPRESSION_RECORD_BYTES)
                .ok_or(HxfsError::NoSpace)?,
        )
        .ok_or(HxfsError::NoSpace)?;
    if out.len() < required {
        return Err(HxfsError::BufferTooSmall);
    }
    write_header(
        out,
        COMPRESSION_MAGIC,
        COMPRESSION_RECORD_BYTES,
        policies.len(),
    );
    for (index, policy) in policies.iter().copied().enumerate() {
        if policy.policy_id == 0
            || policies[..index]
                .iter()
                .any(|entry| entry.policy_id == policy.policy_id)
        {
            return Err(HxfsError::CompressionPolicyInvalid);
        }
        compression::validate_policy(policy).map_err(|_| HxfsError::CompressionPolicyInvalid)?;
        let offset = POLICY_HEADER_BYTES + index * COMPRESSION_RECORD_BYTES;
        out[offset..offset + 4].copy_from_slice(&policy.policy_id.to_le_bytes());
        out[offset + 4..offset + 8].copy_from_slice(&policy.algorithm.to_le_bytes());
        out[offset + 8..offset + 12].copy_from_slice(&policy.min_size_bytes.to_le_bytes());
    }
    Ok(required)
}

fn parse_table_header(
    block: &[u8],
    base: usize,
    magic: u32,
    record_bytes: usize,
) -> Result<usize, HxfsError> {
    if read_u32(block, base)? != magic
        || read_u16(block, base + 4)? != POLICY_TABLE_VERSION
        || usize::from(read_u16(block, base + 6)?) != record_bytes
        || read_u32(block, base + 12)? != 0
    {
        return Err(HxfsError::BadTree);
    }
    let count = read_u32(block, base + 8)? as usize;
    if count > MAX_POLICY_RECORDS {
        return Err(HxfsError::BadTree);
    }
    let end = base
        .checked_add(POLICY_HEADER_BYTES)
        .and_then(|value| value.checked_add(count.checked_mul(record_bytes)?))
        .ok_or(HxfsError::BadTree)?;
    if end > block.len() {
        return Err(HxfsError::BadTree);
    }
    Ok(count)
}

fn write_header(out: &mut [u8], magic: u32, record_bytes: usize, count: usize) {
    out[..4].copy_from_slice(&magic.to_le_bytes());
    out[4..6].copy_from_slice(&POLICY_TABLE_VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&(record_bytes as u16).to_le_bytes());
    out[8..12].copy_from_slice(&(count as u32).to_le_bytes());
    out[12..16].fill(0);
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, HxfsError> {
    let raw = bytes.get(offset..offset + 2).ok_or(HxfsError::BadTree)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, HxfsError> {
    let raw = bytes.get(offset..offset + 4).ok_or(HxfsError::BadTree)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_payload_round_trips_shape() {
        let policy = EncryptionPolicy {
            policy_id: 7,
            algorithm: crypto::ALGORITHM_AES_XTS,
            data_unit_bytes: crypto::DATA_UNIT_BYTES_4K,
            provider: KeyProvider::TpmOrBootloader,
        };
        let mut payload = [0u8; 128];
        let length = encode_encryption_payload(&[policy], &mut payload);
        assert_eq!(length, Ok(POLICY_HEADER_BYTES + ENCRYPTION_RECORD_BYTES));
        assert_eq!(read_u32(&payload, 0), Ok(ENCRYPTION_MAGIC));
        assert_eq!(read_u32(&payload, POLICY_HEADER_BYTES), Ok(7));
    }

    #[test]
    fn compression_payload_rejects_duplicate_ids() {
        let policy = CompressionPolicy {
            policy_id: 1,
            algorithm: compression::COMPRESSION_LZ4,
            min_size_bytes: 4096,
        };
        let mut payload = [0u8; 128];
        assert_eq!(
            encode_compression_payload(&[policy, policy], &mut payload),
            Err(HxfsError::CompressionPolicyInvalid)
        );
    }

    #[test]
    fn table_header_rejects_unknown_version_and_large_count() {
        let mut payload = [0u8; 64];
        write_header(&mut payload, ENCRYPTION_MAGIC, ENCRYPTION_RECORD_BYTES, 1);
        payload[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            parse_table_header(&payload, 0, ENCRYPTION_MAGIC, ENCRYPTION_RECORD_BYTES),
            Err(HxfsError::BadTree)
        );
    }
}
