//! Hxfs encryption policy, key wrapping descriptors, and AES-XTS backend.
//!
//! Policy state remains separate from live keys. Hxfs never persists live
//! handles or raw volume keys; a key provider unwraps a per-volume key into RAM,
//! then the crypto layer uses AES-XTS over 4 KiB data units. The software AES
//! primitive is provided by RustCrypto's `aes` crate; this module implements the
//! Hxfs block-level XTS glue for full 4 KiB units.

#[cfg(feature = "crypto-aes")]
use aes::Aes256;
#[cfg(feature = "crypto-aes")]
use cipher::generic_array::GenericArray;
#[cfg(feature = "crypto-aes")]
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use crate::format::BLOCK_SIZE;

/// Encryption algorithm id for AES-XTS.
pub const ALGORITHM_AES_XTS: u32 = 1;
/// Required data unit size: one Hxfs block.
pub const DATA_UNIT_BYTES_4K: u32 = 4096;
/// Maximum wrapped key bytes retained in a volume descriptor side record.
pub const WRAPPED_KEY_BYTES: usize = 64;
/// AES-256-XTS key bytes: 256-bit data key + 256-bit tweak key.
pub const AES_256_XTS_KEY_BYTES: usize = 64;
/// AES block bytes.
pub const AES_BLOCK_BYTES: usize = 16;

/// Key provider for volume keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProvider {
    /// TPM / bootloader provided master key.
    TpmOrBootloader,
}

/// Crypto backend selected for a mounted volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoBackend {
    /// NVMe inline crypto/keyslot backend.
    HardwareNvmeInline,
    /// Software AES-XTS backend.
    SoftwareAesXts,
}

/// Per-volume encryption policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionPolicy {
    /// Policy id referenced by volume/object descriptors.
    pub policy_id: u32,
    /// Algorithm id. Must be [`ALGORITHM_AES_XTS`] for encrypted v1 volumes.
    pub algorithm: u32,
    /// Data unit bytes. Must be 4096 for v1.
    pub data_unit_bytes: u32,
    /// Provider for the wrapping/master key.
    pub provider: KeyProvider,
}

/// Wrapped volume key descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrappedVolumeKey {
    /// Policy id this key belongs to.
    pub policy_id: u32,
    /// Wrapping algorithm/version id.
    pub wrapping_version: u32,
    /// Used bytes in [`Self::wrapped`].
    pub wrapped_len: u16,
    /// Wrapped key bytes.
    pub wrapped: [u8; WRAPPED_KEY_BYTES],
}

impl WrappedVolumeKey {
    /// Create a descriptor from wrapped bytes.
    pub fn new(policy_id: u32, wrapping_version: u32, bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > WRAPPED_KEY_BYTES {
            return None;
        }
        let mut wrapped = [0u8; WRAPPED_KEY_BYTES];
        wrapped[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            policy_id,
            wrapping_version,
            wrapped_len: bytes.len() as u16,
            wrapped,
        })
    }
}

/// In-RAM AES-256-XTS volume key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aes256XtsKey {
    /// AES data key.
    pub data_key: [u8; 32],
    /// AES tweak key.
    pub tweak_key: [u8; 32],
}

impl Aes256XtsKey {
    /// Split a 64-byte raw volume key into data/tweak halves.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != AES_256_XTS_KEY_BYTES {
            return None;
        }
        let mut data_key = [0u8; 32];
        let mut tweak_key = [0u8; 32];
        data_key.copy_from_slice(&bytes[..32]);
        tweak_key.copy_from_slice(&bytes[32..64]);
        Some(Self {
            data_key,
            tweak_key,
        })
    }
}

/// Crypto policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// Unsupported algorithm.
    UnsupportedAlgorithm,
    /// Unsupported data unit size.
    UnsupportedDataUnit,
    /// Required TPM/bootloader key provider is absent.
    MissingKeyProvider,
    /// Raw key shape is invalid.
    BadKey,
    /// Data unit is not exactly one 4 KiB Hxfs block.
    BadDataUnit,
    /// Software AES-XTS engine is not linked in this build.
    EngineUnavailable,
}

/// Validate a policy against available key providers.
pub fn validate_policy(
    policy: EncryptionPolicy,
    key_provider_available: bool,
) -> Result<(), CryptoError> {
    if policy.algorithm != ALGORITHM_AES_XTS {
        return Err(CryptoError::UnsupportedAlgorithm);
    }
    if policy.data_unit_bytes != DATA_UNIT_BYTES_4K {
        return Err(CryptoError::UnsupportedDataUnit);
    }
    if !key_provider_available {
        return Err(CryptoError::MissingKeyProvider);
    }
    Ok(())
}

/// Select a crypto backend. Hardware is preferred but software AES-XTS fallback
/// is mandatory when keys are available.
pub fn select_backend(hardware_inline_crypto: bool) -> CryptoBackend {
    if hardware_inline_crypto {
        CryptoBackend::HardwareNvmeInline
    } else {
        CryptoBackend::SoftwareAesXts
    }
}

/// Derive the XTS data-unit number for a 4 KiB filesystem block.
pub const fn xts_data_unit(block_number: u64) -> u128 {
    block_number as u128
}

/// Encrypt one 4 KiB Hxfs block in place using AES-256-XTS.
pub fn encrypt_block_in_place(
    key: Aes256XtsKey,
    data_unit: u128,
    block: &mut [u8; BLOCK_SIZE],
) -> Result<(), CryptoError> {
    #[cfg(feature = "crypto-aes")]
    {
        return crypt_block_in_place(key, data_unit, block, true);
    }
    #[cfg(not(feature = "crypto-aes"))]
    {
        let _ = key;
        let _ = data_unit;
        let _ = block;
        Err(CryptoError::EngineUnavailable)
    }
}

/// Decrypt one 4 KiB Hxfs block in place using AES-256-XTS.
pub fn decrypt_block_in_place(
    key: Aes256XtsKey,
    data_unit: u128,
    block: &mut [u8; BLOCK_SIZE],
) -> Result<(), CryptoError> {
    #[cfg(feature = "crypto-aes")]
    {
        return crypt_block_in_place(key, data_unit, block, false);
    }
    #[cfg(not(feature = "crypto-aes"))]
    {
        let _ = key;
        let _ = data_unit;
        let _ = block;
        Err(CryptoError::EngineUnavailable)
    }
}

#[cfg(feature = "crypto-aes")]
fn crypt_block_in_place(
    key: Aes256XtsKey,
    data_unit: u128,
    block: &mut [u8; BLOCK_SIZE],
    encrypt: bool,
) -> Result<(), CryptoError> {
    let data_cipher = Aes256::new(GenericArray::from_slice(&key.data_key));
    let tweak_cipher = Aes256::new(GenericArray::from_slice(&key.tweak_key));
    let mut tweak = data_unit.to_le_bytes();
    let mut tweak_block = GenericArray::clone_from_slice(&tweak);
    tweak_cipher.encrypt_block(&mut tweak_block);
    tweak.copy_from_slice(&tweak_block);

    let mut offset = 0usize;
    while offset < block.len() {
        let mut work = [0u8; AES_BLOCK_BYTES];
        work.copy_from_slice(&block[offset..offset + AES_BLOCK_BYTES]);
        xor_block(&mut work, &tweak);
        let mut aes_block = GenericArray::clone_from_slice(&work);
        if encrypt {
            data_cipher.encrypt_block(&mut aes_block);
        } else {
            data_cipher.decrypt_block(&mut aes_block);
        }
        work.copy_from_slice(&aes_block);
        xor_block(&mut work, &tweak);
        block[offset..offset + AES_BLOCK_BYTES].copy_from_slice(&work);
        multiply_tweak_alpha(&mut tweak);
        offset += AES_BLOCK_BYTES;
    }
    Ok(())
}

#[cfg(feature = "crypto-aes")]
fn xor_block(block: &mut [u8; AES_BLOCK_BYTES], tweak: &[u8; AES_BLOCK_BYTES]) {
    let mut index = 0usize;
    while index < AES_BLOCK_BYTES {
        block[index] ^= tweak[index];
        index += 1;
    }
}

#[cfg(feature = "crypto-aes")]
fn multiply_tweak_alpha(tweak: &mut [u8; AES_BLOCK_BYTES]) {
    let mut carry = 0u8;
    let mut index = 0usize;
    while index < AES_BLOCK_BYTES {
        let next_carry = tweak[index] >> 7;
        tweak[index] = (tweak[index] << 1) | carry;
        carry = next_carry;
        index += 1;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EncryptionPolicy {
        EncryptionPolicy {
            policy_id: 7,
            algorithm: ALGORITHM_AES_XTS,
            data_unit_bytes: DATA_UNIT_BYTES_4K,
            provider: KeyProvider::TpmOrBootloader,
        }
    }

    #[cfg(feature = "crypto-aes")]
    fn key() -> Aes256XtsKey {
        let mut raw = [0u8; AES_256_XTS_KEY_BYTES];
        let mut index = 0usize;
        while index < raw.len() {
            raw[index] = index as u8;
            index += 1;
        }
        let mut data_key = [0u8; 32];
        let mut tweak_key = [0u8; 32];
        data_key.copy_from_slice(&raw[..32]);
        tweak_key.copy_from_slice(&raw[32..]);
        Aes256XtsKey {
            data_key,
            tweak_key,
        }
    }

    #[test]
    fn validates_policy_and_requires_key_provider() {
        assert_eq!(validate_policy(policy(), true), Ok(()));
        assert_eq!(
            validate_policy(policy(), false),
            Err(CryptoError::MissingKeyProvider)
        );
    }

    #[test]
    fn selects_hardware_then_software_fallback() {
        assert_eq!(select_backend(true), CryptoBackend::HardwareNvmeInline);
        assert_eq!(select_backend(false), CryptoBackend::SoftwareAesXts);
    }

    #[test]
    fn wrapped_key_bounds_are_enforced() {
        assert!(WrappedVolumeKey::new(1, 1, &[1, 2, 3]).is_some());
        assert!(WrappedVolumeKey::new(1, 1, &[]).is_none());
        assert!(WrappedVolumeKey::new(1, 1, &[0u8; WRAPPED_KEY_BYTES + 1]).is_none());
    }

    #[cfg(feature = "crypto-aes")]
    #[test]
    fn aes_xts_round_trips_one_block() {
        let key = key();
        let mut block = [0u8; BLOCK_SIZE];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = (index & 0xff) as u8;
        }
        let original = block;
        assert_eq!(
            encrypt_block_in_place(key, xts_data_unit(42), &mut block),
            Ok(())
        );
        assert_ne!(block, original);
        assert_eq!(
            decrypt_block_in_place(key, xts_data_unit(42), &mut block),
            Ok(())
        );
        assert_eq!(block, original);
    }

    #[cfg(feature = "crypto-aes")]
    #[test]
    fn xts_tweak_depends_on_data_unit() {
        let key = key();
        let mut a = [0x5au8; BLOCK_SIZE];
        let mut b = a;
        assert_eq!(
            encrypt_block_in_place(key, xts_data_unit(1), &mut a),
            Ok(())
        );
        assert_eq!(
            encrypt_block_in_place(key, xts_data_unit(2), &mut b),
            Ok(())
        );
        assert_ne!(a, b);
    }
}
