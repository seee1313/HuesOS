//! Hxfs encryption policy and key wrapping descriptors.
//!
//! Hxfs uses per-volume AES-XTS policy. This module models policy validation,
//! key wrapping metadata, and backend selection. It does not perform AES in the
//! filesystem core; actual hardware/software crypto backends are separate.

/// Encryption algorithm id for AES-XTS.
pub const ALGORITHM_AES_XTS: u32 = 1;
/// Required data unit size: one Hxfs block.
pub const DATA_UNIT_BYTES_4K: u32 = 4096;
/// Maximum wrapped key bytes retained in a volume descriptor side record.
pub const WRAPPED_KEY_BYTES: usize = 64;

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

/// Crypto policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// Unsupported algorithm.
    UnsupportedAlgorithm,
    /// Unsupported data unit size.
    UnsupportedDataUnit,
    /// Required TPM/bootloader key provider is absent.
    MissingKeyProvider,
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
}
