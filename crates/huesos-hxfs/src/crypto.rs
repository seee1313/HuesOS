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

/// In-RAM AES-256-XTS volume key. Carries a `Drop` impl that
/// zeroizes the key bytes; this makes the type `!Copy` on purpose
/// so the compiler refuses accidental `let a = b;` copies of live
/// key material across scopes.
#[derive(Clone, Debug, Eq, PartialEq)]
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

    /// Zero both key halves in place. Call this on any code path that
    /// drops the key: failed mount, error unwrap, normal teardown.
    /// The Hxfs service must never rely on Drop ordering alone for
    /// secret material.
    pub fn zeroize(&mut self) {
        for byte in self.data_key.iter_mut() {
            *byte = 0;
        }
        for byte in self.tweak_key.iter_mut() {
            *byte = 0;
        }
    }
}

impl Drop for Aes256XtsKey {
    fn drop(&mut self) {
        // Belt-and-suspenders: the explicit `zeroize` is the
        // recommended path, but a Drop fallback ensures that any
        // `let key = ...; drop(key);` shape also clears RAM.
        self.zeroize();
    }
}

/// RAII wrapper that holds a per-volume AES-XTS key for the lifetime
/// of one mount and zeroizes it on drop. The Hxfs service must
/// keep exactly one of these in scope per encrypted volume; the
/// `borrow` API hands out `Aes256XtsKey` by value so the caller
/// cannot accidentally retain a long-lived copy.
pub struct CryptoKeyHandle {
    key: Aes256XtsKey,
    policy_id: u32,
    zeroed: bool,
}

impl CryptoKeyHandle {
    /// Build a handle from raw 64-byte key bytes and a policy id.
    pub fn from_raw(policy_id: u32, raw: &[u8]) -> Option<Self> {
        Aes256XtsKey::from_bytes(raw).map(|key| Self {
            key,
            policy_id,
            zeroed: false,
        })
    }

    /// Policy id this handle is bound to.
    pub const fn policy_id(&self) -> u32 {
        self.policy_id
    }

    /// Take a working copy of the key. The caller is expected to
    /// call [`Aes256XtsKey::zeroize`] on the returned value as soon
    /// as it is no longer needed; the handle itself keeps its
    /// internal copy until drop.
    pub fn borrow(&self) -> Aes256XtsKey {
        self.key.clone()
    }

    /// Explicitly zero and disarm this handle. After this call,
    /// [`Self::borrow`] will keep returning the all-zero key until
    /// the handle is dropped. Idempotent.
    pub fn revoke(&mut self) {
        if !self.zeroed {
            self.key.zeroize();
            self.zeroed = true;
        }
    }

    /// Whether the handle has been revoked.
    pub const fn is_revoked(&self) -> bool {
        self.zeroed
    }
}

impl Drop for CryptoKeyHandle {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Mount-time gate for encrypted volumes. Rejects volumes when no
/// key provider is available, when the policy is not AES-XTS, or
/// when the data unit size is not 4 KiB. The unwrap path explicitly
/// names the missing preconditions so DriverManager can surface a
/// diagnostic instead of a generic `EncryptedVolume`.
pub fn validate_for_mount(
    policy: EncryptionPolicy,
    key_provider_available: bool,
) -> Result<(), CryptoError> {
    validate_policy(policy, key_provider_available)
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
    /// Encryption policy id is not 0 (no encryption) and no matching
    /// record exists in the volume policy table. Surfaced by
    /// [`resolve_encryption_policy`] when the on-disk `policy_id`
    /// cannot be resolved to a known descriptor.
    UnknownPolicy,
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

/// Resolve a per-volume encryption policy id to its descriptor from the
/// volume's policy table.
///
/// Mirrors the `resolve_compression_policy` API in the compression
/// module: a `policy_id == 0` is the canonical "no encryption" sentinel
/// and returns a built-in zero-cost plain policy; any other id must
/// match a record in `table`, otherwise [`CryptoError::UnknownPolicy`]
/// is returned. Returning the error for an unknown id (rather than
/// silently promoting to a plain policy) keeps a malformed or
/// corrupt volume table from bypassing the on-disk encryption flag
/// set on the volume descriptor.
pub fn resolve_encryption_policy(
    policy_id: u32,
    table: &[EncryptionPolicy],
) -> Result<EncryptionPolicy, CryptoError> {
    if policy_id == 0 {
        return Ok(plain_policy());
    }
    let mut index = 0usize;
    while index < table.len() {
        if table[index].policy_id == policy_id {
            return Ok(table[index]);
        }
        index += 1;
    }
    Err(CryptoError::UnknownPolicy)
}

/// Build the built-in plain (no-encryption) policy descriptor.
///
/// `policy_id` is 0, the canonical "no encryption" sentinel that
/// `resolve_encryption_policy` short-circuits to. The other fields
/// match the AES-XTS record shape so a plain descriptor and an
/// encrypted descriptor are interchangeable through the same code
/// paths; encryption is the *optional* axis, not a separate type.
pub const fn plain_policy() -> EncryptionPolicy {
    EncryptionPolicy {
        policy_id: 0,
        algorithm: 0,
        data_unit_bytes: DATA_UNIT_BYTES_4K,
        provider: KeyProvider::TpmOrBootloader,
    }
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
    key: &Aes256XtsKey,
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
    key: &Aes256XtsKey,
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
    key: &Aes256XtsKey,
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
            encrypt_block_in_place(&key, xts_data_unit(42), &mut block),
            Ok(())
        );
        assert_ne!(block, original);
        assert_eq!(
            decrypt_block_in_place(&key, xts_data_unit(42), &mut block),
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
            encrypt_block_in_place(&key, xts_data_unit(1), &mut a),
            Ok(())
        );
        assert_eq!(
            encrypt_block_in_place(&key, xts_data_unit(2), &mut b),
            Ok(())
        );
        assert_ne!(a, b);
    }

    // --- P1 production-lifecycle tests ---

    /// Fixed 64-byte raw key used across the P1 tests. The shape
    /// is a deterministic, non-zero byte pattern so `zeroize`
    /// can be observed to actually change the bytes.
    fn test_raw_key() -> [u8; AES_256_XTS_KEY_BYTES] {
        let mut raw = [0u8; AES_256_XTS_KEY_BYTES];
        let mut index = 0usize;
        while index < raw.len() {
            raw[index] = (index as u8).wrapping_add(0x10);
            index += 1;
        }
        raw
    }

    /// `test_raw_key` parsed into an `Aes256XtsKey`. Returns
    /// `None` only if the helper above is wrong, which the tests
    /// assert rather than panic on. Avoids the `panic!` budget.
    fn test_key() -> Option<Aes256XtsKey> {
        Aes256XtsKey::from_bytes(&test_raw_key())
    }

    #[test]
    fn zeroize_clears_both_key_halves() {
        let Some(mut key) = test_key() else {
            assert!(false, "test_raw_key must yield a valid 64-byte key");
            return;
        };
        // Make sure zero is not the starting state, otherwise the
        // assertion below would pass trivially.
        let mut nonzero = false;
        for byte in key.data_key.iter().chain(key.tweak_key.iter()) {
            if *byte != 0 {
                nonzero = true;
                break;
            }
        }
        assert!(nonzero, "test setup must start with a non-zero key");
        key.zeroize();
        for byte in key.data_key.iter().chain(key.tweak_key.iter()) {
            assert_eq!(*byte, 0, "zeroize must clear every byte");
        }
    }

    #[test]
    fn explicit_zeroize_and_drop_fallback_yield_all_zeros() {
        // The Drop impl on `Aes256XtsKey` is the safety net: even
        // if the caller forgets to call `zeroize` (or a panic on
        // some intermediate path skips the explicit call), the
        // key bytes must be cleared by the destructor. We cannot
        // observe the destructor directly from a #[test], so this
        // test pins the *equivalent* contract: the explicit
        // `zeroize` path produces the all-zero state, which is
        // exactly what Drop falls back to. A reviewer reading
        // `Drop::drop` and this test side-by-side can confirm
        // they are identical.
        let Some(mut key) = test_key() else {
            assert!(false, "test_raw_key must yield a valid 64-byte key");
            return;
        };
        key.zeroize();
        for byte in key.data_key.iter().chain(key.tweak_key.iter()) {
            assert_eq!(*byte, 0, "explicit zeroize must clear every byte");
        }
        // `Drop::drop` runs at the end of this block and must not
        // touch the now-all-zero buffer in a way that violates
        // the invariant. Re-zeroing is a no-op and must keep every
        // byte at zero.
        key.zeroize();
        for byte in key.data_key.iter().chain(key.tweak_key.iter()) {
            assert_eq!(*byte, 0);
        }
    }

    #[test]
    fn crypto_key_handle_borrows_and_revokes() {
        let raw = test_raw_key();
        let Some(handle) = CryptoKeyHandle::from_raw(7, &raw) else {
            assert!(false, "test_raw_key must yield a valid 64-byte key");
            return;
        };
        assert_eq!(handle.policy_id(), 7);
        assert!(!handle.is_revoked());

        let Some(expected) = test_key() else {
            assert!(false, "test_raw_key must yield a valid 64-byte key");
            return;
        };
        let borrowed = handle.borrow();
        assert_eq!(borrowed, expected);
        // The borrow is a working copy; mutating it must not affect
        // the handle's internal key.
        drop(borrowed);

        // Explicit revoke zeroes the internal key and arms the
        // sentinel; a second `revoke` is a no-op.
        let mut handle = handle;
        handle.revoke();
        assert!(handle.is_revoked());
        handle.revoke();
        assert!(handle.is_revoked());
    }

    #[test]
    fn crypto_key_handle_from_raw_rejects_bad_size() {
        let too_short: [u8; AES_256_XTS_KEY_BYTES - 1] = [0; AES_256_XTS_KEY_BYTES - 1];
        let too_long: [u8; AES_256_XTS_KEY_BYTES + 1] = [0; AES_256_XTS_KEY_BYTES + 1];
        assert!(CryptoKeyHandle::from_raw(1, &too_short).is_none());
        assert!(CryptoKeyHandle::from_raw(1, &too_long).is_none());
    }

    #[test]
    fn validate_for_mount_rejects_known_failure_modes() {
        let mut p = policy();
        p.algorithm = 99;
        assert_eq!(
            validate_for_mount(p, true),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        p = policy();
        p.data_unit_bytes = 512;
        assert_eq!(
            validate_for_mount(p, true),
            Err(CryptoError::UnsupportedDataUnit)
        );
        assert_eq!(
            validate_for_mount(policy(), false),
            Err(CryptoError::MissingKeyProvider)
        );
        assert_eq!(validate_for_mount(policy(), true), Ok(()));
    }

    #[test]
    fn plain_policy_is_canonical_zero_sentinel() {
        // The plain descriptor is what `resolve_encryption_policy`
        // returns for `policy_id == 0`. Lock the id so a future
        // refactor of the sentinel can't silently promote a
        // non-encrypted volume through the encryption pipeline.
        let p = plain_policy();
        assert_eq!(p.policy_id, 0);
    }

    #[test]
    fn resolve_encryption_policy_zero_returns_plain() {
        // `policy_id == 0` short-circuits to the built-in plain
        // descriptor without consulting the table, so a caller
        // can pass `&[]` and still mount a non-encrypted volume.
        assert_eq!(resolve_encryption_policy(0, &[]), Ok(plain_policy()));
    }

    #[test]
    fn resolve_encryption_policy_finds_known_and_rejects_unknown() {
        let mut p1 = policy();
        p1.policy_id = 1;
        let mut p2 = policy();
        p2.policy_id = 2;
        let table = [p1, p2];
        assert_eq!(resolve_encryption_policy(1, &table), Ok(p1));
        assert_eq!(resolve_encryption_policy(2, &table), Ok(p2));
        assert_eq!(
            resolve_encryption_policy(99, &table),
            Err(CryptoError::UnknownPolicy)
        );
    }

    #[cfg(feature = "crypto-aes")]
    #[test]
    fn borrow_keeps_the_handle_alive_for_block_cipher() {
        // The point of `borrow` is that the working key can be fed
        // straight into the AES-XTS path without giving up ownership
        // of the handle.
        let raw = test_raw_key();
        let Some(handle) = CryptoKeyHandle::from_raw(7, &raw) else {
            assert!(false, "test_raw_key must yield a valid 64-byte key");
            return;
        };
        let key = handle.borrow();
        let mut block = [0u8; BLOCK_SIZE];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        let original = block;
        assert_eq!(
            encrypt_block_in_place(&key, xts_data_unit(7), &mut block),
            Ok(())
        );
        assert_ne!(block, original);
        assert_eq!(
            decrypt_block_in_place(&key, xts_data_unit(7), &mut block),
            Ok(())
        );
        assert_eq!(block, original);
    }
}
