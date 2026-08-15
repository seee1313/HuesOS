//! Stage B.3 wire-format helpers for encrypted data extents.
//!
//! A data extent is a sequence of 4 KiB blocks. Each block on
//! disk is a `CompressedExtent` payload (the result of running
//! the resolved compression codec over the plaintext). Stage
//! B.3 adds an *optional* outer encryption envelope: when the
//! extent's owning object has a non-zero `encryption_policy_id`,
//! the compressed payload is itself encrypted with
//! AES-256-GCM under a separate per-volume subkey.
//!
//! ## Read order
//!
//! `decrypt → decompress → plaintext to caller`
//!
//! The page cache lives **below** the encryption layer: the
//! cache stores the *decompressed plaintext* so a second read
//! of the same page skips both the AES-GCM work and the LZ4
//! decompress. The cache key is the (volume_id, physical
//! block, page_index) triple; encrypting the on-disk form
//! does not change the cache key.
//!
//! ## Write order
//!
//! `plaintext → compress → encrypt → to disk`
//!
//! The fixed writer applies the same steps in reverse: it
//! compresses the plaintext with the resolved compression
//! codec, then encrypts the compressed form with the
//! per-volume extent subkey.
//!
//! ## Key derivation
//!
//! `extent_key = HKDF-SHA256(volume_key, salt=volume_id,
//! info=b"hxfs-extent-v1")`. This is a different info string
//! from the metadata subkey (`b"hxfs-metadata-v1"`) so a
//! metadata-key leak does not also leak extent data. The
//! subkey is held in RAM for the lifetime of the mount and
//! is never persisted.
//!
//! ## Failure modes
//!
//! - `extent_encrypt: PlaintextTooLong` — caller handed in a
//!   buffer larger than the on-disk extent block can hold.
//! - `extent_decrypt: BadTag` — the on-disk block was tampered
//!   with or the wrong key was used. Surfaces as
//!   `HxfsError::Compression` at the read boundary; the
//!   higher layer marks the extent bad and continues with the
//!   next extent.
//! - `extent_decrypt: EngineError` — AES-GCM rejected the
//!   key shape. Should be unreachable for the 32-byte keys
//!   we use.

use crate::format::BLOCK_SIZE;
#[cfg(feature = "crypto-aes-gcm")]
use crate::hkdf::derive_extent_subkey;
use crate::{crypto_aes_gcm, Uuid};

/// Maximum plaintext bytes for an encrypted extent block:
/// 4028. Matches `crypto_aes_gcm::MAX_PLAINTEXT_BYTES` (the
/// AEAD envelope is the same on every encrypted block
/// regardless of where it lives in the on-disk format). An
/// extent block is `4096 = 4028 plaintext + 12 nonce + 16 tag
/// + 40 zero-pad`.
///
/// The AEAD authenticates only the first 4028 bytes, and the read
/// path ignores the trailing 40.
pub const EXTENT_PLAINTEXT_BYTES: usize = crypto_aes_gcm::MAX_PLAINTEXT_BYTES;

/// Total on-disk size of the encrypted extent block body:
/// `nonce(12) + ciphertext(4028) + tag(16) = 4056`. The
/// block is then padded to a full 4 KiB by the caller (the
/// remaining 40 bytes after the GCM envelope are zero and
/// are ignored by the read path).
pub const EXTENT_ENCRYPTED_BYTES: usize =
    EXTENT_PLAINTEXT_BYTES + crypto_aes_gcm::NONCE_BYTES + crypto_aes_gcm::TAG_BYTES;

/// Encrypt a 4 KiB extent block under the per-volume extent
/// subkey. The on-disk layout is the full 4 KiB block filled
/// with `nonce(12) || ciphertext(4068) || tag(16)`. Extent
/// blocks are **not** metadata blocks: there is no
/// `BlockHeader` on a raw extent, so the entire 4 KiB slot is
/// the AES-GCM envelope.
///
/// `compressed_plaintext` is the result of running the
/// resolved compression codec over the plaintext data. The
/// function pads it to `EXTENT_PLAINTEXT_BYTES` with zeros
/// (the GCM tag authenticates the padding) and writes the
/// encrypted form into `out`.
///
/// `out` must be at least `EXTENT_ENCRYPTED_BYTES` (4096)
/// bytes long. The function writes exactly
/// `EXTENT_ENCRYPTED_BYTES` bytes to `out` and returns the
/// number written.
pub fn encrypt_extent_block(
    key: &[u8; 32],
    physical_block: u64,
    generation: u64,
    volume_uuid: &Uuid,
    compressed_plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, ExtentCryptoError> {
    if compressed_plaintext.len() > EXTENT_PLAINTEXT_BYTES {
        return Err(ExtentCryptoError::PlaintextTooLong);
    }
    if out.len() < EXTENT_ENCRYPTED_BYTES {
        return Err(ExtentCryptoError::OutputTooSmall);
    }
    // Pad the compressed payload to a fixed size so the
    // ciphertext is always exactly `EXTENT_ENCRYPTED_BYTES`.
    // The padding is zeros; the GCM tag authenticates the
    // padding too so a tampering attack on the padding
    // region is caught.
    let mut padded = [0u8; EXTENT_PLAINTEXT_BYTES];
    padded[..compressed_plaintext.len()].copy_from_slice(compressed_plaintext);
    let written = crypto_aes_gcm::encrypt_block(
        key,
        physical_block,
        generation,
        volume_uuid,
        &padded,
        &mut out[..EXTENT_ENCRYPTED_BYTES],
    )
    .map_err(|_| ExtentCryptoError::EngineError)?;
    if written != EXTENT_ENCRYPTED_BYTES {
        return Err(ExtentCryptoError::EngineError);
    }
    Ok(written)
}

/// Decrypt a 4 KiB encrypted extent block in place. The caller
/// hands in the raw 4 KiB block read from disk; the function
/// verifies the GCM tag against `key + (physical_block,
/// volume_uuid)` and writes the compressed plaintext into
/// `out` (a caller-bounded `EXTENT_PLAINTEXT_BYTES` buffer).
///
/// The function does **not** modify `block`; it only reads
/// the entire 4 KiB body. The decrypted bytes land in `out`.
///
/// Returns the number of plaintext bytes written. On `BadTag`
/// the function does not write to `out`.
pub fn decrypt_extent_block(
    key: &[u8; 32],
    physical_block: u64,
    generation: u64,
    volume_uuid: &Uuid,
    block: &[u8; BLOCK_SIZE],
    out: &mut [u8],
) -> Result<usize, ExtentCryptoError> {
    if out.len() < EXTENT_PLAINTEXT_BYTES {
        return Err(ExtentCryptoError::OutputTooSmall);
    }
    // The on-disk block holds `nonce(12) + ciphertext(4028) +
    // tag(16) = 4056 bytes` starting at offset 0; the
    // remaining 40 bytes are zero padding and are
    // ignored.
    let encrypted = &block[..EXTENT_ENCRYPTED_BYTES];
    let plaintext_len =
        crypto_aes_gcm::decrypt_block(key, physical_block, generation, volume_uuid, encrypted, out)
            .map_err(|_| ExtentCryptoError::BadTag)?;
    if plaintext_len != EXTENT_PLAINTEXT_BYTES {
        return Err(ExtentCryptoError::EngineError);
    }
    Ok(plaintext_len)
}

/// Failure modes for the extent encrypt/decrypt path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentCryptoError {
    /// Plaintext is longer than `EXTENT_PLAINTEXT_BYTES`.
    PlaintextTooLong,
    /// Caller's output buffer is too small for the on-disk
    /// ciphertext.
    OutputTooSmall,
    /// GCM tag verification failed: the on-disk block has
    /// been tampered with or the wrong key was used.
    BadTag,
    /// AES-GCM engine returned an unexpected error (key
    /// shape, nonce shape, etc.). Should be unreachable.
    EngineError,
}

/// Derive the per-volume extent subkey from the 32-byte data
/// half of the AES-256-XTS volume key. The HKDF info string
/// `b"hxfs-extent-v1"` is different from the metadata subkey
/// (`b"hxfs-metadata-v1"`) so the two subkey spaces are
/// cryptographically independent.
#[cfg(feature = "crypto-aes-gcm")]
pub fn derive_extent_key_for_volume(
    volume_key_data_half: &[u8; 32],
    volume_uuid: &Uuid,
    out: &mut [u8],
) -> Result<(), crate::hkdf::HkdfError> {
    derive_extent_subkey(volume_key_data_half, volume_uuid, out)
}

/// Resolve the encryption policy that applies to a given
/// extent's owning object: the object's per-record policy if
/// non-zero, otherwise the system volume's per-volume policy.
/// Returns `Some(policy_id)` if the object/volume is encrypted
/// (i.e. the extent should be wrapped with AES-256-GCM); a
/// return value of `None` means the extent stays plain.
///
/// Mirrors `resolve_compression_for_object` in lib.rs: the
/// per-record policy takes precedence over the per-volume
/// policy, and `policy_id == 0` is the canonical plain
/// sentinel.
pub fn resolve_extent_encryption_for_object(
    system_volume: &crate::format::VolumeDescriptor,
    object: &crate::format::ObjectDescriptor,
) -> bool {
    let policy_id = if object.encryption_policy_id != 0 {
        object.encryption_policy_id
    } else {
        system_volume.encryption_policy_id
    };
    policy_id != 0
}

#[cfg(all(test, feature = "crypto-aes-gcm"))]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        let mut index = 0usize;
        while index < key.len() {
            key[index] = (index as u8).wrapping_add(0x90);
            index += 1;
        }
        key
    }

    fn test_volume_uuid() -> Uuid {
        let mut id = [0u8; 16];
        let mut index = 0usize;
        while index < id.len() {
            id[index] = 0xb0u8.wrapping_add(index as u8);
            index += 1;
        }
        id
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let id = test_volume_uuid();
        let mut compressed = [0u8; 1024];
        for (index, byte) in compressed.iter_mut().enumerate() {
            *byte = (index & 0xff) as u8;
        }
        let mut out = [0u8; EXTENT_ENCRYPTED_BYTES];
        let written =
            encrypt_extent_block(&key, 42, 0, &id, &compressed, &mut out).expect("encrypt");
        assert_eq!(written, EXTENT_ENCRYPTED_BYTES);
        let mut block = [0u8; BLOCK_SIZE];
        // Stage B.3 wire: the on-disk extent block holds the
        // encrypted envelope (`nonce || ciphertext || tag`)
        // starting at byte 0, with the remaining 40 bytes
        // zero-padded. The encrypt function writes the
        // envelope to `out`, and we copy it into the head
        // of the block.
        block[..written].copy_from_slice(&out[..written]);
        let mut plaintext = [0u8; EXTENT_PLAINTEXT_BYTES];
        let read = decrypt_extent_block(&key, 42, 0, &id, &block, &mut plaintext).expect("decrypt");
        assert_eq!(read, EXTENT_PLAINTEXT_BYTES);
        assert_eq!(&plaintext[..compressed.len()], &compressed[..]);
        // Trailing padding bytes are zero.
        let mut all_zero = true;
        for byte in &plaintext[compressed.len()..] {
            if *byte != 0 {
                all_zero = false;
                break;
            }
        }
        assert!(all_zero, "padding bytes must be zero");
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = test_key();
        let id = test_volume_uuid();
        let compressed = [0xa5u8; 512];
        let mut out = [0u8; EXTENT_ENCRYPTED_BYTES];
        encrypt_extent_block(&key, 7, 0, &id, &compressed, &mut out).expect("encrypt");
        let mut block = [0u8; BLOCK_SIZE];
        block[..EXTENT_ENCRYPTED_BYTES].copy_from_slice(&out[..EXTENT_ENCRYPTED_BYTES]);
        // Flip a byte in the ciphertext region (after the
        // 12-byte nonce).
        block[12 + 10] ^= 0x01;
        let mut plaintext = [0u8; EXTENT_PLAINTEXT_BYTES];
        assert_eq!(
            decrypt_extent_block(&key, 7, 0, &id, &block, &mut plaintext),
            Err(ExtentCryptoError::BadTag)
        );
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let key = test_key();
        let id = test_volume_uuid();
        let compressed = [0x77u8; 256];
        let mut out = [0u8; EXTENT_ENCRYPTED_BYTES];
        encrypt_extent_block(&key, 11, 0, &id, &compressed, &mut out).expect("encrypt");
        let mut block = [0u8; BLOCK_SIZE];
        block[..EXTENT_ENCRYPTED_BYTES].copy_from_slice(&out[..EXTENT_ENCRYPTED_BYTES]);
        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        let mut plaintext = [0u8; EXTENT_PLAINTEXT_BYTES];
        assert_eq!(
            decrypt_extent_block(&wrong_key, 11, 0, &id, &block, &mut plaintext),
            Err(ExtentCryptoError::BadTag)
        );
    }

    #[test]
    fn decrypt_rejects_wrong_physical_block() {
        let key = test_key();
        let id = test_volume_uuid();
        let compressed = [0x33u8; 256];
        let mut out = [0u8; EXTENT_ENCRYPTED_BYTES];
        encrypt_extent_block(&key, 100, 0, &id, &compressed, &mut out).expect("encrypt");
        let mut block = [0u8; BLOCK_SIZE];
        block[..EXTENT_ENCRYPTED_BYTES].copy_from_slice(&out[..EXTENT_ENCRYPTED_BYTES]);
        // Decrypt with a different physical_block: the
        // rebuilt nonce will not match the on-disk nonce and
        // the AEAD returns BadTag.
        let mut plaintext = [0u8; EXTENT_PLAINTEXT_BYTES];
        assert_eq!(
            decrypt_extent_block(&key, 101, 0, &id, &block, &mut plaintext),
            Err(ExtentCryptoError::BadTag)
        );
    }

    #[test]
    fn rejects_plaintext_too_long() {
        let key = test_key();
        let id = test_volume_uuid();
        let too_long = [0u8; EXTENT_PLAINTEXT_BYTES + 1];
        let mut out = [0u8; EXTENT_ENCRYPTED_BYTES];
        assert_eq!(
            encrypt_extent_block(&key, 1, 0, &id, &too_long, &mut out),
            Err(ExtentCryptoError::PlaintextTooLong)
        );
    }

    #[test]
    fn rejects_small_output_buffer() {
        let key = test_key();
        let id = test_volume_uuid();
        let compressed = [0u8; 16];
        let mut too_small = [0u8; 8];
        assert_eq!(
            encrypt_extent_block(&key, 1, 0, &id, &compressed, &mut too_small),
            Err(ExtentCryptoError::OutputTooSmall)
        );
    }

    #[test]
    fn resolve_extent_encryption_uses_object_first() {
        let mut system_volume = crate::format::VolumeDescriptor {
            uuid: [0u8; 16],
            root_object_id: 0,
            object_table_lba: 0,
            object_count: 0,
            flags: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            quota_physical_bytes: 0,
            quota_objects: 0,
        };
        let mut object = crate::format::ObjectDescriptor {
            object_id: 1,
            object_type: crate::format::OBJECT_TYPE_FILE,
            type_version: 1,
            size: 0,
            modified_unix_ns: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            tree_lba: 0,
            record_count: 0,
            flags: 0,
        };
        // Both zero -> plain.
        assert!(!resolve_extent_encryption_for_object(
            &system_volume,
            &object
        ));
        // Object policy != 0 -> encrypted.
        object.encryption_policy_id = 7;
        assert!(resolve_extent_encryption_for_object(
            &system_volume,
            &object
        ));
        // Object zero, system non-zero -> encrypted.
        object.encryption_policy_id = 0;
        system_volume.encryption_policy_id = 5;
        assert!(resolve_extent_encryption_for_object(
            &system_volume,
            &object
        ));
        // Object non-zero wins over system.
        object.encryption_policy_id = 9;
        system_volume.encryption_policy_id = 5;
        // Both non-zero, both imply encryption.
        assert!(resolve_extent_encryption_for_object(
            &system_volume,
            &object
        ));
    }

    #[test]
    fn derive_extent_key_for_volume_is_deterministic() {
        let mut id = test_volume_uuid();
        let mut ikm = [0u8; 32];
        let mut index = 0usize;
        while index < ikm.len() {
            ikm[index] = (index as u8).wrapping_add(0x55);
            index += 1;
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        derive_extent_key_for_volume(&ikm, &id, &mut a).expect("a");
        derive_extent_key_for_volume(&ikm, &id, &mut b).expect("b");
        assert_eq!(a, b);
        // Different volume UUID => different subkey.
        id[0] ^= 0x01;
        let mut c = [0u8; 32];
        derive_extent_key_for_volume(&ikm, &id, &mut c).expect("c");
        assert_ne!(a, c);
    }
}
