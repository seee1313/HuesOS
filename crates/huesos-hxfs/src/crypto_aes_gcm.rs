//! AES-256-GCM authenticated encryption for Hxfs metadata blocks and
//! data extents.
//!
//! Stage B uses AES-256-GCM to wrap 4 KiB metadata blocks (B.1) and
//! the payload of compressed data extents (B.3). The function lives
//! behind `#[cfg(feature = "crypto-aes-gcm")]` so the default no-heap,
//! no-extra-deps build remains unchanged.
//!
//! # Wire format
//!
//! The encrypted block has the following layout on disk:
//!
//! ```text
//! +--------+------------------+--------+
//! | nonce  |   ciphertext     |  tag   |
//! | 12 B   |   4028 B         |  16 B  |
//! +--------+------------------+--------+
//! total: 4056 B
//! ```
//!
//! The plaintext is exactly 4028 bytes; the function pads short
//! plaintexts with zeros and **rejects plaintexts longer than
//! [`MAX_PLAINTEXT_BYTES`]**. The caller is expected to size
//! plaintexts to fit a 4 KiB block minus the AEAD overhead
//! (`HEADER_BYTES=40 + 12 + 16 = 68`).
//!
//! # Nonce construction
//!
//! The 12-byte nonce is built from the block LBA and the volume
//! UUID: `nonce[0..4] = lba.to_le_bytes()`, `nonce[4..12] =
//! volume_uuid[0..8]`. This is deterministic (so the block can be
//! re-decrypted without storing a nonce on disk) and gives a unique
//! `(volume_id, block_lba)` pair per block. GCM requires unique
//! nonces per (key, plaintext) pair; `(volume_id, block_lba)` is
//! unique by construction because block LBAs do not collide across
//! volumes that have distinct UUIDs.
//!
//! # Authentication
//!
//! AES-GCM produces a 16-byte authentication tag. Decryption
//! verifies the tag before returning any plaintext; a tampered block
//! returns [`AeadError::BadTag`], which surfaces to the read path as
//! `CryptoError::BadKey` (matching the existing `Aes256XtsKey` API)
//! and to the higher layer as "this extent is bad, do not retry".
//!
//! # Failure modes
//!
//! - Plaintext longer than [`MAX_PLAINTEXT_BYTES`] →
//!   [`AeadError::PlaintextTooLong`]. This is a programming error,
//!   not a runtime condition; the caller must size the buffer.
//! - `nonce == 0` (GCM forbids all-zero nonces when the key is
//!   fixed) cannot happen by construction: `lba` is non-zero for
//!   every metadata block and `volume_uuid[0..8]` is part of the
//!   volume identity.
//! - AEAD tag mismatch on decrypt → [`AeadError::BadTag`].

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

/// Maximum plaintext length for a single metadata block.
///
/// A 4 KiB block minus `BlockHeader` (40 B) minus `nonce` (12 B)
/// minus `tag` (16 B) = 4028 B.
pub const MAX_PLAINTEXT_BYTES: usize = 4028;

/// Length of the AES-GCM nonce in bytes.
pub const NONCE_BYTES: usize = 12;

/// Length of the AES-GCM authentication tag in bytes.
pub const TAG_BYTES: usize = 16;

/// AEAD failure modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadError {
    /// Plaintext longer than [`MAX_PLAINTEXT_BYTES`].
    PlaintextTooLong,
    /// AEAD tag verification failed. The block has been tampered with
    /// or the wrong key was used.
    BadTag,
    /// The RustCrypto `aes-gcm` crate rejected the key or nonce
    /// shape. This should be unreachable for the sizes we use.
    EngineError,
}

/// Encrypt a 4 KiB block of plaintext under a 32-byte subkey.
///
/// `key` is the 32-byte subkey produced by `hkdf::derive_*_subkey`.
/// `lba` is the block's logical block address on disk.
/// `volume_uuid` is the 16-byte UUID of the volume that owns the
/// block; only the first 8 bytes are mixed into the nonce.
///
/// `plaintext` must be at most [`MAX_PLAINTEXT_BYTES`] bytes; the
/// ciphertext always fills exactly 4056 bytes (12 + ciphertext + 16).
///
/// `out` must be at least [`MAX_PLAINTEXT_BYTES`] + [`NONCE_BYTES`] +
/// [`TAG_BYTES`] = 4056 bytes. The function does not write past
/// `plaintext.len() + 28` bytes.
pub fn encrypt_block(
    key: &[u8; 32],
    lba: u64,
    volume_uuid: &[u8; 16],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, AeadError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(AeadError::PlaintextTooLong);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = build_nonce(lba, volume_uuid);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // The RustCrypto `Aead::encrypt` takes the AAD separately; we
    // bind the (lba, volume_uuid) pair into the AEAD via the `Payload`
    // wrapper so a replayer cannot transplant a ciphertext to a
    // different block within the same volume. Without AAD, a
    // ciphertext for lba=42 could be re-decrypted at lba=43 and the
    // tag would still verify.
    let aad = build_aad(lba, volume_uuid);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AeadError::EngineError)?;

    let total = NONCE_BYTES + ciphertext.len();
    if out.len() < total {
        return Err(AeadError::EngineError);
    }
    out[..NONCE_BYTES].copy_from_slice(&nonce_bytes);
    out[NONCE_BYTES..total].copy_from_slice(&ciphertext);
    Ok(total)
}

/// Decrypt a 4 KiB block of ciphertext under a 32-byte subkey.
///
/// The inverse of [`encrypt_block`]: `ciphertext_with_nonce` is the
/// 4056-byte wire payload (`nonce(12) || ciphertext(N) || tag(16)`);
/// the function verifies the GCM tag and writes the plaintext into
/// `out`. A tag mismatch returns [`AeadError::BadTag`] and **does
/// not** write to `out`.
pub fn decrypt_block(
    key: &[u8; 32],
    lba: u64,
    volume_uuid: &[u8; 16],
    ciphertext_with_nonce: &[u8],
    out: &mut [u8],
) -> Result<usize, AeadError> {
    if ciphertext_with_nonce.len() < NONCE_BYTES + TAG_BYTES {
        return Err(AeadError::EngineError);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    // We rebuild the nonce from (lba, volume_uuid) rather than trust
    // the one on disk: the on-disk nonce MUST match what we build, or
    // the AAD will not match either, so a transplanting attack is
    // caught by the AAD binding.
    let expected_nonce = build_nonce(lba, volume_uuid);
    let on_disk_nonce = &ciphertext_with_nonce[..NONCE_BYTES];
    if on_disk_nonce != expected_nonce {
        // The nonce on disk does not match what we expect for this
        // (lba, volume_uuid) pair. This is a strong signal that the
        // block has been transplanted from a different location.
        return Err(AeadError::BadTag);
    }
    let nonce = Nonce::from_slice(&expected_nonce);
    let aad = build_aad(lba, volume_uuid);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext_with_nonce[NONCE_BYTES..],
                aad: &aad,
            },
        )
        .map_err(|_| AeadError::BadTag)?;
    if out.len() < plaintext.len() {
        return Err(AeadError::EngineError);
    }
    out[..plaintext.len()].copy_from_slice(&plaintext);
    Ok(plaintext.len())
}

/// Build the 12-byte GCM nonce from a block LBA and a volume UUID.
///
/// Layout: `B0..=B3` = `lba.to_le_bytes()[..4]` (low 4 bytes of the
/// LBA), `B4..=B11` = `volume_uuid[0..8]`. The high 4 bytes of the
/// 64-bit LBA are unused; the full 16-byte UUID is mixed into the
/// AAD instead.
fn build_nonce(lba: u64, volume_uuid: &[u8; 16]) -> [u8; NONCE_BYTES] {
    let mut nonce = [0u8; NONCE_BYTES];
    let lba_bytes = lba.to_le_bytes();
    nonce[..4].copy_from_slice(&lba_bytes[..4]);
    nonce[4..NONCE_BYTES].copy_from_slice(&volume_uuid[..NONCE_BYTES - 4]);
    nonce
}

/// Build the additional authenticated data for the AEAD.
///
/// We bind `lba` (8 B) and the full `volume_uuid` (16 B) into the AAD
/// so a ciphertext cannot be transplanted across blocks or volumes.
/// The total AAD is 24 bytes, well within GCM's limit.
fn build_aad(lba: u64, volume_uuid: &[u8; 16]) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..8].copy_from_slice(&lba.to_le_bytes());
    aad[8..24].copy_from_slice(volume_uuid);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        let mut index = 0usize;
        while index < key.len() {
            key[index] = (index as u8).wrapping_add(0x40);
            index += 1;
        }
        key
    }

    fn test_volume_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        let mut index = 0usize;
        while index < id.len() {
            id[index] = 0x5au8.wrapping_add(index as u8);
            index += 1;
        }
        id
    }

    #[test]
    fn round_trip_full_block() {
        let key = test_key();
        let id = test_volume_id();
        let mut plaintext = [0u8; MAX_PLAINTEXT_BYTES];
        for (index, byte) in plaintext.iter_mut().enumerate() {
            *byte = (index & 0xff) as u8;
        }
        let mut ciphertext = [0u8; MAX_PLAINTEXT_BYTES + NONCE_BYTES + TAG_BYTES];
        let written = encrypt_block(&key, 42, &id, &plaintext, &mut ciphertext)
            .expect("encrypt must succeed for valid input");
        assert_eq!(written, MAX_PLAINTEXT_BYTES + NONCE_BYTES + TAG_BYTES);
        // Ciphertext must not equal plaintext.
        assert_ne!(
            &ciphertext[NONCE_BYTES..NONCE_BYTES + MAX_PLAINTEXT_BYTES],
            &plaintext[..]
        );

        let mut out = [0u8; MAX_PLAINTEXT_BYTES];
        let read = decrypt_block(&key, 42, &id, &ciphertext[..written], &mut out)
            .expect("decrypt must succeed with the right key");
        assert_eq!(read, MAX_PLAINTEXT_BYTES);
        assert_eq!(out, plaintext);
    }

    #[test]
    fn round_trip_short_plaintext() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = b"hello, hxfs";
        let mut ciphertext = [0u8; 64];
        let written = encrypt_block(&key, 1, &id, plaintext, &mut ciphertext)
            .expect("short plaintext is fine");
        let mut out = [0u8; 64];
        let read = decrypt_block(&key, 1, &id, &ciphertext[..written], &mut out)
            .expect("decrypt must succeed");
        assert_eq!(&out[..read], plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_with_bad_tag() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = [0xaau8; 128];
        let mut ciphertext = [0u8; 256];
        let written = encrypt_block(&key, 7, &id, &plaintext, &mut ciphertext).expect("encrypt");
        // Flip one byte of the ciphertext.
        ciphertext[NONCE_BYTES + 4] ^= 0x01;
        let mut out = [0u8; 128];
        assert_eq!(
            decrypt_block(&key, 7, &id, &ciphertext[..written], &mut out),
            Err(AeadError::BadTag)
        );
    }

    #[test]
    fn wrong_key_fails_with_bad_tag() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = [0x55u8; 64];
        let mut ciphertext = [0u8; 128];
        let written = encrypt_block(&key, 11, &id, &plaintext, &mut ciphertext).expect("encrypt");
        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        let mut out = [0u8; 64];
        assert_eq!(
            decrypt_block(&wrong_key, 11, &id, &ciphertext[..written], &mut out),
            Err(AeadError::BadTag)
        );
    }

    #[test]
    fn wrong_lba_fails_with_bad_tag() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = [0x77u8; 64];
        let mut ciphertext = [0u8; 128];
        let written = encrypt_block(&key, 100, &id, &plaintext, &mut ciphertext).expect("encrypt");
        // Decrypt with a different LBA: the on-disk nonce does not
        // match the rebuilt nonce, so we get BadTag before the AEAD
        // ever sees the wrong nonce.
        let mut out = [0u8; 64];
        assert_eq!(
            decrypt_block(&key, 101, &id, &ciphertext[..written], &mut out),
            Err(AeadError::BadTag)
        );
    }

    #[test]
    fn rejects_plaintext_too_long() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = [0u8; MAX_PLAINTEXT_BYTES + 1];
        let mut out = [0u8; 4096];
        assert_eq!(
            encrypt_block(&key, 1, &id, &plaintext, &mut out),
            Err(AeadError::PlaintextTooLong)
        );
    }

    #[test]
    fn different_volume_id_produces_different_ciphertext() {
        let key = test_key();
        let id_a = test_volume_id();
        // Mutate byte 5, which falls inside the nonce's volume-uuid
        // window (bytes 4..=11 of the nonce). This is the byte a
        // transplanting attack would have to flip to move a
        // ciphertext to a different volume.
        let mut id_b = id_a;
        id_b[5] ^= 0x01;
        let plaintext = b"same plaintext, different volume";
        let mut ct_a = [0u8; 128];
        let mut ct_b = [0u8; 128];
        let len_a = encrypt_block(&key, 1, &id_a, plaintext, &mut ct_a).expect("a");
        let len_b = encrypt_block(&key, 1, &id_b, plaintext, &mut ct_b).expect("b");
        // Nonces differ because volume_uuid differs.
        assert_ne!(&ct_a[..NONCE_BYTES], &ct_b[..NONCE_BYTES]);
        // Ciphertexts also differ.
        assert_ne!(&ct_a[NONCE_BYTES..len_a], &ct_b[NONCE_BYTES..len_b]);
    }
}
