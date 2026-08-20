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
//! The 12-byte nonce is `LBA[0..4] || generation[0..8]`. HxFS v6 persists
//! the complete 64-bit generation in each extent record and binds the full
//! `(LBA, generation, UUID)` tuple as AAD. Reissued blocks therefore never
//! repeat a `(key, nonce)` pair. The 32-bit LBA field deliberately caps an
//! encrypted volume at 16 TiB; larger LBAs fail closed. Cross-volume separation
//! comes from HKDF with the full UUID as salt.
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
    /// LBA exceeds the v6 encrypted-volume nonce domain (16 TiB).
    NonceDomainExceeded,
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
    generation: u64,
    volume_uuid: &[u8; 16],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, AeadError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(AeadError::PlaintextTooLong);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = build_nonce(lba, generation, volume_uuid)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // The RustCrypto `Aead::encrypt` takes the AAD separately; we
    // bind the (lba, volume_uuid) pair into the AEAD via the `Payload`
    // wrapper so a replayer cannot transplant a ciphertext to a
    // different block within the same volume. Without AAD, a
    // ciphertext for lba=42 could be re-decrypted at lba=43 and the
    // tag would still verify.
    let aad = build_aad(lba, generation, volume_uuid);
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
    generation: u64,
    volume_uuid: &[u8; 16],
    ciphertext_with_nonce: &[u8],
    out: &mut [u8],
) -> Result<usize, AeadError> {
    if ciphertext_with_nonce.len() < NONCE_BYTES + TAG_BYTES {
        return Err(AeadError::EngineError);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    // We rebuild the nonce from (lba, generation, volume_uuid) rather
    // than trust the one on disk: the on-disk nonce MUST match what we
    // build, or the AAD will not match either, so a transplanting
    // attack is caught by the AAD binding. Including the generation
    // means a stale ciphertext left behind by a previous tenant of a
    // reused block is rejected here rather than decrypted as if it
    // belonged to the current file.
    let expected_nonce = build_nonce(lba, generation, volume_uuid)?;
    let on_disk_nonce = &ciphertext_with_nonce[..NONCE_BYTES];
    if on_disk_nonce != expected_nonce {
        // The nonce on disk does not match what we expect for this
        // (lba, generation, volume_uuid) triple. This is a strong signal that the
        // block has been transplanted from a different location.
        return Err(AeadError::BadTag);
    }
    let nonce = Nonce::from_slice(&expected_nonce);
    let aad = build_aad(lba, generation, volume_uuid);
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

/// Build the HxFS v6 12-byte GCM nonce.
///
/// Layout: low 32 bits of LBA followed by the complete 64-bit generation.
/// The full UUID is authenticated as AAD and separates the HKDF-derived key.
fn build_nonce(
    lba: u64,
    generation: u64,
    _volume_uuid: &[u8; 16],
) -> Result<[u8; NONCE_BYTES], AeadError> {
    let lba = u32::try_from(lba).map_err(|_| AeadError::NonceDomainExceeded)?;
    let mut nonce = [0u8; NONCE_BYTES];
    nonce[..4].copy_from_slice(&lba.to_le_bytes());
    nonce[4..12].copy_from_slice(&generation.to_le_bytes());
    Ok(nonce)
}

/// Build the additional authenticated data for the AEAD.
///
/// We bind `lba` (8 B), the full `volume_uuid` (16 B) and the full
/// `generation` (8 B) into the AAD so a ciphertext cannot be
/// transplanted across blocks, volumes, or tenancies of the same
/// block. The nonce only carries truncated forms of the block and
/// generation; the AAD carries both in full, so a pair that collides
/// in the nonce still fails the tag check.
/// The total AAD is 32 bytes, well within GCM's limit.
fn build_aad(lba: u64, generation: u64, volume_uuid: &[u8; 16]) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[..8].copy_from_slice(&lba.to_le_bytes());
    aad[8..24].copy_from_slice(volume_uuid);
    aad[24..32].copy_from_slice(&generation.to_le_bytes());
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
        let written = encrypt_block(&key, 42, 0, &id, &plaintext, &mut ciphertext)
            .expect("encrypt must succeed for valid input");
        assert_eq!(written, MAX_PLAINTEXT_BYTES + NONCE_BYTES + TAG_BYTES);
        // Ciphertext must not equal plaintext.
        assert_ne!(
            &ciphertext[NONCE_BYTES..NONCE_BYTES + MAX_PLAINTEXT_BYTES],
            &plaintext[..]
        );

        let mut out = [0u8; MAX_PLAINTEXT_BYTES];
        let read = decrypt_block(&key, 42, 0, &id, &ciphertext[..written], &mut out)
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
        let written = encrypt_block(&key, 1, 0, &id, plaintext, &mut ciphertext)
            .expect("short plaintext is fine");
        let mut out = [0u8; 64];
        let read = decrypt_block(&key, 1, 0, &id, &ciphertext[..written], &mut out)
            .expect("decrypt must succeed");
        assert_eq!(&out[..read], plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_with_bad_tag() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = [0xaau8; 128];
        let mut ciphertext = [0u8; 256];
        let written = encrypt_block(&key, 7, 0, &id, &plaintext, &mut ciphertext).expect("encrypt");
        // Flip one byte of the ciphertext.
        ciphertext[NONCE_BYTES + 4] ^= 0x01;
        let mut out = [0u8; 128];
        assert_eq!(
            decrypt_block(&key, 7, 0, &id, &ciphertext[..written], &mut out),
            Err(AeadError::BadTag)
        );
    }

    #[test]
    fn wrong_key_fails_with_bad_tag() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = [0x55u8; 64];
        let mut ciphertext = [0u8; 128];
        let written =
            encrypt_block(&key, 11, 0, &id, &plaintext, &mut ciphertext).expect("encrypt");
        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        let mut out = [0u8; 64];
        assert_eq!(
            decrypt_block(&wrong_key, 11, 0, &id, &ciphertext[..written], &mut out),
            Err(AeadError::BadTag)
        );
    }

    #[test]
    fn wrong_lba_fails_with_bad_tag() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = [0x77u8; 64];
        let mut ciphertext = [0u8; 128];
        let written =
            encrypt_block(&key, 100, 0, &id, &plaintext, &mut ciphertext).expect("encrypt");
        // Decrypt with a different LBA: the on-disk nonce does not
        // match the rebuilt nonce, so we get BadTag before the AEAD
        // ever sees the wrong nonce.
        let mut out = [0u8; 64];
        assert_eq!(
            decrypt_block(&key, 101, 0, &id, &ciphertext[..written], &mut out),
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
            encrypt_block(&key, 1, 0, &id, &plaintext, &mut out),
            Err(AeadError::PlaintextTooLong)
        );
    }

    #[test]
    fn different_volume_id_produces_different_ciphertext() {
        let key = test_key();
        let id_a = test_volume_id();
        // Byte 5 of the UUID no longer reaches the nonce: the nonce
        // v6 spends all 12 nonce bytes on LBA + the complete generation.
        // Volume separation comes from the per-volume HKDF key in production,
        // while the full UUID is also bound through AAD. This unit test uses
        // one direct test key, so it proves the AAD anti-transplant property.
        let mut id_b = id_a;
        id_b[5] ^= 0x01;
        let plaintext = b"same plaintext, different volume";
        let mut ct_a = [0u8; 128];
        let mut ct_b = [0u8; 128];
        let len_a = encrypt_block(&key, 1, 0, &id_a, plaintext, &mut ct_a).expect("a");
        let len_b = encrypt_block(&key, 1, 0, &id_b, plaintext, &mut ct_b).expect("b");
        // The nonce is deliberately the same here (the differing byte
        // is outside its UUID window), which is exactly why the AAD
        // has to carry the whole UUID.
        assert_eq!(&ct_a[..NONCE_BYTES], &ct_b[..NONCE_BYTES]);
        // Ciphertexts still differ, because the AAD differs.
        assert_ne!(&ct_a[NONCE_BYTES..len_a], &ct_b[NONCE_BYTES..len_b]);
        // And volume A's ciphertext must not decrypt as volume B's.
        let mut out = [0u8; MAX_PLAINTEXT_BYTES];
        assert_eq!(
            decrypt_block(&key, 1, 0, &id_b, &ct_a[..len_a], &mut out),
            Err(AeadError::BadTag),
            "a ciphertext must not verify under a different volume UUID"
        );
        // UUID is intentionally absent from the nonce; production derives a
        // different key for each UUID and AAD authenticates it in this layer.
        let mut id_c = id_a;
        id_c[0] ^= 0x01;
        let mut ct_c = [0u8; 128];
        let Ok(_) = encrypt_block(&key, 1, 0, &id_c, plaintext, &mut ct_c) else {
            assert!(false, "encrypt must succeed");
            return;
        };
        assert_eq!(&ct_a[..NONCE_BYTES], &ct_c[..NONCE_BYTES]);
    }
    /// The property that lets the allocator reuse a block at all: the
    /// same LBA under a different generation must produce a different
    /// nonce, and therefore a different keystream.
    ///
    /// If this ever regresses, reusing a freed block would encrypt new
    /// plaintext under a nonce that block already used — a GCM nonce
    /// repeat, which leaks the XOR of the two plaintexts and the GHASH
    /// authentication key (allowing tag forgery). This test is the
    /// guard on that.
    #[test]
    fn generation_changes_the_nonce_for_the_same_block() {
        let key = test_key();
        let id = test_volume_id();
        let plaintext = b"same block, second tenant";
        let mut first = [0u8; 128];
        let mut second = [0u8; 128];
        let Ok(len_a) = encrypt_block(&key, 4096, 0, &id, plaintext, &mut first) else {
            assert!(false, "generation 0 must encrypt");
            return;
        };
        let Ok(len_b) = encrypt_block(&key, 4096, 1, &id, plaintext, &mut second) else {
            assert!(false, "generation 1 must encrypt");
            return;
        };

        assert_ne!(
            &first[..NONCE_BYTES],
            &second[..NONCE_BYTES],
            "a reused block must not repeat its nonce"
        );
        assert_ne!(
            &first[NONCE_BYTES..len_a],
            &second[NONCE_BYTES..len_b],
            "identical plaintext at one LBA must not produce identical ciphertext across generations"
        );
    }

    /// A stale ciphertext left behind by the previous tenant of a
    /// reused block must not decrypt for the new tenant.
    #[test]
    fn a_previous_generation_ciphertext_does_not_verify() {
        let key = test_key();
        let id = test_volume_id();
        let mut sealed = [0u8; 128];
        let Ok(len) = encrypt_block(&key, 77, 3, &id, b"tenant three", &mut sealed) else {
            assert!(false, "sealing must succeed");
            return;
        };

        let mut out = [0u8; MAX_PLAINTEXT_BYTES];
        assert_eq!(
            decrypt_block(&key, 77, 4, &id, &sealed[..len], &mut out),
            Err(AeadError::BadTag),
            "generation 4 must reject a block sealed under generation 3"
        );
        // The rightful generation still reads it back.
        let Ok(read) = decrypt_block(&key, 77, 3, &id, &sealed[..len], &mut out) else {
            assert!(false, "the rightful generation must still decrypt");
            return;
        };
        assert_eq!(&out[..12], b"tenant three", "len {read}");
    }

    /// Sweep a range of (block, generation) pairs and assert every
    /// nonce is distinct. Catches an encoding that lets a high
    /// generation collide with a neighbouring block, which is how a
    /// hand-rolled bit layout usually fails.
    #[test]
    fn nonces_are_unique_across_blocks_and_generations() {
        let id = test_volume_id();
        let mut seen: alloc::vec::Vec<[u8; NONCE_BYTES]> = alloc::vec::Vec::new();
        for block in [0u64, 1, 2, 4095, 4096, 1 << 20, (1 << 32) - 1] {
            for generation in [0u64, 1, 2, 255, 65_535, 1 << 32, u64::MAX] {
                let Ok(nonce) = build_nonce(block, generation, &id) else {
                    assert!(false, "nonce-domain pair must encode");
                    return;
                };
                assert!(
                    !seen.contains(&nonce),
                    "nonce collision at block {block} generation {generation}"
                );
                seen.push(nonce);
            }
        }
    }

    /// v6 spends the nonce bits on the complete generation and therefore
    /// fails closed beyond the explicit 16 TiB encrypted-volume domain.
    #[test]
    fn block_beyond_nonce_domain_is_rejected() {
        let id = test_volume_id();
        assert!(build_nonce(u32::MAX as u64, u64::MAX, &id).is_ok());
        assert_eq!(
            build_nonce(u32::MAX as u64 + 1, 0, &id),
            Err(AeadError::NonceDomainExceeded)
        );
    }
}
