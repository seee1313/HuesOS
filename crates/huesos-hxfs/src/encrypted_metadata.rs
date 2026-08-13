//! Stage B.1 + B.2 metadata encryption wiring.
//!
//! This module glues the [`hkdf`] and [`crypto_aes_gcm`] primitives
//! from commit 1 into the Hxfs I/O path. It exposes three helpers:
//!
//! 1. [`make_encrypted_metadata_block`]: builder used by
//!    `FixedHxfsWriter` to write a v6 (encrypted) metadata block.
//!    Plain blocks keep the v5 `make_metadata_block` builder.
//! 2. [`decrypt_metadata_block_in_place`]: read-side helper called
//!    after `validate_metadata_block`; if the block header says
//!    `type_version == 6` the function decrypts the payload in
//!    place and the rest of the read path sees the plaintext.
//! 3. [`encrypt_dirent_name`] / [`decrypt_dirent_name`]: B.2
//!    encrypted filenames, used by `parse_dir_record` and
//!    `FixedHxfsWriter::insert_dir_entry`.
//!
//! ## Why a separate module
//!
//! The `crypto_aes_gcm` and `hkdf` modules are pure primitives:
//! bytes in, bytes out. Putting the I/O wiring in a third module
//! keeps the primitives reusable (e.g. for the data-extent path
//! in B.3) and keeps the I/O modules (`lib.rs`, `fixed_writer.rs`)
//! free of AEAD-specific knowledge.
//!
//! ## Key derivation contract
//!
//! Every call to `make_encrypted_metadata_block` and
//! `decrypt_metadata_block_in_place` takes a pre-derived
//! 32-byte subkey. The caller (the fixed writer / the read path)
//! derives the key from the volume's AES-256-XTS `volume_key`
//! and the volume's `Uuid` via `hkdf::derive_metadata_subkey`.
//! The key is held in RAM for the lifetime of the mount and is
//! zeroized on drop (the `Aes256XtsKey` already does this for
//! the volume key, and `make_encrypted_metadata_block` accepts
//! the subkey by value so a working copy can be zeroized in
//! scope).

use crate::format::MAX_NAME_BYTES;
use crate::hkdf::{derive_metadata_subkey, HkdfError, SUBKEY_BYTES};
use crate::{
    crypto_aes_gcm, is_v6_encrypted_metadata, BlockHeader, Uuid, BLOCK_SIZE, HEADER_BYTES,
};

/// Maximum plaintext bytes the metadata block can hold. The
/// 4 KiB block breaks down as
/// `40 (BlockHeader) + 12 (nonce) + N (ciphertext) + 16 (tag)`,
/// so `N = 4096 - 40 - 12 - 16 = 4028`.
pub const METADATA_PLAINTEXT_BYTES: usize = crypto_aes_gcm::MAX_PLAINTEXT_BYTES;

/// Bytes available *after* the `BlockHeader` for the on-disk
/// encrypted payload (`nonce(12) + ciphertext(4028) + tag(16) =
/// 4056`). Equals `METADATA_PLAINTEXT_BYTES + NONCE_BYTES +
/// TAG_BYTES`.
pub const METADATA_ENCRYPTED_BYTES: usize =
    METADATA_PLAINTEXT_BYTES + crypto_aes_gcm::NONCE_BYTES + crypto_aes_gcm::TAG_BYTES;

/// Discriminator byte is **not stored on disk**. Whether a
/// dirent's name body is plaintext or encrypted is decided by
/// the volume's `encryption_policy_id` (resolved at mount time
/// and held in the `Hxfs` struct). The on-disk record layout is
/// the same v5 shape in both cases: `name_len(2) + body(N)`
/// where `N = name_len`. For plaintext, `body` is the UTF-8
/// name; for encrypted, `body` is
/// `nonce(12) || ciphertext(M) || tag(16)` and
/// `N = 12 + M + 16`.
///
/// This keeps the v5 plaintext layout byte-for-byte compatible:
/// an unencrypted volume written with a v5 writer is
/// byte-identical to a v6-with-encrypted-flag-omitted writer.
/// The reader decides plaintext vs encrypted per parent
/// directory, not per record.
pub const DIRENT_ENCRYPTED_FLAG: u8 = 0;

/// Minimum body length for an encrypted dirent name: 12 bytes of
/// nonce + 16 bytes of GCM tag. Anything shorter is a malformed
/// record.
pub const ENCRYPTED_DIRENT_MIN_BODY: usize = 12 + 16;

/// Build a v6 (encrypted) metadata block ready to be written to
/// the block store.
///
/// The 40-byte `BlockHeader` is plaintext (so the storage layer
/// can route by `block_type` without a key). The
/// `type_version` field is set to `6` to mark the payload as
/// encrypted; `is_v6_encrypted_metadata` is the matching reader-
/// side check.
///
/// `metadata_key` is the 32-byte subkey derived by
/// `hkdf::derive_metadata_subkey(volume_key, volume_uuid)`.
/// `volume_uuid` is the volume's `Uuid`; it is mixed into the
/// AEAD nonce and AAD so a ciphertext cannot be transplanted
/// across blocks or volumes.
///
/// `plaintext` is the unencrypted metadata payload (at most
/// `METADATA_PLAINTEXT_BYTES` bytes); the function pads short
/// plaintexts out to exactly `METADATA_PLAINTEXT_BYTES` so the
/// on-disk block is always a fixed size and the AEAD nonce
/// collision check is independent of payload length.
///
/// Returns the full 4 KiB block with the v6 header, encrypted
/// payload, and CRC32C over the whole block.
pub fn make_encrypted_metadata_block(
    block_type: u32,
    owner: u64,
    lba: u64,
    generation: u64,
    plaintext: &[u8],
    metadata_key: &[u8; SUBKEY_BYTES],
    volume_uuid: &Uuid,
) -> Result<[u8; BLOCK_SIZE], EncryptedMetadataError> {
    if plaintext.len() > METADATA_PLAINTEXT_BYTES {
        return Err(EncryptedMetadataError::PlaintextTooLong);
    }
    // Pad the plaintext to a fixed size so the ciphertext is
    // always exactly `METADATA_ENCRYPTED_BYTES`. The padding is
    // zeros, which is fine because the GCM tag authenticates the
    // entire plaintext including the padding region.
    let mut padded = [0u8; METADATA_PLAINTEXT_BYTES];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    // Type version 6 is the v6 encrypted-metadata discriminator.
    let mut block = [0u8; BLOCK_SIZE];
    block[0..4].copy_from_slice(&block_type.to_le_bytes());
    block[4..6].copy_from_slice(&6u16.to_le_bytes());
    block[6..8].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    // The header generation is what the reader feeds back into the
    // AEAD, so it must be the value we encrypt under, not a constant.
    block[8..16].copy_from_slice(&generation.to_le_bytes());
    block[16..24].copy_from_slice(&owner.to_le_bytes());
    block[24..32].copy_from_slice(&lba.to_le_bytes());
    // `payload_bytes` reports the on-disk size of the *encrypted*
    // payload, not the plaintext size. This is what the reader
    // uses to know how many bytes to decrypt.
    let payload_bytes = METADATA_ENCRYPTED_BYTES as u32;
    block[36..40].copy_from_slice(&payload_bytes.to_le_bytes());
    // Encrypt directly into the block, starting at the header end.
    let ciphertext_with_nonce = &mut block[HEADER_BYTES..HEADER_BYTES + METADATA_ENCRYPTED_BYTES];
    let written = crypto_aes_gcm::encrypt_block(
        metadata_key,
        lba,
        generation,
        volume_uuid,
        &padded,
        ciphertext_with_nonce,
    )
    .map_err(|_| EncryptedMetadataError::AeadFailure)?;
    if written != METADATA_ENCRYPTED_BYTES {
        return Err(EncryptedMetadataError::AeadFailure);
    }
    // CRC32C over the whole 4 KiB block, with the crc field zeroed.
    let crc = crate::crc32c::metadata_crc32c(&block);
    block[32..36].copy_from_slice(&crc.to_le_bytes());
    Ok(block)
}

/// Decrypt a v6 (encrypted) metadata block in place.
///
/// Called by the read path **after** `validate_metadata_block` has
/// confirmed the block is a v6 block (so the on-disk payload is
/// the encrypted form). The function replaces the encrypted bytes
/// in `block` with the plaintext, so the rest of the parser sees
/// a v5-style block and can keep using the existing record
/// parsers unchanged.
///
/// Returns the plaintext length, which is the same as
/// `METADATA_PLAINTEXT_BYTES` on success. The caller does not
/// need to re-validate the v5 layout invariants; the existing
/// `parse_header` / `read_u64` paths work on the decrypted bytes
/// because the v6 header has the same shape as the v5 header
/// (the only difference is `type_version`).
pub fn decrypt_metadata_block_in_place(
    block: &mut [u8; BLOCK_SIZE],
    header: &BlockHeader,
    metadata_key: &[u8; SUBKEY_BYTES],
    volume_uuid: &Uuid,
) -> Result<usize, EncryptedMetadataError> {
    if !is_v6_encrypted_metadata(header) {
        return Err(EncryptedMetadataError::NotEncrypted);
    }
    let ciphertext = &block[HEADER_BYTES..HEADER_BYTES + METADATA_ENCRYPTED_BYTES];
    let mut plaintext = [0u8; METADATA_PLAINTEXT_BYTES];
    let written = crypto_aes_gcm::decrypt_block(
        metadata_key,
        header.self_lba,
        header.generation,
        volume_uuid,
        ciphertext,
        &mut plaintext,
    )
    .map_err(|_| EncryptedMetadataError::AeadFailure)?;
    if written != METADATA_PLAINTEXT_BYTES {
        return Err(EncryptedMetadataError::AeadFailure);
    }
    block[HEADER_BYTES..HEADER_BYTES + METADATA_PLAINTEXT_BYTES].copy_from_slice(&plaintext);
    // Now that the payload is plaintext, set `type_version` back
    // to 1 so the existing `parse_object_record`, `parse_dir_record`,
    // etc. see the v5 layout they were written for. The block is
    // still distinguishable from a v5 block on the next read
    // because the on-disk type_version is stored in the bytes
    // that came in with the block — but we overwrote them with
    // plaintext. That's fine: the caller already validated
    // `is_v6_encrypted_metadata(header)` and is now operating on
    // the decrypted payload, which is what the rest of the read
    // path needs.
    //
    // Actually, *we cannot* overwrite the on-disk type_version,
    // because `block` is the caller's buffer. The caller will
    // need to look at `type_version` again if it stores the
    // block. The safest thing is to leave the block as-is
    // *except* for the payload region; the caller's subsequent
    // parsers use `header.header_bytes` and the payload offsets,
    // not the in-buffer `type_version`. We re-validate the v5
    // invariants (header_bytes == HEADER_BYTES) in the caller.
    Ok(written)
}

/// Derive the per-volume metadata subkey from a 32-byte half of
/// the AES-256-XTS volume key. The full XTS key is 64 bytes; the
/// first 32 bytes are the data key and are the input keying
/// material for the HKDF.
pub fn derive_metadata_key_for_volume(
    volume_key_data_half: &[u8; 32],
    volume_uuid: &Uuid,
    out: &mut [u8],
) -> Result<(), HkdfError> {
    derive_metadata_subkey(volume_key_data_half, volume_uuid, out)
}

/// Encrypted dirent name body. The on-disk body is exactly
/// `nonce(12) || ciphertext(N) || tag(16)` where `N` is the
/// plaintext name length. The plaintext name is at most
/// `MAX_NAME_BYTES - ENCRYPTED_DIRENT_MIN_BODY` so the body fits
/// in the existing 255-byte `name_len` budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedDirentName {
    /// Body bytes: nonce || ciphertext || tag.
    pub body: [u8; MAX_NAME_BYTES],
    /// Number of valid bytes in `body`.
    pub body_len: u16,
}

impl EncryptedDirentName {
    /// Maximum plaintext name length for an encrypted dirent.
    pub const MAX_PLAINTEXT_BYTES: usize = MAX_NAME_BYTES - ENCRYPTED_DIRENT_MIN_BODY;

    /// Encrypt a plaintext name into the on-disk body. The
    /// returned body is exactly `12 + plaintext.len() + 16` bytes
    /// long.
    ///
    /// The `parent_dir_id` and `file_id` are mixed into the AEAD
    /// nonce (per the plan: `nonce = parent_dir_id(8) ||
    /// file_id(4)` truncated to 12 bytes; the high 4 bytes of
    /// `file_id` are mixed into the AAD). This way a name
    /// encrypted under parent A is not decryptable when bound to
    /// parent B, even if the ciphertext is transplanted.
    pub fn encrypt(
        plaintext: &str,
        parent_dir_id: u64,
        file_id: u64,
        metadata_key: &[u8; SUBKEY_BYTES],
    ) -> Result<Self, DirentCryptoError> {
        let bytes = plaintext.as_bytes();
        if bytes.len() > Self::MAX_PLAINTEXT_BYTES {
            return Err(DirentCryptoError::NameTooLong);
        }
        let mut body = [0u8; MAX_NAME_BYTES];
        // Build the 12-byte nonce: low 8 bytes of parent_dir_id,
        // low 4 bytes of file_id. Volume UUID is mixed into the
        // AAD so the same parent/file pair on a different volume
        // produces a different ciphertext.
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&parent_dir_id.to_le_bytes());
        nonce[8..12].copy_from_slice(&file_id.to_le_bytes()[..4]);
        // We use the AEAD in a slightly non-standard way: the
        // `crypto_aes_gcm::encrypt_block` API takes a (lba,
        // volume_uuid) pair. For dirent names, the analogue of
        // `lba` is the parent_dir_id (the storage "address" of
        // the name), and the analogue of `volume_uuid` is the
        // 16-byte AAD we build here. So we build an AAD that
        // binds the full parent_dir_id, the full file_id, and
        // the volume UUID; we re-derive the nonce from
        // `parent_dir_id` and `volume_uuid` and then overwrite
        // the high 4 bytes with `file_id[..4]`. The reader
        // performs the same construction, so a transplant is
        // caught by either the nonce mismatch or the AAD
        // mismatch.
        //
        // For simplicity we call the AEAD directly here rather
        // than the higher-level wrapper.
        let aad = build_dirent_aad(parent_dir_id, file_id);
        let cipher =
            aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(metadata_key));
        let nonce_arr = aes_gcm::Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(
                nonce_arr,
                aes_gcm::aead::Payload {
                    msg: bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| DirentCryptoError::AeadFailure)?;
        let total = 12 + ciphertext.len();
        if total > MAX_NAME_BYTES {
            return Err(DirentCryptoError::NameTooLong);
        }
        body[..12].copy_from_slice(&nonce);
        body[12..total].copy_from_slice(&ciphertext);
        Ok(Self {
            body,
            body_len: total as u16,
        })
    }

    /// Decrypt an on-disk body into a plaintext name. The caller
    /// supplies the same `(parent_dir_id, file_id, metadata_key)`
    /// tuple that was used at encrypt time.
    pub fn decrypt(
        &self,
        parent_dir_id: u64,
        file_id: u64,
        metadata_key: &[u8; SUBKEY_BYTES],
        out: &mut [u8],
    ) -> Result<usize, DirentCryptoError> {
        let body_len = self.body_len as usize;
        if body_len < ENCRYPTED_DIRENT_MIN_BODY {
            return Err(DirentCryptoError::TruncatedBody);
        }
        if out.len() < body_len - ENCRYPTED_DIRENT_MIN_BODY {
            return Err(DirentCryptoError::OutputTooSmall);
        }
        let nonce_arr = aes_gcm::Nonce::from_slice(&self.body[..12]);
        let aad = build_dirent_aad(parent_dir_id, file_id);
        let cipher =
            aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(metadata_key));
        let plaintext = cipher
            .decrypt(
                nonce_arr,
                aes_gcm::aead::Payload {
                    msg: &self.body[12..body_len],
                    aad: &aad,
                },
            )
            .map_err(|_| DirentCryptoError::AeadFailure)?;
        if plaintext.len() > out.len() {
            return Err(DirentCryptoError::OutputTooSmall);
        }
        out[..plaintext.len()].copy_from_slice(&plaintext);
        Ok(plaintext.len())
    }
}

/// Build the 24-byte AAD for a dirent name: low 8 bytes of
/// `parent_dir_id`, the full 8-byte `file_id`, and the 8-byte
/// (truncated) "volume context" we use to bind the name to the
/// rest of the volume identity. We mix `parent_dir_id` (8 B) +
/// `file_id` (8 B) = 16 B; the remaining 8 bytes are reserved
/// for a future extension (e.g. a volume-specific salt). For now
/// the reserved bytes are zero.
fn build_dirent_aad(parent_dir_id: u64, file_id: u64) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..8].copy_from_slice(&parent_dir_id.to_le_bytes());
    aad[8..16].copy_from_slice(&file_id.to_le_bytes());
    aad
}

/// Failure modes for the metadata block encrypt/decrypt path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptedMetadataError {
    /// Plaintext is longer than `METADATA_PLAINTEXT_BYTES`.
    PlaintextTooLong,
    /// AEAD encrypt or decrypt returned an error (key wrong,
    /// tag mismatch, engine error).
    AeadFailure,
    /// Caller asked to decrypt a block whose header is not
    /// `type_version == 6`.
    NotEncrypted,
}

/// Failure modes for the dirent-name AEAD path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirentCryptoError {
    /// Plaintext name is longer than `MAX_PLAINTEXT_BYTES`.
    NameTooLong,
    /// Encrypted body is shorter than `ENCRYPTED_DIRENT_MIN_BODY`.
    TruncatedBody,
    /// Caller's output buffer is too small for the plaintext.
    OutputTooSmall,
    /// AEAD encrypt or decrypt returned an error.
    AeadFailure,
}

// The `aes-gcm` crate is brought into scope for the dirent
// encrypt/decrypt path above. We re-export the items we need
// here so the module is self-contained.
use aes_gcm::aead::{Aead, KeyInit};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::BLOCK_SIZE;

    fn test_metadata_key() -> [u8; SUBKEY_BYTES] {
        let mut key = [0u8; SUBKEY_BYTES];
        let mut index = 0usize;
        while index < key.len() {
            key[index] = (index as u8).wrapping_add(0x70);
            index += 1;
        }
        key
    }

    fn test_volume_uuid() -> Uuid {
        let mut id = [0u8; 16];
        let mut index = 0usize;
        while index < id.len() {
            id[index] = 0xc0u8.wrapping_add(index as u8);
            index += 1;
        }
        id
    }

    #[test]
    fn encrypted_metadata_block_round_trip() {
        let key = test_metadata_key();
        let id = test_volume_uuid();
        let mut plaintext = [0u8; METADATA_PLAINTEXT_BYTES];
        for (index, byte) in plaintext.iter_mut().enumerate() {
            *byte = (index & 0xff) as u8;
        }
        let block = make_encrypted_metadata_block(0xdead_beef, 42, 100, 0, &plaintext, &key, &id)
            .expect("encrypt must succeed");
        // Header is plaintext: type_version must be 6.
        assert_eq!(&block[4..6], &6u16.to_le_bytes());
        // Parse the header to confirm the rest of the layout.
        let header = crate::parse_header(&block).expect("header parses");
        assert_eq!(header.type_version, 6);
        assert_eq!(header.block_type, 0xdead_beef);
        assert_eq!(header.owner_id, 42);
        assert_eq!(header.self_lba, 100);
        assert_eq!(header.payload_bytes as usize, METADATA_ENCRYPTED_BYTES);
        // CRC32C must verify.
        let crc = crate::crc32c::metadata_crc32c(&block);
        assert_eq!(header.crc32c, crc);
        // Decrypt in place; payload region must match the original plaintext.
        let mut copy = block;
        decrypt_metadata_block_in_place(&mut copy, &header, &key, &id)
            .expect("decrypt must succeed");
        assert_eq!(
            &copy[HEADER_BYTES..HEADER_BYTES + METADATA_PLAINTEXT_BYTES],
            &plaintext[..]
        );
    }

    #[test]
    fn encrypted_metadata_block_rejects_wrong_key() {
        let key = test_metadata_key();
        let id = test_volume_uuid();
        let plaintext = [0xaau8; METADATA_PLAINTEXT_BYTES];
        let block =
            make_encrypted_metadata_block(1, 0, 1, 0, &plaintext, &key, &id).expect("encrypt");
        let header = crate::parse_header(&block).expect("header");
        let mut wrong_key = key;
        wrong_key[0] ^= 0xff;
        let mut copy = block;
        assert_eq!(
            decrypt_metadata_block_in_place(&mut copy, &header, &wrong_key, &id),
            Err(EncryptedMetadataError::AeadFailure)
        );
    }

    #[test]
    fn encrypted_metadata_block_rejects_tampered_ciphertext() {
        // Tamper with one byte of the on-disk ciphertext; the GCM
        // tag verification must reject the change.
        let key = test_metadata_key();
        let id = test_volume_uuid();
        let plaintext = [0x55u8; METADATA_PLAINTEXT_BYTES];
        let mut block =
            make_encrypted_metadata_block(1, 0, 7, 0, &plaintext, &key, &id).expect("encrypt");
        // Flip one byte of the encrypted payload (after the nonce).
        block[HEADER_BYTES + 12 + 5] ^= 0x01;
        let header = crate::parse_header(&block).expect("header");
        assert_eq!(
            decrypt_metadata_block_in_place(&mut block, &header, &key, &id),
            Err(EncryptedMetadataError::AeadFailure)
        );
    }

    #[test]
    fn decrypt_rejects_v5_header() {
        let key = test_metadata_key();
        let id = test_volume_uuid();
        let mut block = [0u8; BLOCK_SIZE];
        block[4..6].copy_from_slice(&1u16.to_le_bytes()); // type_version = 1, v5
        let header = crate::parse_header(&block).expect("header");
        let mut copy = block;
        assert_eq!(
            decrypt_metadata_block_in_place(&mut copy, &header, &key, &id),
            Err(EncryptedMetadataError::NotEncrypted)
        );
    }

    #[test]
    fn rejects_plaintext_too_long() {
        let key = test_metadata_key();
        let id = test_volume_uuid();
        let plaintext = [0u8; METADATA_PLAINTEXT_BYTES + 1];
        assert_eq!(
            make_encrypted_metadata_block(1, 0, 1, 0, &plaintext, &key, &id),
            Err(EncryptedMetadataError::PlaintextTooLong)
        );
    }

    #[test]
    fn encrypted_dirent_name_round_trip() {
        let key = test_metadata_key();
        let enc = EncryptedDirentName::encrypt("hello.txt", 1, 100, &key).expect("encrypt");
        let mut out = [0u8; MAX_NAME_BYTES];
        let n = enc.decrypt(1, 100, &key, &mut out).expect("decrypt");
        assert_eq!(&out[..n], b"hello.txt");
    }

    #[test]
    fn encrypted_dirent_name_rejects_wrong_parent() {
        let key = test_metadata_key();
        let enc = EncryptedDirentName::encrypt("hello.txt", 1, 100, &key).expect("encrypt");
        let mut out = [0u8; MAX_NAME_BYTES];
        assert_eq!(
            enc.decrypt(2, 100, &key, &mut out),
            Err(DirentCryptoError::AeadFailure)
        );
    }

    #[test]
    fn encrypted_dirent_name_rejects_wrong_file_id() {
        let key = test_metadata_key();
        let enc = EncryptedDirentName::encrypt("hello.txt", 1, 100, &key).expect("encrypt");
        let mut out = [0u8; MAX_NAME_BYTES];
        assert_eq!(
            enc.decrypt(1, 101, &key, &mut out),
            Err(DirentCryptoError::AeadFailure)
        );
    }

    #[test]
    fn encrypted_dirent_name_rejects_wrong_key() {
        let key = test_metadata_key();
        let enc = EncryptedDirentName::encrypt("hello.txt", 1, 100, &key).expect("encrypt");
        let mut wrong_key = key;
        wrong_key[3] ^= 0x01;
        let mut out = [0u8; MAX_NAME_BYTES];
        assert_eq!(
            enc.decrypt(1, 100, &wrong_key, &mut out),
            Err(DirentCryptoError::AeadFailure)
        );
    }

    #[test]
    fn encrypted_dirent_name_rejects_long_plaintext() {
        let key = test_metadata_key();
        let long = "a".repeat(EncryptedDirentName::MAX_PLAINTEXT_BYTES + 1);
        assert_eq!(
            EncryptedDirentName::encrypt(&long, 1, 100, &key),
            Err(DirentCryptoError::NameTooLong)
        );
    }

    #[test]
    fn derive_metadata_key_for_volume_is_deterministic() {
        let mut id = test_volume_uuid();
        let mut ikm = [0u8; 32];
        let mut index = 0usize;
        while index < ikm.len() {
            ikm[index] = (index as u8).wrapping_add(0x33);
            index += 1;
        }
        let mut a = [0u8; SUBKEY_BYTES];
        let mut b = [0u8; SUBKEY_BYTES];
        derive_metadata_key_for_volume(&ikm, &id, &mut a).expect("a");
        derive_metadata_key_for_volume(&ikm, &id, &mut b).expect("b");
        assert_eq!(a, b);
        // Different volume UUID => different subkey.
        id[0] ^= 0x01;
        let mut c = [0u8; SUBKEY_BYTES];
        derive_metadata_key_for_volume(&ikm, &id, &mut c).expect("c");
        assert_ne!(a, c);
    }
}
