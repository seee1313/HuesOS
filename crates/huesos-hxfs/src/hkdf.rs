//! HKDF-SHA256 key derivation for Hxfs subkeys.
//!
//! Stage B uses HKDF-SHA256 to derive two per-volume subkeys from the
//! AES-256-XTS `volume_key`:
//!
//! - `metadata_key = HKDF(volume_key, salt=volume_id,
//!   info=b"hxfs-metadata-v1")` — used to encrypt/decrypt metadata
//!   blocks (dirent, extent table, allocation tree, refcount tree,
//!   backref tree, quota tree).
//! - `extent_key = HKDF(volume_key, salt=volume_id,
//!   info=b"hxfs-extent-v1")` — used to encrypt/decrypt data extents
//!   on the `decrypt → decompress` / `compress → encrypt` path.
//!
//! Both subkeys are 32 bytes; the AES-256-GCM AEAD consumes a 32-byte
//! key. The function lives behind `#[cfg(feature = "crypto-aes-gcm")]`
//! so the default no-heap, no-extra-deps build remains unchanged.
//!
//! Why HKDF and not a single SHA-256 over `volume_key || info`:
//! - HKDF is the standard primitive for this job; it has an extract
//!   step (HKDF-Extract) that takes the entropy from the input key
//!   material even if the input has low entropy, and an expand step
//!   (HKDF-Expand) that lets us derive multiple subkeys from the
//!   same IKM by changing the `info` string. The audit footprint is
//!   small because we only ever call into the RustCrypto `hkdf` crate
//!   which is in turn a thin wrapper around RustCrypto's `sha2` and
//!   `hmac` crates.
//!
//! The function returns a stack-allocated `[u8; 32]`; the caller is
//! expected to zeroize the buffer after use. The function itself
//! has no `unsafe` blocks.

use hkdf::Hkdf;
use sha2::Sha256;

/// Length of an Hxfs subkey in bytes. AES-256-GCM takes a 32-byte key.
pub const SUBKEY_BYTES: usize = 32;

/// Domain-separation string for the metadata subkey.
pub const METADATA_INFO: &[u8] = b"hxfs-metadata-v1";

/// Domain-separation string for the extent subkey.
pub const EXTENT_INFO: &[u8] = b"hxfs-extent-v1";

/// Derive the 32-byte metadata subkey for a given volume.
///
/// `volume_key` is the 64-byte AES-256-XTS volume key (data + tweak).
/// Only the first 32 bytes (the data half) are used as the HKDF input
/// keying material; using the full 64 bytes would couple the XTS tweak
/// key into the AEAD key, which is not the design we want.
///
/// `volume_id` is the `format::Uuid` of the volume; it is used as the
/// HKDF salt so two volumes with the same `volume_key` get different
/// subkeys.
///
/// The output is written into `out`, which must be exactly
/// [`SUBKEY_BYTES`] long. The function returns `Err(HkdfError::OutputLength)`
/// if the slice is the wrong size; that is the only failure mode.
pub fn derive_metadata_subkey(
    volume_key: &[u8; 32],
    volume_id: &[u8; 16],
    out: &mut [u8],
) -> Result<(), HkdfError> {
    if out.len() != SUBKEY_BYTES {
        return Err(HkdfError::OutputLength);
    }
    let hk = Hkdf::<Sha256>::new(Some(volume_id), volume_key);
    hk.expand(METADATA_INFO, out)
        .map_err(|_| HkdfError::ExpandFailure)
}

/// Derive the 32-byte extent subkey for a given volume. See
/// [`derive_metadata_subkey`] for the parameter contract; the only
/// difference is the `info` string.
pub fn derive_extent_subkey(
    volume_key: &[u8; 32],
    volume_id: &[u8; 16],
    out: &mut [u8],
) -> Result<(), HkdfError> {
    if out.len() != SUBKEY_BYTES {
        return Err(HkdfError::OutputLength);
    }
    let hk = Hkdf::<Sha256>::new(Some(volume_id), volume_key);
    hk.expand(EXTENT_INFO, out)
        .map_err(|_| HkdfError::ExpandFailure)
}

/// HKDF failure modes. The function is total over a well-formed
/// input: the only `Err` returns are from the RustCrypto `hkdf` crate
/// itself, which in practice means "output buffer is the wrong size".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HkdfError {
    /// `out` is not exactly [`SUBKEY_BYTES`].
    OutputLength,
    /// HKDF-Expand rejected the requested output length.
    ExpandFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic 32-byte IKM used across the HKDF tests.
    fn test_ikm() -> [u8; 32] {
        let mut ikm = [0u8; 32];
        let mut index = 0usize;
        while index < ikm.len() {
            ikm[index] = (index as u8).wrapping_add(1);
            index += 1;
        }
        ikm
    }

    /// Deterministic 16-byte volume id used across the HKDF tests.
    fn test_volume_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        let mut index = 0usize;
        while index < id.len() {
            id[index] = 0xa0u8.wrapping_add(index as u8);
            index += 1;
        }
        id
    }

    #[test]
    fn derive_metadata_subkey_is_deterministic() {
        let ikm = test_ikm();
        let id = test_volume_id();
        let mut a = [0u8; SUBKEY_BYTES];
        let mut b = [0u8; SUBKEY_BYTES];
        derive_metadata_subkey(&ikm, &id, &mut a).expect("first derive");
        derive_metadata_subkey(&ikm, &id, &mut b).expect("second derive");
        assert_eq!(
            a, b,
            "HKDF must be deterministic for the same IKM+info+salt"
        );
    }

    #[test]
    fn derive_extent_subkey_differs_from_metadata_subkey() {
        let ikm = test_ikm();
        let id = test_volume_id();
        let mut meta = [0u8; SUBKEY_BYTES];
        let mut ext = [0u8; SUBKEY_BYTES];
        derive_metadata_subkey(&ikm, &id, &mut meta).expect("metadata");
        derive_extent_subkey(&ikm, &id, &mut ext).expect("extent");
        assert_ne!(
            meta, ext,
            "different info strings must produce different subkeys"
        );
    }

    #[test]
    fn different_volume_id_produces_different_subkey() {
        let ikm = test_ikm();
        let id1 = test_volume_id();
        let mut id2 = id1;
        id2[0] ^= 0x01;
        let mut k1 = [0u8; SUBKEY_BYTES];
        let mut k2 = [0u8; SUBKEY_BYTES];
        derive_metadata_subkey(&ikm, &id1, &mut k1).expect("id1");
        derive_metadata_subkey(&ikm, &id2, &mut k2).expect("id2");
        assert_ne!(k1, k2, "different salt must produce different subkey");
    }

    #[test]
    fn rejects_wrong_output_length() {
        let ikm = test_ikm();
        let id = test_volume_id();
        let mut too_short = [0u8; 16];
        assert_eq!(
            derive_metadata_subkey(&ikm, &id, &mut too_short),
            Err(HkdfError::OutputLength)
        );
        let mut too_long = [0u8; 64];
        assert_eq!(
            derive_extent_subkey(&ikm, &id, &mut too_long),
            Err(HkdfError::OutputLength)
        );
    }
}
