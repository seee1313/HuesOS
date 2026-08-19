//! Test-only synthetic key context shared by the image seeding
//! tool (`tools/hxfs-seed`), the kernel boot key blob and the
//! `hxfs-service` boot self-check (Stage B.5 / Stage D).
//!
//! The AEAD IKM is an explicit 32-byte volume key
//! ([`VOLUME_KEY`]): the seed tool writes the volume with it, the
//! soak harness exports its hex to the kernel build
//! (`HUESOS_VOLUME_KEY_HEX`, see `huesos-kernel/build.rs`), the
//! kernel moves it once into KeyBroker, and a generation-bound grant
//! delivers it to the service for `mount_with_keys`. There is no implicit
//! placeholder key material in the library anymore: an encrypted
//! volume without a key context is rejected with
//! `EncryptedVolumeKeyUnavailable`.
//!
//! **This module is test wiring only.** The Stage D production
//! KeyProvider derives the real volume key from the bootloader /
//! TPM; nothing in this module is reachable from a default
//! (non-`crypto-aes-gcm`) build.

use crate::compression::CompressionPolicy;
use crate::crypto::EncryptionPolicy;

/// The synthetic volume key (32 bytes) shared by the seed tool,
/// the kernel boot blob and the service's test wiring.
///
/// Developer test material only; the production key comes from the
/// bootloader/TPM key path (Stage D). The soak harness derives
/// `HUESOS_VOLUME_KEY_HEX` from this constant via
/// `hxfs-seed --print-volume-key-hex`, so the kernel blob and the
/// volume on disk always agree.
pub const VOLUME_KEY: [u8; 32] = [
    0x53, 0x59, 0x4e, 0x54, 0x48, 0x45, 0x54, 0x49, // "SYNTHETI"
    0x43, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x33, 0x32, // "C_KEY_32"
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// Encryption policy id used by synthetic-key volumes.
pub const POLICY_ID: u32 = 7;

/// Compression policy id used by synthetic-key volumes (LZ4).
pub const COMPRESSION_POLICY_ID: u32 = crate::compression::COMPRESSION_LZ4;

/// Name of the seed file the image tool writes and the service
/// self-check reads.
pub const SEED_FILE_NAME: &str = "seed.bin";

/// Encryption policy descriptor shared by the seed tool and the
/// service. The volume table references `POLICY_ID`; the AEAD
/// subkeys are derived from the volume's `instance_uuid` at mount
/// time, so both sides agree without exchanging key material.
pub const fn encryption_policy() -> EncryptionPolicy {
    EncryptionPolicy {
        policy_id: POLICY_ID,
        algorithm: crate::crypto::ALGORITHM_AES_XTS,
        data_unit_bytes: crate::crypto::DATA_UNIT_BYTES_4K,
        provider: crate::crypto::KeyProvider::TpmOrBootloader,
    }
}

/// Compression policy descriptor: LZ4 with a 1-byte minimum so
/// every written block is considered for compression.
pub const fn compression_policy() -> CompressionPolicy {
    CompressionPolicy {
        policy_id: COMPRESSION_POLICY_ID,
        algorithm: crate::compression::COMPRESSION_LZ4,
        min_size_bytes: 1,
    }
}
