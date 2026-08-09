//! Test-only synthetic key context shared by the image seeding
//! tool (`tools/hxfs-seed`) and the `hxfs-service` boot self-check
//! (Stage B.5).
//!
//! Stage B exercises the full encrypted + compressed I/O pipeline
//! on target with a synthetic key context. The AEAD IKM is a
//! documented developer placeholder derived from the volume's
//! `instance_uuid` at mount time (see `Hxfs::mount_with_keys`), so
//! the only state the mount path needs from the caller is the
//! policy table below — there is no secret material to carry.
//!
//! **This module is test wiring only.** The Stage D TPM-backed
//! KeyProvider replaces both the placeholder IKM and these
//! descriptors in the production boot path; nothing in this
//! module is reachable from a default (non-`crypto-aes-gcm`)
//! build.

use crate::compression::CompressionPolicy;
use crate::crypto::EncryptionPolicy;

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
