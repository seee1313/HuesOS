//! Compression policy descriptors and extent records for Hxfs.
//!
//! Stage Q selects audited LZ4/Zstd engines as the production codecs while
//! keeping the filesystem core no-heap. The default build defines stable policy,
//! extent, and validation records. Engine adapters are feature-gated behind
//! `compression-engines` so the no-heap service can link only codecs that are
//! approved for its target profile.

use crate::format::BLOCK_SIZE_U64;

/// No compression.
pub const COMPRESSION_NONE: u32 = 0;
/// LZ4 fast compression policy id.
pub const COMPRESSION_LZ4: u32 = 1;
/// Zstd high-ratio compression policy id.
pub const COMPRESSION_ZSTD: u32 = 2;
/// Audited LZ4 crate selected for engine integration.
pub const AUDITED_LZ4_CRATE: &str = "lz4_flex";
/// Audited Zstd crate selected for engine integration.
pub const AUDITED_ZSTD_CRATE: &str = "zstd";

/// Compression policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressionPolicy {
    /// Policy id referenced by objects.
    pub policy_id: u32,
    /// Algorithm id.
    pub algorithm: u32,
    /// Minimum file size before compression is considered.
    pub min_size_bytes: u32,
}

/// Compression validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionError {
    /// Algorithm id is unknown.
    UnknownAlgorithm,
    /// Policy shape is invalid.
    InvalidPolicy,
    /// Compressed extent descriptor is invalid.
    BadExtent,
    /// Compression would not reduce size and should fall back to plain extents.
    Incompressible,
    /// Requested codec engine is not linked in this build.
    EngineUnavailable,
}

/// Persistent compressed extent descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressedExtent {
    /// Logical file block.
    pub logical_block: u64,
    /// Physical block containing compressed payload bytes.
    pub physical_block: u64,
    /// Uncompressed byte length.
    pub uncompressed_bytes: u32,
    /// Compressed byte length.
    pub compressed_bytes: u32,
    /// Algorithm used for the payload.
    pub algorithm: u32,
    /// CRC32C over compressed payload bytes.
    pub payload_crc32c: u32,
}

/// Compression planning result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionDecision {
    /// Store a normal uncompressed extent.
    StorePlain,
    /// Try to compress with this algorithm.
    Compress {
        /// Algorithm selected for this compression attempt.
        algorithm: u32,
    },
}

/// Validate a compression policy descriptor.
pub fn validate_policy(policy: CompressionPolicy) -> Result<(), CompressionError> {
    match policy.algorithm {
        COMPRESSION_NONE => {
            if policy.min_size_bytes != 0 {
                return Err(CompressionError::InvalidPolicy);
            }
        }
        COMPRESSION_LZ4 | COMPRESSION_ZSTD => {
            if policy.min_size_bytes == 0 {
                return Err(CompressionError::InvalidPolicy);
            }
        }
        _ => return Err(CompressionError::UnknownAlgorithm),
    }
    Ok(())
}

/// Decide whether to attempt compression for `size_bytes`.
pub fn plan_compression(
    policy: CompressionPolicy,
    size_bytes: u64,
) -> Result<CompressionDecision, CompressionError> {
    validate_policy(policy)?;
    if policy.algorithm == COMPRESSION_NONE || size_bytes < u64::from(policy.min_size_bytes) {
        return Ok(CompressionDecision::StorePlain);
    }
    Ok(CompressionDecision::Compress {
        algorithm: policy.algorithm,
    })
}

/// Validate a compressed extent descriptor.
pub fn validate_compressed_extent(extent: CompressedExtent) -> Result<(), CompressionError> {
    if !matches!(extent.algorithm, COMPRESSION_LZ4 | COMPRESSION_ZSTD)
        || extent.uncompressed_bytes == 0
        || extent.compressed_bytes == 0
        || u64::from(extent.uncompressed_bytes) > BLOCK_SIZE_U64
        || u64::from(extent.compressed_bytes) > BLOCK_SIZE_U64
        || extent.compressed_bytes >= extent.uncompressed_bytes
    {
        return Err(CompressionError::BadExtent);
    }
    Ok(())
}

/// Return whether this build links a codec engine for `algorithm`.
pub const fn engine_available(algorithm: u32) -> bool {
    match algorithm {
        COMPRESSION_NONE => true,
        COMPRESSION_LZ4 | COMPRESSION_ZSTD => cfg!(feature = "compression-engines"),
        _ => false,
    }
}

#[cfg(feature = "compression-engines")]
/// Feature-gated LZ4 block compression adapter using the selected audited crate.
pub fn compress_lz4(input: &[u8], out: &mut [u8]) -> Result<usize, CompressionError> {
    let written =
        lz4_flex::block::compress_into(input, out).map_err(|_| CompressionError::BadExtent)?;
    if written >= input.len() {
        return Err(CompressionError::Incompressible);
    }
    Ok(written)
}

#[cfg(feature = "compression-engines")]
/// Feature-gated LZ4 block decompression adapter using the selected audited crate.
pub fn decompress_lz4(input: &[u8], out: &mut [u8]) -> Result<usize, CompressionError> {
    lz4_flex::block::decompress_into(input, out).map_err(|_| CompressionError::BadExtent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_compression_policies() {
        assert_eq!(
            validate_policy(CompressionPolicy {
                policy_id: 0,
                algorithm: COMPRESSION_NONE,
                min_size_bytes: 0,
            }),
            Ok(())
        );
        assert_eq!(
            validate_policy(CompressionPolicy {
                policy_id: 1,
                algorithm: COMPRESSION_LZ4,
                min_size_bytes: 4096,
            }),
            Ok(())
        );
        assert_eq!(
            validate_policy(CompressionPolicy {
                policy_id: 2,
                algorithm: COMPRESSION_ZSTD,
                min_size_bytes: 4096,
            }),
            Ok(())
        );
        assert_eq!(
            validate_policy(CompressionPolicy {
                policy_id: 1,
                algorithm: 99,
                min_size_bytes: 4096,
            }),
            Err(CompressionError::UnknownAlgorithm)
        );
    }

    #[test]
    fn plans_lz4_and_zstd_by_policy_threshold() {
        assert_eq!(
            plan_compression(
                CompressionPolicy {
                    policy_id: 1,
                    algorithm: COMPRESSION_LZ4,
                    min_size_bytes: 4096,
                },
                1024,
            ),
            Ok(CompressionDecision::StorePlain)
        );
        assert_eq!(
            plan_compression(
                CompressionPolicy {
                    policy_id: 2,
                    algorithm: COMPRESSION_ZSTD,
                    min_size_bytes: 4096,
                },
                8192,
            ),
            Ok(CompressionDecision::Compress {
                algorithm: COMPRESSION_ZSTD,
            })
        );
    }

    #[test]
    fn validates_compressed_extent_shape() {
        assert_eq!(
            validate_compressed_extent(CompressedExtent {
                logical_block: 0,
                physical_block: 10,
                uncompressed_bytes: 4096,
                compressed_bytes: 1000,
                algorithm: COMPRESSION_LZ4,
                payload_crc32c: 1,
            }),
            Ok(())
        );
        assert_eq!(
            validate_compressed_extent(CompressedExtent {
                logical_block: 0,
                physical_block: 10,
                uncompressed_bytes: 4096,
                compressed_bytes: 4096,
                algorithm: COMPRESSION_ZSTD,
                payload_crc32c: 1,
            }),
            Err(CompressionError::BadExtent)
        );
    }
}
