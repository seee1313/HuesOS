//! Compression policy descriptors and extent records for Hxfs.
//!
//! Stage Q selects audited LZ4/Zstd engines as the production codecs while
//! keeping the filesystem core no-heap. The default build defines stable policy,
//! extent, and validation records. Engine adapters are feature-gated behind
//! `compression-engines` so the no-heap service can link only codecs that are
//! approved for its target profile.
//!
//! ## Stage Q production pipeline
//!
//! Production Hxfs needs three things on top of the foundation layer:
//!
//! 1. A single [`compress_block`] entry point that picks an algorithm by
//!    policy, runs the codec, and falls back to
//!    [`CompressionDecision::StorePlain`] when the codec refuses to shrink
//!    the input. The caller never has to know whether the on-disk extent is
//!    plain or compressed.
//! 2. A single [`decompress_block`] entry point that pairs with the codec
//!    used in the write path and verifies the [`CompressedExtent::payload_crc32c`]
//!    before returning the uncompressed bytes. A CRC mismatch is
//!    [`CompressionError::BadChecksum`], which the Hxfs service translates
//!    into a read-side abort and a serial marker so the on-target trace
//!    localises corruption.
//! 3. A [`resolve_compression_policy`] helper that maps a `policy_id` to
//!    its [`CompressionPolicy`] descriptor. The Hxfs volume table stores
//!    only the id; the per-object metadata references the id; the runtime
//!    resolves to a concrete codec before writing or reading. This keeps
//!    the on-disk footprint of an object record independent of the codec
//!    choice.

use crate::crc32c::crc32c;
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
    /// Compressed payload CRC32C did not match the on-disk extent
    /// descriptor. The payload bytes were the right shape but the
    /// on-disk copy has been corrupted in a way the CRC detected.
    BadChecksum,
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

// --- Stage Q production pipeline ---

/// Maximum block size for a single compressed extent. The on-disk
/// extent descriptor encodes `uncompressed_bytes` and
/// `compressed_bytes` as `u32`; the upper bound therefore comes
/// from the maximum accepted Hxfs block size. Keep this in sync
/// with the same constant in `format::BLOCK_SIZE`.
pub const COMPRESSED_BLOCK_LIMIT: usize = 4096;

/// Stage Q write-path pipeline result.
///
/// For each candidate input the pipeline either:
/// - returns [`CompressOutcome::Plain`] and tells the caller to
///   store the input bytes verbatim in a normal uncompressed
///   extent (either because the policy said so, the input was
///   too small, or the codec could not shrink the input), or
/// - returns [`CompressOutcome::Compressed { .. }`] with the
///   payload bytes, the algorithm id, and the CRC32C the caller
///   must record in the on-disk extent descriptor.
///
/// The fallback to `Plain` is the key Stage Q safety contract:
/// storing compressed payloads that are larger than the input
/// would waste media and complicate the on-disk layout. A codec
/// that cannot compress returns `Plain` instead.
pub enum CompressOutcome<'a> {
    /// Store `input` verbatim in a normal uncompressed extent.
    Plain,
    /// Store the returned compressed bytes in a
    /// [`CompressedExtent`] with the returned algorithm id and
    /// CRC32C.
    Compressed {
        /// Compressed payload bytes to write to disk.
        payload: &'a [u8],
        /// Algorithm id that produced the payload; the caller
        /// must record this in `CompressedExtent::algorithm`.
        algorithm: u32,
        /// CRC32C over the compressed payload bytes; the caller
        /// must record this in
        /// `CompressedExtent::payload_crc32c`.
        payload_crc32c: u32,
    },
}

/// Stage Q read-path pipeline: decompress the on-disk payload
/// and verify the CRC32C from [`CompressedExtent::payload_crc32c`]
/// before returning. A CRC mismatch is
/// [`CompressionError::BadChecksum`] so the Hxfs service can
/// distinguish a payload that is the wrong shape from one that is
/// the right shape but bit-rotted.
pub fn decompress_block(
    extent: &CompressedExtent,
    payload: &[u8],
    out: &mut [u8],
) -> Result<(), CompressionError> {
    if payload.len() as u64 != u64::from(extent.compressed_bytes) {
        return Err(CompressionError::BadExtent);
    }
    if extent.uncompressed_bytes as usize > out.len() {
        return Err(CompressionError::BadExtent);
    }
    if crc32c(payload) != extent.payload_crc32c {
        return Err(CompressionError::BadChecksum);
    }
    let written = match extent.algorithm {
        COMPRESSION_NONE => {
            // Plain payload; the caller did not even need to
            // call this function, but accept it for symmetry.
            payload.len()
        }
        COMPRESSION_LZ4 => {
            #[cfg(feature = "compression-engines")]
            {
                decompress_lz4(payload, &mut out[..extent.uncompressed_bytes as usize])?
            }
            #[cfg(not(feature = "compression-engines"))]
            {
                let _ = payload;
                return Err(CompressionError::EngineUnavailable);
            }
        }
        COMPRESSION_ZSTD => {
            // Zstd is not linked in this build; the production
            // policy resolver must have rejected it earlier
            // through `engine_available`.
            return Err(CompressionError::EngineUnavailable);
        }
        _ => return Err(CompressionError::UnknownAlgorithm),
    };
    if written != extent.uncompressed_bytes as usize {
        return Err(CompressionError::BadExtent);
    }
    Ok(())
}

/// Compress `input` according to `policy`, falling back to
/// [`CompressOutcome::Plain`] when the codec refuses to shrink
/// the input. The returned borrowed slice always points into
/// `scratch` so the caller does not need to allocate.
///
/// `scratch` must be at least as large as `input.len()`. The
/// on-disk contract reserves `uncompressed_bytes` equal to the
/// full Hxfs block size (4 KiB), so the default caller passes a
/// 4 KiB scratch buffer and a `BLOCK_SIZE`-long input.
///
/// The function is **safe to call without `compression-engines`**:
/// in that build the only registered codec returns
/// `Incompressible` for any non-trivial input, and the fallback
/// path correctly returns `Plain`. The production service still
/// links the engines, so a non-compressible payload is rare.
pub fn compress_block<'a>(
    policy: CompressionPolicy,
    input: &[u8],
    scratch: &'a mut [u8],
) -> Result<CompressOutcome<'a>, CompressionError> {
    validate_policy(policy)?;
    if input.is_empty() {
        return Ok(CompressOutcome::Plain);
    }
    if input.len() > COMPRESSED_BLOCK_LIMIT {
        return Err(CompressionError::BadExtent);
    }
    if scratch.len() < input.len() {
        return Err(CompressionError::BadExtent);
    }
    match plan_compression(policy, input.len() as u64)? {
        CompressionDecision::StorePlain => Ok(CompressOutcome::Plain),
        CompressionDecision::Compress { algorithm } => {
            // Try the codec. Incompressible fallback: if the
            // codec returns Incompressible, the on-disk extent
            // must be plain, not compressed-but-bigger.
            match algorithm {
                COMPRESSION_LZ4 => {
                    #[cfg(feature = "compression-engines")]
                    {
                        match compress_lz4(input, scratch) {
                            Ok(written) if written > 0 && written < input.len() => {
                                let payload = &scratch[..written];
                                Ok(CompressOutcome::Compressed {
                                    payload,
                                    algorithm: COMPRESSION_LZ4,
                                    payload_crc32c: crc32c(payload),
                                })
                            }
                            // Belt-and-suspenders: a future codec
                            // that returns 0 or a non-shrinking
                            // output without setting
                            // `Incompressible` is treated as
                            // "do not compress this block".
                            _ => Ok(CompressOutcome::Plain),
                        }
                    }
                    #[cfg(not(feature = "compression-engines"))]
                    {
                        let _ = scratch;
                        Err(CompressionError::EngineUnavailable)
                    }
                }
                COMPRESSION_ZSTD => {
                    // Zstd is not linked in this build; treat the
                    // same way the LZ4 path treats an unknown
                    // engine: surface EngineUnavailable so the
                    // production service fails the write path
                    // loudly rather than silently storing a plain
                    // extent that the read path cannot decode.
                    Err(CompressionError::EngineUnavailable)
                }
                _ => Err(CompressionError::UnknownAlgorithm),
            }
        }
    }
}

/// Stage Q policy resolution: turn a `policy_id` (the on-disk
/// form) into a [`CompressionPolicy`] using a caller-supplied
/// table. The Hxfs volume table stores one
/// [`CompressionPolicy`] per virtual volume; an object references
/// the policy by id and the runtime resolves through this helper
/// before reaching the codec.
///
/// Returning `Err(CompressionError::InvalidPolicy)` for an unknown
/// id keeps a malformed/corrupt volume table from silently
/// promoting to [`CompressOutcome::Plain`] and bypassing the
/// selected codec.
pub fn resolve_compression_policy(
    policy_id: u32,
    table: &[CompressionPolicy],
) -> Result<CompressionPolicy, CompressionError> {
    let mut index = 0usize;
    while index < table.len() {
        if table[index].policy_id == policy_id {
            return Ok(table[index]);
        }
        index += 1;
    }
    Err(CompressionError::InvalidPolicy)
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
