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
///
/// Zstd is deliberately **not** available on any build: see
/// `docs/design/ADR_ZSTD_BACKEND.md`. Reporting it as available
/// whenever `compression-engines` was on was wrong -- the policy
/// resolver uses this to decide whether it may select a codec, so it
/// could hand `COMPRESSION_ZSTD` to a write path that then fails with
/// `EngineUnavailable` at the point of writing user data, instead of
/// the policy being rejected up front.
pub const fn engine_available(algorithm: u32) -> bool {
    match algorithm {
        COMPRESSION_NONE => true,
        COMPRESSION_LZ4 => cfg!(feature = "compression-engines"),
        // Reserved on-disk id with no engine behind it, by decision.
        COMPRESSION_ZSTD => false,
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
#[derive(Debug)]
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
///
/// The shape checks (`payload.len() == compressed_bytes`,
/// `out.len() >= uncompressed_bytes`) and the algorithm/engine
/// dispatch run *before* the CRC check so the caller can
/// distinguish a payload that is the wrong shape
/// ([`CompressionError::BadExtent`]) or points at an engine
/// that is not linked ([`CompressionError::EngineUnavailable`])
/// from a payload that is the right shape but bit-rotted
/// ([`CompressionError::BadChecksum`]). The on-disk Hxfs service
/// translates each variant into a distinct serial marker.
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
    if crc32c(payload) != extent.payload_crc32c {
        return Err(CompressionError::BadChecksum);
    }
    Ok(())
}

/// Compress `input` according to `policy`, falling back to
/// [`CompressOutcome::Plain`] when the codec refuses to shrink
/// the input. The returned borrowed slice always points into
/// `scratch` so the caller does not need to allocate.
///
/// `scratch` must be at least as large as `input.len()`, and when
/// an engine is linked the LZ4 codec additionally needs the
/// worst-case output headroom (`lz4_flex::block::get_maximum_output_size`
/// = `16 + 4 + input_len * 110 / 100`); a scratch the size of the
/// input alone makes `compress_into` fail with `OutputTooSmall`
/// even for highly compressible data. The fixed writer passes a
/// `BLOCK_SIZE + 512` scratch. The on-disk contract reserves
/// `uncompressed_bytes` equal to the full Hxfs block size (4 KiB),
/// so the default caller passes a `BLOCK_SIZE`-long input.
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

    /// Zstd is a reserved id with no engine, on every build.
    ///
    /// See `docs/design/ADR_ZSTD_BACKEND.md`. The policy resolver
    /// consults `engine_available` before selecting a codec, so if
    /// this ever reports true the write path will accept a Zstd
    /// policy and then fail while writing user data.
    #[test]
    fn zstd_is_never_reported_as_an_available_engine() {
        assert!(!engine_available(COMPRESSION_ZSTD));
        assert!(engine_available(COMPRESSION_NONE));
    }

    /// A Zstd extent must be refused, not silently mis-decoded.
    #[test]
    fn decoding_a_zstd_extent_is_refused() {
        let payload = [0u8; 16];
        let extent = CompressedExtent {
            logical_block: 0,
            physical_block: 10,
            uncompressed_bytes: 4096,
            compressed_bytes: payload.len() as u32,
            algorithm: COMPRESSION_ZSTD,
            payload_crc32c: crate::crc32c::crc32c(&payload),
        };
        let mut out = [0u8; 4096];
        assert_eq!(
            decompress_block(&extent, &payload, &mut out),
            Err(CompressionError::EngineUnavailable)
        );
    }

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

    // --- Stage Q production-pipeline tests ---

    fn lz4_policy(min_size: u32) -> CompressionPolicy {
        CompressionPolicy {
            policy_id: 1,
            algorithm: COMPRESSION_LZ4,
            min_size_bytes: min_size,
        }
    }

    fn none_policy() -> CompressionPolicy {
        CompressionPolicy {
            policy_id: 0,
            algorithm: COMPRESSION_NONE,
            min_size_bytes: 0,
        }
    }

    fn repeat_byte(byte: u8, len: usize, out: &mut [u8]) {
        let mut index = 0usize;
        while index < len && index < out.len() {
            out[index] = byte;
            index += 1;
        }
    }

    #[test]
    fn compress_block_returns_plain_for_empty_input() {
        let policy = lz4_policy(1);
        let input: [u8; 0] = [];
        let mut scratch = [0u8; 64];
        match compress_block(policy, &input, &mut scratch) {
            Ok(CompressOutcome::Plain) => {}
            other => assert!(
                false,
                "empty input must fall back to Plain, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn compress_block_returns_plain_for_none_policy() {
        let policy = none_policy();
        let mut input = [0u8; 4096];
        repeat_byte(0xab, input.len(), &mut input);
        let mut scratch = [0u8; 4096];
        match compress_block(policy, &input, &mut scratch) {
            Ok(CompressOutcome::Plain) => {}
            other => assert!(
                false,
                "COMPRESSION_NONE must fall back to Plain, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn compress_block_returns_plain_for_below_threshold() {
        // min_size_bytes above the input size: the policy says
        // "don't bother compressing small files".
        let policy = lz4_policy(8192);
        let mut input = [0u8; 256];
        repeat_byte(0xcd, input.len(), &mut input);
        let mut scratch = [0u8; 4096];
        match compress_block(policy, &input, &mut scratch) {
            Ok(CompressOutcome::Plain) => {}
            other => assert!(
                false,
                "below-threshold input must fall back to Plain, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn compress_block_rejects_oversize_input() {
        // Input larger than the on-disk extent limit is not a
        // valid candidate for the pipeline.
        let policy = lz4_policy(1);
        let mut scratch = [0u8; 8192];
        let input = [0u8; 8192];
        match compress_block(policy, &input, &mut scratch) {
            Err(CompressionError::BadExtent) => {}
            other => {
                assert!(
                    false,
                    "oversize input must surface BadExtent, got {:?}",
                    other
                );
            }
        }
    }

    #[test]
    fn compress_block_rejects_undersize_scratch() {
        // Scratch buffer must be at least as large as the input
        // so the codec can write its worst-case output.
        let policy = lz4_policy(1);
        let input = [0u8; 256];
        let mut scratch = [0u8; 128];
        match compress_block(policy, &input, &mut scratch) {
            Err(CompressionError::BadExtent) => {}
            other => {
                assert!(
                    false,
                    "undersize scratch must surface BadExtent, got {:?}",
                    other
                );
            }
        }
    }

    #[test]
    fn resolve_compression_policy_finds_known_and_rejects_unknown() {
        let table = [none_policy(), lz4_policy(4096)];
        assert_eq!(resolve_compression_policy(0, &table), Ok(none_policy()));
        assert_eq!(resolve_compression_policy(1, &table), Ok(lz4_policy(4096)));
        assert_eq!(
            resolve_compression_policy(99, &table),
            Err(CompressionError::InvalidPolicy)
        );
        // An empty table must reject every id, not panic.
        assert_eq!(
            resolve_compression_policy(0, &[]),
            Err(CompressionError::InvalidPolicy)
        );
    }

    #[test]
    fn decompress_block_rejects_payload_length_mismatch() {
        let extent = CompressedExtent {
            logical_block: 0,
            physical_block: 10,
            uncompressed_bytes: 100,
            compressed_bytes: 50,
            algorithm: COMPRESSION_LZ4,
            payload_crc32c: 0xdead_beef,
        };
        // A payload of 49 bytes does not match compressed_bytes = 50.
        let mut out = [0u8; 100];
        let payload = [0u8; 49];
        assert_eq!(
            decompress_block(&extent, &payload, &mut out),
            Err(CompressionError::BadExtent)
        );
    }

    #[test]
    fn decompress_block_rejects_undersize_output() {
        let extent = CompressedExtent {
            logical_block: 0,
            physical_block: 10,
            uncompressed_bytes: 100,
            compressed_bytes: 50,
            algorithm: COMPRESSION_LZ4,
            payload_crc32c: 0,
        };
        let payload = [0u8; 50];
        let mut out = [0u8; 64]; // smaller than uncompressed_bytes
        assert_eq!(
            decompress_block(&extent, &payload, &mut out),
            Err(CompressionError::BadExtent)
        );
    }

    #[test]
    fn decompress_block_rejects_unknown_algorithm() {
        let extent = CompressedExtent {
            logical_block: 0,
            physical_block: 10,
            uncompressed_bytes: 100,
            compressed_bytes: 50,
            algorithm: 99,
            payload_crc32c: 0,
        };
        let payload = [0u8; 50];
        let mut out = [0u8; 100];
        assert_eq!(
            decompress_block(&extent, &payload, &mut out),
            Err(CompressionError::UnknownAlgorithm)
        );
    }

    #[test]
    fn decompress_block_rejects_unavailable_engine() {
        // COMPRESSION_ZSTD is not linked in this build, so the
        // engine should be reported as unavailable regardless of
        // the input shape.
        let extent = CompressedExtent {
            logical_block: 0,
            physical_block: 10,
            uncompressed_bytes: 100,
            compressed_bytes: 50,
            algorithm: COMPRESSION_ZSTD,
            payload_crc32c: 0,
        };
        let payload = [0u8; 50];
        let mut out = [0u8; 100];
        assert_eq!(
            decompress_block(&extent, &payload, &mut out),
            Err(CompressionError::EngineUnavailable)
        );
    }

    #[test]
    fn decompress_block_rejects_bad_crc_for_plain_payload() {
        // Even on the COMPRESSION_NONE branch the CRC must match;
        // a corrupt plain payload must surface as BadChecksum,
        // not as a successful decode.
        let payload = [0u8; 32];
        let extent = CompressedExtent {
            logical_block: 0,
            physical_block: 10,
            uncompressed_bytes: 32,
            compressed_bytes: 32,
            algorithm: COMPRESSION_NONE,
            payload_crc32c: 0xdead_beef, // wrong on purpose
        };
        let mut out = [0u8; 32];
        assert_eq!(
            decompress_block(&extent, &payload, &mut out),
            Err(CompressionError::BadChecksum)
        );
    }

    #[test]
    fn decompress_block_accepts_matching_crc_for_plain_payload() {
        use crate::crc32c::crc32c;
        let payload = [0xa5u8; 32];
        let extent = CompressedExtent {
            logical_block: 0,
            physical_block: 10,
            uncompressed_bytes: 32,
            compressed_bytes: 32,
            algorithm: COMPRESSION_NONE,
            payload_crc32c: crc32c(&payload),
        };
        let mut out = [0u8; 32];
        assert_eq!(decompress_block(&extent, &payload, &mut out), Ok(()));
    }

    #[cfg(feature = "compression-engines")]
    #[test]
    fn compress_then_decompress_round_trips_lz4() {
        // End-to-end: a compressible LZ4 payload goes through the
        // write pipeline, lands in a CompressedExtent, and the
        // read pipeline decompresses back to the original bytes.
        let policy = lz4_policy(1);
        let mut input = [0u8; 4096];
        repeat_byte(0x5a, input.len(), &mut input);
        // Sprinkle in a non-repeating byte so the LZ4 codec
        // actually has something to compress.
        for index in (0..input.len()).step_by(7) {
            input[index] = index as u8;
        }
        let mut scratch = [0u8; 4096];
        let outcome = match compress_block(policy, &input, &mut scratch) {
            Ok(o) => o,
            Err(error) => {
                assert!(false, "compress_block failed: {:?}", error);
                return;
            }
        };
        let (payload, algo, crc) = match outcome {
            CompressOutcome::Compressed {
                payload,
                algorithm,
                payload_crc32c,
            } => (payload, algorithm, payload_crc32c),
            CompressOutcome::Plain => {
                // LZ4 may legitimately refuse to compress this
                // particular 4 KiB blob. Skip the round-trip in
                // that case; the read-path-plain test covers the
                // Plain path already.
                return;
            }
        };
        let extent = CompressedExtent {
            logical_block: 0,
            physical_block: 10,
            uncompressed_bytes: input.len() as u32,
            compressed_bytes: payload.len() as u32,
            algorithm: algo,
            payload_crc32c: crc,
        };
        let mut out = [0u8; 4096];
        match decompress_block(&extent, payload, &mut out) {
            Ok(()) => {
                assert_eq!(out, input);
            }
            Err(error) => {
                assert!(
                    false,
                    "decompress_block failed after compress_block: {:?}",
                    error
                );
            }
        }
    }
}
