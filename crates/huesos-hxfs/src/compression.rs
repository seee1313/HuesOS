//! Compression policy descriptors for Hxfs.
//!
//! Compression is a per-volume/per-object policy. Stage I defines validation and
//! ids only; actual compressors are separate pluggable backends.

/// No compression.
pub const COMPRESSION_NONE: u32 = 0;
/// LZ4-like fast compression policy id.
pub const COMPRESSION_LZ4: u32 = 1;
/// Zstd-like high-ratio compression policy id.
pub const COMPRESSION_ZSTD: u32 = 2;

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
                policy_id: 1,
                algorithm: 99,
                min_size_bytes: 4096,
            }),
            Err(CompressionError::UnknownAlgorithm)
        );
    }
}
