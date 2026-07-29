//! Safe CRC32C implementation for Hxfs metadata blocks.

/// Compute CRC32C (Castagnoli) over bytes.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        let mut bit = 0;
        while bit < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
            bit += 1;
        }
    }
    !crc
}

/// Compute a Hxfs metadata-block checksum. Bytes 32..36, where the stored CRC
/// lives in [`crate::format::BlockHeader`], are treated as zero.
pub fn metadata_crc32c(block: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    let mut index = 0usize;
    while index < block.len() {
        let byte = if (32..36).contains(&index) {
            0
        } else {
            block[index]
        };
        crc ^= u32::from(byte);
        let mut bit = 0;
        while bit < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
            bit += 1;
        }
        index += 1;
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_answer() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }
}
