//! Read-only BlobFS v1 parser for HuesOS.
//!
//! This is the Stage-E immutable, content-addressed format. It is optimized for
//! NVMe/SSD systems: blob payloads are treated as random-access immutable data,
//! no rotational media layout heuristics are present, and mutation/GC are out
//! of scope for v1.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

/// BlobFS v1 magic: `HBLOBFS1`.
pub const MAGIC: [u8; 8] = *b"HBLOBFS1";
/// BlobFS format version.
pub const VERSION: u32 = 1;
/// Fixed superblock size.
pub const SUPERBLOCK_BYTES: usize = 64;
/// Fixed table-entry size.
pub const ENTRY_BYTES: usize = 64;
/// SHA-256 digest size.
pub const HASH_BYTES: usize = 32;
/// Minimum SSD-friendly payload alignment for blob data.
pub const PAYLOAD_ALIGNMENT: u64 = 4096;

/// A SHA-256 digest.
pub type BlobHash = [u8; HASH_BYTES];

/// Parsed superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    /// Number of blob entries.
    pub blob_count: u32,
    /// Byte offset of the blob table.
    pub table_offset: u64,
    /// Byte offset at which payload data begins.
    pub data_offset: u64,
    /// Total image size in bytes.
    pub image_size: u64,
}

/// One immutable blob entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobEntry {
    /// Content hash.
    pub hash: BlobHash,
    /// Payload byte offset in the image.
    pub offset: u64,
    /// Payload byte length.
    pub length: u64,
    /// Reserved flags. Must be zero in v1.
    pub flags: u32,
}

/// BlobFS parser/mount failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobFsError {
    /// Image is too small.
    TooSmall,
    /// Magic does not match.
    BadMagic,
    /// Version is unsupported.
    BadVersion,
    /// Offset/count arithmetic overflowed or pointed outside the image.
    BadLayout,
    /// Payload ranges overlap, are unsorted, or violate alignment.
    Overlap,
    /// A table entry contains non-zero reserved data.
    ReservedNonZero,
    /// Hash verification failed.
    HashMismatch,
    /// Requested blob was not found.
    NotFound,
}

/// Read-only BlobFS image over a byte slice.
pub struct BlobFs<'a> {
    image: &'a [u8],
    superblock: Superblock,
}

impl<'a> BlobFs<'a> {
    /// Parse and validate a complete BlobFS image.
    pub fn mount(image: &'a [u8]) -> Result<Self, BlobFsError> {
        let superblock = parse_superblock(image)?;
        validate_layout_and_hashes(image, superblock)?;
        Ok(Self { image, superblock })
    }

    /// Superblock metadata.
    pub const fn superblock(&self) -> Superblock {
        self.superblock
    }

    /// Number of blobs.
    pub const fn blob_count(&self) -> u32 {
        self.superblock.blob_count
    }

    /// Return the `index`-th entry.
    pub fn entry(&self, index: u32) -> Result<BlobEntry, BlobFsError> {
        if index >= self.superblock.blob_count {
            return Err(BlobFsError::NotFound);
        }
        let offset = self
            .superblock
            .table_offset
            .checked_add(u64::from(index) * ENTRY_BYTES as u64)
            .ok_or(BlobFsError::BadLayout)?;
        parse_entry(self.image, offset as usize)
    }

    /// Open a blob by content hash, returning the verified payload bytes.
    pub fn open(&self, hash: &BlobHash) -> Result<&'a [u8], BlobFsError> {
        let mut index = 0u32;
        while index < self.superblock.blob_count {
            let entry = self.entry(index)?;
            if &entry.hash == hash {
                let start = entry.offset as usize;
                let end = start
                    .checked_add(entry.length as usize)
                    .ok_or(BlobFsError::BadLayout)?;
                return self.image.get(start..end).ok_or(BlobFsError::BadLayout);
            }
            index += 1;
        }
        Err(BlobFsError::NotFound)
    }

    /// Copy the newline-separated list of blob hashes into `out` as lowercase
    /// hex. Returns bytes written; truncates at `out.len()` without failing.
    pub fn list_hex(&self, out: &mut [u8]) -> usize {
        let mut writer = ByteWriter::new(out);
        let mut index = 0u32;
        while index < self.superblock.blob_count {
            if let Ok(entry) = self.entry(index) {
                writer.write_hex(&entry.hash);
                writer.write_byte(b'\n');
            }
            index += 1;
        }
        writer.len()
    }
}

/// Parse a lowercase/uppercase 64-character hex digest.
pub fn parse_hash_hex(input: &[u8]) -> Option<BlobHash> {
    if input.len() != HASH_BYTES * 2 {
        return None;
    }
    let mut out = [0u8; HASH_BYTES];
    let mut i = 0usize;
    while i < HASH_BYTES {
        let hi = hex_nibble(input[i * 2])?;
        let lo = hex_nibble(input[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

/// Compute SHA-256 over `bytes`.
pub fn sha256(bytes: &[u8]) -> BlobHash {
    Sha256::new().update(bytes).finish()
}

/// Parse a BlobFS superblock from the first [`SUPERBLOCK_BYTES`] bytes of an
/// image. Unlike [`BlobFs::mount`], this accepts a prefix and therefore can be
/// used by a block-backed service before reading the whole image.
pub fn parse_superblock_prefix(bytes: &[u8]) -> Result<Superblock, BlobFsError> {
    parse_superblock_inner(bytes, None)
}

fn parse_superblock(image: &[u8]) -> Result<Superblock, BlobFsError> {
    parse_superblock_inner(image, Some(image.len() as u64))
}

fn parse_superblock_inner(
    image: &[u8],
    expected_image_size: Option<u64>,
) -> Result<Superblock, BlobFsError> {
    if image.len() < SUPERBLOCK_BYTES {
        return Err(BlobFsError::TooSmall);
    }
    if image.get(0..8) != Some(&MAGIC) {
        return Err(BlobFsError::BadMagic);
    }
    if read_u32(image, 8)? != VERSION {
        return Err(BlobFsError::BadVersion);
    }
    let blob_count = read_u32(image, 12)?;
    let table_offset = read_u64(image, 16)?;
    let data_offset = read_u64(image, 24)?;
    let image_size = read_u64(image, 32)?;
    let mut reserved = 40usize;
    while reserved < SUPERBLOCK_BYTES {
        if image[reserved] != 0 {
            return Err(BlobFsError::ReservedNonZero);
        }
        reserved += 1;
    }
    if expected_image_size.is_some_and(|expected| expected != image_size)
        || table_offset < SUPERBLOCK_BYTES as u64
        || table_offset > data_offset
        || data_offset > image_size
    {
        return Err(BlobFsError::BadLayout);
    }
    Ok(Superblock {
        blob_count,
        table_offset,
        data_offset,
        image_size,
    })
}

/// Parse one table entry from an exact [`ENTRY_BYTES`] record.
pub fn parse_entry_record(record: &[u8]) -> Result<BlobEntry, BlobFsError> {
    parse_entry(record, 0)
}

fn parse_entry(image: &[u8], offset: usize) -> Result<BlobEntry, BlobFsError> {
    let entry = image
        .get(offset..offset + ENTRY_BYTES)
        .ok_or(BlobFsError::BadLayout)?;
    let mut hash = [0u8; HASH_BYTES];
    hash.copy_from_slice(&entry[..HASH_BYTES]);
    let blob_offset = read_u64(entry, 32)?;
    let length = read_u64(entry, 40)?;
    let flags = read_u32(entry, 48)?;
    let mut reserved = 52usize;
    while reserved < ENTRY_BYTES {
        if entry[reserved] != 0 {
            return Err(BlobFsError::ReservedNonZero);
        }
        reserved += 1;
    }
    Ok(BlobEntry {
        hash,
        offset: blob_offset,
        length,
        flags,
    })
}

fn validate_layout_and_hashes(image: &[u8], sb: Superblock) -> Result<(), BlobFsError> {
    let table_bytes = u64::from(sb.blob_count)
        .checked_mul(ENTRY_BYTES as u64)
        .ok_or(BlobFsError::BadLayout)?;
    let table_end = sb
        .table_offset
        .checked_add(table_bytes)
        .ok_or(BlobFsError::BadLayout)?;
    if table_end > sb.data_offset || sb.data_offset > sb.image_size {
        return Err(BlobFsError::BadLayout);
    }

    let mut previous_end = sb.data_offset;
    let mut index = 0u32;
    while index < sb.blob_count {
        let entry = parse_entry(
            image,
            (sb.table_offset + u64::from(index) * ENTRY_BYTES as u64) as usize,
        )?;
        if entry.flags != 0
            || entry.offset < sb.data_offset
            || entry.offset % PAYLOAD_ALIGNMENT != 0
        {
            return Err(BlobFsError::BadLayout);
        }
        let end = entry
            .offset
            .checked_add(entry.length)
            .ok_or(BlobFsError::BadLayout)?;
        if end > sb.image_size || entry.offset < previous_end {
            return Err(BlobFsError::Overlap);
        }
        let payload = image
            .get(entry.offset as usize..end as usize)
            .ok_or(BlobFsError::BadLayout)?;
        if sha256(payload) != entry.hash {
            return Err(BlobFsError::HashMismatch);
        }
        previous_end = end;
        index += 1;
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BlobFsError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(BlobFsError::BadLayout)?
            .try_into()
            .map_err(|_| BlobFsError::BadLayout)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, BlobFsError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(BlobFsError::BadLayout)?
            .try_into()
            .map_err(|_| BlobFsError::BadLayout)?,
    ))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

struct ByteWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> ByteWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_byte(&mut self, byte: u8) {
        if self.len < self.out.len() {
            self.out[self.len] = byte;
            self.len += 1;
        }
    }

    fn write_hex(&mut self, hash: &BlobHash) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &byte in hash {
            self.write_byte(HEX[(byte >> 4) as usize]);
            self.write_byte(HEX[(byte & 0x0f) as usize]);
        }
    }
}

/// Incremental SHA-256 context used by the read-only BlobFS verifier.
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    bit_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Create a new SHA-256 context.
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    /// Feed bytes into this context.
    pub fn update(mut self, bytes: &[u8]) -> Self {
        for &byte in bytes {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.bit_len = self.bit_len.wrapping_add(512);
                self.buffer_len = 0;
            }
        }
        self
    }

    /// Finish and return the digest.
    pub fn finish(mut self) -> BlobHash {
        self.bit_len = self.bit_len.wrapping_add((self.buffer_len as u64) * 8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        self.buffer[56..64].copy_from_slice(&self.bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut out = [0u8; HASH_BYTES];
        let mut i = 0usize;
        while i < self.state.len() {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
            i += 1;
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        let mut i = 0usize;
        while i < 16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        i = 0;
        while i < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
            i += 1;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    fn build_image(blobs: &[&[u8]]) -> Vec<u8> {
        let table_offset = SUPERBLOCK_BYTES as u64;
        let data_offset = align_up(
            table_offset + blobs.len() as u64 * ENTRY_BYTES as u64,
            PAYLOAD_ALIGNMENT,
        );
        let mut image = vec![0u8; data_offset as usize];
        image[0..8].copy_from_slice(&MAGIC);
        image[8..12].copy_from_slice(&VERSION.to_le_bytes());
        image[12..16].copy_from_slice(&(blobs.len() as u32).to_le_bytes());
        image[16..24].copy_from_slice(&table_offset.to_le_bytes());
        image[24..32].copy_from_slice(&data_offset.to_le_bytes());
        let mut cursor = data_offset;
        for (index, blob) in blobs.iter().enumerate() {
            let entry = table_offset as usize + index * ENTRY_BYTES;
            image[entry..entry + HASH_BYTES].copy_from_slice(&sha256(blob));
            image[entry + 32..entry + 40].copy_from_slice(&cursor.to_le_bytes());
            image[entry + 40..entry + 48].copy_from_slice(&(blob.len() as u64).to_le_bytes());
            if image.len() < cursor as usize {
                image.resize(cursor as usize, 0);
            }
            image.extend_from_slice(blob);
            cursor += blob.len() as u64;
            cursor = align_up(cursor, PAYLOAD_ALIGNMENT);
            image.resize(cursor as usize, 0);
        }
        image[32..40].copy_from_slice(&(image.len() as u64).to_le_bytes());
        image
    }

    fn align_up(value: u64, align: u64) -> u64 {
        (value + align - 1) & !(align - 1)
    }

    #[test]
    fn sha256_known_answer() {
        let got = sha256(b"abc");
        let expected =
            parse_hash_hex(b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(Some(got), expected);
    }

    #[test]
    fn mounts_and_opens_blob_by_hash() {
        let image = build_image(&[b"alpha", b"beta"]);
        let fs = BlobFs::mount(&image);
        assert!(fs.is_ok());
        let Ok(fs) = fs else { return };
        let hash = sha256(b"beta");
        assert_eq!(fs.open(&hash), Ok(b"beta".as_slice()));
        let mut list = [0u8; 130];
        let len = fs.list_hex(&mut list);
        assert!(len > 64);
    }

    #[test]
    fn rejects_bad_magic_and_hash_mismatch() {
        let mut image = build_image(&[b"alpha"]);
        image[0] = 0;
        assert_eq!(BlobFs::mount(&image).err(), Some(BlobFsError::BadMagic));
        let mut image = build_image(&[b"alpha"]);
        let Ok(payload_offset) = read_u64(&image[SUPERBLOCK_BYTES + 32..], 0) else {
            assert!(false, "test image must contain first entry offset");
            return;
        };
        image[payload_offset as usize] ^= 1;
        assert_eq!(BlobFs::mount(&image).err(), Some(BlobFsError::HashMismatch));
    }

    #[test]
    fn rejects_overlapping_payloads() {
        let mut image = build_image(&[b"alpha", b"beta"]);
        let Ok(first_offset) = read_u64(&image[SUPERBLOCK_BYTES + 32..], 0) else {
            assert!(false, "test image must contain first entry offset");
            return;
        };
        let second = SUPERBLOCK_BYTES + ENTRY_BYTES;
        image[second + 32..second + 40].copy_from_slice(&first_offset.to_le_bytes());
        assert_eq!(BlobFs::mount(&image).err(), Some(BlobFsError::Overlap));
    }

    #[test]
    fn parses_hash_hex() {
        let hash = sha256(b"abc");
        let mut out = [0u8; 64];
        let mut writer = ByteWriter::new(&mut out);
        writer.write_hex(&hash);
        assert_eq!(parse_hash_hex(&out), Some(hash));
    }
}
