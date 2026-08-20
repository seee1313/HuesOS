//! Signed HBI v2.2 parser for HuesOS.
//! Safe structural parsing plus fail-closed Ed25519 verification before modules
//! become visible to privileged boot code.

use ed25519_dalek::{Signature, VerifyingKey};

include!(concat!(env!("OUT_DIR"), "/hbi_verify_key.rs"));

const HBI_VERSION: u32 = 0x0002_0002;
const HBI_FLAG_SIGNED: u32 = 1;
const SIGNATURE_ALGORITHM_ED25519: u32 = 1;
const SIGNATURE_TRAILER_BYTES: usize = 72;
const SIGNATURE_MAGIC: &[u8; 8] = b"HUESIG1\0";

/// Types of modules that can be present in an HBI image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ModuleType {
    /// The kernel ELF binary.
    Kernel = 1,
    /// Boot filesystem image.
    Bootfs = 2,
    /// Kernel command line.
    Cmdline = 3,
    /// Platform-specific data (device tree like).
    Platform = 4,
    /// TPM2B public/private volume-key object, signed but excluded from PCR12
    /// to avoid a sealed-policy circular dependency.
    SealedKey = 5,
    /// Unknown module type.
    Unknown,
}

impl From<u32> for ModuleType {
    fn from(val: u32) -> Self {
        match val {
            1 => ModuleType::Kernel,
            2 => ModuleType::Bootfs,
            3 => ModuleType::Cmdline,
            4 => ModuleType::Platform,
            5 => ModuleType::SealedKey,
            _ => ModuleType::Unknown,
        }
    }
}

/// Global header of an HBI image.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GlobalHeader {
    /// Magic bytes: "HUESOS_H".
    pub magic: [u8; 8],
    /// Version of the HBI format (currently signed v2.2 / `0x0002_0002`).
    pub version: u32,
    /// Flags (reserved for future use).
    pub flags: u32,
    /// Number of directory entries that follow the header.
    pub num_entries: u32,
    /// Total size of the header section (including this header).
    pub header_size: u32,
    /// Total size of the entire HBI image.
    pub image_size: u64,
    /// Architecture identifier.
    pub arch_id: u32,
    /// Reserved for future use.
    pub reserved: [u8; 36],
}

/// Directory entry describing one module inside the HBI image.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirectoryEntry {
    /// Module type (see [`ModuleType`]).
    pub type_id: u32,
    /// Offset from the start of the image to the module data.
    pub offset: u32,
    /// Length of the module data (after the per-module EntryHeader).
    pub length: u32,
    /// Flags for this entry.
    pub flags: u32,
}

/// Per-module header that immediately precedes the payload.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EntryHeader {
    pub type_id: u32,
    pub flags: u32,
    pub length: u32,
    pub extra: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// Parsed HBI image.
pub struct HbiImage<'a> {
    data: &'a [u8],
    header: GlobalHeader,
    entries: alloc::vec::Vec<DirectoryEntry>,
}

/// Errors that can occur while parsing an HBI image.
#[derive(Debug)]
pub enum HbiError {
    /// Magic bytes did not match.
    InvalidMagic,
    /// Unsupported HBI version.
    UnsupportedVersion,
    /// Input buffer too small for the declared header.
    BufferTooSmall,
    /// Requested module was not present.
    ModuleNotFound,
    /// Offset/length in directory entry was invalid.
    InvalidOffset,
    /// Generic parse error (e.g. arithmetic overflow).
    ParseError,
    /// The declared image_size does not match the actual buffer length.
    ImageSizeMismatch,
    /// The number of directory entries exceeds the sanity bound.
    TooManyEntries,
    /// A directory entry's type_id/length is inconsistent with its per-module
    /// EntryHeader.
    EntryMismatch,
    /// A module payload failed its recorded CRC32 check.
    ChecksumMismatch,
    /// This kernel was built without an HBI verification public key.
    MissingVerificationKey,
    /// Signed-image flags/trailer metadata are absent or malformed.
    InvalidSignatureMetadata,
    /// Ed25519 verification failed.
    InvalidSignature,
}

impl<'a> HbiImage<'a> {
    /// Parse an HBI image from a byte slice.
    ///
    /// This function is safe and performs all necessary size checks:
    /// - Magic and version validation.
    /// - `image_size` consistency with the actual buffer length.
    /// - `num_entries` sanity bound (max 256 directory entries).
    /// - Checked arithmetic for all offset/length computations.
    /// - Directory entry offset/length bounds against the buffer.
    /// - Directory entry ↔ EntryHeader type_id consistency.
    pub fn parse(data: &'a [u8]) -> Result<Self, HbiError> {
        if !HBI_VERIFY_KEY_CONFIGURED {
            return Err(HbiError::MissingVerificationKey);
        }
        Self::parse_with_key(data, &HBI_VERIFY_KEY)
    }

    /// Parse and verify with an explicit Ed25519 public key.
    ///
    /// Exposed for deterministic host tests and key-rotation tooling; boot code
    /// uses [`Self::parse`] with the key embedded at kernel build time.
    pub fn parse_with_key(data: &'a [u8], public_key: &[u8; 32]) -> Result<Self, HbiError> {
        const HEADER_SIZE: usize = core::mem::size_of::<GlobalHeader>();
        /// Sanity upper bound on directory entries. The boot image generator
        /// produces a handful of entries (kernel, bootfs, cmdline, platform);
        /// anything above this is either corrupted or a malicious image.
        const MAX_ENTRIES: usize = 256;

        if data.len() < HEADER_SIZE {
            return Err(HbiError::BufferTooSmall);
        }

        // Read header via unaligned read to avoid UB on arbitrary byte slices.
        let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const GlobalHeader) };

        if &header.magic != b"HUESOS_H" {
            return Err(HbiError::InvalidMagic);
        }

        if header.version != HBI_VERSION {
            return Err(HbiError::UnsupportedVersion);
        }
        if header.image_size as usize != data.len() {
            return Err(HbiError::ImageSizeMismatch);
        }
        if header.flags != HBI_FLAG_SIGNED
            || u32::from_le_bytes([
                header.reserved[0],
                header.reserved[1],
                header.reserved[2],
                header.reserved[3],
            ]) != SIGNATURE_ALGORITHM_ED25519
            || u32::from_le_bytes([
                header.reserved[4],
                header.reserved[5],
                header.reserved[6],
                header.reserved[7],
            ]) as usize
                != SIGNATURE_TRAILER_BYTES
            || header.reserved[16..].iter().any(|byte| *byte != 0)
        {
            return Err(HbiError::InvalidSignatureMetadata);
        }
        let signed_len = u64::from_le_bytes([
            header.reserved[8],
            header.reserved[9],
            header.reserved[10],
            header.reserved[11],
            header.reserved[12],
            header.reserved[13],
            header.reserved[14],
            header.reserved[15],
        ]) as usize;
        let expected_signed_len = data
            .len()
            .checked_sub(SIGNATURE_TRAILER_BYTES)
            .ok_or(HbiError::InvalidSignatureMetadata)?;
        if signed_len != expected_signed_len || signed_len < HEADER_SIZE {
            return Err(HbiError::InvalidSignatureMetadata);
        }
        let trailer = data
            .get(signed_len..)
            .ok_or(HbiError::InvalidSignatureMetadata)?;
        if trailer.get(..8) != Some(SIGNATURE_MAGIC.as_slice()) {
            return Err(HbiError::InvalidSignatureMetadata);
        }
        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(
            trailer
                .get(8..72)
                .ok_or(HbiError::InvalidSignatureMetadata)?,
        );
        let verifying_key =
            VerifyingKey::from_bytes(public_key).map_err(|_| HbiError::InvalidSignatureMetadata)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify_strict(&data[..signed_len], &signature)
            .map_err(|_| HbiError::InvalidSignature)?;

        let num_entries = header.num_entries as usize;
        if num_entries > MAX_ENTRIES {
            return Err(HbiError::TooManyEntries);
        }

        let header_size = header.header_size as usize;
        if header_size < HEADER_SIZE || signed_len < header_size {
            return Err(HbiError::BufferTooSmall);
        }

        let entries_byte_len = num_entries
            .checked_mul(core::mem::size_of::<DirectoryEntry>())
            .ok_or(HbiError::ParseError)?;

        let entries_start = HEADER_SIZE;
        let entries_end = entries_start
            .checked_add(entries_byte_len)
            .ok_or(HbiError::ParseError)?;

        if entries_end > signed_len || entries_end > header_size {
            return Err(HbiError::BufferTooSmall);
        }

        // Read each directory entry with an unaligned read.
        let mut entries: alloc::vec::Vec<DirectoryEntry> =
            alloc::vec::Vec::with_capacity(num_entries);
        let entry_size = core::mem::size_of::<DirectoryEntry>();
        for i in 0..num_entries {
            let off = entries_start
                .checked_add(i.checked_mul(entry_size).ok_or(HbiError::ParseError)?)
                .ok_or(HbiError::ParseError)?;
            let entry = unsafe {
                core::ptr::read_unaligned(data.as_ptr().add(off) as *const DirectoryEntry)
            };

            // Validate each entry's offset/length bounds before accepting it.
            let eh_offset = entry.offset as usize;
            if eh_offset < header_size {
                return Err(HbiError::InvalidOffset);
            }
            let entry_header_end = eh_offset
                .checked_add(core::mem::size_of::<EntryHeader>())
                .ok_or(HbiError::InvalidOffset)?;
            if entry_header_end > signed_len {
                return Err(HbiError::InvalidOffset);
            }
            let payload_start = entry_header_end;
            let payload_end = payload_start
                .checked_add(entry.length as usize)
                .ok_or(HbiError::InvalidOffset)?;
            if payload_end > signed_len {
                return Err(HbiError::InvalidOffset);
            }

            let header = unsafe {
                core::ptr::read_unaligned(data.as_ptr().add(eh_offset) as *const EntryHeader)
            };
            if header.type_id != entry.type_id || header.length != entry.length {
                return Err(HbiError::EntryMismatch);
            }
            if crc32(&data[payload_start..payload_end]) != header.crc32 {
                return Err(HbiError::ChecksumMismatch);
            }

            for existing in &entries {
                let existing_start = existing.offset as usize;
                let existing_payload_start = existing_start
                    .checked_add(core::mem::size_of::<EntryHeader>())
                    .ok_or(HbiError::InvalidOffset)?;
                let existing_payload_end = existing_payload_start
                    .checked_add(existing.length as usize)
                    .ok_or(HbiError::InvalidOffset)?;
                if ranges_overlap(
                    eh_offset,
                    payload_end.saturating_sub(eh_offset),
                    existing_start,
                    existing_payload_end.saturating_sub(existing_start),
                ) {
                    return Err(HbiError::InvalidOffset);
                }
            }

            entries.push(entry);
        }

        Ok(Self {
            data,
            header,
            entries,
        })
    }

    /// Get the raw payload of a module by type.
    ///
    /// The directory entry bounds were already validated during [`parse`];
    /// this re-validates for defense-in-depth in case entries are ever
    /// constructed by another path.
    pub fn get_module(&self, module_type: ModuleType) -> Result<&'a [u8], HbiError> {
        let type_id = module_type as u32;

        let entry = self
            .entries
            .iter()
            .find(|e| e.type_id == type_id)
            .ok_or(HbiError::ModuleNotFound)?;

        let offset = entry.offset as usize;
        let length = entry.length as usize;

        let payload_start = offset
            .checked_add(core::mem::size_of::<EntryHeader>())
            .ok_or(HbiError::InvalidOffset)?;

        let payload_end = payload_start
            .checked_add(length)
            .ok_or(HbiError::InvalidOffset)?;

        if payload_end > self.data.len() {
            return Err(HbiError::InvalidOffset);
        }

        Ok(&self.data[payload_start..payload_end])
    }

    /// Number of directory entries in this image.
    pub fn get_num_entries(&self) -> u32 {
        self.header.num_entries
    }

    /// Reference to the parsed global header.
    pub fn header(&self) -> &GlobalHeader {
        &self.header
    }
}

fn ranges_overlap(a_base: usize, a_size: usize, b_base: usize, b_size: usize) -> bool {
    let Some(a_end) = a_base.checked_add(a_size) else {
        return true;
    };
    let Some(b_end) = b_base.checked_add(b_size) else {
        return true;
    };
    a_size == 0 || b_size == 0 || (a_base < b_end && b_base < a_end)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= byte as u32;
        let mut bit = 0;
        while bit < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            bit += 1;
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_SEED: [u8; 32] = [0x42; 32];

    fn signed_fixture(num_entries: u32) -> (alloc::vec::Vec<u8>, [u8; 32]) {
        let key = SigningKey::from_bytes(&TEST_SEED);
        let public = key.verifying_key().to_bytes();
        let signed_len = 128usize;
        let image_size = signed_len + SIGNATURE_TRAILER_BYTES;
        let mut data = vec![0u8; signed_len];
        data[..8].copy_from_slice(b"HUESOS_H");
        data[8..12].copy_from_slice(&HBI_VERSION.to_le_bytes());
        data[12..16].copy_from_slice(&HBI_FLAG_SIGNED.to_le_bytes());
        data[16..20].copy_from_slice(&num_entries.to_le_bytes());
        data[20..24].copy_from_slice(&(core::mem::size_of::<GlobalHeader>() as u32).to_le_bytes());
        data[24..32].copy_from_slice(&(image_size as u64).to_le_bytes());
        data[36..40].copy_from_slice(&SIGNATURE_ALGORITHM_ED25519.to_le_bytes());
        data[40..44].copy_from_slice(&(SIGNATURE_TRAILER_BYTES as u32).to_le_bytes());
        data[44..52].copy_from_slice(&(signed_len as u64).to_le_bytes());
        let signature = key.sign(&data);
        data.extend_from_slice(SIGNATURE_MAGIC);
        data.extend_from_slice(&signature.to_bytes());
        (data, public)
    }

    #[test]
    fn signed_header_verifies() {
        let (data, public) = signed_fixture(0);
        let Ok(image) = HbiImage::parse_with_key(&data, &public) else {
            assert!(false, "valid signed fixture must verify");
            return;
        };
        assert_eq!(image.get_num_entries(), 0);
    }

    #[test]
    fn invalid_magic_and_short_input_are_rejected() {
        let (mut data, public) = signed_fixture(0);
        data[0] = 0;
        assert!(matches!(
            HbiImage::parse_with_key(&data, &public),
            Err(HbiError::InvalidMagic)
        ));
        assert!(matches!(
            HbiImage::parse_with_key(&[0u8; 10], &public),
            Err(HbiError::BufferTooSmall)
        ));
    }

    #[test]
    fn image_size_and_entry_count_are_bounded() {
        let (mut bad_size, public) = signed_fixture(0);
        bad_size[24..32].copy_from_slice(&999u64.to_le_bytes());
        assert!(matches!(
            HbiImage::parse_with_key(&bad_size, &public),
            Err(HbiError::ImageSizeMismatch)
        ));

        let (too_many, public) = signed_fixture(257);
        assert!(matches!(
            HbiImage::parse_with_key(&too_many, &public),
            Err(HbiError::TooManyEntries)
        ));
    }

    #[test]
    fn tamper_and_wrong_key_fail_signature() {
        let (mut tampered, public) = signed_fixture(0);
        tampered[100] ^= 1;
        assert!(matches!(
            HbiImage::parse_with_key(&tampered, &public),
            Err(HbiError::InvalidSignature)
        ));

        let (data, _) = signed_fixture(0);
        let wrong = SigningKey::from_bytes(&[0x24; 32])
            .verifying_key()
            .to_bytes();
        assert!(matches!(
            HbiImage::parse_with_key(&data, &wrong),
            Err(HbiError::InvalidSignature)
        ));
    }
}
