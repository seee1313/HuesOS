//! PCR selection, reading, and extension.
//!
//! A PCR (Platform Configuration Register) cannot be written, only
//! *extended*: `PCR_new = SHA256(PCR_old || digest)`. That one-way
//! chaining is the whole basis of measured boot -- software can add a
//! measurement but cannot rewind the register to a value that was
//! already passed, so it cannot forge the state of an earlier boot
//! stage after the fact.
//!
//! Sealing the volume key against a PCR policy therefore binds the key
//! to *which software booted*, not to a secret the software holds. An
//! attacker who replaces the kernel gets different PCR values and the
//! TPM refuses to unseal; there is nothing on disk for them to read.

use crate::crb::{execute_ok, CrbTransport, TpmCommandError};
use crate::{
    begin_command, command, finish_command, push, push_u16, push_u32, read_u16, read_u32, tag,
    MAX_MESSAGE_BYTES,
};

/// Bytes in a SHA-256 PCR digest.
pub const PCR_DIGEST_BYTES: usize = 32;

/// PCRs in the platform bank this crate addresses (0..23).
pub const PCR_COUNT: usize = 24;

/// `TPM_ALG_SHA256`.
pub const ALG_SHA256: u16 = 0x000B;

/// A SHA-256 PCR digest.
pub type PcrValue = [u8; PCR_DIGEST_BYTES];

/// PCR index HuesOS binds the volume key to.
///
/// PCR 12 is in the OS-controlled range and is where the boot chain
/// records the kernel measurement. PCRs 0-7 belong to the firmware:
/// binding to those would make the volume unmountable after any
/// unrelated UEFI update, which in practice trains people to keep a
/// plaintext recovery key next to the machine -- a worse outcome than
/// the narrower binding.
pub const PCR_KERNEL_MEASUREMENT: u32 = 12;

/// A selection of PCRs within the SHA-256 bank.
///
/// Encoded on the wire as a `TPML_PCR_SELECTION` with one bank and a
/// 3-byte bitmap covering PCRs 0..23.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PcrSelection {
    bitmap: [u8; 3],
}

impl PcrSelection {
    /// An empty selection.
    pub const fn new() -> Self {
        Self { bitmap: [0; 3] }
    }

    /// A selection containing exactly `index`.
    pub fn single(index: u32) -> Option<Self> {
        let mut selection = Self::new();
        selection.add(index)?;
        Some(selection)
    }

    /// Add a PCR to the selection. `None` if the index is out of range.
    pub fn add(&mut self, index: u32) -> Option<()> {
        if index as usize >= PCR_COUNT {
            return None;
        }
        let byte = (index / 8) as usize;
        let bit = (index % 8) as u8;
        self.bitmap[byte] |= 1 << bit;
        Some(())
    }

    /// Whether `index` is selected.
    pub fn contains(&self, index: u32) -> bool {
        if index as usize >= PCR_COUNT {
            return false;
        }
        let byte = (index / 8) as usize;
        let bit = (index % 8) as u8;
        self.bitmap[byte] & (1 << bit) != 0
    }

    /// Number of PCRs selected.
    pub fn count(&self) -> u32 {
        self.bitmap.iter().map(|b| b.count_ones()).sum()
    }

    /// Whether nothing is selected.
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// The raw 3-byte bitmap.
    pub fn bitmap(&self) -> [u8; 3] {
        self.bitmap
    }

    /// Encode as a `TPML_PCR_SELECTION` with a single SHA-256 bank.
    pub(crate) fn encode(
        &self,
        out: &mut [u8],
        cursor: &mut usize,
    ) -> Result<(), TpmCommandError> {
        push_u32(out, cursor, 1)?;
        push_u16(out, cursor, ALG_SHA256)?;
        push(out, cursor, &[3u8])?;
        push(out, cursor, &self.bitmap)
    }
}

/// Read one PCR from the SHA-256 bank.
///
/// Returns `None` when the TPM reports the value is not present, which
/// the caller must treat as "cannot bind", never as a zero digest: a
/// zero PCR is a legitimate value (an unextended register), so
/// substituting it would silently seal against the wrong state.
pub fn pcr_read<T: CrbTransport>(
    transport: &mut T,
    index: u32,
) -> Result<Option<PcrValue>, TpmCommandError> {
    let Some(selection) = PcrSelection::single(index) else {
        return Err(TpmCommandError::InvalidArgument);
    };
    let mut command_buf = [0u8; 64];
    let mut cursor = begin_command(&mut command_buf, tag::NO_SESSIONS, command::PCR_READ)?;
    selection.encode(&mut command_buf, &mut cursor)?;
    finish_command(&mut command_buf, cursor)?;

    let mut response_buf = [0u8; MAX_MESSAGE_BYTES];
    let body = execute_ok(transport, &command_buf[..cursor], &mut response_buf)?;

    // Body: pcrUpdateCounter (u32), TPML_PCR_SELECTION, TPML_DIGEST.
    let mut offset = 4usize;
    let banks = read_u32(body, offset).ok_or(TpmCommandError::TruncatedField)?;
    offset += 4;
    let mut bank = 0u32;
    while bank < banks {
        offset = offset
            .checked_add(2)
            .ok_or(TpmCommandError::TruncatedField)?;
        let size = *body.get(offset).ok_or(TpmCommandError::TruncatedField)? as usize;
        offset = offset
            .checked_add(1 + size)
            .ok_or(TpmCommandError::TruncatedField)?;
        bank += 1;
    }
    let digest_count = read_u32(body, offset).ok_or(TpmCommandError::TruncatedField)?;
    offset += 4;
    if digest_count == 0 {
        return Ok(None);
    }
    let digest_size = read_u16(body, offset).ok_or(TpmCommandError::TruncatedField)? as usize;
    offset += 2;
    if digest_size != PCR_DIGEST_BYTES {
        // A bank other than SHA-256 answered; binding to it would be
        // binding to something we did not ask for.
        return Err(TpmCommandError::MalformedResponse);
    }
    let end = offset
        .checked_add(PCR_DIGEST_BYTES)
        .ok_or(TpmCommandError::TruncatedField)?;
    let slice = body
        .get(offset..end)
        .ok_or(TpmCommandError::TruncatedField)?;
    let mut value = [0u8; PCR_DIGEST_BYTES];
    value.copy_from_slice(slice);
    Ok(Some(value))
}

/// Extend a PCR with a SHA-256 digest.
///
/// Used by the boot chain to record a measurement. Extending is
/// irreversible for the life of the boot: there is no command to put a
/// PCR back, only a platform reset.
pub fn pcr_extend<T: CrbTransport>(
    transport: &mut T,
    index: u32,
    digest: &PcrValue,
) -> Result<(), TpmCommandError> {
    if index as usize >= PCR_COUNT {
        return Err(TpmCommandError::InvalidArgument);
    }
    let mut command_buf = [0u8; 128];
    let mut cursor = begin_command(&mut command_buf, tag::SESSIONS, command::PCR_EXTEND)?;
    // Handle area: the PCR itself.
    push_u32(&mut command_buf, &mut cursor, index)?;
    // Authorisation area: a password session with an empty password.
    let auth_start = cursor;
    push_u32(&mut command_buf, &mut cursor, 0)?; // size placeholder
    push_u32(&mut command_buf, &mut cursor, 0x4000_0009)?; // TPM_RS_PW
    push_u16(&mut command_buf, &mut cursor, 0)?; // nonce
    push(&mut command_buf, &mut cursor, &[0u8])?; // attributes
    push_u16(&mut command_buf, &mut cursor, 0)?; // hmac
    let auth_size = cursor - auth_start - 4;
    let auth_size = u32::try_from(auth_size).map_err(|_| TpmCommandError::BufferTooSmall)?;
    command_buf[auth_start..auth_start + 4].copy_from_slice(&auth_size.to_be_bytes());
    // Parameter area: TPML_DIGEST_VALUES with one SHA-256 digest.
    push_u32(&mut command_buf, &mut cursor, 1)?;
    push_u16(&mut command_buf, &mut cursor, ALG_SHA256)?;
    push(&mut command_buf, &mut cursor, digest)?;
    finish_command(&mut command_buf, cursor)?;

    let mut response_buf = [0u8; MAX_MESSAGE_BYTES];
    execute_ok(transport, &command_buf[..cursor], &mut response_buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_bitmap_matches_the_wire_layout() {
        let Some(selection) = PcrSelection::single(12) else {
            assert!(false, "PCR 12 is a valid index");
            return;
        };
        // PCR 12 -> byte 1, bit 4.
        assert_eq!(selection.bitmap(), [0x00, 0x10, 0x00]);
        assert!(selection.contains(12));
        assert!(!selection.contains(11));
        assert_eq!(selection.count(), 1);
    }

    #[test]
    fn out_of_range_pcrs_are_refused() {
        assert_eq!(PcrSelection::single(24), None);
        let mut selection = PcrSelection::new();
        assert_eq!(selection.add(99), None);
        assert!(selection.is_empty());
    }

    #[test]
    fn selection_encodes_one_sha256_bank() {
        let Some(selection) = PcrSelection::single(0) else {
            assert!(false, "PCR 0 is a valid index");
            return;
        };
        let mut buf = [0u8; 16];
        let mut cursor = 0usize;
        assert!(selection.encode(&mut buf, &mut cursor).is_ok());
        // count=1, alg=SHA256, sizeofSelect=3, bitmap.
        assert_eq!(&buf[..cursor], &[0, 0, 0, 1, 0x00, 0x0B, 3, 0x01, 0x00, 0x00]);
    }
}
