//! TPM 2.0 support: CRB transport, command marshalling, and PCR-bound
//! sealing of the volume key.
//!
//! # Why this exists
//!
//! Until now the volume key was baked into the kernel image at build
//! time (`HUESOS_VOLUME_KEY_HEX`) and handed to the storage service
//! through the `VolumeKeyGet` syscall. That is a key sitting in
//! plaintext inside the boot image: anyone who can read the image can
//! read the key, and "full disk encryption" against an attacker with
//! the disk is then theatre.
//!
//! This crate replaces the source of that key. The key is sealed to
//! the TPM against a PCR policy, so it can only be unsealed by a
//! machine booting the same measured software. Tamper with the boot
//! chain and the unseal fails; the volume does not mount, which is the
//! correct outcome, not a fallback to plaintext.
//!
//! # Scope and layering
//!
//! The crate is `no_std` and holds no I/O of its own: [`CrbTransport`]
//! is a trait, so the same command layer drives real MMIO in the
//! kernel/driver and a simulated responder in tests. Everything here
//! is deterministic byte-level work -- header encoding, response
//! parsing, bounds checks -- which is exactly the part that is worth
//! unit testing and exactly the part that is easy to get subtly wrong.
//!
//! # What is deliberately strict
//!
//! Every response is length-checked against the header's own
//! `responseSize` before any field is read, and `responseSize` is
//! checked against the bytes actually returned. A TPM is an external
//! device: on a compromised or buggy platform its responses are
//! attacker-influenced input, and a parser that trusts a
//! device-supplied length is a memory-safety bug waiting for the right
//! firmware.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod crb;
pub mod pcr;
pub mod seal;

pub use crb::{CrbError, CrbTransport, TpmCommandError};
pub use pcr::{PcrSelection, PcrValue, PCR_COUNT, PCR_DIGEST_BYTES};
pub use seal::{SealError, SealedKey, VolumeKey, SEALED_BLOB_MAX_BYTES, VOLUME_KEY_BYTES};

/// TPM 2.0 command tags (`TPMI_ST_COMMAND_TAG`).
pub mod tag {
    /// Command with no sessions.
    pub const NO_SESSIONS: u16 = 0x8001;
    /// Command with an authorisation session area.
    pub const SESSIONS: u16 = 0x8002;
}

/// TPM 2.0 command codes used by this crate.
pub mod command {
    /// `TPM2_Startup`.
    pub const STARTUP: u32 = 0x0000_0144;
    /// `TPM2_GetRandom`.
    pub const GET_RANDOM: u32 = 0x0000_017B;
    /// `TPM2_PCR_Read`.
    pub const PCR_READ: u32 = 0x0000_017E;
    /// `TPM2_PCR_Extend`.
    pub const PCR_EXTEND: u32 = 0x0000_0182;
    /// `TPM2_Create`.
    pub const CREATE: u32 = 0x0000_0153;
    /// `TPM2_Load`.
    pub const LOAD: u32 = 0x0000_0157;
    /// `TPM2_Unseal`.
    pub const UNSEAL: u32 = 0x0000_015E;
    /// `TPM2_StartAuthSession`.
    pub const START_AUTH_SESSION: u32 = 0x0000_0176;
    /// `TPM2_PolicyPCR`.
    pub const POLICY_PCR: u32 = 0x0000_017F;
    /// `TPM2_FlushContext`.
    pub const FLUSH_CONTEXT: u32 = 0x0000_0165;
    /// `TPM2_CreatePrimary`.
    pub const CREATE_PRIMARY: u32 = 0x0000_0131;
}

/// Selected TPM 2.0 response codes.
pub mod response_code {
    /// Command completed successfully.
    pub const SUCCESS: u32 = 0x0000;
    /// A policy check failed. This is what a PCR mismatch looks like
    /// on the wire, i.e. the "boot chain changed" answer.
    pub const POLICY_FAIL: u32 = 0x0000_099D;
    /// Authorisation failed.
    pub const AUTH_FAIL: u32 = 0x0000_098E;
    /// Integrity check on a loaded blob failed.
    pub const INTEGRITY: u32 = 0x0000_099F;
}

/// Bytes in a TPM 2.0 command/response header: tag, size, code.
pub const HEADER_BYTES: usize = 10;

/// Largest command or response this crate will build or accept.
///
/// Bounded so every buffer in the stack is a fixed-size array: the
/// unseal path runs in a no-heap context, and a device-supplied length
/// must never drive an allocation.
pub const MAX_MESSAGE_BYTES: usize = 4096;

/// Read a big-endian `u16` at `offset`, if it is fully in bounds.
///
/// Public so transport implementations and tests can parse the same
/// wire format the command layer does.
pub fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

/// Read a big-endian `u32` at `offset`, if it is fully in bounds.
pub fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// A TPM 2.0 response header, already validated against the buffer it
/// was parsed from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseHeader {
    /// Response tag.
    pub tag: u16,
    /// Total response size in bytes, including this header.
    pub size: u32,
    /// TPM response code; `0` is success.
    pub code: u32,
}

/// Parse and validate a response header.
///
/// Rejects a response whose declared `responseSize` does not match the
/// bytes actually received, and one that claims to be smaller than its
/// own header. Both are how a malformed or hostile response would try
/// to make a caller read past the end of a buffer or treat trailing
/// garbage as payload.
pub fn parse_response_header(bytes: &[u8]) -> Result<ResponseHeader, TpmCommandError> {
    if bytes.len() < HEADER_BYTES {
        return Err(TpmCommandError::ShortResponse);
    }
    let tag = read_u16(bytes, 0).ok_or(TpmCommandError::ShortResponse)?;
    let size = read_u32(bytes, 2).ok_or(TpmCommandError::ShortResponse)?;
    let code = read_u32(bytes, 6).ok_or(TpmCommandError::ShortResponse)?;
    if (size as usize) < HEADER_BYTES {
        return Err(TpmCommandError::MalformedResponse);
    }
    if size as usize != bytes.len() {
        return Err(TpmCommandError::MalformedResponse);
    }
    Ok(ResponseHeader { tag, size, code })
}

/// Build a TPM 2.0 command header into `out`, returning bytes written.
///
/// The size field is patched by [`finish_command`] once the body is
/// known; writing a placeholder here keeps the caller from having to
/// compute the length twice and get it wrong once.
pub fn begin_command(out: &mut [u8], tag: u16, code: u32) -> Result<usize, TpmCommandError> {
    if out.len() < HEADER_BYTES {
        return Err(TpmCommandError::BufferTooSmall);
    }
    out[0..2].copy_from_slice(&tag.to_be_bytes());
    out[2..6].copy_from_slice(&0u32.to_be_bytes());
    out[6..10].copy_from_slice(&code.to_be_bytes());
    Ok(HEADER_BYTES)
}

/// Patch the command size field now that the body length is known.
pub fn finish_command(out: &mut [u8], len: usize) -> Result<(), TpmCommandError> {
    if len < HEADER_BYTES || len > out.len() {
        return Err(TpmCommandError::BufferTooSmall);
    }
    let size = u32::try_from(len).map_err(|_| TpmCommandError::BufferTooSmall)?;
    out[2..6].copy_from_slice(&size.to_be_bytes());
    Ok(())
}

/// Append bytes to a command being built.
pub(crate) fn push(out: &mut [u8], cursor: &mut usize, bytes: &[u8]) -> Result<(), TpmCommandError> {
    let end = cursor
        .checked_add(bytes.len())
        .ok_or(TpmCommandError::BufferTooSmall)?;
    if end > out.len() {
        return Err(TpmCommandError::BufferTooSmall);
    }
    out[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
    Ok(())
}

/// Append a big-endian `u16`.
pub(crate) fn push_u16(
    out: &mut [u8],
    cursor: &mut usize,
    value: u16,
) -> Result<(), TpmCommandError> {
    push(out, cursor, &value.to_be_bytes())
}

/// Append a big-endian `u32`.
pub(crate) fn push_u32(
    out: &mut [u8],
    cursor: &mut usize,
    value: u32,
) -> Result<(), TpmCommandError> {
    push(out, cursor, &value.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let mut buf = [0u8; 32];
        let Ok(mut cursor) = begin_command(&mut buf, tag::NO_SESSIONS, command::GET_RANDOM) else {
            assert!(false, "header must fit a 32-byte buffer");
            return;
        };
        assert!(push_u16(&mut buf, &mut cursor, 32).is_ok());
        assert!(finish_command(&mut buf, cursor).is_ok());
        assert_eq!(read_u16(&buf, 0), Some(tag::NO_SESSIONS));
        assert_eq!(read_u32(&buf, 2), Some(cursor as u32));
        assert_eq!(read_u32(&buf, 6), Some(command::GET_RANDOM));
    }

    /// A response whose declared size disagrees with the bytes
    /// received must be rejected. Trusting the device's length is how
    /// a parser ends up reading past its buffer.
    #[test]
    fn response_size_must_match_the_received_bytes() {
        let mut response = [0u8; 12];
        response[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
        // Claims 64 bytes, only 12 present.
        response[2..6].copy_from_slice(&64u32.to_be_bytes());
        response[6..10].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            parse_response_header(&response),
            Err(TpmCommandError::MalformedResponse)
        );

        // Claims fewer bytes than its own header.
        response[2..6].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(
            parse_response_header(&response),
            Err(TpmCommandError::MalformedResponse)
        );

        // Correct length parses.
        response[2..6].copy_from_slice(&12u32.to_be_bytes());
        let Ok(header) = parse_response_header(&response) else {
            assert!(false, "a well-formed header must parse");
            return;
        };
        assert_eq!(header.size, 12);
        assert_eq!(header.code, response_code::SUCCESS);
    }

    #[test]
    fn truncated_responses_are_rejected() {
        assert_eq!(
            parse_response_header(&[]),
            Err(TpmCommandError::ShortResponse)
        );
        assert_eq!(
            parse_response_header(&[0u8; HEADER_BYTES - 1]),
            Err(TpmCommandError::ShortResponse)
        );
    }

    #[test]
    fn push_helpers_refuse_to_overflow() {
        let mut buf = [0u8; 4];
        let mut cursor = 0usize;
        assert!(push_u32(&mut buf, &mut cursor, 1).is_ok());
        assert_eq!(
            push_u16(&mut buf, &mut cursor, 1),
            Err(TpmCommandError::BufferTooSmall)
        );
    }
}
