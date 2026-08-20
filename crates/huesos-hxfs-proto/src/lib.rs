//! Wire-protocol logic for the Hxfs filesystem service.
//!
//! This crate holds the parts of `huesos-hxfs-service` that are pure
//! functions of bytes: framing a native request out of a channel
//! message, sizing the receive buffer, building responses, and mapping
//! filesystem errors onto protocol statuses.
//!
//! It exists so those rules can be unit tested on the host. The
//! service itself is a `no_std` binary whose logic previously required
//! live kernel channels to exercise, which meant a latent deadlock in
//! its receive-buffer sizing (a 256-byte buffer against a 4 KiB inline
//! write) shipped untested. See [`POLL_BUF_BYTES`].

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

use huesos_abi::hxfs::{
    HxfsHandleKind, HxfsRequest, HxfsResponse, HxfsStatus, HXFS_MAX_INLINE_WRITE_BYTES,
    HXFS_REQUEST_BYTES, HXFS_RESPONSE_BYTES,
};
use huesos_hxfs::HxfsError;

/// The largest native request a client may send: a fixed header plus
/// the maximum inline write payload the ABI permits.
pub const MAX_NATIVE_REQUEST_BYTES: usize = HXFS_REQUEST_BYTES + HXFS_MAX_INLINE_WRITE_BYTES;

/// Receive-buffer capacity for every channel the service polls.
///
/// This **must** equal [`MAX_NATIVE_REQUEST_BYTES`]. The kernel
/// returns `BytesTooSmall` for an oversized message *without*
/// dequeuing it, so a buffer smaller than the largest legal request
/// wedges the channel permanently: the service can never drain the
/// message at the head of the queue, and the client blocks forever.
///
/// This was a real defect — the buffer was 256 bytes, sized to the
/// largest request seen in the boot smoke test rather than to the ABI
/// limit. [`poll_buffer_admits_largest_legal_request`] pins it.
///
/// [`poll_buffer_admits_largest_legal_request`]: #
pub const POLL_BUF_BYTES: usize = MAX_NATIVE_REQUEST_BYTES;

/// Fields the service fills in when answering a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseMeta {
    /// Protocol status for the operation.
    pub status: HxfsStatus,
    /// Kind of handle returned, if any.
    pub handle_kind: HxfsHandleKind,
    /// Identifier of the returned handle.
    pub handle_id: u64,
    /// Rights granted with the handle.
    pub rights: u64,
    /// Filesystem object the response refers to.
    pub object_id: u64,
    /// Operation-specific scalar result.
    pub value: u64,
    /// Response flags.
    pub flags: u32,
}

impl ResponseMeta {
    /// A meta carrying only an error status.
    pub const fn error(status: HxfsStatus) -> Self {
        Self {
            status,
            handle_kind: HxfsHandleKind::None,
            handle_id: 0,
            rights: 0,
            object_id: 0,
            value: 0,
            flags: 0,
        }
    }
}

/// Split a received message into its request header and payload.
///
/// Returns `None` unless the message is exactly a header followed by
/// precisely `payload_len` bytes: a short, long or malformed frame is
/// rejected rather than being interpreted against adjacent bytes.
pub fn decode_native_message(bytes: &[u8]) -> Option<(HxfsRequest, &[u8])> {
    if bytes.len() < HXFS_REQUEST_BYTES {
        return None;
    }
    let request = HxfsRequest::decode(&bytes[..HXFS_REQUEST_BYTES])?;
    let payload_len = request.payload_len as usize;
    if bytes.len() != HXFS_REQUEST_BYTES.checked_add(payload_len)? {
        return None;
    }
    Some((request, &bytes[HXFS_REQUEST_BYTES..]))
}

/// Build the response header for `request`.
pub fn make_response(
    request: HxfsRequest,
    meta: ResponseMeta,
    payload_len: u32,
) -> [u8; HXFS_RESPONSE_BYTES] {
    HxfsResponse {
        version: huesos_abi::hxfs::HXFS_PROTOCOL_VERSION,
        reserved0: 0,
        status: meta.status,
        flags: meta.flags,
        request_id: request.request_id,
        handle_id: meta.handle_id,
        handle_kind: meta.handle_kind,
        rights: meta.rights,
        object_id: meta.object_id,
        value: meta.value,
        payload_len,
        reserved1: 0,
    }
    .encode()
}

/// Serialize a response and its payload into `out`.
///
/// The payload is truncated to [`HXFS_MAX_INLINE_WRITE_BYTES`] and the
/// declared `payload_len` always matches what was written, so a caller
/// cannot advertise more bytes than the frame carries. Returns the
/// number of bytes to send, or `None` if `out` is too small.
pub fn encode_response(
    request: HxfsRequest,
    meta: ResponseMeta,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let payload_len = payload.len().min(HXFS_MAX_INLINE_WRITE_BYTES);
    let total = HXFS_RESPONSE_BYTES.checked_add(payload_len)?;
    if out.len() < total {
        return None;
    }
    let response = make_response(request, meta, payload_len as u32);
    out[..HXFS_RESPONSE_BYTES].copy_from_slice(&response);
    out[HXFS_RESPONSE_BYTES..total].copy_from_slice(&payload[..payload_len]);
    Some(total)
}

/// Map a filesystem error onto the protocol status a client sees.
pub fn status_for_error(error: HxfsError) -> HxfsStatus {
    match error {
        HxfsError::NotFound => HxfsStatus::NotFound,
        HxfsError::AlreadyExists => HxfsStatus::AlreadyExists,
        HxfsError::WrongType | HxfsError::DirectoryNotEmpty => HxfsStatus::WrongType,
        HxfsError::NeedsRecovery | HxfsError::BadJournal => HxfsStatus::NeedsRecovery,
        HxfsError::Io => HxfsStatus::IoError,
        HxfsError::NoSpace | HxfsError::QuotaExceeded => HxfsStatus::NoSpace,
        HxfsError::Compression => HxfsStatus::IoError,
        HxfsError::Unsupported | HxfsError::UnsupportedFormat | HxfsError::LegacyReadOnly => {
            HxfsStatus::Unsupported
        }
        HxfsError::EncryptedVolumeKeyUnavailable
        | HxfsError::EncryptedPolicyUnknown
        | HxfsError::EncryptedPolicyInvalid => HxfsStatus::EncryptedUnavailable,
        HxfsError::BufferTooSmall
        | HxfsError::OutOfRange
        | HxfsError::BadChecksum
        | HxfsError::BadBlock
        | HxfsError::BadTree
        | HxfsError::BadName
        | HxfsError::CompressionPolicyInvalid => HxfsStatus::Invalid,
    }
}

/// Split `bytes` into two NUL-separated non-empty UTF-8 strings.
pub fn split_two_strings(bytes: &[u8]) -> Option<(&str, &str)> {
    let split = bytes.iter().position(|&byte| byte == 0)?;
    let left = core::str::from_utf8(&bytes[..split]).ok()?;
    let right = core::str::from_utf8(&bytes[split + 1..]).ok()?;
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some((left, right))
}

/// Write `size=<decimal>` into `out`, returning the byte count.
pub fn write_size_info(out: &mut [u8], size: u64) -> usize {
    let prefix = b"size=";
    let mut len = prefix.len().min(out.len());
    out[..len].copy_from_slice(&prefix[..len]);
    let mut tmp = [0u8; 20];
    let mut value = size;
    let mut idx = tmp.len();
    if value == 0 {
        idx -= 1;
        tmp[idx] = b'0';
    }
    while value != 0 {
        idx -= 1;
        tmp[idx] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let digits = &tmp[idx..];
    let take = digits.len().min(out.len().saturating_sub(len));
    out[len..len + take].copy_from_slice(&digits[..take]);
    len += take;
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_abi::hxfs::HxfsOp;

    fn request(op: HxfsOp, payload_len: u32) -> HxfsRequest {
        HxfsRequest {
            version: huesos_abi::hxfs::HXFS_PROTOCOL_VERSION,
            reserved0: 0,
            op,
            flags: 0,
            request_id: 42,
            handle_id: 1,
            handle_kind: HxfsHandleKind::File,
            rights: 0,
            arg0: 0,
            arg1: 0,
            payload_len,
            reserved1: 0,
        }
    }

    /// Regression for the wedged-channel defect (audit finding #4).
    ///
    /// The receive buffer must admit the largest message the ABI lets
    /// a client send. When it was 256 bytes, a legal 4 KiB inline
    /// write could never be dequeued and the channel wedged forever.
    #[test]
    fn poll_buffer_admits_largest_legal_request() {
        assert_eq!(POLL_BUF_BYTES, MAX_NATIVE_REQUEST_BYTES);
        assert!(
            POLL_BUF_BYTES >= HXFS_REQUEST_BYTES + HXFS_MAX_INLINE_WRITE_BYTES,
            "a legal inline write must fit in the receive buffer"
        );

        // Build the largest legal frame and confirm it both fits the
        // buffer and decodes.
        let mut frame = [0u8; MAX_NATIVE_REQUEST_BYTES];
        let header = request(HxfsOp::WriteAt, HXFS_MAX_INLINE_WRITE_BYTES as u32).encode();
        frame[..HXFS_REQUEST_BYTES].copy_from_slice(&header);
        assert!(frame.len() <= POLL_BUF_BYTES);
        let Some((decoded, payload)) = decode_native_message(&frame) else {
            assert!(false, "largest legal frame must decode");
            return;
        };
        assert_eq!(decoded.payload_len as usize, HXFS_MAX_INLINE_WRITE_BYTES);
        assert_eq!(payload.len(), HXFS_MAX_INLINE_WRITE_BYTES);
    }

    #[test]
    fn decode_rejects_truncated_and_overlong_frames() {
        let header = request(HxfsOp::WriteAt, 8).encode();

        // Header only, payload missing.
        assert!(decode_native_message(&header).is_none());

        // Short header.
        assert!(decode_native_message(&header[..HXFS_REQUEST_BYTES - 1]).is_none());

        // Declares 8 payload bytes, carries 9.
        let mut long = [0u8; HXFS_REQUEST_BYTES + 9];
        long[..HXFS_REQUEST_BYTES].copy_from_slice(&header);
        assert!(decode_native_message(&long).is_none());

        // Exactly right.
        let mut exact = [0u8; HXFS_REQUEST_BYTES + 8];
        exact[..HXFS_REQUEST_BYTES].copy_from_slice(&header);
        let Some((_, payload)) = decode_native_message(&exact) else {
            assert!(false, "well-formed frame must decode");
            return;
        };
        assert_eq!(payload.len(), 8);
    }

    #[test]
    fn decode_rejects_payload_len_beyond_abi_limit() {
        // `HxfsRequest::decode` enforces the inline-write cap, so an
        // oversized declaration never reaches the framing check.
        let header = request(HxfsOp::WriteAt, HXFS_MAX_INLINE_WRITE_BYTES as u32 + 1).encode();
        let mut frame = [0u8; HXFS_REQUEST_BYTES];
        frame.copy_from_slice(&header);
        assert!(decode_native_message(&frame).is_none());
    }

    #[test]
    fn encode_response_declares_the_length_it_writes() {
        let req = request(HxfsOp::ReadAt, 0);
        let payload = [7u8; 32];
        let mut out = [0u8; MAX_NATIVE_REQUEST_BYTES];
        let Some(total) =
            encode_response(req, ResponseMeta::error(HxfsStatus::Ok), &payload, &mut out)
        else {
            assert!(false, "encoding must succeed");
            return;
        };
        assert_eq!(total, HXFS_RESPONSE_BYTES + payload.len());
        let Some(decoded) = HxfsResponse::decode(&out[..HXFS_RESPONSE_BYTES]) else {
            assert!(false, "response must decode");
            return;
        };
        assert_eq!(decoded.payload_len as usize, payload.len());
        assert_eq!(decoded.request_id, req.request_id);
        assert_eq!(&out[HXFS_RESPONSE_BYTES..total], &payload[..]);
    }

    #[test]
    fn encode_response_truncates_oversized_payload_consistently() {
        let req = request(HxfsOp::ReadAt, 0);
        let payload = [1u8; HXFS_MAX_INLINE_WRITE_BYTES + 64];
        let mut out = [0u8; MAX_NATIVE_REQUEST_BYTES];
        let Some(total) =
            encode_response(req, ResponseMeta::error(HxfsStatus::Ok), &payload, &mut out)
        else {
            assert!(false, "encoding must succeed");
            return;
        };
        assert_eq!(total, HXFS_RESPONSE_BYTES + HXFS_MAX_INLINE_WRITE_BYTES);
        let Some(decoded) = HxfsResponse::decode(&out[..HXFS_RESPONSE_BYTES]) else {
            assert!(false, "response must decode");
            return;
        };
        // The declared length must never exceed what was written.
        assert_eq!(
            decoded.payload_len as usize,
            total - HXFS_RESPONSE_BYTES,
            "declared payload_len must match the bytes actually sent"
        );
    }

    #[test]
    fn encode_response_refuses_a_short_buffer() {
        let req = request(HxfsOp::ReadAt, 0);
        let mut out = [0u8; HXFS_RESPONSE_BYTES];
        assert_eq!(
            encode_response(
                req,
                ResponseMeta::error(HxfsStatus::Ok),
                &[1, 2, 3],
                &mut out
            ),
            None
        );
    }

    #[test]
    fn quota_errors_map_to_no_space() {
        // The roadmap makes NoSpace the user-visible quota breach.
        assert_eq!(
            status_for_error(HxfsError::QuotaExceeded),
            HxfsStatus::NoSpace
        );
        assert_eq!(status_for_error(HxfsError::NoSpace), HxfsStatus::NoSpace);
        assert_eq!(status_for_error(HxfsError::NotFound), HxfsStatus::NotFound);
        assert_eq!(
            status_for_error(HxfsError::DirectoryNotEmpty),
            HxfsStatus::WrongType
        );
    }

    #[test]
    fn split_two_strings_requires_two_non_empty_parts() {
        assert_eq!(split_two_strings(b"from\0to"), Some(("from", "to")));
        assert_eq!(split_two_strings(b"\0to"), None);
        assert_eq!(split_two_strings(b"from\0"), None);
        assert_eq!(split_two_strings(b"no-separator"), None);
    }

    #[test]
    fn write_size_info_formats_and_bounds() {
        let mut out = [0u8; 32];
        let n = write_size_info(&mut out, 0);
        assert_eq!(&out[..n], b"size=0");

        let n = write_size_info(&mut out, 4096);
        assert_eq!(&out[..n], b"size=4096");

        let n = write_size_info(&mut out, u64::MAX);
        assert_eq!(&out[..n], b"size=18446744073709551615");

        // A short buffer must be respected, not overrun.
        let mut small = [0u8; 7];
        let n = write_size_info(&mut small, 123_456);
        assert!(n <= small.len());
        assert_eq!(&small[..n], b"size=12");
    }

    /// A CreateBlob response carries a 32-byte content hash after the
    /// fixed header, and the frame the service builds must declare
    /// exactly that much payload.
    ///
    /// Regression: the service originally answered CreateBlob with a
    /// bare header, so the caller received a readable view of an
    /// object whose name it could never learn -- useless in a
    /// content-addressed store.
    #[test]
    fn create_blob_frame_carries_the_content_hash() {
        let request = request(HxfsOp::CreateBlob, 0);
        let hash = [0xA7u8; 32];
        let meta = ResponseMeta {
            status: huesos_abi::hxfs::HxfsStatus::Ok,
            handle_kind: huesos_abi::hxfs::HxfsHandleKind::BlobView,
            handle_id: 9,
            rights: huesos_abi::hxfs::rights::READ,
            object_id: 0,
            value: 52,
            flags: huesos_abi::hxfs::response_flags::HANDLE_TRANSFERRED,
        };
        let mut out = [0u8; MAX_NATIVE_REQUEST_BYTES];
        let Some(total) = encode_response(request, meta, &hash, &mut out) else {
            assert!(false, "a 32-byte payload must encode");
            return;
        };
        assert_eq!(total, HXFS_RESPONSE_BYTES + 32);
        let Some(decoded) = HxfsResponse::decode(&out[..HXFS_RESPONSE_BYTES]) else {
            assert!(false, "the header must decode");
            return;
        };
        assert_eq!(decoded.payload_len, 32);
        assert_eq!(&out[HXFS_RESPONSE_BYTES..total], &hash);
    }

    /// The response must echo the request id, so a client can tell an
    /// answer to its own request from one left over on the channel.
    ///
    /// Regression: `request_id` used to be a constant nobody checked.
    /// A client that abandoned one request then read every later
    /// answer one message out of step -- and for a handle-carrying
    /// response that means adopting a view of the wrong object.
    #[test]
    fn responses_echo_the_request_id() {
        let mut request = request(HxfsOp::OpenBlob, 0);
        request.request_id = 0xDEAD_BEEF;
        let meta = ResponseMeta {
            status: huesos_abi::hxfs::HxfsStatus::Ok,
            handle_kind: huesos_abi::hxfs::HxfsHandleKind::BlobView,
            handle_id: 1,
            rights: huesos_abi::hxfs::rights::READ,
            object_id: 0,
            value: 0,
            flags: 0,
        };
        let encoded = make_response(request, meta, 0);
        let Some(decoded) = HxfsResponse::decode(&encoded) else {
            assert!(false, "the header must decode");
            return;
        };
        assert_eq!(decoded.request_id, 0xDEAD_BEEF);
    }
}
