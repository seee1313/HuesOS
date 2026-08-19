//! Versioned KeyBroker wire protocol.
//!
//! The master volume key is never available through an ambient syscall. The
//! kernel transfers it once to the KeyBroker under a `VolumeKey` Resource
//! capability. DriverManager owns the unique manager channel delegated by init
//! and requests one single-use reply channel for each HxFS service generation.

/// Protocol version understood by this build.
pub const VERSION: u16 = 1;
/// Encoded grant request bytes.
pub const GRANT_REQUEST_BYTES: usize = 16;
/// Encoded grant reply bytes.
pub const GRANT_REPLY_BYTES: usize = 48;

const REQUEST_MAGIC: u32 = 0x4b42_4752; // "KBGR"
const REPLY_MAGIC: u32 = 0x4b42_5250; // "KBRP"
const OPCODE_GRANT: u16 = 1;

/// Request carried with a newly-created, single-use reply channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantRequest {
    /// HxFS service generation selected by DriverManager.
    pub generation: u64,
}

impl GrantRequest {
    /// Construct a request for `generation`.
    pub const fn new(generation: u64) -> Self {
        Self { generation }
    }

    /// Encode the fixed-size wire record.
    pub fn encode(self) -> [u8; GRANT_REQUEST_BYTES] {
        let mut out = [0u8; GRANT_REQUEST_BYTES];
        out[0..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&OPCODE_GRANT.to_le_bytes());
        out[8..16].copy_from_slice(&self.generation.to_le_bytes());
        out
    }

    /// Decode and validate a grant request.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != GRANT_REQUEST_BYTES
            || read_u32(bytes, 0)? != REQUEST_MAGIC
            || read_u16(bytes, 4)? != VERSION
            || read_u16(bytes, 6)? != OPCODE_GRANT
        {
            return None;
        }
        let generation = read_u64(bytes, 8)?;
        if generation == 0 {
            return None;
        }
        Some(Self { generation })
    }
}

/// Result status returned by KeyBroker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum GrantStatus {
    /// The reply carries the volume key.
    Granted = 0,
    /// This boot has no volume key; only plain volumes may mount.
    NotFound = 1,
    /// The requested generation was already served or moved backwards.
    StaleGeneration = 2,
    /// The manager request was malformed or not authorized by protocol state.
    Denied = 3,
}

impl GrantStatus {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0 => Some(Self::Granted),
            1 => Some(Self::NotFound),
            2 => Some(Self::StaleGeneration),
            3 => Some(Self::Denied),
            _ => None,
        }
    }
}

/// Single-use KeyBroker reply.
///
/// `Debug` is intentionally not implemented: a derived debug formatter for
/// this type would print the master key.
pub struct GrantReply {
    generation: u64,
    status: GrantStatus,
    key: [u8; 32],
}

impl GrantReply {
    /// Build a successful reply.
    pub const fn granted(generation: u64, key: [u8; 32]) -> Self {
        Self {
            generation,
            status: GrantStatus::Granted,
            key,
        }
    }

    /// Build a reply without secret payload.
    pub const fn without_key(generation: u64, status: GrantStatus) -> Self {
        Self {
            generation,
            status,
            key: [0; 32],
        }
    }

    /// Service generation bound into this reply.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Reply status.
    pub const fn status(&self) -> GrantStatus {
        self.status
    }

    /// Borrow the key only for a successful reply.
    pub fn key(&self) -> Option<&[u8; 32]> {
        if self.status == GrantStatus::Granted {
            Some(&self.key)
        } else {
            None
        }
    }

    /// Encode the fixed-size reply.
    pub fn encode(&self) -> [u8; GRANT_REPLY_BYTES] {
        let mut out = [0u8; GRANT_REPLY_BYTES];
        out[0..4].copy_from_slice(&REPLY_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&(self.status as u16).to_le_bytes());
        out[8..16].copy_from_slice(&self.generation.to_le_bytes());
        out[16..48].copy_from_slice(&self.key);
        out
    }

    /// Decode and validate a fixed-size reply.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != GRANT_REPLY_BYTES
            || read_u32(bytes, 0)? != REPLY_MAGIC
            || read_u16(bytes, 4)? != VERSION
        {
            return None;
        }
        let status = GrantStatus::from_raw(read_u16(bytes, 6)?)?;
        let generation = read_u64(bytes, 8)?;
        if generation == 0 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes.get(16..48)?);
        if status != GrantStatus::Granted && key.iter().any(|byte| *byte != 0) {
            clear_secret(&mut key);
            return None;
        }
        Some(Self {
            generation,
            status,
            key,
        })
    }
}

impl Drop for GrantReply {
    fn drop(&mut self) {
        clear_secret(&mut self.key);
    }
}

fn clear_secret(secret: &mut [u8]) {
    for byte in secret {
        *byte = 0;
        let _ = core::hint::black_box(*byte);
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
        *bytes.get(offset + 4)?,
        *bytes.get(offset + 5)?,
        *bytes.get(offset + 6)?,
        *bytes.get(offset + 7)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_and_rejects_generation_zero() {
        let request = GrantRequest::new(7);
        assert_eq!(GrantRequest::decode(&request.encode()), Some(request));
        assert_eq!(GrantRequest::decode(&GrantRequest::new(0).encode()), None);
    }

    #[test]
    fn granted_reply_round_trip_keeps_generation_and_key() {
        let key = [0x5au8; 32];
        let encoded = GrantReply::granted(11, key).encode();
        let Some(reply) = GrantReply::decode(&encoded) else {
            assert!(false, "valid reply must decode");
            return;
        };
        assert_eq!(reply.generation(), 11);
        assert_eq!(reply.status(), GrantStatus::Granted);
        assert_eq!(reply.key(), Some(&key));
    }

    #[test]
    fn non_granted_reply_must_not_carry_secret_bytes() {
        let mut encoded = GrantReply::without_key(3, GrantStatus::NotFound).encode();
        encoded[16] = 1;
        assert!(GrantReply::decode(&encoded).is_none());
    }

    #[test]
    fn malformed_records_are_rejected() {
        assert!(GrantRequest::decode(&[0; GRANT_REQUEST_BYTES]).is_none());
        assert!(GrantReply::decode(&[0; GRANT_REPLY_BYTES]).is_none());
        assert!(GrantReply::decode(&[0; GRANT_REPLY_BYTES - 1]).is_none());
    }
}
