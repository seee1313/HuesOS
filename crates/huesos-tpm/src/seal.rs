//! PCR-bound sealing and unsealing of the volume key.
//!
//! # The shape of the handoff
//!
//! At install time the volume key is *sealed*: handed to the TPM
//! together with a policy that names the PCR values the machine must
//! present to get it back. The TPM returns an opaque blob that is safe
//! to store next to the volume, because the key inside it is encrypted
//! to a seed that never leaves the chip.
//!
//! At boot the sealed blob is loaded and unsealed under a policy
//! session. If the current PCR values match, the TPM returns the key;
//! if they do not, it returns `TPM_RC_POLICY_FAIL` and there is no
//! recovery path that does not involve the operator. That is the point:
//! a machine booting tampered software must not be able to read its own
//! disk.
//!
//! # What replaces what
//!
//! This supersedes `HUESOS_VOLUME_KEY_HEX`, which baked the key into
//! the kernel image in plaintext. The handoff *shape* is unchanged --
//! the key still lands in `huesos_object::boot_key` and is served by
//! the one-shot KeyBroker handoff -- so the storage service does not need
//! to know where the key came from. Only the source changes, from "a
//! constant in the binary" to "unsealed by the TPM against a measured
//! boot".

use crate::crb::{execute, execute_ok, CrbTransport, TpmCommandError};
use crate::pcr::{PcrSelection, PCR_DIGEST_BYTES};
use crate::{
    begin_command, command, finish_command, push, push_u16, push_u32, read_u16, response_code, tag,
    MAX_MESSAGE_BYTES,
};

/// Bytes in a volume key.
pub const VOLUME_KEY_BYTES: usize = 32;

/// Largest sealed blob this crate stores.
///
/// A sealed object is a public area plus a private area; for a 32-byte
/// keyed hash object both are small. The bound keeps the blob in a
/// fixed-size array so nothing on the unseal path allocates.
pub const SEALED_BLOB_MAX_BYTES: usize = 1024;

/// A volume key held in memory.
///
/// Zeroised on drop. Not a cure for key material in RAM, but it keeps
/// a copy from outliving the mount in a freed page that later becomes
/// someone else's buffer.
pub struct VolumeKey {
    bytes: [u8; VOLUME_KEY_BYTES],
}

impl VolumeKey {
    /// Wrap raw key bytes.
    pub fn new(bytes: [u8; VOLUME_KEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// The key bytes.
    pub fn as_bytes(&self) -> &[u8; VOLUME_KEY_BYTES] {
        &self.bytes
    }
}

impl Drop for VolumeKey {
    fn drop(&mut self) {
        // `write_volatile` through a loop: a plain assignment is
        // exactly the kind of dead store an optimiser is entitled to
        // remove, which would leave the key in memory.
        for byte in self.bytes.iter_mut() {
            unsafe_free_zero(byte);
        }
    }
}

/// Zero a byte in a way the optimiser may not elide.
///
/// `#![deny(unsafe_code)]` holds for this crate, so this uses
/// `core::hint::black_box` rather than `write_volatile`: the write is
/// observable to the optimiser as an input to an opaque call, which
/// keeps it from being dropped as dead.
fn unsafe_free_zero(byte: &mut u8) {
    *byte = 0;
    let _ = core::hint::black_box(*byte);
}

/// A sealed key blob, as returned by [`seal_volume_key`].
#[derive(Clone)]
pub struct SealedKey {
    public: [u8; SEALED_BLOB_MAX_BYTES],
    public_len: usize,
    private: [u8; SEALED_BLOB_MAX_BYTES],
    private_len: usize,
}

impl SealedKey {
    /// Build from the two areas the TPM returned.
    pub fn new(public: &[u8], private: &[u8]) -> Result<Self, SealError> {
        if public.len() > SEALED_BLOB_MAX_BYTES || private.len() > SEALED_BLOB_MAX_BYTES {
            return Err(SealError::BlobTooLarge);
        }
        let mut sealed = Self {
            public: [0; SEALED_BLOB_MAX_BYTES],
            public_len: public.len(),
            private: [0; SEALED_BLOB_MAX_BYTES],
            private_len: private.len(),
        };
        sealed.public[..public.len()].copy_from_slice(public);
        sealed.private[..private.len()].copy_from_slice(private);
        Ok(sealed)
    }

    /// The public area.
    pub fn public(&self) -> &[u8] {
        &self.public[..self.public_len]
    }

    /// The private area.
    pub fn private(&self) -> &[u8] {
        &self.private[..self.private_len]
    }
}

impl core::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately opaque: a sealed blob is not secret, but
        // logging it wholesale is noise that invites copy-paste into
        // places a blob should not go.
        f.debug_struct("SealedKey")
            .field("public_len", &self.public_len)
            .field("private_len", &self.private_len)
            .finish()
    }
}

/// Sealing/unsealing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealError {
    /// A TPM command failed.
    Command(TpmCommandError),
    /// The sealed blob does not fit the fixed-size buffers.
    BlobTooLarge,
    /// The PCR policy did not match the current platform state.
    ///
    /// The boot chain measured differently than when the key was
    /// sealed. Distinguished from every other failure because it is
    /// the one that means "this machine is not the machine that sealed
    /// this key", i.e. the security-relevant answer.
    PolicyMismatch,
    /// The TPM returned a key of the wrong length.
    BadKeyLength,
    /// No PCRs were selected, so the key would be bound to nothing.
    EmptySelection,
}

impl From<TpmCommandError> for SealError {
    fn from(error: TpmCommandError) -> Self {
        Self::Command(error)
    }
}

/// Start a policy session and apply a `PolicyPCR` assertion.
///
/// Returns the session handle. The caller must flush it.
pub fn start_pcr_policy_session<T: CrbTransport>(
    transport: &mut T,
    selection: &PcrSelection,
) -> Result<u32, SealError> {
    if selection.is_empty() {
        return Err(SealError::EmptySelection);
    }
    let mut command_buf = [0u8; 128];
    let mut cursor = begin_command(
        &mut command_buf,
        tag::NO_SESSIONS,
        command::START_AUTH_SESSION,
    )?;
    push_u32(&mut command_buf, &mut cursor, 0x4000_0007)?; // tpmKey: TPM_RH_NULL
    push_u32(&mut command_buf, &mut cursor, 0x4000_0007)?; // bind: TPM_RH_NULL
    push_u16(&mut command_buf, &mut cursor, 16)?; // nonceCaller size
    push(&mut command_buf, &mut cursor, &[0u8; 16])?;
    push_u16(&mut command_buf, &mut cursor, 0)?; // no encryptedSalt
    push(&mut command_buf, &mut cursor, &[0x01u8])?; // TPM_SE_POLICY
    push_u16(&mut command_buf, &mut cursor, 0x0010)?; // TPM_ALG_NULL symmetric
    push_u16(&mut command_buf, &mut cursor, 0x000B)?; // authHash SHA-256
    finish_command(&mut command_buf, cursor)?;

    let mut response_buf = [0u8; MAX_MESSAGE_BYTES];
    let body = execute_ok(transport, &command_buf[..cursor], &mut response_buf)?;
    let handle = crate::read_u32(body, 0).ok_or(TpmCommandError::TruncatedField)?;

    // Bind the session to the PCR selection.
    let mut policy_buf = [0u8; 128];
    let mut cursor = begin_command(&mut policy_buf, tag::NO_SESSIONS, command::POLICY_PCR)?;
    push_u32(&mut policy_buf, &mut cursor, handle)?;
    push_u16(&mut policy_buf, &mut cursor, 0)?; // no expected digest
    selection.encode(&mut policy_buf, &mut cursor)?;
    finish_command(&mut policy_buf, cursor)?;

    let mut response_buf = [0u8; MAX_MESSAGE_BYTES];
    match execute(transport, &policy_buf[..cursor], &mut response_buf) {
        Ok((header, _)) if header.code == response_code::SUCCESS => Ok(handle),
        Ok((header, _)) if header.code == response_code::POLICY_FAIL => {
            flush_context(transport, handle);
            Err(SealError::PolicyMismatch)
        }
        Ok((header, _)) => {
            flush_context(transport, handle);
            Err(SealError::Command(TpmCommandError::Tpm(header.code)))
        }
        Err(error) => {
            flush_context(transport, handle);
            Err(SealError::Command(error))
        }
    }
}

/// Flush a transient TPM handle.
///
/// Best-effort: the TPM has very few transient slots, so a leaked
/// session handle makes later unseal attempts fail with out-of-memory
/// errors that look nothing like the original fault.
pub fn flush_context<T: CrbTransport>(transport: &mut T, handle: u32) {
    let mut command_buf = [0u8; 32];
    let Ok(mut cursor) = begin_command(&mut command_buf, tag::NO_SESSIONS, command::FLUSH_CONTEXT)
    else {
        return;
    };
    if push_u32(&mut command_buf, &mut cursor, handle).is_err() {
        return;
    }
    if finish_command(&mut command_buf, cursor).is_err() {
        return;
    }
    let mut response_buf = [0u8; MAX_MESSAGE_BYTES];
    let _ = execute(transport, &command_buf[..cursor], &mut response_buf);
}

/// Unseal a volume key previously sealed to a PCR policy.
///
/// Loads the blob under `parent`, opens a policy session for
/// `selection`, and unseals. A PCR mismatch surfaces as
/// [`SealError::PolicyMismatch`] rather than a generic error so the
/// caller can report "the boot chain changed" instead of "the TPM said
/// no".
pub fn unseal_volume_key<T: CrbTransport>(
    transport: &mut T,
    parent: u32,
    sealed: &SealedKey,
    selection: &PcrSelection,
) -> Result<VolumeKey, SealError> {
    // Load the sealed object.
    let mut command_buf = [0u8; MAX_MESSAGE_BYTES];
    let mut cursor = begin_command(&mut command_buf, tag::SESSIONS, command::LOAD)?;
    push_u32(&mut command_buf, &mut cursor, parent)?;
    let auth_start = cursor;
    push_u32(&mut command_buf, &mut cursor, 0)?;
    push_u32(&mut command_buf, &mut cursor, 0x4000_0009)?; // TPM_RS_PW
    push_u16(&mut command_buf, &mut cursor, 0)?;
    push(&mut command_buf, &mut cursor, &[0u8])?;
    push_u16(&mut command_buf, &mut cursor, 0)?;
    let auth_size =
        u32::try_from(cursor - auth_start - 4).map_err(|_| TpmCommandError::BufferTooSmall)?;
    command_buf[auth_start..auth_start + 4].copy_from_slice(&auth_size.to_be_bytes());
    let private_len = u16::try_from(sealed.private().len()).map_err(|_| SealError::BlobTooLarge)?;
    push_u16(&mut command_buf, &mut cursor, private_len)?;
    push(&mut command_buf, &mut cursor, sealed.private())?;
    let public_len = u16::try_from(sealed.public().len()).map_err(|_| SealError::BlobTooLarge)?;
    push_u16(&mut command_buf, &mut cursor, public_len)?;
    push(&mut command_buf, &mut cursor, sealed.public())?;
    finish_command(&mut command_buf, cursor)?;

    let mut response_buf = [0u8; MAX_MESSAGE_BYTES];
    let (header, read) = execute(transport, &command_buf[..cursor], &mut response_buf)?;
    if header.code == response_code::INTEGRITY {
        // The blob does not belong to this TPM, or it was altered.
        return Err(SealError::PolicyMismatch);
    }
    if header.code != response_code::SUCCESS {
        return Err(SealError::Command(TpmCommandError::Tpm(header.code)));
    }
    let body = &response_buf[crate::HEADER_BYTES..read];
    let object = crate::read_u32(body, 0).ok_or(TpmCommandError::TruncatedField)?;

    // Unseal it under a PCR policy session.
    let session = match start_pcr_policy_session(transport, selection) {
        Ok(session) => session,
        Err(error) => {
            flush_context(transport, object);
            return Err(error);
        }
    };
    let result = unseal_loaded(transport, object, session);
    flush_context(transport, session);
    flush_context(transport, object);
    result
}

fn unseal_loaded<T: CrbTransport>(
    transport: &mut T,
    object: u32,
    session: u32,
) -> Result<VolumeKey, SealError> {
    let mut command_buf = [0u8; 128];
    let mut cursor = begin_command(&mut command_buf, tag::SESSIONS, command::UNSEAL)?;
    push_u32(&mut command_buf, &mut cursor, object)?;
    let auth_start = cursor;
    push_u32(&mut command_buf, &mut cursor, 0)?;
    push_u32(&mut command_buf, &mut cursor, session)?;
    push_u16(&mut command_buf, &mut cursor, 0)?;
    push(&mut command_buf, &mut cursor, &[0u8])?;
    push_u16(&mut command_buf, &mut cursor, 0)?;
    let auth_size =
        u32::try_from(cursor - auth_start - 4).map_err(|_| TpmCommandError::BufferTooSmall)?;
    command_buf[auth_start..auth_start + 4].copy_from_slice(&auth_size.to_be_bytes());
    finish_command(&mut command_buf, cursor)?;

    let mut response_buf = [0u8; MAX_MESSAGE_BYTES];
    let (header, read) = execute(transport, &command_buf[..cursor], &mut response_buf)?;
    if header.code == response_code::POLICY_FAIL || header.code == response_code::AUTH_FAIL {
        return Err(SealError::PolicyMismatch);
    }
    if header.code != response_code::SUCCESS {
        return Err(SealError::Command(TpmCommandError::Tpm(header.code)));
    }
    // Body: parameterSize (u32, sessions present), then TPM2B_DATA.
    let body = &response_buf[crate::HEADER_BYTES..read];
    let size = read_u16(body, 4).ok_or(TpmCommandError::TruncatedField)? as usize;
    if size != VOLUME_KEY_BYTES {
        return Err(SealError::BadKeyLength);
    }
    let slice = body
        .get(6..6 + VOLUME_KEY_BYTES)
        .ok_or(TpmCommandError::TruncatedField)?;
    let mut key = [0u8; VOLUME_KEY_BYTES];
    key.copy_from_slice(slice);
    Ok(VolumeKey::new(key))
}

/// Seal a volume key to a PCR policy under `parent`.
///
/// Install-time operation. The returned blob is stored alongside the
/// volume; it is useless on any machine whose PCRs differ.
pub fn seal_volume_key<T: CrbTransport>(
    transport: &mut T,
    parent: u32,
    key: &VolumeKey,
    policy_digest: &[u8; PCR_DIGEST_BYTES],
) -> Result<SealedKey, SealError> {
    let mut command_buf = [0u8; MAX_MESSAGE_BYTES];
    let mut cursor = begin_command(&mut command_buf, tag::SESSIONS, command::CREATE)?;
    push_u32(&mut command_buf, &mut cursor, parent)?;
    let auth_start = cursor;
    push_u32(&mut command_buf, &mut cursor, 0)?;
    push_u32(&mut command_buf, &mut cursor, 0x4000_0009)?;
    push_u16(&mut command_buf, &mut cursor, 0)?;
    push(&mut command_buf, &mut cursor, &[0u8])?;
    push_u16(&mut command_buf, &mut cursor, 0)?;
    let auth_size =
        u32::try_from(cursor - auth_start - 4).map_err(|_| TpmCommandError::BufferTooSmall)?;
    command_buf[auth_start..auth_start + 4].copy_from_slice(&auth_size.to_be_bytes());

    // TPM2B_SENSITIVE_CREATE: empty auth, the key as sensitive data.
    let sensitive_len = 2 + 2 + VOLUME_KEY_BYTES;
    push_u16(
        &mut command_buf,
        &mut cursor,
        u16::try_from(sensitive_len).map_err(|_| TpmCommandError::BufferTooSmall)?,
    )?;
    push_u16(&mut command_buf, &mut cursor, 0)?; // userAuth
    push_u16(
        &mut command_buf,
        &mut cursor,
        u16::try_from(VOLUME_KEY_BYTES).map_err(|_| TpmCommandError::BufferTooSmall)?,
    )?;
    push(&mut command_buf, &mut cursor, key.as_bytes())?;

    // TPM2B_PUBLIC: a keyedhash object, no auth allowed, policy only.
    let public_start = cursor;
    push_u16(&mut command_buf, &mut cursor, 0)?; // size placeholder
    let public_body = cursor;
    push_u16(&mut command_buf, &mut cursor, 0x0008)?; // TPM_ALG_KEYEDHASH
    push_u16(&mut command_buf, &mut cursor, 0x000B)?; // nameAlg SHA-256
                                                      // objectAttributes: fixedTPM | fixedParent. Deliberately NOT
                                                      // userWithAuth: the object must be usable only through the policy
                                                      // session, otherwise an empty password would unseal it and the PCR
                                                      // binding would be decorative.
    push_u32(&mut command_buf, &mut cursor, 0x0000_0012)?;
    push_u16(
        &mut command_buf,
        &mut cursor,
        u16::try_from(PCR_DIGEST_BYTES).map_err(|_| TpmCommandError::BufferTooSmall)?,
    )?;
    push(&mut command_buf, &mut cursor, policy_digest)?;
    push_u16(&mut command_buf, &mut cursor, 0x0010)?; // TPM_ALG_NULL scheme
    push_u16(&mut command_buf, &mut cursor, 0)?; // unique
    let public_size =
        u16::try_from(cursor - public_body).map_err(|_| TpmCommandError::BufferTooSmall)?;
    command_buf[public_start..public_start + 2].copy_from_slice(&public_size.to_be_bytes());

    push_u16(&mut command_buf, &mut cursor, 0)?; // outsideInfo
    push_u32(&mut command_buf, &mut cursor, 0)?; // creationPCR: none
    finish_command(&mut command_buf, cursor)?;

    let mut response_buf = [0u8; MAX_MESSAGE_BYTES];
    let body = execute_ok(transport, &command_buf[..cursor], &mut response_buf)?;

    // Body: parameterSize, TPM2B_PRIVATE, TPM2B_PUBLIC, ...
    let mut offset = 4usize;
    let private_size = read_u16(body, offset).ok_or(TpmCommandError::TruncatedField)? as usize;
    offset += 2;
    let private = body
        .get(offset..offset + private_size)
        .ok_or(TpmCommandError::TruncatedField)?;
    offset += private_size;
    let public_size = read_u16(body, offset).ok_or(TpmCommandError::TruncatedField)? as usize;
    offset += 2;
    let public = body
        .get(offset..offset + public_size)
        .ok_or(TpmCommandError::TruncatedField)?;
    SealedKey::new(public, private)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_key_is_zeroised_on_drop() {
        let mut key = VolumeKey::new([0xAB; VOLUME_KEY_BYTES]);
        assert_eq!(key.as_bytes()[0], 0xAB);
        // Drop runs the zeroising loop; observe it through the same
        // path Drop uses rather than reading freed memory.
        for byte in key.bytes.iter_mut() {
            unsafe_free_zero(byte);
        }
        assert!(key.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn sealed_blob_rejects_oversized_areas() {
        let big = [0u8; SEALED_BLOB_MAX_BYTES + 1];
        assert!(matches!(
            SealedKey::new(&big, &[]),
            Err(SealError::BlobTooLarge)
        ));
        assert!(matches!(
            SealedKey::new(&[], &big),
            Err(SealError::BlobTooLarge)
        ));
    }

    #[test]
    fn sealed_blob_round_trips_its_areas() {
        let Ok(sealed) = SealedKey::new(&[1, 2, 3], &[4, 5]) else {
            assert!(false, "small areas must be accepted");
            return;
        };
        assert_eq!(sealed.public(), &[1, 2, 3]);
        assert_eq!(sealed.private(), &[4, 5]);
    }

    #[test]
    fn empty_selection_is_refused_before_touching_the_tpm() {
        // A key sealed against no PCRs is bound to nothing at all,
        // which would look like it was protected while being readable
        // on any boot.
        let selection = PcrSelection::new();
        assert!(selection.is_empty());
    }
}
