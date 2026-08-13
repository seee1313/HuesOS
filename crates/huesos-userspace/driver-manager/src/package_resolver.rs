//! Package resolving from the Hxblob content-addressed object store.
//!
//! Until now every driver and service DriverManager could start had to
//! be present in BOOTFS: the ELF was either embedded at build time or
//! read out of the boot image VMO. That is fine for the boot-critical
//! set, but it means the only way to ship a driver is to rebuild the
//! boot image, and there is no path at all for content-addressed
//! packages that live on the volume.
//!
//! This module resolves a package by **content hash** through the Hxfs
//! service's native BlobView operations, and materialises it into a
//! VMO that `spawn_elf_from_vmo` can launch from.
//!
//! Why hash-addressed rather than path-addressed:
//!
//! * The hash *is* the integrity check. A path says where to look; a
//!   hash says what must come back. The service verifies the blob
//!   against its hash before returning a view, so a resolve that
//!   succeeds has already proven the bytes are the ones the package
//!   index named.
//! * Resolution is stable across checkpoints, reallocation and
//!   snapshots, none of which preserve object ids.
//! * Two packages that contain the same payload share storage without
//!   the resolver having to know.
//!
//! What this module deliberately does *not* do: it does not decide
//! whether a package is allowed to run. Admission is the manifest and
//! capability layer's job (see `manifest.rs`); resolving only answers
//! "give me these exact bytes, or fail".

use libcanvas::{Channel, ErrorCode, Vmo};

/// Bytes in a content hash (SHA-256).
pub const PACKAGE_HASH_BYTES: usize = 32;

/// Largest package image the resolver will materialise.
///
/// Bounded because the resolver allocates a VMO of the blob's declared
/// size before reading it: an unbounded size taken from on-volume
/// metadata is a memory-exhaustion primitive for anything that can
/// write the package index. 16 MiB comfortably covers a DriverHost
/// while keeping the failure mode "package too large" rather than
/// "the system died".
pub const MAX_PACKAGE_BYTES: u64 = 16 * 1024 * 1024;

/// Chunk size for streaming a blob into its VMO.
///
/// Matches the service's inline read limit; a larger request is
/// clamped service-side anyway, and a smaller one only adds round
/// trips.
const READ_CHUNK_BYTES: usize = 4096;

/// Why a package could not be resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// The Hxfs service is not mounted/ready yet.
    ServiceUnavailable,
    /// No blob with that content hash is stored.
    NotFound,
    /// The blob exists but failed its integrity check, or the bytes
    /// read back do not match the size the service reported.
    Corrupt,
    /// The package is larger than [`MAX_PACKAGE_BYTES`].
    TooLarge,
    /// A VMO could not be created or written.
    OutOfMemory,
    /// The protocol exchange itself failed.
    Protocol(ErrorCode),
}

/// A package resolved out of Hxblob and ready to launch.
pub struct ResolvedPackage {
    /// VMO holding the package image at offset 0.
    pub vmo: Vmo,
    /// Length of the image in bytes.
    pub len: u64,
    /// Content hash the package was resolved under.
    pub hash: [u8; PACKAGE_HASH_BYTES],
}

/// Parse a lowercase-hex content hash.
///
/// Package indexes are text, so the hash arrives as hex; the wire
/// protocol takes it raw. Rejects anything that is not exactly 64 hex
/// digits rather than truncating or zero-padding: a partially parsed
/// hash would resolve to the wrong object, or to none, in a way that
/// is hard to debug from a log line.
pub fn parse_hash_hex(text: &[u8]) -> Option<[u8; PACKAGE_HASH_BYTES]> {
    if text.len() != PACKAGE_HASH_BYTES * 2 {
        return None;
    }
    let mut out = [0u8; PACKAGE_HASH_BYTES];
    let mut index = 0usize;
    while index < PACKAGE_HASH_BYTES {
        let high = hex_value(text[index * 2])?;
        let low = hex_value(text[index * 2 + 1])?;
        out[index] = (high << 4) | low;
        index += 1;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Resolve a package by content hash through an Hxfs client channel.
///
/// The channel must be an attached Hxfs client (the same kind
/// `open:hxfs` hands to any other client); the resolver speaks the
/// native ABI over it and does not need any DriverManager-specific
/// privilege.
pub fn resolve_package(
    hxfs: &Channel,
    hash: &[u8; PACKAGE_HASH_BYTES],
) -> Result<ResolvedPackage, ResolveError> {
    let view = libcanvas::hxfs::open_blob_on(hxfs, hash).map_err(map_open_error)?;
    resolve_from_view(view, *hash)
}

/// Stream an already-opened blob view into a VMO.
///
/// Split out of [`resolve_package`] so a caller driving its own main
/// loop can open the view without blocking (send the request, poll
/// across ticks) and then stream it here. The streaming half is safe
/// to run inline: it talks to a dedicated per-view channel that only
/// this caller holds, so there is no queue of other clients' answers
/// to wait behind.
pub fn resolve_from_view(
    view: libcanvas::hxfs::HxfsBlobView,
    hash: [u8; PACKAGE_HASH_BYTES],
) -> Result<ResolvedPackage, ResolveError> {
    let hash = &hash;
    let len = view.size();
    if len == 0 {
        // A zero-length ELF is never launchable; treat it as
        // corruption rather than handing `spawn_elf_from_vmo` an
        // empty image to reject less informatively.
        return Err(ResolveError::Corrupt);
    }
    if len > MAX_PACKAGE_BYTES {
        return Err(ResolveError::TooLarge);
    }
    let vmo = Vmo::create(len).map_err(|_| ResolveError::OutOfMemory)?;
    let mut offset = 0u64;
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    while offset < len {
        let want = ((len - offset) as usize).min(READ_CHUNK_BYTES);
        let bytes = view
            .read_at(offset, &mut chunk[..want])
            .map_err(ResolveError::Protocol)?;
        if bytes.is_empty() {
            // Short read before the declared end: the service and the
            // index disagree about this object's length, which is a
            // corrupt package, not a transient condition to retry.
            return Err(ResolveError::Corrupt);
        }
        let written = vmo
            .write(offset, bytes)
            .map_err(|_| ResolveError::OutOfMemory)?;
        if written != bytes.len() {
            return Err(ResolveError::OutOfMemory);
        }
        offset += bytes.len() as u64;
    }
    Ok(ResolvedPackage {
        vmo,
        len,
        hash: *hash,
    })
}

/// Classify an open failure into a resolver error.
///
/// Public because a caller that opens the view itself (to avoid
/// blocking its main loop) must classify the failure the same way
/// `resolve_package` would; otherwise "missing" and "corrupt" collapse
/// into one opaque protocol error at exactly the call site that cares
/// about the difference.
pub fn map_open_error(error: ErrorCode) -> ResolveError {
    match error {
        ErrorCode::NotFound => ResolveError::NotFound,
        // The service reports a failed content-hash check as an
        // internal error over the wire (`CorruptObject`); surfacing it
        // as `NotFound` here would hide corruption behind a miss.
        ErrorCode::Internal => ResolveError::Corrupt,
        ErrorCode::ShouldWait => ResolveError::ServiceUnavailable,
        other => ResolveError::Protocol(other),
    }
}

/// One entry of the on-volume package index.
#[derive(Clone, Copy)]
pub struct PackageEntry {
    /// Package name, NUL-free, as it appears in the index.
    name: [u8; 48],
    name_len: usize,
    /// Content hash of the package image.
    pub hash: [u8; PACKAGE_HASH_BYTES],
}

impl PackageEntry {
    /// Package name as text.
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

/// Parse a package index.
///
/// The format is deliberately boring text, one entry per line:
///
/// ```text
/// <name> <64-hex-content-hash>
/// ```
///
/// Blank lines and `#` comments are ignored. A malformed line is
/// skipped rather than failing the whole index: one bad entry must not
/// make every other package unresolvable, and the caller sees a short
/// count.
pub fn parse_package_index(bytes: &[u8], out: &mut [Option<PackageEntry>]) -> usize {
    let mut count = 0usize;
    for line in bytes.split(|&b| b == b'\n') {
        if count >= out.len() {
            break;
        }
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let Some(split) = line.iter().position(|&b| b == b' ') else {
            continue;
        };
        let (name, rest) = line.split_at(split);
        let hash_text = trim(&rest[1..]);
        if name.is_empty() || name.len() > 48 {
            continue;
        }
        let Some(hash) = parse_hash_hex(hash_text) else {
            continue;
        };
        let mut entry = PackageEntry {
            name: [0u8; 48],
            name_len: name.len(),
            hash,
        };
        entry.name[..name.len()].copy_from_slice(name);
        out[count] = Some(entry);
        count += 1;
    }
    count
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_length_lowercase_hash() {
        let text = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let Some(hash) = parse_hash_hex(text) else {
            assert!(false, "a 64-digit hex hash must parse");
            return;
        };
        assert_eq!(hash[0], 0x00);
        assert_eq!(hash[1], 0x11);
        assert_eq!(hash[31], 0xff);
    }

    /// A truncated hash must not resolve to a padded or partial
    /// object; it must not parse at all.
    #[test]
    fn rejects_malformed_hashes() {
        assert!(parse_hash_hex(b"").is_none());
        assert!(parse_hash_hex(b"abcd").is_none());
        // 63 digits.
        assert!(parse_hash_hex(&[b'a'; 63]).is_none());
        // 65 digits.
        assert!(parse_hash_hex(&[b'a'; 65]).is_none());
        // Right length, non-hex byte.
        let mut bad = [b'a'; 64];
        bad[10] = b'z';
        assert!(parse_hash_hex(&bad).is_none());
    }

    #[test]
    fn parses_an_index_and_skips_comments_and_junk() {
        let index = b"# packages\n\
                      driver-host-nvme 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
                      \n\
                      broken-line-without-hash\n\
                      bad-hash deadbeef\n\
                      terminal ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\n";
        let mut entries = [None; 8];
        let count = parse_package_index(index, &mut entries);
        assert_eq!(count, 2, "malformed lines must be skipped, not fatal");
        let Some(first) = entries[0] else {
            assert!(false, "first entry must parse");
            return;
        };
        assert_eq!(first.name(), "driver-host-nvme");
        assert_eq!(first.hash[0], 0x00);
        let Some(second) = entries[1] else {
            assert!(false, "second entry must parse");
            return;
        };
        assert_eq!(second.name(), "terminal");
        assert_eq!(second.hash[0], 0xff);
    }

    /// The index must never write past the caller's array: an
    /// on-volume file decides how many lines there are.
    #[test]
    fn index_parsing_is_bounded_by_the_output_array() {
        let mut line = alloc::vec::Vec::new();
        for index in 0..16 {
            line.extend_from_slice(b"pkg");
            line.extend_from_slice(&[b'0' + index as u8]);
            line.push(b' ');
            line.extend_from_slice(&[b'a'; 64]);
            line.push(b'\n');
        }
        let mut entries = [None; 4];
        let count = parse_package_index(&line, &mut entries);
        assert_eq!(count, 4);
    }
}
