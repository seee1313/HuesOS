//! The read-only boot filesystem.
//!
//! Every program that is not itself in `BOOTFS` is loaded from there: the image
//! is one VMO laid out as a header followed by fixed-size entries that point at
//! ELF blobs inside the same VMO. The shell resolves `/bin/ls` that way, and so
//! does [`crate::process::Command`].
//!
//! The format is deliberately trivial (a header, then 216-byte records) because
//! it is written by the kernel's build script and read by the first processes
//! before a filesystem service exists.
//!
//! ```text
//! offset 0   magic "HBOOTFS1"
//! offset 8   u32 entry count
//! offset 12  u32 reserved
//! offset 16  entry 0: path[192] | offset u64 | length u64 | flags u64
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use libcanvas::stdio::{take_cap_handle, CapKind};
use libcanvas::Vmo;

use crate::error::{Error, ErrorKind, Result};

/// Bytes of the boot filesystem header.
pub const HEADER_SIZE: u64 = 16;
/// Bytes per directory entry.
pub const ENTRY_SIZE: u64 = 216;
/// Bytes reserved for a path inside an entry.
pub const PATH_SIZE: usize = 192;
/// Magic identifying a boot filesystem image.
pub const MAGIC: &[u8; 8] = b"HBOOTFS1";

/// One file in the boot filesystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Absolute path inside the image, e.g. `/bin/ls.elf`.
    pub path: String,
    /// Byte offset of the blob inside the image VMO.
    pub offset: u64,
    /// Byte length of the blob.
    pub length: u64,
}

/// A parsed boot filesystem.
pub struct BootFs {
    image: Vmo,
    entries: Vec<Entry>,
}

impl BootFs {
    /// Wrap an image VMO, reading its directory.
    pub fn new(image: Vmo) -> Result<Self> {
        let mut header = [0u8; HEADER_SIZE as usize];
        image.read(0, &mut header).map_err(Error::from)?;
        if &header[..8] != MAGIC {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let count = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let mut entries = Vec::with_capacity(count as usize);
        let mut raw = [0u8; ENTRY_SIZE as usize];
        for index in 0..count {
            let at = HEADER_SIZE + u64::from(index) * ENTRY_SIZE;
            if image.read(at, &mut raw).map_err(Error::from)? != raw.len() {
                break;
            }
            let path_len = raw[..PATH_SIZE]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(PATH_SIZE);
            let path = match core::str::from_utf8(&raw[..path_len]) {
                Ok(path) => String::from(path),
                Err(_) => continue,
            };
            let meta = &raw[PATH_SIZE..];
            let mut word = [0u8; 8];
            word.copy_from_slice(&meta[..8]);
            let offset = u64::from_le_bytes(word);
            word.copy_from_slice(&meta[8..16]);
            let length = u64::from_le_bytes(word);
            entries.push(Entry {
                path,
                offset,
                length,
            });
        }
        Ok(Self { image, entries })
    }

    /// Take the process' read-only boot filesystem capability, if it has one.
    pub fn from_capability() -> Option<BootFs> {
        let handle = take_cap_handle(CapKind::BootfsRo)?;
        BootFs::new(Vmo::from_handle(handle)).ok()
    }

    /// The image VMO, which the loader needs for the dynamic linker.
    pub fn image(&self) -> &Vmo {
        &self.image
    }

    /// A duplicate of the image, for handing to a child process.
    pub fn duplicate_image(&self) -> Result<Vmo> {
        self.image
            .duplicate(libcanvas::rights::READ | libcanvas::rights::TRANSFER)
            .map_err(Error::from)
    }

    /// Every entry, in image order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Look an entry up by path.
    pub fn find(&self, path: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.path == path)
    }

    /// Resolve `name` the way the shell does: an absolute path first, then
    /// `/bin/<name>` and `/bin/<name>.elf`.
    pub fn resolve(&self, name: &str) -> Option<&Entry> {
        if name.starts_with('/') {
            if let Some(entry) = self.find(name) {
                return Some(entry);
            }
            // `/bin/ls` and `/bin/ls.elf` name the same file.
            let with_suffix = alloc::format!("{name}.elf");
            return self.find(&with_suffix);
        }
        let direct = alloc::format!("/bin/{name}");
        if let Some(entry) = self.find(&direct) {
            return Some(entry);
        }
        let with_suffix = alloc::format!("{direct}.elf");
        self.find(&with_suffix)
    }

    /// Every `/bin` program in the image, sorted.
    pub fn programs(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .entries
            .iter()
            .filter_map(|entry| entry.path.strip_prefix("/bin/"))
            .collect();
        names.sort_unstable();
        names
    }
}

/// Read `path` out of a boot filesystem image as a byte vector.
///
/// Only used by tools that want the bytes rather than a VMO handle (`hexdump`,
/// `mkfs`'s "is this a real program" checks); the loader path uses the VMO.
pub fn read_file(bootfs: &BootFs, path: &str) -> Result<Vec<u8>> {
    let entry = bootfs.find(path).ok_or(Error::new(ErrorKind::NotFound))?;
    let mut bytes = alloc::vec![0u8; entry.length as usize];
    let read = bootfs
        .image()
        .read(entry.offset, &mut bytes)
        .map_err(Error::from)?;
    bytes.truncate(read);
    Ok(bytes)
}
