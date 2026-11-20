//! Files and directories over the `Hxfs` service.
//!
//! Two capability shapes reach the filesystem, and both must keep working:
//!
//! * the **service channel** (`CapKind::HxfsService`), which addresses the
//!   namespace by absolute path — what the shell and the coreutils normally
//!   get;
//! * a **scoped directory handle** (`CapKind::HxfsDir`), which can only see
//!   one subtree and resolves paths relative to it — what a sandboxed program
//!   gets.
//!
//! [`File`] hides the difference: it resolves the path against whichever
//! capability exists, then speaks offsets so a writer can seek. The service is
//! the authority for every check; nothing here caches a handle across calls,
//! because a handle's rights are the whole security story.

use alloc::string::String;
use alloc::vec::Vec;

use libcanvas::stdio::{take_cap_handle, CapKind};
use libcanvas::{Channel, Hxfs, HxfsDirectory, HxfsFile};

use crate::error::{Error, ErrorKind, Result};
use crate::io::{Seek, SeekFrom};
use crate::path;

/// The largest directory listing one call will buffer.
pub const LIST_BYTES: usize = 4096;

/// What a directory entry names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// Neither, or a kind this build does not know.
    Other,
}

impl EntryKind {
    /// Parse the `kind` column of a listing line.
    pub fn parse(text: &str) -> Self {
        match text {
            "file" => Self::File,
            "dir" => Self::Dir,
            _ => Self::Other,
        }
    }
}

/// One line of a directory listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Name relative to the directory, not a full path.
    pub name: String,
    /// What the entry is.
    pub kind: EntryKind,
    /// Size in bytes, when the service reported one.
    pub size: Option<u64>,
}

/// Take the granted `Hxfs` service channel, if this process has one.
pub fn service() -> Option<Hxfs> {
    take_cap_handle(CapKind::HxfsService).map(|h| Hxfs::from_channel(Channel::from_handle(h)))
}

/// Take the granted scoped directory handle, if this process has one.
pub fn directory() -> Option<HxfsDirectory> {
    take_cap_handle(CapKind::HxfsDir).map(|h| HxfsDirectory::from_channel(Channel::from_handle(h)))
}

/// True when the process can reach the filesystem at all.
pub fn is_available() -> bool {
    // Taking a handle consumes it, so probe without consuming: the bootstrap
    // keeps the raw value around even after the handle is taken.
    libcanvas::stdio::cap_handle(CapKind::HxfsService).is_some()
        || libcanvas::stdio::cap_handle(CapKind::HxfsDir).is_some()
}

fn open_file(path: &str, create: bool) -> Result<HxfsFile> {
    let normalized = path::normalize(path);
    if let Some(service) = service() {
        return if create {
            service.create_file(&normalized)
        } else {
            service.open_file(&normalized)
        }
        .map_err(Error::from);
    }
    if let Some(root) = directory() {
        let relative = path::relative(&normalized);
        // A scoped handle cannot address `/`, so it must never be asked to.
        if relative.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        return if create {
            root.create_file(relative)
        } else {
            root.open_file(relative)
        }
        .map_err(Error::from);
    }
    Err(Error::capability())
}

fn open_dir(path: &str) -> Result<HxfsDirectory> {
    let normalized = path::normalize(path);
    if let Some(service) = service() {
        return service.open_dir(&normalized).map_err(Error::from);
    }
    if let Some(root) = directory() {
        let relative = path::relative(&normalized);
        if relative.is_empty() {
            return Ok(root);
        }
        return root.open_dir(relative).map_err(Error::from);
    }
    Err(Error::capability())
}

/// An open file with a cursor.
///
/// The service writes at explicit offsets only, so `write` advances the
/// cursor as it goes and `seek` is what makes an append, an overwrite in the
/// middle, or a whole-file rewrite the same operation.
pub struct File {
    inner: HxfsFile,
    position: u64,
}

impl File {
    fn wrap(inner: HxfsFile) -> Self {
        Self { inner, position: 0 }
    }

    /// Open an existing file for reading and writing.
    pub fn open(path: &str) -> Result<Self> {
        open_file(path, false).map(Self::wrap)
    }

    /// Create (or truncate to empty) a file for writing.
    pub fn create(path: &str) -> Result<Self> {
        let file = open_file(path, true)?;
        // `create_file` on an existing name keeps the old bytes; truncating
        // here is what makes `create` mean "start empty" for a caller.
        file.truncate(0).map_err(Error::from)?;
        Ok(Self::wrap(file))
    }

    /// The file's length in bytes, without a cached size.
    pub fn size(&self) -> Result<u64> {
        self.inner.size().map_err(Error::from)
    }

    /// The current cursor.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Read at the cursor and advance it.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = {
            let data = self
                .inner
                .read_at(self.position, buf)
                .map_err(Error::from)?;
            data.len()
        };
        self.position += read as u64;
        Ok(read)
    }

    /// Write at the cursor and advance it.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let written = self
            .inner
            .write_at(self.position, buf)
            .map_err(Error::from)?;
        self.position += written as u64;
        Ok(written)
    }

    /// Read the whole file from the start.
    pub fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let size = usize::try_from(self.size()?).unwrap_or(0);
        let mut out = Vec::with_capacity(size);
        self.position = 0;
        let mut buf = [0u8; 4096];
        while out.len() < size {
            let want = core::cmp::min(buf.len(), size - out.len());
            let n = self.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(out)
    }

    /// Truncate or zero-extend the file.
    pub fn truncate(&mut self, size: u64) -> Result<()> {
        self.inner.truncate(size).map_err(Error::from)?;
        self.position = self.position.min(size);
        Ok(())
    }

    /// Flush to the volume.
    pub fn fsync(&self) -> Result<()> {
        self.inner.fsync().map_err(Error::from)
    }
}

/// `File` is a byte stream, so the `io` traits apply to it as well as the
/// inherent methods; `write_all` and `read_to_end` then work on files and
/// streams with the same code.
impl crate::io::Read for File {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        File::read(self, buf)
    }
}

impl crate::io::Write for File {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        File::write(self, buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.fsync()
    }
}

impl Seek for File {
    fn seek(&mut self, from: SeekFrom) -> Result<u64> {
        let target = match from {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => add_signed(self.position, delta)?,
            SeekFrom::End(delta) => add_signed(self.size()?, delta)?,
        };
        self.position = target;
        Ok(target)
    }
}

fn add_signed(base: u64, delta: i64) -> Result<u64> {
    let target = if delta >= 0 {
        base.checked_add(delta.unsigned_abs())
    } else {
        base.checked_sub(delta.unsigned_abs())
    };
    target.ok_or(Error::new(ErrorKind::InvalidInput))
}

/// Read a whole file.
pub fn read(path: &str) -> Result<Vec<u8>> {
    File::open(path)?.read_to_end()
}

/// Create or replace a file with `data`, then flush it.
pub fn write(path: &str, data: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    let mut remaining = data;
    while !remaining.is_empty() {
        let n = file.write(remaining)?;
        if n == 0 {
            return Err(Error::new(ErrorKind::Io));
        }
        remaining = &remaining[n..];
    }
    file.fsync()
}

/// List a directory.
pub fn list(path: &str) -> Result<Vec<Entry>> {
    let dir = open_dir(path)?;
    let mut raw = [0u8; LIST_BYTES];
    let text = {
        let bytes = dir.list(&mut raw).map_err(Error::from)?;
        String::from_utf8_lossy(bytes).into_owned()
    };
    let mut entries = Vec::new();
    for line in text.lines() {
        let mut columns = line.split_whitespace();
        let Some(name) = columns.next() else {
            continue;
        };
        let kind = EntryKind::parse(columns.next().unwrap_or(""));
        let size = columns.next().and_then(|text| text.parse::<u64>().ok());
        entries.push(Entry {
            name: String::from(name),
            kind,
            size,
        });
    }
    Ok(entries)
}

/// Create a directory.
pub fn create_dir(path: &str) -> Result<HxfsDirectory> {
    let normalized = path::normalize(path);
    if let Some(service) = service() {
        return service.mkdir(&normalized).map_err(Error::from);
    }
    if let Some(root) = directory() {
        let relative = path::relative(&normalized);
        if relative.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        return root.mkdir(relative).map_err(Error::from);
    }
    Err(Error::capability())
}

/// Remove a file.
pub fn remove(path: &str) -> Result<()> {
    let normalized = path::normalize(path);
    if let Some(service) = service() {
        return service.unlink(&normalized).map_err(Error::from);
    }
    if let Some(root) = directory() {
        let relative = path::relative(&normalized);
        if relative.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        return root.unlink(relative).map_err(Error::from);
    }
    Err(Error::capability())
}

/// `(used_bytes, capacity_bytes)` of the volume, when a service reports it.
pub fn volume_bytes() -> Result<(u64, u64)> {
    service()
        .ok_or_else(Error::capability)?
        .volume_info()
        .map_err(Error::from)
}
