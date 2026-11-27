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
    /// A symbolic link.
    Symlink,
    /// Neither, or a kind this build does not know.
    Other,
}

impl EntryKind {
    /// Parse the `kind` column of a listing line.
    pub fn parse(text: &str) -> Self {
        match text {
            "file" => Self::File,
            "dir" => Self::Dir,
            "symlink" => Self::Symlink,
            _ => Self::Other,
        }
    }

    /// Parse the HxFS `OBJECT_TYPE_*` discriminant returned by `stat_path`.
    pub fn from_object_type(object_type: u32) -> Self {
        match object_type {
            1 => Self::File,
            2 => Self::Dir,
            3 => Self::Symlink,
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

/// The granted `Hxfs` service channel, if this process has one.
///
/// A capability slot can be *taken* exactly once (`take_cap_handle` swaps the
/// slot for `INVALID_HANDLE`), so the handle is taken here on first use and
/// then lent out. Every call reaching for the slot itself would hand the first
/// caller the capability and every later caller `capability denied` -- which is
/// what a directory walk or a two-step `create` + `write` does on its second
/// call. The handle lives for the rest of the process, as a capability should.
pub fn service() -> Option<&'static Hxfs> {
    static SERVICE: spin::Once<Option<Hxfs>> = spin::Once::new();
    SERVICE
        .call_once(|| {
            take_cap_handle(CapKind::HxfsService)
                .map(|handle| Hxfs::from_channel(Channel::from_handle(handle)))
        })
        .as_ref()
}

/// The granted scoped directory handle, if this process has one.
///
/// Borrowed from the same one-shot slot as [`service`]. Calls are not
/// serialised: the channel speaks one request at a time, so a process that
/// shares it across threads must not issue filesystem requests concurrently.
pub fn directory() -> Option<&'static HxfsDirectory> {
    static DIRECTORY: spin::Once<Option<HxfsDirectory>> = spin::Once::new();
    DIRECTORY
        .call_once(|| {
            take_cap_handle(CapKind::HxfsDir)
                .map(|handle| HxfsDirectory::from_channel(Channel::from_handle(handle)))
        })
        .as_ref()
}

/// True when the process can reach the filesystem at all.
///
/// Answered from the cached handles, so asking does not spend the capability.
pub fn is_available() -> bool {
    service().is_some() || directory().is_some()
}

fn walk_scoped_parent<'a>(
    root: &HxfsDirectory,
    relative: &'a str,
) -> Result<(Option<HxfsDirectory>, &'a str)> {
    let mut parts = relative.split('/').filter(|seg| !seg.is_empty());
    let Some(mut cur_seg) = parts.next() else {
        return Err(Error::new(ErrorKind::InvalidInput));
    };
    let mut current_dir: Option<HxfsDirectory> = None;
    for next_seg in parts {
        let next_dir = match &current_dir {
            Some(dir) => dir.open_dir(cur_seg).map_err(Error::from)?,
            None => root.open_dir(cur_seg).map_err(Error::from)?,
        };
        current_dir = Some(next_dir);
        cur_seg = next_seg;
    }
    Ok((current_dir, cur_seg))
}

enum FileInner {
    Hxfs(HxfsFile),
    UsbFat { rel_path: String },
    Synth(crate::vfs_synth::SynthFile),
}

fn usb_mount_available() -> bool {
    (service().is_some() || directory().is_some()) && crate::usb_fat::shared_registry().is_some()
}

fn open_file(path: &str, create: bool) -> Result<FileInner> {
    let normalized = path::normalize(path);
    if crate::vfs_synth::is_synth_path(&normalized) {
        return crate::vfs_synth::open_file(&normalized).map(FileInner::Synth);
    }
    if usb_mount_available() {
        if normalized == "/mnt" {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        if let Some(sub) = crate::usb_fat::split_usb_mount_path(&normalized) {
            let rel_path = crate::usb_fat::open_existing_or_create(sub, create)?;
            return Ok(FileInner::UsbFat { rel_path });
        }
    }
    if let Some(service) = service() {
        return if create {
            service.create_file(&normalized)
        } else {
            service.open_file(&normalized)
        }
        .map(FileInner::Hxfs)
        .map_err(Error::from);
    }
    if let Some(root) = directory() {
        let relative = path::relative(&normalized);
        // A scoped handle cannot address `/`, so it must never be asked to.
        if relative.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let (parent_opt, leaf) = walk_scoped_parent(root, relative)?;
        let parent = parent_opt.as_ref().unwrap_or(root);
        return if create {
            parent.create_file(leaf)
        } else {
            parent.open_file(leaf)
        }
        .map(FileInner::Hxfs)
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
            // The scoped handle *is* the root: hand the caller its own handle
            // for the same capability rather than pretending `/` is
            // unreachable. Duplicating cannot widen the rights, so an
            // attenuation of the original mask still yields the same subtree.
            let rights =
                huesos_abi::rights::READ | huesos_abi::rights::WRITE | huesos_abi::rights::TRANSFER;
            let handle = root.channel().handle().duplicate(rights)?;
            return Ok(HxfsDirectory::from_channel(Channel::from_handle(handle)));
        }
        let (parent_opt, leaf) = walk_scoped_parent(root, relative)?;
        let parent = parent_opt.as_ref().unwrap_or(root);
        return parent.open_dir(leaf).map_err(Error::from);
    }
    Err(Error::capability())
}

/// An open file with a cursor.
///
/// The service writes at explicit offsets only, so `write` advances the
/// cursor as it goes and `seek` is what makes an append, an overwrite in the
/// middle, or a whole-file rewrite the same operation.
pub struct File {
    inner: FileInner,
    position: u64,
}

impl File {
    fn wrap(inner: FileInner) -> Self {
        Self { inner, position: 0 }
    }

    /// Open an existing file for reading and writing.
    pub fn open(path: &str) -> Result<Self> {
        open_file(path, false).map(Self::wrap)
    }

    /// Create (or truncate to empty) a file for writing.
    pub fn create(path: &str) -> Result<Self> {
        // `create` means "start empty", not "fail on an existing name": the
        // service answers `AlreadyExists` for a name that is already there and
        // the ABI has no code to carry that answer, so an existing file is
        // opened and truncated instead. Without this, creating a file that a
        // previous run left behind looked like a bad request.
        let inner = match open_file(path, false) {
            Ok(inner) => inner,
            Err(error) if error.kind() == ErrorKind::NotFound => open_file(path, true)?,
            Err(error) => return Err(error),
        };
        let mut file = Self::wrap(inner);
        file.truncate(0)?;
        Ok(file)
    }

    /// The file's length in bytes, without a cached size.
    pub fn size(&self) -> Result<u64> {
        match &self.inner {
            FileInner::Hxfs(file) => file.size().map_err(Error::from),
            FileInner::UsbFat { rel_path } => crate::usb_fat::file_size(rel_path),
            FileInner::Synth(synth) => Ok(synth.size()),
        }
    }

    /// The current cursor.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Read at the cursor and advance it.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = match &mut self.inner {
            FileInner::Hxfs(file) => {
                let data = file.read_at(self.position, buf).map_err(Error::from)?;
                data.len()
            }
            FileInner::UsbFat { rel_path } => {
                crate::usb_fat::read_at(rel_path, self.position, buf)?
            }
            FileInner::Synth(synth) => synth.read_at(self.position, buf)?,
        };
        self.position += read as u64;
        Ok(read)
    }

    /// Write at the cursor and advance it.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let written = match &mut self.inner {
            FileInner::Hxfs(file) => {
                let cap = buf.len().min(huesos_abi::hxfs::HXFS_MAX_INLINE_WRITE_BYTES);
                file.write_at(self.position, &buf[..cap])
                    .map_err(Error::from)?
            }
            FileInner::UsbFat { rel_path } => {
                crate::usb_fat::write_at(rel_path, self.position, buf)?
            }
            FileInner::Synth(synth) => synth.write(buf)?,
        };
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

    /// Set the file's length: truncate or zero-extend, like `File::set_len`.
    ///
    /// The service implements `truncate` as "retype the object with this
    /// length", so growing a file leaves the new region zero-filled and the
    /// cursor where it was, which is what `dd seek=` and `hexdump -s` need.
    pub fn set_len(&mut self, size: u64) -> Result<()> {
        match &mut self.inner {
            FileInner::Hxfs(file) => file.truncate(size).map_err(Error::from)?,
            FileInner::UsbFat { rel_path } => crate::usb_fat::truncate(rel_path, size)?,
            FileInner::Synth(synth) => synth.truncate()?,
        }
        self.position = self.position.min(size);
        Ok(())
    }

    /// Truncate or zero-extend the file.
    pub fn truncate(&mut self, size: u64) -> Result<()> {
        self.set_len(size)
    }

    /// Flush to the volume.
    pub fn fsync(&self) -> Result<()> {
        match &self.inner {
            FileInner::Hxfs(file) => file.fsync().map_err(Error::from),
            FileInner::UsbFat { .. } => crate::usb_fat::flush(),
            FileInner::Synth(synth) => synth.fsync(),
        }
    }
}

/// Options for [`OpenOptions::open`], mirroring `std::fs::OpenOptions`.
///
/// The HxFS service has no mode bits — a granted capability *is* the authority,
/// and the service decides whether a write is allowed — so `read`/`write` are
/// honoured as "the caller may issue reads/writes" and the rest are file-level
/// semantics: `create`, `create_new`, `truncate`, `append`.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    create: bool,
    create_new: bool,
    truncate: bool,
    append: bool,
}

impl OpenOptions {
    /// Everything off; set at least `read` or `write`.
    pub const fn new() -> Self {
        Self {
            read: false,
            write: false,
            create: false,
            create_new: false,
            truncate: false,
            append: false,
        }
    }

    /// Allow reads.
    pub const fn read(mut self, enable: bool) -> Self {
        self.read = enable;
        self
    }

    /// Allow writes.
    pub const fn write(mut self, enable: bool) -> Self {
        self.write = enable;
        self
    }

    /// Create the file if it is missing.
    pub const fn create(mut self, enable: bool) -> Self {
        self.create = enable;
        self
    }

    /// Create the file, failing if it already exists.
    pub const fn create_new(mut self, enable: bool) -> Self {
        self.create_new = enable;
        self
    }

    /// Start with an empty file.
    pub const fn truncate(mut self, enable: bool) -> Self {
        self.truncate = enable;
        self
    }

    /// Start the cursor at the end, so writes append.
    pub const fn append(mut self, enable: bool) -> Self {
        self.append = enable;
        self
    }

    /// Open `path` with these options.
    pub fn open(&self, path: &str) -> Result<File> {
        if !self.read && !self.write {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        if self.truncate && !self.write {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        if self.create_new {
            let mut file = match open_file(path, true) {
                Ok(file) => File::wrap(file),
                Err(error) => {
                    if error.kind() == ErrorKind::InvalidInput && exists(path) {
                        return Err(Error::new(ErrorKind::AlreadyExists));
                    }
                    return Err(error);
                }
            };
            if self.append {
                let end = file.size()?;
                let _ = file.seek(SeekFrom::Start(end))?;
            }
            return Ok(file);
        }
        let mut file = if self.create {
            match open_file(path, false) {
                Ok(file) => File::wrap(file),
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    File::wrap(open_file(path, true)?)
                }
                Err(error) => return Err(error),
            }
        } else {
            File::wrap(open_file(path, false)?)
        };
        if self.truncate {
            file.set_len(0)?;
        }
        if self.append {
            let end = file.size()?;
            let _ = file.seek(SeekFrom::Start(end))?;
        }
        Ok(file)
    }
}

impl File {
    /// Open `path` with `options`.
    pub fn options(path: &str, options: &OpenOptions) -> Result<Self> {
        options.open(path)
    }

    /// Start the cursor at `position` without reading.
    pub fn rewind_to(&mut self, position: u64) -> Result<u64> {
        self.seek(SeekFrom::Start(position))
    }
}

/// What a path names, without opening it for I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    /// Persistent object identifier (`0` if unknown).
    pub object_id: u64,
    /// File size in bytes; `0` for a directory.
    pub len: u64,
    /// File, directory, or symbolic link.
    pub kind: EntryKind,
    /// POSIX mode bits (12-bit `0o7777`).
    pub mode: u32,
    /// Last modification timestamp in nanoseconds.
    pub modified_unix_ns: i64,
}

impl Metadata {
    /// True for a directory.
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, EntryKind::Dir)
    }

    /// True for a regular file.
    pub fn is_file(&self) -> bool {
        matches!(self.kind, EntryKind::File)
    }

    /// True for a symbolic link.
    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, EntryKind::Symlink)
    }

    /// Size in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// POSIX mode bits (`0o7777`).
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// True when the object is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Look up `path` following symlinks (`stat`), and report its metadata.
pub fn metadata(path: &str) -> Result<Metadata> {
    metadata_inner(path, true)
}

/// Look up `path` without following a final symlink (`lstat`), and report its metadata.
pub fn symlink_metadata(path: &str) -> Result<Metadata> {
    metadata_inner(path, false)
}

fn metadata_inner(path: &str, follow_final: bool) -> Result<Metadata> {
    let normalized = path::normalize(path);
    if crate::vfs_synth::is_synth_path(&normalized) {
        return crate::vfs_synth::metadata(&normalized);
    }
    if usb_mount_available() {
        if normalized == "/mnt" {
            return Ok(Metadata {
                object_id: 0,
                len: 0,
                kind: EntryKind::Dir,
                mode: 0o755,
                modified_unix_ns: 0,
            });
        }
        if let Some(sub) = crate::usb_fat::split_usb_mount_path(&normalized) {
            return crate::usb_fat::metadata(sub);
        }
    }
    let raw = if let Some(service) = service() {
        service
            .stat_path(&normalized, follow_final)
            .map_err(Error::from)?
    } else if let Some(root) = directory() {
        let rel = path::relative(&normalized);
        let target = if rel.is_empty() { "." } else { rel };
        root.stat_path(target, follow_final).map_err(Error::from)?
    } else {
        return Err(Error::capability());
    };
    Ok(Metadata {
        object_id: raw.object_id,
        len: raw.size,
        kind: EntryKind::from_object_type(raw.object_type),
        mode: raw.mode,
        modified_unix_ns: raw.modified_unix_ns,
    })
}

/// True when `path` exists (following symlinks).
pub fn exists(path: &str) -> bool {
    metadata(path).is_ok()
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

/// Handle returned by [`create_dir`] for optional directory `fsync`.
pub struct CreatedDir {
    inner: Option<HxfsDirectory>,
}

impl CreatedDir {
    /// Flush newly created directory metadata to backing storage.
    pub fn fsync(&self) -> Result<()> {
        match &self.inner {
            Some(dir) => dir.fsync().map_err(Error::from),
            None => crate::usb_fat::flush(),
        }
    }
}

/// List a directory.
pub fn list(path: &str) -> Result<Vec<Entry>> {
    let normalized = path::normalize(path);
    if crate::vfs_synth::is_synth_path(&normalized) {
        return crate::vfs_synth::list(&normalized);
    }
    if usb_mount_available() {
        if normalized == "/mnt" {
            let mut out = Vec::new();
            if crate::usb_fat::is_mounted() {
                out.push(Entry {
                    name: String::from("usb0"),
                    kind: EntryKind::Dir,
                    size: None,
                });
            }
            return Ok(out);
        }
        if let Some(sub) = crate::usb_fat::split_usb_mount_path(&normalized) {
            return crate::usb_fat::list(sub);
        }
    }
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
pub fn create_dir(path: &str) -> Result<CreatedDir> {
    let normalized = path::normalize(path);
    if usb_mount_available() {
        if normalized == "/mnt" {
            return Err(Error::new(ErrorKind::AlreadyExists));
        }
        if let Some(sub) = crate::usb_fat::split_usb_mount_path(&normalized) {
            crate::usb_fat::create_dir(sub)?;
            return Ok(CreatedDir { inner: None });
        }
    }
    if let Some(service) = service() {
        return service
            .mkdir(&normalized)
            .map(|dir| CreatedDir { inner: Some(dir) })
            .map_err(Error::from);
    }
    if let Some(root) = directory() {
        let relative = path::relative(&normalized);
        if relative.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let (parent_opt, leaf) = walk_scoped_parent(root, relative)?;
        let parent = parent_opt.as_ref().unwrap_or(root);
        return parent
            .mkdir(leaf)
            .map(|dir| CreatedDir { inner: Some(dir) })
            .map_err(Error::from);
    }
    Err(Error::capability())
}

/// Remove a file or empty directory.
pub fn remove(path: &str) -> Result<()> {
    let normalized = path::normalize(path);
    if usb_mount_available() {
        if normalized == "/mnt" {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        if let Some(sub) = crate::usb_fat::split_usb_mount_path(&normalized) {
            return crate::usb_fat::remove(sub);
        }
    }
    if let Some(service) = service() {
        return service.unlink(&normalized).map_err(Error::from);
    }
    if let Some(root) = directory() {
        let relative = path::relative(&normalized);
        if relative.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let (parent_opt, leaf) = walk_scoped_parent(root, relative)?;
        let parent = parent_opt.as_ref().unwrap_or(root);
        return parent.unlink(leaf).map_err(Error::from);
    }
    Err(Error::capability())
}

/// Rename a file, directory, or symlink within the granted namespace.
pub fn rename(from: &str, to: &str) -> Result<()> {
    let from_norm = path::normalize(from);
    let to_norm = path::normalize(to);
    if usb_mount_available() {
        match (
            crate::usb_fat::split_usb_mount_path(&from_norm),
            crate::usb_fat::split_usb_mount_path(&to_norm),
        ) {
            (Some(from_sub), Some(to_sub)) => return crate::usb_fat::rename(from_sub, to_sub),
            (Some(_), None) | (None, Some(_)) => {
                return Err(Error::new(ErrorKind::InvalidInput));
            }
            (None, None) => {}
        }
    }
    if let Some(service) = service() {
        return service.rename(&from_norm, &to_norm).map_err(Error::from);
    }
    if let Some(root) = directory() {
        let from_rel = path::relative(&from_norm);
        let to_rel = path::relative(&to_norm);
        if from_rel.is_empty() || to_rel.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        return root.rename(from_rel, to_rel).map_err(Error::from);
    }
    Err(Error::capability())
}

/// Create a symbolic link at `link_path` pointing to `target`.
pub fn symlink(target: &str, link_path: &str) -> Result<()> {
    let norm_link = path::normalize(link_path);
    if let Some(service) = service() {
        return service.symlink(&norm_link, target).map_err(Error::from);
    }
    if let Some(root) = directory() {
        let rel_link = path::relative(&norm_link);
        if rel_link.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        return root.symlink(rel_link, target).map_err(Error::from);
    }
    Err(Error::capability())
}

/// Read the target of a symbolic link.
pub fn read_link(path: &str) -> Result<String> {
    let mut buf = [0u8; huesos_abi::hxfs::HXFS_MAX_PATH_BYTES];
    if let Some(service) = service() {
        let normalized = path::normalize(path);
        let s = service
            .readlink(&normalized, &mut buf)
            .map_err(Error::from)?;
        return Ok(String::from(s));
    }
    if let Some(root) = directory() {
        let normalized = path::normalize(path);
        let rel = path::relative(&normalized);
        if rel.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let s = root.readlink(rel, &mut buf).map_err(Error::from)?;
        return Ok(String::from(s));
    }
    Err(Error::capability())
}

/// Update POSIX mode bits (`0o7777`) on `path`.
pub fn set_permissions(path: &str, mode: u32) -> Result<()> {
    let normalized = path::normalize(path);
    if usb_mount_available()
        && (normalized == "/mnt" || crate::usb_fat::split_usb_mount_path(&normalized).is_some())
    {
        return Ok(());
    }
    if let Some(service) = service() {
        return service
            .set_attr(&normalized, Some(mode), None, true)
            .map_err(Error::from);
    }
    if let Some(root) = directory() {
        let normalized = path::normalize(path);
        let rel = path::relative(&normalized);
        let target = if rel.is_empty() { "." } else { rel };
        return root
            .set_attr(target, Some(mode), None, true)
            .map_err(Error::from);
    }
    Err(Error::capability())
}

/// Query filesystem capacity and object statistics (`StatFs`).
pub fn stat_fs() -> Result<huesos_abi::hxfs::HxfsStatFsInfo> {
    if let Some(service) = service() {
        return service.stat_fs().map_err(Error::from);
    }
    if let Some(root) = directory() {
        return root.stat_fs().map_err(Error::from);
    }
    Err(Error::capability())
}

/// Publish any dirty mutations on the volume checkpoint.
pub fn sync_all() -> Result<()> {
    if let Some(service) = service() {
        return service.checkpoint().map_err(Error::from);
    }
    if let Some(root) = directory() {
        return root.fsync().map_err(Error::from);
    }
    Err(Error::capability())
}

/// Bytes every regular file reachable from `root` holds, added up.
///
/// HxFS reports a size with every directory entry, so this costs one round
/// trip per directory and no per-file lookup. Nothing is cached: the walk sees
/// the volume as it is now, which is what a usage report is supposed to mean.
/// Depth is capped so a malformed tree cannot spin here forever.
pub fn used_bytes(root: &str) -> Result<u64> {
    /// Deepest tree this walk will descend.
    const MAX_DEPTH: usize = 64;
    let normalized = path::normalize(root);
    let mut total = 0u64;
    let mut pending = alloc::vec![(normalized.clone(), 0usize)];
    while let Some((dir, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        // A subtree the caller cannot read contributes nothing to the total;
        // only the root itself has to be readable for the answer to mean
        // anything.
        let entries = match list(&dir) {
            Ok(entries) => entries,
            Err(error) if dir == normalized => return Err(error),
            Err(_) => continue,
        };
        for entry in entries {
            match entry.kind {
                EntryKind::Dir => pending.push((path::join(&dir, &entry.name), depth + 1)),
                _ => total = total.saturating_add(entry.size.unwrap_or(0)),
            }
        }
    }
    Ok(total)
}
