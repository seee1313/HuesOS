//! Transparent FAT16/FAT32 USB flash drive mount at `/mnt/usb0`.
//!
//! Connects lazily to `/dev/block/usb0` (`open:block:usb` on the granted
//! `DriverManager` registry channel) and mounts the volume with
//! [`huesos_fat::FatFileSystem::mount_auto`] (GPT, MBR, or raw superfloppy).

use alloc::string::String;
use alloc::vec::Vec;

use huesos_abi::auxv::caps_mask;
use huesos_fat::{BlockDevice as FatBlockTrait, DriverError, FatFileSystem};
use libcanvas::block::BlockDevice as AsyncBlockClient;
use libcanvas::stdio::{caps_mask as proc_caps_mask, take_cap_handle, CapKind};
use libcanvas::Channel;

use crate::error::{Error, ErrorKind, Result};
use crate::fs::{Entry, EntryKind, Metadata};

/// Canonical mount point for the primary USB Mass Storage volume.
pub const USB0_MOUNT_POINT: &str = "/mnt/usb0";

struct UsbSectorAdapter<'a> {
    dev: &'a spin::Mutex<AsyncBlockClient>,
}

impl FatBlockTrait for UsbSectorAdapter<'_> {
    fn read_sector(&self, sector: u32, buf: &mut [u8]) -> core::result::Result<(), DriverError> {
        if buf.len() != 512 {
            return Err(DriverError::InvalidSector);
        }
        self.dev
            .lock()
            .read_blocks(u64::from(sector), 1, buf)
            .map_err(|_| DriverError::ReadError)
    }

    fn write_sector(&self, sector: u32, buf: &[u8]) -> core::result::Result<(), DriverError> {
        if buf.len() != 512 {
            return Err(DriverError::InvalidSector);
        }
        self.dev
            .lock()
            .write_blocks(u64::from(sector), 1, buf)
            .map_err(|_| DriverError::WriteError)
    }

    fn sector_size(&self) -> u32 {
        512
    }
}

fn require_ro_caps() -> Result<()> {
    let mask = proc_caps_mask();
    if (mask & caps_mask::HXFS_RO) == 0 || (mask & caps_mask::QUERY_RO) == 0 {
        return Err(Error::capability());
    }
    Ok(())
}

fn require_rw_caps() -> Result<()> {
    require_ro_caps()?;
    if (proc_caps_mask() & caps_mask::HXFS_RW) == 0 {
        return Err(Error::capability());
    }
    Ok(())
}

/// Shared lazy `DriverManager` registry channel for VFS/block discovery.
pub fn shared_registry() -> Option<&'static spin::Mutex<Channel>> {
    static REG: spin::Once<Option<spin::Mutex<Channel>>> = spin::Once::new();
    if (proc_caps_mask() & caps_mask::QUERY_RO) == 0 {
        return None;
    }
    REG.call_once(|| {
        take_cap_handle(CapKind::Registry).map(|h| spin::Mutex::new(Channel::from_handle(h)))
    })
    .as_ref()
}

/// Shared lazy `/dev/block/usb0` client for this process.
pub fn usb_block_device() -> Result<&'static spin::Mutex<AsyncBlockClient>> {
    static USB_DEV: spin::Once<Option<spin::Mutex<AsyncBlockClient>>> = spin::Once::new();
    let reg = shared_registry().ok_or_else(Error::capability)?;
    USB_DEV
        .call_once(|| {
            let guard = reg.lock();
            AsyncBlockClient::open_usb(&guard).ok().map(spin::Mutex::new)
        })
        .as_ref()
        .ok_or(Error::new(ErrorKind::NotFound))
}

/// True when `/dev/block/usb0` is online and carries a mountable FAT16/FAT32 volume.
pub fn is_mounted() -> bool {
    if require_ro_caps().is_err() {
        return false;
    }
    let Ok(dev) = usb_block_device() else {
        return false;
    };
    let adapter = UsbSectorAdapter { dev };
    FatFileSystem::mount_auto(&adapter).is_ok()
}

/// Split normalized path into a relative path inside `/mnt/usb0` if targeted.
pub fn split_usb_mount_path(normalized: &str) -> Option<&str> {
    if normalized == USB0_MOUNT_POINT {
        Some("/")
    } else {
        normalized.strip_prefix("/mnt/usb0/")
    }
}

fn to_rel_fat_path(sub: &str) -> String {
    if sub.is_empty() || sub == "/" {
        String::from("/")
    } else if sub.starts_with('/') {
        String::from(sub)
    } else {
        let mut s = String::with_capacity(1 + sub.len());
        s.push('/');
        s.push_str(sub);
        s
    }
}

fn map_fat_err(err: DriverError) -> Error {
    match err {
        DriverError::FileNotFound => Error::new(ErrorKind::NotFound),
        DriverError::AlreadyExists => Error::new(ErrorKind::AlreadyExists),
        DriverError::NotADirectory
        | DriverError::IsADirectory
        | DriverError::DirectoryNotEmpty
        | DriverError::PathTooLong
        | DriverError::InvalidPath
        | DriverError::BufferTooSmall => Error::new(ErrorKind::InvalidInput),
        DriverError::DiskFull => Error::new(ErrorKind::NoMemory),
        DriverError::ReadError
        | DriverError::WriteError
        | DriverError::InvalidSector
        | DriverError::InvalidFat => Error::new(ErrorKind::Io),
    }
}

type FatResult<T> = core::result::Result<T, DriverError>;

fn with_fat<R>(
    write: bool,
    f: impl FnOnce(&FatFileSystem<'_, UsbSectorAdapter<'_>>) -> FatResult<R>,
) -> Result<R> {
    if write {
        require_rw_caps()?;
    } else {
        require_ro_caps()?;
    }
    let dev = usb_block_device()?;
    let adapter = UsbSectorAdapter { dev };
    let fs = FatFileSystem::mount_auto(&adapter).map_err(map_fat_err)?;
    f(&fs).map_err(map_fat_err)
}

pub(crate) fn open_existing_or_create(sub: &str, create: bool) -> Result<String> {
    let rel = to_rel_fat_path(sub);
    if create {
        with_fat(true, |fs| match fs.stat(&rel) {
            Ok(info) if info.is_dir => Err(DriverError::IsADirectory),
            Ok(_) => Err(DriverError::AlreadyExists),
            Err(DriverError::FileNotFound) => fs.create_file(&rel),
            Err(e) => Err(e),
        })?;
    } else {
        with_fat(false, |fs| {
            let info = fs.stat(&rel)?;
            if info.is_dir {
                return Err(DriverError::IsADirectory);
            }
            Ok(())
        })?;
    }
    Ok(rel)
}

pub(crate) fn file_size(rel: &str) -> Result<u64> {
    with_fat(false, |fs| fs.file_size(rel))
}

pub(crate) fn read_at(rel: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
    with_fat(false, |fs| fs.read_at(rel, offset, buf))
}

pub(crate) fn write_at(rel: &str, offset: u64, data: &[u8]) -> Result<usize> {
    with_fat(true, |fs| fs.write_at(rel, offset, data))
}

pub(crate) fn truncate(rel: &str, size: u64) -> Result<()> {
    with_fat(true, |fs| fs.truncate(rel, size))
}

pub(crate) fn flush() -> Result<()> {
    require_ro_caps()?;
    let dev = usb_block_device()?;
    let mut guard = dev.lock();
    guard.flush().map_err(Error::from)
}

pub(crate) fn metadata(sub: &str) -> Result<Metadata> {
    let rel = to_rel_fat_path(sub);
    let info = with_fat(false, |fs| fs.stat(&rel))?;
    Ok(Metadata {
        object_id: u64::from(info.first_cluster),
        len: if info.is_dir { 0 } else { u64::from(info.size) },
        kind: if info.is_dir {
            EntryKind::Dir
        } else {
            EntryKind::File
        },
        mode: if info.is_dir { 0o755 } else { 0o644 },
        modified_unix_ns: 0,
    })
}

pub(crate) fn list(sub: &str) -> Result<Vec<Entry>> {
    let rel = to_rel_fat_path(sub);
    let items = with_fat(false, |fs| fs.list_dir(&rel))?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(Entry {
            name: item.name,
            kind: if item.is_dir {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            size: if item.is_dir {
                None
            } else {
                Some(u64::from(item.size))
            },
        });
    }
    Ok(out)
}

pub(crate) fn create_dir(sub: &str) -> Result<()> {
    let rel = to_rel_fat_path(sub);
    with_fat(true, |fs| fs.mkdir(&rel))
}

pub(crate) fn remove(sub: &str) -> Result<()> {
    let rel = to_rel_fat_path(sub);
    with_fat(true, |fs| fs.unlink(&rel))
}

pub(crate) fn rename(from_sub: &str, to_sub: &str) -> Result<()> {
    let from_rel = to_rel_fat_path(from_sub);
    let to_rel = to_rel_fat_path(to_sub);
    with_fat(true, |fs| fs.rename(&from_rel, &to_rel))
}

/// Return `(total_bytes, used_bytes, avail_bytes, fs_type)` for `/mnt/usb0` if online.
pub fn stat_fs() -> Option<(u64, u64, u64, &'static str)> {
    let (total, free, kind) = with_fat(false, |fs| fs.volume_stats()).ok()?;
    Some((total, total.saturating_sub(free), free, kind))
}
