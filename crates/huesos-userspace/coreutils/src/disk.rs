//! Block-device plumbing shared by `lsblk`, `df`, `fsck` and `mkfs`.
//!
//! Two shapes of storage exist, and both speak 512-byte sectors:
//!
//! * a **block device channel** (`@caps(block=rw)`), which the kernel hands to
//!   exactly one process and which reports its own geometry;
//! * a **file on the mounted volume**, which is how the test suite and a
//!   developer exercise partitioning and formatting without touching the disk.
//!
//! [`DiskIo`] hides the difference behind `huesos-gpt`'s [`BlockIo512`] trait,
//! which is what the partition-table code, the HxFS probe and `lsblk` all
//! consume. A `DiskIo` opened read-only refuses writes locally, so a tool that
//! forgot to check the capability cannot scribble on the device.

use core::cell::RefCell;

use alloc::format;
use alloc::string::String;
use alloc::vec;

use huesos_gpt::{BlockIo512, LBA_SIZE};
use huesos_hxfs::recovery::BlockStore as HxfsBlockStore;
use huesos_hxfs::{probe_bare_volume, BareVolume, BlockReader as HxfsReader, HxfsError};
use huesos_std::io::{Seek, SeekFrom};
use huesos_std::{fs, io, Error, Result};

use libcanvas::block::BlockDevice;
use libcanvas::stdio::{take_cap_handle, CapKind};
use libcanvas::Channel;

/// HxFS stores 4 KiB blocks; the block services speak 512-byte LBAs.
pub const HXFS_BLOCK_SIZE: usize = 4096;
/// 512-byte LBAs per 4 KiB HxFS block.
pub const LBAS_PER_HXFS_BLOCK: u64 = (HXFS_BLOCK_SIZE / LBA_SIZE) as u64;

/// Backing store behind a [`DiskIo`].
///
/// Both variants live behind a `RefCell` because `huesos-gpt`'s
/// [`BlockIo512::read_lba`] takes `&self`: a partition table must be readable
/// from a shared borrow, and the file cursor or the device channel is the only
/// mutable state involved. Borrows never nest — every accessor takes the cell
/// for the duration of one syscall — so a failed borrow can only mean a bug,
/// and it is reported as an error rather than panicking.
enum Backing {
    /// An image file on the mounted volume.
    File(RefCell<fs::File>),
    /// The process-wide raw block device singleton, plus its hardware block size.
    Device(&'static spin::Mutex<BlockDevice>, u32),
}

/// The block device this process was granted, held for its whole lifetime.
///
/// `take_cap_handle` empties the slot, so taking it once here and lending a
/// locked reference out is what allows a second and third open in the same
/// process (`lsblk`, `df`, `fsck`, `mkfs`) without duplicating the kernel
/// `Channel` endpoint and corrupting the 1:1 `BlockDevice` IPC state.
pub fn block_device() -> Result<&'static spin::Mutex<BlockDevice>> {
    static DEVICE: spin::Once<Option<spin::Mutex<BlockDevice>>> = spin::Once::new();
    DEVICE
        .call_once(|| {
            take_cap_handle(CapKind::BlockDev)
                .and_then(|handle| BlockDevice::from_channel(Channel::from_handle(handle)).ok())
                .map(spin::Mutex::new)
        })
        .as_ref()
        .ok_or_else(Error::capability)
}

/// True when this process has a block device at all.
pub fn has_block_device() -> bool {
    libcanvas::stdio::cap_handle(CapKind::BlockDev).is_some() || block_device().is_ok()
}

/// A 512-byte-sector view of a file or a block device.
pub struct DiskIo {
    backing: Backing,
    total_lbas: u64,
    writable: bool,
    label: String,
}

impl DiskIo {
    /// Open an image file for reading, or for writing when `writable`.
    pub fn open_image(path: &str, writable: bool) -> Result<Self> {
        let file = if writable {
            fs::OpenOptions::new().read(true).write(true).open(path)?
        } else {
            fs::File::open(path)?
        };
        let size = file.size()?;
        Ok(Self {
            backing: Backing::File(RefCell::new(file)),
            total_lbas: size / LBA_SIZE as u64,
            writable,
            label: String::from(path),
        })
    }

    /// Create (or truncate) an image file of exactly `bytes`.
    pub fn create_image(path: &str, bytes: u64) -> Result<Self> {
        let mut file = fs::File::create(path)?;
        file.set_len(bytes)?;
        Ok(Self {
            backing: Backing::File(RefCell::new(file)),
            total_lbas: bytes / LBA_SIZE as u64,
            writable: true,
            label: String::from(path),
        })
    }

    /// Open the block device the process was granted, if any.
    ///
    /// Reuses the process-wide `BlockDevice` singleton under a mutex instead
    /// of duplicating its underlying `Channel` handle (a kernel `Channel` has
    /// exactly two endpoints, so re-running `BlockDevice::from_channel` on a
    /// duplicated endpoint handle would collide on IPC replies).
    pub fn open_device() -> Result<Self> {
        let shared = block_device()?;
        let info = shared.lock().info()?;
        let block_size = info.block_size.max(LBA_SIZE as u32);
        let total_lbas = info.block_count * u64::from(block_size / LBA_SIZE as u32);
        Ok(Self {
            backing: Backing::Device(shared, block_size),
            total_lbas,
            writable: true,
            label: String::from("/dev/nvme0"),
        })
    }

    /// Open `path` as an image, or the granted device when `path` is
    /// `/dev/nvme0`, `/dev/disk` or `None`.
    pub fn open(path: Option<&str>, writable: bool) -> Result<Self> {
        match path {
            None | Some("/dev/nvme0") | Some("/dev/disk") => {
                let mut io = Self::open_device()?;
                io.writable = writable;
                Ok(io)
            }
            Some(path) => Self::open_image(path, writable),
        }
    }

    /// Total capacity in 512-byte LBAs.
    pub const fn total_lbas(&self) -> u64 {
        self.total_lbas
    }

    /// Total capacity in bytes.
    pub const fn capacity_bytes(&self) -> u64 {
        self.total_lbas * LBA_SIZE as u64
    }

    /// True when writes reach the store.
    pub const fn is_writable(&self) -> bool {
        self.writable
    }

    /// The store's name, for output columns.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Bytes per hardware block (512 for image files).
    pub fn hardware_block_size(&self) -> u32 {
        match &self.backing {
            Backing::File(_) => LBA_SIZE as u32,
            Backing::Device(_, block_size) => *block_size,
        }
    }

    /// Read `count` LBAs starting at `lba` into `out`.
    pub fn read(&self, lba: u64, count: u32, out: &mut [u8]) -> Result<()> {
        let bytes = count as usize * LBA_SIZE;
        if out.len() < bytes {
            return Err(Error::new(huesos_std::ErrorKind::InvalidInput));
        }
        if lba.saturating_add(u64::from(count)) > self.total_lbas {
            return Err(Error::new(huesos_std::ErrorKind::InvalidInput));
        }
        match &self.backing {
            Backing::File(file) => {
                let mut file = file
                    .try_borrow_mut()
                    .map_err(|_| Error::new(huesos_std::ErrorKind::Busy))?;
                file.seek(SeekFrom::Start(lba * LBA_SIZE as u64))?;
                let mut filled = 0;
                while filled < bytes {
                    let read = file.read(&mut out[filled..bytes])?;
                    if read == 0 {
                        // Past the end of a sparsely created image: zeros.
                        out[filled..bytes].fill(0);
                        break;
                    }
                    filled += read;
                }
                Ok(())
            }
            Backing::Device(device, block_size) => {
                let ratio = u64::from((*block_size / LBA_SIZE as u32).max(1));
                let hw_lba = lba / ratio;
                let end_lba = lba.saturating_add(u64::from(count));
                let end_hw = end_lba.div_ceil(ratio);
                let hw_count =
                    u32::try_from(end_hw.saturating_sub(hw_lba).max(1)).unwrap_or(u32::MAX);
                let mut scratch = vec![0u8; hw_count as usize * *block_size as usize];
                let mut device = device.lock();
                device.read_blocks(hw_lba, hw_count, &mut scratch)?;
                let skip = ((lba % ratio) as usize) * LBA_SIZE;
                out[..bytes].copy_from_slice(&scratch[skip..skip + bytes]);
                Ok(())
            }
        }
    }

    /// Read one LBA.
    pub fn read_sector(&self, lba: u64) -> Result<[u8; LBA_SIZE]> {
        let mut sector = [0u8; LBA_SIZE];
        self.read(lba, 1, &mut sector)?;
        Ok(sector)
    }

    /// Write `count` LBAs starting at `lba`.
    pub fn write(&mut self, lba: u64, count: u32, data: &[u8]) -> Result<()> {
        if !self.writable {
            return Err(Error::new(huesos_std::ErrorKind::AccessDenied));
        }
        let bytes = count as usize * LBA_SIZE;
        if data.len() < bytes {
            return Err(Error::new(huesos_std::ErrorKind::InvalidInput));
        }
        match &self.backing {
            Backing::File(file) => {
                let mut file = file
                    .try_borrow_mut()
                    .map_err(|_| Error::new(huesos_std::ErrorKind::Busy))?;
                file.seek(SeekFrom::Start(lba * LBA_SIZE as u64))?;
                io::write_all(&mut *file, &data[..bytes])
            }
            Backing::Device(device, block_size) => {
                let ratio = u64::from((*block_size / LBA_SIZE as u32).max(1));
                let hw_lba = lba / ratio;
                let end_lba = lba.saturating_add(u64::from(count));
                let end_hw = end_lba.div_ceil(ratio);
                let hw_count =
                    u32::try_from(end_hw.saturating_sub(hw_lba).max(1)).unwrap_or(u32::MAX);
                let mut scratch = vec![0u8; hw_count as usize * *block_size as usize];
                let mut device = device.lock();
                if !lba.is_multiple_of(ratio) || !end_lba.is_multiple_of(ratio) {
                    // Partial hardware blocks must be read-modify-written so the
                    // neighbouring sectors survive.
                    device.read_blocks(hw_lba, hw_count, &mut scratch)?;
                }
                let skip = ((lba % ratio) as usize) * LBA_SIZE;
                scratch[skip..skip + bytes].copy_from_slice(&data[..bytes]);
                Ok(device.write_blocks(hw_lba, hw_count, &scratch)?)
            }
        }
    }

    /// Write one LBA.
    pub fn write_sector(&mut self, lba: u64, data: &[u8; LBA_SIZE]) -> Result<()> {
        self.write(lba, 1, data)
    }

    /// Flush to the volume or the device.
    pub fn flush(&mut self) -> Result<()> {
        match &self.backing {
            Backing::File(file) => {
                let file = file
                    .try_borrow_mut()
                    .map_err(|_| Error::new(huesos_std::ErrorKind::Busy))?;
                file.fsync()
            }
            Backing::Device(device, _) => {
                let mut device = device.lock();
                Ok(device.flush()?)
            }
        }
    }

    /// Ensure the store is at least `bytes` long (images only).
    pub fn ensure_len(&mut self, bytes: u64) -> Result<()> {
        let Backing::File(file) = &self.backing else {
            return Err(Error::new(huesos_std::ErrorKind::Unsupported));
        };
        let mut file = file
            .try_borrow_mut()
            .map_err(|_| Error::new(huesos_std::ErrorKind::Busy))?;
        if file.size()? >= bytes {
            return Ok(());
        }
        if !self.writable {
            return Err(Error::new(huesos_std::ErrorKind::AccessDenied));
        }
        file.set_len(bytes)?;
        self.total_lbas = bytes / LBA_SIZE as u64;
        Ok(())
    }
}

impl BlockIo512 for DiskIo {
    fn total_lbas(&self) -> u64 {
        self.total_lbas
    }

    fn read_lba(&self, lba: u64, out: &mut [u8; LBA_SIZE]) -> core::result::Result<(), String> {
        self.read(lba, 1, out)
            .map_err(|error| format!("read lba {lba}: {error}"))
    }

    fn write_lba(&mut self, lba: u64, data: &[u8; LBA_SIZE]) -> core::result::Result<(), String> {
        self.write(lba, 1, data)
            .map_err(|error| format!("write lba {lba}: {error}"))
    }

    fn flush(&mut self) -> core::result::Result<(), String> {
        DiskIo::flush(self).map_err(|error| format!("flush: {error}"))
    }
}

/// Adapter from [`DiskIo`] to the 4 KiB reader the HxFS probe wants.
pub struct HxfsProbeIo<'a> {
    /// The 512-byte view.
    pub io: &'a DiskIo,
}

impl HxfsReader for HxfsProbeIo<'_> {
    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        out: &mut [u8],
    ) -> core::result::Result<(), HxfsError> {
        read_4k(self.io, 0, lba, blocks, out)
    }
}

/// Probe a whole store for a bare `HxFS` volume (a "superfloppy").
pub fn probe_hxfs(io: &DiskIo) -> Option<BareVolume> {
    if io.total_lbas() < LBAS_PER_HXFS_BLOCK {
        return None;
    }
    let mut reader = HxfsProbeIo { io };
    probe_bare_volume(&mut reader).ok()
}

/// Probe the HxFS volume that starts at `lba0` of `io`.
pub fn probe_hxfs_at(io: &DiskIo, lba0: u64) -> Option<BareVolume> {
    if lba0 == 0 {
        return probe_hxfs(io);
    }
    let mut reader = HxfsProbeIoAt { io, lba0 };
    probe_bare_volume(&mut reader).ok()
}

/// Adapter that offsets every read by `lba0`, for a partition inside a disk.
struct HxfsProbeIoAt<'a> {
    /// The 512-byte view.
    io: &'a DiskIo,
    /// First LBA of the volume.
    lba0: u64,
}

impl HxfsReader for HxfsProbeIoAt<'_> {
    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        out: &mut [u8],
    ) -> core::result::Result<(), HxfsError> {
        read_4k(self.io, self.lba0, lba, blocks, out)
    }
}

/// Read `blocks` 4 KiB blocks of the volume that starts at `base_lba`.
///
/// One call down to [`DiskIo::read`] covers the whole range: the 512-byte view
/// already knows how to walk a device whose hardware blocks are larger, so the
/// 4 KiB layer never repeats that arithmetic.
fn read_4k(
    io: &DiskIo,
    base_lba: u64,
    lba: u64,
    blocks: u32,
    out: &mut [u8],
) -> core::result::Result<(), HxfsError> {
    let bytes = (blocks as usize)
        .checked_mul(HXFS_BLOCK_SIZE)
        .ok_or(HxfsError::OutOfRange)?;
    if out.len() < bytes {
        return Err(HxfsError::BufferTooSmall);
    }
    let count = u32::try_from(u64::from(blocks) * LBAS_PER_HXFS_BLOCK)
        .map_err(|_| HxfsError::OutOfRange)?;
    let start = base_lba
        .checked_add(
            lba.checked_mul(LBAS_PER_HXFS_BLOCK)
                .ok_or(HxfsError::OutOfRange)?,
        )
        .ok_or(HxfsError::OutOfRange)?;
    io.read(start, count, &mut out[..bytes])
        .map_err(|_| HxfsError::Io)
}

/// The 4 KiB read-write store a structural `fsck` mounts.
///
/// `huesos-hxfs`'s report-only checker is generic over the recovery layer's
/// block store and therefore needs both directions even though the check itself
/// only reads: mounting may replay a recovering journal, and replaying a
/// journal means writing the blocks it replays.
pub struct HxfsStore<'a> {
    /// The 512-byte view, opened writable.
    pub io: &'a mut DiskIo,
    /// First LBA of the volume inside the store.
    pub base_lba: u64,
}

impl HxfsReader for HxfsStore<'_> {
    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        out: &mut [u8],
    ) -> core::result::Result<(), HxfsError> {
        read_4k(self.io, self.base_lba, lba, blocks, out)
    }
}

impl HxfsBlockStore for HxfsStore<'_> {
    fn write_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        input: &[u8],
    ) -> core::result::Result<(), HxfsError> {
        let bytes = (blocks as usize)
            .checked_mul(HXFS_BLOCK_SIZE)
            .ok_or(HxfsError::OutOfRange)?;
        if input.len() < bytes {
            return Err(HxfsError::BufferTooSmall);
        }
        let count = u32::try_from(u64::from(blocks) * LBAS_PER_HXFS_BLOCK)
            .map_err(|_| HxfsError::OutOfRange)?;
        let start = self
            .base_lba
            .checked_add(
                lba.checked_mul(LBAS_PER_HXFS_BLOCK)
                    .ok_or(HxfsError::OutOfRange)?,
            )
            .ok_or(HxfsError::OutOfRange)?;
        self.io
            .write(start, count, &input[..bytes])
            .map_err(|_| HxfsError::Io)
    }

    fn flush(&mut self) -> core::result::Result<(), HxfsError> {
        DiskIo::flush(self.io).map_err(|_| HxfsError::Io)
    }
}

/// `512`, `4.0K`, `1.5M`, `2.0G`: the shape `df -h` and `lsblk` use.
pub fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}K", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

/// Parse `4M`, `512k`, `1024` or `0x200` into bytes.
pub fn parse_size(text: &str) -> Option<u64> {
    let (digits, scale) = match text.as_bytes().last() {
        Some(b'k') | Some(b'K') => (&text[..text.len() - 1], 1024u64),
        Some(b'm') | Some(b'M') => (&text[..text.len() - 1], 1024 * 1024),
        Some(b'g') | Some(b'G') => (&text[..text.len() - 1], 1024 * 1024 * 1024),
        _ => (text, 1),
    };
    let value = match digits.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u64>().ok()?,
    };
    Some(value.saturating_mul(scale))
}

/// A mount point this tool can see, for `lsblk`'s `MOUNTPOINT` column.
pub const HXFS_MOUNT_POINT: &str = "/";
/// Marker for "nothing is mounted here".
pub const NOT_MOUNTED: &str = "-";
/// Marker for "the filesystem type could not be determined".
pub const NO_FSTYPE: &str = "-";
/// The number of partition-table entries a GPT disk carries.
pub const GPT_ENTRIES: usize = 128;
/// Bytes of a GPT entry array.
pub const GPT_ARRAY_BYTES: usize = GPT_ENTRIES * huesos_gpt::GPT_ENTRY_SIZE;
