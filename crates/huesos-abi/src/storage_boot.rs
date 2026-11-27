//! Boot-time storage DMA pool metadata shared from the kernel to init and
//! DriverManager (Stage J.3: no kernel PCI/NVMe descriptors remain here).

/// Magic for the storage boot-info blob: ASCII-ish `HSTG` in little endian.
pub const MAGIC: u32 = 0x4754_5348;
/// Current storage boot-info format version (v2: DMA pool + storage_off only).
pub const VERSION: u16 = 2;
/// Fixed binary header size.
pub const HEADER_BYTES: usize = 32;
/// Maximum encoded blob size.
pub const MAX_ENCODED_BYTES: usize = HEADER_BYTES;

/// Offset of the fixed NVMe DMA window in the boot DMA pool.
pub const NVME_DMA_OFFSET: u64 = 0;
/// Size of the fixed NVMe DMA window.
pub const NVME_DMA_LEN: u64 = 64 * 1024 * 1024;
/// Offset of the fixed virtio-net DMA window.
pub const NET_DMA_OFFSET: u64 = NVME_DMA_OFFSET + NVME_DMA_LEN;
/// Size of the fixed virtio-net DMA window.
pub const NET_DMA_LEN: u64 = 4 * 1024 * 1024;
/// Offset of the fixed WLAN DMA window.
pub const WLAN_DMA_OFFSET: u64 = NET_DMA_OFFSET + NET_DMA_LEN;
/// Size of the fixed WLAN DMA window.
pub const WLAN_DMA_LEN: u64 = 4 * 1024 * 1024;
/// Offset of the fixed xHCI DMA window.
pub const XHCI_DMA_OFFSET: u64 = WLAN_DMA_OFFSET + WLAN_DMA_LEN;
/// Size of the fixed xHCI DMA window.
pub const XHCI_DMA_LEN: u64 = 4 * 1024 * 1024;
/// Offset of the fixed VirtIO-Sound (`driver-host-snd`) DMA window.
pub const AUDIO_DMA_OFFSET: u64 = XHCI_DMA_OFFSET + XHCI_DMA_LEN;
/// Size of the fixed VirtIO-Sound (`driver-host-snd`) DMA window.
pub const AUDIO_DMA_LEN: u64 = 4 * 1024 * 1024;
/// Length of the fixed boot-device portion before live hotplug slices.
pub const STATIC_DMA_POOL_LEN: u64 = AUDIO_DMA_OFFSET + AUDIO_DMA_LEN;
/// Fixed offset of the live hotplug area inside the boot DMA pool.
pub const HOTPLUG_DMA_OFFSET: u64 = STATIC_DMA_POOL_LEN;
/// Size of one live hotplug DMA slice.
pub const HOTPLUG_DMA_SLOT_LEN: u64 = 4 * 1024 * 1024;
/// Number of kernel-defined live hotplug DMA slices.
pub const HOTPLUG_DMA_SLOT_COUNT: usize = 4;
/// Total kernel-reserved DMA pool length, including all live slices.
pub const BOOT_DMA_POOL_LEN: u64 =
    HOTPLUG_DMA_OFFSET + HOTPLUG_DMA_SLOT_LEN * HOTPLUG_DMA_SLOT_COUNT as u64;

/// Storage boot-info header flag: a DMA pool was reserved.
pub const FLAG_DMA_POOL_PRESENT: u32 = 1 << 0;
/// Storage boot-info header flag: `init.storage=off` disabled storage.
pub const FLAG_STORAGE_OFF: u32 = 1 << 1;

/// HBI/kernel command-line token that disables all NVMe/PCI storage
/// discovery and userspace NVMe grants.
///
/// Exact whitespace-delimited match. `init.storage=offx` and
/// unprefixed `storage=off` do not count.
pub const STORAGE_OFF_TOKEN: &[u8] = b"init.storage=off";

/// Whether `cmdline` contains `needle` as a whole whitespace-delimited token.
pub fn cmdline_has_token(cmdline: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    cmdline
        .split(|byte| byte.is_ascii_whitespace())
        .any(|token| token == needle)
}

/// Whether the boot command line requested the storage kill switch.
pub fn storage_off_requested(cmdline: &[u8]) -> bool {
    cmdline_has_token(cmdline, STORAGE_OFF_TOKEN)
}

/// Preallocated boot DMA pool descriptor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DmaPoolInfo {
    /// Physical base address of the reserved DMA pool.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
}

impl DmaPoolInfo {
    /// Whether this descriptor names a non-empty pool.
    pub const fn is_present(&self) -> bool {
        self.base != 0 && self.len != 0
    }
}

/// Decoded storage boot-info (DMA pool reservation + storage kill-switch).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageBootInfo {
    /// Header flags (`FLAG_DMA_POOL_PRESENT`, `FLAG_STORAGE_OFF`).
    pub flags: u32,
    /// Preallocated DMA pool.
    pub dma_pool: DmaPoolInfo,
}

impl StorageBootInfo {
    /// Empty boot-info descriptor.
    pub const fn empty() -> Self {
        Self {
            flags: 0,
            dma_pool: DmaPoolInfo { base: 0, len: 0 },
        }
    }

    /// True if `init.storage=off` was requested.
    pub const fn storage_off(&self) -> bool {
        (self.flags & FLAG_STORAGE_OFF) != 0
    }
}

/// Encode storage boot-info into `out`, returning the number of bytes written.
pub fn encode(info: &StorageBootInfo, out: &mut [u8]) -> Option<usize> {
    if out.len() < HEADER_BYTES {
        return None;
    }
    out[..HEADER_BYTES].fill(0);
    write_u32(out, 0, MAGIC)?;
    write_u16(out, 4, VERSION)?;
    write_u16(out, 6, HEADER_BYTES as u16)?;
    write_u16(out, 8, 0)?;
    write_u16(out, 10, 0)?;
    write_u32(out, 12, info.flags)?;
    write_u64(out, 16, info.dma_pool.base)?;
    write_u64(out, 24, info.dma_pool.len)?;
    Some(HEADER_BYTES)
}

/// Decode a storage boot-info blob.
pub fn decode(bytes: &[u8]) -> Option<StorageBootInfo> {
    if bytes.len() < HEADER_BYTES {
        return None;
    }
    if read_u32(bytes, 0)? != MAGIC || read_u16(bytes, 4)? != VERSION {
        return None;
    }
    let header_bytes = read_u16(bytes, 6)? as usize;
    let entry_bytes = read_u16(bytes, 8)? as usize;
    let count = read_u16(bytes, 10)? as usize;
    if header_bytes != HEADER_BYTES || entry_bytes != 0 || count != 0 {
        return None;
    }
    let mut info = StorageBootInfo::empty();
    info.flags = read_u32(bytes, 12)?;
    if info.flags & !(FLAG_DMA_POOL_PRESENT | FLAG_STORAGE_OFF) != 0 {
        return None;
    }
    info.dma_pool = DmaPoolInfo {
        base: read_u64(bytes, 16)?,
        len: read_u64(bytes, 24)?,
    };
    let has_pool = (info.flags & FLAG_DMA_POOL_PRESENT) != 0;
    if has_pool != info.dma_pool.is_present()
        || (!has_pool && info.dma_pool.base != 0)
        || (has_pool && info.dma_pool.len != BOOT_DMA_POOL_LEN)
        || (has_pool && info.dma_pool.base >= (1u64 << 32))
        || (has_pool
            && info
                .dma_pool
                .base
                .checked_add(info.dma_pool.len)
                .is_none_or(|end| end > (1u64 << 32)))
        || (info.dma_pool.base & 0xFFF) != 0
        || (info.dma_pool.len != 0 && (info.dma_pool.len & 0xFFF) != 0)
        || info.dma_pool.base.checked_add(info.dma_pool.len).is_none()
    {
        return None;
    }
    Some(info)
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) -> Option<()> {
    let bytes = value.to_le_bytes();
    out.get_mut(offset..offset + 2)?.copy_from_slice(&bytes);
    Some(())
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) -> Option<()> {
    let bytes = value.to_le_bytes();
    out.get_mut(offset..offset + 4)?.copy_from_slice(&bytes);
    Some(())
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) -> Option<()> {
    let bytes = value.to_le_bytes();
    out.get_mut(offset..offset + 8)?.copy_from_slice(&bytes);
    Some(())
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

    fn sample() -> StorageBootInfo {
        StorageBootInfo {
            flags: FLAG_DMA_POOL_PRESENT,
            dma_pool: DmaPoolInfo {
                base: 0x1000_0000,
                len: BOOT_DMA_POOL_LEN,
            },
        }
    }

    #[test]
    fn round_trip_storage_boot_info() {
        let info = sample();
        let mut bytes = [0u8; MAX_ENCODED_BYTES];
        let Some(len) = encode(&info, &mut bytes) else {
            assert!(false, "encode must fit fixed buffer");
            return;
        };
        assert_eq!(len, HEADER_BYTES);
        assert_eq!(decode(&bytes[..len]), Some(info));
    }

    #[test]
    fn rejects_bad_magic_and_truncated_entry() {
        let info = sample();
        let mut bytes = [0u8; MAX_ENCODED_BYTES];
        let Some(len) = encode(&info, &mut bytes) else {
            assert!(false, "encode must fit fixed buffer");
            return;
        };
        bytes[0] = 0;
        assert!(decode(&bytes[..len]).is_none());
        let mut bytes = [0u8; MAX_ENCODED_BYTES];
        let Some(len) = encode(&info, &mut bytes) else {
            assert!(false, "encode must fit fixed buffer");
            return;
        };
        assert!(decode(&bytes[..len - 1]).is_none());
    }

    #[test]
    fn storage_off_token_is_exact_and_delimited() {
        assert!(!storage_off_requested(b""));
        assert!(storage_off_requested(b"init.storage=off"));
        assert!(storage_off_requested(
            b"panic_test=1 init.storage=off extable_test=1"
        ));
        assert!(storage_off_requested(b"init.storage=off\n"));
        assert!(!storage_off_requested(b"init.storage=offx"));
        assert!(!storage_off_requested(b"xinit.storage=off"));
        assert!(!storage_off_requested(b"storage=off"));
        assert!(!storage_off_requested(b"init.storage=on"));
        assert!(!storage_off_requested(b"init.storage="));
        assert!(!cmdline_has_token(b"foo bar", b""));
    }

    #[test]
    fn rejects_nonzero_nvme_count() {
        let mut bytes = [0u8; HEADER_BYTES];
        write_u32(&mut bytes, 0, MAGIC);
        write_u16(&mut bytes, 4, VERSION);
        write_u16(&mut bytes, 6, HEADER_BYTES as u16);
        write_u16(&mut bytes, 8, 64);
        write_u16(&mut bytes, 10, 1);
        assert!(decode(&bytes).is_none());
    }

    #[test]
    fn canonical_dma_geometry_is_contiguous() {
        assert_eq!(NVME_DMA_OFFSET, 0);
        assert_eq!(NET_DMA_OFFSET, NVME_DMA_LEN);
        assert_eq!(WLAN_DMA_OFFSET, NET_DMA_OFFSET + NET_DMA_LEN);
        assert_eq!(XHCI_DMA_OFFSET, WLAN_DMA_OFFSET + WLAN_DMA_LEN);
        assert_eq!(AUDIO_DMA_OFFSET, XHCI_DMA_OFFSET + XHCI_DMA_LEN);
        assert_eq!(STATIC_DMA_POOL_LEN, 80 * 1024 * 1024);
        assert_eq!(HOTPLUG_DMA_OFFSET, STATIC_DMA_POOL_LEN);
        assert_eq!(BOOT_DMA_POOL_LEN, 96 * 1024 * 1024);
        assert_eq!(
            BOOT_DMA_POOL_LEN,
            STATIC_DMA_POOL_LEN + HOTPLUG_DMA_SLOT_LEN * HOTPLUG_DMA_SLOT_COUNT as u64
        );
    }

    #[test]
    fn rejects_flag_and_pool_presence_mismatch() {
        let mut bytes = [0u8; MAX_ENCODED_BYTES];
        let info = StorageBootInfo {
            flags: 0,
            dma_pool: DmaPoolInfo {
                base: 0x1000,
                len: 0x1000,
            },
        };
        let Some(len) = encode(&info, &mut bytes) else {
            assert!(false, "encode must fit fixed buffer");
            return;
        };
        assert!(decode(&bytes[..len]).is_none());

        let mut bytes = [0u8; MAX_ENCODED_BYTES];
        let info = StorageBootInfo {
            flags: FLAG_DMA_POOL_PRESENT,
            dma_pool: DmaPoolInfo {
                base: 0x1000,
                len: 0,
            },
        };
        let Some(len) = encode(&info, &mut bytes) else {
            assert!(false, "encode must fit fixed buffer");
            return;
        };
        assert!(decode(&bytes[..len]).is_none());
    }
}
