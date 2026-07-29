//! Boot-time storage hardware metadata shared from the kernel to init and
//! DriverManager.
//!
//! This is intentionally small and append-only. The kernel performs the very
//! early, platform-specific discovery that cannot be delegated yet (legacy PCI
//! config-space access and the preallocated DMA pool reservation), serializes a
//! bounded descriptor VMO, and userspace consumes it to mint/forward ordinary
//! Resource handles. The NVMe driver still runs in userspace.

/// Magic for the storage boot-info blob: ASCII-ish `HSTG` in little endian.
pub const MAGIC: u32 = 0x4754_5348;
/// Current storage boot-info format version.
pub const VERSION: u16 = 1;
/// Maximum NVMe PCI functions described in one boot-info blob.
pub const MAX_NVME_FUNCTIONS: usize = 4;
/// Fixed binary header size.
pub const HEADER_BYTES: usize = 32;
/// Fixed binary NVMe entry size.
pub const NVME_ENTRY_BYTES: usize = 64;
/// Maximum encoded blob size for version 1.
pub const MAX_ENCODED_BYTES: usize = HEADER_BYTES + MAX_NVME_FUNCTIONS * NVME_ENTRY_BYTES;

/// Storage boot-info header flag: a DMA pool was reserved.
pub const FLAG_DMA_POOL_PRESENT: u32 = 1 << 0;
/// NVMe entry flag: legacy INTx line is present in `irq_line`.
pub const NVME_FLAG_INTX_PRESENT: u32 = 1 << 0;
/// NVMe entry flag: MSI capability was present in PCI config space.
pub const NVME_FLAG_MSI_PRESENT: u32 = 1 << 1;
/// NVMe entry flag: MSI-X capability was present in PCI config space.
pub const NVME_FLAG_MSIX_PRESENT: u32 = 1 << 2;

/// Preallocated boot DMA pool descriptor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DmaPoolInfo {
    /// Device-visible physical base address.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
}

impl DmaPoolInfo {
    /// Whether this descriptor names a non-empty pool.
    pub const fn is_present(&self) -> bool {
        self.len != 0
    }
}

/// One discovered NVMe PCI function.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NvmeBootFunction {
    /// PCI bus number.
    pub bus: u8,
    /// PCI device number.
    pub device: u8,
    /// PCI function number.
    pub function: u8,
    /// PCI interrupt pin (1=A, 2=B, ...), zero when absent.
    pub interrupt_pin: u8,
    /// PCI vendor ID.
    pub vendor_id: u16,
    /// PCI device ID.
    pub device_id: u16,
    /// NVMe BAR0 physical base.
    pub bar0_base: u64,
    /// NVMe BAR0 byte length.
    pub bar0_len: u64,
    /// Legacy IRQ line, or `0xff` when firmware did not provide one.
    pub irq_line: u32,
    /// Bitmask of [`NVME_FLAG_INTX_PRESENT`], [`NVME_FLAG_MSI_PRESENT`],
    /// and [`NVME_FLAG_MSIX_PRESENT`].
    pub flags: u32,
    /// Number of MSI vectors requested/supported by the device capability.
    pub msi_vector_count: u16,
    /// MSI-X table size from the capability, if present.
    pub msix_table_size: u16,
    /// MSI-X table BAR indicator register (BIR), if present.
    pub msix_table_bir: u8,
    /// Reserved for alignment / future flags. Must be zero in v1.
    pub reserved0: u8,
    /// MSI-X table offset within `msix_table_bir`, if present.
    pub msix_table_offset: u32,
}

/// Decoded storage boot-info.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageBootInfo {
    /// Header flags.
    pub flags: u32,
    /// Preallocated DMA pool.
    pub dma_pool: DmaPoolInfo,
    /// Number of valid entries in [`Self::nvme`].
    pub nvme_count: usize,
    /// Discovered NVMe PCI functions.
    pub nvme: [NvmeBootFunction; MAX_NVME_FUNCTIONS],
}

impl StorageBootInfo {
    /// Empty boot-info descriptor.
    pub const fn empty() -> Self {
        Self {
            flags: 0,
            dma_pool: DmaPoolInfo { base: 0, len: 0 },
            nvme_count: 0,
            nvme: [NvmeBootFunction {
                bus: 0,
                device: 0,
                function: 0,
                interrupt_pin: 0,
                vendor_id: 0,
                device_id: 0,
                bar0_base: 0,
                bar0_len: 0,
                irq_line: 0,
                flags: 0,
                msi_vector_count: 0,
                msix_table_size: 0,
                msix_table_bir: 0,
                reserved0: 0,
                msix_table_offset: 0,
            }; MAX_NVME_FUNCTIONS],
        }
    }

    /// Append one NVMe function if capacity allows. Returns whether the entry
    /// was recorded.
    pub fn push_nvme(&mut self, function: NvmeBootFunction) -> bool {
        if self.nvme_count >= self.nvme.len() {
            return false;
        }
        self.nvme[self.nvme_count] = function;
        self.nvme_count += 1;
        true
    }
}

/// Encode storage boot-info into `out`, returning the number of bytes written.
pub fn encode(info: &StorageBootInfo, out: &mut [u8]) -> Option<usize> {
    let count = info.nvme_count.min(MAX_NVME_FUNCTIONS);
    let total = HEADER_BYTES.checked_add(count.checked_mul(NVME_ENTRY_BYTES)?)?;
    if out.len() < total {
        return None;
    }
    out[..total].fill(0);
    write_u32(out, 0, MAGIC)?;
    write_u16(out, 4, VERSION)?;
    write_u16(out, 6, HEADER_BYTES as u16)?;
    write_u16(out, 8, NVME_ENTRY_BYTES as u16)?;
    write_u16(out, 10, count as u16)?;
    write_u32(out, 12, info.flags)?;
    write_u64(out, 16, info.dma_pool.base)?;
    write_u64(out, 24, info.dma_pool.len)?;

    let mut idx = 0usize;
    while idx < count {
        let base = HEADER_BYTES + idx * NVME_ENTRY_BYTES;
        encode_nvme(&info.nvme[idx], out, base)?;
        idx += 1;
    }
    Some(total)
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
    if header_bytes != HEADER_BYTES || entry_bytes != NVME_ENTRY_BYTES {
        return None;
    }
    if count > MAX_NVME_FUNCTIONS {
        return None;
    }
    let total = HEADER_BYTES.checked_add(count.checked_mul(NVME_ENTRY_BYTES)?)?;
    if bytes.len() < total {
        return None;
    }
    let mut info = StorageBootInfo::empty();
    info.flags = read_u32(bytes, 12)?;
    info.dma_pool = DmaPoolInfo {
        base: read_u64(bytes, 16)?,
        len: read_u64(bytes, 24)?,
    };
    let mut idx = 0usize;
    while idx < count {
        info.nvme[idx] = decode_nvme(bytes, HEADER_BYTES + idx * NVME_ENTRY_BYTES)?;
        idx += 1;
    }
    info.nvme_count = count;
    Some(info)
}

fn encode_nvme(entry: &NvmeBootFunction, out: &mut [u8], base: usize) -> Option<()> {
    *out.get_mut(base)? = entry.bus;
    *out.get_mut(base + 1)? = entry.device;
    *out.get_mut(base + 2)? = entry.function;
    *out.get_mut(base + 3)? = entry.interrupt_pin;
    write_u16(out, base + 4, entry.vendor_id)?;
    write_u16(out, base + 6, entry.device_id)?;
    write_u64(out, base + 8, entry.bar0_base)?;
    write_u64(out, base + 16, entry.bar0_len)?;
    write_u32(out, base + 24, entry.irq_line)?;
    write_u32(out, base + 28, entry.flags)?;
    write_u16(out, base + 32, entry.msi_vector_count)?;
    write_u16(out, base + 34, entry.msix_table_size)?;
    *out.get_mut(base + 36)? = entry.msix_table_bir;
    *out.get_mut(base + 37)? = entry.reserved0;
    write_u32(out, base + 40, entry.msix_table_offset)?;
    Some(())
}

fn decode_nvme(bytes: &[u8], base: usize) -> Option<NvmeBootFunction> {
    Some(NvmeBootFunction {
        bus: *bytes.get(base)?,
        device: *bytes.get(base + 1)?,
        function: *bytes.get(base + 2)?,
        interrupt_pin: *bytes.get(base + 3)?,
        vendor_id: read_u16(bytes, base + 4)?,
        device_id: read_u16(bytes, base + 6)?,
        bar0_base: read_u64(bytes, base + 8)?,
        bar0_len: read_u64(bytes, base + 16)?,
        irq_line: read_u32(bytes, base + 24)?,
        flags: read_u32(bytes, base + 28)?,
        msi_vector_count: read_u16(bytes, base + 32)?,
        msix_table_size: read_u16(bytes, base + 34)?,
        msix_table_bir: *bytes.get(base + 36)?,
        reserved0: *bytes.get(base + 37)?,
        msix_table_offset: read_u32(bytes, base + 40)?,
    })
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
        let mut info = StorageBootInfo::empty();
        info.flags = FLAG_DMA_POOL_PRESENT;
        info.dma_pool = DmaPoolInfo {
            base: 0x1000_0000,
            len: 0x400_0000,
        };
        assert!(info.push_nvme(NvmeBootFunction {
            bus: 0,
            device: 4,
            function: 0,
            interrupt_pin: 1,
            vendor_id: 0x8086,
            device_id: 0x5845,
            bar0_base: 0xfe00_0000,
            bar0_len: 0x4000,
            irq_line: 11,
            flags: NVME_FLAG_INTX_PRESENT | NVME_FLAG_MSIX_PRESENT,
            msi_vector_count: 0,
            msix_table_size: 3,
            msix_table_bir: 0,
            reserved0: 0,
            msix_table_offset: 0x2000,
        }));
        info
    }

    #[test]
    fn round_trip_storage_boot_info() {
        let info = sample();
        let mut bytes = [0u8; MAX_ENCODED_BYTES];
        let Some(len) = encode(&info, &mut bytes) else {
            assert!(false, "encode must fit fixed buffer");
            return;
        };
        assert_eq!(len, HEADER_BYTES + NVME_ENTRY_BYTES);
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
    fn rejects_too_many_entries() {
        let mut bytes = [0u8; HEADER_BYTES];
        write_u32(&mut bytes, 0, MAGIC);
        write_u16(&mut bytes, 4, VERSION);
        write_u16(&mut bytes, 6, HEADER_BYTES as u16);
        write_u16(&mut bytes, 8, NVME_ENTRY_BYTES as u16);
        write_u16(&mut bytes, 10, (MAX_NVME_FUNCTIONS + 1) as u16);
        assert!(decode(&bytes).is_none());
    }
}
