//! Storage boot DMA pool reservation descriptor (Stage J.3).
//!
//! All PCI enumeration, BAR sizing, and MSI/MSI-X programming now live in
//! userspace (`pci-manager`); the kernel only reports the reserved boot DMA
//! pool and the `init.storage=off` flag.

use alloc::vec::Vec;
use core::fmt::Write;

use huesos_abi::storage_boot::{
    self, DmaPoolInfo, StorageBootInfo, FLAG_DMA_POOL_PRESENT, FLAG_STORAGE_OFF,
};

use crate::init::BootDmaPool;

/// Build an encoded storage boot-info blob for init.
///
/// Only reports the reserved boot DMA pool and whether `init.storage=off`
/// was set on the command line; no PCI config space is accessed.
pub fn build_storage_boot_info(dma_pool: Option<BootDmaPool>, storage_off: bool) -> Vec<u8> {
    let mut info = StorageBootInfo::empty();
    if let Some(pool) = dma_pool {
        info.flags |= FLAG_DMA_POOL_PRESENT;
        info.dma_pool = DmaPoolInfo {
            base: pool.base,
            len: pool.len,
        };
    }

    if storage_off {
        info.flags |= FLAG_STORAGE_OFF;
        log_line("[storage] disabled by init.storage=off");
    }

    let mut encoded = alloc::vec![0u8; storage_boot::MAX_ENCODED_BYTES];
    let len = storage_boot::encode(&info, &mut encoded).unwrap_or(0);
    encoded.truncate(len);
    log_storage_info(&info);
    encoded
}

fn log_storage_info(info: &StorageBootInfo) {
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        writer,
        "[storage] boot info: dma={:#x}+{:#x} storage_off={}",
        info.dma_pool.base,
        info.dma_pool.len,
        info.storage_off()
    );
}

fn log_line(message: &str) {
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(writer, "{}", message);
}
