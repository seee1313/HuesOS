//! Stage-A storage boot hardware discovery.
//!
//! The userspace NVMe driver remains the real hardware driver. This module is
//! only the bootstrap shim needed before DriverManager has its own PCI access:
//! reserve/report the boot DMA pool and discover enough PCI metadata to mint
//! Resource handles for the userspace DriverHost.

use alloc::vec::Vec;
use core::fmt::Write;

use huesos_abi::storage_boot::{
    self, DmaPoolInfo, NvmeBootFunction, StorageBootInfo, FLAG_DMA_POOL_PRESENT,
    NVME_FLAG_INTX_PRESENT, NVME_FLAG_MSIX_PRESENT, NVME_FLAG_MSI_PRESENT,
};
use huesos_pci::{command, parse_interrupt_capabilities, Bar, ClassCode, ConfigSpace};

use crate::init::BootDmaPool;

const PCI_CONFIG_ADDRESS: u16 = 0x0cf8;
const PCI_CONFIG_DATA: u16 = 0x0cfc;
const MAX_BUSES: u16 = 256;
const MAX_DEVICES: u8 = 32;
const MAX_FUNCTIONS: u8 = 8;
const MIN_NVME_BAR0_LEN: u64 = 0x1000;

#[derive(Clone, Copy)]
struct PciLocation {
    bus: u8,
    device: u8,
    function: u8,
}

#[derive(Clone, Copy)]
struct Bar0Info {
    base: u64,
    len: u64,
}

/// Build an encoded storage boot-info blob for init.
pub fn build_storage_boot_info(dma_pool: Option<BootDmaPool>) -> Vec<u8> {
    let mut info = StorageBootInfo::empty();
    if let Some(pool) = dma_pool {
        info.flags |= FLAG_DMA_POOL_PRESENT;
        info.dma_pool = DmaPoolInfo {
            base: pool.base,
            len: pool.len,
        };
    }

    discover_nvme_functions(&mut info);

    let mut encoded = alloc::vec![0u8; storage_boot::MAX_ENCODED_BYTES];
    let len = storage_boot::encode(&info, &mut encoded).unwrap_or(0);
    encoded.truncate(len);
    log_storage_info(&info);
    encoded
}

fn discover_nvme_functions(info: &mut StorageBootInfo) {
    let mut bus = 0u16;
    while bus < MAX_BUSES && info.nvme_count < storage_boot::MAX_NVME_FUNCTIONS {
        let mut device = 0u8;
        while device < MAX_DEVICES && info.nvme_count < storage_boot::MAX_NVME_FUNCTIONS {
            let mut function = 0u8;
            while function < MAX_FUNCTIONS && info.nvme_count < storage_boot::MAX_NVME_FUNCTIONS {
                let location = PciLocation {
                    bus: bus as u8,
                    device,
                    function,
                };
                if let Some(entry) = inspect_function(location) {
                    let _ = info.push_nvme(entry);
                }
                function += 1;
            }
            device += 1;
        }
        bus += 1;
    }
}

fn inspect_function(location: PciLocation) -> Option<NvmeBootFunction> {
    let vendor = read_config_u16(location, huesos_pci::off::VENDOR_ID);
    if vendor == 0xffff {
        return None;
    }

    let config = read_config_space(location);
    if !config.class_code().matches(ClassCode::NVME) || config.header_type() != 0 {
        return None;
    }

    let bar0 = size_bar0(location, &config)?;
    if bar0.len < MIN_NVME_BAR0_LEN {
        log_line("[storage] ignoring NVMe with undersized BAR0");
        return None;
    }

    let interrupts = parse_interrupt_capabilities(&config);
    let mut flags = 0u32;
    if interrupts.intx_line.is_some() {
        flags |= NVME_FLAG_INTX_PRESENT;
    }
    if interrupts.msi.is_some() {
        flags |= NVME_FLAG_MSI_PRESENT;
    }
    if interrupts.msix.is_some() {
        flags |= NVME_FLAG_MSIX_PRESENT;
    }
    let msi_vector_count = interrupts.msi.map(|m| m.vector_count).unwrap_or(0);
    let msix = interrupts.msix.unwrap_or_default();

    Some(NvmeBootFunction {
        bus: location.bus,
        device: location.device,
        function: location.function,
        interrupt_pin: interrupts.intx_pin.unwrap_or(0),
        vendor_id: config.vendor_id(),
        device_id: config.device_id(),
        bar0_base: bar0.base,
        bar0_len: bar0.len,
        irq_line: u32::from(interrupts.intx_line.unwrap_or(0xff)),
        flags,
        msi_vector_count,
        msix_table_size: msix.table_size,
        msix_table_bir: msix.table_bir,
        reserved0: 0,
        msix_table_offset: msix.table_offset,
    })
}

fn read_config_space(location: PciLocation) -> ConfigSpace {
    let mut bytes = [0u8; 256];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let value = read_config_u32(location, offset);
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        offset += 4;
    }
    ConfigSpace(bytes)
}

fn size_bar0(location: PciLocation, config: &ConfigSpace) -> Option<Bar0Info> {
    let lo = config.bar_raw(0)?;
    if lo & 1 != 0 {
        return None;
    }
    let is_64 = ((lo >> 1) & 0x3) == 0b10;
    let hi = if is_64 {
        config.bar_raw(1).unwrap_or_default()
    } else {
        0
    };
    let decoded = huesos_pci::decode_memory_bar(lo, hi, 1);
    let Bar::Memory { base, .. } = decoded else {
        return None;
    };
    if base == 0 {
        return None;
    }

    let command_before = config.command();
    let command_sized = command_before & !(command::MEMORY_SPACE | command::BUS_MASTER);
    write_config_u16(location, huesos_pci::off::COMMAND, command_sized);
    write_config_u32(location, huesos_pci::off::BAR0, 0xffff_ffff);
    if is_64 {
        write_config_u32(location, huesos_pci::off::BAR0 + 4, 0xffff_ffff);
    }
    let mask_lo = read_config_u32(location, huesos_pci::off::BAR0);
    let mask_hi = if is_64 {
        read_config_u32(location, huesos_pci::off::BAR0 + 4)
    } else {
        0
    };
    write_config_u32(location, huesos_pci::off::BAR0, lo);
    if is_64 {
        write_config_u32(location, huesos_pci::off::BAR0 + 4, hi);
    }
    write_config_u16(location, huesos_pci::off::COMMAND, command_before);

    let size = if is_64 {
        let mask = ((mask_hi as u64) << 32) | u64::from(mask_lo & 0xffff_fff0);
        (!mask).wrapping_add(1)
    } else {
        huesos_pci::memory_bar_size(mask_lo)
    };
    if size == 0 || !size.is_power_of_two() {
        return None;
    }
    Some(Bar0Info { base, len: size })
}

fn read_config_u16(location: PciLocation, offset: usize) -> u16 {
    let value = read_config_u32(location, offset & !0x3);
    let shift = ((offset & 0x2) * 8) as u32;
    ((value >> shift) & 0xffff) as u16
}

fn write_config_u16(location: PciLocation, offset: usize, value: u16) {
    let aligned = offset & !0x3;
    let mut current = read_config_u32(location, aligned);
    let shift = ((offset & 0x2) * 8) as u32;
    current &= !(0xffffu32 << shift);
    current |= u32::from(value) << shift;
    write_config_u32(location, aligned, current);
}

fn config_address(location: PciLocation, offset: usize) -> u32 {
    0x8000_0000
        | ((location.bus as u32) << 16)
        | ((location.device as u32) << 11)
        | ((location.function as u32) << 8)
        | ((offset as u32) & 0xfc)
}

fn read_config_u32(location: PciLocation, offset: usize) -> u32 {
    use x86_64::instructions::port::Port;

    let address = config_address(location, offset);
    // SAFETY: CF8/CFC are the architected x86 PCI Configuration Mechanism #1
    // ports. This boot-only scanner performs aligned DWORD config accesses and
    // restores any BAR/command state it temporarily changes during sizing.
    unsafe {
        let mut addr = Port::<u32>::new(PCI_CONFIG_ADDRESS);
        let mut data = Port::<u32>::new(PCI_CONFIG_DATA);
        addr.write(address);
        data.read()
    }
}

fn write_config_u32(location: PciLocation, offset: usize, value: u32) {
    use x86_64::instructions::port::Port;

    let address = config_address(location, offset);
    // SAFETY: same CF8/CFC contract as `read_config_u32`; callers only write
    // standard PCI config registers while the BSP is still single-threaded for
    // storage discovery purposes.
    unsafe {
        let mut addr = Port::<u32>::new(PCI_CONFIG_ADDRESS);
        let mut data = Port::<u32>::new(PCI_CONFIG_DATA);
        addr.write(address);
        data.write(value);
    }
}

fn log_storage_info(info: &StorageBootInfo) {
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(
        writer,
        "[storage] boot info: dma={:#x}+{:#x}, nvme_count={}",
        info.dma_pool.base, info.dma_pool.len, info.nvme_count
    );
    let mut idx = 0usize;
    while idx < info.nvme_count {
        let entry = info.nvme[idx];
        let _ = writeln!(
            writer,
            "[storage] nvme{} pci={:02x}:{:02x}.{} vendor={:#x} device={:#x} bar0={:#x}+{:#x} irq={} flags={:#x}",
            idx,
            entry.bus,
            entry.device,
            entry.function,
            entry.vendor_id,
            entry.device_id,
            entry.bar0_base,
            entry.bar0_len,
            entry.irq_line,
            entry.flags
        );
        idx += 1;
    }
}

fn log_line(message: &str) {
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(writer, "{}", message);
}
