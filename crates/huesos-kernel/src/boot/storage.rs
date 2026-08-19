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
    NVME_FLAG_INTX_PRESENT, NVME_FLAG_MSIX_ENABLED, NVME_FLAG_MSIX_PRESENT, NVME_FLAG_MSI_ENABLED,
    NVME_FLAG_MSI_PRESENT,
};
use huesos_pci::{
    command, parse_interrupt_capabilities, Bar, ClassCode, ConfigOffset, ConfigSpace,
    ConfigSpaceKind, ConfigWidth, LegacyConfigPlan, PciAddress, LEGACY_CONFIG_ADDRESS_PORT,
    LEGACY_CONFIG_DATA_PORT,
};

use crate::init::BootDmaPool;

const MAX_BUSES: u16 = 256;
const MAX_DEVICES: u8 = 32;
const MAX_FUNCTIONS: u8 = 8;
const MIN_NVME_BAR0_LEN: u64 = 0x1000;
const MAX_NVME_MSIX_VECTORS: u16 = huesos_arch::idt::NVME_MSI_VECTOR_COUNT as u16;
const NVME_MSI_VECTOR_BASE: u8 = huesos_arch::idt::NVME_MSI_VECTOR_BASE;
const MSI_MESSAGE_ADDRESS_BASE: u32 = 0xFEE0_0000;
const MSIX_ENTRY_BYTES: u64 = 16;
const MSIX_VECTOR_CONTROL_MASKED: u32 = 1;
const MSIX_CONTROL_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_CONTROL_ENABLE: u16 = 1 << 15;
const MSI_CONTROL_ENABLE: u16 = 1;
const MSI_CONTROL_MME_MASK: u16 = 0x7 << 4;
const MSI_CONTROL_64BIT: u16 = 1 << 7;

#[derive(Clone, Copy)]
struct Bar0Info {
    base: u64,
    len: u64,
}

#[derive(Clone, Copy)]
struct InterruptRoute {
    flags: u32,
    irq_base: u32,
    irq_count: u16,
}

/// Build an encoded storage boot-info blob for init.
///
/// When `storage_off` is true the kernel must not touch PCI config or
/// NVMe MMIO: no BAR sizing, no MSI/MSI-X programming, no bus-master
/// enable. The encoded blob still carries an optional DMA-pool
/// reservation so userspace sees a consistent descriptor with
/// `nvme_count = 0`.
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
        log_line("[storage] disabled by init.storage=off");
    } else {
        discover_nvme_functions(&mut info);
    }

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
                if let Ok(location) = PciAddress::try_new(0, bus as u8, device, function) {
                    if let Some(entry) = inspect_function(location) {
                        let _ = info.push_nvme(entry);
                    }
                }
                function += 1;
            }
            device += 1;
        }
        bus += 1;
    }
}

fn inspect_function(location: PciAddress) -> Option<NvmeBootFunction> {
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

    let interrupts = match parse_interrupt_capabilities(&config) {
        Ok(interrupts) => interrupts,
        Err(_) => {
            log_line("[storage] ignoring NVMe with malformed PCI capability list");
            return None;
        }
    };
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
    let route = configure_interrupts(location, &bar0, &interrupts, flags);

    Some(NvmeBootFunction {
        bus: location.bus(),
        device: location.device(),
        function: location.function(),
        interrupt_pin: interrupts.intx_pin.unwrap_or(0),
        vendor_id: config.vendor_id(),
        device_id: config.device_id(),
        bar0_base: bar0.base,
        bar0_len: bar0.len,
        irq_line: route.irq_base,
        flags: route.flags,
        msi_vector_count,
        msix_table_size: msix.table_size,
        msix_table_bir: msix.table_bir,
        reserved0: 0,
        irq_vector_count: route.irq_count,
        msix_table_offset: msix.table_offset,
    })
}

fn configure_interrupts(
    location: PciAddress,
    bar0: &Bar0Info,
    interrupts: &huesos_pci::InterruptCapabilities,
    base_flags: u32,
) -> InterruptRoute {
    if let Some(msix) = interrupts.msix {
        if let Some(route) = try_configure_msix(location, bar0, msix, base_flags) {
            return route;
        }
    }
    if let Some(msi) = interrupts.msi {
        if let Some(route) = try_configure_msi(location, msi, base_flags) {
            return route;
        }
    }
    InterruptRoute {
        flags: base_flags,
        irq_base: u32::from(interrupts.intx_line.unwrap_or(0xff)),
        irq_count: interrupts.intx_line.map(|_| 1).unwrap_or(0),
    }
}

fn try_configure_msix(
    location: PciAddress,
    bar0: &Bar0Info,
    msix: huesos_pci::MsixCapability,
    base_flags: u32,
) -> Option<InterruptRoute> {
    if msix.table_bir != 0 || msix.table_size == 0 {
        return None;
    }
    let count = msix.table_size.min(MAX_NVME_MSIX_VECTORS);
    let table_bytes = u64::from(count).checked_mul(MSIX_ENTRY_BYTES)?;
    let table_end = u64::from(msix.table_offset).checked_add(table_bytes)?;
    if table_end > bar0.len {
        return None;
    }
    let table_phys = bar0.base.checked_add(u64::from(msix.table_offset))?;
    map_mmio_window(table_phys, table_bytes).ok()?;

    let control = read_config_u16(location, msix.offset as usize + 2);
    write_config_u16(
        location,
        msix.offset as usize + 2,
        control | MSIX_CONTROL_FUNCTION_MASK,
    );
    let mut idx = 0u16;
    while idx < count {
        let vector = NVME_MSI_VECTOR_BASE.wrapping_add(idx as u8);
        program_msix_entry(table_phys, idx, vector);
        idx += 1;
    }
    write_config_u16(
        location,
        msix.offset as usize + 2,
        (control | MSIX_CONTROL_ENABLE) & !MSIX_CONTROL_FUNCTION_MASK,
    );
    enable_device_bus_master(location);
    Some(InterruptRoute {
        flags: base_flags | NVME_FLAG_MSIX_ENABLED,
        irq_base: u32::from(NVME_MSI_VECTOR_BASE),
        irq_count: count,
    })
}

fn try_configure_msi(
    location: PciAddress,
    msi: huesos_pci::MsiCapability,
    base_flags: u32,
) -> Option<InterruptRoute> {
    let vector = NVME_MSI_VECTOR_BASE;
    let control = read_config_u16(location, msi.offset as usize + 2);
    let message_address = msi_message_address();
    write_config_u32(location, msi.offset as usize + 4, message_address);
    let data_offset = if control & MSI_CONTROL_64BIT != 0 {
        write_config_u32(location, msi.offset as usize + 8, 0);
        msi.offset as usize + 12
    } else {
        msi.offset as usize + 8
    };
    write_config_u16(location, data_offset, u16::from(vector));
    write_config_u16(
        location,
        msi.offset as usize + 2,
        (control & !MSI_CONTROL_MME_MASK) | MSI_CONTROL_ENABLE,
    );
    enable_device_bus_master(location);
    Some(InterruptRoute {
        flags: base_flags | NVME_FLAG_MSI_ENABLED,
        irq_base: u32::from(vector),
        irq_count: 1,
    })
}

fn map_mmio_window(phys: u64, len: u64) -> Result<(), huesos_arch::paging::KernelPageError> {
    use x86_64::structures::paging::PageTableFlags;
    huesos_arch::paging::map_hhdm_range_flags(
        phys,
        len,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::NO_EXECUTE,
    )
}

fn program_msix_entry(table_phys: u64, index: u16, vector: u8) {
    let entry_phys = table_phys + u64::from(index) * MSIX_ENTRY_BYTES;
    let entry = huesos_arch::paging::phys_to_virt(entry_phys).as_u64();
    let message_address = msi_message_address();
    // SAFETY: `try_configure_msix` bounds-checks the table against BAR0, maps
    // the MMIO page(s) uncached, and calls this with `index < programmed_count`.
    // MSI-X table writes are volatile MMIO writes to architected entry fields.
    unsafe {
        core::ptr::write_volatile((entry + 12) as *mut u32, MSIX_VECTOR_CONTROL_MASKED);
        core::ptr::write_volatile(entry as *mut u32, message_address);
        core::ptr::write_volatile((entry + 4) as *mut u32, 0);
        core::ptr::write_volatile((entry + 8) as *mut u32, u32::from(vector));
        core::ptr::write_volatile((entry + 12) as *mut u32, 0);
    }
}

fn msi_message_address() -> u32 {
    MSI_MESSAGE_ADDRESS_BASE | ((huesos_arch::lapic::id() & 0xff) << 12)
}

fn enable_device_bus_master(location: PciAddress) {
    let command = read_config_u16(location, huesos_pci::off::COMMAND);
    write_config_u16(
        location,
        huesos_pci::off::COMMAND,
        command | command::MEMORY_SPACE | command::BUS_MASTER | command::INTX_DISABLE,
    );
}

fn read_config_space(location: PciAddress) -> ConfigSpace {
    let mut bytes = [0u8; 256];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let value = read_config_u32(location, offset);
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        offset += 4;
    }
    ConfigSpace(bytes)
}

fn size_bar0(location: PciAddress, config: &ConfigSpace) -> Option<Bar0Info> {
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

fn legacy_plan(
    location: PciAddress,
    offset: usize,
    width: ConfigWidth,
) -> Option<LegacyConfigPlan> {
    let raw_offset = u16::try_from(offset).ok()?;
    let offset = ConfigOffset::try_new(raw_offset, width, ConfigSpaceKind::Conventional).ok()?;
    LegacyConfigPlan::try_new(location, offset).ok()
}

fn read_config_u16(location: PciAddress, offset: usize) -> u16 {
    let Some(plan) = legacy_plan(location, offset, ConfigWidth::Word) else {
        return u16::MAX;
    };
    plan.extract(read_legacy_dword(plan.address_register())) as u16
}

fn write_config_u16(location: PciAddress, offset: usize, value: u16) {
    let Some(plan) = legacy_plan(location, offset, ConfigWidth::Word) else {
        return;
    };
    let current = read_legacy_dword(plan.address_register());
    write_legacy_dword(
        plan.address_register(),
        plan.merge(current, u32::from(value)),
    );
}

fn read_config_u32(location: PciAddress, offset: usize) -> u32 {
    let Some(plan) = legacy_plan(location, offset, ConfigWidth::Dword) else {
        return u32::MAX;
    };
    read_legacy_dword(plan.address_register())
}

fn write_config_u32(location: PciAddress, offset: usize, value: u32) {
    let Some(plan) = legacy_plan(location, offset, ConfigWidth::Dword) else {
        return;
    };
    write_legacy_dword(plan.address_register(), value);
}

fn read_legacy_dword(address: u32) -> u32 {
    use x86_64::instructions::port::Port;

    // SAFETY: CF8/CFC are the architected x86 PCI Configuration Mechanism #1
    // ports. The checked LegacyConfigPlan supplied the complete aligned address
    // cycle, and this boot-only scanner is the sole accessor at this stage.
    unsafe {
        let mut addr = Port::<u32>::new(LEGACY_CONFIG_ADDRESS_PORT);
        let mut data = Port::<u32>::new(LEGACY_CONFIG_DATA_PORT);
        addr.write(address);
        data.read()
    }
}

fn write_legacy_dword(address: u32, value: u32) {
    use x86_64::instructions::port::Port;

    // SAFETY: same CF8/CFC contract as `read_legacy_dword`; callers provide a
    // checked plan and only mutate standard registers during BSP boot storage
    // discovery. BAR sizing restores all temporarily changed state.
    unsafe {
        let mut addr = Port::<u32>::new(LEGACY_CONFIG_ADDRESS_PORT);
        let mut data = Port::<u32>::new(LEGACY_CONFIG_DATA_PORT);
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
            "[storage] nvme{} pci={:02x}:{:02x}.{} vendor={:#x} device={:#x} bar0={:#x}+{:#x} irq={} count={} flags={:#x}",
            idx,
            entry.bus,
            entry.device,
            entry.function,
            entry.vendor_id,
            entry.device_id,
            entry.bar0_base,
            entry.bar0_len,
            entry.irq_line,
            entry.irq_vector_count,
            entry.flags
        );
        idx += 1;
    }
}

fn log_line(message: &str) {
    let mut writer = huesos_arch::serial::SerialWriter;
    let _ = writeln!(writer, "{}", message);
}
