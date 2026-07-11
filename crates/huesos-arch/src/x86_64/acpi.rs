//! Minimal, defensive ACPI discovery for SMP bootstrap.
//!
//! The parser follows `RSDP -> RSDT/XSDT -> MADT` and extracts only the data
//! required before userspace drivers exist: enabled Local APIC identifiers,
//! the Local APIC MMIO base, and I/O APIC descriptors. It deliberately does
//! not interpret AML or provide a general ACPI namespace.
//!
//! ## Memory model
//!
//! Firmware tables are packed byte streams. Their physical addresses are not
//! guaranteed to satisfy Rust alignment, so this module never creates a
//! reference to an ACPI structure. Every header/field is copied by value with
//! `read_unaligned`. Table lengths, arithmetic, entry sizes, and parser work
//! are bounded before advancing a cursor.
//!
//! The boot layer maps ACPI reclaimable/NVS ranges into the HHDM before calling
//! this parser. That mapping lifetime is the central unsafe precondition; once
//! established, malformed firmware should produce `None`, not Rust UB.
//!
//! ## Concurrency
//!
//! Parsing runs once on the BSP before AP scheduling begins and mutates no
//! global state. The returned fixed-capacity arrays are owned by the caller.

#![allow(missing_docs)]

use core::mem::size_of;

/// ACPI System Description Table header (common to all SDTs).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

impl SdtHeader {
    pub fn signature_str(&self) -> &[u8] {
        &self.signature
    }
}

/// Root System Description Pointer (ACPI 1.0).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RsdpV1 {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_addr: u32,
}

/// Extended RSDP fields (ACPI 2.0+).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RsdpV2Ext {
    pub length: u32,
    pub xsdt_addr: u64,
    pub ext_checksum: u8,
    pub _reserved: [u8; 3],
}

/// Parsed CPU info from MADT.
#[derive(Debug, Clone, Copy)]
pub struct CpuInfo {
    pub acpi_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

/// Parsed I/O APIC info from MADT.
#[derive(Debug, Clone, Copy)]
pub struct IoApicInfo {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

/// Result of MADT parsing.
#[derive(Debug)]
pub struct MadtInfo {
    pub local_apic_phys: u32,
    pub cpus: [Option<CpuInfo>; 64],
    pub cpu_count: usize,
    pub io_apics: [Option<IoApicInfo>; 8],
    pub io_apic_count: usize,
}

impl MadtInfo {
    pub const fn empty() -> Self {
        Self {
            local_apic_phys: 0,
            cpus: [None; 64],
            cpu_count: 0,
            io_apics: [None; 8],
            io_apic_count: 0,
        }
    }
}

/// Parse the RSDP and walk tables to find the MADT.
///
/// `phys_to_virt` translates a physical address to a kernel-accessible
/// virtual address. Firmware structures are packed and are therefore always
/// copied with `read_unaligned`; creating references to them would be UB when
/// firmware chooses a naturally unaligned address.
///
/// # Safety
/// `rsdp_phys` and every physical address returned by ACPI must be mapped for
/// at least the validated table length by `phys_to_virt`. The caller establishes
/// this from the bootloader memory map before parsing.
pub unsafe fn parse_madt(rsdp_phys: u64, phys_to_virt: impl Fn(u64) -> u64) -> Option<MadtInfo> {
    let rsdp_virt = phys_to_virt(rsdp_phys);
    // SAFETY: guaranteed by this function's caller contract; the helper makes
    // an unaligned value copy and never creates a firmware-memory reference.
    unsafe { parse_madt_from_root(rsdp_virt, phys_to_virt) }
}

/// Copy a packed firmware value from an already mapped virtual address.
///
/// # Safety
/// `[address, address + size_of::<T>())` must be readable mapped memory.
/// Marker for packed ACPI values whose every bit pattern is valid.
///
/// Keeping this trait private prevents a future parser change from using the
/// generic reader for references, `bool`, enums, or other types where arbitrary
/// firmware bytes could create an invalid Rust value.
trait FirmwarePod: Copy {}
impl FirmwarePod for u8 {}
impl FirmwarePod for u32 {}
impl FirmwarePod for u64 {}
impl FirmwarePod for RsdpV1 {}
impl FirmwarePod for RsdpV2Ext {}
impl FirmwarePod for SdtHeader {}

unsafe fn read_firmware<T: FirmwarePod>(address: u64) -> T {
    // SAFETY: delegated to the caller; unaligned access is intentional and T
    // is restricted to plain data with no invalid bit patterns.
    unsafe { core::ptr::read_unaligned(address as *const T) }
}

unsafe fn parse_madt_from_root(
    rsdp_virt: u64,
    phys_to_virt: impl Fn(u64) -> u64,
) -> Option<MadtInfo> {
    // SAFETY: parse_madt contract covers the fixed RSDP prefix.
    let rsdp: RsdpV1 = unsafe { read_firmware(rsdp_virt) };
    if &rsdp.signature != b"RSD PTR " {
        return None;
    }

    let (ptr_base, entry_size, entries) = if rsdp.revision >= 2 {
        // SAFETY: ACPI 2+ guarantees the extension after the v1 prefix.
        let ext: RsdpV2Ext =
            unsafe { read_firmware(rsdp_virt.checked_add(size_of::<RsdpV1>() as u64)?) };
        if ext.length < (size_of::<RsdpV1>() + size_of::<RsdpV2Ext>()) as u32 {
            return None;
        }
        let table = phys_to_virt(ext.xsdt_addr);
        // SAFETY: root table header is covered by the ACPI mapping contract.
        let header: SdtHeader = unsafe { read_firmware(table) };
        if &header.signature != b"XSDT" {
            return None;
        }
        let payload = (header.length as usize).checked_sub(size_of::<SdtHeader>())?;
        (
            table.checked_add(size_of::<SdtHeader>() as u64)?,
            8usize,
            payload / 8,
        )
    } else {
        let table = phys_to_virt(rsdp.rsdt_addr as u64);
        // SAFETY: root table header is covered by the ACPI mapping contract.
        let header: SdtHeader = unsafe { read_firmware(table) };
        if &header.signature != b"RSDT" {
            return None;
        }
        let payload = (header.length as usize).checked_sub(size_of::<SdtHeader>())?;
        (
            table.checked_add(size_of::<SdtHeader>() as u64)?,
            4usize,
            payload / 4,
        )
    };

    // A corrupt firmware length must not turn boot into an unbounded table
    // walk even when the enclosing mapped region is large.
    if entries > 4096 {
        return None;
    }

    for index in 0..entries {
        let entry_address = ptr_base.checked_add((index * entry_size) as u64)?;
        // SAFETY: the root table length validated the complete entry array.
        let physical = unsafe {
            if entry_size == 8 {
                read_firmware::<u64>(entry_address)
            } else {
                read_firmware::<u32>(entry_address) as u64
            }
        };
        let table = phys_to_virt(physical);
        // SAFETY: each SDT address is firmware-owned mapped memory.
        let header: SdtHeader = unsafe { read_firmware(table) };
        if header.length < size_of::<SdtHeader>() as u32 {
            continue;
        }
        if &header.signature == b"APIC" {
            // SAFETY: header.length bounds the parser and the ACPI mapping
            // contract covers the advertised table.
            return unsafe { parse_madt_entries(table, header.length) };
        }
    }
    None
}

unsafe fn parse_madt_entries(madt_virt: u64, length: u32) -> Option<MadtInfo> {
    const MADT_FIXED_BYTES: usize = size_of::<SdtHeader>() + 8;
    if (length as usize) < MADT_FIXED_BYTES {
        return None;
    }
    let table_end = madt_virt.checked_add(length as u64)?;
    let lapic_address = madt_virt.checked_add(size_of::<SdtHeader>() as u64)?;

    let mut info = MadtInfo::empty();
    // SAFETY: the fixed MADT body length was validated above.
    info.local_apic_phys = unsafe { read_firmware::<u32>(lapic_address) };

    let mut cursor = madt_virt.checked_add(MADT_FIXED_BYTES as u64)?;
    while cursor.checked_add(2)? <= table_end {
        // SAFETY: the two-byte entry prefix is inside the validated table.
        let entry_type = unsafe { read_firmware::<u8>(cursor) };
        let entry_len = unsafe { read_firmware::<u8>(cursor + 1) } as u64;
        if entry_len < 2 {
            return None;
        }
        let next = cursor.checked_add(entry_len)?;
        if next > table_end {
            return None;
        }

        match entry_type {
            0 if entry_len >= 8 && info.cpu_count < info.cpus.len() => {
                // SAFETY: entry_len validates all Local APIC fields.
                let acpi_id = unsafe { read_firmware::<u8>(cursor + 2) };
                let apic_id = unsafe { read_firmware::<u8>(cursor + 3) };
                let flags = unsafe { read_firmware::<u32>(cursor + 4) };
                if flags & 1 != 0 {
                    info.cpus[info.cpu_count] = Some(CpuInfo {
                        acpi_id,
                        apic_id,
                        flags,
                    });
                    info.cpu_count += 1;
                }
            }
            1 if entry_len >= 12 && info.io_apic_count < info.io_apics.len() => {
                // SAFETY: entry_len validates all I/O APIC fields.
                let id = unsafe { read_firmware::<u8>(cursor + 2) };
                let address = unsafe { read_firmware::<u32>(cursor + 4) };
                let gsi_base = unsafe { read_firmware::<u32>(cursor + 8) };
                info.io_apics[info.io_apic_count] = Some(IoApicInfo {
                    id,
                    address,
                    gsi_base,
                });
                info.io_apic_count += 1;
            }
            _ => {}
        }
        cursor = next;
    }
    Some(info)
}
