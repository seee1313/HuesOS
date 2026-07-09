//! Minimal ACPI parser: RSDP -> RSDT/XSDT -> MADT.
//! Extracts Local APIC IDs and I/O APIC info for SMP bring-up.

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
/// `phys_to_virt` must translate a physical address to a kernel-accessible
/// virtual address (e.g. via HHDM).
///
/// # Safety
/// `rsdp_phys` must point to a valid RSDP in physical memory.
pub unsafe fn parse_madt(
    rsdp_phys: u64,
    phys_to_virt: impl Fn(u64) -> u64,
) -> Option<MadtInfo> {
    let rsdp_virt = phys_to_virt(rsdp_phys);
    parse_madt_from_root(rsdp_virt, phys_to_virt)
}

unsafe fn parse_madt_from_root(
    rsdp_virt: u64,
    phys_to_virt: impl Fn(u64) -> u64,
) -> Option<MadtInfo> {
    let rsdp = unsafe { &*(rsdp_virt as *const RsdpV1) };

    if &rsdp.signature != b"RSD PTR " {
        return None;
    }

    let (ptr_base, entry_size, entries): (u64, usize, usize) = if rsdp.revision >= 2 {
        let ext = unsafe { &*((rsdp_virt + size_of::<RsdpV1>() as u64) as *const RsdpV2Ext) };
        let xsdt_virt = phys_to_virt(ext.xsdt_addr);
        let xsdt_hdr = unsafe { &*(xsdt_virt as *const SdtHeader) };
        let n = (xsdt_hdr.length as usize - size_of::<SdtHeader>()) / 8;
        (xsdt_virt + size_of::<SdtHeader>() as u64, 8, n)
    } else {
        let rsdt_virt = phys_to_virt(rsdp.rsdt_addr as u64);
        let rsdt_hdr = unsafe { &*(rsdt_virt as *const SdtHeader) };
        let n = (rsdt_hdr.length as usize - size_of::<SdtHeader>()) / 4;
        (rsdt_virt + size_of::<SdtHeader>() as u64, 4, n)
    };

    for i in 0..entries {
        let addr = if entry_size == 8 {
            let ptr = (ptr_base + (i * 8) as u64) as *const u64;
            unsafe { *ptr }
        } else {
            let ptr = (ptr_base + (i * 4) as u64) as *const u32;
            (unsafe { *ptr }) as u64
        };
        let sdt_virt = phys_to_virt(addr);
        let hdr = unsafe { &*(sdt_virt as *const SdtHeader) };
        if &hdr.signature == b"APIC" {
            return parse_madt_entries(sdt_virt, hdr.length);
        }
    }
    None
}

unsafe fn parse_madt_entries(madt_virt: u64, length: u32) -> Option<MadtInfo> {
    let mut info = MadtInfo::empty();

    // Local APIC address is at offset 36 in MADT (after standard 36-byte SDT header).
    let lapic_addr_ptr = (madt_virt + size_of::<SdtHeader>() as u64) as *const u32;
    info.local_apic_phys = unsafe { *lapic_addr_ptr };

    let entries_start = madt_virt + size_of::<SdtHeader>() as u64 + 8;
    let entries_end = madt_virt + length as u64;
    let mut cursor = entries_start;

    while cursor + 2 <= entries_end {
        let entry_type = unsafe { *(cursor as *const u8) };
        let entry_len = unsafe { *((cursor + 1) as *const u8) } as u64;
        if entry_len == 0 {
            break;
        }

        match entry_type {
            0 => {
                // Processor Local APIC
                if cursor + 8 <= entries_end && info.cpu_count < 64 {
                    let acpi_id = unsafe { *((cursor + 2) as *const u8) };
                    let apic_id = unsafe { *((cursor + 3) as *const u8) };
                    let flags = unsafe { *((cursor + 4) as *const u32) };
                    if flags & 1 != 0 {
                        // CPU enabled
                        info.cpus[info.cpu_count] = Some(CpuInfo {
                            acpi_id,
                            apic_id,
                            flags,
                        });
                        info.cpu_count += 1;
                    }
                }
            }
            1 => {
                // I/O APIC
                if cursor + 12 <= entries_end && info.io_apic_count < 8 {
                    let id = unsafe { *((cursor + 2) as *const u8) };
                    let address = unsafe { *((cursor + 4) as *const u32) };
                    let gsi_base = unsafe { *((cursor + 8) as *const u32) };
                    info.io_apics[info.io_apic_count] = Some(IoApicInfo {
                        id,
                        address,
                        gsi_base,
                    });
                    info.io_apic_count += 1;
                }
            }
            _ => {}
        }

        cursor += entry_len;
    }

    Some(info)
}
