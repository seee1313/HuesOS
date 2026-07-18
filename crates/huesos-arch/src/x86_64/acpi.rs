//! Minimal, defensive ACPI discovery for SMP bootstrap.
//!
//! uACPI discovers, maps, and validates the MADT. This bounded byte-slice
//! consumer extracts only the data required before userspace drivers exist: enabled Local APIC identifiers,
//! the Local APIC MMIO base, and I/O APIC descriptors. It deliberately does
//! not interpret AML or provide a general ACPI namespace.
//!
//! ## Memory model
//!
//! uACPI retains the mapped table while passing this module an ordinary byte
//! slice. Table lengths, arithmetic, entry sizes, and parser work are bounded
//! before advancing a cursor; malformed firmware returns `None` without raw
//! pointer access in this consumer.
//!
//! ## Concurrency
//!
//! Parsing runs once on the BSP before AP scheduling begins and mutates no
//! global state. The returned fixed-capacity arrays are owned by the caller.

#![allow(missing_docs)]

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

/// Parse a uACPI-referenced MADT byte slice without dereferencing firmware
/// pointers. uACPI owns table discovery, mapping, checksum validation, and the
/// reference lifetime; this consumer validates every field boundary again.
pub fn parse_madt_bytes(table: &[u8]) -> Option<MadtInfo> {
    const HEADER_BYTES: usize = 36;
    const MADT_FIXED_BYTES: usize = HEADER_BYTES + 8;

    if table.len() < MADT_FIXED_BYTES || table.get(..4)? != b"APIC" {
        return None;
    }
    let declared = u32::from_le_bytes(table.get(4..8)?.try_into().ok()?) as usize;
    if !(MADT_FIXED_BYTES..=table.len()).contains(&declared) {
        return None;
    }

    let mut info = MadtInfo::empty();
    info.local_apic_phys =
        u32::from_le_bytes(table.get(HEADER_BYTES..HEADER_BYTES + 4)?.try_into().ok()?);

    let mut cursor = MADT_FIXED_BYTES;
    while cursor < declared {
        let prefix = table.get(cursor..cursor.checked_add(2)?)?;
        let entry_type = prefix[0];
        let entry_len = prefix[1] as usize;
        if entry_len < 2 {
            return None;
        }
        let next = cursor.checked_add(entry_len)?;
        let entry = table.get(cursor..next)?;
        if next > declared {
            return None;
        }

        match entry_type {
            0 if entry_len >= 8 && info.cpu_count < info.cpus.len() => {
                let flags = u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?);
                if flags & 1 != 0 {
                    info.cpus[info.cpu_count] = Some(CpuInfo {
                        acpi_id: entry[2],
                        apic_id: entry[3],
                        flags,
                    });
                    info.cpu_count += 1;
                }
            }
            1 if entry_len >= 12 && info.io_apic_count < info.io_apics.len() => {
                info.io_apics[info.io_apic_count] = Some(IoApicInfo {
                    id: entry[2],
                    address: u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?),
                    gsi_base: u32::from_le_bytes(entry.get(8..12)?.try_into().ok()?),
                });
                info.io_apic_count += 1;
            }
            _ => {}
        }
        cursor = next;
    }
    Some(info)
}

#[cfg(test)]
mod byte_tests {
    use super::parse_madt_bytes;

    fn table_with_cpu() -> [u8; 52] {
        let mut table = [0u8; 52];
        table[..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&52u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44] = 0;
        table[45] = 8;
        table[46] = 7;
        table[47] = 3;
        table[48..52].copy_from_slice(&1u32.to_le_bytes());
        table
    }

    #[test]
    fn parses_uacpi_madt_slice() {
        let table = table_with_cpu();
        let parsed = parse_madt_bytes(&table);
        assert_eq!(
            parsed
                .as_ref()
                .map(|info| (info.local_apic_phys, info.cpu_count)),
            Some((0xfee0_0000, 1))
        );
        assert_eq!(
            parsed
                .as_ref()
                .and_then(|info| info.cpus[0])
                .map(|cpu| cpu.apic_id),
            Some(3)
        );
    }

    #[test]
    fn rejects_truncated_or_zero_length_entry() {
        let mut table = table_with_cpu();
        table[4..8].copy_from_slice(&60u32.to_le_bytes());
        assert!(parse_madt_bytes(&table).is_none());
        table[4..8].copy_from_slice(&52u32.to_le_bytes());
        table[45] = 0;
        assert!(parse_madt_bytes(&table).is_none());
    }
}
