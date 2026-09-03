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
    /// ACPI processor UID. Type-0 entries widen their 8-bit ID here.
    pub acpi_uid: u32,
    /// Hardware Local APIC/x2APIC ID. Never use this as an array index.
    pub apic_id: u32,
    pub flags: u32,
    /// True when this record came from MADT Local x2APIC type 9.
    pub x2apic: bool,
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
    pub local_apic_phys: u64,
    pub cpus: [Option<CpuInfo>; huesos_sched::MAX_CPUS],
    pub cpu_count: usize,
    pub io_apics: [Option<IoApicInfo>; 8],
    pub io_apic_count: usize,
}

impl MadtInfo {
    pub const fn empty() -> Self {
        Self {
            local_apic_phys: 0,
            cpus: [None; huesos_sched::MAX_CPUS],
            cpu_count: 0,
            io_apics: [None; 8],
            io_apic_count: 0,
        }
    }
}

fn push_cpu(info: &mut MadtInfo, cpu: CpuInfo) -> Option<()> {
    if info.cpu_count == info.cpus.len()
        || info.cpus[..info.cpu_count]
            .iter()
            .flatten()
            .any(|known| known.apic_id == cpu.apic_id || known.acpi_uid == cpu.acpi_uid)
    {
        return None;
    }
    info.cpus[info.cpu_count] = Some(cpu);
    info.cpu_count += 1;
    Some(())
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
    info.local_apic_phys = u64::from(u32::from_le_bytes(
        table.get(HEADER_BYTES..HEADER_BYTES + 4)?.try_into().ok()?,
    ));

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
            0 if entry_len >= 8 => {
                let flags = u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?);
                if flags & 1 != 0 {
                    push_cpu(
                        &mut info,
                        CpuInfo {
                            acpi_uid: u32::from(entry[2]),
                            apic_id: u32::from(entry[3]),
                            flags,
                            x2apic: false,
                        },
                    )?;
                }
            }
            1 if entry_len >= 12 => {
                if info.io_apic_count == info.io_apics.len() {
                    return None;
                }
                info.io_apics[info.io_apic_count] = Some(IoApicInfo {
                    id: entry[2],
                    address: u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?),
                    gsi_base: u32::from_le_bytes(entry.get(8..12)?.try_into().ok()?),
                });
                info.io_apic_count += 1;
            }
            // Local APIC Address Override. The reserved field at bytes 2..4
            // must be zero and the 64-bit address supersedes the fixed MADT
            // header value.
            5 if entry_len >= 12 => {
                if entry.get(2..4)? != [0, 0] {
                    return None;
                }
                info.local_apic_phys = u64::from_le_bytes(entry.get(4..12)?.try_into().ok()?);
            }
            // Processor Local x2APIC. Runtime hot-add is outside v2 scope, so
            // only firmware-enabled processors enter the boot CPU set.
            9 if entry_len >= 16 => {
                let flags = u32::from_le_bytes(entry.get(8..12)?.try_into().ok()?);
                if flags & 1 != 0 {
                    push_cpu(
                        &mut info,
                        CpuInfo {
                            acpi_uid: u32::from_le_bytes(entry.get(12..16)?.try_into().ok()?),
                            apic_id: u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?),
                            flags,
                            x2apic: true,
                        },
                    )?;
                }
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
    fn parses_enabled_x2apic_and_wide_acpi_uid() {
        let mut table = [0u8; 60];
        table[..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&60u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44] = 9;
        table[45] = 16;
        table[48..52].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        table[52..56].copy_from_slice(&1u32.to_le_bytes());
        table[56..60].copy_from_slice(&0xfeed_beefu32.to_le_bytes());
        let parsed = parse_madt_bytes(&table);
        let cpu = parsed.as_ref().and_then(|info| info.cpus[0]);
        assert_eq!(cpu.map(|entry| entry.apic_id), Some(0x1234_5678));
        assert_eq!(cpu.map(|entry| entry.acpi_uid), Some(0xfeed_beef));
        assert_eq!(cpu.map(|entry| entry.x2apic), Some(true));
    }

    #[test]
    fn local_apic_address_override_is_64_bit_and_authoritative() {
        let mut table = [0u8; 56];
        table[..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&56u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44] = 5;
        table[45] = 12;
        table[48..56].copy_from_slice(&0x0000_0001_fee0_0000u64.to_le_bytes());
        assert_eq!(
            parse_madt_bytes(&table).map(|info| info.local_apic_phys),
            Some(0x0000_0001_fee0_0000)
        );
    }

    #[test]
    fn duplicate_apic_or_acpi_identity_is_rejected() {
        let mut table = [0u8; 60];
        table[..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&60u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44..52].copy_from_slice(&[0, 8, 1, 7, 1, 0, 0, 0]);
        table[52..60].copy_from_slice(&[0, 8, 2, 7, 1, 0, 0, 0]);
        assert!(parse_madt_bytes(&table).is_none());
        table[55] = 8;
        table[54] = 1;
        assert!(parse_madt_bytes(&table).is_none());
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
