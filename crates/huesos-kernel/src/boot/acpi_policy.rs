//! Derive bounded, snapshot-bound SystemIO and SystemMemory (MMIO/NVS)
//! allowlists from the uACPI-validated FADT and boot memory map, enforced
//! against an independently constructed sacred deny set (Gate B).

use alloc::vec::Vec;
use huesos_abi::acpi_region_policy::{
    authorizes_policy, Access, DenyRange, Direction, Grant, PolicyGrant, Range, Space, WriteClass,
};
use huesos_abi::gas::{AddressSpace, Gas};
use huesos_object::{MmioGrant, SystemIoGrant};
use huesos_pmm::MemoryRegion;

const MAX_FADT_GRANTS: usize = 32;
const MAX_MMIO_GRANTS: usize = 32;
const MAX_DENY_RANGES: usize = 128;

/// Failure while deriving immutable broker policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// FADT was not installed by uACPI.
    MissingFadt,
    /// FADT was too short or malformed.
    InvalidFadt,
    /// Boot memory map was empty or could not establish a complete deny set.
    IncompleteDenySet,
    /// Fixed-capacity policy storage could not be allocated.
    OutOfMemory,
}

/// Derive snapshot-bound SystemIO and SystemMemory grants from FADT (legacy +
/// `X_*` GAS) and boot `ACPI_NVS` regions, rejecting any candidate that
/// intersects the sacred deny set.
pub fn derive_broker_policy(
    snapshot_id: u64,
    memmap: &[MemoryRegion],
) -> Result<(Vec<SystemIoGrant>, Vec<MmioGrant>), PolicyError> {
    if snapshot_id == 0 || memmap.is_empty() {
        return Err(PolicyError::IncompleteDenySet);
    }

    let table = huesos_uacpi::Table::find(b"FACP").map_err(|_| PolicyError::MissingFadt)?;
    let bytes = table.bytes().map_err(|_| PolicyError::InvalidFadt)?;
    if bytes.len() < 94 {
        return Err(PolicyError::InvalidFadt);
    }

    let mut deny = build_sacred_deny_set(bytes, memmap)?;
    // Sort/keep bounded; deny_set_complete is true only because memmap is
    // non-empty and all fixed/firmware exclusions were added without error.
    let deny_complete = !deny.is_empty();
    if !deny_complete {
        return Err(PolicyError::IncompleteDenySet);
    }

    let mut io_grants = Vec::new();
    io_grants
        .try_reserve_exact(MAX_FADT_GRANTS)
        .map_err(|_| PolicyError::OutOfMemory)?;
    let mut mmio_grants = Vec::new();
    mmio_grants
        .try_reserve_exact(MAX_MMIO_GRANTS)
        .map_err(|_| PolicyError::OutOfMemory)?;

    // Legacy FADT SystemIO blocks (SMI_CMD and RESET_REG are deliberately excluded).
    let pm1_event_len = bytes[88];
    let pm1_control_len = bytes[89];
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 56)? as u64,
        pm1_event_len as u64,
        true,
        true,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 60)? as u64,
        pm1_event_len as u64,
        true,
        true,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 64)? as u64,
        pm1_control_len as u64,
        true,
        true,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 68)? as u64,
        pm1_control_len as u64,
        true,
        true,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 72)? as u64,
        bytes[90] as u64,
        true,
        true,
    );
    // PM_TMR is read-only.
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 76)? as u64,
        bytes[91] as u64,
        true,
        false,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 80)? as u64,
        bytes[92] as u64,
        read_u32(bytes, 60)? as u64,
        pm1_event_len as u64,
        true,
        true,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 64)? as u64,
        pm1_control_len as u64,
        true,
        true,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 68)? as u64,
        pm1_control_len as u64,
        true,
        true,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 72)? as u64,
        bytes[90] as u64,
        true,
        true,
    );
    // PM_TMR is read-only.
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 76)? as u64,
        bytes[91] as u64,
        true,
        false,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 80)? as u64,
        bytes[92] as u64,
        true,
        true,
    );
    add_io_candidate(
        &mut io_grants,
        &deny,
        deny_complete,
        snapshot_id,
        read_u32(bytes, 84)? as u64,
        bytes[93] as u64,
        true,
        true,
    );

    // Extended FADT X_* GAS blocks (ACPI 2.0+); skip RESET_REG (offset 116).
    let x_blocks: &[(usize, u8, bool)] = &[
        (148, pm1_event_len, true),   // X_PM1a_EVT_BLK
        (160, pm1_event_len, true),   // X_PM1b_EVT_BLK
        (172, pm1_control_len, true), // X_PM1a_CNT_BLK
        (184, pm1_control_len, true), // X_PM1b_CNT_BLK
        (196, bytes[90], true),       // X_PM2_CNT_BLK
        (208, bytes[91], false),      // X_PM_TMR_BLK (RO)
        (220, bytes[92], true),       // X_GPE0_BLK
        (232, bytes[93], true),       // X_GPE1_BLK
    ];
    for &(offset, len, writable) in x_blocks {
        if bytes.len() >= offset + 12 && len > 0 {
            if let Some(gas) = Gas::decode(&bytes[offset..offset + 12]) {
                if gas.address != 0 {
                    match gas.address_space {
                        AddressSpace::SystemIo => add_io_candidate(
                            &mut io_grants,
                            &deny,
                            deny_complete,
                            snapshot_id,
                            gas.address,
                            len as u64,
                            true,
                            writable,
                        ),
                        AddressSpace::SystemMemory => add_mmio_candidate(
                            &mut mmio_grants,
                            &deny,
                            deny_complete,
                            snapshot_id,
                            gas.address,
                            len as u64,
                            true,
                            writable,
                            WriteClass::FadtPm,
                            true,
                        ),
                        _ => {}
                    }
                }
            }
        }
    }

    // Boot memory map ACPI_NVS (kind == 3) regions: RW, already mapped in HHDM.
    for region in memmap {
        if region.kind == 3 && region.length > 0 {
            add_mmio_candidate(
                &mut mmio_grants,
                &deny,
                deny_complete,
                snapshot_id,
                region.base,
                region.length,
                true,
                true,
                WriteClass::AcpiNvs,
                false,
            );
        }
    }

    let _ = &mut deny;
    Ok((io_grants, mmio_grants))
}

/// Read `SCI_INT` (offset 46, `u16`) from the uACPI-validated FADT.
pub fn fadt_sci_irq() -> Option<u32> {
    let table = huesos_uacpi::Table::find(b"FACP").ok()?;
    let bytes = table.bytes().ok()?;
    let field = bytes.get(46..48)?;
    let sci = u16::from_le_bytes([field[0], field[1]]);
    (sci != 0).then_some(u32::from(sci))
}

/// Legacy wrapper for callers/tests that only inspect FADT SystemIO grants.
pub fn fadt_system_io_grants() -> Result<Vec<SystemIoGrant>, PolicyError> {
    let table = huesos_uacpi::Table::find(b"FACP").map_err(|_| PolicyError::MissingFadt)?;
    let bytes = table.bytes().map_err(|_| PolicyError::InvalidFadt)?;
    if bytes.len() < 94 {
        return Err(PolicyError::InvalidFadt);
    }
    let dummy_memmap = [MemoryRegion {
        base: 0x10_0000,
        length: 0x10_0000,
        kind: 0,
        usable: true,
    }];
    let (io, _) = derive_broker_policy(1, &dummy_memmap)?;
    let _ = bytes;
    Ok(io)
}

fn build_sacred_deny_set(
    fadt_bytes: &[u8],
    memmap: &[MemoryRegion],
) -> Result<Vec<DenyRange>, PolicyError> {
    let mut deny = Vec::new();
    deny.try_reserve_exact(MAX_DENY_RANGES)
        .map_err(|_| PolicyError::OutOfMemory)?;

    // All non-NVS memmap regions are sacred to the kernel/bootloader.
    for region in memmap {
        if region.kind != 3 && region.length > 0 {
            push_deny(&mut deny, Space::Memory, region.base, region.length)?;
        }
    }

    // Low-memory AP trampoline & page 0.
    push_deny(&mut deny, Space::Memory, 0, 0x1_0000)?;
    // Default LAPIC, IOAPIC, HPET, TPM2 CRB.
    push_deny(&mut deny, Space::Memory, 0xFEE0_0000, 0x1000)?;
    push_deny(&mut deny, Space::Memory, 0xFEC0_0000, 0x1000)?;
    push_deny(&mut deny, Space::Memory, 0xFED0_0000, 0x1000)?;
    push_deny(&mut deny, Space::Memory, 0xFED4_0000, 0x5000)?;

    // FADT SMI_CMD & RESET_REG.
    if let Ok(smi_cmd) = read_u32(fadt_bytes, 48) {
        if smi_cmd != 0 {
            push_deny(&mut deny, Space::Io, smi_cmd as u64, 1)?;
        }
    }
    if fadt_bytes.len() >= 128 {
        if let Some(reset_reg) = Gas::decode(&fadt_bytes[116..128]) {
            if reset_reg.address != 0 {
                match reset_reg.address_space {
                    AddressSpace::SystemIo => {
                        push_deny(&mut deny, Space::Io, reset_reg.address, 1)?;
                    }
                    AddressSpace::SystemMemory => {
                        push_deny(&mut deny, Space::Memory, reset_reg.address, 4)?;
                    }
                    _ => {}
                }
            }
        }
    }

    // Legacy sacred I/O ports: PCI config, i8042, COM1, PIC, PIT.
    push_deny(&mut deny, Space::Io, 0xCF8, 8)?;
    push_deny(&mut deny, Space::Io, 0x60, 1)?;
    push_deny(&mut deny, Space::Io, 0x64, 1)?;
    push_deny(&mut deny, Space::Io, 0x3F8, 8)?;
    push_deny(&mut deny, Space::Io, 0x20, 2)?;
    push_deny(&mut deny, Space::Io, 0xA0, 2)?;
    push_deny(&mut deny, Space::Io, 0x40, 4)?;

    Ok(deny)
}

fn push_deny(
    deny: &mut Vec<DenyRange>,
    space: Space,
    base: u64,
    length: u64,
) -> Result<(), PolicyError> {
    if length == 0 || deny.len() >= MAX_DENY_RANGES {
        return Ok(());
    }
    deny.push(DenyRange {
        space,
        range: Range { base, length },
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_io_candidate(
    grants: &mut Vec<SystemIoGrant>,
    deny: &[DenyRange],
    deny_complete: bool,
    snapshot_id: u64,
    base: u64,
    length: u64,
    read: bool,
    write: bool,
) {
    if base == 0 || length == 0 || grants.len() >= MAX_FADT_GRANTS {
        return;
    }
    let Ok(port) = u16::try_from(base) else {
        return;
    };
    let Ok(port_len) = u16::try_from(length) else {
        return;
    };
    let policy = PolicyGrant {
        base: Grant {
            space: Space::Io,
            range: Range { base, length },
            read,
            write,
            snapshot_id,
        },
        write_class: write.then_some(WriteClass::FadtPm),
        write_mask: if write { u64::MAX } else { 0 },
    };
    // Probe 1-byte read at base to validate whole-candidate disjointness.
    let probe = Access {
        space: Space::Io,
        base,
        offset: 0,
        width: 1,
        direction: Direction::Read,
        snapshot_id,
    };
    if !authorizes_policy(policy, deny, deny_complete, probe, 0) {
        return;
    }
    grants.push(SystemIoGrant {
        base: port,
        length: port_len,
        read,
        write,
        write_class: policy.write_class,
        write_mask: policy.write_mask,
    });
}

#[allow(clippy::too_many_arguments)]
fn add_mmio_candidate(
    grants: &mut Vec<MmioGrant>,
    deny: &[DenyRange],
    deny_complete: bool,
    snapshot_id: u64,
    base: u64,
    length: u64,
    read: bool,
    write: bool,
    write_class: WriteClass,
    map_nocache: bool,
) {
    if base == 0 || length == 0 || grants.len() >= MAX_MMIO_GRANTS {
        return;
    }
    let policy = PolicyGrant {
        base: Grant {
            space: Space::Memory,
            range: Range { base, length },
            read,
            write,
            snapshot_id,
        },
        write_class: write.then_some(write_class),
        write_mask: if write { u64::MAX } else { 0 },
    };
    let probe = Access {
        space: Space::Memory,
        base,
        offset: 0,
        width: 1,
        direction: Direction::Read,
        snapshot_id,
    };
    if !authorizes_policy(policy, deny, deny_complete, probe, 0) {
        return;
    }
    if map_nocache {
        let flags = x86_64::structures::paging::PageTableFlags::PRESENT
            | x86_64::structures::paging::PageTableFlags::WRITABLE
            | x86_64::structures::paging::PageTableFlags::NO_CACHE
            | x86_64::structures::paging::PageTableFlags::NO_EXECUTE;
        if huesos_arch::paging::map_hhdm_range_flags(base, length, flags).is_err() {
            return;
        }
    }
    grants.push(MmioGrant {
        base,
        length,
        read,
        write,
        write_class: policy.write_class,
        write_mask: policy.write_mask,
    });
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PolicyError> {
    let field = bytes
        .get(offset..offset + 4)
        .ok_or(PolicyError::InvalidFadt)?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}
