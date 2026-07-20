//! Isolated Ring-3 ACPI manager bootstrap.
//!
//! This stage validates the immutable table archive and establishes lifecycle
//! supervision. Full uACPI namespace/AML execution is added only after the
//! privileged broker channel and deny-by-default resource grants are present.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::acpi_archive::PhysicalIndex;
use huesos_abi::acpi_broker::{
    MAX_ARCHIVE_BYTES, MAX_TABLE_BYTES, MAX_TABLES, TableArchiveEntry,
    TABLE_ARCHIVE_ENTRY_BYTES, TABLE_ARCHIVE_HEADER_BYTES, TABLE_ARCHIVE_MAGIC, VERSION,
};
use libcanvas::{Channel, ErrorCode, Vmo, println};

const ARCHIVE_MESSAGE: &[u8] = b"acpi-tables-vmo";
const BROKER_MESSAGE: &[u8] = b"acpi-broker";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[acpi-manager] isolated Ring-3 service started");
    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"acpi-manager:starting");

    let Some(archive) = receive_archive(&bootstrap) else {
        let _ = bootstrap.write(b"acpi-manager:archive-failed");
        libcanvas::process::exit(-1);
    };
    match validate_archive(&archive) {
        Ok((table_count, index)) => {
            println!(
                "[acpi-manager] validated {} ACPI tables, {} physical ranges indexed",
                table_count, index.len()
            );
        }
        Err(error) => {
            println!("[acpi-manager] invalid table archive: {}", error.as_str());
            let _ = bootstrap.write(b"acpi-manager:archive-failed");
            libcanvas::process::exit(-2);
        }
    }
    let Some(broker) = receive_broker(&bootstrap) else {
        let _ = bootstrap.write(b"acpi-manager:broker-failed");
        libcanvas::process::exit(-3);
    };
    if !verify_deny_by_default(&broker) {
        println!("[acpi-manager] broker deny-by-default self-test failed");
        let _ = bootstrap.write(b"acpi-manager:broker-failed");
        libcanvas::process::exit(-4);
    }
    println!("[acpi-manager] broker deny-by-default self-test OK");
    let _ = bootstrap.write(b"acpi-manager:ready");

    let mut yields = 0u32;
    loop {
        yields = yields.wrapping_add(1);
        if yields == 0 {
            let _ = bootstrap.write(b"heartbeat:acpi");
        }
        libcanvas::process::yield_now();
    }
}

fn receive_archive(bootstrap: &Channel) -> Option<Vmo> {
    let mut message = [0u8; 32];
    for _ in 0..100_000 {
        match bootstrap.read_handle(&mut message) {
            Ok((length, handle)) if &message[..length] == ARCHIVE_MESSAGE => {
                return Some(Vmo::from_handle(handle));
            }
            Ok((_length, _handle)) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(_) => return None,
        }
    }
    None
}

fn receive_broker(bootstrap: &Channel) -> Option<libcanvas::acpi_broker::AcpiBroker> {
    let mut message = [0u8; 32];
    for _ in 0..100_000 {
        match bootstrap.read_handle(&mut message) {
            Ok((length, handle)) if &message[..length] == BROKER_MESSAGE => {
                return Some(libcanvas::acpi_broker::AcpiBroker::from_handle(handle));
            }
            Ok((_length, _handle)) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(_) => return None,
        }
    }
    None
}

fn verify_deny_by_default(broker: &libcanvas::acpi_broker::AcpiBroker) -> bool {
    let request = huesos_abi::acpi_broker::Request {
        version: VERSION,
        opcode: huesos_abi::acpi_broker::Opcode::SystemIoRead as u16,
        width: 1,
        request_id: 1,
        address: 0x80,
        ..huesos_abi::acpi_broker::Request::default()
    };
    broker.call(&request).is_ok_and(|response| {
        response.status == huesos_abi::acpi_broker::Status::AccessDenied as i32
            && response.request_id == request.request_id
    })
}

#[derive(Clone, Copy)]
enum ArchiveError {
    Header,
    Count,
    Range,
    Read,
}

impl ArchiveError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Count => "table count",
            Self::Range => "table range",
            Self::Read => "short VMO read",
        }
    }
}

fn validate_archive(vmo: &Vmo) -> Result<(u32, PhysicalIndex), ArchiveError> {
    let mut header = [0u8; TABLE_ARCHIVE_HEADER_BYTES as usize];
    read_exact(vmo, 0, &mut header)?;
    if header[..8] != TABLE_ARCHIVE_MAGIC
        || u16_at(&header, 8)? != VERSION
        || u16_at(&header, 10)? != TABLE_ARCHIVE_HEADER_BYTES
    {
        return Err(ArchiveError::Header);
    }
    let count = u32_at(&header, 12)?;
    let total_size = u64_at(&header, 16)?;
    if count > MAX_TABLES || total_size > MAX_ARCHIVE_BYTES {
        return Err(ArchiveError::Count);
    }
    let metadata_end = (TABLE_ARCHIVE_HEADER_BYTES as u64)
        .checked_add(
            u64::from(count)
                .checked_mul(TABLE_ARCHIVE_ENTRY_BYTES as u64)
                .ok_or(ArchiveError::Range)?,
        )
        .ok_or(ArchiveError::Range)?;
    if metadata_end > total_size {
        return Err(ArchiveError::Range);
    }

    let mut previous_end = metadata_end;
    let mut index = PhysicalIndex::empty();
    let mut raw = [0u8; TABLE_ARCHIVE_ENTRY_BYTES];
    for index_in_archive in 0..count {
        let offset = u64::from(TABLE_ARCHIVE_HEADER_BYTES)
            + u64::from(index_in_archive) * TABLE_ARCHIVE_ENTRY_BYTES as u64;
        read_exact(vmo, offset, &mut raw)?;
        // SAFETY: raw is a 32-byte buffer matching TableArchiveEntry's repr(C)
        // layout; read_unaligned tolerates the unaligned slice base.
        let entry: TableArchiveEntry =
            unsafe { core::ptr::read_unaligned(raw.as_ptr().cast::<TableArchiveEntry>()) };
        if entry.reserved != [0; 3] {
            return Err(ArchiveError::Header);
        }
        if !(36..=MAX_TABLE_BYTES).contains(&entry.length) || entry.offset < metadata_end {
            return Err(ArchiveError::Range);
        }
        if entry.physical_address != 0
            && entry
                .physical_address
                .checked_add(u64::from(entry.length))
                .is_none()
        {
            return Err(ArchiveError::Range);
        }
        if entry.offset < previous_end {
            return Err(ArchiveError::Range);
        }
        let end = entry
            .offset
            .checked_add(u64::from(entry.length))
            .ok_or(ArchiveError::Range)?;
        if end > total_size {
            return Err(ArchiveError::Range);
        }
        // Only firmware physical ranges back the deny-by-default map index
        // that the future Ring-3 uACPI map callback must consult.
        if entry.physical_address != 0 {
            let _ = index.insert(entry.physical_address, u64::from(entry.length));
        }
        previous_end = end;
    }
    if total_size != 0 {
        let mut probe = [0u8; 1];
        read_exact(vmo, total_size - 1, &mut probe)?;
    }
    Ok((count, index))
}

fn read_exact(vmo: &Vmo, offset: u64, output: &mut [u8]) -> Result<(), ArchiveError> {
    match vmo.read(offset, output) {
        Ok(length) if length == output.len() => Ok(()),
        Ok(_) | Err(_) => Err(ArchiveError::Read),
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ArchiveError> {
    let range = bytes.get(offset..offset + 2).ok_or(ArchiveError::Header)?;
    Ok(u16::from_le_bytes([range[0], range[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ArchiveError> {
    let range = bytes.get(offset..offset + 4).ok_or(ArchiveError::Header)?;
    Ok(u32::from_le_bytes([range[0], range[1], range[2], range[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ArchiveError> {
    let range = bytes.get(offset..offset + 8).ok_or(ArchiveError::Header)?;
    Ok(u64::from_le_bytes([
        range[0], range[1], range[2], range[3], range[4], range[5], range[6], range[7],
    ]))
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[acpi-manager] PANIC\n");
    libcanvas::process::exit(-127);
}
