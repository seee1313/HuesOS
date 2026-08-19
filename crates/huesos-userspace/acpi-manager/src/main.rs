//! Isolated Ring-3 ACPI manager bootstrap.
//!
//! This stage validates version-1 or version-2 immutable table archives and
//! establishes lifecycle supervision. Full uACPI namespace/AML execution is
//! added only after the privileged callbacks and deny-by-default resource
//! grants land in their dedicated stages.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::acpi_archive::{ArchiveReadError, ArchiveReader, ArchiveSummary};
use huesos_abi::acpi_broker::{ArchiveError, MAX_ARCHIVE_BYTES, VERSION};
use libcanvas::{println, wait_any, Channel, ErrorCode, Signals, Vmo, WaitItem};

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
        Ok(summary) => {
            println!(
                "[acpi-manager] validated ACPI archive v{}: {} tables, {} physical mappings, snapshot {}",
                summary.version,
                summary.table_count,
                summary.mapping_count,
                summary.firmware_snapshot_id
            );
        }
        Err(error) => {
            println!(
                "[acpi-manager] invalid table archive: {}",
                archive_error_name(error)
            );
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
    let items = [WaitItem::new(
        bootstrap.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];
    loop {
        wait_any(&items, 0).ok()?;
        loop {
            match bootstrap.read_optional_handle(&mut message) {
                Ok((length, Some(handle))) if &message[..length] == ARCHIVE_MESSAGE => {
                    return Some(Vmo::from_handle(handle));
                }
                Ok((_length, Some(handle))) => drop(handle),
                Ok((_length, None)) => {}
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                Err(_) => return None,
            }
        }
    }
}

fn receive_broker(bootstrap: &Channel) -> Option<libcanvas::acpi_broker::AcpiBroker> {
    let mut message = [0u8; 32];
    let items = [WaitItem::new(
        bootstrap.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];
    loop {
        wait_any(&items, 0).ok()?;
        loop {
            match bootstrap.read_optional_handle(&mut message) {
                Ok((length, Some(handle))) if &message[..length] == BROKER_MESSAGE => {
                    return Some(libcanvas::acpi_broker::AcpiBroker::from_handle(handle));
                }
                Ok((_length, Some(handle))) => drop(handle),
                Ok((_length, None)) => {}
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                Err(_) => return None,
            }
        }
    }
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

struct VmoArchiveReader<'a> {
    vmo: &'a Vmo,
}

impl ArchiveReader for VmoArchiveReader<'_> {
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ArchiveReadError> {
        match self.vmo.read(offset, output) {
            Ok(length) if length == output.len() => Ok(()),
            Ok(_) | Err(_) => Err(ArchiveReadError),
        }
    }
}

fn validate_archive(vmo: &Vmo) -> Result<ArchiveSummary, ArchiveError> {
    let reader = VmoArchiveReader { vmo };
    huesos_abi::acpi_archive::validate(&reader, MAX_ARCHIVE_BYTES)
}

const fn archive_error_name(error: ArchiveError) -> &'static str {
    match error {
        ArchiveError::Format => "format",
        ArchiveError::UnsupportedVersion => "unsupported version",
        ArchiveError::Metadata => "metadata",
        ArchiveError::Range => "range",
        ArchiveError::Overlap => "overlap",
        ArchiveError::Reserved => "reserved field",
        ArchiveError::Checksum => "checksum",
        ArchiveError::Translation => "physical translation",
        ArchiveError::Capacity => "capacity",
        ArchiveError::Read => "short VMO read",
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[acpi-manager] PANIC\n");
    libcanvas::process::exit(-127);
}
