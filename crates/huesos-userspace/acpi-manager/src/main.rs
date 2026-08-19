//! Supervised isolated Ring-3 ACPI manager bootstrap.
//!
//! AP-6 validates generation-tagged lifecycle control plus retained archive,
//! broker, and self-VMAR capabilities. Full uACPI namespace execution remains
//! disabled until the later AML stages.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::acpi_archive::{ArchiveReadError, ArchiveReader, ArchiveSummary};
use huesos_abi::acpi_broker::{ArchiveError, MAX_ARCHIVE_BYTES, VERSION};
use huesos_abi::acpi_manager;
use libcanvas::{println, wait_any, Channel, ErrorCode, Signals, Vmar, Vmo, WaitItem};

struct BootstrapInputs {
    generation: Option<u64>,
    hello_flags: u32,
    archive: Option<Vmo>,
    broker: Option<libcanvas::acpi_broker::AcpiBroker>,
    self_vmar: Option<Vmar>,
}

impl BootstrapInputs {
    const fn new() -> Self {
        Self {
            generation: None,
            hello_flags: 0,
            archive: None,
            broker: None,
            self_vmar: None,
        }
    }

    fn complete(&self) -> bool {
        self.generation.is_some()
            && self.archive.is_some()
            && self.broker.is_some()
            && self.self_vmar.is_some()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[acpi-manager] isolated Ring-3 service started");
    let bootstrap = libcanvas::channel::bootstrap();
    let Some(mut inputs) = receive_bootstrap(&bootstrap) else {
        libcanvas::process::exit(-1);
    };
    let Some(generation) = inputs.generation else {
        libcanvas::process::exit(-2);
    };

    #[cfg(feature = "restart-smoke")]
    if generation == 1 && inputs.hello_flags & acpi_manager::HELLO_FLAG_INJECT_PRE_READY_EXIT != 0 {
        println!("[acpi-manager] injected pre-ready exit generation 1");
        libcanvas::process::exit(-70);
    }

    let Some(archive) = inputs.archive.take() else {
        send_failure(
            &bootstrap,
            generation,
            acpi_manager::Status::MissingCapability,
            1,
        );
        libcanvas::process::exit(-3);
    };
    let summary = match validate_archive(&archive) {
        Ok(summary) => summary,
        Err(error) => {
            println!(
                "[acpi-manager] invalid table archive: {}",
                archive_error_name(error)
            );
            send_failure(
                &bootstrap,
                generation,
                acpi_manager::Status::InvalidArchive,
                error as u32,
            );
            libcanvas::process::exit(-4);
        }
    };
    println!(
        "[acpi-manager] validated ACPI archive v{}: {} tables, {} physical mappings, snapshot {}",
        summary.version, summary.table_count, summary.mapping_count, summary.firmware_snapshot_id
    );

    let Some(broker) = inputs.broker.take() else {
        send_failure(
            &bootstrap,
            generation,
            acpi_manager::Status::MissingCapability,
            2,
        );
        libcanvas::process::exit(-5);
    };
    if !verify_deny_by_default(&broker) {
        println!("[acpi-manager] broker deny-by-default self-test failed");
        send_failure(
            &bootstrap,
            generation,
            acpi_manager::Status::BrokerDenied,
            0,
        );
        libcanvas::process::exit(-6);
    }
    println!("[acpi-manager] broker deny-by-default self-test OK");

    let Some(_self_vmar) = inputs.self_vmar.take() else {
        send_failure(
            &bootstrap,
            generation,
            acpi_manager::Status::MissingCapability,
            3,
        );
        libcanvas::process::exit(-7);
    };
    if !send_control(
        &bootstrap,
        acpi_manager::Message::ready(generation, summary.table_count),
    ) {
        libcanvas::process::exit(-8);
    }
    println!(
        "[acpi-manager] generation {} archive/broker capabilities ready",
        generation
    );

    let mut fallback_ticks = 0u64;
    let mut last_heartbeat = monotonic_or(&mut fallback_ticks);
    loop {
        let now = monotonic_or(&mut fallback_ticks);
        if now.saturating_sub(last_heartbeat) >= 100 {
            let heartbeat = acpi_manager::Message {
                opcode: acpi_manager::Opcode::Heartbeat,
                manager_generation: generation,
                status: acpi_manager::Status::Ok,
                detail: 0,
            };
            if !send_control(&bootstrap, heartbeat) {
                libcanvas::process::exit(-9);
            }
            last_heartbeat = now;
        }
        libcanvas::process::yield_now();
    }
}

fn receive_bootstrap(bootstrap: &Channel) -> Option<BootstrapInputs> {
    let mut inputs = BootstrapInputs::new();
    let mut bytes = [0u8; 64];
    let items = [WaitItem::new(
        bootstrap.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];
    while !inputs.complete() {
        wait_any(&items, 0).ok()?;
        loop {
            match bootstrap.read_optional_handle(&mut bytes) {
                Ok((length, Some(handle)))
                    if &bytes[..length] == acpi_manager::TABLES_VMO_LABEL =>
                {
                    if inputs.archive.is_some() {
                        drop(handle);
                        return None;
                    }
                    inputs.archive = Some(Vmo::from_handle(handle));
                }
                Ok((length, Some(handle))) if &bytes[..length] == acpi_manager::BROKER_LABEL => {
                    if inputs.broker.is_some() {
                        drop(handle);
                        return None;
                    }
                    inputs.broker = Some(libcanvas::acpi_broker::AcpiBroker::from_handle(handle));
                }
                Ok((length, Some(handle))) if &bytes[..length] == acpi_manager::SELF_VMAR_LABEL => {
                    if inputs.self_vmar.is_some() {
                        drop(handle);
                        return None;
                    }
                    inputs.self_vmar = Some(Vmar::from_handle(handle));
                }
                Ok((_length, Some(handle))) => drop(handle),
                Ok((length, None)) => {
                    let message = acpi_manager::decode(&bytes[..length])?;
                    if message.opcode != acpi_manager::Opcode::Hello
                        || message.status != acpi_manager::Status::Ok
                        || inputs.generation.is_some()
                    {
                        return None;
                    }
                    inputs.generation = Some(message.manager_generation);
                    inputs.hello_flags = message.detail;
                }
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                Err(_) => return None,
            }
        }
    }
    Some(inputs)
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

fn send_failure(bootstrap: &Channel, generation: u64, status: acpi_manager::Status, detail: u32) {
    let _ = send_control(
        bootstrap,
        acpi_manager::Message {
            opcode: acpi_manager::Opcode::Failed,
            manager_generation: generation,
            status,
            detail,
        },
    );
}

fn send_control(bootstrap: &Channel, message: acpi_manager::Message) -> bool {
    let mut bytes = [0u8; acpi_manager::MESSAGE_BYTES];
    let Some(length) = acpi_manager::encode(message, &mut bytes) else {
        return false;
    };
    bootstrap.write(&bytes[..length]).is_ok()
}

fn monotonic_or(fallback: &mut u64) -> u64 {
    match libcanvas::system::monotonic_ticks() {
        Ok(ticks) => ticks,
        Err(_) => {
            *fallback = fallback.saturating_add(1);
            *fallback
        }
    }
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
