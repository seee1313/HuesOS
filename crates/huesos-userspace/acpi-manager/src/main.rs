//! Supervised isolated Ring-3 ACPI manager bootstrap.
//!
//! AP-6 validates generation-tagged lifecycle control plus retained archive,
//! broker, and self-VMAR capabilities. AP-7 additionally interprets the
//! archived `MCFG` table and publishes one bounded, immutable `HMCF`
//! config-window snapshot for DriverManager to retain. Full uACPI namespace
//! execution remains disabled until the later AML stages.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::acpi_archive::{
    ArchiveReadError, ArchiveReader, ArchiveSummary, TABLE_ENTRY_BYTES,
};
use huesos_abi::acpi_broker::{ArchiveError, MAX_ARCHIVE_BYTES};
use huesos_abi::acpi_manager;
use huesos_abi::hmcf;
use libcanvas::{println, wait_any, Channel, ErrorCode, Signals, Vmar, Vmo, WaitItem};

#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

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
    // SAFETY: called once at process startup before any allocation or
    // additional thread exists.
    if unsafe { !HEAP.init() } {
        libcanvas::debug::write_str("[acpi-manager] hardened heap init failed\n");
        libcanvas::process::exit(-10);
    }
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
    #[cfg(feature = "restart-smoke")]
    if inputs.hello_flags & acpi_manager::HELLO_FLAG_INJECT_PRE_READY_ALWAYS != 0 {
        println!(
            "[acpi-manager] injected pre-ready exit generation {}",
            generation
        );
        libcanvas::process::exit(-71);
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
    // AP-7: publish the bounded HMCF snapshot from the archived MCFG.
    // Never blocks readiness: absence of a valid MCFG is reported and
    // the lifecycle continues fail-closed (no HMCF, no config
    // authority downstream).
    let hmcf_image = publish_hmcf(&bootstrap, generation, &archive, &summary);

    let Some(self_vmar) = inputs.self_vmar.take() else {
        send_failure(
            &bootstrap,
            generation,
            acpi_manager::Status::MissingCapability,
            3,
        );
        libcanvas::process::exit(-7);
    };
    if let Err(err) = huesos_uacpi_runtime::install_archive(archive, self_vmar) {
        println!("[acpi-manager] archive installation failed: {:?}", err);
        send_failure(
            &bootstrap,
            generation,
            acpi_manager::Status::InvalidArchive,
            0,
        );
        libcanvas::process::exit(-7);
    }

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
    if !huesos_uacpi_runtime::install_broker(broker, summary.firmware_snapshot_id) {
        println!("[acpi-manager] broker runtime installation failed");
        send_failure(
            &bootstrap,
            generation,
            acpi_manager::Status::BrokerDenied,
            0,
        );
        libcanvas::process::exit(-6);
    }
    huesos_uacpi_runtime::work::reset_generation(generation);
    match huesos_uacpi_runtime::namespace::load_namespace(summary.firmware_snapshot_id) {
        Ok(ns) => println!(
            "[acpi-manager] AML namespace loaded (snapshot {}, degraded={})",
            ns.snapshot_id, ns.degraded_opregions
        ),
        Err(err) => {
            println!("[acpi-manager] AML namespace load failed: {:?}", err);
            send_failure(
                &bootstrap,
                generation,
                acpi_manager::Status::BrokerDenied,
                0,
            );
            libcanvas::process::exit(-7);
        }
    }

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

    // Crash-after-readiness smoke: announce readiness, then die. The next
    // generation observes a peer-closed channel after a recorded Ready.
    #[cfg(feature = "restart-smoke")]
    if generation == 2 && inputs.hello_flags & acpi_manager::HELLO_FLAG_INJECT_POST_READY_EXIT != 0
    {
        println!("[acpi-manager] injected post-ready exit generation 2");
        libcanvas::process::exit(-72);
    }

    // Stale-control smoke: a single heartbeat carrying a foreign generation
    // must be ignored by DriverManager's generation check.
    #[cfg(feature = "restart-smoke")]
    if generation >= 3 && inputs.hello_flags & acpi_manager::HELLO_FLAG_INJECT_STALE_HEARTBEAT != 0
    {
        let _ = send_control(
            &bootstrap,
            acpi_manager::Message {
                opcode: acpi_manager::Opcode::Heartbeat,
                manager_generation: generation - 1,
                status: acpi_manager::Status::Ok,
                detail: 0,
            },
        );
        println!(
            "[acpi-manager] injected foreign-generation heartbeat {} (self {})",
            generation - 1,
            generation
        );
    }

    let mut fallback_ticks = 0u64;
    let mut last_heartbeat = monotonic_or(&mut fallback_ticks);
    let mut pending_mediation: Option<Channel> = None;
    let mut last_pci_generation: Option<u64> = None;
    let mut namespace_initialized = false;
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
        drain_mediation_bootstrap(
            &bootstrap,
            &mut pending_mediation,
            &mut last_pci_generation,
            &mut namespace_initialized,
            generation,
            summary.firmware_snapshot_id,
            hmcf_image.as_ref().map(|(buf, len)| &buf[..*len]),
        );
        libcanvas::process::yield_now();
    }
}

/// Drain any mediation-channel traffic that arrives after readiness:
/// the one private channel end (label
/// [`huesos_abi::pci_mediation::MEDIATION_CHANNEL_LABEL`]) and the
/// plain `pci-config-read-gen:<generation>` announcement that binds the
/// PCI Manager generation. Once both are present, install/refresh the
/// mediation requester in `uacpi-runtime`, run the bounded self-test, and
/// (once per `acpi-manager` generation) execute AP-14 namespace
/// initialization (`_PIC(IOAPIC)`, `_REG`, `_STA`, `_INI`) followed by AP-15
/// `HPCI` root-bridge publication when eligible.
fn drain_mediation_bootstrap(
    bootstrap: &Channel,
    pending_mediation: &mut Option<Channel>,
    last_pci_generation: &mut Option<u64>,
    namespace_initialized: &mut bool,
    generation: u64,
    firmware_snapshot_id: u64,
    hmcf_bytes: Option<&[u8]>,
) {
    let mut bytes = [0u8; 64];
    for _ in 0..4 {
        match bootstrap.read_optional_handle(&mut bytes) {
            Ok((length, Some(handle)))
                if &bytes[..length] == huesos_abi::pci_mediation::MEDIATION_CHANNEL_LABEL =>
            {
                *pending_mediation = Some(Channel::from_handle(handle));
            }
            Ok((_length, Some(handle))) => drop(handle),
            Ok((length, None)) => {
                if let Some(pci_generation) = parse_generation_announcement(&bytes[..length]) {
                    if *last_pci_generation != Some(pci_generation) {
                        if let Some(channel) = pending_mediation.take() {
                            if huesos_uacpi_runtime::install_or_refresh_pci_mediation(
                                channel,
                                generation,
                                pci_generation,
                                firmware_snapshot_id,
                            ) {
                                *last_pci_generation = Some(pci_generation);
                                huesos_uacpi_runtime::run_mediation_self_test();
                                if !*namespace_initialized {
                                    *namespace_initialized = true;
                                    run_namespace_initialize(
                                        bootstrap,
                                        generation,
                                        firmware_snapshot_id,
                                        hmcf_bytes,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
            Err(_) => break,
        }
    }
}

fn run_namespace_initialize(
    bootstrap: &Channel,
    generation: u64,
    firmware_snapshot_id: u64,
    hmcf_bytes: Option<&[u8]>,
) {
    match huesos_uacpi_runtime::namespace::initialize_namespace(firmware_snapshot_id) {
        Ok(init) => {
            println!(
                "[acpi-manager] AML namespace initialized (snapshot {}, degraded={}, hpci_eligible={}, detail=0x{:x}, pic_status={})",
                init.snapshot_id,
                init.degraded,
                init.hpci_eligible,
                init.detail_flags,
                init.pic_status
            );
            let mut detail_flags = init.detail_flags;
            if init.hpci_eligible {
                if let Some(hmcf) = hmcf_bytes {
                    if !publish_hpci(bootstrap, generation, firmware_snapshot_id, hmcf) {
                        detail_flags |= acpi_manager::INIT_DETAIL_AML_ERROR;
                    }
                } else {
                    println!(
                        "[acpi-manager] HMCF absent; withholding HPCI publication (snapshot {})",
                        firmware_snapshot_id
                    );
                }
            } else {
                println!(
                    "[acpi-manager] withholding HPCI due to blocking init flags 0x{:x}",
                    detail_flags
                );
            }
            let msg = acpi_manager::Message::namespace_initialized(
                generation,
                init.degraded || acpi_manager::detail_blocks_hpci(detail_flags),
                detail_flags,
            );
            if !send_control(bootstrap, msg) {
                libcanvas::process::exit(-10);
            }
        }
        Err(err) => {
            println!("[acpi-manager] AML namespace initialize failed: {:?}", err);
            let msg = acpi_manager::Message {
                opcode: acpi_manager::Opcode::NamespaceInitialized,
                manager_generation: generation,
                status: acpi_manager::Status::NamespaceInitFailed,
                detail: acpi_manager::INIT_DETAIL_AML_ERROR,
            };
            if !send_control(bootstrap, msg) {
                libcanvas::process::exit(-10);
            }
        }
    }
}

fn publish_hpci(
    bootstrap: &Channel,
    generation: u64,
    firmware_snapshot_id: u64,
    hmcf_bytes: &[u8],
) -> bool {
    let mut hpci_buf = [0u8; huesos_abi::pci::MAX_ENCODED_BYTES];
    let (hpci_len, table) = match huesos_uacpi_runtime::roots::collect_and_encode_hpci(
        firmware_snapshot_id,
        hmcf_bytes,
        &mut hpci_buf,
    ) {
        Ok(res) => res,
        Err(error) => {
            println!(
                "[acpi-manager] HPCI root collection failed (withholding HPCI): {:?}",
                error
            );
            return false;
        }
    };
    let Ok(vmo) = Vmo::create(hpci_len as u64) else {
        println!("[acpi-manager] failed to create HPCI VMO; withholding HPCI");
        return false;
    };
    match vmo.write(0, &hpci_buf[..hpci_len]) {
        Ok(written) if written == hpci_len => {}
        _ => {
            println!("[acpi-manager] failed to populate HPCI VMO; withholding HPCI");
            return false;
        }
    }
    let rights =
        huesos_abi::rights::READ | huesos_abi::rights::DUPLICATE | huesos_abi::rights::TRANSFER;
    let Ok(duplicate) = vmo.duplicate(rights) else {
        println!("[acpi-manager] failed to seal HPCI VMO rights; withholding HPCI");
        return false;
    };
    drop(vmo);
    if let Err((error, _handle)) =
        bootstrap.write_handle(acpi_manager::HPCI_VMO_LABEL, duplicate.into_handle())
    {
        println!("[acpi-manager] HPCI transfer failed: {}", error.as_str());
        return false;
    }
    println!(
        "[acpi-manager] published HPCI: {} root(s), {} aperture(s), snapshot {}, generation {}",
        table.root_count, table.aperture_count, firmware_snapshot_id, generation
    );
    true
}

/// Parse `pci-config-read-gen:<decimal>` with a non-zero result.
fn parse_generation_announcement(bytes: &[u8]) -> Option<u64> {
    let rest = bytes.strip_prefix(huesos_abi::pci_mediation::MEDIATION_GENERATION_PREFIX)?;
    if rest.is_empty() || rest.len() > 20 {
        return None;
    }
    let mut value = 0u64;
    for &digit in rest {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
    }
    (value != 0).then_some(value)
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
    let io_denied = broker.system_io_read(0x80, 1, 1, 1).is_ok_and(|response| {
        response.status == huesos_abi::acpi_broker::Status::AccessDenied as i32
            && response.request_id == 1
    });
    let mmio_denied = broker
        .mmio_read(0xFEE0_0000, 4, 1, 2)
        .is_ok_and(|response| {
            response.status == huesos_abi::acpi_broker::Status::AccessDenied as i32
                && response.request_id == 2
        });
    io_denied && mmio_denied
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

/// Interpret the archived `MCFG` table and publish one bounded,
/// immutable `HMCF` config-window snapshot on `bootstrap`.
///
/// Fail-closed at every step: any inconsistency — archive mutation
/// under us, an ambiguous or invalid MCFG, an identity mismatch —
/// means no HMCF is published. Readiness is unaffected; consumers
/// stay fail-closed until a valid bound snapshot arrives.
fn publish_hmcf(
    bootstrap: &Channel,
    generation: u64,
    archive: &Vmo,
    summary: &ArchiveSummary,
) -> Option<([u8; hmcf::MAX_BYTES], usize)> {
    let mut header = [0u8; huesos_abi::acpi_archive::HEADER_BYTES];
    if !vmo_read_exact(archive, 0, &mut header) {
        println!("[acpi-manager] failed to re-read archive header; HMCF not published");
        return None;
    }
    let Ok(header_v2) = huesos_abi::acpi_archive::decode_v2_header(&header) else {
        println!("[acpi-manager] archive header rejected on re-read; HMCF not published");
        return None;
    };
    if header_v2.firmware_snapshot_id != summary.firmware_snapshot_id {
        println!("[acpi-manager] archive snapshot changed under us; HMCF not published");
        return None;
    }

    // Locate the MCFG table. At most one is accepted; ambiguity is
    // rejected rather than guessed.
    let mut mcfg: Option<(u64, u32)> = None;
    for index in 0..header_v2.table_count {
        let entry_offset =
            header_v2.table_entries_offset + u64::from(index) * TABLE_ENTRY_BYTES as u64;
        let mut entry_bytes = [0u8; TABLE_ENTRY_BYTES];
        if !vmo_read_exact(archive, entry_offset, &mut entry_bytes) {
            println!(
                "[acpi-manager] table directory truncated at entry {}; HMCF not published",
                index
            );
            return None;
        }
        let Ok(entry) = huesos_abi::acpi_archive::decode_v2_table_entry(&entry_bytes) else {
            println!(
                "[acpi-manager] table directory entry {} invalid; HMCF not published",
                index
            );
            return None;
        };
        if entry.signature == *b"MCFG" {
            if mcfg.is_some() {
                println!("[acpi-manager] multiple MCFG tables in archive; HMCF not published");
                return None;
            }
            mcfg = Some((entry.offset, entry.length));
        }
    }
    let Some((mcfg_offset, mcfg_length)) = mcfg else {
        println!("[acpi-manager] no MCFG table in archive; HMCF not published");
        return None;
    };
    const MCFG_MAX_BYTES: usize = huesos_pci::mcfg::MCFG_HEADER_BYTES
        + huesos_pci::mcfg::MAX_MCFG_ALLOCATIONS * huesos_pci::mcfg::MCFG_ALLOCATION_BYTES;
    let length = mcfg_length as usize;
    if !(huesos_pci::mcfg::MCFG_HEADER_BYTES..=MCFG_MAX_BYTES).contains(&length) {
        println!(
            "[acpi-manager] MCFG table length {} out of bounds; HMCF not published",
            length
        );
        return None;
    }
    let mut mcfg_bytes = [0u8; MCFG_MAX_BYTES];
    if !vmo_read_exact(archive, mcfg_offset, &mut mcfg_bytes[..length]) {
        println!("[acpi-manager] MCFG table read failed; HMCF not published");
        return None;
    }
    let (window_count, windows) = match huesos_pci::mcfg::decode_all(&mcfg_bytes[..length]) {
        Ok(decoded) => decoded,
        Err(error) => {
            println!(
                "[acpi-manager] MCFG validation failed: {}; HMCF not published",
                mcfg_error_name(error)
            );
            return None;
        }
    };
    if window_count == 0 {
        println!("[acpi-manager] MCFG contains no allocations; HMCF not published");
        return None;
    }

    const EMPTY: hmcf::HmcfRecord = hmcf::HmcfRecord {
        segment: 0,
        start_bus: 0,
        end_bus: 0,
        ecam_base: 0,
        span_bytes: 0,
        flags: 0,
    };
    let mut records = [EMPTY; hmcf::MAX_RECORDS as usize];
    for (slot, region) in records.iter_mut().zip(windows.iter().take(window_count)) {
        let Ok(record) = hmcf::HmcfRecord::new(
            region.segment(),
            region.start_bus(),
            region.end_bus(),
            region.base(),
        ) else {
            println!("[acpi-manager] ECAM window failed derivation; HMCF not published");
            return None;
        };
        *slot = record;
    }
    let count = window_count;
    let mut image = [0u8; hmcf::MAX_BYTES];
    let Ok(total) = hmcf::encode(
        summary.firmware_snapshot_id,
        generation,
        &records[..count],
        &mut image,
    ) else {
        println!("[acpi-manager] HMCF encoding rejected; HMCF not published");
        return None;
    };

    let vmo = match Vmo::create(total as u64) {
        Ok(vmo) => vmo,
        Err(_) => {
            println!("[acpi-manager] failed to create HMCF VMO; HMCF not published");
            return None;
        }
    };
    match vmo.write(0, &image[..total]) {
        Ok(written) if written == total => {}
        _ => {
            println!("[acpi-manager] failed to fill HMCF VMO; HMCF not published");
            return None;
        }
    }
    // Publish read-only from every handle that leaves this process:
    // duplicate with READ|DUPLICATE|TRANSFER (no WRITE, no MAP), then
    // drop our own write-capable handle so the bytes are immutable
    // system-wide from this point on.
    let rights =
        huesos_abi::rights::READ | huesos_abi::rights::DUPLICATE | huesos_abi::rights::TRANSFER;
    let Ok(duplicate) = vmo.duplicate(rights) else {
        println!("[acpi-manager] failed to seal HMCF VMO rights; HMCF not published");
        return None;
    };
    drop(vmo);
    if let Err((error, _handle)) =
        bootstrap.write_handle(acpi_manager::HMCF_VMO_LABEL, duplicate.into_handle())
    {
        println!("[acpi-manager] HMCF transfer failed: {}", error.as_str());
        return None;
    }
    println!(
        "[acpi-manager] published HMCF: {} window(s), snapshot {}, generation {}",
        count, summary.firmware_snapshot_id, generation
    );
    Some((image, total))
}

/// Read exactly `buf.len()` bytes from the archive VMO at `offset`.
fn vmo_read_exact(vmo: &Vmo, offset: u64, buf: &mut [u8]) -> bool {
    let mut filled = 0usize;
    while filled < buf.len() {
        let Some(cursor) = offset.checked_add(filled as u64) else {
            return false;
        };
        match vmo.read(cursor, &mut buf[filled..]) {
            Ok(0) => return false,
            Ok(read_bytes) => filled += read_bytes,
            Err(_) => return false,
        }
    }
    true
}

const fn mcfg_error_name(error: huesos_pci::mcfg::McfgError) -> &'static str {
    match error {
        huesos_pci::mcfg::McfgError::BadSignature => "bad signature",
        huesos_pci::mcfg::McfgError::BadLength => "bad length",
        huesos_pci::mcfg::McfgError::BadChecksum => "bad checksum",
        huesos_pci::mcfg::McfgError::ReservedNonZero => "reserved field non-zero",
        huesos_pci::mcfg::McfgError::TooManyAllocations => "too many allocations",
        huesos_pci::mcfg::McfgError::InvalidAllocation(_) => "invalid allocation",
        huesos_pci::mcfg::McfgError::Overlap => "overlapping windows",
        huesos_pci::mcfg::McfgError::NoMemory => "allocation failure",
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
