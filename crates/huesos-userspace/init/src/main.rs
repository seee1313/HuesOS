//! # HuesOS userspace init
//!
//! The first userspace process, launched by the kernel after boot. Init now
//! acts as a tiny userspace service launcher: it validates the syscall/IPC
//! basics, then starts DriverManager and the framebuffer terminal as real
//! child processes through the Zircon-like `ProcessCreate` -> `VmarMap` ->
//! `ThreadCreate` -> `ThreadStart` path.

#![no_std]
#![no_main]

mod log;

use core::panic::PanicInfo;
use libcanvas::{Channel, ErrorCode, Process, Vmo};
use log::InitLogger;

macro_rules! init_logln {
    ($logger:expr, $($arg:tt)*) => {{
        $logger.line(format_args!($($arg)*));
    }};
}

static DRIVER_MANAGER_ELF: &[u8] = include_bytes!(env!("HUESOS_DRIVER_MANAGER_PATH"));
static TERMINAL_ELF: &[u8] = include_bytes!(env!("HUESOS_TERMINAL_PATH"));
static FAULT_PROBE_ELF: &[u8] = include_bytes!(env!("HUESOS_FAULT_PROBE_PATH"));
static SHUTDOWN_BROKER_ELF: &[u8] = include_bytes!(env!("HUESOS_SHUTDOWN_BROKER_PATH"));

const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";

#[derive(Clone, Copy)]
struct BootfsEntry {
    offset: u64,
    len: u64,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut logger = InitLogger::new();
    let bootfs = Vmo::take_init_bootfs();
    let acpi_tables = Vmo::take_init_acpi_tables();
    let storage_boot_info = Vmo::take_init_storage_boot_info();
    let acpi_broker = libcanvas::Handle::take_init_acpi_broker();
    init_logln!(logger, "[init] hello from ring3 userspace, via libcanvas");

    if libcanvas::diagnostics::user_pointer_guard_smoke_test() {
        init_logln!(logger, "[init] user pointer guard smoke OK");
    } else {
        init_logln!(logger, "[init] user pointer guard smoke FAILED");
    }

    run_vmo_check(&mut logger);
    run_channel_check(&mut logger);
    run_monotonic_clock_check(&mut logger);
    run_smp_affinity_check(&mut logger);
    run_process_wait_check(&mut logger);
    run_waitset_check(&mut logger);
    run_fault_isolation_check(&mut logger);
    run_shutdown_authorization_check(&mut logger);

    let driver_manager = launch_service(&mut logger, "driver-manager", DRIVER_MANAGER_ELF);

    if let Some((_, channel)) = &driver_manager {
        read_ready_message(&mut logger, "driver-manager", channel);
        send_bootfs_vmo(&mut logger, channel, &bootfs);
        send_acpi_tables_vmo(&mut logger, channel, &acpi_tables);
        send_acpi_broker(&mut logger, channel, acpi_broker);
        send_storage_boot_info_vmo(&mut logger, channel, &storage_boot_info);
        send_manifest_grants(
            &mut logger,
            channel,
            &bootfs,
            b"/manifests/input-host.hdriver",
        );
        send_nvme_boot_grants(&mut logger, channel, &storage_boot_info);
    }

    // DriverManager owns the isolated ACPI manager launch because it receives
    // both the immutable table archive and the unique broker capability over
    // its bootstrap channel. Launching a second ACPI manager directly from init
    // would strand that process without its required handles.

    // Launch shutdown-broker: the userspace capability owner for
    // atomic halt (Fuchsia-style inversion of control, see
    // docs/ARCHITECTURE_ROADMAP.md §3). Init mints two Resources
    // (IoPort 0x64 + PowerControl), transfers them to the broker, and
    // marks the broker critical so a broker crash before it delivers
    // the halt triggers the kernel-side critical-exit fallback.
    let shutdown_broker = launch_shutdown_broker(&mut logger);

    let registry_pair = create_driver_manager_registry_channel(&mut logger, &driver_manager);

    init_logln!(
        logger,
        "[init] framebuffer log handoff: starting terminal service"
    );
    logger.release_framebuffer();

    let terminal = launch_service(&mut logger, "terminal", TERMINAL_ELF);
    if let Some((_, channel)) = &terminal {
        read_ready_message(&mut logger, "terminal", channel);
        send_terminal_registry_channel(&mut logger, channel, registry_pair);
    }

    init_logln!(
        logger,
        "[init] service launch complete; parking as init supervisor"
    );
    let mut supervisor_message = [0u8; 64];
    let mut doom_process: Option<Process> = None;
    loop {
        let _keep_services_alive = &driver_manager;
        if let Some((_, channel)) = &terminal {
            match channel.read_optional_handle(&mut supervisor_message) {
                Ok((n, None)) if &supervisor_message[..n] == b"system:shutdown" => {
                    init_logln!(logger, "[init] terminal requested orderly shutdown");
                    if let Some((_, broker_channel)) = &shutdown_broker {
                        // Preferred path: forward to shutdown-broker.
                        // The broker performs 8042 quiesce over its
                        // IoPort resource and then invokes sys_hard_halt
                        // via its PowerControl resource. It never
                        // returns, so we do not read for an ack —
                        // this write is the last thing init does on
                        // this path.
                        if let Err(error) = broker_channel.write(b"shutdown") {
                            init_logln!(
                                logger,
                                "[init] shutdown-broker forward failed: {}; falling back",
                                error.as_str()
                            );
                            fallback_legacy_shutdown(&mut logger);
                        }
                    } else {
                        init_logln!(
                            logger,
                            "[init] shutdown-broker unavailable; using legacy SystemShutdown"
                        );
                        fallback_legacy_shutdown(&mut logger);
                    }
                }
                Ok((n, Some(handle))) if &supervisor_message[..n] == b"system:launch-doom" => {
                    if doom_process.is_none() {
                        doom_process = launch_doom(
                            &mut logger,
                            channel,
                            Channel::from_handle(handle),
                            &bootfs,
                        );
                    } else {
                        init_logln!(logger, "[init] Doom is already running");
                        let _ = channel.write(b"doom:error:busy");
                    }
                }
                Ok(_) | Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                Err(error) => init_logln!(
                    logger,
                    "[init] terminal supervisor channel error: {}",
                    error.as_str()
                ),
            }

            let doom_exit = doom_process
                .as_ref()
                .and_then(|process| process.poll_exit().ok().flatten());
            if let Some(code) = doom_exit {
                init_logln!(logger, "[init] Doom exited with status {}", code);
                doom_process = None;
                let _ = channel.write(b"doom:exited");
            }
        }
        libcanvas::process::yield_now();
    }
}

fn launch_doom(
    logger: &mut InitLogger,
    terminal: &Channel,
    keyboard: Channel,
    bootfs: &Vmo,
) -> Option<Process> {
    init_logln!(logger, "[init] launching DoomGeneric/Freedoom from BOOTFS");
    let result = (|| -> libcanvas::Result<Process> {
        let doom = find_bootfs_entry(bootfs, b"/bin/doom.elf")?;
        let wad = find_bootfs_entry(bootfs, b"/data/freedoom1.wad")?;
        let (process, bootstrap) =
            libcanvas::process::spawn_elf_from_vmo("doom", bootfs, doom.offset, doom.len)?;
        init_logln!(logger, "[init] Doom process created; passing capabilities");
        bootstrap
            .write_handle(b"keyboard", keyboard.into_handle())
            .map_err(|(error, _handle)| error)?;

        let wad_vmo = bootfs.duplicate(libcanvas::rights::READ | libcanvas::rights::TRANSFER)?;
        let mut metadata = [0u8; 20];
        metadata[..4].copy_from_slice(b"wad\0");
        metadata[4..12].copy_from_slice(&wad.offset.to_le_bytes());
        metadata[12..20].copy_from_slice(&wad.len.to_le_bytes());
        bootstrap
            .write_handle(&metadata, wad_vmo.into_handle())
            .map_err(|(error, _handle)| error)?;

        init_logln!(logger, "[init] Doom keyboard and read-only WAD VMO passed");
        terminal.write(b"doom:started")?;
        Ok(process)
    })();
    match result {
        Ok(process) => Some(process),
        Err(error) => {
            init_logln!(logger, "[init] Doom launch failed: {}", error.as_str());
            let _ = terminal.write(b"doom:error");
            None
        }
    }
}

fn send_bootfs_vmo(logger: &mut InitLogger, dm_bootstrap: &Channel, bootfs: &Vmo) {
    let duplicate = bootfs.duplicate(
        libcanvas::rights::READ | libcanvas::rights::DUPLICATE | libcanvas::rights::TRANSFER,
    );
    let Ok(vmo) = duplicate else {
        init_logln!(logger, "[init] failed to duplicate HBI BOOTFS VMO");
        return;
    };
    match dm_bootstrap.write_handle(b"bootfs-vmo", vmo.into_handle()) {
        Ok(()) => init_logln!(logger, "[init] passed HBI BOOTFS VMO to DriverManager"),
        Err((e, _handle)) => {
            init_logln!(logger, "[init] failed to pass BOOTFS VMO: {}", e.as_str())
        }
    }
}

fn send_acpi_tables_vmo(logger: &mut InitLogger, dm_bootstrap: &Channel, tables: &Vmo) {
    let duplicate = tables.duplicate(
        libcanvas::rights::READ | libcanvas::rights::DUPLICATE | libcanvas::rights::TRANSFER,
    );
    let Ok(vmo) = duplicate else {
        init_logln!(logger, "[init] ACPI table archive unavailable");
        return;
    };
    match dm_bootstrap.write_handle(b"acpi-tables-vmo", vmo.into_handle()) {
        Ok(()) => init_logln!(logger, "[init] passed ACPI table archive to DriverManager"),
        Err((e, _handle)) => {
            init_logln!(logger, "[init] failed to pass ACPI archive: {}", e.as_str())
        }
    }
}

fn send_acpi_broker(logger: &mut InitLogger, dm_bootstrap: &Channel, broker: libcanvas::Handle) {
    match dm_bootstrap.write_handle(b"acpi-broker", broker) {
        Ok(()) => init_logln!(logger, "[init] transferred ACPI broker capability"),
        Err((error, _handle)) => init_logln!(
            logger,
            "[init] failed to transfer ACPI broker: {}",
            error.as_str()
        ),
    }
}

fn send_storage_boot_info_vmo(logger: &mut InitLogger, dm_bootstrap: &Channel, storage: &Vmo) {
    let duplicate = storage.duplicate(
        libcanvas::rights::READ | libcanvas::rights::DUPLICATE | libcanvas::rights::TRANSFER,
    );
    let Ok(vmo) = duplicate else {
        init_logln!(logger, "[init] storage boot-info VMO unavailable");
        return;
    };
    match dm_bootstrap.write_handle(b"storage-boot-vmo", vmo.into_handle()) {
        Ok(()) => init_logln!(
            logger,
            "[init] passed storage boot-info VMO to DriverManager"
        ),
        Err((error, _handle)) => init_logln!(
            logger,
            "[init] failed to pass storage boot-info VMO: {}",
            error.as_str()
        ),
    }
}

/// Read a driver manifest from BOOTFS, mint the kernel-side `Resource`
/// capabilities it declares, and transfer each handle to driver-manager
/// via its bootstrap channel. The wire label carries the metadata
/// driver-manager needs to know what to do with each handle: it uses
/// the format `resource:<driver_name>:<kind>:<base_hex>:<len_hex>:<mode>`
/// (e.g. `resource:input-host:ioport:0x60:0x1:excl`).
///
/// See `docs/ARCHITECTURE_ROADMAP.md` §4: init is the root userspace
/// supervisor for this MVP and thus the only process the kernel will
/// accept `Syscall::ResourceCreate` from.
fn send_manifest_grants(
    logger: &mut InitLogger,
    dm_bootstrap: &Channel,
    bootfs: &Vmo,
    manifest_path: &[u8],
) {
    use libcanvas::manifest::{parse_for_grants, MAX_RESOURCE_GRANTS};
    use libcanvas::resource::Resource;

    // 1. Locate + read the manifest file.
    let entry = match find_bootfs_entry(bootfs, manifest_path) {
        Ok(entry) => entry,
        Err(e) => {
            init_logln!(
                logger,
                "[init] manifest grants: BOOTFS entry not found for {}: {}",
                core::str::from_utf8(manifest_path).unwrap_or("?"),
                e.as_str()
            );
            return;
        }
    };
    // Bounded static buffer: manifests are small (well under 1 KiB in MVP).
    let mut buf = [0u8; 1024];
    if entry.len as usize > buf.len() {
        init_logln!(
            logger,
            "[init] manifest grants: manifest too large for bounded parser"
        );
        return;
    }
    let take = entry.len as usize;
    let read = match bootfs.read(entry.offset, &mut buf[..take]) {
        Ok(n) => n,
        Err(e) => {
            init_logln!(
                logger,
                "[init] manifest grants: read failed: {}",
                e.as_str()
            );
            return;
        }
    };
    let manifest = parse_for_grants(&buf[..read]);
    let driver_name = manifest.name();
    let grants = manifest.grants();
    if grants.is_empty() {
        init_logln!(
            logger,
            "[init] manifest {} declares no resource grants; sending barrier",
            driver_name
        );
    } else {
        init_logln!(
            logger,
            "[init] manifest {}: minting {} resource grant(s)",
            driver_name,
            grants.len()
        );
    }

    // 2. For each grant: mint + transfer. Bounded-loop iteration keeps
    // us allocation-free even though the manifest is dynamically sized.
    let mut sent = 0usize;
    let mut i = 0usize;
    while i < grants.len() && i < MAX_RESOURCE_GRANTS {
        let grant = grants[i];
        let resource = match Resource::create(grant.kind, grant.base, grant.len, grant.exclusive) {
            Ok(r) => r,
            Err(e) => {
                init_logln!(
                    logger,
                    "[init] manifest {}: Resource::create({:?}, base={:#x}, len={:#x}) failed: {}",
                    driver_name,
                    grant.kind,
                    grant.base,
                    grant.len,
                    e.as_str()
                );
                i += 1;
                continue;
            }
        };
        // Build the wire label into a bounded stack buffer.
        let mut label = [0u8; 96];
        let label_len = format_grant_label(&mut label, driver_name, &grant);
        // SAFETY: label_len is set by format_grant_label to a value
        // <= label.len(), so slicing is in-bounds. Guard against a
        // future formatter bug by clamping.
        let label_slice = &label[..label_len.min(label.len())];
        // Consume the Resource into an owned Handle and hand it to
        // the transfer syscall. On failure, write_handle returns the still-owned
        // handle; this call drops it after logging, so no reservation leaks.
        match dm_bootstrap.write_handle(label_slice, resource.into_handle()) {
            Ok(()) => sent += 1,
            Err((e, _handle)) => init_logln!(
                logger,
                "[init] manifest {}: write_handle failed for {}: {}",
                driver_name,
                core::str::from_utf8(label_slice).unwrap_or("?"),
                e.as_str()
            ),
        }
        i += 1;
    }
    init_logln!(
        logger,
        "[init] manifest {}: transferred {}/{} resource handle(s) to DriverManager",
        driver_name,
        sent,
        grants.len()
    );

    // 3. Critical flag: mark the eventual driver-host process critical
    // after driver-manager launches it. Currently we cannot mark it
    // from here because we don't own the driver-host process handle;
    // driver-manager does the mark_critical syscall when it spawns
    // the host. Signal our intent via a control message so driver-
    // manager knows to make the call.
    if manifest.critical {
        let mut label = [0u8; 64];
        let len = format_critical_label(&mut label, driver_name);
        let payload = &label[..len.min(label.len())];
        match dm_bootstrap.write(payload) {
            Ok(()) => init_logln!(
                logger,
                "[init] manifest {}: signalled critical=true to DriverManager",
                driver_name
            ),
            Err(e) => init_logln!(
                logger,
                "[init] manifest {}: failed to signal critical: {}",
                driver_name,
                e.as_str()
            ),
        }
    }

    // 4. Grants-complete barrier: tell DriverManager it is now safe
    // to spawn this DriverHost. Every `resource:*` transfer and any
    // `resource:mark-critical:*` control message queued before this
    // one is guaranteed by channel FIFO order to be observable by
    // DM before it processes the barrier — so `forward_pending_resources`
    // sees the full grant set. Without this signal DM used to spawn
    // the host as soon as the BOOTFS VMO arrived, racing init's
    // still-in-flight `Resource::create` calls.
    let mut label = [0u8; 96];
    let len = format_grants_complete_label(&mut label, driver_name);
    let payload = &label[..len.min(label.len())];
    match dm_bootstrap.write(payload) {
        Ok(()) => init_logln!(
            logger,
            "[init] manifest {}: signalled grants-complete to DriverManager",
            driver_name
        ),
        Err(e) => init_logln!(
            logger,
            "[init] manifest {}: failed to signal grants-complete: {}",
            driver_name,
            e.as_str()
        ),
    }
}

fn send_nvme_boot_grants(logger: &mut InitLogger, dm_bootstrap: &Channel, storage: &Vmo) {
    use libcanvas::manifest::ResourceGrant;
    use libcanvas::resource::{kind, Resource};
    use libcanvas::storage_boot;

    let mut bytes = [0u8; storage_boot::MAX_ENCODED_BYTES];
    let read = match storage.read(0, &mut bytes) {
        Ok(n) => n,
        Err(error) => {
            init_logln!(
                logger,
                "[init] NVMe boot grants skipped: storage boot-info read failed: {}",
                error.as_str()
            );
            return;
        }
    };
    let Some(info) = storage_boot::decode(&bytes[..read]) else {
        init_logln!(
            logger,
            "[init] NVMe boot grants skipped: bad storage boot-info"
        );
        return;
    };
    if info.nvme_count == 0 {
        init_logln!(
            logger,
            "[init] NVMe boot grants skipped: no NVMe PCI function"
        );
        return;
    }

    let nvme = info.nvme[0];
    let grants = [
        ResourceGrant {
            kind: kind::MMIO,
            base: nvme.bar0_base,
            len: nvme.bar0_len,
            exclusive: true,
        },
        ResourceGrant {
            kind: kind::IRQ,
            base: nvme.irq_line as u64,
            len: 1,
            exclusive: true,
        },
        ResourceGrant {
            kind: kind::DMA_POOL,
            base: info.dma_pool.base,
            len: info.dma_pool.len,
            exclusive: true,
        },
    ];

    init_logln!(
        logger,
        "[init] NVMe boot grants: pci={:02x}:{:02x}.{} bar0={:#x}+{:#x} irq={} dma={:#x}+{:#x}",
        nvme.bus,
        nvme.device,
        nvme.function,
        nvme.bar0_base,
        nvme.bar0_len,
        nvme.irq_line,
        info.dma_pool.base,
        info.dma_pool.len
    );

    let mut sent = 0usize;
    let mut idx = 0usize;
    while idx < grants.len() {
        let grant = grants[idx];
        let resource = match Resource::create(grant.kind, grant.base, grant.len, grant.exclusive) {
            Ok(resource) => resource,
            Err(error) => {
                init_logln!(
                    logger,
                    "[init] NVMe boot grant {:?} base={:#x} len={:#x} failed: {}",
                    grant.kind,
                    grant.base,
                    grant.len,
                    error.as_str()
                );
                idx += 1;
                continue;
            }
        };
        let mut label = [0u8; 96];
        let label_len = format_grant_label(&mut label, "driver-host-nvme", &grant);
        let payload = &label[..label_len.min(label.len())];
        match dm_bootstrap.write_handle(payload, resource.into_handle()) {
            Ok(()) => sent += 1,
            Err((error, _handle)) => init_logln!(
                logger,
                "[init] NVMe boot grant transfer failed for {}: {}",
                core::str::from_utf8(payload).unwrap_or("?"),
                error.as_str()
            ),
        }
        idx += 1;
    }
    init_logln!(
        logger,
        "[init] NVMe boot grants: transferred {}/{} resource handle(s)",
        sent,
        grants.len()
    );

    let mut label = [0u8; 96];
    let len = format_grants_complete_label(&mut label, "driver-host-nvme");
    let payload = &label[..len.min(label.len())];
    match dm_bootstrap.write(payload) {
        Ok(()) => init_logln!(logger, "[init] NVMe boot grants-complete signalled"),
        Err(error) => init_logln!(
            logger,
            "[init] NVMe boot grants-complete failed: {}",
            error.as_str()
        ),
    }
}

fn format_grants_complete_label(out: &mut [u8], driver: &str) -> usize {
    let mut w = FixedWriter::new(out);
    let _ = w.write_bytes(b"manifest:grants-complete:");
    let _ = w.write_bytes(driver.as_bytes());
    w.len()
}

/// Write `resource:<driver>:<kind>:0x<base>:0x<len>:<mode>` into `out`;
/// return the number of bytes written.
fn format_grant_label(
    out: &mut [u8],
    driver: &str,
    grant: &libcanvas::manifest::ResourceGrant,
) -> usize {
    use libcanvas::resource::ResourceKind;
    // "pwr" is used as the short wire label for PowerControl to keep
    // shutdown-broker's manifest / label matcher compact.
    let kind = match grant.kind {
        ResourceKind::IoPort => "ioport",
        ResourceKind::Mmio => "mmio",
        ResourceKind::Irq => "irq",
        ResourceKind::PowerControl => "pwr",
        ResourceKind::DmaPool => "dma",
    };
    let mode = if grant.exclusive { "excl" } else { "shared" };
    let mut w = FixedWriter::new(out);
    let _ = w.write_bytes(b"resource:");
    let _ = w.write_bytes(driver.as_bytes());
    let _ = w.write_bytes(b":");
    let _ = w.write_bytes(kind.as_bytes());
    let _ = w.write_bytes(b":0x");
    let _ = w.write_hex_u64(grant.base);
    let _ = w.write_bytes(b":0x");
    let _ = w.write_hex_u64(grant.len);
    let _ = w.write_bytes(b":");
    let _ = w.write_bytes(mode.as_bytes());
    w.len()
}

fn format_critical_label(out: &mut [u8], driver: &str) -> usize {
    let mut w = FixedWriter::new(out);
    let _ = w.write_bytes(b"resource:mark-critical:");
    let _ = w.write_bytes(driver.as_bytes());
    w.len()
}

/// Bounded no-alloc byte writer used to synthesise the wire labels
/// above. Silently truncates once the target slice is full so a
/// pathologically long driver name cannot cause a panic.
struct FixedWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> FixedWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ()> {
        for &b in bytes {
            if self.len >= self.buf.len() {
                return Err(());
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }

    fn write_hex_u64(&mut self, mut value: u64) -> Result<(), ()> {
        if value == 0 {
            return self.write_bytes(b"0");
        }
        let mut tmp = [0u8; 16];
        let mut idx = tmp.len();
        while value != 0 {
            idx -= 1;
            let nibble = (value & 0xf) as u8;
            tmp[idx] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + (nibble - 10)
            };
            value >>= 4;
        }
        self.write_bytes(&tmp[idx..])
    }
}

fn find_bootfs_entry(vmo: &Vmo, wanted: &[u8]) -> libcanvas::Result<BootfsEntry> {
    let mut header = [0u8; BOOTFS_HEADER_SIZE as usize];
    if vmo.read(0, &mut header)? != header.len() || &header[..8] != BOOTFS_MAGIC {
        return Err(ErrorCode::InvalidArgs);
    }
    let count = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if count > 4096 {
        return Err(ErrorCode::InvalidArgs);
    }
    let data_start = BOOTFS_HEADER_SIZE
        .checked_add(u64::from(count) * BOOTFS_ENTRY_SIZE)
        .ok_or(ErrorCode::InvalidArgs)?;
    let mut raw = [0u8; BOOTFS_ENTRY_SIZE as usize];
    for index in 0..count {
        let offset = BOOTFS_HEADER_SIZE + u64::from(index) * BOOTFS_ENTRY_SIZE;
        if vmo.read(offset, &mut raw)? != raw.len() {
            return Err(ErrorCode::InvalidArgs);
        }
        let path_len = match raw[..BOOTFS_PATH_SIZE].iter().position(|byte| *byte == 0) {
            Some(len) => len,
            None => BOOTFS_PATH_SIZE,
        };
        if &raw[..path_len] != wanted {
            continue;
        }
        let meta = &raw[BOOTFS_PATH_SIZE..];
        let file_offset =
            u64::from_le_bytes(meta[..8].try_into().map_err(|_| ErrorCode::InvalidArgs)?);
        let len = u64::from_le_bytes(meta[8..16].try_into().map_err(|_| ErrorCode::InvalidArgs)?);
        let end = file_offset
            .checked_add(len)
            .filter(|end| file_offset >= data_start && *end > file_offset)
            .ok_or(ErrorCode::InvalidArgs)?;
        // BOOTFS has no size syscall dependency: probing the final byte proves
        // the complete checked range is backed by this VMO.
        let mut probe = [0u8; 1];
        if vmo.read(end - 1, &mut probe)? != 1 {
            return Err(ErrorCode::InvalidArgs);
        }
        return Ok(BootfsEntry {
            offset: file_offset,
            len,
        });
    }
    Err(ErrorCode::NotFound)
}

fn create_driver_manager_registry_channel(
    logger: &mut InitLogger,
    driver_manager: &Option<(Process, Channel)>,
) -> Option<Channel> {
    let Some((_, dm_bootstrap)) = driver_manager else {
        return None;
    };
    match Channel::pair() {
        Ok((terminal_end, dm_end)) => {
            match dm_bootstrap.write_handle(b"registry-channel", dm_end.into_handle()) {
                Ok(()) => {
                    init_logln!(logger, "[init] passed registry channel to DriverManager");
                    Some(terminal_end)
                }
                Err((e, _handle)) => {
                    init_logln!(
                        logger,
                        "[init] failed to pass registry channel: {}",
                        e.as_str()
                    );
                    None
                }
            }
        }
        Err(e) => {
            init_logln!(
                logger,
                "[init] failed to create registry channel: {}",
                e.as_str()
            );
            None
        }
    }
}

fn send_terminal_registry_channel(
    logger: &mut InitLogger,
    terminal_bootstrap: &Channel,
    registry: Option<Channel>,
) {
    let Some(registry) = registry else {
        init_logln!(
            logger,
            "[init] no DriverManager registry channel for terminal"
        );
        return;
    };
    match terminal_bootstrap.write_handle(b"driver-manager-registry", registry.into_handle()) {
        Ok(()) => init_logln!(logger, "[init] passed DriverManager registry to terminal"),
        Err((e, _handle)) => init_logln!(
            logger,
            "[init] failed to pass registry to terminal: {}",
            e.as_str()
        ),
    }
}

fn launch_service(logger: &mut InitLogger, name: &str, elf: &[u8]) -> Option<(Process, Channel)> {
    match libcanvas::process::spawn_elf(name, elf) {
        Ok((process, bootstrap)) => {
            init_logln!(logger, "[init] launched {}", name);
            Some((process, bootstrap))
        }
        Err(e) => {
            init_logln!(logger, "[init] failed to launch {}: {}", name, e.as_str());
            None
        }
    }
}

/// Launch the userspace shutdown-broker, transfer it the two Resource
/// handles it needs (IoPort 0x64 + PowerControl), mark it critical, and
/// wait for its ready message. On any failure returns `None`; the main
/// supervisor loop then falls back to the legacy `SystemShutdown`
/// syscall path.
fn launch_shutdown_broker(logger: &mut InitLogger) -> Option<(Process, Channel)> {
    use libcanvas::manifest::ResourceGrant;
    use libcanvas::resource::{kind, Resource};

    // 1. Mint the two capabilities before spawn so any Resource-create
    // failure is diagnosed before we commit the child process.
    let ioport_grant = ResourceGrant {
        kind: kind::IO_PORT,
        base: 0x64,
        len: 1,
        exclusive: true,
    };
    let power_grant = ResourceGrant {
        kind: kind::POWER_CONTROL,
        base: 0,
        len: 0,
        exclusive: true,
    };
    let ioport = match Resource::create(
        ioport_grant.kind,
        ioport_grant.base,
        ioport_grant.len,
        ioport_grant.exclusive,
    ) {
        Ok(r) => r,
        Err(e) => {
            init_logln!(
                logger,
                "[init] shutdown-broker: IoPort resource mint failed: {}",
                e.as_str()
            );
            return None;
        }
    };
    let power = match Resource::create(
        power_grant.kind,
        power_grant.base,
        power_grant.len,
        power_grant.exclusive,
    ) {
        Ok(r) => r,
        Err(e) => {
            init_logln!(
                logger,
                "[init] shutdown-broker: PowerControl mint failed: {}",
                e.as_str()
            );
            drop(ioport);
            return None;
        }
    };

    // 2. Spawn the broker.
    let (process, bootstrap) =
        match libcanvas::process::spawn_elf("shutdown-broker", SHUTDOWN_BROKER_ELF) {
            Ok(pair) => pair,
            Err(e) => {
                init_logln!(
                    logger,
                    "[init] shutdown-broker: spawn failed: {}",
                    e.as_str()
                );
                drop(ioport);
                drop(power);
                return None;
            }
        };
    init_logln!(logger, "[init] shutdown-broker: spawned");

    // 3. Transfer capabilities via labelled bootstrap messages. Labels
    // are the same format PR-C uses for other manifest grants so the
    // broker can reuse a single parser.
    let mut label = [0u8; 96];
    let ioport_label_len = format_grant_label(&mut label, "shutdown-broker", &ioport_grant);
    let ioport_label = &label[..ioport_label_len.min(label.len())];
    if let Err((e, _handle)) = bootstrap.write_handle(ioport_label, ioport.into_handle()) {
        init_logln!(
            logger,
            "[init] shutdown-broker: IoPort transfer failed: {}",
            e.as_str()
        );
        drop(power);
        return None;
    }
    let mut label2 = [0u8; 96];
    let power_label_len = format_grant_label(&mut label2, "shutdown-broker", &power_grant);
    let power_label = &label2[..power_label_len.min(label2.len())];
    if let Err((e, _handle)) = bootstrap.write_handle(power_label, power.into_handle()) {
        init_logln!(
            logger,
            "[init] shutdown-broker: PowerControl transfer failed: {}",
            e.as_str()
        );
        return None;
    }

    // 4. Mark critical *before* the go barrier, so a broker crash
    // between now and the shutdown command trips the kernel's
    // critical-exit halt fallback.
    if let Err(e) = libcanvas::resource::mark_process_critical(process.handle().raw()) {
        init_logln!(
            logger,
            "[init] shutdown-broker: mark_critical failed: {}",
            e.as_str()
        );
        return None;
    }
    init_logln!(logger, "[init] shutdown-broker: marked critical");

    // 5. Release the broker into its main loop.
    if let Err(e) = bootstrap.write(b"shutdown-broker:go") {
        init_logln!(
            logger,
            "[init] shutdown-broker: go message failed: {}",
            e.as_str()
        );
        return None;
    }

    // 6. Wait for the ready ack.
    let mut buf = [0u8; 64];
    let mut attempts = 0u32;
    loop {
        match bootstrap.read_into(&mut buf) {
            Ok(n) if &buf[..n] == b"shutdown-broker:ready" => {
                init_logln!(logger, "[init] shutdown-broker: ready");
                return Some((process, bootstrap));
            }
            Ok(_) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(e) => {
                init_logln!(
                    logger,
                    "[init] shutdown-broker: ready-wait failed: {}",
                    e.as_str()
                );
                return None;
            }
        }
        attempts = attempts.saturating_add(1);
        if attempts >= 200_000 {
            init_logln!(logger, "[init] shutdown-broker: ready timeout");
            return None;
        }
        libcanvas::process::yield_now();
    }
}

fn fallback_legacy_shutdown(logger: &mut InitLogger) {
    if let Err(error) = libcanvas::system::shutdown() {
        init_logln!(
            logger,
            "[init] shutdown request rejected: {}",
            error.as_str()
        );
    }
}

fn read_ready_message(logger: &mut InitLogger, name: &str, channel: &Channel) {
    let mut buf = [0u8; 64];
    // Cooperative poll with a high attempt budget. Under SMP the service may
    // be scheduled much later; avoid timed-park here (timeout arming is still
    // young) so a stuck waiter cannot freeze init.
    for _ in 0..8_000 {
        match channel.read_into(&mut buf) {
            Ok(n) => {
                let msg = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
                init_logln!(logger, "[init] {} says {}", name, msg);
                return;
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(e) => {
                init_logln!(
                    logger,
                    "[init] {} bootstrap read failed: {}",
                    name,
                    e.as_str()
                );
                return;
            }
        }
    }
    init_logln!(logger, "[init] {} did not send ready message yet", name);
}

fn run_monotonic_clock_check(logger: &mut InitLogger) {
    let result = (|| -> libcanvas::Result<u64> {
        let (_tx, rx) = Channel::pair()?;
        let start = libcanvas::system::monotonic_ticks()?;
        let mut byte = [0u8; 1];
        match rx.read_into_timeout(&mut byte, 10) {
            Err(ErrorCode::TimedOut) => {}
            Ok(_) => return Err(ErrorCode::Busy),
            Err(error) => return Err(error),
        }
        Ok(libcanvas::system::monotonic_ticks()?.saturating_sub(start))
    })();

    match result {
        Ok(elapsed) if (9..=12).contains(&elapsed) => init_logln!(
            logger,
            "[init] monotonic clock OK (10-tick wait measured {} ticks)",
            elapsed
        ),
        Ok(elapsed) => init_logln!(
            logger,
            "[init] monotonic clock FAILED (measured {} ticks)",
            elapsed
        ),
        Err(error) => init_logln!(logger, "[init] monotonic clock FAILED ({})", error.as_str()),
    }
}

fn run_smp_affinity_check(logger: &mut InitLogger) {
    let cpu_count = match libcanvas::system::cpu_count() {
        Ok(count) => count,
        Err(error) => {
            init_logln!(
                logger,
                "[init] SMP affinity self-test skipped ({})",
                error.as_str()
            );
            return;
        }
    };
    if cpu_count < 2 {
        init_logln!(logger, "[init] SMP affinity self-test skipped (single CPU)");
        return;
    }
    let result = (|| -> libcanvas::Result<i64> {
        let (process, bootstrap) =
            libcanvas::process::spawn_elf_on_cpu("affinity-probe", FAULT_PROBE_ELF, 1)?;
        match process.set_affinity(0) {
            Err(ErrorCode::Busy) => {}
            Ok(()) => return Err(ErrorCode::Busy),
            Err(error) => return Err(error),
        }
        bootstrap.write(b"cpu")?;
        wait_process_exit(&process)
    })();
    match result {
        Ok(1) => init_logln!(
            logger,
            "[init] SMP affinity self-test OK (child ran on CPU 1)"
        ),
        Ok(cpu) => init_logln!(
            logger,
            "[init] SMP affinity self-test FAILED (child ran on CPU {})",
            cpu
        ),
        Err(error) => init_logln!(
            logger,
            "[init] SMP affinity self-test FAILED ({})",
            error.as_str()
        ),
    }
}

fn wait_process_exit(process: &Process) -> libcanvas::Result<i64> {
    // Early boot must not park init on a still-maturing cross-process wait
    // queue: a missed wake would prevent every later service from launching.
    // Cooperative polling keeps scheduler progress explicit and is bounded so
    // a broken probe degrades diagnostics instead of hanging the boot forever.
    for _ in 0..100_000 {
        if let Some(code) = process.poll_exit()? {
            return Ok(code);
        }
        libcanvas::process::yield_now();
    }
    Err(ErrorCode::TimedOut)
}

fn run_process_wait_check(logger: &mut InitLogger) {
    let Ok((process, bootstrap)) = libcanvas::process::spawn_elf("wait-probe", FAULT_PROBE_ELF)
    else {
        init_logln!(logger, "[init] ProcessWait lifecycle FAILED (launch)");
        return;
    };
    if bootstrap.write(b"wait").is_err() {
        init_logln!(logger, "[init] ProcessWait lifecycle FAILED (command)");
        return;
    }
    drop(bootstrap);

    // Unlike the early-boot polling helper, this deliberately parks in the
    // blocking syscall. The child yields before exit, so QEMU must exercise
    // registration, park, wake, and lifecycle exit publication.
    match process.wait_exit() {
        Ok(0) => init_logln!(logger, "[init] ProcessWait lifecycle OK (blocked wake)"),
        Ok(code) => init_logln!(
            logger,
            "[init] ProcessWait lifecycle FAILED (exit code {})",
            code
        ),
        Err(error) => init_logln!(
            logger,
            "[init] ProcessWait lifecycle FAILED ({})",
            error.as_str()
        ),
    }
}

fn run_shutdown_authorization_check(logger: &mut InitLogger) {
    let Ok((process, bootstrap)) = libcanvas::process::spawn_elf("shutdown-probe", FAULT_PROBE_ELF)
    else {
        init_logln!(logger, "[init] shutdown authorization FAILED (launch)");
        return;
    };
    if bootstrap.write(b"shutdown").is_err() {
        init_logln!(logger, "[init] shutdown authorization FAILED (command)");
        return;
    }
    drop(bootstrap);
    match wait_process_exit(&process) {
        Ok(0) => init_logln!(
            logger,
            "[init] shutdown authorization OK (unprivileged caller denied)"
        ),
        Ok(code) => init_logln!(
            logger,
            "[init] shutdown authorization FAILED (exit code {})",
            code
        ),
        Err(error) => init_logln!(
            logger,
            "[init] shutdown authorization FAILED ({})",
            error.as_str()
        ),
    }
}

fn run_fault_isolation_check(logger: &mut InitLogger) {
    let cases: [(&[u8], i64); 4] = [
        (b"page", libcanvas::fault_exit::PAGE_FAULT),
        (b"opcode", libcanvas::fault_exit::INVALID_OPCODE),
        (b"gpf", libcanvas::fault_exit::GENERAL_PROTECTION),
        (b"divide", libcanvas::fault_exit::DIVIDE_ERROR),
    ];

    for (command, expected) in cases {
        let Ok((process, bootstrap)) =
            libcanvas::process::spawn_elf("fault-probe", FAULT_PROBE_ELF)
        else {
            init_logln!(logger, "[init] user fault isolation FAILED (launch)");
            return;
        };
        if let Err(error) = bootstrap.write(command) {
            init_logln!(
                logger,
                "[init] user fault isolation FAILED (command: {})",
                error.as_str()
            );
            return;
        }
        drop(bootstrap);
        match wait_process_exit(&process) {
            Ok(code) if code == expected => {}
            Ok(code) => {
                init_logln!(
                    logger,
                    "[init] user fault isolation FAILED (exit code {}, expected {})",
                    code,
                    expected
                );
                return;
            }
            Err(error) => {
                init_logln!(
                    logger,
                    "[init] user fault isolation FAILED ({})",
                    error.as_str()
                );
                return;
            }
        }
    }
    init_logln!(
        logger,
        "[init] user fault isolation OK (#PF/#UD/#GP/#DE contained)"
    );
}

fn run_vmo_check(logger: &mut InitLogger) {
    let payload = b"HuesOS VMO round-trip OK\n";
    let ok = (|| -> libcanvas::Result<bool> {
        let vmo = Vmo::create(4096)?;
        vmo.write(0, payload)?;
        let mut readback = [0u8; 32];
        let n = vmo.read(0, &mut readback)?;
        Ok(n >= payload.len() && &readback[..payload.len()] == payload)
    })();

    match ok {
        Ok(true) => init_logln!(logger, "[init] VMO read/write round-trip OK"),
        Ok(false) => init_logln!(
            logger,
            "[init] VMO read/write round-trip FAILED (data mismatch)"
        ),
        Err(e) => init_logln!(
            logger,
            "[init] VMO read/write round-trip FAILED ({})",
            e.as_str()
        ),
    }
}

fn run_channel_check(logger: &mut InitLogger) {
    let msg = b"ping over huesos channel\n";
    let ok = (|| -> libcanvas::Result<bool> {
        let (tx, rx) = libcanvas::Channel::pair()?;
        tx.write(msg)?;
        let (buf, n) = rx.read()?;
        Ok(n == msg.len() && &buf[..n] == msg)
    })();

    match ok {
        Ok(true) => init_logln!(logger, "[init] channel IPC round-trip OK"),
        Ok(false) => init_logln!(
            logger,
            "[init] channel IPC round-trip FAILED (data mismatch)"
        ),
        Err(e) => init_logln!(
            logger,
            "[init] channel IPC round-trip FAILED ({})",
            e.as_str()
        ),
    }
}

/// Regression suite for `Syscall::WaitSetWait`.
///
/// Three properties, each a live end-to-end syscall probe:
///
/// 1. **READABLE fires on channel wake.** A `wait_any` on the empty
///    receiver returns pending; after the peer writes a message the
///    same wait wakes and reports `Signals::READABLE` for the item.
///    The read then returns the payload — proving the wake was not
///    a spurious poll.
///
/// 2. **`timeout_ticks` is honoured.** A `wait_any` on a channel
///    that never becomes readable returns `Err(TimedOut)` within
///    the requested budget. Between PR #126 and this PR the kernel
///    silently ignored `timeout_ticks` and looped forever, and the
///    only reason it did not lock up any real boot was that every
///    caller either passed `0` (wait forever) or had a peer that
///    eventually wrote something. driver-host-input was the first
///    caller that actually depended on timeout firing, and it
///    stalled.
///
/// 3. **Ports report `READABLE`, not `SIGNALED`.** Bound-key IRQ
///    packets on a Port were previously reported under
///    `Signals::SIGNALED` while every driver awaited `READABLE`, so
///    the two never intersected and Port-based `wait_any` never
///    fired. Rectified in the same PR as this test.
fn run_waitset_check(logger: &mut InitLogger) {
    use libcanvas::{wait_any, Signals, WaitItem};

    init_logln!(logger, "[init] waitset self-test starting");

    // Property 1 — READABLE fires on channel wake.
    let Ok((tx, rx)) = libcanvas::Channel::pair() else {
        init_logln!(logger, "[init] waitset self-test FAILED (channel pair)");
        return;
    };
    if let Err(e) = tx.write(b"waitset-probe") {
        init_logln!(
            logger,
            "[init] waitset self-test FAILED (write: {})",
            e.as_str()
        );
        return;
    }
    let items = [WaitItem::new(rx.handle().raw(), Signals::READABLE, 7)];
    match wait_any(&items, 0) {
        Ok(outcome) => {
            let found = outcome
                .satisfied()
                .iter()
                .any(|r| r.key == 7 && (r.active_signals & Signals::READABLE.bits()) != 0);
            if !found {
                init_logln!(
                    logger,
                    "[init] waitset self-test FAILED (READABLE not reported for channel)"
                );
                return;
            }
        }
        Err(e) => {
            init_logln!(
                logger,
                "[init] waitset self-test FAILED (channel wait_any: {})",
                e.as_str()
            );
            return;
        }
    }
    init_logln!(logger, "[init] waitset self-test channel-readable OK");
    // Drain the probe message so the next iteration starts empty.
    let mut buf = [0u8; 32];
    let _ = rx.read_into(&mut buf);

    // Property 2 — timeout_ticks is honoured.
    let empty_items = [WaitItem::new(rx.handle().raw(), Signals::READABLE, 8)];
    match wait_any(&empty_items, 4) {
        Err(libcanvas::ErrorCode::TimedOut) => {}
        Ok(_) => {
            init_logln!(
                logger,
                "[init] waitset self-test FAILED (timeout returned Ok on empty channel)"
            );
            return;
        }
        Err(e) => {
            init_logln!(
                logger,
                "[init] waitset self-test FAILED (timeout wait_any: {})",
                e.as_str()
            );
            return;
        }
    }
    init_logln!(logger, "[init] waitset self-test channel-timeout OK");

    // Property 3 — Port with no packet queued parks past the
    // deadline (times out) instead of spinning. This closes the
    // second half of the WaitSetWait timeout regression: even for
    // a Port item (which has different signal semantics than a
    // Channel) the timeout budget must be honoured.
    //
    // The complementary "packet arrives → wait wakes with
    // READABLE" property for Ports is validated end-to-end at
    // runtime by the input-host driver loop and asserted by the
    // CI serial-marker chain; init cannot re-run that check
    // without stealing the keyboard IRQ capability from input-host
    // (Interrupt::keyboard is exclusive).
    let Ok(idle_port) = libcanvas::Port::create() else {
        init_logln!(logger, "[init] waitset self-test FAILED (port create)");
        return;
    };
    let idle_items = [WaitItem::new(
        idle_port.handle().raw(),
        Signals::READABLE,
        9,
    )];
    match wait_any(&idle_items, 4) {
        Err(libcanvas::ErrorCode::TimedOut) => {}
        Ok(_) => {
            init_logln!(
                logger,
                "[init] waitset self-test FAILED (port timeout returned Ok on empty port)"
            );
            return;
        }
        Err(e) => {
            init_logln!(
                logger,
                "[init] waitset self-test FAILED (idle port wait_any: {})",
                e.as_str()
            );
            return;
        }
    }
    init_logln!(logger, "[init] waitset self-test port-timeout OK");

    // Property 4 — PEER_CLOSED wakes wait_any. This is the invariant
    // the shutdown-broker bootstrap loop depends on for its "peer
    // died before completing the handshake" fast-fail path: without
    // it, closing one end of a channel with no queued messages would
    // leave the other end permanently parked in wait_any(READABLE |
    // PEER_CLOSED). Regression coverage for the broker rewrite from
    // bounded-yield-loop to blocking wait_any in PR-H.
    let Ok((peer_tx, peer_rx)) = libcanvas::Channel::pair() else {
        init_logln!(
            logger,
            "[init] waitset self-test FAILED (peer channel pair)"
        );
        return;
    };
    drop(peer_tx);
    let peer_items = [WaitItem::new(
        peer_rx.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        10,
    )];
    match wait_any(&peer_items, 0) {
        Ok(outcome) => {
            let found = outcome
                .satisfied()
                .iter()
                .any(|r| r.key == 10 && (r.active_signals & Signals::PEER_CLOSED.bits()) != 0);
            if !found {
                init_logln!(
                    logger,
                    "[init] waitset self-test FAILED (PEER_CLOSED not reported on dropped tx)"
                );
                return;
            }
        }
        Err(e) => {
            init_logln!(
                logger,
                "[init] waitset self-test FAILED (peer wait_any: {})",
                e.as_str()
            );
            return;
        }
    }
    init_logln!(logger, "[init] waitset self-test peer-closed OK");

    init_logln!(logger, "[init] waitset self-test OK");
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[init] PANIC in userspace init\n");
    libcanvas::process::exit(-1);
}
