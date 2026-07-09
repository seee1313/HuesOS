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
static BOOTFS_IMAGE: &[u8] = include_bytes!(env!("HUESOS_BOOTFS_PATH"));

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut logger = InitLogger::new();
    init_logln!(logger, "[init] hello from ring3 userspace, via libcanvas");

    run_vmo_check(&mut logger);
    run_channel_check(&mut logger);

    let driver_manager = launch_service(&mut logger, "driver-manager", DRIVER_MANAGER_ELF);

    if let Some((_, channel)) = &driver_manager {
        read_ready_message(&mut logger, "driver-manager", channel);
        send_bootfs_vmo(&mut logger, channel);
    }

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
    loop {
        let _keep_services_alive = (&driver_manager, &terminal);
        libcanvas::process::yield_now();
    }
}



fn send_bootfs_vmo(logger: &mut InitLogger, dm_bootstrap: &Channel) {
    let Ok(vmo) = Vmo::create(BOOTFS_IMAGE.len() as u64) else {
        init_logln!(logger, "[init] failed to create BOOTFS VMO");
        return;
    };
    match vmo.write(0, BOOTFS_IMAGE) {
        Ok(written) if written == BOOTFS_IMAGE.len() => {}
        Ok(written) => {
            init_logln!(logger, "[init] short BOOTFS VMO write: {} bytes", written);
            return;
        }
        Err(e) => {
            init_logln!(logger, "[init] failed to write BOOTFS VMO: {}", e.as_str());
            return;
        }
    }
    match dm_bootstrap.write_handle(b"bootfs-vmo", vmo.into_handle()) {
        Ok(()) => init_logln!(logger, "[init] passed BOOTFS VMO to DriverManager"),
        Err(e) => init_logln!(logger, "[init] failed to pass BOOTFS VMO: {}", e.as_str()),
    }
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
                Err(e) => {
                    init_logln!(logger, "[init] failed to pass registry channel: {}", e.as_str());
                    None
                }
            }
        }
        Err(e) => {
            init_logln!(logger, "[init] failed to create registry channel: {}", e.as_str());
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
        init_logln!(logger, "[init] no DriverManager registry channel for terminal");
        return;
    };
    match terminal_bootstrap.write_handle(b"driver-manager-registry", registry.into_handle()) {
        Ok(()) => init_logln!(logger, "[init] passed DriverManager registry to terminal"),
        Err(e) => init_logln!(logger, "[init] failed to pass registry to terminal: {}", e.as_str()),
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[init] PANIC in userspace init\n");
    libcanvas::process::exit(-1);
}
