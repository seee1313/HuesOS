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
static DOOM_ELF: &[u8] = include_bytes!(env!("HUESOS_DOOM_PATH"));
static FAULT_PROBE_ELF: &[u8] = include_bytes!(env!("HUESOS_FAULT_PROBE_PATH"));
static BOOTFS_IMAGE: &[u8] = include_bytes!(env!("HUESOS_BOOTFS_PATH"));

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut logger = InitLogger::new();
    init_logln!(logger, "[init] hello from ring3 userspace, via libcanvas");

    if libcanvas::diagnostics::user_pointer_guard_smoke_test() {
        init_logln!(logger, "[init] user pointer guard smoke OK");
    } else {
        init_logln!(logger, "[init] user pointer guard smoke FAILED");
    }

    run_vmo_check(&mut logger);
    run_channel_check(&mut logger);
    run_monotonic_clock_check(&mut logger);
    run_fault_isolation_check(&mut logger);
    run_shutdown_authorization_check(&mut logger);

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
    let mut supervisor_message = [0u8; 64];
    let mut supervisor_handles = [0u32; 1];
    let mut doom_process: Option<Process> = None;
    loop {
        let _keep_services_alive = &driver_manager;
        if let Some((_, channel)) = &terminal {
            match channel.read_etc(&mut supervisor_message, &mut supervisor_handles) {
                Ok((n, 0)) if &supervisor_message[..n] == b"system:shutdown" => {
                    init_logln!(logger, "[init] terminal requested orderly shutdown");
                    if let Err(error) = libcanvas::system::shutdown() {
                        init_logln!(
                            logger,
                            "[init] shutdown request rejected: {}",
                            error.as_str()
                        );
                    }
                }
                Ok((n, 1)) if &supervisor_message[..n] == b"system:launch-doom" => {
                    let handle = unsafe { libcanvas::Handle::from_raw(supervisor_handles[0]) };
                    if doom_process.is_none() {
                        doom_process =
                            launch_doom(&mut logger, channel, Channel::from_handle(handle));
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
) -> Option<Process> {
    init_logln!(logger, "[init] launching DoomGeneric/Freedoom");
    let result = (|| -> libcanvas::Result<Process> {
        let (process, bootstrap) = libcanvas::process::spawn_elf("doom", DOOM_ELF)?;
        init_logln!(logger, "[init] Doom process created; passing keyboard");
        bootstrap.write_handle(b"keyboard", keyboard.into_handle())?;
        init_logln!(logger, "[init] Doom keyboard passed; process running");
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
        Err(error) => init_logln!(
            logger,
            "[init] monotonic clock FAILED ({})",
            error.as_str()
        ),
    }
}

fn run_shutdown_authorization_check(logger: &mut InitLogger) {
    let Ok((process, bootstrap)) =
        libcanvas::process::spawn_elf("shutdown-probe", FAULT_PROBE_ELF)
    else {
        init_logln!(logger, "[init] shutdown authorization FAILED (launch)");
        return;
    };
    if bootstrap.write(b"shutdown").is_err() {
        init_logln!(logger, "[init] shutdown authorization FAILED (command)");
        return;
    }
    drop(bootstrap);
    match process.wait_exit() {
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
        match process.wait_exit() {
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[init] PANIC in userspace init\n");
    libcanvas::process::exit(-1);
}
