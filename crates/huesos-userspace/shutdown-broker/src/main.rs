//! HuesOS shutdown-broker: userspace atomic-halt owner.
//!
//! The broker holds two capabilities transferred from init at spawn:
//!
//! * an `IoPort` [`Resource`] over the 8042 command port (0x64), used to
//!   disable both PS/2 interfaces before halting the machine; and
//! * a `PowerControl` [`Resource`], the capability check for
//!   [`libcanvas::resource::hard_halt`].
//!
//! It is marked `critical` in its manifest: if this process exits for
//! any reason before it has delivered the atomic halt, the kernel's
//! critical-exit hook forces a hard halt of its own so the system
//! cannot be left in a half-shutdown state (Fuchsia's "critical to
//! root job" analogue; see `docs/ARCHITECTURE_ROADMAP.md` §3).
//!
//! The protocol on the bootstrap channel is:
//!
//! ```text
//! init -> broker:  handle transfer, label = "resource:shutdown-broker:ioport:0x64:0x1:excl"
//! init -> broker:  handle transfer, label = "resource:shutdown-broker:pwr:0x0:0x0:excl"
//! init -> broker:  bytes            = "shutdown-broker:go"
//! broker -> init:  bytes            = "shutdown-broker:ready"
//! ...
//! init -> broker:  bytes            = "shutdown"
//! broker: 8042 quiesce over IoPort resource; then sys_hard_halt (never returns)
//! ```

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::resource::IoPort;
use libcanvas::{println, Channel, ErrorCode, Handle};

const READY_MESSAGE: &[u8] = b"shutdown-broker:ready";
const GO_MESSAGE: &[u8] = b"shutdown-broker:go";
const SHUTDOWN_COMMAND: &[u8] = b"shutdown";

const RESOURCE_LABEL_PREFIX: &[u8] = b"resource:shutdown-broker:";

const PS2_STATUS_PORT: u16 = 0x64;
const PS2_CMD_DISABLE_FIRST: u8 = 0xAD;
const PS2_CMD_DISABLE_SECOND: u8 = 0xA7;
const PS2_STATUS_INPUT_BUFFER_FULL: u8 = 0x02;
const PS2_STATUS_POLL_LIMIT: u32 = 100_000;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[shutdown-broker] started");
    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"shutdown-broker:starting");

    // 1. Receive the two capability handles init transferred to us at spawn.
    let mut ioport: Option<IoPort> = None;
    let mut power: Option<Handle> = None;
    receive_capabilities(&bootstrap, &mut ioport, &mut power);

    let (Some(ioport), Some(power)) = (ioport, power) else {
        println!("[shutdown-broker] missing required capability handles; exiting");
        let _ = bootstrap.write(b"shutdown-broker:missing-caps");
        // Non-critical failure path: init has not yet marked us critical
        // (the mark_critical control message is normally sent alongside
        // the handles it did in fact deliver); exit non-zero so the
        // supervisor can log the fault. If we *were* marked critical
        // and are missing caps anyway, the kernel critical-exit hook
        // still fires and halts, which is the correct conservative
        // behaviour for a broken bootstrap.
        libcanvas::process::exit(-1);
    };

    // 2. Wait for the explicit "go" barrier from init so init has had a
    // chance to mark us critical before we start acknowledging
    // shutdown requests. This closes a race where a shutdown message
    // that arrives before mark_critical would still commit but a
    // subsequent broker crash would not trigger the fallback halt.
    if !wait_for_go(&bootstrap) {
        println!("[shutdown-broker] init did not send go barrier; exiting");
        libcanvas::process::exit(-2);
    }

    let _ = bootstrap.write(READY_MESSAGE);
    println!("[shutdown-broker] ready; awaiting shutdown command");

    // 3. Main loop: wait for `shutdown`; then quiesce 8042 and invoke
    // the atomic halt syscall. hard_halt never returns.
    loop {
        let mut buf = [0u8; 32];
        match bootstrap.read_into(&mut buf) {
            Ok(n) if &buf[..n] == SHUTDOWN_COMMAND => {
                println!("[shutdown-broker] shutdown command received");
                quiesce_8042(&ioport);
                println!("[shutdown-broker] 8042 quiesced; invoking hard_halt");
                libcanvas::resource::hard_halt(&power);
            }
            Ok(n) => {
                // Unknown control byte; log and keep listening. Never
                // exit voluntarily — an unmarked exit would trip the
                // critical-fallback halt.
                println!("[shutdown-broker] ignoring {} unexpected byte(s)", n);
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(e) => {
                println!("[shutdown-broker] bootstrap read failed: {}", e.as_str());
                libcanvas::process::yield_now();
            }
        }
    }
}

fn receive_capabilities(
    bootstrap: &Channel,
    ioport: &mut Option<IoPort>,
    power: &mut Option<Handle>,
) {
    let mut label = [0u8; 96];
    // Bounded poll: init transfers the two handles very early, so we
    // should see both within a few thousand yields. If not, exit path
    // above prints the diagnostic.
    for _ in 0..100_000 {
        if ioport.is_some() && power.is_some() {
            return;
        }
        match bootstrap.read_handle(&mut label) {
            Ok((n, handle)) => {
                let msg = &label[..n];
                if !msg.starts_with(RESOURCE_LABEL_PREFIX) {
                    // Unrelated transfer; drop the handle (closes on
                    // scope exit) to avoid accumulating.
                    println!("[shutdown-broker] unexpected handle-transfer label");
                    drop(handle);
                    continue;
                }
                let tail = &msg[RESOURCE_LABEL_PREFIX.len()..];
                if tail.starts_with(b"ioport:") {
                    if ioport.is_some() {
                        println!("[shutdown-broker] duplicate ioport handle");
                        drop(handle);
                        continue;
                    }
                    *ioport = Some(IoPort::from_handle(handle));
                } else if tail.starts_with(b"pwr:") {
                    if power.is_some() {
                        println!("[shutdown-broker] duplicate power handle");
                        drop(handle);
                        continue;
                    }
                    *power = Some(handle);
                } else {
                    println!("[shutdown-broker] unknown resource kind in label");
                    drop(handle);
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(e) => {
                println!("[shutdown-broker] handle read failed: {}", e.as_str());
                return;
            }
        }
    }
}

fn wait_for_go(bootstrap: &Channel) -> bool {
    let mut buf = [0u8; 32];
    for _ in 0..100_000 {
        match bootstrap.read_into(&mut buf) {
            Ok(n) if &buf[..n] == GO_MESSAGE => return true,
            Ok(_) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(e) => {
                println!("[shutdown-broker] go read failed: {}", e.as_str());
                return false;
            }
        }
    }
    false
}

/// Disable both PS/2 interfaces (commands 0xAD, 0xA7) over the granted
/// IoPort resource. Mirrors the historical `huesos-arch::keyboard::
/// prepare_shutdown` logic that used to live kernel-side. Any single
/// step failing is non-fatal because the machine is about to halt
/// anyway; we log and continue.
fn quiesce_8042(ioport: &IoPort) {
    for value in [PS2_CMD_DISABLE_FIRST, PS2_CMD_DISABLE_SECOND] {
        // Poll the input-buffer-full status bit before issuing the
        // command; bounded loop so broken/non-PS2 hardware cannot hang
        // shutdown forever.
        let mut ready = false;
        for _ in 0..PS2_STATUS_POLL_LIMIT {
            match ioport.read_u8(PS2_STATUS_PORT) {
                Ok(status) => {
                    if status & PS2_STATUS_INPUT_BUFFER_FULL == 0 {
                        ready = true;
                        break;
                    }
                }
                Err(e) => {
                    println!("[shutdown-broker] 8042 status read failed: {}", e.as_str());
                    return;
                }
            }
        }
        if !ready {
            println!("[shutdown-broker] 8042 input buffer never drained; proceeding");
        }
        if let Err(e) = ioport.write_u8(PS2_STATUS_PORT, value) {
            println!(
                "[shutdown-broker] 8042 command {:#04x} failed: {}",
                value,
                e.as_str()
            );
            return;
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Do not use println! here in case the framebuffer path is torn
    // down; libcanvas debug writes go through the kernel debug syscall
    // and remain functional right up to hard_halt.
    libcanvas::debug::write_str("[shutdown-broker] PANIC\n");
    let _ = info;
    libcanvas::process::exit(-99);
}
