//! Input DriverHost.
//!
//! This userspace process hosts input-class drivers. The current MVP hosts
//! the PS/2 keyboard driver: it binds keyboard IRQ1 to a Port, observes raw
//! scancode packets, and reports readiness/heartbeats to DriverManager over
//! its bootstrap channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::{
    println, wait_any, ErrorCode, Interrupt, Port, Signals, WaitItem, PORT_PACKET_INTERRUPT,
};

const KEY_KEYBOARD: u64 = 1;
const ATTACH_KEYBOARD_CLIENT: &[u8] = b"keyboard-client";
const HEARTBEAT_EVERY_SCANCODES: u64 = 256;
const KEY_ARROW_UP: u8 = 0x80;
const KEY_ARROW_DOWN: u8 = 0x81;
const KEY_ARROW_LEFT: u8 = 0x82;
const KEY_ARROW_RIGHT: u8 = 0x83;

// wait_any keys used by the event loop.
const WAIT_KEY_BOOTSTRAP: u64 = 0;
const WAIT_KEY_PORT: u64 = 1;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[driver-host:input] started");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"driver-host:input:starting");

    // PR-D verification (fixes PR-C limitation): consume every
    // manifest-driven Resource handle DriverManager forwards through
    // our bootstrap channel and log what we received. We do not yet
    // *use* these handles (the legacy Interrupt::keyboard() path
    // below remains the live source of scancodes for this MVP), but
    // holding them alive proves the end-to-end
    // manifest → init(mint) → driver-manager(forward) → driver(hold)
    // capability path works. See docs/ARCHITECTURE_ROADMAP.md §4.
    consume_manifest_resources(&bootstrap);

    match setup_keyboard_irq_bridge() {
        Ok(port) => {
            let _ = bootstrap.write(b"service:keyboard:ready");
            let _ = bootstrap.write(b"driver-host:input:ready");
            run_driver_loop(port, bootstrap);
        }
        Err(e) => {
            println!("[driver-host:input] keyboard setup failed: {}", e.as_str());
            let _ = bootstrap.write(b"service:keyboard:failed");
            libcanvas::process::exit(-1);
        }
    }
}

const RESOURCE_LABEL_PREFIX: &[u8] = b"resource:";
/// End-of-transfer sentinel that DriverManager writes on the
/// bootstrap channel immediately after the last per-driver resource
/// handle. Its arrival is the deterministic signal that
/// `consume_manifest_resources` uses to stop draining. Kept in sync
/// with `driver-manager::supervisor::forward_pending_resources`.
const RESOURCE_TRANSFER_COMPLETE: &[u8] = b"resource:transfer-complete";

/// Drain every `resource:*` handle-transfer message DriverManager
/// forwards on the bootstrap channel, log each one, and hold on to
/// the handles so they stay valid for the driver's lifetime. Exits
/// on the `resource:transfer-complete` sentinel, on `PEER_CLOSED`, or
/// on any read error. Blocking wait — zero busy-yield, and no
/// dependence on `WaitSetWait`'s timeout parameter. The kernel now parks the
/// task on the watched object queues and uses the shared timeout table rather
/// than busy-yielding between polls.
fn consume_manifest_resources(bootstrap: &libcanvas::Channel) {
    // Bounded static storage for received handles. `Handle` holds a
    // raw HandleValue; keeping the Handles in an array without an
    // allocator satisfies the CONTRIBUTING no-panic rule and matches
    // libcanvas's zero-alloc style.
    let mut received: [Option<libcanvas::Handle>; 8] = [const { None }; 8];
    let mut received_count = 0usize;
    let mut buf = [0u8; 96];
    let items = [WaitItem::new(
        bootstrap.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        WAIT_KEY_BOOTSTRAP,
    )];
    'outer: loop {
        // Park until the bootstrap channel becomes readable (or
        // peer-closed). Wait forever — the sentinel below is the
        // real exit condition.
        match wait_any(&items, 0) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "[driver-host:input] resource-drain wait failed: {}",
                    e.as_str()
                );
                break;
            }
        }
        // Drain everything currently readable in one burst before we
        // park again. `read_optional_handle` is the right primitive
        // here because the stream interleaves handle-transfer
        // messages (resource grants) with plain byte messages (the
        // transfer-complete sentinel). Using `read_handle` would
        // silently drop the sentinel — see the docs on
        // `Channel::read_handle` for the exact failure mode.
        loop {
            match bootstrap.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if buf[..n].starts_with(RESOURCE_LABEL_PREFIX) => {
                    if received_count < received.len() {
                        let text = core::str::from_utf8(&buf[..n]).unwrap_or("?");
                        println!(
                            "[driver-host:input] received manifest resource #{}: {}",
                            received_count + 1,
                            text
                        );
                        received[received_count] = Some(handle);
                        received_count += 1;
                    } else {
                        println!("[driver-host:input] resource buffer full, dropping label");
                        drop(handle);
                    }
                }
                Ok((n, Some(handle))) => {
                    let text = core::str::from_utf8(&buf[..n]).unwrap_or("?");
                    println!(
                        "[driver-host:input] non-resource handle transfer ignored: {}",
                        text
                    );
                    drop(handle);
                }
                Ok((n, None)) if &buf[..n] == RESOURCE_TRANSFER_COMPLETE => {
                    // DriverManager is done. Every resource this
                    // driver was granted is either in `received`
                    // above or was explicitly logged as dropped.
                    break 'outer;
                }
                Ok((n, None)) => {
                    let text = core::str::from_utf8(&buf[..n]).unwrap_or("?");
                    println!(
                        "[driver-host:input] unexpected plain bootstrap message: {}",
                        text
                    );
                }
                Err(ErrorCode::ShouldWait) => break, // drained; park again
                Err(e) => {
                    println!(
                        "[driver-host:input] resource-drain read failed: {}",
                        e.as_str()
                    );
                    // Fall through to retain what we already have.
                    break 'outer;
                }
            }
        }
    }
    println!(
        "[driver-host:input] retained {} manifest resource handle(s)",
        received_count
    );
    // Keep every received handle alive for the driver-host lifetime.
    // Future PRs will migrate the input driver off the legacy
    // Interrupt::keyboard() and Port::create() paths onto these
    // manifest-granted Resources; forget() prevents close-on-drop
    // in the meantime.
    for slot in received.into_iter().flatten() {
        core::mem::forget(slot);
    }
}

fn setup_keyboard_irq_bridge() -> libcanvas::Result<Port> {
    let port = Port::create()?;
    let keyboard = Interrupt::keyboard()?;
    keyboard.bind_port(&port, KEY_KEYBOARD)?;
    // Keep the Interrupt handle alive for this DriverHost lifetime. A later
    // driver object table will own this handle explicitly.
    core::mem::forget(keyboard);
    println!("[driver-host:input] keyboard IRQ bound to Port");
    Ok(port)
}

fn run_driver_loop(port: Port, bootstrap: libcanvas::Channel) -> ! {
    let mut keyboard_client: Option<libcanvas::Channel> = None;
    let mut decoder = KeyboardDecoder::new();
    let mut scancode_count: u64 = 0;

    // Event-driven: park on either the IRQ Port or the bootstrap
    // Channel. Zero CPU is spent when the keyboard is idle. When a
    // key press wakes us, we drain every readable packet in one
    // burst before parking again, so we never leave events sitting
    // in the queue when they could be delivered right now.
    //
    // The `WaitItem` order matches the sat-set walk order the kernel
    // uses when both are ready simultaneously; putting the Port
    // first means keypresses (the latency-critical path) are
    // dispatched before bootstrap control messages when both fire
    // in the same wake.
    let items = [
        WaitItem::new(port.handle().raw(), Signals::READABLE, WAIT_KEY_PORT),
        WaitItem::new(
            bootstrap.handle().raw(),
            Signals::READABLE | Signals::PEER_CLOSED,
            WAIT_KEY_BOOTSTRAP,
        ),
    ];

    loop {
        // Timeout = 0 means block indefinitely: we wake only on real
        // I/O, never on a tick. This is the "no dumb yields" path
        // the driver has been missing.
        let outcome = match wait_any(&items, 0) {
            Ok(outcome) => outcome,
            Err(e) => {
                println!("[driver-host:input] wait_any failed: {}", e.as_str());
                let _ = bootstrap.write(b"driver-host:input:error");
                libcanvas::process::yield_now();
                continue;
            }
        };

        // The order we drain matters only when both fire in the same
        // wake: doing the Port first keeps key-to-terminal latency
        // minimal.
        let mut port_ready = false;
        let mut bootstrap_ready = false;
        for result in outcome.satisfied() {
            match result.key {
                WAIT_KEY_PORT => port_ready = true,
                WAIT_KEY_BOOTSTRAP => bootstrap_ready = true,
                _ => {}
            }
        }

        if port_ready {
            drain_keyboard_port(
                &port,
                &keyboard_client,
                &mut decoder,
                &bootstrap,
                &mut scancode_count,
            );
        }
        if bootstrap_ready {
            poll_bootstrap(&bootstrap, &mut keyboard_client);
        }
    }
}

/// Drain every currently-queued IRQ packet from the port and dispatch
/// its scancode. Called once per wake; loops internally until
/// `ShouldWait` so a keystroke burst never leaves events pending.
fn drain_keyboard_port(
    port: &Port,
    keyboard_client: &Option<libcanvas::Channel>,
    decoder: &mut KeyboardDecoder,
    bootstrap: &libcanvas::Channel,
    scancode_count: &mut u64,
) {
    loop {
        match port.read() {
            Ok(packet)
                if packet.packet_type == PORT_PACKET_INTERRUPT && packet.key == KEY_KEYBOARD =>
            {
                let scancode = packet.data[1] as u8;
                *scancode_count = scancode_count.wrapping_add(1);
                if let Some(event) = decoder.feed(scancode) {
                    send_keyboard_event(keyboard_client, event);
                }
                // Heartbeat only every N scancodes so we never burn a
                // DebugWrite syscall per key press. First-few-events
                // spam log removed for the same reason.
                if (*scancode_count).is_multiple_of(HEARTBEAT_EVERY_SCANCODES) {
                    let _ = bootstrap.write(b"heartbeat:input");
                }
            }
            Ok(_) => {
                // A non-interrupt packet slipped through (should not
                // happen with the current IRQ bridge); skip and keep
                // draining.
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
            Err(e) => {
                println!("[driver-host:input] port read failed: {}", e.as_str());
                let _ = bootstrap.write(b"driver-host:input:error");
                return;
            }
        }
    }
}

fn poll_bootstrap(
    bootstrap: &libcanvas::Channel,
    keyboard_client: &mut Option<libcanvas::Channel>,
) {
    let mut buf = [0u8; 64];
    loop {
        match bootstrap.read_channel_handle(&mut buf) {
            Ok((n, channel)) if &buf[..n] == ATTACH_KEYBOARD_CLIENT => {
                println!("[driver-host:input] attached keyboard client");
                *keyboard_client = Some(channel);
            }
            Ok((_n, _channel)) => println!("[driver-host:input] unknown handle message"),
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::InvalidArgs) => return,
            Err(e) => {
                println!("[driver-host:input] bootstrap read failed: {}", e.as_str());
                return;
            }
        }
    }
}

fn send_keyboard_event(client: &Option<libcanvas::Channel>, event: KeyEvent) {
    let Some(client) = client.as_ref() else {
        return;
    };
    // Unified event protocol: 'k', pressed(1/0), logical ASCII/control code.
    // Consumers that only need text ignore releases; games receive true hold
    // duration instead of guessing a synthetic key-up deadline.
    let msg = [b'k', event.pressed as u8, event.key];
    let _ = client.write(&msg);
}

#[derive(Clone, Copy)]
struct KeyEvent {
    key: u8,
    pressed: bool,
}

struct KeyboardDecoder {
    shift: bool,
    caps_lock: bool,
    extended: bool,
}

impl KeyboardDecoder {
    const fn new() -> Self {
        Self {
            shift: false,
            caps_lock: false,
            extended: false,
        }
    }

    fn feed(&mut self, scancode: u8) -> Option<KeyEvent> {
        if scancode == 0xe0 {
            self.extended = true;
            return None;
        }
        if self.extended {
            self.extended = false;
            return self.feed_extended(scancode);
        }
        match scancode {
            0x2a | 0x36 => {
                self.shift = true;
                return None;
            }
            0xaa | 0xb6 => {
                self.shift = false;
                return None;
            }
            0x3a => {
                self.caps_lock = !self.caps_lock;
                return None;
            }
            0xba => return None,
            _ => {}
        }
        let pressed = scancode & 0x80 == 0;
        let index = (scancode & 0x7f) as usize;
        let table = if self.shift { &SET1_UPPER } else { &SET1_LOWER };
        let mut byte = table.get(index).copied().unwrap_or(0);
        if self.caps_lock && byte.is_ascii_alphabetic() {
            byte ^= 0x20;
        }
        if byte == 0 {
            None
        } else {
            Some(KeyEvent { key: byte, pressed })
        }
    }

    fn feed_extended(&self, scancode: u8) -> Option<KeyEvent> {
        let pressed = scancode & 0x80 == 0;
        let key = match scancode & 0x7f {
            0x48 => KEY_ARROW_UP,
            0x50 => KEY_ARROW_DOWN,
            0x4b => KEY_ARROW_LEFT,
            0x4d => KEY_ARROW_RIGHT,
            _ => return None,
        };
        Some(KeyEvent { key, pressed })
    }
}

const SET1_LOWER: [u8; 58] = [
    0, 27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8, b'\t', b'q',
    b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', 0, b'a', b's', b'd',
    b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`', 0, b'\\', b'z', b'x', b'c', b'v', b'b',
    b'n', b'm', b',', b'.', b'/', 0, b'*', 0, b' ',
];

const SET1_UPPER: [u8; 58] = [
    0, 27, b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 8, b'\t', b'Q',
    b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', b'\n', 0, b'A', b'S', b'D',
    b'F', b'G', b'H', b'J', b'K', b'L', b':', b'"', b'~', 0, b'|', b'Z', b'X', b'C', b'V', b'B',
    b'N', b'M', b'<', b'>', b'?', 0, b'*', 0, b' ',
];

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[driver-host:input] PANIC\n");
    libcanvas::process::exit(-1);
}
