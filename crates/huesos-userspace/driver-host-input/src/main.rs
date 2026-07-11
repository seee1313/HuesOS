//! Input DriverHost.
//!
//! This userspace process hosts input-class drivers. The current MVP hosts
//! the PS/2 keyboard driver: it binds keyboard IRQ1 to a Port, observes raw
//! scancode packets, and reports readiness/heartbeats to DriverManager over
//! its bootstrap channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::{println, ErrorCode, Interrupt, Port, PORT_PACKET_INTERRUPT};

const KEY_KEYBOARD: u64 = 1;
const ATTACH_KEYBOARD_CLIENT: &[u8] = b"keyboard-client";
const HEARTBEAT_EVERY_SCANCODES: u64 = 32;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[driver-host:input] started");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"driver-host:input:starting");

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
    let mut idle = 0u32;
    loop {
        // Always service bootstrap first so attach/ready paths stay live.
        poll_bootstrap(&bootstrap, &mut keyboard_client);

        // Non-blocking port read. Full park/block is still too sharp under
        // SMP+TCG for the only IRQ consumer during bring-up.
        match port.read() {
            Ok(packet)
                if packet.packet_type == PORT_PACKET_INTERRUPT && packet.key == KEY_KEYBOARD =>
            {
                idle = 0;
                let irq = packet.data[0];
                let scancode = packet.data[1] as u8;
                let count = packet.data[2];
                println!(
                    "[driver-host:input] irq={} scancode={:#x} count={}",
                    irq, scancode, count
                );
                if let Some(event) = decoder.feed(scancode) {
                    send_keyboard_event(&keyboard_client, event);
                }
                if count % HEARTBEAT_EVERY_SCANCODES == 0 {
                    let _ = bootstrap.write(b"heartbeat:input");
                }
            }
            Ok(_) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                idle = idle.wrapping_add(1);
                if idle >= 1024 {
                    idle = 0;
                    let _ = bootstrap.write(b"heartbeat:input");
                }
                libcanvas::process::yield_now();
            }
            Err(e) => {
                println!("[driver-host:input] port read failed: {}", e.as_str());
                let _ = bootstrap.write(b"driver-host:input:error");
                libcanvas::process::yield_now();
            }
        }
    }
}

fn poll_bootstrap(bootstrap: &libcanvas::Channel, keyboard_client: &mut Option<libcanvas::Channel>) {
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
}

impl KeyboardDecoder {
    const fn new() -> Self {
        Self { shift: false }
    }

    fn feed(&mut self, scancode: u8) -> Option<KeyEvent> {
        match scancode {
            0x2a | 0x36 => {
                self.shift = true;
                return None;
            }
            0xaa | 0xb6 => {
                self.shift = false;
                return None;
            }
            _ => {}
        }
        let pressed = scancode & 0x80 == 0;
        let index = (scancode & 0x7f) as usize;
        let table = if self.shift { &SET1_UPPER } else { &SET1_LOWER };
        let byte = table.get(index).copied().unwrap_or(0);
        if byte == 0 {
            None
        } else {
            Some(KeyEvent {
                key: byte,
                pressed,
            })
        }
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
