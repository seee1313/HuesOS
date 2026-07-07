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
const HEARTBEAT_EVERY_IDLE_POLLS: u32 = 1024;
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
    let mut idle_polls = 0u32;
    loop {
        match port.read() {
            Ok(packet) if packet.packet_type == PORT_PACKET_INTERRUPT && packet.key == KEY_KEYBOARD => {
                idle_polls = 0;
                let irq = packet.data[0];
                let scancode = packet.data[1];
                let count = packet.data[2];
                println!(
                    "[driver-host:input] irq={} scancode={:#x} count={}",
                    irq, scancode, count
                );
                if count % HEARTBEAT_EVERY_SCANCODES == 0 {
                    let _ = bootstrap.write(b"heartbeat:input");
                }
            }
            Ok(_) => {}
            Err(ErrorCode::ShouldWait) => {
                idle_polls = idle_polls.wrapping_add(1);
                if idle_polls >= HEARTBEAT_EVERY_IDLE_POLLS {
                    idle_polls = 0;
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[driver-host:input] PANIC\n");
    libcanvas::process::exit(-1);
}
