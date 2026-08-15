//! Fail-closed userspace PCI Manager skeleton.
//!
//! PCI-9 establishes process isolation, typed bootstrap, readiness, heartbeat,
//! and supervisor restart behavior. It deliberately receives no ECAM/CF8
//! authority and performs no physical configuration access until the live ACPI
//! root-descriptor handoff and DeviceLease kernel enforcement land.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::pci_manager::{self, Message, Opcode, Status, MESSAGE_BYTES};
use libcanvas::{println, wait_any, Channel, ErrorCode, Signals, WaitItem};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[pci-manager] userspace service started (configuration disabled)");
    let bootstrap = libcanvas::channel::bootstrap();
    let Some(hello) = receive_hello(&bootstrap) else {
        libcanvas::process::exit(-1);
    };

    let ready = Message::ready_without_roots(hello.manager_generation);
    if !send(&bootstrap, ready) {
        libcanvas::process::exit(-2);
    }
    println!("[pci-manager] ready without root descriptors; fail-closed");

    let mut yields = 0u32;
    loop {
        let mut bytes = [0u8; MESSAGE_BYTES];
        match bootstrap.read_into(&mut bytes) {
            Ok(length) => {
                let valid_generation = pci_manager::decode(&bytes[..length])
                    .is_some_and(|message| message.manager_generation == hello.manager_generation);
                if !valid_generation {
                    let _ = send(
                        &bootstrap,
                        Message {
                            opcode: Opcode::Heartbeat,
                            manager_generation: hello.manager_generation,
                            status: Status::InvalidMessage,
                            detail: 0,
                        },
                    );
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => libcanvas::process::exit(0),
        }

        yields = yields.wrapping_add(1);
        if yields.is_multiple_of(65_536) {
            let _ = send(
                &bootstrap,
                Message {
                    opcode: Opcode::Heartbeat,
                    manager_generation: hello.manager_generation,
                    status: Status::NoRootsFailClosed,
                    detail: 0,
                },
            );
        }
        libcanvas::process::yield_now();
    }
}

fn receive_hello(bootstrap: &Channel) -> Option<Message> {
    let items = [WaitItem::new(
        bootstrap.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];
    let mut bytes = [0u8; MESSAGE_BYTES];
    loop {
        wait_any(&items, 0).ok()?;
        match bootstrap.read_into(&mut bytes) {
            Ok(length) => {
                let message = pci_manager::decode(&bytes[..length])?;
                if message.opcode == Opcode::Hello && message.status == Status::Ok {
                    return Some(message);
                }
                return None;
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => return None,
        }
    }
}

fn send(bootstrap: &Channel, message: Message) -> bool {
    let mut bytes = [0u8; MESSAGE_BYTES];
    let Some(length) = pci_manager::encode(message, &mut bytes) else {
        return false;
    };
    bootstrap.write(&bytes[..length]).is_ok()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[pci-manager] PANIC\n");
    libcanvas::process::exit(-127);
}
