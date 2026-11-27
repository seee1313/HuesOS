//! Ring-3 integration probe for the append-only PCI hotplug trigger syscall.
//!
//! DriverManager supplies a duplicate of the ACPI manager's write endpoint.
//! Its peer is the endpoint delivered to PCI Manager, so the test exercises
//! kernel argument copying, channel rights, the canonical 40-byte event, and
//! the live PCI manager receiver without a cmdline or synthetic kernel shortcut.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::pci_hotplug::{
    HotplugWireEvent, HOTPLUG_TEST_CHANNEL_LABEL, NOTIFY_BUS_CHECK,
};
use libcanvas::{Channel, ErrorCode};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let bootstrap = libcanvas::channel::bootstrap();
    let mut bytes = [0u8; 64];
    let mut attempts = 0u32;
    while attempts < 1_000 {
        attempts += 1;
        match bootstrap.read_optional_handle_timeout(&mut bytes, 10) {
            Ok((length, Some(handle))) if &bytes[..length] == HOTPLUG_TEST_CHANNEL_LABEL => {
                let channel = Channel::from_handle(handle);
                let event = HotplugWireEvent::function_rescan(0, 0, 0, 0, NOTIFY_BUS_CHECK);
                match libcanvas::pci_hotplug::trigger(&channel, event) {
                    Ok(()) => {
                        let _ = bootstrap.write(b"syscall=98 event=40 bytes bdf=00:00.0 status=ok");
                        libcanvas::println!(
                            "[pci-hotplug-test] syscall=98 event=40 bytes bdf=00:00.0 status=ok"
                        );
                        libcanvas::process::exit(0);
                    }
                    Err(error) => {
                        let _ = bootstrap.write(b"syscall=98 event=40 bytes status=error");
                        libcanvas::println!(
                            "[pci-hotplug-test] syscall=98 event=40 bytes status=error {}",
                            error.as_str()
                        );
                        libcanvas::process::exit(98);
                    }
                }
            }
            Ok((_, Some(handle))) => drop(handle),
            Ok((_, None)) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(error) => {
                let _ = bootstrap.write(b"syscall=98 bootstrap status=error");
                libcanvas::println!(
                    "[pci-hotplug-test] bootstrap failed: {}",
                    error.as_str()
                );
                libcanvas::process::exit(97);
            }
        }
    }
    let _ = bootstrap.write(b"syscall=98 private trigger endpoint unavailable");
    libcanvas::println!("[pci-hotplug-test] private trigger endpoint unavailable");
    libcanvas::process::exit(96);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::process::exit(-1)
}
