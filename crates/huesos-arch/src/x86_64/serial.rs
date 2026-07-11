//! Serial port (COM1) driver using the `uart_16550` crate.

use core::fmt;
use uart_16550::SerialPort;
use crate::IrqSafeTicketLock;

static SERIAL: IrqSafeTicketLock<SerialPort> = IrqSafeTicketLock::new(unsafe { SerialPort::new(0x3F8) });

/// Initialize COM1 to 115200 8N1.
pub fn init() {
    SERIAL.lock().init();
}

/// Write a single byte to COM1.
pub fn write_byte(b: u8) {
    SERIAL.lock().send(b);
}

/// Blocking read of a single byte from COM1.
pub fn read_byte() -> u8 {
    SERIAL.lock().receive()
}

/// Write without taking the normal serial lock. Intended only for fatal panic
/// paths where the interrupted CPU might already own that lock.
pub fn emergency_write(s: &str) {
    let mut port = unsafe { SerialPort::new(0x3F8) };
    for byte in s.bytes() {
        port.send(byte);
    }
}

/// Writer for `core::fmt::Write`.
pub struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut port = SERIAL.lock();
        for b in s.bytes() {
            port.send(b);
        }
        Ok(())
    }
}
