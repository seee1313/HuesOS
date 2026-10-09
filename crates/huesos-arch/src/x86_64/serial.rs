//! Serial port (COM1) driver using the `uart_16550` crate.

use crate::IrqSafeTicketLock;
use core::fmt;
use uart_16550::SerialPort;

static SERIAL: IrqSafeTicketLock<SerialPort> =
    IrqSafeTicketLock::new(unsafe { SerialPort::new(0x3F8) });

/// Initialize COM1 to 115200 8N1.
pub fn init() {
    SERIAL.lock().init();
}

/// Write a single byte to COM1.
pub fn write_byte(b: u8) {
    SERIAL.lock().send(b);
}

// Note: there is deliberately no `read_byte` API. `uart_16550::receive`
// polls until a byte arrives, so a blocking read taken under the serial
// lock (as every other entry point here is) would spin the calling CPU
// *inside the lock* for as long as nothing is transmitted — stalling
// every other CPU's logging, and with it the whole machine's only
// post-mortem channel, with no timeout to break the stall. If serial
// input is ever needed, it has to be interrupt-driven with a queue,
// not a lock-held poll.

/// Write without taking the normal serial lock. Intended only for fatal panic
/// paths where the interrupted CPU might already own that lock.
pub fn emergency_write(s: &str) {
    let mut port = unsafe { SerialPort::new(0x3F8) };
    for byte in s.bytes() {
        port.send(byte);
    }
}

/// Write a byte slice while holding the serial lock for the whole slice.
///
/// Callers that emit one logical log line must use this (or `SerialWriter`'s
/// `write_fmt`) rather than per-byte `write_byte`: separate lock
/// acquisitions let another CPU's output land in the middle of the line, and
/// the boot smoke greps for whole lines.
pub fn write_bytes(bytes: &[u8]) {
    let mut port = SERIAL.lock();
    for &b in bytes {
        port.send(b);
    }
}

/// Adapter that writes formatted text into an already-locked port.
struct LockedPortWriter<'a>(&'a mut SerialPort);

impl fmt::Write for LockedPortWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            self.0.send(b);
        }
        Ok(())
    }
}

/// Writer for `core::fmt::Write`.
pub struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_bytes(s.as_bytes());
        Ok(())
    }

    /// Format the whole argument list under one lock acquisition, so a
    /// `writeln!` line is never split by another CPU's output.
    ///
    /// Formatting must not re-enter the serial console; a `Display` impl that
    /// logs would deadlock here.
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        let mut port = SERIAL.lock();
        fmt::write(&mut LockedPortWriter(&mut port), args)
    }
}
