//! Serial port (COM1) driver using the `uart_16550` crate.

use crate::IrqSafeTicketLock;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use uart_16550::SerialPort;

static SERIAL: IrqSafeTicketLock<SerialPort> =
    IrqSafeTicketLock::new(unsafe { SerialPort::new(0x3F8) });

/// Controls whether non-emergency diagnostic output (`SerialWriter` /
/// `write_bytes` / `write_byte` / `SysDebugWrite`) is emitted to COM1.
///
/// Defaults to `false` (quiet release/production mode). Enabled early in
/// `kmain` for test builds (`boot-selftest`) or when the verified HBI command
/// line requests verbose diagnostics. Fatal paths (`emergency_write`,
/// `write_error_bytes`, `ErrorSerialWriter`) always write regardless of this
/// flag.
static VERBOSE_SERIAL: AtomicBool = AtomicBool::new(false);

/// Enable or disable non-emergency diagnostic output on COM1.
pub fn set_verbose(enabled: bool) {
    VERBOSE_SERIAL.store(enabled, Ordering::Release);
}

/// Whether non-emergency diagnostic output on COM1 is currently enabled.
#[inline]
pub fn is_verbose() -> bool {
    VERBOSE_SERIAL.load(Ordering::Acquire)
}

/// Initialize COM1 to 115200 8N1.
pub fn init() {
    SERIAL.lock().init();
}

/// Write a single byte to COM1 when verbose diagnostics are enabled.
pub fn write_byte(b: u8) {
    if !is_verbose() {
        return;
    }
    SERIAL.lock().send(b);
}

/// Write a single byte unconditionally to COM1 (panic / fatal paths).
pub fn write_error_byte(b: u8) {
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

/// Unconditionally write a byte slice while holding the serial lock.
///
/// Used for `PANIC` / `ERROR` / fatal boot diagnostics that must surface on
/// COM1 even in silent release builds.
pub fn write_error_bytes(bytes: &[u8]) {
    let mut port = SERIAL.lock();
    for &b in bytes {
        port.send(b);
    }
}

/// Write a byte slice while holding the serial lock for the whole slice,
/// gated on [`is_verbose`].
///
/// Callers that emit one logical log line must use this (or `SerialWriter`'s
/// `write_fmt`) rather than per-byte `write_byte`: separate lock
/// acquisitions let another CPU's output land in the middle of the line, and
/// the boot smoke greps for whole lines.
pub fn write_bytes(bytes: &[u8]) {
    if !is_verbose() {
        return;
    }
    write_error_bytes(bytes);
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

/// Verbose-gated writer for `core::fmt::Write`.
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
        if !is_verbose() {
            return Ok(());
        }
        let mut port = SERIAL.lock();
        fmt::write(&mut LockedPortWriter(&mut port), args)
    }
}

/// Unconditional error/critical writer for `core::fmt::Write`.
///
/// Emits output even when [`is_verbose`] is `false` so fatal boot failures,
/// signature rejections, and hardware/VM faults remain visible in release builds.
pub struct ErrorSerialWriter;

impl fmt::Write for ErrorSerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_error_bytes(s.as_bytes());
        Ok(())
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        let mut port = SERIAL.lock();
        fmt::write(&mut LockedPortWriter(&mut port), args)
    }
}
