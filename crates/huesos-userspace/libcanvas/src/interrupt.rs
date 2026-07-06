//! Interrupt objects: userspace-visible kernel IRQ bridge endpoints.

use crate::handle::Handle;
use crate::port::Port;
use crate::raw;
use huesos_abi::{HandleValue, Syscall, INVALID_HANDLE};

/// Legacy PIC IRQ number for the PS/2 keyboard.
pub const KEYBOARD_IRQ: u32 = 1;

/// A userspace-owned Interrupt handle.
#[derive(Debug)]
pub struct Interrupt(Handle);

impl Interrupt {
    /// Create an Interrupt object for `irq`.
    ///
    /// The current kernel implementation supports [`KEYBOARD_IRQ`] only.
    pub fn create(irq: u32) -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = unsafe {
            raw::syscall2(
                Syscall::InterruptCreate,
                irq as u64,
                &mut out as *mut HandleValue as u64,
            )
        };
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Create an Interrupt object for the keyboard IRQ.
    pub fn keyboard() -> crate::Result<Self> {
        Self::create(KEYBOARD_IRQ)
    }

    /// Bind interrupt notifications to `port` using `key`.
    pub fn bind_port(&self, port: &Port, key: u64) -> crate::Result<()> {
        let ret = unsafe {
            raw::syscall3(
                Syscall::InterruptBindPort,
                self.0.raw() as u64,
                port.handle().raw() as u64,
                key,
            )
        };
        raw::decode(ret)?;
        Ok(())
    }

    /// Borrow the underlying handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}
