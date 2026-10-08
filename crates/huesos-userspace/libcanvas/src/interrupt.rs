//! Interrupt objects: userspace-visible kernel IRQ bridge endpoints.

use crate::handle::Handle;
use crate::port::Port;
use crate::raw;
use huesos_abi::{HandleValue, Syscall, INVALID_HANDLE};

fn owned_handle_from_syscall(raw: HandleValue) -> Handle {
    // SAFETY: callers invoke this only after a successful create syscall has
    // written a fresh, valid handle value into the output slot.
    unsafe { Handle::from_raw(raw) }
}

/// Legacy PIC IRQ number for the PS/2 keyboard.
pub const KEYBOARD_IRQ: u32 = 1;

/// A userspace-owned Interrupt handle.
#[derive(Debug)]
pub struct Interrupt(Handle);

impl Interrupt {
    /// Create an Interrupt object for `irq`.
    ///
    /// The unprivileged form is retained for the keyboard IRQ compatibility
    /// path; other devices should use an `Irq` Resource capability.
    pub fn create(irq: u32) -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall2(
            Syscall::InterruptCreate,
            irq as u64,
            &mut out as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok(Self(owned_handle_from_syscall(out)))
    }

    /// Create an Interrupt object for a legacy ISA IRQ or pre-routed MSI/MSI-X
    /// vector using an IRQ Resource capability. Use
    /// [`Self::create_gsi_from_resource`] for raw GSIs.
    pub fn create_from_resource(resource: &Handle, irq: u32) -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall3(
            Syscall::InterruptCreateForResource,
            resource.raw() as u64,
            irq as u64,
            &mut out as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok(Self(owned_handle_from_syscall(out)))
    }

    /// Create an Interrupt object for an explicit raw GSI using an IRQ Resource
    /// capability. The number is never interpreted as a legacy IRQ or MSI
    /// vector, so low/high GSI values remain unambiguous.
    pub fn create_gsi_from_resource(resource: &Handle, gsi: u32) -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall3(
            Syscall::InterruptCreateGsiForResource,
            resource.raw() as u64,
            u64::from(gsi),
            &mut out as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok(Self(owned_handle_from_syscall(out)))
    }

    /// Create an Interrupt object for the keyboard IRQ.
    pub fn keyboard() -> crate::Result<Self> {
        Self::create(KEYBOARD_IRQ)
    }

    /// Bind interrupt notifications to `port` using `key`.
    pub fn bind_port(&self, port: &Port, key: u64) -> crate::Result<()> {
        let ret = raw::syscall3(
            Syscall::InterruptBindPort,
            self.0.raw() as u64,
            port.handle().raw() as u64,
            key,
        );
        raw::decode(ret)?;
        Ok(())
    }

    /// Acknowledge one delivered level-triggered interrupt after the device
    /// has been serviced and its interrupt condition deasserted. Edge-triggered
    /// routes and pre-routed MSI vectors are no-ops.
    pub fn acknowledge(&self) -> crate::Result<()> {
        let ret = raw::syscall1(Syscall::InterruptAcknowledge, self.0.raw() as u64);
        raw::decode(ret)?;
        Ok(())
    }

    /// Borrow the underlying handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}
