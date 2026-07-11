//! Ports: fixed-size event queues used by interrupt and future wait APIs.

use crate::handle::Handle;
use crate::raw;
use huesos_abi::{HandleValue, PortPacket, Syscall, INVALID_HANDLE};

/// A userspace-owned Port handle.
#[derive(Debug)]
pub struct Port(Handle);

impl Port {
    /// Create a new Port event queue.
    pub fn create() -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall1(Syscall::PortCreate, &mut out as *mut HandleValue as u64);
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Read one queued event packet. Non-blocking: returns
    /// `ErrorCode::ShouldWait` if the Port is empty.
    pub fn read(&self) -> crate::Result<PortPacket> {
        self.read_flags(false)
    }

    /// Blocking read: park until a packet is queued.
    pub fn read_blocking(&self) -> crate::Result<PortPacket> {
        self.read_mode(1)
    }

    /// Blocking read with a timeout in kernel scheduler ticks.
    pub fn read_timeout(&self, ticks: u64) -> crate::Result<PortPacket> {
        let mode = if ticks == 0 { 1 } else { ticks.max(2) };
        self.read_mode(mode)
    }

    fn read_flags(&self, block: bool) -> crate::Result<PortPacket> {
        self.read_mode(if block { 1 } else { 0 })
    }

    fn read_mode(&self, wait_mode: u64) -> crate::Result<PortPacket> {
        let mut packet = PortPacket::default();
        let ret = raw::syscall3(
            Syscall::PortRead,
            self.0.raw() as u64,
            &mut packet as *mut PortPacket as u64,
            wait_mode,
        );
        raw::decode(ret)?;
        Ok(packet)
    }

    /// Borrow the underlying handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}
