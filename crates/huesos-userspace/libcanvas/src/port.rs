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
        let ret = unsafe {
            raw::syscall1(Syscall::PortCreate, &mut out as *mut HandleValue as u64)
        };
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Read one queued event packet. Non-blocking: returns
    /// `ErrorCode::ShouldWait` if the Port is empty.
    pub fn read(&self) -> crate::Result<PortPacket> {
        let mut packet = PortPacket::default();
        let ret = unsafe {
            raw::syscall2(
                Syscall::PortRead,
                self.0.raw() as u64,
                &mut packet as *mut PortPacket as u64,
            )
        };
        raw::decode(ret)?;
        Ok(packet)
    }

    /// Borrow the underlying handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}
