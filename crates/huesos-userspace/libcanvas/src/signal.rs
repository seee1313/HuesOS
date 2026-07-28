//! Level-triggered signal objects.

use crate::handle::Handle;
use crate::raw;
use huesos_abi::{HandleValue, Syscall, INVALID_HANDLE};

/// A level-triggered waitable signal object.
#[derive(Debug)]
pub struct Signal(Handle);

impl Signal {
    /// Create a new unsignaled object.
    pub fn create() -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall1(Syscall::SignalCreate, &mut out as *mut HandleValue as u64);
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Set the signal. Waiters observing [`Signals::SIGNALED`](crate::Signals::SIGNALED)
    /// wake and the signal remains active until [`clear`](Self::clear).
    pub fn set(&self) -> crate::Result<()> {
        let ret = raw::syscall1(Syscall::SignalSet, self.0.raw() as u64);
        raw::decode(ret)?;
        Ok(())
    }

    /// Clear the signal.
    pub fn clear(&self) -> crate::Result<()> {
        let ret = raw::syscall1(Syscall::SignalClear, self.0.raw() as u64);
        raw::decode(ret)?;
        Ok(())
    }

    /// Borrow the underlying handle for `wait_any` / `wait_all`.
    pub fn handle(&self) -> &Handle {
        &self.0
    }

    /// Consume this wrapper and return the generic handle.
    pub fn into_handle(self) -> Handle {
        self.0
    }
}
