//! Channels: connected pairs of IPC endpoints for message passing.

use crate::handle::Handle;
use crate::raw;
use huesos_abi::{HandleValue, Syscall, INVALID_HANDLE};

/// A maximum message size accepted by [`Channel::read`]'s default buffer
/// helper. Callers with larger messages should size their own buffer and
/// call [`Channel::read_into`] directly.
pub const DEFAULT_MAX_MESSAGE: usize = 4096;

/// One endpoint of a channel pair.
#[derive(Debug)]
pub struct Channel(Handle);

impl Channel {
    /// Wrap a raw handle known to name a Channel endpoint.
    ///
    /// This is crate-private for now: public code should receive typed
    /// channels from safe constructors/syscalls rather than guessing handle
    /// types. The process/thread bootstrap helpers use it for the parent
    /// endpoint returned by `ThreadStart`.
    pub(crate) unsafe fn from_raw(raw: HandleValue) -> Self {
        Self(unsafe { Handle::from_raw(raw) })
    }

    /// Create a connected pair of channel endpoints. Sending on one is
    /// received on the other, and vice versa.
    pub fn pair() -> crate::Result<(Channel, Channel)> {
        let mut h0: HandleValue = INVALID_HANDLE;
        let mut h1: HandleValue = INVALID_HANDLE;
        let ret = unsafe {
            raw::syscall2(
                Syscall::ChannelCreate,
                &mut h0 as *mut HandleValue as u64,
                &mut h1 as *mut HandleValue as u64,
            )
        };
        raw::decode(ret)?;
        Ok((
            Channel(unsafe { Handle::from_raw(h0) }),
            Channel(unsafe { Handle::from_raw(h1) }),
        ))
    }

    /// Send a message (raw bytes; no handle transfer support in this safe
    /// wrapper yet — see `huesos-abi::Syscall::ChannelWrite`'s lower-level
    /// handle-array parameters if you need that).
    pub fn write(&self, data: &[u8]) -> crate::Result<()> {
        let ret = unsafe {
            raw::syscall5(
                Syscall::ChannelWrite,
                self.0.raw() as u64,
                data.as_ptr() as u64,
                data.len() as u64,
                0, // no handles array
                0, // num_handles = 0
            )
        };
        raw::decode(ret)?;
        Ok(())
    }

    /// Read a message into a caller-provided buffer. Returns the number of
    /// bytes actually written into `buf`. Non-blocking: returns
    /// `Err(ErrorCode::ShouldWait)` if no message is currently queued
    /// (there is no blocking wait primitive yet — see the kernel roadmap's
    /// notes on `Port`).
    pub fn read_into(&self, buf: &mut [u8]) -> crate::Result<usize> {
        let mut actual: u32 = 0;
        let ret = unsafe {
            raw::syscall4(
                Syscall::ChannelRead,
                self.0.raw() as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                &mut actual as *mut u32 as u64,
            )
        };
        raw::decode(ret)?;
        Ok(actual as usize)
    }

    /// Read a message into a fixed-size on-stack buffer
    /// ([`DEFAULT_MAX_MESSAGE`] bytes) and return exactly the bytes
    /// received. Convenience wrapper around [`Channel::read_into`] for
    /// the common case of "I don't have a specific buffer already".
    pub fn read(&self) -> crate::Result<([u8; DEFAULT_MAX_MESSAGE], usize)> {
        let mut buf = [0u8; DEFAULT_MAX_MESSAGE];
        let n = self.read_into(&mut buf)?;
        Ok((buf, n))
    }
}
