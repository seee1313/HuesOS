//! Virtual Memory Objects: anonymous, kernel-managed blocks of memory,
//! referenced by handle and moved around by copying bytes in/out (no
//! `mmap`-style address-space mapping exposed to userspace yet — see the
//! kernel's roadmap).

use crate::handle::Handle;
use crate::raw;
use huesos_abi::{HandleValue, Syscall, INVALID_HANDLE};

/// An owned Virtual Memory Object.
#[derive(Debug)]
pub struct Vmo(Handle);

impl Vmo {
    /// Wrap a raw handle known to name a VMO.
    ///
    /// # Safety
    /// `raw` must be an owned VMO handle in this process.
    pub unsafe fn from_raw(raw: HandleValue) -> Self {
        Self(unsafe { Handle::from_raw(raw) })
    }

    /// Build a VMO from an owned generic handle.
    pub fn from_handle(handle: Handle) -> Self {
        Self(handle)
    }

    /// Consume this VMO and return the underlying generic handle.
    pub fn into_handle(self) -> Handle {
        self.0
    }

    /// Create a new VMO of at least `size` bytes, zero-filled.
    pub fn create(size: u64) -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = unsafe {
            raw::syscall2(
                Syscall::VmoCreate,
                size,
                &mut out as *mut HandleValue as u64,
            )
        };
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Write `data` into this VMO starting at `offset`. Returns the number
    /// of bytes actually written (may be less than `data.len()` if the
    /// write would run past the VMO's current size).
    pub fn write(&self, offset: u64, data: &[u8]) -> crate::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let ret = unsafe {
            raw::syscall4(
                Syscall::VmoWrite,
                self.0.raw() as u64,
                offset,
                data.as_ptr() as u64,
                data.len() as u64,
            )
        };
        raw::decode(ret).map(|n| n as usize)
    }

    /// Read up to `buf.len()` bytes from this VMO starting at `offset`
    /// into `buf`. Returns the number of bytes actually read.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let ret = unsafe {
            raw::syscall4(
                Syscall::VmoRead,
                self.0.raw() as u64,
                offset,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
        raw::decode(ret).map(|n| n as usize)
    }

    /// Borrow the underlying handle (e.g. to pass to
    /// [`crate::framebuffer::blit`], which needs a raw handle value).
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}
