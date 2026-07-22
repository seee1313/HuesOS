//! Virtual Memory Objects: anonymous, kernel-managed blocks of memory,
//! referenced by handle and moved around by copying bytes in/out (no
//! `mmap`-style address-space mapping exposed to userspace yet — see the
//! kernel's roadmap).

use crate::handle::Handle;
use crate::raw;
use huesos_abi::{HandleValue, INVALID_HANDLE, Syscall};

/// An owned Virtual Memory Object.
#[derive(Debug)]
pub struct Vmo(Handle);

impl Vmo {
    /// Wrap a raw handle known to name a VMO.
    ///
    /// # Safety
    /// `raw` must be an owned VMO handle in this process.
    pub unsafe fn from_raw(raw: HandleValue) -> Self {
        Self::from_abi_owned(raw)
    }

    /// Take ownership of the fixed read-only BOOTFS capability installed only
    /// in the initial process by the kernel.
    pub fn take_init_bootfs() -> Self {
        Self::from_abi_owned(huesos_abi::INIT_BOOTFS_HANDLE)
    }

    /// Take ownership of the immutable validated ACPI table archive installed
    /// only in the initial process by the kernel.
    pub fn take_init_acpi_tables() -> Self {
        Self::from_abi_owned(huesos_abi::INIT_ACPI_TABLES_HANDLE)
    }

    fn from_abi_owned(raw: HandleValue) -> Self {
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
        let ret = raw::syscall2(
            Syscall::VmoCreate,
            size,
            &mut out as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Create a VMO with explicit creation flags from [`huesos_abi::vmo_create_flags`].
    pub fn create_with_flags(size: u64, flags: u32) -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall3(
            Syscall::VmoCreateEx,
            size,
            flags as u64,
            &mut out as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok(Self::from_abi_owned(out))
    }

    /// Write `data` into this VMO starting at `offset`. Returns the number
    /// of bytes actually written (may be less than `data.len()` if the
    /// write would run past the VMO's current size).
    pub fn write(&self, offset: u64, data: &[u8]) -> crate::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let ret = raw::syscall4(
            Syscall::VmoWrite,
            self.0.raw() as u64,
            offset,
            data.as_ptr() as u64,
            data.len() as u64,
        );
        raw::decode(ret).map(|n| n as usize)
    }

    /// Read up to `buf.len()` bytes from this VMO starting at `offset`
    /// into `buf`. Returns the number of bytes actually read.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let ret = raw::syscall4(
            Syscall::VmoRead,
            self.0.raw() as u64,
            offset,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        );
        raw::decode(ret).map(|n| n as usize)
    }

    /// Duplicate this VMO handle with an explicit rights mask.
    pub fn duplicate(&self, rights: u32) -> crate::Result<Self> {
        self.0.duplicate(rights).map(Self)
    }

    /// Borrow the underlying handle (e.g. to pass to
    /// [`crate::framebuffer::blit`], which needs a raw handle value).
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}
