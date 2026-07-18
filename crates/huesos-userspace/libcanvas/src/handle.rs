//! RAII handle wrapper: closes the underlying kernel handle automatically
//! when dropped, so application code can't accidentally leak handles by
//! forgetting to call `close()` — the single most common resource-leak bug
//! in capability-based systems like this one and its inspiration, Zircon.

use crate::raw;
use huesos_abi::{HandleValue, Syscall, INVALID_HANDLE};

/// An owned kernel handle. Closes itself on `Drop`; use
/// [`Handle::into_raw`]/[`Handle::from_raw`] if you need to transfer
/// ownership across an FFI-ish boundary without closing it.
#[derive(Debug)]
pub struct Handle(HandleValue);

impl Handle {
    /// Wrap a raw handle value returned by a syscall. Takes ownership: the
    /// handle will be closed when this `Handle` is dropped.
    ///
    /// # Safety
    /// `raw` must be a handle value this process actually owns (typically,
    /// one a syscall just handed back), and must not already be owned by
    /// another `Handle` (double-closing a handle is at worst a wasted
    /// syscall, but aliasing ownership defeats the point of this wrapper).
    pub unsafe fn from_raw(raw: HandleValue) -> Self {
        Self(raw)
    }

    /// The raw handle value, for passing to a syscall that needs it
    /// without transferring ownership (the `Handle` still closes it on
    /// drop).
    pub fn raw(&self) -> HandleValue {
        self.0
    }

    /// Take ownership of the fixed ACPI broker capability installed only in
    /// the initial process by the kernel.
    pub fn take_init_acpi_broker() -> Self {
        // SAFETY: the kernel reserves this slot for exactly one init-owned
        // broker handle; init calls this once before transferring ownership.
        unsafe { Self::from_raw(huesos_abi::INIT_ACPI_BROKER_HANDLE) }
    }

    /// Consume this `Handle` without closing the underlying kernel handle,
    /// returning the raw value. Use this when transferring ownership
    /// elsewhere (e.g. sending it over a channel) instead of letting this
    /// wrapper close it.
    pub fn into_raw(self) -> HandleValue {
        let raw = self.0;
        core::mem::forget(self);
        raw
    }

    /// Duplicate this handle. `rights` is a bitmask from
    /// [`huesos_abi::rights`], or [`huesos_abi::rights::SAME_RIGHTS`] to
    /// copy this handle's rights exactly.
    pub fn duplicate(&self, rights: u32) -> crate::Result<Handle> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall3(
            Syscall::HandleDuplicate,
            self.0 as u64,
            rights as u64,
            &mut out as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok(unsafe { Handle::from_raw(out) })
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE {
            let _ = raw::syscall1(Syscall::HandleClose, self.0 as u64);
        }
    }
}
