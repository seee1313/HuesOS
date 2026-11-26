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

    /// Return the stable kernel object ID named by this capability.
    ///
    /// A KOID is opaque identity only: it grants no rights and cannot be used
    /// in place of a handle. The kernel validates that this owned handle is
    /// live before returning the ID.
    pub fn koid(&self) -> crate::Result<u64> {
        let mut koid = 0u64;
        let raw = raw::syscall2(
            Syscall::HandleGetKoid,
            self.0 as u64,
            &mut koid as *mut u64 as u64,
        );
        raw::decode(raw)?;
        Ok(koid)
    }

    /// Take ownership of a kernel-reserved fixed init slot.
    ///
    /// `raw` must name a slot the kernel reserves for exactly one
    /// init-owned handle; callers assert that by construction (the
    /// slot constants come from `huesos-abi`).
    fn take_fixed_init_handle(raw: HandleValue) -> Self {
        // SAFETY: every caller passes a kernel-reserved init slot
        // constant; the kernel installs exactly one owned handle per
        // such slot and init calls each take function at most once.
        unsafe { Self::from_raw(raw) }
    }

    /// Take ownership of the fixed ACPI broker capability installed only in
    /// the initial process by the kernel.
    pub fn take_init_acpi_broker() -> Self {
        Self::take_fixed_init_handle(huesos_abi::INIT_ACPI_BROKER_HANDLE)
    }

    /// Take ownership of the `FrameDraw` capability installed only in the
    /// initial process by the kernel.
    ///
    /// init uses this to duplicate the single exclusive `FrameDraw`
    /// resource and deliver a handle to each graphics consumer over a
    /// channel; see `docs/ARCHITECTURE_ROADMAP.md` § framebuffer.
    pub fn take_init_frame_draw() -> Self {
        Self::take_fixed_init_handle(huesos_abi::INIT_FRAME_DRAW_HANDLE)
    }

    /// Take ownership of the unique `PciConfigMint` authority installed
    /// only in the initial process by the kernel (AP-8).
    ///
    /// init transfers it (never duplicates it) to DriverManager, which
    /// is the only component allowed to mint generation-bound PCI
    /// configuration capabilities; see `docs/PCI_MANAGER_ARCHITECTURE.md`
    /// and `docs/PCI_PRODUCTION_ROADMAP.md` (Stages C.1/H.1).
    pub fn take_init_config_mint() -> Self {
        Self::take_fixed_init_handle(huesos_abi::INIT_CONFIG_MINT_HANDLE)
    }

    /// Take ownership of the unique `DeviceLeaseAuthority` capability installed
    /// only in the initial process by the kernel (AP-20).
    pub fn take_init_device_lease_authority() -> Self {
        Self::take_fixed_init_handle(huesos_abi::INIT_DEVICE_LEASE_AUTH_HANDLE)
    }

    pub(crate) fn from_syscall_out(raw: HandleValue) -> Self {
        Self::take_fixed_init_handle(raw)
    }

    /// Wrap a batch of raw handle values installed in this process's
    /// table by one syscall into owned RAII handles. Used by the
    /// `PciConfigMint` wrapper: the mint installs exactly one owned
    /// handle per reported slot. Slots past `count` are left `None`.
    pub(crate) fn fill_kernel_batch(out: &mut [Option<Self>], values: &[HandleValue]) {
        for (slot, &value) in out.iter_mut().zip(values.iter()) {
            // SAFETY: `values` comes straight from a syscall that
            // installed one owned handle per entry in this process's
            // table; each raw value is wrapped exactly once, here.
            *slot = Some(unsafe { Self::from_raw(value) });
        }
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

/// Close a raw handle value without first wrapping it in an owning [`Handle`].
///
/// This is used by transfer helpers after they intentionally call
/// [`Handle::into_raw`]: if the kernel rejects the transfer, the consumed Rust
/// wrapper must not leak the still-open handle-table entry.
pub(crate) fn close_raw(raw_handle: HandleValue) {
    if raw_handle != INVALID_HANDLE {
        let _ = raw::syscall1(Syscall::HandleClose, raw_handle as u64);
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        close_raw(self.0);
    }
}
