//! Safe userspace wrapper for `Syscall::ResourceCreate` and
//! `Syscall::ProcessMarkCritical`.
//!
//! These calls are restricted by the kernel to the root userspace
//! supervisor (init KOID). Every other process gets `AccessDenied`,
//! so this module is only useful for init / driver-manager / a
//! future component_manager. See `docs/ARCHITECTURE_ROADMAP.md` §4.

use crate::{raw, Handle, Result};
use huesos_abi::{HandleValue, Syscall, INVALID_HANDLE};

pub use huesos_abi::ResourceKindAbi as ResourceKind;

/// Immutable capability grant handle. Wraps a raw handle so it closes
/// itself on `Drop` via the shared `Handle` machinery.
pub struct Resource(Handle);

impl Resource {
    /// Mint a new `Resource` in the kernel and return an owning handle
    /// in this process's handle table. Fails with `AccessDenied` unless
    /// this process is the root userspace supervisor.
    pub fn create(kind: ResourceKind, base: u64, len: u64, exclusive: bool) -> Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall5(
            Syscall::ResourceCreate,
            kind as u32 as u64,
            base,
            len,
            if exclusive { 1 } else { 0 },
            &mut out as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        // SAFETY: kernel wrote a valid handle owned by this process
        // when ResourceCreate returned success.
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Access the underlying handle for transfer through a channel.
    pub fn handle(&self) -> &Handle {
        &self.0
    }

    /// Consume `self` and yield the raw handle for transfer semantics
    /// (e.g. `channel.write_with_handle(&msg, resource.into_raw())`),
    /// suppressing `Drop` so the receiver becomes the owner.
    pub fn into_raw(self) -> HandleValue {
        self.0.into_raw()
    }

    /// Consume `self` and yield the owned `Handle` for channel
    /// transfer via `Channel::write_handle`. This is the safe path
    /// callers should prefer over `into_raw()` — no `unsafe` needed
    /// on the caller side.
    pub fn into_handle(self) -> Handle {
        self.0
    }
}

/// Mark the target process as critical (see the kernel
/// `Process::mark_critical` docs). Fails with `AccessDenied` unless
/// the caller is the root userspace supervisor.
pub fn mark_process_critical(process_handle: HandleValue) -> Result<()> {
    let ret = raw::syscall1(Syscall::ProcessMarkCritical, process_handle as u64);
    raw::decode(ret)?;
    Ok(())
}

/// Wire-level ABI kind values, re-exported for callers that want to
/// name the enum without importing `huesos-abi` separately.
pub mod kind {
    use huesos_abi::ResourceKindAbi;

    /// x86 port I/O space.
    pub const IO_PORT: ResourceKindAbi = ResourceKindAbi::IoPort;
    /// Physical memory-mapped I/O region.
    pub const MMIO: ResourceKindAbi = ResourceKindAbi::Mmio;
    /// Physical interrupt vector / IRQ line.
    pub const IRQ: ResourceKindAbi = ResourceKindAbi::Irq;
}
