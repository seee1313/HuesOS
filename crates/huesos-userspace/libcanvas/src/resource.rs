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
    /// Atomic-halt / reboot / power-off capability.
    pub const POWER_CONTROL: ResourceKindAbi = ResourceKindAbi::PowerControl;
    /// Preallocated DMA pool capability for userspace DriverHosts.
    pub const DMA_POOL: ResourceKindAbi = ResourceKindAbi::DmaPool;
}

/// Safe wrapper over an `IoPort` [`Resource`] handle. Provides typed
/// `read_u8`/`write_u8` methods that go through the kernel's
/// capability-checked `IoPortRead8`/`IoPortWrite8` syscalls.
pub struct IoPort {
    handle: Handle,
}

impl IoPort {
    /// Adopt an already-owned handle (e.g. one just received over a
    /// bootstrap channel) as an `IoPort` capability. The caller is
    /// responsible for having verified the handle really names an
    /// IoPort resource (the kernel will reject reads/writes with the
    /// wrong kind, so this is a safety-net, not a security check).
    pub fn from_handle(handle: Handle) -> Self {
        Self { handle }
    }

    /// The underlying raw handle, for passing to a syscall that needs
    /// it without transferring ownership.
    pub fn raw(&self) -> HandleValue {
        self.handle.raw()
    }

    /// Write one byte to `port`. Fails with `AccessDenied` if the port
    /// lies outside the resource's granted `[base, base+len)` range,
    /// or with `WrongType` if the handle does not name an IoPort
    /// resource.
    pub fn write_u8(&self, port: u16, value: u8) -> Result<()> {
        let ret = raw::syscall3(
            Syscall::IoPortWrite8,
            self.handle.raw() as u64,
            port as u64,
            value as u64,
        );
        raw::decode(ret)?;
        Ok(())
    }

    /// Read one byte from `port`. Same capability contract as
    /// [`Self::write_u8`].
    pub fn read_u8(&self, port: u16) -> Result<u8> {
        let ret = raw::syscall2(Syscall::IoPortRead8, self.handle.raw() as u64, port as u64);
        let value = raw::decode(ret)?;
        Ok(value as u8)
    }
}

/// Invoke the kernel's capability-gated atomic halt. Never returns on
/// success; on failure the kernel returns an `ErrorCode` and the
/// caller decides what to do. `power_control` must be a live handle
/// naming a [`ResourceKind::PowerControl`] resource; every other
/// process gets `AccessDenied`.
pub fn hard_halt(power_control: &Handle) -> ! {
    let ret = raw::syscall1(Syscall::HardHalt, power_control.raw() as u64);
    // If the kernel returned, halting failed. Fall through to an
    // exit-1 loop so the surrounding driver-manager's critical-exit
    // fallback still fires. This should never happen if the caller
    // holds a live PowerControl handle.
    let _ = raw::decode(ret);
    crate::process::exit(-1);
}
