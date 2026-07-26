//! Syscall handlers for the immutable `Resource` capability primitive
//! and its capability-gated system-control operations.
//!
//! `sys_resource_create` and `sys_process_mark_critical` are gated on the
//! root userspace supervisor (init KOID) so a compromised driver process
//! cannot forge capabilities. `sys_hard_halt` and the `sys_ioport_*`
//! operations gate on **capability possession** instead: the caller must
//! present a live `Resource` handle whose kind (and, for I/O ports,
//! whose range) authorises the requested operation. This matches the
//! Zircon model where a resource handle *is* the capability. See
//! `docs/ARCHITECTURE_ROADMAP.md` §2 and §3 for the design.

use huesos_abi::{ErrorCode, HandleValue, ResourceKindAbi};
use huesos_object::{
    current_process, register_object, unregister_object, Handle, KernelObject, KernelObjectExt,
    Process, Resource, ResourceError, ResourceKind, Rights,
};

use crate::user_memory;
use crate::SyscallResult;

/// Kernel-installed atomic halt. Diverges: the syscall never returns
/// to the caller. Registered once at boot from
/// `huesos_kernel::init::syscall_init`.
pub type HardHaltFn = fn() -> !;
static HARD_HALT_FN: spin::Mutex<Option<HardHaltFn>> = spin::Mutex::new(None);

/// Install the kernel-side atomic halt implementation. Called once
/// from `huesos_kernel::init::syscall_init`.
pub fn set_hard_halt_fn(f: HardHaltFn) {
    *HARD_HALT_FN.lock() = Some(f);
}

/// Kernel-configurable predicate: is `caller_koid` the root userspace
/// supervisor? Set once by the kernel during init via
/// [`set_root_supervisor_predicate`].
type RootSupervisorPredicate = fn(u64) -> bool;
static ROOT_SUPERVISOR_FN: spin::Mutex<Option<RootSupervisorPredicate>> = spin::Mutex::new(None);

/// Install the "is this KOID the root supervisor?" predicate. Called
/// once by `huesos-kernel::init` after the init process KOID is known.
pub fn set_root_supervisor_predicate(f: RootSupervisorPredicate) {
    *ROOT_SUPERVISOR_FN.lock() = Some(f);
}

fn caller_is_root_supervisor() -> Result<(), ErrorCode> {
    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let predicate = (*ROOT_SUPERVISOR_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    if !predicate(caller.koid().0) {
        return Err(ErrorCode::AccessDenied);
    }
    Ok(())
}

pub(crate) fn sys_resource_create(
    kind: u32,
    base: u64,
    len: u64,
    exclusive: u32,
    out_handle: *mut HandleValue,
) -> SyscallResult {
    caller_is_root_supervisor()?;
    user_memory::validate_write(out_handle)?;

    let abi = ResourceKindAbi::from_raw(kind).ok_or(ErrorCode::InvalidArgs)?;
    let kernel_kind = match abi {
        ResourceKindAbi::IoPort => ResourceKind::IoPort,
        ResourceKindAbi::Mmio => ResourceKind::Mmio,
        ResourceKindAbi::Irq => ResourceKind::Irq,
        ResourceKindAbi::PowerControl => ResourceKind::PowerControl,
    };

    // `PowerControl` is a binary capability with no meaningful range;
    // force base/len to zero at mint time so overlap-checked collisions
    // deterministically fire only on genuine double-mint attempts.
    // Every other kind keeps the caller-supplied range.
    let (mint_base, mint_len) = if matches!(kernel_kind, ResourceKind::PowerControl) {
        (0, 1)
    } else {
        (base, len)
    };

    let resource = if exclusive != 0 {
        Resource::try_create_exclusive(kernel_kind, mint_base, mint_len)
    } else {
        Resource::try_create_shared(kernel_kind, mint_base, mint_len)
    }
    .map_err(|e| match e {
        ResourceError::InvalidRange => ErrorCode::InvalidArgs,
        ResourceError::Conflict => ErrorCode::Busy,
    })?;

    let koid = resource.koid();
    // The Resource constructor already registered it via
    // registry::try_register_resource_locked; do not register_object
    // again. Install the caller-owned handle with the standard triple
    // (READ | WRITE | TRANSFER) so the caller can transfer it via a
    // channel to the eventual driver process without needing extra
    // rights juggling later.
    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let rights = Rights::READ | Rights::WRITE | Rights::TRANSFER;
    let handle_value = caller.handles.add(Handle::new(koid, rights));

    if user_memory::write_value(out_handle, &handle_value).is_err() {
        // Rollback: caller could not receive the handle, so return the
        // registry to its previous state instead of leaking a Resource
        // range reservation the caller cannot address.
        let _ = caller.handles.remove(handle_value);
        unregister_object(koid);
        return Err(ErrorCode::InvalidArgs);
    }
    let _ = register_object; // Silence unused warning in this module; the symbol is imported for future rollback paths.
    Ok(0)
}

pub(crate) fn sys_process_mark_critical(process_handle: HandleValue) -> SyscallResult {
    caller_is_root_supervisor()?;
    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let handle = caller
        .handles
        .get(process_handle)
        .ok_or(ErrorCode::BadHandle)?;
    let object = huesos_object::lookup_object(handle.koid).ok_or(ErrorCode::BadHandle)?;
    let process = object
        .downcast_ref::<Process>()
        .ok_or(ErrorCode::WrongType)?;
    process.mark_critical();
    Ok(0)
}

/// Look up a caller-owned handle and confirm it names a live
/// [`Resource`] of the requested kind. Returns the owning `Arc<dyn
/// KernelObject>` so the caller can downcast to `Resource` at the
/// point of use (the borrow-checker keeps the resource alive for
/// exactly the duration of the caller's use).
fn require_resource_of_kind(
    handle: HandleValue,
    kind: ResourceKind,
) -> Result<alloc::sync::Arc<dyn KernelObject>, ErrorCode> {
    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let entry = caller.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    let object = huesos_object::lookup_object(entry.koid).ok_or(ErrorCode::BadHandle)?;
    let resource = object
        .downcast_ref::<Resource>()
        .ok_or(ErrorCode::WrongType)?;
    if resource.kind() != kind {
        return Err(ErrorCode::WrongType);
    }
    Ok(object)
}

pub(crate) fn sys_hard_halt(resource_handle: HandleValue) -> SyscallResult {
    // Capability check: caller must present a live PowerControl resource
    // handle. Fuchsia-inspired inversion of control: the kernel does
    // not decide *when* to halt, only that halting is safe *now*.
    let guard = require_resource_of_kind(resource_handle, ResourceKind::PowerControl)?;
    let halt = (*HARD_HALT_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    // Drop the Arc explicitly before the diverging call so the object
    // account is released even though the halt is followed by an hlt
    // loop that would otherwise reap the whole registry.
    drop(guard);
    halt();
}

pub(crate) fn sys_ioport_write8(
    resource_handle: HandleValue,
    port: u32,
    value: u32,
) -> SyscallResult {
    let guard = require_resource_of_kind(resource_handle, ResourceKind::IoPort)?;
    let resource = guard
        .downcast_ref::<Resource>()
        .ok_or(ErrorCode::WrongType)?;
    // Port must fit in u16 (x86 architectural limit) and lie entirely
    // inside the resource's granted range.
    let port_u16 = u16::try_from(port).map_err(|_| ErrorCode::InvalidArgs)?;
    if !resource.contains(ResourceKind::IoPort, u64::from(port_u16), 1) {
        return Err(ErrorCode::AccessDenied);
    }
    let byte = (value & 0xff) as u8;
    // SAFETY: the port is inside a range the caller was granted; the
    // ranged capability check above has been performed under the
    // current handle-table lock. `Port::write` performs a single `out`
    // instruction to a validated port.
    unsafe { x86_64::instructions::port::Port::<u8>::new(port_u16).write(byte) };
    Ok(0)
}

pub(crate) fn sys_ioport_read8(resource_handle: HandleValue, port: u32) -> SyscallResult {
    let guard = require_resource_of_kind(resource_handle, ResourceKind::IoPort)?;
    let resource = guard
        .downcast_ref::<Resource>()
        .ok_or(ErrorCode::WrongType)?;
    let port_u16 = u16::try_from(port).map_err(|_| ErrorCode::InvalidArgs)?;
    if !resource.contains(ResourceKind::IoPort, u64::from(port_u16), 1) {
        return Err(ErrorCode::AccessDenied);
    }
    // SAFETY: same capability contract as sys_ioport_write8 above.
    let byte: u8 = unsafe { x86_64::instructions::port::Port::<u8>::new(port_u16).read() };
    Ok(i64::from(byte))
}
