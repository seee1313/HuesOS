//! Syscall handlers for the immutable `Resource` capability primitive.
//!
//! Currently exposes two operations, both restricted to the root
//! userspace supervisor (init KOID) so a compromised driver-manager or
//! driver process cannot forge capabilities. See
//! `docs/ARCHITECTURE_ROADMAP.md` §2 and §3 for the model.
//!
//! * `sys_resource_create` mints a `Resource` and installs its handle in
//!   the caller's handle table with `READ | WRITE | TRANSFER` rights.
//!   The caller (init or driver-manager on its behalf) later transfers
//!   the handle to the target driver via a channel.
//! * `sys_process_mark_critical` marks a target process as critical
//!   (see `Process::critical` docs).

use huesos_abi::{ErrorCode, HandleValue, ResourceKindAbi};
use huesos_object::{
    current_process, register_object, unregister_object, Handle, KernelObject, KernelObjectExt,
    Process, Resource, ResourceError, ResourceKind, Rights,
};

use crate::user_memory;
use crate::SyscallResult;

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
    };

    let resource = if exclusive != 0 {
        Resource::try_create_exclusive(kernel_kind, base, len)
    } else {
        Resource::try_create_shared(kernel_kind, base, len)
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
