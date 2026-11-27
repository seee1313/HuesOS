//! Syscall handlers for the kernel-enforced `DeviceLease` capability (AP-20).

use alloc::sync::Arc;
use huesos_abi::pci_lease::{
    revoke_flags, DeviceLeaseBindPortArgs, DeviceLeaseCreateArgs, DeviceLeaseInfo,
    DeviceLeaseMintResourceArgs,
};
use huesos_abi::{ErrorCode, HandleValue, ResourceKindAbi};
use huesos_object::{
    current_process, unregister_object, DeviceLease, DeviceLeaseError, Handle, KernelObject,
    KernelObjectExt, Port, Resource, ResourceError, ResourceKind, Rights,
};

use crate::resource::require_resource_of_kind;
use crate::user_memory;
use crate::SyscallResult;

pub(crate) fn sys_device_lease_create(
    args_ptr: *const DeviceLeaseCreateArgs,
    out_handle: *mut HandleValue,
) -> SyscallResult {
    user_memory::validate_write(out_handle)?;
    let args = user_memory::read_value(args_ptr)?;
    if !args.validate() {
        return Err(ErrorCode::InvalidArgs);
    }

    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let auth_handle = caller
        .handles
        .get(args.authority)
        .ok_or(ErrorCode::BadHandle)?;
    if !auth_handle.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let _auth_obj = require_resource_of_kind(args.authority, ResourceKind::DeviceLeaseAuthority)?;

    let lease = DeviceLease::try_create(
        args.device_id,
        args.firmware_snapshot_id,
        args.pci_address_packed,
    )
    .map_err(map_lease_error)?;
    let koid = lease.koid();
    let rights = Rights::DEFAULT;
    match caller
        .handles
        .add_with_commit(Handle::new(koid, rights), |handle_value| {
            user_memory::write_value(out_handle, &handle_value)
        }) {
        Ok(_) => Ok(0),
        Err(error) => {
            unregister_object(koid);
            Err(error)
        }
    }
}

pub(crate) fn sys_device_lease_mint_resource(
    args_ptr: *const DeviceLeaseMintResourceArgs,
    out_handle: *mut HandleValue,
) -> SyscallResult {
    user_memory::validate_write(out_handle)?;
    let args = user_memory::read_value(args_ptr)?;
    if !args.validate() {
        return Err(ErrorCode::InvalidArgs);
    }

    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let lease_handle = caller.handles.get(args.lease).ok_or(ErrorCode::BadHandle)?;
    if !lease_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let lease_obj = huesos_object::lookup_object(lease_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let lease = lease_obj
        .downcast_ref::<DeviceLease>()
        .ok_or(ErrorCode::WrongType)?;

    if lease.is_revoked() {
        return Err(ErrorCode::AccessDenied);
    }
    if !lease.is_generation_active(args.expected_generation) {
        return Err(ErrorCode::Busy);
    }

    let kind = match ResourceKindAbi::from_raw(args.kind) {
        Some(ResourceKindAbi::IoPort) => ResourceKind::IoPort,
        Some(ResourceKindAbi::Mmio) => ResourceKind::Mmio,
        Some(ResourceKindAbi::Irq) => ResourceKind::Irq,
        Some(ResourceKindAbi::DmaPool) => ResourceKind::DmaPool,
        _ => return Err(ErrorCode::InvalidArgs),
    };

    if kind == ResourceKind::DmaPool
        && (!huesos_object::dma_pool_range_owned(args.base, args.len)
            || !huesos_object::dynamic_slot_range_owned(args.base, args.len))
    {
        // A lease-bound DmaPool is reserved for one complete kernel-owned
        // live-hotplug slice. Static boot grants are unbound resources minted
        // by init and do not enter this path.
        return Err(ErrorCode::AccessDenied);
    }

    let resource = Resource::try_create_leased(
        kind,
        args.base,
        args.len,
        args.exclusive != 0,
        lease.koid(),
        args.expected_generation,
    )
    .map_err(|e| match e {
        ResourceError::InvalidRange => ErrorCode::InvalidArgs,
        ResourceError::Conflict => ErrorCode::Busy,
    })?;

    // Re-check generation after creating the resource so a concurrent
    // revocation cannot leave a live handle to an already-dead generation.
    if !lease.is_generation_active(args.expected_generation) {
        unregister_object(resource.koid());
        return Err(ErrorCode::AccessDenied);
    }

    if kind == ResourceKind::DmaPool {
        if let Err(err) = lease.attach_dma_range(args.expected_generation, args.base, args.len) {
            unregister_object(resource.koid());
            // A hardware bind failure is fail-closed for the whole lease. A
            // future hook implementation may have installed part of a domain
            // before reporting an error; revoke synchronously tears down any
            // such partial state before the caller can continue using the
            // lease. A concurrent revoke simply makes this cleanup a no-op.
            let _ = lease.revoke(args.expected_generation, true);
            return Err(map_lease_error(err));
        }
    }

    let koid = resource.koid();
    let rights = Rights::READ | Rights::WRITE | Rights::TRANSFER;
    match caller
        .handles
        .add_with_commit(Handle::new(koid, rights), |handle_value| {
            user_memory::write_value(out_handle, &handle_value)
        }) {
        Ok(_) => Ok(0),
        Err(error) => {
            unregister_object(koid);
            // The resource is the capability view; the lease owns the
            // dynamic slot and may already have an IOMMU mapping. Do not let
            // a failed handle copy-out release the slot while the generation
            // remains active. Revoke synchronously tears down and releases it.
            if kind == ResourceKind::DmaPool {
                let _ = lease.revoke(args.expected_generation, true);
            }
            Err(error)
        }
    }
}

pub(crate) fn sys_device_lease_revoke(
    lease_handle_val: HandleValue,
    expected_generation: u64,
    reason_flags: u32,
) -> SyscallResult {
    if reason_flags & !revoke_flags::ALL != 0 || expected_generation == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let lease_handle = caller
        .handles
        .get(lease_handle_val)
        .ok_or(ErrorCode::BadHandle)?;
    if !lease_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let lease_obj = huesos_object::lookup_object(lease_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let lease = lease_obj
        .downcast_ref::<DeviceLease>()
        .ok_or(ErrorCode::WrongType)?;
    let failed = (reason_flags & revoke_flags::FAILED) != 0;
    let revoked_gen = lease
        .revoke(expected_generation, failed)
        .map_err(map_lease_error)?;
    Ok(revoked_gen as i64)
}

pub(crate) fn sys_device_lease_bind_gone_port(
    args_ptr: *const DeviceLeaseBindPortArgs,
) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    if !args.validate() {
        return Err(ErrorCode::InvalidArgs);
    }
    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let lease_handle = caller.handles.get(args.lease).ok_or(ErrorCode::BadHandle)?;
    if !lease_handle.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let port_handle = caller.handles.get(args.port).ok_or(ErrorCode::BadHandle)?;
    if !port_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let lease_obj = huesos_object::lookup_object(lease_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let lease = lease_obj
        .downcast_ref::<DeviceLease>()
        .ok_or(ErrorCode::WrongType)?;
    let port_obj = huesos_object::lookup_object(port_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let port: Arc<Port> = port_obj
        .downcast_arc::<Port>()
        .map_err(|_| ErrorCode::WrongType)?;

    lease
        .bind_gone_port(port, args.key)
        .map_err(map_lease_error)?;
    Ok(0)
}

pub(crate) fn sys_device_lease_query(
    lease_handle_val: HandleValue,
    out_info: *mut DeviceLeaseInfo,
) -> SyscallResult {
    user_memory::validate_write(out_info)?;
    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let lease_handle = caller
        .handles
        .get(lease_handle_val)
        .ok_or(ErrorCode::BadHandle)?;
    if !lease_handle.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let lease_obj = huesos_object::lookup_object(lease_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let lease = lease_obj
        .downcast_ref::<DeviceLease>()
        .ok_or(ErrorCode::WrongType)?;
    let snap = lease.info();
    let info = DeviceLeaseInfo {
        device_id: snap.device_id,
        generation: snap.generation,
        firmware_snapshot_id: snap.firmware_snapshot_id,
        pci_address_packed: snap.pci_address_packed,
        state: snap.state as u32,
        revoked: u32::from(snap.revoked),
    };
    user_memory::write_value(out_info, &info)?;
    Ok(0)
}

pub(crate) fn sys_device_lease_attach_dma(
    lease_handle_val: HandleValue,
    dma_handle_val: HandleValue,
    expected_generation: u64,
) -> SyscallResult {
    if expected_generation == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let caller = current_process().ok_or(ErrorCode::AccessDenied)?;
    let lease_handle = caller
        .handles
        .get(lease_handle_val)
        .ok_or(ErrorCode::BadHandle)?;
    if !lease_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let dma_entry = caller
        .handles
        .get(dma_handle_val)
        .ok_or(ErrorCode::BadHandle)?;
    if !dma_entry.has_rights(Rights::READ | Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let dma_obj = require_resource_of_kind(dma_handle_val, ResourceKind::DmaPool)?;
    let dma_res = dma_obj
        .downcast_ref::<Resource>()
        .ok_or(ErrorCode::WrongType)?;
    if !dma_res.is_lease_active()
        || !huesos_object::dma_pool_range_owned(dma_res.base(), dma_res.len())
    {
        return Err(ErrorCode::AccessDenied);
    }
    // Static boot grants are intentionally unbound and may be attached by
    // their trusted supervisor. Dynamic hotplug DmaPool resources are already
    // bound to the creating lease; never let a second lease attach the same
    // physical slice, even if both callers hold a writable lease handle.
    if let Some((bound_lease, bound_generation)) = dma_res.lease_binding() {
        if bound_lease != lease_handle.koid || bound_generation != expected_generation {
            return Err(ErrorCode::AccessDenied);
        }
    } else if huesos_object::range_overlaps_dynamic_area(dma_res.base(), dma_res.len()) {
        // A generic root-created resource may cover only fixed boot slices;
        // the live hotplug area requires the lease-bound slot path.
        return Err(ErrorCode::AccessDenied);
    }
    let lease_obj = huesos_object::lookup_object(lease_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let lease = lease_obj
        .downcast_ref::<DeviceLease>()
        .ok_or(ErrorCode::WrongType)?;

    lease
        .attach_dma_range(expected_generation, dma_res.base(), dma_res.len())
        .map_err(map_lease_error)?;
    Ok(0)
}

const fn map_lease_error(err: DeviceLeaseError) -> ErrorCode {
    match err {
        DeviceLeaseError::InvalidArgs => ErrorCode::InvalidArgs,
        DeviceLeaseError::StaleOrRevoked => ErrorCode::Busy,
        DeviceLeaseError::TooManyPorts => ErrorCode::NoMemory,
        DeviceLeaseError::GenerationExhausted => ErrorCode::Internal,
        DeviceLeaseError::IommuBindFailed => ErrorCode::Busy,
    }
}
