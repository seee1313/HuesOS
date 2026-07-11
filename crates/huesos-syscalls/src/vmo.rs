//! VMO syscalls.

use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{user_memory, util::current_proc, SyscallResult};

/// Upper bound on a single VMO's size (4 GiB). This is not yet a per-job
/// memory quota; it rejects pathological requests before allocator metadata
/// construction can overflow.
const MAX_VMO_SIZE: usize = 4 * 1024 * 1024 * 1024;

pub(crate) fn sys_vmo_create(size: usize, out_handle: *mut HandleValue) -> SyscallResult {
    if size == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    if size > MAX_VMO_SIZE {
        return Err(ErrorCode::NoMemory);
    }
    // Validate before allocating frames or installing a handle: an invalid
    // output pointer must leave no externally visible side effect.
    user_memory::validate_write(out_handle)?;

    let vmo = huesos_object::Vmo::new(size).map_err(|_| ErrorCode::NoMemory)?;
    let koid = vmo.koid();
    huesos_object::register_object(vmo);
    let proc = current_proc()?;
    let hv = proc.handles.add(Handle::new(koid, Rights::DEFAULT_VMO));
    user_memory::write_value(out_handle, &hv)?;
    Ok(0)
}

pub(crate) fn sys_vmo_read(
    handle: HandleValue,
    offset: u64,
    buf: *mut u8,
    len: usize,
) -> SyscallResult {
    if len == 0 || len > user_memory::MAX_VMO_TRANSFER {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_range(buf as u64, len, true)?;

    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;
    let mut tmp = user_memory::zeroed_buffer(len)?;
    let n = vmo.read(offset as usize, &mut tmp);
    user_memory::copy_to_user(buf, &tmp[..n])?;
    Ok(n as i64)
}

pub(crate) fn sys_vmo_write(
    handle: HandleValue,
    offset: u64,
    buf: *const u8,
    len: usize,
) -> SyscallResult {
    if len == 0 || len > user_memory::MAX_VMO_TRANSFER {
        return Err(ErrorCode::InvalidArgs);
    }
    // Copy first so no VMO lock is held while touching untrusted memory.
    let bytes = user_memory::copy_from_user(buf, len)?;

    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;
    let n = vmo.write(offset as usize, &bytes);
    Ok(n as i64)
}
