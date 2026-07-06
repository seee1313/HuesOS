//! VMO syscalls.

use alloc::vec;
use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{util::current_proc, SyscallResult};

/// Upper bound on a single VMO's size (4 GiB). This is *not* a real memory
/// accounting/quota system (see the Job resource-limits roadmap item) — it
/// exists purely to reject obviously-bogus sizes (e.g. a userspace bug
/// passing `usize::MAX`) before they reach `Vec::with_capacity`, which
/// would otherwise abort the whole kernel with a "capacity overflow" panic
/// while trying to allocate a frame-address array sized for an
/// astronomical page count, rather than cleanly failing the syscall.
const MAX_VMO_SIZE: usize = 4 * 1024 * 1024 * 1024;

pub(crate) fn sys_vmo_create(size: usize, out_handle: *mut HandleValue) -> SyscallResult {
    if out_handle.is_null() || size == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    if size > MAX_VMO_SIZE {
        return Err(ErrorCode::NoMemory);
    }
    let vmo = huesos_object::Vmo::new(size).map_err(|_| ErrorCode::NoMemory)?;
    let koid = vmo.koid();
    huesos_object::register_object(vmo);
    let proc = current_proc()?;
    let hv = proc.handles.add(Handle::new(koid, Rights::DEFAULT_VMO));
    unsafe {
        *out_handle = hv;
    }
    Ok(0)
}

pub(crate) fn sys_vmo_read(
    handle: HandleValue,
    offset: u64,
    buf: *mut u8,
    len: usize,
) -> SyscallResult {
    if buf.is_null() || len == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;
    let mut tmp = vec![0u8; len];
    let n = vmo.read(offset as usize, &mut tmp);
    unsafe {
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n);
    }
    Ok(n as i64)
}

pub(crate) fn sys_vmo_write(
    handle: HandleValue,
    offset: u64,
    buf: *const u8,
    len: usize,
) -> SyscallResult {
    if buf.is_null() || len == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;
    let tmp = unsafe { core::slice::from_raw_parts(buf, len) };
    let n = vmo.write(offset as usize, tmp);
    Ok(n as i64)
}
