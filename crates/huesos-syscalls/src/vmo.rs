//! VMO syscalls.

use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{user_memory, util::current_proc, SyscallResult};

/// Upper bound on a single VMO's size (4 GiB). This is not yet a per-job
/// memory quota; it rejects pathological requests before allocator metadata
/// construction can overflow.
const MAX_VMO_SIZE: usize = 4 * 1024 * 1024 * 1024;

pub(crate) fn sys_vmo_create(size: usize, out_handle: *mut HandleValue) -> SyscallResult {
    sys_vmo_create_with_rights(size, false, out_handle)
}

pub(crate) fn sys_vmo_create_ex(
    size: usize,
    flags: u32,
    out_handle: *mut HandleValue,
) -> SyscallResult {
    if flags & !huesos_abi::vmo_create_flags::EXECUTABLE != 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    sys_vmo_create_with_rights(
        size,
        flags & huesos_abi::vmo_create_flags::EXECUTABLE != 0,
        out_handle,
    )
}

fn sys_vmo_create_with_rights(
    size: usize,
    executable: bool,
    out_handle: *mut HandleValue,
) -> SyscallResult {
    if size == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    if size > MAX_VMO_SIZE {
        return Err(ErrorCode::NoMemory);
    }
    // Validate before allocating frames or installing a handle: an invalid
    // output pointer must leave no externally visible side effect.
    user_memory::validate_write(out_handle)?;

    let proc = current_proc()?;
    let vmo =
        huesos_object::Vmo::new_in_job(size, Some(proc.job())).map_err(|_| ErrorCode::NoMemory)?;
    let koid = vmo.koid();
    huesos_object::register_object(vmo);
    let mut rights = Rights::DEFAULT_VMO;
    if executable {
        rights |= Rights::EXECUTE;
    }
    proc.handles
        .add_with_commit(Handle::new(koid, rights), |hv| {
            user_memory::write_value(out_handle, &hv)
        })
        .map(|_| 0)
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
    let start_offset = usize::try_from(offset).map_err(|_| ErrorCode::InvalidArgs)?;
    let mut chunk = [0u8; 2048];
    let mut total_read = 0usize;
    while total_read < len {
        let step = (len - total_read).min(chunk.len());
        let off = start_offset
            .checked_add(total_read)
            .ok_or(ErrorCode::InvalidArgs)?;
        let n = vmo.read(off, &mut chunk[..step]);
        if n == 0 {
            break;
        }
        let dst = (buf as u64)
            .checked_add(total_read as u64)
            .ok_or(ErrorCode::InvalidArgs)? as *mut u8;
        user_memory::copy_to_user(dst, &chunk[..n])?;
        total_read += n;
        if n < step {
            break;
        }
    }
    Ok(total_read as i64)
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
    user_memory::validate_range(buf as u64, len, false)?;

    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;
    let start_offset = usize::try_from(offset).map_err(|_| ErrorCode::InvalidArgs)?;
    let mut chunk = [0u8; 2048];
    let mut total_written = 0usize;
    while total_written < len {
        let step = (len - total_written).min(chunk.len());
        let src = (buf as u64)
            .checked_add(total_written as u64)
            .ok_or(ErrorCode::InvalidArgs)? as *const u8;
        user_memory::copy_from_user_into(src, &mut chunk[..step])?;
        let off = start_offset
            .checked_add(total_written)
            .ok_or(ErrorCode::InvalidArgs)?;
        let n = vmo.write(off, &chunk[..step]);
        total_written += n;
        if n < step {
            break;
        }
    }
    Ok(total_written as i64)
}
