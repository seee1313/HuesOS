//! Handle syscalls.

use huesos_abi::{ErrorCode, HandleValue, INVALID_HANDLE};
use huesos_object::{Handle, Rights};

use crate::{util::current_proc, SyscallResult};

pub(crate) fn sys_handle_close(handle: HandleValue) -> SyscallResult {
    if handle == INVALID_HANDLE {
        return Err(ErrorCode::BadHandle);
    }
    let proc = current_proc()?;
    proc.handles.remove(handle).ok_or(ErrorCode::BadHandle)?;
    Ok(0)
}

pub(crate) fn sys_handle_duplicate(
    handle: HandleValue,
    rights: u32,
    out: *mut HandleValue,
) -> SyscallResult {
    if handle == INVALID_HANDLE || out.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    let new_rights = if rights == huesos_abi::rights::SAME_RIGHTS {
        h.rights
    } else {
        Rights::from_bits_truncate(rights)
    };
    let new_h = Handle::new(h.koid, new_rights);
    let new_hv = proc.handles.add(new_h);
    unsafe {
        *out = new_hv;
    }
    Ok(0)
}
