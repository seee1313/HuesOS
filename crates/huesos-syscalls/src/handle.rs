//! Handle syscalls.

use huesos_abi::{ErrorCode, HandleValue, INVALID_HANDLE};
use huesos_object::{Handle, Rights};

use crate::{user_memory, util::current_proc, SyscallResult};

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
    if handle == INVALID_HANDLE {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_write(out)?;

    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::DUPLICATE) {
        return Err(ErrorCode::AccessDenied);
    }
    let new_rights = if rights == huesos_abi::rights::SAME_RIGHTS {
        h.rights
    } else {
        let requested = Rights::from_bits(rights).ok_or(ErrorCode::InvalidArgs)?;
        // Duplication may preserve or reduce a capability, never amplify it.
        if !h.rights.contains(requested) {
            return Err(ErrorCode::AccessDenied);
        }
        requested
    };
    let new_hv = proc.handles.add(Handle::new(h.koid, new_rights));
    if let Err(error) = user_memory::write_value(out, &new_hv) {
        let _ = proc.handles.remove(new_hv);
        return Err(error);
    }
    Ok(0)
}
