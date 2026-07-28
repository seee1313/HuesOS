//! Signal object syscalls.

use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{user_memory, util::current_proc, SyscallResult};

/// Create a level-triggered signal object.
pub(crate) fn sys_signal_create(out: *mut HandleValue) -> SyscallResult {
    user_memory::validate_write(out)?;
    let proc = current_proc()?;
    let signal = huesos_object::Signal::new();
    let koid = signal.koid();
    huesos_object::register_object(signal);
    match proc
        .handles
        .add_with_commit(Handle::new(koid, Rights::DEFAULT), |handle| {
            user_memory::write_value(out, &handle)
        }) {
        Ok((handle, _)) => Ok(handle as i64),
        Err(error) => {
            huesos_object::unregister_object(koid);
            Err(error)
        }
    }
}

/// Set a signal object.
pub(crate) fn sys_signal_set(handle: HandleValue) -> SyscallResult {
    signal_op(handle, true)
}

/// Clear a signal object.
pub(crate) fn sys_signal_clear(handle: HandleValue) -> SyscallResult {
    signal_op(handle, false)
}

fn signal_op(handle: HandleValue, set: bool) -> SyscallResult {
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let object = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let signal = object
        .downcast_ref::<huesos_object::Signal>()
        .ok_or(ErrorCode::WrongType)?;
    if set {
        signal.set();
    } else {
        signal.clear();
    }
    Ok(0)
}
