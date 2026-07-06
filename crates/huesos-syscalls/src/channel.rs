//! Channel IPC syscalls.

use alloc::vec::Vec;
use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{util::current_proc, SyscallResult};

pub(crate) fn sys_channel_create(out0: *mut HandleValue, out1: *mut HandleValue) -> SyscallResult {
    if out0.is_null() || out1.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let (ch0, ch1) = huesos_object::Channel::pair();
    let koid0 = ch0.koid();
    let koid1 = ch1.koid();
    huesos_object::register_object(ch0);
    huesos_object::register_object(ch1);
    let proc = current_proc()?;
    let hv0 = proc.handles.add(Handle::new(koid0, Rights::DEFAULT));
    let hv1 = proc.handles.add(Handle::new(koid1, Rights::DEFAULT));
    unsafe {
        *out0 = hv0;
        *out1 = hv1;
    }
    Ok(0)
}

pub(crate) fn sys_channel_write(
    handle: HandleValue,
    bytes: *const u8,
    num_bytes: u32,
    handles: *const HandleValue,
    num_handles: u32,
) -> SyscallResult {
    if bytes.is_null() && num_bytes > 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;
    let data: Vec<u8> = if num_bytes > 0 {
        unsafe { core::slice::from_raw_parts(bytes, num_bytes as usize).to_vec() }
    } else {
        Vec::new()
    };
    let mut transferred = Vec::new();
    for i in 0..num_handles {
        let hv = unsafe { *handles.add(i as usize) };
        let inner_h = proc.handles.get(hv).ok_or(ErrorCode::BadHandle)?;
        transferred.push(inner_h);
    }
    ch.send(huesos_object::ChannelMessage {
        data,
        handles: transferred,
    });
    Ok(0)
}

pub(crate) fn sys_channel_read(
    handle: HandleValue,
    buf: *mut u8,
    len: u32,
    out_actual: *mut u32,
) -> SyscallResult {
    if buf.is_null() || out_actual.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;
    let msg = ch.recv().ok_or(ErrorCode::ShouldWait)?;
    let to_copy = msg.data.len().min(len as usize);
    unsafe {
        core::ptr::copy_nonoverlapping(msg.data.as_ptr(), buf, to_copy);
        *out_actual = to_copy as u32;
    }
    Ok(0)
}
