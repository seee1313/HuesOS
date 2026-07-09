//! Channel IPC syscalls.

use alloc::vec::Vec;
use huesos_abi::{ChannelReadEtcArgs, ErrorCode, HandleValue};
use huesos_object::{ChannelRecvError, Handle, KernelObject, KernelObjectExt, Rights};

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
    if handles.is_null() && num_handles > 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let mut raw_handles = Vec::new();
    let mut transferred = Vec::new();
    for i in 0..num_handles {
        let hv = unsafe { *handles.add(i as usize) };
        if raw_handles.iter().any(|seen| *seen == hv) {
            return Err(ErrorCode::InvalidArgs);
        }
        let inner_h = proc.handles.get(hv).ok_or(ErrorCode::BadHandle)?;
        if !inner_h.has_rights(Rights::TRANSFER) {
            return Err(ErrorCode::AccessDenied);
        }
        raw_handles.push(hv);
        transferred.push(inner_h);
    }
    for hv in raw_handles {
        // Keep handle-count alive while the capability is in-flight in the message.
        let _ = proc.handles.remove_keep_alive(hv);
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
    wait_mode: u64,
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
    // 0 = nonblock, 1 = forever, >=2 = timeout in scheduler ticks
    let msg = match wait_mode {
        0 => ch.recv().ok_or(ErrorCode::ShouldWait)?,
        1 => ch.recv_blocking(),
        ticks => ch
            .recv_blocking_timeout(ticks)
            .ok_or(ErrorCode::TimedOut)?,
    };
    let to_copy = msg.data.len().min(len as usize);
    unsafe {
        core::ptr::copy_nonoverlapping(msg.data.as_ptr(), buf, to_copy);
        *out_actual = to_copy as u32;
    }
    Ok(0)
}


pub(crate) fn sys_channel_read_etc(args_ptr: *const ChannelReadEtcArgs, wait_mode: u64) -> SyscallResult {
    if args_ptr.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let args = unsafe { core::ptr::read_unaligned(args_ptr) };
    if args.out_bytes.is_null() || args.out_handles.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    if args.bytes_capacity > 0 && args.bytes.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    if args.handles_capacity > 0 && args.handles.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }

    let proc = current_proc()?;
    let h = proc.handles.get(args.channel).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;
    let mut msg = if wait_mode == 0 {
        match ch.recv_if_fits(args.bytes_capacity as usize, args.handles_capacity as usize) {
            Ok(Some(msg)) => msg,
            Ok(None) => return Err(ErrorCode::ShouldWait),
            Err(ChannelRecvError::BytesTooSmall | ChannelRecvError::HandlesTooSmall) => {
                return Err(ErrorCode::InvalidArgs)
            }
        }
    } else {
        // Blocking (timeout ignored for read_etc MVP — use ChannelRead for timed waits).
        match ch.recv_if_fits_blocking(args.bytes_capacity as usize, args.handles_capacity as usize)
        {
            Ok(msg) => msg,
            Err(ChannelRecvError::BytesTooSmall | ChannelRecvError::HandlesTooSmall) => {
                return Err(ErrorCode::InvalidArgs)
            }
        }
    };

    unsafe {
        if !msg.data.is_empty() {
            core::ptr::copy_nonoverlapping(msg.data.as_ptr(), args.bytes, msg.data.len());
        }
        *args.out_bytes = msg.data.len() as u32;
    }

    let n_handles = msg.handles.len();
    // Take handles so ChannelMessage::Drop does not release their counts.
    let transferred = core::mem::take(&mut msg.handles);
    for (i, handle) in transferred.into_iter().enumerate() {
        let hv = proc.handles.add_existing(handle);
        unsafe {
            *args.handles.add(i) = hv;
        }
    }
    unsafe {
        *args.out_handles = n_handles as u32;
    }
    Ok(0)
}
