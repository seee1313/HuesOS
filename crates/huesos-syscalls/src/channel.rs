//! Channel IPC syscalls.

use alloc::vec::Vec;
use huesos_abi::{ChannelConsumeArgs, ChannelPeekArgs, ChannelReadEtcArgs, ErrorCode, HandleValue};
use huesos_object::{ChannelRecvError, Handle, KernelObject, KernelObjectExt, Rights};

use crate::{user_memory, util::{current_proc, DeferGuard}, SyscallResult};

fn map_recv_error(error: ChannelRecvError) -> huesos_abi::ErrorCode {
    match error {
        ChannelRecvError::BytesTooSmall | ChannelRecvError::HandlesTooSmall => {
            ErrorCode::InvalidArgs
        }
        ChannelRecvError::PeerClosed => ErrorCode::PeerClosed,
    }
}

pub(crate) fn sys_channel_create(out0: *mut HandleValue, out1: *mut HandleValue) -> SyscallResult {
    if out0 == out1 {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_write(out0)?;
    user_memory::validate_write(out1)?;

    let (ch0, ch1) = huesos_object::Channel::pair().map_err(|_| ErrorCode::NoMemory)?;
    let koid0 = ch0.koid();
    let koid1 = ch1.koid();
    huesos_object::register_object(ch0);
    huesos_object::register_object(ch1);
    let proc = current_proc()?;
    let hv0 = proc.handles.add(Handle::new(koid0, Rights::DEFAULT));
    let hv1 = proc.handles.add(Handle::new(koid1, Rights::DEFAULT));

    // Rollback: if either write fails, remove both handles and unregister
    // both channel objects so the pair is fully cleaned up.
    let rollback = DeferGuard::new(|| {
        let _ = proc.handles.remove(hv0);
        let _ = proc.handles.remove(hv1);
        huesos_object::unregister_object(koid0);
        huesos_object::unregister_object(koid1);
    });

    user_memory::write_value(out0, &hv0)?;
    user_memory::write_value(out1, &hv1)?;
    rollback.commit();
    Ok(0)
}

pub(crate) fn sys_channel_write(
    handle: HandleValue,
    bytes: *const u8,
    num_bytes: u32,
    handles: *const HandleValue,
    num_handles: u32,
) -> SyscallResult {
    let byte_count = num_bytes as usize;
    let handle_count = num_handles as usize;
    if byte_count > user_memory::MAX_CHANNEL_BYTES
        || handle_count > user_memory::MAX_CHANNEL_HANDLES
    {
        return Err(ErrorCode::InvalidArgs);
    }

    // Snapshot all caller-controlled memory before inspecting capabilities or
    // mutating the sender's handle table.
    let data = user_memory::copy_from_user(bytes, byte_count)?;
    let raw_handles = user_memory::read_array(handles, handle_count)?;

    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;

    for (i, &hv) in raw_handles.iter().enumerate() {
        if raw_handles[..i].contains(&hv) {
            return Err(ErrorCode::InvalidArgs);
        }
        let inner_h = proc.handles.get(hv).ok_or(ErrorCode::BadHandle)?;
        if !inner_h.has_rights(Rights::TRANSFER) {
            return Err(ErrorCode::AccessDenied);
        }
    }
    let transferred = proc
        .handles
        .remove_many_keep_alive(&raw_handles)
        .map_err(|error| match error {
            huesos_object::HandleTableError::Missing => ErrorCode::BadHandle,
            huesos_object::HandleTableError::Duplicate => ErrorCode::InvalidArgs,
            huesos_object::HandleTableError::OutOfMemory => ErrorCode::NoMemory,
        })?;
    let message = huesos_object::ChannelMessage { seq: 0,
        data,
        handles: transferred,
    };
    match ch.send(message) {
        Ok(()) => Ok(0),
        Err(error) => {
            // Queue admission is quota-governed. Restore every moved handle
            // when admission fails so the operation remains all-or-nothing.
            let (mut message, reason) = error.into_parts();
            for (hv, inner_h) in raw_handles.iter().copied().zip(message.handles.drain(..)) {
                match proc.handles.restore_existing_at(hv, inner_h) {
                    Ok(()) => {}
                    Err(lost) => huesos_object::note_handle_close(lost.koid),
                }
            }
            let status = match reason {
                huesos_object::ChannelSendFailure::PeerClosed => ErrorCode::PeerClosed,
                huesos_object::ChannelSendFailure::QuotaExceeded
                | huesos_object::ChannelSendFailure::OutOfMemory => ErrorCode::NoMemory,
            };
            Err(status)
        }
    }
}

pub(crate) fn sys_channel_read(
    handle: HandleValue,
    buf: *mut u8,
    len: u32,
    out_actual: *mut u32,
    wait_mode: u64,
) -> SyscallResult {
    let capacity = len as usize;
    if capacity > user_memory::MAX_CHANNEL_BYTES {
        return Err(ErrorCode::InvalidArgs);
    }
    // Validate before blocking/dequeueing. Zero-capacity reads may use a null
    // byte pointer, but the actual-count output is always required.
    user_memory::validate_range(buf as u64, capacity, true)?;
    user_memory::validate_write(out_actual)?;

    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;
    let msg = match wait_mode {
        0 => ch
            .recv_status()
            .map_err(map_recv_error)?
            .ok_or(ErrorCode::ShouldWait)?,
        1 => ch.recv_blocking().map_err(map_recv_error)?,
        ticks => ch
            .recv_blocking_timeout(ticks)
            .map_err(map_recv_error)?
            .ok_or(ErrorCode::TimedOut)?,
    };

    // The message is dequeued; if copy_to_user or write_value fail, the
    // message data is lost but ChannelMessage::Drop releases any in-flight
    // handles via note_handle_close. No handle leak, but data loss is
    // unavoidable without a peek/consume split (future hardening).
    let to_copy = msg.data.len().min(capacity);
    user_memory::copy_to_user(buf, &msg.data[..to_copy])?;
    user_memory::write_value(out_actual, &(to_copy as u32))?;
    Ok(0)
}

pub(crate) fn sys_channel_read_etc(
    args_ptr: *const ChannelReadEtcArgs,
    wait_mode: u64,
) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    let byte_capacity = args.bytes_capacity as usize;
    let handle_capacity = args.handles_capacity as usize;
    if byte_capacity > user_memory::MAX_CHANNEL_BYTES
        || handle_capacity > user_memory::MAX_CHANNEL_HANDLES
    {
        return Err(ErrorCode::InvalidArgs);
    }

    // Validate every destination before waiting or consuming the message.
    user_memory::validate_range(args.bytes as u64, byte_capacity, true)?;
    user_memory::validate_write_array(args.handles, handle_capacity)?;
    user_memory::validate_write(args.out_bytes)?;
    user_memory::validate_write(args.out_handles)?;

    let proc = current_proc()?;
    let h = proc.handles.get(args.channel).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;
    // Reserve the bounded destination handle staging area before dequeueing.
    // An OOM result must not consume a message or its in-flight capabilities.
    let mut received_values = Vec::new();
    received_values
        .try_reserve_exact(handle_capacity)
        .map_err(|_| ErrorCode::NoMemory)?;

    let mut msg = if wait_mode == 0 {
        match ch.recv_if_fits(byte_capacity, handle_capacity) {
            Ok(Some(msg)) => msg,
            Ok(None) => return Err(ErrorCode::ShouldWait),
            Err(error) => return Err(map_recv_error(error)),
        }
    } else {
        match ch.recv_if_fits_blocking(byte_capacity, handle_capacity) {
            Ok(msg) => msg,
            Err(error) => return Err(map_recv_error(error)),
        }
    };

    user_memory::copy_to_user(args.bytes, &msg.data)?;
    user_memory::write_value(args.out_bytes, &(msg.data.len() as u32))?;

    let transferred = core::mem::take(&mut msg.handles);
    for handle in transferred {
        received_values.push(proc.handles.add_existing(handle));
    }

    // Rollback: if the handle-array or count write fails after handles have
    // been inserted into the caller's table, remove them. The transferred
    // Handle objects are dropped (note_handle_close fires for each).
    let rollback = DeferGuard::new(|| {
        for &hv in &received_values {
            let _ = proc.handles.remove(hv);
        }
    });

    user_memory::write_array(args.handles, &received_values)?;
    user_memory::write_value(args.out_handles, &(received_values.len() as u32))?;
    rollback.commit();
    Ok(0)
}

/// Peek at the next channel message without dequeueing it. Returns the
/// message's byte size, handle count, and an opaque cookie for a
/// subsequent [`sys_channel_consume`] call. Supports blocking and timeout
/// wait modes via the existing channel wait-queue infrastructure.
pub(crate) fn sys_channel_peek(args_ptr: *const ChannelPeekArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    user_memory::validate_write(args.out_byte_size)?;
    user_memory::validate_write(args.out_handle_count)?;
    user_memory::validate_write(args.out_cookie)?;

    let proc = current_proc()?;
    let h = proc.handles.get(args.channel).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;

    // Blocking/timeout: use the same prepare/park pattern as recv_blocking.
    if args.wait_mode != 0 {
        loop {
            match ch.peek().map_err(map_recv_error)? {
                Some(_) => break,
                None => {
                    if args.wait_mode == 1 {
                        let prepared = ch
                            .reader_queue()
                            .prepare()
                            .ok_or(ErrorCode::PeerClosed)?;
                        if ch.peek().map_err(map_recv_error)?.is_some() {
                            prepared.cancel();
                            break;
                        }
                        prepared.park();
                    } else {
                        let prepared = ch
                            .reader_queue()
                            .prepare()
                            .ok_or(ErrorCode::PeerClosed)?;
                        if ch.peek().map_err(map_recv_error)?.is_some() {
                            prepared.cancel();
                            break;
                        }
                        match prepared.park_timeout(args.wait_mode) {
                            huesos_object::wait::ParkResult::Woken => continue,
                            huesos_object::wait::ParkResult::TimedOut => {
                                return Err(ErrorCode::TimedOut);
                            }
                        }
                    }
                }
            }
        }
    }

    let (byte_size, handle_count, cookie) = ch.peek().map_err(map_recv_error)?.ok_or(ErrorCode::ShouldWait)?;
    user_memory::write_value(args.out_byte_size, &(byte_size as u32))?;
    user_memory::write_value(args.out_handle_count, &(handle_count as u32))?;
    user_memory::write_value(args.out_cookie, &cookie)?;
    Ok(0)
}

/// Dequeue and copy out the message identified by a cookie from a prior
/// [`sys_channel_peek`]. If the cookie is stale (the queue moved on),
/// returns [`ErrorCode::InvalidArgs`].
pub(crate) fn sys_channel_consume(args_ptr: *const ChannelConsumeArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    let byte_capacity = args.bytes_capacity as usize;
    let handle_capacity = args.handles_capacity as usize;
    if byte_capacity > user_memory::MAX_CHANNEL_BYTES
        || handle_capacity > user_memory::MAX_CHANNEL_HANDLES
    {
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::validate_range(args.bytes as u64, byte_capacity, true)?;
    user_memory::validate_write_array(args.handles, handle_capacity)?;
    user_memory::validate_write(args.out_bytes)?;
    user_memory::validate_write(args.out_handles)?;

    let proc = current_proc()?;
    let h = proc.handles.get(args.channel).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;

    let mut msg = ch.consume(args.cookie).ok_or(ErrorCode::InvalidArgs)?;

    // Message dequeued; copy out data + handles.
    if msg.data.len() > byte_capacity {
        // Caller peeked a larger message but provided a smaller buffer.
        // Drop the message (handles released via ChannelMessage::Drop).
        return Err(ErrorCode::InvalidArgs);
    }
    user_memory::copy_to_user(args.bytes, &msg.data)?;
    user_memory::write_value(args.out_bytes, &(msg.data.len() as u32))?;

    let transferred = core::mem::take(&mut msg.handles);
    if transferred.len() > handle_capacity {
        // Should not happen (peek reported handle_count), but guard anyway.
        for handle in transferred {
            huesos_object::note_handle_close(handle.koid);
        }
        return Err(ErrorCode::InvalidArgs);
    }

    let mut received_values = alloc::vec::Vec::new();
    received_values
        .try_reserve_exact(transferred.len())
        .map_err(|_| ErrorCode::NoMemory)?;

    for handle in transferred {
        received_values.push(proc.handles.add_existing(handle));
    }

    // If write_array fails, roll back the handle-table insertions manually
    // (no DeferGuard — avoids a borrow conflict with the Vec).
    if let Err(e) = user_memory::write_array(args.handles, &received_values) {
        for &hv in &received_values {
            let _ = proc.handles.remove(hv);
        }
        return Err(e);
    }
    user_memory::write_value(args.out_handles, &(received_values.len() as u32))?;
    Ok(0)
}
