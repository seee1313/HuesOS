//! Channel IPC syscalls.

use huesos_abi::{ChannelConsumeArgs, ChannelPeekArgs, ChannelReadEtcArgs, ErrorCode, HandleValue};
use huesos_object::{ChannelRecvError, Handle, KernelObject, KernelObjectExt, Rights};

use crate::{user_memory, util::current_proc, SyscallResult};

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
    proc.handles
        .add_pair_with_commit(
            Handle::new(koid0, Rights::DEFAULT),
            Handle::new(koid1, Rights::DEFAULT),
            |hv0, hv1| {
                user_memory::write_value(out0, &hv0)?;
                user_memory::write_value(out1, &hv1)
            },
        )
        .map(|_| 0)
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

    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;

    if byte_count <= huesos_object::CHANNEL_INLINE_BYTES
        && handle_count <= huesos_object::CHANNEL_INLINE_HANDLES
    {
        let mut inline_bytes = [0u8; huesos_object::CHANNEL_INLINE_BYTES];
        user_memory::copy_from_user_into(bytes, &mut inline_bytes[..byte_count])?;
        let mut raw_handles = [0 as HandleValue; huesos_object::CHANNEL_INLINE_HANDLES];
        for (index, slot) in raw_handles[..handle_count].iter_mut().enumerate() {
            *slot = user_memory::read_value(handles.wrapping_add(index))?;
        }
        for (i, &hv) in raw_handles[..handle_count].iter().enumerate() {
            if raw_handles[..i].contains(&hv) {
                return Err(ErrorCode::InvalidArgs);
            }
            let inner_h = proc.handles.get(hv).ok_or(ErrorCode::BadHandle)?;
            if !inner_h.has_rights(Rights::TRANSFER) {
                return Err(ErrorCode::AccessDenied);
            }
        }
        let mut transferred =
            [huesos_object::Handle::new(huesos_object::Koid::INVALID, Rights::DEFAULT);
                huesos_object::CHANNEL_INLINE_HANDLES];
        proc.handles
            .remove_many_keep_alive_into(&raw_handles[..handle_count], &mut transferred)
            .map_err(|error| match error {
                huesos_object::HandleTableError::Missing => ErrorCode::BadHandle,
                huesos_object::HandleTableError::Duplicate => ErrorCode::InvalidArgs,
                huesos_object::HandleTableError::OutOfMemory => ErrorCode::NoMemory,
            })?;
        let message = huesos_object::ChannelMessage::inline(
            &inline_bytes[..byte_count],
            &transferred[..handle_count],
        )
        .ok_or(ErrorCode::Internal)?;
        return send_or_restore(ch, &proc, &raw_handles[..handle_count], message);
    }

    // Slow path: snapshot larger caller-controlled memory into bounded Vecs.
    let data = user_memory::copy_from_user(bytes, byte_count)?;
    let raw_handles = user_memory::read_array(handles, handle_count)?;
    for (i, &hv) in raw_handles.iter().enumerate() {
        if raw_handles[..i].contains(&hv) {
            return Err(ErrorCode::InvalidArgs);
        }
        let inner_h = proc.handles.get(hv).ok_or(ErrorCode::BadHandle)?;
        if !inner_h.has_rights(Rights::TRANSFER) {
            return Err(ErrorCode::AccessDenied);
        }
    }
    let transferred =
        proc.handles
            .remove_many_keep_alive(&raw_handles)
            .map_err(|error| match error {
                huesos_object::HandleTableError::Missing => ErrorCode::BadHandle,
                huesos_object::HandleTableError::Duplicate => ErrorCode::InvalidArgs,
                huesos_object::HandleTableError::OutOfMemory => ErrorCode::NoMemory,
            })?;
    let message = huesos_object::ChannelMessage::new(data, transferred);
    send_or_restore(ch, &proc, &raw_handles, message)
}

fn send_or_restore(
    ch: &huesos_object::Channel,
    proc: &huesos_object::Process,
    raw_handles: &[HandleValue],
    message: huesos_object::ChannelMessage,
) -> SyscallResult {
    match ch.send(message) {
        Ok(()) => Ok(0),
        Err(error) => {
            let (mut message, reason) = error.into_parts();
            let mut restored =
                [huesos_object::Handle::new(huesos_object::Koid::INVALID, Rights::DEFAULT);
                    user_memory::MAX_CHANNEL_HANDLES];
            let restored_count = message.take_handles_into(&mut restored);
            for (hv, inner_h) in raw_handles
                .iter()
                .copied()
                .zip(restored[..restored_count].iter().copied())
            {
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
        0 => match ch.recv_if_fits(capacity, 0) {
            Ok(Some(msg)) => msg,
            Ok(None) => return Err(ErrorCode::ShouldWait),
            Err(error) => return Err(map_recv_error(error)),
        },
        1 => ch
            .recv_if_fits_blocking(capacity, 0)
            .map_err(map_recv_error)?,
        ticks => loop {
            match ch.recv_if_fits(capacity, 0) {
                Ok(Some(msg)) => break msg,
                Ok(None) => {
                    let prepared = ch.reader_queue().prepare().ok_or(ErrorCode::PeerClosed)?;
                    match ch.recv_if_fits(capacity, 0) {
                        Ok(Some(msg)) => {
                            prepared.cancel();
                            break msg;
                        }
                        Ok(None) => match prepared.park_timeout(ticks) {
                            huesos_object::wait::ParkResult::Woken => continue,
                            huesos_object::wait::ParkResult::TimedOut => {
                                return Err(ErrorCode::TimedOut);
                            }
                        },
                        Err(error) => {
                            prepared.cancel();
                            return Err(map_recv_error(error));
                        }
                    }
                }
                Err(error) => return Err(map_recv_error(error)),
            }
        },
    };

    user_memory::copy_to_user(buf, msg.data())?;
    user_memory::write_value(out_actual, &(msg.data_len() as u32))?;
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

    user_memory::copy_to_user(args.bytes, msg.data())?;
    user_memory::write_value(args.out_bytes, &(msg.data_len() as u32))?;

    let mut transferred =
        [huesos_object::Handle::new(huesos_object::Koid::INVALID, Rights::DEFAULT);
            user_memory::MAX_CHANNEL_HANDLES];
    let transferred_count = msg.take_handles_into(&mut transferred);
    let mut received_values = [0 as HandleValue; user_memory::MAX_CHANNEL_HANDLES];
    proc.handles.add_existing_many_with_commit(
        &transferred[..transferred_count],
        &mut received_values[..transferred_count],
        |values| {
            user_memory::write_array(args.handles, values)?;
            user_memory::write_value(args.out_handles, &(values.len() as u32))
        },
    )?;
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
                        let prepared = ch.reader_queue().prepare().ok_or(ErrorCode::PeerClosed)?;
                        if ch.peek().map_err(map_recv_error)?.is_some() {
                            prepared.cancel();
                            break;
                        }
                        prepared.park();
                    } else {
                        let prepared = ch.reader_queue().prepare().ok_or(ErrorCode::PeerClosed)?;
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

    let (byte_size, handle_count, cookie) = ch
        .peek()
        .map_err(map_recv_error)?
        .ok_or(ErrorCode::ShouldWait)?;
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

    let mut msg = ch
        .consume_if_fits(args.cookie, byte_capacity, handle_capacity)
        .map_err(map_recv_error)?
        .ok_or(ErrorCode::InvalidArgs)?;

    user_memory::copy_to_user(args.bytes, msg.data())?;
    user_memory::write_value(args.out_bytes, &(msg.data_len() as u32))?;

    let mut transferred =
        [huesos_object::Handle::new(huesos_object::Koid::INVALID, Rights::DEFAULT);
            user_memory::MAX_CHANNEL_HANDLES];
    let transferred_count = msg.take_handles_into(&mut transferred);
    let mut received_values = [0 as HandleValue; user_memory::MAX_CHANNEL_HANDLES];
    proc.handles.add_existing_many_with_commit(
        &transferred[..transferred_count],
        &mut received_values[..transferred_count],
        |values| {
            user_memory::write_array(args.handles, values)?;
            user_memory::write_value(args.out_handles, &(values.len() as u32))
        },
    )?;
    Ok(0)
}
