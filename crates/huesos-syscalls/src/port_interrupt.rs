//! Port and interrupt bridge syscalls.

use huesos_abi::{ErrorCode, HandleValue, PortPacket};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{user_memory, util::{current_proc, map_handle_install_error}, SyscallResult};

pub(crate) fn sys_port_create(out: *mut HandleValue) -> SyscallResult {
    user_memory::validate_write(out)?;
    let port = huesos_object::Port::new().map_err(|_| ErrorCode::NoMemory)?;
    let koid = port.koid();
    huesos_object::register_object(port);
    let proc = current_proc()?;
    let handle = match proc.handles.try_add(Handle::new(koid, Rights::DEFAULT)) {
        Ok(handle) => handle,
        Err(error) => {
            huesos_object::unregister_object(koid);
            return Err(map_handle_install_error(error));
        }
    };
    user_memory::write_value(out, &handle)?;
    Ok(0)
}

pub(crate) fn sys_port_read(
    port_handle: HandleValue,
    out: *mut PortPacket,
    wait_mode: u64,
) -> SyscallResult {
    // Validate before a blocking wait and before consuming a queued packet.
    user_memory::validate_write(out)?;
    let proc = current_proc()?;
    let h = proc.handles.get(port_handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let port = obj
        .downcast_ref::<huesos_object::Port>()
        .ok_or(ErrorCode::WrongType)?;
    let packet = match wait_mode {
        0 => port.read().ok_or(ErrorCode::ShouldWait)?,
        1 => port.read_blocking(),
        ticks => port
            .read_blocking_timeout(ticks)
            .ok_or(ErrorCode::TimedOut)?,
    };
    let packet = PortPacket {
        key: packet.key,
        packet_type: packet.packet_type,
        status: packet.status,
        data: packet.data,
    };
    user_memory::write_value(out, &packet)?;
    Ok(0)
}

const KEYBOARD_IRQ: u32 = 1;

pub(crate) fn sys_interrupt_create(irq: u32, out: *mut HandleValue) -> SyscallResult {
    user_memory::validate_write(out)?;
    if irq != KEYBOARD_IRQ {
        return Err(ErrorCode::NotSupported);
    }

    let interrupt = huesos_object::Interrupt::new(irq as u8);
    let koid = interrupt.koid();
    huesos_object::register_interrupt(interrupt);

    let proc = current_proc()?;
    let handle = match proc.handles.try_add(Handle::new(koid, Rights::DEFAULT)) {
        Ok(handle) => handle,
        Err(error) => {
            huesos_object::unregister_object(koid);
            return Err(map_handle_install_error(error));
        }
    };
    user_memory::write_value(out, &handle)?;
    Ok(0)
}

pub(crate) fn sys_interrupt_bind_port(
    interrupt_handle: HandleValue,
    port_handle: HandleValue,
    key: u64,
) -> SyscallResult {
    let proc = current_proc()?;
    let interrupt_h = proc
        .handles
        .get(interrupt_handle)
        .ok_or(ErrorCode::BadHandle)?;
    if !interrupt_h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let port_h = proc.handles.get(port_handle).ok_or(ErrorCode::BadHandle)?;
    if !port_h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }

    let interrupt_obj =
        huesos_object::lookup_object(interrupt_h.koid).ok_or(ErrorCode::BadHandle)?;
    let interrupt = interrupt_obj
        .downcast_ref::<huesos_object::Interrupt>()
        .ok_or(ErrorCode::WrongType)?;

    let port_obj = huesos_object::lookup_object(port_h.koid).ok_or(ErrorCode::BadHandle)?;
    let port = port_obj
        .downcast_ref::<huesos_object::Port>()
        .ok_or(ErrorCode::WrongType)?;

    interrupt.bind_port(port.koid(), key);
    Ok(0)
}
