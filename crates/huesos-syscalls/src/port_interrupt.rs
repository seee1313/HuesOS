//! Port and interrupt bridge syscalls.

use huesos_abi::{ErrorCode, HandleValue, PortPacket};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Resource, ResourceKind, Rights};

use crate::{user_memory, util::current_proc, SyscallResult};

pub(crate) fn sys_port_create(out: *mut HandleValue) -> SyscallResult {
    user_memory::validate_write(out)?;
    let port = huesos_object::Port::new().map_err(|_| ErrorCode::NoMemory)?;
    let koid = port.koid();
    huesos_object::register_object(port);
    let proc = current_proc()?;
    proc.handles
        .add_with_commit(Handle::new(koid, Rights::DEFAULT), |handle| {
            user_memory::write_value(out, &handle)
        })
        .map(|_| 0)
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

pub(crate) fn sys_port_queue(port_handle: HandleValue, packet: *const PortPacket) -> SyscallResult {
    let packet = user_memory::read_value(packet)?;
    let proc = current_proc()?;
    let h = proc.handles.get(port_handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let port = obj
        .downcast_ref::<huesos_object::Port>()
        .ok_or(ErrorCode::WrongType)?;
    port.queue(huesos_object::PortPacket {
        key: packet.key,
        packet_type: packet.packet_type,
        status: packet.status,
        data: packet.data,
    })
    .map_err(|_| ErrorCode::NoMemory)?;
    Ok(0)
}

const KEYBOARD_IRQ: u32 = 1;

pub(crate) fn sys_interrupt_create(irq: u32, out: *mut HandleValue) -> SyscallResult {
    user_memory::validate_write(out)?;
    if irq != KEYBOARD_IRQ {
        return Err(ErrorCode::NotSupported);
    }
    install_interrupt_object(huesos_object::Interrupt::new(irq), out)
}

pub(crate) fn sys_interrupt_create_for_resource(
    resource_handle: HandleValue,
    irq: u32,
    out: *mut HandleValue,
) -> SyscallResult {
    if irq >= 16 && !(0xD0..=0xDF).contains(&irq) {
        return Err(ErrorCode::NotSupported);
    }
    validate_irq_resource(resource_handle, irq)?;
    user_memory::validate_write(out)?;
    install_interrupt_object(huesos_object::Interrupt::new(irq), out)
}

pub(crate) fn sys_interrupt_create_gsi_for_resource(
    resource_handle: HandleValue,
    gsi: u32,
    out: *mut HandleValue,
) -> SyscallResult {
    validate_irq_resource(resource_handle, gsi)?;
    user_memory::validate_write(out)?;
    install_interrupt_object(huesos_object::Interrupt::new_gsi(gsi), out)
}

fn validate_irq_resource(resource_handle: HandleValue, irq_or_gsi: u32) -> Result<(), ErrorCode> {
    let proc = current_proc()?;
    let handle = proc
        .handles
        .get(resource_handle)
        .ok_or(ErrorCode::BadHandle)?;
    if !handle.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let object = huesos_object::lookup_object(handle.koid).ok_or(ErrorCode::BadHandle)?;
    let resource = object
        .downcast_ref::<Resource>()
        .ok_or(ErrorCode::WrongType)?;
    if !resource.contains(ResourceKind::Irq, u64::from(irq_or_gsi), 1) {
        return Err(ErrorCode::AccessDenied);
    }
    Ok(())
}

fn install_interrupt_object(
    interrupt: alloc::sync::Arc<huesos_object::Interrupt>,
    out: *mut HandleValue,
) -> SyscallResult {
    let proc = current_proc()?;
    let koid = interrupt.koid();
    huesos_object::register_interrupt(interrupt);
    proc.handles
        .add_with_commit(Handle::new(koid, Rights::DEFAULT), |handle| {
            user_memory::write_value(out, &handle)
        })
        .map(|_| 0)
}

pub(crate) fn sys_interrupt_acknowledge(interrupt_handle: HandleValue) -> SyscallResult {
    let proc = current_proc()?;
    let interrupt_h = proc
        .handles
        .get(interrupt_handle)
        .ok_or(ErrorCode::BadHandle)?;
    if !interrupt_h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let interrupt_obj =
        huesos_object::lookup_object(interrupt_h.koid).ok_or(ErrorCode::BadHandle)?;
    let interrupt = interrupt_obj
        .downcast_ref::<huesos_object::Interrupt>()
        .ok_or(ErrorCode::WrongType)?;
    interrupt
        .acknowledge()
        .map_err(|_| ErrorCode::NotSupported)?;
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
        .downcast_arc::<huesos_object::Port>()
        .map_err(|_| ErrorCode::WrongType)?;

    interrupt
        .bind_port(port, key)
        .map_err(|_| ErrorCode::NotSupported)?;
    Ok(0)
}
