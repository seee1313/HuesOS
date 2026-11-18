//! Capability-checked privileged operations for the Ring-3 ACPI manager.

use crate::user_memory;
use huesos_abi::acpi_broker::{Opcode, Request, Response, Status};
use huesos_abi::broker_policy::AuditOutcome;
use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::{KernelObjectExt, ResourceKind, Rights};
use x86_64::instructions::port::Port;

use crate::SyscallResult;

pub(crate) fn sys_acpi_broker_call(
    broker_handle: HandleValue,
    request_ptr: *const Request,
    response_ptr: *mut Response,
) -> SyscallResult {
    user_memory::validate_write(response_ptr)?;
    let request = user_memory::read_value(request_ptr)?;
    let validated = match request.validate() {
        Ok(request) => request,
        Err(_) => {
            let response = response(&request, Status::InvalidRequest, 0);
            user_memory::write_value(response_ptr, &response)?;
            return Ok(0);
        }
    };

    let process = huesos_object::current_process().ok_or(ErrorCode::Internal)?;
    let handle = process
        .handles
        .get(broker_handle)
        .ok_or(ErrorCode::BadHandle)?;
    let required = match validated.opcode {
        Opcode::SystemIoRead | Opcode::PciRead | Opcode::MmioRead => Rights::READ,
        Opcode::SystemIoWrite
        | Opcode::PciWrite
        | Opcode::MmioWrite
        | Opcode::InstallInterrupt
        | Opcode::RemoveInterrupt
        | Opcode::Reset
        | Opcode::PowerOff => Rights::WRITE,
    };
    if !handle.has_rights(required) {
        return Err(ErrorCode::AccessDenied);
    }
    let object = huesos_object::lookup_object(handle.koid).ok_or(ErrorCode::BadHandle)?;
    let broker = object
        .downcast_ref::<huesos_object::AcpiBroker>()
        .ok_or(ErrorCode::WrongType)?;
    if !broker.check_rate_limit(0) {
        broker.record_audit(
            validated.opcode as u8,
            AuditOutcome::Denied,
            validated.address,
        );
        let response = response(&request, Status::AccessDenied, 0);
        user_memory::write_value(response_ptr, &response)?;
        return Ok(0);
    }
    let conflict = match validated.opcode {
        Opcode::SystemIoRead | Opcode::SystemIoWrite => huesos_object::has_resource_conflict(
            ResourceKind::IoPort,
            validated.address,
            u64::from(validated.width),
        ),
        Opcode::MmioRead | Opcode::MmioWrite => huesos_object::has_resource_conflict(
            ResourceKind::Mmio,
            validated.address,
            u64::from(validated.width),
        ),
        _ => false,
    };
    if conflict || !broker.authorizes(&validated) {
        broker.record_audit(
            validated.opcode as u8,
            AuditOutcome::Denied,
            validated.address,
        );
        let response = response(&request, Status::AccessDenied, 0);
        user_memory::write_value(response_ptr, &response)?;
        return Ok(0);
    }

    let (status, value) = execute(&validated);
    broker.record_audit(
        validated.opcode as u8,
        if status == Status::Ok {
            AuditOutcome::Allowed
        } else {
            AuditOutcome::Denied
        },
        validated.address,
    );
    let response = response(&request, status, value);
    user_memory::write_value(response_ptr, &response)?;
    Ok(0)
}

fn response(request: &Request, status: Status, value: u64) -> Response {
    Response {
        version: huesos_abi::acpi_broker::VERSION,
        reserved: 0,
        status: status as i32,
        request_id: request.request_id,
        value,
    }
}

fn execute(request: &huesos_abi::acpi_broker::ValidRequest) -> (Status, u64) {
    match request.opcode {
        Opcode::SystemIoRead | Opcode::SystemIoWrite => {
            let port = request.address as u16;
            // SAFETY: the immutable broker capability authorized this exact
            // port, width, and snapshot, and REGISTRY had no conflicting IoPort.
            unsafe {
                match (request.opcode, request.width) {
                    (Opcode::SystemIoRead, 1) => (Status::Ok, Port::<u8>::new(port).read() as u64),
                    (Opcode::SystemIoRead, 2) => (Status::Ok, Port::<u16>::new(port).read() as u64),
                    (Opcode::SystemIoRead, 4) => (Status::Ok, Port::<u32>::new(port).read() as u64),
                    (Opcode::SystemIoWrite, 1) => {
                        Port::<u8>::new(port).write(request.value as u8);
                        (Status::Ok, 0)
                    }
                    (Opcode::SystemIoWrite, 2) => {
                        Port::<u16>::new(port).write(request.value as u16);
                        (Status::Ok, 0)
                    }
                    (Opcode::SystemIoWrite, 4) => {
                        Port::<u32>::new(port).write(request.value as u32);
                        (Status::Ok, 0)
                    }
                    _ => (Status::InvalidRequest, 0),
                }
            }
        }
        Opcode::MmioRead | Opcode::MmioWrite => {
            let virt = huesos_arch::paging::phys_to_virt(request.address).as_u64();
            if virt == 0 {
                return (Status::Internal, 0);
            }
            // SAFETY: the immutable broker capability authorized this exact
            // physical address, natural alignment, width, and snapshot; kernel
            // mapped the approved MMIO/NVS range into HHDM; REGISTRY had no
            // conflicting Mmio or DmaPool resource.
            unsafe {
                match (request.opcode, request.width) {
                    (Opcode::MmioRead, 1) => (
                        Status::Ok,
                        core::ptr::read_volatile(virt as *const u8) as u64,
                    ),
                    (Opcode::MmioRead, 2) => (
                        Status::Ok,
                        core::ptr::read_volatile(virt as *const u16) as u64,
                    ),
                    (Opcode::MmioRead, 4) => (
                        Status::Ok,
                        core::ptr::read_volatile(virt as *const u32) as u64,
                    ),
                    (Opcode::MmioRead, 8) => {
                        (Status::Ok, core::ptr::read_volatile(virt as *const u64))
                    }
                    (Opcode::MmioWrite, 1) => {
                        core::ptr::write_volatile(virt as *mut u8, request.value as u8);
                        (Status::Ok, 0)
                    }
                    (Opcode::MmioWrite, 2) => {
                        core::ptr::write_volatile(virt as *mut u16, request.value as u16);
                        (Status::Ok, 0)
                    }
                    (Opcode::MmioWrite, 4) => {
                        core::ptr::write_volatile(virt as *mut u32, request.value as u32);
                        (Status::Ok, 0)
                    }
                    (Opcode::MmioWrite, 8) => {
                        core::ptr::write_volatile(virt as *mut u64, request.value);
                        (Status::Ok, 0)
                    }
                    _ => (Status::InvalidRequest, 0),
                }
            }
        }
        // PCI, interrupt, and power operations remain deny-by-default until
        // their resource-specific backends are implemented and fuzzed.
        _ => (Status::NotFound, 0),
    }
}
