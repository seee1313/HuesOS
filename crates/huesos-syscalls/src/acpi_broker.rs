//! Capability-checked privileged operations for the Ring-3 ACPI manager.

use crate::user_memory;
use huesos_abi::acpi_broker::{Opcode, Request, Response, Status};
use huesos_abi::{ErrorCode, HandleValue};
use huesos_object::{KernelObjectExt, Rights};
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
        Opcode::SystemIoRead | Opcode::PciRead => Rights::READ,
        Opcode::SystemIoWrite
        | Opcode::PciWrite
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
    if !broker.authorizes(&validated) {
        let response = response(&request, Status::AccessDenied, 0);
        user_memory::write_value(response_ptr, &response)?;
        return Ok(0);
    }

    let (status, value) = execute(&validated);
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
    let port = request.address as u16;
    match (request.opcode, request.width) {
        (Opcode::SystemIoRead, 1) => {
            // SAFETY: the immutable broker capability authorized this exact
            // port and width before the privileged instruction.
            (Status::Ok, unsafe { Port::<u8>::new(port).read() } as u64)
        }
        (Opcode::SystemIoRead, 2) => {
            // SAFETY: same exact-width capability contract as above.
            (Status::Ok, unsafe { Port::<u16>::new(port).read() } as u64)
        }
        (Opcode::SystemIoRead, 4) => {
            // SAFETY: same exact-width capability contract as above.
            (Status::Ok, unsafe { Port::<u32>::new(port).read() } as u64)
        }
        (Opcode::SystemIoWrite, 1) => {
            // SAFETY: the capability authorizes this exact-width write.
            unsafe { Port::<u8>::new(port).write(request.value as u8) };
            (Status::Ok, 0)
        }
        (Opcode::SystemIoWrite, 2) => {
            // SAFETY: the capability authorizes this exact-width write.
            unsafe { Port::<u16>::new(port).write(request.value as u16) };
            (Status::Ok, 0)
        }
        (Opcode::SystemIoWrite, 4) => {
            // SAFETY: the capability authorizes this exact-width write.
            unsafe { Port::<u32>::new(port).write(request.value as u32) };
            (Status::Ok, 0)
        }
        // PCI, interrupt, and power operations remain deny-by-default until
        // their resource-specific backends are implemented and fuzzed.
        _ => (Status::NotFound, 0),
    }
}
