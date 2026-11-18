//! Safe userspace wrapper for the restricted ACPI broker capability.

use crate::{raw, Handle, Result};
use huesos_abi::acpi_broker::{Opcode, Request, Response, VERSION};
use huesos_abi::Syscall;

/// Unique capability for privileged operations authorized to an ACPI manager.
pub struct AcpiBroker(Handle);

impl AcpiBroker {
    /// Construct from a transferred broker handle.
    pub fn from_handle(handle: Handle) -> Self {
        Self(handle)
    }

    /// Submit one request and return the broker's explicit protocol response.
    pub fn call(&self, request: &Request) -> Result<Response> {
        let mut response = Response::default();
        let result = raw::syscall3(
            Syscall::AcpiBrokerCall,
            self.0.raw() as u64,
            request as *const Request as u64,
            &mut response as *mut Response as u64,
        );
        raw::decode(result)?;
        Ok(response)
    }

    /// Perform a snapshot-bound SystemIO read.
    pub fn system_io_read(
        &self,
        port: u16,
        width: u8,
        snapshot_id: u64,
        request_id: u64,
    ) -> Result<Response> {
        self.call(&Request {
            version: VERSION,
            opcode: Opcode::SystemIoRead as u16,
            width,
            request_id,
            address: u64::from(port),
            value: 0,
            argument: snapshot_id,
            ..Request::default()
        })
    }

    /// Perform a snapshot-bound SystemIO write.
    pub fn system_io_write(
        &self,
        port: u16,
        width: u8,
        value: u64,
        snapshot_id: u64,
        request_id: u64,
    ) -> Result<Response> {
        self.call(&Request {
            version: VERSION,
            opcode: Opcode::SystemIoWrite as u16,
            width,
            request_id,
            address: u64::from(port),
            value,
            argument: snapshot_id,
            ..Request::default()
        })
    }

    /// Perform a snapshot-bound SystemMemory (MMIO/NVS) read.
    pub fn mmio_read(
        &self,
        address: u64,
        width: u8,
        snapshot_id: u64,
        request_id: u64,
    ) -> Result<Response> {
        self.call(&Request {
            version: VERSION,
            opcode: Opcode::MmioRead as u16,
            width,
            request_id,
            address,
            value: 0,
            argument: snapshot_id,
            ..Request::default()
        })
    }

    /// Perform a snapshot-bound SystemMemory (MMIO/NVS) write.
    pub fn mmio_write(
        &self,
        address: u64,
        width: u8,
        value: u64,
        snapshot_id: u64,
        request_id: u64,
    ) -> Result<Response> {
        self.call(&Request {
            version: VERSION,
            opcode: Opcode::MmioWrite as u16,
            width,
            request_id,
            address,
            value,
            argument: snapshot_id,
            ..Request::default()
        })
    }
}
