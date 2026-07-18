//! Safe userspace wrapper for the restricted ACPI broker capability.

use crate::{Handle, Result, raw};
use huesos_abi::Syscall;
use huesos_abi::acpi_broker::{Request, Response};

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
}
