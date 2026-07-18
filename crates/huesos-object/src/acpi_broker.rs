//! Deny-by-default capability policy for the Ring-3 ACPI broker.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use huesos_abi::acpi_broker::{Opcode, ValidRequest};

use crate::{KernelObject, Koid, ObjectType, alloc_koid};

/// Exact SystemIO range granted to one ACPI manager instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemIoGrant {
    /// First I/O port.
    pub base: u16,
    /// Number of ports in the half-open range.
    pub length: u16,
    /// Read operations are permitted.
    pub read: bool,
    /// Write operations are permitted.
    pub write: bool,
}

/// One PCI function granted to the ACPI manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciFunctionGrant {
    /// PCI segment group.
    pub segment: u16,
    /// Bus number.
    pub bus: u8,
    /// Device number, 0..31.
    pub device: u8,
    /// Function number, 0..7.
    pub function: u8,
    /// Configuration reads are permitted.
    pub read: bool,
    /// Configuration writes are permitted.
    pub write: bool,
}

/// Immutable authority consulted before privileged ACPI broker operations.
pub struct AcpiBroker {
    koid: Koid,
    system_io: Vec<SystemIoGrant>,
    pci: Vec<PciFunctionGrant>,
    allow_reset: bool,
    allow_power_off: bool,
}

impl AcpiBroker {
    /// Construct a broker with no privileged grants.
    pub fn deny_all() -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            system_io: Vec::new(),
            pci: Vec::new(),
            allow_reset: false,
            allow_power_off: false,
        })
    }

    /// Test both operation type and immutable resource allowlist.
    pub fn authorizes(&self, request: &ValidRequest) -> bool {
        match request.opcode {
            Opcode::SystemIoRead | Opcode::SystemIoWrite => self.authorizes_system_io(request),
            Opcode::PciRead | Opcode::PciWrite => self.authorizes_pci(request),
            Opcode::Reset => self.allow_reset,
            Opcode::PowerOff => self.allow_power_off,
            Opcode::InstallInterrupt | Opcode::RemoveInterrupt => false,
        }
    }

    fn authorizes_system_io(&self, request: &ValidRequest) -> bool {
        let Ok(port) = u16::try_from(request.address) else {
            return false;
        };
        let Some(end) = port.checked_add(request.width as u16) else {
            return false;
        };
        self.system_io.iter().any(|grant| {
            let Some(grant_end) = grant.base.checked_add(grant.length) else {
                return false;
            };
            let operation_allowed = match request.opcode {
                Opcode::SystemIoRead => grant.read,
                Opcode::SystemIoWrite => grant.write,
                _ => false,
            };
            operation_allowed && port >= grant.base && end <= grant_end
        })
    }

    fn authorizes_pci(&self, request: &ValidRequest) -> bool {
        let segment = (request.address >> 32) as u16;
        let bus = (request.address >> 24) as u8;
        let device = ((request.address >> 19) & 0x1f) as u8;
        let function = ((request.address >> 16) & 0x07) as u8;
        let offset = (request.address & 0x0fff) as u16;
        if request.address & 0xffff_0000_0000_f000 != 0
            || offset.checked_add(request.width as u16).is_none_or(|end| end > 4096)
        {
            return false;
        }
        self.pci.iter().any(|grant| {
            let operation_allowed = match request.opcode {
                Opcode::PciRead => grant.read,
                Opcode::PciWrite => grant.write,
                _ => false,
            };
            operation_allowed
                && grant.segment == segment
                && grant.bus == bus
                && grant.device == device
                && grant.function == function
        })
    }
}

impl KernelObject for AcpiBroker {
    fn object_type(&self) -> ObjectType {
        ObjectType::AcpiBroker
    }

    fn koid(&self) -> Koid {
        self.koid
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_abi::acpi_broker::{Request, VERSION};

    #[test]
    fn empty_broker_denies_structurally_valid_request() {
        let request = Request {
            version: VERSION,
            opcode: Opcode::SystemIoRead as u16,
            width: 1,
            address: 0x80,
            ..Request::default()
        };
        let validated = request.validate();
        assert!(validated.as_ref().is_ok_and(|request| !AcpiBroker::deny_all().authorizes(request)));
    }
}
