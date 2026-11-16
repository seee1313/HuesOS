//! Deny-by-default capability policy for the Ring-3 ACPI broker.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use huesos_abi::acpi_broker::{Opcode, ValidRequest};

use crate::{alloc_koid, KernelObject, Koid, ObjectType};

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

/// One firmware MMIO range granted to the ACPI manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioGrant {
    /// First byte of the granted MMIO range (firmware physical address).
    pub base: u64,
    /// Length of the granted range in bytes.
    pub length: u64,
    /// Reads are permitted.
    pub read: bool,
    /// Writes are permitted.
    pub write: bool,
}

/// Immutable authority consulted before privileged ACPI broker operations.
pub struct AcpiBroker {
    koid: Koid,
    system_io: Vec<SystemIoGrant>,
    mmio: Vec<MmioGrant>,
    allow_reset: bool,
    allow_power_off: bool,
}

impl AcpiBroker {
    /// Construct a broker with no privileged grants.
    pub fn deny_all() -> Arc<Self> {
        Self::with_policy(Vec::new(), Vec::new(), false, false)
    }

    /// Construct an immutable broker policy from firmware-derived grants.
    /// Callers must pass only resources parsed from validated uACPI tables.
    ///
    /// PCI configuration access is deliberately absent: the legacy broker
    /// opcodes remain decodable in [`huesos_abi::acpi_broker`] but can
    /// never be authorized (AP-10). The only path to configuration space
    /// is the dedicated mediated channel to the supervised PCI Manager.
    pub fn with_policy(
        system_io: Vec<SystemIoGrant>,
        mmio: Vec<MmioGrant>,
        allow_reset: bool,
        allow_power_off: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            system_io,
            mmio,
            allow_reset,
            allow_power_off,
        })
    }

    /// Test both operation type and immutable resource allowlist.
    pub fn authorizes(&self, request: &ValidRequest) -> bool {
        match request.opcode {
            Opcode::SystemIoRead | Opcode::SystemIoWrite => self.authorizes_system_io(request),
            // AP-10: PCI configuration opcodes are never authorizable,
            // under any grant. AML reaches configuration space only via
            // the mediated ACPI → PCI channel served by PCI Manager.
            Opcode::PciRead | Opcode::PciWrite => false,
            Opcode::MmioRead | Opcode::MmioWrite => self.authorizes_mmio(request),
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

    fn authorizes_mmio(&self, request: &ValidRequest) -> bool {
        let start = request.address;
        let Some(end) = start.checked_add(request.width as u64) else {
            return false;
        };
        self.mmio.iter().any(|grant| {
            let Some(grant_end) = grant.base.checked_add(grant.length) else {
                return false;
            };
            let operation_allowed = match request.opcode {
                Opcode::MmioRead => grant.read,
                Opcode::MmioWrite => grant.write,
                _ => false,
            };
            operation_allowed && start >= grant.base && end <= grant_end
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
        assert!(validated
            .as_ref()
            .is_ok_and(|request| !AcpiBroker::deny_all().authorizes(request)));
    }

    #[test]
    fn system_io_grant_is_exact_and_directional() {
        let broker = AcpiBroker::with_policy(
            alloc::vec![SystemIoGrant {
                base: 0x400,
                length: 4,
                read: true,
                write: false,
            }],
            Vec::new(),
            false,
            false,
        );
        let read = Request {
            version: VERSION,
            opcode: Opcode::SystemIoRead as u16,
            width: 2,
            address: 0x402,
            ..Request::default()
        }
        .validate();
        let write = Request {
            version: VERSION,
            opcode: Opcode::SystemIoWrite as u16,
            width: 2,
            address: 0x402,
            ..Request::default()
        }
        .validate();
        assert!(read
            .as_ref()
            .is_ok_and(|request| broker.authorizes(request)));
        assert!(write
            .as_ref()
            .is_ok_and(|request| !broker.authorizes(request)));
    }

    #[test]
    fn mmio_grant_is_exact_and_directional() {
        let broker = AcpiBroker::with_policy(
            Vec::new(),
            alloc::vec![MmioGrant {
                base: 0xFEC0_0000,
                length: 0x1000,
                read: true,
                write: false,
            }],
            false,
            false,
        );
        let read = Request {
            version: VERSION,
            opcode: Opcode::MmioRead as u16,
            width: 4,
            address: 0xFEC0_0004,
            ..Request::default()
        }
        .validate();
        let write = Request {
            version: VERSION,
            opcode: Opcode::MmioWrite as u16,
            width: 4,
            address: 0xFEC0_0004,
            ..Request::default()
        }
        .validate();
        assert!(read
            .as_ref()
            .is_ok_and(|request| broker.authorizes(request)));
        assert!(write
            .as_ref()
            .is_ok_and(|request| !broker.authorizes(request)));
        // A read starting outside the granted range is denied.
        let outside = Request {
            version: VERSION,
            opcode: Opcode::MmioRead as u16,
            width: 4,
            address: 0xFEC1_0000,
            ..Request::default()
        }
        .validate();
        assert!(outside
            .as_ref()
            .is_ok_and(|request| !broker.authorizes(request)));
    }
}

#[cfg(test)]
mod pci_denial_tests {
    use super::*;
    use huesos_abi::acpi_broker::{Request, VERSION};

    fn pci_request(opcode: Opcode) -> ValidRequest {
        Request {
            version: VERSION,
            opcode: opcode as u16,
            width: 4,
            address: (0x1234 << 32) | (0 << 24) | (0 << 19) | (0 << 16),
            ..Request::default()
        }
        .validate()
        .unwrap_or_else(|_| {
            assert!(false, "structurally valid PCI request");
            loop {}
        })
    }

    #[test]
    fn pci_read_and_write_are_never_authorizable() {
        // AP-10: even with a maximally permissive policy object, PCI
        // configuration opcodes must answer denial. A future regression
        // that re-enables `authorizes_pci` fails here.
        let broker = AcpiBroker::with_policy(Vec::new(), Vec::new(), true, true);
        assert!(!broker.authorizes(&pci_request(Opcode::PciRead)));
        assert!(!broker.authorizes(&pci_request(Opcode::PciWrite)));
        let denied = AcpiBroker::deny_all();
        assert!(!denied.authorizes(&pci_request(Opcode::PciRead)));
        assert!(!denied.authorizes(&pci_request(Opcode::PciWrite)));
    }
}
