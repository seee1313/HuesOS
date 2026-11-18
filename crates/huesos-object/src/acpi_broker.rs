//! Deny-by-default capability policy for the Ring-3 ACPI broker.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use huesos_abi::acpi_broker::{Opcode, ValidRequest};
use huesos_abi::acpi_region_policy::WriteClass;
use huesos_abi::broker_policy::{AuditLog, AuditOutcome, RateLimiter};

use crate::irq_guard::IrqSafeMutex;
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
    /// Write class when `write` is true.
    pub write_class: Option<WriteClass>,
    /// Allowed write bitmask when `write` is true.
    pub write_mask: u64,
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
    /// Write class when `write` is true.
    pub write_class: Option<WriteClass>,
    /// Allowed write bitmask when `write` is true.
    pub write_mask: u64,
}

/// Immutable authority consulted before privileged ACPI broker operations.
pub struct AcpiBroker {
    koid: Koid,
    firmware_snapshot_id: u64,
    system_io: Vec<SystemIoGrant>,
    mmio: Vec<MmioGrant>,
    allowed_irqs: Vec<u32>,
    allow_reset: bool,
    allow_power_off: bool,
    rate_limiter: IrqSafeMutex<RateLimiter>,
    audit_log: IrqSafeMutex<AuditLog<64>>,
}

impl AcpiBroker {
    /// Construct a broker with no privileged grants.
    pub fn deny_all() -> Arc<Self> {
        Self::with_snapshot_policy(0, Vec::new(), Vec::new(), false, false)
    }

    /// Construct an immutable broker policy from firmware-derived grants.
    pub fn with_policy(
        system_io: Vec<SystemIoGrant>,
        mmio: Vec<MmioGrant>,
        allow_reset: bool,
        allow_power_off: bool,
    ) -> Arc<Self> {
        Self::with_snapshot_policy(0, system_io, mmio, allow_reset, allow_power_off)
    }

    /// Construct a snapshot-bound immutable broker policy from firmware-derived grants.
    pub fn with_snapshot_policy(
        firmware_snapshot_id: u64,
        system_io: Vec<SystemIoGrant>,
        mmio: Vec<MmioGrant>,
        allow_reset: bool,
        allow_power_off: bool,
    ) -> Arc<Self> {
        Self::with_full_policy(
            firmware_snapshot_id,
            system_io,
            mmio,
            Vec::new(),
            allow_reset,
            allow_power_off,
        )
    }

    /// Construct a snapshot-bound immutable broker policy with explicit IRQ grants.
    pub fn with_full_policy(
        firmware_snapshot_id: u64,
        system_io: Vec<SystemIoGrant>,
        mmio: Vec<MmioGrant>,
        allowed_irqs: Vec<u32>,
        allow_reset: bool,
        allow_power_off: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            firmware_snapshot_id,
            system_io,
            mmio,
            allowed_irqs,
            allow_reset,
            allow_power_off,
            rate_limiter: IrqSafeMutex::new(RateLimiter::new(100_000, 4096)),
            audit_log: IrqSafeMutex::new(AuditLog::new()),
        })
    }

    /// Snapshot identity bound to this broker policy.
    pub fn firmware_snapshot_id(&self) -> u64 {
        self.firmware_snapshot_id
    }

    /// Record an authorization decision in the bounded audit log.
    pub fn record_audit(&self, opcode: u8, outcome: AuditOutcome, argument: u64) {
        self.audit_log.lock().record(opcode, outcome, argument);
    }

    /// Enforce per-window rate limit for broker operations.
    pub fn check_rate_limit(&self, tick: u64) -> bool {
        self.rate_limiter.lock().try_acquire(tick)
    }

    /// Test both operation type and immutable resource allowlist.
    pub fn authorizes(&self, request: &ValidRequest) -> bool {
        if self.firmware_snapshot_id != 0
            && matches!(
                request.opcode,
                Opcode::SystemIoRead | Opcode::SystemIoWrite | Opcode::MmioRead | Opcode::MmioWrite
            )
            && request.argument != self.firmware_snapshot_id
        {
            return false;
        }
        match request.opcode {
            Opcode::SystemIoRead | Opcode::SystemIoWrite => self.authorizes_system_io(request),
            // AP-10: PCI configuration opcodes are never authorizable,
            // under any grant. AML reaches configuration space only via
            // the mediated ACPI → PCI channel served by PCI Manager.
            Opcode::PciRead | Opcode::PciWrite => false,
            Opcode::MmioRead | Opcode::MmioWrite => self.authorizes_mmio(request),
            Opcode::Reset => self.allow_reset,
            Opcode::PowerOff => self.allow_power_off,
            Opcode::InstallInterrupt | Opcode::RemoveInterrupt => {
                let Ok(gsi) = u32::try_from(request.address) else {
                    return false;
                };
                self.allowed_irqs.contains(&gsi)
            }
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
                Opcode::SystemIoWrite => {
                    grant.write
                        && grant.write_class.is_some()
                        && grant.write_mask != 0
                        && (request.value & !grant.write_mask) == 0
                }
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
                Opcode::MmioWrite => {
                    grant.write
                        && grant.write_class.is_some()
                        && grant.write_mask != 0
                        && (request.value & !grant.write_mask) == 0
                }
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
                write_class: None,
                write_mask: 0,
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
                write_class: None,
                write_mask: 0,
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
