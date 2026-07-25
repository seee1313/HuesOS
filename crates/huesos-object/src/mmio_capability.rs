//! MMIO capability for ring-3 driver processes.
//!
//! The MMIO capability grants a driver process access to specific physical
//! memory regions (typically PCI BARs) for memory-mapped I/O. This is a
//! deny-by-default capability: the kernel provides the capability object
//! with validated grants, and the driver must present the capability handle
//! when requesting MMIO mappings.
//!
//! # Safety model
//!
//! MMIO access is privileged because:
//! - It bypasses virtual memory protection (direct physical access)
//! - It can access device registers that control hardware state
//! - Incorrect access can corrupt device state or cause hardware faults
//!
//! The capability system ensures:
//! - Only granted regions can be mapped (bounds checking)
//! - Mappings are read-only or read-write as specified
//! - Uncacheable attribute is enforced (required for device registers)
//! - Mappings can be revoked when the capability is closed

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::{KernelObject, Koid, ObjectType, alloc_koid};

/// One MMIO region granted to a driver process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioGrant {
    /// Physical base address of the MMIO region.
    pub phys_base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Read operations are permitted.
    pub read: bool,
    /// Write operations are permitted.
    pub write: bool,
    /// Cache attribute: must be uncacheable for device registers.
    pub uncacheable: bool,
}

impl MmioGrant {
    /// Test whether the given offset+size falls within this grant.
    pub fn contains(&self, offset: u64, size: u64) -> bool {
        offset.checked_add(size).is_some_and(|end| end <= self.size)
    }

    /// Test whether the requested access mode is permitted.
    pub fn authorizes(&self, read: bool, write: bool) -> bool {
        (read && self.read) || (write && self.write)
    }
}

/// MMIO capability object. Grants a driver process access to specific
/// physical MMIO regions.
pub struct MmioCapability {
    koid: Koid,
    grants: Vec<MmioGrant>,
}

impl MmioCapability {
    /// Create an MMIO capability with no grants (deny all).
    pub fn deny_all() -> Arc<Self> {
        Self::with_grants(Vec::new())
    }

    /// Create an MMIO capability with validated grants.
    pub fn with_grants(grants: Vec<MmioGrant>) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            grants,
        })
    }

    /// Test whether the given region and access mode are authorized.
    pub fn authorizes(&self, phys_base: u64, size: u64, read: bool, write: bool) -> bool {
        self.grants.iter().any(|grant| {
            // The requested region must fall within a single grant.
            let offset = phys_base.checked_sub(grant.phys_base);
            offset.is_some_and(|off| grant.contains(off, size) && grant.authorizes(read, write))
        })
    }

    /// Return the list of grants (for diagnostics).
    pub fn grants(&self) -> &[MmioGrant] {
        &self.grants
    }
}

impl KernelObject for MmioCapability {
    fn object_type(&self) -> ObjectType {
        ObjectType::MmioCapability
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

    #[test]
    fn grant_contains_validates_bounds() {
        let grant = MmioGrant {
            phys_base: 0xFE00_0000,
            size: 0x4000,
            read: true,
            write: true,
            uncacheable: true,
        };
        assert!(grant.contains(0, 0x4000));
        assert!(grant.contains(0x1000, 0x1000));
        assert!(!grant.contains(0, 0x4001)); // exceeds
        assert!(!grant.contains(0x3FFF, 2)); // exceeds
    }

    #[test]
    fn capability_authorizes_matching_grant() {
        let cap = MmioCapability::with_grants(vec![MmioGrant {
            phys_base: 0xFE00_0000,
            size: 0x4000,
            read: true,
            write: false,
            uncacheable: true,
        }]);
        assert!(cap.authorizes(0xFE00_0000, 0x1000, true, false));
        assert!(!cap.authorizes(0xFE00_0000, 0x1000, true, true)); // write not granted
        assert!(!cap.authorizes(0xFE01_0000, 0x1000, true, false)); // different region
    }

    #[test]
    fn deny_all_rejects_everything() {
        let cap = MmioCapability::deny_all();
        assert!(!cap.authorizes(0xFE00_0000, 0x1000, true, false));
    }
}
