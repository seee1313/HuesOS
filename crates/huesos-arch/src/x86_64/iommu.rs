//! Unified Ring-0 hardware IOMMU dispatcher across Intel VT-d and AMD-Vi.

use huesos_abi::pci_iommu::{IommuHardwareKind, KernelIommuStatus};
use huesos_iommu::FaultRecord;

use super::vtd::VtdHwError;
use super::{amd_vi, vtd};

/// True when either Intel VT-d or AMD-Vi hardware translation is active.
pub fn is_active() -> bool {
    vtd::is_active() || amd_vi::is_active()
}

/// Active hardware IOMMU architecture (`IntelVtd`, `AmdVi`, or `None`).
pub fn active_kind() -> IommuHardwareKind {
    if vtd::is_active() {
        IommuHardwareKind::IntelVtd
    } else if amd_vi::is_active() {
        IommuHardwareKind::AmdVi
    } else {
        IommuHardwareKind::None
    }
}

/// Snapshot live Ring-0 IOMMU telemetry for `Syscall::SystemIommuStatus`.
pub fn status() -> KernelIommuStatus {
    if vtd::is_active() {
        vtd::status()
    } else if amd_vi::is_active() {
        amd_vi::status()
    } else {
        KernelIommuStatus::TRUSTED_INACTIVE
    }
}

/// Bind `[base, base + len)` (`IOVA == HPA`, `READ | WRITE`) into the active
/// hardware IOMMU domain for `(lease_koid, lease_generation)`.
pub fn bind_lease_dma(
    pci_address_packed: u64,
    lease_koid: u64,
    lease_generation: u64,
    base: u64,
    len: u64,
) -> Result<(), VtdHwError> {
    if vtd::is_active() {
        vtd::bind_lease_dma(pci_address_packed, lease_koid, lease_generation, base, len)
    } else if amd_vi::is_active() {
        amd_vi::bind_lease_dma(pci_address_packed, lease_koid, lease_generation, base, len)
    } else {
        Ok(())
    }
}

/// Synchronously revoke and tear down the hardware IOMMU domain for `(lease_koid, lease_generation)`.
pub fn teardown_lease(pci_address_packed: u64, lease_koid: u64, lease_generation: u64) {
    if vtd::is_active() {
        vtd::teardown_lease(pci_address_packed, lease_koid, lease_generation);
    } else if amd_vi::is_active() {
        amd_vi::teardown_lease(pci_address_packed, lease_koid, lease_generation);
    }
}

/// Drain pending hardware IOMMU fault records from the active engine.
pub fn drain_faults(out: &mut [FaultRecord]) -> usize {
    if vtd::is_active() {
        vtd::drain_faults(out)
    } else if amd_vi::is_active() {
        amd_vi::drain_faults(out)
    } else {
        0
    }
}
