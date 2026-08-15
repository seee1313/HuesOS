//! Generation-safe DeviceLease lifecycle policy.
//!
//! This is a pure policy core: it owns no kernel handles and performs no
//! hardware access. The future kernel object and userspace PCI Manager must use
//! these transition and generation rules so BDF reuse, relocation, removal,
//! and stale replies cannot resurrect old authority.

use crate::PciAddress;

/// Stable identity for one observed device presence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(u64);

impl DeviceId {
    /// Construct a non-zero device identity.
    pub const fn try_new(raw: u64) -> Result<Self, LeaseError> {
        if raw == 0 {
            Err(LeaseError::InvalidIdentity)
        } else {
            Ok(Self(raw))
        }
    }

    /// Raw identity value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic lease generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LeaseGeneration(u64);

impl LeaseGeneration {
    /// Construct a non-zero generation.
    pub const fn try_new(raw: u64) -> Result<Self, LeaseError> {
        if raw == 0 {
            Err(LeaseError::InvalidGeneration)
        } else {
            Ok(Self(raw))
        }
    }

    /// Raw generation value.
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, LeaseError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(LeaseError::GenerationExhausted)
    }
}

/// Driver relocation contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationClass {
    /// Device cannot move while this driver is active.
    Fixed,
    /// DriverHost is stopped and restarted with a new lease.
    Restart,
    /// Driver can quiesce and accept replacement resources in-process.
    QuiesceRemap,
}

/// DMA trust/isolation mode attached to a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaIsolation {
    /// No IOMMU enforcement; controlling driver belongs to the machine TCB.
    Trusted,
    /// Per-device IOMMU domain.
    IommuDomain(u64),
}

/// DeviceLease lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    /// Function discovered but not configured.
    Discovered,
    /// BAR/IRQ/DMA plan committed; resources may be minted for a driver.
    Configured,
    /// Driver process has been attached but has not reported ready.
    DriverStarting,
    /// Driver and device are operational.
    Online,
    /// Driver is draining I/O for relocation/removal.
    Quiescing,
    /// Old generation is revoked and hardware relocation may be applied.
    Rebalancing,
    /// Old generation is revoked and teardown/removal is in progress.
    Removing,
    /// Device presence ended normally or by surprise removal.
    Removed,
    /// Lease failed closed and cannot return Online.
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Intent {
    Relocate,
    Remove,
}

/// Lifecycle event submitted by PCI Manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseEvent {
    /// Initial resource plan committed.
    Configure,
    /// Attach a DriverHost process KOID.
    StartDriver {
        /// Non-zero process KOID selected by the supervisor.
        process_koid: u64,
    },
    /// Attached DriverHost reached ready state.
    DriverReady,
    /// Begin relocation under the declared relocation class.
    BeginRelocation,
    /// Begin orderly device removal.
    BeginRemoval,
    /// Driver acknowledged quiesce and stopped issuing I/O.
    DriverQuiesced,
    /// Hardware plan committed at a new current routing address.
    CommitRelocation {
        /// New segment:BDF published by the committed resource plan.
        new_address: PciAddress,
    },
    /// Removal and resource teardown completed.
    CompleteRemoval,
    /// Device disappeared without orderly quiesce.
    SurpriseRemove,
    /// Fail closed due to policy, timeout, or hardware error.
    Fail,
}

/// Result metadata for one accepted transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseTransition {
    /// Previous state.
    pub from: LeaseState,
    /// New state.
    pub to: LeaseState,
    /// Generation after the transition.
    pub generation: LeaseGeneration,
    /// True when old resource authority was invalidated.
    pub generation_changed: bool,
}

/// Rejected lifecycle operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseError {
    /// Device ID or process KOID is zero.
    InvalidIdentity,
    /// Generation zero is reserved.
    InvalidGeneration,
    /// Generation cannot advance without wrapping.
    GenerationExhausted,
    /// Event carries a stale generation.
    StaleGeneration,
    /// Event is illegal in the current state/intent.
    InvalidTransition,
    /// Fixed driver/device cannot relocate.
    RelocationForbidden,
    /// IOMMU domain zero is invalid.
    InvalidDmaDomain,
}

/// Pure DeviceLease state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceLeasePolicy {
    device_id: DeviceId,
    generation: LeaseGeneration,
    address: PciAddress,
    state: LeaseState,
    relocation: RelocationClass,
    dma_isolation: DmaIsolation,
    driver_process: Option<u64>,
    intent: Option<Intent>,
}

impl DeviceLeasePolicy {
    /// Create one discovered lease presence.
    pub const fn try_new(
        device_id: DeviceId,
        generation: LeaseGeneration,
        address: PciAddress,
        relocation: RelocationClass,
        dma_isolation: DmaIsolation,
    ) -> Result<Self, LeaseError> {
        if matches!(dma_isolation, DmaIsolation::IommuDomain(0)) {
            return Err(LeaseError::InvalidDmaDomain);
        }
        Ok(Self {
            device_id,
            generation,
            address,
            state: LeaseState::Discovered,
            relocation,
            dma_isolation,
            driver_process: None,
            intent: None,
        })
    }

    /// Stable device-presence identity.
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Current lease generation.
    pub const fn generation(self) -> LeaseGeneration {
        self.generation
    }

    /// Current mutable segment:BDF routing address.
    pub const fn address(self) -> PciAddress {
        self.address
    }

    /// Lifecycle state.
    pub const fn state(self) -> LeaseState {
        self.state
    }

    /// Relocation class.
    pub const fn relocation(self) -> RelocationClass {
        self.relocation
    }

    /// DMA trust/isolation mode.
    pub const fn dma_isolation(self) -> DmaIsolation {
        self.dma_isolation
    }

    /// Attached DriverHost KOID, if any.
    pub const fn driver_process(self) -> Option<u64> {
        self.driver_process
    }

    /// Whether this generation may mint new child resources.
    pub const fn can_mint_resources(self, generation: LeaseGeneration) -> bool {
        generation.0 == self.generation.0
            && matches!(
                self.state,
                LeaseState::Configured | LeaseState::DriverStarting | LeaseState::Online
            )
    }

    /// Whether client I/O may be reported successful.
    pub const fn accepts_io(self, generation: LeaseGeneration) -> bool {
        generation.0 == self.generation.0 && matches!(self.state, LeaseState::Online)
    }

    /// Apply one generation-checked lifecycle event.
    pub fn apply(
        &mut self,
        expected_generation: LeaseGeneration,
        event: LeaseEvent,
    ) -> Result<LeaseTransition, LeaseError> {
        if expected_generation != self.generation {
            return Err(LeaseError::StaleGeneration);
        }
        let from = self.state;
        let old_generation = self.generation;
        match event {
            LeaseEvent::Configure if self.state == LeaseState::Discovered => {
                self.state = LeaseState::Configured;
            }
            LeaseEvent::StartDriver { process_koid } if self.state == LeaseState::Configured => {
                if process_koid == 0 {
                    return Err(LeaseError::InvalidIdentity);
                }
                self.driver_process = Some(process_koid);
                self.state = LeaseState::DriverStarting;
            }
            LeaseEvent::DriverReady if self.state == LeaseState::DriverStarting => {
                self.state = LeaseState::Online;
            }
            LeaseEvent::BeginRelocation if self.state == LeaseState::Online => {
                if self.relocation == RelocationClass::Fixed {
                    return Err(LeaseError::RelocationForbidden);
                }
                self.intent = Some(Intent::Relocate);
                self.state = LeaseState::Quiescing;
            }
            LeaseEvent::BeginRemoval
                if matches!(self.state, LeaseState::DriverStarting | LeaseState::Online) =>
            {
                self.intent = Some(Intent::Remove);
                self.state = LeaseState::Quiescing;
            }
            LeaseEvent::BeginRemoval
                if matches!(self.state, LeaseState::Discovered | LeaseState::Configured) =>
            {
                self.revoke_generation()?;
                self.state = LeaseState::Removing;
            }
            LeaseEvent::DriverQuiesced
                if self.state == LeaseState::Quiescing && self.intent == Some(Intent::Relocate) =>
            {
                self.revoke_generation()?;
                self.state = LeaseState::Rebalancing;
                self.intent = None;
            }
            LeaseEvent::DriverQuiesced
                if self.state == LeaseState::Quiescing && self.intent == Some(Intent::Remove) =>
            {
                self.revoke_generation()?;
                self.state = LeaseState::Removing;
                self.intent = None;
            }
            LeaseEvent::CommitRelocation { new_address }
                if self.state == LeaseState::Rebalancing =>
            {
                self.address = new_address;
                self.state = LeaseState::Configured;
            }
            LeaseEvent::CompleteRemoval if self.state == LeaseState::Removing => {
                self.state = LeaseState::Removed;
            }
            LeaseEvent::SurpriseRemove
                if !matches!(self.state, LeaseState::Removed | LeaseState::Failed) =>
            {
                self.revoke_generation()?;
                self.state = LeaseState::Removed;
                self.intent = None;
            }
            LeaseEvent::Fail if !matches!(self.state, LeaseState::Removed | LeaseState::Failed) => {
                self.revoke_generation()?;
                self.state = LeaseState::Failed;
                self.intent = None;
            }
            _ => return Err(LeaseError::InvalidTransition),
        }
        Ok(LeaseTransition {
            from,
            to: self.state,
            generation: self.generation,
            generation_changed: old_generation != self.generation,
        })
    }

    fn revoke_generation(&mut self) -> Result<(), LeaseError> {
        self.generation = self.generation.next()?;
        self.driver_process = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(relocation: RelocationClass) -> DeviceLeasePolicy {
        let device_id = match DeviceId::try_new(7) {
            Ok(value) => value,
            Err(_) => return fallback(relocation),
        };
        let generation = match LeaseGeneration::try_new(1) {
            Ok(value) => value,
            Err(_) => return fallback(relocation),
        };
        match DeviceLeasePolicy::try_new(
            device_id,
            generation,
            PciAddress::ZERO,
            relocation,
            DmaIsolation::Trusted,
        ) {
            Ok(lease) => lease,
            Err(_) => fallback(relocation),
        }
    }

    fn fallback(relocation: RelocationClass) -> DeviceLeasePolicy {
        DeviceLeasePolicy {
            device_id: DeviceId(1),
            generation: LeaseGeneration(1),
            address: PciAddress::ZERO,
            state: LeaseState::Discovered,
            relocation,
            dma_isolation: DmaIsolation::Trusted,
            driver_process: None,
            intent: None,
        }
    }

    fn bring_online(lease: &mut DeviceLeasePolicy) {
        let generation = lease.generation();
        assert!(lease.apply(generation, LeaseEvent::Configure).is_ok());
        assert!(lease
            .apply(generation, LeaseEvent::StartDriver { process_koid: 42 })
            .is_ok());
        assert!(lease.apply(generation, LeaseEvent::DriverReady).is_ok());
    }

    #[test]
    fn normal_start_reaches_online_and_accepts_io() {
        let mut lease = lease(RelocationClass::Restart);
        bring_online(&mut lease);
        assert_eq!(lease.state(), LeaseState::Online);
        assert_eq!(lease.driver_process(), Some(42));
        assert!(lease.can_mint_resources(lease.generation()));
        assert!(lease.accepts_io(lease.generation()));
    }

    #[test]
    fn relocation_revokes_before_hardware_rebalance_and_rejects_stale_generation() {
        let mut lease = lease(RelocationClass::Restart);
        bring_online(&mut lease);
        let old = lease.generation();
        assert!(lease.apply(old, LeaseEvent::BeginRelocation).is_ok());
        let transition = lease.apply(old, LeaseEvent::DriverQuiesced);
        assert!(matches!(
            transition,
            Ok(LeaseTransition {
                to: LeaseState::Rebalancing,
                generation_changed: true,
                ..
            })
        ));
        assert!(!lease.can_mint_resources(old));
        assert_eq!(
            lease.apply(
                old,
                LeaseEvent::CommitRelocation {
                    new_address: PciAddress::ZERO,
                }
            ),
            Err(LeaseError::StaleGeneration)
        );
        let current = lease.generation();
        let Ok(new_address) = PciAddress::try_new(0, 4, 0, 0) else {
            assert!(false, "new test BDF should construct");
            return;
        };
        assert!(lease
            .apply(current, LeaseEvent::CommitRelocation { new_address })
            .is_ok());
        assert_eq!(lease.state(), LeaseState::Configured);
        assert_eq!(lease.address(), new_address);
        assert_eq!(lease.driver_process(), None);
    }

    #[test]
    fn fixed_lease_refuses_relocation() {
        let mut lease = lease(RelocationClass::Fixed);
        bring_online(&mut lease);
        assert_eq!(
            lease.apply(lease.generation(), LeaseEvent::BeginRelocation),
            Err(LeaseError::RelocationForbidden)
        );
        assert_eq!(lease.state(), LeaseState::Online);
    }

    #[test]
    fn orderly_removal_revokes_after_quiesce() {
        let mut lease = lease(RelocationClass::Restart);
        bring_online(&mut lease);
        let old = lease.generation();
        assert!(lease.apply(old, LeaseEvent::BeginRemoval).is_ok());
        assert_eq!(lease.state(), LeaseState::Quiescing);
        assert!(lease.apply(old, LeaseEvent::DriverQuiesced).is_ok());
        assert_eq!(lease.state(), LeaseState::Removing);
        assert_ne!(lease.generation(), old);
        assert!(lease
            .apply(lease.generation(), LeaseEvent::CompleteRemoval)
            .is_ok());
        assert_eq!(lease.state(), LeaseState::Removed);
        assert!(!lease.can_mint_resources(lease.generation()));
    }

    #[test]
    fn surprise_removal_and_failure_are_fail_closed() {
        let mut removed = lease(RelocationClass::Restart);
        bring_online(&mut removed);
        let old = removed.generation();
        assert!(removed.apply(old, LeaseEvent::SurpriseRemove).is_ok());
        assert_eq!(removed.state(), LeaseState::Removed);
        assert_ne!(removed.generation(), old);
        assert!(!removed.accepts_io(removed.generation()));

        let mut failed = lease(RelocationClass::Restart);
        assert!(failed.apply(failed.generation(), LeaseEvent::Fail).is_ok());
        assert_eq!(failed.state(), LeaseState::Failed);
        assert!(!failed.can_mint_resources(failed.generation()));
    }

    #[test]
    fn rejects_invalid_id_generation_domain_and_process() {
        assert_eq!(DeviceId::try_new(0), Err(LeaseError::InvalidIdentity));
        assert_eq!(
            LeaseGeneration::try_new(0),
            Err(LeaseError::InvalidGeneration)
        );
        let device = match DeviceId::try_new(1) {
            Ok(value) => value,
            Err(_) => return,
        };
        let generation = match LeaseGeneration::try_new(1) {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(
            DeviceLeasePolicy::try_new(
                device,
                generation,
                PciAddress::ZERO,
                RelocationClass::Restart,
                DmaIsolation::IommuDomain(0),
            ),
            Err(LeaseError::InvalidDmaDomain)
        );
        let mut lease = lease(RelocationClass::Restart);
        assert!(lease
            .apply(lease.generation(), LeaseEvent::Configure)
            .is_ok());
        assert_eq!(
            lease.apply(
                lease.generation(),
                LeaseEvent::StartDriver { process_koid: 0 }
            ),
            Err(LeaseError::InvalidIdentity)
        );
    }

    #[test]
    fn generation_exhaustion_refuses_revocation_without_wrap() {
        let mut lease = DeviceLeasePolicy {
            device_id: DeviceId(1),
            generation: LeaseGeneration(u64::MAX),
            address: PciAddress::ZERO,
            state: LeaseState::Configured,
            relocation: RelocationClass::Restart,
            dma_isolation: DmaIsolation::Trusted,
            driver_process: None,
            intent: None,
        };
        assert_eq!(
            lease.apply(lease.generation(), LeaseEvent::BeginRemoval),
            Err(LeaseError::GenerationExhausted)
        );
        assert_eq!(lease.generation().get(), u64::MAX);
        assert_eq!(lease.state(), LeaseState::Configured);
    }

    #[test]
    fn bdf_reuse_does_not_make_distinct_device_ids_equal() {
        let first = DeviceId::try_new(1);
        let second = DeviceId::try_new(2);
        assert_ne!(first, second);
        let first_address = PciAddress::ZERO;
        let second_address = PciAddress::ZERO;
        assert_eq!(first_address, second_address);
    }

    #[test]
    fn invalid_transition_does_not_mutate_state() {
        let mut lease = lease(RelocationClass::Restart);
        let before = lease;
        assert_eq!(
            lease.apply(lease.generation(), LeaseEvent::DriverReady),
            Err(LeaseError::InvalidTransition)
        );
        assert_eq!(lease, before);
    }
}
