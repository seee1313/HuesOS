//! Kernel-enforced `DeviceLease` object (AP-20 / Stages G.2 + G.3).
//!
//! A `DeviceLease` binds hardware resource authority to a stable
//! `(device_id, generation, firmware_snapshot_id)` tuple. Child `Resource`
//! objects minted under the lease carry `(lease_koid, generation)`. When the
//! lease is revoked (surprise removal, relocation, or failure), its active
//! generation is invalidated, child resources become unusable for new mappings,
//! I/O ports, or interrupts, and every bound `Port` receives a
//! `PORT_PACKET_DEVICE_GONE` packet.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::irq_guard::IrqSafeMutex;
use crate::wait::WaitQueue;
use crate::{alloc_koid, KernelObject, Koid, ObjectType, Port, PortPacket, ResourceError};

/// Port packet type matching `huesos_abi::PORT_PACKET_DEVICE_GONE`.
pub const PORT_PACKET_DEVICE_GONE: u32 = 5;

/// Maximum bound `Port` listeners per `DeviceLease`.
pub const MAX_GONE_PORTS: usize = 8;

/// Lifecycle state of a kernel `DeviceLease`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DeviceLeaseState {
    /// Initial plan committed; child resources may be minted.
    Configured = 1,
    /// Controlling driver reported operational.
    Online = 2,
    /// Removal or relocation is in progress; minting disabled.
    Removing = 3,
    /// Lease ended normally or by surprise removal.
    Removed = 4,
    /// Lease failed closed and cannot return online.
    Failed = 5,
}

/// Snapshot metadata returned by [`DeviceLease::info`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceLeaseSnapshot {
    /// Stable non-zero device identity.
    pub device_id: u64,
    /// Current monotonic lease generation.
    pub generation: u64,
    /// Bound firmware snapshot identity.
    pub firmware_snapshot_id: u64,
    /// Canonical packed PCI address.
    pub pci_address_packed: u64,
    /// Current lifecycle state.
    pub state: DeviceLeaseState,
    /// Whether this lease has been revoked (`DeviceGone`).
    pub revoked: bool,
}

/// Failure modes for [`DeviceLease`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceLeaseError {
    /// Identity, snapshot, alignment, or expected generation was zero/invalid.
    InvalidArgs,
    /// Expected generation does not match the live generation, or lease is
    /// already revoked.
    StaleOrRevoked,
    /// Too many `Port` bindings or DMA ranges on this lease.
    TooManyPorts,
    /// Generation counter would overflow.
    GenerationExhausted,
    /// Hardware IOMMU domain binding failed (overlap, isolation-group conflict, or OOM).
    IommuBindFailed,
}

/// Ring-0 hook mapping `[base, base + len)` into `(pci_address_packed, lease_koid, generation)`.
///
/// The callback is invoked while the lease's lifecycle mutex is held. It must
/// be non-reentrant: it may take architecture/IOMMU state locks and perform
/// synchronous hardware work, but must not call back into this `DeviceLease`
/// (or any operation that waits for the same lease mutex). On an error it
/// must either leave no mapping or tolerate the immediate idempotent teardown
/// callback issued by `attach_dma_range()`. The installed architecture hooks
/// satisfy this contract and do not inspect object-layer lease state.
pub type IommuBindDmaFn = fn(u64, u64, u64, u64, u64) -> Result<(), DeviceLeaseError>;
/// Ring-0 hook synchronously tearing down `(pci_address_packed, lease_koid, generation)`.
pub type IommuTeardownFn = fn(u64, u64, u64);

/// Kernel-registered hardware IOMMU callbacks invoked by [`DeviceLease`] (Stage N.2).
#[derive(Clone, Copy)]
pub struct IommuLeaseHooks {
    /// Program a validated `DmaPool` range into the lease's hardware IOMMU domain.
    pub bind_dma: IommuBindDmaFn,
    /// Synchronously unbind the BDF, flush Context/IOTLB caches, and free page tables.
    pub teardown: IommuTeardownFn,
}

static IOMMU_LEASE_HOOKS: IrqSafeMutex<Option<IommuLeaseHooks>> = IrqSafeMutex::new(None);

/// Install the hardware IOMMU lease lifecycle callbacks.
pub fn set_iommu_lease_hooks(hooks: Option<IommuLeaseHooks>) {
    *IOMMU_LEASE_HOOKS.lock() = hooks;
}

struct DeviceLeaseInner {
    generation: u64,
    pci_address_packed: u64,
    state: DeviceLeaseState,
    iommu_bound: bool,
    gone_ports: Vec<(Arc<Port>, u64)>,
}

/// Kernel capability object governing one PCI device presence generation.
pub struct DeviceLease {
    koid: Koid,
    device_id: u64,
    firmware_snapshot_id: u64,
    inner: IrqSafeMutex<DeviceLeaseInner>,
    /// Lock-free active-generation observation used while the object registry
    /// scans bound resources. It avoids acquiring `inner` under the registry
    /// lock; lifecycle writers update it while holding `inner`.
    active_generation: AtomicU64,
    waiters: WaitQueue,
}

impl DeviceLease {
    /// Construct a new active `DeviceLease` at generation 1 in `Configured`
    /// state and register it in the global kernel object registry.
    pub fn try_create(
        device_id: u64,
        firmware_snapshot_id: u64,
        pci_address_packed: u64,
    ) -> Result<Arc<Self>, DeviceLeaseError> {
        if device_id == 0 || firmware_snapshot_id == 0 || (pci_address_packed >> 32) != 0 {
            return Err(DeviceLeaseError::InvalidArgs);
        }
        let lease = Arc::new(Self {
            koid: alloc_koid(),
            device_id,
            firmware_snapshot_id,
            inner: IrqSafeMutex::new(DeviceLeaseInner {
                generation: 1,
                pci_address_packed,
                state: DeviceLeaseState::Configured,
                iommu_bound: false,
                gone_ports: Vec::new(),
            }),
            active_generation: AtomicU64::new(1),
            waiters: WaitQueue::new(),
        });
        crate::register_object(Arc::clone(&lease) as Arc<dyn KernelObject>);
        Ok(lease)
    }

    /// Stable non-zero device identity.
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Bound firmware snapshot identity.
    pub const fn firmware_snapshot_id(&self) -> u64 {
        self.firmware_snapshot_id
    }

    /// Return `true` iff `expected_generation` matches the live generation and
    /// the lease has not been revoked.
    pub fn is_generation_active(&self, expected_generation: u64) -> bool {
        expected_generation != 0
            && self.active_generation.load(Ordering::Acquire) == expected_generation
    }

    /// Run a bound-resource transaction while the lease generation remains
    /// active. The callback may claim a dynamic DMA slot and register the
    /// child resource; `revoke()` cannot invalidate or release that claim
    /// until the callback returns.
    ///
    /// The registry observes `active_generation` atomically rather than
    /// taking `inner`, so this lock order does not create a registry-to-lease
    /// inversion while existing resources are scanned.
    pub(crate) fn with_active_generation<T, F>(
        &self,
        expected_generation: u64,
        operation: F,
    ) -> Result<T, ResourceError>
    where
        F: FnOnce() -> Result<T, ResourceError>,
    {
        let inner = self.inner.lock();
        if expected_generation == 0
            || inner.generation != expected_generation
            || !matches!(
                inner.state,
                DeviceLeaseState::Configured | DeviceLeaseState::Online
            )
            || self.active_generation.load(Ordering::Acquire) != expected_generation
        {
            return Err(ResourceError::Conflict);
        }
        operation()
    }

    /// Return `true` if the lease has been revoked (`Removing`/`Removed`/`Failed`).
    pub fn is_revoked(&self) -> bool {
        let inner = self.inner.lock();
        matches!(
            inner.state,
            DeviceLeaseState::Removing | DeviceLeaseState::Removed | DeviceLeaseState::Failed
        )
    }

    /// Current metadata snapshot.
    pub fn info(&self) -> DeviceLeaseSnapshot {
        let inner = self.inner.lock();
        let revoked = matches!(
            inner.state,
            DeviceLeaseState::Removing | DeviceLeaseState::Removed | DeviceLeaseState::Failed
        );
        DeviceLeaseSnapshot {
            device_id: self.device_id,
            generation: inner.generation,
            firmware_snapshot_id: self.firmware_snapshot_id,
            pci_address_packed: inner.pci_address_packed,
            state: inner.state,
            revoked,
        }
    }

    /// Bind a `Port` to receive `PORT_PACKET_DEVICE_GONE` when this lease is
    /// revoked. If the lease is already revoked, the packet is delivered
    /// immediately to `port`.
    pub fn bind_gone_port(&self, port: Arc<Port>, key: u64) -> Result<(), DeviceLeaseError> {
        let immediate_packet = {
            let mut inner = self.inner.lock();
            let revoked = matches!(
                inner.state,
                DeviceLeaseState::Removing | DeviceLeaseState::Removed | DeviceLeaseState::Failed
            );
            if revoked {
                Some(self.make_gone_packet(key, inner.generation, inner.state))
            } else {
                let already = inner.gone_ports.iter().any(|(existing, existing_key)| {
                    existing.koid() == port.koid() && *existing_key == key
                });
                if !already {
                    if inner.gone_ports.len() >= MAX_GONE_PORTS {
                        return Err(DeviceLeaseError::TooManyPorts);
                    }
                    inner.gone_ports.push((Arc::clone(&port), key));
                }
                None
            }
        };

        if let Some(packet) = immediate_packet {
            let _ = port.queue(packet);
        }
        Ok(())
    }

    /// Bind a 4 KiB-aligned `DmaPool` physical range `[base, base + len)` into
    /// this lease's hardware IOMMU domain for `expected_generation` (Stage N.2).
    pub fn attach_dma_range(
        &self,
        expected_generation: u64,
        base: u64,
        len: u64,
    ) -> Result<(), DeviceLeaseError> {
        if expected_generation == 0
            || len == 0
            || (base & 0xFFF) != 0
            || (len & 0xFFF) != 0
            || base.checked_add(len).is_none()
        {
            return Err(DeviceLeaseError::InvalidArgs);
        }
        // Serialize the hardware bind with revoke/drop. If the lock were
        // released while the architecture hook ran, revoke could release the
        // dynamic DMA slot and a replacement lease could reuse it before this
        // stale bind was torn down. The architecture hooks do not call back
        // into DeviceLease, so keeping this short critical section held is
        // safe and gives the bind/revoke pair a single ordering point.
        let mut inner = self.inner.lock();
        if inner.generation != expected_generation
            || !matches!(
                inner.state,
                DeviceLeaseState::Configured | DeviceLeaseState::Online
            )
        {
            return Err(DeviceLeaseError::StaleOrRevoked);
        }
        let pci_address_packed = inner.pci_address_packed;
        let hooks = *IOMMU_LEASE_HOOKS.lock();
        if let Some(h) = hooks {
            if let Err(error) = (h.bind_dma)(
                pci_address_packed,
                self.koid.0,
                expected_generation,
                base,
                len,
            ) {
                // A hook may have installed part of a domain before it can
                // report an overlap/isolation failure. Teardown is required
                // to be idempotent for this rollback path; calling it here
                // makes a failed bind safe even for in-kernel callers that do
                // not immediately revoke the lease.
                (h.teardown)(pci_address_packed, self.koid.0, expected_generation);
                return Err(error);
            }
        }
        inner.iommu_bound = true;
        Ok(())
    }

    /// Revoke the active generation (`expected_generation`), synchronously
    /// tearing down any bound hardware IOMMU domain, invalidating all child
    /// `Resource` capabilities bound to it, advancing the monotonic generation
    /// so the revoked generation can never be replayed, and delivering
    /// `PORT_PACKET_DEVICE_GONE` to every bound `Port`.
    pub fn revoke(&self, expected_generation: u64, failed: bool) -> Result<u64, DeviceLeaseError> {
        if expected_generation == 0 {
            return Err(DeviceLeaseError::InvalidArgs);
        }
        let (revoked_gen, pci_address_packed, was_bound, new_state, ports) = {
            let mut inner = self.inner.lock();
            if inner.generation != expected_generation
                || !matches!(
                    inner.state,
                    DeviceLeaseState::Configured | DeviceLeaseState::Online
                )
            {
                return Err(DeviceLeaseError::StaleOrRevoked);
            }
            let next_generation = inner
                .generation
                .checked_add(1)
                .ok_or(DeviceLeaseError::GenerationExhausted)?;
            let was_bound = inner.iommu_bound;
            inner.generation = next_generation;
            inner.iommu_bound = false;
            inner.state = if failed {
                DeviceLeaseState::Failed
            } else {
                DeviceLeaseState::Removed
            };
            self.active_generation.store(0, Ordering::Release);
            let ports = core::mem::take(&mut inner.gone_ports);
            (
                expected_generation,
                inner.pci_address_packed,
                was_bound,
                inner.state,
                ports,
            )
        };

        // Tear down the old IOMMU domain before making its physical DMA slice
        // available for a replacement lease. Releasing the slot first would
        // permit immediate reuse while stale translations could still issue
        // DMA to the old range.
        if was_bound {
            let hooks = *IOMMU_LEASE_HOOKS.lock();
            if let Some(h) = hooks {
                (h.teardown)(pci_address_packed, self.koid.0, revoked_gen);
            }
        }
        // The slot owner includes the old generation, so a late Resource drop
        // cannot release a replacement lease's claim.
        crate::dma_pool::release_dynamic_slots_for_lease(self.koid, revoked_gen);

        for (port, key) in ports {
            let packet = self.make_gone_packet(key, revoked_gen, new_state);
            let _ = port.queue(packet);
        }
        self.waiters.wake_all();
        Ok(revoked_gen)
    }

    /// Wait queue signaled on revocation.
    pub fn wait_queue(&self) -> &WaitQueue {
        &self.waiters
    }

    const fn make_gone_packet(
        &self,
        key: u64,
        generation: u64,
        state: DeviceLeaseState,
    ) -> PortPacket {
        PortPacket {
            key,
            packet_type: PORT_PACKET_DEVICE_GONE,
            status: 0,
            data: [
                self.device_id,
                generation,
                self.firmware_snapshot_id,
                state as u64,
            ],
        }
    }
}

impl Drop for DeviceLease {
    fn drop(&mut self) {
        let teardown_target = {
            let mut inner = self.inner.lock();
            self.active_generation.store(0, Ordering::Release);
            if inner.iommu_bound {
                inner.iommu_bound = false;
                Some((inner.pci_address_packed, inner.generation))
            } else {
                None
            }
        };
        if let Some((pci_address_packed, active_gen)) = teardown_target {
            // The IOMMU teardown is synchronous. Keep the physical slice
            // reserved until translations and page tables are gone, then
            // permit a replacement lease to claim it.
            let hooks = *IOMMU_LEASE_HOOKS.lock();
            if let Some(h) = hooks {
                (h.teardown)(pci_address_packed, self.koid.0, active_gen);
            }
            crate::dma_pool::release_dynamic_slots_for_lease(self.koid, active_gen);
        } else {
            // A lease can have no IOMMU binding while still owning a dynamic
            // slice during a failed handoff. Do not leak that kernel claim.
            let generation = self.inner.lock().generation;
            crate::dma_pool::release_dynamic_slots_for_lease(self.koid, generation);
        }
    }
}

impl KernelObject for DeviceLease {
    fn object_type(&self) -> ObjectType {
        ObjectType::DeviceLease
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
    use crate::{unregister_object, Resource, ResourceError, ResourceKind};

    #[test]
    fn device_lease_rejects_zero_identity_or_snapshot() {
        assert_eq!(
            DeviceLease::try_create(0, 1, 0).err(),
            Some(DeviceLeaseError::InvalidArgs)
        );
        assert_eq!(
            DeviceLease::try_create(1, 0, 0).err(),
            Some(DeviceLeaseError::InvalidArgs)
        );
        assert_eq!(
            DeviceLease::try_create(1, 1, 1u64 << 32).err(),
            Some(DeviceLeaseError::InvalidArgs)
        );
    }

    #[test]
    fn device_lease_revocation_delivers_device_gone_and_invalidates_child_resources() {
        let Ok(lease) = DeviceLease::try_create(42, 0xCAFE_BABE, 0x0000_0008) else {
            assert!(false, "DeviceLease::try_create should succeed");
            return;
        };
        let Ok(port) = Port::new() else {
            assert!(false, "Port::new should succeed");
            unregister_object(lease.koid());
            return;
        };
        crate::register_object(Arc::clone(&port) as Arc<dyn KernelObject>);

        assert!(lease.bind_gone_port(Arc::clone(&port), 0x1234).is_ok());

        let Ok(bar) = Resource::try_create_leased(
            ResourceKind::Mmio,
            0xFE00_0000,
            0x1000,
            true,
            lease.koid(),
            1,
        ) else {
            assert!(false, "try_create_leased should succeed");
            unregister_object(port.koid());
            unregister_object(lease.koid());
            return;
        };
        assert!(bar.is_lease_active());

        // Stale generation revocation must fail without revoking generation 1.
        assert_eq!(
            lease.revoke(2, false),
            Err(DeviceLeaseError::StaleOrRevoked)
        );
        assert!(bar.is_lease_active());

        // Active generation revocation succeeds, invalidates child resource, and delivers DeviceGone.
        assert_eq!(lease.revoke(1, false), Ok(1));
        assert!(!lease.is_generation_active(1));
        assert!(lease.is_revoked());
        assert!(!bar.is_lease_active());

        let Some(packet) = port.read() else {
            assert!(false, "DeviceGone packet must be queued on bound port");
            unregister_object(bar.koid());
            unregister_object(port.koid());
            unregister_object(lease.koid());
            return;
        };
        assert_eq!(packet.key, 0x1234);
        assert_eq!(packet.packet_type, PORT_PACKET_DEVICE_GONE);
        assert_eq!(packet.data[0], 42);
        assert_eq!(packet.data[1], 1);
        assert_eq!(packet.data[2], 0xCAFE_BABE);

        // Late port binding after revocation must deliver DeviceGone immediately.
        assert!(lease.bind_gone_port(Arc::clone(&port), 0x5678).is_ok());
        let Some(late_packet) = port.read() else {
            assert!(false, "late port binding must still receive DeviceGone");
            unregister_object(bar.koid());
            unregister_object(port.koid());
            unregister_object(lease.koid());
            return;
        };
        assert_eq!(late_packet.key, 0x5678);
        assert_eq!(late_packet.packet_type, PORT_PACKET_DEVICE_GONE);

        // Re-claiming the exact same physical BDF/MMIO under a fresh lease must succeed (no stale conflict)
        // while the revoked resource stays permanently inactive (ABA-safe).
        let Ok(lease2) = DeviceLease::try_create(43, 0xCAFE_BABE, 0x0000_0008) else {
            assert!(false, "replacement DeviceLease should succeed");
            unregister_object(bar.koid());
            unregister_object(port.koid());
            unregister_object(lease.koid());
            return;
        };
        let bar2 = Resource::try_create_leased(
            ResourceKind::Mmio,
            0xFE00_0000,
            0x1000,
            true,
            lease2.koid(),
            1,
        );
        assert!(
            !matches!(bar2, Err(ResourceError::Conflict)),
            "revoked leased resource must not block a fresh lease for the same range"
        );
        if let Ok(r2) = bar2 {
            assert!(r2.is_lease_active());
            assert!(!bar.is_lease_active());
            unregister_object(r2.koid());
        }

        unregister_object(bar.koid());
        unregister_object(port.koid());
        unregister_object(lease.koid());
        unregister_object(lease2.koid());
    }

    #[test]
    fn device_lease_iommu_hooks_bind_and_synchronously_teardown_on_revoke_and_drop() {
        use core::sync::atomic::{AtomicU64, Ordering};

        static BOUND_PAGES: AtomicU64 = AtomicU64::new(0);
        static TEARDOWNS: AtomicU64 = AtomicU64::new(0);

        fn mock_bind(
            bdf: u64,
            _koid: u64,
            _gen: u64,
            _base: u64,
            len: u64,
        ) -> Result<(), DeviceLeaseError> {
            if bdf == 0x0020 || bdf == 0x0028 {
                BOUND_PAGES.fetch_add(len / 4096, Ordering::SeqCst);
            }
            Ok(())
        }
        fn mock_teardown(bdf: u64, _koid: u64, _gen: u64) {
            if bdf == 0x0020 || bdf == 0x0028 {
                TEARDOWNS.fetch_add(1, Ordering::SeqCst);
            }
        }

        BOUND_PAGES.store(0, Ordering::SeqCst);
        TEARDOWNS.store(0, Ordering::SeqCst);
        set_iommu_lease_hooks(Some(IommuLeaseHooks {
            bind_dma: mock_bind,
            teardown: mock_teardown,
        }));

        let Ok(lease) = DeviceLease::try_create(99, 0x1111, 0x0020) else {
            set_iommu_lease_hooks(None);
            assert!(false, "DeviceLease::try_create failed");
            return;
        };
        assert_eq!(
            lease.attach_dma_range(1, 0x1001, 4096),
            Err(DeviceLeaseError::InvalidArgs)
        );
        assert_eq!(lease.attach_dma_range(1, 0x0200_0000, 8192), Ok(()));
        assert_eq!(BOUND_PAGES.load(Ordering::SeqCst), 2);
        assert_eq!(lease.revoke(1, false), Ok(1));
        assert_eq!(TEARDOWNS.load(Ordering::SeqCst), 1);
        assert_eq!(
            lease.attach_dma_range(1, 0x0200_2000, 4096),
            Err(DeviceLeaseError::StaleOrRevoked)
        );
        unregister_object(lease.koid());

        // Also prove Drop tears down an un-revoked bound lease when its last Arc drops.
        if let Ok(ephemeral) = DeviceLease::try_create(100, 0x1111, 0x0028) {
            let eph_koid = ephemeral.koid();
            assert_eq!(ephemeral.attach_dma_range(1, 0x0300_0000, 4096), Ok(()));
            unregister_object(eph_koid);
            drop(ephemeral);
            assert_eq!(TEARDOWNS.load(Ordering::SeqCst), 2);
        }

        set_iommu_lease_hooks(None);
    }
}
