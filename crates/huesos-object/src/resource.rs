//! Immutable capability primitive for physical-address-space grants.
//!
//! A `Resource` represents a per-kind, half-open range `[base, base+len)`
//! that a process holds authority over. Kinds are `IoPort` (x86 port I/O
//! space), `Mmio` (physical MMIO), `Irq` (physical interrupt vector), and
//! the binary capabilities `PowerControl` and `FrameDraw` (which have
//! no meaningful range; the syscall handler forces `base=0, len=1` at
//! mint time).
//!
//! # Design
//!
//! Adapted from Zircon's `zx_resource_t`
//! (`zircon/kernel/object/resource_dispatcher.cc`), simplified for the
//! HuesOS MVP:
//!
//! * **Immutable after `try_create*`.** A resource's `kind`, `base`,
//!   `len`, and `exclusive` flag never change.
//! * **Exclusive vs shared.** An exclusive create walks the per-kind
//!   registry and fails on any intersection with any existing resource
//!   of the same kind. A shared create fails only on intersection with
//!   an existing `exclusive` resource of the same kind; shared/shared
//!   overlap is permitted.
//! * **No root resource.** Every `Resource` is minted directly by the
//!   kernel inside a trusted spawn path (`spawn_init_process`). There
//!   is intentionally no "does anything" capability, so
//!   `component_manager` cannot exist as a super-key holder; see
//!   `docs/ARCHITECTURE_ROADMAP.md` §5.
//! * **No user syscall for create in MVP.** Only kernel-side callers
//!   construct resources; a `component_manager`-driven syscall will be
//!   introduced in the manifest-driven grants PR.
//!
//! Objects downstream of a resource (e.g. an `Interrupt` bound via an
//! IRQ resource) do not hold a reference to the resource itself, mirroring
//! Zircon: the resource is only a validation gate at object-creation time.

use alloc::sync::Arc;
use core::any::Any;

use crate::{alloc_koid, KernelObject, Koid, ObjectType};

/// Kind of physical-address-space grant a `Resource` represents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ResourceKind {
    /// x86 port I/O space (`in`/`out` instructions).
    IoPort = 1,
    /// Physical memory-mapped I/O region.
    Mmio = 2,
    /// Physical interrupt vector / IRQ line.
    Irq = 3,
    /// Authority to invoke the atomic-halt / reboot / (future)
    /// mexec/suspend syscalls. A `PowerControl` resource has no
    /// meaningful base/len (both should be zero at mint time); the
    /// capability is binary. See `docs/ARCHITECTURE_ROADMAP.md` §3.
    PowerControl = 4,
    /// Preallocated DMA pool for userspace DriverHosts. The range is a
    /// device-visible physical window reserved and mapped by the kernel.
    DmaPool = 5,
    /// Authority to invoke [`crate::abi::Syscall::FramebufferBlit`].
    /// A `FrameDraw` resource is a binary capability, exactly like
    /// [`Self::PowerControl`]: it has no meaningful `base`/`len`, so
    /// the syscall handler forces both to `(0, 1)` at mint time. The
    /// handle is the only authority that lets a userspace process
    /// copy (blit) a rectangle from a VMO it owns onto the real
    /// framebuffer. Minted exclusively by the root userspace
    /// supervisor (`init`) and transferred to legitimate graphics
    /// processes over a channel. See
    /// `docs/ARCHITECTURE_ROADMAP.md` § framebuffer.
    FrameDraw = 6,
    /// Authority to change system-wide runtime knobs
    /// (`Syscall::SystemKnobSet`). A binary capability with no
    /// meaningful base/len, deliberately distinct from
    /// [`Self::PowerControl`]: tuning the system and halting it are
    /// different authorities, and a process that needs the former
    /// should not have to be trusted with the latter. Minted by the
    /// root supervisor (`init`) and transferred over a channel.
    SystemControl = 7,
}

/// Reason a `Resource::try_create*` call was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceError {
    /// Requested range wraps past `u64::MAX`, or `len == 0`.
    InvalidRange,
    /// Requested range conflicts with an existing resource: an
    /// exclusive create hit any overlap of the same kind, or a shared
    /// create hit an exclusive overlap of the same kind.
    Conflict,
}

/// Immutable capability object for a `[base, base+len)` range of a kind.
///
/// See module-level documentation for the ownership and overlap rules.
pub struct Resource {
    koid: Koid,
    kind: ResourceKind,
    base: u64,
    len: u64,
    exclusive: bool,
}

impl Resource {
    /// Attempt to mint an exclusive resource. Fails with
    /// `ResourceError::Conflict` if any existing resource of the same
    /// kind overlaps `[base, base+len)`.
    ///
    /// The returned `Arc` is already `register_object`-ed with the
    /// global registry so subsequent `lookup_object(koid)` calls and
    /// future overlap checks see it. The caller is responsible for
    /// wrapping the koid in a `Handle` and inserting it into a process
    /// handle table.
    pub fn try_create_exclusive(
        kind: ResourceKind,
        base: u64,
        len: u64,
    ) -> Result<Arc<Self>, ResourceError> {
        Self::try_create(kind, base, len, true)
    }

    /// Attempt to mint a shared resource. Fails only on intersection
    /// with an existing `exclusive` resource of the same kind.
    pub fn try_create_shared(
        kind: ResourceKind,
        base: u64,
        len: u64,
    ) -> Result<Arc<Self>, ResourceError> {
        Self::try_create(kind, base, len, false)
    }

    fn try_create(
        kind: ResourceKind,
        base: u64,
        len: u64,
        exclusive: bool,
    ) -> Result<Arc<Self>, ResourceError> {
        // Half-open range validation. `len == 0` describes an empty
        // range and is meaningless as a capability; wrap-past-u64::MAX
        // means the range does not exist in any linear address space.
        if len == 0 {
            return Err(ResourceError::InvalidRange);
        }
        if base.checked_add(len).is_none() {
            return Err(ResourceError::InvalidRange);
        }

        // Overlap check under the single registry lock via the private
        // `try_reserve_resource_range` helper: it walks the registry
        // atomically, and if no conflict is found the new Resource is
        // registered before the lock is released. Doing the walk and
        // the register in one critical section avoids the TOCTOU
        // window a two-step (check-then-insert) API would open.
        let resource = Arc::new(Self {
            koid: alloc_koid(),
            kind,
            base,
            len,
            exclusive,
        });
        crate::registry::try_register_resource_locked(resource.clone())?;
        Ok(resource)
    }

    /// Resource kind (IoPort, Mmio, or Irq).
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    /// Inclusive lower bound of the granted range.
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// Length of the granted range in `kind`-native units (ports, bytes, IRQs).
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// `true` iff the granted range is empty. A `Resource` cannot be
    /// constructed with `len == 0` (rejected as `InvalidRange`), so
    /// this always returns `false` for a live resource; the accessor
    /// exists to satisfy clippy's `len_without_is_empty` rule and to
    /// document the invariant in the public API.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether this resource is exclusive (no other resource of the
    /// same kind may overlap it, in either direction).
    pub const fn is_exclusive(&self) -> bool {
        self.exclusive
    }

    /// Test whether `[addr, addr+width)` is fully contained inside this
    /// resource and matches the requested kind. Used by syscall
    /// handlers to authorize a specific access before touching hardware.
    pub fn contains(&self, kind: ResourceKind, addr: u64, width: u64) -> bool {
        if self.kind != kind || width == 0 {
            return false;
        }
        let Some(end) = addr.checked_add(width) else {
            return false;
        };
        addr >= self.base && end <= self.base.saturating_add(self.len)
    }

    /// Test whether `[base, base+len)` intersects this resource's own
    /// range. Kind-agnostic; the caller filters by kind before calling
    /// this on registry-walk callbacks.
    pub fn intersects(&self, base: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let Some(other_end) = base.checked_add(len) else {
            return false;
        };
        let self_end = self.base.saturating_add(self.len);
        base < self_end && self.base < other_end
    }
}

impl KernelObject for Resource {
    fn object_type(&self) -> ObjectType {
        ObjectType::Resource
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
    use crate::unregister_object;

    // Each test unregisters what it created so the shared global
    // registry does not leak state into later tests.

    #[test]
    fn zero_length_range_rejected() {
        assert_eq!(
            Resource::try_create_exclusive(ResourceKind::IoPort, 0x60, 0).map(|_| ()),
            Err(ResourceError::InvalidRange)
        );
    }

    #[test]
    fn wrap_past_u64_max_rejected() {
        assert_eq!(
            Resource::try_create_exclusive(ResourceKind::Mmio, u64::MAX, 1).map(|_| ()),
            Err(ResourceError::InvalidRange)
        );
    }

    #[test]
    fn contains_is_kind_sensitive_and_bounds_checked() {
        let Ok(r) = Resource::try_create_exclusive(ResourceKind::IoPort, 0x60, 4) else {
            assert!(false, "single IoPort resource must be mintable");
            return;
        };
        // In-range accesses of matching kind succeed.
        assert!(r.contains(ResourceKind::IoPort, 0x60, 1));
        assert!(r.contains(ResourceKind::IoPort, 0x63, 1));
        assert!(r.contains(ResourceKind::IoPort, 0x60, 4));
        // Wrong kind, out-of-range, and zero-width accesses all fail.
        assert!(!r.contains(ResourceKind::Mmio, 0x60, 1));
        assert!(!r.contains(ResourceKind::IoPort, 0x60, 5));
        assert!(!r.contains(ResourceKind::IoPort, 0x5f, 1));
        assert!(!r.contains(ResourceKind::IoPort, 0x60, 0));
        // Wrap-past-u64::MAX access is rejected via the checked_add.
        assert!(!r.contains(ResourceKind::IoPort, u64::MAX, 1));

        unregister_object(r.koid());
    }

    #[test]
    fn exclusive_and_exclusive_of_same_kind_conflict_when_overlapping() {
        let Ok(a) = Resource::try_create_exclusive(ResourceKind::IoPort, 0x300, 8) else {
            assert!(false, "first exclusive IoPort must succeed");
            return;
        };
        // Any overlap with an existing exclusive of the same kind is
        // rejected regardless of the second create's exclusivity.
        assert_eq!(
            Resource::try_create_exclusive(ResourceKind::IoPort, 0x304, 4).map(|_| ()),
            Err(ResourceError::Conflict)
        );
        assert_eq!(
            Resource::try_create_shared(ResourceKind::IoPort, 0x304, 4).map(|_| ()),
            Err(ResourceError::Conflict)
        );
        // Non-overlapping same-kind resources are fine.
        let Ok(b) = Resource::try_create_exclusive(ResourceKind::IoPort, 0x310, 4) else {
            assert!(false, "non-overlapping exclusive must succeed");
            unregister_object(a.koid());
            return;
        };
        // Different kinds never conflict, even when numerically overlapping.
        let Ok(c) = Resource::try_create_exclusive(ResourceKind::Mmio, 0x300, 8) else {
            assert!(false, "different-kind resource at same base must succeed");
            unregister_object(a.koid());
            unregister_object(b.koid());
            return;
        };
        unregister_object(a.koid());
        unregister_object(b.koid());
        unregister_object(c.koid());
    }

    #[test]
    fn dma_pool_ranges_conflict_like_mmio() {
        let Ok(pool) = Resource::try_create_exclusive(ResourceKind::DmaPool, 0x1000_0000, 0x4000)
        else {
            assert!(false, "first DMA pool should mint");
            return;
        };
        assert!(pool.contains(ResourceKind::DmaPool, 0x1000_1000, 0x1000));
        assert!(!pool.contains(ResourceKind::Mmio, 0x1000_1000, 0x1000));
        assert_eq!(
            Resource::try_create_exclusive(ResourceKind::DmaPool, 0x1000_2000, 0x1000).map(|_| ()),
            Err(ResourceError::Conflict)
        );
        unregister_object(pool.koid());
    }

    #[test]
    fn shared_and_shared_of_same_kind_may_overlap() {
        let Ok(a) = Resource::try_create_shared(ResourceKind::Mmio, 0xfec00000, 0x1000) else {
            assert!(false, "first shared Mmio must succeed");
            return;
        };
        let Ok(b) = Resource::try_create_shared(ResourceKind::Mmio, 0xfec00800, 0x1000) else {
            assert!(false, "overlapping shared Mmio must succeed");
            unregister_object(a.koid());
            return;
        };
        // But adding an exclusive over that same region is rejected.
        assert_eq!(
            Resource::try_create_exclusive(ResourceKind::Mmio, 0xfec00400, 0x400).map(|_| ()),
            Err(ResourceError::Conflict)
        );
        unregister_object(a.koid());
        unregister_object(b.koid());
    }

    #[test]
    fn shared_rejected_when_overlapping_existing_exclusive() {
        let Ok(a) = Resource::try_create_exclusive(ResourceKind::Irq, 40, 1) else {
            assert!(false, "single IRQ 40 exclusive must succeed");
            return;
        };
        assert_eq!(
            Resource::try_create_shared(ResourceKind::Irq, 40, 1).map(|_| ()),
            Err(ResourceError::Conflict)
        );
        // A neighbouring IRQ is unaffected.
        let Ok(b) = Resource::try_create_shared(ResourceKind::Irq, 41, 1) else {
            assert!(false, "IRQ 41 shared must succeed");
            unregister_object(a.koid());
            return;
        };
        unregister_object(a.koid());
        unregister_object(b.koid());
    }

    #[test]
    fn intersects_matches_half_open_range_semantics() {
        let Ok(r) = Resource::try_create_exclusive(ResourceKind::IoPort, 0x400, 4) else {
            assert!(false, "IoPort 0x400..0x404 exclusive must succeed");
            return;
        };
        // Immediately-adjacent ranges do not intersect (half-open semantics).
        assert!(!r.intersects(0x3fc, 4));
        assert!(!r.intersects(0x404, 4));
        // Any strict overlap does intersect.
        assert!(r.intersects(0x400, 1));
        assert!(r.intersects(0x403, 4));
        assert!(r.intersects(0x3ff, 2));
        // Empty and wrapping ranges never intersect.
        assert!(!r.intersects(0x400, 0));
        assert!(!r.intersects(u64::MAX, 2));
        unregister_object(r.koid());
    }

    #[test]
    fn resource_koid_lookup_returns_registered_object() {
        use crate::{lookup_object, KernelObjectExt};

        let Ok(r) = Resource::try_create_exclusive(ResourceKind::IoPort, 0x2f8, 8) else {
            assert!(false, "IoPort resource must be mintable");
            return;
        };
        let koid = r.koid();

        let Some(via_registry) = lookup_object(koid) else {
            assert!(false, "registered resource must be looked up by koid");
            unregister_object(koid);
            return;
        };
        let Some(downcast) = via_registry.downcast_ref::<Resource>() else {
            assert!(false, "registry lookup must downcast to Resource");
            unregister_object(koid);
            return;
        };
        assert_eq!(downcast.kind(), ResourceKind::IoPort);
        assert_eq!(downcast.base(), 0x2f8);
        assert_eq!(downcast.len(), 8);
        assert!(downcast.is_exclusive());
        unregister_object(koid);
    }
}
