//! Kernel-owned physical ranges reserved for userspace DMA pools.
//!
//! A `StorageBootInfo` blob is metadata, not authority. The kernel records the
//! one physically reserved boot DMA pool before userspace starts, and
//! lease/resource syscalls may only mint a `DmaPool` subrange contained by
//! that recorded reservation. Dynamic hotplug DMA is stricter: only the four
//! kernel-defined 4 MiB slices at the end of the reservation are lease-bound,
//! and each slice is claimed by exactly one `(DeviceLease, generation)` pair.
//!
//! The userspace PCI manager may keep a matching bitmap as a scheduling hint,
//! but it cannot make a physical range authoritative. The claim table below is
//! the source of truth and is updated before a lease-bound `DmaPool` resource
//! becomes visible to userspace.

use crate::irq_guard::IrqSafeMutex;
use crate::Koid;

/// Offset of the live hotplug area inside the boot DMA reservation.
pub const HOTPLUG_DMA_OFFSET: u64 = huesos_abi::storage_boot::HOTPLUG_DMA_OFFSET;
/// Size of one kernel-owned live hotplug DMA slice.
pub const HOTPLUG_DMA_SLOT_LEN: u64 = huesos_abi::storage_boot::HOTPLUG_DMA_SLOT_LEN;
/// Number of bounded live hotplug DMA slices.
pub const HOTPLUG_DMA_SLOT_COUNT: usize = huesos_abi::storage_boot::HOTPLUG_DMA_SLOT_COUNT;

/// The immutable physical reservation made during early kernel boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BootDmaPoolRange {
    base: u64,
    len: u64,
}

/// Owner of one dynamic slice. The generation is part of the owner identity so
/// a revoked lease can never release or reuse a replacement lease's slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DynamicSlotOwner {
    lease_koid: Koid,
    generation: u64,
}

static BOOT_DMA_POOL: IrqSafeMutex<Option<BootDmaPoolRange>> = IrqSafeMutex::new(None);
static HOTPLUG_DMA_SLOT_OWNERS:
    IrqSafeMutex<[Option<DynamicSlotOwner>; HOTPLUG_DMA_SLOT_COUNT]> =
    IrqSafeMutex::new([const { None }; HOTPLUG_DMA_SLOT_COUNT]);

/// Register the boot DMA reservation exactly once.
///
/// The reservation is installed before the first userspace process is
/// launched. A second registration is rejected so a later caller cannot
/// replace the ownership root while live `DmaPool` capabilities exist.
pub fn set_boot_dma_pool(base: u64, len: u64) -> bool {
    // The layout is an ABI contract, not a hint supplied by userspace. Keep
    // the kernel ownership root identical to the boot allocator's canonical
    // 92 MiB reservation and below the 32-bit DMA aperture.
    if len != huesos_abi::storage_boot::BOOT_DMA_POOL_LEN
        || base == 0
        || base >= (1u64 << 32)
        || (base & 0xFFF) != 0
        || (len & 0xFFF) != 0
    {
        return false;
    }
    let Some(end) = base.checked_add(len) else {
        return false;
    };
    if end > (1u64 << 32) || end <= base {
        return false;
    }
    let mut slot = BOOT_DMA_POOL.lock();
    if slot.is_some() {
        return false;
    }
    *slot = Some(BootDmaPoolRange { base, len: end - base });
    true
}

/// Whether `[base, base + len)` is a page-aligned subrange of the kernel's
/// registered boot DMA reservation.
///
/// This is deliberately fail-closed when boot registration did not happen.
pub fn dma_pool_range_owned(base: u64, len: u64) -> bool {
    if len == 0 || (base & 0xFFF) != 0 || (len & 0xFFF) != 0 {
        return false;
    }
    let Some(end) = base.checked_add(len) else {
        return false;
    };
    let slot = BOOT_DMA_POOL.lock();
    let Some(pool) = *slot else {
        return false;
    };
    let Some(pool_end) = pool.base.checked_add(pool.len) else {
        return false;
    };
    base >= pool.base && end <= pool_end
}

/// Return `true` only for one complete, page-aligned live hotplug slice.
///
/// Static boot grants intentionally use [`dma_pool_range_owned`] instead: they
/// occupy the first 76 MiB and are minted by the trusted init path. This
/// predicate is for lease-bound dynamic endpoints and is not, on its own, an
/// ownership claim.
pub fn dynamic_slot_range_owned(base: u64, len: u64) -> bool {
    if len != HOTPLUG_DMA_SLOT_LEN || (base & 0xFFF) != 0 {
        return false;
    }
    dynamic_slot_index(base).is_some()
}

/// Return `true` when a valid boot-pool subrange intersects the reserved
/// dynamic hotplug area. Unbound static grants must not cover this area: doing
/// so would let a root-created generic resource bypass the per-slot lease
/// generation binding.
pub fn range_overlaps_dynamic_area(base: u64, len: u64) -> bool {
    if len == 0 || (base & 0xFFF) != 0 || (len & 0xFFF) != 0 {
        return false;
    }
    let Some(end) = base.checked_add(len) else {
        return false;
    };
    let pool = *BOOT_DMA_POOL.lock();
    let Some(pool) = pool else {
        return false;
    };
    let Some(pool_end) = pool.base.checked_add(pool.len) else {
        return false;
    };
    let Some(dynamic_base) = pool.base.checked_add(HOTPLUG_DMA_OFFSET) else {
        return false;
    };
    let Some(dynamic_len) = HOTPLUG_DMA_SLOT_LEN
        .checked_mul(HOTPLUG_DMA_SLOT_COUNT as u64)
    else {
        return false;
    };
    let Some(dynamic_end) = dynamic_base.checked_add(dynamic_len) else {
        return false;
    };
    base >= pool.base
        && end <= pool_end
        && base < dynamic_end
        && dynamic_base < end
}

/// Claim the exact dynamic slice for a lease generation.
///
/// This is the authoritative allocation operation. It is intentionally
/// separate from the userspace hotplug bitmap and serialized with all other
/// kernel claims. A claim is made before the corresponding `Resource` is
/// registered and remains owned by the lease until that generation is revoked
/// or dropped; closing the resource handle alone must not make a still-bound
/// IOMMU range reusable. Callers must release it if later registration fails.
pub(crate) fn claim_dynamic_slot(
    lease_koid: Koid,
    generation: u64,
    base: u64,
    len: u64,
) -> bool {
    if !lease_koid.is_valid()
        || generation == 0
        || !dma_pool_range_owned(base, len)
        || !dynamic_slot_range_owned(base, len)
    {
        return false;
    }
    let Some(index) = dynamic_slot_index(base) else {
        return false;
    };
    let mut owners = HOTPLUG_DMA_SLOT_OWNERS.lock();
    if owners[index].is_some() {
        return false;
    }
    owners[index] = Some(DynamicSlotOwner {
        lease_koid,
        generation,
    });
    true
}

/// Release one exact dynamic slice if it is still owned by this lease
/// generation. The owner comparison makes late cleanup from an old resource
/// harmless after the slot has already been reused by a replacement lease.
pub(crate) fn release_dynamic_slot(
    lease_koid: Koid,
    generation: u64,
    base: u64,
    len: u64,
) {
    let Some(index) = dynamic_slot_index(base).filter(|_| len == HOTPLUG_DMA_SLOT_LEN) else {
        return;
    };
    let mut owners = HOTPLUG_DMA_SLOT_OWNERS.lock();
    if owners[index]
        == Some(DynamicSlotOwner {
            lease_koid,
            generation,
        })
    {
        owners[index] = None;
    }
}

/// Release every slice owned by one lease generation during revoke/drop.
pub(crate) fn release_dynamic_slots_for_lease(lease_koid: Koid, generation: u64) {
    if !lease_koid.is_valid() || generation == 0 {
        return;
    }
    let mut owners = HOTPLUG_DMA_SLOT_OWNERS.lock();
    for owner in owners.iter_mut() {
        if *owner
            == Some(DynamicSlotOwner {
                lease_koid,
                generation,
            })
        {
            *owner = None;
        }
    }
}

fn dynamic_slot_index(base: u64) -> Option<usize> {
    let pool = *BOOT_DMA_POOL.lock();
    let pool = pool?;
    let pool_end = pool.base.checked_add(pool.len)?;
    let offset_base = pool.base.checked_add(HOTPLUG_DMA_OFFSET)?;
    let dynamic_len = HOTPLUG_DMA_SLOT_LEN.checked_mul(HOTPLUG_DMA_SLOT_COUNT as u64)?;
    let dynamic_end = offset_base.checked_add(dynamic_len)?;
    if dynamic_end > pool_end || base < offset_base || base >= dynamic_end {
        return None;
    }
    let slot_end = base.checked_add(HOTPLUG_DMA_SLOT_LEN)?;
    if slot_end > pool_end {
        return None;
    }
    let relative = base.checked_sub(offset_base)?;
    if relative % HOTPLUG_DMA_SLOT_LEN != 0 {
        return None;
    }
    let index = relative / HOTPLUG_DMA_SLOT_LEN;
    (index < HOTPLUG_DMA_SLOT_COUNT as u64).then_some(index as usize)
}
