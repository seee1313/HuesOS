//! Virtual memory address region bookkeeping.

use crate::irq_guard::IrqSafeMutex;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::{alloc_koid, KernelObject, KernelObjectExt, Koid, ObjectType};

/// VMAR bookkeeping failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmarError {
    /// Mapping lies outside this VMAR or has an invalid/overflowing range.
    InvalidRange,
    /// Mapping overlaps an existing mapping or child VMAR.
    Overlap,
}

/// A VMAR mapping record: a VMO range mapped into a process address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmarMapping {
    /// Mapped virtual base address.
    pub base: u64,
    /// Mapping length in bytes.
    pub size: u64,
    /// Backing VMO koid.
    pub vmo: Koid,
    /// Byte offset within the backing VMO.
    pub vmo_offset: u64,
    /// ABI mapping flags used when the mapping was created.
    pub flags: u32,
}

/// A child VMAR range reserved inside a parent VMAR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmarChild {
    /// Child VMAR koid.
    pub koid: Koid,
    /// Child virtual base address.
    pub base: u64,
    /// Child VMAR size in bytes.
    pub size: u64,
}

/// VMAR — a userspace virtual-memory address region.
///
/// The first implementation uses only a process root VMAR for fixed-address
/// ELF/stack mappings, but the object already records child ranges so the
/// later VMAR tree API can enforce non-overlap without changing the object
/// shape.
pub struct Vmar {
    koid: Koid,
    name: IrqSafeMutex<String>,
    process: Koid,
    parent: Option<Koid>,
    base: u64,
    size: u64,
    mappings: IrqSafeMutex<Vec<VmarMapping>>,
    children: IrqSafeMutex<Vec<VmarChild>>,
}

impl Vmar {
    /// Create a root VMAR for `process` covering `[base, base + size)`.
    pub fn new_root(process: Koid, base: u64, size: u64) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: IrqSafeMutex::new(String::from("root")),
            process,
            parent: None,
            base,
            size,
            mappings: IrqSafeMutex::new(Vec::new()),
            children: IrqSafeMutex::new(Vec::new()),
        })
    }

    /// Create a child VMAR reserved inside `parent`.
    ///
    /// The caller must first reserve the range in the parent with
    /// [`record_child`](Self::record_child) and hold a kernel reference to the
    /// parent for this child's lifetime.
    pub fn new_child(parent: &Vmar, base: u64, size: u64) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: IrqSafeMutex::new(String::from("child")),
            process: parent.process,
            parent: Some(parent.koid),
            base,
            size,
            mappings: IrqSafeMutex::new(Vec::new()),
            children: IrqSafeMutex::new(Vec::new()),
        })
    }

    /// Process koid this VMAR belongs to.
    pub const fn process(&self) -> Koid {
        self.process
    }

    /// Parent VMAR koid, if this is a child VMAR.
    pub const fn parent(&self) -> Option<Koid> {
        self.parent
    }

    /// VMAR base address.
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// VMAR size in bytes.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Exclusive VMAR end address, or `None` on overflow.
    pub const fn end(&self) -> Option<u64> {
        self.base.checked_add(self.size)
    }

    /// Return whether `[base, base + size)` is fully inside this VMAR.
    pub fn contains_range(&self, base: u64, size: u64) -> bool {
        let Some(end) = base.checked_add(size) else {
            return false;
        };
        let Some(vmar_end) = self.end() else {
            return false;
        };
        size > 0 && base >= self.base && end <= vmar_end
    }

    /// Return whether `[base, base + size)` overlaps an existing mapping or
    /// child VMAR range.
    pub fn overlaps_existing(&self, base: u64, size: u64) -> bool {
        let mappings = self.mappings.lock();
        if mappings
            .iter()
            .any(|m| ranges_overlap(base, size, m.base, m.size))
        {
            return true;
        }
        drop(mappings);

        self.children
            .lock()
            .iter()
            .any(|c| ranges_overlap(base, size, c.base, c.size))
    }

    /// Record a mapping if it is inside this VMAR and does not overlap any
    /// existing mapping/child range.
    pub fn record_mapping(&self, mapping: VmarMapping) -> Result<(), VmarError> {
        if !self.contains_range(mapping.base, mapping.size) {
            return Err(VmarError::InvalidRange);
        }
        // Hold the mapping lock across check+insert so two threads cannot both
        // validate the same range and then race page-table mutation.
        let mut mappings = self.mappings.lock();
        if mappings.iter().any(|existing| {
            ranges_overlap(mapping.base, mapping.size, existing.base, existing.size)
        }) || self
            .children
            .lock()
            .iter()
            .any(|child| ranges_overlap(mapping.base, mapping.size, child.base, child.size))
        {
            return Err(VmarError::Overlap);
        }
        mappings.push(mapping);
        Ok(())
    }

    /// Record a child VMAR reservation.
    pub fn record_child(&self, child: VmarChild) -> Result<(), VmarError> {
        if !self.contains_range(child.base, child.size) {
            return Err(VmarError::InvalidRange);
        }
        let mappings = self.mappings.lock();
        if mappings
            .iter()
            .any(|mapping| ranges_overlap(child.base, child.size, mapping.base, mapping.size))
        {
            return Err(VmarError::Overlap);
        }
        drop(mappings);

        let mut children = self.children.lock();
        if children
            .iter()
            .any(|existing| ranges_overlap(child.base, child.size, existing.base, existing.size))
        {
            return Err(VmarError::Overlap);
        }
        children.push(child);
        Ok(())
    }

    /// Remove a child VMAR reservation.
    pub fn remove_child(&self, koid: Koid) -> bool {
        let mut children = self.children.lock();
        let Some(index) = children.iter().position(|child| child.koid == koid) else {
            return false;
        };
        children.swap_remove(index);
        true
    }

    /// Find one exact mapping reservation.
    pub fn mapping(&self, base: u64, size: u64) -> Option<VmarMapping> {
        self.mappings
            .lock()
            .iter()
            .find(|mapping| mapping.base == base && mapping.size == size)
            .copied()
    }

    /// Find one mapping reservation that fully covers a requested subrange.
    pub fn mapping_covering(&self, base: u64, size: u64) -> Option<VmarMapping> {
        let end = base.checked_add(size)?;
        self.mappings
            .lock()
            .iter()
            .find(|mapping| {
                let Some(mapping_end) = mapping.base.checked_add(mapping.size) else {
                    return false;
                };
                size > 0 && base >= mapping.base && end <= mapping_end
            })
            .copied()
    }

    /// Atomically replace one mapping record with split records.
    pub fn replace_mapping(
        &self,
        old: VmarMapping,
        replacements: &[VmarMapping],
    ) -> Result<(), VmarError> {
        for mapping in replacements {
            if !self.contains_range(mapping.base, mapping.size) {
                return Err(VmarError::InvalidRange);
            }
            if mapping.vmo != old.vmo {
                return Err(VmarError::InvalidRange);
            }
        }
        for (index, mapping) in replacements.iter().enumerate() {
            if replacements
                .iter()
                .skip(index + 1)
                .any(|other| ranges_overlap(mapping.base, mapping.size, other.base, other.size))
            {
                return Err(VmarError::Overlap);
            }
        }

        let mut mappings = self.mappings.lock();
        let Some(old_index) = mappings.iter().position(|existing| *existing == old) else {
            return Err(VmarError::InvalidRange);
        };
        let children = self.children.lock();
        for child in children.iter() {
            if replacements
                .iter()
                .any(|mapping| ranges_overlap(mapping.base, mapping.size, child.base, child.size))
            {
                return Err(VmarError::Overlap);
            }
        }
        drop(children);

        mappings.swap_remove(old_index);
        for mapping in replacements {
            mappings.push(*mapping);
        }
        Ok(())
    }

    /// Update permissions on one exact mapping reservation.
    pub fn update_mapping_flags(&self, mapping: VmarMapping, flags: u32) -> bool {
        let mut mappings = self.mappings.lock();
        let Some(existing) = mappings.iter_mut().find(|existing| **existing == mapping) else {
            return false;
        };
        existing.flags = flags;
        true
    }

    /// Remove one exact mapping reservation during transaction rollback.
    pub fn remove_mapping(&self, mapping: VmarMapping) -> bool {
        let mut mappings = self.mappings.lock();
        let Some(index) = mappings.iter().position(|existing| *existing == mapping) else {
            return false;
        };
        mappings.swap_remove(index);
        true
    }

    /// Return a snapshot of known mappings.
    pub fn mappings(&self) -> Vec<VmarMapping> {
        self.mappings.lock().clone()
    }

    /// Return a snapshot of child reservations.
    pub fn children(&self) -> Vec<VmarChild> {
        self.children.lock().clone()
    }
}

impl Drop for Vmar {
    fn drop(&mut self) {
        // Every recorded mapping owns one kernel reference to its backing VMO.
        // Release after taking the vector so no VMAR lock is held while object
        // collection may drop a VMO and return physical frames to the PMM.
        let mappings = core::mem::take(&mut *self.mappings.lock());
        for mapping in mappings {
            crate::note_kernel_ref_close(mapping.vmo);
        }

        if let Some(parent) = self.parent {
            if let Some(parent_object) = crate::lookup_object(parent) {
                if let Some(parent_vmar) = parent_object.downcast_ref::<Vmar>() {
                    let _ = parent_vmar.remove_child(self.koid);
                }
            }
            crate::note_kernel_ref_close(parent);
        }
    }
}

impl KernelObject for Vmar {
    fn object_type(&self) -> ObjectType {
        ObjectType::Vmar
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn ranges_overlap(a_base: u64, a_size: u64, b_base: u64, b_size: u64) -> bool {
    // An empty range overlaps nothing. (This used to count as an overlap
    // — a trap for future callers; current call sites all pass
    // validated non-zero sizes, so the behavior change is invisible to
    // them.)
    if a_size == 0 || b_size == 0 {
        return false;
    }
    let Some(a_end) = a_base.checked_add(a_size) else {
        return true;
    };
    let Some(b_end) = b_base.checked_add(b_size) else {
        return true;
    };
    a_base < b_end && b_base < a_end
}

#[cfg(test)]
mod tests {
    use super::{ranges_overlap, Vmar, VmarError, VmarMapping};
    use crate::Koid;

    #[test]
    fn empty_ranges_do_not_overlap() {
        assert!(!ranges_overlap(0x1000, 0, 0x1000, 0x1000));
        assert!(!ranges_overlap(0x1000, 0x1000, 0x1000, 0));
        assert!(!ranges_overlap(0x1000, 0, 0x2000, 0));
    }

    #[test]
    fn overlapping_and_adjacent_ranges() {
        assert!(ranges_overlap(0x1000, 0x1000, 0x1000, 0x1000));
        assert!(ranges_overlap(0x1000, 0x1000, 0x1fff, 0x1000));
        assert!(!ranges_overlap(0x1000, 0x1000, 0x2000, 0x1000));
    }

    #[test]
    fn zero_size_candidate_is_rejected_as_invalid_not_overlap() {
        let root = Vmar::new_root(Koid(1), 0x10000, 0x100000);
        let base = VmarMapping {
            base: 0x10000,
            size: 0x1000,
            vmo: Koid(2),
            vmo_offset: 0,
            flags: 0,
        };
        assert!(root.record_mapping(base).is_ok());
        // A zero-size candidate must fail with InvalidRange (from
        // contains_range), not be reported as overlapping the existing
        // mapping.
        let empty = VmarMapping { size: 0, ..base };
        assert_eq!(root.record_mapping(empty), Err(VmarError::InvalidRange));
    }
}
