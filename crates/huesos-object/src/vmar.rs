//! Virtual memory address region bookkeeping.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use spin::Mutex;

use crate::{alloc_koid, KernelObject, Koid, ObjectType};

/// A VMAR mapping record: a VMO range mapped into a process address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmarMapping {
    /// Mapped virtual base address.
    pub base: u64,
    /// Mapping length in bytes.
    pub size: u64,
    /// Backing VMO koid.
    pub vmo: Koid,
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
    name: Mutex<String>,
    process: Koid,
    base: u64,
    size: u64,
    mappings: Mutex<Vec<VmarMapping>>,
    children: Mutex<Vec<VmarChild>>,
}

impl Vmar {
    /// Create a root VMAR for `process` covering `[base, base + size)`.
    pub fn new_root(process: Koid, base: u64, size: u64) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: Mutex::new(String::from("root")),
            process,
            base,
            size,
            mappings: Mutex::new(Vec::new()),
            children: Mutex::new(Vec::new()),
        })
    }

    /// Process koid this VMAR belongs to.
    pub const fn process(&self) -> Koid {
        self.process
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
    pub fn record_mapping(&self, mapping: VmarMapping) -> Result<(), ()> {
        if !self.contains_range(mapping.base, mapping.size)
            || self.overlaps_existing(mapping.base, mapping.size)
        {
            return Err(());
        }
        self.mappings.lock().push(mapping);
        Ok(())
    }

    /// Return a snapshot of known mappings.
    pub fn mappings(&self) -> Vec<VmarMapping> {
        self.mappings.lock().clone()
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
    let Some(a_end) = a_base.checked_add(a_size) else {
        return true;
    };
    let Some(b_end) = b_base.checked_add(b_size) else {
        return true;
    };
    a_size == 0 || b_size == 0 || (a_base < b_end && b_base < a_end)
}
