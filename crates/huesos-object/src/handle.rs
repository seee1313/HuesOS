//! Capability handles and per-process handle tables.

use alloc::vec::Vec;
use bitflags::bitflags;
use spin::Mutex;

use crate::Koid;

bitflags! {
    /// Capability rights on a Handle.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Rights: u32 {
        /// May duplicate this handle.
        const DUPLICATE = 1 << 0;
        /// May transfer this handle to another process via a channel.
        const TRANSFER = 1 << 1;
        /// May read from the underlying object.
        const READ = 1 << 2;
        /// May write to the underlying object.
        const WRITE = 1 << 3;
        /// May execute (map executable) the underlying object.
        const EXECUTE = 1 << 4;
        /// May map the underlying object into an address space.
        const MAP = 1 << 5;
        /// May query properties of the underlying object.
        const GET_PROPERTY = 1 << 6;
        /// May modify properties of the underlying object.
        const SET_PROPERTY = 1 << 7;
        /// May enumerate children (e.g. jobs).
        const ENUMERATE = 1 << 8;
        /// May destroy the underlying object.
        const DESTROY = 1 << 9;
        /// Placeholder meaning "duplicate with the same rights".
        const SAME_RIGHTS = 1 << 31;
        /// Default rights for most objects.
        const DEFAULT = Self::READ.bits() | Self::WRITE.bits() | Self::DUPLICATE.bits() | Self::TRANSFER.bits();
        /// Default rights for VMOs.
        const DEFAULT_VMO = Self::READ.bits() | Self::WRITE.bits() | Self::MAP.bits() | Self::DUPLICATE.bits() | Self::TRANSFER.bits();
    }
}

/// A Handle is a `(Koid, Rights)` pair in a process handle table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    /// Object koid.
    pub koid: Koid,
    /// Rights.
    pub rights: Rights,
}

impl Handle {
    /// Create a new handle.
    pub const fn new(koid: Koid, rights: Rights) -> Self {
        Self { koid, rights }
    }
    /// Check if rights contain `required`.
    pub fn has_rights(self, required: Rights) -> bool {
        self.rights.contains(required)
    }
}

/// Userspace handle value (index into handle table).
pub type HandleValue = u32;
/// Invalid handle value.
pub const INVALID_HANDLE: HandleValue = 0;

/// Per-process handle table.
pub struct HandleTable {
    table: Mutex<Vec<Option<Handle>>>,
}

impl HandleTable {
    /// Create empty handle table.
    pub fn new() -> Self {
        Self {
            table: Mutex::new(Vec::new()),
        }
    }
    /// Add a handle, return its value. Value 0 is reserved as
    /// [`INVALID_HANDLE`], so real handles start at 1.
    pub fn add(&self, handle: Handle) -> HandleValue {
        let mut t = self.table.lock();
        if t.is_empty() {
            t.push(None); // reserve slot 0
        }
        for (i, slot) in t.iter_mut().enumerate().skip(1) {
            if slot.is_none() {
                *slot = Some(handle);
                return i as u32;
            }
        }
        let idx = t.len() as u32;
        t.push(Some(handle));
        idx
    }
    /// Insert a handle at an exact handle value. Fails if `value` is invalid
    /// or already occupied.
    pub fn insert_at(&self, value: HandleValue, handle: Handle) -> Result<(), Handle> {
        if value == INVALID_HANDLE {
            return Err(handle);
        }
        let mut t = self.table.lock();
        while t.len() <= value as usize {
            t.push(None);
        }
        let slot = &mut t[value as usize];
        if slot.is_some() {
            return Err(handle);
        }
        *slot = Some(handle);
        Ok(())
    }

    /// Get handle by value.
    pub fn get(&self, value: HandleValue) -> Option<Handle> {
        if value == INVALID_HANDLE {
            return None;
        }
        self.table.lock().get(value as usize).copied().flatten()
    }
    /// Remove handle.
    pub fn remove(&self, value: HandleValue) -> Option<Handle> {
        if value == INVALID_HANDLE {
            return None;
        }
        self.table
            .lock()
            .get_mut(value as usize)
            .and_then(|h| h.take())
    }

    /// Drop every handle slot (process teardown).
    pub fn clear(&self) {
        let mut t = self.table.lock();
        for slot in t.iter_mut() {
            *slot = None;
        }
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}
