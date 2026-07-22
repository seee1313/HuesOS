//! Capability handles and per-process handle tables.

use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::bitflags;
use spin::Mutex;

use crate::{note_handle_close, note_handle_open, Job, Koid};
use huesos_quota::Resource;

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

/// Failure while preparing a transactional batch handle move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleTableError {
    /// One of the requested slots is no longer occupied.
    Missing,
    /// Kernel memory could not hold the bounded batch.
    OutOfMemory,
    /// The same slot was requested more than once.
    Duplicate,
    /// The owning Job has no handle quota left.
    QuotaExceeded,
}

/// Per-process handle table.
pub struct HandleTable {
    table: Mutex<Vec<Option<Handle>>>,
    job: Option<Arc<Job>>,
}

impl HandleTable {
    /// Create empty handle table.
    pub fn new() -> Self {
        Self {
            table: Mutex::new(Vec::new()),
            job: None,
        }
    }

    /// Create a handle table charged to `job`.
    pub fn new_in_job(job: Arc<Job>) -> Self {
        Self {
            table: Mutex::new(Vec::new()),
            job: Some(job),
        }
    }

    /// Owning Job, if this table participates in handle accounting.
    pub fn job(&self) -> Option<Arc<Job>> {
        self.job.clone()
    }

    /// Add a handle, return its value. Value 0 is reserved as
    /// [`INVALID_HANDLE`], so real handles start at 1.
    pub fn add(&self, handle: Handle) -> HandleValue {
        note_handle_open(handle.koid);
        self.add_existing(handle)
    }

    /// Add a handle while charging the owning Job's handle budget.
    pub fn try_add(&self, handle: Handle) -> Result<HandleValue, HandleTableError> {
        if let Some(job) = &self.job {
            if !job.charge(Resource::Handles, 1) {
                return Err(HandleTableError::QuotaExceeded);
            }
        }
        note_handle_open(handle.koid);
        Ok(self.add_existing(handle))
    }

    /// Insert a handle that is already accounted for in the global handle
    /// count (e.g. received via channel transfer).
    pub fn add_existing(&self, handle: Handle) -> HandleValue {
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
        note_handle_open(handle.koid);
        *slot = Some(handle);
        Ok(())
    }

    /// Insert a handle at an exact slot while charging the owning Job.
    pub fn try_insert_at(
        &self,
        value: HandleValue,
        handle: Handle,
    ) -> Result<(), HandleTableError> {
        if value == INVALID_HANDLE {
            return Err(HandleTableError::Missing);
        }
        if let Some(job) = &self.job {
            if !job.charge(Resource::Handles, 1) {
                return Err(HandleTableError::QuotaExceeded);
            }
        }
        match self.insert_at(value, handle) {
            Ok(()) => Ok(()),
            Err(handle) => {
                if let Some(job) = &self.job {
                    let _ = job.release(Resource::Handles, 1);
                }
                Err(HandleTableError::Missing)
            }
        }
    }

    /// Get handle by value.
    pub fn get(&self, value: HandleValue) -> Option<Handle> {
        if value == INVALID_HANDLE {
            return None;
        }
        self.table.lock().get(value as usize).copied().flatten()
    }
    /// Remove handle and drop the handle-table reference (may free object).
    pub fn remove(&self, value: HandleValue) -> Option<Handle> {
        let h = self.remove_keep_alive(value)?;
        note_handle_close(h.koid);
        if let Some(job) = &self.job {
            let _ = job.release(Resource::Handles, 1);
        }
        Some(h)
    }

    /// Remove handle from the table without adjusting the global handle
    /// count — used when the handle is transferred into a channel message
    /// (still "alive", just not in this table).
    pub fn remove_keep_alive(&self, value: HandleValue) -> Option<Handle> {
        if value == INVALID_HANDLE {
            return None;
        }
        self.table
            .lock()
            .get_mut(value as usize)
            .and_then(|h| h.take())
    }

    /// Remove a distinct batch of handles while preserving their in-flight
    /// handle-count ownership. Validation and allocation happen before the
    /// first slot is changed, so a missing slot cannot produce a partial move.
    pub fn remove_many_keep_alive(
        &self,
        values: &[HandleValue],
    ) -> Result<Vec<Handle>, HandleTableError> {
        let mut t = self.table.lock();
        for (index, &value) in values.iter().enumerate() {
            if values[..index].contains(&value) {
                return Err(HandleTableError::Duplicate);
            }
            if value == INVALID_HANDLE
                || t.get(value as usize).and_then(|slot| slot.as_ref()).is_none()
            {
                return Err(HandleTableError::Missing);
            }
        }
        let mut removed = Vec::new();
        removed
            .try_reserve_exact(values.len())
            .map_err(|_| HandleTableError::OutOfMemory)?;
        for &value in values {
            let handle = t[value as usize].take();
            match handle {
                Some(handle) => removed.push(handle),
                None => return Err(HandleTableError::Missing),
            }
        }
        Ok(removed)
    }

    /// Restore a handle to an exact slot after a failed transactional move.
    ///
    /// The handle-count ownership is intentionally preserved: callers use this
    /// only for a handle that was removed with [`Self::remove_keep_alive`].
    pub fn restore_existing_at(&self, value: HandleValue, handle: Handle) -> Result<(), Handle> {
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

    /// Drop every handle slot (process teardown).
    pub fn clear(&self) {
        let mut t = self.table.lock();
        for slot in t.iter_mut() {
            if let Some(h) = slot.take() {
                note_handle_close(h.koid);
                if let Some(job) = &self.job {
                    let _ = job.release(Resource::Handles, 1);
                }
            }
        }
    }
}

impl Drop for HandleTable {
    fn drop(&mut self) {
        // Clear is idempotent and ensures process/object teardown cannot leak
        // global handle references when a table is dropped outside the normal
        // explicit ProcessExit path (including construction failures/tests).
        self.clear();
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}
