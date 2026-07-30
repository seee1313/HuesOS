//! Fixed-capacity quota B-tree policy core.
//!
//! Stage O persists per-volume quota records and enforces physical-byte/object
//! charges before allocator publication. The root-leaf fixed array is no-heap
//! friendly and keeps records sorted by volume UUID bytes.

use crate::format::Uuid;

/// Quota tree operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaTreeError {
    /// The fixed quota tree is full.
    Full,
    /// A requested quota record was not found.
    NotFound,
    /// A charge would exceed a quota limit.
    Exceeded,
    /// Arithmetic overflow or invalid quota record.
    BadRecord,
}

/// Persistent per-volume quota record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaRecord {
    /// Virtual volume UUID.
    pub volume_uuid: Uuid,
    /// Physical-byte limit. Zero means unlimited.
    pub physical_limit_bytes: u64,
    /// Charged physical bytes.
    pub physical_used_bytes: u64,
    /// Object-count limit. Zero means unlimited.
    pub object_limit: u64,
    /// Charged object count.
    pub object_count: u64,
}

impl QuotaRecord {
    /// Check whether adding `bytes` and `objects` would fit this quota.
    pub fn admits(self, bytes: u64, objects: u64) -> Result<bool, QuotaTreeError> {
        let next_bytes = self
            .physical_used_bytes
            .checked_add(bytes)
            .ok_or(QuotaTreeError::BadRecord)?;
        let next_objects = self
            .object_count
            .checked_add(objects)
            .ok_or(QuotaTreeError::BadRecord)?;
        let bytes_ok = self.physical_limit_bytes == 0 || next_bytes <= self.physical_limit_bytes;
        let objects_ok = self.object_limit == 0 || next_objects <= self.object_limit;
        Ok(bytes_ok && objects_ok)
    }
}

/// Fixed-capacity quota B-tree root/leaf.
pub struct QuotaBtree<const N: usize> {
    records: [Option<QuotaRecord>; N],
}

impl<const N: usize> QuotaBtree<N> {
    /// Create an empty quota tree.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
        }
    }

    /// Immutable fixed record array.
    pub const fn records(&self) -> &[Option<QuotaRecord>; N] {
        &self.records
    }

    /// Count occupied records.
    pub fn record_count(&self) -> usize {
        let mut count = 0usize;
        let mut index = 0usize;
        while index < self.records.len() {
            if self.records[index].is_some() {
                count += 1;
            }
            index += 1;
        }
        count
    }

    /// Insert or replace a quota record for a volume UUID.
    pub fn upsert(&mut self, record: QuotaRecord) -> Result<(), QuotaTreeError> {
        if record.physical_limit_bytes != 0
            && record.physical_used_bytes > record.physical_limit_bytes
        {
            return Err(QuotaTreeError::Exceeded);
        }
        if record.object_limit != 0 && record.object_count > record.object_limit {
            return Err(QuotaTreeError::Exceeded);
        }
        let mut free = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(existing) = self.records[index] {
                if existing.volume_uuid == record.volume_uuid {
                    self.records[index] = Some(record);
                    self.sort();
                    return Ok(());
                }
            } else if free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(QuotaTreeError::Full)?;
        self.records[slot] = Some(record);
        self.sort();
        Ok(())
    }

    /// Return a quota record by volume UUID.
    pub fn get(&self, volume_uuid: Uuid) -> Result<QuotaRecord, QuotaTreeError> {
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.volume_uuid == volume_uuid {
                    return Ok(record);
                }
            }
            index += 1;
        }
        Err(QuotaTreeError::NotFound)
    }

    /// Charge bytes and objects to a quota record.
    pub fn charge(
        &mut self,
        volume_uuid: Uuid,
        bytes: u64,
        objects: u64,
    ) -> Result<QuotaRecord, QuotaTreeError> {
        let mut record = self.get(volume_uuid)?;
        if !record.admits(bytes, objects)? {
            return Err(QuotaTreeError::Exceeded);
        }
        record.physical_used_bytes = record
            .physical_used_bytes
            .checked_add(bytes)
            .ok_or(QuotaTreeError::BadRecord)?;
        record.object_count = record
            .object_count
            .checked_add(objects)
            .ok_or(QuotaTreeError::BadRecord)?;
        self.upsert(record)?;
        Ok(record)
    }

    /// Release bytes and objects from a quota record, saturating at zero.
    pub fn release(
        &mut self,
        volume_uuid: Uuid,
        bytes: u64,
        objects: u64,
    ) -> Result<QuotaRecord, QuotaTreeError> {
        let mut record = self.get(volume_uuid)?;
        record.physical_used_bytes = record.physical_used_bytes.saturating_sub(bytes);
        record.object_count = record.object_count.saturating_sub(objects);
        self.upsert(record)?;
        Ok(record)
    }

    /// Validate all quota records.
    pub fn validate(&self) -> Result<(), QuotaTreeError> {
        let mut previous: Option<Uuid> = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.physical_limit_bytes != 0
                    && record.physical_used_bytes > record.physical_limit_bytes
                {
                    return Err(QuotaTreeError::Exceeded);
                }
                if record.object_limit != 0 && record.object_count > record.object_limit {
                    return Err(QuotaTreeError::Exceeded);
                }
                if let Some(prev) = previous {
                    if prev >= record.volume_uuid {
                        return Err(QuotaTreeError::BadRecord);
                    }
                }
                previous = Some(record.volume_uuid);
            }
            index += 1;
        }
        Ok(())
    }

    fn sort(&mut self) {
        let mut i = 0usize;
        while i < self.records.len() {
            let mut j = i + 1;
            while j < self.records.len() {
                if should_swap(self.records[i], self.records[j]) {
                    self.records.swap(i, j);
                }
                j += 1;
            }
            i += 1;
        }
    }
}

fn should_swap(left: Option<QuotaRecord>, right: Option<QuotaRecord>) -> bool {
    match (left, right) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => a.volume_uuid > b.volume_uuid,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VOLUME: Uuid = [7; 16];

    #[test]
    fn quota_charges_and_releases() {
        let mut tree = QuotaBtree::<4>::new();
        assert!(tree
            .upsert(QuotaRecord {
                volume_uuid: VOLUME,
                physical_limit_bytes: 8192,
                physical_used_bytes: 4096,
                object_limit: 4,
                object_count: 1,
            })
            .is_ok());
        assert!(tree.charge(VOLUME, 4096, 1).is_ok());
        assert_eq!(tree.charge(VOLUME, 1, 0), Err(QuotaTreeError::Exceeded));
        assert!(tree.release(VOLUME, 4096, 1).is_ok());
        assert!(tree.validate().is_ok());
    }

    #[test]
    fn quota_records_are_sorted_by_uuid() {
        let mut tree = QuotaBtree::<4>::new();
        assert!(tree
            .upsert(QuotaRecord {
                volume_uuid: [9; 16],
                physical_limit_bytes: 0,
                physical_used_bytes: 0,
                object_limit: 0,
                object_count: 0,
            })
            .is_ok());
        assert!(tree
            .upsert(QuotaRecord {
                volume_uuid: [1; 16],
                physical_limit_bytes: 0,
                physical_used_bytes: 0,
                object_limit: 0,
                object_count: 0,
            })
            .is_ok());
        assert_eq!(
            tree.records()[0].map(|record| record.volume_uuid),
            Some([1; 16])
        );
    }
}
