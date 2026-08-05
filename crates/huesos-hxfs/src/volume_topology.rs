//! Hxfs virtual-volume topology policy core.
//!
//! Stage T records Hxfs replacing FVM with per-filesystem virtual volumes. This
//! fixed-capacity root-leaf tree is no-heap and enforces the selected v1 rules:
//! no nested volumes and no moving objects between volumes.

use crate::format::Uuid;

/// Virtual volume role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VirtualVolumeRole {
    /// Boot-selected system volume.
    System = 1,
    /// User home/data volume.
    UserHome = 2,
    /// Hxblob immutable package volume.
    Hxblob = 3,
    /// Generic data volume for future use.
    Data = 4,
}

/// Virtual-volume tree operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeTopologyError {
    /// The fixed tree is full.
    Full,
    /// Volume UUID already exists.
    DuplicateUuid,
    /// Role uniqueness rule was violated.
    DuplicateRole,
    /// Requested volume was not found.
    NotFound,
    /// Record shape is invalid.
    BadRecord,
    /// Cross-volume object move is forbidden.
    CrossVolumeMove,
}

/// One virtual volume descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualVolumeRecord {
    /// Virtual volume UUID.
    pub uuid: Uuid,
    /// Role in the installed system layout.
    pub role: VirtualVolumeRole,
    /// Root object id for this volume namespace.
    pub root_object_id: u64,
    /// Object table root LBA.
    pub object_table_lba: u64,
    /// Allocation tree root LBA.
    pub allocation_tree_lba: u64,
    /// Refcount tree root LBA.
    pub refcount_tree_lba: u64,
    /// Quota tree root LBA.
    pub quota_tree_lba: u64,
    /// Encryption policy id.
    pub encryption_policy_id: u32,
    /// Compression policy id.
    pub compression_policy_id: u32,
    /// Physical-byte quota. Zero means unlimited.
    pub quota_physical_bytes: u64,
    /// Object-count quota. Zero means unlimited.
    pub quota_objects: u64,
}

/// Fixed-capacity virtual-volume tree.
pub struct VirtualVolumeTree<const N: usize> {
    records: [Option<VirtualVolumeRecord>; N],
}

impl<const N: usize> Default for VirtualVolumeTree<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> VirtualVolumeTree<N> {
    /// Create an empty virtual-volume tree.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; N],
        }
    }

    /// Immutable record array.
    pub const fn records(&self) -> &[Option<VirtualVolumeRecord>; N] {
        &self.records
    }

    /// Insert a virtual-volume descriptor.
    pub fn insert(&mut self, record: VirtualVolumeRecord) -> Result<(), VolumeTopologyError> {
        validate_record(record)?;
        let mut free = None;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(existing) = self.records[index] {
                if existing.uuid == record.uuid {
                    return Err(VolumeTopologyError::DuplicateUuid);
                }
                if unique_role(record.role) && existing.role == record.role {
                    return Err(VolumeTopologyError::DuplicateRole);
                }
            } else if free.is_none() {
                free = Some(index);
            }
            index += 1;
        }
        let slot = free.ok_or(VolumeTopologyError::Full)?;
        self.records[slot] = Some(record);
        self.sort();
        Ok(())
    }

    /// Find a volume by UUID.
    pub fn get(&self, uuid: Uuid) -> Result<VirtualVolumeRecord, VolumeTopologyError> {
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.uuid == uuid {
                    return Ok(record);
                }
            }
            index += 1;
        }
        Err(VolumeTopologyError::NotFound)
    }

    /// Find a unique role.
    pub fn find_role(
        &self,
        role: VirtualVolumeRole,
    ) -> Result<VirtualVolumeRecord, VolumeTopologyError> {
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                if record.role == role {
                    return Ok(record);
                }
            }
            index += 1;
        }
        Err(VolumeTopologyError::NotFound)
    }

    /// Validate no-duplicate, sorted topology invariants.
    pub fn validate(&self) -> Result<(), VolumeTopologyError> {
        let mut previous: Option<Uuid> = None;
        let mut seen_system = false;
        let mut seen_home = false;
        let mut seen_hxblob = false;
        let mut index = 0usize;
        while index < self.records.len() {
            if let Some(record) = self.records[index] {
                validate_record(record)?;
                if let Some(prev) = previous {
                    if prev >= record.uuid {
                        return Err(VolumeTopologyError::DuplicateUuid);
                    }
                }
                match record.role {
                    VirtualVolumeRole::System if seen_system => {
                        return Err(VolumeTopologyError::DuplicateRole)
                    }
                    VirtualVolumeRole::System => seen_system = true,
                    VirtualVolumeRole::UserHome if seen_home => {
                        return Err(VolumeTopologyError::DuplicateRole)
                    }
                    VirtualVolumeRole::UserHome => seen_home = true,
                    VirtualVolumeRole::Hxblob if seen_hxblob => {
                        return Err(VolumeTopologyError::DuplicateRole)
                    }
                    VirtualVolumeRole::Hxblob => seen_hxblob = true,
                    VirtualVolumeRole::Data => {}
                }
                previous = Some(record.uuid);
            }
            index += 1;
        }
        Ok(())
    }

    /// Enforce the no-moving-objects-between-volumes rule.
    pub fn validate_object_move(
        &self,
        source_volume: Uuid,
        target_volume: Uuid,
    ) -> Result<(), VolumeTopologyError> {
        if source_volume == target_volume {
            return Ok(());
        }
        Err(VolumeTopologyError::CrossVolumeMove)
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

fn unique_role(role: VirtualVolumeRole) -> bool {
    matches!(
        role,
        VirtualVolumeRole::System | VirtualVolumeRole::UserHome | VirtualVolumeRole::Hxblob
    )
}

fn validate_record(record: VirtualVolumeRecord) -> Result<(), VolumeTopologyError> {
    if record.root_object_id == 0 || record.object_table_lba == 0 {
        return Err(VolumeTopologyError::BadRecord);
    }
    Ok(())
}

fn should_swap(left: Option<VirtualVolumeRecord>, right: Option<VirtualVolumeRecord>) -> bool {
    match (left, right) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => a.uuid > b.uuid,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(byte: u8, role: VirtualVolumeRole) -> VirtualVolumeRecord {
        VirtualVolumeRecord {
            uuid: [byte; 16],
            role,
            root_object_id: u64::from(byte) + 1,
            object_table_lba: u64::from(byte) + 100,
            allocation_tree_lba: 0,
            refcount_tree_lba: 0,
            quota_tree_lba: 0,
            encryption_policy_id: 0,
            compression_policy_id: 0,
            quota_physical_bytes: 0,
            quota_objects: 0,
        }
    }

    #[test]
    fn inserts_roles_and_enforces_uniqueness() {
        let mut tree = VirtualVolumeTree::<4>::new();
        assert!(tree.insert(record(9, VirtualVolumeRole::Hxblob)).is_ok());
        assert!(tree.insert(record(1, VirtualVolumeRole::System)).is_ok());
        assert_eq!(tree.records()[0].map(|record| record.uuid), Some([1; 16]));
        assert_eq!(
            tree.insert(record(2, VirtualVolumeRole::System)),
            Err(VolumeTopologyError::DuplicateRole)
        );
        assert!(tree.validate().is_ok());
    }

    #[test]
    fn forbids_cross_volume_moves() {
        let tree = VirtualVolumeTree::<2>::new();
        assert_eq!(tree.validate_object_move([1; 16], [1; 16]), Ok(()));
        assert_eq!(
            tree.validate_object_move([1; 16], [2; 16]),
            Err(VolumeTopologyError::CrossVolumeMove)
        );
    }

    // Production-gate volume-topology coverage: each test pins
    // one invariant from the virtual-volume rules in
    // docs/STORAGE_NVME_FS_ROADMAP.md §L (Stage T).
    //
    //   T1 feat(volume): add GPT-backed system volume discovery
    //   T2 feat(hxfs): persist virtual volume table
    //   T3 feat(hxfs): expose virtual VolumeHandle operations
    //   T4 feat(hxfs): create system/user/hxblob volume roles
    //   T5 test(hxfs): add virtual volume policy/remount tests
    //
    // The fixed-capacity virtual-volume tree has to surface
    // Full / DuplicateUuid / DuplicateRole / BadRecord / NotFound
    // without panicking, keep its sorted-by-uuid invariant across
    // mixed insert/remove, and let `find_role` return the
    // first matching record.

    #[test]
    fn duplicate_uuid_is_rejected() {
        let mut tree = VirtualVolumeTree::<4>::new();
        assert!(tree.insert(record(1, VirtualVolumeRole::System)).is_ok());
        assert_eq!(
            tree.insert(record(1, VirtualVolumeRole::UserHome)),
            Err(VolumeTopologyError::DuplicateUuid)
        );
    }

    #[test]
    fn insert_overflow_surfaces_full() {
        let mut tree = VirtualVolumeTree::<2>::new();
        assert!(tree.insert(record(1, VirtualVolumeRole::System)).is_ok());
        assert!(tree.insert(record(2, VirtualVolumeRole::UserHome)).is_ok());
        assert_eq!(
            tree.insert(record(3, VirtualVolumeRole::Hxblob)),
            Err(VolumeTopologyError::Full)
        );
    }

    #[test]
    fn get_missing_uuid_returns_not_found() {
        let tree = VirtualVolumeTree::<4>::new();
        assert_eq!(tree.get([42; 16]), Err(VolumeTopologyError::NotFound));
    }

    #[test]
    fn find_role_unknown_returns_not_found() {
        let tree = VirtualVolumeTree::<4>::new();
        assert_eq!(
            tree.find_role(VirtualVolumeRole::Hxblob),
            Err(VolumeTopologyError::NotFound)
        );
    }

    #[test]
    fn data_role_does_not_uniquely_singleton() {
        // The Data role is intentionally not a singleton: a host
        // can mount many data volumes. Two Data inserts must
        // succeed and validate() must not raise DuplicateRole.
        let mut tree = VirtualVolumeTree::<4>::new();
        assert!(tree.insert(record(1, VirtualVolumeRole::System)).is_ok());
        assert!(tree.insert(record(2, VirtualVolumeRole::Data)).is_ok());
        assert!(tree.insert(record(3, VirtualVolumeRole::Data)).is_ok());
        assert!(tree.validate().is_ok());
    }

    #[test]
    fn validate_empty_tree_is_ok() {
        let tree = VirtualVolumeTree::<4>::new();
        assert_eq!(tree.validate(), Ok(()));
    }

    #[test]
    fn userhome_role_uniqueness_is_enforced() {
        let mut tree = VirtualVolumeTree::<4>::new();
        assert!(tree.insert(record(1, VirtualVolumeRole::UserHome)).is_ok());
        assert_eq!(
            tree.insert(record(2, VirtualVolumeRole::UserHome)),
            Err(VolumeTopologyError::DuplicateRole)
        );
    }

    #[test]
    fn cross_volume_move_distinguishes_unknown_volumes() {
        // A move from a UUID that is not in the tree and a move
        // to a UUID that is not in the tree are both rejected
        // with CrossVolumeMove, not NotFound. The contract is
        // "the topology forbids cross-volume moves", not "the
        // topology records exist", so the absence check is
        // upstream of the topology.
        let tree = VirtualVolumeTree::<4>::new();
        assert_eq!(
            tree.validate_object_move([99; 16], [100; 16]),
            Err(VolumeTopologyError::CrossVolumeMove)
        );
    }
}
