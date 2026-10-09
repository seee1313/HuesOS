//! Deterministic stale-ID regressions of the directory/allocator helper protocol.
//! The current kernel reaper omits directory clear/drain; these tests deliberately
//! exercise the helper contract, NOT that reaper sequence or concurrent reuse.
//! See docs/PROCESS_LIFECYCLE_REGRESSIONS.md for the reproduced integration gap.
use super::{task_operations, CpuIndex, DirectoryError, TaskDirectory, TaskId, TaskSlotAllocator};

#[test]
fn directory_helper_protocol_rejects_stale_operations_after_clear() {
    let directory = TaskDirectory::new();
    let allocator = TaskSlotAllocator::new();
    let Some((slot, generation)) = allocator.allocate() else {
        assert!(false, "fresh allocator must have a slot");
        return;
    };
    let Some(old) = TaskId::new(slot, generation) else {
        assert!(false, "allocated identity must be encodable");
        return;
    };
    let Some(cpu) = CpuIndex::new(1) else {
        assert!(false, "test CPU must be representable");
        return;
    };
    assert_eq!(directory.publish(old, cpu, 7), Ok(()));
    assert_eq!(
        directory.publish_operations(old, task_operations::WAKE),
        Ok(true)
    );
    assert_eq!(directory.clear(old), Err(DirectoryError::PendingOperations));
    assert_eq!(directory.take_operations(old), Ok(task_operations::WAKE));
    assert_eq!(directory.clear(old), Ok(()));
    assert_eq!(allocator.free(slot), Ok(()));
    let Some((reused, next_generation)) = allocator.allocate() else {
        assert!(false, "released slot must be reusable");
        return;
    };
    assert_eq!(reused, slot);
    assert_eq!(next_generation, generation + 1);
    let Some(current) = TaskId::new(reused, next_generation) else {
        assert!(false, "replacement identity must be encodable");
        return;
    };
    assert_eq!(directory.publish(current, cpu, 7), Ok(()));
    // Simulate delayed timeout, duplicate reaper and stale consumer AFTER reuse.
    // This intentionally does not claim a concurrent check-to-reuse race proof.
    assert_eq!(
        directory.publish_operations(old, task_operations::WAKE),
        Err(DirectoryError::StaleIdentity)
    );
    assert_eq!(
        directory.take_operations(old),
        Err(DirectoryError::StaleIdentity)
    );
    assert_eq!(directory.clear(old), Err(DirectoryError::StaleIdentity));
    assert!(directory.locate(current).is_ok());
    assert_eq!(directory.take_operations(current), Ok(0));
    assert_eq!(
        directory.publish_operations(current, task_operations::WAKE),
        Ok(true)
    );
    assert_eq!(
        directory.take_operations(current),
        Ok(task_operations::WAKE)
    );
    assert_eq!(directory.clear(current), Ok(()));
    assert_eq!(allocator.free(reused), Ok(()));
}

#[test]
fn directory_helper_clear_protocol_survives_repeated_slot_churn() {
    let directory = TaskDirectory::new();
    let allocator = TaskSlotAllocator::new();
    let Some(cpu) = CpuIndex::new(0) else {
        assert!(false, "test CPU must be representable");
        return;
    };
    let mut first = None;
    for generation in 1..=4096 {
        let Some((slot, actual_generation)) = allocator.allocate() else {
            assert!(false, "serial churn must not exhaust slots");
            return;
        };
        assert_eq!(slot, 0);
        assert_eq!(actual_generation, generation);
        let Some(id) = TaskId::new(slot, actual_generation) else {
            assert!(false, "churn identity must be encodable");
            return;
        };
        assert_eq!(directory.publish(id, cpu, 0), Ok(()));
        if let Some(stale) = first {
            assert_eq!(
                directory.publish_operations(stale, task_operations::WAKE),
                Err(DirectoryError::StaleIdentity)
            );
            assert_eq!(directory.clear(stale), Err(DirectoryError::StaleIdentity));
        } else {
            first = Some(id);
        }
        assert_eq!(directory.published_id(slot), Some(id));
        assert_eq!(directory.take_operations(id), Ok(0));
        assert_eq!(directory.clear(id), Ok(()));
        assert_eq!(allocator.free(slot), Ok(()));
    }
}
