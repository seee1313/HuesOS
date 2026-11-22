//! Stale-ID regressions for the directory/allocator protocol: checked clear,
//! forced retirement, generation-tagged CAS interleavings and concurrent reuse.
//! These are host tests of the real helpers, not on-target scheduler stress.
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

#[test]
fn migration_preserves_pending_flags_but_reuse_discards_them() {
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    let Some(id) = TaskId::new(9, 1) else {
        assert!(false);
        return;
    };
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    let Some(target) = CpuIndex::new(1) else {
        assert!(false);
        return;
    };
    let Some(next) = id.next_generation() else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(id, owner, 3), Ok(()));
    assert_eq!(
        DIRECTORY.publish_operations(id, task_operations::ALL),
        Ok(true)
    );
    assert_eq!(DIRECTORY.publish(id, target, 4), Ok(()));
    assert_eq!(DIRECTORY.take_operations(id), Ok(task_operations::ALL));
    assert_eq!(
        DIRECTORY.publish_operations(id, task_operations::WAKE),
        Ok(true)
    );
    assert_eq!(DIRECTORY.retire(id), Ok(task_operations::WAKE));
    assert_eq!(DIRECTORY.published_id(id.slot()), None);
    assert_eq!(
        DIRECTORY.publish_operations(id, task_operations::WAKE),
        Err(DirectoryError::StaleIdentity)
    );
    assert_eq!(DIRECTORY.publish(next, target, 4), Ok(()));
    assert_eq!(DIRECTORY.take_operations(next), Ok(0));
    assert_eq!(DIRECTORY.retire(id), Err(DirectoryError::StaleIdentity));
    assert_eq!(
        DIRECTORY.publish_operations(next, task_operations::WAKE),
        Ok(true)
    );
    assert_eq!(DIRECTORY.take_operations(next), Ok(task_operations::WAKE));
}

#[test]
fn invalid_operation_bits_cannot_modify_the_generation_tag() {
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    let Some(id) = TaskId::new(10, super::MAX_TASK_GENERATION) else {
        assert!(false);
        return;
    };
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(id, owner, 0), Ok(()));
    for bits in [1 << 8, 1 << super::TASK_INDEX_BITS, u64::MAX] {
        assert_eq!(
            DIRECTORY.publish_operations(id, bits),
            Err(DirectoryError::InvalidOperations)
        );
    }
    assert_eq!(DIRECTORY.publish_operations(id, 0), Ok(false));
    assert_eq!(
        DIRECTORY.publish_operations(id, task_operations::ALL),
        Ok(true)
    );
    assert_eq!(DIRECTORY.take_operations(id), Ok(task_operations::ALL));
    assert_eq!(DIRECTORY.take_operations(id), Ok(0));
    assert_eq!(DIRECTORY.clear(id), Ok(()));
}

// Drive the *same* transition and atomic primitive as publish/take, with the
// reuse boundary inserted exactly between load and CAS. A retry must validate
// the observed generation again, not just retry an unchecked OR or swap.
#[test]
fn delayed_cas_cannot_publish_into_or_consume_a_replacement() {
    use core::sync::atomic::Ordering;
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    let Some(old) = TaskId::new(11, 1) else {
        assert!(false);
        return;
    };
    let Some(next) = old.next_generation() else {
        assert!(false);
        return;
    };
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(old, owner, 0), Ok(()));
    assert_eq!(
        DIRECTORY.publish_operations(old, task_operations::WAKE),
        Ok(true)
    );
    let atomic = &DIRECTORY.entries[old.slot()].pending_operations;
    let snapshot = atomic.load(Ordering::Acquire);
    let Some(delayed_publish) =
        super::operation_update(snapshot, old, task_operations::POLICY, false)
    else {
        assert!(false);
        return;
    };
    let Some(delayed_take) = super::operation_update(snapshot, old, 0, true) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.retire(old), Ok(task_operations::WAKE));
    assert_eq!(DIRECTORY.publish(next, owner, 0), Ok(()));
    assert_eq!(
        DIRECTORY.publish_operations(next, task_operations::WAKE),
        Ok(true)
    );
    for desired in [delayed_publish, delayed_take] {
        let Err(observed) =
            atomic.compare_exchange(snapshot, desired, Ordering::AcqRel, Ordering::Acquire)
        else {
            assert!(false, "stale CAS succeeded");
            return;
        };
        assert_eq!(
            super::operation_update(observed, old, task_operations::POLICY, false),
            None
        );
        assert_eq!(super::operation_update(observed, old, 0, true), None);
    }
    assert_eq!(DIRECTORY.take_operations(next), Ok(task_operations::WAKE));
}

#[test]
fn concurrent_publishers_coalesce_without_losing_distinct_flags() {
    extern crate std;
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    let Some(id) = TaskId::new(12, 1) else {
        assert!(false);
        return;
    };
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(id, owner, 0), Ok(()));
    std::thread::scope(|scope| {
        for bit in 0..8 {
            scope.spawn(move || {
                for _ in 0..1024 {
                    assert!(DIRECTORY.publish_operations(id, 1 << bit).is_ok());
                }
            });
        }
    });
    assert_eq!(DIRECTORY.take_operations(id), Ok(task_operations::ALL));
    assert_eq!(DIRECTORY.take_operations(id), Ok(0));
}

#[test]
fn stale_producers_and_consumers_cannot_cross_concurrent_slot_churn() {
    extern crate std;
    use core::sync::atomic::{AtomicBool, Ordering};
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    let Some(old) = TaskId::new(13, 1) else {
        assert!(false);
        return;
    };
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(old, owner, 0), Ok(()));
    let stop = AtomicBool::new(false);
    let start = std::sync::Barrier::new(5);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let stop = &stop;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                while !stop.load(Ordering::Acquire) {
                    let _ = DIRECTORY.publish_operations(old, task_operations::POLICY);
                    let _ = DIRECTORY.take_operations(old);
                }
            });
        }
        start.wait();
        // Threads race POLICY publishes/drains; the mask reported at retire
        // time may carry zero or more POLICY bits, nothing else.
        match DIRECTORY.retire(old) {
            Ok(mask) => assert_eq!(mask & !task_operations::POLICY, 0),
            Err(_) => assert!(false, "retire must succeed for the live generation"),
        }
        for generation in 2..=4096 {
            let Some(current) = TaskId::new(old.slot(), generation) else {
                assert!(false);
                break;
            };
            assert_eq!(DIRECTORY.publish(current, owner, 0), Ok(()));
            assert_eq!(DIRECTORY.take_operations(current), Ok(0));
            assert_eq!(
                DIRECTORY.publish_operations(current, task_operations::WAKE),
                Ok(true)
            );
            assert_eq!(
                DIRECTORY.take_operations(current),
                Ok(task_operations::WAKE)
            );
            assert_eq!(DIRECTORY.retire(current), Ok(0));
        }
        stop.store(true, Ordering::Release);
    });
}

#[test]
fn reaper_retirement_recycles_more_than_global_capacity_without_carry_over() {
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    static ALLOCATOR: TaskSlotAllocator = TaskSlotAllocator::new();
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    let mut previous = None;
    for expected_generation in 1..=(super::MAX_TASKS as u64 * 2) {
        let Some((slot, generation)) = ALLOCATOR.allocate() else {
            assert!(false, "serial retirement must recycle the global slot");
            return;
        };
        assert_eq!(slot, 0);
        assert_eq!(generation, expected_generation);
        let Some(id) = TaskId::new(slot, generation) else {
            assert!(false);
            return;
        };
        assert_eq!(DIRECTORY.publish(id, owner, 1), Ok(()));
        assert_eq!(DIRECTORY.take_operations(id), Ok(0));
        if let Some(stale) = previous {
            assert_eq!(DIRECTORY.retire(stale), Err(DirectoryError::StaleIdentity));
            assert_eq!(
                DIRECTORY.take_operations(stale),
                Err(DirectoryError::StaleIdentity)
            );
        }
        assert_eq!(
            DIRECTORY.publish_operations(id, task_operations::ALL),
            Ok(true)
        );
        // Exact kernel release order: retire directory before freeing global slot.
        assert_eq!(DIRECTORY.retire(id), Ok(task_operations::ALL));
        assert_eq!(DIRECTORY.published_id(slot), None);
        assert_eq!(ALLOCATOR.free(slot), Ok(()));
        previous = Some(id);
    }
}

// Drain semantics for the kernel reaper: retire() reports the operation bits
// that were pending on the dying identity, atomically in the same publication
// step that unpublishes it. The replacement generation never observes them.
#[test]
fn retire_reports_pending_remote_operations_atomically() {
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    let Some(old) = TaskId::new(21, 1) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(old, owner, 2), Ok(()));
    assert_eq!(
        DIRECTORY.publish_operations(old, task_operations::WAKE),
        Ok(true)
    );
    assert_eq!(
        DIRECTORY.publish_operations(old, task_operations::MIGRATION),
        Ok(true)
    );
    assert_eq!(
        DIRECTORY.retire(old),
        Ok(task_operations::WAKE | task_operations::MIGRATION)
    );
    // One-shot: a second drain of the same identity reports nothing and fails.
    assert_eq!(DIRECTORY.retire(old), Err(DirectoryError::StaleIdentity));
    assert_eq!(
        DIRECTORY.take_operations(old),
        Err(DirectoryError::StaleIdentity)
    );
}

#[test]
fn retire_reports_empty_mask_when_no_operations_pending() {
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    let Some(id) = TaskId::new(22, 1) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(id, owner, 1), Ok(()));
    assert_eq!(DIRECTORY.retire(id), Ok(0));
}

#[test]
fn replacement_generation_never_inherits_discarded_remote_operations() {
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    static ALLOCATOR: TaskSlotAllocator = TaskSlotAllocator::new();
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    let Some((slot, generation)) = ALLOCATOR.allocate() else {
        assert!(false);
        return;
    };
    let Some(old) = TaskId::new(slot, generation) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(old, owner, 5), Ok(()));
    assert_eq!(
        DIRECTORY.publish_operations(old, task_operations::WAKE | task_operations::KILL),
        Ok(true)
    );
    // Exact kernel release order: retire (draining at retire), mark local
    // slot Reaped, then free the global slot for reuse.
    assert_eq!(
        DIRECTORY.retire(old),
        Ok(task_operations::WAKE | task_operations::KILL)
    );
    assert_eq!(ALLOCATOR.free(slot), Ok(()));
    let Some((reused, next_generation)) = ALLOCATOR.allocate() else {
        assert!(false);
        return;
    };
    assert_eq!(reused, slot);
    let Some(current) = TaskId::new(reused, next_generation) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(current, owner, 5), Ok(()));
    assert_eq!(DIRECTORY.take_operations(current), Ok(0));
}

#[test]
fn publish_replacement_discards_stale_flags_even_without_retire() {
    // Defense-in-depth contract, pinned so it cannot silently regress: if a
    // bug ever frees the global slot without retiring the directory first,
    // publish() still replaces the whole generation-tagged word on reuse, so
    // the stale flags never reach the replacement identity.
    static DIRECTORY: TaskDirectory = TaskDirectory::new();
    static ALLOCATOR: TaskSlotAllocator = TaskSlotAllocator::new();
    let Some(owner) = CpuIndex::new(0) else {
        assert!(false);
        return;
    };
    let Some((slot, generation)) = ALLOCATOR.allocate() else {
        assert!(false);
        return;
    };
    let Some(old) = TaskId::new(slot, generation) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(old, owner, 3), Ok(()));
    assert_eq!(
        DIRECTORY.publish_operations(old, task_operations::WAKE),
        Ok(true)
    );
    // Bug-for-bug replay of the legacy sequence: free without retire.
    assert_eq!(ALLOCATOR.free(slot), Ok(()));
    let Some((reused, next_generation)) = ALLOCATOR.allocate() else {
        assert!(false);
        return;
    };
    assert_eq!(reused, slot);
    let Some(current) = TaskId::new(reused, next_generation) else {
        assert!(false);
        return;
    };
    assert_eq!(DIRECTORY.publish(current, owner, 3), Ok(()));
    assert_eq!(DIRECTORY.take_operations(current), Ok(0));
}
