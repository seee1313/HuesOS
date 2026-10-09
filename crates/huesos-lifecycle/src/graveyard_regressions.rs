use super::{InsertOutcome, TaskGraveyard};

#[test]
fn stale_observation_does_not_reap_reused_koid_after_old_record_eviction() {
    let mut yard = TaskGraveyard::<2>::new();
    let (old, _) = yard.record_exit_with_generation(7, 10, -1, 1);
    let (_, _) = yard.record_exit_with_generation(8, 11, 0, 2);
    let (current, outcome) = yard.record_exit_with_generation(7, 12, 42, 3);
    assert_eq!(outcome, InsertOutcome::Evicted(old));
    assert_eq!(yard.find(7, 10), None);
    assert_eq!(yard.find_latest(7), Some(current));
    assert_eq!(
        yard.reap_waited(|koid, generation| koid == old.koid && generation == old.generation),
        0
    );
    assert_eq!(yard.find(7, 12), Some(current));
    assert_eq!(
        yard.reap_waited(
            |koid, generation| koid == current.koid && generation == current.generation
        ),
        1
    );
    assert_eq!(
        yard.reap_waited(
            |koid, generation| koid == current.koid && generation == current.generation
        ),
        0
    );
    assert_eq!(
        yard.total_recorded(),
        yard.total_evicted() + yard.total_reaped() + yard.len() as u64
    );
}

#[test]
fn zero_capacity_returns_lifecycle_identity_to_eviction_caller() {
    let mut yard = TaskGraveyard::<0>::new();
    let (record, outcome) = yard.record_exit_with_generation(3, 1234, -9, 100);
    assert_eq!(outcome, InsertOutcome::Evicted(record));
    assert_eq!(record.generation, 1234);
    assert!(yard.is_empty());
    assert_eq!(yard.total_recorded(), 1);
    assert_eq!(yard.total_evicted(), 1);
    assert_eq!(yard.reap_waited(|_, _| true), 0);
}
