//! Host regressions of the actual IPC/handle transaction helpers used by syscalls.
//! Copy faults are injected at the commit boundary; no host page tables are mocked.
use crate::channel::{send_or_restore, validate_move_dispositions};
use huesos_abi::ErrorCode;
use huesos_object::{
    lookup_object, object_ref_counts, register_object, Channel, ChannelMessage, ChannelRecvError,
    Handle, HandleTableError, KernelObject, Process, Rights, Signal,
};

fn tracked_handle(process: &Process) -> (u32, Handle) {
    let signal = Signal::new();
    let handle = Handle::new(signal.koid(), Rights::DEFAULT);
    register_object(signal);
    (process.handles.add(handle), handle)
}

#[test]
fn duplicate_and_missing_move_leave_every_source_handle_untouched() {
    let process = Process::new("bad-move");
    let (a, ha) = tracked_handle(&process);
    let (b, hb) = tracked_handle(&process);
    assert_eq!(
        validate_move_dispositions(&process, &[a, b, a]),
        Err(ErrorCode::InvalidArgs)
    );
    assert_eq!(
        validate_move_dispositions(&process, &[a, 0, b]),
        Err(ErrorCode::BadHandle)
    );
    for (slot, handle) in [(a, ha), (b, hb)] {
        assert_eq!(process.handles.get(slot), Some(handle));
        assert_eq!(object_ref_counts(handle.koid), (1, 0));
    }
    process.handles.clear();
    assert!(lookup_object(ha.koid).is_none());
    assert!(lookup_object(hb.koid).is_none());
}

#[test]
fn inline_move_capacity_failure_is_atomic() {
    let process = Process::new("short-staging");
    let (a, ha) = tracked_handle(&process);
    let (b, hb) = tracked_handle(&process);
    let mut staging = [ha; 1];
    assert_eq!(
        process
            .handles
            .remove_many_keep_alive_into(&[a, b], &mut staging),
        Err(HandleTableError::OutOfMemory)
    );
    assert_eq!(process.handles.get(a), Some(ha));
    assert_eq!(process.handles.get(b), Some(hb));
    assert_eq!(object_ref_counts(ha.koid), (1, 0));
    assert_eq!(object_ref_counts(hb.koid), (1, 0));
}

#[test]
fn pair_publication_fault_collects_both_objects_without_touching_existing_handle() {
    let process = Process::new("pair-copy-fault");
    let (old, old_handle) = tracked_handle(&process);
    let first = Signal::new();
    let second = Signal::new();
    let first_id = first.koid();
    let second_id = second.koid();
    register_object(first);
    register_object(second);
    let mut published = [0; 2];
    let result = process.handles.add_pair_with_commit(
        Handle::new(first_id, Rights::DEFAULT),
        Handle::new(second_id, Rights::DEFAULT),
        |a, b| {
            published = [a, b];
            Err::<(), _>(ErrorCode::InvalidArgs)
        },
    );
    assert_eq!(result, Err(ErrorCode::InvalidArgs));
    for slot in published {
        assert!(process.handles.get(slot).is_none());
    }
    for id in [first_id, second_id] {
        assert_eq!(object_ref_counts(id), (0, 0));
        assert!(lookup_object(id).is_none());
    }
    assert_eq!(process.handles.get(old), Some(old_handle));
}

#[test]
fn duplicate_publication_fault_restores_reference_count() {
    let process = Process::new("duplicate-copy-fault");
    let (slot, handle) = tracked_handle(&process);
    let mut attempted = 0;
    let result = process.handles.add_with_commit(handle, |new_slot| {
        attempted = new_slot;
        Err::<(), _>(ErrorCode::InvalidArgs)
    });
    assert_eq!(result, Err(ErrorCode::InvalidArgs));
    assert!(process.handles.get(attempted).is_none());
    assert_eq!(process.handles.get(slot), Some(handle));
    assert_eq!(object_ref_counts(handle.koid), (1, 0));
    process.handles.clear();
    assert!(lookup_object(handle.koid).is_none());
}

#[test]
fn receive_publication_fault_releases_inflight_references() {
    let sender = Process::new("sender");
    let receiver = Process::new("receiver");
    let (slot, handle) = tracked_handle(&sender);
    let moved = sender.handles.remove_many_keep_alive(&[slot]);
    assert!(moved.is_ok());
    let Ok(moved) = moved else {
        return;
    };
    let mut values = [0];
    assert_eq!(
        receiver
            .handles
            .add_existing_many_with_commit(&moved, &mut values, |_| Err::<(), _>(
                ErrorCode::InvalidArgs
            )),
        Err(ErrorCode::InvalidArgs)
    );
    assert!(sender.handles.get(slot).is_none());
    assert!(receiver.handles.get(values[0]).is_none());
    assert_eq!(object_ref_counts(handle.koid), (0, 0));
    assert!(lookup_object(handle.koid).is_none());
}

#[test]
fn peer_closed_send_restores_exact_slot_rights_and_reference_count() {
    let process = Process::new("send-rollback");
    let pair = Channel::pair();
    assert!(pair.is_ok());
    let Ok((sender, peer)) = pair else {
        return;
    };
    drop(peer);
    let (slot, handle) = tracked_handle(&process);
    let moved = process.handles.remove_many_keep_alive(&[slot]);
    assert!(moved.is_ok());
    let Ok(moved) = moved else {
        return;
    };
    let message = ChannelMessage::new(alloc::vec![1, 2, 3], moved);
    assert_eq!(
        send_or_restore(&sender, &process, &[slot], message),
        Err(ErrorCode::PeerClosed)
    );
    assert_eq!(process.handles.get(slot), Some(handle));
    assert_eq!(object_ref_counts(handle.koid), (1, 0));
    process.handles.clear();
    assert!(lookup_object(handle.koid).is_none());
}

#[test]
fn full_queue_send_restores_handle_then_recovers_after_drain() {
    let process = Process::new("queue-rollback");
    let pair = Channel::pair();
    assert!(pair.is_ok());
    let Ok((sender, peer)) = pair else {
        return;
    };
    // Actual bounded queue admission, not a simulated allocator failure.
    for _ in 0..256 {
        assert!(sender
            .send(ChannelMessage::new(alloc::vec![], alloc::vec![]))
            .is_ok());
    }
    let (slot, handle) = tracked_handle(&process);
    let moved = process.handles.remove_many_keep_alive(&[slot]);
    assert!(moved.is_ok());
    let Ok(moved) = moved else {
        return;
    };
    assert_eq!(
        send_or_restore(
            &sender,
            &process,
            &[slot],
            ChannelMessage::new(alloc::vec![], moved)
        ),
        Err(ErrorCode::NoMemory)
    );
    assert_eq!(process.handles.get(slot), Some(handle));
    assert_eq!(object_ref_counts(handle.koid), (1, 0));
    assert!(peer.recv().is_some());
    assert!(sender
        .send(ChannelMessage::new(alloc::vec![], alloc::vec![]))
        .is_ok());
}

#[test]
fn undersized_receive_preserves_message_cookie_and_inflight_handle() {
    let process = Process::new("short-receive");
    let pair = Channel::pair();
    assert!(pair.is_ok());
    let Ok((sender, peer)) = pair else {
        return;
    };
    let (slot, handle) = tracked_handle(&process);
    let moved = process.handles.remove_many_keep_alive(&[slot]);
    assert!(moved.is_ok());
    let Ok(moved) = moved else {
        return;
    };
    assert!(sender
        .send(ChannelMessage::new(alloc::vec![1, 2, 3], moved))
        .is_ok());
    let before = peer.peek();
    assert!(matches!(before, Ok(Some((3, 1, _)))));
    assert!(matches!(
        peer.recv_if_fits(2, 1),
        Err(ChannelRecvError::BytesTooSmall)
    ));
    assert!(matches!(
        peer.recv_if_fits(3, 0),
        Err(ChannelRecvError::HandlesTooSmall)
    ));
    assert_eq!(peer.peek(), before);
    assert_eq!(object_ref_counts(handle.koid), (1, 0));
    let message = peer.recv_if_fits(3, 1);
    assert!(matches!(message, Ok(Some(_))));
    drop(message);
    assert_eq!(object_ref_counts(handle.koid), (0, 0));
    assert!(lookup_object(handle.koid).is_none());
}

#[test]
fn dispatch_rejects_hostile_outputs_before_process_or_paging_access() {
    use huesos_abi::Syscall;
    // These ranges fail ABI bounds before any CR3 access. Do not pass an
    // ordinary host pointer, which would require real kernel page tables.
    let kernel = 0xffff_8000_0000_0000;
    let end = huesos_abi::USER_ASPACE_END;
    let cases = [
        (Syscall::VmoCreate, [4096, kernel, 0, 0, 0]),
        (Syscall::VmoCreate, [4096, end - 2, 0, 0, 0]),
        (Syscall::ChannelCreate, [kernel, kernel + 8, 0, 0, 0]),
        (Syscall::HandleDuplicate, [1, 0, kernel, 0, 0]),
        (Syscall::ProcessCreate, [0, 0, kernel, kernel + 8, 0]),
        (Syscall::PortRead, [1, kernel, 0, 0, 0]),
        (Syscall::VmoRead, [1, 0, kernel, 8, 0]),
    ];
    for (number, [a, b, c, d, e]) in cases {
        assert_eq!(
            crate::dispatch(number as u64, a, b, c, d, e),
            Err(ErrorCode::InvalidArgs),
            "syscall {number:?}"
        );
    }
}

#[test]
fn dispatch_rejects_excessive_sizes_and_unknown_syscalls() {
    use huesos_abi::Syscall;
    assert_eq!(
        crate::dispatch(u64::MAX, 0, 0, 0, 0, 0),
        Err(ErrorCode::NotSupported)
    );
    assert_eq!(
        crate::dispatch(Syscall::VmoCreate as u64, 0, 0, 0, 0, 0),
        Err(ErrorCode::InvalidArgs)
    );
    assert_eq!(
        crate::dispatch(Syscall::VmoCreate as u64, (4u64 << 30) + 1, 0, 0, 0, 0),
        Err(ErrorCode::NoMemory)
    );
    assert_eq!(
        crate::dispatch(Syscall::ChannelWrite as u64, 0, 0, 65537, 0, 0),
        Err(ErrorCode::InvalidArgs)
    );
    assert_eq!(
        crate::dispatch(Syscall::ChannelWrite as u64, 0, 0, 0, 0, 65),
        Err(ErrorCode::InvalidArgs)
    );
    assert_eq!(
        crate::dispatch(Syscall::VmoRead as u64, 0, 0, 0, 1048577, 0),
        Err(ErrorCode::InvalidArgs)
    );
}
