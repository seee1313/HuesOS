//! Regressions against actual Process/ProcessWait objects, without scheduler mocks.
extern crate std;

use super::{Process, ProcessWait};
use crate::{object_ref_counts, register_object, KernelObject, Port};
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use huesos_lifecycle::{InsertOutcome, TaskGraveyard};
use huesos_proclife::ProcState;
use std::sync::Barrier;
use std::task::Wake;

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn exit_before_first_poll_and_repeated_waits_keep_original_status() {
    let process = Process::new("late-waits");
    assert!(process.set_exit_code(-17));
    let before = process.exit_info();
    assert!(before.is_some());
    assert_eq!(process.lifecycle_state(), ProcState::Reaped);
    assert!(!process.add_exit_waiter());
    assert!(!process.set_exit_code(99));
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    for _ in 0..32 {
        let mut wait = ProcessWait::new(&process);
        assert_eq!(Pin::new(&mut wait).poll(&mut cx), Poll::Ready(-17));
        assert_eq!(Pin::new(&mut wait).poll(&mut cx), Poll::Ready(-17));
    }
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    assert_eq!(process.exit_info(), before);
    assert_eq!(process.lifecycle.lock().waiter_count(), 0);
}

#[test]
fn pending_async_waits_wake_once_per_distinct_waker() {
    let process = Process::new("async-waits");
    assert!(process.start());
    let a = Arc::new(WakeCount::default());
    let b = Arc::new(WakeCount::default());
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    let mut ca = Context::from_waker(&wa);
    let mut cb = Context::from_waker(&wb);
    let mut first = ProcessWait::new(&process);
    let mut second = ProcessWait::new(&process);
    for _ in 0..16 {
        assert_eq!(Pin::new(&mut first).poll(&mut ca), Poll::Pending);
        assert_eq!(Pin::new(&mut second).poll(&mut cb), Poll::Pending);
    }
    assert!(process.set_exit_code(i64::MIN));
    assert_eq!(a.0.load(Ordering::SeqCst), 1);
    assert_eq!(b.0.load(Ordering::SeqCst), 1);
    assert_eq!(Pin::new(&mut first).poll(&mut ca), Poll::Ready(i64::MIN));
    assert_eq!(Pin::new(&mut second).poll(&mut cb), Poll::Ready(i64::MIN));
    assert!(!process.set_exit_code(0));
    assert_eq!(a.0.load(Ordering::SeqCst), 1);
    assert_eq!(b.0.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_of_counted_waiter_before_exit_does_not_pin_reaping() {
    let process = Process::new("cancel-counted-wait");
    assert!(process.start());
    assert!(process.add_exit_waiter());
    assert!(process.add_exit_waiter());
    process.remove_exit_waiter();
    assert_eq!(process.lifecycle.lock().waiter_count(), 1);
    assert!(process.set_exit_code(7));
    assert_eq!(process.lifecycle_state(), ProcState::Exited);
    process.remove_exit_waiter();
    assert_eq!(process.lifecycle_state(), ProcState::Reaped);
    process.remove_exit_waiter();
    assert_eq!(process.lifecycle.lock().waiter_count(), 0);
    assert_eq!(process.exit_code(), Some(7));
}

#[test]
fn concurrent_counted_waiters_release_only_the_last_reap_gate() {
    let process = Process::new("parallel-waiters");
    assert!(process.start());
    let ready = Barrier::new(9);
    let exited = Barrier::new(9);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                let registered = process.add_exit_waiter();
                ready.wait();
                exited.wait();
                // Assert only after both barriers, so a regression does not
                // strand the parent or another observer at a rendezvous.
                assert!(registered);
                assert_eq!(process.exit_code(), Some(-9));
                process.remove_exit_waiter();
            });
        }
        ready.wait();
        let waiter_count = process.lifecycle.lock().waiter_count();
        let transitioned = process.set_exit_code(-9);
        let state_before_release = process.lifecycle_state();
        let reap_before_release = process.can_reap();
        exited.wait();
        assert_eq!(waiter_count, 8);
        assert!(transitioned);
        assert_eq!(state_before_release, ProcState::Exited);
        assert!(!reap_before_release);
    });
    assert_eq!(process.lifecycle.lock().waiter_count(), 0);
    assert_eq!(process.lifecycle_state(), ProcState::Reaped);
    assert!(!process.add_exit_waiter());
}

#[test]
fn concurrent_exit_attempts_publish_one_immutable_exit() {
    let process = Process::new("exit-once");
    assert!(process.start());
    let gate = Barrier::new(8);
    let winners = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for code in 0..8 {
            let gate = &gate;
            let winners = &winners;
            let process = &process;
            scope.spawn(move || {
                gate.wait();
                if process.set_exit_code(code) {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(winners.load(Ordering::SeqCst), 1);
    let info = process.exit_info();
    assert!(info.is_some_and(|info| (0..8).contains(&info.exit_code)));
    assert!(!process.set_exit_code(-1));
    assert_eq!(process.exit_info(), info);
}

#[test]
fn early_and_late_exit_ports_deliver_same_generation_and_first_status() {
    let process = Process::new("exit-port-observers");
    let port = Port::new();
    assert!(port.is_ok());
    let Ok(port) = port else {
        return;
    };
    let id = port.koid();
    register_object(port.clone());
    assert!(process.bind_exit_port(port.clone(), 10).is_ok());
    assert!(process.bind_exit_port(port.clone(), 20).is_ok());
    assert_eq!(object_ref_counts(id), (0, 2));
    assert!(process.set_exit_code(-42));
    let info = process.exit_info();
    assert!(info.is_some());
    let Some(info) = info else {
        return;
    };
    assert!(!process.set_exit_code(42));
    assert!(process.bind_exit_port(port.clone(), 30).is_ok());
    for key in [10, 20, 30] {
        let packet = port.read();
        assert!(packet.is_some());
        let Some(packet) = packet else {
            return;
        };
        assert_eq!(packet.key, key);
        assert_eq!(packet.packet_type, huesos_abi::PORT_PACKET_PROCESS_EXIT);
        assert_eq!(packet.status, 0);
        assert_eq!(
            packet.data,
            [info.koid, info.generation, (-42i64) as u64, 0]
        );
    }
    assert!(port.read().is_none());
    drop(process);
    assert_eq!(object_ref_counts(id), (0, 0));
    assert!(crate::lookup_object(id).is_none());
}

#[test]
fn actual_process_exit_identity_survives_graveyard_overflow() {
    let mut yard = TaskGraveyard::<256>::new();
    for sequence in 0..4096 {
        let process = Process::new("graveyard-churn");
        assert!(process.start());
        assert!(process.set_exit_code(sequence));
        let info = process.exit_info();
        assert!(info.is_some());
        let Some(info) = info else {
            return;
        };
        let (record, outcome) = yard.record_exit_with_generation(
            info.koid,
            info.generation,
            info.exit_code,
            sequence as u64,
        );
        assert!(process.observed_exit_generation(record.generation));
        assert!(!process.observed_exit_generation(record.generation + 1));
        assert_eq!(yard.find(info.koid, info.generation), Some(record));
        if sequence < 256 {
            assert_eq!(outcome, InsertOutcome::Retained);
        } else {
            assert!(
                matches!(outcome, InsertOutcome::Evicted(old) if old.exit_code == sequence - 256)
            );
        }
        assert!(yard.len() <= 256);
        assert_eq!(
            yard.total_recorded(),
            yard.total_evicted() + yard.total_reaped() + yard.len() as u64
        );
    }
    assert_eq!(yard.total_recorded(), 4096);
    assert_eq!(yard.total_evicted(), 3840);
    assert_eq!(yard.reap_waited(|_, _| true), 256);
    assert!(yard.is_empty());
    assert_eq!(yard.total_reaped(), 256);
}
