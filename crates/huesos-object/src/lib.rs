//! # HuesOS Kernel Object Subsystem
//!
//! Object-centric design in the spirit of Zircon: everything is a Kernel
//! Object. Userspace references them via Handles (capabilities with rights).

#![no_std]
#![warn(missing_docs)]
#![allow(dead_code)] // `name` fields are reserved for future GET_PROPERTY/SET_PROPERTY syscalls

extern crate alloc;

mod acpi_broker;
mod channel;
mod handle;
mod interrupt;
mod irq_guard;
mod job;
mod koid;
mod object;
mod port;
mod process;
mod registry;
mod resource;
mod signal;
mod supervision;
mod thread;
mod vmar;
mod vmo;
pub mod wait;

pub use acpi_broker::{AcpiBroker, PciFunctionGrant, SystemIoGrant};
pub use channel::{
    Channel, ChannelCreateError, ChannelMessage, ChannelRecvError, ChannelSendError,
    ChannelSendFailure, CHANNEL_INLINE_BYTES, CHANNEL_INLINE_HANDLES,
};
pub use handle::{Handle, HandleTable, HandleTableError, HandleValue, Rights, INVALID_HANDLE};
pub use interrupt::{Interrupt, InterruptBinding};
pub use job::{flush_pending_quota_notifications, Job};
pub use koid::{alloc_koid, Koid};
pub use object::{KernelObject, KernelObjectExt, ObjectType};
pub use port::{Port, PortCreateError, PortPacket, PortQueueError};
pub use process::{Process, ProcessExitPortError};
pub(crate) use registry::phys_to_virt;
pub use registry::{
    acquire_kernel_ref, collect_exited_process, current_process, lookup_interrupts_by_irq,
    lookup_object, lookup_process, note_handle_close, note_handle_open, note_kernel_ref_close,
    note_kernel_ref_open, object_ref_counts, register_interrupt, register_object, register_process,
    root_job, set_cpu_id_callback, set_current_process, set_phys_to_virt, unregister_object,
};
pub use resource::{Resource, ResourceError, ResourceKind};
pub use signal::Signal;
pub use supervision::{CrashThrottle, SupervisionAction, SupervisionDecision};
pub use thread::Thread;
pub use vmar::{Vmar, VmarChild, VmarError, VmarMapping};
pub use vmo::{Vmo, VmoError};
pub use wait::{set_scheduler_hooks, TaskId, WaitQueue};

/// Initialize root job and kernel objects. Does not set up the
/// phys-to-virt translator; call [`set_phys_to_virt`] separately once
/// paging is initialized.
pub fn init() {
    let root = Job::root();
    registry::set_root_job(root.clone());
    register_object(root);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};
    use spin::Mutex;
    use std::vec;

    // Like huesos-pmm's own tests, these run against the real global PMM
    // and phys_to_virt state, so they're serialized with a lock and each
    // sets up a fresh PMM backed by a real heap buffer treated as if
    // address 0 were that buffer's address (hhdm_offset = buffer's addr,
    // phys_to_virt = identity + hhdm_offset).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_fresh_env<R>(total_bytes: u64, f: impl FnOnce() -> R) -> R {
        let _guard = TEST_LOCK.lock();
        let mut backing = vec![0u8; total_bytes as usize];
        let hhdm_offset = backing.as_mut_ptr() as u64;
        let regions = [huesos_pmm::MemoryRegion {
            base: 0,
            length: total_bytes,
            usable: true,
            kind: 0,
        }];
        // SAFETY: single-threaded test-only bring-up of the PMM; the test
        // lock upstream serializes concurrent runs.
        match unsafe { huesos_pmm::init(&regions, hhdm_offset) } {
            Ok(()) => {}
            Err(error) => {
                // In tests we treat this as a fixture failure; assert! is
                // budget-allowed while unwrap/expect are not.
                assert!(false, "test PMM init unexpectedly failed: {error:?}");
                return f();
            }
        }
        // `set_phys_to_virt` only accepts a plain `fn` (no captures), so we
        // route the per-test hhdm_offset through a static instead of a
        // closure.
        TEST_HHDM_OFFSET.store(hhdm_offset, Ordering::SeqCst);
        set_phys_to_virt(|phys| TEST_HHDM_OFFSET.load(Ordering::SeqCst) + phys);
        f()
    }

    static TEST_HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn vmo_create_read_write_roundtrip() {
        with_fresh_env(1024 * 1024, || {
            let vmo = Vmo::new(100).expect("small VMO should always succeed");
            let payload = b"hello vmo";
            let written = vmo.write(0, payload);
            assert_eq!(written, payload.len());

            let mut readback = [0u8; 9];
            let read = vmo.read(0, &mut readback);
            assert_eq!(read, payload.len());
            assert_eq!(&readback, payload);
        });
    }

    #[test]
    fn vmo_create_fails_gracefully_on_oom_instead_of_panicking() {
        // A tiny backing pool: a handful of frames plus whatever the PMM's
        // own bitmap consumes. Requesting a VMO far bigger than that must
        // return Err, not panic/abort the process (which, in the real
        // kernel, means "not take down the whole machine").
        with_fresh_env(huesos_pmm::FRAME_SIZE * 4, || {
            let huge = Vmo::new(1024 * 1024 * 1024); // 1 GiB, way more than 4 frames
            assert!(
                huge.is_err(),
                "oversized VMO allocation should fail cleanly"
            );

            // The PMM must not have leaked partial allocations from the
            // failed attempt: we should still be able to allocate whatever
            // frames were actually available.
            let free_before = huesos_pmm::free_frames();
            assert!(free_before > 0, "failed VMO::new must not leak frames");
        });
    }

    #[test]
    fn vmo_set_size_grows_and_fails_gracefully_on_oom() {
        with_fresh_env(huesos_pmm::FRAME_SIZE * 8, || {
            let vmo = Vmo::new(4096).expect("initial small VMO should succeed");
            assert_eq!(vmo.size(), 4096);

            // Grow within available memory.
            vmo.set_size(3 * 4096)
                .expect("growing within budget should succeed");
            assert_eq!(vmo.size(), 3 * 4096);

            // Now try to grow far beyond what's left; must fail cleanly,
            // not panic, and must leave the VMO at a consistent (if
            // smaller-than-requested) size rather than corrupt state.
            let result = vmo.set_size(10 * 1024 * 1024);
            assert!(result.is_err());
            assert!(
                vmo.size() >= 3 * 4096,
                "size must not regress below what succeeded"
            );
        });
    }

    #[test]
    fn vmar_rejects_out_of_range_and_overlapping_mappings() {
        let vmar = Vmar::new_root(Koid(1), 0x10000, 0x10000);
        let first = VmarMapping {
            base: 0x12000,
            size: 0x2000,
            vmo: Koid(2),
            vmo_offset: 0,
            flags: 0,
        };
        assert!(vmar.record_mapping(first).is_ok());

        let overlap = VmarMapping {
            base: 0x13000,
            size: 0x1000,
            vmo: Koid(3),
            vmo_offset: 0,
            flags: 0,
        };
        assert!(vmar.record_mapping(overlap).is_err());

        let outside = VmarMapping {
            base: 0x1f000,
            size: 0x2000,
            vmo: Koid(4),
            vmo_offset: 0,
            flags: 0,
        };
        assert!(vmar.record_mapping(outside).is_err());

        assert!(vmar.remove_mapping(first));
        assert!(!vmar.overlaps_existing(first.base, first.size));
        assert!(!vmar.remove_mapping(first));
    }

    #[test]
    fn vmar_children_reserve_parent_ranges_and_mappings_can_split() {
        let parent = Vmar::new_root(Koid(1), 0x10000, 0x10000);
        let child = Vmar::new_child(&parent, 0x14000, 0x2000);
        let reservation = VmarChild {
            koid: child.koid(),
            base: child.base(),
            size: child.size(),
        };
        assert!(parent.record_child(reservation).is_ok());
        assert!(parent
            .record_mapping(VmarMapping {
                base: 0x14000,
                size: 0x1000,
                vmo: Koid(2),
                vmo_offset: 0,
                flags: 0,
            })
            .is_err());

        let mapping = VmarMapping {
            base: 0x11000,
            size: 0x3000,
            vmo: Koid(3),
            vmo_offset: 0,
            flags: 1,
        };
        assert!(parent.record_mapping(mapping).is_ok());
        assert_eq!(parent.mapping_covering(0x12000, 0x1000), Some(mapping));
        let replacements = [
            VmarMapping {
                base: 0x11000,
                size: 0x1000,
                vmo: Koid(3),
                vmo_offset: 0,
                flags: 1,
            },
            VmarMapping {
                base: 0x13000,
                size: 0x1000,
                vmo: Koid(3),
                vmo_offset: 0x2000,
                flags: 1,
            },
        ];
        assert!(parent.replace_mapping(mapping, &replacements).is_ok());
        assert!(parent.mapping(0x12000, 0x1000).is_none());
        assert!(parent.mapping(0x11000, 0x1000).is_some());
        assert!(parent.remove_child(child.koid()));
    }

    #[test]
    fn process_scheduler_flags_are_created_state_only() {
        let process = Process::new("sched-flags");
        assert_eq!(process.scheduler_flags(), 0);
        assert!(process.set_scheduler_flags(1, 1));
        assert_eq!(process.scheduler_flags(), 1);
        assert!(!process.set_scheduler_flags(2, 1));
        assert!(process.start());
        assert!(!process.set_scheduler_flags(0, 1));
        assert_eq!(process.scheduler_flags(), 1);
    }

    #[test]
    fn process_exit_queues_bound_port_packet() {
        let process = Process::new("watched");
        let port = match Port::new() {
            Ok(port) => port,
            Err(_) => return,
        };
        assert!(process.bind_exit_port(port.clone(), 0xCAFE).is_ok());
        assert!(process.set_exit_code(42));
        let packet = port.read();
        assert!(packet.is_some(), "exit should queue a packet");
        if let Some(packet) = packet {
            assert_eq!(packet.key, 0xCAFE);
            assert_eq!(packet.packet_type, 2);
            assert_eq!(packet.data[0], process.koid().0);
            assert_eq!(packet.data[2], 42);
        }
    }

    #[test]
    fn failed_child_vmar_reservation_releases_parent_kernel_ref() {
        let parent = Vmar::new_root(Koid(100), 0x1000, 0x4000);
        let parent_koid = parent.koid();
        register_object(parent.clone());
        assert!(parent
            .record_child(VmarChild {
                koid: Koid(200),
                base: 0x1000,
                size: 0x1000,
            })
            .is_ok());

        let Some(_parent_ref) = acquire_kernel_ref(parent_koid) else {
            assert!(false, "registered VMAR must acquire a kernel ref");
            return;
        };
        assert_eq!(object_ref_counts(parent_koid), (0, 1));
        let child = Vmar::new_child(&parent, 0x1000, 0x1000);
        assert!(parent
            .record_child(VmarChild {
                koid: child.koid(),
                base: child.base(),
                size: child.size(),
            })
            .is_err());
        drop(child);
        assert_eq!(object_ref_counts(parent_koid), (0, 0));
        unregister_object(parent_koid);
    }

    #[test]
    fn signal_is_level_triggered() {
        let signal = Signal::new();
        assert_eq!(signal.object_type(), ObjectType::Signal);
        assert!(!signal.is_signaled());
        signal.set();
        assert!(signal.is_signaled());
        signal.set();
        assert!(signal.is_signaled());
        signal.clear();
        assert!(!signal.is_signaled());
    }

    #[test]
    fn interrupt_signal_queues_port_packet() {
        let port = match Port::new() {
            Ok(port) => port,
            Err(_) => return,
        };
        let port_koid = port.koid();
        register_object(port.clone());

        let interrupt = Interrupt::new(1);
        interrupt.bind_port(port.clone(), 0xabc);
        interrupt.signal(1, 0x1e);

        let Some(packet) = port.read() else {
            assert!(false, "interrupt should queue one packet");
            unregister_object(port_koid);
            return;
        };
        assert_eq!(packet.key, 0xabc);
        assert_eq!(packet.packet_type, 1);
        assert_eq!(packet.data[0], 1);
        assert_eq!(packet.data[1], 0x1e);
        assert_eq!(packet.data[2], 1);

        unregister_object(port_koid);
    }

    #[test]
    fn register_process_populates_typed_registry() {
        let process = Process::new("typed-registry-test");
        let koid = process.koid();
        register_process(process);
        assert!(lookup_process(koid).is_some());
        unregister_object(koid);
        assert!(lookup_process(koid).is_none());
    }

    #[test]
    fn process_name_can_be_copied_without_allocation() {
        let process = Process::new("fault-reporter");
        let mut buffer = [0u8; 8];
        let count = process.copy_name(&mut buffer);
        assert_eq!(count, 8);
        assert_eq!(&buffer, b"fault-re");
    }

    #[test]
    fn thread_records_owning_process() {
        let thread = Thread::new_for_process("worker", Koid(123));
        assert_eq!(thread.process(), Koid(123));
        assert_eq!(*thread.task_id.lock(), None);
    }

    #[test]
    fn final_handle_close_collects_vmo_and_returns_frames() {
        with_fresh_env(huesos_pmm::FRAME_SIZE * 16, || {
            let free_before = huesos_pmm::free_frames();
            let vmo = Vmo::new(4096).expect("one-page VMO");
            let koid = vmo.koid();
            register_object(vmo);
            let table = HandleTable::new();
            let value = table.add(Handle::new(koid, Rights::DEFAULT_VMO));
            assert_eq!(huesos_pmm::free_frames(), free_before - 1);
            assert!(lookup_object(koid).is_some());

            table.remove(value).expect("live handle");
            assert!(lookup_object(koid).is_none());
            assert_eq!(huesos_pmm::free_frames(), free_before);
        });
    }

    #[test]
    fn kernel_mapping_reference_keeps_vmo_alive_after_handle_close() {
        with_fresh_env(huesos_pmm::FRAME_SIZE * 16, || {
            let free_before = huesos_pmm::free_frames();
            let vmo = Vmo::new(4096).expect("one-page VMO");
            let koid = vmo.koid();
            register_object(vmo);
            let table = HandleTable::new();
            let value = table.add(Handle::new(koid, Rights::DEFAULT_VMO));
            note_kernel_ref_open(koid);

            table.remove(value).expect("live handle");
            assert!(lookup_object(koid).is_some());
            assert_eq!(huesos_pmm::free_frames(), free_before - 1);

            note_kernel_ref_close(koid);
            assert_eq!(object_ref_counts(koid), (0, 0));
            assert!(lookup_object(koid).is_none());
            assert_eq!(huesos_pmm::free_frames(), free_before);
        });
    }

    #[test]
    fn once_collected_object_stays_gone_and_ignores_stale_notes() {
        // Regression for the RefAccount migration: once try_collect succeeds
        // in the registry, further note_handle_open / note_kernel_ref_open
        // calls for the same koid must not resurrect the account. This is
        // what protects against ABA-style stale-koid bugs after slot reuse.
        //
        // Written without unwrap / expect per CONTRIBUTING rule 1; asserts
        // are the budget-allowed diagnostic and `return` after them keeps
        // the type flow sound for the remainder of the closure.
        with_fresh_env(huesos_pmm::FRAME_SIZE * 16, || {
            let free_before = huesos_pmm::free_frames();
            let Ok(vmo) = Vmo::new(4096) else {
                assert!(false, "one-page VMO must allocate in test fixture");
                return;
            };
            let koid = vmo.koid();
            register_object(vmo);
            let table = HandleTable::new();
            let value = table.add(Handle::new(koid, Rights::DEFAULT_VMO));

            assert!(table.remove(value).is_some(), "live handle must remove");
            assert!(lookup_object(koid).is_none());
            assert_eq!(object_ref_counts(koid), (0, 0));
            assert_eq!(huesos_pmm::free_frames(), free_before);

            // A stale note_handle_open must be a no-op: the account is
            // gone, the object is gone, and lookup must stay None.
            note_handle_open(koid);
            note_kernel_ref_open(koid);
            assert_eq!(object_ref_counts(koid), (0, 0));
            assert!(lookup_object(koid).is_none());
            assert_eq!(huesos_pmm::free_frames(), free_before);
        });
    }

    #[test]
    fn handle_table_can_insert_at_fixed_slot() {
        let table = HandleTable::new();
        let h = Handle::new(alloc_koid(), Rights::DEFAULT);
        assert!(table.insert_at(3, h).is_ok());
        assert_eq!(table.get(3), Some(h));
        assert!(table.insert_at(3, h).is_err());
        assert!(table.insert_at(INVALID_HANDLE, h).is_err());
    }

    #[test]
    fn handle_table_reserves_slot_zero_as_invalid() {
        let table = HandleTable::new();
        let h = Handle::new(alloc_koid(), Rights::DEFAULT);
        let hv = table.add(h);
        assert_ne!(
            hv, INVALID_HANDLE,
            "first real handle must not be INVALID_HANDLE (0)"
        );
        assert_eq!(table.get(hv), Some(h));
        assert_eq!(table.get(INVALID_HANDLE), None);
    }

    #[test]
    fn handle_table_reuses_freed_slots() {
        let table = HandleTable::new();
        let h1 = table.add(Handle::new(alloc_koid(), Rights::DEFAULT));
        let _h2 = table.add(Handle::new(alloc_koid(), Rights::DEFAULT));
        table.remove(h1);
        let h3 = table.add(Handle::new(alloc_koid(), Rights::DEFAULT));
        assert_eq!(h3, h1, "freed handle slots should be reused, not leaked");
    }

    #[test]
    fn channel_pair_delivers_messages_to_the_peer_not_the_sender() {
        let (a, b) = match Channel::pair() {
            Ok(pair) => pair,
            Err(_) => return,
        };
        let _ = a.send(ChannelMessage::new(alloc::vec![1, 2, 3], Vec::new()));
        // The regression this guards against: sys_channel_create used to
        // create two disconnected Channel::new() objects instead of a real
        // pair, so a message sent on `a` was never visible on `b`.
        assert!(a.recv().is_none(), "a must not receive its own message");
        let msg = b.recv().expect("b must receive what a sent");
        assert_eq!(msg.data(), &[1, 2, 3]);
    }
    #[test]
    fn channel_queue_is_bounded_and_returns_failed_message() {
        let (a, _b) = match Channel::pair() {
            Ok(pair) => pair,
            Err(_) => return,
        };
        for _ in 0..channel::MAX_CHANNEL_QUEUE_MESSAGES {
            let result = a.send(ChannelMessage::new(Vec::new(), Vec::new()));
            assert!(result.is_ok());
        }
        let failed = a.send(ChannelMessage::new(Vec::new(), Vec::new()));
        assert!(failed.is_err());
        if let Err(error) = failed {
            let (message, reason) = error.into_parts();
            assert_eq!(reason, ChannelSendFailure::QuotaExceeded);
            assert_eq!(message.data_len(), 0);
            assert_eq!(message.handle_count(), 0);
        }
    }

    #[test]
    fn port_queue_is_bounded_without_irq_allocation() {
        let port = match Port::new() {
            Ok(port) => port,
            Err(_) => return,
        };
        let packet = PortPacket {
            key: 1,
            packet_type: 1,
            status: 0,
            data: [0; 4],
        };
        for _ in 0..port::MAX_PORT_PACKETS {
            assert!(port.queue(packet).is_ok());
        }
        assert_eq!(port.queue(packet), Err(PortQueueError::QuotaExceeded));
        assert_eq!(port.dropped_packets(), 1);
    }

    #[test]
    fn port_has_pending_is_non_destructive() {
        // Regression: the WaitSetWait signal probe in
        // huesos-syscalls used to call port.read() during ready
        // checks, which dequeued the packet and threw it away.
        // The result was that every IRQ delivered while a driver
        // was parked in wait_any got consumed by the kernel and
        // never surfaced to the driver — keystrokes vanished
        // between the input host and its consumers. `has_pending`
        // is the non-destructive replacement used by the fix.
        let port = match Port::new() {
            Ok(port) => port,
            Err(_) => return,
        };
        assert!(!port.has_pending(), "fresh port has no packets");

        let packet = PortPacket {
            key: 0xdead,
            packet_type: 1,
            status: 0,
            data: [0xaa, 0xbb, 0xcc, 0xdd],
        };
        assert!(port.queue(packet).is_ok());

        // Probing readiness must NEVER consume the packet, no matter
        // how many times it's called (the syscall handler polls in
        // a loop while waiting).
        assert!(port.has_pending());
        assert!(port.has_pending());
        assert!(port.has_pending());

        // After all those probes the actual read still returns the
        // original packet — proof no probe silently drained it.
        let Some(read_back) = port.read() else {
            assert!(false, "read must still see the packet");
            return;
        };
        assert_eq!(read_back.key, 0xdead);
        assert_eq!(read_back.data[0], 0xaa);
        assert!(!port.has_pending(), "after real read, port is empty");
    }

    #[test]
    fn batch_handle_move_validates_before_mutating() {
        let table = HandleTable::new();
        let first = table.add(Handle::new(alloc_koid(), Rights::DEFAULT));
        let result = table.remove_many_keep_alive(&[first, first + 100]);
        assert_eq!(result, Err(HandleTableError::Missing));
        assert!(table.get(first).is_some());
        let duplicate = table.remove_many_keep_alive(&[first, first]);
        assert_eq!(duplicate, Err(HandleTableError::Duplicate));
        assert!(table.get(first).is_some());
    }

    #[test]
    fn channel_peer_close_is_observable_and_rejects_send() {
        let (a, b) = match Channel::pair() {
            Ok(pair) => pair,
            Err(_) => return,
        };
        drop(a);
        assert!(b.peer_closed());
        let send = b.send(ChannelMessage::new(Vec::new(), Vec::new()));
        assert!(send.is_err());
        if let Err(error) = send {
            let (_message, reason) = error.into_parts();
            assert_eq!(reason, ChannelSendFailure::PeerClosed);
        }
        assert!(matches!(
            b.recv_if_fits(0, 0),
            Err(ChannelRecvError::PeerClosed)
        ));
    }

    #[test]
    fn process_object_drives_lifecycle_policy_and_reap_waiters() {
        let process = Process::new("lifecycle");
        assert!(process.start());
        assert!(!process.start());
        assert!(process.add_exit_waiter());
        assert!(process.set_exit_code(17));
        assert_eq!(process.exit_code(), Some(17));
        assert!(!process.can_reap());
        assert!(process.exit_info().is_some());
        process.remove_exit_waiter();
        assert_eq!(
            process.lifecycle_state(),
            huesos_proclife::ProcState::Reaped
        );
        assert!(!process.set_exit_code(18));
    }

    #[test]
    fn vmo_memory_charge_is_released_on_drop() {
        with_fresh_env(huesos_pmm::FRAME_SIZE * 16, || {
            let job = Job::root_with_limits(huesos_quota::Limits {
                max_memory: huesos_pmm::FRAME_SIZE,
                max_handles: huesos_quota::UNLIMITED,
                max_cpu_ticks: huesos_quota::UNLIMITED,
            });
            let vmo = match Vmo::new_in_job(4096, Some(job.clone())) {
                Ok(vmo) => vmo,
                Err(_) => return,
            };
            assert_eq!(job.usage().map(|usage| usage.memory), Ok(4096));
            drop(vmo);
            assert_eq!(job.usage().map(|usage| usage.memory), Ok(0));
            assert!(Vmo::new_in_job(8192, Some(job)).is_err());
        });
    }
}
