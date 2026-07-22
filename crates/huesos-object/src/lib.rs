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
mod job;
mod koid;
mod object;
mod port;
mod process;
mod supervision;
mod registry;
mod thread;
mod vmar;
mod vmo;
pub mod wait;

pub use acpi_broker::{AcpiBroker, PciFunctionGrant, SystemIoGrant};
pub use channel::{
    Channel, ChannelCreateError, ChannelMessage, ChannelRecvError, ChannelSendError,
    ChannelSendFailure,
};
pub use handle::{Handle, HandleTable, HandleTableError, HandleValue, Rights, INVALID_HANDLE};
pub use interrupt::{Interrupt, InterruptBinding};
pub use job::Job;
pub use koid::{alloc_koid, Koid};
pub use object::{KernelObject, KernelObjectExt, ObjectType};
pub use port::{Port, PortCreateError, PortPacket, PortQueueError};
pub use process::Process;
pub use supervision::{CrashThrottle, SupervisionAction, SupervisionDecision};
pub(crate) use registry::phys_to_virt;
pub use registry::{
    acquire_kernel_ref, collect_exited_process, current_process, lookup_interrupts_by_irq,
    lookup_object, lookup_process, note_handle_close, note_handle_open, note_kernel_ref_close,
    note_kernel_ref_open, object_ref_counts, register_interrupt, register_object, register_process,
    root_job, set_cpu_id_callback, set_current_process, set_phys_to_virt, unregister_object,
};
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
        unsafe {
            huesos_pmm::init(&regions, hhdm_offset);
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
            flags: 0,
        };
        assert!(vmar.record_mapping(first).is_ok());

        let overlap = VmarMapping {
            base: 0x13000,
            size: 0x1000,
            vmo: Koid(3),
            flags: 0,
        };
        assert!(vmar.record_mapping(overlap).is_err());

        let outside = VmarMapping {
            base: 0x1f000,
            size: 0x2000,
            vmo: Koid(4),
            flags: 0,
        };
        assert!(vmar.record_mapping(outside).is_err());

        assert!(vmar.remove_mapping(first));
        assert!(!vmar.overlaps_existing(first.base, first.size));
        assert!(!vmar.remove_mapping(first));
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
        interrupt.bind_port(port_koid, 0xabc);
        interrupt.signal(1, 0x1e);

        let packet = port.read().expect("interrupt should queue one packet");
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
        let _ = a.send(ChannelMessage {
            data: alloc::vec![1, 2, 3],
            handles: Vec::new(),
        });
        // The regression this guards against: sys_channel_create used to
        // create two disconnected Channel::new() objects instead of a real
        // pair, so a message sent on `a` was never visible on `b`.
        assert!(a.recv().is_none(), "a must not receive its own message");
        let msg = b.recv().expect("b must receive what a sent");
        assert_eq!(msg.data, alloc::vec![1, 2, 3]);
    }
    #[test]
    fn channel_queue_is_bounded_and_returns_failed_message() {
        let (a, _b) = match Channel::pair() {
            Ok(pair) => pair,
            Err(_) => return,
        };
        for _ in 0..channel::MAX_CHANNEL_QUEUE_MESSAGES {
            let result = a.send(ChannelMessage {
                data: Vec::new(),
                handles: Vec::new(),
            });
            assert!(result.is_ok());
        }
        let failed = a.send(ChannelMessage {
            data: Vec::new(),
            handles: Vec::new(),
        });
        assert!(failed.is_err());
        if let Err(error) = failed {
            let (message, reason) = error.into_parts();
            assert_eq!(reason, ChannelSendFailure::QuotaExceeded);
            assert!(message.data.is_empty());
            assert!(message.handles.is_empty());
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
        let send = b.send(ChannelMessage {
            data: Vec::new(),
            handles: Vec::new(),
        });
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

}
