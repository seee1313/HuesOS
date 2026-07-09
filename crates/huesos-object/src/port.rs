//! Port event queue objects.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use spin::Mutex;

use crate::wait::{self, WaitQueue};
use crate::{alloc_koid, KernelObject, Koid, ObjectType};

/// Port — wait queue for async events.
pub struct Port {
    koid: Koid,
    packets: Mutex<Vec<PortPacket>>,
    waiters: WaitQueue,
}

/// A packet queued to a port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortPacket {
    /// Key used to identify the source.
    pub key: u64,
    /// Packet type. Mirrors `huesos_abi::PORT_PACKET_*` values at the syscall
    /// boundary without making this arch-independent crate depend on the ABI
    /// crate.
    pub packet_type: u32,
    /// Status associated with this event.
    pub status: i32,
    /// Fixed-size source-specific payload.
    pub data: [u64; 4],
}

impl Port {
    /// Create a new port.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            packets: Mutex::new(Vec::new()),
            waiters: WaitQueue::new(),
        })
    }

    /// Queue a packet and wake one blocked reader.
    pub fn queue(&self, packet: PortPacket) {
        self.packets.lock().push(packet);
        self.waiters.wake_one();
    }

    /// Read a packet (non-blocking, FIFO order).
    pub fn read(&self) -> Option<PortPacket> {
        let mut q = self.packets.lock();
        if q.is_empty() {
            None
        } else {
            Some(q.remove(0))
        }
    }

    /// Blocking read: park until a packet is available.
    pub fn read_blocking(&self) -> PortPacket {
        self.read_blocking_timeout(0).expect("infinite wait")
    }

    /// Blocking read with timeout in scheduler ticks (`0` = forever).
    pub fn read_blocking_timeout(&self, timeout_ticks: u64) -> Option<PortPacket> {
        use wait::ParkResult;
        if timeout_ticks == 0 {
            loop {
                if let Some(p) = self.read() {
                    return Some(p);
                }
                wait::park_on(&self.waiters);
            }
        }
        loop {
            if let Some(p) = self.read() {
                return Some(p);
            }
            match wait::park_on_timeout(&self.waiters, timeout_ticks) {
                ParkResult::Woken => continue,
                ParkResult::TimedOut => return self.read(),
            }
        }
    }
}

impl KernelObject for Port {
    fn object_type(&self) -> ObjectType {
        ObjectType::Port
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
