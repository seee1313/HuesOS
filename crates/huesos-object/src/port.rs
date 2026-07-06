//! Port event queue objects.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use spin::Mutex;

use crate::{alloc_koid, KernelObject, Koid, ObjectType};

/// Port — wait queue for async events.
pub struct Port {
    koid: Koid,
    packets: Mutex<Vec<PortPacket>>,
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
        })
    }
    /// Queue a packet.
    pub fn queue(&self, packet: PortPacket) {
        self.packets.lock().push(packet);
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
