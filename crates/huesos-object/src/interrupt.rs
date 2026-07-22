//! Interrupt bridge objects.

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::{
    alloc_koid, lookup_object, KernelObject, KernelObjectExt, Koid, ObjectType, Port, PortPacket,
};

/// Binding from an interrupt object to a port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptBinding {
    /// Destination port koid.
    pub port: Koid,
    /// User-supplied key copied into queued packets.
    pub key: u64,
}

/// Interrupt — userspace-visible IRQ bridge object.
pub struct Interrupt {
    koid: Koid,
    irq: u8,
    binding: Mutex<Option<InterruptBinding>>,
    count: AtomicU64,
}

impl Interrupt {
    /// Create a new interrupt object for `irq`.
    pub fn new(irq: u8) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            irq,
            binding: Mutex::new(None),
            count: AtomicU64::new(0),
        })
    }

    /// IRQ number represented by this object.
    pub const fn irq(&self) -> u8 {
        self.irq
    }

    /// Bind this interrupt to `port` with a user-supplied `key`.
    pub fn bind_port(&self, port: Koid, key: u64) {
        *self.binding.lock() = Some(InterruptBinding { port, key });
    }

    /// Signal this interrupt and queue a packet to the bound port, if any.
    pub fn signal(&self, packet_type: u32, data0: u64) {
        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        let Some(binding) = *self.binding.lock() else {
            return;
        };
        let Some(port_obj) = lookup_object(binding.port) else {
            return;
        };
        let Some(port) = port_obj.downcast_ref::<Port>() else {
            return;
        };
        let _ = port.queue(PortPacket {
            key: binding.key,
            packet_type,
            status: 0,
            data: [self.irq as u64, data0, count, 0],
        });
    }

    /// Number of times this interrupt object has been signalled.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl KernelObject for Interrupt {
    fn object_type(&self) -> ObjectType {
        ObjectType::Interrupt
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
