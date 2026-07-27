//! Interrupt bridge objects.

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::irq_guard::IrqSafeMutex;
use crate::{alloc_koid, KernelObject, Koid, ObjectType, Port, PortPacket};

/// Binding from an interrupt object to a port.
///
/// Holds an owning `Arc<Port>` (not just its `Koid`) so the IRQ handler's
/// `signal()` never needs to consult the global object registry. This is
/// the seL4-style minimization of the IRQ critical section: the registry
/// lookup is only ever needed once, at `bind_port` time (ordinary syscall
/// context), not on every interrupt.
#[derive(Clone)]
pub struct InterruptBinding {
    /// The bound port, held alive independently of userspace handles.
    port: Arc<Port>,
    /// User-supplied key copied into queued packets.
    key: u64,
}

/// Interrupt — userspace-visible IRQ bridge object.
pub struct Interrupt {
    koid: Koid,
    irq: u8,
    binding: IrqSafeMutex<Option<InterruptBinding>>,
    count: AtomicU64,
}

impl Interrupt {
    /// Create a new interrupt object for `irq`.
    pub fn new(irq: u8) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            irq,
            binding: IrqSafeMutex::new(None),
            count: AtomicU64::new(0),
        })
    }

    /// IRQ number represented by this object.
    pub const fn irq(&self) -> u8 {
        self.irq
    }

    /// Bind this interrupt to `port` with a user-supplied `key`.
    ///
    /// Called from ordinary syscall context (`Syscall::InterruptBindPort`).
    /// This is the only place that needs the target `Port`'s `Arc`; `signal`
    /// below never looks it up again, so the IRQ handler's critical section
    /// never touches the object registry.
    pub fn bind_port(&self, port: Arc<Port>, key: u64) {
        *self.binding.lock() = Some(InterruptBinding { port, key });
    }

    /// Signal this interrupt and queue a packet to the bound port, if any.
    ///
    /// Called from the IRQ handler. `binding` is an `IrqSafeMutex`, so this
    /// cannot self-deadlock a CPU whose syscall context (`bind_port`)
    /// already holds it when an interrupt lands (see `crate::irq_guard`).
    /// The clone below is a cheap `Arc` refcount bump, not a registry
    /// lookup — the port itself is looked up once, at bind time.
    pub fn signal(&self, packet_type: u32, data0: u64) {
        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        let Some(binding) = self.binding.lock().clone() else {
            return;
        };
        let _ = binding.port.queue(PortPacket {
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
