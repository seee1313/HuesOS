//! Interrupt bridge objects and route-lifetime hooks.

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::irq_guard::IrqSafeMutex;
use crate::{alloc_koid, KernelObject, Koid, ObjectType, Port, PortPacket};

/// How an interrupt object's numeric key is interpreted by the architecture
/// interrupt router and IRQ event bridge.
pub use huesos_abi::InterruptEventKind as InterruptRouteKind;

/// Failure while binding an interrupt object to its device route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptBindError {
    /// The architecture has no safe route for this IRQ/GSI on this boot.
    RouteUnavailable,
}

/// Function that acquires an architecture route when an interrupt is bound.
/// Returns whether the route requires an explicit userspace acknowledgement.
pub type InterruptRouteAcquireFn = fn(InterruptRouteKind, u32) -> Option<bool>;
/// Function that releases an architecture route when its last object is gone.
pub type InterruptRouteReleaseFn = fn(InterruptRouteKind, u32);
/// Function that completes one userspace service cycle for a route.
pub type InterruptRouteAcknowledgeFn = fn(InterruptRouteKind, u32) -> bool;

#[derive(Clone, Copy)]
struct InterruptRouteHooks {
    acquire: InterruptRouteAcquireFn,
    acknowledge: InterruptRouteAcknowledgeFn,
    release: InterruptRouteReleaseFn,
}

static ROUTE_HOOKS: IrqSafeMutex<Option<InterruptRouteHooks>> = IrqSafeMutex::new(None);

/// Install architecture-owned route lifetime callbacks. Called once during
/// kernel initialization before userspace can create or bind interrupt objects.
pub fn set_interrupt_route_hooks(
    acquire: InterruptRouteAcquireFn,
    acknowledge: InterruptRouteAcknowledgeFn,
    release: InterruptRouteReleaseFn,
) {
    *ROUTE_HOOKS.lock() = Some(InterruptRouteHooks {
        acquire,
        acknowledge,
        release,
    });
}

/// Binding from an interrupt object to a port.
///
/// Holds an owning `Arc<Port>` (not just its `Koid`) so the IRQ handler's
/// `signal()` never needs to consult the global object registry. This is the
/// seL4-style minimization of the IRQ critical section: the registry lookup is
/// only ever needed once, at `bind_port` time (ordinary syscall context), not
/// on every interrupt.
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
    irq: u32,
    route_kind: InterruptRouteKind,
    binding: IrqSafeMutex<Option<InterruptBinding>>,
    route_lock: IrqSafeMutex<()>,
    route_active: AtomicBool,
    ack_required: AtomicBool,
    pending_acks: AtomicU64,
    count: AtomicU64,
}

impl Interrupt {
    /// Create an interrupt object for a legacy IRQ or pre-routed vector.
    pub fn new(irq: u32) -> Arc<Self> {
        Self::new_with_route_kind(irq, InterruptRouteKind::LegacyOrVector)
    }

    /// Create an interrupt object for an explicit Global System Interrupt.
    pub fn new_gsi(gsi: u32) -> Arc<Self> {
        Self::new_with_route_kind(gsi, InterruptRouteKind::Gsi)
    }

    fn new_with_route_kind(irq: u32, route_kind: InterruptRouteKind) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            irq,
            route_kind,
            binding: IrqSafeMutex::new(None),
            route_lock: IrqSafeMutex::new(()),
            route_active: AtomicBool::new(false),
            ack_required: AtomicBool::new(false),
            pending_acks: AtomicU64::new(0),
            count: AtomicU64::new(0),
        })
    }

    /// IRQ, GSI, or pre-routed vector number represented by this object.
    pub const fn irq(&self) -> u32 {
        self.irq
    }

    /// Architecture routing namespace used for this object.
    pub const fn route_kind(&self) -> InterruptRouteKind {
        self.route_kind
    }

    /// Bind this interrupt to `port` with a user-supplied `key` and acquire its
    /// physical route. The binding is published before unmasking the hardware,
    /// so an immediately pending interrupt can already be delivered.
    pub fn bind_port(&self, port: Arc<Port>, key: u64) -> Result<(), InterruptBindError> {
        *self.binding.lock() = Some(InterruptBinding { port, key });

        // Serialize repeated/concurrent binds so one object owns exactly one
        // architecture route reference, even if two callers race here.
        let _route_guard = self.route_lock.lock();
        if self.route_active.load(Ordering::Acquire) {
            return Ok(());
        }
        let hooks = *ROUTE_HOOKS.lock();
        let Some(hooks) = hooks else {
            // Host tests and architecture-independent object users can still
            // exercise the event object without a platform IRQ controller.
            return Ok(());
        };
        // Publish conservative level-route acknowledgement state before the
        // architecture hook can unmask a pending source.
        self.ack_required.store(true, Ordering::Release);
        self.route_active.store(true, Ordering::Release);
        match (hooks.acquire)(self.route_kind, self.irq) {
            Some(ack_required) => {
                self.ack_required.store(ack_required, Ordering::Release);
                Ok(())
            }
            None => {
                self.route_active.store(false, Ordering::Release);
                self.ack_required.store(false, Ordering::Release);
                Err(InterruptBindError::RouteUnavailable)
            }
        }
    }

    /// Signal this interrupt and queue a packet to the bound port, if any.
    ///
    /// Called from an IRQ handler. `binding` is an `IrqSafeMutex`, so this
    /// cannot self-deadlock a CPU whose syscall context (`bind_port`) already
    /// holds it when an interrupt lands (see `crate::irq_guard`). The clone
    /// below is a cheap `Arc` refcount bump, not a registry lookup.
    pub fn signal(&self, packet_type: u32, data0: u64) {
        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        let Some(binding) = self.binding.lock().clone() else {
            return;
        };
        let needs_ack =
            self.route_active.load(Ordering::Acquire) && self.ack_required.load(Ordering::Acquire);
        if needs_ack {
            self.pending_acks.fetch_add(1, Ordering::AcqRel);
        }
        if binding
            .port
            .queue(PortPacket {
                key: binding.key,
                packet_type,
                status: 0,
                data: [u64::from(self.irq), data0, count, 0],
            })
            .is_err()
            && needs_ack
        {
            self.pending_acks.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Acknowledge one delivered level-triggered interrupt after the device
    /// has been serviced/deasserted. Edge-triggered routes and pre-routed MSI
    /// vectors are no-ops. Duplicate acknowledgements are ignored.
    pub fn acknowledge(&self) -> Result<(), InterruptBindError> {
        if !self.route_active.load(Ordering::Acquire) || !self.ack_required.load(Ordering::Acquire)
        {
            return Ok(());
        }
        let mut pending = self.pending_acks.load(Ordering::Acquire);
        loop {
            if pending == 0 {
                return Ok(());
            }
            match self.pending_acks.compare_exchange_weak(
                pending,
                pending - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => pending = actual,
            }
        }
        let hooks = *ROUTE_HOOKS.lock();
        if let Some(hooks) = hooks {
            if (hooks.acknowledge)(self.route_kind, self.irq) {
                return Ok(());
            }
        }
        self.pending_acks.fetch_add(1, Ordering::AcqRel);
        Err(InterruptBindError::RouteUnavailable)
    }

    /// Number of times this interrupt object has been signalled.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl Drop for Interrupt {
    fn drop(&mut self) {
        if !self.route_active.swap(false, Ordering::AcqRel) {
            return;
        }
        let hooks = *ROUTE_HOOKS.lock();
        if let Some(hooks) = hooks {
            (hooks.release)(self.route_kind, self.irq);
        }
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
