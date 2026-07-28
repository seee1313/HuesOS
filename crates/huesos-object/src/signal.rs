//! Level-triggered signal objects.

use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::irq_guard::IrqSafeMutex;
use crate::wait::WaitQueue;
use crate::{alloc_koid, KernelObject, Koid, ObjectType};

/// A userspace-visible level-triggered signal object.
///
/// `set` makes [`Signals::SIGNALED`](huesos_waitset::Signals::SIGNALED)
/// active until a later `clear`. Waiters park on `waiters` and wake whenever
/// the signal becomes active or the handle is closed.
pub struct Signal {
    koid: Koid,
    name: IrqSafeMutex<String>,
    signaled: AtomicBool,
    waiters: WaitQueue,
}

impl Signal {
    /// Create a new, initially unsignaled object.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: IrqSafeMutex::new(String::from("signal")),
            signaled: AtomicBool::new(false),
            waiters: WaitQueue::new(),
        })
    }

    /// Whether the signal is currently active.
    pub fn is_signaled(&self) -> bool {
        self.signaled.load(Ordering::Acquire)
    }

    /// Set the signal and wake every waiter. Level-triggered semantics mean
    /// repeated sets are harmless; waking on every set also covers races where
    /// a waiter parked after observing the old value but before this syscall.
    pub fn set(&self) {
        self.signaled.store(true, Ordering::Release);
        self.waiters.wake_all();
    }

    /// Clear the signal. Does not wake waiters because the active signal set
    /// only shrinks.
    pub fn clear(&self) {
        self.signaled.store(false, Ordering::Release);
    }

    /// Wait queue used by `WaitSetWait`.
    pub fn wait_queue(&self) -> &WaitQueue {
        &self.waiters
    }

    /// Human-readable object name.
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }
}

impl KernelObject for Signal {
    fn object_type(&self) -> ObjectType {
        ObjectType::Signal
    }

    fn koid(&self) -> Koid {
        self.koid
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
