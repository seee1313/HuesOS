//! Thread objects.

use crate::irq_guard::IrqSafeMutex;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use crate::{alloc_koid, KernelObject, Koid, ObjectType};

/// Thread — execution context (userspace-visible object wrapping a kernel
/// scheduler task).
pub struct Thread {
    koid: Koid,
    name: IrqSafeMutex<String>,
    process: Koid,
    /// Scheduler task id this Thread object corresponds to.
    pub task_id: IrqSafeMutex<Option<u64>>,
}

impl Thread {
    /// Create a thread object (not yet bound to a scheduler task).
    pub fn new(name: &str) -> Arc<Self> {
        Self::new_for_process(name, Koid::INVALID)
    }

    /// Create a suspended thread object associated with `process`.
    pub fn new_for_process(name: &str, process: Koid) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: IrqSafeMutex::new(String::from(name)),
            process,
            task_id: IrqSafeMutex::new(None),
        })
    }

    /// Process this thread belongs to.
    pub const fn process(&self) -> Koid {
        self.process
    }
}

impl KernelObject for Thread {
    fn object_type(&self) -> ObjectType {
        ObjectType::Thread
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
