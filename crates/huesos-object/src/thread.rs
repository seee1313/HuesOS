//! Thread objects.

use crate::irq_guard::IrqSafeMutex;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use crate::{alloc_koid, KernelObject, Koid, ObjectType};

const TASK_STARTING_SENTINEL: u64 = u64::MAX;

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

    /// Atomically reserve this thread for start. Returns `false` if another
    /// caller already started it or is in the middle of starting it.
    pub fn begin_start(&self) -> bool {
        let mut state = self.task_id.lock();
        if state.is_some() {
            return false;
        }
        *state = Some(TASK_STARTING_SENTINEL);
        true
    }

    /// Publish the scheduler task id after a successful start.
    pub fn finish_start(&self, task_id: u64) {
        *self.task_id.lock() = Some(task_id);
    }

    /// Roll back a failed start reservation.
    pub fn cancel_start(&self) {
        let mut state = self.task_id.lock();
        if *state == Some(TASK_STARTING_SENTINEL) {
            *state = None;
        }
    }

    /// Whether this thread has already been started or reserved for start.
    pub fn start_in_progress_or_done(&self) -> bool {
        self.task_id.lock().is_some()
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
