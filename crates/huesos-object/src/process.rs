//! Process objects.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use crate::wait::WaitQueue;
use crate::{alloc_koid, HandleTable, KernelObject, Koid, ObjectType};

/// Process — address space + handle table + exit state.
pub struct Process {
    koid: Koid,
    name: Mutex<String>,
    /// Handle table for this process.
    pub handles: HandleTable,
    /// Exit code, set by `ProcessExit`. `None` while still running.
    pub exit_code: Mutex<Option<i64>>,
    /// Waiters blocked in `ProcessWait` until this process exits.
    pub exit_waiters: WaitQueue,
    /// Opaque pointer to the arch-specific address space (owned elsewhere;
    /// stored here so syscalls/scheduler can find it without a separate
    /// process table). Boxed `dyn Any` to avoid a dependency on huesos-arch.
    pub address_space: Mutex<Option<Box<dyn Any + Send + Sync>>>,
}

impl Process {
    /// Create a process.
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: Mutex::new(String::from(name)),
            handles: HandleTable::new(),
            exit_code: Mutex::new(None),
            exit_waiters: WaitQueue::new(),
            address_space: Mutex::new(None),
        })
    }

    /// Human-readable process name as an owned string.
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }

    /// Copy the process name into caller-owned storage without allocating.
    /// Returns the number of bytes copied. Fatal/fault diagnostics use this
    /// path so reporting a userspace exception cannot itself fail on OOM.
    pub fn copy_name(&self, output: &mut [u8]) -> usize {
        let name = self.name.lock();
        let count = name.len().min(output.len());
        output[..count].copy_from_slice(&name.as_bytes()[..count]);
        count
    }

    /// Record the exit code and wake anyone blocked in ProcessWait.
    /// Idempotent: the first exit code wins.
    pub fn set_exit_code(&self, code: i64) {
        let mut slot = self.exit_code.lock();
        if slot.is_none() {
            *slot = Some(code);
        }
        drop(slot);
        self.exit_waiters.wake_all();
    }

    /// Snapshot exit code if the process has already exited.
    pub fn exit_code(&self) -> Option<i64> {
        *self.exit_code.lock()
    }
}

impl KernelObject for Process {
    fn object_type(&self) -> ObjectType {
        ObjectType::Process
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
