//! Process objects.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use crate::{alloc_koid, HandleTable, KernelObject, Koid, ObjectType};

/// Process — address space + handle table + exit state.
pub struct Process {
    koid: Koid,
    name: Mutex<String>,
    /// Handle table for this process.
    pub handles: HandleTable,
    /// Exit code, set by `ProcessExit`. `None` while still running.
    pub exit_code: Mutex<Option<i64>>,
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
            address_space: Mutex::new(None),
        })
    }

    /// Human-readable process name.
    pub fn name(&self) -> String {
        self.name.lock().clone()
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
