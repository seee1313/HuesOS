//! Job container objects.

use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use crate::{alloc_koid, KernelObject, Koid, ObjectType};

/// Job — container of processes (hierarchy root for resource limits).
pub struct Job {
    koid: Koid,
    name: Mutex<String>,
}

impl Job {
    /// Create the root job.
    pub fn root() -> Arc<Self> {
        Arc::new(Self {
            koid: alloc_koid(),
            name: Mutex::new(String::from("root")),
        })
    }
}

impl KernelObject for Job {
    fn object_type(&self) -> ObjectType {
        ObjectType::Job
    }
    fn koid(&self) -> Koid {
        self.koid
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
