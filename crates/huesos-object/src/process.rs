//! Process objects.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use crate::wait::WaitQueue;
use huesos_proclife::{ExitInfo, ProcessLifecycle, ProcState};
use crate::{alloc_koid, root_job, HandleTable, Job, KernelObject, Koid, ObjectType};

/// Process — address space + handle table + exit state.
pub struct Process {
    koid: Koid,
    name: Mutex<String>,
    /// Handle table for this process.
    pub handles: HandleTable,
    /// Job that owns this process's resource charges.
    pub job: Arc<Job>,
    /// Lifecycle state machine shared with the host-tested policy core.
    pub lifecycle: Mutex<ProcessLifecycle>,
    /// Waiters blocked in `ProcessWait` until this process exits.
    pub exit_waiters: WaitQueue,
    /// Serializes validated kernel copies with VMAR mutation operations.
    pub user_memory_lock: Mutex<()>,
    /// Opaque pointer to the arch-specific address space (owned elsewhere;
    /// stored here so syscalls/scheduler can find it without a separate
    /// process table). Boxed `dyn Any` to avoid a dependency on huesos-arch.
    pub address_space: Mutex<Option<Box<dyn Any + Send + Sync>>>,
}

impl Process {
    /// Create a process.
    pub fn new(name: &str) -> Arc<Self> {
        let job = match root_job() {
            Some(job) => job,
            None => Job::root(),
        };
        Self::new_in_job(name, job)
    }

    /// Create a process attached to an explicit Job.
    pub fn new_in_job(name: &str, job: Arc<Job>) -> Arc<Self> {
        let koid = alloc_koid();
        Arc::new(Self {
            koid,
            name: Mutex::new(String::from(name)),
            handles: HandleTable::new(),
            job,
            lifecycle: Mutex::new(ProcessLifecycle::new(koid.0, koid.0)),
            exit_waiters: WaitQueue::new(),
            user_memory_lock: Mutex::new(()),
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

    /// Return the Job owning this process's resource charges.
    pub fn job(&self) -> Arc<Job> {
        Arc::clone(&self.job)
    }

    /// Mark the process as running. The policy accepts this only once, when
    /// the first thread is started.
    pub fn start(&self) -> bool {
        self.lifecycle.lock().start()
    }

    /// Record the exit code and wake anyone blocked in ProcessWait.
    /// Idempotent: the first exit code wins.
    pub fn set_exit_code(&self, code: i64) -> bool {
        let exited = self.lifecycle.lock().exit(code);
        if exited {
            self.exit_waiters.wake_all();
        }
        exited
    }

    /// Snapshot exit code if the process has already exited.
    pub fn exit_code(&self) -> Option<i64> {
        self.lifecycle.lock().exit_code()
    }

    /// Current policy state.
    pub fn lifecycle_state(&self) -> ProcState {
        self.lifecycle.lock().state()
    }

    /// Register one blocking exit waiter. Returns false if the process has
    /// already exited and the caller should observe the stored status without
    /// parking.
    pub fn add_exit_waiter(&self) -> bool {
        self.lifecycle.lock().add_waiter()
    }

    /// Release one blocking exit waiter.
    pub fn remove_exit_waiter(&self) {
        self.lifecycle.lock().remove_waiter();
    }

    /// Whether lifecycle policy permits final metadata reaping.
    pub fn can_reap(&self) -> bool {
        self.lifecycle.lock().can_reap()
    }

    /// Snapshot the generation-bearing exit payload.
    pub fn exit_info(&self) -> Option<ExitInfo> {
        self.lifecycle.lock().exit_info()
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
