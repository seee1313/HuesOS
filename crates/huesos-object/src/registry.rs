//! Global object ownership, typed registries, and process-local context.
//!
//! ## Ownership model
//!
//! One mutex protects object entries, per-object reference accounts (via the
//! host-tested [`huesos_lifecycle::RefAccount`] policy model), and typed
//! indexes. Keeping the state together makes final-close collection atomic
//! and establishes one lock order. The registry owns one strong `Arc` while
//! an object is discoverable. Handles are lightweight `(koid, rights)`
//! values counted here; in-flight Channel handles keep the same count. VMAR
//! mappings hold explicit kernel references.
//!
//! Collection removes the registry `Arc` only when [`RefAccount::may_collect`]
//! returns true (i.e. both counts are zero and the object is still
//! registered). The removed `Arc` is dropped after releasing the mutex
//! because dropping a Channel may drop queued transferred handles and
//! recursively update this registry.
//!
//! All shared state in this module is behind [`crate::irq_guard::IrqSafeMutex`]
//! rather than a plain `spin::Mutex`: `lookup_object` and
//! `lookup_interrupts_by_irq` are called from the keyboard IRQ1 bridge
//! (`Interrupt::signal`) on the same CPU that runs ordinary syscall-context
//! code locking `REGISTRY`, and `IrqSafeMutex` makes it impossible to
//! reintroduce the self-deadlock that hazard caused by locking without
//! disabling interrupts. See `crate::irq_guard` for the full writeup.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use huesos_lifecycle::RefAccount;

use crate::irq_guard::IrqSafeMutex;
use crate::{
    Channel, Interrupt, Job, KernelObject, KernelObjectExt, Koid, Port, Process, Resource,
    ResourceError, Signal,
};

struct RegistryState {
    objects: BTreeMap<Koid, Arc<dyn KernelObject>>,
    /// Two-counter reference account per registered object, sourced from the
    /// host-tested `huesos_lifecycle::RefAccount` specification model. One
    /// entry replaces the previous split `handle_counts` + `kernel_refs`
    /// maps, and every `open_*` / `close_*` / `try_collect` call goes
    /// through the same well-tested API.
    accounts: BTreeMap<Koid, RefAccount>,
    processes: BTreeMap<Koid, Arc<Process>>,
    interrupts: BTreeMap<u8, Vec<Arc<Interrupt>>>,
}

impl RegistryState {
    const fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            accounts: BTreeMap::new(),
            processes: BTreeMap::new(),
            interrupts: BTreeMap::new(),
        }
    }

    /// Handle and kernel reference counts as `(handles, kernel_refs)`.
    fn ref_counts(&self, koid: Koid) -> (u32, u32) {
        match self.accounts.get(&koid) {
            Some(account) => (account.handle_refs() as u32, account.kernel_refs() as u32),
            None => (0, 0),
        }
    }

    fn collect_object(&mut self, koid: Koid) -> Option<Arc<dyn KernelObject>> {
        // try_collect() only succeeds when both counts are zero AND the
        // account is registered AND not already collected. This is the
        // single point in the file that removes the registry Arc; earlier
        // hand-rolled checks were spread across three call sites.
        let account = self.accounts.get_mut(&koid)?;
        if !account.try_collect() {
            return None;
        }
        self.accounts.remove(&koid);
        let object = self.objects.remove(&koid)?;

        // Interrupt registry ownership exists only to deliver events to live
        // userspace handles; remove it with the final handle.
        for list in self.interrupts.values_mut() {
            list.retain(|interrupt| interrupt.koid() != koid);
        }
        self.interrupts.retain(|_, list| !list.is_empty());

        // A running process remains typed-owned by the scheduler/process
        // registry even if userspace closes its last handle. Once exited, no
        // handle and no kernel reference means it can leave the typed index.
        if let Some(process) = self.processes.get(&koid) {
            if process.exit_code().is_some() {
                self.processes.remove(&koid);
            }
        }
        Some(object)
    }
}

static REGISTRY: IrqSafeMutex<RegistryState> = IrqSafeMutex::new(RegistryState::new());

/// Register a new object before publishing its first handle. Idempotent
/// re-registration is not supported; the caller must not register the same
/// koid twice.
pub fn register_object(object: Arc<dyn KernelObject>) {
    let koid = object.koid();
    let mut state = REGISTRY.lock();
    state.accounts.insert(koid, RefAccount::registered());
    state.objects.insert(koid, object);
}

/// Record one new userspace handle reference.
pub fn note_handle_open(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let mut state = REGISTRY.lock();
    if let Some(account) = state.accounts.get_mut(&koid) {
        // open_handles returns false if the account has already been
        // collected; ignoring is correct because a stale reference to a
        // collected koid cannot resurrect the object.
        let _ = account.open_handles(1);
    }
}

/// Release one userspace/in-flight handle reference and collect if unused.
pub fn note_handle_close(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let removed = {
        let mut state = REGISTRY.lock();
        if let Some(account) = state.accounts.get_mut(&koid) {
            account.close_handles(1);
        }
        state.collect_object(koid)
    };
    drop(removed);
}

/// Acquire an object reference and one kernel-owned lifetime reference in a
/// single registry critical section.
///
/// This is the only safe entry point for a new VMAR mapping: a concurrent last
/// handle close cannot collect the object between lookup and kernel-reference
/// accounting. The returned `Arc` keeps the object alive while the caller
/// installs its metadata/page-table transaction.
pub fn acquire_kernel_ref(koid: Koid) -> Option<Arc<dyn KernelObject>> {
    if !koid.is_valid() {
        return None;
    }
    let mut state = REGISTRY.lock();
    let object = state.objects.get(&koid).cloned()?;
    let account = state.accounts.get_mut(&koid)?;
    // open_kernel_refs returns false only if collected — impossible here
    // because we just cloned the object Arc under the same mutex.
    let _ = account.open_kernel_refs(1);
    Some(object)
}

/// Hold an object independently of userspace handles (for example a VMAR
/// mapping that must keep VMO frames alive after the mapping handle closes).
pub fn note_kernel_ref_open(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let mut state = REGISTRY.lock();
    if let Some(account) = state.accounts.get_mut(&koid) {
        let _ = account.open_kernel_refs(1);
    }
}

/// Release one kernel-owned reference and collect if no handles remain.
pub fn note_kernel_ref_close(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let removed = {
        let mut state = REGISTRY.lock();
        if let Some(account) = state.accounts.get_mut(&koid) {
            account.close_kernel_refs(1);
        }
        state.collect_object(koid)
    };
    drop(removed);
}

/// Register a process in object and typed indexes.
pub fn register_process(process: Arc<Process>) {
    let koid = process.koid();
    {
        let mut state = REGISTRY.lock();
        state.processes.insert(koid, Arc::clone(&process));
    }
    register_object(process);
}

/// Re-run process collection after setting its exit status.
pub fn collect_exited_process(koid: Koid) {
    let removed = {
        let mut state = REGISTRY.lock();
        let exited = state
            .processes
            .get(&koid)
            .is_some_and(|process| process.exit_code().is_some());
        let (handles, kernel) = state.ref_counts(koid);
        if exited && handles == 0 && kernel == 0 {
            state.processes.remove(&koid);
        }
        state.collect_object(koid)
    };
    drop(removed);
}

/// Return `(handle_refs, kernel_refs)` for diagnostics and leak tests.
pub fn object_ref_counts(koid: Koid) -> (u32, u32) {
    REGISTRY.lock().ref_counts(koid)
}

/// Lookup an object by koid, returning an owning temporary reference.
pub fn lookup_object(koid: Koid) -> Option<Arc<dyn KernelObject>> {
    REGISTRY.lock().objects.get(&koid).cloned()
}

/// Lookup a process by koid.
pub fn lookup_process(koid: Koid) -> Option<Arc<Process>> {
    REGISTRY.lock().processes.get(&koid).cloned()
}

/// Atomically overlap-check a candidate `Resource` against existing
/// resources of the same kind, and register it on success.
///
/// The walk and the insert both happen under a single lock acquisition
/// so no other thread can insert a conflicting resource between the
/// check and the commit (a two-step public API would open a
/// time-of-check-to-time-of-use window).
///
/// # Overlap rules
///
/// * Exclusive candidate: any range-intersection with any existing
///   resource of the same kind (exclusive or shared) is a `Conflict`.
/// * Shared candidate: only range-intersection with an existing
///   `exclusive` resource of the same kind is a `Conflict`.
///
/// See `docs/ARCHITECTURE_ROADMAP.md` §2 and the Zircon reference in
/// `resource.rs`.
pub(crate) fn try_register_resource_locked(candidate: Arc<Resource>) -> Result<(), ResourceError> {
    let koid = candidate.koid();
    let mut state = REGISTRY.lock();
    for existing in state.objects.values() {
        if existing.object_type() != crate::ObjectType::Resource {
            continue;
        }
        let Some(other) = existing.downcast_ref::<Resource>() else {
            continue;
        };
        if other.kind() != candidate.kind() {
            continue;
        }
        if !other.intersects(candidate.base(), candidate.len()) {
            continue;
        }
        // Both exclusive vs. one exclusive → conflict.
        // Shared vs. shared is permitted; only reject shared when the
        // other side is exclusive.
        if candidate.is_exclusive() || other.is_exclusive() {
            return Err(ResourceError::Conflict);
        }
    }
    state.accounts.insert(koid, RefAccount::registered());
    state
        .objects
        .insert(koid, candidate as Arc<dyn KernelObject>);
    Ok(())
}

/// Register an interrupt for both object lookup and IRQ fanout.
pub fn register_interrupt(interrupt: Arc<Interrupt>) {
    {
        let mut state = REGISTRY.lock();
        state
            .interrupts
            .entry(interrupt.irq())
            .or_default()
            .push(Arc::clone(&interrupt));
    }
    register_object(interrupt);
}

/// Snapshot interrupt listeners for an IRQ.
pub fn lookup_interrupts_by_irq(irq: u8) -> Vec<Arc<Interrupt>> {
    REGISTRY
        .lock()
        .interrupts
        .get(&irq)
        .cloned()
        .unwrap_or_default()
}

/// Wake waiters observing an object whose handle state changed.
///
/// Multi-object waits enqueue on the underlying object's ordinary wait queue;
/// when a process closes a waited handle, the object may stay alive because the
/// wait syscall holds a temporary Arc. Waking here lets that waiter re-check its
/// handle table and report `Signals::CANCELED` instead of sleeping forever.
pub(crate) fn wake_object_waiters(koid: Koid) {
    let object = REGISTRY.lock().objects.get(&koid).cloned();
    let Some(object) = object else {
        return;
    };
    if let Some(channel) = object.downcast_ref::<Channel>() {
        channel.reader_queue().wake_all();
    } else if let Some(port) = object.downcast_ref::<Port>() {
        port.wait_queue().wake_all();
    } else if let Some(process) = object.downcast_ref::<Process>() {
        process.exit_waiters.wake_all();
    } else if let Some(signal) = object.downcast_ref::<Signal>() {
        signal.wait_queue().wake_all();
    }
}

/// Explicitly remove an object and all typed indexes. Unlike the
/// count-driven `note_*_close` paths, this ignores the reference account
/// and always removes the object; existing kernel call sites use it for
/// hard cleanup after a spawn failure or an explicit teardown.
pub fn unregister_object(koid: Koid) {
    let removed = {
        let mut state = REGISTRY.lock();
        state.accounts.remove(&koid);
        state.processes.remove(&koid);
        for list in state.interrupts.values_mut() {
            list.retain(|interrupt| interrupt.koid() != koid);
        }
        state.interrupts.retain(|_, list| !list.is_empty());
        state.objects.remove(&koid)
    };
    drop(removed);
}

/// Current process per CPU core (set by the scheduler on every context switch).
static PER_CPU_PROCESSES: IrqSafeMutex<[Option<Arc<Process>>; 64]> =
    IrqSafeMutex::new([const { None }; 64]);

static CPU_ID_CALLBACK: IrqSafeMutex<Option<fn() -> usize>> = IrqSafeMutex::new(None);

/// Register a callback to retrieve the current CPU ID.
pub fn set_cpu_id_callback(f: fn() -> usize) {
    *CPU_ID_CALLBACK.lock() = Some(f);
}

pub(crate) fn current_cpu() -> usize {
    // Drop the lock before calling the callback (see
    // `huesos_object::wait::park_current` for why holding a callback
    // mutex guard across the call is unsafe in general, even though this
    // particular callback is short and non-blocking).
    let cpu_id_fn = *CPU_ID_CALLBACK.lock();
    if let Some(f) = cpu_id_fn {
        f()
    } else {
        0
    }
}

/// Set the current process.
pub fn set_current_process(p: Arc<Process>) {
    let cpu = current_cpu().min(63);
    PER_CPU_PROCESSES.lock()[cpu] = Some(p);
}

/// Get the current process.
pub fn current_process() -> Option<Arc<Process>> {
    let cpu = current_cpu().min(63);
    PER_CPU_PROCESSES.lock()[cpu].clone()
}

/// Root job (set during object init).
static ROOT_JOB: IrqSafeMutex<Option<Arc<Job>>> = IrqSafeMutex::new(None);

/// Get the root job.
pub fn root_job() -> Option<Arc<Job>> {
    ROOT_JOB.lock().clone()
}

/// Set the root job during object subsystem initialization.
pub(crate) fn set_root_job(root: Arc<Job>) {
    *ROOT_JOB.lock() = Some(root);
}

/// Callback used to translate a physical address into a kernel-accessible
/// virtual address (the HHDM). Injected by the kernel at init time so that
/// `huesos-object` doesn't need to depend on `huesos-arch` directly.
type PhysToVirtFn = fn(u64) -> u64;
static PHYS_TO_VIRT: IrqSafeMutex<Option<PhysToVirtFn>> = IrqSafeMutex::new(None);

/// Register the physical-to-virtual translator. Must be called once during
/// kernel init, after paging is set up.
pub fn set_phys_to_virt(f: fn(u64) -> u64) {
    *PHYS_TO_VIRT.lock() = Some(f);
}

pub(crate) fn phys_to_virt(phys: u64) -> u64 {
    (PHYS_TO_VIRT.lock().expect("phys_to_virt not registered"))(phys)
}
