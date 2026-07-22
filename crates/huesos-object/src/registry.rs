//! Global object ownership, typed registries, and process-local context.
//!
//! ## Ownership model
//!
//! One mutex protects object entries, userspace-handle counts, kernel mapping
//! references, and typed indexes. Keeping the state together makes final-close
//! collection atomic and establishes one lock order. The registry owns one
//! strong `Arc` while an object is discoverable. Handles are lightweight
//! `(koid, rights)` values counted here; in-flight Channel handles keep the same
//! count. VMAR mappings hold explicit kernel references.
//!
//! Collection removes the registry Arc only when both counts reach zero. The
//! removed Arc is dropped after releasing the mutex because dropping a Channel
//! may drop queued transferred handles and recursively update this registry.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::{Interrupt, Job, KernelObject, Koid, Process};

struct RegistryState {
    objects: BTreeMap<Koid, Arc<dyn KernelObject>>,
    handle_counts: BTreeMap<Koid, u32>,
    kernel_refs: BTreeMap<Koid, u32>,
    processes: BTreeMap<Koid, Arc<Process>>,
    interrupts: BTreeMap<u8, Vec<Arc<Interrupt>>>,
}

impl RegistryState {
    const fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            handle_counts: BTreeMap::new(),
            kernel_refs: BTreeMap::new(),
            processes: BTreeMap::new(),
            interrupts: BTreeMap::new(),
        }
    }

    fn unused(&self, koid: Koid) -> bool {
        self.handle_counts.get(&koid).copied().unwrap_or(0) == 0
            && self.kernel_refs.get(&koid).copied().unwrap_or(0) == 0
    }

    fn collect_object(&mut self, koid: Koid) -> Option<Arc<dyn KernelObject>> {
        if !self.unused(koid) {
            return None;
        }
        self.handle_counts.remove(&koid);
        self.kernel_refs.remove(&koid);
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

static REGISTRY: Mutex<RegistryState> = Mutex::new(RegistryState::new());

/// Register a new object before publishing its first handle.
pub fn register_object(object: Arc<dyn KernelObject>) {
    let koid = object.koid();
    let mut state = REGISTRY.lock();
    state.handle_counts.entry(koid).or_insert(0);
    state.kernel_refs.entry(koid).or_insert(0);
    state.objects.insert(koid, object);
}

/// Record one new userspace handle reference.
pub fn note_handle_open(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let mut state = REGISTRY.lock();
    let count = state.handle_counts.entry(koid).or_insert(0);
    *count = count.saturating_add(1);
}

/// Release one userspace/in-flight handle reference and collect if unused.
pub fn note_handle_close(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let removed = {
        let mut state = REGISTRY.lock();
        if let Some(count) = state.handle_counts.get_mut(&koid) {
            *count = count.saturating_sub(1);
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
    let count = state.kernel_refs.entry(koid).or_insert(0);
    *count = count.saturating_add(1);
    Some(object)
}

/// Hold an object independently of userspace handles (for example a VMAR
/// mapping that must keep VMO frames alive after the mapping handle closes).
pub fn note_kernel_ref_open(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let mut state = REGISTRY.lock();
    let count = state.kernel_refs.entry(koid).or_insert(0);
    *count = count.saturating_add(1);
}

/// Release one kernel-owned reference and collect if no handles remain.
pub fn note_kernel_ref_close(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let removed = {
        let mut state = REGISTRY.lock();
        if let Some(count) = state.kernel_refs.get_mut(&koid) {
            *count = count.saturating_sub(1);
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
        if exited && state.unused(koid) {
            state.processes.remove(&koid);
        }
        state.collect_object(koid)
    };
    drop(removed);
}

/// Return `(handle_refs, kernel_refs)` for diagnostics and leak tests.
pub fn object_ref_counts(koid: Koid) -> (u32, u32) {
    let state = REGISTRY.lock();
    (
        state.handle_counts.get(&koid).copied().unwrap_or(0),
        state.kernel_refs.get(&koid).copied().unwrap_or(0),
    )
}

/// Lookup an object by koid, returning an owning temporary reference.
pub fn lookup_object(koid: Koid) -> Option<Arc<dyn KernelObject>> {
    REGISTRY.lock().objects.get(&koid).cloned()
}

/// Lookup a process by koid.
pub fn lookup_process(koid: Koid) -> Option<Arc<Process>> {
    REGISTRY.lock().processes.get(&koid).cloned()
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

/// Explicitly remove an object and all typed indexes.
pub fn unregister_object(koid: Koid) {
    let removed = {
        let mut state = REGISTRY.lock();
        state.handle_counts.remove(&koid);
        state.kernel_refs.remove(&koid);
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
static PER_CPU_PROCESSES: Mutex<[Option<Arc<Process>>; 64]> = Mutex::new([const { None }; 64]);

static CPU_ID_CALLBACK: Mutex<Option<fn() -> usize>> = Mutex::new(None);

/// Register a callback to retrieve the current CPU ID.
pub fn set_cpu_id_callback(f: fn() -> usize) {
    *CPU_ID_CALLBACK.lock() = Some(f);
}

fn current_cpu() -> usize {
    if let Some(f) = *CPU_ID_CALLBACK.lock() {
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
static ROOT_JOB: Mutex<Option<Arc<Job>>> = Mutex::new(None);

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
static PHYS_TO_VIRT: Mutex<Option<PhysToVirtFn>> = Mutex::new(None);

/// Register the physical-to-virtual translator. Must be called once during
/// kernel init, after paging is set up.
pub fn set_phys_to_virt(f: fn(u64) -> u64) {
    *PHYS_TO_VIRT.lock() = Some(f);
}

pub(crate) fn phys_to_virt(phys: u64) -> u64 {
    (PHYS_TO_VIRT.lock().expect("phys_to_virt not registered"))(phys)
}
