//! Global object registries and process-local current context.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::{Interrupt, Job, KernelObject, Koid, Process};

/// Global object registry (koid -> Arc<dyn KernelObject>).
static OBJECT_REGISTRY: Mutex<BTreeMap<Koid, Arc<dyn KernelObject>>> = Mutex::new(BTreeMap::new());
/// Typed process registry for kernel subsystems that must hold an owning
/// `Arc<Process>` rather than a type-erased object reference.
static PROCESS_REGISTRY: Mutex<BTreeMap<Koid, Arc<Process>>> = Mutex::new(BTreeMap::new());
/// Typed interrupt registry indexed by IRQ number for fast IRQ bridge lookup.
/// Multiple userspace interrupt objects may observe the same IRQ during the
/// migration window (e.g. DriverManager diagnostics plus a temporary terminal
/// keyboard consumer), so each IRQ maps to a fanout list.
static INTERRUPT_REGISTRY: Mutex<BTreeMap<u8, Vec<Arc<Interrupt>>>> = Mutex::new(BTreeMap::new());

/// Register a kernel object globally.
pub fn register_object(obj: Arc<dyn KernelObject>) {
    OBJECT_REGISTRY.lock().insert(obj.koid(), obj);
}

/// Register a process in both the type-erased object registry and the typed
/// process registry.
pub fn register_process(process: Arc<Process>) {
    PROCESS_REGISTRY
        .lock()
        .insert(process.koid(), process.clone());
    register_object(process);
}

/// Lookup a kernel object by koid.
pub fn lookup_object(koid: Koid) -> Option<Arc<dyn KernelObject>> {
    OBJECT_REGISTRY.lock().get(&koid).cloned()
}

/// Lookup a process by koid, returning a typed owning reference.
pub fn lookup_process(koid: Koid) -> Option<Arc<Process>> {
    PROCESS_REGISTRY.lock().get(&koid).cloned()
}

/// Register an interrupt in both the type-erased object registry and the
/// typed IRQ registry.
pub fn register_interrupt(interrupt: Arc<Interrupt>) {
    INTERRUPT_REGISTRY
        .lock()
        .entry(interrupt.irq())
        .or_insert_with(Vec::new)
        .push(interrupt.clone());
    register_object(interrupt);
}

/// Lookup all interrupt objects registered for an IRQ number.
pub fn lookup_interrupts_by_irq(irq: u8) -> Vec<Arc<Interrupt>> {
    INTERRUPT_REGISTRY
        .lock()
        .get(&irq)
        .cloned()
        .unwrap_or_else(Vec::new)
}

/// Remove an object from the global registry (called on final handle close
/// in a full refcounted implementation; for the MVP this is invoked
/// explicitly by `ProcessExit`/object-specific teardown).
pub fn unregister_object(koid: Koid) {
    OBJECT_REGISTRY.lock().remove(&koid);
    PROCESS_REGISTRY.lock().remove(&koid);
    let mut interrupts = INTERRUPT_REGISTRY.lock();
    for list in interrupts.values_mut() {
        list.retain(|interrupt| interrupt.koid() != koid);
    }
    interrupts.retain(|_, list| !list.is_empty());
}

/// Current process (set by the scheduler on every context switch).
static CURRENT_PROCESS: Mutex<Option<Arc<Process>>> = Mutex::new(None);

/// Set the current process.
pub fn set_current_process(p: Arc<Process>) {
    *CURRENT_PROCESS.lock() = Some(p);
}

/// Get the current process.
pub fn current_process() -> Option<Arc<Process>> {
    CURRENT_PROCESS.lock().clone()
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
static PHYS_TO_VIRT: Mutex<Option<fn(u64) -> u64>> = Mutex::new(None);

/// Register the physical-to-virtual translator. Must be called once during
/// kernel init, after paging is set up.
pub fn set_phys_to_virt(f: fn(u64) -> u64) {
    *PHYS_TO_VIRT.lock() = Some(f);
}

pub(crate) fn phys_to_virt(phys: u64) -> u64 {
    (PHYS_TO_VIRT.lock().expect("phys_to_virt not registered"))(phys)
}
