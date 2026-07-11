//! Global object registries and process-local current context.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::{Interrupt, Job, KernelObject, Koid, Process};

/// Global object registry (koid -> Arc<dyn KernelObject>).
static OBJECT_REGISTRY: Mutex<BTreeMap<Koid, Arc<dyn KernelObject>>> = Mutex::new(BTreeMap::new());
/// Number of live process handles referring to each koid. When this hits
/// zero, the registry Arc is dropped so object Drop (e.g. Vmo frames) runs.
static HANDLE_COUNTS: Mutex<BTreeMap<Koid, u32>> = Mutex::new(BTreeMap::new());
/// Typed process registry for kernel subsystems that must hold an owning
/// `Arc<Process>` rather than a type-erased object reference.
static PROCESS_REGISTRY: Mutex<BTreeMap<Koid, Arc<Process>>> = Mutex::new(BTreeMap::new());
/// Typed interrupt registry indexed by IRQ number for fast IRQ bridge lookup.
/// Multiple userspace interrupt objects may observe the same IRQ during the
/// migration window (e.g. DriverManager diagnostics plus a temporary terminal
/// keyboard consumer), so each IRQ maps to a fanout list.
static INTERRUPT_REGISTRY: Mutex<BTreeMap<u8, Vec<Arc<Interrupt>>>> = Mutex::new(BTreeMap::new());

/// Register a kernel object globally. Handle count starts at 0; the first
/// [`note_handle_open`] (from `HandleTable::add`) makes it reachable.
pub fn register_object(obj: Arc<dyn KernelObject>) {
    let koid = obj.koid();
    OBJECT_REGISTRY.lock().insert(koid, obj);
    HANDLE_COUNTS.lock().entry(koid).or_insert(0);
}

/// A process handle table now references `koid`.
pub fn note_handle_open(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let mut counts = HANDLE_COUNTS.lock();
    *counts.entry(koid).or_insert(0) += 1;
}

/// A process handle table no longer references `koid`.
///
/// Counts are tracked for diagnostics and future GC, but we intentionally
/// **do not** auto-unregister at zero: channel transfers, in-flight messages,
/// and kernel-held Arcs (scheduler tasks, process registry) make "zero table
/// handles" an unreliable signal. Explicit teardown paths call
/// [`unregister_object`] when it is actually safe.
pub fn note_handle_close(koid: Koid) {
    if !koid.is_valid() {
        return;
    }
    let mut counts = HANDLE_COUNTS.lock();
    let entry = counts.entry(koid).or_insert(0);
    if *entry > 0 {
        *entry -= 1;
    }
    if *entry == 0 {
        counts.remove(&koid);
    }
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
        .or_default()
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
