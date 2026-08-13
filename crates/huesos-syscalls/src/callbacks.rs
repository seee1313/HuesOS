//! Scheduler/kernel callbacks registered by `huesos-kernel`.

use alloc::sync::Arc;
use huesos_abi::{ErrorCode, HeapExtendArgs, ResourceMapArgs, VmarMapArgs, VmarOpArgs};
use spin::Mutex;

/// Global yield callback (set by kernel scheduler to avoid circular deps).
pub(crate) static YIELD_FN: Mutex<Option<fn()>> = Mutex::new(None);
/// Global process-exit callback (set by kernel scheduler).
pub(crate) static EXIT_FN: Mutex<Option<fn(i64) -> !>> = Mutex::new(None);
/// Kernel debug sink callback.
pub type DebugWriteFn = fn(&[u8]);
/// Privileged orderly-shutdown callback.
pub type ShutdownFn = fn() -> Result<(), ErrorCode>;

/// Global debug-write callback (set by kernel to point at the serial writer).
pub(crate) static DEBUG_WRITE_FN: Mutex<Option<DebugWriteFn>> = Mutex::new(None);
/// Global monotonic-clock callback.
pub(crate) static CLOCK_FN: Mutex<Option<fn() -> u64>> = Mutex::new(None);
/// Global online-CPU mask callback.
pub(crate) static CPU_MASK_FN: Mutex<Option<fn() -> u64>> = Mutex::new(None);
/// Global current-CPU callback.
pub(crate) static CURRENT_CPU_FN: Mutex<Option<fn() -> usize>> = Mutex::new(None);
/// Global privileged shutdown callback.
pub(crate) static SHUTDOWN_FN: Mutex<Option<ShutdownFn>> = Mutex::new(None);

/// Kernel callback type used by the syscall layer to create a suspended process.
pub type ProcessCreateFn =
    fn(&str) -> Result<(Arc<huesos_object::Process>, Arc<huesos_object::Vmar>), ErrorCode>;
/// Kernel callback type used to create a suspended process in an explicit Job.
pub type ProcessCreateInJobFn =
    fn(
        &str,
        Arc<huesos_object::Job>,
    ) -> Result<(Arc<huesos_object::Process>, Arc<huesos_object::Vmar>), ErrorCode>;
/// Kernel callback type used by the syscall layer to map a VMO into a VMAR.
pub type VmarMapFn =
    fn(&huesos_object::Vmar, &huesos_object::Vmo, VmarMapArgs) -> Result<u64, ErrorCode>;
/// Kernel callback type used by VMAR unmap/protect operations.
pub type VmarOpFn = fn(&huesos_object::Vmar, VmarOpArgs) -> Result<u64, ErrorCode>;
/// Kernel callback type used to map an `Mmio`/`DmaPool` Resource into the
/// caller's root VMAR.
pub type ResourceMapFn = fn(&huesos_object::Resource, ResourceMapArgs) -> Result<u64, ErrorCode>;
/// Kernel callback type used to commit/decommit pages in the calling
/// process's own reserved heap window (`VmarHeapExtend`).
pub type HeapExtendFn = fn(HeapExtendArgs) -> Result<u64, ErrorCode>;
/// Kernel callback type used by the syscall layer to start a suspended thread.
pub type ThreadStartFn = fn(&huesos_object::Thread, u64, u64) -> Result<u64, ErrorCode>;

/// Global process-create callback (set by the kernel process layer).
pub(crate) static PROCESS_CREATE_FN: Mutex<Option<ProcessCreateFn>> = Mutex::new(None);
/// Global explicit-job process-create callback.
pub(crate) static PROCESS_CREATE_IN_JOB_FN: Mutex<Option<ProcessCreateInJobFn>> = Mutex::new(None);
/// Global VMAR-map callback (set by the kernel process layer).
pub(crate) static VMAR_MAP_FN: Mutex<Option<VmarMapFn>> = Mutex::new(None);
/// Global VMAR-unmap callback.
pub(crate) static VMAR_UNMAP_FN: Mutex<Option<VmarOpFn>> = Mutex::new(None);
/// Global VMAR-protect callback.
pub(crate) static VMAR_PROTECT_FN: Mutex<Option<VmarOpFn>> = Mutex::new(None);
/// Global Resource-map callback.
pub(crate) static RESOURCE_MAP_FN: Mutex<Option<ResourceMapFn>> = Mutex::new(None);
/// Global heap-extend callback (set by the kernel process layer).
pub(crate) static HEAP_EXTEND_FN: Mutex<Option<HeapExtendFn>> = Mutex::new(None);
/// Global thread-start callback (set by the kernel scheduler/process layer).
pub(crate) static THREAD_START_FN: Mutex<Option<ThreadStartFn>> = Mutex::new(None);

/// Set the yield function. Called once by kernel init.
pub fn set_yield_fn(f: fn()) {
    *YIELD_FN.lock() = Some(f);
}

/// Set the process-exit function. Called once by kernel init.
pub fn set_exit_fn(f: fn(i64) -> !) {
    *EXIT_FN.lock() = Some(f);
}

/// Set the debug-write function. Called once by kernel init.
pub fn set_debug_write_fn(f: DebugWriteFn) {
    *DEBUG_WRITE_FN.lock() = Some(f);
}

/// Set the monotonic clock source. Called once by kernel init.
pub fn set_clock_fn(f: fn() -> u64) {
    *CLOCK_FN.lock() = Some(f);
}

/// Set the online CPU mask callback. Called once by kernel init.
pub fn set_cpu_mask_fn(f: fn() -> u64) {
    *CPU_MASK_FN.lock() = Some(f);
}

/// Set the current dense CPU index callback. Called once by kernel init.
pub fn set_current_cpu_fn(f: fn() -> usize) {
    *CURRENT_CPU_FN.lock() = Some(f);
}

/// Set the privileged orderly-shutdown callback. Called once by kernel init.
pub fn set_shutdown_fn(f: ShutdownFn) {
    *SHUTDOWN_FN.lock() = Some(f);
}

/// Set the process-create function. Called once by kernel init.
pub fn set_process_create_fn(f: ProcessCreateFn) {
    *PROCESS_CREATE_FN.lock() = Some(f);
}

/// Set the explicit-job process-create function. Called once by kernel init.
pub fn set_process_create_in_job_fn(f: ProcessCreateInJobFn) {
    *PROCESS_CREATE_IN_JOB_FN.lock() = Some(f);
}

/// Set the VMAR-map function. Called once by kernel init.
pub fn set_vmar_map_fn(f: VmarMapFn) {
    *VMAR_MAP_FN.lock() = Some(f);
}

/// Set the VMAR-unmap function. Called once by kernel init.
pub fn set_vmar_unmap_fn(f: VmarOpFn) {
    *VMAR_UNMAP_FN.lock() = Some(f);
}

/// Set the VMAR-protect function. Called once by kernel init.
pub fn set_vmar_protect_fn(f: VmarOpFn) {
    *VMAR_PROTECT_FN.lock() = Some(f);
}

/// Set the Resource-map function. Called once by kernel init.
pub fn set_resource_map_fn(f: ResourceMapFn) {
    *RESOURCE_MAP_FN.lock() = Some(f);
}

/// Set the heap-extend function. Called once by kernel init.
pub fn set_heap_extend_fn(f: HeapExtendFn) {
    *HEAP_EXTEND_FN.lock() = Some(f);
}

/// Set the thread-start function. Called once by kernel init.
pub fn set_thread_start_fn(f: ThreadStartFn) {
    *THREAD_START_FN.lock() = Some(f);
}
