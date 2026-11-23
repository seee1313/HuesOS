//! Scheduler/kernel callbacks registered by `huesos-kernel`.

use alloc::sync::Arc;
use huesos_abi::{
    ErrorCode, HeapExtendArgs, ResourceMapArgs, ResourceUnmapArgs, VmarMapArgs, VmarOpArgs,
};
use spin::{Mutex, Once};

/// Global yield callback (set by kernel scheduler to avoid circular deps).
pub(crate) static YIELD_FN: Once<fn()> = Once::new();
/// Global process-exit callback (set by kernel scheduler).
pub(crate) static EXIT_FN: Mutex<Option<fn(i64) -> !>> = Mutex::new(None);
/// Kernel debug sink callback.
pub type DebugWriteFn = fn(&[u8]);
/// Privileged orderly-shutdown callback.
pub type ShutdownFn = fn() -> Result<(), ErrorCode>;

/// Global debug-write callback (set by kernel to point at the serial writer).
pub(crate) static DEBUG_WRITE_FN: Mutex<Option<DebugWriteFn>> = Mutex::new(None);
/// Global monotonic-clock callback.
pub(crate) static CLOCK_FN: Once<fn() -> u64> = Once::new();
/// Global online-CPU mask callback.
type CpuCountFn = fn() -> usize;
type CpuOnlineFn = fn(usize) -> bool;

pub(crate) static CPU_MASK_FN: Mutex<Option<fn() -> u64>> = Mutex::new(None);
pub(crate) static CPU_COUNT_FN: Mutex<Option<CpuCountFn>> = Mutex::new(None);
pub(crate) static CPU_ONLINE_FN: Mutex<Option<CpuOnlineFn>> = Mutex::new(None);
/// Global current-CPU callback.
pub(crate) static CURRENT_CPU_FN: Once<fn() -> usize> = Once::new();
/// Global privileged shutdown callback.
pub(crate) static SHUTDOWN_FN: Mutex<Option<ShutdownFn>> = Mutex::new(None);
/// Scheduler snapshot callbacks: aggregate counters, then per-CPU.
pub type SchedSummaryFn = fn(&mut huesos_abi::SchedSummary);
pub type SchedCpuFn = fn(usize, &mut huesos_abi::SchedCpuRecord);
pub type TaskRecordFn = fn(usize, &mut [huesos_abi::TaskRecord]) -> (usize, usize);
pub(crate) static SCHED_SUMMARY_FN: Mutex<Option<SchedSummaryFn>> = Mutex::new(None);
pub(crate) static SCHED_CPU_FN: Mutex<Option<SchedCpuFn>> = Mutex::new(None);
pub(crate) static TASK_RECORD_FN: Mutex<Option<TaskRecordFn>> = Mutex::new(None);
/// Live-task count callback, used to page the task table.
pub type TaskCountFn = fn() -> usize;
pub(crate) static TASK_COUNT_FN: Mutex<Option<TaskCountFn>> = Mutex::new(None);

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
/// Kernel callback type used to remove a Resource mapping installed by
/// [`ResourceMapFn`].
pub type ResourceUnmapFn =
    fn(&huesos_object::Resource, ResourceUnmapArgs) -> Result<u64, ErrorCode>;
/// Kernel callback type used to commit/decommit pages in the calling
/// process's own reserved heap window (`VmarHeapExtend`).
pub type HeapExtendFn = fn(HeapExtendArgs) -> Result<u64, ErrorCode>;
/// Kernel callback type used by the syscall layer to start a suspended thread.
pub type ThreadStartFn = fn(&huesos_object::Thread, u64, u64) -> Result<u64, ErrorCode>;
/// Kernel callback type used to start a suspended intra-process thread with
/// explicit `arg0` (`rdi`) and `fs_base`.
pub type ThreadStartExFn = fn(&huesos_object::Thread, u64, u64, u64, u64) -> Result<u64, ErrorCode>;
/// Kernel callback type used by `ThreadSetFsBase` to update the calling
/// thread's `MSR_FS_BASE`.
pub type ThreadSetFsBaseFn = fn(u64) -> Result<(), ErrorCode>;
/// Kernel callback type used by `ThreadSetGsBase` to update the calling
/// thread's Ring-3 `GS_BASE` (`IA32_KERNEL_GS_BASE`).
pub type ThreadSetGsBaseFn = fn(u64) -> Result<(), ErrorCode>;
/// Kernel callback type used by `ThreadGetGsBase` to read the calling
/// thread's Ring-3 `GS_BASE`.
pub type ThreadGetGsBaseFn = fn() -> Result<u64, ErrorCode>;
/// Kernel callback type used by `ProcessTerminate` to end a *foreign*
/// process. The koid names the victim; the code is the exit status every
/// `ProcessWait` observer must wake with.
pub type ProcessTerminateFn = fn(huesos_object::Koid, i64) -> Result<(), ErrorCode>;

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
/// Global Resource-unmap callback.
pub(crate) static RESOURCE_UNMAP_FN: Mutex<Option<ResourceUnmapFn>> = Mutex::new(None);
/// Global heap-extend callback (set by the kernel process layer).
pub(crate) static HEAP_EXTEND_FN: Mutex<Option<HeapExtendFn>> = Mutex::new(None);
/// Global thread-start callback (set by the kernel scheduler/process layer).
pub(crate) static THREAD_START_FN: Mutex<Option<ThreadStartFn>> = Mutex::new(None);
/// Global extended thread-start callback (set by the kernel scheduler/process layer).
pub(crate) static THREAD_START_EX_FN: Mutex<Option<ThreadStartExFn>> = Mutex::new(None);
/// Global single-thread exit callback (set by the kernel scheduler).
pub(crate) static THREAD_EXIT_FN: Mutex<Option<fn(i64) -> !>> = Mutex::new(None);
/// Global thread `FS_BASE` callback (set by the kernel scheduler).
pub(crate) static THREAD_SET_FS_BASE_FN: Mutex<Option<ThreadSetFsBaseFn>> = Mutex::new(None);
/// Global thread `GS_BASE` update callback (set by the kernel scheduler).
pub(crate) static THREAD_SET_GS_BASE_FN: Mutex<Option<ThreadSetGsBaseFn>> = Mutex::new(None);
/// Global thread `GS_BASE` query callback (set by the kernel scheduler).
pub(crate) static THREAD_GET_GS_BASE_FN: Mutex<Option<ThreadGetGsBaseFn>> = Mutex::new(None);
/// Global foreign-process terminate callback (set by the kernel scheduler).
pub(crate) static PROCESS_TERMINATE_FN: Mutex<Option<ProcessTerminateFn>> = Mutex::new(None);

/// Set the yield function. Called once by kernel init.
pub fn set_yield_fn(f: fn()) {
    YIELD_FN.call_once(|| f);
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
    CLOCK_FN.call_once(|| f);
}

/// Set the online CPU mask callback. Called once by kernel init.
pub fn set_cpu_mask_fn(f: fn() -> u64) {
    *CPU_MASK_FN.lock() = Some(f);
}

/// Install the online CPU count for the complete 256-CPU namespace.
pub fn set_cpu_count_fn(f: fn() -> usize) {
    *CPU_COUNT_FN.lock() = Some(f);
}

/// Install the full-namespace online-CPU predicate for 256-bit affinity.
pub fn set_cpu_online_fn(f: fn(usize) -> bool) {
    *CPU_ONLINE_FN.lock() = Some(f);
}

/// Set the scheduler snapshot callbacks. Called once by kernel init.
pub fn set_sched_stats_fns(summary: SchedSummaryFn, cpu: SchedCpuFn) {
    *SCHED_SUMMARY_FN.lock() = Some(summary);
    *SCHED_CPU_FN.lock() = Some(cpu);
}

/// Set the task-table callbacks. Called once by kernel init.
pub fn set_task_record_fn(f: TaskRecordFn) {
    *TASK_RECORD_FN.lock() = Some(f);
}

/// Set the live-task count callback. Called once by kernel init.
pub fn set_task_count_fn(f: TaskCountFn) {
    *TASK_COUNT_FN.lock() = Some(f);
}

/// Set the current dense CPU index callback. Called once by kernel init.
pub fn set_current_cpu_fn(f: fn() -> usize) {
    CURRENT_CPU_FN.call_once(|| f);
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

/// Set the Resource-unmap function. Called once by kernel init.
pub fn set_resource_unmap_fn(f: ResourceUnmapFn) {
    *RESOURCE_UNMAP_FN.lock() = Some(f);
}

/// Set the heap-extend function. Called once by kernel init.
pub fn set_heap_extend_fn(f: HeapExtendFn) {
    *HEAP_EXTEND_FN.lock() = Some(f);
}

/// Set the thread-start function. Called once by kernel init.
pub fn set_thread_start_fn(f: ThreadStartFn) {
    *THREAD_START_FN.lock() = Some(f);
}

/// Set the extended thread-start function. Called once by kernel init.
pub fn set_thread_start_ex_fn(f: ThreadStartExFn) {
    *THREAD_START_EX_FN.lock() = Some(f);
}

/// Set the single-thread exit function. Called once by kernel init.
pub fn set_thread_exit_fn(f: fn(i64) -> !) {
    *THREAD_EXIT_FN.lock() = Some(f);
}

/// Set the foreign-process terminate function. Called once by kernel init.
pub fn set_process_terminate_fn(f: ProcessTerminateFn) {
    *PROCESS_TERMINATE_FN.lock() = Some(f);
}

/// Set the thread `FS_BASE` update function. Called once by kernel init.
pub fn set_thread_set_fs_base_fn(f: ThreadSetFsBaseFn) {
    *THREAD_SET_FS_BASE_FN.lock() = Some(f);
}

/// Set the thread `GS_BASE` update function. Called once by kernel init.
pub fn set_thread_set_gs_base_fn(f: ThreadSetGsBaseFn) {
    *THREAD_SET_GS_BASE_FN.lock() = Some(f);
}

/// Set the thread `GS_BASE` query function. Called once by kernel init.
pub fn set_thread_get_gs_base_fn(f: ThreadGetGsBaseFn) {
    *THREAD_GET_GS_BASE_FN.lock() = Some(f);
}
