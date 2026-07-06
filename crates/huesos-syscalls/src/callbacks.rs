//! Scheduler/kernel callbacks registered by `huesos-kernel`.

use alloc::sync::Arc;
use huesos_abi::{ErrorCode, VmarMapArgs};
use spin::Mutex;

/// Global yield callback (set by kernel scheduler to avoid circular deps).
pub(crate) static YIELD_FN: Mutex<Option<fn()>> = Mutex::new(None);
/// Global process-exit callback (set by kernel scheduler).
pub(crate) static EXIT_FN: Mutex<Option<fn(i64) -> !>> = Mutex::new(None);
/// Global debug-write callback (set by kernel to point at the serial writer).
pub(crate) static DEBUG_WRITE_FN: Mutex<Option<fn(&[u8])>> = Mutex::new(None);

/// Kernel callback type used by the syscall layer to create a suspended process.
pub type ProcessCreateFn =
    fn(&str) -> Result<(Arc<huesos_object::Process>, Arc<huesos_object::Vmar>), ErrorCode>;
/// Kernel callback type used by the syscall layer to map a VMO into a VMAR.
pub type VmarMapFn =
    fn(&huesos_object::Vmar, &huesos_object::Vmo, VmarMapArgs) -> Result<u64, ErrorCode>;
/// Kernel callback type used by the syscall layer to start a suspended thread.
pub type ThreadStartFn = fn(&huesos_object::Thread, u64, u64) -> Result<u64, ErrorCode>;

/// Global process-create callback (set by the kernel process layer).
pub(crate) static PROCESS_CREATE_FN: Mutex<Option<ProcessCreateFn>> = Mutex::new(None);
/// Global VMAR-map callback (set by the kernel process layer).
pub(crate) static VMAR_MAP_FN: Mutex<Option<VmarMapFn>> = Mutex::new(None);
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
pub fn set_debug_write_fn(f: fn(&[u8])) {
    *DEBUG_WRITE_FN.lock() = Some(f);
}

/// Set the process-create function. Called once by kernel init.
pub fn set_process_create_fn(f: ProcessCreateFn) {
    *PROCESS_CREATE_FN.lock() = Some(f);
}

/// Set the VMAR-map function. Called once by kernel init.
pub fn set_vmar_map_fn(f: VmarMapFn) {
    *VMAR_MAP_FN.lock() = Some(f);
}

/// Set the thread-start function. Called once by kernel init.
pub fn set_thread_start_fn(f: ThreadStartFn) {
    *THREAD_START_FN.lock() = Some(f);
}
