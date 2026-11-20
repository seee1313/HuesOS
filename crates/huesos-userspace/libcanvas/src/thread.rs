//! Safe intra-process multi-threading and per-thread TLS support.
//!
//! When used in dynamically linked binaries (`dyn-client`) or inside
//! `libcanvas.so` (`c-abi`), spawned threads automatically receive a fresh
//! Variant-II TLS block, TCB (`%fs:0`), and DTV (`%fs:8`) from `ld-huesos.so`
//! and clean them up on exit.

#[cfg(feature = "thread-tasks")]
use alloc::boxed::Box;
#[cfg(feature = "thread-tasks")]
use alloc::vec::Vec;
#[cfg(feature = "dyn-client")]
use core::ffi::{c_char, c_void};
#[cfg(feature = "thread-tasks")]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "dyn-client")]
#[link(name = "canvas", kind = "dylib")]
unsafe extern "C" {
    /// `entry` is an `extern "C" fn(*mut c_void) -> i64`. It is declared as an
    /// opaque pointer so that a *safe* trampoline can be passed as well as the
    /// `unsafe extern "C" fn` callers supply: the two are the same machine code
    /// and the callee only ever jumps to it.
    fn canvas_thread_spawn(
        name: *const c_char,
        entry: *const c_void,
        arg: *mut c_void,
        stack_size: usize,
        out_thread: *mut *mut c_void,
    ) -> i64;
    fn canvas_thread_join(thread: *mut c_void, out_exit_code: *mut i64) -> i64;
    fn canvas_thread_exit(code: i64) -> !;
}

/// An opaque handle to a spawned intra-process thread.
#[cfg(feature = "dyn-client")]
pub struct JoinHandle {
    raw: *mut c_void,
    /// Identifier handed out by [`spawn_task`]; `0` for [`spawn`].
    pub(crate) id: usize,
}

#[cfg(feature = "dyn-client")]
impl JoinHandle {
    /// Identifier handed out by [`spawn_task`] (`0` for [`spawn`]).
    pub fn thread_id(&self) -> u64 {
        self.id as u64
    }

    /// Block until the thread exits and return its exit code.
    pub fn join(mut self) -> crate::Result<i64> {
        self.release()
    }

    /// Join the underlying thread exactly once, if it is still live.
    ///
    /// A handle that was already joined returns `Ok(0)` instead of joining a
    /// second time: the pointer is cleared before the call, so the FFI is only
    /// ever reached with a handle the runtime still knows about.
    fn release(&mut self) -> crate::Result<i64> {
        let ptr = core::mem::replace(&mut self.raw, core::ptr::null_mut());
        if ptr.is_null() {
            return Ok(0);
        }
        let mut code: i64 = 0;
        // SAFETY: `ptr` was returned by `canvas_thread_spawn`, and clearing the
        // field first means exactly one call to `canvas_thread_join` per handle.
        let rc = unsafe { canvas_thread_join(ptr, &mut code) };
        if rc < 0 {
            Err(huesos_abi::ErrorCode::from_raw(rc).unwrap_or(huesos_abi::ErrorCode::InvalidArgs))
        } else {
            Ok(code)
        }
    }
}

#[cfg(feature = "dyn-client")]
impl Drop for JoinHandle {
    fn drop(&mut self) {
        // Reclaim the runtime's per-thread resources even if nobody joined.
        let _ = self.release();
    }
}

/// Spawn a new thread inside the current dynamic process with an optional stack
/// size (`0` uses the default 64 KiB profile) and per-thread TLS/TCB/DTV.
///
/// # Safety
/// `arg` must be valid for the lifetime of the spawned thread if `entry`
/// dereferences it.
#[cfg(feature = "dyn-client")]
pub unsafe fn spawn(
    name: &str,
    entry: unsafe extern "C" fn(*mut c_void) -> i64,
    arg: *mut c_void,
    stack_size: usize,
) -> crate::Result<JoinHandle> {
    let mut name_buf = [0u8; 64];
    let copy_len = name.len().min(63);
    name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
    name_buf[copy_len] = 0;
    let mut out_thread: *mut c_void = core::ptr::null_mut();
    // SAFETY: `name_buf` is NUL-terminated and `out_thread` is stack-allocated.
    let rc = unsafe {
        canvas_thread_spawn(
            name_buf.as_ptr().cast::<c_char>(),
            entry as *const c_void,
            arg,
            stack_size,
            &mut out_thread,
        )
    };
    if rc < 0 {
        Err(huesos_abi::ErrorCode::from_raw(rc).unwrap_or(huesos_abi::ErrorCode::InvalidArgs))
    } else {
        Ok(JoinHandle {
            raw: out_thread,
            id: 0,
        })
    }
}

/// Exit only the calling thread (cleaning up its dynamic TLS/TCB/DTV).
#[cfg(feature = "dyn-client")]
pub fn exit(code: i64) -> ! {
    // SAFETY: `canvas_thread_exit` never returns.
    unsafe { canvas_thread_exit(code) }
}

// Everything below needs `alloc` for the task table. It is a separate feature
// from `dyn-client` on purpose: a dynamic binary that never spawns a closure
// must not be forced to bring a global allocator into its own crate graph.

/// The exit code reported for a task whose slot had already been claimed.
#[cfg(feature = "thread-tasks")]
const TASK_LOST: i64 = -1;

/// Boxed worker body. `Send` only: the task runs on another thread, so the
/// captured state must be able to move there, but nothing else is required.
#[cfg(feature = "thread-tasks")]
type Task = Box<dyn FnOnce() -> i64 + Send>;

/// Pending worker bodies, indexed by the integer handed to the trampoline.
///
/// A thread entry point receives exactly one `*mut c_void`, and reclaiming a
/// `Box` from that pointer would need `unsafe`. The task therefore travels by
/// *index* instead: the spawner stores the box here and passes a number, and
/// the trampoline takes it out through ordinary safe `Vec`/`Mutex` access.
#[cfg(feature = "thread-tasks")]
static TASKS: spin::Mutex<Vec<Option<Task>>> = spin::Mutex::new(Vec::new());

/// Next thread id handed out to [`spawn_task`] callers.
#[cfg(feature = "thread-tasks")]
static NEXT_THREAD_ID: AtomicUsize = AtomicUsize::new(1);

/// Trampoline: take the worker body for `arg` (an index) and run it.
#[cfg(feature = "thread-tasks")]
extern "C" fn task_trampoline(arg: *mut c_void) -> i64 {
    let index = arg as usize;
    let task = {
        let mut tasks = TASKS.lock();
        tasks.get_mut(index).and_then(Option::take)
    };
    match task {
        Some(task) => task(),
        None => TASK_LOST,
    }
}

/// Spawn `task` on a fresh thread and return a join handle.
///
/// Unlike [`spawn`] this is safe: the closure owns its captures, and the
/// thread entry is a trampoline that reads them out of the task table.
#[cfg(feature = "thread-tasks")]
pub fn spawn_task<F>(name: &str, task: F, stack_size: usize) -> crate::Result<JoinHandle>
where
    F: FnOnce() -> i64 + Send + 'static,
{
    let index = {
        let mut tasks = TASKS.lock();
        let index = match tasks.iter().position(Option::is_none) {
            Some(free) => free,
            None => {
                tasks.push(None);
                tasks.len() - 1
            }
        };
        tasks[index] = Some(Box::new(task));
        index
    };
    let mut name_buf = [0u8; 64];
    let copy_len = name.len().min(63);
    name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
    let mut out_thread: *mut c_void = core::ptr::null_mut();
    // SAFETY: `entry` is this module's trampoline, `arg` is the index of a
    // live slot in TASKS (not a pointer), `name_buf` is NUL-terminated and
    // `out_thread` is a valid stack slot.
    let rc = unsafe {
        canvas_thread_spawn(
            name_buf.as_ptr().cast::<c_char>(),
            task_trampoline as *const c_void,
            index as *mut c_void,
            stack_size,
            &mut out_thread,
        )
    };
    if rc < 0 {
        // The trampoline never ran, so the slot is still ours: clear it.
        TASKS.lock()[index] = None;
        return Err(
            huesos_abi::ErrorCode::from_raw(rc).unwrap_or(huesos_abi::ErrorCode::InvalidArgs)
        );
    }
    Ok(JoinHandle {
        raw: out_thread,
        id: NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed),
    })
}

/// The identifier of a thread spawned with [`spawn_task`].
#[cfg(feature = "dyn-client")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ThreadId(
    /// Monotonic id, unique within the process.
    pub u64,
);
