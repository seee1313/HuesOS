//! Safe intra-process multi-threading and per-thread TLS support.
//!
//! When used in dynamically linked binaries (`dyn-client`) or inside
//! `libcanvas.so` (`c-abi`), spawned threads automatically receive a fresh
//! Variant-II TLS block, TCB (`%fs:0`), and DTV (`%fs:8`) from `ld-huesos.so`
//! and clean them up on exit.

#[cfg(feature = "dyn-client")]
use core::ffi::{c_char, c_void};

#[cfg(feature = "dyn-client")]
#[link(name = "canvas", kind = "dylib")]
unsafe extern "C" {
    fn canvas_thread_spawn(
        name: *const c_char,
        entry: unsafe extern "C" fn(*mut c_void) -> i64,
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
}

#[cfg(feature = "dyn-client")]
impl JoinHandle {
    /// Block until the thread exits and return its exit code.
    pub fn join(mut self) -> crate::Result<i64> {
        let mut code: i64 = 0;
        let ptr = core::mem::replace(&mut self.raw, core::ptr::null_mut());
        // SAFETY: `ptr` was returned by `canvas_thread_spawn` and has not yet
        // been joined.
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
        if !self.raw.is_null() {
            let mut ignored = 0i64;
            // SAFETY: ensure spawned thread resources are reclaimed on drop.
            let _ = unsafe { canvas_thread_join(self.raw, &mut ignored) };
            self.raw = core::ptr::null_mut();
        }
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
            entry,
            arg,
            stack_size,
            &mut out_thread,
        )
    };
    if rc < 0 {
        Err(huesos_abi::ErrorCode::from_raw(rc).unwrap_or(huesos_abi::ErrorCode::InvalidArgs))
    } else {
        Ok(JoinHandle { raw: out_thread })
    }
}

/// Exit only the calling thread (cleaning up its dynamic TLS/TCB/DTV).
#[cfg(feature = "dyn-client")]
pub fn exit(code: i64) -> ! {
    // SAFETY: `canvas_thread_exit` never returns.
    unsafe { canvas_thread_exit(code) }
}
