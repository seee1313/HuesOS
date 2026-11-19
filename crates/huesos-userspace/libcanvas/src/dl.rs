//! Capability-first dynamic module loading wrappers (`dyn-client`).
//!
//! All dynamic loading goes through capability handles (`Vmo`, `HxfsDirectory`,
//! `HxfsBlobView`, or validated `SONAME`s without path traversal) exported by
//! `libcanvas.so` and implemented by `/lib/ld-huesos.so`.

#[cfg(feature = "dyn-client")]
use core::ffi::{c_char, c_void};

#[cfg(feature = "dyn-client")]
pub use crate::rtld_abi::{
    CanvasDlInfo, CanvasDlPhdrInfo, RTLD_GLOBAL, RTLD_LAZY, RTLD_LOCAL, RTLD_NODELETE, RTLD_NOLOAD,
    RTLD_NOW,
};

#[cfg(feature = "dyn-client")]
#[link(name = "canvas", kind = "dylib")]
unsafe extern "C" {
    fn canvas_dlopen_vmo(vmo_handle: u32, flags: i32) -> *mut c_void;
    fn canvas_dlopen_soname(soname: *const c_char, flags: i32) -> *mut c_void;
    fn canvas_dlopen_blob(blob_ch: u32, flags: i32) -> *mut c_void;
    fn canvas_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn canvas_dlclose(handle: *mut c_void) -> i32;
    fn canvas_dlerror() -> *const c_char;
    fn canvas_dladdr(addr: *const c_void, out_info: *mut CanvasDlInfo) -> i32;
    fn canvas_dl_set_lib_dir(hxfs_dir_ch: u32) -> i32;
    fn canvas_dl_set_hxfs_service(hxfs_ch: u32) -> i32;
    fn canvas_atexit(func: extern "C" fn()) -> i64;
}

/// An owned dynamic module handle returned by [`open_vmo`], [`open_soname`],
/// or [`open_blob`].
#[cfg(feature = "dyn-client")]
pub struct DynamicModule {
    handle: *mut c_void,
}

#[cfg(feature = "dyn-client")]
impl DynamicModule {
    /// Load or reference a shared object directly from a `Vmo` capability.
    pub fn open_vmo(vmo: &crate::Vmo, flags: i32) -> Option<Self> {
        // SAFETY: `vmo` is a valid owned VMO handle in this process.
        let handle = unsafe { canvas_dlopen_vmo(vmo.handle().raw(), flags) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }

    /// Load a shared object by validated `SONAME` (no `/` or `..`).
    pub fn open_soname(soname: &str, flags: i32) -> Option<Self> {
        let mut buf = [0u8; 256];
        if soname.is_empty() || soname.len() >= buf.len() {
            return None;
        }
        buf[..soname.len()].copy_from_slice(soname.as_bytes());
        buf[soname.len()] = 0;
        // SAFETY: `buf` is NUL-terminated.
        let handle = unsafe { canvas_dlopen_soname(buf.as_ptr().cast::<c_char>(), flags) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }

    /// Load a shared object from an `HxfsBlobView` channel handle.
    pub fn open_blob_handle(blob_ch: &crate::Channel, flags: i32) -> Option<Self> {
        // SAFETY: `blob_ch` is a valid channel handle in this process.
        let handle = unsafe { canvas_dlopen_blob(blob_ch.handle().raw(), flags) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }

    /// Look up an exported symbol address inside this module.
    pub fn symbol(&self, name: &str) -> Option<*mut c_void> {
        let mut buf = [0u8; 256];
        if name.is_empty() || name.len() >= buf.len() {
            return None;
        }
        buf[..name.len()].copy_from_slice(name.as_bytes());
        buf[name.len()] = 0;
        // SAFETY: `self.handle` is live and `buf` is NUL-terminated.
        let ptr = unsafe { canvas_dlsym(self.handle, buf.as_ptr().cast::<c_char>()) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }

    /// Return the raw module handle pointer.
    pub fn as_raw(&self) -> *mut c_void {
        self.handle
    }
}

#[cfg(feature = "dyn-client")]
impl Drop for DynamicModule {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: `self.handle` was returned by `canvas_dlopen_*`.
            let _ = unsafe { canvas_dlclose(self.handle) };
            self.handle = core::ptr::null_mut();
        }
    }
}

/// Return the last dynamic-linker error message for the calling thread, or
/// `None` if no error is pending.
#[cfg(feature = "dyn-client")]
pub fn last_error() -> Option<&'static str> {
    // SAFETY: `canvas_dlerror` returns NULL or a static/per-thread NUL-terminated string.
    let ptr = unsafe { canvas_dlerror() };
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: `ptr` points to a NUL-terminated string owned by ld-huesos.
    unsafe {
        while *ptr.add(len) != 0 && len < 256 {
            len += 1;
        }
        let bytes = core::slice::from_raw_parts(ptr.cast::<u8>(), len);
        core::str::from_utf8(bytes).ok()
    }
}

/// Query address metadata via `canvas_dladdr`.
#[cfg(feature = "dyn-client")]
pub fn addr_info(addr: usize) -> Option<CanvasDlInfo> {
    let mut info = CanvasDlInfo {
        dli_fname: core::ptr::null(),
        dli_fbase: core::ptr::null_mut(),
        dli_sname: core::ptr::null(),
        dli_saddr: core::ptr::null_mut(),
    };
    // SAFETY: `canvas_dladdr` treats `addr` purely as a virtual address to look
    // up in loaded ELF symbol tables without dereferencing it, and `info` is
    // valid writable stack storage.
    let rc = unsafe { canvas_dladdr(addr as *const c_void, &mut info) };
    if rc != 0 {
        Some(info)
    } else {
        None
    }
}

/// Register an `HxfsDirectory` channel as the primary capability library directory.
#[cfg(feature = "dyn-client")]
pub fn set_lib_dir(dir: &crate::HxfsDirectory) -> bool {
    // SAFETY: `dir.channel()` holds an open directory channel handle.
    unsafe { canvas_dl_set_lib_dir(dir.channel().handle().raw()) == 0 }
}

/// Register an `Hxfs` service channel (opens `/lib` for SONAME lookup).
#[cfg(feature = "dyn-client")]
pub fn set_hxfs_service(fs: &crate::Hxfs) -> bool {
    // SAFETY: `fs.channel()` holds an open HxFS service channel handle.
    unsafe { canvas_dl_set_hxfs_service(fs.channel().handle().raw()) == 0 }
}

/// Register a process-exit callback via `canvas_atexit`.
#[cfg(feature = "dyn-client")]
pub fn atexit(func: extern "C" fn()) -> bool {
    // SAFETY: `func` is a valid `extern "C" fn()` pointer.
    unsafe { canvas_atexit(func) == 0 }
}
