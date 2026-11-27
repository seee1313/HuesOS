//! Shared ABI contract between `/lib/ld-huesos.so` and `libcanvas.so`.
//!
//! Breaking `DT_NEEDED` cycles: `ld-huesos.so` registers an [`RtldOps`] table
//! into `libcanvas.so` via `__huesos_register_rtld` right after relocating
//! `libcanvas.so`, and receives [`HostAllocOps`] backed by `libcanvas.so`'s
//! `ScudoHeap` for per-thread DTV / dynamic TLS block management.

use core::ffi::{c_char, c_void};

/// Current [`RtldOps`] and [`HostAllocOps`] ABI version.
pub const RTLD_OPS_VERSION: u32 = 1;

/// `dlopen` flag: accepted for compatibility; HuesOS always enforces `BIND_NOW`.
pub const RTLD_LAZY: i32 = 0x0001;
/// `dlopen` flag: bind all relocations eagerly (`BIND_NOW`).
pub const RTLD_NOW: i32 = 0x0002;
/// `dlopen` flag: keep symbols local to this module's dependency graph (default).
pub const RTLD_LOCAL: i32 = 0x0000;
/// `dlopen` flag: expose symbols to subsequent global lookups.
pub const RTLD_GLOBAL: i32 = 0x0100;
/// `dlopen` flag: return an existing handle if already loaded, else `NULL`.
pub const RTLD_NOLOAD: i32 = 0x0004;
/// `dlopen` flag: pin module so `canvas_dlclose` does not unload it.
pub const RTLD_NODELETE: i32 = 0x1000;

/// Symbol/object metadata returned by `canvas_dladdr`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CanvasDlInfo {
    /// Loaded object `SONAME` or path NUL-terminated string (or `NULL`).
    pub dli_fname: *const c_char,
    /// Load bias / base address of the object containing `addr`.
    pub dli_fbase: *mut c_void,
    /// Nearest symbol name NUL-terminated string (or `NULL`).
    pub dli_sname: *const c_char,
    /// Resolved virtual address of `dli_sname` (or `NULL`).
    pub dli_saddr: *mut c_void,
}

/// Loaded object metadata passed to `canvas_dl_iterate_phdr` callbacks.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CanvasDlPhdrInfo {
    /// Object relocation bias (`dlpi_addr`).
    pub dlpi_addr: u64,
    /// Object `SONAME` or name NUL-terminated string.
    pub dlpi_name: *const c_char,
    /// Pointer to `Elf64_Phdr[]` in memory (`NULL` if not mapped).
    pub dlpi_phdr: *const u8,
    /// Number of program headers in `dlpi_phdr`.
    pub dlpi_phnum: u16,
    /// Monotonic counter of object loads (`dlpi_adds`).
    pub dlpi_adds: u64,
    /// Monotonic counter of object unloads (`dlpi_subs`).
    pub dlpi_subs: u64,
    /// Dynamic TLS module ID (`0` when the object has no `PT_TLS`).
    pub dlpi_tls_modid: usize,
    /// Calling thread's TLS block address for this module (or `NULL`).
    pub dlpi_tls_data: *mut c_void,
}

/// Allocator callbacks provided by `libcanvas.so` (`ScudoHeap`) to `ld-huesos.so`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostAllocOps {
    /// Struct ABI version (`RTLD_OPS_VERSION`).
    pub version: u32,
    /// Allocate `size` bytes aligned to `align` from `ScudoHeap`.
    pub alloc: unsafe extern "C" fn(size: usize, align: usize) -> *mut u8,
    /// Free a pointer previously returned by `alloc`.
    pub free: unsafe extern "C" fn(ptr: *mut u8),
}

/// Runtime dynamic linker dispatch table registered by `ld-huesos.so` into
/// `libcanvas.so`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtldOps {
    /// Struct ABI version (`RTLD_OPS_VERSION`).
    pub version: u32,
    /// General-Dynamic / Local-Dynamic TLS resolver (`__tls_get_addr`).
    pub tls_get_addr: unsafe extern "C" fn(ti: *const u8) -> *mut u8,
    /// Load/open a shared object from an explicit `Vmo` capability handle.
    pub dlopen_vmo: unsafe extern "C" fn(vmo_handle: u32, flags: i32) -> *mut c_void,
    /// Load/open a shared object by validated `SONAME` using HxFS -> BOOTFS.
    pub dlopen_soname: unsafe extern "C" fn(soname: *const c_char, flags: i32) -> *mut c_void,
    /// Load/open a shared object from an `HxfsBlobView` channel handle.
    pub dlopen_blob: unsafe extern "C" fn(blob_ch: u32, flags: i32) -> *mut c_void,
    /// Resolve an exported symbol from a module handle (or `NULL` for global).
    pub dlsym: unsafe extern "C" fn(handle: *mut c_void, symbol: *const c_char) -> *mut c_void,
    /// Decrement module refcount and unload + run destructors at zero.
    pub dlclose: unsafe extern "C" fn(handle: *mut c_void) -> i32,
    /// Return and clear the per-thread error message from the last `dl*` call.
    pub dlerror: unsafe extern "C" fn() -> *const c_char,
    /// Resolve address metadata (`CanvasDlInfo`).
    pub dladdr: unsafe extern "C" fn(addr: *const c_void, out_info: *mut CanvasDlInfo) -> i32,
    /// Iterate currently loaded shared objects.
    pub dl_iterate_phdr: unsafe extern "C" fn(
        cb: Option<unsafe extern "C" fn(*mut CanvasDlPhdrInfo, usize, *mut c_void) -> i32>,
        data: *mut c_void,
    ) -> i32,
    /// Register or replace the HxFS `DirectoryHandle` capability for SONAME lookup.
    pub dl_set_lib_dir: unsafe extern "C" fn(hxfs_dir_ch: u32) -> i32,
    /// Register an `Hxfs` service channel capability (opens `/lib` lazily).
    pub dl_set_hxfs_service: unsafe extern "C" fn(hxfs_ch: u32) -> i32,
    /// Register a DSO destructor callback (`__cxa_atexit`).
    pub cxa_atexit: unsafe extern "C" fn(
        func: Option<unsafe extern "C" fn(*mut c_void)>,
        arg: *mut c_void,
        dso_handle: *mut c_void,
    ) -> i32,
    /// Run `__cxa_atexit` and reverse-topological `DT_FINI_ARRAY` / `DT_FINI` once.
    pub run_process_fini: unsafe extern "C" fn(),
    /// Allocate and initialize Variant-II static TLS + TCB + DTV for a new thread.
    pub alloc_thread_tls: unsafe extern "C" fn() -> u64,
    /// Free dynamic TLS blocks and unmap the TLS VMO of an exiting thread.
    pub free_thread_tls: unsafe extern "C" fn(tp: u64),
}

/// Process bootstrap metadata passed by `/lib/ld-huesos.so` to `libcanvas.so`
/// before any `.init_array` or `_start` executes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessBootstrapInfo {
    /// Struct ABI version (`RTLD_OPS_VERSION`).
    pub version: u32,
    /// Number of arguments in `argv`.
    pub argc: usize,
    /// Pointer to `argc` NUL-terminated argument pointers on the initial stack.
    pub argv: *const *const c_char,
    /// Attenuated `@caps(...)` capability bitmask (`huesos_abi::auxv::caps_mask`).
    pub caps_mask: u64,
    /// Capability handle for `stdin` channel (`INVALID_HANDLE` if absent).
    pub stdin_ch: u32,
    /// Capability handle for `stdout` channel (`INVALID_HANDLE` if absent).
    pub stdout_ch: u32,
    /// Capability handle for `stderr` channel (`INVALID_HANDLE` if absent).
    pub stderr_ch: u32,
    /// Capability handle for attenuated HxFS directory (`INVALID_HANDLE` if absent).
    pub hxfs_dir_ch: u32,
    /// Capability handle for HxFS service (`INVALID_HANDLE` if absent).
    pub hxfs_service_ch: u32,
    /// Capability handle for block device (`INVALID_HANDLE` if absent).
    pub block_dev_ch: u32,
    /// Capability handle for framebuffer draw resource (`INVALID_HANDLE` if absent).
    pub frame_draw_ch: u32,
    /// Capability handle for read-only `BOOTFS` VMO (`INVALID_HANDLE` if absent/`bootfs=none`).
    pub bootfs_vmo: u32,
    /// Capability handle for `DriverManager` query/registry channel (`INVALID_HANDLE` if absent).
    pub registry_ch: u32,
    /// Capability handle for `net-service` (`Plan 9 /net`) channel (`INVALID_HANDLE` if absent).
    pub net_service_ch: u32,
    /// Capability handle for `wlan-service` channel (`INVALID_HANDLE` if absent).
    pub wlan_service_ch: u32,
    /// Capability handle for `btl-service` (`Plan 9 /net/btl`) channel (`INVALID_HANDLE` if absent).
    pub btl_service_ch: u32,
    /// Capability handle for `audio-service` (`/dev/audio`) channel (`INVALID_HANDLE` if absent).
    pub audio_service_ch: u32,
    /// Target PE32+ `.exe` VMO handle when launching `/lib/ld-pe.so` (`INVALID_HANDLE` otherwise).
    pub pe_vmo: u32,
    /// Self root VMAR handle retained exclusively for `/lib/ld-pe.so` (`INVALID_HANDLE` otherwise).
    pub pe_self_vmar: u32,
    /// Byte offset of the target PE32+ `.exe` inside `pe_vmo`.
    pub pe_offset: u64,
    /// Byte length of the target PE32+ `.exe` inside `pe_vmo`.
    pub pe_len: u64,
}
