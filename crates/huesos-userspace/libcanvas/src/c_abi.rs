//! Stable C ABI exported by `libcanvas.so` (`cdylib` with `--features c-abi`).
//!
//! Every exported symbol here matches `include/canvas.h` verbatim. Applications
//! linked dynamically against `libcanvas.so` share this single Scudo heap
//! instance (auto-initialised via `.init_array` before `_start`) and route all
//! syscalls through `canvas_syscall` or the typed `canvas_*` helpers.

extern crate alloc;

use alloc::boxed::Box;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::ffi::{c_char, c_void};
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use huesos_abi::{
    wait_mode, ChannelReadEtcArgs, ErrorCode, FramebufferBlitArgs, FramebufferInfo, HandleValue,
    Syscall, VmarMapArgs, VmarOpArgs, WaitSetItem, WaitSetResult, WaitSetWaitArgs,
    BOOTSTRAP_HANDLE, INVALID_HANDLE,
};

use crate::framebuffer::{Canvas, TextFont};
use crate::heap::ScudoHeap;
use crate::hxfs::{Hxfs, HxfsFile};
use crate::rtld_abi::{CanvasDlInfo, CanvasDlPhdrInfo, HostAllocOps, RtldOps, RTLD_OPS_VERSION};
use crate::{debug, memory, process, raw, system};

/// Single process-wide Scudo heap living inside `libcanvas.so`.
#[global_allocator]
static GLOBAL_HEAP: ScudoHeap = ScudoHeap::new();

static RTLD_OPS_PTR: AtomicPtr<RtldOps> = AtomicPtr::new(ptr::null_mut());
static FINI_EXECUTED: AtomicBool = AtomicBool::new(false);

#[inline]
fn rtld_ops() -> Option<&'static RtldOps> {
    let ptr = RTLD_OPS_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: `ld-huesos.so` registers a static `'static` `RtldOps` table
        // via `__huesos_register_rtld` before any application code runs.
        Some(unsafe { &*ptr })
    }
}

/// Run registered `__cxa_atexit` / `DT_FINI_ARRAY` / `DT_FINI` finalisers once
/// before terminating the process.
pub(crate) fn run_process_fini_once() {
    if FINI_EXECUTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        if let Some(ops) = rtld_ops() {
            // SAFETY: registered `RtldOps::run_process_fini` handles locking
            // and reverse-topological execution once.
            unsafe { (ops.run_process_fini)() };
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn libcanvas_panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    debug::write_str("[libcanvas.so] PANIC\n");
    process::exit(-1);
}

extern "C" fn canvas_ctor_init() {
    // SAFETY: `.init_array` executes once during dynamic-linker setup before
    // `_start` while the process is single-threaded.
    let _ = unsafe { GLOBAL_HEAP.init() };
}

#[used]
#[unsafe(link_section = ".init_array")]
static CANVAS_INIT_ARRAY_ENTRY: extern "C" fn() = canvas_ctor_init;

const ABI_VERSION: u32 = 1;
const MAX_WAIT_ITEMS: usize = crate::waitset::MAX_ITEMS;

/// Framebuffer geometry C ABI mirror (`CanvasFbInfo` in `include/canvas.h`).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct CanvasFbInfo {
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u16,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
}

/// Multiplexed wait item C ABI mirror (`CanvasWaitItem` in `include/canvas.h`).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct CanvasWaitItem {
    pub handle: u32,
    pub awaited_signals: u32,
    pub key: u64,
    pub observed_signals: u32,
    pub _reserved: u32,
}

/// Heap stats C ABI mirror (`CanvasHeapStats` in `include/canvas.h`).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct CanvasHeapStats {
    pub allocations: u64,
    pub deallocations: u64,
    pub oom_failures: u64,
    pub corruption_failures: u64,
    pub live_bytes: u64,
}

/// Opaque off-screen drawing surface (`CanvasSurface` in `include/canvas.h`).
pub struct CanvasSurface {
    inner: Canvas,
}

/// Opaque HxFS client (`CanvasFs` in `include/canvas.h`).
pub struct CanvasFs {
    inner: Hxfs,
}

/// Opaque HxFS file (`CanvasFsFile` in `include/canvas.h`).
pub struct CanvasFsFile {
    inner: HxfsFile,
}

#[inline]
fn err_code(err: ErrorCode) -> i64 {
    err as i64
}

#[inline]
fn to_abi_result(res: crate::Result<()>) -> i64 {
    match res {
        Ok(()) => 0,
        Err(err) => err_code(err),
    }
}

/// Validate and borrow an immutable C byte buffer.
///
/// # Safety
/// If `len > 0`, `ptr` must point to `len` readable bytes.
unsafe fn read_bytes<'a>(ptr: *const u8, len: usize) -> crate::Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    // SAFETY: caller guarantees `ptr..ptr+len` is valid for reads.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Validate and borrow a mutable C slice of `T`.
///
/// # Safety
/// If `len > 0`, `ptr` must be non-null, aligned, and valid for `len` writable items.
unsafe fn write_slice<'a, T>(ptr: *mut T, len: usize) -> crate::Result<&'a mut [T]> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() || !(ptr as usize).is_multiple_of(core::mem::align_of::<T>()) {
        return Err(ErrorCode::InvalidArgs);
    }
    // SAFETY: caller guarantees `ptr..ptr+len` is valid for writes and aligned.
    Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

/// Validate and borrow an immutable C slice of `T`.
///
/// # Safety
/// If `len > 0`, `ptr` must be non-null, aligned, and valid for `len` readable items.
unsafe fn read_slice<'a, T>(ptr: *const T, len: usize) -> crate::Result<&'a [T]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() || !(ptr as usize).is_multiple_of(core::mem::align_of::<T>()) {
        return Err(ErrorCode::InvalidArgs);
    }
    // SAFETY: caller guarantees `ptr..ptr+len` is valid for reads and aligned.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Write a `Copy` output value to a C out-pointer after null/alignment validation.
///
/// # Safety
/// When non-null and aligned, `out` must point to writable memory of size `size_of::<T>()`.
unsafe fn write_out<T: Copy>(out: *mut T, value: T) -> crate::Result<()> {
    if out.is_null() || !(out as usize).is_multiple_of(core::mem::align_of::<T>()) {
        return Err(ErrorCode::InvalidArgs);
    }
    // SAFETY: null and alignment checked; caller guarantees valid writable storage.
    unsafe { ptr::write(out, value) };
    Ok(())
}

/// Box `value` on the shared Scudo heap and store its pointer in `out`.
///
/// # Safety
/// `out` must be a valid writable pointer when non-null.
unsafe fn box_into_out<T>(out: *mut *mut T, value: T) -> crate::Result<()> {
    if out.is_null() || !(out as usize).is_multiple_of(core::mem::align_of::<*mut T>()) {
        return Err(ErrorCode::InvalidArgs);
    }
    let boxed = Box::new(value);
    let raw_ptr = Box::into_raw(boxed);
    // SAFETY: `out` is non-null, aligned, and valid per caller contract.
    unsafe { ptr::write(out, raw_ptr) };
    Ok(())
}

/// Borrow an opaque pointer created via `Box::into_raw`.
///
/// # Safety
/// If non-null, `ptr` must point to a live `T` owned on the shared heap.
unsafe fn borrow_ref<'a, T>(ptr: *const T) -> crate::Result<&'a T> {
    if ptr.is_null() || !(ptr as usize).is_multiple_of(core::mem::align_of::<T>()) {
        return Err(ErrorCode::InvalidArgs);
    }
    // SAFETY: null and alignment checked; caller guarantees live `T`.
    Ok(unsafe { &*ptr })
}

/// Mutably borrow an opaque pointer created via `Box::into_raw`.
///
/// # Safety
/// If non-null, `ptr` must point to a live, exclusively borrowed `T`.
unsafe fn borrow_mut<'a, T>(ptr: *mut T) -> crate::Result<&'a mut T> {
    if ptr.is_null() || !(ptr as usize).is_multiple_of(core::mem::align_of::<T>()) {
        return Err(ErrorCode::InvalidArgs);
    }
    // SAFETY: null and alignment checked; caller guarantees exclusive live `T`.
    Ok(unsafe { &mut *ptr })
}

/// Reclaim and drop a boxed opaque pointer.
///
/// # Safety
/// If non-null, `ptr` must have been allocated by `Box::into_raw` on `GLOBAL_HEAP`.
unsafe fn drop_boxed<T>(ptr: *mut T) {
    if !ptr.is_null() && (ptr as usize).is_multiple_of(core::mem::align_of::<T>()) {
        // SAFETY: `ptr` was produced by `Box::into_raw` and is dropped once here.
        let _ = unsafe { Box::from_raw(ptr) };
    }
}

/* --------------------------------------------------------------------------
 * ABI metadata & raw syscall gateway
 * -------------------------------------------------------------------------- */

/// Return the stable C ABI version (`CANVAS_ABI_VERSION`).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_abi_version() -> u32 {
    ABI_VERSION
}

/// Return a static NUL-terminated error string for a raw HuesOS error code.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_error_str(err: i64) -> *const u8 {
    let text: &'static [u8] = if err == 0 {
        b"Ok\0"
    } else {
        match ErrorCode::from_raw(err) {
            Some(ErrorCode::InvalidArgs) => b"InvalidArgs\0",
            Some(ErrorCode::BadHandle) => b"BadHandle\0",
            Some(ErrorCode::WrongType) => b"WrongType\0",
            Some(ErrorCode::AccessDenied) => b"AccessDenied\0",
            Some(ErrorCode::NoMemory) => b"NoMemory\0",
            Some(ErrorCode::Busy) => b"Busy\0",
            Some(ErrorCode::ShouldWait) => b"ShouldWait\0",
            Some(ErrorCode::NotFound) => b"NotFound\0",
            Some(ErrorCode::NoFramebuffer) => b"NoFramebuffer\0",
            Some(ErrorCode::NotSupported) => b"NotSupported\0",
            Some(ErrorCode::TimedOut) => b"TimedOut\0",
            Some(ErrorCode::Internal) => b"Internal\0",
            Some(ErrorCode::PeerClosed) => b"PeerClosed\0",
            None => b"UnknownError\0",
        }
    };
    text.as_ptr()
}

/// Forward a raw HuesOS syscall through `libcanvas.so`'s audited trampoline.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_syscall(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let Some(syscall) = Syscall::from_raw(num) else {
        return err_code(ErrorCode::NotSupported);
    };
    raw::syscall5(syscall, a1, a2, a3, a4, a5)
}

/* --------------------------------------------------------------------------
 * Process, thread, console & system primitives
 * -------------------------------------------------------------------------- */

/// Terminate the calling process immediately.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_exit(code: i64) -> ! {
    process::exit(code)
}

/// Cooperatively yield the current scheduling quantum.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_yield() {
    process::yield_now();
}

/// Set the calling thread's x86-64 `MSR_FS_BASE`.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_set_fs_base(fs_base: u64) -> i64 {
    to_abi_result(process::set_fs_base(fs_base))
}

/// Write `len` bytes to the kernel serial debug log.
///
/// # Safety
/// If `len > 0`, `bytes` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_debug_write(bytes: *const u8, len: usize) {
    // SAFETY: forwarded from C caller contract.
    if let Ok(slice) = unsafe { read_bytes(bytes, len) } {
        debug::write_bytes(slice);
    }
}

/// Write a NUL-terminated C string to the kernel debug log (bounded at 4096 bytes).
///
/// # Safety
/// If non-null, `cstr` must point to a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_debug_puts(cstr: *const u8) {
    if cstr.is_null() {
        return;
    }
    let mut len = 0usize;
    while len < 4096 {
        // SAFETY: caller guarantees NUL-terminated string within valid memory.
        let byte = unsafe { *cstr.add(len) };
        if byte == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `len` stops before or at 4096 inside the valid C string.
    if let Ok(slice) = unsafe { read_bytes(cstr, len) } {
        debug::write_bytes(slice);
    }
}

/// Read the monotonic scheduler clock in 100 Hz ticks.
///
/// # Safety
/// `out_ticks` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_monotonic_ticks(out_ticks: *mut u64) -> i64 {
    match system::monotonic_ticks() {
        // SAFETY: validated by `write_out`.
        Ok(ticks) => to_abi_result(unsafe { write_out(out_ticks, ticks) }),
        Err(err) => err_code(err),
    }
}

/// Query online CPU count.
///
/// # Safety
/// `out_count` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_cpu_count(out_count: *mut usize) -> i64 {
    match system::cpu_count() {
        // SAFETY: validated by `write_out`.
        Ok(count) => to_abi_result(unsafe { write_out(out_count, count) }),
        Err(err) => err_code(err),
    }
}

/// Query the calling thread's current dense CPU index.
///
/// # Safety
/// `out_cpu` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_current_cpu(out_cpu: *mut usize) -> i64 {
    match system::current_cpu() {
        // SAFETY: validated by `write_out`.
        Ok(cpu) => to_abi_result(unsafe { write_out(out_cpu, cpu) }),
        Err(err) => err_code(err),
    }
}

/// Request an orderly software shutdown (restricted to root supervisor).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_shutdown() -> i64 {
    to_abi_result(system::shutdown())
}

/// Fill `out_buf` with up to `len` CSPRNG bytes from the kernel.
///
/// # Safety
/// `out_buf` must point to `len` writable bytes; `out_written` may be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_get_entropy(
    out_buf: *mut u8,
    len: usize,
    out_written: *mut usize,
) -> i64 {
    // SAFETY: validated by `write_slice`.
    let Ok(buf) = (unsafe { write_slice(out_buf, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match memory::get_entropy(buf) {
        Ok(written) => {
            if !out_written.is_null() {
                // SAFETY: validated by `write_out`.
                return to_abi_result(unsafe { write_out(out_written, written) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/* --------------------------------------------------------------------------
 * Scudo userspace heap
 * -------------------------------------------------------------------------- */

/// Initialise the shared Scudo heap (idempotent; also invoked via `.init_array`).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_heap_init() -> i64 {
    // SAFETY: single-threaded process contract; `ScudoHeap::init` is idempotent.
    if unsafe { GLOBAL_HEAP.init() } {
        0
    } else {
        err_code(ErrorCode::Internal)
    }
}

/// Return 1 if Scudo is initialised, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_heap_is_initialised() -> u8 {
    u8::from(GLOBAL_HEAP.is_initialised())
}

/// Query Scudo runtime counters.
///
/// # Safety
/// `out_stats` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_heap_stats(out_stats: *mut CanvasHeapStats) -> i64 {
    let Some(stats) = GLOBAL_HEAP.stats() else {
        return err_code(ErrorCode::ShouldWait);
    };
    let abi_stats = CanvasHeapStats {
        allocations: stats.allocations,
        deallocations: stats.deallocations,
        oom_failures: stats.oom_failures,
        corruption_failures: stats.corruption_failures,
        live_bytes: stats.live_bytes as u64,
    };
    // SAFETY: validated by `write_out`.
    to_abi_result(unsafe { write_out(out_stats, abi_stats) })
}

/// Allocate `size` bytes with `align` alignment from the shared Scudo heap.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_alloc(size: usize, align: usize) -> *mut u8 {
    let align = align.max(1);
    let Ok(layout) = Layout::from_size_align(size, align) else {
        return ptr::null_mut();
    };
    // SAFETY: `GLOBAL_HEAP` implements `GlobalAlloc`; layout was validated.
    unsafe { GLOBAL_HEAP.alloc(layout) }
}

/// Allocate `size` bytes with default 16-byte alignment from the shared Scudo heap.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_malloc(size: usize) -> *mut u8 {
    canvas_alloc(size, 16)
}

/// Allocate zero-initialised array of `count * size` bytes from the shared Scudo heap.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_calloc(count: usize, size: usize) -> *mut u8 {
    let Some(total) = count.checked_mul(size) else {
        return ptr::null_mut();
    };
    let ptr = canvas_malloc(total);
    if !ptr.is_null() && total > 0 {
        // SAFETY: `canvas_malloc` returned `total` writable bytes.
        unsafe { ptr::write_bytes(ptr, 0, total) };
    }
    ptr
}

/// Resize an existing Scudo allocation (or allocate/free when `ptr` is null / `new_size == 0`).
///
/// # Safety
/// When non-null, `ptr` must have been returned by `canvas_alloc`/`canvas_malloc`/`canvas_calloc`/`canvas_realloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
    if ptr.is_null() {
        return canvas_malloc(new_size);
    }
    if new_size == 0 {
        // SAFETY: caller passes a valid live allocation.
        unsafe { canvas_free(ptr) };
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `ptr` is a live allocation from `GLOBAL_HEAP`.
    let Some(old_usable) = (unsafe { GLOBAL_HEAP.usable_size(ptr) }) else {
        return ptr::null_mut();
    };
    if new_size <= old_usable {
        return ptr;
    }
    let next = canvas_malloc(new_size);
    if next.is_null() {
        return ptr::null_mut();
    }
    let copy_len = old_usable.min(new_size);
    // SAFETY: `ptr` has `old_usable` readable bytes and `next` has `new_size` writable bytes, disjoint.
    unsafe {
        ptr::copy_nonoverlapping(ptr, next, copy_len);
        canvas_free(ptr);
    }
    next
}

/// Free a pointer previously returned by `canvas_*` heap functions.
///
/// # Safety
/// If non-null, `ptr` must be a live allocation returned by `GLOBAL_HEAP`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let Ok(layout) = Layout::from_size_align(1, 1) else {
        return;
    };
    // SAFETY: `ScudoHeap::dealloc` validates chunk headers and ignores `_layout`.
    unsafe { GLOBAL_HEAP.dealloc(ptr, layout) };
}

/// Commit `len` bytes at `offset` inside the process heap window.
///
/// # Safety
/// `out_addr` may be null or a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_heap_commit(
    offset: usize,
    len: usize,
    out_addr: *mut usize,
) -> i64 {
    match memory::heap_commit(offset, len) {
        Ok(addr) => {
            if !out_addr.is_null() {
                // SAFETY: validated by `write_out`.
                return to_abi_result(unsafe { write_out(out_addr, addr) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/// Decommit `len` bytes at `offset` inside the process heap window.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_heap_decommit(offset: usize, len: usize) -> i64 {
    to_abi_result(memory::heap_decommit(offset, len).map(|_| ()))
}

/* --------------------------------------------------------------------------
 * Capability handles & channels
 * -------------------------------------------------------------------------- */

/// Return the well-known bootstrap channel handle (`BOOTSTRAP_HANDLE`).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_bootstrap_handle() -> u32 {
    BOOTSTRAP_HANDLE
}

/// Close a kernel handle.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_handle_close(handle: u32) -> i64 {
    if handle == INVALID_HANDLE {
        return err_code(ErrorCode::BadHandle);
    }
    let ret = raw::syscall1(Syscall::HandleClose, handle as u64);
    to_abi_result(raw::decode(ret).map(|_| ()))
}

/// Duplicate `handle` with `rights` mask.
///
/// # Safety
/// `out_handle` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_handle_duplicate(
    handle: u32,
    rights: u32,
    out_handle: *mut u32,
) -> i64 {
    let mut new_handle: HandleValue = INVALID_HANDLE;
    let ret = raw::syscall3(
        Syscall::HandleDuplicate,
        handle as u64,
        rights as u64,
        &mut new_handle as *mut HandleValue as u64,
    );
    match raw::decode(ret) {
        // SAFETY: validated by `write_out`.
        Ok(_) => to_abi_result(unsafe { write_out(out_handle, new_handle) }),
        Err(err) => err_code(err),
    }
}

/// Create a connected channel pair.
///
/// # Safety
/// `out_h0` and `out_h1` must be valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_channel_create(out_h0: *mut u32, out_h1: *mut u32) -> i64 {
    let mut h0: HandleValue = INVALID_HANDLE;
    let mut h1: HandleValue = INVALID_HANDLE;
    let ret = raw::syscall2(
        Syscall::ChannelCreate,
        &mut h0 as *mut HandleValue as u64,
        &mut h1 as *mut HandleValue as u64,
    );
    if let Err(err) = raw::decode(ret) {
        return err_code(err);
    }
    // SAFETY: validated by `write_out`.
    if let Err(err) = unsafe { write_out(out_h0, h0) } {
        let _ = canvas_handle_close(h0);
        let _ = canvas_handle_close(h1);
        return err_code(err);
    }
    // SAFETY: validated by `write_out`.
    if let Err(err) = unsafe { write_out(out_h1, h1) } {
        let _ = canvas_handle_close(h0);
        let _ = canvas_handle_close(h1);
        return err_code(err);
    }
    0
}

/// Write raw bytes to channel `ch`.
///
/// # Safety
/// If `len > 0`, `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_channel_write(ch: u32, data: *const u8, len: usize) -> i64 {
    // SAFETY: validated by `read_bytes`.
    let Ok(bytes) = (unsafe { read_bytes(data, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let ret = raw::syscall5(
        Syscall::ChannelWrite,
        ch as u64,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        0,
        0,
    );
    to_abi_result(raw::decode(ret).map(|_| ()))
}

/// Write raw bytes plus transferred handles to channel `ch`.
///
/// # Safety
/// `data` (`len` bytes) and `handles` (`num_handles` items) must be valid for reads when non-empty.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_channel_write_handles(
    ch: u32,
    data: *const u8,
    len: usize,
    handles: *const u32,
    num_handles: usize,
) -> i64 {
    // SAFETY: validated by `read_bytes`.
    let Ok(bytes) = (unsafe { read_bytes(data, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    // SAFETY: validated by `read_slice`.
    let Ok(hslice) = (unsafe { read_slice(handles, num_handles) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let ret = raw::syscall5(
        Syscall::ChannelWrite,
        ch as u64,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        hslice.as_ptr() as u64,
        hslice.len() as u64,
    );
    to_abi_result(raw::decode(ret).map(|_| ()))
}

fn channel_read_mode(ch: u32, buf: &mut [u8], wait_mode: u64) -> crate::Result<usize> {
    let mut actual: u32 = 0;
    let ret = raw::syscall5(
        Syscall::ChannelRead,
        ch as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        &mut actual as *mut u32 as u64,
        wait_mode,
    );
    raw::decode(ret)?;
    Ok(actual as usize)
}

/// Non-blocking channel read.
///
/// # Safety
/// `buf` (`buf_len` bytes) and `out_len` must be valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_channel_read(
    ch: u32,
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> i64 {
    // SAFETY: validated by `write_slice`.
    let Ok(slice) = (unsafe { write_slice(buf, buf_len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match channel_read_mode(ch, slice, 0) {
        // SAFETY: validated by `write_out`.
        Ok(n) => to_abi_result(unsafe { write_out(out_len, n) }),
        Err(err) => err_code(err),
    }
}

/// Blocking channel read.
///
/// # Safety
/// `buf` (`buf_len` bytes) and `out_len` must be valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_channel_read_blocking(
    ch: u32,
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> i64 {
    // SAFETY: validated by `write_slice`.
    let Ok(slice) = (unsafe { write_slice(buf, buf_len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match channel_read_mode(ch, slice, 1) {
        // SAFETY: validated by `write_out`.
        Ok(n) => to_abi_result(unsafe { write_out(out_len, n) }),
        Err(err) => err_code(err),
    }
}

/// Read message bytes and transferred handles from channel `ch`.
///
/// # Safety
/// Output buffers and length pointers must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_channel_read_handles(
    ch: u32,
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
    handles_out: *mut u32,
    max_handles: usize,
    out_num_handles: *mut usize,
) -> i64 {
    // SAFETY: validated by `write_slice`.
    let Ok(bslice) = (unsafe { write_slice(buf, buf_len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    // SAFETY: validated by `write_slice`.
    let Ok(hslice) = (unsafe { write_slice(handles_out, max_handles) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let mut actual_bytes: u32 = 0;
    let mut actual_handles: u32 = 0;
    let args = ChannelReadEtcArgs {
        channel: ch,
        bytes: bslice.as_mut_ptr(),
        bytes_capacity: bslice.len() as u32,
        out_bytes: &mut actual_bytes as *mut u32,
        handles: hslice.as_mut_ptr(),
        handles_capacity: hslice.len() as u32,
        out_handles: &mut actual_handles as *mut u32,
    };
    let ret = raw::syscall1(Syscall::ChannelReadEtc, &args as *const _ as u64);
    if let Err(err) = raw::decode(ret) {
        return err_code(err);
    }
    if !out_len.is_null() {
        // SAFETY: validated by `write_out`.
        if let Err(err) = unsafe { write_out(out_len, actual_bytes as usize) } {
            return err_code(err);
        }
    }
    if !out_num_handles.is_null() {
        // SAFETY: validated by `write_out`.
        if let Err(err) = unsafe { write_out(out_num_handles, actual_handles as usize) } {
            return err_code(err);
        }
    }
    0
}

/* --------------------------------------------------------------------------
 * Virtual Memory Objects (VMO) & VMAR
 * -------------------------------------------------------------------------- */

/// Create a zero-filled VMO of `size` bytes.
///
/// # Safety
/// `out_vmo` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_vmo_create(size: u64, out_vmo: *mut u32) -> i64 {
    let mut vmo: HandleValue = INVALID_HANDLE;
    let ret = raw::syscall2(
        Syscall::VmoCreate,
        size,
        &mut vmo as *mut HandleValue as u64,
    );
    match raw::decode(ret) {
        // SAFETY: validated by `write_out`.
        Ok(_) => to_abi_result(unsafe { write_out(out_vmo, vmo) }),
        Err(err) => err_code(err),
    }
}

/// Create a VMO with explicit `vmo_create_flags`.
///
/// # Safety
/// `out_vmo` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_vmo_create_ex(size: u64, flags: u32, out_vmo: *mut u32) -> i64 {
    let mut vmo: HandleValue = INVALID_HANDLE;
    let ret = raw::syscall3(
        Syscall::VmoCreateEx,
        size,
        flags as u64,
        &mut vmo as *mut HandleValue as u64,
    );
    match raw::decode(ret) {
        // SAFETY: validated by `write_out`.
        Ok(_) => to_abi_result(unsafe { write_out(out_vmo, vmo) }),
        Err(err) => err_code(err),
    }
}

/// Read up to `len` bytes from `vmo` at `offset`.
///
/// # Safety
/// `buf` must hold `len` writable bytes; `out_read` may be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_vmo_read(
    vmo: u32,
    offset: u64,
    buf: *mut u8,
    len: usize,
    out_read: *mut usize,
) -> i64 {
    // SAFETY: validated by `write_slice`.
    let Ok(slice) = (unsafe { write_slice(buf, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let read = if slice.is_empty() {
        0
    } else {
        let ret = raw::syscall4(
            Syscall::VmoRead,
            vmo as u64,
            offset,
            slice.as_mut_ptr() as u64,
            slice.len() as u64,
        );
        match raw::decode(ret) {
            Ok(n) => n as usize,
            Err(err) => return err_code(err),
        }
    };
    if !out_read.is_null() {
        // SAFETY: validated by `write_out`.
        return to_abi_result(unsafe { write_out(out_read, read) });
    }
    0
}

/// Write up to `len` bytes into `vmo` at `offset`.
///
/// # Safety
/// `data` must hold `len` readable bytes; `out_written` may be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_vmo_write(
    vmo: u32,
    offset: u64,
    data: *const u8,
    len: usize,
    out_written: *mut usize,
) -> i64 {
    // SAFETY: validated by `read_bytes`.
    let Ok(slice) = (unsafe { read_bytes(data, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let written = if slice.is_empty() {
        0
    } else {
        let ret = raw::syscall4(
            Syscall::VmoWrite,
            vmo as u64,
            offset,
            slice.as_ptr() as u64,
            slice.len() as u64,
        );
        match raw::decode(ret) {
            Ok(n) => n as usize,
            Err(err) => return err_code(err),
        }
    };
    if !out_written.is_null() {
        // SAFETY: validated by `write_out`.
        return to_abi_result(unsafe { write_out(out_written, written) });
    }
    0
}

/// Map `vmo` into `vmar`.
///
/// # Safety
/// `out_addr` may be null or a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_vmar_map(
    vmar: u32,
    vaddr: u64,
    vmo: u32,
    vmo_offset: u64,
    len: u64,
    flags: u32,
    out_addr: *mut u64,
) -> i64 {
    let args = VmarMapArgs {
        vmar,
        vmo,
        vmo_offset,
        addr: vaddr,
        len,
        flags,
    };
    let ret = raw::syscall1(Syscall::VmarMap, &args as *const _ as u64);
    match raw::decode(ret) {
        Ok(addr) => {
            if !out_addr.is_null() {
                // SAFETY: validated by `write_out`.
                return to_abi_result(unsafe { write_out(out_addr, addr as u64) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/// Update VMAR mapping protection flags (`flags`).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_vmar_protect(vmar: u32, vaddr: u64, len: u64, flags: u32) -> i64 {
    let args = VmarOpArgs {
        vmar,
        addr: vaddr,
        len,
        flags,
    };
    let ret = raw::syscall1(Syscall::VmarProtect, &args as *const _ as u64);
    to_abi_result(raw::decode(ret).map(|_| ()))
}

/// Unmap a page-aligned range from `vmar`.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_vmar_unmap(vmar: u32, vaddr: u64, len: u64) -> i64 {
    let args = VmarOpArgs {
        vmar,
        addr: vaddr,
        len,
        flags: 0,
    };
    let ret = raw::syscall1(Syscall::VmarUnmap, &args as *const _ as u64);
    to_abi_result(raw::decode(ret).map(|_| ()))
}

/* --------------------------------------------------------------------------
 * Waitsets & signals
 * -------------------------------------------------------------------------- */

/// Create a level-triggered signal object.
///
/// # Safety
/// `out_signal` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_signal_create(out_signal: *mut u32) -> i64 {
    let mut sig: HandleValue = INVALID_HANDLE;
    let ret = raw::syscall1(Syscall::SignalCreate, &mut sig as *mut HandleValue as u64);
    match raw::decode(ret) {
        // SAFETY: validated by `write_out`.
        Ok(_) => to_abi_result(unsafe { write_out(out_signal, sig) }),
        Err(err) => err_code(err),
    }
}

/// Assert `SIGNALED` on a signal handle.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_signal_set(signal: u32) -> i64 {
    let ret = raw::syscall1(Syscall::SignalSet, signal as u64);
    to_abi_result(raw::decode(ret).map(|_| ()))
}

/// Clear `SIGNALED` on a signal handle.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_signal_clear(signal: u32) -> i64 {
    let ret = raw::syscall1(Syscall::SignalClear, signal as u64);
    to_abi_result(raw::decode(ret).map(|_| ()))
}

/// Multiplexed wait on up to `MAX_WAIT_ITEMS` handles.
///
/// # Safety
/// `items` must point to `count` readable/writable `CanvasWaitItem` elements;
/// `out_satisfied` may be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_wait_many(
    items: *mut CanvasWaitItem,
    count: usize,
    mode: u32,
    timeout_ticks: u64,
    out_satisfied: *mut usize,
) -> i64 {
    if count == 0 || count > MAX_WAIT_ITEMS || (mode != wait_mode::ANY && mode != wait_mode::ALL) {
        return err_code(ErrorCode::InvalidArgs);
    }
    // SAFETY: validated by `write_slice`.
    let Ok(c_items) = (unsafe { write_slice(items, count) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let mut abi_items = [WaitSetItem {
        handle: 0,
        awaited_signals: 0,
        key: 0,
    }; MAX_WAIT_ITEMS];
    for (dst, src) in abi_items.iter_mut().zip(c_items.iter()) {
        *dst = WaitSetItem {
            handle: src.handle,
            awaited_signals: src.awaited_signals,
            key: src.key,
        };
    }
    let mut results = [WaitSetResult {
        key: 0,
        active_signals: 0,
    }; MAX_WAIT_ITEMS];
    let mut satisfied: u32 = 0;
    let args = WaitSetWaitArgs {
        items: abi_items.as_ptr(),
        item_count: count as u32,
        mode,
        timeout_ticks,
        out_results: results.as_mut_ptr(),
        out_count: &mut satisfied as *mut u32,
    };
    let rc = raw::syscall1(Syscall::WaitSetWait, &args as *const _ as u64);
    if let Err(err) = raw::decode(rc) {
        return err_code(err);
    }
    for item in c_items.iter_mut() {
        item.observed_signals = 0;
        for res in results.iter().take(satisfied as usize) {
            if res.key == item.key {
                item.observed_signals |= res.active_signals;
            }
        }
    }
    if !out_satisfied.is_null() {
        // SAFETY: validated by `write_out`.
        return to_abi_result(unsafe { write_out(out_satisfied, satisfied as usize) });
    }
    0
}

/* --------------------------------------------------------------------------
 * Framebuffer & 2D drawing surface
 * -------------------------------------------------------------------------- */

/// Query framebuffer geometry.
///
/// # Safety
/// `out_info` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_fb_info(out_info: *mut CanvasFbInfo) -> i64 {
    let mut info = FramebufferInfo::default();
    let ret = raw::syscall1(Syscall::FramebufferInfo, &mut info as *mut _ as u64);
    if let Err(err) = raw::decode(ret) {
        return err_code(err);
    }
    let abi_info = CanvasFbInfo {
        width: info.width,
        height: info.height,
        pitch: info.pitch,
        bpp: info.bpp,
        red_mask_size: info.red_mask_size,
        red_mask_shift: info.red_mask_shift,
        green_mask_size: info.green_mask_size,
        green_mask_shift: info.green_mask_shift,
        blue_mask_size: info.blue_mask_size,
        blue_mask_shift: info.blue_mask_shift,
    };
    // SAFETY: validated by `write_out`.
    to_abi_result(unsafe { write_out(out_info, abi_info) })
}

/// Blit a rectangle from `vmo` onto the display using `frame_draw_cap`.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_fb_blit(
    vmo: u32,
    frame_draw_cap: u32,
    dst_x: u32,
    dst_y: u32,
    width: u32,
    height: u32,
    src_stride_bytes: u32,
) -> i64 {
    let args = FramebufferBlitArgs {
        vmo,
        vmo_offset: 0,
        src_width: width,
        src_height: height,
        src_stride: src_stride_bytes,
        dst_x,
        dst_y,
    };
    let ret = raw::syscall2(
        Syscall::FramebufferBlit,
        frame_draw_cap as u64,
        &args as *const _ as u64,
    );
    to_abi_result(raw::decode(ret).map(|_| ()))
}

/// Create an off-screen drawing surface.
///
/// # Safety
/// `out_surface` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_create(
    width: u32,
    height: u32,
    frame_draw_cap: u32,
    out_surface: *mut *mut CanvasSurface,
) -> i64 {
    match Canvas::new_with_cap(width, height, frame_draw_cap) {
        // SAFETY: validated by `box_into_out`.
        Ok(inner) => to_abi_result(unsafe { box_into_out(out_surface, CanvasSurface { inner }) }),
        Err(err) => err_code(err),
    }
}

/// Create a fullscreen off-screen drawing surface.
///
/// # Safety
/// `out_surface` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_create_fullscreen(
    frame_draw_cap: u32,
    out_surface: *mut *mut CanvasSurface,
) -> i64 {
    match Canvas::new_fullscreen_with_cap(frame_draw_cap) {
        // SAFETY: validated by `box_into_out`.
        Ok(inner) => to_abi_result(unsafe { box_into_out(out_surface, CanvasSurface { inner }) }),
        Err(err) => err_code(err),
    }
}

/// Destroy a surface previously returned by `canvas_surface_create*`.
///
/// # Safety
/// If non-null, `surface` must be an owned `CanvasSurface` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_destroy(surface: *mut CanvasSurface) {
    // SAFETY: validated by `drop_boxed`.
    unsafe { drop_boxed(surface) };
}

/// Surface width in pixels (0 if `surface` is null).
///
/// # Safety
/// If non-null, `surface` must point to a live `CanvasSurface`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_width(surface: *const CanvasSurface) -> u32 {
    // SAFETY: validated by `borrow_ref`.
    unsafe { borrow_ref(surface) }.map_or(0, |s| s.inner.width())
}

/// Surface height in pixels (0 if `surface` is null).
///
/// # Safety
/// If non-null, `surface` must point to a live `CanvasSurface`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_height(surface: *const CanvasSurface) -> u32 {
    // SAFETY: validated by `borrow_ref`.
    unsafe { borrow_ref(surface) }.map_or(0, |s| s.inner.height())
}

/// Raw VMO handle backing this surface (`CANVAS_INVALID_HANDLE` if null).
///
/// # Safety
/// If non-null, `surface` must point to a live `CanvasSurface`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_vmo(surface: *const CanvasSurface) -> u32 {
    // SAFETY: validated by `borrow_ref`.
    unsafe { borrow_ref(surface) }.map_or(INVALID_HANDLE, |s| s.inner.vmo_handle())
}

/// Set one pixel on `surface`.
///
/// # Safety
/// `surface` must point to a live `CanvasSurface`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_set_pixel(
    surface: *mut CanvasSurface,
    x: u32,
    y: u32,
    r: u8,
    g: u8,
    b: u8,
) -> i64 {
    // SAFETY: validated by `borrow_mut`.
    match unsafe { borrow_mut(surface) } {
        Ok(s) => to_abi_result(s.inner.set_pixel(x, y, r, g, b)),
        Err(err) => err_code(err),
    }
}

/// Fill an axis-aligned rectangle on `surface`.
///
/// # Safety
/// `surface` must point to a live `CanvasSurface`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_fill_rect(
    surface: *mut CanvasSurface,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    r: u8,
    g: u8,
    b: u8,
) -> i64 {
    // SAFETY: validated by `borrow_mut`.
    match unsafe { borrow_mut(surface) } {
        Ok(s) => to_abi_result(s.inner.fill_rect(x, y, w, h, r, g, b)),
        Err(err) => err_code(err),
    }
}

/// Draw UTF-8 text on `surface` with the default Cozette 6x13 font.
///
/// # Safety
/// `surface` must be live; `utf8` must point to `len` valid UTF-8 bytes when `len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_draw_text(
    surface: *mut CanvasSurface,
    x: u32,
    y: u32,
    utf8: *const u8,
    len: usize,
    r: u8,
    g: u8,
    b: u8,
) -> i64 {
    // SAFETY: delegates to `canvas_surface_draw_text_font` with identical pointer preconditions.
    unsafe { canvas_surface_draw_text_font(surface, x, y, utf8, len, r, g, b, 0) }
}

/// Draw UTF-8 text on `surface` with explicit font (`CanvasTextFont`).
///
/// # Safety
/// `surface` must be live; `utf8` must point to `len` readable bytes when `len > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_draw_text_font(
    surface: *mut CanvasSurface,
    x: u32,
    y: u32,
    utf8: *const u8,
    len: usize,
    r: u8,
    g: u8,
    b: u8,
    font: u32,
) -> i64 {
    // SAFETY: validated by `borrow_mut`.
    let Ok(s) = (unsafe { borrow_mut(surface) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    // SAFETY: validated by `read_bytes`.
    let Ok(bytes) = (unsafe { read_bytes(utf8, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let Ok(text) = core::str::from_utf8(bytes) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let font = match font {
        0 => TextFont::Cozette6x13,
        1 => TextFont::Tty8x16,
        2 => TextFont::Compact8x8,
        _ => return err_code(ErrorCode::InvalidArgs),
    };
    to_abi_result(s.inner.draw_text_with_font(x, y, text, r, g, b, font))
}

/// Blit the entire surface to `(0, 0)` on the framebuffer.
///
/// # Safety
/// `surface` must point to a live `CanvasSurface`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_present(surface: *const CanvasSurface) -> i64 {
    // SAFETY: validated by `borrow_ref`.
    match unsafe { borrow_ref(surface) } {
        Ok(s) => to_abi_result(s.inner.present()),
        Err(err) => err_code(err),
    }
}

/// Blit the entire surface to `(dst_x, dst_y)` on the framebuffer.
///
/// # Safety
/// `surface` must point to a live `CanvasSurface`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_surface_present_at(
    surface: *const CanvasSurface,
    dst_x: u32,
    dst_y: u32,
) -> i64 {
    // SAFETY: validated by `borrow_ref`.
    match unsafe { borrow_ref(surface) } {
        Ok(s) => to_abi_result(s.inner.present_at(dst_x, dst_y)),
        Err(err) => err_code(err),
    }
}

/* --------------------------------------------------------------------------
 * HxFS filesystem helpers
 * -------------------------------------------------------------------------- */

/// Open the HxFS client via DriverManager `registry_ch` (handle is borrowed, not consumed).
///
/// # Safety
/// `out_fs` must be a valid writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_fs_open(registry_ch: u32, out_fs: *mut *mut CanvasFs) -> i64 {
    if registry_ch == INVALID_HANDLE {
        return err_code(ErrorCode::BadHandle);
    }
    let mut dup: HandleValue = INVALID_HANDLE;
    // SAFETY: `dup` is a valid stack pointer.
    let dup_rc =
        unsafe { canvas_handle_duplicate(registry_ch, huesos_abi::rights::SAME_RIGHTS, &mut dup) };
    if dup_rc != 0 {
        return dup_rc;
    }
    // SAFETY: `dup` is a freshly duplicated owned channel handle.
    let registry = crate::Channel::from_handle(unsafe { crate::Handle::from_raw(dup) });
    match Hxfs::open(&registry) {
        // SAFETY: validated by `box_into_out`.
        Ok(inner) => to_abi_result(unsafe { box_into_out(out_fs, CanvasFs { inner }) }),
        Err(err) => err_code(err),
    }
}

/// Close an HxFS client opened with `canvas_fs_open`.
///
/// # Safety
/// If non-null, `fs` must be an owned `CanvasFs` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_fs_close(fs: *mut CanvasFs) {
    // SAFETY: validated by `drop_boxed`.
    unsafe { drop_boxed(fs) };
}

/// Open an absolute file path on HxFS.
///
/// # Safety
/// `fs` must be live; `path` must point to `path_len` UTF-8 bytes; `out_file` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_fs_open_file(
    fs: *mut CanvasFs,
    path: *const u8,
    path_len: usize,
    out_file: *mut *mut CanvasFsFile,
) -> i64 {
    // SAFETY: validated by `borrow_ref`.
    let Ok(fs_ref) = (unsafe { borrow_ref(fs) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    // SAFETY: validated by `read_bytes`.
    let Ok(bytes) = (unsafe { read_bytes(path, path_len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let Ok(path_str) = core::str::from_utf8(bytes) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match fs_ref.inner.open_file(path_str) {
        // SAFETY: validated by `box_into_out`.
        Ok(inner) => to_abi_result(unsafe { box_into_out(out_file, CanvasFsFile { inner }) }),
        Err(err) => err_code(err),
    }
}

/// Read inline small-file contents into `buf`.
///
/// # Safety
/// `file` must be live; `buf` (`buf_len` bytes) and `out_len` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_fs_file_read(
    file: *mut CanvasFsFile,
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> i64 {
    // SAFETY: validated by `borrow_ref`.
    let Ok(f_ref) = (unsafe { borrow_ref(file) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    // SAFETY: validated by `write_slice`.
    let Ok(slice) = (unsafe { write_slice(buf, buf_len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match f_ref.inner.read(slice) {
        Ok(read) => {
            let n = read.len();
            if !out_len.is_null() {
                // SAFETY: validated by `write_out`.
                return to_abi_result(unsafe { write_out(out_len, n) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/// Read up to `len` bytes starting at `offset` from an open HxFS file.
///
/// # Safety
/// `file` must be live; `buf` (`len` bytes) and `out_len` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_fs_file_read_at(
    file: *mut CanvasFsFile,
    offset: u64,
    buf: *mut u8,
    len: usize,
    out_len: *mut usize,
) -> i64 {
    // SAFETY: validated by `borrow_ref`.
    let Ok(f_ref) = (unsafe { borrow_ref(file) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    // SAFETY: validated by `write_slice`.
    let Ok(slice) = (unsafe { write_slice(buf, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match f_ref.inner.read_at(offset, slice) {
        Ok(read) => {
            let n = read.len();
            if !out_len.is_null() {
                // SAFETY: validated by `write_out`.
                return to_abi_result(unsafe { write_out(out_len, n) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/// Close an open HxFS file handle.
///
/// # Safety
/// If non-null, `file` must be an owned `CanvasFsFile` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_fs_file_close(file: *mut CanvasFsFile) {
    // SAFETY: validated by `drop_boxed`.
    unsafe { drop_boxed(file) };
}

/* --------------------------------------------------------------------------
 * Dynamic linker bridge, TLS, capability dlopen & intra-process threading
 * -------------------------------------------------------------------------- */

unsafe extern "C" fn host_scudo_alloc(size: usize, align: usize) -> *mut u8 {
    canvas_alloc(size, align)
}

unsafe extern "C" fn host_scudo_free(ptr: *mut u8) {
    // SAFETY: delegates to `canvas_free` on the global Scudo heap.
    unsafe { canvas_free(ptr) }
}

/// Handshake called once by `/lib/ld-huesos.so` right after relocating
/// `libcanvas.so` to exchange [`RtldOps`] and [`HostAllocOps`].
///
/// # Safety
/// `ops` must point to a `'static` [`RtldOps`] table; if non-null, `out_host`
/// must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __huesos_register_rtld(
    ops: *const RtldOps,
    out_host: *mut HostAllocOps,
) -> i32 {
    if ops.is_null() {
        return -1;
    }
    // SAFETY: caller guarantees `ops` points to a readable `RtldOps` struct.
    if unsafe { (*ops).version } != RTLD_OPS_VERSION {
        return -1;
    }
    RTLD_OPS_PTR.store(ops.cast_mut(), Ordering::Release);
    if !out_host.is_null() {
        // SAFETY: `out_host` is non-null and valid writable storage per contract.
        unsafe {
            ptr::write(
                out_host,
                HostAllocOps {
                    version: RTLD_OPS_VERSION,
                    alloc: host_scudo_alloc,
                    free: host_scudo_free,
                },
            );
        }
    }
    0
}

/// General-Dynamic / Local-Dynamic TLS resolver (`__tls_get_addr`).
///
/// # Safety
/// `ti` must point to an ELF64 `TlsIndex { ti_module: usize, ti_offset: usize }`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __tls_get_addr(ti: *const u8) -> *mut u8 {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so` DTV resolver.
            unsafe { (ops.tls_get_addr)(ti) }
        }
        None => ptr::null_mut(),
    }
}

/// Register a DSO destructor callback (`__cxa_atexit`).
///
/// # Safety
/// `func`, `arg`, and `dso_handle` follow the Itanium C++ ABI contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_atexit(
    func: Option<unsafe extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    dso_handle: *mut c_void,
) -> i32 {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: forwarded to `ld-huesos.so`'s `__cxa_atexit` registry.
            unsafe { (ops.cxa_atexit)(func, arg, dso_handle) }
        }
        None => -1,
    }
}

unsafe extern "C" fn plain_atexit_trampoline(fn_ptr: *mut c_void) {
    if !fn_ptr.is_null() {
        // SAFETY: `fn_ptr` was converted from `extern "C" fn()` in `atexit` / `canvas_atexit`.
        let f: extern "C" fn() = unsafe { core::mem::transmute(fn_ptr) };
        f();
    }
}

/// Register a process-exit callback (`canvas_atexit`).
///
/// # Safety
/// `func` must be a valid `extern "C" fn()` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_atexit(func: Option<extern "C" fn()>) -> i64 {
    let Some(f) = func else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let Some(ops) = rtld_ops() else {
        return err_code(ErrorCode::NotSupported);
    };
    // SAFETY: `f` is passed as `arg` to `plain_atexit_trampoline` with null DSO handle.
    let rc = unsafe {
        (ops.cxa_atexit)(
            Some(plain_atexit_trampoline),
            f as *mut c_void,
            ptr::null_mut(),
        )
    };
    if rc == 0 {
        0
    } else {
        err_code(ErrorCode::NoMemory)
    }
}

/// Standard C `atexit` alias.
///
/// # Safety
/// `func` must be a valid `extern "C" fn()` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atexit(func: Option<extern "C" fn()>) -> i32 {
    // SAFETY: forwarded to `canvas_atexit`.
    if unsafe { canvas_atexit(func) } == 0 {
        0
    } else {
        -1
    }
}

/// Standard C `malloc` alias backed by `GLOBAL_HEAP`.
///
/// # Safety
/// Returned pointer must be freed via `free` / `canvas_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    canvas_malloc(size).cast::<c_void>()
}

/// Standard C `calloc` alias backed by `GLOBAL_HEAP`.
///
/// # Safety
/// Returned pointer must be freed via `free` / `canvas_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
    canvas_calloc(count, size).cast::<c_void>()
}

/// Standard C `realloc` alias backed by `GLOBAL_HEAP`.
///
/// # Safety
/// `ptr` must be null or previously returned by `malloc`/`calloc`/`realloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
    // SAFETY: forwarded to `canvas_realloc`.
    unsafe { canvas_realloc(ptr.cast::<u8>(), new_size) }.cast::<c_void>()
}

/// Standard C `free` alias backed by `GLOBAL_HEAP`.
///
/// # Safety
/// `ptr` must be null or previously returned by `malloc`/`calloc`/`realloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    // SAFETY: forwarded to `canvas_free`.
    unsafe { canvas_free(ptr.cast::<u8>()) }
}

/// Load a shared object directly from a `Vmo` capability handle.
///
/// # Safety
/// `vmo_handle` must be a valid readable/executable VMO handle in this process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dlopen_vmo(vmo_handle: u32, flags: i32) -> *mut c_void {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dlopen_vmo)(vmo_handle, flags) }
        }
        None => ptr::null_mut(),
    }
}

/// Load a shared object by validated `SONAME` (no `/` or `..`).
///
/// # Safety
/// `soname` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dlopen_soname(soname: *const c_char, flags: i32) -> *mut c_void {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dlopen_soname)(soname, flags) }
        }
        None => ptr::null_mut(),
    }
}

/// Load a shared object from an `HxfsBlobView` channel handle.
///
/// # Safety
/// `blob_ch` must be a valid `BlobView` channel handle in this process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dlopen_blob(blob_ch: u32, flags: i32) -> *mut c_void {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dlopen_blob)(blob_ch, flags) }
        }
        None => ptr::null_mut(),
    }
}

/// Resolve an exported symbol from `handle` (or global scope when `handle == NULL`).
///
/// # Safety
/// `handle` must be null or returned by `canvas_dlopen_*`; `symbol` must be a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dlsym)(handle, symbol) }
        }
        None => ptr::null_mut(),
    }
}

/// Decrement module refcount and unload (running destructors) when zero.
///
/// # Safety
/// `handle` must have been returned by `canvas_dlopen_*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dlclose(handle: *mut c_void) -> i32 {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dlclose)(handle) }
        }
        None => -1,
    }
}

/// Return and clear the per-thread error message from the last `canvas_dl*` failure.
///
/// # Safety
/// Returns either `NULL` or a NUL-terminated diagnostic string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dlerror() -> *const c_char {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dlerror)() }
        }
        None => c"dynamic linker unavailable".as_ptr(),
    }
}

/// Resolve the loaded object and nearest symbol containing `addr`.
///
/// # Safety
/// `out_info` must point to writable [`CanvasDlInfo`] storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dladdr(addr: *const c_void, out_info: *mut CanvasDlInfo) -> i32 {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dladdr)(addr, out_info) }
        }
        None => 0,
    }
}

/// Iterate over loaded shared objects (`dl_iterate_phdr`).
///
/// # Safety
/// `callback` must follow the `CanvasDlPhdrInfo` iteration contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut CanvasDlPhdrInfo, usize, *mut c_void) -> i32>,
    data: *mut c_void,
) -> i32 {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dl_iterate_phdr)(callback, data) }
        }
        None => 0,
    }
}

/// Register an `HxfsDirectory` capability channel for `SONAME` loading.
///
/// # Safety
/// `hxfs_dir_ch` must be a valid `HxfsDirectory` channel handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dl_set_lib_dir(hxfs_dir_ch: u32) -> i32 {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dl_set_lib_dir)(hxfs_dir_ch) }
        }
        None => -1,
    }
}

/// Register an `Hxfs` service capability channel for `SONAME` loading.
///
/// # Safety
/// `hxfs_ch` must be a valid `Hxfs` channel handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_dl_set_hxfs_service(hxfs_ch: u32) -> i32 {
    match rtld_ops() {
        Some(ops) => {
            // SAFETY: delegated to `ld-huesos.so`.
            unsafe { (ops.dl_set_hxfs_service)(hxfs_ch) }
        }
        None => -1,
    }
}

/// Opaque intra-process thread handle (`CanvasThread` in `include/canvas.h`).
pub struct CanvasThread {
    handle: crate::Handle,
    stack_ptr: *mut u8,
    stack_layout: Layout,
}

struct ThreadStartContext {
    entry: unsafe extern "C" fn(*mut c_void) -> i64,
    arg: *mut c_void,
    tp: u64,
}

extern "C" fn thread_entry_trampoline(ctx_ptr: *mut ThreadStartContext) -> ! {
    // SAFETY: `ctx_ptr` was allocated on `GLOBAL_HEAP` by `canvas_thread_spawn`
    // and transferred uniquely to this new thread.
    let ctx = unsafe { *Box::from_raw(ctx_ptr) };
    // SAFETY: caller supplied a valid `extern "C" fn(*mut c_void) -> i64` and `arg`.
    let code = unsafe { (ctx.entry)(ctx.arg) };
    if let Some(ops) = rtld_ops() {
        // SAFETY: releases any dynamic TLS blocks + per-thread TLS VMO for `ctx.tp`.
        unsafe { (ops.free_thread_tls)(ctx.tp) };
    }
    process::exit_thread(code)
}

/// Spawn a new intra-process thread with independent per-thread TLS/TCB/DTV.
///
/// # Safety
/// `entry` must be a valid function pointer; `out_thread` must be writable; if
/// non-null, `name` must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_thread_spawn(
    name: *const c_char,
    entry: Option<unsafe extern "C" fn(*mut c_void) -> i64>,
    arg: *mut c_void,
    stack_size: usize,
    out_thread: *mut *mut CanvasThread,
) -> i64 {
    let Some(entry_fn) = entry else {
        return err_code(ErrorCode::InvalidArgs);
    };
    if out_thread.is_null()
        || !(out_thread as usize).is_multiple_of(core::mem::align_of::<*mut CanvasThread>())
    {
        return err_code(ErrorCode::InvalidArgs);
    }

    let name_str = if name.is_null() {
        "thread"
    } else {
        let mut len = 0usize;
        while len < 63 {
            // SAFETY: caller guarantees NUL-terminated `name`.
            if unsafe { *name.add(len) } == 0 {
                break;
            }
            len += 1;
        }
        // SAFETY: `name..name+len` is non-NUL readable bytes.
        let bytes = unsafe { slice::from_raw_parts(name.cast::<u8>(), len) };
        core::str::from_utf8(bytes).unwrap_or("thread")
    };

    let stack_bytes = if stack_size == 0 {
        huesos_abi::USER_STACK_DEFAULT_SIZE as usize
    } else {
        stack_size.max(16 * 1024)
    };
    let stack_aligned = (stack_bytes + 15) & !15;
    let Ok(stack_layout) = Layout::from_size_align(stack_aligned, 16) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    // SAFETY: `stack_layout` has non-zero size and 16-byte alignment.
    let stack_ptr = unsafe { GLOBAL_HEAP.alloc(stack_layout) };
    if stack_ptr.is_null() {
        return err_code(ErrorCode::NoMemory);
    }

    let tp = match rtld_ops() {
        Some(ops) => {
            // SAFETY: allocates and initializes per-thread Variant-II TLS + TCB + DTV.
            let tp = unsafe { (ops.alloc_thread_tls)() };
            if tp == 0 {
                // SAFETY: `stack_ptr` was allocated with `stack_layout` above.
                unsafe { GLOBAL_HEAP.dealloc(stack_ptr, stack_layout) };
                return err_code(ErrorCode::NoMemory);
            }
            tp
        }
        None => 0,
    };

    let self_proc = match process::Process::current() {
        Ok(p) => p,
        Err(err) => {
            if tp != 0 {
                if let Some(ops) = rtld_ops() {
                    // SAFETY: roll back allocated TLS VMO on error.
                    unsafe { (ops.free_thread_tls)(tp) };
                }
            }
            // SAFETY: `stack_ptr` was allocated with `stack_layout` above.
            unsafe { GLOBAL_HEAP.dealloc(stack_ptr, stack_layout) };
            return err_code(err);
        }
    };

    let thread = match process::Thread::create(&self_proc, name_str) {
        Ok(t) => t,
        Err(err) => {
            if tp != 0 {
                if let Some(ops) = rtld_ops() {
                    // SAFETY: roll back allocated TLS VMO on error.
                    unsafe { (ops.free_thread_tls)(tp) };
                }
            }
            // SAFETY: `stack_ptr` was allocated with `stack_layout` above.
            unsafe { GLOBAL_HEAP.dealloc(stack_ptr, stack_layout) };
            return err_code(err);
        }
    };

    let ctx_raw = Box::into_raw(Box::new(ThreadStartContext {
        entry: entry_fn,
        arg,
        tp,
    }));
    let initial_rsp = (((stack_ptr as u64) + (stack_aligned as u64)) & !0xf) - 8;

    let mut dup_raw: HandleValue = INVALID_HANDLE;
    // SAFETY: `dup_raw` is stack-allocated and writable.
    let dup_rc = unsafe {
        canvas_handle_duplicate(
            thread.handle().raw(),
            huesos_abi::rights::SAME_RIGHTS,
            &mut dup_raw,
        )
    };
    if dup_rc != 0 {
        // SAFETY: thread has not started yet, reclaim `ctx_raw` and `stack_ptr`.
        let _ = unsafe { Box::from_raw(ctx_raw) };
        if tp != 0 {
            if let Some(ops) = rtld_ops() {
                unsafe { (ops.free_thread_tls)(tp) };
            }
        }
        unsafe { GLOBAL_HEAP.dealloc(stack_ptr, stack_layout) };
        return dup_rc;
    }

    // SAFETY: `dup_raw` is an owned duplicated thread handle.
    let owned_handle = unsafe { crate::Handle::from_raw(dup_raw) };
    let thread_box = Box::into_raw(Box::new(CanvasThread {
        handle: owned_handle,
        stack_ptr,
        stack_layout,
    }));

    if let Err(err) = thread.start_ex(
        thread_entry_trampoline as *const () as u64,
        initial_rsp,
        ctx_raw as u64,
        tp,
    ) {
        // SAFETY: start_ex failed before scheduling, so reclaim all allocations.
        let _ = unsafe { Box::from_raw(thread_box) };
        let _ = unsafe { Box::from_raw(ctx_raw) };
        if tp != 0 {
            if let Some(ops) = rtld_ops() {
                unsafe { (ops.free_thread_tls)(tp) };
            }
        }
        unsafe { GLOBAL_HEAP.dealloc(stack_ptr, stack_layout) };
        return err_code(err);
    }

    // SAFETY: `out_thread` was validated non-null and aligned above.
    unsafe { ptr::write(out_thread, thread_box) };
    0
}

/// Wait for `thread` to exit, reclaim its stack, and optionally return its exit code.
///
/// # Safety
/// `thread` must be an owned pointer returned by `canvas_thread_spawn`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_thread_join(
    thread: *mut CanvasThread,
    out_exit_code: *mut i64,
) -> i64 {
    if thread.is_null() || !(thread as usize).is_multiple_of(core::mem::align_of::<CanvasThread>())
    {
        return err_code(ErrorCode::InvalidArgs);
    }
    // SAFETY: caller transfers ownership of `thread` to `canvas_thread_join`.
    let t = unsafe { Box::from_raw(thread) };
    let mut code: i64 = 0;
    let ret = raw::syscall2(
        Syscall::ThreadWait,
        t.handle.raw() as u64,
        &mut code as *mut i64 as u64,
    );
    if let Err(err) = raw::decode(ret) {
        // Re-leak box? No — wait only fails on invalid handle; reclaim stack safely.
        // SAFETY: `t.stack_ptr` was allocated with `t.stack_layout`.
        unsafe { GLOBAL_HEAP.dealloc(t.stack_ptr, t.stack_layout) };
        return err_code(err);
    }
    // SAFETY: thread has exited ring3 and been marked finished in kernel before Wait returned.
    unsafe { GLOBAL_HEAP.dealloc(t.stack_ptr, t.stack_layout) };
    if !out_exit_code.is_null() {
        // SAFETY: `write_out` checks alignment.
        if let Err(err) = unsafe { write_out(out_exit_code, code) } {
            return err_code(err);
        }
    }
    0
}

/// Exit only the calling thread (cleaning up its per-thread TLS/TCB/DTV).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_thread_exit(code: i64) -> ! {
    if let Some(ops) = rtld_ops() {
        // SAFETY: `0` instructs `free_thread_tls` to read and clean current `%fs:0`.
        unsafe { (ops.free_thread_tls)(0) };
    }
    process::exit_thread(code)
}

/* --------------------------------------------------------------------------
 * Process arguments, standard streams & @caps(...) handles
 * -------------------------------------------------------------------------- */

/// Internal entrypoint invoked by `/lib/ld-huesos.so` before `.init_array`
/// to populate `argc`/`argv`, `@caps(...)` mask, and stdio/capability handles.
///
/// # Safety
/// `info` must point to a valid `ProcessBootstrapInfo`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __huesos_set_process_ctx(
    info: *const crate::rtld_abi::ProcessBootstrapInfo,
) -> i32 {
    if info.is_null() {
        return -1;
    }
    // SAFETY: `ld-huesos.so` passes a valid stack-allocated `ProcessBootstrapInfo`.
    let ctx = unsafe { &*info };
    if ctx.version != crate::rtld_abi::RTLD_OPS_VERSION {
        return -1;
    }
    crate::stdio::set_process_ctx(ctx);
    0
}

/// Return the number of command-line arguments (`argc`).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_args_count() -> usize {
    crate::stdio::args_count()
}

/// Copy argument `index` into `out_buf` (up to `buf_len`) and write its full
/// byte length to `*out_len`.
///
/// # Safety
/// If `buf_len > 0`, `out_buf` must be writable; `out_len` must be writable if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_arg_get(
    index: usize,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> i64 {
    // SAFETY: caller guarantees `out_buf` is valid for `buf_len` bytes.
    let Ok(dst) = (unsafe { write_slice(out_buf, buf_len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    let Some(full_len) = crate::stdio::arg_get(index, dst) else {
        return err_code(ErrorCode::NotFound);
    };
    if !out_len.is_null() {
        // SAFETY: `write_out` checks pointer validity/alignment.
        return to_abi_result(unsafe { write_out(out_len, full_len) });
    }
    0
}

/// Read up to `buf_len` bytes from `stdin` into `out_buf` (`*out_read == 0` on EOF).
///
/// # Safety
/// `out_buf` must be writable for `buf_len` bytes and `out_read` must be valid if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_stdin_read(
    out_buf: *mut u8,
    buf_len: usize,
    out_read: *mut usize,
) -> i64 {
    // SAFETY: caller guarantees `out_buf` is valid for `buf_len` bytes.
    let Ok(dst) = (unsafe { write_slice(out_buf, buf_len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match crate::stdio::stdin_read(dst) {
        Ok(n) => {
            if !out_read.is_null() {
                // SAFETY: `write_out` checks pointer validity/alignment.
                return to_abi_result(unsafe { write_out(out_read, n) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/// Read up to `buf_len` bytes from `stdin`, waiting at most `ticks` scheduler
/// ticks. Returns `-TimedOut` when nothing arrived; `*out_read == 0` on EOF.
///
/// # Safety
/// `out_buf` must be writable for `buf_len` bytes and `out_read` must be valid if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_stdin_read_timeout(
    out_buf: *mut u8,
    buf_len: usize,
    ticks: u64,
    out_read: *mut usize,
) -> i64 {
    // SAFETY: caller guarantees `out_buf` is valid for `buf_len` bytes.
    let Ok(dst) = (unsafe { write_slice(out_buf, buf_len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match crate::stdio::stdin_read_timeout(dst, ticks) {
        Ok(n) => {
            if !out_read.is_null() {
                // SAFETY: `write_out` checks pointer validity/alignment.
                return to_abi_result(unsafe { write_out(out_read, n) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/// Park the calling thread on the futex word at `uaddr` while it holds
/// `expected`.
///
/// Returns `0` when woken or when the word already differed, `-HuesOS`
/// [`ErrorCode::TimedOut`] when `timeout_ticks` elapsed first (`0` means
/// "wait forever"), and `-HuesOS InvalidArgs` for a word that is not a
/// readable, 4-byte-aligned address inside the calling process.
///
/// # Safety
/// `uaddr` must point at a live, 4-byte-aligned `uint32_t` owned by the
/// calling process. The kernel only reads it, and reads it recoverably, but
/// the caller must make the surrounding compare protocol atomic (use
/// `_Atomic` or an atomic builtin) for the futex to be sound.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_futex_wait(
    uaddr: *const u32,
    expected: u32,
    timeout_ticks: u64,
) -> i64 {
    if uaddr.is_null() {
        return err_code(ErrorCode::InvalidArgs);
    }
    let ret = raw::syscall3(
        Syscall::FutexWait,
        uaddr as u64,
        expected as u64,
        timeout_ticks,
    );
    match raw::decode(ret) {
        Ok(_) => 0,
        Err(err) => err_code(err),
    }
}

/// Wake up to `max_wake` threads parked on the futex word at `uaddr`,
/// returning the number woken (never negative) or a negative
/// [`ErrorCode`] for a misaligned pointer.
///
/// Waking does not dereference `uaddr`, so it stays valid for a word whose
/// page was unmapped after the waiters parked.
///
/// # Safety
/// `uaddr` must be a 4-byte-aligned address; it need not be readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_futex_wake(uaddr: *const u32, max_wake: u32) -> i64 {
    let ret = raw::syscall2(Syscall::FutexWake, uaddr as u64, max_wake as u64);
    match raw::decode(ret) {
        Ok(woken) => woken,
        Err(err) => err_code(err),
    }
}

/// Write `len` bytes from `data` to `stdout` in `4096`-byte chunks.
///
/// # Safety
/// `data` must be readable for `len` bytes and `out_written` must be valid if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_stdout_write(
    data: *const u8,
    len: usize,
    out_written: *mut usize,
) -> i64 {
    // SAFETY: caller guarantees `data` is readable for `len` bytes.
    let Ok(src) = (unsafe { read_bytes(data, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match crate::stdio::stdout_write(src) {
        Ok(n) => {
            if !out_written.is_null() {
                // SAFETY: `write_out` checks pointer validity/alignment.
                return to_abi_result(unsafe { write_out(out_written, n) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/// Write `len` bytes from `data` to `stderr` in `4096`-byte chunks.
///
/// # Safety
/// `data` must be readable for `len` bytes and `out_written` must be valid if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn canvas_stderr_write(
    data: *const u8,
    len: usize,
    out_written: *mut usize,
) -> i64 {
    // SAFETY: caller guarantees `data` is readable for `len` bytes.
    let Ok(src) = (unsafe { read_bytes(data, len) }) else {
        return err_code(ErrorCode::InvalidArgs);
    };
    match crate::stdio::stderr_write(src) {
        Ok(n) => {
            if !out_written.is_null() {
                // SAFETY: `write_out` checks pointer validity/alignment.
                return to_abi_result(unsafe { write_out(out_written, n) });
            }
            0
        }
        Err(err) => err_code(err),
    }
}

/// Run destructors, close stdio channels (`PeerClosed` EOF), and exit with `code`.
#[unsafe(no_mangle)]
pub extern "C" fn canvas_exit_code(code: i32) -> ! {
    run_process_fini_once();
    crate::stdio::exit(code)
}

/// Return the attenuated `@caps(...)` capability bitmask (`huesos_abi::auxv::caps_mask`).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_caps_mask() -> u64 {
    crate::stdio::caps_mask()
}

/// Return a raw handle value for `kind` (`INVALID_HANDLE` if not granted).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_cap_handle(kind: u32) -> u32 {
    let Some(cap) = crate::stdio::cap_kind_from_u32(kind) else {
        return crate::INVALID_HANDLE;
    };
    crate::stdio::cap_raw_or_invalid(cap)
}

/// Take ownership of a granted capability handle once (`INVALID_HANDLE` if absent/taken).
#[unsafe(no_mangle)]
pub extern "C" fn canvas_take_cap_handle(kind: u32) -> u32 {
    let Some(cap) = crate::stdio::cap_kind_from_u32(kind) else {
        return crate::INVALID_HANDLE;
    };
    match crate::stdio::take_cap_handle(cap) {
        Some(handle) => handle.into_raw(),
        None => crate::INVALID_HANDLE,
    }
}
