//! HuesOS native PE32+ `/lib/ucrtbase.dll` (Universal C Runtime + `vcruntime140` ABI).
//!
//! Serves direct `ucrtbase.dll` imports as well as `api-ms-win-crt-*` and
//! `vcruntime140*.dll` ApiSet redirections resolved by `/lib/ld-pe.so`.

#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use huesos_pe::win64_abi::{
    CREATE_ALWAYS, CREATE_NEW, DEFAULT_PROCESS_HEAP, FALSE, FILE_BEGIN, FILE_CURRENT, FILE_END,
    GENERIC_READ, GENERIC_WRITE, HANDLE_STDERR, HANDLE_STDIN, HANDLE_STDOUT, INVALID_HANDLE_VALUE,
    OPEN_ALWAYS, OPEN_EXISTING, PeHostApi, TRUE, TRUNCATE_EXISTING,
};

#[used]
#[unsafe(no_mangle)]
pub static _fltused: i32 = 0;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "win64" {
    fn __huesos_ntdll_host() -> *const PeHostApi;
    fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> usize;
    fn RtlReAllocateHeap(heap: usize, flags: u32, ptr_val: usize, size: usize) -> usize;
    fn RtlFreeHeap(heap: usize, flags: u32, ptr_val: usize) -> u8;
    fn RtlSizeHeap(heap: usize, flags: u32, ptr_val: usize) -> usize;
    fn NtTerminateProcess(process_handle: usize, exit_status: u32) -> !;
}

#[inline]
fn host() -> Option<&'static PeHostApi> {
    // SAFETY: imported via PE32+ IAT from `ntdll.dll`.
    let p = unsafe { __huesos_ntdll_host() };
    if p.is_null() {
        None
    } else {
        // SAFETY: `p` points to `'static` `PE_HOST_API`.
        Some(unsafe { &*p })
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // SAFETY: terminates process on panic.
    unsafe { NtTerminateProcess(usize::MAX, 101) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _DllMainCRTStartup(
    _hinst_dll: usize,
    _fdw_reason: u32,
    _lpv_reserved: usize,
) -> i32 {
    TRUE
}

// ============================================================================
// CRT Globals (`errno`, `argc`/`argv`/`environ`, `atexit` table)
// ============================================================================

static ERRNO_CELL: AtomicI32 = AtomicI32::new(0);
static FMODE_CELL: AtomicI32 = AtomicI32::new(0x4000); // _O_TEXT
static COMMODE_CELL: AtomicI32 = AtomicI32::new(0);
static NEW_MODE_CELL: AtomicI32 = AtomicI32::new(0);

static ARGC_CELL: AtomicI32 = AtomicI32::new(1);
static ARGV_PTR_CELL: AtomicUsize = AtomicUsize::new(0);
static ENVIRON_PTR_CELL: AtomicUsize = AtomicUsize::new(0);
static ARGV_INIT_ONCE: AtomicUsize = AtomicUsize::new(0);

const MAX_ATEXIT: usize = 64;
static ATEXIT_COUNT: AtomicUsize = AtomicUsize::new(0);
static ATEXIT_FNS: [AtomicUsize; MAX_ATEXIT] = [const { AtomicUsize::new(0) }; MAX_ATEXIT];

#[unsafe(no_mangle)]
pub extern "win64" fn _errno() -> *mut i32 {
    ERRNO_CELL.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "win64" fn __p__fmode() -> *mut i32 {
    FMODE_CELL.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "win64" fn _set_fmode(mode: i32) -> i32 {
    FMODE_CELL.store(mode, Ordering::Relaxed);
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn __p__commode() -> *mut i32 {
    COMMODE_CELL.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "win64" fn _set_new_mode(mode: i32) -> i32 {
    NEW_MODE_CELL.swap(mode, Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub extern "win64" fn _set_app_type(_app_type: i32) {}

#[unsafe(no_mangle)]
pub extern "win64" fn __setusermatherr(_pf: usize) {}

#[unsafe(no_mangle)]
pub extern "win64" fn _configthreadlocale(_flag: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn _invalid_parameter_noinfo() {}

#[unsafe(no_mangle)]
pub extern "win64" fn _invalid_parameter_noinfo_noreturn() -> ! {
    abort()
}

fn ensure_narrow_args_parsed() {
    if ARGV_INIT_ONCE.load(Ordering::Acquire) == 2 {
        return;
    }
    if ARGV_INIT_ONCE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        while ARGV_INIT_ONCE.load(Ordering::Acquire) != 2 {
            core::hint::spin_loop();
        }
        return;
    }

    if let Some(h) = host() {
        let cmd = (h.get_command_line_a)();
        if !cmd.is_null() {
            let mut len = 0usize;
            while len < 4096 {
                // SAFETY: `cmd` is NUL-terminated inside `ld-pe`.
                if unsafe { *cmd.add(len) } == 0 {
                    break;
                }
                len += 1;
            }
            // Copy command line + up to 32 `char*` pointers into heap.
            let buf_addr = malloc(len + 1 + 34 * core::mem::size_of::<usize>());
            if !buf_addr.is_null() {
                let ptrs = buf_addr.cast::<*mut u8>();
                // SAFETY: freshly allocated heap block.
                let str_area = unsafe { buf_addr.add(34 * core::mem::size_of::<usize>()) };
                // SAFETY: copies command line bytes into `str_area`.
                unsafe {
                    ptr::copy_nonoverlapping(cmd, str_area, len + 1);
                }
                let mut argc = 0usize;
                let mut i = 0usize;
                while i < len && argc < 32 {
                    // SAFETY: `i < len` inside `str_area`.
                    while i < len && unsafe { (*str_area.add(i)).is_ascii_whitespace() } {
                        i += 1;
                    }
                    if i >= len {
                        break;
                    }
                    // SAFETY: `argc < 32` inside `ptrs`.
                    unsafe {
                        let start = if *str_area.add(i) == b'"' {
                            i += 1;
                            let s = str_area.add(i);
                            while i < len && *str_area.add(i) != b'"' {
                                i += 1;
                            }
                            if i < len {
                                *str_area.add(i) = 0;
                                i += 1;
                            }
                            s
                        } else {
                            let s = str_area.add(i);
                            while i < len && !(*str_area.add(i)).is_ascii_whitespace() {
                                i += 1;
                            }
                            if i < len {
                                *str_area.add(i) = 0;
                                i += 1;
                            }
                            s
                        };
                        ptr::write(ptrs.add(argc), start);
                    }
                    argc += 1;
                }
                if argc == 0 {
                    // SAFETY: writes empty string pointer.
                    unsafe {
                        *str_area = 0;
                        ptr::write(ptrs, str_area);
                    }
                    argc = 1;
                }
                // SAFETY: NUL-terminate `argv[argc]` and empty `environ[0]`.
                unsafe {
                    ptr::write(ptrs.add(argc), ptr::null_mut());
                    ptr::write(ptrs.add(33), ptr::null_mut());
                    ENVIRON_PTR_CELL.store(ptrs.add(33) as usize, Ordering::Release);
                }
                ARGC_CELL.store(argc as i32, Ordering::Release);
                ARGV_PTR_CELL.store(ptrs as usize, Ordering::Release);
            }
        }
    }
    ARGV_INIT_ONCE.store(2, Ordering::Release);
}

#[unsafe(no_mangle)]
pub extern "win64" fn _configure_narrow_argv(_mode: i32) -> i32 {
    ensure_narrow_args_parsed();
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn _initialize_narrow_environment() -> i32 {
    ensure_narrow_args_parsed();
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn _get_initial_narrow_environment() -> *mut *mut u8 {
    ensure_narrow_args_parsed();
    ENVIRON_PTR_CELL.load(Ordering::Acquire) as *mut *mut u8
}

#[unsafe(no_mangle)]
pub extern "win64" fn __p___argc() -> *mut i32 {
    ensure_narrow_args_parsed();
    ARGC_CELL.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "win64" fn __p___argv() -> *mut *mut *mut u8 {
    ensure_narrow_args_parsed();
    ARGV_PTR_CELL.as_ptr().cast::<*mut *mut u8>()
}

#[unsafe(no_mangle)]
pub extern "win64" fn __p___environ() -> *mut *mut *mut u8 {
    ensure_narrow_args_parsed();
    ENVIRON_PTR_CELL.as_ptr().cast::<*mut *mut u8>()
}

#[unsafe(no_mangle)]
pub extern "win64" fn _initterm(start: *const usize, end: *const usize) {
    if start.is_null() || end.is_null() {
        return;
    }
    let mut cur = start;
    while (cur as usize) < (end as usize) {
        // SAFETY: `cur` walks `[start, end)` function pointer table.
        let fn_addr = unsafe { ptr::read(cur) };
        if fn_addr != 0 {
            // SAFETY: non-null C initializer entry `void (*)(void)`.
            unsafe {
                let f: extern "win64" fn() = core::mem::transmute(fn_addr);
                f();
            }
        }
        // SAFETY: advances by 1 pointer slot.
        cur = unsafe { cur.add(1) };
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _initterm_e(start: *const usize, end: *const usize) -> i32 {
    if start.is_null() || end.is_null() {
        return 0;
    }
    let mut cur = start;
    while (cur as usize) < (end as usize) {
        // SAFETY: `cur` walks `[start, end)` initializer table.
        let fn_addr = unsafe { ptr::read(cur) };
        if fn_addr != 0 {
            // SAFETY: non-null C initializer entry `int (*)(void)`.
            let rc = unsafe {
                let f: extern "win64" fn() -> i32 = core::mem::transmute(fn_addr);
                f()
            };
            if rc != 0 {
                return rc;
            }
        }
        // SAFETY: advances by 1 pointer slot.
        cur = unsafe { cur.add(1) };
    }
    0
}

#[repr(C)]
pub struct OnExitTable {
    pub first: usize,
    pub last: usize,
    pub end: usize,
}

#[unsafe(no_mangle)]
pub extern "win64" fn _initialize_onexit_table(table: *mut OnExitTable) -> i32 {
    if !table.is_null() {
        // SAFETY: `table` checked non-null.
        unsafe {
            ptr::write_unaligned(
                table,
                OnExitTable {
                    first: 0,
                    last: 0,
                    end: 0,
                },
            );
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn _register_onexit_function(_table: *mut OnExitTable, func: usize) -> i32 {
    _crt_atexit(func)
}

#[unsafe(no_mangle)]
pub extern "win64" fn _execute_onexit_table(_table: *mut OnExitTable) -> i32 {
    run_atexit_handlers();
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn _crt_atexit(func: usize) -> i32 {
    if func == 0 {
        return 0;
    }
    let mut idx = ATEXIT_COUNT.load(Ordering::Acquire);
    while idx < MAX_ATEXIT {
        match ATEXIT_COUNT.compare_exchange_weak(idx, idx + 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                ATEXIT_FNS[idx].store(func, Ordering::Release);
                return 0;
            }
            Err(cur) => idx = cur,
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub extern "win64" fn _register_thread_local_exe_atexit_callback(_cb: usize) {}

fn run_atexit_handlers() {
    loop {
        let count = ATEXIT_COUNT.load(Ordering::Acquire);
        if count == 0 {
            break;
        }
        if ATEXIT_COUNT
            .compare_exchange(count, count - 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let fn_addr = ATEXIT_FNS[count - 1].swap(0, Ordering::AcqRel);
            if fn_addr != 0 {
                // SAFETY: `fn_addr` registered via `_crt_atexit`.
                unsafe {
                    let f: extern "win64" fn() = core::mem::transmute(fn_addr);
                    f();
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _cexit() {
    run_atexit_handlers();
}

#[unsafe(no_mangle)]
pub extern "win64" fn _c_exit() {}

#[unsafe(no_mangle)]
pub extern "win64" fn exit(status: i32) -> ! {
    run_atexit_handlers();
    _exit(status)
}

#[unsafe(no_mangle)]
pub extern "win64" fn _exit(status: i32) -> ! {
    // SAFETY: terminates process with `status`.
    unsafe { NtTerminateProcess(usize::MAX, status as u32) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn abort() -> ! {
    _exit(3)
}

// ============================================================================
// Heap Allocation (`malloc`, `calloc`, `realloc`, `free`, `_aligned_*`)
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn malloc(size: usize) -> *mut u8 {
    let alloc_sz = size.max(1);
    // SAFETY: allocates from default process heap.
    unsafe { RtlAllocateHeap(DEFAULT_PROCESS_HEAP, 0, alloc_sz) as *mut u8 }
}

#[unsafe(no_mangle)]
pub extern "win64" fn calloc(num: usize, size: usize) -> *mut u8 {
    let Some(total) = num.checked_mul(size) else {
        return ptr::null_mut();
    };
    let alloc_sz = total.max(1);
    // SAFETY: `HEAP_ZERO_MEMORY = 0x08` zeroes allocation.
    unsafe { RtlAllocateHeap(DEFAULT_PROCESS_HEAP, 0x08, alloc_sz) as *mut u8 }
}

#[unsafe(no_mangle)]
pub extern "win64" fn realloc(ptr_val: *mut u8, new_size: usize) -> *mut u8 {
    if ptr_val.is_null() {
        return malloc(new_size);
    }
    if new_size == 0 {
        free(ptr_val);
        return ptr::null_mut();
    }
    // SAFETY: reallocates existing heap block.
    unsafe { RtlReAllocateHeap(DEFAULT_PROCESS_HEAP, 0, ptr_val as usize, new_size) as *mut u8 }
}

#[unsafe(no_mangle)]
pub extern "win64" fn free(ptr_val: *mut u8) {
    if !ptr_val.is_null() {
        // SAFETY: frees heap block.
        unsafe {
            let _ = RtlFreeHeap(DEFAULT_PROCESS_HEAP, 0, ptr_val as usize);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _msize(ptr_val: *mut u8) -> usize {
    if ptr_val.is_null() {
        return 0;
    }
    // SAFETY: queries heap block size.
    unsafe { RtlSizeHeap(DEFAULT_PROCESS_HEAP, 0, ptr_val as usize) }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _aligned_malloc(size: usize, alignment: usize) -> *mut u8 {
    let align = alignment.max(core::mem::size_of::<usize>());
    if !align.is_power_of_two() {
        return ptr::null_mut();
    }
    let Some(total) = size
        .max(1)
        .checked_add(align)
        .and_then(|v| v.checked_add(core::mem::size_of::<usize>()))
    else {
        return ptr::null_mut();
    };
    let raw = malloc(total) as usize;
    if raw == 0 {
        return ptr::null_mut();
    }
    let aligned = (raw + core::mem::size_of::<usize>() + (align - 1)) & !(align - 1);
    // SAFETY: stores original pointer immediately preceding `aligned`.
    unsafe {
        ptr::write((aligned - core::mem::size_of::<usize>()) as *mut usize, raw);
    }
    aligned as *mut u8
}

#[unsafe(no_mangle)]
pub extern "win64" fn _aligned_free(aligned_ptr: *mut u8) {
    if aligned_ptr.is_null() {
        return;
    }
    // SAFETY: reads original pointer stored by `_aligned_malloc`.
    let raw = unsafe {
        ptr::read(((aligned_ptr as usize) - core::mem::size_of::<usize>()) as *const usize)
    };
    free(raw as *mut u8);
}

// ============================================================================
// Memory, Strings, & Numeric Conversions
// ============================================================================

#[unsafe(export_name = "memcpy")]
pub unsafe extern "C" fn crt_memcpy(
    dst: *mut core::ffi::c_void,
    src: *const core::ffi::c_void,
    n: usize,
) -> *mut core::ffi::c_void {
    if n > 0 && !dst.is_null() && !src.is_null() {
        // SAFETY: non-overlapping byte copy per C `memcpy` contract (manual byte loop avoids recursion).
        let mut i = 0usize;
        let d = dst.cast::<u8>();
        let s = src.cast::<u8>();
        while i < n {
            unsafe { *d.add(i) = *s.add(i) };
            i += 1;
        }
    }
    dst
}

#[unsafe(export_name = "memmove")]
pub unsafe extern "C" fn crt_memmove(
    dst: *mut core::ffi::c_void,
    src: *const core::ffi::c_void,
    n: usize,
) -> *mut core::ffi::c_void {
    if n > 0 && !dst.is_null() && !src.is_null() && (dst as usize) != (src as usize) {
        let d = dst.cast::<u8>();
        let s = src.cast::<u8>();
        if (d as usize) < (s as usize) {
            let mut i = 0usize;
            while i < n {
                // SAFETY: forward byte copy.
                unsafe { *d.add(i) = *s.add(i) };
                i += 1;
            }
        } else {
            let mut i = n;
            while i > 0 {
                i -= 1;
                // SAFETY: backward byte copy.
                unsafe { *d.add(i) = *s.add(i) };
            }
        }
    }
    dst
}

#[unsafe(export_name = "memset")]
pub unsafe extern "C" fn crt_memset(
    dst: *mut core::ffi::c_void,
    c: i32,
    n: usize,
) -> *mut core::ffi::c_void {
    if n > 0 && !dst.is_null() {
        let d = dst.cast::<u8>();
        let val = c as u8;
        let mut i = 0usize;
        while i < n {
            // SAFETY: byte fill without recursive `memset` lowering.
            unsafe { ptr::write_volatile(d.add(i), val) };
            i += 1;
        }
    }
    dst
}

#[unsafe(export_name = "memcmp")]
pub unsafe extern "C" fn crt_memcmp(
    a: *const core::ffi::c_void,
    b: *const core::ffi::c_void,
    n: usize,
) -> i32 {
    let pa = a.cast::<u8>();
    let pb = b.cast::<u8>();
    let mut i = 0usize;
    while i < n {
        // SAFETY: `i < n` within `a` and `b`.
        let (va, vb) = unsafe { (*pa.add(i), *pb.add(i)) };
        if va != vb {
            return i32::from(va) - i32::from(vb);
        }
        i += 1;
    }
    0
}

#[unsafe(export_name = "memchr")]
pub extern "win64" fn crt_memchr(s: *const u8, c: i32, n: usize) -> *const u8 {
    let needle = c as u8;
    for i in 0..n {
        // SAFETY: `i < n` within `s`.
        if unsafe { *s.add(i) } == needle {
            // SAFETY: `i < n`.
            return unsafe { s.add(i) };
        }
    }
    ptr::null()
}

fn cstr_len_u8(s: *const u8) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    loop {
        // SAFETY: C NUL-terminated string.
        if unsafe { *s.add(n) } == 0 {
            return n;
        }
        n += 1;
    }
}

#[unsafe(export_name = "strlen")]
pub unsafe extern "C" fn crt_strlen(s: *const i8) -> usize {
    cstr_len_u8(s.cast::<u8>())
}

#[unsafe(no_mangle)]
pub extern "win64" fn strnlen(s: *const u8, maxlen: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    while n < maxlen {
        // SAFETY: bounded by `maxlen`.
        if unsafe { *s.add(n) } == 0 {
            break;
        }
        n += 1;
    }
    n
}

#[unsafe(no_mangle)]
pub extern "win64" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0usize;
    loop {
        // SAFETY: C NUL-terminated strings.
        let (va, vb) = unsafe { (*a.add(i), *b.add(i)) };
        if va != vb || va == 0 {
            return i32::from(va) - i32::from(vb);
        }
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn strncmp(a: *const u8, b: *const u8, max_n: usize) -> i32 {
    for i in 0..max_n {
        // SAFETY: bounded by `max_n` and NUL terminator.
        let (va, vb) = unsafe { (*a.add(i), *b.add(i)) };
        if va != vb || va == 0 {
            return i32::from(va) - i32::from(vb);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn _stricmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0usize;
    loop {
        // SAFETY: C NUL-terminated strings.
        let (va, vb) = unsafe {
            (
                (*a.add(i)).to_ascii_lowercase(),
                (*b.add(i)).to_ascii_lowercase(),
            )
        };
        if va != vb || va == 0 {
            return i32::from(va) - i32::from(vb);
        }
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    let len = cstr_len_u8(src);
    // SAFETY: copies `len + 1` bytes including NUL terminator.
    unsafe { ptr::copy_nonoverlapping(src, dst, len + 1) };
    dst
}

#[unsafe(no_mangle)]
pub extern "win64" fn strncpy(dst: *mut u8, src: *const u8, count: usize) -> *mut u8 {
    let len = strnlen(src, count);
    // SAFETY: copies up to `len` bytes and zero-pads remainder up to `count`.
    unsafe {
        ptr::copy_nonoverlapping(src, dst, len);
        if len < count {
            ptr::write_bytes(dst.add(len), 0, count - len);
        }
    }
    dst
}

#[unsafe(no_mangle)]
pub extern "win64" fn strchr(s: *const u8, c: i32) -> *const u8 {
    if s.is_null() {
        return ptr::null();
    }
    let needle = c as u8;
    let mut i = 0usize;
    loop {
        // SAFETY: C NUL-terminated string.
        let ch = unsafe { *s.add(i) };
        if ch == needle {
            // SAFETY: within string.
            return unsafe { s.add(i) };
        }
        if ch == 0 {
            return ptr::null();
        }
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn strstr(haystack: *const u8, needle: *const u8) -> *const u8 {
    if haystack.is_null() || needle.is_null() {
        return ptr::null();
    }
    let nlen = cstr_len_u8(needle);
    if nlen == 0 {
        return haystack;
    }
    let hlen = cstr_len_u8(haystack);
    if nlen > hlen {
        return ptr::null();
    }
    for i in 0..=(hlen - nlen) {
        // SAFETY: `i + nlen <= hlen`.
        let p = unsafe { haystack.add(i) };
        if strncmp(p, needle, nlen) == 0 {
            return p;
        }
    }
    ptr::null()
}

#[unsafe(no_mangle)]
pub extern "win64" fn strtoll(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
    if s.is_null() {
        return 0;
    }
    let mut i = 0usize;
    // SAFETY: skips leading whitespace in NUL-terminated string.
    while unsafe { (*s.add(i)).is_ascii_whitespace() } {
        i += 1;
    }
    let mut neg = false;
    // SAFETY: checks optional sign.
    let first = unsafe { *s.add(i) };
    if first == b'-' {
        neg = true;
        i += 1;
    } else if first == b'+' {
        i += 1;
    }
    let radix: u32 = if base == 0 {
        // SAFETY: checks `0x` / `0` prefix.
        let c0 = unsafe { *s.add(i) };
        if c0 == b'0' {
            let c1 = unsafe { *s.add(i + 1) };
            if c1 == b'x' || c1 == b'X' {
                i += 2;
                16
            } else {
                8
            }
        } else {
            10
        }
    } else {
        if base == 16 {
            // SAFETY: skips optional `0x` prefix.
            let c0 = unsafe { *s.add(i) };
            let c1 = unsafe { *s.add(i + 1) };
            if c0 == b'0' && (c1 == b'x' || c1 == b'X') {
                i += 2;
            }
        }
        (base as u32).clamp(2, 36)
    };

    let mut acc = 0i64;
    let mut any = false;
    loop {
        // SAFETY: reads next character.
        let ch = unsafe { *s.add(i) };
        let Some(d) = (ch as char).to_digit(radix) else {
            break;
        };
        any = true;
        acc = acc
            .wrapping_mul(i64::from(radix))
            .wrapping_add(i64::from(d));
        i += 1;
    }
    if !endptr.is_null() {
        // SAFETY: writes end pointer.
        unsafe {
            let end = if any { s.add(i) } else { s };
            ptr::write_unaligned(endptr, end.cast_mut());
        }
    }
    if neg { acc.wrapping_neg() } else { acc }
}

#[unsafe(no_mangle)]
pub extern "win64" fn strtoull(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
    strtoll(s, endptr, base) as u64
}

#[unsafe(no_mangle)]
pub extern "win64" fn strtol(s: *const u8, endptr: *mut *mut u8, base: i32) -> i32 {
    strtoll(s, endptr, base) as i32
}

#[unsafe(no_mangle)]
pub extern "win64" fn strtoul(s: *const u8, endptr: *mut *mut u8, base: i32) -> u32 {
    strtoll(s, endptr, base) as u32
}

#[unsafe(no_mangle)]
pub extern "win64" fn atoi(s: *const u8) -> i32 {
    strtol(s, ptr::null_mut(), 10)
}

#[unsafe(no_mangle)]
pub extern "win64" fn atol(s: *const u8) -> i32 {
    strtol(s, ptr::null_mut(), 10)
}

#[unsafe(no_mangle)]
pub extern "win64" fn _atoi64(s: *const u8) -> i64 {
    strtoll(s, ptr::null_mut(), 10)
}

// ============================================================================
// Stdio (`FILE*`, `__acrt_iob_func`, `fopen`, `fwrite`, `fread`, `puts`, etc.)
// ============================================================================

#[repr(C)]
pub struct CrtFile {
    pub handle: AtomicUsize,
    pub flags: AtomicI32, // bit 0 = eof, bit 1 = err, bit 2 = owned handle
    pub fd: i32,
}

static STDIO_STREAMS: [CrtFile; 3] = [
    CrtFile {
        handle: AtomicUsize::new(HANDLE_STDIN),
        flags: AtomicI32::new(0),
        fd: 0,
    },
    CrtFile {
        handle: AtomicUsize::new(HANDLE_STDOUT),
        flags: AtomicI32::new(0),
        fd: 1,
    },
    CrtFile {
        handle: AtomicUsize::new(HANDLE_STDERR),
        flags: AtomicI32::new(0),
        fd: 2,
    },
];

#[unsafe(no_mangle)]
pub extern "win64" fn __acrt_iob_func(idx: u32) -> *mut CrtFile {
    if (idx as usize) < STDIO_STREAMS.len() {
        (&raw const STDIO_STREAMS[idx as usize]).cast_mut()
    } else {
        ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn fopen(filename: *const u8, mode: *const u8) -> *mut CrtFile {
    if filename.is_null() || mode.is_null() {
        return ptr::null_mut();
    }
    let Some(h) = host() else {
        return ptr::null_mut();
    };
    let path_len = strnlen(filename, 512);
    let mode_len = strnlen(mode, 16);
    // SAFETY: `mode` valid for `mode_len` bytes.
    let mode_bytes = unsafe { core::slice::from_raw_parts(mode, mode_len) };
    let has_plus = mode_bytes.contains(&b'+');
    let first = mode_bytes.first().copied().unwrap_or(b'r');
    let (access, disp) = match first {
        b'r' => (
            if has_plus {
                GENERIC_READ | GENERIC_WRITE
            } else {
                GENERIC_READ
            },
            OPEN_EXISTING,
        ),
        b'w' => (
            if has_plus {
                GENERIC_READ | GENERIC_WRITE
            } else {
                GENERIC_WRITE
            },
            CREATE_ALWAYS,
        ),
        b'a' => (
            if has_plus {
                GENERIC_READ | GENERIC_WRITE
            } else {
                GENERIC_WRITE
            },
            OPEN_ALWAYS,
        ),
        _ => {
            let _ = (CREATE_NEW, TRUNCATE_EXISTING);
            return ptr::null_mut();
        }
    };
    let handle = (h.create_file_utf8)(filename, path_len, access, disp);
    if handle == INVALID_HANDLE_VALUE || handle == 0 {
        return ptr::null_mut();
    }
    if first == b'a' {
        let mut new_pos = 0i64;
        let _ = (h.set_file_pointer)(handle, 0, &raw mut new_pos, FILE_END);
    }
    let raw = malloc(core::mem::size_of::<CrtFile>()).cast::<CrtFile>();
    if raw.is_null() {
        let _ = (h.close_handle)(handle);
        return ptr::null_mut();
    }
    // SAFETY: initializes freshly allocated `CrtFile`.
    unsafe {
        ptr::write(
            raw,
            CrtFile {
                handle: AtomicUsize::new(handle),
                flags: AtomicI32::new(4),
                fd: 3,
            },
        );
    }
    raw
}

#[unsafe(no_mangle)]
pub extern "win64" fn fclose(stream: *mut CrtFile) -> i32 {
    if stream.is_null() {
        return -1;
    }
    // SAFETY: `stream` checked non-null.
    let f = unsafe { &*stream };
    let flags = f.flags.load(Ordering::Acquire);
    if (flags & 4) != 0 {
        let handle = f.handle.swap(INVALID_HANDLE_VALUE, Ordering::AcqRel);
        if let Some(h) = host() {
            let _ = (h.close_handle)(handle);
        }
        free(stream.cast::<u8>());
    }
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn fwrite(
    buffer: *const u8,
    size: usize,
    count: usize,
    stream: *mut CrtFile,
) -> usize {
    if buffer.is_null() || stream.is_null() || size == 0 || count == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(count) else {
        return 0;
    };
    let Some(h) = host() else {
        return 0;
    };
    // SAFETY: `stream` checked non-null.
    let f = unsafe { &*stream };
    let handle = f.handle.load(Ordering::Acquire);
    let mut written = 0u32;
    if (h.write_file)(
        handle,
        buffer,
        total.min(u32::MAX as usize) as u32,
        &raw mut written,
    ) == FALSE
    {
        f.flags.fetch_or(2, Ordering::Relaxed);
        return 0;
    }
    (written as usize) / size
}

#[unsafe(no_mangle)]
pub extern "win64" fn fread(
    buffer: *mut u8,
    size: usize,
    count: usize,
    stream: *mut CrtFile,
) -> usize {
    if buffer.is_null() || stream.is_null() || size == 0 || count == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(count) else {
        return 0;
    };
    let Some(h) = host() else {
        return 0;
    };
    // SAFETY: `stream` checked non-null.
    let f = unsafe { &*stream };
    let handle = f.handle.load(Ordering::Acquire);
    let mut read_n = 0u32;
    if (h.read_file)(
        handle,
        buffer,
        total.min(u32::MAX as usize) as u32,
        &raw mut read_n,
    ) == FALSE
    {
        f.flags.fetch_or(2, Ordering::Relaxed);
        return 0;
    }
    if read_n == 0 {
        f.flags.fetch_or(1, Ordering::Relaxed);
    }
    (read_n as usize) / size
}

#[unsafe(no_mangle)]
pub extern "win64" fn fseek(stream: *mut CrtFile, offset: i32, origin: i32) -> i32 {
    if stream.is_null() {
        return -1;
    }
    let Some(h) = host() else {
        return -1;
    };
    let method = match origin {
        0 => FILE_BEGIN,
        1 => FILE_CURRENT,
        2 => FILE_END,
        _ => return -1,
    };
    // SAFETY: `stream` checked non-null.
    let f = unsafe { &*stream };
    let mut new_pos = 0i64;
    if (h.set_file_pointer)(
        f.handle.load(Ordering::Acquire),
        i64::from(offset),
        &raw mut new_pos,
        method,
    ) != FALSE
    {
        f.flags.fetch_and(!1, Ordering::Relaxed);
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn ftell(stream: *mut CrtFile) -> i32 {
    if stream.is_null() {
        return -1;
    }
    let Some(h) = host() else {
        return -1;
    };
    // SAFETY: `stream` checked non-null.
    let f = unsafe { &*stream };
    let mut pos = 0i64;
    if (h.set_file_pointer)(
        f.handle.load(Ordering::Acquire),
        0,
        &raw mut pos,
        FILE_CURRENT,
    ) != FALSE
    {
        pos as i32
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn fflush(_stream: *mut CrtFile) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "win64" fn feof(stream: *mut CrtFile) -> i32 {
    if stream.is_null() {
        return 0;
    }
    // SAFETY: `stream` checked non-null.
    (unsafe { &*stream }.flags.load(Ordering::Relaxed)) & 1
}

#[unsafe(no_mangle)]
pub extern "win64" fn ferror(stream: *mut CrtFile) -> i32 {
    if stream.is_null() {
        return 0;
    }
    // SAFETY: `stream` checked non-null.
    ((unsafe { &*stream }.flags.load(Ordering::Relaxed)) >> 1) & 1
}

#[unsafe(no_mangle)]
pub extern "win64" fn fputc(ch: i32, stream: *mut CrtFile) -> i32 {
    let b = ch as u8;
    if fwrite(&raw const b, 1, 1, stream) == 1 {
        i32::from(b)
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn putchar(ch: i32) -> i32 {
    fputc(ch, __acrt_iob_func(1))
}

#[unsafe(no_mangle)]
pub extern "win64" fn fputs(s: *const u8, stream: *mut CrtFile) -> i32 {
    if s.is_null() {
        return -1;
    }
    let len = cstr_len_u8(s);
    if len == 0 || fwrite(s, 1, len, stream) == len {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn puts(s: *const u8) -> i32 {
    let out = __acrt_iob_func(1);
    if fputs(s, out) < 0 {
        return -1;
    }
    if fputc(i32::from(b'\n'), out) < 0 {
        -1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _fileno(stream: *mut CrtFile) -> i32 {
    if stream.is_null() {
        -1
    } else {
        // SAFETY: `stream` checked non-null.
        unsafe { (*stream).fd }
    }
}

#[unsafe(no_mangle)]
pub extern "win64" fn _isatty(fd: i32) -> i32 {
    i32::from((0..=2).contains(&fd))
}

// ============================================================================
// Environment, Time, & Exception Frame Handlers (`vcruntime140`)
// ============================================================================

#[unsafe(no_mangle)]
pub extern "win64" fn getenv(_name: *const u8) -> *const u8 {
    ptr::null()
}

#[unsafe(no_mangle)]
pub extern "win64" fn _time64(dest: *mut i64) -> i64 {
    let secs = host().map_or(0, |h| ((h.get_tick_count64)() / 1_000) as i64) + 1_795_392_000;
    if !dest.is_null() {
        // SAFETY: `dest` checked non-null.
        unsafe { ptr::write_unaligned(dest, secs) };
    }
    secs
}

#[unsafe(no_mangle)]
pub extern "win64" fn time(dest: *mut i64) -> i64 {
    _time64(dest)
}

#[unsafe(no_mangle)]
pub extern "win64" fn clock() -> i32 {
    host().map_or(0, |h| (h.get_tick_count64)() as i32)
}

#[unsafe(no_mangle)]
pub extern "win64" fn __C_specific_handler(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    1 // ExceptionContinueSearch
}

#[unsafe(no_mangle)]
pub extern "win64" fn __CxxFrameHandler3(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "win64" fn __CxxFrameHandler4(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "win64" fn __std_terminate() -> ! {
    abort()
}

#[unsafe(no_mangle)]
pub extern "win64" fn _CxxThrowException(_exc_obj: usize, _throw_info: usize) -> ! {
    abort()
}
