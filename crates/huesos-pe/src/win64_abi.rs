//! Shared Win64 / NT / Win32 ABI structures, constants, and the `PeHostApi`
//! bridge contract between `/lib/ld-pe.so` and `/lib/ntdll.dll`.

/// Version tag of [`PeHostApi`].
pub const PE_HOST_API_VERSION: u32 = 2;

/// Exported binder symbol in `ntdll.dll` invoked by `/lib/ld-pe.so` immediately
/// after relocating `ntdll.dll` and before `DllMain(DLL_PROCESS_ATTACH)`.
pub const NTDLL_BIND_HOST_SYMBOL: &[u8] = b"__huesos_ntdll_bind_host";

/// `DllMain` reason codes.
pub const DLL_PROCESS_DETACH: u32 = 0;
/// `DllMain` process attach reason.
pub const DLL_PROCESS_ATTACH: u32 = 1;
/// `DllMain` thread attach reason.
pub const DLL_THREAD_ATTACH: u32 = 2;
/// `DllMain` thread detach reason.
pub const DLL_THREAD_DETACH: u32 = 3;

/// Win32 `BOOL` constants.
pub const FALSE: i32 = 0;
/// Win32 `TRUE`.
pub const TRUE: i32 = 1;

/// Invalid Win32 `HANDLE` sentinel (`(HANDLE)-1`).
pub const INVALID_HANDLE_VALUE: usize = usize::MAX;

/// Standard Win32 console handle selectors (`GetStdHandle`).
pub const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
/// Standard output selector.
pub const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
/// Standard error selector.
pub const STD_ERROR_HANDLE: u32 = (-12i32) as u32;

/// Concrete pseudo-handle values returned by `GetStdHandle`.
pub const HANDLE_STDIN: usize = 0x0000_0010;
/// Standard output handle value.
pub const HANDLE_STDOUT: usize = 0x0000_0011;
/// Standard error handle value.
pub const HANDLE_STDERR: usize = 0x0000_0012;

/// Default `GetProcessHeap()` handle token.
pub const DEFAULT_PROCESS_HEAP: usize = 0x0000_0001;

/// Win32 error codes (`GetLastError` / `SetLastError`).
pub const ERROR_SUCCESS: u32 = 0;
/// File not found (`2`).
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
/// Path not found (`3`).
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
/// Access denied (`5`).
pub const ERROR_ACCESS_DENIED: u32 = 5;
/// Invalid handle (`6`).
pub const ERROR_INVALID_HANDLE: u32 = 6;
/// Not enough memory (`8`).
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// Invalid parameter (`87`).
pub const ERROR_INVALID_PARAMETER: u32 = 87;
/// Insufficient buffer (`122`).
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// Module not found (`126`).
pub const ERROR_MOD_NOT_FOUND: u32 = 126;
/// Procedure not found (`127`).
pub const ERROR_PROC_NOT_FOUND: u32 = 127;
/// Already exists (`183`).
pub const ERROR_ALREADY_EXISTS: u32 = 183;
/// No more TLS slots (`259` / `TLS_OUT_OF_INDEXES` companion).
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
/// Timeout expired (`1460`).
pub const ERROR_TIMEOUT: u32 = 1460;

/// Sentinel returned by `TlsAlloc` on exhaustion.
pub const TLS_OUT_OF_INDEXES: u32 = 0xffff_ffff;
/// Number of standard Win64 TEB `TlsSlots` (`gs:[0x1480..0x1680]`).
pub const TLS_MINIMUM_AVAILABLE: usize = 64;

/// Wait return codes (`WaitForSingleObject` / `WaitForMultipleObjects`).
pub const WAIT_OBJECT_0: u32 = 0x0000_0000;
/// Wait timed out.
pub const WAIT_TIMEOUT: u32 = 0x0000_0102;
/// Wait failed (`GetLastError` holds reason).
pub const WAIT_FAILED: u32 = 0xffff_ffff;
/// Infinite wait timeout (`INFINITE`).
pub const INFINITE: u32 = 0xffff_ffff;

/// `VirtualAlloc` / `VirtualFree` allocation flags.
pub const MEM_COMMIT: u32 = 0x0000_1000;
/// Reserve virtual address space.
pub const MEM_RESERVE: u32 = 0x0000_2000;
/// Decommit pages.
pub const MEM_DECOMMIT: u32 = 0x0000_4000;
/// Release region.
pub const MEM_RELEASE: u32 = 0x0000_8000;

/// Win32 page protection constants (`VirtualAlloc` / `VirtualProtect`).
pub const PAGE_NOACCESS: u32 = 0x01;
/// Read-only page protection.
pub const PAGE_READONLY: u32 = 0x02;
/// Read/write page protection.
pub const PAGE_READWRITE: u32 = 0x04;
/// Copy-on-write page protection.
pub const PAGE_WRITECOPY: u32 = 0x08;
/// Execute-only page protection.
pub const PAGE_EXECUTE: u32 = 0x10;
/// Read+execute page protection.
pub const PAGE_EXECUTE_READ: u32 = 0x20;
/// Read+write+execute (strictly rejected by HuesOS W^X policy).
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
/// Writecopy+execute (strictly rejected by HuesOS W^X policy).
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// `HeapAlloc` / `HeapReAlloc` flag requesting zero-initialized memory.
pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

/// `CreateFile` desired access flags.
pub const GENERIC_READ: u32 = 0x8000_0000;
/// Write access flag.
pub const GENERIC_WRITE: u32 = 0x4000_0000;

/// `CreateFile` creation disposition constants.
pub const CREATE_NEW: u32 = 1;
/// Always create/truncate file.
pub const CREATE_ALWAYS: u32 = 2;
/// Open existing file only.
pub const OPEN_EXISTING: u32 = 3;
/// Open existing or create new file.
pub const OPEN_ALWAYS: u32 = 4;
/// Truncate existing file.
pub const TRUNCATE_EXISTING: u32 = 5;

/// `SetFilePointerEx` move methods.
pub const FILE_BEGIN: u32 = 0;
/// Seek relative to current cursor.
pub const FILE_CURRENT: u32 = 1;
/// Seek relative to end of file.
pub const FILE_END: u32 = 2;

/// Win64 TEB (`GS_BASE`) byte offsets matching Windows x64 ABI.
pub mod teb_offsets {
    /// `NT_TIB.ExceptionList`
    pub const EXCEPTION_LIST: usize = 0x0000;
    /// `NT_TIB.StackBase` (high stack address)
    pub const STACK_BASE: usize = 0x0008;
    /// `NT_TIB.StackLimit` (low stack address)
    pub const STACK_LIMIT: usize = 0x0010;
    /// `NT_TIB.Self` — linear address of TEB (`gs:[0x30]`)
    pub const SELF_PTR: usize = 0x0030;
    /// `ClientId.UniqueProcess` (`gs:[0x40]`)
    pub const PROCESS_ID: usize = 0x0040;
    /// `ClientId.UniqueThread` (`gs:[0x48]`)
    pub const THREAD_ID: usize = 0x0048;
    /// `ThreadLocalStoragePointer` (`gs:[0x58]`) for PE `.tls` Directory #9
    pub const TLS_ARRAY_PTR: usize = 0x0058;
    /// `ProcessEnvironmentBlock` (`gs:[0x60]`)
    pub const PEB_PTR: usize = 0x0060;
    /// `LastErrorValue` (`gs:[0x68]`, `u32`)
    pub const LAST_ERROR_VALUE: usize = 0x0068;
    /// `TlsSlots[0..64]` (`gs:[0x1480..0x1680]`)
    pub const TLS_SLOTS: usize = 0x1480;
    /// Total TEB allocation size (2 pages = 8 KiB).
    pub const TEB_TOTAL_BYTES: usize = 0x2000;
}

/// Minimal Win64 `PEB` layout pointed to by `gs:[0x60]`.
#[repr(C)]
pub struct Peb64 {
    /// Reserved flags (`[0..2)`).
    pub reserved1: [u8; 2],
    /// `BeingDebugged` (`0` under normal execution).
    pub being_debugged: u8,
    /// Padding (`[3..16)`).
    pub reserved2: [u8; 13],
    /// Main `.exe` mapped base (`0x10`).
    pub image_base_address: u64,
    /// Loader data pointer (`0x18`).
    pub ldr: u64,
    /// `RTL_USER_PROCESS_PARAMETERS` pointer (`0x20`).
    pub process_parameters: u64,
    /// SubSystemData (`0x28`).
    pub sub_system_data: u64,
    /// Default process heap handle (`0x30`).
    pub process_heap: u64,
}

/// Win64 `RTL_CRITICAL_SECTION` (40 bytes on x64).
#[repr(C)]
pub struct RtlCriticalSection {
    /// Debug info pointer (unused, `0`).
    pub debug_info: usize,
    /// Lock state (`0` = unlocked, `1` = uncontended locked, `2` = contended).
    pub lock_count: u32,
    /// Recursive acquisition count for `owning_thread`.
    pub recursion_count: u32,
    /// Owning Win64 thread ID (`0` when unlocked).
    pub owning_thread: usize,
    /// Reserved semaphore handle (`0`).
    pub lock_semaphore: usize,
    /// Spin count hint.
    pub spin_count: usize,
}

/// Win64 `RTL_SRWLOCK` (8 bytes on x64).
#[repr(C)]
pub struct RtlSrwLock {
    /// Atomic state word (`0` = unlocked, `0xffff_ffff` = exclusive, `1..` = shared readers).
    pub ptr: usize,
}

/// Win64 `RTL_CONDITION_VARIABLE` (8 bytes on x64).
#[repr(C)]
pub struct RtlConditionVariable {
    /// Atomic sequence counter woken via futex.
    pub ptr: usize,
}

/// Win64 `SYSTEM_INFO` (48 bytes on x64).
#[repr(C)]
pub struct SystemInfo64 {
    /// Processor architecture (`9` = `PROCESSOR_ARCHITECTURE_AMD64`).
    pub processor_architecture: u16,
    /// Reserved (`0`).
    pub reserved: u16,
    /// Page size (`4096`).
    pub page_size: u32,
    /// Minimum application address.
    pub minimum_application_address: usize,
    /// Maximum application address.
    pub maximum_application_address: usize,
    /// Active processor mask.
    pub active_processor_mask: usize,
    /// Logical processor count.
    pub number_of_processors: u32,
    /// Processor type (`8664`).
    pub processor_type: u32,
    /// Allocation granularity (`65536` or `4096`).
    pub allocation_granularity: u32,
    /// Processor level.
    pub processor_level: u16,
    /// Processor revision.
    pub processor_revision: u16,
}

/// Win64 `CONTEXT` (1232 bytes, 16-byte aligned on x64).
///
/// Matches the exact Microsoft x64 ABI byte offsets for `ContextFlags` (`0x30`),
/// `Rax..R15` (`0x78..0xF8`), `Rip` (`0xF8`), and `EFlags` (`0x44`).
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Win64Context {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    /// General-purpose registers `[rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8..r15]` at `0x78`.
    pub gpr: [u64; 16],
    /// Instruction pointer at `0xF8`.
    pub rip: u64,
    /// FXSAVE / XMM area + vector registers (`0x100..0x4D0`).
    pub flt_and_vector_area: [u8; 0x3D0],
}

impl Win64Context {
    pub const fn zeroed() -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            context_flags: 0x0010_000B,
            mx_csr: 0x1F80,
            seg_cs: 0x33,
            seg_ds: 0x2B,
            seg_es: 0x2B,
            seg_fs: 0x53,
            seg_gs: 0x2B,
            seg_ss: 0x2B,
            eflags: 0x202,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            gpr: [0; 16],
            rip: 0,
            flt_and_vector_area: [0; 0x3D0],
        }
    }
}

/// Win64 thread start routine (`LPTHREAD_START_ROUTINE`).
pub type Win64ThreadStart = extern "win64" fn(usize) -> u32;

/// Win64 FLS destructor callback (`PFLS_CALLBACK_FUNCTION`).
pub type Win64FlsCallback = unsafe extern "win64" fn(usize);

/// Host capability bridge table exported by `/lib/ld-pe.so` to `/lib/ntdll.dll`.
///
/// Every callback uses the Microsoft x64 (`extern "win64"`) calling convention
/// so `ntdll.dll` and companion Win64 system DLLs invoke them directly.
#[repr(C)]
pub struct PeHostApi {
    /// Struct version (`PE_HOST_API_VERSION`).
    pub version: u32,
    /// Current HuesOS process ID / koid-derived ID.
    pub process_id: u32,
    /// `VirtualAlloc` backing via `VMAR` + `VMO` (strictly W^X).
    pub virtual_alloc: extern "win64" fn(usize, usize, u32, u32) -> usize,
    /// `VirtualFree` backing via `VMAR::unmap`.
    pub virtual_free: extern "win64" fn(usize, usize, u32) -> i32,
    /// `VirtualProtect` backing via `VMAR::protect` (strictly W^X).
    pub virtual_protect: extern "win64" fn(usize, usize, u32, *mut u32) -> i32,
    /// `HeapCreate` backing.
    pub heap_create: extern "win64" fn(u32, usize, usize) -> usize,
    /// `HeapDestroy` backing.
    pub heap_destroy: extern "win64" fn(usize) -> i32,
    /// `HeapAlloc` backing over `ScudoHeap`.
    pub heap_alloc: extern "win64" fn(usize, u32, usize) -> usize,
    /// `HeapReAlloc` backing over `ScudoHeap`.
    pub heap_realloc: extern "win64" fn(usize, u32, usize, usize) -> usize,
    /// `HeapFree` backing over `ScudoHeap`.
    pub heap_free: extern "win64" fn(usize, u32, usize) -> i32,
    /// `HeapSize` query.
    pub heap_size: extern "win64" fn(usize, u32, usize) -> usize,
    /// `GetStdHandle` backing.
    pub get_std_handle: extern "win64" fn(u32) -> usize,
    /// `CreateFile` UTF-8 path opener over HxFS / BOOTFS.
    pub create_file_utf8: extern "win64" fn(*const u8, usize, u32, u32) -> usize,
    /// `ReadFile` over console stdin or HxFS/BOOTFS file handle.
    pub read_file: extern "win64" fn(usize, *mut u8, u32, *mut u32) -> i32,
    /// `WriteFile` over console stdout/stderr or HxFS file handle.
    pub write_file: extern "win64" fn(usize, *const u8, u32, *mut u32) -> i32,
    /// `SetFilePointerEx` backing.
    pub set_file_pointer: extern "win64" fn(usize, i64, *mut i64, u32) -> i32,
    /// `GetFileSizeEx` backing.
    pub get_file_size: extern "win64" fn(usize, *mut i64) -> i32,
    /// `DeleteFile` UTF-8 backing.
    pub delete_file_utf8: extern "win64" fn(*const u8, usize) -> i32,
    /// `CreateDirectory` UTF-8 backing.
    pub create_dir_utf8: extern "win64" fn(*const u8, usize) -> i32,
    /// `CloseHandle` for files, threads, and events.
    pub close_handle: extern "win64" fn(usize) -> i32,
    /// Futex wait (`0` = ok, `ERROR_TIMEOUT` = timeout).
    pub futex_wait: extern "win64" fn(*const u32, u32, u32) -> u32,
    /// Futex wake (`count` woken).
    pub futex_wake: extern "win64" fn(*const u32, u32) -> u32,
    /// `CreateEvent` backing.
    pub create_event: extern "win64" fn(i32, i32) -> usize,
    /// `SetEvent` backing.
    pub set_event: extern "win64" fn(usize) -> i32,
    /// `ResetEvent` backing.
    pub reset_event: extern "win64" fn(usize) -> i32,
    /// `CreateThread` backing (allocates ELF TLS + Win64 TEB `GS_BASE` + runs `DllMain`).
    pub create_thread: extern "win64" fn(usize, Win64ThreadStart, usize, u32, *mut u32) -> usize,
    /// `WaitForSingleObject` backing.
    pub wait_for_single_object: extern "win64" fn(usize, u32) -> u32,
    /// `WaitForMultipleObjects` backing.
    pub wait_for_multiple_objects: extern "win64" fn(u32, *const usize, i32, u32) -> u32,
    /// `GetExitCodeThread` backing.
    pub get_exit_code_thread: extern "win64" fn(usize, *mut u32) -> i32,
    /// `TlsAlloc` slot allocator (`0..64`).
    pub tls_alloc: extern "win64" fn() -> u32,
    /// `TlsFree` slot releaser.
    pub tls_free: extern "win64" fn(u32) -> i32,
    /// `ExitThread` termination.
    pub exit_thread: extern "win64" fn(u32) -> !,
    /// `ExitProcess` termination.
    pub exit_process: extern "win64" fn(u32) -> !,
    /// `LoadLibrary` dynamic PE32+ DLL loader.
    pub load_library_utf8: extern "win64" fn(*const u8, usize) -> usize,
    /// `GetModuleHandle` lookup (`NULL` / `len == 0` returns main `.exe` base).
    pub get_module_handle_utf8: extern "win64" fn(*const u8, usize) -> usize,
    /// `GetProcAddress` symbol/ordinal resolver.
    pub get_proc_address: extern "win64" fn(usize, *const u8, usize, u32) -> usize,
    /// `FreeLibrary` refcount decrement.
    pub free_library: extern "win64" fn(usize) -> i32,
    /// NUL-terminated ANSI command line (`GetCommandLineA`).
    pub get_command_line_a: extern "win64" fn() -> *const u8,
    /// NUL-terminated UTF-16LE command line (`GetCommandLineW`).
    pub get_command_line_w: extern "win64" fn() -> *const u16,
    /// Double-NUL-terminated UTF-16LE environment block (`GetEnvironmentStringsW`).
    pub get_env_strings_w: extern "win64" fn() -> *const u16,
    /// High-resolution performance counter (`QueryPerformanceCounter`).
    pub query_perf_counter: extern "win64" fn() -> u64,
    /// High-resolution counter frequency in Hz (`QueryPerformanceFrequency`).
    pub query_perf_freq: extern "win64" fn() -> u64,
    /// Milliseconds since boot (`GetTickCount64`).
    pub get_tick_count64: extern "win64" fn() -> u64,
    /// Cooperative/scheduler sleep in milliseconds (`Sleep`).
    pub sleep_ms: extern "win64" fn(u32),
    /// Online logical processor count (`GetSystemInfo`).
    pub get_num_cpus: extern "win64" fn() -> u32,
    /// `.pdata` `RtlLookupFunctionEntry` across loaded PE32+ modules and dynamic function tables.
    pub lookup_function_entry: extern "win64" fn(u64, *mut u64) -> usize,
    /// `.xdata` `RtlVirtualUnwind` single frame step.
    pub virtual_unwind_step:
        extern "win64" fn(u32, u64, u64, usize, *mut Win64Context, *mut usize, *mut u64) -> usize,
    /// `RtlAddFunctionTable` dynamic `.pdata` registration (`JIT` / dynamic frames).
    pub add_function_table: extern "win64" fn(usize, u32, u64) -> u8,
    /// `RtlDeleteFunctionTable` unregistration.
    pub delete_function_table: extern "win64" fn(usize) -> u8,
    /// Kernel CSPRNG buffer fill (`BCryptGenRandom` / `ProcessPrng` / `RtlGenRandom`).
    pub gen_random: extern "win64" fn(*mut u8, usize) -> i32,
    /// Winsock2 DNS IPv4 resolver (`0` = ok, non-zero = WSA error).
    pub net_resolve_ipv4: extern "win64" fn(*const u8, usize, *mut u32) -> i32,
    /// Winsock2 TCP socket create (`INVALID_SOCKET = usize::MAX` on failure).
    pub net_tcp_socket: extern "win64" fn() -> usize,
    /// Winsock2 TCP connect (`ip_be`, `port_host`, returns `0` or WSA error).
    pub net_tcp_connect: extern "win64" fn(usize, u32, u16) -> i32,
    /// Winsock2 TCP send (`>= 0` bytes sent or `-wsa_err`).
    pub net_tcp_send: extern "win64" fn(usize, *const u8, usize) -> isize,
    /// Winsock2 TCP recv (`>= 0` bytes read or `-wsa_err`).
    pub net_tcp_recv: extern "win64" fn(usize, *mut u8, usize) -> isize,
    /// Winsock2 TCP nonblocking toggle (`0` = ok).
    pub net_tcp_set_nonblocking: extern "win64" fn(usize, u32) -> i32,
    /// Winsock2 TCP closesocket (`0` = ok).
    pub net_tcp_close: extern "win64" fn(usize) -> i32,
}
