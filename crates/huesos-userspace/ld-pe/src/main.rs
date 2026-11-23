//! HuesOS native Win64 PE32+ runtime loader and capability host bridge (`/lib/ld-pe.so`).
//!
//! Invoked by `libcanvas::process::launcher` when spawning a `.exe` (`MZ` / `PE\0\0`,
//! `Machine = 0x8664`). Maps the main `.exe` and its transitive PE32+ DLL graph
//! (`/lib/ntdll.dll`, `/lib/kernel32.dll`, plus `LoadLibrary*` modules) with strict
//! W^X `VMAR` permissions, initializes the process `PEB` and per-thread `TEB`
//! (`ThreadSetGsBase`), wires `PeHostApi` into `ntdll.dll`, runs PE TLS callbacks
//! and `DllMain(DLL_PROCESS_ATTACH)`, and transfers control to the `.exe` entry
//! point using the Microsoft x64 ABI (`extern "win64"`).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use huesos_abi::{vmar_flags, vmo_create_flags, ProcessAbi};
use huesos_pe::win64_abi::{
    teb_offsets, PeHostApi, Peb64, Win64ThreadStart, CREATE_ALWAYS, CREATE_NEW,
    DEFAULT_PROCESS_HEAP, DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH,
    DLL_THREAD_DETACH, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_MOD_NOT_FOUND, ERROR_NOT_ENOUGH_MEMORY,
    ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND, ERROR_PROC_NOT_FOUND, ERROR_SUCCESS, ERROR_TIMEOUT,
    FALSE, FILE_BEGIN, FILE_CURRENT, FILE_END, GENERIC_WRITE, HANDLE_STDERR, HANDLE_STDIN,
    HANDLE_STDOUT, HEAP_ZERO_MEMORY, INFINITE, INVALID_HANDLE_VALUE, MEM_DECOMMIT, MEM_RELEASE,
    NTDLL_BIND_HOST_SYMBOL, OPEN_ALWAYS, OPEN_EXISTING, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, PE_HOST_API_VERSION, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    TLS_MINIMUM_AVAILABLE, TLS_OUT_OF_INDEXES, TRUE, TRUNCATE_EXISTING, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use huesos_pe::{
    apply_base_relocations, eq_dll_name_ignore_ascii_case, parse_import_binding,
    parse_import_descriptor, parse_tls_directory, resolve_export_by_name,
    resolve_export_by_ordinal, write_iat_slot, DataDirectory, ExportTarget, ImportSymbol, PeImage,
    TlsDirectory64, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
};
use huesos_std::bootfs::BootFs;
use huesos_std::io::{Read, Seek, SeekFrom, Write};
use huesos_std::{bootfs, env, eprintln, fs, io, time};
use libcanvas::process::{Process, Thread, Vmar};
use libcanvas::stdio::{pe_image_span, take_cap_handle, CapKind};
use libcanvas::{futex, system, Vmo};
use spin::{Mutex, Once};

huesos_std::entry!(pe_loader_main);

const PAGE_SIZE: u64 = 4096;
const WIN64_ALLOC_GRANULARITY: u64 = 0x1_0000;
const DEFAULT_EXE_FALLBACK_BASE: u64 = 0x0000_0001_4000_0000;
const DLL_ARENA_BASE: u64 = 0x0000_0002_0000_0000;
const VIRTUAL_ALLOC_ARENA_BASE: u64 = 0x0000_0003_0000_0000;
const MAX_TLS_MODULES: usize = 32;
const HEAP_HEADER_BYTES: usize = 16;

type DllMainFn = unsafe extern "win64" fn(usize, u32, usize) -> i32;
type TlsCallbackFn = unsafe extern "win64" fn(usize, u32, usize);
type NtdllBindFn = unsafe extern "win64" fn(*const PeHostApi);
type ExeEntryFn = unsafe extern "win64" fn() -> u32;

struct SyncPebCell(UnsafeCell<Peb64>);
// SAFETY: `PEB_STORAGE` is initialized once before secondary threads start and
// subsequently read-only across Win64 threads via `gs:[0x60]`.
unsafe impl Sync for SyncPebCell {}

static PEB_STORAGE: SyncPebCell = SyncPebCell(UnsafeCell::new(Peb64 {
    reserved1: [0; 2],
    being_debugged: 0,
    reserved2: [0; 13],
    image_base_address: 0,
    ldr: 0,
    process_parameters: 0,
    sub_system_data: 0,
    process_heap: DEFAULT_PROCESS_HEAP as u64,
}));

struct LoadedPeModule {
    name: String,
    base: u64,
    entry_rva: u32,
    is_dll: bool,
    export_dir: DataDirectory,
    tls: Option<TlsDirectory64>,
    tls_slot_index: Option<usize>,
    ref_count: usize,
    dll_main_called: bool,
    image_copy: Vec<u8>,
    _backing_vmo: Vmo,
}

struct VirtualRegion {
    base: u64,
    len: u64,
    win_protect: u32,
    _vmo: Vmo,
}

enum OpenFileKind {
    Hxfs(fs::File),
    ReadOnlyBytes { data: Vec<u8>, cursor: usize },
}

struct ThreadObject {
    tid: u32,
    state: AtomicU32, // 0 = running, 1 = exited
    exit_code: AtomicU32,
}

struct EventObject {
    manual_reset: bool,
    signaled: AtomicU32,
}

enum WinHandleEntry {
    File(Mutex<OpenFileKind>),
    Thread(&'static ThreadObject),
    Event(&'static EventObject),
}

struct HandleTableSlot {
    id: usize,
    entry: WinHandleEntry,
}

struct RuntimeState {
    vmar: Once<Vmar>,
    bootfs: Once<Option<BootFs>>,
    modules: Mutex<Vec<LoadedPeModule>>,
    next_dll_addr: AtomicU64,
    next_valloc_addr: AtomicU64,
    valloc_regions: Mutex<Vec<VirtualRegion>>,
    handles: Mutex<Vec<HandleTableSlot>>,
    next_handle_id: AtomicU64,
    next_heap_id: AtomicU64,
    next_tid: AtomicU32,
    tls_module_count: AtomicU32,
    tls_bitmap: AtomicU64,
    cmd_line_a: Once<Vec<u8>>,
    cmd_line_w: Once<Vec<u16>>,
    env_block_w: Once<Vec<u16>>,
    tsc_freq_hz: Once<u64>,
}

static STATE: RuntimeState = RuntimeState {
    vmar: Once::new(),
    bootfs: Once::new(),
    modules: Mutex::new(Vec::new()),
    next_dll_addr: AtomicU64::new(DLL_ARENA_BASE),
    next_valloc_addr: AtomicU64::new(VIRTUAL_ALLOC_ARENA_BASE),
    valloc_regions: Mutex::new(Vec::new()),
    handles: Mutex::new(Vec::new()),
    next_handle_id: AtomicU64::new(0x100),
    next_heap_id: AtomicU64::new(0x10),
    next_tid: AtomicU32::new(1001),
    tls_module_count: AtomicU32::new(0),
    tls_bitmap: AtomicU64::new(0),
    cmd_line_a: Once::new(),
    cmd_line_w: Once::new(),
    env_block_w: Once::new(),
    tsc_freq_hz: Once::new(),
};

static PE_HOST_API: PeHostApi = PeHostApi {
    version: PE_HOST_API_VERSION,
    process_id: 1,
    virtual_alloc: host_virtual_alloc,
    virtual_free: host_virtual_free,
    virtual_protect: host_virtual_protect,
    heap_create: host_heap_create,
    heap_destroy: host_heap_destroy,
    heap_alloc: host_heap_alloc,
    heap_realloc: host_heap_realloc,
    heap_free: host_heap_free,
    heap_size: host_heap_size,
    get_std_handle: host_get_std_handle,
    create_file_utf8: host_create_file_utf8,
    read_file: host_read_file,
    write_file: host_write_file,
    set_file_pointer: host_set_file_pointer,
    get_file_size: host_get_file_size,
    delete_file_utf8: host_delete_file_utf8,
    create_dir_utf8: host_create_dir_utf8,
    close_handle: host_close_handle,
    futex_wait: host_futex_wait,
    futex_wake: host_futex_wake,
    create_event: host_create_event,
    set_event: host_set_event,
    reset_event: host_reset_event,
    create_thread: host_create_thread,
    wait_for_single_object: host_wait_for_single_object,
    wait_for_multiple_objects: host_wait_for_multiple_objects,
    get_exit_code_thread: host_get_exit_code_thread,
    tls_alloc: host_tls_alloc,
    tls_free: host_tls_free,
    exit_thread: host_exit_thread,
    exit_process: host_exit_process,
    load_library_utf8: host_load_library_utf8,
    get_module_handle_utf8: host_get_module_handle_utf8,
    get_proc_address: host_get_proc_address,
    free_library: host_free_library,
    get_command_line_a: host_get_command_line_a,
    get_command_line_w: host_get_command_line_w,
    get_env_strings_w: host_get_env_strings_w,
    query_perf_counter: host_query_perf_counter,
    query_perf_freq: host_query_perf_freq,
    get_tick_count64: host_get_tick_count64,
    sleep_ms: host_sleep_ms,
    get_num_cpus: host_get_num_cpus,
};

const fn align_up(val: u64, align: u64) -> u64 {
    let mask = align - 1;
    (val + mask) & !mask
}

const fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
}

fn boot_fs() -> Option<&'static BootFs> {
    STATE.bootfs.call_once(BootFs::from_capability).as_ref()
}

fn set_last_error(code: u32) {
    if let Ok(teb) = Thread::get_current_gs_base() {
        if teb != 0 {
            // SAFETY: `teb` was allocated by `alloc_thread_teb` with size `TEB_TOTAL_BYTES` (8 KiB).
            unsafe {
                ptr::write_volatile(
                    (teb as usize + teb_offsets::LAST_ERROR_VALUE) as *mut u32,
                    code,
                );
            }
        }
    }
}

struct ThreadTebAllocation {
    raw_ptr: *mut u8,
    layout: Layout,
    tls_blocks: Vec<(*mut u8, Layout)>,
    tls_array: Box<[usize; MAX_TLS_MODULES]>,
}

fn alloc_thread_teb(tid: u32, stack_hint_addr: usize) -> Result<ThreadTebAllocation, ()> {
    let layout = Layout::from_size_align(teb_offsets::TEB_TOTAL_BYTES, PAGE_SIZE as usize)
        .map_err(|_| ())?;
    // SAFETY: `layout` has non-zero size `0x2000` and power-of-two alignment `4096`.
    let raw_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if raw_ptr.is_null() {
        return Err(());
    }

    let mut tls_array = Box::new([0usize; MAX_TLS_MODULES]);
    let mut tls_blocks = Vec::new();
    {
        let modules = STATE.modules.lock();
        for m in modules.iter() {
            if let (Some(tls), Some(slot)) = (m.tls, m.tls_slot_index) {
                if slot >= MAX_TLS_MODULES {
                    continue;
                }
                let raw_len =
                    tls.end_address_of_raw_data
                        .saturating_sub(tls.start_address_of_raw_data) as usize;
                let total_len = raw_len
                    .saturating_add(tls.size_of_zero_fill as usize)
                    .max(16);
                if let Ok(blk_layout) = Layout::from_size_align(total_len, 16) {
                    // SAFETY: `blk_layout` has non-zero size and power-of-two alignment.
                    let blk_ptr = unsafe { alloc::alloc::alloc_zeroed(blk_layout) };
                    if !blk_ptr.is_null() {
                        if raw_len > 0 && tls.start_address_of_raw_data >= m.base {
                            let rva = (tls.start_address_of_raw_data - m.base) as usize;
                            if let Some(template) = m.image_copy.get(rva..rva + raw_len) {
                                // SAFETY: `blk_ptr` has `total_len >= raw_len` writable bytes.
                                unsafe {
                                    ptr::copy_nonoverlapping(template.as_ptr(), blk_ptr, raw_len);
                                }
                            }
                        }
                        tls_array[slot] = blk_ptr as usize;
                        tls_blocks.push((blk_ptr, blk_layout));
                    }
                }
            }
        }
    }

    let teb_va = raw_ptr as usize as u64;
    let stack_base = align_up(stack_hint_addr as u64, PAGE_SIZE);
    let stack_limit = stack_base.saturating_sub(64 * 1024);
    let peb_va = PEB_STORAGE.0.get() as usize as u64;
    let tls_array_va = tls_array.as_ptr() as usize as u64;

    // SAFETY: `raw_ptr` points to an 8 KiB zero-initialized buffer.
    unsafe {
        ptr::write(
            (raw_ptr.add(teb_offsets::EXCEPTION_LIST)) as *mut u64,
            u64::MAX,
        );
        ptr::write(
            (raw_ptr.add(teb_offsets::STACK_BASE)) as *mut u64,
            stack_base,
        );
        ptr::write(
            (raw_ptr.add(teb_offsets::STACK_LIMIT)) as *mut u64,
            stack_limit,
        );
        ptr::write((raw_ptr.add(teb_offsets::SELF_PTR)) as *mut u64, teb_va);
        ptr::write((raw_ptr.add(teb_offsets::PROCESS_ID)) as *mut u64, 1);
        ptr::write(
            (raw_ptr.add(teb_offsets::THREAD_ID)) as *mut u64,
            u64::from(tid),
        );
        ptr::write(
            (raw_ptr.add(teb_offsets::TLS_ARRAY_PTR)) as *mut u64,
            tls_array_va,
        );
        ptr::write((raw_ptr.add(teb_offsets::PEB_PTR)) as *mut u64, peb_va);
        ptr::write((raw_ptr.add(teb_offsets::LAST_ERROR_VALUE)) as *mut u32, 0);
    }

    if Thread::set_current_gs_base(teb_va).is_err() {
        free_thread_teb(ThreadTebAllocation {
            raw_ptr,
            layout,
            tls_blocks,
            tls_array,
        });
        return Err(());
    }

    Ok(ThreadTebAllocation {
        raw_ptr,
        layout,
        tls_blocks,
        tls_array,
    })
}

fn free_thread_teb(teb: ThreadTebAllocation) {
    let _ = Thread::set_current_gs_base(0);
    drop(teb.tls_array);
    for (ptr, layout) in teb.tls_blocks {
        // SAFETY: `ptr` was allocated with `layout` in `alloc_thread_teb`.
        unsafe { alloc::alloc::dealloc(ptr, layout) };
    }
    // SAFETY: `raw_ptr` was allocated with `layout` in `alloc_thread_teb`.
    unsafe { alloc::alloc::dealloc(teb.raw_ptr, teb.layout) };
}

fn normalize_win_path(raw_path: &str) -> String {
    let trimmed = raw_path.trim();
    let stripped = if let Some(rest) = trimmed.strip_prefix("\\\\?\\") {
        rest
    } else {
        trimmed
    };
    let after_drive = if stripped.len() >= 2 && stripped.as_bytes()[1] == b':' {
        &stripped[2..]
    } else {
        stripped
    };
    let mut out = String::with_capacity(after_drive.len() + 1);
    if !after_drive.starts_with('/') && !after_drive.starts_with('\\') {
        out.push('/');
    }
    for ch in after_drive.chars() {
        if ch == '\\' {
            if !out.ends_with('/') {
                out.push('/');
            }
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn read_dll_bytes(dll_name: &str) -> Option<(String, Vec<u8>)> {
    let base_leaf = dll_name.rsplit(['/', '\\']).next().unwrap_or(dll_name);
    let mut lower_leaf = String::with_capacity(base_leaf.len() + 4);
    for ch in base_leaf.chars() {
        lower_leaf.push(ch.to_ascii_lowercase());
    }
    if !lower_leaf.ends_with(".dll") && !lower_leaf.ends_with(".exe") {
        lower_leaf.push_str(".dll");
    }

    let mut candidates = Vec::with_capacity(3);
    if dll_name.contains('/') || dll_name.contains('\\') || dll_name.contains(':') {
        candidates.push(normalize_win_path(dll_name));
    }
    candidates.push(format!("/lib/{lower_leaf}"));
    candidates.push(format!("/bin/{lower_leaf}"));

    for path in &candidates {
        if let Ok(bytes) = fs::read(path) {
            return Some((lower_leaf, bytes));
        }
        if let Some(bfs) = boot_fs() {
            if let Ok(bytes) = bootfs::read_file(bfs, path) {
                return Some((lower_leaf, bytes));
            }
        }
    }
    None
}

fn win_protect_to_vmar_flags(protect: u32) -> Result<u32, u32> {
    match protect & 0xff {
        PAGE_NOACCESS => Ok(vmar_flags::USER | vmar_flags::SPECIFIC),
        PAGE_READONLY => Ok(vmar_flags::READ | vmar_flags::USER | vmar_flags::SPECIFIC),
        PAGE_READWRITE | PAGE_WRITECOPY => {
            Ok(vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC)
        }
        PAGE_EXECUTE | PAGE_EXECUTE_READ => {
            Ok(vmar_flags::READ | vmar_flags::EXECUTE | vmar_flags::USER | vmar_flags::SPECIFIC)
        }
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => Err(ERROR_INVALID_PARAMETER),
        _ => Err(ERROR_INVALID_PARAMETER),
    }
}

fn find_loaded_module_index(modules: &[LoadedPeModule], name: &str) -> Option<usize> {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mut normalized = String::with_capacity(leaf.len() + 4);
    for ch in leaf.chars() {
        normalized.push(ch.to_ascii_lowercase());
    }
    let normalized_with_ext = if !normalized.ends_with(".dll") && !normalized.ends_with(".exe") {
        format!("{normalized}.dll")
    } else {
        normalized.clone()
    };
    modules.iter().position(|m| {
        eq_dll_name_ignore_ascii_case(&m.name, &normalized)
            || eq_dll_name_ignore_ascii_case(&m.name, &normalized_with_ext)
    })
}

fn ensure_dll_loaded(dll_name: &str, depth: usize) -> Result<u64, &'static str> {
    if depth > 16 {
        return Err("DLL import recursion depth exceeded");
    }
    {
        let mut modules = STATE.modules.lock();
        if let Some(idx) = find_loaded_module_index(&modules, dll_name) {
            modules[idx].ref_count = modules[idx].ref_count.saturating_add(1);
            return Ok(modules[idx].base);
        }
    }

    let Some((canonical_name, raw_bytes)) = read_dll_bytes(dll_name) else {
        return Err("imported DLL not found in HxFS or BOOTFS");
    };
    load_pe_image(&canonical_name, &raw_bytes, true, depth + 1)
}

fn resolve_module_export(
    module_base: u64,
    symbol: ImportSymbol<'_>,
    depth: usize,
) -> Result<u64, &'static str> {
    if depth > 16 {
        return Err("export forwarder recursion depth exceeded");
    }
    enum Action {
        Found(u64),
        Forward(String),
    }
    let action = {
        let modules = STATE.modules.lock();
        let Some(m) = modules.iter().find(|m| m.base == module_base) else {
            return Err("target DLL module not loaded");
        };
        let target = match symbol {
            ImportSymbol::ByName { name, .. } => {
                resolve_export_by_name(&m.image_copy, m.export_dir, name)
            }
            ImportSymbol::ByOrdinal(ord) => {
                resolve_export_by_ordinal(&m.image_copy, m.export_dir, ord)
            }
        }
        .map_err(|_| "symbol missing from DLL export table")?;

        match target {
            ExportTarget::CodeOrDataRva(rva) => Action::Found(m.base.wrapping_add(u64::from(rva))),
            ExportTarget::Forwarded(spec) => Action::Forward(String::from(spec)),
        }
    };

    match action {
        Action::Found(va) => Ok(va),
        Action::Forward(spec) => {
            let Some((fwd_dll, fwd_sym)) = spec.split_once('.') else {
                return Err("malformed PE export forwarder");
            };
            let fwd_base = ensure_dll_loaded(fwd_dll, depth + 1)?;
            let sym = if let Some(ord_str) = fwd_sym.strip_prefix('#') {
                let ord = ord_str
                    .parse::<u16>()
                    .map_err(|_| "bad forwarded ordinal")?;
                ImportSymbol::ByOrdinal(ord)
            } else {
                ImportSymbol::ByName {
                    hint: 0,
                    name: fwd_sym,
                }
            };
            resolve_module_export(fwd_base, sym, depth + 1)
        }
    }
}

fn load_pe_image(
    name: &str,
    raw_bytes: &[u8],
    expect_dll: bool,
    depth: usize,
) -> Result<u64, &'static str> {
    let pe = PeImage::parse(raw_bytes).map_err(|_| "invalid or non-W^X PE32+ image")?;
    if expect_dll && !pe.is_dll() {
        return Err("expected PE32+ DLL characteristic");
    }
    let vmar = STATE.vmar.get().ok_or("missing PE self VMAR capability")?;
    let aligned_img_len = align_up(u64::from(pe.optional().size_of_image), PAGE_SIZE);
    let arena_span = align_up(aligned_img_len, WIN64_ALLOC_GRANULARITY);

    let preferred_base = pe.optional().image_base;
    let actual_base =
        if !pe.is_dll() && (0x0000_0000_0040_0000..DLL_ARENA_BASE).contains(&preferred_base) {
            preferred_base
        } else if !pe.is_dll() {
            DEFAULT_EXE_FALLBACK_BASE
        } else {
            STATE.next_dll_addr.fetch_add(arena_span, Ordering::SeqCst)
        };

    let mut staging = vec![0u8; aligned_img_len as usize];
    pe.materialize_into(&mut staging)
        .map_err(|_| "failed materializing PE32+ sections")?;

    let reloc_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    apply_base_relocations(&mut staging, reloc_dir, preferred_base, actual_base)
        .map_err(|_| "failed applying PE32+ DIR64 base relocations")?;

    // Resolve transitive DLL imports and patch IAT slots in `staging` before mapping read-only.
    let import_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if import_dir.is_present() {
        let mut pending_patches: Vec<(u32, u64)> = Vec::new();
        let mut desc_idx = 0usize;
        while let Some(desc) = parse_import_descriptor(&staging, import_dir, desc_idx)
            .map_err(|_| "malformed PE32+ import descriptor")?
        {
            let dll_name = String::from(desc.dll_name);
            let dep_base = ensure_dll_loaded(&dll_name, depth + 1)?;
            let mut thunk_idx = 0usize;
            while let Some(binding) = parse_import_binding(&staging, &desc, thunk_idx)
                .map_err(|_| "malformed PE32+ import thunk")?
            {
                let resolved_va = resolve_module_export(dep_base, binding.symbol, depth + 1)?;
                pending_patches.push((binding.iat_slot_rva, resolved_va));
                thunk_idx += 1;
            }
            desc_idx += 1;
        }
        for (slot_rva, resolved_va) in pending_patches {
            write_iat_slot(&mut staging, slot_rva, resolved_va)
                .map_err(|_| "failed writing PE32+ IAT slot")?;
        }
    }

    let tls = parse_tls_directory(&staging, pe.data_directory(IMAGE_DIRECTORY_ENTRY_TLS))
        .map_err(|_| "malformed PE32+ TLS directory")?;
    let tls_slot_index = if let Some(ref tls_dir) = tls {
        let slot = STATE.tls_module_count.fetch_add(1, Ordering::SeqCst) as usize;
        if slot < MAX_TLS_MODULES && tls_dir.address_of_index >= actual_base {
            let idx_rva = (tls_dir.address_of_index - actual_base) as usize;
            if let Some(dst) = staging.get_mut(idx_rva..idx_rva + 4) {
                dst.copy_from_slice(&(slot as u32).to_le_bytes());
            }
        }
        Some(slot)
    } else {
        None
    };

    let backing_vmo = Vmo::create_with_flags(aligned_img_len, vmo_create_flags::EXECUTABLE)
        .map_err(|_| "failed creating executable VMO for PE32+ image")?;
    backing_vmo
        .write(0, &staging)
        .map_err(|_| "failed writing materialized PE32+ image to VMO")?;

    let hdr_map_len = align_up(u64::from(pe.optional().size_of_headers), PAGE_SIZE);
    if hdr_map_len > 0 {
        vmar.map(
            &backing_vmo,
            0,
            actual_base,
            hdr_map_len,
            vmar_flags::READ | vmar_flags::USER | vmar_flags::SPECIFIC,
        )
        .map_err(|_| "failed mapping PE32+ headers into VMAR")?;
    }

    for sec in pe.sections() {
        let span = u64::from(sec.mapped_len());
        if span == 0 {
            continue;
        }
        let sec_start = align_down(u64::from(sec.virtual_address), PAGE_SIZE);
        let sec_end = align_up(u64::from(sec.virtual_address) + span, PAGE_SIZE);
        let sec_len = sec_end.saturating_sub(sec_start);
        if sec_len == 0 {
            continue;
        }
        let flags = if sec.is_executable() {
            vmar_flags::READ | vmar_flags::EXECUTE | vmar_flags::USER | vmar_flags::SPECIFIC
        } else if sec.is_writable() {
            vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC
        } else {
            vmar_flags::READ | vmar_flags::USER | vmar_flags::SPECIFIC
        };
        vmar.map(
            &backing_vmo,
            sec_start,
            actual_base + sec_start,
            sec_len,
            flags,
        )
        .map_err(|_| "failed mapping PE32+ section with W^X permissions")?;
    }

    let export_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
    let bind_rva = if pe.is_dll() && eq_dll_name_ignore_ascii_case(name, "ntdll.dll") {
        let sym_str = core::str::from_utf8(NTDLL_BIND_HOST_SYMBOL).unwrap_or("");
        match resolve_export_by_name(&staging, export_dir, sym_str) {
            Ok(ExportTarget::CodeOrDataRva(rva)) => Some(rva),
            _ => None,
        }
    } else {
        None
    };

    {
        let mut modules = STATE.modules.lock();
        modules.push(LoadedPeModule {
            name: String::from(name),
            base: actual_base,
            entry_rva: pe.optional().address_of_entry_point,
            is_dll: pe.is_dll(),
            export_dir,
            tls,
            tls_slot_index,
            ref_count: 1,
            dll_main_called: false,
            image_copy: staging,
            _backing_vmo: backing_vmo,
        });
    }

    if let Some(rva) = bind_rva {
        let fn_va = actual_base.wrapping_add(u64::from(rva));
        // SAFETY: `fn_va` is the mapped `extern "win64"` `__huesos_ntdll_bind_host` export in `ntdll.dll`.
        unsafe {
            let bind_fn: NtdllBindFn = core::mem::transmute(fn_va as usize);
            bind_fn(&PE_HOST_API as *const PeHostApi);
        }
    }

    Ok(actual_base)
}

fn run_tls_callbacks_for_module(base: u64, tls: TlsDirectory64, reason: u32) {
    if tls.address_of_callbacks == 0 {
        return;
    }
    let mut slot_va = tls.address_of_callbacks as usize;
    for _ in 0..32 {
        // SAFETY: `address_of_callbacks` points to a NUL-terminated array of `PIMAGE_TLS_CALLBACK` VAs in mapped `.rdata`.
        let cb_va = unsafe { ptr::read(slot_va as *const usize) };
        if cb_va == 0 {
            break;
        }
        // SAFETY: `cb_va` is a relocated PE32+ `PIMAGE_TLS_CALLBACK` (`extern "win64"`).
        unsafe {
            let cb: TlsCallbackFn = core::mem::transmute(cb_va);
            cb(base as usize, reason, 0);
        }
        slot_va += core::mem::size_of::<usize>();
    }
}

fn run_pending_process_initializers() -> Result<(), &'static str> {
    loop {
        let next = {
            let mut modules = STATE.modules.lock();
            modules.iter_mut().find(|m| !m.dll_main_called).map(|m| {
                m.dll_main_called = true;
                (m.base, m.is_dll, m.entry_rva, m.tls)
            })
        };
        let Some((base, is_dll, entry_rva, tls)) = next else {
            break;
        };
        if let Some(tls_dir) = tls {
            run_tls_callbacks_for_module(base, tls_dir, DLL_PROCESS_ATTACH);
        }
        if is_dll && entry_rva != 0 {
            let fn_va = base.wrapping_add(u64::from(entry_rva)) as usize;
            // SAFETY: `fn_va` is the relocated `DllMain` (`extern "win64"`) of this PE32+ DLL.
            let ok = unsafe {
                let dll_main: DllMainFn = core::mem::transmute(fn_va);
                dll_main(base as usize, DLL_PROCESS_ATTACH, 0)
            };
            if ok == FALSE {
                return Err("DllMain(DLL_PROCESS_ATTACH) returned FALSE");
            }
        }
    }
    Ok(())
}

fn notify_thread_lifecycle(reason: u32) {
    let snapshot: Vec<(u64, bool, u32, Option<TlsDirectory64>)> = {
        let modules = STATE.modules.lock();
        modules
            .iter()
            .filter(|m| m.dll_main_called)
            .map(|m| (m.base, m.is_dll, m.entry_rva, m.tls))
            .collect()
    };
    if reason == DLL_THREAD_ATTACH {
        for (base, is_dll, entry_rva, tls) in snapshot {
            if let Some(tls_dir) = tls {
                run_tls_callbacks_for_module(base, tls_dir, reason);
            }
            if is_dll && entry_rva != 0 {
                let fn_va = base.wrapping_add(u64::from(entry_rva)) as usize;
                // SAFETY: `fn_va` is a validated `DllMain` entry point.
                unsafe {
                    let dll_main: DllMainFn = core::mem::transmute(fn_va);
                    let _ = dll_main(base as usize, reason, 0);
                }
            }
        }
    } else {
        for (base, is_dll, entry_rva, tls) in snapshot.into_iter().rev() {
            if is_dll && entry_rva != 0 {
                let fn_va = base.wrapping_add(u64::from(entry_rva)) as usize;
                // SAFETY: `fn_va` is a validated `DllMain` entry point.
                unsafe {
                    let dll_main: DllMainFn = core::mem::transmute(fn_va);
                    let _ = dll_main(base as usize, reason, 0);
                }
            }
            if let Some(tls_dir) = tls {
                run_tls_callbacks_for_module(base, tls_dir, reason);
            }
        }
    }
}

fn pe_loader_main() -> i32 {
    let _ = Process::set_current_abi(ProcessAbi::Pe64);

    let Some(vmar_handle) = take_cap_handle(CapKind::PeSelfVmar) else {
        eprintln!("ld-pe: missing PeSelfVmar bootstrap capability");
        return 127;
    };
    STATE.vmar.call_once(|| Vmar::from_handle(vmar_handle));

    let Some(pe_vmo_handle) = take_cap_handle(CapKind::PeVmo) else {
        eprintln!("ld-pe: missing PeVmo bootstrap capability");
        return 127;
    };
    let pe_vmo = Vmo::from_handle(pe_vmo_handle);
    let (pe_offset, pe_len) = pe_image_span();
    if pe_len == 0 || pe_len > 64 * 1024 * 1024 {
        eprintln!("ld-pe: invalid PE image length ({pe_len})");
        return 127;
    }

    let mut exe_bytes = vec![0u8; pe_len as usize];
    let mut read_done = 0usize;
    while read_done < exe_bytes.len() {
        let step = (exe_bytes.len() - read_done).min(16 * 1024);
        match pe_vmo.read(
            pe_offset + read_done as u64,
            &mut exe_bytes[read_done..read_done + step],
        ) {
            Ok(n) if n > 0 => read_done += n,
            _ => {
                eprintln!("ld-pe: failed reading PE image from VMO");
                return 127;
            }
        }
    }
    drop(pe_vmo);

    // Ensure `ntdll.dll` and `kernel32.dll` are loaded first in canonical NT order.
    if let Err(msg) = ensure_dll_loaded("ntdll.dll", 0) {
        eprintln!("ld-pe: ntdll.dll load failed: {msg}");
        return 127;
    }
    let _ = ensure_dll_loaded("kernel32.dll", 0);

    let exe_name = env::argv()
        .first()
        .map(|s| String::from(s.rsplit(['/', '\\']).next().unwrap_or(s.as_str())))
        .unwrap_or_else(|| String::from("main.exe"));

    let exe_base = match load_pe_image(&exe_name, &exe_bytes, false, 0) {
        Ok(base) => base,
        Err(msg) => {
            eprintln!("ld-pe: failed loading {exe_name}: {msg}");
            return 127;
        }
    };
    drop(exe_bytes);

    // Populate PEB (`gs:[0x60]`) before allocating main thread's TEB.
    // SAFETY: single-threaded startup before any Win64 code runs.
    unsafe {
        (*PEB_STORAGE.0.get()).image_base_address = exe_base;
    }

    let stack_anchor = 0u64;
    let main_teb = match alloc_thread_teb(1000, &stack_anchor as *const u64 as usize) {
        Ok(teb) => teb,
        Err(()) => {
            eprintln!("ld-pe: failed initializing Win64 TEB / GS_BASE");
            return 127;
        }
    };

    if let Err(msg) = run_pending_process_initializers() {
        eprintln!("ld-pe: {msg}");
        free_thread_teb(main_teb);
        return 127;
    }

    let exe_entry_rva = {
        let modules = STATE.modules.lock();
        modules
            .iter()
            .find(|m| m.base == exe_base)
            .map(|m| m.entry_rva)
            .unwrap_or(0)
    };
    if exe_entry_rva == 0 {
        eprintln!("ld-pe: executable has zero AddressOfEntryPoint");
        free_thread_teb(main_teb);
        return 127;
    }

    let entry_va = exe_base.wrapping_add(u64::from(exe_entry_rva)) as usize;
    // SAFETY: `entry_va` is the mapped, relocated `extern "win64"` entry point of the `.exe`.
    let code = unsafe {
        let entry: ExeEntryFn = core::mem::transmute(entry_va);
        entry()
    };

    notify_thread_lifecycle(DLL_PROCESS_DETACH);
    free_thread_teb(main_teb);
    code as i32
}

// ============================================================================
// `extern "win64"` Host Bridge Implementation (`PE_HOST_API`)
// ============================================================================

extern "win64" fn host_virtual_alloc(
    addr: usize,
    size: usize,
    _alloc_type: u32,
    protect: u32,
) -> usize {
    if size == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let vmar_prot = match win_protect_to_vmar_flags(protect) {
        Ok(flags) => flags,
        Err(err) => {
            set_last_error(err);
            return 0;
        }
    };
    let Some(vmar) = STATE.vmar.get() else {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    };
    let aligned_len = align_up(size as u64, PAGE_SIZE);
    let arena_step = align_up(aligned_len, WIN64_ALLOC_GRANULARITY);
    let target_va = if addr != 0 {
        align_down(addr as u64, PAGE_SIZE)
    } else {
        STATE
            .next_valloc_addr
            .fetch_add(arena_step, Ordering::SeqCst)
    };

    let Ok(vmo) = Vmo::create_with_flags(aligned_len, vmo_create_flags::EXECUTABLE) else {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    if vmar
        .map(&vmo, 0, target_va, aligned_len, vmar_prot)
        .is_err()
    {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    STATE.valloc_regions.lock().push(VirtualRegion {
        base: target_va,
        len: aligned_len,
        win_protect: protect,
        _vmo: vmo,
    });
    target_va as usize
}

extern "win64" fn host_virtual_free(addr: usize, size: usize, free_type: u32) -> i32 {
    let Some(vmar) = STATE.vmar.get() else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    if free_type == MEM_RELEASE {
        if size != 0 {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        let mut regions = STATE.valloc_regions.lock();
        if let Some(pos) = regions.iter().position(|r| r.base == addr as u64) {
            let reg = regions.swap_remove(pos);
            let _ = vmar.unmap(reg.base, reg.len);
            return TRUE;
        }
        set_last_error(ERROR_INVALID_PARAMETER);
        FALSE
    } else if free_type == MEM_DECOMMIT && size > 0 {
        let base = align_down(addr as u64, PAGE_SIZE);
        let len = align_up(size as u64, PAGE_SIZE);
        match vmar.protect(base, len, vmar_flags::USER | vmar_flags::SPECIFIC) {
            Ok(_) => TRUE,
            Err(_) => {
                set_last_error(ERROR_INVALID_PARAMETER);
                FALSE
            }
        }
    } else {
        set_last_error(ERROR_INVALID_PARAMETER);
        FALSE
    }
}

extern "win64" fn host_virtual_protect(
    addr: usize,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    if size == 0 || old_protect.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let vmar_prot = match win_protect_to_vmar_flags(new_protect) {
        Ok(flags) => flags,
        Err(err) => {
            set_last_error(err);
            return FALSE;
        }
    };
    let Some(vmar) = STATE.vmar.get() else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let base = align_down(addr as u64, PAGE_SIZE);
    let end = align_up(addr as u64 + size as u64, PAGE_SIZE);
    let len = end.saturating_sub(base);
    if vmar.protect(base, len, vmar_prot).is_err() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let mut prev = PAGE_READWRITE;
    {
        let mut regions = STATE.valloc_regions.lock();
        if let Some(reg) = regions
            .iter_mut()
            .find(|r| base >= r.base && base < r.base + r.len)
        {
            prev = reg.win_protect;
            reg.win_protect = new_protect;
        }
    }
    // SAFETY: `old_protect` was checked non-null by caller contract.
    unsafe { ptr::write(old_protect, prev) };
    TRUE
}

extern "win64" fn host_heap_create(_options: u32, _init_size: usize, _max_size: usize) -> usize {
    STATE.next_heap_id.fetch_add(1, Ordering::Relaxed) as usize
}

extern "win64" fn host_heap_destroy(heap: usize) -> i32 {
    if heap == 0 || heap == DEFAULT_PROCESS_HEAP {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    TRUE
}

extern "win64" fn host_heap_alloc(heap: usize, flags: u32, bytes: usize) -> usize {
    if heap == 0 {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    let payload = bytes.max(1);
    let Some(total) = payload.checked_add(HEAP_HEADER_BYTES) else {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    let Ok(layout) = Layout::from_size_align(total, 16) else {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    // SAFETY: `layout` has non-zero size and alignment 16.
    let base = unsafe {
        if (flags & HEAP_ZERO_MEMORY) != 0 {
            alloc::alloc::alloc_zeroed(layout)
        } else {
            alloc::alloc::alloc(layout)
        }
    };
    if base.is_null() {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: `base` has at least `HEAP_HEADER_BYTES` writable bytes.
    unsafe {
        ptr::write(base as *mut usize, bytes);
        ptr::write((base as *mut usize).add(1), heap);
        base.add(HEAP_HEADER_BYTES) as usize
    }
}

extern "win64" fn host_heap_realloc(
    heap: usize,
    flags: u32,
    user_ptr: usize,
    bytes: usize,
) -> usize {
    if user_ptr == 0 {
        return host_heap_alloc(heap, flags, bytes);
    }
    let new_ptr = host_heap_alloc(heap, flags, bytes);
    if new_ptr == 0 {
        return 0;
    }
    let old_size = host_heap_size(heap, 0, user_ptr);
    if old_size != usize::MAX {
        let copy_len = old_size.min(bytes);
        if copy_len > 0 {
            // SAFETY: both `user_ptr` and `new_ptr` are valid heap allocations of at least `copy_len` bytes.
            unsafe {
                ptr::copy_nonoverlapping(user_ptr as *const u8, new_ptr as *mut u8, copy_len);
            }
        }
    }
    let _ = host_heap_free(heap, 0, user_ptr);
    new_ptr
}

extern "win64" fn host_heap_free(heap: usize, _flags: u32, user_ptr: usize) -> i32 {
    if user_ptr == 0 {
        return TRUE;
    }
    if heap == 0 || user_ptr < HEAP_HEADER_BYTES {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    // SAFETY: `user_ptr` was returned by `host_heap_alloc` with a 16-byte header.
    unsafe {
        let base = (user_ptr as *mut u8).sub(HEAP_HEADER_BYTES);
        let orig_bytes = ptr::read(base as *const usize);
        let payload = orig_bytes.max(1);
        if let Ok(layout) = Layout::from_size_align(payload + HEAP_HEADER_BYTES, 16) {
            alloc::alloc::dealloc(base, layout);
            return TRUE;
        }
    }
    set_last_error(ERROR_INVALID_PARAMETER);
    FALSE
}

extern "win64" fn host_heap_size(_heap: usize, _flags: u32, user_ptr: usize) -> usize {
    if user_ptr < HEAP_HEADER_BYTES {
        set_last_error(ERROR_INVALID_PARAMETER);
        return usize::MAX;
    }
    // SAFETY: `user_ptr` was returned by `host_heap_alloc`.
    unsafe { ptr::read((user_ptr - HEAP_HEADER_BYTES) as *const usize) }
}

extern "win64" fn host_get_std_handle(std_id: u32) -> usize {
    match std_id {
        STD_INPUT_HANDLE => HANDLE_STDIN,
        STD_OUTPUT_HANDLE => HANDLE_STDOUT,
        STD_ERROR_HANDLE => HANDLE_STDERR,
        _ => {
            set_last_error(ERROR_INVALID_HANDLE);
            INVALID_HANDLE_VALUE
        }
    }
}

fn register_handle(entry: WinHandleEntry) -> usize {
    let id = STATE.next_handle_id.fetch_add(1, Ordering::Relaxed) as usize;
    STATE.handles.lock().push(HandleTableSlot { id, entry });
    id
}

extern "win64" fn host_create_file_utf8(
    path_ptr: *const u8,
    path_len: usize,
    access: u32,
    disp: u32,
) -> usize {
    if path_ptr.is_null() || path_len == 0 || path_len > 1024 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    // SAFETY: `path_ptr..path_ptr + path_len` is caller-provided buffer.
    let raw_bytes = unsafe { slice::from_raw_parts(path_ptr, path_len) };
    let Ok(raw_str) = core::str::from_utf8(raw_bytes) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };
    let path = normalize_win_path(raw_str);
    let wants_write = (access & GENERIC_WRITE) != 0;

    let opened = match disp {
        CREATE_ALWAYS => fs::File::create(&path).map(OpenFileKind::Hxfs),
        CREATE_NEW => {
            if fs::exists(&path) {
                set_last_error(ERROR_ALREADY_EXISTS);
                return INVALID_HANDLE_VALUE;
            }
            fs::File::create(&path).map(OpenFileKind::Hxfs)
        }
        OPEN_ALWAYS => match fs::File::open(&path) {
            Ok(f) => {
                set_last_error(ERROR_ALREADY_EXISTS);
                Ok(OpenFileKind::Hxfs(f))
            }
            Err(_) => fs::File::create(&path).map(OpenFileKind::Hxfs),
        },
        TRUNCATE_EXISTING => {
            if !fs::exists(&path) {
                set_last_error(ERROR_FILE_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            fs::File::create(&path).map(OpenFileKind::Hxfs)
        }
        OPEN_EXISTING => match fs::File::open(&path) {
            Ok(f) => Ok(OpenFileKind::Hxfs(f)),
            Err(err) => {
                if !wants_write {
                    if let Some(bfs) = boot_fs() {
                        if let Ok(data) = bootfs::read_file(bfs, &path) {
                            return register_handle(WinHandleEntry::File(Mutex::new(
                                OpenFileKind::ReadOnlyBytes { data, cursor: 0 },
                            )));
                        }
                    }
                }
                Err(err)
            }
        },
        _ => {
            set_last_error(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }
    };

    match opened {
        Ok(kind) => register_handle(WinHandleEntry::File(Mutex::new(kind))),
        Err(err) => {
            let code = match err.kind() {
                huesos_std::ErrorKind::NotFound => ERROR_FILE_NOT_FOUND,
                huesos_std::ErrorKind::AccessDenied => ERROR_ACCESS_DENIED,
                _ => ERROR_PATH_NOT_FOUND,
            };
            set_last_error(code);
            INVALID_HANDLE_VALUE
        }
    }
}

extern "win64" fn host_read_file(handle: usize, buf: *mut u8, len: u32, out_read: *mut u32) -> i32 {
    if (len > 0 && buf.is_null()) || handle == INVALID_HANDLE_VALUE {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if !out_read.is_null() {
        // SAFETY: `out_read` checked non-null.
        unsafe { ptr::write(out_read, 0) };
    }
    if len == 0 {
        return TRUE;
    }
    // SAFETY: `buf` is non-null for `len` bytes.
    let dst = unsafe { slice::from_raw_parts_mut(buf, len as usize) };

    if handle == HANDLE_STDIN {
        match io::stdin().read(dst) {
            Ok(n) => {
                if !out_read.is_null() {
                    // SAFETY: `out_read` checked non-null.
                    unsafe { ptr::write(out_read, n as u32) };
                }
                return TRUE;
            }
            Err(_) => {
                set_last_error(ERROR_ACCESS_DENIED);
                return FALSE;
            }
        }
    }

    let handles = STATE.handles.lock();
    let Some(slot) = handles.iter().find(|s| s.id == handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let WinHandleEntry::File(file_mtx) = &slot.entry else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let mut guard = file_mtx.lock();
    let res = match &mut *guard {
        OpenFileKind::Hxfs(f) => f.read(dst),
        OpenFileKind::ReadOnlyBytes { data, cursor } => {
            let avail = data.len().saturating_sub(*cursor).min(dst.len());
            dst[..avail].copy_from_slice(&data[*cursor..*cursor + avail]);
            *cursor += avail;
            Ok(avail)
        }
    };
    match res {
        Ok(n) => {
            if !out_read.is_null() {
                // SAFETY: `out_read` checked non-null.
                unsafe { ptr::write(out_read, n as u32) };
            }
            TRUE
        }
        Err(_) => {
            set_last_error(ERROR_ACCESS_DENIED);
            FALSE
        }
    }
}

extern "win64" fn host_write_file(
    handle: usize,
    buf: *const u8,
    len: u32,
    out_written: *mut u32,
) -> i32 {
    if (len > 0 && buf.is_null()) || handle == INVALID_HANDLE_VALUE {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if !out_written.is_null() {
        // SAFETY: `out_written` checked non-null.
        unsafe { ptr::write(out_written, 0) };
    }
    if len == 0 {
        return TRUE;
    }
    // SAFETY: `buf` is non-null for `len` bytes.
    let src = unsafe { slice::from_raw_parts(buf, len as usize) };

    if handle == HANDLE_STDOUT {
        let mut out = io::stdout();
        let mut rem = src;
        while !rem.is_empty() {
            match out.write(rem) {
                Ok(0) | Err(_) => {
                    set_last_error(ERROR_ACCESS_DENIED);
                    return FALSE;
                }
                Ok(n) => rem = &rem[n..],
            }
        }
        let _ = out.flush();
        if !out_written.is_null() {
            // SAFETY: `out_written` checked non-null.
            unsafe { ptr::write(out_written, len) };
        }
        return TRUE;
    }
    if handle == HANDLE_STDERR {
        let mut err_out = io::stderr();
        let mut rem = src;
        while !rem.is_empty() {
            match err_out.write(rem) {
                Ok(0) | Err(_) => {
                    set_last_error(ERROR_ACCESS_DENIED);
                    return FALSE;
                }
                Ok(n) => rem = &rem[n..],
            }
        }
        let _ = err_out.flush();
        if !out_written.is_null() {
            // SAFETY: `out_written` checked non-null.
            unsafe { ptr::write(out_written, len) };
        }
        return TRUE;
    }

    let handles = STATE.handles.lock();
    let Some(slot) = handles.iter().find(|s| s.id == handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let WinHandleEntry::File(file_mtx) = &slot.entry else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let mut guard = file_mtx.lock();
    match &mut *guard {
        OpenFileKind::Hxfs(f) => {
            let mut rem = src;
            while !rem.is_empty() {
                match f.write(rem) {
                    Ok(0) | Err(_) => {
                        set_last_error(ERROR_ACCESS_DENIED);
                        return FALSE;
                    }
                    Ok(n) => rem = &rem[n..],
                }
            }
            let _ = f.flush();
            if !out_written.is_null() {
                // SAFETY: `out_written` checked non-null.
                unsafe { ptr::write(out_written, len) };
            }
            TRUE
        }
        OpenFileKind::ReadOnlyBytes { .. } => {
            set_last_error(ERROR_ACCESS_DENIED);
            FALSE
        }
    }
}

extern "win64" fn host_set_file_pointer(
    handle: usize,
    dist: i64,
    out_new: *mut i64,
    method: u32,
) -> i32 {
    let handles = STATE.handles.lock();
    let Some(slot) = handles.iter().find(|s| s.id == handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let WinHandleEntry::File(file_mtx) = &slot.entry else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let mut guard = file_mtx.lock();
    let seek_res = match &mut *guard {
        OpenFileKind::Hxfs(f) => {
            let sf = match method {
                FILE_BEGIN if dist >= 0 => SeekFrom::Start(dist as u64),
                FILE_CURRENT => SeekFrom::Current(dist),
                FILE_END => SeekFrom::End(dist),
                _ => {
                    set_last_error(ERROR_INVALID_PARAMETER);
                    return FALSE;
                }
            };
            f.seek(sf)
        }
        OpenFileKind::ReadOnlyBytes { data, cursor } => {
            let base = match method {
                FILE_BEGIN => 0i64,
                FILE_CURRENT => *cursor as i64,
                FILE_END => data.len() as i64,
                _ => {
                    set_last_error(ERROR_INVALID_PARAMETER);
                    return FALSE;
                }
            };
            match base.checked_add(dist) {
                Some(pos) if pos >= 0 => {
                    *cursor = pos as usize;
                    Ok(pos as u64)
                }
                _ => {
                    set_last_error(ERROR_INVALID_PARAMETER);
                    return FALSE;
                }
            }
        }
    };
    match seek_res {
        Ok(pos) => {
            if !out_new.is_null() {
                // SAFETY: `out_new` checked non-null.
                unsafe { ptr::write(out_new, pos as i64) };
            }
            TRUE
        }
        Err(_) => {
            set_last_error(ERROR_INVALID_PARAMETER);
            FALSE
        }
    }
}

extern "win64" fn host_get_file_size(handle: usize, out_size: *mut i64) -> i32 {
    if out_size.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let handles = STATE.handles.lock();
    let Some(slot) = handles.iter().find(|s| s.id == handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let WinHandleEntry::File(file_mtx) = &slot.entry else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let guard = file_mtx.lock();
    let size = match &*guard {
        OpenFileKind::Hxfs(f) => match f.size() {
            Ok(sz) => sz,
            Err(_) => {
                set_last_error(ERROR_ACCESS_DENIED);
                return FALSE;
            }
        },
        OpenFileKind::ReadOnlyBytes { data, .. } => data.len() as u64,
    };
    // SAFETY: `out_size` checked non-null.
    unsafe { ptr::write(out_size, size as i64) };
    TRUE
}

extern "win64" fn host_delete_file_utf8(path_ptr: *const u8, path_len: usize) -> i32 {
    if path_ptr.is_null() || path_len == 0 || path_len > 1024 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: `path_ptr` is valid for `path_len` bytes.
    let Ok(raw) = core::str::from_utf8(unsafe { slice::from_raw_parts(path_ptr, path_len) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    };
    match fs::remove(&normalize_win_path(raw)) {
        Ok(()) => TRUE,
        Err(_) => {
            set_last_error(ERROR_FILE_NOT_FOUND);
            FALSE
        }
    }
}

extern "win64" fn host_create_dir_utf8(path_ptr: *const u8, path_len: usize) -> i32 {
    if path_ptr.is_null() || path_len == 0 || path_len > 1024 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    // SAFETY: `path_ptr` is valid for `path_len` bytes.
    let Ok(raw) = core::str::from_utf8(unsafe { slice::from_raw_parts(path_ptr, path_len) }) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    };
    match fs::create_dir(&normalize_win_path(raw)) {
        Ok(_) => TRUE,
        Err(_) => {
            set_last_error(ERROR_ALREADY_EXISTS);
            FALSE
        }
    }
}

extern "win64" fn host_close_handle(handle: usize) -> i32 {
    if matches!(handle, HANDLE_STDIN | HANDLE_STDOUT | HANDLE_STDERR) {
        return TRUE;
    }
    let mut handles = STATE.handles.lock();
    if let Some(pos) = handles.iter().position(|s| s.id == handle) {
        let _ = handles.swap_remove(pos);
        TRUE
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        FALSE
    }
}

fn timeout_ms_to_ticks(timeout_ms: u32) -> Option<u64> {
    if timeout_ms == 0 {
        return None;
    }
    if timeout_ms == INFINITE {
        return Some(0);
    }
    // 100 Hz scheduler ticks = 10 ms/tick, rounded up.
    Some(u64::from(timeout_ms).div_ceil(10).max(1))
}

extern "win64" fn host_futex_wait(addr: *const u32, expected: u32, timeout_ms: u32) -> u32 {
    if addr.is_null() || (addr as usize & 0x3) != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: `addr` is non-null and 4-byte aligned in userspace memory.
    let word = unsafe { &*(addr as *const AtomicU32) };
    if timeout_ms == 0 {
        return if word.load(Ordering::SeqCst) == expected {
            set_last_error(ERROR_TIMEOUT);
            ERROR_TIMEOUT
        } else {
            ERROR_SUCCESS
        };
    }
    let ticks = timeout_ms_to_ticks(timeout_ms).unwrap_or(0);
    match futex::wait(word, expected, ticks) {
        Ok(()) => ERROR_SUCCESS,
        Err(libcanvas::ErrorCode::TimedOut) => {
            set_last_error(ERROR_TIMEOUT);
            ERROR_TIMEOUT
        }
        Err(_) => {
            set_last_error(ERROR_INVALID_PARAMETER);
            ERROR_INVALID_PARAMETER
        }
    }
}

extern "win64" fn host_futex_wake(addr: *const u32, count: u32) -> u32 {
    if addr.is_null() || (addr as usize & 0x3) != 0 {
        return 0;
    }
    // SAFETY: `addr` is non-null and 4-byte aligned.
    let word = unsafe { &*(addr as *const AtomicU32) };
    futex::wake(word, count).unwrap_or(0) as u32
}

extern "win64" fn host_create_event(manual_reset: i32, initial_state: i32) -> usize {
    let ev: &'static EventObject = Box::leak(Box::new(EventObject {
        manual_reset: manual_reset != 0,
        signaled: AtomicU32::new(u32::from(initial_state != 0)),
    }));
    register_handle(WinHandleEntry::Event(ev))
}

extern "win64" fn host_set_event(handle: usize) -> i32 {
    let ev = {
        let handles = STATE.handles.lock();
        match handles.iter().find(|s| s.id == handle).map(|s| &s.entry) {
            Some(WinHandleEntry::Event(ev)) => *ev,
            _ => {
                set_last_error(ERROR_INVALID_HANDLE);
                return FALSE;
            }
        }
    };
    ev.signaled.store(1, Ordering::Release);
    let wake_cnt = if ev.manual_reset { u32::MAX } else { 1 };
    let _ = futex::wake(&ev.signaled, wake_cnt);
    TRUE
}

extern "win64" fn host_reset_event(handle: usize) -> i32 {
    let ev = {
        let handles = STATE.handles.lock();
        match handles.iter().find(|s| s.id == handle).map(|s| &s.entry) {
            Some(WinHandleEntry::Event(ev)) => *ev,
            _ => {
                set_last_error(ERROR_INVALID_HANDLE);
                return FALSE;
            }
        }
    };
    ev.signaled.store(0, Ordering::Release);
    TRUE
}

struct SpawnedWinThreadCtx {
    start: Win64ThreadStart,
    param: usize,
    obj: &'static ThreadObject,
}

extern "C" fn win64_thread_trampoline(raw_ctx: *mut c_void) -> i64 {
    // SAFETY: `raw_ctx` was allocated via `Box::into_raw` in `host_create_thread`.
    let ctx = unsafe { Box::from_raw(raw_ctx as *mut SpawnedWinThreadCtx) };
    let stack_anchor = 0u64;
    let Ok(teb) = alloc_thread_teb(ctx.obj.tid, &stack_anchor as *const u64 as usize) else {
        ctx.obj.exit_code.store(u32::MAX, Ordering::Release);
        ctx.obj.state.store(1, Ordering::Release);
        let _ = futex::wake(&ctx.obj.state, u32::MAX);
        return -1;
    };

    notify_thread_lifecycle(DLL_THREAD_ATTACH);
    let code = (ctx.start)(ctx.param);
    notify_thread_lifecycle(DLL_THREAD_DETACH);

    free_thread_teb(teb);
    ctx.obj.exit_code.store(code, Ordering::Release);
    ctx.obj.state.store(1, Ordering::Release);
    let _ = futex::wake(&ctx.obj.state, u32::MAX);
    i64::from(code)
}

extern "win64" fn host_create_thread(
    stack_size: usize,
    start: Win64ThreadStart,
    param: usize,
    _flags: u32,
    out_tid: *mut u32,
) -> usize {
    let tid = STATE.next_tid.fetch_add(1, Ordering::Relaxed);
    let obj: &'static ThreadObject = Box::leak(Box::new(ThreadObject {
        tid,
        state: AtomicU32::new(0),
        exit_code: AtomicU32::new(259), // STILL_ACTIVE
    }));
    let ctx = Box::new(SpawnedWinThreadCtx { start, param, obj });
    let raw_ctx = Box::into_raw(ctx) as *mut c_void;
    let effective_stack = if stack_size == 0 {
        128 * 1024
    } else {
        stack_size.max(64 * 1024)
    };

    // SAFETY: `raw_ctx` remains valid until `win64_thread_trampoline` reclaims it.
    let spawn_res = unsafe {
        libcanvas::thread::spawn(
            "win64-worker",
            win64_thread_trampoline,
            raw_ctx,
            effective_stack,
        )
    };
    match spawn_res {
        Ok(join_handle) => {
            // Detach `JoinHandle` so `WaitForSingleObject` / `CloseHandle` control Win32 lifetime
            // without blocking inside `Drop`.
            core::mem::forget(join_handle);
            if !out_tid.is_null() {
                // SAFETY: `out_tid` checked non-null.
                unsafe { ptr::write(out_tid, tid) };
            }
            register_handle(WinHandleEntry::Thread(obj))
        }
        Err(_) => {
            // SAFETY: thread failed to start, reclaim `raw_ctx`.
            unsafe { drop(Box::from_raw(raw_ctx as *mut SpawnedWinThreadCtx)) };
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            0
        }
    }
}

enum WaitableRef {
    Thread(&'static ThreadObject),
    Event(&'static EventObject),
}

fn lookup_waitable(handle: usize) -> Option<WaitableRef> {
    let handles = STATE.handles.lock();
    match handles.iter().find(|s| s.id == handle)?.entry {
        WinHandleEntry::Thread(t) => Some(WaitableRef::Thread(t)),
        WinHandleEntry::Event(e) => Some(WaitableRef::Event(e)),
        WinHandleEntry::File(_) => None,
    }
}

fn try_acquire_waitable(w: &WaitableRef) -> bool {
    match w {
        WaitableRef::Thread(t) => t.state.load(Ordering::Acquire) != 0,
        WaitableRef::Event(e) => {
            if e.manual_reset {
                e.signaled.load(Ordering::Acquire) != 0
            } else {
                e.signaled
                    .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            }
        }
    }
}

extern "win64" fn host_wait_for_single_object(handle: usize, timeout_ms: u32) -> u32 {
    let Some(w) = lookup_waitable(handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return WAIT_FAILED;
    };
    let start_ticks = system::monotonic_ticks().unwrap_or(0);
    let budget_ticks = timeout_ms_to_ticks(timeout_ms);

    loop {
        if try_acquire_waitable(&w) {
            return WAIT_OBJECT_0;
        }
        if timeout_ms == 0 {
            return WAIT_TIMEOUT;
        }
        let wait_ticks = match budget_ticks {
            Some(0) => 0,
            Some(total) => {
                let elapsed = system::monotonic_ticks()
                    .unwrap_or(start_ticks)
                    .saturating_sub(start_ticks);
                if elapsed >= total {
                    return WAIT_TIMEOUT;
                }
                total - elapsed
            }
            None => return WAIT_TIMEOUT,
        };
        let atom = match &w {
            WaitableRef::Thread(t) => &t.state,
            WaitableRef::Event(e) => &e.signaled,
        };
        if let Err(libcanvas::ErrorCode::TimedOut) = futex::wait(atom, 0, wait_ticks) {
            if try_acquire_waitable(&w) {
                return WAIT_OBJECT_0;
            }
            return WAIT_TIMEOUT;
        }
    }
}

extern "win64" fn host_wait_for_multiple_objects(
    count: u32,
    handles_ptr: *const usize,
    wait_all: i32,
    timeout_ms: u32,
) -> u32 {
    if count == 0 || count > 64 || handles_ptr.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return WAIT_FAILED;
    }
    // SAFETY: `handles_ptr` is non-null for `count` `usize` handles.
    let raw_handles = unsafe { slice::from_raw_parts(handles_ptr, count as usize) };
    let mut waitables = Vec::with_capacity(count as usize);
    for &h in raw_handles {
        let Some(w) = lookup_waitable(h) else {
            set_last_error(ERROR_INVALID_HANDLE);
            return WAIT_FAILED;
        };
        waitables.push(w);
    }

    if wait_all != 0 {
        for &h in raw_handles {
            let rc = host_wait_for_single_object(h, timeout_ms);
            if rc != WAIT_OBJECT_0 {
                return rc;
            }
        }
        WAIT_OBJECT_0
    } else {
        let start_ticks = system::monotonic_ticks().unwrap_or(0);
        let budget_ticks = timeout_ms_to_ticks(timeout_ms);
        loop {
            for (idx, w) in waitables.iter().enumerate() {
                if try_acquire_waitable(w) {
                    return WAIT_OBJECT_0 + idx as u32;
                }
            }
            if timeout_ms == 0 {
                return WAIT_TIMEOUT;
            }
            if let Some(total) = budget_ticks {
                if total != 0 {
                    let elapsed = system::monotonic_ticks()
                        .unwrap_or(start_ticks)
                        .saturating_sub(start_ticks);
                    if elapsed >= total {
                        return WAIT_TIMEOUT;
                    }
                }
            }
            let first_atom = match &waitables[0] {
                WaitableRef::Thread(t) => &t.state,
                WaitableRef::Event(e) => &e.signaled,
            };
            let _ = futex::wait(first_atom, 0, 1);
        }
    }
}

extern "win64" fn host_get_exit_code_thread(handle: usize, out_code: *mut u32) -> i32 {
    if out_code.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let Some(WaitableRef::Thread(t)) = lookup_waitable(handle) else {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    };
    let code = if t.state.load(Ordering::Acquire) == 0 {
        259 // STILL_ACTIVE
    } else {
        t.exit_code.load(Ordering::Acquire)
    };
    // SAFETY: `out_code` checked non-null.
    unsafe { ptr::write(out_code, code) };
    TRUE
}

extern "win64" fn host_tls_alloc() -> u32 {
    loop {
        let cur = STATE.tls_bitmap.load(Ordering::Relaxed);
        if cur == u64::MAX {
            set_last_error(ERROR_NO_MORE_ITEMS);
            return TLS_OUT_OF_INDEXES;
        }
        let slot = (!cur).trailing_zeros();
        if slot >= TLS_MINIMUM_AVAILABLE as u32 {
            set_last_error(ERROR_NO_MORE_ITEMS);
            return TLS_OUT_OF_INDEXES;
        }
        let next = cur | (1u64 << slot);
        if STATE
            .tls_bitmap
            .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return slot;
        }
    }
}

extern "win64" fn host_tls_free(index: u32) -> i32 {
    if index as usize >= TLS_MINIMUM_AVAILABLE {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    let bit = 1u64 << index;
    let prev = STATE.tls_bitmap.fetch_and(!bit, Ordering::AcqRel);
    if (prev & bit) == 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    TRUE
}

extern "win64" fn host_exit_thread(code: u32) -> ! {
    notify_thread_lifecycle(DLL_THREAD_DETACH);
    let _ = Thread::set_current_gs_base(0);
    libcanvas::thread::exit(i64::from(code))
}

extern "win64" fn host_exit_process(code: u32) -> ! {
    notify_thread_lifecycle(DLL_PROCESS_DETACH);
    huesos_std::process::exit(code as i32)
}

extern "win64" fn host_load_library_utf8(name_ptr: *const u8, name_len: usize) -> usize {
    if name_ptr.is_null() || name_len == 0 || name_len > 512 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: `name_ptr` is valid for `name_len` bytes.
    let Ok(name) = core::str::from_utf8(unsafe { slice::from_raw_parts(name_ptr, name_len) })
    else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Ok(base) = ensure_dll_loaded(name, 0) else {
        set_last_error(ERROR_MOD_NOT_FOUND);
        return 0;
    };
    if run_pending_process_initializers().is_err() {
        set_last_error(ERROR_MOD_NOT_FOUND);
        return 0;
    }
    base as usize
}

extern "win64" fn host_get_module_handle_utf8(name_ptr: *const u8, name_len: usize) -> usize {
    if name_ptr.is_null() || name_len == 0 {
        // SAFETY: `PEB_STORAGE` initialized before Win64 execution.
        return unsafe { (*PEB_STORAGE.0.get()).image_base_address as usize };
    }
    // SAFETY: `name_ptr` is valid for `name_len` bytes.
    let Ok(name) = core::str::from_utf8(unsafe { slice::from_raw_parts(name_ptr, name_len) })
    else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let modules = STATE.modules.lock();
    match find_loaded_module_index(&modules, name) {
        Some(idx) => modules[idx].base as usize,
        None => {
            set_last_error(ERROR_MOD_NOT_FOUND);
            0
        }
    }
}

extern "win64" fn host_get_proc_address(
    module: usize,
    name_ptr: *const u8,
    name_len: usize,
    ordinal: u32,
) -> usize {
    if module == 0 {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    let sym = if ordinal != 0 {
        let Ok(ord16) = u16::try_from(ordinal) else {
            set_last_error(ERROR_PROC_NOT_FOUND);
            return 0;
        };
        ImportSymbol::ByOrdinal(ord16)
    } else {
        if name_ptr.is_null() || name_len == 0 || name_len > 512 {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        // SAFETY: `name_ptr` is valid for `name_len` bytes.
        let Ok(sym_name) =
            core::str::from_utf8(unsafe { slice::from_raw_parts(name_ptr, name_len) })
        else {
            set_last_error(ERROR_PROC_NOT_FOUND);
            return 0;
        };
        ImportSymbol::ByName {
            hint: 0,
            name: sym_name,
        }
    };
    match resolve_module_export(module as u64, sym, 0) {
        Ok(va) => va as usize,
        Err(_) => {
            set_last_error(ERROR_PROC_NOT_FOUND);
            0
        }
    }
}

extern "win64" fn host_free_library(module: usize) -> i32 {
    let mut modules = STATE.modules.lock();
    if let Some(m) = modules.iter_mut().find(|m| m.base == module as u64) {
        if m.ref_count > 1 {
            m.ref_count -= 1;
        }
        TRUE
    } else {
        set_last_error(ERROR_INVALID_HANDLE);
        FALSE
    }
}

fn build_cmdline_string() -> String {
    let mut out = String::new();
    for (idx, arg) in env::argv().into_iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        if arg.contains(' ') {
            out.push('"');
            out.push_str(&arg);
            out.push('"');
        } else {
            out.push_str(&arg);
        }
    }
    if out.is_empty() {
        out.push_str("app.exe");
    }
    out
}

extern "win64" fn host_get_command_line_a() -> *const u8 {
    STATE
        .cmd_line_a
        .call_once(|| {
            let mut v = build_cmdline_string().into_bytes();
            v.push(0);
            v
        })
        .as_ptr()
}

extern "win64" fn host_get_command_line_w() -> *const u16 {
    STATE
        .cmd_line_w
        .call_once(|| {
            let mut v: Vec<u16> = build_cmdline_string().encode_utf16().collect();
            v.push(0);
            v
        })
        .as_ptr()
}

extern "win64" fn host_get_env_strings_w() -> *const u16 {
    STATE
        .env_block_w
        .call_once(|| {
            let entries = [
                "OS=HuesOS_PE64",
                "PATH=/bin;/lib",
                "SYSTEMROOT=/",
                "TEMP=/tmp",
            ];
            let mut block = Vec::new();
            for entry in entries {
                block.extend(entry.encode_utf16());
                block.push(0);
            }
            block.push(0);
            block
        })
        .as_ptr()
}

fn calibrate_tsc_hz() -> u64 {
    let t0 = system::monotonic_ticks().unwrap_or(0);
    // Spin until tick edge, then measure 1 tick (10 ms) of TSC delta.
    let mut spin_guard = 0u32;
    let mut edge_start = t0;
    while edge_start == t0 && spin_guard < 5_000_000 {
        edge_start = system::monotonic_ticks().unwrap_or(t0);
        spin_guard += 1;
        core::hint::spin_loop();
    }
    if edge_start == t0 {
        return 2_000_000_000;
    }
    // SAFETY: `_rdtsc` is an unprivileged x86_64 instruction.
    let c0 = unsafe { core::arch::x86_64::_rdtsc() };
    let mut edge_end = edge_start;
    let mut spin_guard2 = 0u32;
    while edge_end == edge_start && spin_guard2 < 20_000_000 {
        edge_end = system::monotonic_ticks().unwrap_or(edge_start);
        spin_guard2 += 1;
        core::hint::spin_loop();
    }
    // SAFETY: `_rdtsc` is an unprivileged x86_64 instruction.
    let c1 = unsafe { core::arch::x86_64::_rdtsc() };
    let dt = edge_end.saturating_sub(edge_start);
    if dt == 0 || c1 <= c0 {
        2_000_000_000
    } else {
        ((c1 - c0) * time::TICKS_PER_SEC / dt).max(1_000_000)
    }
}

extern "win64" fn host_query_perf_counter() -> u64 {
    // SAFETY: `_rdtsc` is an unprivileged x86_64 cycle counter read.
    unsafe { core::arch::x86_64::_rdtsc() }
}

extern "win64" fn host_query_perf_freq() -> u64 {
    *STATE.tsc_freq_hz.call_once(calibrate_tsc_hz)
}

extern "win64" fn host_get_tick_count64() -> u64 {
    system::monotonic_ticks().unwrap_or(0).saturating_mul(10)
}

extern "win64" fn host_sleep_ms(ms: u32) {
    if ms == 0 {
        huesos_std::process::yield_now();
    } else {
        huesos_std::thread::sleep(time::Duration::from_millis(u64::from(ms)));
    }
}

extern "win64" fn host_get_num_cpus() -> u32 {
    system::cpu_count().unwrap_or(1).max(1) as u32
}
