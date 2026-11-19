//! HuesOS userspace ELF64 dynamic linker (`/lib/ld-huesos.so`).
//!
//! Invoked by the userspace process launcher when a binary carries `PT_INTERP`.
//! Implements a strictly non-POSIX, capability-first dynamic linking architecture:
//! - Eager `BIND_NOW` + Full `PT_GNU_RELRO` (`VmarProtect(READ)`).
//! - Multi-threaded Variant-II TLS + General-Dynamic TLS (`__tls_get_addr` / DTV).
//! - Capability-first runtime loading (`canvas_dlopen_vmo`, `canvas_dlopen_soname`,
//!   `canvas_dlopen_blob`, `canvas_dlsym`, `canvas_dlclose`, `canvas_dlerror`,
//!   `canvas_dladdr`, `canvas_dl_iterate_phdr`) up to `MAX_OBJECTS = 64` with
//!   module-graph refcounting and fail-closed `SONAME` validation.
//! - `HxFS v7` (`DirectoryHandle` / `BlobView`) library provider via `auxv`
//!   (`AT_HUESOS_HXFS_DIR`) with transparent fallback to `BOOTFS` (`AT_HUESOS_LIB_VMO`).
//! - `__cxa_atexit` + reverse-topological `DT_FINI_ARRAY` / `DT_FINI`.
//! - Strict GNU ELF symbol versioning (`DT_VERSYM` / `DT_VERDEF` / `DT_VERNEED`).

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};
use core::panic::PanicInfo;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use huesos_abi::auxv::{
    caps_mask, AuxEntry, AT_BASE, AT_ENTRY, AT_HUESOS_BLOCK_DEV, AT_HUESOS_CAPS_MASK,
    AT_HUESOS_FRAME_DRAW, AT_HUESOS_HXFS_DIR, AT_HUESOS_HXFS_SERVICE, AT_HUESOS_LD_BOOTSTRAP,
    AT_HUESOS_LIB_VMO, AT_HUESOS_STDERR, AT_HUESOS_STDIN, AT_HUESOS_STDOUT, AT_NULL, AT_PHDR,
    AT_PHENT, AT_PHNUM, LD_BOOTSTRAP_BLOCK_DEV_LABEL, LD_BOOTSTRAP_FRAME_DRAW_LABEL,
    LD_BOOTSTRAP_HXFS_DIR_LABEL, LD_BOOTSTRAP_HXFS_SERVICE_LABEL, LD_BOOTSTRAP_LIB_VMO_LABEL,
    LD_BOOTSTRAP_SELF_VMAR_LABEL, LD_BOOTSTRAP_STDERR_LABEL, LD_BOOTSTRAP_STDIN_LABEL,
    LD_BOOTSTRAP_STDOUT_LABEL,
};
use huesos_abi::{
    rights, vmar_flags, vmo_create_flags, HandleValue, USER_HEAP_BASE, USER_HEAP_SIZE,
};
use huesos_elf::dynamic::{
    cstr_at, dt, find_verneed_by_ndx, gnu_hash_lookup, r_x86_64, read_phdr64,
    symbol_version_matches, sysv_hash_lookup, validate_soname, validate_verneed_table, Dyn64,
    DynamicSummary, Phdr64, Rela64, Sym64, TlsSegment, EM_X86_64, ET_DYN, MAX_DT_NEEDED, PF_R,
    PF_W, PF_X, PT_DYNAMIC, PT_GNU_RELRO, PT_LOAD, PT_PHDR, PT_TLS, STB_LOCAL, STB_WEAK,
    VERSYM_VERSION_MASK,
};
use libcanvas::hxfs::HxfsBlobView;
use libcanvas::process::Vmar;
use libcanvas::rtld_abi::{
    CanvasDlInfo, CanvasDlPhdrInfo, HostAllocOps, ProcessBootstrapInfo, RtldOps, RTLD_GLOBAL,
    RTLD_NODELETE, RTLD_NOLOAD, RTLD_OPS_VERSION,
};
use libcanvas::{
    debug, memory, process, Channel, Handle, Hxfs, HxfsDirectory, Vmo, INVALID_HANDLE,
};

const PAGE_SIZE: u64 = 4096;
const MAX_OBJECTS: usize = 64;
const MAX_NAME_LEN: usize = 96;
const MAX_LOAD_SEGS: usize = 8;
const MAX_ATEXIT: usize = 128;
const HEADER_BUF_LEN: usize = 16 * 1024;
const DSO_ASLR_BASE: u64 = 0x0000_0002_0000_0000;
const DSO_ASLR_MASK: u64 = 0x000f_ffff;
const TLS_ASLR_BASE: u64 = 0x0000_0003_8000_0000;
const TLS_ASLR_MASK: u64 = 0x0003_ffff;
const TCB_MAGIC: u64 = 0x4855_4553_544c_5332;
const DLERROR_CAP: usize = 159;

const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";

/// ELF64 header raw offsets used during early self-relocation.
const EHDR_PHOFF_OFF: usize = 32;
const EHDR_PHENTSIZE_OFF: usize = 54;
const EHDR_PHNUM_OFF: usize = 56;
const PHDR_TYPE_OFF: usize = 0;
const PHDR_VADDR_OFF: usize = 16;
const PHDR_MEMSZ_OFF: usize = 40;

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rsp",
        "call {entry}",
        "xor rdx, rdx",
        "jmp rax",
        entry = sym ld_entry,
    );
}

#[panic_handler]
fn ld_panic(_info: &PanicInfo<'_>) -> ! {
    debug::write_str("[ld-huesos] PANIC\n");
    process::exit(-10);
}

struct RtldLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

impl<T> RtldLock<T> {
    const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    #[inline]
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        struct Unlock<'a>(&'a AtomicBool);
        impl Drop for Unlock<'_> {
            #[inline]
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _guard = Unlock(&self.locked);
        // SAFETY: `self.locked` was acquired atomically via Acquire CAS and is
        // released only when `_guard` drops.
        f(unsafe { &mut *self.data.get() })
    }
}

// SAFETY: `RtldLock` enforces mutual exclusion via `AtomicBool` Acquire/Release.
unsafe impl<T: Send> Sync for RtldLock<T> {}

#[repr(C)]
struct TlsIndex {
    ti_module: usize,
    ti_offset: usize,
}

#[repr(C)]
struct ThreadControlBlock {
    self_ptr: u64,
    dtv_ptr: *mut u64,
    magic: u64,
    map_base: u64,
    map_len: u64,
    dtv: [u64; MAX_OBJECTS + 1],
    dyn_allocs: [u64; MAX_OBJECTS + 1],
    mod_gens: [u64; MAX_OBJECTS + 1],
    dlerror_pending: u8,
    dlerror_buf: [u8; DLERROR_CAP],
}

#[derive(Clone, Copy)]
struct AtExitEntry {
    active: bool,
    func: Option<unsafe extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    dso_handle: *mut c_void,
}

impl AtExitEntry {
    const fn empty() -> Self {
        Self {
            active: false,
            func: None,
            arg: ptr::null_mut(),
            dso_handle: ptr::null_mut(),
        }
    }
}

// SAFETY: `arg` and `dso_handle` are opaque userspace values managed exclusively
// under `RTLD_STATE` synchronization and executed per Itanium C++ ABI rules.
unsafe impl Send for AtExitEntry {}

#[derive(Clone, Copy)]
struct MappedRange {
    va: u64,
    len: u64,
}

impl MappedRange {
    const fn empty() -> Self {
        Self { va: 0, len: 0 }
    }
}

#[derive(Clone, Copy)]
struct LoadedObject {
    active: bool,
    gen_id: u32,
    refcount: u32,
    pinned: bool,
    global: bool,
    init_run: bool,
    fini_run: bool,
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    bias: u64,
    min_va: u64,
    max_va: u64,
    phdr_addr: u64,
    phnum: u16,
    dyn_vaddr: u64,
    dyn_memsz: u64,
    relro_vaddr: u64,
    relro_memsz: u64,
    has_relro: bool,
    tls: Option<TlsSegment>,
    tls_modid: usize,
    tls_tp_offset: u64,
    summary: DynamicSummary,
    sym_count: usize,
    gnu_hash_words: usize,
    mapped_ranges: [MappedRange; MAX_LOAD_SEGS],
    mapped_count: usize,
    deps: [usize; MAX_DT_NEEDED],
    dep_count: usize,
}

impl LoadedObject {
    const fn empty() -> Self {
        Self {
            active: false,
            gen_id: 1,
            refcount: 0,
            pinned: false,
            global: false,
            init_run: false,
            fini_run: false,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            bias: 0,
            min_va: 0,
            max_va: 0,
            phdr_addr: 0,
            phnum: 0,
            dyn_vaddr: 0,
            dyn_memsz: 0,
            relro_vaddr: 0,
            relro_memsz: 0,
            has_relro: false,
            tls: None,
            tls_modid: 0,
            tls_tp_offset: 0,
            summary: DynamicSummary {
                needed_offs: [0; MAX_DT_NEEDED],
                needed_count: 0,
                soname_off: None,
                strtab: 0,
                strsz: 0,
                symtab: 0,
                syment: 24,
                rela: 0,
                relasz: 0,
                relaent: 24,
                jmprel: 0,
                pltrelsz: 0,
                pltrel_is_rela: false,
                hash: 0,
                gnu_hash: 0,
                versym: 0,
                verdef: 0,
                verdefnum: 0,
                verneed: 0,
                verneednum: 0,
                init: 0,
                fini: 0,
                init_array: 0,
                init_arraysz: 0,
                fini_array: 0,
                fini_arraysz: 0,
                bind_now: false,
                symbolic: false,
            },
            sym_count: 0,
            gnu_hash_words: 0,
            mapped_ranges: [MappedRange::empty(); MAX_LOAD_SEGS],
            mapped_count: 0,
            deps: [0; MAX_DT_NEEDED],
            dep_count: 0,
        }
    }

    fn set_name(&mut self, bytes: &[u8]) {
        let len = bytes.len().min(MAX_NAME_LEN.saturating_sub(1));
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
        self.name_len = len;
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

struct RtldState {
    self_vmar: Option<Vmar>,
    lib_vmo: Option<Vmo>,
    hxfs_dir: Option<HxfsDirectory>,
    hxfs_service: Option<Hxfs>,
    objects: [LoadedObject; MAX_OBJECTS],
    static_tls_total: u64,
    static_tls_align: u64,
    tls_gen: u64,
    modid_gen: [u64; MAX_OBJECTS + 1],
    dl_adds: u64,
    dl_subs: u64,
    host_alloc: Option<unsafe extern "C" fn(usize, usize) -> *mut u8>,
    host_free: Option<unsafe extern "C" fn(*mut u8)>,
    atexit: [AtExitEntry; MAX_ATEXIT],
    atexit_len: usize,
    fini_started: bool,
    fallback_dlerror_pending: bool,
    fallback_dlerror_buf: [u8; DLERROR_CAP],
}

impl RtldState {
    const fn new() -> Self {
        Self {
            self_vmar: None,
            lib_vmo: None,
            hxfs_dir: None,
            hxfs_service: None,
            objects: [const { LoadedObject::empty() }; MAX_OBJECTS],
            static_tls_total: 0,
            static_tls_align: 16,
            tls_gen: 1,
            modid_gen: [0; MAX_OBJECTS + 1],
            dl_adds: 0,
            dl_subs: 0,
            host_alloc: None,
            host_free: None,
            atexit: [const { AtExitEntry::empty() }; MAX_ATEXIT],
            atexit_len: 0,
            fini_started: false,
            fallback_dlerror_pending: false,
            fallback_dlerror_buf: [0; DLERROR_CAP],
        }
    }
}

static TLS_GEN_FAST: AtomicU64 = AtomicU64::new(1);
static RTLD_STATE: RtldLock<RtldState> = RtldLock::new(RtldState::new());

static RTLD_OPS: RtldOps = RtldOps {
    version: RTLD_OPS_VERSION,
    tls_get_addr: rtld_tls_get_addr,
    dlopen_vmo: rtld_dlopen_vmo,
    dlopen_soname: rtld_dlopen_soname,
    dlopen_blob: rtld_dlopen_blob,
    dlsym: rtld_dlsym,
    dlclose: rtld_dlclose,
    dlerror: rtld_dlerror,
    dladdr: rtld_dladdr,
    dl_iterate_phdr: rtld_dl_iterate_phdr,
    dl_set_lib_dir: rtld_dl_set_lib_dir,
    dl_set_hxfs_service: rtld_dl_set_hxfs_service,
    cxa_atexit: rtld_cxa_atexit,
    run_process_fini: rtld_run_process_fini,
    alloc_thread_tls: rtld_alloc_thread_tls,
    free_thread_tls: rtld_free_thread_tls,
};

extern "C" fn ld_entry(sp: *const u64) -> u64 {
    let interp_base = find_at_base_raw(sp);
    if interp_base == 0 {
        return 0;
    }
    // SAFETY: `interp_base` is the page-aligned base address of `ld-huesos.so`
    // mapped by the launcher; self-relocation touches only our own RELATIVE entries.
    unsafe { self_relocate(interp_base) };
    ld_main(sp)
}

fn find_at_base_raw(sp: *const u64) -> u64 {
    if sp.is_null() {
        return 0;
    }
    // SAFETY: kernel + launcher mapped the initial user stack with argc/argv/envp/auxv.
    unsafe {
        let argc = *sp as usize;
        let mut cursor = sp.add(1 + argc + 1);
        while *cursor != 0 {
            cursor = cursor.add(1);
        }
        cursor = cursor.add(1);
        let mut aux = cursor as *const AuxEntry;
        loop {
            let entry = *aux;
            if entry.a_type == AT_NULL {
                break;
            }
            if entry.a_type == AT_BASE {
                return entry.a_val;
            }
            aux = aux.add(1);
        }
    }
    0
}

#[inline(never)]
unsafe fn self_relocate(base: u64) {
    // SAFETY: caller guarantees `base` points to our mapped ELF64 image.
    unsafe {
        let base_ptr = base as *const u8;
        let phoff = ptr::read_unaligned(base_ptr.add(EHDR_PHOFF_OFF) as *const u64);
        let phentsize = ptr::read_unaligned(base_ptr.add(EHDR_PHENTSIZE_OFF) as *const u16);
        let phnum = ptr::read_unaligned(base_ptr.add(EHDR_PHNUM_OFF) as *const u16);

        let mut dyn_vaddr: u64 = 0;
        let mut dyn_memsz: u64 = 0;
        let mut i = 0u16;
        while i < phnum {
            let ph = base_ptr.add(phoff as usize + (i as usize) * (phentsize as usize));
            let p_type = ptr::read_unaligned(ph.add(PHDR_TYPE_OFF) as *const u32);
            if p_type == PT_DYNAMIC {
                dyn_vaddr = ptr::read_unaligned(ph.add(PHDR_VADDR_OFF) as *const u64);
                dyn_memsz = ptr::read_unaligned(ph.add(PHDR_MEMSZ_OFF) as *const u64);
                break;
            }
            i += 1;
        }
        if dyn_vaddr == 0 || dyn_memsz == 0 {
            return;
        }

        let dyn_ptr = (base + dyn_vaddr) as *const Dyn64;
        let max_entries = (dyn_memsz as usize) / core::mem::size_of::<Dyn64>();
        let mut rela_off: u64 = 0;
        let mut rela_sz: u64 = 0;
        let mut idx = 0usize;
        while idx < max_entries {
            let d = *dyn_ptr.add(idx);
            if d.d_tag == dt::NULL {
                break;
            }
            if d.d_tag == dt::RELA {
                rela_off = d.d_val;
            } else if d.d_tag == dt::RELASZ {
                rela_sz = d.d_val;
            }
            idx += 1;
        }
        if rela_off == 0 || rela_sz == 0 {
            return;
        }

        let rela_ptr = (base + rela_off) as *const Rela64;
        let count = (rela_sz as usize) / core::mem::size_of::<Rela64>();
        let mut r = 0usize;
        while r < count {
            let rel = *rela_ptr.add(r);
            if (rel.r_info as u32) == r_x86_64::RELATIVE {
                let target = (base + rel.r_offset) as *mut u64;
                let value = (base as i64).wrapping_add(rel.r_addend) as u64;
                *target = value;
            }
            r += 1;
        }
    }
}

#[derive(Clone, Copy)]
struct AuxInfo {
    argc: usize,
    argv: *const *const c_char,
    phdr: u64,
    phent: u64,
    phnum: u64,
    base: u64,
    entry: u64,
    ld_bootstrap: bool,
    expect_lib_vmo: bool,
    expect_hxfs_dir: bool,
    expect_stdin: bool,
    expect_stdout: bool,
    expect_stderr: bool,
    expect_hxfs_service: bool,
    expect_block_dev: bool,
    expect_frame_draw: bool,
    caps_mask: u64,
}

fn parse_auxv(sp: *const u64) -> Option<AuxInfo> {
    if sp.is_null() {
        return None;
    }
    let mut info = AuxInfo {
        argc: 0,
        argv: ptr::null(),
        phdr: 0,
        phent: 0,
        phnum: 0,
        base: 0,
        entry: 0,
        ld_bootstrap: false,
        expect_lib_vmo: true,
        expect_hxfs_dir: false,
        expect_stdin: false,
        expect_stdout: false,
        expect_stderr: false,
        expect_hxfs_service: false,
        expect_block_dev: false,
        expect_frame_draw: false,
        caps_mask: caps_mask::ALL_DEFAULT,
    };
    // SAFETY: stack was constructed by the parent process launcher per SysV ABI.
    unsafe {
        let argc = *sp as usize;
        info.argc = argc;
        info.argv = sp.add(1) as *const *const c_char;
        let mut cursor = sp.add(1 + argc + 1);
        while *cursor != 0 {
            cursor = cursor.add(1);
        }
        cursor = cursor.add(1);
        let mut aux = cursor as *const AuxEntry;
        loop {
            let entry = *aux;
            match entry.a_type {
                AT_NULL => break,
                AT_PHDR => info.phdr = entry.a_val,
                AT_PHENT => info.phent = entry.a_val,
                AT_PHNUM => info.phnum = entry.a_val,
                AT_BASE => info.base = entry.a_val,
                AT_ENTRY => info.entry = entry.a_val,
                AT_HUESOS_LD_BOOTSTRAP => info.ld_bootstrap = entry.a_val != 0,
                AT_HUESOS_LIB_VMO => info.expect_lib_vmo = entry.a_val != 0,
                AT_HUESOS_HXFS_DIR => info.expect_hxfs_dir = entry.a_val != 0,
                AT_HUESOS_STDIN => info.expect_stdin = entry.a_val != 0,
                AT_HUESOS_STDOUT => info.expect_stdout = entry.a_val != 0,
                AT_HUESOS_STDERR => info.expect_stderr = entry.a_val != 0,
                AT_HUESOS_CAPS_MASK => info.caps_mask = entry.a_val,
                AT_HUESOS_HXFS_SERVICE => info.expect_hxfs_service = entry.a_val != 0,
                AT_HUESOS_BLOCK_DEV => info.expect_block_dev = entry.a_val != 0,
                AT_HUESOS_FRAME_DRAW => info.expect_frame_draw = entry.a_val != 0,
                _ => {}
            }
            aux = aux.add(1);
        }
    }
    Some(info)
}

struct BootstrapExtras {
    stdin_ch: u32,
    stdout_ch: u32,
    stderr_ch: u32,
    hxfs_dir_ch: u32,
    hxfs_service_ch: u32,
    block_dev_ch: u32,
    frame_draw_ch: u32,
}

fn fail(msg: &str) -> ! {
    debug::write_str("[ld-huesos] error: ");
    debug::write_str(msg);
    debug::write_str("\n");
    process::exit(-10);
}

#[inline(never)]
fn ld_main(sp: *const u64) -> u64 {
    let Some(aux) = parse_auxv(sp) else {
        fail("invalid auxv");
    };
    if aux.entry == 0 || aux.phdr == 0 || aux.phnum == 0 || !aux.ld_bootstrap {
        fail("missing required auxv entries");
    }

    let (self_vmar, lib_vmo, hxfs_dir, extras) = receive_bootstrap_handles(&aux);

    let main_obj = build_main_object(&aux);
    let initial_count = RTLD_STATE.with(|state| {
        state.self_vmar = Some(self_vmar);
        state.lib_vmo = lib_vmo;
        state.hxfs_dir = hxfs_dir;
        state.objects[0] = main_obj;
        let mut obj_count = 1usize;

        // Breadth-first load of all DT_NEEDED shared objects.
        let mut scan_idx = 0usize;
        while scan_idx < obj_count {
            let needed_count = state.objects[scan_idx].summary.needed_count;
            let needed_offs = state.objects[scan_idx].summary.needed_offs;
            let strtab_addr = state.objects[scan_idx].bias + state.objects[scan_idx].summary.strtab;
            let strsz = state.objects[scan_idx].summary.strsz as usize;
            let mut n = 0usize;
            while n < needed_count {
                let Some(soname) = read_cstr_slice(strtab_addr, strsz, needed_offs[n]) else {
                    fail("invalid DT_NEEDED string");
                };
                if !validate_soname(soname) {
                    fail("invalid DT_NEEDED SONAME (path traversal rejected)");
                }
                let dep_idx =
                    if let Some(existing_idx) = find_loaded_by_name(&state.objects, soname) {
                        existing_idx
                    } else {
                        let Some(free_slot) = alloc_object_slot(&mut state.objects) else {
                            fail("too many shared objects");
                        };
                        let loaded = match load_soname_object_locked(state, soname, true, true) {
                            Ok(obj) => obj,
                            Err(msg) => fail(msg),
                        };
                        state.objects[free_slot] = loaded;
                        obj_count = obj_count.max(free_slot + 1);
                        free_slot
                    };
                record_dep(&mut state.objects[scan_idx], dep_idx);
                state.objects[dep_idx].refcount = state.objects[dep_idx].refcount.saturating_add(1);
                n += 1;
            }
            scan_idx += 1;
        }

        // Validate symbol versioning (`DT_VERNEED` against `DT_VERDEF`) on all initial objects.
        for idx in 0..obj_count {
            if state.objects[idx].active {
                if let Err(msg) = validate_object_versions(&state.objects[idx], &state.objects) {
                    fail(msg);
                }
            }
        }

        // Compute static TLS layout for initial objects and allocate primary thread TCB+DTV.
        compute_initial_static_tls(state);
        let tp = match allocate_thread_tls_locked(state) {
            Ok(tp) => tp,
            Err(msg) => fail(msg),
        };
        if process::set_fs_base(tp).is_err() {
            fail("ThreadSetFsBase failed");
        }

        // Apply relocations (`BIND_NOW`, including `TPOFF64`, `DTPMOD64`, `DTPOFF64`).
        for idx in 0..obj_count {
            if state.objects[idx].active {
                if let Err(msg) = apply_object_relocations(idx, &state.objects) {
                    fail(msg);
                }
            }
        }

        // Apply `PT_GNU_RELRO` read-only protections.
        if let Some(vmar) = state.self_vmar.as_ref() {
            for idx in 0..obj_count {
                if state.objects[idx].active {
                    if let Err(msg) = protect_object_relro(vmar, &state.objects[idx]) {
                        fail(msg);
                    }
                }
            }
            protect_self_relro(vmar, aux.base);
        }

        state.dl_adds = obj_count as u64;
        obj_count
    });

    // Register `RtldOps` with `libcanvas.so` (receiving `ScudoHeap` alloc/free callbacks)
    // before any `.init_array` runs so constructors can use `__tls_get_addr`, `__cxa_atexit`,
    // and `canvas_dl*`.
    register_rtld_into_libcanvas(initial_count);

    // Enforce `@caps(bootfs=none)` by dropping the BOOTFS `lib_vmo` capability
    // immediately after initial `DT_NEEDED` resolution, before `.init_array` or `_start`.
    if (aux.caps_mask & caps_mask::BOOTFS_RO) == 0 {
        RTLD_STATE.with(|state| {
            state.lib_vmo = None;
        });
    }

    // Pass `argc`/`argv`, `@caps(...)` mask, and stdio/capability handles to `libcanvas.so`.
    register_process_ctx_into_libcanvas(initial_count, &aux, &extras);

    // Run `.init` and `.init_array` in dependency-first order (reverse load order).
    let mut ctor_idx = initial_count;
    while ctor_idx > 0 {
        ctor_idx -= 1;
        let ctors = RTLD_STATE.with(|state| {
            if state.objects[ctor_idx].active && !state.objects[ctor_idx].init_run {
                state.objects[ctor_idx].init_run = true;
                Some(snapshot_object_inits(&state.objects[ctor_idx]))
            } else {
                None
            }
        });
        if let Some(ctors) = ctors {
            run_ctor_snapshot(&ctors);
        }
    }

    aux.entry
}

fn register_rtld_into_libcanvas(obj_count: usize) {
    let reg_addr = RTLD_STATE.with(|state| {
        for idx in 1..obj_count {
            let obj = &state.objects[idx];
            if obj.active {
                if let Some((_sidx, sym)) =
                    lookup_in_object(obj, b"__huesos_register_rtld", None, true)
                {
                    return Some(obj.bias.wrapping_add(sym.st_value));
                }
            }
        }
        None
    });
    if let Some(addr) = reg_addr {
        let mut host = HostAllocOps {
            version: 0,
            alloc: dummy_host_alloc,
            free: dummy_host_free,
        };
        // SAFETY: `__huesos_register_rtld` in `libcanvas.so` matches this exact signature.
        let reg_fn: unsafe extern "C" fn(*const RtldOps, *mut HostAllocOps) -> i32 =
            unsafe { core::mem::transmute(addr) };
        // SAFETY: `RTLD_OPS` is `'static` and `host` is writable stack storage.
        let rc = unsafe { reg_fn(&RTLD_OPS as *const RtldOps, &mut host as *mut HostAllocOps) };
        if rc == 0 && host.version == RTLD_OPS_VERSION {
            RTLD_STATE.with(|state| {
                state.host_alloc = Some(host.alloc);
                state.host_free = Some(host.free);
            });
        }
    }
}

fn register_process_ctx_into_libcanvas(obj_count: usize, aux: &AuxInfo, extras: &BootstrapExtras) {
    let reg_addr = RTLD_STATE.with(|state| {
        for idx in 1..obj_count {
            let obj = &state.objects[idx];
            if obj.active {
                if let Some((_sidx, sym)) =
                    lookup_in_object(obj, b"__huesos_set_process_ctx", None, true)
                {
                    return Some(obj.bias.wrapping_add(sym.st_value));
                }
            }
        }
        None
    });
    if let Some(addr) = reg_addr {
        let info = ProcessBootstrapInfo {
            version: RTLD_OPS_VERSION,
            argc: aux.argc,
            argv: aux.argv,
            caps_mask: aux.caps_mask,
            stdin_ch: extras.stdin_ch,
            stdout_ch: extras.stdout_ch,
            stderr_ch: extras.stderr_ch,
            hxfs_dir_ch: extras.hxfs_dir_ch,
            hxfs_service_ch: extras.hxfs_service_ch,
            block_dev_ch: extras.block_dev_ch,
            frame_draw_ch: extras.frame_draw_ch,
        };
        // SAFETY: `__huesos_set_process_ctx` in `libcanvas.so` matches this exact signature.
        let set_fn: unsafe extern "C" fn(*const ProcessBootstrapInfo) -> i32 =
            unsafe { core::mem::transmute(addr) };
        // SAFETY: `info` is valid stack storage.
        let _ = unsafe { set_fn(&info as *const ProcessBootstrapInfo) };
    }
}

unsafe extern "C" fn dummy_host_alloc(_size: usize, _align: usize) -> *mut u8 {
    ptr::null_mut()
}

unsafe extern "C" fn dummy_host_free(_ptr: *mut u8) {}

fn receive_bootstrap_handles(
    aux: &AuxInfo,
) -> (Vmar, Option<Vmo>, Option<HxfsDirectory>, BootstrapExtras) {
    let bootstrap = libcanvas::channel::bootstrap();
    let mut self_vmar: Option<Handle> = None;
    let mut lib_vmo: Option<Handle> = None;
    let mut hxfs_dir: Option<Handle> = None;
    let mut stdin_h: Option<Handle> = None;
    let mut stdout_h: Option<Handle> = None;
    let mut stderr_h: Option<Handle> = None;
    let mut hxfs_svc_h: Option<Handle> = None;
    let mut block_dev_h: Option<Handle> = None;
    let mut frame_draw_h: Option<Handle> = None;
    let mut buf = [0u8; 64];

    while self_vmar.is_none()
        || (aux.expect_lib_vmo && lib_vmo.is_none())
        || (aux.expect_hxfs_dir && hxfs_dir.is_none())
        || (aux.expect_stdin && stdin_h.is_none())
        || (aux.expect_stdout && stdout_h.is_none())
        || (aux.expect_stderr && stderr_h.is_none())
        || (aux.expect_hxfs_service && hxfs_svc_h.is_none())
        || (aux.expect_block_dev && block_dev_h.is_none())
        || (aux.expect_frame_draw && frame_draw_h.is_none())
    {
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_SELF_VMAR_LABEL => {
                self_vmar = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_LIB_VMO_LABEL => {
                lib_vmo = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_HXFS_DIR_LABEL => {
                hxfs_dir = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_STDIN_LABEL => {
                stdin_h = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_STDOUT_LABEL => {
                stdout_h = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_STDERR_LABEL => {
                stderr_h = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_HXFS_SERVICE_LABEL => {
                hxfs_svc_h = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_BLOCK_DEV_LABEL => {
                block_dev_h = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_FRAME_DRAW_LABEL => {
                frame_draw_h = Some(handle);
            }
            Ok((_n, _)) => {
                fail("unexpected bootstrap message before dynamic link");
            }
            Err(libcanvas::ErrorCode::ShouldWait) | Err(libcanvas::ErrorCode::TimedOut) => {
                process::yield_now();
            }
            Err(_) => {
                fail("failed reading ld bootstrap handles");
            }
        }
    }

    let _ = bootstrap.into_handle().into_raw();

    let Some(vmar_h) = self_vmar else {
        fail("missing self_vmar bootstrap handle");
    };

    let (rtld_hxfs_dir, app_hxfs_dir_ch) = match hxfs_dir {
        Some(h) => {
            let dup = h.duplicate(rights::SAME_RIGHTS).ok();
            let app_raw = h.into_raw();
            (
                dup.map(|d| HxfsDirectory::from_channel(Channel::from_handle(d))),
                app_raw,
            )
        }
        None => (None, INVALID_HANDLE),
    };

    let extras = BootstrapExtras {
        stdin_ch: stdin_h.map_or(INVALID_HANDLE, Handle::into_raw),
        stdout_ch: stdout_h.map_or(INVALID_HANDLE, Handle::into_raw),
        stderr_ch: stderr_h.map_or(INVALID_HANDLE, Handle::into_raw),
        hxfs_dir_ch: app_hxfs_dir_ch,
        hxfs_service_ch: hxfs_svc_h.map_or(INVALID_HANDLE, Handle::into_raw),
        block_dev_ch: block_dev_h.map_or(INVALID_HANDLE, Handle::into_raw),
        frame_draw_ch: frame_draw_h.map_or(INVALID_HANDLE, Handle::into_raw),
    };

    (
        Vmar::from_handle(vmar_h),
        lib_vmo.map(Vmo::from_handle),
        rtld_hxfs_dir,
        extras,
    )
}

fn build_main_object(aux: &AuxInfo) -> LoadedObject {
    let phent = aux.phent as usize;
    let phnum = aux.phnum as usize;
    if phent < 56 || phnum == 0 {
        fail("bad main AT_PHDR geometry");
    }
    let ph_bytes_len = phnum.saturating_mul(phent);
    // SAFETY: `AT_PHDR` points to the mapped program headers of the main executable.
    let ph_table = unsafe { slice::from_raw_parts(aux.phdr as *const u8, ph_bytes_len) };

    let mut pt_phdr_vaddr: Option<u64> = None;
    let mut first_load_vaddr: Option<u64> = None;
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut dyn_vaddr = 0u64;
    let mut dyn_memsz = 0u64;
    let mut relro_vaddr = 0u64;
    let mut relro_memsz = 0u64;
    let mut has_relro = false;
    let mut tls: Option<TlsSegment> = None;

    let mut i = 0usize;
    while i < phnum {
        let off = i * phent;
        let ph = read_phdr64_from_slice(&ph_table[off..off + phent]);
        match ph.p_type {
            PT_PHDR => pt_phdr_vaddr = Some(ph.p_vaddr),
            PT_LOAD => {
                if first_load_vaddr.is_none() {
                    first_load_vaddr = Some(ph.p_vaddr);
                }
                let start = align_down(ph.p_vaddr, PAGE_SIZE);
                let end = align_up(ph.p_vaddr.saturating_add(ph.p_memsz), PAGE_SIZE);
                if start < min_vaddr {
                    min_vaddr = start;
                }
                if end > max_vaddr {
                    max_vaddr = end;
                }
            }
            PT_DYNAMIC => {
                dyn_vaddr = ph.p_vaddr;
                dyn_memsz = ph.p_memsz;
            }
            PT_GNU_RELRO => {
                relro_vaddr = ph.p_vaddr;
                relro_memsz = ph.p_memsz;
                has_relro = true;
            }
            PT_TLS => {
                tls = Some(TlsSegment {
                    vaddr: ph.p_vaddr,
                    filesz: ph.p_filesz,
                    memsz: ph.p_memsz,
                    align: ph.p_align.max(1),
                });
            }
            _ => {}
        }
        i += 1;
    }

    let bias = if let Some(vaddr) = pt_phdr_vaddr {
        aux.phdr.wrapping_sub(vaddr)
    } else if let Some(load_va) = first_load_vaddr {
        align_down(aux.phdr, PAGE_SIZE).wrapping_sub(align_down(load_va, PAGE_SIZE))
    } else {
        0
    };

    let mut obj = LoadedObject::empty();
    obj.active = true;
    obj.refcount = 1;
    obj.pinned = true;
    obj.global = true;
    obj.set_name(b"<main>");
    obj.bias = bias;
    obj.min_va = bias.wrapping_add(min_vaddr);
    obj.max_va = bias.wrapping_add(max_vaddr);
    obj.phdr_addr = aux.phdr;
    obj.phnum = aux.phnum as u16;
    obj.dyn_vaddr = bias.wrapping_add(dyn_vaddr);
    obj.dyn_memsz = dyn_memsz;
    obj.relro_vaddr = bias.wrapping_add(relro_vaddr);
    obj.relro_memsz = relro_memsz;
    obj.has_relro = has_relro;
    obj.tls = tls;
    populate_dynamic_info(&mut obj);
    obj
}

fn read_phdr64_from_slice(bytes: &[u8]) -> Phdr64 {
    Phdr64 {
        p_type: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        p_flags: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        p_offset: u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
        p_vaddr: u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        p_paddr: u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
        p_filesz: u64::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]),
        p_memsz: u64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]),
        p_align: u64::from_le_bytes([
            bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55],
        ]),
    }
}

fn populate_dynamic_info(obj: &mut LoadedObject) {
    if obj.dyn_vaddr == 0 || obj.dyn_memsz == 0 {
        return;
    }
    let count = (obj.dyn_memsz as usize) / core::mem::size_of::<Dyn64>();
    // SAFETY: `PT_DYNAMIC` is mapped inside the loaded ELF image.
    let entries = unsafe { slice::from_raw_parts(obj.dyn_vaddr as *const Dyn64, count) };
    obj.summary = DynamicSummary::from_entries(entries);
    if obj.summary.hash != 0 {
        let hash_ptr = (obj.bias + obj.summary.hash) as *const u32;
        // SAFETY: `DT_HASH` begins with `[nbuckets, nchains]`.
        let nchains = unsafe { *hash_ptr.add(1) } as usize;
        obj.sym_count = nchains;
    }
    if obj.summary.gnu_hash != 0 {
        let (sym_count, words) = probe_gnu_hash_bounds(obj.bias + obj.summary.gnu_hash);
        if obj.sym_count == 0 {
            obj.sym_count = sym_count;
        }
        obj.gnu_hash_words = words;
    }
}

fn probe_gnu_hash_bounds(addr: u64) -> (usize, usize) {
    let ptr = addr as *const u32;
    // SAFETY: `DT_GNU_HASH` header is at least 4 `u32` words.
    let (nbuckets, symoffset, bloom_size) =
        unsafe { (*ptr as usize, *ptr.add(1) as usize, *ptr.add(2) as usize) };
    if nbuckets == 0 || bloom_size == 0 {
        return (0, 0);
    }
    let buckets_start = 4usize + bloom_size * 2;
    let chains_start = buckets_start + nbuckets;
    let mut max_sym = symoffset;
    let mut b = 0usize;
    while b < nbuckets {
        // SAFETY: `buckets` array has `nbuckets` entries.
        let bucket = unsafe { *ptr.add(buckets_start + b) } as usize;
        if bucket > max_sym {
            max_sym = bucket;
        }
        b += 1;
    }
    if max_sym < symoffset {
        return (symoffset, chains_start);
    }
    let mut sym_idx = max_sym;
    loop {
        let chain_idx = sym_idx - symoffset;
        // SAFETY: walking chain inside mapped `.gnu.hash` until terminator bit 0.
        let chain_val = unsafe { *ptr.add(chains_start + chain_idx) };
        if (chain_val & 1) != 0 {
            return (sym_idx + 1, chains_start + chain_idx + 1);
        }
        sym_idx += 1;
    }
}

fn alloc_object_slot(objects: &mut [LoadedObject; MAX_OBJECTS]) -> Option<usize> {
    objects.iter().position(|o| !o.active)
}

fn alloc_tls_modid(state: &mut RtldState) -> Option<usize> {
    for modid in 1..=MAX_OBJECTS {
        if state.modid_gen[modid] == 0 {
            state.tls_gen = state.tls_gen.saturating_add(1);
            state.modid_gen[modid] = state.tls_gen;
            TLS_GEN_FAST.store(state.tls_gen, Ordering::Release);
            return Some(modid);
        }
    }
    None
}

fn record_dep(parent: &mut LoadedObject, dep_idx: usize) {
    for &existing in &parent.deps[..parent.dep_count] {
        if existing == dep_idx {
            return;
        }
    }
    if parent.dep_count < MAX_DT_NEEDED {
        parent.deps[parent.dep_count] = dep_idx;
        parent.dep_count += 1;
    }
}

fn object_soname(obj: &LoadedObject) -> Option<&[u8]> {
    if let Some(off) = obj.summary.soname_off {
        let strtab_addr = obj.bias + obj.summary.strtab;
        return read_cstr_slice(strtab_addr, obj.summary.strsz as usize, off);
    }
    None
}

fn find_loaded_by_name(objects: &[LoadedObject], wanted: &[u8]) -> Option<usize> {
    for (idx, obj) in objects.iter().enumerate() {
        if !obj.active {
            continue;
        }
        if obj.name_bytes() == wanted {
            return Some(idx);
        }
        if object_soname(obj) == Some(wanted) {
            return Some(idx);
        }
    }
    None
}

fn resolve_soname_to_vmo(
    state: &mut RtldState,
    soname: &[u8],
) -> Result<Option<Vmo>, &'static str> {
    if !validate_soname(soname) {
        return Err("invalid SONAME (path traversal rejected)");
    }
    let soname_str = core::str::from_utf8(soname).map_err(|_| "non-UTF8 SONAME")?;

    // Lazy-open `/lib` if an HxFS service handle was registered without a DirectoryHandle.
    if state.hxfs_dir.is_none() {
        if let Some(ref fs) = state.hxfs_service {
            if let Ok(dir) = fs.open_dir("/lib") {
                state.hxfs_dir = Some(dir);
            }
        }
    }

    if let Some(ref dir) = state.hxfs_dir {
        if let Ok(file) = dir.open_file(soname_str) {
            if let Ok(vmo) = file.read_into_vmo() {
                return Ok(Some(vmo));
            }
        }
    }
    Ok(None)
}

fn load_soname_object_locked(
    state: &mut RtldState,
    soname: &[u8],
    pinned: bool,
    global: bool,
) -> Result<LoadedObject, &'static str> {
    let hxfs_vmo = resolve_soname_to_vmo(state, soname)?;
    let mut obj = if let Some(vmo) = hxfs_vmo {
        let Some(self_vmar) = state.self_vmar.as_ref() else {
            return Err("missing self VMAR capability");
        };
        map_shared_object_from_vmo(self_vmar, &vmo, 0, None, soname, &state.objects)?
    } else {
        let (Some(self_vmar), Some(lib_vmo)) = (state.self_vmar.as_ref(), state.lib_vmo.as_ref())
        else {
            return Err("shared library not found (no HxFS/BOOTFS)");
        };
        let mut path_buf = [0u8; 192];
        let path = build_bootfs_lib_path(soname, &mut path_buf)?;
        let Some((elf_off, elf_len)) = find_bootfs_entry(lib_vmo, path) else {
            return Err("shared library not found in HxFS or BOOTFS");
        };
        map_shared_object_from_vmo(
            self_vmar,
            lib_vmo,
            elf_off,
            Some(elf_len),
            soname,
            &state.objects,
        )?
    };
    obj.pinned = pinned;
    obj.global = global;
    if obj.tls.is_some() {
        let Some(modid) = alloc_tls_modid(state) else {
            if let Some(self_vmar) = state.self_vmar.as_ref() {
                unmap_object_ranges(self_vmar, &obj);
            }
            return Err("TLS module capacity exhausted");
        };
        obj.tls_modid = modid;
    }
    Ok(obj)
}

fn map_shared_object_from_vmo(
    self_vmar: &Vmar,
    vmo: &Vmo,
    elf_off: u64,
    known_len: Option<u64>,
    fallback_name: &[u8],
    existing: &[LoadedObject; MAX_OBJECTS],
) -> Result<LoadedObject, &'static str> {
    let mut hdr_buf = [0u8; HEADER_BUF_LEN];
    let want_first = match known_len {
        Some(len) => (len as usize).min(4096).min(hdr_buf.len()),
        None => 4096,
    };
    let Ok(first_len) = vmo.read(elf_off, &mut hdr_buf[..want_first]) else {
        return Err("failed reading shared object ELF header");
    };
    if first_len < 64 || !huesos_elf::dynamic::is_valid_elf64_header(&hdr_buf[..first_len]) {
        return Err("invalid ELF64 header");
    }
    let e_type = u16::from_le_bytes([hdr_buf[16], hdr_buf[17]]);
    let e_machine = u16::from_le_bytes([hdr_buf[18], hdr_buf[19]]);
    let e_phoff = u64::from_le_bytes([
        hdr_buf[32],
        hdr_buf[33],
        hdr_buf[34],
        hdr_buf[35],
        hdr_buf[36],
        hdr_buf[37],
        hdr_buf[38],
        hdr_buf[39],
    ]);
    let e_phentsize = u16::from_le_bytes([hdr_buf[54], hdr_buf[55]]);
    let e_phnum = u16::from_le_bytes([hdr_buf[56], hdr_buf[57]]);
    if e_type != ET_DYN || e_machine != EM_X86_64 || e_phentsize != 56 || e_phnum == 0 {
        return Err("unsupported shared object ELF format");
    }
    let phdr_end =
        e_phoff.saturating_add(u64::from(e_phnum).saturating_mul(u64::from(e_phentsize)));
    if let Some(len) = known_len {
        if phdr_end > len {
            return Err("program headers exceed object length");
        }
    }
    if phdr_end as usize > HEADER_BUF_LEN {
        return Err("program headers exceed header buffer");
    }
    let hdr_len = if phdr_end as usize > first_len {
        let Ok(n) = vmo.read(elf_off, &mut hdr_buf[..phdr_end as usize]) else {
            return Err("failed reading shared object phdrs");
        };
        if n < phdr_end as usize {
            return Err("truncated shared object phdrs");
        }
        n
    } else {
        first_len
    };
    let hdr_slice = &hdr_buf[..hdr_len];

    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut dyn_vaddr = 0u64;
    let mut dyn_memsz = 0u64;
    let mut relro_vaddr = 0u64;
    let mut relro_memsz = 0u64;
    let mut has_relro = false;
    let mut tls: Option<TlsSegment> = None;
    let mut pt_phdr_vaddr: Option<u64> = None;
    let mut first_load_vaddr: Option<u64> = None;

    for i in 0..usize::from(e_phnum) {
        let Ok(ph) = read_phdr64(hdr_slice, e_phoff, i) else {
            return Err("corrupt shared object phdr");
        };
        match ph.p_type {
            PT_PHDR => pt_phdr_vaddr = Some(ph.p_vaddr),
            PT_LOAD => {
                if first_load_vaddr.is_none() {
                    first_load_vaddr = Some(ph.p_vaddr);
                }
                let start = align_down(ph.p_vaddr, PAGE_SIZE);
                let end = align_up(ph.p_vaddr.saturating_add(ph.p_memsz), PAGE_SIZE);
                if start < min_vaddr {
                    min_vaddr = start;
                }
                if end > max_vaddr {
                    max_vaddr = end;
                }
            }
            PT_DYNAMIC => {
                dyn_vaddr = ph.p_vaddr;
                dyn_memsz = ph.p_memsz;
            }
            PT_GNU_RELRO => {
                relro_vaddr = ph.p_vaddr;
                relro_memsz = ph.p_memsz;
                has_relro = true;
            }
            PT_TLS => {
                tls = Some(TlsSegment {
                    vaddr: ph.p_vaddr,
                    filesz: ph.p_filesz,
                    memsz: ph.p_memsz,
                    align: ph.p_align.max(1),
                });
            }
            _ => {}
        }
    }

    if min_vaddr >= max_vaddr {
        return Err("shared object has no PT_LOAD");
    }
    let span = max_vaddr - min_vaddr;
    let load_base = choose_aslr_region(DSO_ASLR_BASE, DSO_ASLR_MASK, span, existing)
        .ok_or("ASLR region exhausted")?;
    let bias = load_base.wrapping_sub(min_vaddr);

    let mut obj = LoadedObject::empty();
    for j in 0..usize::from(e_phnum) {
        let Ok(ph) = read_phdr64(hdr_slice, e_phoff, j) else {
            unmap_object_ranges(self_vmar, &obj);
            return Err("corrupt shared object phdr");
        };
        if ph.p_type == PT_LOAD {
            match map_load_segment_from_vmo(self_vmar, vmo, elf_off, known_len, bias, ph) {
                Ok(Some(range)) => {
                    if obj.mapped_count < MAX_LOAD_SEGS {
                        obj.mapped_ranges[obj.mapped_count] = range;
                        obj.mapped_count += 1;
                    }
                }
                Ok(None) => {}
                Err(msg) => {
                    unmap_object_ranges(self_vmar, &obj);
                    return Err(msg);
                }
            }
        }
    }

    obj.active = true;
    obj.bias = bias;
    obj.min_va = load_base;
    obj.max_va = load_base + span;
    obj.phdr_addr = if let Some(vaddr) = pt_phdr_vaddr {
        bias.wrapping_add(vaddr)
    } else if let Some(load_va) = first_load_vaddr {
        bias.wrapping_add(load_va).wrapping_add(e_phoff)
    } else {
        0
    };
    obj.phnum = e_phnum;
    obj.dyn_vaddr = bias.wrapping_add(dyn_vaddr);
    obj.dyn_memsz = dyn_memsz;
    obj.relro_vaddr = bias.wrapping_add(relro_vaddr);
    obj.relro_memsz = relro_memsz;
    obj.has_relro = has_relro;
    obj.tls = tls;
    populate_dynamic_info(&mut obj);

    if let Some(soname) = object_soname(&obj) {
        let mut copy = [0u8; MAX_NAME_LEN];
        let n = soname.len().min(MAX_NAME_LEN - 1);
        copy[..n].copy_from_slice(&soname[..n]);
        obj.set_name(&copy[..n]);
    } else {
        obj.set_name(fallback_name);
    }
    Ok(obj)
}

fn unmap_object_ranges(self_vmar: &Vmar, obj: &LoadedObject) {
    for r in &obj.mapped_ranges[..obj.mapped_count] {
        if r.len > 0 {
            let _ = self_vmar.unmap(r.va, r.len);
        }
    }
}

fn build_bootfs_lib_path<'a>(
    soname: &[u8],
    buf: &'a mut [u8; 192],
) -> Result<&'a [u8], &'static str> {
    if !validate_soname(soname) {
        return Err("invalid SONAME");
    }
    let prefix = b"/lib/";
    let total = prefix.len() + soname.len();
    if total > buf.len() {
        return Err("SONAME too long");
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..total].copy_from_slice(soname);
    Ok(&buf[..total])
}

fn find_bootfs_entry(vmo: &Vmo, wanted: &[u8]) -> Option<(u64, u64)> {
    let mut header = [0u8; BOOTFS_HEADER_SIZE as usize];
    if vmo.read(0, &mut header).ok()? != header.len() || &header[..8] != BOOTFS_MAGIC {
        return None;
    }
    let count = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let mut raw = [0u8; BOOTFS_ENTRY_SIZE as usize];
    let mut index = 0u32;
    while index < count {
        let entry_off = BOOTFS_HEADER_SIZE + u64::from(index) * BOOTFS_ENTRY_SIZE;
        if vmo.read(entry_off, &mut raw).ok()? != raw.len() {
            return None;
        }
        let path_len = raw[..BOOTFS_PATH_SIZE]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(BOOTFS_PATH_SIZE);
        if &raw[..path_len] == wanted {
            let meta = &raw[BOOTFS_PATH_SIZE..];
            let offset = u64::from_le_bytes([
                meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6], meta[7],
            ]);
            let len = u64::from_le_bytes([
                meta[8], meta[9], meta[10], meta[11], meta[12], meta[13], meta[14], meta[15],
            ]);
            return Some((offset, len));
        }
        index += 1;
    }
    None
}

fn choose_aslr_region(
    window_base: u64,
    page_mask: u64,
    span: u64,
    existing: &[LoadedObject],
) -> Option<u64> {
    let rand = memory::random_u64().unwrap_or(0x1357_2468);
    let start_slot = rand & page_mask;
    let heap_start = USER_HEAP_BASE;
    let heap_end = USER_HEAP_BASE + USER_HEAP_SIZE;

    let mut attempt = 0u64;
    while attempt < 2048 {
        let candidate =
            window_base + (((start_slot.wrapping_add(attempt * 128)) & page_mask) << 12);
        let cand_end = candidate.saturating_add(span);
        let overlaps_heap = !(cand_end <= heap_start || candidate >= heap_end);
        let mut overlaps_obj = false;
        for obj in existing {
            if obj.active && !(cand_end <= obj.min_va || candidate >= obj.max_va) {
                overlaps_obj = true;
                break;
            }
        }
        if !overlaps_heap && !overlaps_obj {
            return Some(candidate);
        }
        attempt += 1;
    }
    None
}

fn map_load_segment_from_vmo(
    self_vmar: &Vmar,
    vmo: &Vmo,
    elf_off: u64,
    known_len: Option<u64>,
    bias: u64,
    ph: Phdr64,
) -> Result<Option<MappedRange>, &'static str> {
    if ph.p_filesz > ph.p_memsz {
        return Err("PT_LOAD filesz > memsz");
    }
    if let Some(len) = known_len {
        if ph
            .p_offset
            .checked_add(ph.p_filesz)
            .is_none_or(|end| end > len)
        {
            return Err("corrupt PT_LOAD bounds");
        }
    }
    let seg_vaddr = bias.wrapping_add(ph.p_vaddr);
    let page_start = align_down(seg_vaddr, PAGE_SIZE);
    let page_end = align_up(seg_vaddr.saturating_add(ph.p_memsz), PAGE_SIZE);
    if page_end <= page_start {
        return Ok(None);
    }
    let map_len = page_end - page_start;
    let vmo_flags = if ph.p_flags & PF_X != 0 {
        vmo_create_flags::EXECUTABLE
    } else {
        0
    };
    let seg_vmo =
        Vmo::create_with_flags(map_len, vmo_flags).map_err(|_| "Vmo::create_with_flags failed")?;

    if ph.p_filesz > 0 {
        let mut buf = [0u8; 4096];
        let mut copied = 0u64;
        let vmo_file_off = seg_vaddr - page_start;
        while copied < ph.p_filesz {
            let chunk = (ph.p_filesz - copied).min(buf.len() as u64) as usize;
            let src_off = elf_off + ph.p_offset + copied;
            if vmo.read(src_off, &mut buf[..chunk]).ok() != Some(chunk)
                || seg_vmo.write(vmo_file_off + copied, &buf[..chunk]).ok() != Some(chunk)
            {
                return Err("failed copying shared object segment");
            }
            copied += chunk as u64;
        }
    }

    let mut flags = vmar_flags::USER | vmar_flags::SPECIFIC;
    if ph.p_flags & PF_R != 0 {
        flags |= vmar_flags::READ;
    }
    if ph.p_flags & PF_W != 0 {
        flags |= vmar_flags::WRITE;
    }
    if ph.p_flags & PF_X != 0 {
        flags |= vmar_flags::EXECUTE;
    }
    self_vmar
        .map(&seg_vmo, 0, page_start, map_len, flags)
        .map_err(|_| "Vmar::map shared object failed")?;
    Ok(Some(MappedRange {
        va: page_start,
        len: map_len,
    }))
}

fn compute_initial_static_tls(state: &mut RtldState) {
    let mut total_size = 0u64;
    let mut max_align = 16u64;

    for idx in 0..MAX_OBJECTS {
        if !state.objects[idx].active {
            continue;
        }
        if let Some(tls) = state.objects[idx].tls {
            let align = if tls.align.is_power_of_two() {
                tls.align
            } else {
                16
            };
            if align > max_align {
                max_align = align;
            }
            total_size = align_up(total_size + tls.memsz, align);
            state.objects[idx].tls_tp_offset = total_size;
            if state.objects[idx].tls_modid == 0 {
                if let Some(modid) = alloc_tls_modid(state) {
                    state.objects[idx].tls_modid = modid;
                }
            }
        }
    }
    state.static_tls_total = total_size;
    state.static_tls_align = max_align;
}

fn allocate_thread_tls_locked(state: &RtldState) -> Result<u64, &'static str> {
    let Some(self_vmar) = state.self_vmar.as_ref() else {
        return Err("missing self VMAR for thread TLS");
    };
    let tcb_size = core::mem::size_of::<ThreadControlBlock>() as u64;
    let total_size = state.static_tls_total;
    let max_align = state.static_tls_align.max(16);
    let alloc_len = align_up(total_size + tcb_size + max_align, PAGE_SIZE);
    let tls_base = choose_aslr_region(TLS_ASLR_BASE, TLS_ASLR_MASK, alloc_len, &state.objects)
        .ok_or("TLS ASLR region exhausted")?;
    let tls_vmo = Vmo::create(alloc_len).map_err(|_| "failed allocating thread TLS VMO")?;
    let flags = vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC;
    self_vmar
        .map(&tls_vmo, 0, tls_base, alloc_len, flags)
        .map_err(|_| "failed mapping thread TLS VMO")?;

    let tp = align_up(tls_base + total_size, max_align);
    let tcb_ptr = tp as *mut ThreadControlBlock;
    // SAFETY: `tp..tp+tcb_size` lies inside the freshly mapped zeroed writable TLS VMO.
    unsafe {
        ptr::write(
            tcb_ptr,
            ThreadControlBlock {
                self_ptr: tp,
                dtv_ptr: ptr::null_mut(),
                magic: TCB_MAGIC,
                map_base: tls_base,
                map_len: alloc_len,
                dtv: [0; MAX_OBJECTS + 1],
                dyn_allocs: [0; MAX_OBJECTS + 1],
                mod_gens: [0; MAX_OBJECTS + 1],
                dlerror_pending: 0,
                dlerror_buf: [0; DLERROR_CAP],
            },
        );
        (*tcb_ptr).dtv_ptr = (*tcb_ptr).dtv.as_mut_ptr();
        (*tcb_ptr).dtv[0] = state.tls_gen;
    }

    for obj in &state.objects {
        if !obj.active || obj.tls_tp_offset == 0 {
            continue;
        }
        if let Some(tls) = obj.tls {
            let block_addr = tp - obj.tls_tp_offset;
            if tls.filesz > 0 {
                let dst = block_addr as *mut u8;
                let src = obj.bias.wrapping_add(tls.vaddr) as *const u8;
                // SAFETY: `src` is inside mapped `.tdata` and `dst` is inside the thread TLS VMO.
                unsafe { ptr::copy_nonoverlapping(src, dst, tls.filesz as usize) };
            }
            if obj.tls_modid > 0 && obj.tls_modid <= MAX_OBJECTS {
                // SAFETY: `tcb_ptr` is initialized and writable.
                unsafe {
                    (*tcb_ptr).dtv[obj.tls_modid] = block_addr;
                    (*tcb_ptr).mod_gens[obj.tls_modid] = state.modid_gen[obj.tls_modid];
                }
            }
        }
    }

    Ok(tp)
}

#[inline]
fn current_tp() -> u64 {
    let tp: u64;
    // SAFETY: reading `%fs:0` returns `0` when `FS_BASE == 0` or the TCB `self_ptr`.
    // Wait: if `FS_BASE == 0`, reading `%fs:0` would dereference linear 0 and #PF!
    // Check `rdmsr`/`fsbase`? Ring-3 cannot read MSR directly unless `rdfsbase`
    // is enabled, OR `ThreadControlBlock` is ALWAYS mapped on initial thread AND
    // secondary threads! Since `ld_main` unconditionally allocates `tcb` and sets
    // `FS_BASE = tp` before running ANY `.init_array` or user code, `%fs:0` is
    // non-zero on every thread of every dynamic process!
    unsafe {
        core::arch::asm!("mov {}, fs:[0]", out(reg) tp, options(nostack, readonly, preserves_flags));
    }
    tp
}

unsafe extern "C" fn rtld_tls_get_addr(ti_raw: *const u8) -> *mut u8 {
    if ti_raw.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: ELF64 `__tls_get_addr` argument points to `TlsIndex { usize, usize }`.
    let ti = unsafe { &*(ti_raw as *const TlsIndex) };
    let modid = ti.ti_module;
    if modid == 0 || modid > MAX_OBJECTS {
        return ptr::null_mut();
    }

    let tp = current_tp();
    if tp == 0 {
        return ptr::null_mut();
    }
    let tcb = tp as *mut ThreadControlBlock;
    // SAFETY: `tp` points to this thread's live `ThreadControlBlock`.
    unsafe {
        if (*tcb).magic != TCB_MAGIC {
            return ptr::null_mut();
        }
        let fast_gen = TLS_GEN_FAST.load(Ordering::Acquire);
        if (*tcb).dtv[0] == fast_gen {
            let block = (*tcb).dtv[modid];
            if block != 0 {
                return (block as *mut u8).add(ti.ti_offset);
            }
        }
    }

    // Slow path: synchronize DTV and allocate dynamic TLS block on first touch in this thread.
    let block_addr = RTLD_STATE.with(|state| {
        // Refresh static/valid entries and free stale modids whose generation changed.
        for m in 1..=MAX_OBJECTS {
            // SAFETY: exclusive per-thread access to this thread's TCB slots.
            unsafe {
                if (*tcb).mod_gens[m] != state.modid_gen[m] {
                    let old_dyn = (*tcb).dyn_allocs[m];
                    if old_dyn != 0 {
                        if let Some(free_fn) = state.host_free {
                            free_fn(old_dyn as *mut u8);
                        }
                        (*tcb).dyn_allocs[m] = 0;
                    }
                    (*tcb).dtv[m] = 0;
                    (*tcb).mod_gens[m] = 0;
                }
            }
        }
        // SAFETY: `tcb` belongs to the calling thread.
        unsafe { (*tcb).dtv[0] = state.tls_gen };

        // SAFETY: `tcb` belongs to the calling thread.
        let existing = unsafe { (*tcb).dtv[modid] };
        if existing != 0 {
            return existing;
        }

        let target_obj = state
            .objects
            .iter()
            .find(|o| o.active && o.tls_modid == modid);
        let Some(obj) = target_obj else {
            return 0;
        };
        let Some(tls) = obj.tls else {
            return 0;
        };
        if obj.tls_tp_offset != 0 {
            let addr = tp - obj.tls_tp_offset;
            // SAFETY: `tcb` belongs to the calling thread.
            unsafe {
                (*tcb).dtv[modid] = addr;
                (*tcb).mod_gens[modid] = state.modid_gen[modid];
            }
            return addr;
        }

        let Some(alloc_fn) = state.host_alloc else {
            return 0;
        };
        let size = (tls.memsz as usize).max(1);
        let align = (tls.align as usize).max(16);
        // SAFETY: `host_alloc` is `libcanvas.so`'s `canvas_alloc`.
        let block = unsafe { alloc_fn(size, align) };
        if block.is_null() {
            return 0;
        }
        // SAFETY: `block..block+size` is freshly allocated writable memory.
        unsafe {
            ptr::write_bytes(block, 0, size);
            if tls.filesz > 0 {
                let copy_len = (tls.filesz as usize).min(size);
                let src = obj.bias.wrapping_add(tls.vaddr) as *const u8;
                ptr::copy_nonoverlapping(src, block, copy_len);
            }
            (*tcb).dtv[modid] = block as u64;
            (*tcb).dyn_allocs[modid] = block as u64;
            (*tcb).mod_gens[modid] = state.modid_gen[modid];
        }
        block as u64
    });

    if block_addr == 0 {
        ptr::null_mut()
    } else {
        // SAFETY: `ti.ti_offset` is within the TLS block of `modid`.
        unsafe { (block_addr as *mut u8).add(ti.ti_offset) }
    }
}

unsafe extern "C" fn rtld_alloc_thread_tls() -> u64 {
    RTLD_STATE.with(|state| allocate_thread_tls_locked(state).unwrap_or(0))
}

unsafe extern "C" fn rtld_free_thread_tls(tp_arg: u64) {
    let tp = if tp_arg == 0 { current_tp() } else { tp_arg };
    if tp == 0 {
        return;
    }
    let tcb = tp as *mut ThreadControlBlock;
    // SAFETY: `tp` is the exiting thread's `ThreadControlBlock`.
    let (map_base, map_len, valid) = unsafe {
        if (*tcb).magic != TCB_MAGIC {
            (0, 0, false)
        } else {
            (*tcb).magic = 0;
            ((*tcb).map_base, (*tcb).map_len, true)
        }
    };
    if !valid {
        return;
    }
    RTLD_STATE.with(|state| {
        if let Some(free_fn) = state.host_free {
            for m in 1..=MAX_OBJECTS {
                // SAFETY: `tcb` belongs exclusively to this exiting thread.
                let ptr_u64 = unsafe { (*tcb).dyn_allocs[m] };
                if ptr_u64 != 0 {
                    // SAFETY: `ptr_u64` was returned by `host_alloc`.
                    unsafe { free_fn(ptr_u64 as *mut u8) };
                }
            }
        }
        if tp_arg == 0 {
            let _ = process::set_fs_base(0);
        }
        if let Some(ref vmar) = state.self_vmar {
            if map_len > 0 {
                let _ = vmar.unmap(map_base, map_len);
            }
        }
    });
}

fn set_dlerror(msg: &[u8]) {
    let tp = current_tp();
    if tp != 0 {
        let tcb = tp as *mut ThreadControlBlock;
        // SAFETY: `tcb` is this thread's own `ThreadControlBlock`.
        unsafe {
            if (*tcb).magic == TCB_MAGIC {
                let n = msg.len().min(DLERROR_CAP - 1);
                let buf = ptr::addr_of_mut!((*tcb).dlerror_buf) as *mut u8;
                ptr::copy_nonoverlapping(msg.as_ptr(), buf, n);
                *buf.add(n) = 0;
                (*tcb).dlerror_pending = 1;
                return;
            }
        }
    }
    RTLD_STATE.with(|state| {
        let n = msg.len().min(DLERROR_CAP - 1);
        state.fallback_dlerror_buf[..n].copy_from_slice(&msg[..n]);
        state.fallback_dlerror_buf[n] = 0;
        state.fallback_dlerror_pending = true;
    });
}

fn set_dlerror_str(msg: &str) {
    set_dlerror(msg.as_bytes());
}

unsafe extern "C" fn rtld_dlerror() -> *const c_char {
    let tp = current_tp();
    if tp != 0 {
        let tcb = tp as *mut ThreadControlBlock;
        // SAFETY: `tcb` is this thread's own `ThreadControlBlock`.
        unsafe {
            if (*tcb).magic == TCB_MAGIC {
                if (*tcb).dlerror_pending == 0 {
                    return ptr::null();
                }
                (*tcb).dlerror_pending = 0;
                return (*tcb).dlerror_buf.as_ptr().cast::<c_char>();
            }
        }
    }
    RTLD_STATE.with(|state| {
        if !state.fallback_dlerror_pending {
            return ptr::null();
        }
        state.fallback_dlerror_pending = false;
        state.fallback_dlerror_buf.as_ptr().cast::<c_char>()
    })
}

fn encode_dl_handle(slot: usize, gen_id: u32) -> *mut c_void {
    let raw = ((gen_id as usize) << 16) | (slot + 1);
    raw as *mut c_void
}

fn decode_dl_handle(handle: *mut c_void) -> Option<(usize, u32)> {
    let raw = handle as usize;
    if raw == 0 {
        return None;
    }
    let slot = (raw & 0xffff).checked_sub(1)?;
    let gen_id = (raw >> 16) as u32;
    if slot >= MAX_OBJECTS || gen_id == 0 {
        return None;
    }
    Some((slot, gen_id))
}

fn duplicate_borrowed_handle(raw: HandleValue) -> Option<Handle> {
    if raw == huesos_abi::INVALID_HANDLE {
        return None;
    }
    // SAFETY: `borrowed` wraps caller's raw handle solely to duplicate it and is
    // forgotten immediately so caller retains ownership.
    let borrowed = core::mem::ManuallyDrop::new(unsafe { Handle::from_raw(raw) });
    borrowed.duplicate(huesos_abi::rights::SAME_RIGHTS).ok()
}

unsafe extern "C" fn rtld_dl_set_lib_dir(hxfs_dir_ch: u32) -> i32 {
    let Some(dup) = duplicate_borrowed_handle(hxfs_dir_ch) else {
        set_dlerror_str("invalid or non-duplicable HxfsDirectory handle");
        return -1;
    };
    RTLD_STATE.with(|state| {
        state.hxfs_dir = Some(HxfsDirectory::from_channel(Channel::from_handle(dup)));
    });
    0
}

unsafe extern "C" fn rtld_dl_set_hxfs_service(hxfs_service_ch: u32) -> i32 {
    let Some(dup) = duplicate_borrowed_handle(hxfs_service_ch) else {
        set_dlerror_str("invalid or non-duplicable Hxfs service handle");
        return -1;
    };
    RTLD_STATE.with(|state| {
        state.hxfs_service = Some(Hxfs::from_channel(Channel::from_handle(dup)));
    });
    0
}

#[derive(Clone, Copy)]
struct CtorSnapshot {
    init: u64,
    init_array: u64,
    init_arraysz: u64,
}

#[derive(Clone, Copy)]
struct FiniSnapshot {
    fini: u64,
    fini_array: u64,
    fini_arraysz: u64,
}

fn snapshot_object_inits(obj: &LoadedObject) -> CtorSnapshot {
    CtorSnapshot {
        init: if obj.summary.init != 0 {
            obj.bias.wrapping_add(obj.summary.init)
        } else {
            0
        },
        init_array: if obj.summary.init_array != 0 {
            obj.bias.wrapping_add(obj.summary.init_array)
        } else {
            0
        },
        init_arraysz: obj.summary.init_arraysz,
    }
}

fn snapshot_object_finis(obj: &LoadedObject) -> FiniSnapshot {
    FiniSnapshot {
        fini: if obj.summary.fini != 0 {
            obj.bias.wrapping_add(obj.summary.fini)
        } else {
            0
        },
        fini_array: if obj.summary.fini_array != 0 {
            obj.bias.wrapping_add(obj.summary.fini_array)
        } else {
            0
        },
        fini_arraysz: obj.summary.fini_arraysz,
    }
}

fn run_ctor_snapshot(snap: &CtorSnapshot) {
    if snap.init != 0 {
        // SAFETY: `DT_INIT` is an `extern "C" fn()` function inside the mapped segment.
        let func: extern "C" fn() = unsafe { core::mem::transmute(snap.init) };
        func();
    }
    if snap.init_array != 0 && snap.init_arraysz != 0 {
        let count = (snap.init_arraysz as usize) / core::mem::size_of::<u64>();
        // SAFETY: `DT_INIT_ARRAY` holds `count` relocated constructor function pointers.
        let funcs = unsafe { slice::from_raw_parts(snap.init_array as *const u64, count) };
        for &fn_addr in funcs {
            if fn_addr != 0 && fn_addr != u64::MAX {
                // SAFETY: each non-sentinel `.init_array` entry is an `extern "C" fn()`.
                let func: extern "C" fn() = unsafe { core::mem::transmute(fn_addr) };
                func();
            }
        }
    }
}

fn run_fini_snapshot(snap: &FiniSnapshot) {
    if snap.fini_array != 0 && snap.fini_arraysz != 0 {
        let count = (snap.fini_arraysz as usize) / core::mem::size_of::<u64>();
        // SAFETY: `DT_FINI_ARRAY` holds `count` relocated destructor function pointers.
        let funcs = unsafe { slice::from_raw_parts(snap.fini_array as *const u64, count) };
        let mut i = count;
        while i > 0 {
            i -= 1;
            let fn_addr = funcs[i];
            if fn_addr != 0 && fn_addr != u64::MAX {
                // SAFETY: each non-sentinel `.fini_array` entry is an `extern "C" fn()`.
                let func: extern "C" fn() = unsafe { core::mem::transmute(fn_addr) };
                func();
            }
        }
    }
    if snap.fini != 0 {
        // SAFETY: `DT_FINI` is an `extern "C" fn()` function inside the mapped segment.
        let func: extern "C" fn() = unsafe { core::mem::transmute(snap.fini) };
        func();
    }
}

fn load_deps_and_finish_dlopen(
    state: &mut RtldState,
    root_slot: usize,
    flags: i32,
    ctors_out: &mut [CtorSnapshot; MAX_OBJECTS],
    ctor_count_out: &mut usize,
) -> Result<*mut c_void, &'static str> {
    let mut new_slots = [0usize; MAX_OBJECTS];
    let mut new_count = 0usize;
    new_slots[new_count] = root_slot;
    new_count += 1;

    let mut inc_deps = [0usize; MAX_OBJECTS];
    let mut inc_count = 0usize;

    let pinned = (flags & RTLD_NODELETE) != 0;
    let global = (flags & RTLD_GLOBAL) != 0;

    let mut queue = [0usize; MAX_OBJECTS];
    let mut q_head = 0usize;
    let mut q_tail = 0usize;
    queue[q_tail] = root_slot;
    q_tail += 1;

    let res: Result<(), &'static str> = (|| {
        while q_head < q_tail {
            let cur_slot = queue[q_head];
            q_head += 1;

            let needed_count = state.objects[cur_slot].summary.needed_count;
            let needed_offs = state.objects[cur_slot].summary.needed_offs;
            let strtab_addr = state.objects[cur_slot].bias + state.objects[cur_slot].summary.strtab;
            let strsz = state.objects[cur_slot].summary.strsz as usize;

            for &off in &needed_offs[..needed_count] {
                let soname =
                    read_cstr_slice(strtab_addr, strsz, off).ok_or("invalid DT_NEEDED string")?;
                if !validate_soname(soname) {
                    return Err("invalid DT_NEEDED SONAME");
                }
                let dep_slot = if let Some(existing) = find_loaded_by_name(&state.objects, soname) {
                    state.objects[existing].refcount =
                        state.objects[existing].refcount.saturating_add(1);
                    if global {
                        state.objects[existing].global = true;
                    }
                    if pinned {
                        state.objects[existing].pinned = true;
                    }
                    if inc_count < MAX_OBJECTS {
                        inc_deps[inc_count] = existing;
                        inc_count += 1;
                    }
                    existing
                } else {
                    let slot = alloc_object_slot(&mut state.objects)
                        .ok_or("shared object limit reached")?;
                    let mut dep_obj = load_soname_object_locked(state, soname, pinned, global)?;
                    dep_obj.gen_id = state.objects[slot].gen_id;
                    dep_obj.refcount = 1;
                    state.objects[slot] = dep_obj;
                    if new_count < MAX_OBJECTS {
                        new_slots[new_count] = slot;
                        new_count += 1;
                    }
                    if q_tail < MAX_OBJECTS {
                        queue[q_tail] = slot;
                        q_tail += 1;
                    }
                    slot
                };
                record_dep(&mut state.objects[cur_slot], dep_slot);
            }
        }

        // Validate symbol versions for all newly loaded objects.
        for &slot in &new_slots[..new_count] {
            validate_object_versions(&state.objects[slot], &state.objects)?;
        }

        // Apply eager relocations (`BIND_NOW`) for all newly loaded objects.
        for &slot in &new_slots[..new_count] {
            apply_object_relocations(slot, &state.objects)?;
        }

        // Apply `PT_GNU_RELRO`.
        if let Some(ref vmar) = state.self_vmar {
            for &slot in &new_slots[..new_count] {
                protect_object_relro(vmar, &state.objects[slot])?;
            }
        }

        Ok(())
    })();

    if let Err(msg) = res {
        // Roll back newly mapped objects and dependency refcount increments.
        for &slot in &inc_deps[..inc_count] {
            state.objects[slot].refcount = state.objects[slot].refcount.saturating_sub(1);
        }
        for &slot in &new_slots[..new_count] {
            if let Some(ref vmar) = state.self_vmar {
                unmap_object_ranges(vmar, &state.objects[slot]);
            }
            let modid = state.objects[slot].tls_modid;
            if modid > 0 && modid <= MAX_OBJECTS {
                state.modid_gen[modid] = 0;
            }
            let next_gen = state.objects[slot].gen_id.wrapping_add(1).max(1);
            state.objects[slot] = LoadedObject::empty();
            state.objects[slot].gen_id = next_gen;
        }
        return Err(msg);
    }

    state.dl_adds = state.dl_adds.saturating_add(new_count as u64);

    // Dependency-first constructor order (reverse BFS order).
    let mut c = 0usize;
    let mut i = new_count;
    while i > 0 {
        i -= 1;
        let slot = new_slots[i];
        if !state.objects[slot].init_run {
            state.objects[slot].init_run = true;
            ctors_out[c] = snapshot_object_inits(&state.objects[slot]);
            c += 1;
        }
    }
    *ctor_count_out = c;

    Ok(encode_dl_handle(root_slot, state.objects[root_slot].gen_id))
}

unsafe extern "C" fn rtld_dlopen_soname(soname_ptr: *const c_char, flags: i32) -> *mut c_void {
    if soname_ptr.is_null() {
        set_dlerror_str("NULL SONAME");
        return ptr::null_mut();
    }
    // SAFETY: caller provides a NUL-terminated SONAME string.
    let soname = unsafe { read_caller_cstr(soname_ptr, MAX_NAME_LEN) };
    let Some(soname) = soname else {
        set_dlerror_str("invalid or overlong SONAME");
        return ptr::null_mut();
    };
    if !validate_soname(soname) {
        set_dlerror_str("invalid SONAME (path traversal rejected)");
        return ptr::null_mut();
    }

    let mut ctors = [CtorSnapshot {
        init: 0,
        init_array: 0,
        init_arraysz: 0,
    }; MAX_OBJECTS];
    let mut ctor_count = 0usize;

    let res = RTLD_STATE.with(|state| {
        if let Some(existing) = find_loaded_by_name(&state.objects, soname) {
            state.objects[existing].refcount = state.objects[existing].refcount.saturating_add(1);
            if (flags & RTLD_GLOBAL) != 0 {
                state.objects[existing].global = true;
            }
            if (flags & RTLD_NODELETE) != 0 {
                state.objects[existing].pinned = true;
            }
            return Ok(Some(encode_dl_handle(
                existing,
                state.objects[existing].gen_id,
            )));
        }
        if (flags & RTLD_NOLOAD) != 0 {
            return Ok(None);
        }
        let slot = alloc_object_slot(&mut state.objects).ok_or("shared object limit reached")?;
        let pinned = (flags & RTLD_NODELETE) != 0;
        let global = (flags & RTLD_GLOBAL) != 0;
        let mut obj = load_soname_object_locked(state, soname, pinned, global)?;
        obj.gen_id = state.objects[slot].gen_id;
        obj.refcount = 1;
        state.objects[slot] = obj;
        load_deps_and_finish_dlopen(state, slot, flags, &mut ctors, &mut ctor_count).map(Some)
    });

    match res {
        Ok(Some(handle)) => {
            for ctor in &ctors[..ctor_count] {
                run_ctor_snapshot(ctor);
            }
            handle
        }
        Ok(None) => ptr::null_mut(),
        Err(msg) => {
            set_dlerror_str(msg);
            ptr::null_mut()
        }
    }
}

unsafe extern "C" fn rtld_dlopen_vmo(vmo_handle: u32, flags: i32) -> *mut c_void {
    if vmo_handle == huesos_abi::INVALID_HANDLE {
        set_dlerror_str("invalid VMO handle");
        return ptr::null_mut();
    }
    // SAFETY: `vmo_borrowed` wraps caller's handle only for mapping and is never dropped.
    let vmo_borrowed = core::mem::ManuallyDrop::new(unsafe { Vmo::from_raw(vmo_handle) });
    dlopen_from_vmo_impl(&vmo_borrowed, flags, b"<vmo>")
}

unsafe extern "C" fn rtld_dlopen_blob(blob_view_ch: u32, flags: i32) -> *mut c_void {
    if blob_view_ch == huesos_abi::INVALID_HANDLE {
        set_dlerror_str("invalid BlobView channel handle");
        return ptr::null_mut();
    }
    // SAFETY: `blob_borrowed` wraps caller's handle only to stream its bytes into a VMO.
    let mut blob_borrowed =
        core::mem::ManuallyDrop::new(HxfsBlobView::from_channel(Channel::from_handle(unsafe {
            Handle::from_raw(blob_view_ch)
        })));
    let Ok(vmo) = blob_borrowed.read_into_vmo() else {
        set_dlerror_str("failed reading HxFS BlobView into VMO");
        return ptr::null_mut();
    };
    dlopen_from_vmo_impl(&vmo, flags, b"<blob>")
}

fn dlopen_from_vmo_impl(vmo: &Vmo, flags: i32, fallback_name: &[u8]) -> *mut c_void {
    let mut ctors = [CtorSnapshot {
        init: 0,
        init_array: 0,
        init_arraysz: 0,
    }; MAX_OBJECTS];
    let mut ctor_count = 0usize;

    let res = RTLD_STATE.with(|state| {
        if (flags & RTLD_NOLOAD) != 0 {
            return Ok(None);
        }
        let slot = alloc_object_slot(&mut state.objects).ok_or("shared object limit reached")?;
        let mut obj = {
            let Some(self_vmar) = state.self_vmar.as_ref() else {
                return Err("missing self VMAR capability");
            };
            map_shared_object_from_vmo(self_vmar, vmo, 0, None, fallback_name, &state.objects)?
        };
        // Deduplicate by DT_SONAME if already loaded!
        if let Some(soname) = object_soname(&obj) {
            if let Some(existing) = find_loaded_by_name(&state.objects, soname) {
                if let Some(self_vmar) = state.self_vmar.as_ref() {
                    unmap_object_ranges(self_vmar, &obj);
                }
                state.objects[existing].refcount =
                    state.objects[existing].refcount.saturating_add(1);
                if (flags & RTLD_GLOBAL) != 0 {
                    state.objects[existing].global = true;
                }
                if (flags & RTLD_NODELETE) != 0 {
                    state.objects[existing].pinned = true;
                }
                return Ok(Some(encode_dl_handle(
                    existing,
                    state.objects[existing].gen_id,
                )));
            }
        }
        if obj.tls.is_some() {
            let Some(modid) = alloc_tls_modid(state) else {
                if let Some(self_vmar) = state.self_vmar.as_ref() {
                    unmap_object_ranges(self_vmar, &obj);
                }
                return Err("TLS module capacity exhausted");
            };
            obj.tls_modid = modid;
        }
        obj.pinned = (flags & RTLD_NODELETE) != 0;
        obj.global = (flags & RTLD_GLOBAL) != 0;
        obj.gen_id = state.objects[slot].gen_id;
        obj.refcount = 1;
        state.objects[slot] = obj;
        load_deps_and_finish_dlopen(state, slot, flags, &mut ctors, &mut ctor_count).map(Some)
    });

    match res {
        Ok(Some(handle)) => {
            for ctor in &ctors[..ctor_count] {
                run_ctor_snapshot(ctor);
            }
            handle
        }
        Ok(None) => ptr::null_mut(),
        Err(msg) => {
            set_dlerror_str(msg);
            ptr::null_mut()
        }
    }
}

unsafe extern "C" fn rtld_dlsym(handle: *mut c_void, symbol_ptr: *const c_char) -> *mut c_void {
    if symbol_ptr.is_null() {
        set_dlerror_str("NULL symbol name");
        return ptr::null_mut();
    }
    // SAFETY: caller provides a NUL-terminated symbol name.
    let Some(name) = (unsafe { read_caller_cstr(symbol_ptr, 256) }) else {
        set_dlerror_str("invalid or overlong symbol name");
        return ptr::null_mut();
    };

    let found = RTLD_STATE.with(|state| {
        if handle.is_null() {
            let mut weak_addr: Option<u64> = None;
            for obj in &state.objects {
                if !obj.active || !obj.global {
                    continue;
                }
                if let Some((_sidx, sym)) = lookup_in_object(obj, name, None, true) {
                    let addr = obj.bias.wrapping_add(sym.st_value);
                    if sym.binding() == STB_WEAK {
                        if weak_addr.is_none() {
                            weak_addr = Some(addr);
                        }
                    } else {
                        return Ok(Some(addr));
                    }
                }
            }
            return Ok(weak_addr);
        }

        let Some((root_slot, gen_id)) = decode_dl_handle(handle) else {
            return Err("invalid module handle");
        };
        if !state.objects[root_slot].active || state.objects[root_slot].gen_id != gen_id {
            return Err("stale or closed module handle");
        }

        let mut visited = [false; MAX_OBJECTS];
        let mut queue = [0usize; MAX_OBJECTS];
        let mut q_head = 0usize;
        let mut q_tail = 0usize;
        visited[root_slot] = true;
        queue[q_tail] = root_slot;
        q_tail += 1;

        let mut weak_addr: Option<u64> = None;
        while q_head < q_tail {
            let slot = queue[q_head];
            q_head += 1;
            let obj = &state.objects[slot];
            if obj.active {
                if let Some((_sidx, sym)) = lookup_in_object(obj, name, None, true) {
                    let addr = obj.bias.wrapping_add(sym.st_value);
                    if sym.binding() == STB_WEAK {
                        if weak_addr.is_none() {
                            weak_addr = Some(addr);
                        }
                    } else {
                        return Ok(Some(addr));
                    }
                }
                for &dep in &obj.deps[..obj.dep_count] {
                    if dep < MAX_OBJECTS && !visited[dep] && state.objects[dep].active {
                        visited[dep] = true;
                        queue[q_tail] = dep;
                        q_tail += 1;
                    }
                }
            }
        }
        Ok(weak_addr)
    });

    match found {
        Ok(Some(addr)) => addr as *mut c_void,
        Ok(None) => {
            set_dlerror_str("symbol not found");
            ptr::null_mut()
        }
        Err(msg) => {
            set_dlerror_str(msg);
            ptr::null_mut()
        }
    }
}

unsafe extern "C" fn rtld_dlclose(handle: *mut c_void) -> i32 {
    let Some((root_slot, gen_id)) = decode_dl_handle(handle) else {
        set_dlerror_str("invalid module handle");
        return -1;
    };

    let mut unload_slots = [0usize; MAX_OBJECTS];
    let mut unload_count = 0usize;
    let mut finis = [FiniSnapshot {
        fini: 0,
        fini_array: 0,
        fini_arraysz: 0,
    }; MAX_OBJECTS];
    let mut atexit_batch = [AtExitEntry::empty(); MAX_ATEXIT];
    let mut atexit_count = 0usize;

    let check = RTLD_STATE.with(|state| {
        if !state.objects[root_slot].active || state.objects[root_slot].gen_id != gen_id {
            return Err("stale or closed module handle");
        }
        if state.objects[root_slot].pinned {
            return Ok(false);
        }
        state.objects[root_slot].refcount = state.objects[root_slot].refcount.saturating_sub(1);
        if state.objects[root_slot].refcount > 0 {
            return Ok(false);
        }

        // Propagate zero-refcount cascade through dependencies (parents first).
        let mut marked = [false; MAX_OBJECTS];
        marked[root_slot] = true;
        unload_slots[unload_count] = root_slot;
        unload_count += 1;

        let mut scan = 0usize;
        while scan < unload_count {
            let slot = unload_slots[scan];
            scan += 1;
            let dep_count = state.objects[slot].dep_count;
            let deps = state.objects[slot].deps;
            for &dep in &deps[..dep_count] {
                if dep < MAX_OBJECTS && state.objects[dep].active && !state.objects[dep].pinned {
                    state.objects[dep].refcount = state.objects[dep].refcount.saturating_sub(1);
                    if state.objects[dep].refcount == 0 && !marked[dep] {
                        marked[dep] = true;
                        unload_slots[unload_count] = dep;
                        unload_count += 1;
                    }
                }
            }
        }

        for i in 0..unload_count {
            let slot = unload_slots[i];
            state.objects[slot].fini_run = true;
            finis[i] = snapshot_object_finis(&state.objects[slot]);

            // Drain matching `__cxa_atexit` callbacks in LIFO order.
            let min_va = state.objects[slot].min_va;
            let max_va = state.objects[slot].max_va;
            let mut a = state.atexit_len;
            while a > 0 {
                a -= 1;
                if state.atexit[a].active {
                    let dso = state.atexit[a].dso_handle as u64;
                    let fn_u64 = state.atexit[a].func.map_or(0, |f| f as usize as u64);
                    if (dso >= min_va && dso < max_va) || (fn_u64 >= min_va && fn_u64 < max_va) {
                        atexit_batch[atexit_count] = state.atexit[a];
                        atexit_count += 1;
                        state.atexit[a].active = false;
                    }
                }
            }
        }
        Ok(true)
    });

    match check {
        Err(msg) => {
            set_dlerror_str(msg);
            return -1;
        }
        Ok(false) => return 0,
        Ok(true) => {}
    }

    // Run matching `__cxa_atexit` callbacks and `DT_FINI_ARRAY`/`DT_FINI` outside lock.
    for entry in &atexit_batch[..atexit_count] {
        if let Some(func) = entry.func {
            // SAFETY: registered via `__cxa_atexit` for this unloading DSO.
            unsafe { func(entry.arg) };
        }
    }
    for fini in &finis[..unload_count] {
        run_fini_snapshot(fini);
    }

    // Unmap unloaded segments and reclaim slots/TLS modids.
    RTLD_STATE.with(|state| {
        let mut tls_changed = false;
        for &slot in &unload_slots[..unload_count] {
            if let Some(ref vmar) = state.self_vmar {
                unmap_object_ranges(vmar, &state.objects[slot]);
            }
            let modid = state.objects[slot].tls_modid;
            if modid > 0 && modid <= MAX_OBJECTS {
                state.modid_gen[modid] = 0;
                tls_changed = true;
            }
            let next_gen = state.objects[slot].gen_id.wrapping_add(1).max(1);
            state.objects[slot] = LoadedObject::empty();
            state.objects[slot].gen_id = next_gen;
        }
        if tls_changed {
            state.tls_gen = state.tls_gen.saturating_add(1);
            TLS_GEN_FAST.store(state.tls_gen, Ordering::Release);
        }
        state.dl_subs = state.dl_subs.saturating_add(unload_count as u64);
    });
    0
}

unsafe extern "C" fn rtld_dladdr(addr: *const c_void, info: *mut CanvasDlInfo) -> i32 {
    if addr.is_null() || info.is_null() {
        return 0;
    }
    let query = addr as u64;
    RTLD_STATE.with(|state| {
        for obj in &state.objects {
            if !obj.active || query < obj.min_va || query >= obj.max_va {
                continue;
            }
            let mut best_addr = 0u64;
            let mut best_name: *const c_char = ptr::null();
            if obj.summary.symtab != 0 && obj.summary.strtab != 0 && obj.sym_count > 0 {
                let syms_ptr = (obj.bias + obj.summary.symtab) as *const Sym64;
                let strtab_ptr = (obj.bias + obj.summary.strtab) as *const u8;
                let strsz = obj.summary.strsz as usize;
                // SAFETY: `DT_SYMTAB` and `DT_STRTAB` reside within `obj`'s mapped segments.
                let (syms, strtab) = unsafe {
                    (
                        slice::from_raw_parts(syms_ptr, obj.sym_count),
                        slice::from_raw_parts(strtab_ptr, strsz),
                    )
                };
                for sym in syms {
                    if !sym.is_defined() || sym.binding() == STB_LOCAL || sym.st_name == 0 {
                        continue;
                    }
                    let sym_va = obj.bias.wrapping_add(sym.st_value);
                    if sym_va <= query && sym_va >= best_addr {
                        if let Some(cstr) = cstr_at(strtab, u64::from(sym.st_name)) {
                            best_addr = sym_va;
                            best_name = cstr.as_ptr().cast::<c_char>();
                        }
                    }
                }
            }
            // SAFETY: caller passed valid writable `CanvasDlInfo`.
            unsafe {
                (*info).dli_fname = obj.name.as_ptr().cast::<c_char>();
                (*info).dli_fbase = obj.bias as *mut c_void;
                (*info).dli_sname = best_name;
                (*info).dli_saddr = best_addr as *mut c_void;
            }
            return 1;
        }
        0
    })
}

unsafe extern "C" fn rtld_dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut CanvasDlPhdrInfo, usize, *mut c_void) -> i32>,
    data: *mut c_void,
) -> i32 {
    let Some(callback) = callback else {
        return 0;
    };
    let mut infos = [CanvasDlPhdrInfo {
        dlpi_addr: 0,
        dlpi_name: ptr::null(),
        dlpi_phdr: ptr::null(),
        dlpi_phnum: 0,
        dlpi_adds: 0,
        dlpi_subs: 0,
        dlpi_tls_modid: 0,
        dlpi_tls_data: ptr::null_mut(),
    }; MAX_OBJECTS];
    let mut count = 0usize;

    let tp = current_tp();
    RTLD_STATE.with(|state| {
        for obj in &state.objects {
            if !obj.active {
                continue;
            }
            let tls_data = if obj.tls_modid > 0 && tp != 0 {
                let tcb = tp as *const ThreadControlBlock;
                // SAFETY: `tp` is the calling thread's `ThreadControlBlock`.
                unsafe {
                    if (*tcb).magic == TCB_MAGIC && obj.tls_modid <= MAX_OBJECTS {
                        (*tcb).dtv[obj.tls_modid] as *mut c_void
                    } else {
                        ptr::null_mut()
                    }
                }
            } else {
                ptr::null_mut()
            };
            infos[count] = CanvasDlPhdrInfo {
                dlpi_addr: obj.bias,
                dlpi_name: obj.name.as_ptr().cast::<c_char>(),
                dlpi_phdr: obj.phdr_addr as *const u8,
                dlpi_phnum: obj.phnum,
                dlpi_adds: state.dl_adds,
                dlpi_subs: state.dl_subs,
                dlpi_tls_modid: obj.tls_modid,
                dlpi_tls_data: tls_data,
            };
            count += 1;
        }
    });

    let info_size = core::mem::size_of::<CanvasDlPhdrInfo>();
    for info in &mut infos[..count] {
        // SAFETY: invoking caller-provided `dl_iterate_phdr` callback outside RTLD lock.
        let rc = unsafe { callback(info as *mut CanvasDlPhdrInfo, info_size, data) };
        if rc != 0 {
            return rc;
        }
    }
    0
}

unsafe extern "C" fn rtld_cxa_atexit(
    func: Option<unsafe extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    dso_handle: *mut c_void,
) -> i32 {
    if func.is_none() {
        return -1;
    }
    RTLD_STATE.with(|state| {
        if state.atexit_len >= MAX_ATEXIT {
            return -1;
        }
        let idx = state.atexit_len;
        state.atexit[idx] = AtExitEntry {
            active: true,
            func,
            arg,
            dso_handle,
        };
        state.atexit_len += 1;
        0
    })
}

unsafe extern "C" fn rtld_run_process_fini() {
    let mut atexit_batch = [AtExitEntry::empty(); MAX_ATEXIT];
    let mut atexit_count = 0usize;
    let mut finis = [FiniSnapshot {
        fini: 0,
        fini_array: 0,
        fini_arraysz: 0,
    }; MAX_OBJECTS];
    let mut fini_count = 0usize;

    let should_run = RTLD_STATE.with(|state| {
        if state.fini_started {
            return false;
        }
        state.fini_started = true;
        let mut a = state.atexit_len;
        while a > 0 {
            a -= 1;
            if state.atexit[a].active {
                atexit_batch[atexit_count] = state.atexit[a];
                atexit_count += 1;
                state.atexit[a].active = false;
            }
        }
        for obj in state.objects.iter_mut() {
            if obj.active && !obj.fini_run {
                obj.fini_run = true;
                finis[fini_count] = snapshot_object_finis(obj);
                fini_count += 1;
            }
        }
        true
    });

    if !should_run {
        return;
    }

    for entry in &atexit_batch[..atexit_count] {
        if let Some(func) = entry.func {
            // SAFETY: registered via `__cxa_atexit`/`atexit`.
            unsafe { func(entry.arg) };
        }
    }
    for fini in &finis[..fini_count] {
        run_fini_snapshot(fini);
    }
}

unsafe fn read_caller_cstr<'a>(ptr: *const c_char, max_len: usize) -> Option<&'a [u8]> {
    let bytes = ptr.cast::<u8>();
    for i in 0..max_len {
        // SAFETY: scanning caller-provided NUL-terminated string up to `max_len`.
        if unsafe { *bytes.add(i) } == 0 {
            // SAFETY: slice up to the terminating NUL is valid readable memory.
            return Some(unsafe { slice::from_raw_parts(bytes, i) });
        }
    }
    None
}

fn validate_object_versions(
    obj: &LoadedObject,
    objects: &[LoadedObject; MAX_OBJECTS],
) -> Result<(), &'static str> {
    if obj.summary.verneed == 0 || obj.summary.verneednum == 0 || obj.summary.strtab == 0 {
        return Ok(());
    }
    let verneed_va = obj.bias + obj.summary.verneed;
    let verneed_len = obj.max_va.saturating_sub(verneed_va) as usize;
    if verneed_len == 0 {
        return Err("DT_VERNEED out of bounds");
    }
    // SAFETY: `verneed_va..obj.max_va` lies inside `obj`'s mapped segment.
    let verneed_bytes = unsafe { slice::from_raw_parts(verneed_va as *const u8, verneed_len) };
    // SAFETY: `DT_STRTAB` is mapped for `strsz` bytes.
    let strtab = unsafe {
        slice::from_raw_parts(
            (obj.bias + obj.summary.strtab) as *const u8,
            obj.summary.strsz as usize,
        )
    };
    validate_verneed_table(
        verneed_bytes,
        obj.summary.verneednum as usize,
        strtab,
        |file_name| {
            let provider_idx = find_loaded_by_name(objects, file_name)?;
            let provider = &objects[provider_idx];
            if provider.summary.verdef == 0 || provider.summary.verdefnum == 0 {
                return None;
            }
            let verdef_va = provider.bias + provider.summary.verdef;
            let verdef_len = provider.max_va.saturating_sub(verdef_va) as usize;
            if verdef_len == 0 || provider.summary.strtab == 0 {
                return None;
            }
            // SAFETY: `verdef_va..provider.max_va` lies inside `provider`'s mapped segment.
            let verdef_bytes = unsafe { slice::from_raw_parts(verdef_va as *const u8, verdef_len) };
            // SAFETY: `DT_STRTAB` is mapped for `strsz` bytes.
            let p_strtab = unsafe {
                slice::from_raw_parts(
                    (provider.bias + provider.summary.strtab) as *const u8,
                    provider.summary.strsz as usize,
                )
            };
            Some((verdef_bytes, provider.summary.verdefnum as usize, p_strtab))
        },
    )
    .map_err(|_| "required ELF symbol version missing")
}

fn object_verdef_slice(obj: &LoadedObject) -> (&[u8], usize, &[u8]) {
    if obj.summary.verdef == 0 || obj.summary.verdefnum == 0 || obj.summary.strtab == 0 {
        return (&[], 0, &[]);
    }
    let verdef_va = obj.bias + obj.summary.verdef;
    let verdef_len = obj.max_va.saturating_sub(verdef_va) as usize;
    if verdef_len == 0 {
        return (&[], 0, &[]);
    }
    // SAFETY: `verdef_va..obj.max_va` lies inside `obj`'s mapped segment.
    let verdef_bytes = unsafe { slice::from_raw_parts(verdef_va as *const u8, verdef_len) };
    // SAFETY: `DT_STRTAB` is mapped for `strsz` bytes.
    let strtab = unsafe {
        slice::from_raw_parts(
            (obj.bias + obj.summary.strtab) as *const u8,
            obj.summary.strsz as usize,
        )
    };
    (verdef_bytes, obj.summary.verdefnum as usize, strtab)
}

fn object_versym_at(obj: &LoadedObject, sym_idx: usize) -> Option<u16> {
    if obj.summary.versym == 0 {
        return None;
    }
    let versym_ptr = (obj.bias + obj.summary.versym) as *const u16;
    // SAFETY: `DT_VERSYM` has one `u16` per `DT_SYMTAB` symbol.
    Some(unsafe { *versym_ptr.add(sym_idx) })
}

fn required_symbol_version(obj: &LoadedObject, sym_idx: usize) -> Option<(&[u8], u32)> {
    if obj.summary.versym == 0 || obj.summary.verneed == 0 || obj.summary.verneednum == 0 {
        return None;
    }
    let versym_ptr = (obj.bias + obj.summary.versym) as *const u16;
    // SAFETY: `DT_VERSYM` has one `u16` per `DT_SYMTAB` symbol.
    let ndx = unsafe { *versym_ptr.add(sym_idx) } & VERSYM_VERSION_MASK;
    if ndx <= 1 {
        return None;
    }
    let verneed_va = obj.bias + obj.summary.verneed;
    let verneed_len = obj.max_va.saturating_sub(verneed_va) as usize;
    if verneed_len == 0 {
        return None;
    }
    // SAFETY: `verneed_va..obj.max_va` lies inside `obj`'s mapped segment.
    let verneed_bytes = unsafe { slice::from_raw_parts(verneed_va as *const u8, verneed_len) };
    // SAFETY: `DT_STRTAB` is mapped for `strsz` bytes.
    let strtab = unsafe {
        slice::from_raw_parts(
            (obj.bias + obj.summary.strtab) as *const u8,
            obj.summary.strsz as usize,
        )
    };
    let (_lib_name, ver_name, ver_hash, _flags) =
        find_verneed_by_ndx(verneed_bytes, obj.summary.verneednum as usize, strtab, ndx)?;
    Some((ver_name, ver_hash))
}

fn apply_object_relocations(
    obj_idx: usize,
    objects: &[LoadedObject; MAX_OBJECTS],
) -> Result<(), &'static str> {
    let obj = &objects[obj_idx];
    if obj.summary.rela != 0 && obj.summary.relasz != 0 {
        let count = (obj.summary.relasz as usize) / core::mem::size_of::<Rela64>();
        let ptr = (obj.bias + obj.summary.rela) as *const Rela64;
        // SAFETY: `DT_RELA` lies inside the mapped ELF image.
        let relas = unsafe { slice::from_raw_parts(ptr, count) };
        apply_rela_slice(obj_idx, relas, objects)?;
    }
    if obj.summary.jmprel != 0 && obj.summary.pltrelsz != 0 && obj.summary.pltrel_is_rela {
        let count = (obj.summary.pltrelsz as usize) / core::mem::size_of::<Rela64>();
        let ptr = (obj.bias + obj.summary.jmprel) as *const Rela64;
        // SAFETY: `DT_JMPREL` lies inside the mapped ELF image.
        let relas = unsafe { slice::from_raw_parts(ptr, count) };
        apply_rela_slice(obj_idx, relas, objects)?;
    }
    Ok(())
}

fn apply_rela_slice(
    obj_idx: usize,
    relas: &[Rela64],
    objects: &[LoadedObject; MAX_OBJECTS],
) -> Result<(), &'static str> {
    let obj = &objects[obj_idx];
    for &rel in relas {
        let r_type = rel.reloc_type();
        let target = obj.bias.wrapping_add(rel.r_offset) as *mut u64;
        match r_type {
            r_x86_64::NONE => {}
            r_x86_64::RELATIVE => {
                let value = (obj.bias as i64).wrapping_add(rel.r_addend) as u64;
                // SAFETY: `target` is a relocatable slot inside `obj`'s writable data/GOT.
                unsafe { *target = value };
            }
            r_x86_64::IRELATIVE => {
                let resolver_addr = (obj.bias as i64).wrapping_add(rel.r_addend) as u64;
                // SAFETY: `IRELATIVE` resolver is an `extern "C" fn() -> u64` inside `obj`.
                let resolver: extern "C" fn() -> u64 =
                    unsafe { core::mem::transmute(resolver_addr) };
                let resolved = resolver();
                // SAFETY: `target` is the GOT slot for this IFUNC.
                unsafe { *target = resolved };
            }
            r_x86_64::R64 | r_x86_64::GLOB_DAT | r_x86_64::JUMP_SLOT => {
                let sym_idx = rel.sym_index() as usize;
                let (def_obj_idx, sym) = resolve_symbol_for_reloc(obj_idx, sym_idx, objects, false)
                    .ok_or("unresolved dynamic symbol")?;
                let sym_addr = objects[def_obj_idx].bias.wrapping_add(sym.st_value);
                let value = if r_type == r_x86_64::R64 {
                    (sym_addr as i64).wrapping_add(rel.r_addend) as u64
                } else {
                    sym_addr
                };
                // SAFETY: `target` is a relocatable GOT/data slot in `obj`.
                unsafe { *target = value };
            }
            r_x86_64::COPY => {
                let sym_idx = rel.sym_index() as usize;
                let (def_obj_idx, sym) = resolve_symbol_for_reloc(obj_idx, sym_idx, objects, true)
                    .ok_or("unresolved R_X86_64_COPY symbol")?;
                let src = objects[def_obj_idx].bias.wrapping_add(sym.st_value) as *const u8;
                let dst = target as *mut u8;
                // SAFETY: `R_X86_64_COPY` copies `st_size` bytes from defining `.so` to executable `.bss`.
                unsafe { ptr::copy_nonoverlapping(src, dst, sym.st_size as usize) };
            }
            r_x86_64::TPOFF64 => {
                let sym_idx = rel.sym_index() as usize;
                let (def_obj_idx, sym_val) = if sym_idx == 0 {
                    (obj_idx, 0u64)
                } else {
                    let (found_idx, sym) =
                        resolve_symbol_for_reloc(obj_idx, sym_idx, objects, false)
                            .ok_or("unresolved TPOFF64 symbol")?;
                    (found_idx, sym.st_value)
                };
                let def_obj = &objects[def_obj_idx];
                if def_obj.tls_tp_offset == 0 {
                    return Err("TPOFF64 references dynamic TLS module");
                }
                let tpoff = (sym_val as i64)
                    .wrapping_sub(def_obj.tls_tp_offset as i64)
                    .wrapping_add(rel.r_addend);
                // SAFETY: `target` is a GOT slot holding a Variant-II TP offset.
                unsafe { *target = tpoff as u64 };
            }
            r_x86_64::DTPMOD64 => {
                let sym_idx = rel.sym_index() as usize;
                let def_obj_idx = if sym_idx == 0 {
                    obj_idx
                } else {
                    let (found_idx, _sym) =
                        resolve_symbol_for_reloc(obj_idx, sym_idx, objects, false)
                            .ok_or("unresolved DTPMOD64 symbol")?;
                    found_idx
                };
                let modid = objects[def_obj_idx].tls_modid as u64;
                if modid == 0 {
                    return Err("DTPMOD64 target object has no PT_TLS");
                }
                // SAFETY: `target` is a GOT slot holding a `TlsIndex.ti_module` value.
                unsafe { *target = modid };
            }
            r_x86_64::DTPOFF64 => {
                let sym_idx = rel.sym_index() as usize;
                let sym_val = if sym_idx == 0 {
                    0u64
                } else {
                    let (_found_idx, sym) =
                        resolve_symbol_for_reloc(obj_idx, sym_idx, objects, false)
                            .ok_or("unresolved DTPOFF64 symbol")?;
                    sym.st_value
                };
                let dtpoff = (sym_val as i64).wrapping_add(rel.r_addend) as u64;
                // SAFETY: `target` is a GOT slot holding a `TlsIndex.ti_offset` value.
                unsafe { *target = dtpoff };
            }
            _ => {
                return Err("unsupported ELF64 relocation type");
            }
        }
    }
    Ok(())
}

fn resolve_symbol_for_reloc<'a>(
    req_obj_idx: usize,
    sym_idx: usize,
    objects: &'a [LoadedObject; MAX_OBJECTS],
    skip_main: bool,
) -> Option<(usize, &'a Sym64)> {
    let req_obj = &objects[req_obj_idx];
    if req_obj.summary.symtab == 0 || sym_idx >= req_obj.sym_count.max(sym_idx + 1) {
        return None;
    }
    let sym_ptr = (req_obj.bias + req_obj.summary.symtab) as *const Sym64;
    // SAFETY: `sym_idx` is taken from an ELF relocation in `req_obj` pointing into `DT_SYMTAB`.
    let req_sym = unsafe { &*sym_ptr.add(sym_idx) };
    if req_sym.is_defined() && (req_sym.binding() == STB_LOCAL || req_sym.st_name == 0) {
        return Some((req_obj_idx, req_sym));
    }
    if req_sym.st_name == 0 {
        return None;
    }
    let name = read_cstr_slice(
        req_obj.bias + req_obj.summary.strtab,
        req_obj.summary.strsz as usize,
        u64::from(req_sym.st_name),
    )?;
    let req_ver = required_symbol_version(req_obj, sym_idx);

    if req_obj.summary.symbolic && !skip_main {
        if let Some((_sidx, sym)) = lookup_in_object(req_obj, name, req_ver, false) {
            return Some((req_obj_idx, sym));
        }
    }

    let mut weak_fallback: Option<(usize, &'a Sym64)> = None;
    let start = if skip_main { 1 } else { 0 };
    for (idx, candidate) in objects.iter().enumerate().skip(start) {
        if !candidate.active {
            continue;
        }
        // Only search global objects or the requesting object's dependency graph.
        if !candidate.global && idx != req_obj_idx {
            let is_dep = req_obj.deps[..req_obj.dep_count].contains(&idx);
            if !is_dep {
                continue;
            }
        }
        if let Some((_sidx, sym)) = lookup_in_object(candidate, name, req_ver, false) {
            if sym.binding() == STB_WEAK {
                if weak_fallback.is_none() {
                    weak_fallback = Some((idx, sym));
                }
            } else {
                return Some((idx, sym));
            }
        }
    }
    weak_fallback
}

fn lookup_in_object<'a>(
    obj: &'a LoadedObject,
    name: &[u8],
    req_ver: Option<(&[u8], u32)>,
    is_dlsym: bool,
) -> Option<(usize, &'a Sym64)> {
    if obj.summary.symtab == 0 || obj.summary.strtab == 0 || obj.sym_count == 0 {
        return None;
    }
    let syms_ptr = (obj.bias + obj.summary.symtab) as *const Sym64;
    let strtab_ptr = (obj.bias + obj.summary.strtab) as *const u8;
    let strsz = obj.summary.strsz as usize;
    // SAFETY: `DT_SYMTAB` and `DT_STRTAB` reside within `obj`'s mapped read-only segments.
    let (syms, strtab) = unsafe {
        (
            slice::from_raw_parts(syms_ptr, obj.sym_count),
            slice::from_raw_parts(strtab_ptr, strsz),
        )
    };
    let (verdef_bytes, verdefnum, vd_strtab) = object_verdef_slice(obj);

    if obj.summary.gnu_hash != 0 && obj.gnu_hash_words > 0 {
        let gnu_ptr = (obj.bias + obj.summary.gnu_hash) as *const u32;
        // SAFETY: `gnu_hash_words` was bounded by walking the mapped `.gnu.hash` chains.
        let words = unsafe { slice::from_raw_parts(gnu_ptr, obj.gnu_hash_words) };
        if let Some((sidx, sym)) = gnu_hash_lookup(words, syms, strtab, name) {
            let cand_vs = object_versym_at(obj, sidx);
            if symbol_version_matches(
                req_ver,
                cand_vs,
                verdef_bytes,
                verdefnum,
                vd_strtab,
                is_dlsym,
            ) {
                return Some((sidx, sym));
            }
        }
    }
    if obj.summary.hash != 0 {
        let hash_ptr = (obj.bias + obj.summary.hash) as *const u32;
        // SAFETY: `DT_HASH` starts with `[nbuckets, nchains]`.
        let (nbuckets, nchains) = unsafe { (*hash_ptr as usize, *hash_ptr.add(1) as usize) };
        let total = 2usize.saturating_add(nbuckets).saturating_add(nchains);
        // SAFETY: `DT_HASH` has `2 + nbuckets + nchains` words in the mapped segment.
        let words = unsafe { slice::from_raw_parts(hash_ptr, total) };
        if let Some((sidx, sym)) = sysv_hash_lookup(words, syms, strtab, name) {
            let cand_vs = object_versym_at(obj, sidx);
            if symbol_version_matches(
                req_ver,
                cand_vs,
                verdef_bytes,
                verdefnum,
                vd_strtab,
                is_dlsym,
            ) {
                return Some((sidx, sym));
            }
        }
    }
    None
}

fn read_cstr_slice<'a>(strtab_addr: u64, strsz: usize, offset: u64) -> Option<&'a [u8]> {
    if strtab_addr == 0 || strsz == 0 {
        return None;
    }
    // SAFETY: `DT_STRTAB` is mapped for `strsz` bytes inside the ELF image.
    let strtab = unsafe { slice::from_raw_parts(strtab_addr as *const u8, strsz) };
    cstr_at(strtab, offset)
}

fn protect_object_relro(self_vmar: &Vmar, obj: &LoadedObject) -> Result<(), &'static str> {
    if obj.has_relro && obj.relro_memsz > 0 {
        let start = align_down(obj.relro_vaddr, PAGE_SIZE);
        let raw_end = obj.relro_vaddr.saturating_add(obj.relro_memsz);
        let end = if raw_end.is_multiple_of(PAGE_SIZE) {
            raw_end
        } else {
            align_down(raw_end, PAGE_SIZE)
        };
        if end > start {
            let flags = vmar_flags::READ | vmar_flags::USER | vmar_flags::SPECIFIC;
            self_vmar
                .protect(start, end - start, flags)
                .map_err(|_| "VmarProtect RELRO failed")?;
        }
    }
    Ok(())
}

fn protect_self_relro(self_vmar: &Vmar, interp_base: u64) {
    if interp_base == 0 {
        return;
    }
    // SAFETY: `interp_base` points to `ld-huesos.so`'s mapped ELF64 header.
    let hdr = unsafe { slice::from_raw_parts(interp_base as *const u8, 4096) };
    let e_phoff = u64::from_le_bytes([
        hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39],
    ]);
    let e_phnum = u16::from_le_bytes([hdr[56], hdr[57]]);
    for idx in 0..usize::from(e_phnum) {
        let Ok(ph) = read_phdr64(hdr, e_phoff, idx) else {
            break;
        };
        if ph.p_type == PT_GNU_RELRO && ph.p_memsz > 0 {
            let start = align_down(interp_base.wrapping_add(ph.p_vaddr), PAGE_SIZE);
            let raw_end = interp_base
                .wrapping_add(ph.p_vaddr)
                .saturating_add(ph.p_memsz);
            let end = if raw_end.is_multiple_of(PAGE_SIZE) {
                raw_end
            } else {
                align_down(raw_end, PAGE_SIZE)
            };
            if end > start {
                let flags = vmar_flags::READ | vmar_flags::USER | vmar_flags::SPECIFIC;
                if self_vmar.protect(start, end - start, flags).is_err() {
                    fail("VmarProtect self RELRO failed");
                }
            }
            break;
        }
    }
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}
