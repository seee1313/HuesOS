//! HuesOS userspace ELF64 dynamic linker (`/lib/ld-huesos.so`).
//!
//! Invoked by the userspace process launcher when a binary carries `PT_INTERP`.
//! Performs:
//! 1. Self-relocation of `ld-huesos.so` via `AT_BASE`.
//! 2. Reception of `self_vmar` and `lib_vmo` (`BOOTFS`) from `BOOTSTRAP_HANDLE`
//!    when `AT_HUESOS_LD_BOOTSTRAP != 0`.
//! 3. Recursive/BFS loading of `DT_NEEDED` shared objects from `/lib/*.so`
//!    at ASLR-chosen addresses with strict `W^X`.
//! 4. Variant-II static TLS block setup (`PT_TLS`) and `ThreadSetFsBase`.
//! 5. Eager `RELA` + `JMPREL` relocation resolution (`RELATIVE`, `GLOB_DAT`,
//!    `JUMP_SLOT`, `64`, `IRELATIVE`, `COPY`, `TPOFF64`).
//! 6. `PT_GNU_RELRO` read-only protection via `VmarProtect`.
//! 7. Closing `self_vmar` and `lib_vmo` before running `.init`/`.init_array`
//!    in dependency-first order and jumping to `AT_ENTRY` with SysV ABI
//!    (`RSP % 16 == 0` pointing at `argc`, `RDX == 0`).

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ptr;
use core::slice;

use huesos_abi::auxv::{
    AuxEntry, AT_BASE, AT_ENTRY, AT_HUESOS_LD_BOOTSTRAP, AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM,
    LD_BOOTSTRAP_LIB_VMO_LABEL, LD_BOOTSTRAP_SELF_VMAR_LABEL,
};
use huesos_abi::{vmar_flags, vmo_create_flags, USER_HEAP_BASE, USER_HEAP_SIZE};
use huesos_elf::dynamic::{
    cstr_at, dt, gnu_hash_lookup, r_x86_64, read_phdr64, sysv_hash_lookup, Dyn64, DynamicSummary,
    Phdr64, Rela64, Sym64, TlsSegment, EM_X86_64, ET_DYN, MAX_DT_NEEDED, PF_R, PF_W, PF_X,
    PT_DYNAMIC, PT_GNU_RELRO, PT_LOAD, PT_PHDR, PT_TLS, STB_WEAK,
};
use libcanvas::process::Vmar;
use libcanvas::{debug, memory, process, Handle, Vmo};

const PAGE_SIZE: u64 = 4096;
const MAX_OBJECTS: usize = 16;
const MAX_NAME_LEN: usize = 96;
const HEADER_BUF_LEN: usize = 16 * 1024;
const DSO_ASLR_BASE: u64 = 0x0000_0002_0000_0000;
const DSO_ASLR_MASK: u64 = 0x000f_ffff; // 4 GiB window in 4 KiB steps.
const TLS_ASLR_BASE: u64 = 0x0000_0003_8000_0000;
const TLS_ASLR_MASK: u64 = 0x0003_ffff;

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
    // SysV AMD64 entry:
    // - On entry RSP is 16-byte aligned and points to `argc`.
    // - `call` pushes an 8-byte return address so `ld_entry` observes standard
    //   SysV entry alignment (`RSP % 16 == 8`).
    // - On return `RSP` is restored to `argc` (16-byte aligned), `RDX` is
    //   zeroed (`rtld_fini = 0`), and control transfers directly to `AT_ENTRY`.
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

/// Scan initial stack (`argc`, `argv`, `envp`, `auxv`) for `AT_BASE` without
/// touching any relocated globals.
fn find_at_base_raw(sp: *const u64) -> u64 {
    if sp.is_null() {
        return 0;
    }
    // SAFETY: kernel + launcher mapped the initial user stack with argc/argv/envp/auxv.
    unsafe {
        let argc = *sp as usize;
        let mut cursor = sp.add(1 + argc + 1); // skip argc, argv[..], NULL
        while *cursor != 0 {
            cursor = cursor.add(1);
        }
        cursor = cursor.add(1); // skip envp NULL
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

/// Apply `R_X86_64_RELATIVE` relocations to `ld-huesos.so` itself before using
/// any normal Rust functions/tables that might rely on relocated `.got`/`.rodata`.
///
/// # Safety
/// `base` must point to the mapped ELF64 header of `ld-huesos.so`.
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
    phdr: u64,
    phent: u64,
    phnum: u64,
    base: u64,
    entry: u64,
    ld_bootstrap: bool,
}

fn parse_auxv(sp: *const u64) -> Option<AuxInfo> {
    if sp.is_null() {
        return None;
    }
    let mut info = AuxInfo {
        phdr: 0,
        phent: 0,
        phnum: 0,
        base: 0,
        entry: 0,
        ld_bootstrap: false,
    };
    // SAFETY: stack was constructed by the parent process launcher per SysV ABI.
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
            match entry.a_type {
                AT_NULL => break,
                AT_PHDR => info.phdr = entry.a_val,
                AT_PHENT => info.phent = entry.a_val,
                AT_PHNUM => info.phnum = entry.a_val,
                AT_BASE => info.base = entry.a_val,
                AT_ENTRY => info.entry = entry.a_val,
                AT_HUESOS_LD_BOOTSTRAP => info.ld_bootstrap = entry.a_val != 0,
                _ => {}
            }
            aux = aux.add(1);
        }
    }
    Some(info)
}

#[derive(Clone, Copy)]
struct LoadedObject {
    active: bool,
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    bias: u64,
    min_va: u64,
    max_va: u64,
    dyn_vaddr: u64,
    dyn_memsz: u64,
    relro_vaddr: u64,
    relro_memsz: u64,
    has_relro: bool,
    tls: Option<TlsSegment>,
    tls_tp_offset: u64,
    summary: DynamicSummary,
    sym_count: usize,
    gnu_hash_words: usize,
}

impl LoadedObject {
    const fn empty() -> Self {
        Self {
            active: false,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            bias: 0,
            min_va: 0,
            max_va: 0,
            dyn_vaddr: 0,
            dyn_memsz: 0,
            relro_vaddr: 0,
            relro_memsz: 0,
            has_relro: false,
            tls: None,
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
        }
    }

    fn set_name(&mut self, bytes: &[u8]) {
        let len = bytes.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
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

    let (self_vmar, lib_vmo) = receive_bootstrap_handles();

    let mut objects = [LoadedObject::empty(); MAX_OBJECTS];
    let mut obj_count = 0usize;

    let main_obj = build_main_object(&aux);
    objects[obj_count] = main_obj;
    obj_count += 1;

    // Breadth-first load of all DT_NEEDED shared objects.
    let mut scan_idx = 0usize;
    while scan_idx < obj_count {
        let needed_count = objects[scan_idx].summary.needed_count;
        let needed_offs = objects[scan_idx].summary.needed_offs;
        let strtab_addr = objects[scan_idx].bias + objects[scan_idx].summary.strtab;
        let strsz = objects[scan_idx].summary.strsz as usize;
        let mut n = 0usize;
        while n < needed_count {
            let str_slice = read_cstr_slice(strtab_addr, strsz, needed_offs[n]);
            let Some(soname) = str_slice else {
                fail("invalid DT_NEEDED string");
            };
            if find_loaded_by_name(&objects[..obj_count], soname).is_none() {
                if obj_count >= MAX_OBJECTS {
                    fail("too many shared objects");
                }
                let loaded =
                    load_shared_object(&self_vmar, &lib_vmo, soname, &objects[..obj_count]);
                objects[obj_count] = loaded;
                obj_count += 1;
            }
            n += 1;
        }
        scan_idx += 1;
    }

    // Setup static TLS block (`PT_TLS`) and set `FS_BASE` before relocations
    // (`R_X86_64_TPOFF64` depends on `tls_tp_offset`).
    let tls_map_range = setup_static_tls(&self_vmar, &mut objects[..obj_count]);

    // Apply relocations for every loaded object.
    let mut obj_idx = 0usize;
    while obj_idx < obj_count {
        apply_object_relocations(obj_idx, &objects[..obj_count]);
        obj_idx += 1;
    }

    // Apply `PT_GNU_RELRO` read-only protections.
    for obj in objects.iter().take(obj_count) {
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
                if self_vmar.protect(start, end - start, flags).is_err() {
                    fail("VmarProtect RELRO failed");
                }
            }
        }
    }

    // Close privileged bootstrap handles (`self_vmar`, `lib_vmo`) before
    // running constructors or entering the application.
    protect_self_relro(&self_vmar, aux.base);
    let _ = tls_map_range;
    drop(lib_vmo);
    drop(self_vmar);

    // Run `.init` and `.init_array` in dependency-first order (reverse load order).
    let mut ctor_idx = obj_count;
    while ctor_idx > 0 {
        ctor_idx -= 1;
        run_object_constructors(&objects[ctor_idx]);
    }

    aux.entry
}

fn receive_bootstrap_handles() -> (Vmar, Vmo) {
    let bootstrap = libcanvas::channel::bootstrap();
    let mut self_vmar: Option<Handle> = None;
    let mut lib_vmo: Option<Handle> = None;
    let mut buf = [0u8; 64];

    while self_vmar.is_none() || lib_vmo.is_none() {
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_SELF_VMAR_LABEL => {
                self_vmar = Some(handle);
            }
            Ok((n, Some(handle))) if &buf[..n] == LD_BOOTSTRAP_LIB_VMO_LABEL => {
                lib_vmo = Some(handle);
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

    // Keep BOOTSTRAP_HANDLE (1) open for the target application.
    let _ = bootstrap.into_handle().into_raw();

    let (Some(vmar_h), Some(vmo_h)) = (self_vmar, lib_vmo) else {
        fail("missing ld bootstrap handle");
    };
    (Vmar::from_handle(vmar_h), Vmo::from_handle(vmo_h))
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
    obj.set_name(b"<main>");
    obj.bias = bias;
    obj.min_va = bias.wrapping_add(min_vaddr);
    obj.max_va = bias.wrapping_add(max_vaddr);
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

fn find_loaded_by_name(objects: &[LoadedObject], wanted: &[u8]) -> Option<usize> {
    for (idx, obj) in objects.iter().enumerate() {
        if !obj.active {
            continue;
        }
        if obj.name_bytes() == wanted {
            return Some(idx);
        }
        if obj.summary.soname_off.is_some() {
            let strtab_addr = obj.bias + obj.summary.strtab;
            if let Some(off) = obj.summary.soname_off {
                if read_cstr_slice(strtab_addr, obj.summary.strsz as usize, off) == Some(wanted) {
                    return Some(idx);
                }
            }
        }
    }
    None
}

fn load_shared_object(
    self_vmar: &Vmar,
    lib_vmo: &Vmo,
    soname: &[u8],
    existing: &[LoadedObject],
) -> LoadedObject {
    let mut path_buf = [0u8; 192];
    let path = build_lib_path(soname, &mut path_buf);
    let Some((elf_off, elf_len)) = find_bootfs_entry(lib_vmo, path) else {
        fail("shared library not found in BOOTFS");
    };

    let mut hdr_buf = [0u8; HEADER_BUF_LEN];
    let first_len = (elf_len as usize).min(4096).min(hdr_buf.len());
    if first_len < 64 || lib_vmo.read(elf_off, &mut hdr_buf[..first_len]).ok() != Some(first_len) {
        fail("failed reading shared library ELF header");
    }
    if !huesos_elf::dynamic::is_valid_elf64_header(&hdr_buf[..first_len]) {
        fail("invalid shared library ELF64 header");
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
    if e_type != ET_DYN || e_machine != EM_X86_64 || e_phentsize != 56 {
        fail("unsupported shared library ELF format");
    }
    let phdr_end =
        e_phoff.saturating_add(u64::from(e_phnum).saturating_mul(u64::from(e_phentsize)));
    if phdr_end > elf_len || phdr_end as usize > HEADER_BUF_LEN {
        fail("shared library phdrs exceed header buffer");
    }
    let hdr_len = (phdr_end as usize).max(first_len);
    if hdr_len > first_len && lib_vmo.read(elf_off, &mut hdr_buf[..hdr_len]).ok() != Some(hdr_len) {
        fail("failed reading shared library phdrs");
    }
    let hdr_slice = &hdr_buf[..hdr_len];

    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut dyn_vaddr = 0u64;
    let mut dyn_memsz = 0u64;
    let mut relro_vaddr = 0u64;
    let mut relro_memsz = 0u64;
    let mut has_relro = false;
    let mut tls: Option<TlsSegment> = None;

    let mut i = 0u16;
    while i < e_phnum {
        let Ok(ph) = read_phdr64(hdr_slice, e_phoff, usize::from(i)) else {
            fail("bad shared library phdr");
        };
        match ph.p_type {
            PT_LOAD => {
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

    if min_vaddr >= max_vaddr {
        fail("shared library has no PT_LOAD");
    }
    let span = max_vaddr - min_vaddr;
    let load_base = choose_aslr_region(DSO_ASLR_BASE, DSO_ASLR_MASK, span, existing);
    let bias = load_base.wrapping_sub(min_vaddr);

    let mut j = 0u16;
    while j < e_phnum {
        let Ok(ph) = read_phdr64(hdr_slice, e_phoff, usize::from(j)) else {
            fail("bad shared library phdr");
        };
        if ph.p_type == PT_LOAD {
            map_load_segment_from_vmo(self_vmar, lib_vmo, elf_off, elf_len, bias, ph);
        }
        j += 1;
    }

    let mut obj = LoadedObject::empty();
    obj.active = true;
    obj.set_name(soname);
    obj.bias = bias;
    obj.min_va = load_base;
    obj.max_va = load_base + span;
    obj.dyn_vaddr = bias.wrapping_add(dyn_vaddr);
    obj.dyn_memsz = dyn_memsz;
    obj.relro_vaddr = bias.wrapping_add(relro_vaddr);
    obj.relro_memsz = relro_memsz;
    obj.has_relro = has_relro;
    obj.tls = tls;
    populate_dynamic_info(&mut obj);
    obj
}

fn build_lib_path<'a>(soname: &[u8], buf: &'a mut [u8; 192]) -> &'a [u8] {
    if soname.starts_with(b"/") {
        let n = soname.len().min(buf.len());
        buf[..n].copy_from_slice(&soname[..n]);
        return &buf[..n];
    }
    let prefix = b"/lib/";
    let total = prefix.len() + soname.len();
    if total > buf.len() {
        fail("library path too long");
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..total].copy_from_slice(soname);
    &buf[..total]
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
) -> u64 {
    let rand = memory::random_u64().unwrap_or(0x1357_2468);
    let start_slot = rand & page_mask;
    let heap_start = USER_HEAP_BASE;
    let heap_end = USER_HEAP_BASE + USER_HEAP_SIZE;

    let mut attempt = 0u64;
    while attempt < 1024 {
        let candidate =
            window_base + (((start_slot.wrapping_add(attempt * 256)) & page_mask) << 12);
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
            return candidate;
        }
        attempt += 1;
    }
    fail("ASLR region exhausted");
}

fn map_load_segment_from_vmo(
    self_vmar: &Vmar,
    vmo: &Vmo,
    elf_off: u64,
    elf_len: u64,
    bias: u64,
    ph: Phdr64,
) {
    if ph.p_filesz > ph.p_memsz
        || ph
            .p_offset
            .checked_add(ph.p_filesz)
            .is_none_or(|end| end > elf_len)
    {
        fail("corrupt shared object PT_LOAD");
    }
    let seg_vaddr = bias.wrapping_add(ph.p_vaddr);
    let page_start = align_down(seg_vaddr, PAGE_SIZE);
    let page_end = align_up(seg_vaddr.saturating_add(ph.p_memsz), PAGE_SIZE);
    if page_end <= page_start {
        return;
    }
    let map_len = page_end - page_start;
    let vmo_flags = if ph.p_flags & PF_X != 0 {
        vmo_create_flags::EXECUTABLE
    } else {
        0
    };
    let Ok(seg_vmo) = Vmo::create_with_flags(map_len, vmo_flags) else {
        fail("Vmo::create_with_flags failed");
    };

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
                fail("failed copying shared object segment");
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
    if self_vmar
        .map(&seg_vmo, 0, page_start, map_len, flags)
        .is_err()
    {
        fail("Vmar::map shared object failed");
    }
}

fn setup_static_tls(self_vmar: &Vmar, objects: &mut [LoadedObject]) -> Option<(u64, u64)> {
    let mut total_size = 0u64;
    let mut max_align = 16u64;
    let mut any_tls = false;

    for obj in objects.iter_mut() {
        if let Some(tls) = obj.tls {
            any_tls = true;
            let align = tls.align.max(16);
            if align > max_align {
                max_align = align;
            }
            total_size = align_up(total_size + tls.memsz, align);
            obj.tls_tp_offset = total_size;
        }
    }
    if !any_tls {
        return None;
    }

    let tcb_size = 64u64;
    let alloc_len = align_up(total_size + tcb_size + max_align, PAGE_SIZE);
    let tls_base = choose_aslr_region(TLS_ASLR_BASE, TLS_ASLR_MASK, alloc_len, objects);
    let Ok(tls_vmo) = Vmo::create(alloc_len) else {
        fail("failed allocating TLS VMO");
    };
    let flags = vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC;
    if self_vmar
        .map(&tls_vmo, 0, tls_base, alloc_len, flags)
        .is_err()
    {
        fail("failed mapping TLS VMO");
    }

    let tp = align_up(tls_base + total_size, max_align);
    // Variant II TCB self-pointer at `%fs:0`.
    // SAFETY: `tp..tp+8` lies inside the freshly mapped writable TLS region.
    unsafe { ptr::write(tp as *mut u64, tp) };

    for obj in objects.iter() {
        if let Some(tls) = obj.tls {
            if tls.filesz > 0 {
                let dst = (tp - obj.tls_tp_offset) as *mut u8;
                let src = obj.bias.wrapping_add(tls.vaddr) as *const u8;
                // SAFETY: `src` is inside the mapped ELF `.tdata` segment and
                // `dst` is inside the freshly mapped writable TLS block.
                unsafe { ptr::copy_nonoverlapping(src, dst, tls.filesz as usize) };
            }
        }
    }

    if process::set_fs_base(tp).is_err() {
        fail("ThreadSetFsBase failed");
    }
    Some((tls_base, alloc_len))
}

fn apply_object_relocations(obj_idx: usize, objects: &[LoadedObject]) {
    let obj = &objects[obj_idx];
    if obj.summary.rela != 0 && obj.summary.relasz != 0 {
        let count = (obj.summary.relasz as usize) / core::mem::size_of::<Rela64>();
        let ptr = (obj.bias + obj.summary.rela) as *const Rela64;
        // SAFETY: `DT_RELA` lies inside the mapped ELF image.
        let relas = unsafe { slice::from_raw_parts(ptr, count) };
        apply_rela_slice(obj_idx, relas, objects);
    }
    if obj.summary.jmprel != 0 && obj.summary.pltrelsz != 0 && obj.summary.pltrel_is_rela {
        let count = (obj.summary.pltrelsz as usize) / core::mem::size_of::<Rela64>();
        let ptr = (obj.bias + obj.summary.jmprel) as *const Rela64;
        // SAFETY: `DT_JMPREL` lies inside the mapped ELF image.
        let relas = unsafe { slice::from_raw_parts(ptr, count) };
        apply_rela_slice(obj_idx, relas, objects);
    }
}

fn apply_rela_slice(obj_idx: usize, relas: &[Rela64], objects: &[LoadedObject]) {
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
                let Some((def_obj_idx, sym)) =
                    resolve_symbol_for_reloc(obj_idx, sym_idx, objects, false)
                else {
                    fail("unresolved dynamic symbol");
                };
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
                let Some((def_obj_idx, sym)) =
                    resolve_symbol_for_reloc(obj_idx, sym_idx, objects, true)
                else {
                    fail("unresolved R_X86_64_COPY symbol");
                };
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
                    let Some((found_idx, sym)) =
                        resolve_symbol_for_reloc(obj_idx, sym_idx, objects, false)
                    else {
                        fail("unresolved TPOFF64 symbol");
                    };
                    (found_idx, sym.st_value)
                };
                let def_obj = &objects[def_obj_idx];
                let tpoff = (sym_val as i64)
                    .wrapping_sub(def_obj.tls_tp_offset as i64)
                    .wrapping_add(rel.r_addend);
                // SAFETY: `target` is a GOT slot holding a Variant-II TP offset.
                unsafe { *target = tpoff as u64 };
            }
            _ => {
                fail("unsupported ELF64 relocation type");
            }
        }
    }
}

fn resolve_symbol_for_reloc<'a>(
    req_obj_idx: usize,
    sym_idx: usize,
    objects: &'a [LoadedObject],
    skip_main: bool,
) -> Option<(usize, &'a Sym64)> {
    let req_obj = &objects[req_obj_idx];
    if req_obj.summary.symtab == 0 || sym_idx >= req_obj.sym_count.max(sym_idx + 1) {
        return None;
    }
    let sym_ptr = (req_obj.bias + req_obj.summary.symtab) as *const Sym64;
    // SAFETY: `sym_idx` is taken from an ELF relocation in `req_obj` pointing into `DT_SYMTAB`.
    let req_sym = unsafe { &*sym_ptr.add(sym_idx) };
    if req_sym.is_defined()
        && (req_sym.binding() == huesos_elf::dynamic::STB_LOCAL || req_sym.st_name == 0)
    {
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

    if req_obj.summary.symbolic && !skip_main {
        if let Some(sym) = lookup_in_object(req_obj, name) {
            return Some((req_obj_idx, sym));
        }
    }

    let mut weak_fallback: Option<(usize, &'a Sym64)> = None;
    let start = if skip_main { 1 } else { 0 };
    for (idx, candidate) in objects.iter().enumerate().skip(start) {
        if !candidate.active {
            continue;
        }
        if let Some(sym) = lookup_in_object(candidate, name) {
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

fn lookup_in_object<'a>(obj: &'a LoadedObject, name: &[u8]) -> Option<&'a Sym64> {
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

    if obj.summary.gnu_hash != 0 && obj.gnu_hash_words > 0 {
        let gnu_ptr = (obj.bias + obj.summary.gnu_hash) as *const u32;
        // SAFETY: `gnu_hash_words` was bounded by walking the mapped `.gnu.hash` chains.
        let words = unsafe { slice::from_raw_parts(gnu_ptr, obj.gnu_hash_words) };
        if let Some((_, sym)) = gnu_hash_lookup(words, syms, strtab, name) {
            return Some(sym);
        }
    }
    if obj.summary.hash != 0 {
        let hash_ptr = (obj.bias + obj.summary.hash) as *const u32;
        // SAFETY: `DT_HASH` starts with `[nbuckets, nchains]`.
        let (nbuckets, nchains) = unsafe { (*hash_ptr as usize, *hash_ptr.add(1) as usize) };
        let total = 2usize.saturating_add(nbuckets).saturating_add(nchains);
        // SAFETY: `DT_HASH` has `2 + nbuckets + nchains` words in the mapped segment.
        let words = unsafe { slice::from_raw_parts(hash_ptr, total) };
        if let Some((_, sym)) = sysv_hash_lookup(words, syms, strtab, name) {
            return Some(sym);
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

fn run_object_constructors(obj: &LoadedObject) {
    if obj.summary.init != 0 {
        let addr = obj.bias.wrapping_add(obj.summary.init);
        // SAFETY: `DT_INIT` is an `extern "C" fn()` function inside the mapped executable segment.
        let func: extern "C" fn() = unsafe { core::mem::transmute(addr) };
        func();
    }
    if obj.summary.init_array != 0 && obj.summary.init_arraysz != 0 {
        let count = (obj.summary.init_arraysz as usize) / core::mem::size_of::<u64>();
        let ptr = (obj.bias + obj.summary.init_array) as *const u64;
        // SAFETY: `DT_INIT_ARRAY` holds `count` relocated constructor function pointers.
        let funcs = unsafe { slice::from_raw_parts(ptr, count) };
        for &fn_addr in funcs {
            if fn_addr != 0 && fn_addr != u64::MAX {
                // SAFETY: each non-sentinel `.init_array` entry is an `extern "C" fn()`.
                let func: extern "C" fn() = unsafe { core::mem::transmute(fn_addr) };
                func();
            }
        }
    }
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
