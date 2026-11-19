//! Pure-Rust, `no_std`, host-testable ELF64 dynamic linking metadata parser.
//!
//! Used by both the userspace `PT_INTERP` launcher and `/lib/ld-huesos.so`
//! without any `unsafe`, panics, or allocation.

use crate::{read_u16, read_u32, read_u64, ElfLoadError, ELF64_HEADER_BYTES};

/// ELF machine id for x86-64.
pub const EM_X86_64: u16 = 62;
/// `e_type` for static/non-PIE executables.
pub const ET_EXEC: u16 = 2;
/// `e_type` for PIE executables and shared objects.
pub const ET_DYN: u16 = 3;

/// Loadable segment.
pub const PT_LOAD: u32 = 1;
/// Dynamic linking metadata segment (`_DYNAMIC`).
pub const PT_DYNAMIC: u32 = 2;
/// Interpreter path segment (`/lib/ld-huesos.so`).
pub const PT_INTERP: u32 = 3;
/// Program header table location segment.
pub const PT_PHDR: u32 = 6;
/// Thread-local storage template segment.
pub const PT_TLS: u32 = 7;
/// Read-only-after-relocation segment.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

/// Segment execute permission.
pub const PF_X: u32 = 1;
/// Segment write permission.
pub const PF_W: u32 = 2;
/// Segment read permission.
pub const PF_R: u32 = 4;

/// Dynamic entry tags (`d_tag`).
pub mod dt {
    /// End of `_DYNAMIC` array.
    pub const NULL: i64 = 0;
    /// `DT_STRTAB` offset of a needed shared library name.
    pub const NEEDED: i64 = 1;
    /// Byte size of PLT relocations (`DT_JMPREL`).
    pub const PLTRELSZ: i64 = 2;
    /// Address of PLT/GOT.
    pub const PLTGOT: i64 = 3;
    /// SysV symbol hash table address.
    pub const HASH: i64 = 4;
    /// Dynamic string table address.
    pub const STRTAB: i64 = 5;
    /// Dynamic symbol table address.
    pub const SYMTAB: i64 = 6;
    /// Relocation table (`Elf64_Rela`) address.
    pub const RELA: i64 = 7;
    /// Total byte size of `DT_RELA`.
    pub const RELASZ: i64 = 8;
    /// Size of one `Elf64_Rela` entry (24).
    pub const RELAENT: i64 = 9;
    /// Byte size of `DT_STRTAB`.
    pub const STRSZ: i64 = 10;
    /// Size of one `Elf64_Sym` entry (24).
    pub const SYMENT: i64 = 11;
    /// Legacy init function address.
    pub const INIT: i64 = 12;
    /// Legacy fini function address.
    pub const FINI: i64 = 13;
    /// `DT_STRTAB` offset of this shared object's `SONAME`.
    pub const SONAME: i64 = 14;
    /// Prefer resolving symbols inside this object first.
    pub const SYMBOLIC: i64 = 16;
    /// Type of PLT relocations (`DT_RELA` = 7).
    pub const PLTREL: i64 = 20;
    /// PLT relocation table address.
    pub const JMPREL: i64 = 23;
    /// Eager relocation binding requested.
    pub const BIND_NOW: i64 = 24;
    /// Array of init function pointers.
    pub const INIT_ARRAY: i64 = 25;
    /// Array of fini function pointers.
    pub const FINI_ARRAY: i64 = 26;
    /// Byte size of `DT_INIT_ARRAY`.
    pub const INIT_ARRAYSZ: i64 = 27;
    /// Byte size of `DT_FINI_ARRAY`.
    pub const FINI_ARRAYSZ: i64 = 28;
    /// Generic dynamic flags (`DF_*`).
    pub const FLAGS: i64 = 30;
    /// GNU symbol hash table address.
    pub const GNU_HASH: i64 = 0x6fff_fef5;
    /// `Elf64_Half` per-symbol version index table (`DT_VERSYM`).
    pub const VERSYM: i64 = 0x6fff_fff0;
    /// Hint count of `R_X86_64_RELATIVE` entries at start of `DT_RELA`.
    pub const RELACOUNT: i64 = 0x6fff_fff9;
    /// Extended dynamic flags (`DF_1_*`).
    pub const FLAGS_1: i64 = 0x6fff_fffb;
    /// Symbol version definition table (`Elf64_Verdef`).
    pub const VERDEF: i64 = 0x6fff_fffc;
    /// Number of `Elf64_Verdef` entries.
    pub const VERDEFNUM: i64 = 0x6fff_fffd;
    /// Symbol version requirement table (`Elf64_Verneed`).
    pub const VERNEED: i64 = 0x6fff_fffe;
    /// Number of `Elf64_Verneed` entries.
    pub const VERNEEDNUM: i64 = 0x6fff_ffff;

    /// `DF_SYMBOLIC` flag bit.
    pub const DF_SYMBOLIC: u64 = 0x2;
    /// `DF_BIND_NOW` flag bit.
    pub const DF_BIND_NOW: u64 = 0x8;
    /// `DF_1_NOW` flag bit.
    pub const DF_1_NOW: u64 = 0x1;
}

/// x86-64 ELF relocation types.
pub mod r_x86_64 {
    /// No relocation.
    pub const NONE: u32 = 0;
    /// Direct 64-bit (`S + A`).
    pub const R64: u32 = 1;
    /// Copy symbol initial data (`memcpy`).
    pub const COPY: u32 = 5;
    /// GOT entry (`S`).
    pub const GLOB_DAT: u32 = 6;
    /// PLT GOT entry (`S`).
    pub const JUMP_SLOT: u32 = 7;
    /// Base-relative (`B + A`).
    pub const RELATIVE: u32 = 8;
    /// Dynamic TLS module ID (`DTPMOD64`).
    pub const DTPMOD64: u32 = 16;
    /// Dynamic TLS block-relative offset (`DTPOFF64`).
    pub const DTPOFF64: u32 = 17;
    /// Static TLS TP-relative 64-bit offset (`S + A - tls_offset`).
    pub const TPOFF64: u32 = 18;
    /// Indirect function resolver (`B + A` returning address).
    pub const IRELATIVE: u32 = 37;
}

/// GNU symbol versioning constants and structures (`DT_VERSYM`, `DT_VERDEF`, `DT_VERNEED`).
pub const VER_NDX_LOCAL: u16 = 0;
/// Unversioned global symbol version index.
pub const VER_NDX_GLOBAL: u16 = 1;
/// Bit 15 in `DT_VERSYM`: non-default (hidden) version only matched by explicit `DT_VERNEED`.
pub const VERSYM_HIDDEN: u16 = 0x8000;
/// Mask for the 15-bit version index inside `DT_VERSYM`.
pub const VERSYM_VERSION_MASK: u16 = 0x7fff;
/// `vd_flags` bit: base file version definition.
pub const VER_FLG_BASE: u16 = 0x1;
/// `vd_flags` / `vna_flags` bit: weak version requirement.
pub const VER_FLG_WEAK: u16 = 0x2;

/// Decoded `Elf64_Verdef` entry (`20` bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Verdef64 {
    /// Version revision (must be `1`).
    pub vd_version: u16,
    /// Flags (`VER_FLG_*`).
    pub vd_flags: u16,
    /// Version index referenced by `DT_VERSYM`.
    pub vd_ndx: u16,
    /// Number of `Elf64_Verdaux` entries.
    pub vd_cnt: u16,
    /// SysV hash of the version name string.
    pub vd_hash: u32,
    /// Byte offset from start of this `Verdef64` to its first `Verdaux64`.
    pub vd_aux: u32,
    /// Byte offset from start of this `Verdef64` to the next `Verdef64` (`0` = end).
    pub vd_next: u32,
}

/// Decoded `Elf64_Verdaux` entry (`8` bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Verdaux64 {
    /// `DT_STRTAB` offset of the version name string.
    pub vda_name: u32,
    /// Byte offset from start of this `Verdaux64` to the next `Verdaux64` (`0` = end).
    pub vda_next: u32,
}

/// Decoded `Elf64_Verneed` entry (`16` bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Verneed64 {
    /// Version revision (must be `1`).
    pub vn_version: u16,
    /// Number of `Elf64_Vernaux` entries.
    pub vn_cnt: u16,
    /// `DT_STRTAB` offset of the provider `SONAME`.
    pub vn_file: u32,
    /// Byte offset from start of this `Verneed64` to its first `Vernaux64`.
    pub vn_aux: u32,
    /// Byte offset from start of this `Verneed64` to the next `Verneed64` (`0` = end).
    pub vn_next: u32,
}

/// Decoded `Elf64_Vernaux` entry (`16` bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Vernaux64 {
    /// SysV hash of `vna_name`.
    pub vna_hash: u32,
    /// Flags (`VER_FLG_WEAK`).
    pub vna_flags: u16,
    /// Version index referenced by `DT_VERSYM` in the consuming object.
    pub vna_other: u16,
    /// `DT_STRTAB` offset of the required version string.
    pub vna_name: u32,
    /// Byte offset from start of this `Vernaux64` to the next `Vernaux64` (`0` = end).
    pub vna_next: u32,
}

/// Symbol binding (`st_info >> 4`).
pub const STB_LOCAL: u8 = 0;
/// Global symbol.
pub const STB_GLOBAL: u8 = 1;
/// Weak symbol.
pub const STB_WEAK: u8 = 2;
/// Undefined section index.
pub const SHN_UNDEF: u16 = 0;
/// Indirect function symbol type (`STT_GNU_IFUNC`).
pub const STT_GNU_IFUNC: u8 = 10;

/// Maximum `DT_NEEDED` entries recorded per ELF object without allocation.
pub const MAX_DT_NEEDED: usize = 32;

/// Decoded ELF64 program header (`Elf64_Phdr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Phdr64 {
    /// Segment type (`PT_*`).
    pub p_type: u32,
    /// Segment flags (`PF_*`).
    pub p_flags: u32,
    /// File offset.
    pub p_offset: u64,
    /// Virtual address in image.
    pub p_vaddr: u64,
    /// Physical address (unused on userspace).
    pub p_paddr: u64,
    /// Bytes in file.
    pub p_filesz: u64,
    /// Bytes in memory.
    pub p_memsz: u64,
    /// Alignment requirement.
    pub p_align: u64,
}

/// Decoded `Elf64_Dyn` entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Dyn64 {
    /// Entry tag (`dt::*`).
    pub d_tag: i64,
    /// Integer value or virtual address.
    pub d_val: u64,
}

/// Decoded `Elf64_Sym` entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sym64 {
    /// String table offset.
    pub st_name: u32,
    /// Binding + symbol type.
    pub st_info: u8,
    /// Visibility (`STV_*`).
    pub st_other: u8,
    /// Section index (`SHN_UNDEF` when imported).
    pub st_shndx: u16,
    /// Symbol value / virtual address.
    pub st_value: u64,
    /// Symbol size in bytes.
    pub st_size: u64,
}

impl Sym64 {
    /// Symbol binding (`STB_*`).
    pub const fn binding(&self) -> u8 {
        self.st_info >> 4
    }

    /// Symbol type (`STT_*`).
    pub const fn sym_type(&self) -> u8 {
        self.st_info & 0x0f
    }

    /// Whether this symbol is defined by this object (not `SHN_UNDEF`).
    pub const fn is_defined(&self) -> bool {
        self.st_shndx != SHN_UNDEF
    }
}

/// Decoded `Elf64_Rela` entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rela64 {
    /// Virtual address to patch (relative to load bias for `ET_DYN`).
    pub r_offset: u64,
    /// Packed `(symbol_index << 32) | reloc_type`.
    pub r_info: u64,
    /// Explicit addend.
    pub r_addend: i64,
}

impl Rela64 {
    /// Dynamic symbol table index.
    pub const fn sym_index(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    /// Relocation type (`r_x86_64::*`).
    pub const fn reloc_type(&self) -> u32 {
        (self.r_info & 0xffff_ffff) as u32
    }
}

/// Decoded `PT_TLS` template metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TlsSegment {
    /// Template virtual address (unbiased).
    pub vaddr: u64,
    /// Initialized data size (`.tdata`).
    pub filesz: u64,
    /// Total TLS block size (`.tdata + .tbss`).
    pub memsz: u64,
    /// Alignment (power of two).
    pub align: u64,
}

/// Summary of ELF64 file headers and key segments for launcher & `ld-huesos.so`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Elf64Summary {
    /// Object type (`ET_EXEC` or `ET_DYN`).
    pub e_type: u16,
    /// Entry point (`e_entry`).
    pub e_entry: u64,
    /// Program header file offset (`e_phoff`).
    pub e_phoff: u64,
    /// Program header count (`e_phnum`).
    pub e_phnum: u16,
    /// Lowest page-aligned `PT_LOAD` `p_vaddr`.
    pub min_vaddr: u64,
    /// Highest page-aligned end of `PT_LOAD` (`p_vaddr + p_memsz`).
    pub max_vaddr_aligned: u64,
    /// `PT_INTERP` `(p_offset, p_filesz)` if present.
    pub interp: Option<(u64, u64)>,
    /// `PT_DYNAMIC` `(p_vaddr, p_memsz)` if present.
    pub dynamic: Option<(u64, u64)>,
    /// `PT_GNU_RELRO` `(p_vaddr, p_memsz)` if present.
    pub relro: Option<(u64, u64)>,
    /// `PT_TLS` metadata if present.
    pub tls: Option<TlsSegment>,
    /// `PT_PHDR` `p_vaddr` if present.
    pub pt_phdr_vaddr: Option<u64>,
    /// Number of `PT_LOAD` segments.
    pub load_count: usize,
}

impl Elf64Summary {
    /// Total virtual span required when mapping an `ET_DYN` image contiguously.
    pub const fn virtual_span(&self) -> u64 {
        self.max_vaddr_aligned.saturating_sub(self.min_vaddr)
    }
}

/// Validate ELF64 little-endian x86-64 header and summarize its program headers.
pub fn inspect_elf64(data: &[u8]) -> Result<Elf64Summary, ElfLoadError<()>> {
    crate::validate_elf64_header(data)?;
    let e_type = read_u16(data, 16).ok_or(ElfLoadError::ParseError("missing e_type"))?;
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfLoadError::Unsupported(
            "expected ET_EXEC or ET_DYN ELF64 binary",
        ));
    }
    let e_machine = read_u16(data, 18).ok_or(ElfLoadError::ParseError("missing e_machine"))?;
    if e_machine != EM_X86_64 {
        return Err(ElfLoadError::Unsupported("only x86-64 ELF64 is supported"));
    }
    let e_entry = read_u64(data, 24).ok_or(ElfLoadError::ParseError("missing e_entry"))?;
    let e_phoff = read_u64(data, 32).ok_or(ElfLoadError::ParseError("missing e_phoff"))?;
    let e_phnum = read_u16(data, 56).ok_or(ElfLoadError::ParseError("missing e_phnum"))?;

    let mut min_vaddr = u64::MAX;
    let mut max_vaddr_aligned = 0u64;
    let mut interp = None;
    let mut dynamic = None;
    let mut relro = None;
    let mut tls = None;
    let mut pt_phdr_vaddr = None;
    let mut load_count = 0usize;

    for idx in 0..usize::from(e_phnum) {
        let ph = read_phdr64(data, e_phoff, idx)?;
        match ph.p_type {
            PT_LOAD => {
                if ph.p_filesz > ph.p_memsz {
                    return Err(ElfLoadError::ParseError("PT_LOAD filesz > memsz"));
                }
                let file_end = ph
                    .p_offset
                    .checked_add(ph.p_filesz)
                    .ok_or(ElfLoadError::SegmentOutOfBounds)?;
                if file_end > data.len() as u64 {
                    return Err(ElfLoadError::SegmentOutOfBounds);
                }
                let page_start = ph.p_vaddr & !0xfff;
                let mem_end = ph
                    .p_vaddr
                    .checked_add(ph.p_memsz)
                    .ok_or(ElfLoadError::SegmentOutOfBounds)?;
                let page_end = mem_end
                    .checked_add(0xfff)
                    .map(|v| v & !0xfff)
                    .ok_or(ElfLoadError::SegmentOutOfBounds)?;
                if page_start < min_vaddr {
                    min_vaddr = page_start;
                }
                if page_end > max_vaddr_aligned {
                    max_vaddr_aligned = page_end;
                }
                load_count += 1;
            }
            PT_INTERP => {
                let end = ph
                    .p_offset
                    .checked_add(ph.p_filesz)
                    .ok_or(ElfLoadError::SegmentOutOfBounds)?;
                if end > data.len() as u64 || ph.p_filesz == 0 {
                    return Err(ElfLoadError::SegmentOutOfBounds);
                }
                interp = Some((ph.p_offset, ph.p_filesz));
            }
            PT_DYNAMIC => {
                dynamic = Some((ph.p_vaddr, ph.p_memsz));
            }
            PT_GNU_RELRO => {
                relro = Some((ph.p_vaddr, ph.p_memsz));
            }
            PT_TLS => {
                tls = Some(TlsSegment {
                    vaddr: ph.p_vaddr,
                    filesz: ph.p_filesz,
                    memsz: ph.p_memsz,
                    align: ph.p_align.max(1),
                });
            }
            PT_PHDR => {
                pt_phdr_vaddr = Some(ph.p_vaddr);
            }
            _ => {}
        }
    }

    if load_count == 0 {
        return Err(ElfLoadError::ParseError("no PT_LOAD segments"));
    }

    Ok(Elf64Summary {
        e_type,
        e_entry,
        e_phoff,
        e_phnum,
        min_vaddr,
        max_vaddr_aligned,
        interp,
        dynamic,
        relro,
        tls,
        pt_phdr_vaddr,
        load_count,
    })
}

/// Decode one `Elf64_Phdr` at `phoff + index * 56`.
pub fn read_phdr64(data: &[u8], phoff: u64, index: usize) -> Result<Phdr64, ElfLoadError<()>> {
    let base = u64::try_from(index)
        .ok()
        .and_then(|i| i.checked_mul(56))
        .and_then(|rel| phoff.checked_add(rel))
        .and_then(|off| usize::try_from(off).ok())
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;
    let err = || ElfLoadError::ParseError("truncated program header");
    Ok(Phdr64 {
        p_type: read_u32(data, base).ok_or_else(err)?,
        p_flags: read_u32(data, base + 4).ok_or_else(err)?,
        p_offset: read_u64(data, base + 8).ok_or_else(err)?,
        p_vaddr: read_u64(data, base + 16).ok_or_else(err)?,
        p_paddr: read_u64(data, base + 24).ok_or_else(err)?,
        p_filesz: read_u64(data, base + 32).ok_or_else(err)?,
        p_memsz: read_u64(data, base + 40).ok_or_else(err)?,
        p_align: read_u64(data, base + 48).ok_or_else(err)?,
    })
}

/// Extract trimmed `PT_INTERP` string from `data` (strips trailing NUL).
pub fn read_interp_path<'a>(data: &'a [u8], summary: &Elf64Summary) -> Option<&'a str> {
    let (off, filesz) = summary.interp?;
    let start = usize::try_from(off).ok()?;
    let len = usize::try_from(filesz).ok()?;
    let raw = data.get(start..start.checked_add(len)?)?;
    let trimmed = match raw.iter().position(|&b| b == 0) {
        Some(nul) => &raw[..nul],
        None => raw,
    };
    core::str::from_utf8(trimmed).ok()
}

/// Parsed summary of a `PT_DYNAMIC` section (`Elf64_Dyn[]`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DynamicSummary {
    /// Address of `DT_STRTAB` (as encoded in `_DYNAMIC`, i.e. unbiased if unaltered).
    pub strtab: u64,
    /// Size of `DT_STRTAB`.
    pub strsz: u64,
    /// Address of `DT_SYMTAB`.
    pub symtab: u64,
    /// Size of one `Elf64_Sym` (typically 24).
    pub syment: u64,
    /// Address of `DT_RELA`.
    pub rela: u64,
    /// Total size in bytes of `DT_RELA`.
    pub relasz: u64,
    /// Size of one `Elf64_Rela` (typically 24).
    pub relaent: u64,
    /// Address of `DT_JMPREL`.
    pub jmprel: u64,
    /// Total size in bytes of `DT_JMPREL`.
    pub pltrelsz: u64,
    /// Whether `DT_PLTREL == DT_RELA`.
    pub pltrel_is_rela: bool,
    /// Address of `DT_HASH`.
    pub hash: u64,
    /// Address of `DT_GNU_HASH`.
    pub gnu_hash: u64,
    /// Address of `DT_VERSYM`.
    pub versym: u64,
    /// Address of `DT_VERDEF`.
    pub verdef: u64,
    /// Entry count in `DT_VERDEF` (`DT_VERDEFNUM`).
    pub verdefnum: u64,
    /// Address of `DT_VERNEED`.
    pub verneed: u64,
    /// Entry count in `DT_VERNEED` (`DT_VERNEEDNUM`).
    pub verneednum: u64,
    /// Address of `DT_INIT`.
    pub init: u64,
    /// Address of `DT_FINI`.
    pub fini: u64,
    /// Address of `DT_INIT_ARRAY`.
    pub init_array: u64,
    /// Byte size of `DT_INIT_ARRAY`.
    pub init_arraysz: u64,
    /// Address of `DT_FINI_ARRAY`.
    pub fini_array: u64,
    /// Byte size of `DT_FINI_ARRAY`.
    pub fini_arraysz: u64,
    /// `DT_STRTAB` offset of `DT_SONAME`.
    pub soname_off: Option<u64>,
    /// `DT_STRTAB` offsets for `DT_NEEDED`.
    pub needed_offs: [u64; MAX_DT_NEEDED],
    /// Number of valid entries in `needed_offs`.
    pub needed_count: usize,
    /// `DF_SYMBOLIC` or `DT_SYMBOLIC` active.
    pub symbolic: bool,
    /// `DF_BIND_NOW`, `DF_1_NOW`, or `DT_BIND_NOW` active.
    pub bind_now: bool,
}

impl DynamicSummary {
    /// Parse an iterator/slice of `Dyn64` entries until `DT_NULL`.
    pub fn from_entries(entries: &[Dyn64]) -> Self {
        let mut out = Self {
            syment: 24,
            relaent: 24,
            ..Self::default()
        };
        for &entry in entries {
            if entry.d_tag == dt::NULL {
                break;
            }
            match entry.d_tag {
                dt::NEEDED if out.needed_count < MAX_DT_NEEDED => {
                    out.needed_offs[out.needed_count] = entry.d_val;
                    out.needed_count += 1;
                }
                dt::PLTRELSZ => out.pltrelsz = entry.d_val,
                dt::HASH => out.hash = entry.d_val,
                dt::STRTAB => out.strtab = entry.d_val,
                dt::SYMTAB => out.symtab = entry.d_val,
                dt::RELA => out.rela = entry.d_val,
                dt::RELASZ => out.relasz = entry.d_val,
                dt::RELAENT => out.relaent = entry.d_val,
                dt::STRSZ => out.strsz = entry.d_val,
                dt::SYMENT => out.syment = entry.d_val,
                dt::INIT => out.init = entry.d_val,
                dt::FINI => out.fini = entry.d_val,
                dt::SONAME => out.soname_off = Some(entry.d_val),
                dt::SYMBOLIC => out.symbolic = true,
                dt::PLTREL => out.pltrel_is_rela = entry.d_val == dt::RELA as u64,
                dt::JMPREL => out.jmprel = entry.d_val,
                dt::BIND_NOW => out.bind_now = true,
                dt::INIT_ARRAY => out.init_array = entry.d_val,
                dt::INIT_ARRAYSZ => out.init_arraysz = entry.d_val,
                dt::FINI_ARRAY => out.fini_array = entry.d_val,
                dt::FINI_ARRAYSZ => out.fini_arraysz = entry.d_val,
                dt::GNU_HASH => out.gnu_hash = entry.d_val,
                dt::VERSYM => out.versym = entry.d_val,
                dt::VERDEF => out.verdef = entry.d_val,
                dt::VERDEFNUM => out.verdefnum = entry.d_val,
                dt::VERNEED => out.verneed = entry.d_val,
                dt::VERNEEDNUM => out.verneednum = entry.d_val,
                dt::FLAGS => {
                    if (entry.d_val & dt::DF_SYMBOLIC) != 0 {
                        out.symbolic = true;
                    }
                    if (entry.d_val & dt::DF_BIND_NOW) != 0 {
                        out.bind_now = true;
                    }
                }
                dt::FLAGS_1 if (entry.d_val & dt::DF_1_NOW) != 0 => {
                    out.bind_now = true;
                }
                _ => {}
            }
        }
        out
    }
}

/// Standard SysV ELF string hash.
pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = (h << 4).wrapping_add(u32::from(b));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// GNU ELF symbol hash (`DT_GNU_HASH`).
pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_mul(33).wrapping_add(u32::from(b));
    }
    h
}

/// Read a NUL-terminated byte slice from `strtab` at `offset`.
pub fn cstr_at(strtab: &[u8], offset: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let tail = strtab.get(start..)?;
    let len = tail.iter().position(|&b| b == 0)?;
    Some(&tail[..len])
}

/// Look up a symbol by name using a `DT_GNU_HASH` table slice (`u32` words).
///
/// `bloom_words` is `u64` entries when ELF64; `raw_u32` covers the whole
/// `DT_GNU_HASH` region starting at `[nbuckets, symoffset, bloom_size, bloom_shift]`.
pub fn gnu_hash_lookup<'a>(
    raw_u32: &[u32],
    syms: &'a [Sym64],
    strtab: &[u8],
    name: &[u8],
) -> Option<(usize, &'a Sym64)> {
    let nbuckets = *raw_u32.first()? as usize;
    let symoffset = *raw_u32.get(1)? as usize;
    let bloom_size = *raw_u32.get(2)? as usize;
    let bloom_shift = *raw_u32.get(3)?;
    if nbuckets == 0 || bloom_size == 0 {
        return None;
    }
    let bloom_u32_len = bloom_size.checked_mul(2)?;
    let buckets_start = 4usize.checked_add(bloom_u32_len)?;
    let chains_start = buckets_start.checked_add(nbuckets)?;
    if raw_u32.len() < chains_start {
        return None;
    }

    let h = gnu_hash(name);
    let bloom_idx = ((h as usize) / 64) % bloom_size;
    let lo = *raw_u32.get(4 + bloom_idx * 2)?;
    let hi = *raw_u32.get(4 + bloom_idx * 2 + 1)?;
    let bloom_word = u64::from(lo) | (u64::from(hi) << 32);
    let bit1 = 1u64 << (h % 64);
    let bit2 = 1u64 << ((h.wrapping_shr(bloom_shift)) % 64);
    if (bloom_word & (bit1 | bit2)) != (bit1 | bit2) {
        return None;
    }

    let bucket = *raw_u32.get(buckets_start + ((h as usize) % nbuckets))? as usize;
    if bucket < symoffset {
        return None;
    }

    let mut sym_idx = bucket;
    loop {
        let chain_idx = sym_idx.checked_sub(symoffset)?;
        let chain_val = *raw_u32.get(chains_start + chain_idx)?;
        if (chain_val & !1) == (h & !1) {
            if let Some(sym) = syms.get(sym_idx) {
                if sym.is_defined() && cstr_at(strtab, u64::from(sym.st_name)) == Some(name) {
                    return Some((sym_idx, sym));
                }
            }
        }
        if (chain_val & 1) != 0 {
            break;
        }
        sym_idx += 1;
    }
    None
}

/// Look up a symbol by name using a SysV `DT_HASH` table (`u32` words).
pub fn sysv_hash_lookup<'a>(
    raw_u32: &[u32],
    syms: &'a [Sym64],
    strtab: &[u8],
    name: &[u8],
) -> Option<(usize, &'a Sym64)> {
    let nbuckets = *raw_u32.first()? as usize;
    let nchains = *raw_u32.get(1)? as usize;
    if nbuckets == 0 || nchains == 0 {
        return None;
    }
    let buckets_start = 2usize;
    let chains_start = buckets_start.checked_add(nbuckets)?;
    if raw_u32.len() < chains_start.checked_add(nchains)? {
        return None;
    }
    let h = sysv_hash(name);
    let mut idx = *raw_u32.get(buckets_start + ((h as usize) % nbuckets))? as usize;
    let mut steps = 0usize;
    while idx != 0 && idx < nchains && steps < nchains {
        if let Some(sym) = syms.get(idx) {
            if sym.is_defined() && cstr_at(strtab, u64::from(sym.st_name)) == Some(name) {
                return Some((idx, sym));
            }
        }
        idx = *raw_u32.get(chains_start + idx)? as usize;
        steps += 1;
    }
    None
}

/// Verify ELF64 header bytes without failing on unaligned inputs.
pub fn is_valid_elf64_header(data: &[u8]) -> bool {
    data.len() >= ELF64_HEADER_BYTES && crate::validate_elf64_header::<()>(data).is_ok()
}

/// Fail-closed capability-first `SONAME` validator.
///
/// Rejects empty strings, `.`, `..`, any path separators (`/` or `\`), NUL,
/// whitespace, ASCII control characters, or names exceeding 255 bytes.
pub fn validate_soname(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 255 || name == b"." || name == b".." {
        return false;
    }
    for &b in name {
        if b == b'/' || b == b'\\' || b == 0 || b <= 0x20 || b >= 0x7f {
            return false;
        }
    }
    true
}

fn read_verdef64(bytes: &[u8], off: usize) -> Option<Verdef64> {
    if off.checked_add(20)? > bytes.len() {
        return None;
    }
    Some(Verdef64 {
        vd_version: read_u16(bytes, off)?,
        vd_flags: read_u16(bytes, off + 2)?,
        vd_ndx: read_u16(bytes, off + 4)?,
        vd_cnt: read_u16(bytes, off + 6)?,
        vd_hash: read_u32(bytes, off + 8)?,
        vd_aux: read_u32(bytes, off + 12)?,
        vd_next: read_u32(bytes, off + 16)?,
    })
}

fn read_verdaux64(bytes: &[u8], off: usize) -> Option<Verdaux64> {
    if off.checked_add(8)? > bytes.len() {
        return None;
    }
    Some(Verdaux64 {
        vda_name: read_u32(bytes, off)?,
        vda_next: read_u32(bytes, off + 4)?,
    })
}

fn read_verneed64(bytes: &[u8], off: usize) -> Option<Verneed64> {
    if off.checked_add(16)? > bytes.len() {
        return None;
    }
    Some(Verneed64 {
        vn_version: read_u16(bytes, off)?,
        vn_cnt: read_u16(bytes, off + 2)?,
        vn_file: read_u32(bytes, off + 4)?,
        vn_aux: read_u32(bytes, off + 8)?,
        vn_next: read_u32(bytes, off + 12)?,
    })
}

fn read_vernaux64(bytes: &[u8], off: usize) -> Option<Vernaux64> {
    if off.checked_add(16)? > bytes.len() {
        return None;
    }
    Some(Vernaux64 {
        vna_hash: read_u32(bytes, off)?,
        vna_flags: read_u16(bytes, off + 4)?,
        vna_other: read_u16(bytes, off + 6)?,
        vna_name: read_u32(bytes, off + 8)?,
        vna_next: read_u32(bytes, off + 12)?,
    })
}

/// Look up a defined version entry in `DT_VERDEF` by its `vd_ndx` (`>= 2`).
///
/// Returns `(version_name, vd_hash, vd_flags)` on success.
pub fn find_verdef_by_ndx<'a>(
    verdef_bytes: &[u8],
    verdefnum: usize,
    strtab: &'a [u8],
    ndx: u16,
) -> Option<(&'a [u8], u32, u16)> {
    let target = ndx & VERSYM_VERSION_MASK;
    if target < 2 || verdefnum == 0 {
        return None;
    }
    let mut off = 0usize;
    for _ in 0..verdefnum {
        let vd = read_verdef64(verdef_bytes, off)?;
        if vd.vd_version != 1 {
            return None;
        }
        if (vd.vd_ndx & VERSYM_VERSION_MASK) == target && vd.vd_cnt >= 1 {
            let aux_off = off.checked_add(usize::try_from(vd.vd_aux).ok()?)?;
            let aux = read_verdaux64(verdef_bytes, aux_off)?;
            let name = cstr_at(strtab, u64::from(aux.vda_name))?;
            return Some((name, vd.vd_hash, vd.vd_flags));
        }
        if vd.vd_next == 0 {
            break;
        }
        off = off.checked_add(usize::try_from(vd.vd_next).ok()?)?;
    }
    None
}

/// Check whether `DT_VERDEF` defines a version matching `(ver_name, ver_hash)`.
pub fn verdef_contains(
    verdef_bytes: &[u8],
    verdefnum: usize,
    strtab: &[u8],
    ver_name: &[u8],
    ver_hash: u32,
) -> bool {
    let mut off = 0usize;
    for _ in 0..verdefnum {
        let Some(vd) = read_verdef64(verdef_bytes, off) else {
            return false;
        };
        if vd.vd_version != 1 {
            return false;
        }
        if (vd.vd_flags & VER_FLG_BASE) == 0 && vd.vd_hash == ver_hash && vd.vd_cnt >= 1 {
            if let Some(aux_off) = usize::try_from(vd.vd_aux)
                .ok()
                .and_then(|a| off.checked_add(a))
            {
                if let Some(aux) = read_verdaux64(verdef_bytes, aux_off) {
                    if cstr_at(strtab, u64::from(aux.vda_name)) == Some(ver_name) {
                        return true;
                    }
                }
            }
        }
        if vd.vd_next == 0 {
            break;
        }
        let Some(next) = usize::try_from(vd.vd_next)
            .ok()
            .and_then(|n| off.checked_add(n))
        else {
            return false;
        };
        off = next;
    }
    false
}

/// Look up a required version entry in `DT_VERNEED` by its `vna_other` index.
///
/// Returns `(provider_soname, version_name, vna_hash, vna_flags)`.
pub fn find_verneed_by_ndx<'a>(
    verneed_bytes: &[u8],
    verneednum: usize,
    strtab: &'a [u8],
    ndx: u16,
) -> Option<(&'a [u8], &'a [u8], u32, u16)> {
    let target = ndx & VERSYM_VERSION_MASK;
    if target < 2 || verneednum == 0 {
        return None;
    }
    let mut off = 0usize;
    for _ in 0..verneednum {
        let vn = read_verneed64(verneed_bytes, off)?;
        if vn.vn_version != 1 {
            return None;
        }
        let lib_name = cstr_at(strtab, u64::from(vn.vn_file))?;
        let mut aux_off = off.checked_add(usize::try_from(vn.vn_aux).ok()?)?;
        for _ in 0..vn.vn_cnt {
            let vna = read_vernaux64(verneed_bytes, aux_off)?;
            if (vna.vna_other & VERSYM_VERSION_MASK) == target {
                let ver_name = cstr_at(strtab, u64::from(vna.vna_name))?;
                return Some((lib_name, ver_name, vna.vna_hash, vna.vna_flags));
            }
            if vna.vna_next == 0 {
                break;
            }
            aux_off = aux_off.checked_add(usize::try_from(vna.vna_next).ok()?)?;
        }
        if vn.vn_next == 0 {
            break;
        }
        off = off.checked_add(usize::try_from(vn.vn_next).ok()?)?;
    }
    None
}

/// Validate all non-weak `DT_VERNEED` requirements against loaded providers.
///
/// `provider_lookup(soname)` returns `Some((verdef_bytes, verdefnum, strtab))`
/// when `soname` is loaded and defines versions, or `None` if missing.
/// Returns `Err((soname, version_name))` on the first unsatisfied non-weak
/// version requirement.
pub fn validate_verneed_table<'a, F>(
    verneed_bytes: &[u8],
    verneednum: usize,
    req_strtab: &'a [u8],
    mut provider_lookup: F,
) -> Result<(), (&'a [u8], &'a [u8])>
where
    F: FnMut(&[u8]) -> Option<(&'a [u8], usize, &'a [u8])>,
{
    if verneednum == 0 {
        return Ok(());
    }
    let mut off = 0usize;
    for _ in 0..verneednum {
        let Some(vn) = read_verneed64(verneed_bytes, off) else {
            return Err((b"", b"malformed-verneed"));
        };
        if vn.vn_version != 1 {
            return Err((b"", b"bad-verneed-version"));
        }
        let lib_name = cstr_at(req_strtab, u64::from(vn.vn_file)).unwrap_or(b"");
        let provider = provider_lookup(lib_name);
        let mut aux_off = usize::try_from(vn.vn_aux)
            .ok()
            .and_then(|a| off.checked_add(a))
            .ok_or((lib_name, b"malformed-vernaux".as_slice()))?;
        for _ in 0..vn.vn_cnt {
            let Some(vna) = read_vernaux64(verneed_bytes, aux_off) else {
                return Err((lib_name, b"malformed-vernaux"));
            };
            let ver_name = cstr_at(req_strtab, u64::from(vna.vna_name)).unwrap_or(b"");
            if (vna.vna_flags & VER_FLG_WEAK) == 0 {
                let Some((vd_bytes, vd_num, vd_strtab)) = provider else {
                    return Err((lib_name, ver_name));
                };
                if !verdef_contains(vd_bytes, vd_num, vd_strtab, ver_name, vna.vna_hash) {
                    return Err((lib_name, ver_name));
                }
            }
            if vna.vna_next == 0 {
                break;
            }
            aux_off = usize::try_from(vna.vna_next)
                .ok()
                .and_then(|n| aux_off.checked_add(n))
                .ok_or((lib_name, ver_name))?;
        }
        if vn.vn_next == 0 {
            break;
        }
        off = usize::try_from(vn.vn_next)
            .ok()
            .and_then(|n| off.checked_add(n))
            .ok_or((lib_name, b"malformed-verneed".as_slice()))?;
    }
    Ok(())
}

/// Check whether a candidate symbol's `DT_VERSYM` entry satisfies a lookup.
///
/// - `req_ver`: `Some((ver_name, ver_hash))` when the caller specified a
///   version via `DT_VERNEED`, or `None` for unversioned lookup (`dlsym` or
///   unversioned object).
/// - `cand_versym`: `Some(u16)` from the candidate's `DT_VERSYM`, or `None` if
///   the candidate has no `DT_VERSYM`.
pub fn symbol_version_matches(
    req_ver: Option<(&[u8], u32)>,
    cand_versym: Option<u16>,
    cand_verdef_bytes: &[u8],
    cand_verdefnum: usize,
    cand_strtab: &[u8],
    is_dlsym: bool,
) -> bool {
    let Some(vs) = cand_versym else {
        // Unversioned provider satisfies unversioned requests (and base globals).
        return req_ver.is_none();
    };
    let hidden = (vs & VERSYM_HIDDEN) != 0;
    let ndx = vs & VERSYM_VERSION_MASK;
    if ndx == VER_NDX_LOCAL {
        return false;
    }
    match req_ver {
        Some((req_name, req_hash)) => {
            if ndx == VER_NDX_GLOBAL {
                // Global unversioned symbol in candidate does not match explicit
                // versioned import unless candidate has no DT_VERDEF at all.
                return cand_verdefnum == 0;
            }
            let Some((cand_name, cand_hash, _)) =
                find_verdef_by_ndx(cand_verdef_bytes, cand_verdefnum, cand_strtab, ndx)
            else {
                return false;
            };
            cand_hash == req_hash && cand_name == req_name
        }
        None => {
            // Unversioned reference or dlsym: accept global (1) or non-hidden
            // default version (>= 2). Hidden versions are skipped for dlsym
            // and unversioned references.
            if is_dlsym {
                ndx == VER_NDX_GLOBAL || (!hidden && ndx >= 2)
            } else {
                !hidden
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_standard_vectors() {
        assert_eq!(gnu_hash(b""), 5381);
        assert_eq!(gnu_hash(b"printf"), 0x156b_2bb8);
        assert_eq!(sysv_hash(b"printf"), 0x0779_05a6);
    }

    #[test]
    fn dynamic_summary_parses_needed_flags_and_tables() {
        let entries = [
            Dyn64 {
                d_tag: dt::NEEDED,
                d_val: 1,
            },
            Dyn64 {
                d_tag: dt::STRTAB,
                d_val: 0x1000,
            },
            Dyn64 {
                d_tag: dt::SYMTAB,
                d_val: 0x2000,
            },
            Dyn64 {
                d_tag: dt::FLAGS_1,
                d_val: dt::DF_1_NOW,
            },
            Dyn64 {
                d_tag: dt::INIT_ARRAY,
                d_val: 0x3000,
            },
            Dyn64 {
                d_tag: dt::INIT_ARRAYSZ,
                d_val: 16,
            },
            Dyn64 {
                d_tag: dt::NULL,
                d_val: 0,
            },
        ];
        let summary = DynamicSummary::from_entries(&entries);
        assert_eq!(summary.needed_count, 1);
        assert_eq!(summary.needed_offs[0], 1);
        assert_eq!(summary.strtab, 0x1000);
        assert_eq!(summary.symtab, 0x2000);
        assert!(summary.bind_now);
        assert_eq!(summary.init_array, 0x3000);
        assert_eq!(summary.init_arraysz, 16);
    }

    #[test]
    fn gnu_hash_lookup_resolves_defined_symbol_and_skips_undef() {
        let strtab = b"\0missing\0canvas_write\0";
        let syms = [
            Sym64::default(),
            Sym64 {
                st_name: 1,
                st_info: (STB_GLOBAL << 4) | 2,
                st_other: 0,
                st_shndx: SHN_UNDEF,
                st_value: 0,
                st_size: 0,
            },
            Sym64 {
                st_name: 9,
                st_info: (STB_GLOBAL << 4) | 2,
                st_other: 0,
                st_shndx: 1,
                st_value: 0x1234,
                st_size: 32,
            },
        ];
        let h = gnu_hash(b"canvas_write");
        let bit1 = 1u64 << (h % 64);
        let bit2 = 1u64 << ((h >> 6) % 64);
        let bloom = bit1 | bit2;
        let table = [
            1u32,                 // nbuckets
            1u32,                 // symoffset
            1u32,                 // bloom_size
            6u32,                 // bloom_shift
            bloom as u32,         // bloom lo
            (bloom >> 32) as u32, // bloom hi
            1u32,                 // bucket[0] = sym 1
            gnu_hash(b"missing") & !1,
            (h & !1) | 1, // end of chain
        ];
        let found = gnu_hash_lookup(&table, &syms, strtab, b"canvas_write");
        assert_eq!(found.map(|(i, s)| (i, s.st_value)), Some((2, 0x1234)));
        assert_eq!(gnu_hash_lookup(&table, &syms, strtab, b"missing"), None);
        assert_eq!(gnu_hash_lookup(&table, &syms, strtab, b"other"), None);
    }

    #[test]
    fn soname_validator_is_fail_closed() {
        assert!(validate_soname(b"libcanvas.so"));
        assert!(validate_soname(b"libsmoke_plugin-1.0.so"));
        assert!(!validate_soname(b""));
        assert!(!validate_soname(b"."));
        assert!(!validate_soname(b".."));
        assert!(!validate_soname(b"../libcanvas.so"));
        assert!(!validate_soname(b"/lib/libcanvas.so"));
        assert!(!validate_soname(b"sub/libcanvas.so"));
        assert!(!validate_soname(b"sub\\libcanvas.so"));
        assert!(!validate_soname(b"lib\0canvas.so"));
        assert!(!validate_soname(b"lib canvas.so"));
        assert!(!validate_soname(&[b'a'; 256]));
    }

    fn push_u16(buf: &mut [u8], pos: &mut usize, v: u16) {
        buf[*pos..*pos + 2].copy_from_slice(&v.to_le_bytes());
        *pos += 2;
    }

    fn push_u32(buf: &mut [u8], pos: &mut usize, v: u32) {
        buf[*pos..*pos + 4].copy_from_slice(&v.to_le_bytes());
        *pos += 4;
    }

    #[test]
    fn symbol_versioning_verdef_verneed_and_matching() {
        // Provider strtab: \0 libcanvas.so \0 CANVAS_ABI_1.0 \0 CANVAS_ABI_2.0 \0
        let prov_strtab = b"\0libcanvas.so\0CANVAS_ABI_1.0\0CANVAS_ABI_2.0\0";
        let h1 = sysv_hash(b"CANVAS_ABI_1.0");
        let h2 = sysv_hash(b"CANVAS_ABI_2.0");

        // Build DT_VERDEF with 2 entries:
        // [0] ndx=1 BASE ("libcanvas.so", off 1) -> vd_next = 28
        // [1] ndx=2 ("CANVAS_ABI_1.0", off 14) -> vd_next = 0
        let mut verdef = [0u8; 56];
        let mut p = 0usize;
        // Verdef #0 (20 bytes) + Verdaux (8 bytes) = 28 bytes
        push_u16(&mut verdef, &mut p, 1); // vd_version
        push_u16(&mut verdef, &mut p, VER_FLG_BASE);
        push_u16(&mut verdef, &mut p, 1); // vd_ndx
        push_u16(&mut verdef, &mut p, 1); // vd_cnt
        push_u32(&mut verdef, &mut p, sysv_hash(b"libcanvas.so"));
        push_u32(&mut verdef, &mut p, 20); // vd_aux
        push_u32(&mut verdef, &mut p, 28); // vd_next
        push_u32(&mut verdef, &mut p, 1); // vda_name = "libcanvas.so"
        push_u32(&mut verdef, &mut p, 0); // vda_next
                                          // Verdef #1
        push_u16(&mut verdef, &mut p, 1);
        push_u16(&mut verdef, &mut p, 0);
        push_u16(&mut verdef, &mut p, 2); // vd_ndx = 2
        push_u16(&mut verdef, &mut p, 1);
        push_u32(&mut verdef, &mut p, h1);
        push_u32(&mut verdef, &mut p, 20);
        push_u32(&mut verdef, &mut p, 0);
        push_u32(&mut verdef, &mut p, 14); // vda_name = "CANVAS_ABI_1.0"
        push_u32(&mut verdef, &mut p, 0);

        assert!(verdef_contains(
            &verdef,
            2,
            prov_strtab,
            b"CANVAS_ABI_1.0",
            h1
        ));
        assert!(!verdef_contains(
            &verdef,
            2,
            prov_strtab,
            b"CANVAS_ABI_2.0",
            h2
        ));
        assert_eq!(
            find_verdef_by_ndx(&verdef, 2, prov_strtab, 2),
            Some((b"CANVAS_ABI_1.0".as_slice(), h1, 0))
        );

        // Build DT_VERNEED requiring CANVAS_ABI_1.0 (vna_other = 2) and optional weak 2.0 (vna_other = 3)
        let mut verneed = [0u8; 48];
        let mut q = 0usize;
        push_u16(&mut verneed, &mut q, 1); // vn_version
        push_u16(&mut verneed, &mut q, 2); // vn_cnt
        push_u32(&mut verneed, &mut q, 1); // vn_file = "libcanvas.so"
        push_u32(&mut verneed, &mut q, 16); // vn_aux
        push_u32(&mut verneed, &mut q, 0); // vn_next
                                           // Vernaux #0: CANVAS_ABI_1.0 (strong)
        push_u32(&mut verneed, &mut q, h1);
        push_u16(&mut verneed, &mut q, 0);
        push_u16(&mut verneed, &mut q, 2); // vna_other = 2
        push_u32(&mut verneed, &mut q, 14); // vna_name = "CANVAS_ABI_1.0"
        push_u32(&mut verneed, &mut q, 16); // vna_next
                                            // Vernaux #1: CANVAS_ABI_2.0 (weak)
        push_u32(&mut verneed, &mut q, h2);
        push_u16(&mut verneed, &mut q, VER_FLG_WEAK);
        push_u16(&mut verneed, &mut q, 3); // vna_other = 3
        push_u32(&mut verneed, &mut q, 29); // vna_name = "CANVAS_ABI_2.0"
        push_u32(&mut verneed, &mut q, 0);

        assert_eq!(
            find_verneed_by_ndx(&verneed, 1, prov_strtab, 2),
            Some((
                b"libcanvas.so".as_slice(),
                b"CANVAS_ABI_1.0".as_slice(),
                h1,
                0
            ))
        );
        assert!(validate_verneed_table(&verneed, 1, prov_strtab, |lib| {
            (lib == b"libcanvas.so").then_some((&verdef, 2, prov_strtab))
        })
        .is_ok());

        // Turn Vernaux #1 non-weak -> must fail validation on CANVAS_ABI_2.0
        verneed[36..38].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            validate_verneed_table(&verneed, 1, prov_strtab, |lib| {
                (lib == b"libcanvas.so").then_some((&verdef, 2, prov_strtab))
            }),
            Err((b"libcanvas.so".as_slice(), b"CANVAS_ABI_2.0".as_slice()))
        );

        // Symbol version matching: default vs hidden vs local
        assert!(symbol_version_matches(
            Some((b"CANVAS_ABI_1.0", h1)),
            Some(2),
            &verdef,
            2,
            prov_strtab,
            false
        ));
        assert!(symbol_version_matches(
            Some((b"CANVAS_ABI_1.0", h1)),
            Some(2 | VERSYM_HIDDEN),
            &verdef,
            2,
            prov_strtab,
            false
        ));
        assert!(!symbol_version_matches(
            None,
            Some(2 | VERSYM_HIDDEN),
            &verdef,
            2,
            prov_strtab,
            true
        ));
        assert!(symbol_version_matches(
            None,
            Some(2),
            &verdef,
            2,
            prov_strtab,
            true
        ));
        assert!(!symbol_version_matches(
            None,
            Some(VER_NDX_LOCAL),
            &verdef,
            2,
            prov_strtab,
            true
        ));
    }

    #[test]
    fn dynamic_summary_parses_versym_verdef_verneed_and_dtpmod() {
        let entries = [
            Dyn64 {
                d_tag: dt::VERSYM,
                d_val: 0x4000,
            },
            Dyn64 {
                d_tag: dt::VERDEF,
                d_val: 0x4100,
            },
            Dyn64 {
                d_tag: dt::VERDEFNUM,
                d_val: 2,
            },
            Dyn64 {
                d_tag: dt::VERNEED,
                d_val: 0x4200,
            },
            Dyn64 {
                d_tag: dt::VERNEEDNUM,
                d_val: 1,
            },
            Dyn64 {
                d_tag: dt::NULL,
                d_val: 0,
            },
        ];
        let summary = DynamicSummary::from_entries(&entries);
        assert_eq!(summary.versym, 0x4000);
        assert_eq!(summary.verdef, 0x4100);
        assert_eq!(summary.verdefnum, 2);
        assert_eq!(summary.verneed, 0x4200);
        assert_eq!(summary.verneednum, 1);
        assert_eq!(r_x86_64::DTPMOD64, 16);
        assert_eq!(r_x86_64::DTPOFF64, 17);
    }
}
