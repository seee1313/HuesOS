//! # HuesOS ELF Loader
//!
//! Parses static, non-PIE ELF64 executables (the userspace init program and,
//! eventually, any userspace binary) and loads their `PT_LOAD` segments into
//! a target address space via a small trait the kernel implements. Kept
//! independent of `huesos-arch`/`huesos-vmm` so it has no circular deps and
//! can be unit-tested on the host.

#![no_std]
#![warn(missing_docs)]

use xmas_elf::program::{ProgramHeader, Type};
use xmas_elf::ElfFile;

/// Page size assumed by the loader (must match the target architecture).
pub const PAGE_SIZE: u64 = 4096;

/// Permissions requested for a loaded segment.
#[derive(Clone, Copy, Debug, Default)]
pub struct SegmentFlags {
    /// Segment must be readable (always true in practice).
    pub read: bool,
    /// Segment must be writable.
    pub write: bool,
    /// Segment must be executable.
    pub execute: bool,
}

/// Abstraction over "an address space that can have pages mapped into it",
/// implemented by the kernel using its real page-table machinery.
pub trait Loader {
    /// Map a fresh, zeroed page at `vaddr` with the given permissions and
    /// return a kernel-accessible pointer to that page's contents (e.g. via
    /// the HHDM) so the loader can copy segment data into it.
    fn map_zeroed_page(&mut self, vaddr: u64, flags: SegmentFlags) -> *mut u8;
}

/// Errors that can occur while loading an ELF binary.
#[derive(Debug)]
pub enum ElfLoadError {
    /// The file could not be parsed as an ELF64 image.
    ParseError(&'static str),
    /// The ELF is not a supported class/type (must be 64-bit executable).
    Unsupported(&'static str),
    /// A `PT_LOAD` segment's `(offset, file_size)` describes a byte range
    /// that extends past the end of the actual file data. This is *not* a
    /// hypothetical: any hand-written or slightly-off linker script,
    /// truncated file transfer, or plain bug in a from-scratch userspace
    /// program is enough to trigger it, and it must come back as a normal
    /// load error rather than an out-of-bounds slice panic that would take
    /// down the whole kernel just for trying to load a bad binary.
    SegmentOutOfBounds,
}

/// Result of successfully loading an ELF binary.
#[derive(Debug, Clone, Copy)]
pub struct LoadedElf {
    /// Entry point virtual address.
    pub entry_point: u64,
    /// Highest virtual address mapped (useful for placing the initial brk).
    pub highest_addr: u64,
}

/// Load `data` (the raw ELF file bytes) into the address space represented
/// by `loader`, mapping each `PT_LOAD` segment.
pub fn load<L: Loader>(data: &[u8], loader: &mut L) -> Result<LoadedElf, ElfLoadError> {
    let elf = ElfFile::new(data).map_err(ElfLoadError::ParseError)?;

    use xmas_elf::header::Type as HeaderType;
    match elf.header.pt2.type_().as_type() {
        HeaderType::Executable => {}
        _ => return Err(ElfLoadError::Unsupported("only ET_EXEC binaries are supported")),
    }

    let mut highest_addr = 0u64;

    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Load) {
            continue;
        }
        load_segment(&elf, &ph, data, loader)?;
        let seg_end = ph.virtual_addr() + ph.mem_size();
        if seg_end > highest_addr {
            highest_addr = seg_end;
        }
    }

    Ok(LoadedElf {
        entry_point: elf.header.pt2.entry_point(),
        highest_addr,
    })
}

fn load_segment<L: Loader>(
    elf: &ElfFile,
    ph: &ProgramHeader,
    file_data: &[u8],
    loader: &mut L,
) -> Result<(), ElfLoadError> {
    let flags = SegmentFlags {
        read: ph.flags().is_read(),
        write: ph.flags().is_write(),
        execute: ph.flags().is_execute(),
    };

    let vaddr_start = ph.virtual_addr();
    let file_off = ph.offset() as usize;
    let file_size = ph.file_size() as usize;
    let mem_size = ph.mem_size();

    // A well-formed PT_LOAD segment always has file_size <= mem_size (the
    // file only ever provides *initial* contents; anything beyond
    // file_size up to mem_size is BSS-style zero-fill). Reject anything
    // else up front rather than let later arithmetic silently do the
    // wrong thing.
    if file_size as u64 > mem_size {
        return Err(ElfLoadError::SegmentOutOfBounds);
    }

    // Bounds-check the claimed file range against the actual file data
    // *before* slicing into it. `file_off + file_size` on attacker- or
    // corruption-controlled values could also overflow `usize` on a
    // pathological input, so check with checked arithmetic rather than a
    // plain `+`.
    let file_end = file_off
        .checked_add(file_size)
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;
    if file_end > file_data.len() {
        return Err(ElfLoadError::SegmentOutOfBounds);
    }

    let page_start = align_down(vaddr_start, PAGE_SIZE);
    let page_end = align_up(vaddr_start + mem_size, PAGE_SIZE);

    let segment_bytes = &file_data[file_off..file_end];

    let mut page = page_start;
    while page < page_end {
        let dst = loader.map_zeroed_page(page, flags);

        // Compute overlap between [page, page+PAGE_SIZE) and the segment's
        // file-backed range [vaddr_start, vaddr_start+file_size).
        let seg_file_start = vaddr_start;
        let seg_file_end = vaddr_start + file_size as u64;
        let copy_start = core::cmp::max(page, seg_file_start);
        let copy_end = core::cmp::min(page + PAGE_SIZE, seg_file_end);

        if copy_start < copy_end {
            let page_off = (copy_start - page) as usize;
            let src_off = (copy_start - seg_file_start) as usize;
            let len = (copy_end - copy_start) as usize;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    segment_bytes.as_ptr().add(src_off),
                    dst.add(page_off),
                    len,
                );
            }
        }

        page += PAGE_SIZE;
    }

    let _ = elf; // reserved for future use (e.g. relocations)
    Ok(())
}

fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    extern crate alloc;
    extern crate std;

    struct FakeLoader {
        /// Backing store for "mapped pages", keyed by page-aligned vaddr.
        pages: alloc::collections::BTreeMap<u64, Vec<u8>>,
    }

    impl FakeLoader {
        fn new() -> Self {
            Self {
                pages: alloc::collections::BTreeMap::new(),
            }
        }
    }

    impl Loader for FakeLoader {
        fn map_zeroed_page(&mut self, vaddr: u64, _flags: SegmentFlags) -> *mut u8 {
            let page = align_down(vaddr, PAGE_SIZE);
            let buf = self
                .pages
                .entry(page)
                .or_insert_with(|| std::vec![0u8; PAGE_SIZE as usize]);
            buf.as_mut_ptr()
        }
    }

    #[test]
    fn align_helpers() {
        assert_eq!(align_down(0x1234, 0x1000), 0x1000);
        assert_eq!(align_up(0x1234, 0x1000), 0x2000);
        assert_eq!(align_down(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn rejects_garbage_input() {
        let mut loader = FakeLoader::new();
        let result = load(&[0, 1, 2, 3], &mut loader);
        assert!(matches!(result, Err(ElfLoadError::ParseError(_))));
    }

    /// Hand-assemble a minimal, otherwise-valid ELF64 ET_EXEC file with a
    /// single `PT_LOAD` program header, so we can exercise the segment
    /// bounds-checking added after a real out-of-bounds-slice panic bug.
    /// `ph_offset`/`ph_filesz` are deliberately parameterized so tests can
    /// pass in "lies" that a corrupted or hand-rolled linker script could
    /// plausibly produce.
    fn build_minimal_elf(ph_offset: u32, ph_filesz: u32, ph_memsz: u32, total_len: usize) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; total_len.max(64 + 56)];

        // e_ident
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EV_CURRENT

        // ELF64 header (Ehdr), little-endian.
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        buf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // e_machine = x86-64
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        buf[24..32].copy_from_slice(&0x400050u64.to_le_bytes()); // e_entry
        buf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff (right after Ehdr)
        buf[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        buf[48..52].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
        buf[58..60].copy_from_slice(&0u16.to_le_bytes()); // e_shentsize
        buf[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum
        buf[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        // Program header (Phdr) at offset 64.
        let ph = 64usize;
        buf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        buf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R+X
        buf[ph + 8..ph + 16].copy_from_slice(&(ph_offset as u64).to_le_bytes()); // p_offset
        buf[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
        buf[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes()); // p_paddr
        buf[ph + 32..ph + 40].copy_from_slice(&(ph_filesz as u64).to_le_bytes()); // p_filesz
        buf[ph + 40..ph + 48].copy_from_slice(&(ph_memsz as u64).to_le_bytes()); // p_memsz
        buf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

        buf
    }

    #[test]
    fn accepts_well_formed_minimal_elf() {
        // Sanity check for the hand-built ELF helper itself: a segment
        // whose claimed file range genuinely fits within the file must
        // still load successfully.
        let elf = build_minimal_elf(/* ph_offset */ 128, /* filesz */ 16, /* memsz */ 16, 256);
        let mut loader = FakeLoader::new();
        let loaded = load(&elf, &mut loader).expect("well-formed minimal ELF should load");
        assert_eq!(loaded.entry_point, 0x400050);
    }

    #[test]
    fn rejects_segment_extending_past_end_of_file() {
        // p_offset + p_filesz reaches past the actual file length: this
        // used to panic with an out-of-bounds slice index instead of
        // returning a clean error.
        let elf = build_minimal_elf(/* ph_offset */ 128, /* filesz */ 1000, /* memsz */ 1000, 256);
        let mut loader = FakeLoader::new();
        let result = load(&elf, &mut loader);
        assert!(
            matches!(result, Err(ElfLoadError::SegmentOutOfBounds)),
            "expected SegmentOutOfBounds, got {:?}",
            result
        );
    }

    #[test]
    fn rejects_filesz_greater_than_memsz() {
        // A segment claiming more file-backed bytes than its total memory
        // size is never valid (file_size must be <= mem_size).
        let elf = build_minimal_elf(/* ph_offset */ 128, /* filesz */ 64, /* memsz */ 32, 256);
        let mut loader = FakeLoader::new();
        let result = load(&elf, &mut loader);
        assert!(matches!(result, Err(ElfLoadError::SegmentOutOfBounds)));
    }

    #[test]
    fn rejects_offset_overflow_without_panicking() {
        // p_offset near usize::MAX combined with a nonzero filesz must be
        // rejected via checked arithmetic, not wrap around / panic.
        let elf = build_minimal_elf(u32::MAX, 16, 16, 256);
        let mut loader = FakeLoader::new();
        let result = load(&elf, &mut loader);
        assert!(matches!(result, Err(ElfLoadError::SegmentOutOfBounds)));
    }

    #[test]
    fn loads_real_userspace_init_binary() {
        // Built by `crates/huesos-userspace/init`'s own standalone cargo
        // invocation. This test is skipped (not failed) if it hasn't been
        // built yet, since it's a separate, non-workspace build step.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../huesos-userspace/init/target/x86_64-huesos-userspace/release/huesos-init");
        let Ok(bytes) = std::fs::read(&path) else {
            std::eprintln!("skipping: {} not built yet", path.display());
            return;
        };

        let mut loader = FakeLoader::new();
        let loaded = load(&bytes, &mut loader).expect("failed to load real init binary");
        assert_eq!(loaded.entry_point, 0x400050);
        assert!(loaded.highest_addr > 0x400000);
        assert!(
            !loader.pages.is_empty(),
            "expected at least one page to have been mapped"
        );
    }
}
