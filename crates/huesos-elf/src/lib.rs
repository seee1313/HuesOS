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

    let page_start = align_down(vaddr_start, PAGE_SIZE);
    let page_end = align_up(vaddr_start + mem_size, PAGE_SIZE);

    let segment_bytes = &file_data[file_off..file_off + file_size];

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
