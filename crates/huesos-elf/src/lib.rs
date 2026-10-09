//! # HuesOS ELF Loader
//!
//! Parses static, non-PIE ELF64 executables (the userspace init program and,
//! eventually, any userspace binary) and loads their `PT_LOAD` segments into
//! a target address space via a small trait the kernel implements. Kept
//! independent of `huesos-arch`/`huesos-vmm` so it has no circular deps and
//! can be unit-tested on the host.

#![no_std]
#![warn(missing_docs)]

/// ELF64 header size; `e_ehsize` must match.
const ELF64_HEADER_BYTES: usize = 64;
/// ELF64 program header size; `e_phentsize` must match when `e_phnum != 0`.
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
/// `e_type` value for a non-PIE executable.
const ET_EXEC: u16 = 2;
/// `p_type` value for a loadable segment.
const PT_LOAD: u32 = 1;
/// `p_flags` execute bit.
const PF_X: u32 = 1;
/// `p_flags` write bit.
const PF_W: u32 = 2;
/// `p_flags` read bit.
const PF_R: u32 = 4;

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
    /// Target-specific mapping failure.
    type Error;

    /// Map a fresh, zeroed page at `vaddr` with the given permissions and
    /// return a kernel-accessible pointer to that page's contents (e.g. via
    /// the HHDM) so the loader can copy segment data into it.
    fn map_zeroed_page(&mut self, vaddr: u64, flags: SegmentFlags) -> Result<*mut u8, Self::Error>;
}

/// Errors that can occur while loading an ELF binary.
#[derive(Debug)]
pub enum ElfLoadError<E = ()> {
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
    /// The target address space could not map a segment page.
    Mapping(E),
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
///
/// The ELF header and program header table are decoded field by field with
/// byte-wise little-endian reads. Nothing here requires the input, or the
/// table offsets inside it, to be naturally aligned. A typed-struct reader
/// (xmas-elf over `zero::read`) panicked on an unaligned `e_phoff`, and the
/// kernel must not panic on a malformed or hostile binary.
pub fn load<L: Loader>(data: &[u8], loader: &mut L) -> Result<LoadedElf, ElfLoadError<L::Error>> {
    validate_elf64_header(data)?;

    let e_type = read_u16(data, 16).ok_or(ElfLoadError::ParseError("missing e_type"))?;
    if e_type != ET_EXEC {
        return Err(ElfLoadError::Unsupported(
            "only ET_EXEC binaries are supported",
        ));
    }
    let entry_point = read_u64(data, 24).ok_or(ElfLoadError::ParseError("missing e_entry"))?;
    let phoff = read_u64(data, 32).ok_or(ElfLoadError::ParseError("missing e_phoff"))?;
    let phnum = read_u16(data, 56).ok_or(ElfLoadError::ParseError("missing e_phnum"))?;

    let mut highest_addr = 0u64;
    let mut loadable_segments = 0usize;
    for index in 0..usize::from(phnum) {
        let ph = read_program_header(data, phoff, index)?;
        if ph.p_type != PT_LOAD {
            continue;
        }
        load_segment(&ph, data, loader)?;
        loadable_segments += 1;
        let seg_end = ph
            .p_vaddr
            .checked_add(ph.p_memsz)
            .ok_or(ElfLoadError::SegmentOutOfBounds)?;
        if seg_end > highest_addr {
            highest_addr = seg_end;
        }
    }

    // An executable with no PT_LOAD segment has nothing mapped at its entry
    // point. Refuse it instead of returning a successful but unrunnable load.
    if loadable_segments == 0 {
        return Err(ElfLoadError::ParseError("no PT_LOAD segments"));
    }

    Ok(LoadedElf {
        entry_point,
        highest_addr,
    })
}

fn validate_elf64_header<E>(data: &[u8]) -> Result<(), ElfLoadError<E>> {
    if data.len() < ELF64_HEADER_BYTES || data.get(..4) != Some(b"\x7fELF") {
        return Err(ElfLoadError::ParseError("truncated or invalid ELF magic"));
    }
    // Only ELF64 little-endian version 1 is accepted. Other shapes are
    // rejected here, before any field is decoded.
    if data[4] != 2 || data[5] != 1 || data[6] != 1 {
        return Err(ElfLoadError::Unsupported(
            "only little-endian ELF64 version 1 is supported",
        ));
    }
    let ehsize = read_u16(data, 52).ok_or(ElfLoadError::ParseError("missing e_ehsize"))?;
    let phentsize = read_u16(data, 54).ok_or(ElfLoadError::ParseError("missing e_phentsize"))?;
    let phnum = read_u16(data, 56).ok_or(ElfLoadError::ParseError("missing e_phnum"))?;
    let phoff = read_u64(data, 32).ok_or(ElfLoadError::ParseError("missing e_phoff"))?;
    if usize::from(ehsize) != ELF64_HEADER_BYTES
        || (phnum != 0 && usize::from(phentsize) != ELF64_PROGRAM_HEADER_BYTES)
    {
        return Err(ElfLoadError::ParseError("invalid ELF64 header geometry"));
    }
    let table_bytes = u64::from(phnum)
        .checked_mul(u64::from(phentsize))
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;
    let table_end = phoff
        .checked_add(table_bytes)
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;
    if table_end > data.len() as u64 {
        return Err(ElfLoadError::SegmentOutOfBounds);
    }
    Ok(())
}

/// Decoded fields of one ELF64 program header.
#[derive(Clone, Copy, Debug)]
struct ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

/// Decode program header `index` from the table at `phoff`. Every field is
/// read with a byte-wise little-endian load, so `phoff` may be any value.
fn read_program_header<E>(
    data: &[u8],
    phoff: u64,
    index: usize,
) -> Result<ProgramHeader, ElfLoadError<E>> {
    let truncated = ElfLoadError::ParseError("truncated program header");
    let entry_offset = (index as u64)
        .checked_mul(ELF64_PROGRAM_HEADER_BYTES as u64)
        .and_then(|rel| phoff.checked_add(rel))
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;
    let base = usize::try_from(entry_offset).map_err(|_| ElfLoadError::SegmentOutOfBounds)?;
    Ok(ProgramHeader {
        p_type: read_u32(data, base).ok_or(truncated)?,
        p_flags: read_u32(data, base + 4)
            .ok_or(ElfLoadError::ParseError("truncated program header"))?,
        p_offset: read_u64(data, base + 8)
            .ok_or(ElfLoadError::ParseError("truncated program header"))?,
        p_vaddr: read_u64(data, base + 16)
            .ok_or(ElfLoadError::ParseError("truncated program header"))?,
        p_filesz: read_u64(data, base + 32)
            .ok_or(ElfLoadError::ParseError("truncated program header"))?,
        p_memsz: read_u64(data, base + 40)
            .ok_or(ElfLoadError::ParseError("truncated program header"))?,
    })
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = data.get(offset..end)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = data.get(offset..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes = data.get(offset..end)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn load_segment<L: Loader>(
    ph: &ProgramHeader,
    file_data: &[u8],
    loader: &mut L,
) -> Result<(), ElfLoadError<L::Error>> {
    let flags = SegmentFlags {
        read: ph.p_flags & PF_R != 0,
        write: ph.p_flags & PF_W != 0,
        execute: ph.p_flags & PF_X != 0,
    };

    let vaddr_start = ph.p_vaddr;
    let file_off = usize::try_from(ph.p_offset).map_err(|_| ElfLoadError::SegmentOutOfBounds)?;
    let file_size = usize::try_from(ph.p_filesz).map_err(|_| ElfLoadError::SegmentOutOfBounds)?;
    let mem_size = ph.p_memsz;

    // A well-formed PT_LOAD segment always has file_size <= mem_size (the
    // file only ever provides *initial* contents; anything beyond
    // file_size up to mem_size is BSS-style zero-fill). Reject anything
    // else up front rather than let later arithmetic silently do the
    // wrong thing.
    if ph.p_filesz > mem_size {
        return Err(ElfLoadError::SegmentOutOfBounds);
    }

    // Bounds-check the claimed file range against the actual file data
    // *before* slicing into it, with checked arithmetic throughout.
    let file_end = file_off
        .checked_add(file_size)
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;
    if file_end > file_data.len() {
        return Err(ElfLoadError::SegmentOutOfBounds);
    }

    let page_start = align_down(vaddr_start, PAGE_SIZE);
    let mem_end = vaddr_start
        .checked_add(mem_size)
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;
    let page_end = align_up(mem_end, PAGE_SIZE).ok_or(ElfLoadError::SegmentOutOfBounds)?;

    let segment_bytes = &file_data[file_off..file_end];

    let seg_file_end = vaddr_start
        .checked_add(ph.p_filesz)
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;

    let mut page = page_start;
    while page < page_end {
        let dst = loader
            .map_zeroed_page(page, flags)
            .map_err(ElfLoadError::Mapping)?;

        // Compute overlap between [page, page+PAGE_SIZE) and the segment's
        // file-backed range [vaddr_start, seg_file_end).
        let seg_file_start = vaddr_start;
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

    Ok(())
}

fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

/// Round `addr` up to `align`, or `None` if the result would overflow.
fn align_up(addr: u64, align: u64) -> Option<u64> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
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
        type Error = ();

        fn map_zeroed_page(
            &mut self,
            vaddr: u64,
            _flags: SegmentFlags,
        ) -> Result<*mut u8, Self::Error> {
            let page = align_down(vaddr, PAGE_SIZE);
            let buf = self
                .pages
                .entry(page)
                .or_insert_with(|| std::vec![0u8; PAGE_SIZE as usize]);
            Ok(buf.as_mut_ptr())
        }
    }

    #[test]
    fn align_helpers() {
        assert_eq!(align_down(0x1234, 0x1000), 0x1000);
        assert_eq!(align_up(0x1234, 0x1000), Some(0x2000));
        assert_eq!(align_down(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), Some(0x1000));
        // Rounding past u64::MAX must report overflow rather than wrap.
        assert_eq!(align_up(u64::MAX, 0x1000), None);
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
    fn build_minimal_elf(
        ph_offset: u32,
        ph_filesz: u32,
        ph_memsz: u32,
        total_len: usize,
    ) -> alloc::vec::Vec<u8> {
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
        let elf = build_minimal_elf(
            /* ph_offset */ 128, /* filesz */ 16, /* memsz */ 16, 256,
        );
        let mut loader = FakeLoader::new();
        let loaded = load(&elf, &mut loader).expect("well-formed minimal ELF should load");
        assert_eq!(loaded.entry_point, 0x400050);
    }

    #[test]
    fn preserves_target_mapping_failure() {
        #[derive(Debug, Eq, PartialEq)]
        struct InjectedFailure;

        struct FailingLoader;
        impl Loader for FailingLoader {
            type Error = InjectedFailure;

            fn map_zeroed_page(
                &mut self,
                _vaddr: u64,
                _flags: SegmentFlags,
            ) -> Result<*mut u8, Self::Error> {
                Err(InjectedFailure)
            }
        }

        let elf = build_minimal_elf(128, 16, 16, 256);
        let result = load(&elf, &mut FailingLoader);
        assert!(matches!(
            result,
            Err(ElfLoadError::Mapping(InjectedFailure))
        ));
    }

    #[test]
    fn rejects_fuzzed_elf32_shape_without_panicking() {
        // Coverage-guided fuzzing reached the program-header walk with this
        // ELF32/truncated geometry and triggered an out-of-bounds slice panic.
        let bytes = [
            0x7f, 0x45, 0x4c, 0x46, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x46,
            0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x7f, 0x45, 0x4c, 0x46,
            0x01, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x15, 0x45, 0x46, 0x7f, 0x45, 0x4c, 0x46,
            0x01, 0xfe, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x15, 0x45, 0x4c, 0x46, 0x46, 0xfe, 0xfe,
        ];
        let mut loader = FakeLoader::new();
        assert!(matches!(
            load(&bytes, &mut loader),
            Err(ElfLoadError::Unsupported(_)) | Err(ElfLoadError::ParseError(_))
        ));
    }

    #[test]
    fn rejects_segment_extending_past_end_of_file() {
        // p_offset + p_filesz reaches past the actual file length: this
        // used to panic with an out-of-bounds slice index instead of
        // returning a clean error.
        let elf = build_minimal_elf(
            /* ph_offset */ 128, /* filesz */ 1000, /* memsz */ 1000, 256,
        );
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
        let elf = build_minimal_elf(
            /* ph_offset */ 128, /* filesz */ 64, /* memsz */ 32, 256,
        );
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
    fn loads_program_header_table_at_unaligned_offset() {
        // e_phoff = 0x41 is not 8-byte aligned. The loader must decode the
        // table byte-wise and must not panic on the misalignment.
        let base = build_minimal_elf(128, 16, 16, 256);
        let mut elf = alloc::vec![0u8; 256];
        elf[..64].copy_from_slice(&base[..64]);
        elf[32..40].copy_from_slice(&0x41u64.to_le_bytes()); // e_phoff
        elf[0x41..0x41 + 56].copy_from_slice(&base[64..120]);
        let mut loader = FakeLoader::new();
        let result = load(&elf, &mut loader);
        assert!(result.is_ok(), "unaligned e_phoff must load: {:?}", result);
        if let Ok(loaded) = result {
            assert_eq!(loaded.entry_point, 0x400050);
            assert_eq!(loaded.highest_addr, 0x400010);
        }
        assert_eq!(loader.pages.len(), 1);
    }

    #[test]
    fn rejects_fuzzed_unaligned_phoff_without_panicking() {
        // Input from the CI elf_loader fuzz job (crash-ecd7a96b...). Its
        // e_phoff is 38, which made xmas-elf panic on an unaligned typed
        // read. The program header there is not PT_LOAD, so the image has
        // no loadable segment and must be rejected as a parse error.
        const CRASH: [u8; 101] = [
            127, 69, 76, 70, 2, 1, 1, 127, 0, 0, 0, 127, 69, 76, 70, 0, 2, 0, 0, 0, 0, 0, 46, 218,
            218, 218, 218, 218, 218, 218, 218, 64, 38, 0, 0, 0, 0, 0, 0, 0, 218, 218, 218, 218,
            218, 218, 38, 37, 255, 191, 37, 37, 64, 0, 56, 0, 1, 0, 0, 0, 0, 0, 0, 46, 235, 0, 152,
            86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86, 86,
            86, 86, 86, 86, 86, 86, 86, 152, 152, 152, 152, 39,
        ];
        let mut loader = FakeLoader::new();
        let result = load(&CRASH, &mut loader);
        assert!(
            matches!(result, Err(ElfLoadError::ParseError(_))),
            "expected ParseError, got {:?}",
            result
        );
        assert!(loader.pages.is_empty());
    }

    #[test]
    fn rejects_executable_without_pt_load() {
        // Valid header, but the single program header is PT_NOTE (4).
        let mut elf = build_minimal_elf(128, 16, 16, 256);
        elf[64..68].copy_from_slice(&4u32.to_le_bytes());
        let mut loader = FakeLoader::new();
        assert!(matches!(
            load(&elf, &mut loader),
            Err(ElfLoadError::ParseError("no PT_LOAD segments"))
        ));
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
        // The exact entry point address depends on the userspace linker
        // script's load address plus wherever the linker placed `_start`
        // within it, which shifts as huesos-init/libcanvas grow — so we
        // check that it lands in the expected *region* (the user_linker.ld
        // base) rather than pinning an exact byte offset that would need
        // updating every time the userspace binary's code size changes.
        assert!(
            (0x400000..0x500000).contains(&loaded.entry_point),
            "entry point {:#x} outside expected load region",
            loaded.entry_point
        );
        assert!(loaded.highest_addr > 0x400000);
        assert!(
            !loader.pages.is_empty(),
            "expected at least one page to have been mapped"
        );
    }
}
