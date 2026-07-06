//! Tiny static ELF parser used by the userspace launcher.

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
pub(super) const PT_LOAD: u32 = 1;
pub(super) const PF_X: u32 = 1;
pub(super) const PF_W: u32 = 2;
pub(super) const PF_R: u32 = 4;
const ELF64_PHDR_SIZE: u16 = 56;
pub(super) const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy)]
pub(super) struct ElfImage {
    pub(super) entry: u64,
    pub(super) phoff: u64,
    pub(super) phentsize: u16,
    pub(super) phnum: u16,
}

#[derive(Clone, Copy)]
pub(super) struct ProgramHeader {
    pub(super) ty: u32,
    pub(super) flags: u32,
    pub(super) offset: u64,
    pub(super) vaddr: u64,
    pub(super) filesz: u64,
    pub(super) memsz: u64,
}

pub(super) fn parse_elf(data: &[u8]) -> Option<ElfImage> {
    if data.get(0..4)? != &ELF_MAGIC[..] {
        return None;
    }
    if *data.get(4)? != ELFCLASS64 || *data.get(5)? != ELFDATA2LSB || *data.get(6)? != 1 {
        return None;
    }
    if read_u16(data, 16)? != ET_EXEC {
        return None;
    }

    let phentsize = read_u16(data, 54)?;
    if phentsize < ELF64_PHDR_SIZE {
        return None;
    }

    Some(ElfImage {
        entry: read_u64(data, 24)?,
        phoff: read_u64(data, 32)?,
        phentsize,
        phnum: read_u16(data, 56)?,
    })
}

pub(super) fn read_program_header(
    data: &[u8],
    image: ElfImage,
    index: u16,
) -> Option<ProgramHeader> {
    let off = image
        .phoff
        .checked_add(index as u64 * image.phentsize as u64)? as usize;
    Some(ProgramHeader {
        ty: read_u32(data, off)?,
        flags: read_u32(data, off + 4)?,
        offset: read_u64(data, off + 8)?,
        vaddr: read_u64(data, off + 16)?,
        filesz: read_u64(data, off + 32)?,
        memsz: read_u64(data, off + 40)?,
    })
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    let bytes = data.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(super) fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

pub(super) fn align_up(value: u64, align: u64) -> Option<u64> {
    Some(value.checked_add(align - 1)? & !(align - 1))
}
