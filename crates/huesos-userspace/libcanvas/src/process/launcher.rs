//! Static ELF process launcher.

use crate::channel::Channel;
use crate::vmo::Vmo;

use super::elf::{self, ProgramHeader, PAGE_SIZE, PF_R, PF_W, PF_X, PT_LOAD};
use super::{Process, Thread, Vmar};

/// Load a static ELF image into a new process and start its initial thread.
///
/// This is the userspace half of the approved Zircon-like launch model:
/// create a process/root VMAR, map each `PT_LOAD` segment through VMOs,
/// map an initial stack, create a suspended main thread, and start it with
/// a bootstrap channel installed as handle 1 in the child.
pub fn spawn_elf(name: &str, elf: &[u8]) -> crate::Result<(Process, Channel)> {
    let image = elf::parse_elf(elf).ok_or(crate::ErrorCode::InvalidArgs)?;
    let (process, root_vmar) = Process::create(name)?;

    let mut i = 0;
    while i < image.phnum {
        let ph = elf::read_program_header(elf, image, i).ok_or(crate::ErrorCode::InvalidArgs)?;
        if ph.ty == PT_LOAD {
            map_load_segment(&root_vmar, elf, ph)?;
        }
        i += 1;
    }

    map_initial_stack(&root_vmar)?;
    let thread = Thread::create(&process, "main")?;
    let bootstrap = thread.start(image.entry, huesos_abi::USER_STACK_TOP - 32)?;
    Ok((process, bootstrap))
}

/// Load an ELF image from a VMO into a new process and start its initial thread.
pub fn spawn_elf_from_vmo(name: &str, vmo: &Vmo, offset: u64, _len: u64) -> crate::Result<(Process, Channel)> {
    // Read the header and program header table into a temporary buffer.
    // 4KB is usually enough for most ELF headers.
    let mut header_buf = [0u8; 4096];
    let read = vmo.read(offset, &mut header_buf)?;
    let header_slice = &header_buf[..read];

    let image = elf::parse_elf(header_slice).ok_or(crate::ErrorCode::InvalidArgs)?;
    let (process, root_vmar) = Process::create(name)?;

    let mut i = 0;
    while i < image.phnum {
        let ph = elf::read_program_header(header_slice, image, i).ok_or(crate::ErrorCode::InvalidArgs)?;
        if ph.ty == PT_LOAD {
            map_load_segment_from_vmo(&root_vmar, vmo, offset, ph)?;
        }
        i += 1;
    }

    map_initial_stack(&root_vmar)?;
    let thread = Thread::create(&process, "main")?;
    let bootstrap = thread.start(image.entry, huesos_abi::USER_STACK_TOP - 32)?;
    Ok((process, bootstrap))
}

fn map_load_segment(root_vmar: &Vmar, elf: &[u8], ph: ProgramHeader) -> crate::Result<()> {
    if ph.filesz > ph.memsz {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    let file_end = ph
        .offset
        .checked_add(ph.filesz)
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    if file_end > elf.len() as u64 {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    let page_start = elf::align_down(ph.vaddr, PAGE_SIZE);
    let seg_end = ph
        .vaddr
        .checked_add(ph.memsz)
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    let page_end = elf::align_up(seg_end, PAGE_SIZE).ok_or(crate::ErrorCode::InvalidArgs)?;
    if page_end <= page_start {
        return Ok(());
    }

    let map_len = page_end - page_start;
    let vmo = Vmo::create(map_len)?;

    if ph.filesz > 0 {
        let file_start = ph.offset as usize;
        let file_end = file_end as usize;
        let vmo_file_offset = ph.vaddr - page_start;
        let written = vmo.write(vmo_file_offset, &elf[file_start..file_end])?;
        if written != ph.filesz as usize {
            return Err(crate::ErrorCode::InvalidArgs);
        }
    }

    let flags = segment_vmar_flags(ph.flags)?;
    root_vmar.map(&vmo, 0, page_start, map_len, flags)?;
    Ok(())
}

fn map_load_segment_from_vmo(root_vmar: &Vmar, vmo: &Vmo, elf_offset: u64, ph: ProgramHeader) -> crate::Result<()> {
    if ph.filesz > ph.memsz {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    let page_start = elf::align_down(ph.vaddr, PAGE_SIZE);
    let seg_end = ph
        .vaddr
        .checked_add(ph.memsz)
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    let page_end = elf::align_up(seg_end, PAGE_SIZE).ok_or(crate::ErrorCode::InvalidArgs)?;
    if page_end <= page_start {
        return Ok(());
    }

    let map_len = page_end - page_start;
    let seg_vmo = Vmo::create(map_len)?;

    if ph.filesz > 0 {
        let mut buf = [0u8; 4096];
        let mut read_total = 0;
        let vmo_file_offset = ph.vaddr - page_start;

        while read_total < ph.filesz {
            let to_read = (ph.filesz - read_total).min(buf.len() as u64);
            vmo.read(elf_offset + ph.offset + read_total, &mut buf[..to_read as usize])?;
            seg_vmo.write(vmo_file_offset + read_total, &buf[..to_read as usize])?;
            read_total += to_read;
        }
    }

    let flags = segment_vmar_flags(ph.flags)?;
    root_vmar.map(&seg_vmo, 0, page_start, map_len, flags)?;
    Ok(())
}

fn map_initial_stack(root_vmar: &Vmar) -> crate::Result<()> {
    let stack_bottom = huesos_abi::USER_STACK_TOP - huesos_abi::USER_STACK_SIZE;
    let stack = Vmo::create(huesos_abi::USER_STACK_SIZE)?;
    root_vmar.map(
        &stack,
        0,
        stack_bottom,
        huesos_abi::USER_STACK_SIZE,
        huesos_abi::vmar_flags::READ
            | huesos_abi::vmar_flags::WRITE
            | huesos_abi::vmar_flags::USER
            | huesos_abi::vmar_flags::SPECIFIC,
    )?;
    Ok(())
}

fn segment_vmar_flags(ph_flags: u32) -> crate::Result<u32> {
    let mut flags = huesos_abi::vmar_flags::USER | huesos_abi::vmar_flags::SPECIFIC;
    if ph_flags & PF_R != 0 {
        flags |= huesos_abi::vmar_flags::READ;
    }
    if ph_flags & PF_W != 0 {
        flags |= huesos_abi::vmar_flags::WRITE;
    }
    if ph_flags & PF_X != 0 {
        flags |= huesos_abi::vmar_flags::EXECUTE;
    }
    if flags
        & (huesos_abi::vmar_flags::READ
            | huesos_abi::vmar_flags::WRITE
            | huesos_abi::vmar_flags::EXECUTE)
        == 0
    {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    Ok(flags)
}
