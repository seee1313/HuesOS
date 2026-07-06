//! Process/thread-level primitives: exiting, yielding, and the skeleton
//! Zircon-like process launch wrappers.

use crate::channel::Channel;
use crate::handle::Handle;
use crate::raw;
use crate::vmo::Vmo;
use huesos_abi::{HandleValue, Syscall, VmarMapArgs, BOOTSTRAP_HANDLE, INVALID_HANDLE};

/// Initial bootstrap channel handle number installed in a newly-started
/// child process by `Thread::start`.
pub const CHILD_BOOTSTRAP_HANDLE: HandleValue = BOOTSTRAP_HANDLE;

/// An owned process handle.
#[derive(Debug)]
pub struct Process(Handle);

/// An owned thread handle.
#[derive(Debug)]
pub struct Thread(Handle);

/// An owned VMAR handle.
#[derive(Debug)]
pub struct Vmar(Handle);

impl Process {
    /// Create a suspended process and its root VMAR.
    ///
    /// This is an ABI skeleton: current kernels will return
    /// `ErrorCode::NotSupported` until the kernel-side implementation lands.
    pub fn create(name: &str) -> crate::Result<(Self, Vmar)> {
        if name.is_empty() {
            return Err(crate::ErrorCode::InvalidArgs);
        }

        let mut process: HandleValue = INVALID_HANDLE;
        let mut root_vmar: HandleValue = INVALID_HANDLE;
        let ret = unsafe {
            raw::syscall4(
                Syscall::ProcessCreate,
                name.as_ptr() as u64,
                name.len() as u64,
                &mut process as *mut HandleValue as u64,
                &mut root_vmar as *mut HandleValue as u64,
            )
        };
        raw::decode(ret)?;
        Ok((
            Self(unsafe { Handle::from_raw(process) }),
            Vmar(unsafe { Handle::from_raw(root_vmar) }),
        ))
    }

    /// Query the process exit code.
    ///
    /// Returns `Ok(None)` while the process is still running. A future
    /// blocking implementation can keep this wrapper and change only the
    /// kernel side once ports/waits are available.
    pub fn wait_exit(&self) -> crate::Result<Option<i64>> {
        let mut code: i64 = 0;
        let ret = unsafe {
            raw::syscall2(
                Syscall::ProcessWait,
                self.0.raw() as u64,
                &mut code as *mut i64 as u64,
            )
        };
        match raw::decode(ret) {
            Ok(_) => Ok(Some(code)),
            Err(crate::ErrorCode::ShouldWait) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Borrow the underlying process handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}

impl Thread {
    /// Create a suspended thread inside `process`.
    ///
    /// This reserves the userspace-facing wrapper for the approved
    /// create/map/thread/start launch path; the current kernel returns
    /// `ErrorCode::NotSupported` until implementation commits land.
    pub fn create(process: &Process, name: &str) -> crate::Result<Self> {
        if name.is_empty() {
            return Err(crate::ErrorCode::InvalidArgs);
        }

        let mut thread: HandleValue = INVALID_HANDLE;
        let ret = unsafe {
            raw::syscall4(
                Syscall::ThreadCreate,
                process.handle().raw() as u64,
                name.as_ptr() as u64,
                name.len() as u64,
                &mut thread as *mut HandleValue as u64,
            )
        };
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(thread) }))
    }

    /// Start the thread at `entry` with stack pointer `stack`.
    ///
    /// The kernel creates a bootstrap channel pair, installs the child side
    /// as `CHILD_BOOTSTRAP_HANDLE` in the child process, and returns the
    /// parent endpoint to the caller.
    pub fn start(&self, entry: u64, stack: u64) -> crate::Result<Channel> {
        let mut parent_bootstrap: HandleValue = INVALID_HANDLE;
        let ret = unsafe {
            raw::syscall4(
                Syscall::ThreadStart,
                self.0.raw() as u64,
                entry,
                stack,
                &mut parent_bootstrap as *mut HandleValue as u64,
            )
        };
        raw::decode(ret)?;
        Ok(unsafe { Channel::from_raw(parent_bootstrap) })
    }

    /// Borrow the underlying thread handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}

impl Vmar {
    /// Map `vmo` into this VMAR.
    ///
    /// `flags` is a bitmask from [`huesos_abi::vmar_flags`].
    pub fn map(
        &self,
        vmo: &Vmo,
        vmo_offset: u64,
        addr: u64,
        len: u64,
        flags: u32,
    ) -> crate::Result<u64> {
        let args = VmarMapArgs {
            vmar: self.0.raw(),
            vmo: vmo.handle().raw(),
            vmo_offset,
            addr,
            len,
            flags,
        };
        let ret = unsafe { raw::syscall1(Syscall::VmarMap, &args as *const _ as u64) };
        raw::decode(ret).map(|mapped| mapped as u64)
    }

    /// Borrow the underlying VMAR handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}


// ============================================================================
// Static ELF process launcher
// ============================================================================

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ELF64_PHDR_SIZE: u16 = 56;
const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy)]
struct ElfImage {
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    ty: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

/// Load a static ELF image into a new process and start its initial thread.
///
/// This is the userspace half of the approved Zircon-like launch model:
/// create a process/root VMAR, map each `PT_LOAD` segment through VMOs,
/// map an initial stack, create a suspended main thread, and start it with
/// a bootstrap channel installed as handle 1 in the child.
pub fn spawn_elf(name: &str, elf: &[u8]) -> crate::Result<(Process, Channel)> {
    let image = parse_elf(elf).ok_or(crate::ErrorCode::InvalidArgs)?;
    let (process, root_vmar) = Process::create(name)?;

    let mut i = 0;
    while i < image.phnum {
        let ph = read_program_header(elf, image, i).ok_or(crate::ErrorCode::InvalidArgs)?;
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

    let page_start = align_down(ph.vaddr, PAGE_SIZE);
    let seg_end = ph
        .vaddr
        .checked_add(ph.memsz)
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    let page_end = align_up(seg_end, PAGE_SIZE).ok_or(crate::ErrorCode::InvalidArgs)?;
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

fn parse_elf(data: &[u8]) -> Option<ElfImage> {
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

fn read_program_header(data: &[u8], image: ElfImage, index: u16) -> Option<ProgramHeader> {
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

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> Option<u64> {
    Some(value.checked_add(align - 1)? & !(align - 1))
}

/// Exit the current process with `code`. Never returns.
pub fn exit(code: i64) -> ! {
    unsafe {
        let _ = raw::syscall1(Syscall::ProcessExit, code as u64);
    }
    // The kernel's ProcessExit handler never returns control, but the
    // compiler doesn't know that about a syscall; park just in case.
    loop {
        core::hint::spin_loop();
    }
}

/// Yield the remainder of the current thread's scheduling quantum
/// cooperatively.
pub fn yield_now() {
    unsafe {
        let _ = raw::syscall0(Syscall::Yield);
    }
}
