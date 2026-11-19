//! Static and dynamically-linked (`PT_INTERP`) ELF64 process launcher.

use crate::channel::Channel;
use crate::handle::Handle;
use crate::memory;
use crate::vmo::Vmo;
use huesos_abi::auxv::{
    caps_mask, AT_BASE, AT_ENTRY, AT_FLAGS, AT_HUESOS_BLOCK_DEV, AT_HUESOS_CAPS_MASK,
    AT_HUESOS_FRAME_DRAW, AT_HUESOS_HXFS_DIR, AT_HUESOS_HXFS_SERVICE, AT_HUESOS_LD_BOOTSTRAP,
    AT_HUESOS_LIB_VMO, AT_HUESOS_REGISTRY, AT_HUESOS_STDERR, AT_HUESOS_STDIN, AT_HUESOS_STDOUT,
    AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_RANDOM, LD_BOOTSTRAP_BLOCK_DEV_LABEL,
    LD_BOOTSTRAP_FRAME_DRAW_LABEL, LD_BOOTSTRAP_HXFS_DIR_LABEL, LD_BOOTSTRAP_HXFS_SERVICE_LABEL,
    LD_BOOTSTRAP_LIB_VMO_LABEL, LD_BOOTSTRAP_REGISTRY_LABEL, LD_BOOTSTRAP_SELF_VMAR_LABEL,
    LD_BOOTSTRAP_STDERR_LABEL, LD_BOOTSTRAP_STDIN_LABEL, LD_BOOTSTRAP_STDOUT_LABEL,
};
use huesos_abi::{rights, vmar_flags, vmo_create_flags, USER_STACK_TOP};
use huesos_elf::dynamic::{
    is_valid_elf64_header, read_phdr64, Phdr64, EM_X86_64, ET_DYN, ET_EXEC, PF_R, PF_W, PF_X,
    PT_INTERP, PT_LOAD, PT_PHDR,
};

use super::elf::{self, PAGE_SIZE};
use super::{Process, Thread, Vmar};

const HEADER_MAX: usize = 16 * 1024;
const MAIN_ASLR_BASE: u64 = 0x0000_0001_0000_0000;
const INTERP_ASLR_BASE: u64 = 0x0000_0004_0000_0000;
const ASLR_PAGE_MASK: u64 = 0x000f_ffff;
const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";

/// Capability and stdio descriptor passed when spawning a dynamic ELF via
/// [`spawn_elf_with_caps`] or [`spawn_elf_from_vmo_with_caps`].
pub struct SpawnCaps<'a> {
    /// Argument vector (`argv[0..]`); defaults to `[name]` if empty.
    pub args: &'a [&'a str],
    /// Capability bitmask (`huesos_abi::auxv::caps_mask`).
    pub caps_mask: u64,
    /// Optional `stdin` channel endpoint (child reads).
    pub stdin: Option<&'a Channel>,
    /// Optional `stdout` channel endpoint (child writes).
    pub stdout: Option<&'a Channel>,
    /// Optional `stderr` channel endpoint (child writes).
    pub stderr: Option<&'a Channel>,
    /// Optional attenuated HxFS directory channel (`AT_HUESOS_HXFS_DIR`).
    pub hxfs_dir: Option<&'a Channel>,
    /// Optional HxFS service channel (`AT_HUESOS_HXFS_SERVICE`).
    pub hxfs_service: Option<&'a Channel>,
    /// Optional block-device service channel (`AT_HUESOS_BLOCK_DEV`).
    pub block_dev: Option<&'a Channel>,
    /// Optional framebuffer draw resource handle (`AT_HUESOS_FRAME_DRAW`).
    pub frame_draw: Option<&'a Handle>,
    /// Optional `DriverManager` query/registry channel (`AT_HUESOS_REGISTRY`).
    pub registry: Option<&'a Channel>,
    /// Optional CPU pinning affinity.
    pub home_cpu: Option<usize>,
    /// Initial user stack size in bytes.
    pub stack_size: u64,
}

impl<'a> SpawnCaps<'a> {
    /// Construct a default full-capability descriptor with no attached stdio.
    pub const fn new() -> Self {
        Self {
            args: &[],
            caps_mask: caps_mask::ALL_DEFAULT,
            stdin: None,
            stdout: None,
            stderr: None,
            hxfs_dir: None,
            hxfs_service: None,
            block_dev: None,
            frame_draw: None,
            registry: None,
            home_cpu: None,
            stack_size: huesos_abi::USER_STACK_DEFAULT_SIZE,
        }
    }
}

impl<'a> Default for SpawnCaps<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Load a `PT_INTERP` ELF image from a slice with explicit `argv`, `@caps(...)`,
/// and standard-stream channels.
pub fn spawn_elf_with_caps(
    name: &str,
    elf: &[u8],
    lib_vmo: &Vmo,
    caps: &SpawnCaps<'_>,
) -> crate::Result<(Process, Channel)> {
    spawn_elf_with_affinity(name, elf, Some(lib_vmo), caps)
}

/// Load a VMO-backed ELF image with explicit `argv`, `@caps(...)`, and
/// standard-stream channels.
pub fn spawn_elf_from_vmo_with_caps(
    name: &str,
    vmo: &Vmo,
    offset: u64,
    len: u64,
    lib_vmo: &Vmo,
    caps: &SpawnCaps<'_>,
) -> crate::Result<(Process, Channel)> {
    let (process, _root_vmar, bootstrap) =
        spawn_elf_from_vmo_inner(name, vmo, offset, len, Some(lib_vmo), caps)?;
    Ok((process, bootstrap))
}

/// Load an ELF image into a new process and start its initial thread.
///
/// Static `ET_EXEC` binaries run directly; `PT_INTERP` binaries require a
/// library VMO (see [`spawn_elf_with_lib`]).
pub fn spawn_elf(name: &str, elf: &[u8]) -> crate::Result<(Process, Channel)> {
    spawn_elf_with_stack(name, elf, huesos_abi::USER_STACK_DEFAULT_SIZE)
}

/// Load a `PT_INTERP` (or static) ELF image with a library `BOOTFS` VMO.
pub fn spawn_elf_with_lib(
    name: &str,
    elf: &[u8],
    lib_vmo: &Vmo,
) -> crate::Result<(Process, Channel)> {
    let caps = SpawnCaps::new();
    spawn_elf_with_affinity(name, elf, Some(lib_vmo), &caps)
}

/// Load a `PT_INTERP` ELF image with an optional capability `HxFS` library
/// directory/service channel (`AT_HUESOS_HXFS_DIR`) plus `BOOTFS` fallback VMO.
pub fn spawn_elf_with_lib_and_hxfs(
    name: &str,
    elf: &[u8],
    lib_vmo: &Vmo,
    hxfs_dir: Option<&Channel>,
) -> crate::Result<(Process, Channel)> {
    let mut caps = SpawnCaps::new();
    caps.hxfs_dir = hxfs_dir;
    spawn_elf_with_affinity(name, elf, Some(lib_vmo), &caps)
}

/// Load a static ELF with an explicit per-process stack profile.
pub fn spawn_elf_with_stack(
    name: &str,
    elf: &[u8],
    stack_size: u64,
) -> crate::Result<(Process, Channel)> {
    let mut caps = SpawnCaps::new();
    caps.stack_size = stack_size;
    spawn_elf_with_affinity(name, elf, None, &caps)
}

/// Load a static ELF image into a new process with an explicit home CPU.
pub fn spawn_elf_on_cpu(name: &str, elf: &[u8], cpu: usize) -> crate::Result<(Process, Channel)> {
    let mut caps = SpawnCaps::new();
    caps.home_cpu = Some(cpu);
    spawn_elf_with_affinity(name, elf, None, &caps)
}

/// Load an ELF image with an explicit home CPU and library `BOOTFS` VMO.
pub fn spawn_elf_on_cpu_with_lib(
    name: &str,
    elf: &[u8],
    cpu: usize,
    lib_vmo: &Vmo,
) -> crate::Result<(Process, Channel)> {
    let mut caps = SpawnCaps::new();
    caps.home_cpu = Some(cpu);
    spawn_elf_with_affinity(name, elf, Some(lib_vmo), &caps)
}

#[derive(Clone, Copy)]
struct ParsedElfHeader {
    e_type: u16,
    e_entry: u64,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
    min_vaddr: u64,
    pt_phdr_vaddr: Option<u64>,
    interp: Option<(u64, u64)>,
}

fn parse_elf_headers(header_slice: &[u8], total_len: u64) -> crate::Result<ParsedElfHeader> {
    if header_slice.len() < 64 || !is_valid_elf64_header(header_slice) {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let e_type = u16::from_le_bytes([header_slice[16], header_slice[17]]);
    let e_machine = u16::from_le_bytes([header_slice[18], header_slice[19]]);
    if (e_type != ET_EXEC && e_type != ET_DYN) || e_machine != EM_X86_64 {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let e_entry = u64::from_le_bytes([
        header_slice[24],
        header_slice[25],
        header_slice[26],
        header_slice[27],
        header_slice[28],
        header_slice[29],
        header_slice[30],
        header_slice[31],
    ]);
    let e_phoff = u64::from_le_bytes([
        header_slice[32],
        header_slice[33],
        header_slice[34],
        header_slice[35],
        header_slice[36],
        header_slice[37],
        header_slice[38],
        header_slice[39],
    ]);
    let e_phentsize = u16::from_le_bytes([header_slice[54], header_slice[55]]);
    let e_phnum = u16::from_le_bytes([header_slice[56], header_slice[57]]);
    if e_phentsize < 56 || e_phnum == 0 {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let phdr_end = e_phoff
        .checked_add(u64::from(e_phnum).saturating_mul(u64::from(e_phentsize)))
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    if phdr_end > total_len || phdr_end > header_slice.len() as u64 {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    let mut min_vaddr = u64::MAX;
    let mut pt_phdr_vaddr = None;
    let mut interp = None;
    let mut load_count = 0usize;

    for idx in 0..usize::from(e_phnum) {
        let ph =
            read_phdr64(header_slice, e_phoff, idx).map_err(|_| crate::ErrorCode::InvalidArgs)?;
        match ph.p_type {
            PT_LOAD => {
                let start = elf::align_down(ph.p_vaddr, PAGE_SIZE);
                if start < min_vaddr {
                    min_vaddr = start;
                }
                load_count += 1;
            }
            PT_PHDR => pt_phdr_vaddr = Some(ph.p_vaddr),
            PT_INTERP => {
                let end = ph
                    .p_offset
                    .checked_add(ph.p_filesz)
                    .ok_or(crate::ErrorCode::InvalidArgs)?;
                if ph.p_filesz == 0 || end > total_len {
                    return Err(crate::ErrorCode::InvalidArgs);
                }
                interp = Some((ph.p_offset, ph.p_filesz));
            }
            _ => {}
        }
    }

    if load_count == 0 {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    Ok(ParsedElfHeader {
        e_type,
        e_entry,
        e_phoff,
        e_phentsize,
        e_phnum,
        min_vaddr,
        pt_phdr_vaddr,
        interp,
    })
}

fn spawn_elf_with_affinity(
    name: &str,
    elf: &[u8],
    lib_vmo: Option<&Vmo>,
    caps: &SpawnCaps<'_>,
) -> crate::Result<(Process, Channel)> {
    if !huesos_abi::valid_user_stack_size(caps.stack_size) {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let image = parse_elf_headers(elf, elf.len() as u64)?;
    if image.interp.is_none() && image.e_type == ET_DYN {
        return Err(crate::ErrorCode::NotSupported);
    }

    let main_bias = if image.e_type == ET_DYN {
        choose_aslr_base(MAIN_ASLR_BASE).wrapping_sub(image.min_vaddr)
    } else {
        0
    };

    if name == "doom" {
        crate::println!("[doom-launch] ELF parsed, creating process");
    }
    let (process, root_vmar) = Process::create(name)?;
    if let Some(cpu) = caps.home_cpu {
        process.set_affinity(cpu)?;
    }

    let mut at_phdr = main_bias.wrapping_add(image.pt_phdr_vaddr.unwrap_or(0));
    for idx in 0..usize::from(image.e_phnum) {
        let ph = read_phdr64(elf, image.e_phoff, idx).map_err(|_| crate::ErrorCode::InvalidArgs)?;
        if ph.p_type == PT_LOAD {
            if image.pt_phdr_vaddr.is_none()
                && image.e_phoff >= ph.p_offset
                && image.e_phoff < ph.p_offset.saturating_add(ph.p_filesz)
            {
                at_phdr = main_bias
                    .wrapping_add(ph.p_vaddr)
                    .wrapping_add(image.e_phoff - ph.p_offset);
            }
            if name == "doom" {
                crate::println!("[doom-launch] mapping PT_LOAD {}", idx);
            }
            map_load_segment(&root_vmar, elf, main_bias, ph)?;
            if name == "doom" {
                crate::println!("[doom-launch] mapped PT_LOAD {}", idx);
            }
        }
    }

    if let Some((interp_off, interp_len)) = image.interp {
        let Some(lib_vmo) = lib_vmo else {
            return Err(crate::ErrorCode::InvalidArgs);
        };
        let start = usize::try_from(interp_off).map_err(|_| crate::ErrorCode::InvalidArgs)?;
        let len = usize::try_from(interp_len).map_err(|_| crate::ErrorCode::InvalidArgs)?;
        let interp_bytes = elf
            .get(start..start + len)
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        let bootstrap = finish_dynamic_launch(
            name,
            &process,
            &root_vmar,
            lib_vmo,
            caps,
            interp_bytes,
            &image,
            main_bias,
            at_phdr,
        )?;
        return Ok((process, bootstrap));
    }

    if name == "doom" {
        crate::println!("[doom-launch] mapping stack and starting thread");
    }
    map_initial_stack(&root_vmar, caps.stack_size)?;
    let thread = Thread::create(&process, "main")?;
    // iretq enters directly, so synthesize SysV's post-call alignment.
    let bootstrap = thread.start(image.e_entry, initial_user_rsp(USER_STACK_TOP))?;
    if name == "doom" {
        crate::println!("[doom-launch] thread started");
    }
    Ok((process, bootstrap))
}

/// Load an ELF image from a VMO into a new process and start its initial thread.
pub fn spawn_elf_from_vmo(
    name: &str,
    vmo: &Vmo,
    offset: u64,
    len: u64,
) -> crate::Result<(Process, Channel)> {
    spawn_elf_from_vmo_with_stack(name, vmo, offset, len, huesos_abi::USER_STACK_DEFAULT_SIZE)
}

/// Load a VMO-backed ELF image with an explicit library `BOOTFS` VMO.
pub fn spawn_elf_from_vmo_with_lib(
    name: &str,
    vmo: &Vmo,
    offset: u64,
    len: u64,
    lib_vmo: &Vmo,
) -> crate::Result<(Process, Channel)> {
    let caps = SpawnCaps::new();
    let (process, _root_vmar, bootstrap) =
        spawn_elf_from_vmo_inner(name, vmo, offset, len, Some(lib_vmo), &caps)?;
    Ok((process, bootstrap))
}

/// Load a VMO-backed ELF image with an explicit library `BOOTFS` VMO and an
/// optional capability `HxFS` library directory/service channel.
pub fn spawn_elf_from_vmo_with_lib_and_hxfs(
    name: &str,
    vmo: &Vmo,
    offset: u64,
    len: u64,
    lib_vmo: &Vmo,
    hxfs_dir: Option<&Channel>,
) -> crate::Result<(Process, Channel)> {
    let mut caps = SpawnCaps::new();
    caps.hxfs_dir = hxfs_dir;
    let (process, _root_vmar, bootstrap) =
        spawn_elf_from_vmo_inner(name, vmo, offset, len, Some(lib_vmo), &caps)?;
    Ok((process, bootstrap))
}

/// Load a VMO-backed ELF with an explicit per-process stack profile.
pub fn spawn_elf_from_vmo_with_stack(
    name: &str,
    vmo: &Vmo,
    offset: u64,
    len: u64,
    stack_size: u64,
) -> crate::Result<(Process, Channel)> {
    let (process, _root_vmar, bootstrap) =
        spawn_elf_from_vmo_with_vmar_and_stack(name, vmo, offset, len, stack_size)?;
    Ok((process, bootstrap))
}

/// Load/start a VMO-backed ELF and retain the child root VMAR for explicit
/// capability transfer to self-mapping runtimes such as `acpi-manager`.
pub fn spawn_elf_from_vmo_with_vmar(
    name: &str,
    vmo: &Vmo,
    offset: u64,
    len: u64,
) -> crate::Result<(Process, Vmar, Channel)> {
    spawn_elf_from_vmo_with_vmar_and_stack(
        name,
        vmo,
        offset,
        len,
        huesos_abi::USER_STACK_DEFAULT_SIZE,
    )
}

/// Load/start a VMO-backed ELF, retain its VMAR, and select stack size.
pub fn spawn_elf_from_vmo_with_vmar_and_stack(
    name: &str,
    vmo: &Vmo,
    offset: u64,
    len: u64,
    stack_size: u64,
) -> crate::Result<(Process, Vmar, Channel)> {
    let mut caps = SpawnCaps::new();
    caps.stack_size = stack_size;
    // When `vmo` is BOOTFS itself (as in `init` launching `doom`), passing `Some(vmo)`
    // allows `PT_INTERP` images stored inside BOOTFS to resolve `/lib/*.so` seamlessly.
    spawn_elf_from_vmo_inner(name, vmo, offset, len, Some(vmo), &caps)
}

fn spawn_elf_from_vmo_inner(
    name: &str,
    vmo: &Vmo,
    offset: u64,
    len: u64,
    lib_vmo: Option<&Vmo>,
    caps: &SpawnCaps<'_>,
) -> crate::Result<(Process, Vmar, Channel)> {
    if len == 0
        || offset.checked_add(len).is_none()
        || !huesos_abi::valid_user_stack_size(caps.stack_size)
    {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    let (header_buf, header_len, image) = read_vmo_elf_headers(vmo, offset, len)?;
    if image.interp.is_none() && image.e_type == ET_DYN {
        return Err(crate::ErrorCode::NotSupported);
    }
    let header_slice = &header_buf[..header_len];

    let main_bias = if image.e_type == ET_DYN {
        choose_aslr_base(MAIN_ASLR_BASE).wrapping_sub(image.min_vaddr)
    } else {
        0
    };

    let (process, root_vmar) = Process::create(name)?;
    if let Some(cpu) = caps.home_cpu {
        process.set_affinity(cpu)?;
    }
    let mut at_phdr = main_bias.wrapping_add(image.pt_phdr_vaddr.unwrap_or(0));

    for idx in 0..usize::from(image.e_phnum) {
        let ph = read_phdr64(header_slice, image.e_phoff, idx)
            .map_err(|_| crate::ErrorCode::InvalidArgs)?;
        if ph.p_type == PT_LOAD {
            if image.pt_phdr_vaddr.is_none()
                && image.e_phoff >= ph.p_offset
                && image.e_phoff < ph.p_offset.saturating_add(ph.p_filesz)
            {
                at_phdr = main_bias
                    .wrapping_add(ph.p_vaddr)
                    .wrapping_add(image.e_phoff - ph.p_offset);
            }
            map_load_segment_from_vmo(&root_vmar, vmo, offset, len, main_bias, ph)?;
        }
    }

    if let Some((interp_off, interp_len)) = image.interp {
        let Some(lib_vmo) = lib_vmo else {
            return Err(crate::ErrorCode::InvalidArgs);
        };
        let path_len = usize::try_from(interp_len)
            .map_err(|_| crate::ErrorCode::InvalidArgs)?
            .min(192);
        let mut interp_buf = [0u8; 192];
        let src_off = offset
            .checked_add(interp_off)
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        if vmo.read(src_off, &mut interp_buf[..path_len])? != path_len {
            return Err(crate::ErrorCode::InvalidArgs);
        }
        let bootstrap = finish_dynamic_launch(
            name,
            &process,
            &root_vmar,
            lib_vmo,
            caps,
            &interp_buf[..path_len],
            &image,
            main_bias,
            at_phdr,
        )?;
        return Ok((process, root_vmar, bootstrap));
    }

    map_initial_stack(&root_vmar, caps.stack_size)?;
    let thread = Thread::create(&process, "main")?;
    let bootstrap = thread.start(image.e_entry, initial_user_rsp(USER_STACK_TOP))?;
    Ok((process, root_vmar, bootstrap))
}

#[allow(clippy::too_many_arguments)]
fn finish_dynamic_launch(
    name: &str,
    process: &Process,
    root_vmar: &Vmar,
    lib_vmo: &Vmo,
    caps: &SpawnCaps<'_>,
    raw_interp_bytes: &[u8],
    main_image: &ParsedElfHeader,
    main_bias: u64,
    at_phdr: u64,
) -> crate::Result<Channel> {
    let interp_trimmed = match raw_interp_bytes.iter().position(|&b| b == 0) {
        Some(nul) => &raw_interp_bytes[..nul],
        None => raw_interp_bytes,
    };
    let (interp_off, interp_len) =
        find_bootfs_entry(lib_vmo, interp_trimmed).ok_or(crate::ErrorCode::NotFound)?;

    let (interp_hdr_buf, interp_hdr_len, interp_image) =
        read_vmo_elf_headers(lib_vmo, interp_off, interp_len)?;
    if interp_image.e_type != ET_DYN || interp_image.interp.is_some() {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let interp_hdr_slice = &interp_hdr_buf[..interp_hdr_len];

    let interp_load_base = choose_aslr_base(INTERP_ASLR_BASE);
    let interp_bias = interp_load_base.wrapping_sub(interp_image.min_vaddr);
    for idx in 0..usize::from(interp_image.e_phnum) {
        let ph = read_phdr64(interp_hdr_slice, interp_image.e_phoff, idx)
            .map_err(|_| crate::ErrorCode::InvalidArgs)?;
        if ph.p_type == PT_LOAD {
            map_load_segment_from_vmo(root_vmar, lib_vmo, interp_off, interp_len, interp_bias, ph)?;
        }
    }

    let initial_rsp = map_dynamic_initial_stack(
        root_vmar,
        caps.stack_size,
        name,
        caps.args,
        at_phdr,
        main_image.e_phentsize,
        main_image.e_phnum,
        interp_load_base,
        main_bias.wrapping_add(main_image.e_entry),
        true,
        caps,
    )?;

    // Duplicate bootstrap capabilities before Thread::start so all handles are
    // ready to enqueue on the parent bootstrap channel immediately.
    let vmar_dup = root_vmar.handle().duplicate(rights::SAME_RIGHTS)?;
    let lib_vmo_dup = lib_vmo
        .duplicate(rights::READ | rights::TRANSFER | rights::DUPLICATE)?
        .into_handle();
    let hxfs_dir_dup = match caps.hxfs_dir {
        Some(ch) => Some(ch.handle().duplicate(rights::SAME_RIGHTS)?),
        None => None,
    };
    let stdin_dup = match caps.stdin {
        Some(ch) => Some(ch.handle().duplicate(rights::READ | rights::TRANSFER)?),
        None => None,
    };
    let stdout_dup = match caps.stdout {
        Some(ch) => Some(
            ch.handle()
                .duplicate(rights::READ | rights::WRITE | rights::TRANSFER)?,
        ),
        None => None,
    };
    let stderr_dup = match caps.stderr {
        Some(ch) => Some(
            ch.handle()
                .duplicate(rights::READ | rights::WRITE | rights::TRANSFER)?,
        ),
        None => None,
    };
    let hxfs_svc_dup = match caps.hxfs_service {
        Some(ch) => Some(
            ch.handle()
                .duplicate(rights::READ | rights::WRITE | rights::TRANSFER)?,
        ),
        None => None,
    };
    let block_dev_dup = match caps.block_dev {
        Some(ch) => Some(
            ch.handle()
                .duplicate(rights::READ | rights::WRITE | rights::TRANSFER)?,
        ),
        None => None,
    };
    let frame_draw_dup = match caps.frame_draw {
        Some(h) => Some(h.duplicate(rights::SAME_RIGHTS)?),
        None => None,
    };
    let registry_dup = match caps.registry {
        Some(ch) => Some(
            ch.handle()
                .duplicate(rights::READ | rights::WRITE | rights::TRANSFER)?,
        ),
        None => None,
    };

    let thread = Thread::create(process, "main")?;
    let interp_entry = interp_bias.wrapping_add(interp_image.e_entry);
    let bootstrap = match thread.start(interp_entry, initial_rsp) {
        Ok(ch) => ch,
        Err(err) => {
            drop(registry_dup);
            drop(frame_draw_dup);
            drop(block_dev_dup);
            drop(hxfs_svc_dup);
            drop(stderr_dup);
            drop(stdout_dup);
            drop(stdin_dup);
            drop(hxfs_dir_dup);
            drop(lib_vmo_dup);
            drop(vmar_dup);
            return Err(err);
        }
    };

    let sends: [(&[u8], Option<Handle>); 10] = [
        (LD_BOOTSTRAP_SELF_VMAR_LABEL, Some(vmar_dup)),
        (LD_BOOTSTRAP_LIB_VMO_LABEL, Some(lib_vmo_dup)),
        (LD_BOOTSTRAP_HXFS_DIR_LABEL, hxfs_dir_dup),
        (LD_BOOTSTRAP_STDIN_LABEL, stdin_dup),
        (LD_BOOTSTRAP_STDOUT_LABEL, stdout_dup),
        (LD_BOOTSTRAP_STDERR_LABEL, stderr_dup),
        (LD_BOOTSTRAP_HXFS_SERVICE_LABEL, hxfs_svc_dup),
        (LD_BOOTSTRAP_BLOCK_DEV_LABEL, block_dev_dup),
        (LD_BOOTSTRAP_FRAME_DRAW_LABEL, frame_draw_dup),
        (LD_BOOTSTRAP_REGISTRY_LABEL, registry_dup),
    ];
    for (idx, (label, maybe_h)) in sends.into_iter().enumerate() {
        if let Some(handle) = maybe_h {
            if let Err((err, _h)) = bootstrap.write_handle(label, handle) {
                let _ = idx;
                return Err(err);
            }
        }
    }

    Ok(bootstrap)
}

fn read_vmo_elf_headers(
    vmo: &Vmo,
    offset: u64,
    len: u64,
) -> crate::Result<([u8; HEADER_MAX], usize, ParsedElfHeader)> {
    let mut header_buf = [0u8; HEADER_MAX];
    let first_read_len = (len as usize).min(4096).min(header_buf.len());
    if first_read_len < 64 {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    if vmo.read(offset, &mut header_buf[..first_read_len])? != first_read_len {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    if !is_valid_elf64_header(&header_buf[..first_read_len]) {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let e_phoff = u64::from_le_bytes([
        header_buf[32],
        header_buf[33],
        header_buf[34],
        header_buf[35],
        header_buf[36],
        header_buf[37],
        header_buf[38],
        header_buf[39],
    ]);
    let e_phentsize = u16::from_le_bytes([header_buf[54], header_buf[55]]);
    let e_phnum = u16::from_le_bytes([header_buf[56], header_buf[57]]);
    let phdr_end = e_phoff
        .checked_add(u64::from(e_phnum).saturating_mul(u64::from(e_phentsize)))
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    if phdr_end > len || phdr_end as usize > HEADER_MAX {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let header_len = (phdr_end as usize).max(first_read_len);
    if header_len > first_read_len && vmo.read(offset, &mut header_buf[..header_len])? != header_len
    {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let image = parse_elf_headers(&header_buf[..header_len], len)?;
    Ok((header_buf, header_len, image))
}

fn find_bootfs_entry(vmo: &Vmo, wanted: &[u8]) -> Option<(u64, u64)> {
    let mut header = [0u8; BOOTFS_HEADER_SIZE as usize];
    if vmo.read(0, &mut header).ok()? != header.len() || &header[..8] != BOOTFS_MAGIC {
        return None;
    }
    let count = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let mut raw = [0u8; BOOTFS_ENTRY_SIZE as usize];
    for index in 0..count {
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
    }
    None
}

fn choose_aslr_base(window_base: u64) -> u64 {
    let rand = memory::random_u64().unwrap_or(0x1_2345);
    window_base + ((rand & ASLR_PAGE_MASK) << 12)
}

fn initial_user_rsp(stack_top: u64) -> u64 {
    (stack_top & !0xf) - 8
}

#[allow(clippy::too_many_arguments)]
fn map_dynamic_initial_stack(
    root_vmar: &Vmar,
    stack_size: u64,
    name: &str,
    args: &[&str],
    at_phdr: u64,
    at_phent: u16,
    at_phnum: u16,
    at_base: u64,
    at_entry: u64,
    has_lib_vmo: bool,
    caps: &SpawnCaps<'_>,
) -> crate::Result<u64> {
    if !huesos_abi::valid_user_stack_size(stack_size) {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let stack_bottom = USER_STACK_TOP - stack_size;
    let stack = Vmo::create(stack_size)?;

    let mut top_page = [0u8; PAGE_SIZE as usize];
    let top_page_va = USER_STACK_TOP - PAGE_SIZE;

    const MAX_ARGV: usize = 32;
    let mut arg_vas = [0u64; MAX_ARGV];
    let mut str_cursor = PAGE_SIZE as usize;
    let effective_count = if args.is_empty() {
        1
    } else {
        args.len().min(MAX_ARGV)
    };

    // Pack argument strings downwards from the top of the page.
    let mut argc = 0usize;
    for i in (0..effective_count).rev() {
        let arg_bytes = if args.is_empty() {
            name.as_bytes()
        } else {
            args[i].as_bytes()
        };
        let clamped_len = arg_bytes.len().min(255);
        let needed = clamped_len + 1;
        if str_cursor < 2048 + needed {
            break;
        }
        str_cursor -= needed;
        top_page[str_cursor..str_cursor + clamped_len].copy_from_slice(&arg_bytes[..clamped_len]);
        top_page[str_cursor + clamped_len] = 0;
        arg_vas[i] = top_page_va + str_cursor as u64;
        argc += 1;
    }
    if argc == 0 {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    // If truncated at the bottom, shift valid entries to start at index 0.
    let first_valid = effective_count - argc;

    let rand_off = (str_cursor - 16) & !0xf;
    let r0 = memory::random_u64().unwrap_or(0x9e37_79b9_7f4a_7c15);
    let r1 = memory::random_u64().unwrap_or(0xbf58_476d_1ce4_e5b9);
    top_page[rand_off..rand_off + 8].copy_from_slice(&r0.to_le_bytes());
    top_page[rand_off + 8..rand_off + 16].copy_from_slice(&r1.to_le_bytes());
    let rand_va = top_page_va + rand_off as u64;

    let aux_entries: [(u64, u64); 20] = [
        (AT_PHDR, at_phdr),
        (AT_PHENT, u64::from(at_phent)),
        (AT_PHNUM, u64::from(at_phnum)),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, at_base),
        (AT_FLAGS, 0),
        (AT_ENTRY, at_entry),
        (AT_RANDOM, rand_va),
        (AT_HUESOS_LD_BOOTSTRAP, 1),
        (AT_HUESOS_LIB_VMO, u64::from(has_lib_vmo)),
        (AT_HUESOS_HXFS_DIR, u64::from(caps.hxfs_dir.is_some())),
        (AT_HUESOS_STDIN, u64::from(caps.stdin.is_some())),
        (AT_HUESOS_STDOUT, u64::from(caps.stdout.is_some())),
        (AT_HUESOS_STDERR, u64::from(caps.stderr.is_some())),
        (AT_HUESOS_CAPS_MASK, caps.caps_mask),
        (
            AT_HUESOS_HXFS_SERVICE,
            u64::from(caps.hxfs_service.is_some()),
        ),
        (AT_HUESOS_BLOCK_DEV, u64::from(caps.block_dev.is_some())),
        (AT_HUESOS_FRAME_DRAW, u64::from(caps.frame_draw.is_some())),
        (AT_HUESOS_REGISTRY, u64::from(caps.registry.is_some())),
        (AT_NULL, 0),
    ];

    // Words: argc + argv[0..argc] + NULL + envp NULL + auxv pairs.
    let total_words = 1 + argc + 1 + 1 + aux_entries.len() * 2;
    let sp_off = (rand_off - total_words * 8) & !0xf;

    let mut cur = sp_off;
    let write_word = |buf: &mut [u8], pos: &mut usize, val: u64| {
        buf[*pos..*pos + 8].copy_from_slice(&val.to_le_bytes());
        *pos += 8;
    };
    write_word(&mut top_page, &mut cur, argc as u64);
    for &va in &arg_vas[first_valid..effective_count] {
        write_word(&mut top_page, &mut cur, va);
    }
    write_word(&mut top_page, &mut cur, 0); // argv[argc] = NULL
    write_word(&mut top_page, &mut cur, 0); // envp[0] = NULL
    for (a_type, a_val) in aux_entries {
        write_word(&mut top_page, &mut cur, a_type);
        write_word(&mut top_page, &mut cur, a_val);
    }

    stack.write(stack_size - PAGE_SIZE, &top_page)?;
    root_vmar.map(
        &stack,
        0,
        stack_bottom,
        stack_size,
        vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
    )?;

    Ok(top_page_va + sp_off as u64)
}

fn map_load_segment(root_vmar: &Vmar, elf: &[u8], bias: u64, ph: Phdr64) -> crate::Result<()> {
    if ph.p_filesz > ph.p_memsz {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    let file_end = ph
        .p_offset
        .checked_add(ph.p_filesz)
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    if file_end > elf.len() as u64 {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    let seg_vaddr = bias.wrapping_add(ph.p_vaddr);
    let page_start = elf::align_down(seg_vaddr, PAGE_SIZE);
    let seg_end = seg_vaddr
        .checked_add(ph.p_memsz)
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    let page_end = elf::align_up(seg_end, PAGE_SIZE).ok_or(crate::ErrorCode::InvalidArgs)?;
    if page_end <= page_start {
        return Ok(());
    }

    let map_len = page_end - page_start;
    let vmo_flags = if ph.p_flags & PF_X != 0 {
        vmo_create_flags::EXECUTABLE
    } else {
        0
    };
    let vmo = Vmo::create_with_flags(map_len, vmo_flags)?;

    if ph.p_filesz > 0 {
        let file_start = ph.p_offset as usize;
        let file_end = file_end as usize;
        let vmo_file_offset = seg_vaddr - page_start;
        // The kernel intentionally caps one VMO transfer at 1 MiB. Large
        // static assets (for example Freedoom's IWAD in the Doom ELF) must be
        // copied in bounded chunks rather than weakening that syscall limit.
        const CHUNK: usize = 1024 * 1024;
        let mut copied = 0usize;
        let source = &elf[file_start..file_end];
        while copied < source.len() {
            let end = (copied + CHUNK).min(source.len());
            let written = vmo.write(vmo_file_offset + copied as u64, &source[copied..end])?;
            if written != end - copied {
                return Err(crate::ErrorCode::InvalidArgs);
            }
            copied = end;
        }
    }

    let flags = segment_vmar_flags(ph.p_flags)?;
    root_vmar.map(&vmo, 0, page_start, map_len, flags)?;
    Ok(())
}

fn map_load_segment_from_vmo(
    root_vmar: &Vmar,
    vmo: &Vmo,
    elf_offset: u64,
    elf_len: u64,
    bias: u64,
    ph: Phdr64,
) -> crate::Result<()> {
    if ph.p_filesz > ph.p_memsz
        || ph
            .p_offset
            .checked_add(ph.p_filesz)
            .is_none_or(|end| end > elf_len)
    {
        return Err(crate::ErrorCode::InvalidArgs);
    }

    let seg_vaddr = bias.wrapping_add(ph.p_vaddr);
    let page_start = elf::align_down(seg_vaddr, PAGE_SIZE);
    let seg_end = seg_vaddr
        .checked_add(ph.p_memsz)
        .ok_or(crate::ErrorCode::InvalidArgs)?;
    let page_end = elf::align_up(seg_end, PAGE_SIZE).ok_or(crate::ErrorCode::InvalidArgs)?;
    if page_end <= page_start {
        return Ok(());
    }

    let map_len = page_end - page_start;
    let vmo_flags = if ph.p_flags & PF_X != 0 {
        vmo_create_flags::EXECUTABLE
    } else {
        0
    };
    let seg_vmo = Vmo::create_with_flags(map_len, vmo_flags)?;

    if ph.p_filesz > 0 {
        let mut buf = [0u8; 4096];
        let mut read_total = 0;
        let vmo_file_offset = seg_vaddr - page_start;

        while read_total < ph.p_filesz {
            let to_read = (ph.p_filesz - read_total).min(buf.len() as u64);
            let source_offset = elf_offset
                .checked_add(ph.p_offset)
                .and_then(|base| base.checked_add(read_total))
                .ok_or(crate::ErrorCode::InvalidArgs)?;
            let count = to_read as usize;
            if vmo.read(source_offset, &mut buf[..count])? != count
                || seg_vmo.write(vmo_file_offset + read_total, &buf[..count])? != count
            {
                return Err(crate::ErrorCode::InvalidArgs);
            }
            read_total += to_read;
        }
    }

    let flags = segment_vmar_flags(ph.p_flags)?;
    root_vmar.map(&seg_vmo, 0, page_start, map_len, flags)?;
    Ok(())
}

fn map_initial_stack(root_vmar: &Vmar, stack_size: u64) -> crate::Result<()> {
    if !huesos_abi::valid_user_stack_size(stack_size) {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    let stack_bottom = USER_STACK_TOP - stack_size;
    let stack = Vmo::create(stack_size)?;
    root_vmar.map(
        &stack,
        0,
        stack_bottom,
        stack_size,
        vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
    )?;
    Ok(())
}

fn segment_vmar_flags(ph_flags: u32) -> crate::Result<u32> {
    let mut flags = vmar_flags::USER | vmar_flags::SPECIFIC;
    if ph_flags & PF_R != 0 {
        flags |= vmar_flags::READ;
    }
    if ph_flags & PF_W != 0 {
        flags |= vmar_flags::WRITE;
    }
    if ph_flags & PF_X != 0 {
        flags |= vmar_flags::EXECUTE;
    }
    if flags & (vmar_flags::READ | vmar_flags::WRITE | vmar_flags::EXECUTE) == 0 {
        return Err(crate::ErrorCode::InvalidArgs);
    }
    Ok(flags)
}
