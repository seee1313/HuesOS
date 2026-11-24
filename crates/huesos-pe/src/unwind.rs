//! Safe `#![no_std]` Microsoft x64 `.pdata` / `.xdata` Structured Exception
//! Handling (SEH) unwinder and Windows ApiSet (`api-ms-win-*`) schema mapper.

use crate::DataDirectory;

/// `UNW_FLAG_NHANDLER` — function has no exception or termination handler.
pub const UNW_FLAG_NHANDLER: u8 = 0x00;
/// `UNW_FLAG_EHANDLER` — function has an exception filter/handler.
pub const UNW_FLAG_EHANDLER: u8 = 0x01;
/// `UNW_FLAG_UHANDLER` — function has an unwind/termination handler.
pub const UNW_FLAG_UHANDLER: u8 = 0x02;
/// `UNW_FLAG_CHAININFO` — trailer holds a parent `RUNTIME_FUNCTION` rather than a handler.
pub const UNW_FLAG_CHAININFO: u8 = 0x04;

const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_EPILOG: u8 = 6;
const UWOP_SPARE_CODE: u8 = 7;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

/// 12-byte Microsoft x64 `.pdata` `RUNTIME_FUNCTION` entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_rva: u32,
}

/// Integer register file subset mutated during x64 virtual stack unwinding.
///
/// Register indices `0..16` follow the x64 hardware encoding:
/// `0=rax, 1=rcx, 2=rdx, 3=rbx, 4=rsp, 5=rbp, 6=rsi, 7=rdi, 8..15=r8..r15`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win64UnwindRegs {
    pub gpr: [u64; 16],
    pub rip: u64,
}

impl Win64UnwindRegs {
    pub const fn rsp(&self) -> u64 {
        self.gpr[4]
    }

    pub fn set_rsp(&mut self, val: u64) {
        self.gpr[4] = val;
    }
}

/// Output of one `virtual_unwind` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindStepOutcome {
    /// Establisher stack frame pointer (`RSP` prior to prologue allocation, or scaled frame reg).
    pub establisher_frame: u64,
    /// Optional language-specific handler RVA (when `UNW_FLAG_EHANDLER` / `UNW_FLAG_UHANDLER` matches).
    pub handler_rva: Option<u32>,
    /// RVA of the handler-specific data (`SCOPE_TABLE`, etc.) immediately following `handler_rva`.
    pub handler_data_rva: u32,
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let slice = buf.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn starts_with_ignore_ascii_case(haystack: &str, prefix: &str) -> bool {
    haystack
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Map Windows ApiSet virtual DLL names (`api-ms-win-*`, `ext-ms-win-*`) and
/// MSVC runtime helpers (`vcruntime140*.dll`) to concrete HuesOS PE32+ DLLs.
pub fn resolve_apiset_dll(raw_dll_name: &str) -> Option<&'static str> {
    let leaf = raw_dll_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw_dll_name);
    let stem = leaf
        .strip_suffix(".dll")
        .or_else(|| leaf.strip_suffix(".DLL"))
        .unwrap_or(leaf);

    if starts_with_ignore_ascii_case(stem, "api-ms-win-crt-")
        || starts_with_ignore_ascii_case(stem, "vcruntime140")
    {
        Some("ucrtbase.dll")
    } else if starts_with_ignore_ascii_case(stem, "api-ms-win-security-")
        || starts_with_ignore_ascii_case(stem, "api-ms-win-eventing-")
    {
        Some("advapi32.dll")
    } else if starts_with_ignore_ascii_case(stem, "api-ms-win-core-")
        || starts_with_ignore_ascii_case(stem, "api-ms-win-ntuser-")
        || starts_with_ignore_ascii_case(stem, "ext-ms-win-")
    {
        Some("kernel32.dll")
    } else {
        None
    }
}

/// Binary-search `.pdata` (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`) for the
/// [`RuntimeFunction`] covering `rip_rva`.
pub fn lookup_runtime_function(
    mapped_image: &[u8],
    exception_dir: DataDirectory,
    rip_rva: u32,
) -> Option<RuntimeFunction> {
    if !exception_dir.is_present() {
        return None;
    }
    let base_off = exception_dir.virtual_address as usize;
    let total_bytes =
        (exception_dir.size as usize).min(mapped_image.len().saturating_sub(base_off));
    let count = total_bytes / 12;
    if count == 0 {
        return None;
    }

    let read_entry = |idx: usize| -> Option<RuntimeFunction> {
        let off = base_off.checked_add(idx.checked_mul(12)?)?;
        let begin = read_u32_le(mapped_image, off)?;
        let end = read_u32_le(mapped_image, off + 4)?;
        let unwind = read_u32_le(mapped_image, off + 8)?;
        if begin == 0 && end == 0 {
            return None;
        }
        Some(RuntimeFunction {
            begin_address: begin,
            end_address: end,
            unwind_info_rva: unwind,
        })
    };

    // Trim trailing zero padding entries if `.pdata` size includes alignment slack.
    let mut hi = count;
    while hi > 0 && read_entry(hi - 1).is_none() {
        hi -= 1;
    }
    let mut lo = 0usize;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry = read_entry(mid)?;
        if rip_rva < entry.begin_address {
            hi = mid;
        } else if rip_rva >= entry.end_address {
            lo = mid + 1;
        } else {
            return Some(entry);
        }
    }
    None
}

/// Attempt to recognize and simulate a canonical Microsoft x64 function epilogue
/// starting at `rip_rva` (`add rsp, imm` / `lea rsp, [fp + disp]`, zero or more
/// `pop reg`, ending in `ret` `0xC3`).
fn try_unwind_epilogue<F>(
    mapped_image: &[u8],
    rip_rva: u32,
    end_rva: u32,
    frame_reg: u8,
    regs: &mut Win64UnwindRegs,
    read_u64: &mut F,
) -> Option<u64>
where
    F: FnMut(u64) -> Option<u64>,
{
    if rip_rva >= end_rva {
        return None;
    }
    let max_scan = (end_rva - rip_rva).min(32) as usize;
    let start = rip_rva as usize;
    let code = mapped_image.get(start..start.checked_add(max_scan)?)?;
    if code.is_empty() {
        return None;
    }

    // Validate the instruction stream from `code[0..]` is a pure epilogue before mutating `regs`.
    let mut tmp = *regs;
    let mut pc = 0usize;
    let mut first = true;

    loop {
        let b0 = *code.get(pc)?;
        // 1. Direct `ret` (0xC3) or `rep ret` (0xF3 0xC3)
        if b0 == 0xC3 {
            let establisher = tmp.rsp();
            let ret_rip = read_u64(tmp.rsp())?;
            tmp.set_rsp(tmp.rsp().wrapping_add(8));
            tmp.rip = ret_rip;
            *regs = tmp;
            return Some(establisher);
        }
        if b0 == 0xF3 && code.get(pc + 1).copied() == Some(0xC3) {
            let establisher = tmp.rsp();
            let ret_rip = read_u64(tmp.rsp())?;
            tmp.set_rsp(tmp.rsp().wrapping_add(8));
            tmp.rip = ret_rip;
            *regs = tmp;
            return Some(establisher);
        }

        // 2. Stack deallocation allowed only as the first instruction in the remaining epilogue.
        if first {
            // `add rsp, imm8` -> 48 83 C4 ib
            if b0 == 0x48
                && code.get(pc + 1).copied() == Some(0x83)
                && code.get(pc + 2).copied() == Some(0xC4)
            {
                let imm = (*code.get(pc + 3)? as i8) as i64 as u64;
                tmp.set_rsp(tmp.rsp().wrapping_add(imm));
                pc += 4;
                first = false;
                continue;
            }
            // `add rsp, imm32` -> 48 81 C4 id
            if b0 == 0x48
                && code.get(pc + 1).copied() == Some(0x81)
                && code.get(pc + 2).copied() == Some(0xC4)
            {
                let imm_bytes = code.get(pc + 3..pc + 7)?;
                let imm =
                    i32::from_le_bytes([imm_bytes[0], imm_bytes[1], imm_bytes[2], imm_bytes[3]])
                        as i64 as u64;
                tmp.set_rsp(tmp.rsp().wrapping_add(imm));
                pc += 7;
                first = false;
                continue;
            }
            // `lea rsp, [fp + disp8]` or `[fp + disp32]` when `frame_reg != 0`
            if frame_reg != 0
                && (b0 == 0x48 || b0 == 0x49)
                && code.get(pc + 1).copied() == Some(0x8D)
            {
                let modrm = *code.get(pc + 2)?;
                let mod_bits = modrm >> 6;
                let reg_bits = (modrm >> 3) & 7;
                let rm_bits = (modrm & 7) | if b0 == 0x49 { 8 } else { 0 };
                if reg_bits == 4 && rm_bits == frame_reg {
                    if mod_bits == 0 {
                        tmp.set_rsp(tmp.gpr[usize::from(frame_reg)]);
                        pc += 3;
                        first = false;
                        continue;
                    } else if mod_bits == 1 {
                        let disp = (*code.get(pc + 3)? as i8) as i64 as u64;
                        tmp.set_rsp(tmp.gpr[usize::from(frame_reg)].wrapping_add(disp));
                        pc += 4;
                        first = false;
                        continue;
                    } else if mod_bits == 2 {
                        let d = code.get(pc + 3..pc + 7)?;
                        let disp = i32::from_le_bytes([d[0], d[1], d[2], d[3]]) as i64 as u64;
                        tmp.set_rsp(tmp.gpr[usize::from(frame_reg)].wrapping_add(disp));
                        pc += 7;
                        first = false;
                        continue;
                    }
                }
            }
        }
        first = false;

        // 3. `pop r64` (`58..=5F` or `41 58..=5F`)
        if (0x58..=0x5F).contains(&b0) {
            let reg_idx = usize::from(b0 - 0x58);
            let val = read_u64(tmp.rsp())?;
            tmp.set_rsp(tmp.rsp().wrapping_add(8));
            tmp.gpr[reg_idx] = val;
            pc += 1;
            continue;
        }
        if b0 == 0x41 {
            let b1 = *code.get(pc + 1)?;
            if (0x58..=0x5F).contains(&b1) {
                let reg_idx = 8 + usize::from(b1 - 0x58);
                let val = read_u64(tmp.rsp())?;
                tmp.set_rsp(tmp.rsp().wrapping_add(8));
                tmp.gpr[reg_idx] = val;
                pc += 2;
                continue;
            }
        }

        return None;
    }
}

/// Perform one full Microsoft x64 `.xdata` virtual unwind step (`RtlVirtualUnwind` semantics).
pub fn virtual_unwind<F>(
    mapped_image: &[u8],
    image_base: u64,
    initial_func: RuntimeFunction,
    regs: &mut Win64UnwindRegs,
    handler_type_mask: u8,
    mut read_u64: F,
) -> Option<UnwindStepOutcome>
where
    F: FnMut(u64) -> Option<u64>,
{
    let rip_rva_u64 = regs.rip.checked_sub(image_base)?;
    if rip_rva_u64 > u64::from(u32::MAX) {
        return None;
    }
    let rip_rva = rip_rva_u64 as u32;

    // Peek at primary UNWIND_INFO frame_reg for epilogue check.
    let first_uoff = (initial_func.unwind_info_rva & !1) as usize;
    let prolog_sz = *mapped_image.get(first_uoff.checked_add(1)?)?;
    let frame_byte = *mapped_image.get(first_uoff.checked_add(3)?)?;
    let primary_frame_reg = frame_byte & 0x0F;

    if rip_rva.saturating_sub(initial_func.begin_address) >= u32::from(prolog_sz) {
        if let Some(establisher_frame) = try_unwind_epilogue(
            mapped_image,
            rip_rva,
            initial_func.end_address,
            primary_frame_reg,
            regs,
            &mut read_u64,
        ) {
            return Some(UnwindStepOutcome {
                establisher_frame,
                handler_rva: None,
                handler_data_rva: 0,
            });
        }
    }

    let mut cur_func = initial_func;
    let mut establisher_frame = regs.rsp();
    let mut establisher_locked = false;
    let mut primary_handler_rva = None;
    let mut primary_handler_data_rva = 0u32;
    let mut pushed_machframe = false;

    for chain_depth in 0..8usize {
        let uoff = (cur_func.unwind_info_rva & !1) as usize;
        let ver_flags = *mapped_image.get(uoff)?;
        let version = ver_flags & 0x07;
        if version != 1 && version != 2 {
            return None;
        }
        let flags = (ver_flags >> 3) & 0x1F;
        let count_of_codes = usize::from(*mapped_image.get(uoff + 2)?);
        let frame_reg_and_off = *mapped_image.get(uoff + 3)?;
        let frame_reg = frame_reg_and_off & 0x0F;
        let frame_scaled_off = u64::from((frame_reg_and_off >> 4) & 0x0F) * 16;

        let offset_in_func = rip_rva.saturating_sub(cur_func.begin_address);
        if !establisher_locked {
            if frame_reg != 0 && offset_in_func >= u32::from(*mapped_image.get(uoff + 1)?) {
                establisher_frame = regs.gpr[usize::from(frame_reg)].wrapping_sub(frame_scaled_off);
            } else {
                establisher_frame = regs.rsp();
            }
            establisher_locked = true;
        }

        let codes_base = uoff + 4;
        let mut idx = 0usize;
        while idx < count_of_codes {
            let slot_off = codes_base.checked_add(idx * 2)?;
            let code_offset = u32::from(*mapped_image.get(slot_off)?);
            let op_byte = *mapped_image.get(slot_off + 1)?;
            let unwind_op = op_byte & 0x0F;
            let op_info = (op_byte >> 4) & 0x0F;

            let slots_consumed = match unwind_op {
                UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL | UWOP_SET_FPREG | UWOP_EPILOG
                | UWOP_PUSH_MACHFRAME => 1usize,
                UWOP_ALLOC_LARGE => {
                    if op_info == 0 {
                        2
                    } else {
                        3
                    }
                }
                UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => 2,
                UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR | UWOP_SPARE_CODE => 3,
                _ => return None,
            };

            if offset_in_func >= code_offset {
                match unwind_op {
                    UWOP_PUSH_NONVOL => {
                        let val = read_u64(regs.rsp())?;
                        regs.set_rsp(regs.rsp().wrapping_add(8));
                        regs.gpr[usize::from(op_info)] = val;
                    }
                    UWOP_ALLOC_LARGE => {
                        let alloc_bytes = if op_info == 0 {
                            u64::from(read_u16_le(mapped_image, slot_off + 2)?) * 8
                        } else {
                            u64::from(read_u32_le(mapped_image, slot_off + 2)?)
                        };
                        regs.set_rsp(regs.rsp().wrapping_add(alloc_bytes));
                    }
                    UWOP_ALLOC_SMALL => {
                        let alloc_bytes = u64::from(op_info) * 8 + 8;
                        regs.set_rsp(regs.rsp().wrapping_add(alloc_bytes));
                    }
                    UWOP_SET_FPREG if frame_reg != 0 && usize::from(frame_reg) < 16 => {
                        let new_rsp =
                            regs.gpr[usize::from(frame_reg)].wrapping_sub(frame_scaled_off);
                        regs.set_rsp(new_rsp);
                    }
                    UWOP_SAVE_NONVOL => {
                        let scaled = u64::from(read_u16_le(mapped_image, slot_off + 2)?) * 8;
                        let val = read_u64(regs.rsp().wrapping_add(scaled))?;
                        regs.gpr[usize::from(op_info)] = val;
                    }
                    UWOP_SAVE_NONVOL_FAR => {
                        let raw_off = u64::from(read_u32_le(mapped_image, slot_off + 2)?);
                        let val = read_u64(regs.rsp().wrapping_add(raw_off))?;
                        regs.gpr[usize::from(op_info)] = val;
                    }
                    UWOP_PUSH_MACHFRAME => {
                        let base_sp = if op_info == 1 {
                            regs.rsp().wrapping_add(8)
                        } else {
                            regs.rsp()
                        };
                        regs.rip = read_u64(base_sp)?;
                        let saved_rsp = read_u64(base_sp.wrapping_add(24))?;
                        regs.set_rsp(saved_rsp);
                        pushed_machframe = true;
                    }
                    _ => {}
                }
            }

            idx += slots_consumed;
        }

        // Trailer starts after `count_of_codes` rounded up to an even number of u16s (4-byte aligned).
        let aligned_codes = (count_of_codes + 1) & !1;
        let trailer_off = codes_base.checked_add(aligned_codes * 2)?;

        if chain_depth == 0 && (flags & UNW_FLAG_CHAININFO) == 0 && (flags & handler_type_mask) != 0
        {
            let h_rva = read_u32_le(mapped_image, trailer_off)?;
            primary_handler_rva = Some(h_rva);
            primary_handler_data_rva = (trailer_off as u32).saturating_add(4);
        }

        if (flags & UNW_FLAG_CHAININFO) != 0 {
            let parent_begin = read_u32_le(mapped_image, trailer_off)?;
            let parent_end = read_u32_le(mapped_image, trailer_off + 4)?;
            let parent_unwind = read_u32_le(mapped_image, trailer_off + 8)?;
            cur_func = RuntimeFunction {
                begin_address: parent_begin,
                end_address: parent_end,
                unwind_info_rva: parent_unwind,
            };
            continue;
        }
        break;
    }

    if !pushed_machframe {
        let caller_rip = read_u64(regs.rsp())?;
        regs.set_rsp(regs.rsp().wrapping_add(8));
        regs.rip = caller_rip;
    }

    Some(UnwindStepOutcome {
        establisher_frame,
        handler_rva: primary_handler_rva,
        handler_data_rva: primary_handler_data_rva,
    })
}
