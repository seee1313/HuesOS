//! # HuesOS Syscall Interface
//!
//! Table-driven syscall dispatch, called from the arch-level `syscall`
//! trampoline with the raw register frame. Syscall numbers and error codes
//! live in `huesos-abi`, the single shared source of truth between this
//! (kernel-side) dispatcher and `libcanvas` (the userspace-side safe
//! wrapper library) — see that crate's docs for why duplicating these
//! constants in two places would be a bug waiting to happen.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use huesos_abi::{ErrorCode, FramebufferBlitArgs, FramebufferInfo, HandleValue, INVALID_HANDLE};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};
use spin::Mutex;

/// Result type for syscalls: `Ok(value)` or a negative error code.
pub type SyscallResult = Result<i64, ErrorCode>;

/// Global yield callback (set by kernel scheduler to avoid circular deps).
static YIELD_FN: Mutex<Option<fn()>> = Mutex::new(None);
/// Global process-exit callback (set by kernel scheduler).
static EXIT_FN: Mutex<Option<fn(i64) -> !>> = Mutex::new(None);
/// Global debug-write callback (set by kernel to point at the serial writer).
static DEBUG_WRITE_FN: Mutex<Option<fn(&[u8])>> = Mutex::new(None);

/// Set the yield function. Called once by kernel init.
pub fn set_yield_fn(f: fn()) {
    *YIELD_FN.lock() = Some(f);
}

/// Set the process-exit function. Called once by kernel init.
pub fn set_exit_fn(f: fn(i64) -> !) {
    *EXIT_FN.lock() = Some(f);
}

/// Set the debug-write function. Called once by kernel init.
pub fn set_debug_write_fn(f: fn(&[u8])) {
    *DEBUG_WRITE_FN.lock() = Some(f);
}

/// Dispatch a syscall by number. This is architecture-independent; the
/// arch layer is responsible for extracting `num`/`a1..a5` from registers.
///
/// Unknown syscall numbers (including ones from a future ABI version this
/// kernel build predates) return `ErrorCode::NotSupported` rather than
/// silently doing nothing or panicking — callers can detect "this kernel
/// is too old for what I'm asking" as a normal, recoverable condition.
pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> SyscallResult {
    use huesos_abi::Syscall as S;
    let Some(syscall) = S::from_raw(num) else {
        return Err(ErrorCode::NotSupported);
    };
    match syscall {
        S::Nop => sys_nop(),
        S::VmoCreate => sys_vmo_create(a1 as usize, a2 as *mut HandleValue),
        S::HandleClose => sys_handle_close(a1 as HandleValue),
        S::HandleDuplicate => {
            sys_handle_duplicate(a1 as HandleValue, a2 as u32, a3 as *mut HandleValue)
        }
        S::Yield => sys_yield(),
        S::VmoRead => sys_vmo_read(a1 as HandleValue, a2, a3 as *mut u8, a4 as usize),
        S::VmoWrite => sys_vmo_write(a1 as HandleValue, a2, a3 as *const u8, a4 as usize),
        S::ChannelCreate => sys_channel_create(a1 as *mut HandleValue, a2 as *mut HandleValue),
        S::ChannelWrite => sys_channel_write(
            a1 as HandleValue,
            a2 as *const u8,
            a3 as u32,
            a4 as *const HandleValue,
            a5 as u32,
        ),
        S::ChannelRead => {
            sys_channel_read(a1 as HandleValue, a2 as *mut u8, a3 as u32, a4 as *mut u32)
        }
        S::ProcessExit => sys_process_exit(a1 as i64),
        S::DebugWrite => sys_debug_write(a1 as *const u8, a2 as usize),
        S::FramebufferInfo => sys_framebuffer_info(a1 as *mut FramebufferInfo),
        S::FramebufferBlit => sys_framebuffer_blit(a1 as *const FramebufferBlitArgs),
    }
}

fn sys_nop() -> SyscallResult {
    Ok(0)
}

fn current_proc() -> Result<alloc::sync::Arc<huesos_object::Process>, ErrorCode> {
    huesos_object::current_process().ok_or(ErrorCode::BadHandle)
}

/// Upper bound on a single VMO's size (4 GiB). This is *not* a real memory
/// accounting/quota system (see the Job resource-limits roadmap item) — it
/// exists purely to reject obviously-bogus sizes (e.g. a userspace bug
/// passing `usize::MAX`) before they reach `Vec::with_capacity`, which
/// would otherwise abort the whole kernel with a "capacity overflow" panic
/// while trying to allocate a frame-address array sized for an
/// astronomical page count, rather than cleanly failing the syscall.
const MAX_VMO_SIZE: usize = 4 * 1024 * 1024 * 1024;

fn sys_vmo_create(size: usize, out_handle: *mut HandleValue) -> SyscallResult {
    if out_handle.is_null() || size == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    if size > MAX_VMO_SIZE {
        return Err(ErrorCode::NoMemory);
    }
    let vmo = huesos_object::Vmo::new(size).map_err(|_| ErrorCode::NoMemory)?;
    let koid = vmo.koid();
    huesos_object::register_object(vmo);
    let proc = current_proc()?;
    let hv = proc.handles.add(Handle::new(koid, Rights::DEFAULT_VMO));
    unsafe {
        *out_handle = hv;
    }
    Ok(0)
}

fn sys_vmo_read(handle: HandleValue, offset: u64, buf: *mut u8, len: usize) -> SyscallResult {
    if buf.is_null() || len == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;
    let mut tmp = vec![0u8; len];
    let n = vmo.read(offset as usize, &mut tmp);
    unsafe {
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n);
    }
    Ok(n as i64)
}

fn sys_vmo_write(handle: HandleValue, offset: u64, buf: *const u8, len: usize) -> SyscallResult {
    if buf.is_null() || len == 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;
    let tmp = unsafe { core::slice::from_raw_parts(buf, len) };
    let n = vmo.write(offset as usize, tmp);
    Ok(n as i64)
}

fn sys_handle_close(handle: HandleValue) -> SyscallResult {
    if handle == INVALID_HANDLE {
        return Err(ErrorCode::BadHandle);
    }
    let proc = current_proc()?;
    proc.handles.remove(handle).ok_or(ErrorCode::BadHandle)?;
    Ok(0)
}

fn sys_handle_duplicate(handle: HandleValue, rights: u32, out: *mut HandleValue) -> SyscallResult {
    if handle == INVALID_HANDLE || out.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    let new_rights = if rights == huesos_abi::rights::SAME_RIGHTS {
        h.rights
    } else {
        Rights::from_bits_truncate(rights)
    };
    let new_h = Handle::new(h.koid, new_rights);
    let new_hv = proc.handles.add(new_h);
    unsafe {
        *out = new_hv;
    }
    Ok(0)
}

fn sys_yield() -> SyscallResult {
    if let Some(f) = *YIELD_FN.lock() {
        f();
    }
    Ok(0)
}

fn sys_channel_create(out0: *mut HandleValue, out1: *mut HandleValue) -> SyscallResult {
    if out0.is_null() || out1.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let (ch0, ch1) = huesos_object::Channel::pair();
    let koid0 = ch0.koid();
    let koid1 = ch1.koid();
    huesos_object::register_object(ch0);
    huesos_object::register_object(ch1);
    let proc = current_proc()?;
    let hv0 = proc.handles.add(Handle::new(koid0, Rights::DEFAULT));
    let hv1 = proc.handles.add(Handle::new(koid1, Rights::DEFAULT));
    unsafe {
        *out0 = hv0;
        *out1 = hv1;
    }
    Ok(0)
}

fn sys_channel_write(
    handle: HandleValue,
    bytes: *const u8,
    num_bytes: u32,
    handles: *const HandleValue,
    num_handles: u32,
) -> SyscallResult {
    if bytes.is_null() && num_bytes > 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;
    let data: Vec<u8> = if num_bytes > 0 {
        unsafe { core::slice::from_raw_parts(bytes, num_bytes as usize).to_vec() }
    } else {
        Vec::new()
    };
    let mut transferred = Vec::new();
    for i in 0..num_handles {
        let hv = unsafe { *handles.add(i as usize) };
        let inner_h = proc.handles.get(hv).ok_or(ErrorCode::BadHandle)?;
        transferred.push(inner_h);
    }
    ch.send(huesos_object::ChannelMessage {
        data,
        handles: transferred,
    });
    Ok(0)
}

fn sys_channel_read(
    handle: HandleValue,
    buf: *mut u8,
    len: u32,
    out_actual: *mut u32,
) -> SyscallResult {
    if buf.is_null() || out_actual.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let ch = obj
        .downcast_ref::<huesos_object::Channel>()
        .ok_or(ErrorCode::WrongType)?;
    let msg = ch.recv().ok_or(ErrorCode::ShouldWait)?;
    let to_copy = msg.data.len().min(len as usize);
    unsafe {
        core::ptr::copy_nonoverlapping(msg.data.as_ptr(), buf, to_copy);
        *out_actual = to_copy as u32;
    }
    Ok(0)
}

fn sys_process_exit(code: i64) -> SyscallResult {
    if let Some(f) = *EXIT_FN.lock() {
        f(code);
    }
    // No exit handler registered: park forever rather than UB.
    loop {
        huesos_arch::hlt();
    }
}

fn sys_debug_write(buf: *const u8, len: usize) -> SyscallResult {
    if buf.is_null() || len == 0 || len > 4096 {
        return Err(ErrorCode::InvalidArgs);
    }
    let slice = unsafe { core::slice::from_raw_parts(buf, len) };
    if let Some(f) = *DEBUG_WRITE_FN.lock() {
        f(slice);
    }
    Ok(len as i64)
}

fn sys_framebuffer_info(out: *mut FramebufferInfo) -> SyscallResult {
    if out.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let info = huesos_fb::info().ok_or(ErrorCode::NoFramebuffer)?;
    unsafe {
        *out = info;
    }
    Ok(0)
}

/// Upper bound on a single blit's pixel count, to reject obviously-bogus
/// `src_width`/`src_height` before they're used to size a temporary
/// buffer — same rationale as `MAX_VMO_SIZE` above. 64 megapixels is far
/// beyond any real display this kernel is likely to drive.
const MAX_BLIT_PIXELS: u64 = 64 * 1024 * 1024;

fn sys_framebuffer_blit(args_ptr: *const FramebufferBlitArgs) -> SyscallResult {
    if args_ptr.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    // Copy the args struct by value immediately: it lives in userspace
    // memory that could theoretically be concurrently modified by another
    // thread in the same process, so every field below is a local copy,
    // not a live read through the pointer.
    let args = unsafe { core::ptr::read_unaligned(args_ptr) };

    let fb_info = huesos_fb::info().ok_or(ErrorCode::NoFramebuffer)?;
    let bpp_bytes = (fb_info.bpp as u64).div_ceil(8);

    let pixel_count = (args.src_width as u64).saturating_mul(args.src_height as u64);
    if pixel_count == 0 || pixel_count > MAX_BLIT_PIXELS {
        return Err(ErrorCode::InvalidArgs);
    }
    let byte_len = pixel_count
        .saturating_mul(bpp_bytes)
        .min(usize::MAX as u64) as usize;

    let proc = current_proc()?;
    let h = proc.handles.get(args.vmo).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;

    let mut pixels = vec![0u8; byte_len];
    let copied = vmo.read(args.vmo_offset as usize, &mut pixels);
    if copied < byte_len {
        // Source VMO doesn't actually have this many bytes at this
        // offset; truncate what we blit rather than reading garbage.
        pixels.truncate(copied);
    }

    huesos_fb::blit(args.dst_x, args.dst_y, args.src_width, args.src_height, &pixels)
        .map_err(|_| ErrorCode::NoFramebuffer)?;

    Ok(0)
}
