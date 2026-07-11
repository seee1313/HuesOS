//! Framebuffer query/blit syscalls.

use huesos_abi::{ErrorCode, FramebufferBlitArgs, FramebufferInfo};
use huesos_object::{KernelObjectExt, Rights};

use crate::{user_memory, util::current_proc, SyscallResult};

pub(crate) fn sys_framebuffer_info(out: *mut FramebufferInfo) -> SyscallResult {
    user_memory::validate_write(out)?;
    let info = huesos_fb::info().ok_or(ErrorCode::NoFramebuffer)?;
    user_memory::write_value(out, &info)?;
    Ok(0)
}

/// Upper bound on a single blit's source allocation. This is intentionally a
/// byte limit rather than only a pixel limit because framebuffer formats have
/// different bytes-per-pixel values.
const MAX_BLIT_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn sys_framebuffer_blit(args_ptr: *const FramebufferBlitArgs) -> SyscallResult {
    // Snapshot the record through the validated user-copy boundary so a second
    // userspace thread cannot change fields while the operation is in flight.
    let args = user_memory::read_value(args_ptr)?;

    let fb_info = huesos_fb::info().ok_or(ErrorCode::NoFramebuffer)?;
    let bpp_bytes = (fb_info.bpp as u64).div_ceil(8);
    let pixel_count = (args.src_width as u64)
        .checked_mul(args.src_height as u64)
        .ok_or(ErrorCode::InvalidArgs)?;
    let byte_len = pixel_count
        .checked_mul(bpp_bytes)
        .ok_or(ErrorCode::InvalidArgs)?;
    if byte_len == 0 || byte_len > MAX_BLIT_BYTES || byte_len > usize::MAX as u64 {
        return Err(ErrorCode::InvalidArgs);
    }

    let proc = current_proc()?;
    let h = proc.handles.get(args.vmo).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let obj = huesos_object::lookup_object(h.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;

    let mut pixels = user_memory::zeroed_buffer(byte_len as usize)?;
    let copied = vmo.read(args.vmo_offset as usize, &mut pixels);
    if copied < pixels.len() {
        pixels.truncate(copied);
    }

    huesos_fb::blit(
        args.dst_x,
        args.dst_y,
        args.src_width,
        args.src_height,
        &pixels,
    )
    .map_err(|_| ErrorCode::NoFramebuffer)?;

    Ok(0)
}
