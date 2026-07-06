//! Framebuffer query/blit syscalls.

use alloc::vec;
use huesos_abi::{ErrorCode, FramebufferBlitArgs, FramebufferInfo};
use huesos_object::{KernelObjectExt, Rights};

use crate::{util::current_proc, SyscallResult};

pub(crate) fn sys_framebuffer_info(out: *mut FramebufferInfo) -> SyscallResult {
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

pub(crate) fn sys_framebuffer_blit(args_ptr: *const FramebufferBlitArgs) -> SyscallResult {
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
    let byte_len = pixel_count.saturating_mul(bpp_bytes).min(usize::MAX as u64) as usize;

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
