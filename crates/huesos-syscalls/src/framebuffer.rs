//! Framebuffer query and bounded VMO-to-framebuffer blit syscalls.
//!
//! The blit path intentionally avoids allocating a temporary buffer as large
//! as the complete display. It validates the full VMO range first, then copies
//! a bounded group of scanlines at a time. Full HD/1440p presents therefore do
//! not churn multi-megabyte kernel heap blocks every frame.

use huesos_abi::{ErrorCode, FramebufferBlitArgs, FramebufferInfo};
use huesos_object::{KernelObjectExt, Rights};

use crate::{user_memory, util::current_proc, SyscallResult};

pub(crate) fn sys_framebuffer_info(out: *mut FramebufferInfo) -> SyscallResult {
    user_memory::validate_write(out)?;
    let info = huesos_fb::info().ok_or(ErrorCode::NoFramebuffer)?;
    user_memory::write_value(out, &info)?;
    Ok(0)
}

const MAX_BLIT_BYTES: u64 = 64 * 1024 * 1024;
const BLIT_CHUNK_BYTES: usize = 64 * 1024;
const MAX_ROW_BYTES: usize = 1024 * 1024;

pub(crate) fn sys_framebuffer_blit(args_ptr: *const FramebufferBlitArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    let fb_info = huesos_fb::info().ok_or(ErrorCode::NoFramebuffer)?;
    let bytes_per_pixel = (fb_info.bpp as u64).div_ceil(8);
    let row_bytes_u64 = (args.src_width as u64)
        .checked_mul(bytes_per_pixel)
        .ok_or(ErrorCode::InvalidArgs)?;
    let byte_len = row_bytes_u64
        .checked_mul(args.src_height as u64)
        .ok_or(ErrorCode::InvalidArgs)?;
    if byte_len == 0
        || byte_len > MAX_BLIT_BYTES
        || row_bytes_u64 > MAX_ROW_BYTES as u64
        || byte_len > usize::MAX as u64
    {
        return Err(ErrorCode::InvalidArgs);
    }

    let proc = current_proc()?;
    let handle = proc.handles.get(args.vmo).ok_or(ErrorCode::BadHandle)?;
    if !handle.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let object = huesos_object::lookup_object(handle.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = object
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;

    // Validate the whole source before the first visible write, preventing a
    // malformed short VMO from producing a partially updated framebuffer.
    let source_end = args
        .vmo_offset
        .checked_add(byte_len)
        .ok_or(ErrorCode::InvalidArgs)?;
    if source_end > vmo.size() as u64 || args.vmo_offset > usize::MAX as u64 {
        return Err(ErrorCode::InvalidArgs);
    }

    let row_bytes = row_bytes_u64 as usize;
    let rows_per_chunk = (BLIT_CHUNK_BYTES / row_bytes).max(1);
    let buffer_bytes = rows_per_chunk
        .checked_mul(row_bytes)
        .ok_or(ErrorCode::InvalidArgs)?;
    let mut buffer = user_memory::zeroed_buffer(buffer_bytes)?;

    let mut first_row = 0usize;
    let height = args.src_height as usize;
    while first_row < height {
        let rows = rows_per_chunk.min(height - first_row);
        let chunk_len = rows * row_bytes;
        let source_offset = (args.vmo_offset as usize)
            .checked_add(first_row * row_bytes)
            .ok_or(ErrorCode::InvalidArgs)?;
        let copied = vmo.read(source_offset, &mut buffer[..chunk_len]);
        if copied != chunk_len {
            return Err(ErrorCode::InvalidArgs);
        }
        huesos_fb::blit(
            args.dst_x,
            args.dst_y.saturating_add(first_row as u32),
            args.src_width,
            rows as u32,
            &buffer[..chunk_len],
        )
        .map_err(|_| ErrorCode::NoFramebuffer)?;
        first_row += rows;
    }

    Ok(0)
}
