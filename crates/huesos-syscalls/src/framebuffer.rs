//! Framebuffer query and bounded VMO-to-framebuffer blit syscalls.
//!
//! The blit path intentionally avoids allocating a temporary buffer as large
//! as the complete display. It validates the full VMO range first, then copies
//! a bounded group of scanlines at a time. Full HD/1440p presents therefore do
//! not churn multi-megabyte kernel heap blocks every frame.
//!
//! ## Capability check
//!
//! [`sys_framebuffer_blit`] is the only framebuffer syscall that mutates
//! real video memory, so it is the only one gated on a capability:
//! the caller must present a live `FrameDraw` [`Resource`](huesos_object::Resource)
//! handle in `a1`. The check runs **before** any userspace pointer is
//! read so a forged or stale handle value cannot leak information about
//! the caller's address space or about the kernel's framebuffer
//! geometry. The check reuses the `require_resource_of_kind` helper
//! that gates [`crate::resource::sys_hard_halt`] on
//! [`ResourceKind::PowerControl`], so a missing, wrong-kind, or
//! already-transferred handle all surface as `AccessDenied` and the
//! behaviour is uniform across the capability-gated syscalls.
//!
//! `FramebufferInfo` stays public because geometry (resolution, pixel
//! format) is not sensitive: any process that can already see a
//! `Canvas` rendering on screen can learn resolution from the visible
//! image, and pixel format is dictated by the hardware.

use huesos_abi::{ErrorCode, FramebufferBlitArgs, FramebufferInfo, HandleValue};
use huesos_object::{KernelObjectExt, ResourceKind, Rights};

use crate::resource::require_resource_of_kind;
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

fn strided_source_span(row_bytes: u64, stride: u64, height: u32) -> Option<u64> {
    let preceding_rows = u64::from(height.checked_sub(1)?);
    preceding_rows.checked_mul(stride)?.checked_add(row_bytes)
}

pub(crate) fn sys_framebuffer_blit(
    cap_handle: HandleValue,
    args_ptr: *const FramebufferBlitArgs,
) -> SyscallResult {
    // Capability check first: the caller must present a live `FrameDraw`
    // Resource handle. The Arc returned by `require_resource_of_kind`
    // keeps the underlying Resource alive for the duration of this call,
    // so even a concurrent capability revocation in another thread
    // cannot race us into a use-after-free. The Arc is dropped at the
    // end of the function by ordinary Rust scope rules.
    let _cap = require_resource_of_kind(cap_handle, ResourceKind::FrameDraw)?;
    let args = user_memory::read_value(args_ptr)?;
    let fb_info = huesos_fb::info().ok_or(ErrorCode::NoFramebuffer)?;
    let bytes_per_pixel = (fb_info.bpp as u64).div_ceil(8);
    let row_bytes_u64 = (args.src_width as u64)
        .checked_mul(bytes_per_pixel)
        .ok_or(ErrorCode::InvalidArgs)?;
    let stride = args.src_stride as u64;
    let packed_byte_len = row_bytes_u64
        .checked_mul(args.src_height as u64)
        .ok_or(ErrorCode::InvalidArgs)?;
    if packed_byte_len == 0
        || packed_byte_len > MAX_BLIT_BYTES
        || row_bytes_u64 > MAX_ROW_BYTES as u64
        || stride < row_bytes_u64
        || stride > MAX_BLIT_BYTES
        || packed_byte_len > usize::MAX as u64
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
    let source_span = strided_source_span(row_bytes_u64, stride, args.src_height)
        .ok_or(ErrorCode::InvalidArgs)?;
    let source_end = args
        .vmo_offset
        .checked_add(source_span)
        .ok_or(ErrorCode::InvalidArgs)?;
    if source_end > vmo.size() as u64 || source_end > usize::MAX as u64 {
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
        if stride == row_bytes_u64 {
            let source_offset = (args.vmo_offset as usize)
                .checked_add(first_row * row_bytes)
                .ok_or(ErrorCode::InvalidArgs)?;
            if vmo.read(source_offset, &mut buffer[..chunk_len]) != chunk_len {
                return Err(ErrorCode::InvalidArgs);
            }
        } else {
            for row in 0..rows {
                let source_offset = args
                    .vmo_offset
                    .checked_add(
                        (first_row + row)
                            .checked_mul(stride as usize)
                            .ok_or(ErrorCode::InvalidArgs)? as u64,
                    )
                    .ok_or(ErrorCode::InvalidArgs)? as usize;
                let output = &mut buffer[row * row_bytes..(row + 1) * row_bytes];
                if vmo.read(source_offset, output) != row_bytes {
                    return Err(ErrorCode::InvalidArgs);
                }
            }
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

#[cfg(test)]
mod tests {
    use super::{strided_source_span, sys_framebuffer_blit};
    use huesos_abi::{FramebufferBlitArgs, HandleValue};

    #[test]
    fn strided_span_includes_only_bytes_through_last_row() {
        assert_eq!(strided_source_span(16, 64, 1), Some(16));
        assert_eq!(strided_source_span(16, 64, 3), Some(144));
    }

    #[test]
    fn strided_span_rejects_zero_height_and_overflow() {
        assert_eq!(strided_source_span(16, 64, 0), None);
        assert_eq!(strided_source_span(16, u64::MAX, 3), None);
    }

    #[test]
    fn framebuffer_blit_signature_takes_capability_handle() {
        // Lock the public ABI shape of `sys_framebuffer_blit` so a
        // refactor that reorders or removes the capability parameter
        // fails this test before it can ship.
        //
        // The function must take (HandleValue, *const FramebufferBlitArgs)
        // in that order: capability first, then the pointer to the
        // arguments struct. The capability check runs before the
        // pointer is read, so flipping the order would let a forged
        // handle leak information about the caller's address space.
        let _: fn(HandleValue, *const FramebufferBlitArgs) -> _ = sys_framebuffer_blit;
    }
}
