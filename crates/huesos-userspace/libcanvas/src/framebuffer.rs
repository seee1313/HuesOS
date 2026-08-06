//! Safe framebuffer access for userspace.
//!
//! Userspace never gets a mapping of the real video memory — it draws
//! into an ordinary [`Vmo`] it owns, using [`Canvas`]'s pixel/rect/text
//! primitives, then calls [`Canvas::present`] to ask the kernel to copy
//! (blit) that VMO's contents onto the real screen. The kernel's blit
//! syscall bounds-checks everything against the real framebuffer size
//! before touching video memory, so a buggy or malicious blit call can,
//! at worst, draw garbage within its own declared rectangle — it cannot
//! read or corrupt memory outside the VMO it already owns.
//!
//! ## FrameDraw capability
//!
//! Every blit is capability-gated: the kernel's [`Syscall::FramebufferBlit`]
//! handler requires a live `FrameDraw` [`Resource`](huesos_object::Resource)
//! handle owned by the caller. A `Canvas` therefore carries the
//! capability handle it will use for every blit, set at construction
//! time. The handle is set to the canonical initial-process slot
//! [`huesos_abi::INIT_FRAME_DRAW_HANDLE`] by default because the init
//! process is the only place a `FrameDraw` resource exists in the
//! MVP boot path; legitimate graphics processes that receive the
//! handle over a channel from `init` should pass that handle value
//! to [`Canvas::new_with_cap`] (or [`Canvas::new_fullscreen_with_cap`]).
//! Processes that never received a `FrameDraw` capability get
//! `AccessDenied` from the kernel on every blit; the error is
//! surfaced through the usual `Result` return.

use crate::raw;
use crate::vmo::Vmo;
use huesos_abi::{
    FramebufferBlitArgs, FramebufferInfo, HandleValue, Syscall, INIT_FRAME_DRAW_HANDLE,
};

/// Query the real framebuffer's geometry and pixel format. Returns
/// `Err(ErrorCode::NoFramebuffer)` if the system has none (e.g. serial-only
/// boot).
pub fn info() -> crate::Result<FramebufferInfo> {
    let mut info = FramebufferInfo::default();
    let ret = raw::syscall1(Syscall::FramebufferInfo, &mut info as *mut _ as u64);
    raw::decode(ret)?;
    Ok(info)
}

/// Built-in text font selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextFont {
    /// Cozette 6x13 (default). Real hand-drawn bitmap font from
    /// <https://github.com/slavfox/Cozette> (MIT), with proper
    /// baseline metrics, descenders for `g`/`p`/`y`/etc., and a
    /// compact 6-pixel advance width. Regenerate via
    /// `tools/fontgen/bdf2rs.py`.
    Cozette6x13,
    /// TTY-style 8x16 font. Each source 8x8 bitmap row is expanded
    /// to two scanlines. Retained as a fallback so terminal layouts
    /// that hard-code an 8-pixel advance keep working during the
    /// migration.
    Tty8x16,
    /// Original compact 8x8 HuesOS font.
    Compact8x8,
}

impl TextFont {
    /// Advance width in pixels per glyph.
    pub const fn cell_w(self) -> u32 {
        match self {
            Self::Cozette6x13 => crate::font6x13::CELL_W as u32,
            Self::Tty8x16 | Self::Compact8x8 => 8,
        }
    }

    /// Cell height in pixels per line.
    pub const fn cell_h(self) -> u32 {
        match self {
            Self::Cozette6x13 => crate::font6x13::CELL_H as u32,
            Self::Tty8x16 => 16,
            Self::Compact8x8 => 8,
        }
    }
}

/// An off-screen drawing surface, backed by a VMO, matching the real
/// framebuffer's pixel format. Draw into it with `set_pixel`/`fill_rect`/
/// `draw_text`, then call [`Canvas::present`] to blit it to the screen.
pub struct Canvas {
    vmo: Vmo,
    info: FramebufferInfo,
    bytes_per_pixel: u32,
    /// `FrameDraw` capability handle used by every blit. Set at
    /// construction; the kernel rejects any blit whose handle does
    /// not name a live caller-owned `FrameDraw` resource.
    cap: HandleValue,
}

impl Canvas {
    /// Create a canvas the same size as the real framebuffer, using
    /// the default `FrameDraw` capability slot installed in the init
    /// process ([`INIT_FRAME_DRAW_HANDLE`]). Suitable for code that
    /// runs inside the init process itself; graphics processes that
    /// received a transferred capability handle from init should use
    /// [`Canvas::new_fullscreen_with_cap`].
    pub fn new_fullscreen() -> crate::Result<Self> {
        Self::new_fullscreen_with_cap(INIT_FRAME_DRAW_HANDLE)
    }

    /// Like [`Canvas::new_fullscreen`] but lets the caller specify
    /// which `FrameDraw` capability handle to use. The handle must
    /// name a live caller-owned `FrameDraw` resource; otherwise every
    /// blit will return `AccessDenied`.
    pub fn new_fullscreen_with_cap(cap: HandleValue) -> crate::Result<Self> {
        let info = info()?;
        Self::new_with_cap(info.width, info.height, cap)
    }

    /// Create a canvas of an arbitrary size (e.g. smaller than the full
    /// screen, to later blit at some offset via [`Canvas::present_at`]),
    /// using the default `FrameDraw` capability slot.
    pub fn new(width: u32, height: u32) -> crate::Result<Self> {
        Self::new_with_cap(width, height, INIT_FRAME_DRAW_HANDLE)
    }

    /// Create a canvas of an arbitrary size, using an explicit
    /// `FrameDraw` capability handle.
    pub fn new_with_cap(width: u32, height: u32, cap: HandleValue) -> crate::Result<Self> {
        let info = info()?;
        Self::from_info_with_cap(info, width, height, cap)
    }

    /// Internal shared constructor: callers (graphics tests, the
    /// `info`-shaped public constructors) reuse the same VMO sizing
    /// logic but pass an explicit capability handle.
    fn from_info_with_cap(
        info: FramebufferInfo,
        width: u32,
        height: u32,
        cap: HandleValue,
    ) -> crate::Result<Self> {
        let bytes_per_pixel = (info.bpp as u32).div_ceil(8);
        let pitch = width
            .checked_mul(bytes_per_pixel)
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        let size = (pitch as u64)
            .checked_mul(height as u64)
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        let vmo = Vmo::create(size)?;
        Ok(Self {
            vmo,
            info: FramebufferInfo {
                width,
                height,
                pitch, // tightly packed, no padding
                ..info
            },
            bytes_per_pixel,
            cap,
        })
    }

    /// Canvas width in pixels.
    pub fn width(&self) -> u32 {
        self.info.width
    }

    /// Canvas height in pixels.
    pub fn height(&self) -> u32 {
        self.info.height
    }

    /// Number of tightly-packed bytes backing this Canvas.
    pub fn byte_len(&self) -> usize {
        self.info.pitch as usize * self.info.height as usize
    }

    /// Whether the fast userspace raster path can write this Canvas format.
    pub fn supports_buffered_raster(&self) -> bool {
        self.bytes_per_pixel == 4
    }

    /// Fill a caller-provided packed shadow buffer without any syscall.
    pub fn clear_shadow(&self, shadow: &mut [u8], r: u8, g: u8, b: u8) -> crate::Result<()> {
        let len = self.byte_len();
        if !self.supports_buffered_raster() || shadow.len() < len {
            return Err(crate::ErrorCode::InvalidArgs);
        }
        let pixel = self.pack_color(r, g, b).to_le_bytes();
        for output in shadow[..len].chunks_exact_mut(4) {
            output.copy_from_slice(&pixel);
        }
        Ok(())
    }

    /// Fill a clipped rectangle in a packed shadow buffer without syscalls.
    #[allow(clippy::too_many_arguments)]
    pub fn fill_rect_to_shadow(
        &self,
        shadow: &mut [u8],
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        r: u8,
        g: u8,
        b: u8,
    ) -> crate::Result<()> {
        let len = self.byte_len();
        if !self.supports_buffered_raster() || shadow.len() < len {
            return Err(crate::ErrorCode::InvalidArgs);
        }
        let x_end = x.saturating_add(w).min(self.info.width);
        let y_end = y.saturating_add(h).min(self.info.height);
        if x >= x_end || y >= y_end {
            return Ok(());
        }
        let pixel = self.pack_color(r, g, b).to_le_bytes();
        for output_y in y..y_end {
            let row = output_y as usize * self.info.pitch as usize;
            for output_x in x..x_end {
                let offset = row + output_x as usize * 4;
                shadow[offset..offset + 4].copy_from_slice(&pixel);
            }
        }
        Ok(())
    }

    /// Rasterize text directly into a packed shadow buffer without issuing
    /// per-pixel VMO writes. Dispatches on `font` to either the native
    /// Cozette 6x13 rasteriser or the legacy scaled-8x8 rasteriser.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_text_to_shadow(
        &self,
        shadow: &mut [u8],
        x: u32,
        y: u32,
        text: &str,
        r: u8,
        g: u8,
        b: u8,
        font: TextFont,
    ) -> crate::Result<()> {
        let len = self.byte_len();
        if !self.supports_buffered_raster() || shadow.len() < len {
            return Err(crate::ErrorCode::InvalidArgs);
        }
        let pixel = self.pack_color(r, g, b).to_le_bytes();
        match font {
            TextFont::Cozette6x13 => self.draw_text_to_shadow_6x13(shadow, x, y, text, &pixel),
            TextFont::Tty8x16 | TextFont::Compact8x8 => {
                self.draw_text_to_shadow_8x8(shadow, x, y, text, &pixel, font)
            }
        }
    }

    fn draw_text_to_shadow_6x13(
        &self,
        shadow: &mut [u8],
        x: u32,
        y: u32,
        text: &str,
        pixel: &[u8; 4],
    ) -> crate::Result<()> {
        let fallback: [u8; crate::font6x13::CELL_H] = [0b0011_1111; crate::font6x13::CELL_H];
        let cell_w = crate::font6x13::CELL_W as u32;
        let mut cursor_x = x;
        for ch in text.chars() {
            let glyph = crate::font6x13::glyph(ch).unwrap_or(&fallback);
            for (source_y, bits) in glyph.iter().enumerate() {
                let output_y = y + source_y as u32;
                if output_y >= self.info.height {
                    continue;
                }
                for column in 0..cell_w {
                    if bits & (1 << column) == 0 {
                        continue;
                    }
                    let output_x = cursor_x + column;
                    if output_x >= self.info.width {
                        continue;
                    }
                    let offset =
                        output_y as usize * self.info.pitch as usize + output_x as usize * 4;
                    shadow[offset..offset + 4].copy_from_slice(pixel);
                }
            }
            cursor_x = cursor_x.saturating_add(cell_w);
        }
        Ok(())
    }

    fn draw_text_to_shadow_8x8(
        &self,
        shadow: &mut [u8],
        x: u32,
        y: u32,
        text: &str,
        pixel: &[u8; 4],
        font: TextFont,
    ) -> crate::Result<()> {
        let scale = if font == TextFont::Tty8x16 { 2 } else { 1 };
        let mut cursor_x = x;
        for ch in text.chars() {
            let glyph = crate::font8x8::glyph(ch).unwrap_or(&[0xff; 8]);
            for (source_y, bits) in glyph.iter().enumerate() {
                for repeat in 0..scale {
                    let output_y = y + source_y as u32 * scale + repeat;
                    if output_y >= self.info.height {
                        continue;
                    }
                    for column in 0..8u32 {
                        if bits & (1 << column) == 0 {
                            continue;
                        }
                        let output_x = cursor_x + column;
                        if output_x >= self.info.width {
                            continue;
                        }
                        let offset =
                            output_y as usize * self.info.pitch as usize + output_x as usize * 4;
                        shadow[offset..offset + 4].copy_from_slice(pixel);
                    }
                }
            }
            cursor_x = cursor_x.saturating_add(8);
        }
        Ok(())
    }

    /// Upload a dirty shadow-buffer rectangle into the matching VMO region.
    /// Full-width stripes are transferred in one contiguous VMO write; narrower
    /// rectangles still copy row-by-row because the source shadow and VMO retain
    /// the full-canvas stride outside the rectangle.
    pub fn upload_shadow_region(
        &self,
        shadow: &[u8],
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    ) -> crate::Result<()> {
        let len = self.byte_len();
        let x_end = x.checked_add(width).ok_or(crate::ErrorCode::InvalidArgs)?;
        let y_end = y.checked_add(height).ok_or(crate::ErrorCode::InvalidArgs)?;
        if !self.supports_buffered_raster()
            || shadow.len() < len
            || width == 0
            || height == 0
            || x_end > self.info.width
            || y_end > self.info.height
        {
            return Err(crate::ErrorCode::InvalidArgs);
        }
        let pitch = self.info.pitch as usize;
        let row_bytes = width as usize * 4;
        if x == 0 && width == self.info.width {
            const CHUNK: usize = 1024 * 1024;
            let start = y as usize * pitch;
            let end = start + height as usize * pitch;
            let mut offset = start;
            while offset < end {
                let chunk_end = (offset + CHUNK).min(end);
                if self.vmo.write(offset as u64, &shadow[offset..chunk_end])? != chunk_end - offset
                {
                    return Err(crate::ErrorCode::InvalidArgs);
                }
                offset = chunk_end;
            }
            return Ok(());
        }
        for output_y in y..y_end {
            let offset = output_y as usize * pitch + x as usize * 4;
            let end = offset + row_bytes;
            if self.vmo.write(offset as u64, &shadow[offset..end])? != row_bytes {
                return Err(crate::ErrorCode::InvalidArgs);
            }
        }
        Ok(())
    }

    /// Upload a complete packed shadow buffer in bounded 1 MiB transfers.
    pub fn upload_shadow(&self, shadow: &[u8]) -> crate::Result<()> {
        let len = self.byte_len();
        if shadow.len() < len {
            return Err(crate::ErrorCode::InvalidArgs);
        }
        const CHUNK: usize = 1024 * 1024;
        let mut offset = 0usize;
        while offset < len {
            let end = (offset + CHUNK).min(len);
            let written = self.vmo.write(offset as u64, &shadow[offset..end])?;
            if written != end - offset {
                return Err(crate::ErrorCode::InvalidArgs);
            }
            offset = end;
        }
        Ok(())
    }

    #[inline]
    fn pack_color(&self, r: u8, g: u8, b: u8) -> u32 {
        let c = &self.info;
        let r = (r as u32) >> (8u8.saturating_sub(c.red_mask_size));
        let g = (g as u32) >> (8u8.saturating_sub(c.green_mask_size));
        let b = (b as u32) >> (8u8.saturating_sub(c.blue_mask_size));
        (r << c.red_mask_shift) | (g << c.green_mask_shift) | (b << c.blue_mask_shift)
    }

    #[inline]
    fn offset(&self, x: u32, y: u32) -> u64 {
        (y as u64) * (self.info.pitch as u64) + (x as u64) * (self.bytes_per_pixel as u64)
    }

    /// Set a single pixel. Silently clipped if out of bounds.
    pub fn set_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) -> crate::Result<()> {
        if x >= self.info.width || y >= self.info.height {
            return Ok(());
        }
        let packed = self.pack_color(r, g, b);
        let bytes = packed.to_le_bytes();
        self.vmo
            .write(self.offset(x, y), &bytes[..self.bytes_per_pixel as usize])?;
        Ok(())
    }

    /// Fill an axis-aligned rectangle with a solid color. Clips to the
    /// canvas bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn fill_rect(
        &self,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        r: u8,
        g: u8,
        b: u8,
    ) -> crate::Result<()> {
        let packed = self.pack_color(r, g, b);
        let bytes = packed.to_le_bytes();
        let bpp = self.bytes_per_pixel as usize;
        let x_end = x.saturating_add(w).min(self.info.width);
        let y_end = y.saturating_add(h).min(self.info.height);
        if x >= x_end || y >= y_end {
            return Ok(());
        }
        // Build one row's worth of pixel bytes, then write it repeatedly —
        // far fewer syscalls than one VmoWrite per pixel.
        let row_pixels = (x_end - x) as usize;
        let row_bytes = row_pixels
            .checked_mul(bpp)
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        if row_bytes > RowBuf::CAP {
            return Err(crate::ErrorCode::InvalidArgs);
        }
        let mut row = alloc_row(row_bytes);
        for px in 0..row_pixels {
            row[px * bpp..px * bpp + bpp].copy_from_slice(&bytes[..bpp]);
        }
        for py in y..y_end {
            self.vmo.write(self.offset(x, py), &row)?;
        }
        Ok(())
    }

    /// Draw a single line of ASCII text using the kernel's built-in 8x8
    /// bitmap font, by delegating actual glyph rendering to the kernel
    /// (there is no local copy of the font in userspace — see
    /// [`Canvas::draw_text`]'s implementation note).
    ///
    /// Note: for the MVP, text is rendered by writing individual pixels
    /// via `set_pixel` using a small embedded copy of the same 8x8 font
    /// used by the kernel's own framebuffer driver, so this works
    /// entirely within the VMO the caller already owns (no new syscall
    /// needed) — see `crate::font8x8`.
    pub fn draw_text(&self, x: u32, y: u32, text: &str, r: u8, g: u8, b: u8) -> crate::Result<()> {
        self.draw_text_with_font(x, y, text, r, g, b, TextFont::Cozette6x13)
    }

    /// Draw text with an explicit built-in font. Cell width comes
    /// from [`TextFont::cell_w`], so callers do not hard-code
    /// per-font advance widths.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_text_with_font(
        &self,
        x: u32,
        y: u32,
        text: &str,
        r: u8,
        g: u8,
        b: u8,
        font: TextFont,
    ) -> crate::Result<()> {
        let cell_w = font.cell_w();
        let mut cx = x;
        for ch in text.chars() {
            if ch == '\n' {
                continue;
            }
            self.draw_glyph(cx, y, ch, r, g, b, font)?;
            cx += cell_w;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_glyph(
        &self,
        x: u32,
        y: u32,
        ch: char,
        r: u8,
        g: u8,
        b: u8,
        font: TextFont,
    ) -> crate::Result<()> {
        match font {
            TextFont::Cozette6x13 => self.draw_glyph_6x13(x, y, ch, r, g, b),
            TextFont::Tty8x16 | TextFont::Compact8x8 => {
                self.draw_glyph_8x8_scaled(x, y, ch, r, g, b, font)
            }
        }
    }

    fn draw_glyph_6x13(&self, x: u32, y: u32, ch: char, r: u8, g: u8, b: u8) -> crate::Result<()> {
        // Missing glyphs: draw a filled block as a visible placeholder,
        // matching the 8x8 fallback behaviour.
        let fallback: [u8; crate::font6x13::CELL_H] = [0b0011_1111; crate::font6x13::CELL_H];
        let bitmap = crate::font6x13::glyph(ch).unwrap_or(&fallback);
        for (row, bits) in bitmap.iter().enumerate() {
            let py = y + row as u32;
            if py >= self.info.height {
                break;
            }
            for col in 0..crate::font6x13::CELL_W as u32 {
                if bits & (1 << col) != 0 {
                    let px = x + col;
                    if px < self.info.width {
                        self.set_pixel(px, py, r, g, b)?;
                    }
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_glyph_8x8_scaled(
        &self,
        x: u32,
        y: u32,
        ch: char,
        r: u8,
        g: u8,
        b: u8,
        font: TextFont,
    ) -> crate::Result<()> {
        let bitmap = crate::font8x8::glyph(ch).unwrap_or(&[0xFF; 8]);
        let vertical_scale = match font {
            TextFont::Tty8x16 => 2,
            TextFont::Compact8x8 => 1,
            TextFont::Cozette6x13 => 1,
        };
        for (row, bits) in bitmap.iter().enumerate() {
            for scaled_row in 0..vertical_scale {
                let py = y + row as u32 * vertical_scale + scaled_row;
                if py >= self.info.height {
                    break;
                }
                for col in 0..8u32 {
                    if bits & (1 << col) != 0 {
                        let px = x + col;
                        if px < self.info.width {
                            self.set_pixel(px, py, r, g, b)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Replace bytes in the canvas backing VMO. Intended for software
    /// renderers such as Doom that already produce packed framebuffer pixels.
    pub fn write_bytes(&self, offset: u64, bytes: &[u8]) -> crate::Result<usize> {
        self.vmo.write(offset, bytes)
    }

    /// Blit this entire canvas onto the real framebuffer at `(0, 0)`.
    pub fn present(&self) -> crate::Result<()> {
        self.present_at(0, 0)
    }

    /// Blit this entire canvas onto the real framebuffer at `(dst_x, dst_y)`.
    pub fn present_at(&self, dst_x: u32, dst_y: u32) -> crate::Result<()> {
        self.present_region_at(0, 0, self.info.width, self.info.height, dst_x, dst_y)
    }

    /// Present a source rectangle at the same framebuffer coordinates.
    pub fn present_region(&self, x: u32, y: u32, width: u32, height: u32) -> crate::Result<()> {
        self.present_region_at(x, y, width, height, x, y)
    }

    /// Present a source rectangle at an explicit framebuffer destination.
    pub fn present_region_at(
        &self,
        src_x: u32,
        src_y: u32,
        width: u32,
        height: u32,
        dst_x: u32,
        dst_y: u32,
    ) -> crate::Result<()> {
        let src_x_end = src_x
            .checked_add(width)
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        let src_y_end = src_y
            .checked_add(height)
            .ok_or(crate::ErrorCode::InvalidArgs)?;
        if width == 0 || height == 0 || src_x_end > self.info.width || src_y_end > self.info.height
        {
            return Err(crate::ErrorCode::InvalidArgs);
        }
        let args = FramebufferBlitArgs {
            vmo: self.vmo.handle().raw(),
            vmo_offset: self.offset(src_x, src_y),
            src_width: width,
            src_height: height,
            src_stride: self.info.pitch,
            dst_x,
            dst_y,
        };
        // Capability-gated blit: `a1` is the `FrameDraw` handle stored
        // on this Canvas, `a2` points to the args. The kernel's
        // capability check runs before it dereferences `a2`, so a
        // stale or forged handle cannot leak information about the
        // caller's address space.
        let ret = raw::syscall2(
            Syscall::FramebufferBlit,
            self.cap as u64,
            &args as *const _ as u64,
        );
        raw::decode(ret)?;
        Ok(())
    }
}

/// Allocate a zeroed byte buffer without pulling in `alloc` crate-wide:
/// `libcanvas` is `no_std` and deliberately allocation-free everywhere
/// else, but `fill_rect` benefits enough from a scratch row buffer that
/// it's worth a small, self-contained bump allocation instead of forcing
/// every caller to size and pass one in. Backed by a fixed-size on-stack
/// array capped at a real display's plausible max row width, so there is
/// still no heap/global allocator dependency anywhere in this crate.
fn alloc_row(len: usize) -> RowBuf {
    RowBuf::new(len)
}

/// Fixed-capacity row buffer (see [`alloc_row`]). Supports displays up to
/// 8K-wide at 32bpp; anything larger truncates rather than overflowing.
struct RowBuf {
    data: [u8; Self::CAP],
    len: usize,
}

impl RowBuf {
    const CAP: usize = 8192 * 4;

    fn new(len: usize) -> Self {
        Self {
            data: [0; Self::CAP],
            len: len.min(Self::CAP),
        }
    }
}

impl core::ops::Deref for RowBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl core::ops::DerefMut for RowBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl core::ops::Index<core::ops::Range<usize>> for RowBuf {
    type Output = [u8];
    fn index(&self, range: core::ops::Range<usize>) -> &[u8] {
        &self.data[range]
    }
}

impl core::ops::IndexMut<core::ops::Range<usize>> for RowBuf {
    fn index_mut(&mut self, range: core::ops::Range<usize>) -> &mut [u8] {
        &mut self.data[range]
    }
}
