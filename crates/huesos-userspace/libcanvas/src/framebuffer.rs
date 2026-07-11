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

use crate::raw;
use crate::vmo::Vmo;
use huesos_abi::{FramebufferBlitArgs, FramebufferInfo, Syscall};

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
    /// TTY-style 8x16 font (default). Each source bitmap row is expanded to
    /// two scanlines, giving classic VGA console proportions.
    Tty8x16,
    /// Original compact 8x8 HuesOS font.
    Compact8x8,
}

/// An off-screen drawing surface, backed by a VMO, matching the real
/// framebuffer's pixel format. Draw into it with `set_pixel`/`fill_rect`/
/// `draw_text`, then call [`Canvas::present`] to blit it to the screen.
pub struct Canvas {
    vmo: Vmo,
    info: FramebufferInfo,
    bytes_per_pixel: u32,
}

impl Canvas {
    /// Create a canvas the same size as the real framebuffer.
    pub fn new_fullscreen() -> crate::Result<Self> {
        let info = info()?;
        Self::new(info.width, info.height)
    }

    /// Create a canvas of an arbitrary size (e.g. smaller than the full
    /// screen, to later blit at some offset via [`Canvas::present_at`]).
    pub fn new(width: u32, height: u32) -> crate::Result<Self> {
        let info = info()?;
        let bytes_per_pixel = (info.bpp as u32).div_ceil(8);
        let size = width as u64 * height as u64 * bytes_per_pixel as u64;
        let vmo = Vmo::create(size)?;
        Ok(Self {
            vmo,
            info: FramebufferInfo {
                width,
                height,
                pitch: width * bytes_per_pixel, // tightly packed, no padding
                ..info
            },
            bytes_per_pixel,
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

    /// Rasterize text directly into a packed shadow buffer without issuing
    /// per-pixel VMO writes.
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
                        shadow[offset..offset + 4].copy_from_slice(&pixel);
                    }
                }
            }
            cursor_x = cursor_x.saturating_add(8);
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
        let mut row = alloc_row(row_pixels * bpp);
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
        self.draw_text_with_font(x, y, text, r, g, b, TextFont::Tty8x16)
    }

    /// Draw text with an explicit built-in font. The original HuesOS font is
    /// retained as [`TextFont::Compact8x8`].
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
        let mut cx = x;
        for ch in text.chars() {
            if ch == '\n' {
                continue;
            }
            self.draw_glyph(cx, y, ch, r, g, b, font)?;
            cx += 8;
        }
        Ok(())
    }

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
        let bitmap = crate::font8x8::glyph(ch).unwrap_or(&[0xFF; 8]);
        let vertical_scale = match font {
            TextFont::Tty8x16 => 2,
            TextFont::Compact8x8 => 1,
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
        let args = FramebufferBlitArgs {
            vmo: self.vmo.handle().raw(),
            vmo_offset: 0,
            src_width: self.info.width,
            src_height: self.info.height,
            dst_x,
            dst_y,
        };
        let ret = raw::syscall1(Syscall::FramebufferBlit, &args as *const _ as u64);
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
