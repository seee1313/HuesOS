//! # HuesOS Framebuffer Driver
//!
//! A small, real framebuffer driver: owns the physical framebuffer memory
//! handed off by Limine, exposes safe pixel/rect/blit/text primitives to
//! kernel code, and backs the `FramebufferInfo`/`FramebufferBlit` syscalls
//! that let userspace draw *without ever being able to see or map the raw
//! framebuffer memory itself* — userspace only ever gets to `blit` a
//! bounds-checked rectangle copied out of its own VMO.
//!
//! Deliberately English/ASCII-only text rendering (see `font8x8`) — no
//! Unicode shaping, no non-Latin scripts. That's a scope decision, not an
//! oversight.

#![no_std]
#![warn(missing_docs)]

mod font8x8;

use huesos_abi::FramebufferInfo as AbiFramebufferInfo;
use spin::Mutex;

/// Raw framebuffer geometry as received from the bootloader.
#[derive(Clone, Copy)]
pub struct FramebufferConfig {
    /// Pointer to the start of framebuffer memory (kernel-accessible,
    /// e.g. via the HHDM — never handed to userspace).
    pub addr: *mut u8,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per scanline.
    pub pitch: u32,
    /// Bits per pixel.
    pub bpp: u16,
    /// Red channel bit count.
    pub red_mask_size: u8,
    /// Red channel LSB bit position.
    pub red_mask_shift: u8,
    /// Green channel bit count.
    pub green_mask_size: u8,
    /// Green channel LSB bit position.
    pub green_mask_shift: u8,
    /// Blue channel bit count.
    pub blue_mask_size: u8,
    /// Blue channel LSB bit position.
    pub blue_mask_shift: u8,
}

// Safety: the framebuffer pointer is a fixed, kernel-owned MMIO/HHDM
// region for the lifetime of the OS; we only ever access it through the
// Mutex below, which serializes all access.
unsafe impl Send for FramebufferConfig {}

struct Framebuffer {
    config: FramebufferConfig,
}

impl Framebuffer {
    #[inline]
    fn bytes_per_pixel(&self) -> usize {
        (self.config.bpp as usize).div_ceil(8)
    }

    #[inline]
    fn pack_color(&self, r: u8, g: u8, b: u8) -> u32 {
        let c = &self.config;
        let r = (r as u32) >> (8u8.saturating_sub(c.red_mask_size));
        let g = (g as u32) >> (8u8.saturating_sub(c.green_mask_size));
        let b = (b as u32) >> (8u8.saturating_sub(c.blue_mask_size));
        (r << c.red_mask_shift) | (g << c.green_mask_shift) | (b << c.blue_mask_shift)
    }

    /// Offset, in bytes, of pixel `(x, y)` from the start of the
    /// framebuffer. Caller must have already bounds-checked `x < width`
    /// and `y < height`.
    #[inline]
    fn offset_of(&self, x: u32, y: u32) -> usize {
        (y as usize) * (self.config.pitch as usize) + (x as usize) * self.bytes_per_pixel()
    }

    /// Write one pixel. No bounds checking — callers must guarantee
    /// `x < width && y < height` (all public entry points below do this).
    #[inline]
    unsafe fn put_pixel_raw(&mut self, x: u32, y: u32, packed: u32) {
        let off = self.offset_of(x, y);
        let bpp = self.bytes_per_pixel();
        unsafe {
            let ptr = self.config.addr.add(off);
            match bpp {
                4 => core::ptr::write_volatile(ptr as *mut u32, packed),
                3 => {
                    ptr.write_volatile(packed as u8);
                    ptr.add(1).write_volatile((packed >> 8) as u8);
                    ptr.add(2).write_volatile((packed >> 16) as u8);
                }
                2 => core::ptr::write_volatile(ptr as *mut u16, packed as u16),
                1 => ptr.write_volatile(packed as u8),
                _ => {}
            }
        }
    }

    fn set_pixel(&mut self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if x >= self.config.width || y >= self.config.height {
            return;
        }
        let packed = self.pack_color(r, g, b);
        unsafe {
            self.put_pixel_raw(x, y, packed);
        }
    }

    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        let packed = self.pack_color(r, g, b);
        let x_end = (x.saturating_add(w)).min(self.config.width);
        let y_end = (y.saturating_add(h)).min(self.config.height);
        for py in y..y_end {
            for px in x..x_end {
                unsafe {
                    self.put_pixel_raw(px, py, packed);
                }
            }
        }
    }

    fn draw_glyph(&mut self, x: u32, y: u32, ch: char, r: u8, g: u8, b: u8) {
        let bitmap = font8x8::glyph(ch).unwrap_or(
            // Unsupported character: draw a filled box as a visible
            // placeholder rather than silently drawing nothing.
            &[0xFF; 8],
        );
        let packed = self.pack_color(r, g, b);
        for (row, bits) in bitmap.iter().enumerate() {
            let py = y + row as u32;
            if py >= self.config.height {
                break;
            }
            for col in 0..8u32 {
                if bits & (1 << col) != 0 {
                    let px = x + col;
                    if px < self.config.width {
                        unsafe {
                            self.put_pixel_raw(px, py, packed);
                        }
                    }
                }
            }
        }
    }

    fn draw_text(&mut self, x: u32, y: u32, text: &str, r: u8, g: u8, b: u8) {
        let mut cx = x;
        for ch in text.chars() {
            if ch == '\n' {
                continue; // caller handles line breaks; single-line primitive
            }
            self.draw_glyph(cx, y, ch, r, g, b);
            cx += 8;
        }
    }

    /// Copy tightly-packed pixel bytes (`src`, in this framebuffer's own
    /// pixel format) into a rectangular region of the framebuffer, row by
    /// row, honoring the framebuffer's real pitch (which may include
    /// padding `src` doesn't have). Clips to the framebuffer's bounds.
    ///
    /// Returns the number of full rows actually copied (for diagnostics /
    /// testing), not that callers currently need it for correctness.
    fn blit(&mut self, dst_x: u32, dst_y: u32, src_w: u32, src_h: u32, src: &[u8]) -> u32 {
        let bpp = self.bytes_per_pixel();
        let src_pitch = src_w as usize * bpp;
        let copy_w = src_w.min(self.config.width.saturating_sub(dst_x));
        let copy_h = src_h.min(self.config.height.saturating_sub(dst_y));
        let copy_bytes = copy_w as usize * bpp;

        let mut rows_copied = 0u32;
        for row in 0..copy_h {
            let src_row_start = row as usize * src_pitch;
            let src_row_end = src_row_start + copy_bytes;
            if src_row_end > src.len() {
                break; // src buffer shorter than claimed; stop, don't panic/OOB read
            }
            let src_row = &src[src_row_start..src_row_end];
            let dst_off = self.offset_of(dst_x, dst_y + row);
            unsafe {
                let dst_ptr = self.config.addr.add(dst_off);
                core::ptr::copy_nonoverlapping(src_row.as_ptr(), dst_ptr, copy_bytes);
            }
            rows_copied += 1;
        }
        rows_copied
    }
}

static FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);
// Dedicated copy used only by the fatal path. Normal drawing never takes this
// lock, so a panic that interrupted framebuffer code cannot deadlock on the
// ordinary framebuffer mutex.
static PANIC_FRAMEBUFFER: Mutex<Option<FramebufferConfig>> = Mutex::new(None);

/// Initialize the framebuffer driver with geometry handed off by the
/// bootloader. A no-op (leaves the driver "unavailable") if `config` is
/// `None`, e.g. on a system Limine couldn't find a framebuffer for.
pub fn init(config: Option<FramebufferConfig>) {
    *PANIC_FRAMEBUFFER.lock() = config;
    *FRAMEBUFFER.lock() = config.map(|config| Framebuffer { config });
}

struct PanicConsole {
    framebuffer: Framebuffer,
    x: u32,
    y: u32,
}

impl core::fmt::Write for PanicConsole {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for ch in text.chars() {
            if ch == '\n' {
                self.x = 16;
                self.y = self.y.saturating_add(10);
                continue;
            }
            if self.x.saturating_add(8) > self.framebuffer.config.width {
                self.x = 16;
                self.y = self.y.saturating_add(10);
            }
            if self.y.saturating_add(8) > self.framebuffer.config.height {
                break;
            }
            self.framebuffer.draw_glyph(self.x, self.y, ch, 255, 255, 255);
            self.x = self.x.saturating_add(8);
        }
        Ok(())
    }
}

/// Replace the screen with the non-allocating fatal panic console.
///
/// The renderer uses a dedicated framebuffer configuration copy and therefore
/// does not acquire the normal drawing lock. It is intended to be called once
/// by the CPU that won the kernel panic-owner election.
pub fn panic_render(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write;

    let Some(config) = *PANIC_FRAMEBUFFER.lock() else {
        return;
    };
    let mut console = PanicConsole {
        framebuffer: Framebuffer { config },
        x: 16,
        y: 16,
    };
    let width = console.framebuffer.config.width;
    let height = console.framebuffer.config.height;
    console
        .framebuffer
        .fill_rect(0, 0, width, height, 150, 0, 0);
    let _ = console.write_str("HuesOS KERNEL PANIC\n\n");
    let _ = console.write_fmt(args);
}

/// Display the final orderly-shutdown screen without allocating.
pub fn shutdown_render() {
    let Some(config) = *PANIC_FRAMEBUFFER.lock() else {
        return;
    };
    let mut framebuffer = Framebuffer { config };
    let width = framebuffer.config.width;
    let height = framebuffer.config.height;
    framebuffer.fill_rect(0, 0, width, height, 5, 10, 20);

    let title = "HuesOS has been safely halted";
    let message = "It is now safe to power off your computer.";
    let title_x = width.saturating_sub(title.len() as u32 * 8) / 2;
    let message_x = width.saturating_sub(message.len() as u32 * 8) / 2;
    let center_y = height.saturating_sub(24) / 2;
    framebuffer.draw_text(title_x, center_y, title, 120, 210, 255);
    framebuffer.draw_text(message_x, center_y + 20, message, 255, 255, 255);
}

/// Whether a framebuffer is available at all.
pub fn is_available() -> bool {
    FRAMEBUFFER.lock().is_some()
}

/// Query framebuffer geometry in the ABI's wire format, for the
/// `FramebufferInfo` syscall.
pub fn info() -> Option<AbiFramebufferInfo> {
    let fb = FRAMEBUFFER.lock();
    fb.as_ref().map(|fb| AbiFramebufferInfo {
        width: fb.config.width,
        height: fb.config.height,
        pitch: fb.config.pitch,
        bpp: fb.config.bpp,
        red_mask_size: fb.config.red_mask_size,
        red_mask_shift: fb.config.red_mask_shift,
        green_mask_size: fb.config.green_mask_size,
        green_mask_shift: fb.config.green_mask_shift,
        blue_mask_size: fb.config.blue_mask_size,
        blue_mask_shift: fb.config.blue_mask_shift,
    })
}

/// Set a single pixel to an RGB color. Out-of-bounds coordinates are
/// silently clipped (no-op), matching the behavior of `fill_rect`/`blit`.
pub fn set_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) {
    if let Some(fb) = FRAMEBUFFER.lock().as_mut() {
        fb.set_pixel(x, y, r, g, b);
    }
}

/// Fill an axis-aligned rectangle with a solid RGB color. Clips to the
/// framebuffer's bounds; a rectangle entirely off-screen is a silent no-op.
pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
    if let Some(fb) = FRAMEBUFFER.lock().as_mut() {
        fb.fill_rect(x, y, w, h, r, g, b);
    }
}

/// Draw a single line of ASCII text at `(x, y)` (top-left of the first
/// glyph) using the built-in 8x8 bitmap font. Characters outside the
/// printable ASCII range are rendered as a solid placeholder box.
pub fn draw_text(x: u32, y: u32, text: &str, r: u8, g: u8, b: u8) {
    if let Some(fb) = FRAMEBUFFER.lock().as_mut() {
        fb.draw_text(x, y, text, r, g, b);
    }
}

/// Copy tightly-packed pixel data (in the framebuffer's own native pixel
/// format — see [`info`] for the format userspace must produce) into a
/// rectangular region of the real framebuffer, clipped to its bounds.
///
/// This is the *only* function that writes attacker/userspace-controlled
/// pixel data into video memory, so every one of its inputs is treated as
/// untrusted: `src` is only ever read up to its actual length (never
/// beyond, regardless of what `src_w`/`src_h` claim), and the destination
/// rectangle is clipped to the real framebuffer bounds before any write
/// happens.
pub fn blit(dst_x: u32, dst_y: u32, src_w: u32, src_h: u32, src: &[u8]) -> Result<(), ()> {
    let mut guard = FRAMEBUFFER.lock();
    let Some(fb) = guard.as_mut() else {
        return Err(());
    };
    fb.blit(dst_x, dst_y, src_w, src_h, src);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    static GLOBAL_FB_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // Tests drive `Framebuffer` directly against a plain heap buffer
    // standing in for MMIO/framebuffer memory — the struct's methods never
    // assume anything about the backing memory beyond "a valid pointer",
    // so this exercises exactly the same code path real video memory
    // would, just without needing a real device or the global singleton.
    fn make_test_fb(width: u32, height: u32, pitch: u32) -> (Vec<u8>, Framebuffer) {
        let mut backing = vec![0u8; (pitch as usize) * (height as usize)];
        let config = FramebufferConfig {
            addr: backing.as_mut_ptr(),
            width,
            height,
            pitch,
            bpp: 32,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
        };
        (backing, Framebuffer { config })
    }

    fn read_pixel(backing: &[u8], fb: &Framebuffer, x: u32, y: u32) -> (u8, u8, u8) {
        let off = fb.offset_of(x, y);
        let word = u32::from_le_bytes(backing[off..off + 4].try_into().unwrap());
        let r = ((word >> fb.config.red_mask_shift) & 0xFF) as u8;
        let g = ((word >> fb.config.green_mask_shift) & 0xFF) as u8;
        let b = ((word >> fb.config.blue_mask_shift) & 0xFF) as u8;
        (r, g, b)
    }

    #[test]
    fn set_pixel_writes_expected_color_and_position() {
        let (backing, mut fb) = make_test_fb(16, 16, 16 * 4);
        fb.set_pixel(3, 5, 0xAA, 0xBB, 0xCC);
        assert_eq!(read_pixel(&backing, &fb, 3, 5), (0xAA, 0xBB, 0xCC));
        // Neighboring pixels must remain untouched.
        assert_eq!(read_pixel(&backing, &fb, 2, 5), (0, 0, 0));
        assert_eq!(read_pixel(&backing, &fb, 3, 4), (0, 0, 0));
    }

    #[test]
    fn set_pixel_out_of_bounds_is_a_silent_noop_not_a_panic() {
        let (_backing, mut fb) = make_test_fb(16, 16, 16 * 4);
        // Must not panic (would be an out-of-bounds MMIO write on real
        // hardware, i.e. a kernel crash) for any of these.
        fb.set_pixel(1000, 5, 255, 255, 255);
        fb.set_pixel(5, 1000, 255, 255, 255);
        fb.set_pixel(u32::MAX, u32::MAX, 255, 255, 255);
    }

    #[test]
    fn fill_rect_clips_to_framebuffer_bounds() {
        let (backing, mut fb) = make_test_fb(8, 8, 8 * 4);
        // Rectangle partially off both edges; must not panic and must only
        // paint the on-screen portion.
        fb.fill_rect(5, 5, 100, 100, 10, 20, 30);
        assert_eq!(read_pixel(&backing, &fb, 5, 5), (10, 20, 30));
        assert_eq!(read_pixel(&backing, &fb, 7, 7), (10, 20, 30));
        assert_eq!(read_pixel(&backing, &fb, 4, 4), (0, 0, 0)); // just outside the rect
    }

    #[test]
    fn blit_copies_pixels_honoring_dst_pitch_not_src_pitch() {
        // Framebuffer pitch is deliberately larger than width*bpp (padding),
        // to make sure blit uses the *framebuffer's* pitch for destination
        // rows and the source's tightly-packed layout for source rows —
        // mixing these up is an easy, screen-gets-diagonally-smeared bug.
        let (backing, mut fb) = make_test_fb(4, 4, 4 * 4 + 16 /* extra padding */);

        // Tightly packed 2x2 source image, red/green/blue/white.
        let px = |r: u8, g: u8, b: u8| -> [u8; 4] {
            let word = ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
            word.to_le_bytes()
        };
        let mut src = alloc_vec();
        src.extend_from_slice(&px(255, 0, 0));
        src.extend_from_slice(&px(0, 255, 0));
        src.extend_from_slice(&px(0, 0, 255));
        src.extend_from_slice(&px(255, 255, 255));

        let rows = fb.blit(1, 1, 2, 2, &src);
        assert_eq!(rows, 2);
        assert_eq!(read_pixel(&backing, &fb, 1, 1), (255, 0, 0));
        assert_eq!(read_pixel(&backing, &fb, 2, 1), (0, 255, 0));
        assert_eq!(read_pixel(&backing, &fb, 1, 2), (0, 0, 255));
        assert_eq!(read_pixel(&backing, &fb, 2, 2), (255, 255, 255));
    }

    #[test]
    fn blit_with_undersized_src_buffer_stops_cleanly_without_oob_read() {
        // A malicious or buggy caller claims a 10x10 source image but only
        // actually provides a few bytes. This must not panic or read past
        // the end of `src` — it must just stop copying early.
        let (_backing, mut fb) = make_test_fb(16, 16, 16 * 4);
        let src = vec![1u8, 2, 3, 4]; // one pixel's worth, claiming far more
        let rows = fb.blit(0, 0, 10, 10, &src);
        assert_eq!(rows, 0, "must not report rows copied from an undersized buffer");
    }

    #[test]
    fn glyph_lookup_covers_ascii_and_rejects_out_of_range() {
        assert!(font8x8::glyph('A').is_some());
        assert!(font8x8::glyph('~').is_some());
        assert!(font8x8::glyph(' ').is_some());
        assert!(font8x8::glyph('\u{1F600}').is_none(), "non-ASCII must return None");
    }

    #[test]
    fn panic_renderer_uses_red_background_and_white_text() {
        let _serial = GLOBAL_FB_TEST_LOCK.lock().unwrap();
        let mut backing = vec![0u8; 320 * 200 * 4];
        init(Some(FramebufferConfig {
            addr: backing.as_mut_ptr(),
            width: 320,
            height: 200,
            pitch: 320 * 4,
            bpp: 32,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
        }));
        panic_render(format_args!("CPU: 0\nException: TEST\n"));

        let mut red = 0usize;
        let mut white = 0usize;
        for pixel in backing.chunks_exact(4) {
            match (pixel[2], pixel[1], pixel[0]) {
                (150, 0, 0) => red += 1,
                (255, 255, 255) => white += 1,
                _ => {}
            }
        }
        assert!(red > 320 * 200 / 2);
        assert!(white > 100);
    }

    #[test]
    fn shutdown_renderer_uses_dark_background_and_visible_text() {
        let _serial = GLOBAL_FB_TEST_LOCK.lock().unwrap();
        let mut backing = vec![0u8; 640 * 240 * 4];
        init(Some(FramebufferConfig {
            addr: backing.as_mut_ptr(),
            width: 640,
            height: 240,
            pitch: 640 * 4,
            bpp: 32,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
        }));
        shutdown_render();

        let dark = backing
            .chunks_exact(4)
            .filter(|pixel| (pixel[2], pixel[1], pixel[0]) == (5, 10, 20))
            .count();
        let bright = backing
            .chunks_exact(4)
            .filter(|pixel| pixel[2] > 100 && pixel[1] > 180 && pixel[0] > 200)
            .count();
        assert!(dark > 640 * 240 / 2);
        assert!(bright > 100);
    }

    fn alloc_vec() -> Vec<u8> {
        Vec::new()
    }
}
