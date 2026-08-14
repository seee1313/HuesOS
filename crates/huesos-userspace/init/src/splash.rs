//! Boot splash renderer.
//!
//! Owns the framebuffer while init brings services up. All geometry and
//! colour arithmetic lives in `huesos-bootux` so it can be unit-tested
//! on the host; this module is the part that must touch pixels.
//!
//! ## Buffering
//!
//! Double buffering is inherent here rather than hand-rolled. A
//! `Canvas` owns an ordinary VMO that userspace draws into; nothing
//! reaches the screen until `present` asks the kernel to blit that VMO
//! onto real video memory. A half-drawn frame is therefore never
//! visible, and userspace never holds a mapping of the framebuffer.
//!
//! The VMO *is* the back buffer, so this module keeps no shadow copy of
//! its own. An earlier version did, mirroring the terminal, which cost
//! a 16 MiB `static` and two `unsafe` blocks to share it — real budget
//! spent to save syscalls on a surface that repaints a few times a
//! second during boot. `fill_rect` already batches a whole row per
//! `VmoWrite`, which is enough at this rate, and dropping the shadow
//! took this file's unsafe surface to zero.
//!
//! What still matters is the *blit*, so each frame presents only the
//! rectangles that changed: the bar band and the spinner box. The
//! gradient behind them is painted once and re-presented only where it
//! was disturbed.

use huesos_bootux::config::{InitConfig, Rgb};
use huesos_bootux::paint::{
    self, bar_fill_width, centre_text_x, gradient_at, spinner_arm_alpha, Layout, SPINNER_ARMS,
};
use huesos_bootux::progress::{BootProgress, StageState, SCALE};
use libcanvas::framebuffer::{Canvas, TextFont};

const FONT: TextFont = TextFont::Cozette6x13;
const CELL_W: u32 = 6;
const CELL_H: u32 = 13;

const TITLE: &str = "HuesOS";

const COLOR_TITLE: Rgb = Rgb::new(228, 238, 255);
const COLOR_LABEL: Rgb = Rgb::new(150, 170, 205);
const COLOR_TRACK: Rgb = Rgb::new(30, 38, 62);
const COLOR_FAIL: Rgb = Rgb::new(255, 96, 96);

/// The splash surface.
pub struct Splash {
    canvas: Canvas,
    layout: Layout,
    top: Rgb,
    bottom: Rgb,
    accent: Rgb,
    spinner: bool,
    frame: u32,
    last_permille: u32,
    /// Set once the static background has been painted.
    background_ready: bool,
}

impl Splash {
    /// Create the splash and paint its static background.
    ///
    /// Returns `None` when there is no framebuffer (serial-only boot).
    /// That is an ordinary condition, not an error: init stays
    /// UART-only and the caller enables the text console instead.
    pub fn new(config: &InitConfig) -> Option<Self> {
        let canvas = Canvas::new_fullscreen().ok()?;
        let layout = paint::layout(canvas.width(), canvas.height(), CELL_H, CELL_H);
        let mut splash = Self {
            canvas,
            layout,
            top: config.top,
            bottom: config.bottom,
            accent: config.accent,
            spinner: config.spinner,
            frame: 0,
            last_permille: u32::MAX,
            background_ready: false,
        };
        splash.paint_background();
        Some(splash)
    }

    /// Paint the gradient and title, then present the whole frame once.
    fn paint_background(&mut self) {
        let width = self.canvas.width();
        let height = self.canvas.height();
        for y in 0..height {
            let color = gradient_at(self.top, self.bottom, y, height);
            if self
                .canvas
                .fill_rect(0, y, width, 1, color.r, color.g, color.b)
                .is_err()
            {
                return;
            }
        }
        let title_x = centre_text_x(self.layout.title_x, TITLE.len(), CELL_W, width);
        let _ = self.canvas.draw_text_with_font(
            title_x,
            self.layout.title_y,
            TITLE,
            COLOR_TITLE.r,
            COLOR_TITLE.g,
            COLOR_TITLE.b,
            FONT,
        );
        self.background_ready = self.canvas.present().is_ok();
    }

    /// Redraw the animated parts: spinner, bar, and status label.
    ///
    /// Safe to call on every poll iteration; it returns early when
    /// nothing that affects pixels has changed.
    pub fn render(&mut self, progress: &mut BootProgress) {
        if !self.background_ready {
            return;
        }
        let permille = progress.permille();
        let changed = permille != self.last_permille;
        if !changed && !self.spinner {
            return;
        }
        self.last_permille = permille;
        self.frame = self.frame.wrapping_add(1);

        let failed = progress.any_failed();
        let label = progress.current_label();
        let layout = self.layout;

        self.repaint_band(layout.dirty_y, layout.dirty_h);
        self.draw_bar(permille, failed);
        self.draw_label(label, failed);
        let _ = self
            .canvas
            .present_region(0, layout.dirty_y, layout.width, layout.dirty_h);

        if self.spinner {
            self.draw_spinner(failed);
        }
    }

    /// Restore the gradient across a horizontal band, erasing the
    /// previous frame's bar and label without a full-screen clear.
    fn repaint_band(&self, y: u32, height: u32) {
        let bottom = (y + height).min(self.layout.height);
        for row in y..bottom {
            let color = gradient_at(self.top, self.bottom, row, self.layout.height);
            let _ = self
                .canvas
                .fill_rect(0, row, self.layout.width, 1, color.r, color.g, color.b);
        }
    }

    fn draw_bar(&self, permille: u32, failed: bool) {
        let layout = self.layout;
        let _ = self.canvas.fill_rect(
            layout.bar_x,
            layout.bar_y,
            layout.bar_w,
            layout.bar_h,
            COLOR_TRACK.r,
            COLOR_TRACK.g,
            COLOR_TRACK.b,
        );
        let fill = bar_fill_width(layout.bar_w, permille);
        if fill == 0 {
            return;
        }
        let color = if failed { COLOR_FAIL } else { self.accent };
        let _ = self.canvas.fill_rect(
            layout.bar_x,
            layout.bar_y,
            fill,
            layout.bar_h,
            color.r,
            color.g,
            color.b,
        );
        // A brighter leading edge gives the bar a sense of motion even
        // when a slow stage holds it still for a while.
        if fill >= 3 && permille < SCALE {
            let tip = paint::blend(Rgb::new(255, 255, 255), color, 90);
            let _ = self.canvas.fill_rect(
                layout.bar_x + fill - 2,
                layout.bar_y,
                2,
                layout.bar_h,
                tip.r,
                tip.g,
                tip.b,
            );
        }
    }

    fn draw_label(&self, label: &str, failed: bool) {
        let color = if failed { COLOR_FAIL } else { COLOR_LABEL };
        let x = centre_text_x(self.layout.label_x, label.len(), CELL_W, self.layout.width);
        let _ = self.canvas.draw_text_with_font(
            x,
            self.layout.label_y,
            label,
            color.r,
            color.g,
            color.b,
            FONT,
        );
    }

    /// A ring of square arms with a comet-tail brightness falloff.
    ///
    /// Squares rather than arcs: a filled rect per arm is a handful of
    /// row writes, while a rasterised arc would need per-pixel trig
    /// that init has no business doing during boot.
    fn draw_spinner(&self, failed: bool) {
        let layout = self.layout;
        let base = if failed { COLOR_FAIL } else { self.accent };
        let arm_size = (layout.spinner_r / 4).max(2);
        for arm in 0..SPINNER_ARMS {
            let (dx, dy) = ring_offset(arm, layout.spinner_r);
            let x = (layout.spinner_cx as i32 + dx - arm_size as i32 / 2).max(0) as u32;
            let y = (layout.spinner_cy as i32 + dy - arm_size as i32 / 2).max(0) as u32;
            if x + arm_size >= layout.width || y + arm_size >= layout.height {
                continue;
            }
            let alpha = spinner_arm_alpha(arm, self.frame);
            // Blend against the gradient behind the arm so a dim arm
            // fades into the background instead of leaving a dark box.
            let backdrop = gradient_at(self.top, self.bottom, y, layout.height);
            let color = paint::blend(base, backdrop, alpha);
            let _ = self
                .canvas
                .fill_rect(x, y, arm_size, arm_size, color.r, color.g, color.b);
        }
        let side = layout.spinner_r * 2 + arm_size + 4;
        let x = layout
            .spinner_cx
            .saturating_sub(layout.spinner_r + arm_size);
        let y = layout
            .spinner_cy
            .saturating_sub(layout.spinner_r + arm_size);
        let width = side.min(layout.width.saturating_sub(x));
        let height = side.min(layout.height.saturating_sub(y));
        if width > 0 && height > 0 {
            let _ = self.canvas.present_region(x, y, width, height);
        }
    }

    /// Draw the diagnostic banner shown when a stage fails.
    ///
    /// This ignores `log.screen`: a boot that has already gone wrong
    /// must say so on the surface the operator is actually looking at.
    pub fn render_failure(&mut self, progress: &BootProgress) {
        if !self.background_ready {
            return;
        }
        let Some(failed) = progress.first_failure() else {
            return;
        };
        let layout = self.layout;
        let y = layout.label_y + CELL_H * 2;
        if y + CELL_H >= layout.height {
            return;
        }
        self.repaint_band(y, CELL_H + 2);
        let mut line = [0u8; 96];
        let written = format_failure(&mut line, failed.id.as_bytes());
        if let Ok(text) = core::str::from_utf8(&line[..written]) {
            let x = centre_text_x(layout.label_x, written, CELL_W, layout.width);
            let _ = self.canvas.draw_text_with_font(
                x,
                y,
                text,
                COLOR_FAIL.r,
                COLOR_FAIL.g,
                COLOR_FAIL.b,
                FONT,
            );
        }
        let _ = self.canvas.present_region(0, y, layout.width, CELL_H + 2);
    }

    /// Paint the final frame, forcing a redraw even if the bar value is
    /// unchanged.
    pub fn finish(&mut self, progress: &mut BootProgress) {
        self.last_permille = u32::MAX;
        self.render(progress);
        if progress.any_failed() {
            self.render_failure(progress);
        }
    }

    pub fn width(&self) -> u32 {
        self.canvas.width()
    }

    pub fn height(&self) -> u32 {
        self.canvas.height()
    }
}

/// Integer ring coordinates for spinner arm `arm`.
///
/// A twelve-entry table instead of trig: exact, branch-free, and it
/// keeps the boot path free of any float or libm dependency. Values are
/// cos/sin scaled by 1024.
fn ring_offset(arm: u32, radius: u32) -> (i32, i32) {
    const COS: [i32; 12] = [
        1024, 887, 512, 0, -512, -887, -1024, -887, -512, 0, 512, 887,
    ];
    const SIN: [i32; 12] = [
        0, 512, 887, 1024, 887, 512, 0, -512, -887, -1024, -887, -512,
    ];
    let index = (arm % SPINNER_ARMS) as usize;
    let radius = radius as i32;
    (COS[index] * radius / 1024, SIN[index] * radius / 1024)
}

/// Render `"stage '<id>' did not report ready"` into `out`, returning
/// the byte count written.
fn format_failure(out: &mut [u8], id: &[u8]) -> usize {
    let mut written = 0;
    let mut push = |bytes: &[u8], written: &mut usize| {
        for byte in bytes {
            if *written < out.len() {
                out[*written] = *byte;
                *written += 1;
            }
        }
    };
    push(b"stage '", &mut written);
    push(id, &mut written);
    push(b"' did not report ready", &mut written);
    written
}

/// Stage indicator glyph for the log-mode summary.
pub fn state_marker(state: StageState) -> &'static str {
    match state {
        StageState::Pending => "  ",
        StageState::Running => "..",
        StageState::Done => "ok",
        StageState::Failed => "!!",
        StageState::Degraded => "~~",
        StageState::Skipped => "--",
    }
}
