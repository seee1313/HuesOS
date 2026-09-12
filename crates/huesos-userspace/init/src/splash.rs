//! Boot splash renderer.
//!
//! Owns the framebuffer while init brings services up. All geometry and
//! colour arithmetic lives in `huesos-bootux` so it can be unit-tested
//! on the host; this module is the part that must touch pixels.
//!
//! ## Look
//!
//! A systemd-style boot console: a small "HuesOS <version>" brand line
//! in the top-left corner, then one status line per service —
//! `Starting X...` while a stage runs, `[  OK  ] Started X.` when it
//! settles, `[WARN  ]` for a degraded result, `[FAILED]` for a failure,
//! `[SKIP  ]` for a deliberately unrun stage — and, once every stage has
//! reported, the two closing lines `Reached target HuesOS Shell.` and
//! `Startup complete.`. A thin overall progress bar sits in the bottom
//! margin.
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
//! What still matters is the *blit*, so the frame is split into two
//! independently presented bands: the status list (redrawn only when a
//! stage *state* changes — the few times a boot actually moves) and the
//! progress bar (redrawn when the permille changes). The gradient and
//! the brand line are painted once and re-presented only where they
//! were disturbed.

use huesos_bootux::config::{InitConfig, InlineStr, Rgb, MAX_VERSION};
use huesos_bootux::paint::{
    self, bar_fill_width, gradient_at, line_prefix, line_suffix, stage_tag, tag_color, tag_text,
    Layout, COLOR_FAIL, COLOR_MSG, TAG_LEN,
};
use huesos_bootux::progress::{BootProgress, Stage, StageState, SCALE};
use libcanvas::framebuffer::{Canvas, TextFont};

const FONT: TextFont = TextFont::Cozette6x13;
const CELL_W: u32 = 6;
const CELL_H: u32 = 13;

const TITLE: &str = "HuesOS";

const COLOR_TITLE: Rgb = Rgb::new(228, 238, 255);
const COLOR_VERSION: Rgb = Rgb::new(120, 135, 170);
const COLOR_TRACK: Rgb = Rgb::new(30, 38, 62);

/// The splash surface.
pub struct Splash {
    canvas: Canvas,
    layout: Layout,
    top: Rgb,
    bottom: Rgb,
    accent: Rgb,
    /// Legacy config key (`splash.spinner`). The systemd-style status
    /// list replaced the dot ring; the key is still parsed for config
    /// compatibility and ignored by the renderer, so the field is kept
    /// only to document that the parser saw it.
    #[allow(dead_code)]
    spinner: bool,
    last_permille: u32,
    /// Bit-packed stage states plus the settled flag; the list band is
    /// redrawn only when this changes.
    last_signature: u64,
    /// Version for the brand line. Resolved from config in
    /// [`Splash::new`], falling back to the build's own package version
    /// when the operator did not override it.
    version: InlineStr<MAX_VERSION>,
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
        let layout = paint::layout(
            canvas.width(),
            canvas.height(),
            CELL_H,
            config.stages().len(),
        );
        // The splash carries the image's own version unless the operator
        // overrode it in config; an empty configured version is the
        // "not set" marker, not a request for a blank brand line.
        let version = if config.version.is_empty() {
            InlineStr::from_bytes(env!("CARGO_PKG_VERSION").as_bytes())
        } else {
            config.version
        };
        let mut splash = Self {
            canvas,
            layout,
            top: config.top,
            bottom: config.bottom,
            accent: config.accent,
            spinner: config.spinner,
            last_permille: u32::MAX,
            last_signature: u64::MAX,
            version,
            background_ready: false,
        };
        splash.paint_background();
        Some(splash)
    }

    /// Paint the gradient and the brand line, then present the whole
    /// frame once. All of it is static for the boot's lifetime, so it
    /// is uploaded exactly once and never touched again.
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
        // Brand line, top-left: product name in title colour, version
        // dimmed so it reads as metadata rather than a second logo.
        let layout = self.layout;
        let _ = self.canvas.draw_text_with_font(
            layout.brand_x,
            layout.brand_y,
            TITLE,
            COLOR_TITLE.r,
            COLOR_TITLE.g,
            COLOR_TITLE.b,
            FONT,
        );
        let version_x = layout.brand_x + (TITLE.len() as u32 + 1) * CELL_W;
        let _ = self.canvas.draw_text_with_font(
            version_x,
            layout.brand_y,
            self.version.as_str(),
            COLOR_VERSION.r,
            COLOR_VERSION.g,
            COLOR_VERSION.b,
            FONT,
        );
        self.background_ready = self.canvas.present().is_ok();
    }

    /// Redraw whatever changed: the status list and/or the progress bar.
    ///
    /// Safe to call on every poll iteration; it returns early when
    /// neither band changed. The list signature changes only on stage
    /// state transitions, so a long "Starting ..." phase re-uploads the
    /// list once and then just moves the bar.
    pub fn render(&mut self, progress: &mut BootProgress) {
        if !self.background_ready {
            return;
        }
        let permille = progress.permille();
        let bar_changed = permille != self.last_permille;
        let signature = list_signature(progress);
        let list_changed = signature != self.last_signature;
        if !bar_changed && !list_changed {
            return;
        }

        if bar_changed {
            self.last_permille = permille;
            self.draw_bar_band(permille, progress.any_failed());
        }
        if list_changed {
            self.last_signature = signature;
            self.draw_list(progress);
        }
    }

    /// Restore the gradient across a horizontal band, erasing the
    /// previous frame's content without a full-screen clear.
    fn repaint_band(&self, y: u32, height: u32) {
        let bottom = (y + height).min(self.layout.height);
        for row in y..bottom {
            let color = gradient_at(self.top, self.bottom, row, self.layout.height);
            let _ = self
                .canvas
                .fill_rect(0, row, self.layout.width, 1, color.r, color.g, color.b);
        }
    }

    /// Redraw the progress bar in its band and present the band.
    fn draw_bar_band(&mut self, permille: u32, failed: bool) {
        let layout = self.layout;
        let band_y = layout.bar_y.saturating_sub(2);
        let band_h = (layout.bar_h + 6).min(layout.height.saturating_sub(band_y));
        self.repaint_band(band_y, band_h);
        self.draw_bar(permille, failed);
        let _ = self.canvas.present_region(0, band_y, layout.width, band_h);
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

    /// Redraw the whole status list and present its band.
    fn draw_list(&self, progress: &BootProgress) {
        let layout = self.layout;
        self.repaint_band(layout.list_y, layout.list_h);

        let mut row = 0u32;
        for stage in progress.stages() {
            // systemd shows a unit only once it has started: Pending
            // stages have no line at all.
            if stage.state == StageState::Pending {
                continue;
            }
            let mut message = [0u8; 80];
            let written = format_line(
                &mut message,
                line_prefix(stage.state),
                unit_name(stage),
                line_suffix(stage.state),
            );
            let text = core::str::from_utf8(&message[..written]).unwrap_or("");
            self.draw_line(
                layout.list_y + row * layout.line_h,
                stage_tag(stage.state),
                text,
            );
            row += 1;
        }

        // Every stage has reported: close the boot with the target
        // lines, systemd-style.
        if progress.all_settled() {
            let failed = progress.any_failed();
            let degraded = progress.any_degraded();
            let (tag, message) = if failed {
                (paint::StageTag::Failed, "Failed to reach HuesOS Shell.")
            } else if degraded {
                (
                    paint::StageTag::Warn,
                    "Reached target HuesOS Shell (degraded).",
                )
            } else {
                (paint::StageTag::Ok, "Reached target HuesOS Shell.")
            };
            self.draw_line(layout.list_y + row * layout.line_h, tag, message);
            self.draw_line(
                layout.list_y + (row + 1) * layout.line_h,
                paint::StageTag::Blank,
                "Startup complete.",
            );
        }

        let bottom = (layout.list_y + layout.list_h).min(layout.height);
        let _ = self.canvas.present_region(
            0,
            layout.list_y,
            layout.width,
            bottom.saturating_sub(layout.list_y),
        );
    }

    /// One status line: fixed-width tag column, then the message.
    fn draw_line(&self, y: u32, tag: paint::StageTag, message: &str) {
        let layout = self.layout;
        let tag_color = tag_color(tag);
        let _ = self.canvas.draw_text_with_font(
            layout.list_x,
            y,
            tag_text(tag),
            tag_color.r,
            tag_color.g,
            tag_color.b,
            FONT,
        );
        if !message.is_empty() {
            let message_x = layout.list_x + TAG_LEN as u32 * CELL_W;
            let _ = self.canvas.draw_text_with_font(
                message_x,
                y,
                message,
                COLOR_MSG.r,
                COLOR_MSG.g,
                COLOR_MSG.b,
                FONT,
            );
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
        // Just below the status list, inside the message column.
        let y = layout.list_y + layout.list_h + 4;
        if y + CELL_H >= layout.bar_y {
            return;
        }
        self.repaint_band(y, CELL_H + 2);
        let mut line = [0u8; 96];
        let written = format_failure(&mut line, failed.id.as_bytes());
        if let Ok(text) = core::str::from_utf8(&line[..written]) {
            let x = layout.list_x + TAG_LEN as u32 * CELL_W;
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
        let _ = self.canvas.present_region(
            0,
            y,
            layout.width,
            (CELL_H + 2).min(layout.height.saturating_sub(y)),
        );
    }

    /// Paint the final frame, forcing a redraw even if the bar value is
    /// unchanged.
    pub fn finish(&mut self, progress: &mut BootProgress) {
        self.last_permille = u32::MAX;
        self.last_signature = u64::MAX;
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

/// Bit-packed snapshot of the list's content: four bits per stage state
/// plus the settled flag. Any state change — or the final lines
/// appearing — flips the signature, which is exactly when the list band
/// needs repainting.
fn list_signature(progress: &BootProgress) -> u64 {
    let mut signature = if progress.all_settled() {
        1u64 << 56
    } else {
        0
    };
    for (index, stage) in progress.stages().iter().enumerate() {
        let code = match stage.state {
            StageState::Pending => 0u64,
            StageState::Running => 1,
            StageState::Done => 2,
            StageState::Failed => 3,
            StageState::Degraded => 4,
            StageState::Skipped => 5,
        };
        signature |= code << (index * 4);
    }
    signature
}

/// systemd-style unit name for a stage id. Custom stages fall back to
/// the operator-configured label.
fn unit_name(stage: &Stage) -> &str {
    match stage.id.as_str() {
        "selftest" => "HuesOS Kernel Self-Test",
        "driver-manager" => "HuesOS Driver Manager",
        "storage" => "HuesOS Storage Service",
        "shutdown-broker" => "HuesOS Power Control",
        "terminal" => "HuesOS Terminal",
        "key-broker" => "HuesOS Key Broker",
        _ => stage.label.as_str(),
    }
}

/// Render `prefix + unit + suffix` into `out`, returning the byte count
/// written.
fn format_line(out: &mut [u8], prefix: &str, unit: &str, suffix: &str) -> usize {
    let mut written = 0;
    for bytes in [prefix.as_bytes(), unit.as_bytes(), suffix.as_bytes()] {
        for byte in bytes {
            if written < out.len() {
                out[written] = *byte;
                written += 1;
            }
        }
    }
    written
}

/// Render `"stage '<id>' did not report ready"` into `out`, returning
/// the byte count written.
fn format_failure(out: &mut [u8], id: &[u8]) -> usize {
    let mut written = 0;
    for bytes in [b"stage '", id, b"' did not report ready"] {
        for byte in bytes {
            if written < out.len() {
                out[written] = *byte;
                written += 1;
            }
        }
    }
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
