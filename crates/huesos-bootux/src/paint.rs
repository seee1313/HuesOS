//! Splash geometry and colour maths.
//!
//! Kept free of any framebuffer dependency so the arithmetic that is
//! easy to get wrong — gradient interpolation, bar fill width, status
//! line formatting, layout on odd resolutions — is unit-tested on the
//! host. The init crate supplies pixels; this module only decides
//! values.
//!
//! All integer maths. Init has no FPU state guarantee and no reason to
//! pull in soft-float for a background.

use crate::config::Rgb;
use crate::progress::SCALE;

/// Linearly interpolate a vertical gradient at scanline `y`.
///
/// Rounded rather than truncated: truncation biases every channel
/// downward and produces a visible dark band at the top of the screen.
pub fn gradient_at(top: Rgb, bottom: Rgb, y: u32, height: u32) -> Rgb {
    if height <= 1 {
        return top;
    }
    let span = height - 1;
    let y = y.min(span);
    Rgb {
        r: lerp(top.r, bottom.r, y, span),
        g: lerp(top.g, bottom.g, y, span),
        b: lerp(top.b, bottom.b, y, span),
    }
}

fn lerp(from: u8, to: u8, position: u32, span: u32) -> u8 {
    if span == 0 {
        return from;
    }
    let from = from as i32;
    let to = to as i32;
    let delta = to - from;
    // Round to nearest: add half a step before dividing.
    let scaled = delta * position as i32 * 2 + span as i32 * delta.signum();
    let value = from + scaled / (span as i32 * 2);
    value.clamp(0, 255) as u8
}

/// Scale a colour's brightness by `numerator/denominator`.
pub fn shade(color: Rgb, numerator: u32, denominator: u32) -> Rgb {
    if denominator == 0 {
        return color;
    }
    let apply = |channel: u8| -> u8 {
        let value = channel as u32 * numerator / denominator;
        value.min(255) as u8
    };
    Rgb {
        r: apply(color.r),
        g: apply(color.g),
        b: apply(color.b),
    }
}

/// Blend `a` into `b` by `alpha`/255.
pub fn blend(a: Rgb, b: Rgb, alpha: u8) -> Rgb {
    let mix = |x: u8, y: u8| -> u8 {
        let alpha = alpha as u32;
        (((x as u32 * alpha) + (y as u32 * (255 - alpha))) / 255).min(255) as u8
    };
    Rgb {
        r: mix(a.r, b.r),
        g: mix(a.g, b.g),
        b: mix(a.b, b.b),
    }
}

/// Computed splash layout for a given framebuffer size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    pub width: u32,
    pub height: u32,
    /// Top-left origin of the brand line ("HuesOS <version>").
    pub brand_x: u32,
    pub brand_y: u32,
    /// Left margin of the systemd-style status list.
    pub list_x: u32,
    /// Top scanline of the first status line.
    pub list_y: u32,
    /// Row pitch of the status list.
    pub line_h: u32,
    /// Total height of the status list block (stages + final lines).
    pub list_h: u32,
    pub bar_x: u32,
    pub bar_y: u32,
    pub bar_w: u32,
    pub bar_h: u32,
}

/// Column width (glyph cells) of the status-list tag. Fixed at eight so
/// the message column starts on the same scanline for every line.
pub const TAG_LEN: usize = 8;

/// Fixed palette of the systemd-style status list. Muted on purpose:
/// the dark boot gradient is the canvas, the list is the signal.
pub const COLOR_OK: Rgb = Rgb::new(96, 190, 120);
pub const COLOR_WARN: Rgb = Rgb::new(212, 180, 110);
pub const COLOR_FAIL: Rgb = Rgb::new(255, 96, 96);
pub const COLOR_SKIP: Rgb = Rgb::new(110, 120, 150);
/// Message text next to a tag (and the untagged "Starting ..." lines).
pub const COLOR_MSG: Rgb = Rgb::new(150, 170, 205);

/// Tag state of one status line, mirroring systemd's `[  OK  ]` /
/// `[FAILED]` console format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageTag {
    Ok,
    Warn,
    Failed,
    Skip,
    /// Started but not settled yet: blank tag column, like systemd's
    /// untagged `Starting ...` line.
    Starting,
    /// No tag at all (e.g. the final "Startup complete." line).
    Blank,
}

/// Map a stage state onto its line tag.
pub fn stage_tag(state: crate::progress::StageState) -> StageTag {
    use crate::progress::StageState;
    match state {
        StageState::Done => StageTag::Ok,
        StageState::Degraded => StageTag::Warn,
        StageState::Failed => StageTag::Failed,
        StageState::Skipped => StageTag::Skip,
        StageState::Running => StageTag::Starting,
        StageState::Pending => StageTag::Blank,
    }
}

/// The fixed-width tag column for a line.
pub fn tag_text(tag: StageTag) -> &'static str {
    match tag {
        StageTag::Ok => "[  OK  ]",
        StageTag::Warn => "[WARN  ]",
        StageTag::Failed => "[FAILED]",
        StageTag::Skip => "[SKIP  ]",
        StageTag::Starting | StageTag::Blank => "        ",
    }
}

/// Tag colour for a line.
pub fn tag_color(tag: StageTag) -> Rgb {
    match tag {
        StageTag::Ok => COLOR_OK,
        StageTag::Warn => COLOR_WARN,
        StageTag::Failed => COLOR_FAIL,
        StageTag::Skip => COLOR_SKIP,
        StageTag::Starting | StageTag::Blank => COLOR_MSG,
    }
}

/// Message text around the unit name: `prefix + unit + suffix`.
///
/// systemd reads "Starting X...", "Started X.", "Failed to start X." —
/// the unit name is the stage's display name, supplied by the caller.
pub fn line_prefix(state: crate::progress::StageState) -> &'static str {
    use crate::progress::StageState;
    match state {
        StageState::Running => "Starting ",
        StageState::Done => "Started ",
        StageState::Degraded => "Started ",
        StageState::Failed => "Failed to start ",
        StageState::Skipped | StageState::Pending => "",
    }
}

pub fn line_suffix(state: crate::progress::StageState) -> &'static str {
    use crate::progress::StageState;
    match state {
        StageState::Running => "...",
        StageState::Done => ".",
        StageState::Degraded => " (degraded).",
        StageState::Failed => ".",
        StageState::Skipped => " not started.",
        StageState::Pending => "",
    }
}

/// Compute the splash layout.
///
/// The composition, top to bottom: a small brand line ("HuesOS
/// <version>") in the top-left corner, the systemd-style service
/// status list in the upper-middle, and a thin overall progress bar in
/// the bottom margin. Everything is left-aligned like a real boot
/// console; the bar keeps its 44%-of-width band, clamped so it stays
/// sane from 640x480 VGA to a 2560x1600 panel.
pub fn layout(width: u32, height: u32, cell_h: u32, stage_count: usize) -> Layout {
    let margin = (width / 24).clamp(24, 72);
    let brand_y = margin / 2;

    let bar_w = (width * 44 / 100)
        .clamp(160, 900)
        .min(width.saturating_sub(32));
    // Thin bar: a few pixels, not a chunky slab.
    let bar_h = (height / 160).clamp(2, 5);
    let bar_x = (width.saturating_sub(bar_w)) / 2;
    let bar_y = height * 88 / 100;

    // Status list: one row per stage plus the two final lines
    // ("Reached target ..." / "Startup complete."). Row pitch grows
    // with the panel but never crowds the 6x13 glyphs.
    let lines = (stage_count + 2).max(1) as u32;
    let mut line_h = (height / 34).clamp(18, 26);
    let list_y = (height * 30 / 100).max((height / 40).min(24));
    let mut list_h = lines * line_h;
    // Defensive: an oversized custom stage table must not run into the
    // bar — shrink the pitch instead of overflowing the frame.
    if list_y + list_h + 8 > bar_y {
        let room = bar_y
            .saturating_sub(list_y + 8)
            .min(height.saturating_sub(list_y + 8));
        line_h = (room / lines).max(cell_h.min(16));
        list_h = lines * line_h;
    }

    Layout {
        width,
        height,
        brand_x: margin,
        brand_y,
        list_x: margin,
        list_y,
        line_h,
        list_h,
        bar_x,
        bar_y,
        bar_w,
        bar_h,
    }
}

/// Filled width of the progress bar for a given permille.
///
/// Saturates at the track width and never exceeds it, so a rounding
/// error cannot paint one pixel outside the frame.
pub fn bar_fill_width(bar_w: u32, permille: u32) -> u32 {
    let permille = permille.min(SCALE);
    ((bar_w as u64 * permille as u64) / SCALE as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOP: Rgb = Rgb::new(10, 14, 34);
    const BOTTOM: Rgb = Rgb::new(4, 6, 14);

    #[test]
    fn gradient_hits_both_endpoints() {
        assert_eq!(gradient_at(TOP, BOTTOM, 0, 768), TOP);
        assert_eq!(gradient_at(TOP, BOTTOM, 767, 768), BOTTOM);
    }

    #[test]
    fn gradient_is_monotonic() {
        let mut previous = gradient_at(TOP, BOTTOM, 0, 768).r;
        for y in 1..768 {
            let current = gradient_at(TOP, BOTTOM, y, 768).r;
            assert!(current <= previous, "channel must not rise at y={y}");
            previous = current;
        }
    }

    #[test]
    fn gradient_handles_degenerate_heights() {
        assert_eq!(gradient_at(TOP, BOTTOM, 0, 0), TOP);
        assert_eq!(gradient_at(TOP, BOTTOM, 0, 1), TOP);
        // Out-of-range y clamps instead of wrapping.
        assert_eq!(gradient_at(TOP, BOTTOM, 99_999, 768), BOTTOM);
    }

    #[test]
    fn gradient_ascending_direction_works() {
        // Interpolating upward must not underflow the signed maths.
        let result = gradient_at(BOTTOM, TOP, 767, 768);
        assert_eq!(result, TOP);
    }

    #[test]
    fn bar_fill_spans_zero_to_full() {
        assert_eq!(bar_fill_width(600, 0), 0);
        assert_eq!(bar_fill_width(600, SCALE), 600);
        assert_eq!(bar_fill_width(600, SCALE / 2), 300);
    }

    #[test]
    fn bar_fill_never_exceeds_track() {
        // Overlarge input must clamp, not paint outside the frame.
        assert_eq!(bar_fill_width(600, SCALE * 4), 600);
        assert_eq!(bar_fill_width(0, SCALE), 0);
    }

    #[test]
    fn bar_fill_is_monotonic() {
        let mut previous = 0;
        for permille in 0..=SCALE {
            let width = bar_fill_width(613, permille);
            assert!(width >= previous);
            previous = width;
        }
        assert_eq!(previous, 613);
    }

    #[test]
    fn layout_stays_inside_the_frame() {
        // Includes the awkward small mode, a large panel, and both the
        // default five-stage table and the 12-stage max.
        for (w, h) in [
            (640, 480),
            (800, 600),
            (1024, 768),
            (1920, 1080),
            (2560, 1600),
        ] {
            for stage_count in [5usize, crate::config::MAX_STAGES] {
                let layout = layout(w, h, 13, stage_count);
                assert!(layout.bar_x + layout.bar_w <= w, "bar overflows at {w}x{h}");
                assert!(
                    layout.bar_y + layout.bar_h <= h,
                    "bar below frame at {w}x{h}"
                );
                assert!(
                    layout.list_y + layout.list_h <= h,
                    "list below frame at {w}x{h}"
                );
                // Brand line fits one font row below its origin.
                assert!(layout.brand_y + 13 <= h, "brand at {w}x{h}");
                // The status list ends well above the progress bar, so
                // the two independently presented bands never overlap.
                assert!(
                    layout.list_y + layout.list_h + 8 <= layout.bar_y,
                    "list touches bar at {w}x{h}"
                );
                // Rows are tall enough for the 13px glyphs.
                assert!(layout.line_h >= 13, "crowded rows at {w}x{h}");
                assert_eq!(layout.list_h, (stage_count + 2) as u32 * layout.line_h);
            }
        }
    }

    #[test]
    fn layout_left_margins_match_between_brand_and_list() {
        // The brand line and the status list share one left margin,
        // which is what makes the composition read as a console.
        let layout = layout(1024, 768, 13, 5);
        assert_eq!(layout.brand_x, layout.list_x);
    }

    #[test]
    fn status_lines_use_the_systemd_console_format() {
        use crate::progress::StageState;
        // Settled stages.
        assert_eq!(tag_text(stage_tag(StageState::Done)), "[  OK  ]");
        assert_eq!(tag_text(stage_tag(StageState::Degraded)), "[WARN  ]");
        assert_eq!(tag_text(stage_tag(StageState::Failed)), "[FAILED]");
        assert_eq!(tag_text(stage_tag(StageState::Skipped)), "[SKIP  ]");
        // Running and pending stages carry no tag, like systemd's
        // untagged "Starting ..." lines.
        assert_eq!(tag_text(stage_tag(StageState::Running)), "        ");
        assert_eq!(tag_text(stage_tag(StageState::Pending)), "        ");
        // The tag column is fixed width for every tag.
        assert_eq!(TAG_LEN, 8);
        for tag in [
            StageTag::Ok,
            StageTag::Warn,
            StageTag::Failed,
            StageTag::Skip,
            StageTag::Starting,
            StageTag::Blank,
        ] {
            assert_eq!(tag_text(tag).len(), TAG_LEN);
        }
    }

    #[test]
    fn status_lines_read_like_systemd_messages() {
        use crate::progress::StageState;
        let unit = "HuesOS Storage Service";
        assert_eq!(
            format!(
                "{prefix}{unit}{suffix}",
                prefix = line_prefix(StageState::Running),
                suffix = line_suffix(StageState::Running)
            ),
            "Starting HuesOS Storage Service..."
        );
        assert_eq!(
            format!(
                "{prefix}{unit}{suffix}",
                prefix = line_prefix(StageState::Done),
                suffix = line_suffix(StageState::Done)
            ),
            "Started HuesOS Storage Service."
        );
        assert_eq!(
            format!(
                "{prefix}{unit}{suffix}",
                prefix = line_prefix(StageState::Degraded),
                suffix = line_suffix(StageState::Degraded)
            ),
            "Started HuesOS Storage Service (degraded)."
        );
        assert_eq!(
            format!(
                "{prefix}{unit}{suffix}",
                prefix = line_prefix(StageState::Failed),
                suffix = line_suffix(StageState::Failed)
            ),
            "Failed to start HuesOS Storage Service."
        );
        assert_eq!(
            format!(
                "{prefix}{unit}{suffix}",
                prefix = line_prefix(StageState::Skipped),
                suffix = line_suffix(StageState::Skipped)
            ),
            "HuesOS Storage Service not started."
        );
    }

    #[test]
    fn tag_colors_are_distinct_and_readable() {
        assert_eq!(tag_color(StageTag::Ok), COLOR_OK);
        assert_eq!(tag_color(StageTag::Warn), COLOR_WARN);
        assert_eq!(tag_color(StageTag::Failed), COLOR_FAIL);
        assert_eq!(tag_color(StageTag::Skip), COLOR_SKIP);
        assert_eq!(tag_color(StageTag::Starting), COLOR_MSG);
        // Success and failure must never be confused.
        assert_ne!(tag_color(StageTag::Ok), tag_color(StageTag::Failed));
    }

    #[test]
    fn shade_and_blend_stay_in_range() {
        assert_eq!(shade(Rgb::new(200, 100, 50), 0, 4), Rgb::new(0, 0, 0));
        assert_eq!(shade(Rgb::new(200, 100, 50), 4, 4), Rgb::new(200, 100, 50));
        assert_eq!(shade(Rgb::new(200, 100, 50), 8, 4).r, 255);
        assert_eq!(
            blend(Rgb::new(255, 255, 255), Rgb::new(0, 0, 0), 0),
            Rgb::new(0, 0, 0)
        );
        assert_eq!(
            blend(Rgb::new(255, 255, 255), Rgb::new(0, 0, 0), 255),
            Rgb::new(255, 255, 255)
        );
    }
}
