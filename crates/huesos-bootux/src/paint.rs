//! Splash geometry and colour maths.
//!
//! Kept free of any framebuffer dependency so the arithmetic that is
//! easy to get wrong — gradient interpolation, bar fill width, spinner
//! phase, layout on odd resolutions — is unit-tested on the host. The
//! init crate supplies pixels; this module only decides values.
//!
//! All integer maths. Init has no FPU state guarantee and no reason to
//! pull in soft-float for a background.

use crate::config::Rgb;
use crate::progress::SCALE;

/// Spinner arm count. Twelve reads as smooth at the ~15 Hz repaint rate
/// the boot loop can sustain without stealing time from service launch.
pub const SPINNER_ARMS: u32 = 12;

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
    pub bar_x: u32,
    pub bar_y: u32,
    pub bar_w: u32,
    pub bar_h: u32,
    pub label_x: u32,
    pub label_y: u32,
    pub title_x: u32,
    pub title_y: u32,
    pub spinner_cx: u32,
    pub spinner_cy: u32,
    pub spinner_r: u32,
    /// Top scanline of the region the animation repaints each frame.
    pub dirty_y: u32,
    /// Height of that region.
    pub dirty_h: u32,
}

/// Compute the splash layout.
///
/// The bar is centred horizontally at 44% of width, clamped so it stays
/// sane on both a 640x480 VGA fallback and a 2560x1600 panel.
pub fn layout(width: u32, height: u32, title_px: u32, label_px: u32) -> Layout {
    let bar_w = (width * 44 / 100)
        .clamp(160, 900)
        .min(width.saturating_sub(32));
    let bar_h = (height / 90).clamp(4, 14);
    let bar_x = (width.saturating_sub(bar_w)) / 2;
    let bar_y = height * 62 / 100;

    let spinner_r = (height / 22).clamp(10, 34);
    let spinner_cx = width / 2;
    let spinner_cy = height * 38 / 100;

    let title_x = width / 2;
    let title_y = spinner_cy + spinner_r + (height / 24).clamp(12, 44);

    let label_x = width / 2;
    let label_y = bar_y + bar_h + (height / 60).clamp(8, 26);

    // The animated region spans the bar and the label line beneath it.
    // The gradient above is painted once and never re-uploaded.
    let dirty_y = bar_y.saturating_sub(bar_h);
    let dirty_bottom = (label_y + label_px + 4).min(height);
    let dirty_h = dirty_bottom.saturating_sub(dirty_y);

    let _ = title_px;

    Layout {
        width,
        height,
        bar_x,
        bar_y,
        bar_w,
        bar_h,
        label_x,
        label_y,
        title_x,
        title_y,
        spinner_cx,
        spinner_cy,
        spinner_r,
        dirty_y,
        dirty_h,
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

/// Brightness of spinner arm `arm` at animation `frame`, 0..=255.
///
/// A comet tail: the leading arm is brightest and brightness falls off
/// around the ring, which reads as rotation without needing to erase
/// the previous frame separately.
pub fn spinner_arm_alpha(arm: u32, frame: u32) -> u8 {
    let arms = SPINNER_ARMS;
    let head = frame % arms;
    let distance = (arms + head - (arm % arms)) % arms;
    let falloff = 255u32.saturating_sub(distance * (255 / arms));
    falloff.max(24) as u8
}

/// Centre `text_px` wide text on `centre`, clamped to the frame.
pub fn centre_text_x(centre: u32, text_len: usize, cell_w: u32, width: u32) -> u32 {
    let text_px = text_len as u32 * cell_w;
    let half = text_px / 2;
    let x = centre.saturating_sub(half);
    if x + text_px > width {
        width.saturating_sub(text_px)
    } else {
        x
    }
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
        // Includes the awkward small mode and a large panel.
        for (w, h) in [
            (640, 480),
            (800, 600),
            (1024, 768),
            (1920, 1080),
            (2560, 1600),
        ] {
            let layout = layout(w, h, 16, 13);
            assert!(layout.bar_x + layout.bar_w <= w, "bar overflows at {w}x{h}");
            assert!(
                layout.bar_y + layout.bar_h <= h,
                "bar below frame at {w}x{h}"
            );
            assert!(
                layout.dirty_y + layout.dirty_h <= h,
                "dirty region at {w}x{h}"
            );
            assert!(layout.dirty_h > 0);
            assert!(
                layout.spinner_cy > layout.spinner_r,
                "spinner clipped at {w}x{h}"
            );
            assert!(layout.label_y < h);
        }
    }

    #[test]
    fn dirty_region_covers_bar_and_label() {
        let layout = layout(1024, 768, 16, 13);
        assert!(layout.dirty_y <= layout.bar_y);
        assert!(layout.dirty_y + layout.dirty_h >= layout.bar_y + layout.bar_h);
        assert!(layout.dirty_y + layout.dirty_h >= layout.label_y);
    }

    #[test]
    fn dirty_region_excludes_the_static_gradient_above() {
        // The point of the partial upload: the spinner and title sit
        // outside the per-frame region, so a frame is a few thousand
        // pixels rather than the whole screen.
        let layout = layout(1024, 768, 16, 13);
        assert!(layout.dirty_h < layout.height / 2);
    }

    #[test]
    fn spinner_head_is_brightest_and_wraps() {
        let head = spinner_arm_alpha(0, 0);
        let tail = spinner_arm_alpha(1, 0);
        assert!(head > tail);
        // One full revolution returns to the same pattern.
        assert_eq!(
            spinner_arm_alpha(3, 5),
            spinner_arm_alpha(3, 5 + SPINNER_ARMS)
        );
    }

    #[test]
    fn spinner_never_fully_dark() {
        for frame in 0..SPINNER_ARMS * 2 {
            for arm in 0..SPINNER_ARMS {
                assert!(spinner_arm_alpha(arm, frame) >= 24);
            }
        }
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

    #[test]
    fn centred_text_never_leaves_the_frame() {
        assert_eq!(centre_text_x(512, 10, 6, 1024), 512 - 30);
        // Text wider than the screen clamps to zero rather than wrapping.
        assert_eq!(centre_text_x(512, 400, 6, 1024), 0);
        assert_eq!(centre_text_x(0, 10, 6, 1024), 0);
    }
}
