//! Terminal primitives shared by the full-screen programs.
//!
//! `fdisk`, `btop` and `nano` all draw the same things: a header, framed
//! panes, coloured labels, bars, tables and a key-driven main loop. Those
//! pieces live here so the programs differ in *what* they show, not in how a
//! frame or a bar is composed.
//!
//! Everything is plain text on a serial console: no cursor-addressing library,
//! no terminal capability negotiation. A program writes a frame, reads a key,
//! and redraws -- at 115200 baud a full redraw costs less than a bad diff.
//!
//! # Example
//! ```ignore
//! use huesos_std::tui::{self, Key};
//!
//! let mut screen = tui::Screen::new(huesos_std::io::stdout());
//! screen.clear()?;
//! screen.line(&tui::frame_top(" fdisk ", 64))?;
//! screen.line(" [##########----------] 50%")?;
//! screen.line(&tui::frame_bottom(64))?;
//! if let Some(Key::Char(b'q')) = tui::read_key(&mut huesos_std::io::stdin()) {
//!     return;
//! }
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Result;
use crate::io::{self, Read, Write};

/// A full block: one bar cell that is completely filled.
pub const FULL: char = '█';
/// A medium shade, used for the unfilled part of a bar.
pub const SHADE: char = '░';
/// A dark shade, used where a bar needs three tones.
pub const DARK: char = '▓';

/// ANSI control sequences the programs here use.
pub mod ansi {
    /// Reset all attributes.
    pub const RESET: &str = "\x1b[0m";
    /// Bold text.
    pub const BOLD: &str = "\x1b[1m";
    /// Dim (reverse of bold) text.
    pub const DIM: &str = "\x1b[2m";
    /// Inverted background and foreground.
    pub const REVERSE: &str = "\x1b[7m";

    /// Foreground colour code for [`super::color::Color`].
    pub fn fg(color: super::color::Color) -> &'static str {
        match color {
            super::color::Color::Black => "\x1b[30m",
            super::color::Color::Red => "\x1b[31m",
            super::color::Color::Green => "\x1b[32m",
            super::color::Color::Yellow => "\x1b[33m",
            super::color::Color::Blue => "\x1b[34m",
            super::color::Color::Magenta => "\x1b[35m",
            super::color::Color::Cyan => "\x1b[36m",
            super::color::Color::White => "\x1b[37m",
        }
    }

    /// Background colour code for [`super::color::Color`].
    pub fn bg(color: super::color::Color) -> &'static str {
        match color {
            super::color::Color::Black => "\x1b[40m",
            super::color::Color::Red => "\x1b[41m",
            super::color::Color::Green => "\x1b[42m",
            super::color::Color::Yellow => "\x1b[43m",
            super::color::Color::Blue => "\x1b[44m",
            super::color::Color::Magenta => "\x1b[45m",
            super::color::Color::Cyan => "\x1b[46m",
            super::color::Color::White => "\x1b[47m",
        }
    }
}

/// The eight colours the terminal palette defines.
pub mod color {
    /// The terminal palette.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Color {
        /// ANSI 0.
        Black,
        /// ANSI 1.
        Red,
        /// ANSI 2.
        Green,
        /// ANSI 3.
        Yellow,
        /// ANSI 4.
        Blue,
        /// ANSI 5.
        Magenta,
        /// ANSI 6.
        Cyan,
        /// ANSI 7.
        White,
    }
}

pub use color::Color;

/// Wrap `text` in a foreground colour.
pub fn colored(text: &str, color: Color) -> String {
    format!("{}{}{}", ansi::fg(color), text, ansi::RESET)
}

/// Format a byte count the way `df -h` does: `512B`, `4.0K`, `96M`, `1.2G`.
pub fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    if bytes < KIB {
        return format!("{bytes}B");
    }
    let (value, suffix) = if bytes < KIB * KIB {
        (bytes as f64 / KIB as f64, 'K')
    } else if bytes < KIB * KIB * KIB {
        (bytes as f64 / (KIB * KIB) as f64, 'M')
    } else if bytes < KIB * KIB * KIB * KIB {
        (bytes as f64 / (KIB * KIB * KIB) as f64, 'G')
    } else {
        (bytes as f64 / (KIB * KIB * KIB * KIB) as f64, 'T')
    };
    // One decimal below ten, none above, so a column of sizes stays narrow.
    if value < 10.0 {
        format!("{value:.1}{suffix}")
    } else {
        format!("{value:.0}{suffix}")
    }
}

/// Format a count with no decimals: `1.2M`, `18.4K`, `97`.
pub fn human_count(count: u64) -> String {
    if count < 1_000 {
        return format!("{count}");
    }
    let (value, suffix) = if count < 1_000_000 {
        (count as f64 / 1_000.0, 'K')
    } else if count < 1_000_000_000 {
        (count as f64 / 1_000_000.0, 'M')
    } else {
        (count as f64 / 1_000_000_000.0, 'G')
    };
    format!("{value:.1}{suffix}")
}

/// A `[████░░░░]` bar of `width` cells for `used` out of `total`.
pub fn bar(used: u64, total: u64, width: usize) -> String {
    let filled = if total == 0 {
        0
    } else {
        ((used.min(total) as u128 * width as u128) / total as u128) as usize
    };
    let mut text = String::from("[");
    for index in 0..width {
        text.push(if index < filled { FULL } else { SHADE });
    }
    text.push(']');
    text
}

/// A bar with the percentage appended: `[██████░░░░]  63%`.
pub fn percent_bar(used: u64, total: u64, width: usize) -> String {
    let percent = (used.min(total) * 100).checked_div(total).unwrap_or(0);
    format!("{} {percent:>3}%", bar(used, total, width))
}

/// Visible column width of `text`, ignoring ANSI CSI escape sequences (`\x1b[...X`).
pub fn visible_width(text: &str) -> usize {
    let mut width = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        width += 1;
    }
    width
}

/// Truncate `text` to `width` visible columns, or pad it with spaces.
///
/// Preserves embedded SGR escape sequences (`\x1b[...m`) without counting their
/// control bytes against `width`, so colored cells inside [`frame_line`] keep
/// the right border aligned.
pub fn fit(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut seen = 0usize;
    let mut had_escape = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            had_escape = true;
            out.push(ch);
            if chars.peek() == Some(&'[') {
                if let Some(bracket) = chars.next() {
                    out.push(bracket);
                }
                for c in chars.by_ref() {
                    out.push(c);
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        if seen >= width {
            break;
        }
        out.push(ch);
        seen += 1;
    }
    if had_escape && !out.ends_with("\x1b[0m") {
        out.push_str("\x1b[0m");
    }
    while seen < width {
        out.push(' ');
        seen += 1;
    }
    out
}

/// Right-align `text` in `width` characters (truncating from the left).
pub fn fit_right(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count >= width {
        let skip = count - width;
        return text.chars().skip(skip).collect();
    }
    let mut out = String::new();
    for _ in 0..width - count {
        out.push(' ');
    }
    out.push_str(text);
    out
}

/// Top border of a framed pane: `╭─ title ─────╮`.
pub fn frame_top(title: &str, width: usize) -> String {
    let inner = width.saturating_sub(2);
    let label = if title.is_empty() {
        String::new()
    } else {
        format!(" {} ", title.trim())
    };
    let label_len = label.chars().count();
    let mut text = String::from("┌");
    if label_len + 1 > inner {
        text.push_str(&fit(&label, inner));
    } else {
        text.push_str(&label);
        for _ in 0..inner - label_len {
            text.push('─');
        }
    }
    text.push('┐');
    text
}

/// Middle divider of a framed pane: `├────────────┤`.
pub fn frame_rule(width: usize) -> String {
    let mut text = String::from("├");
    for _ in 0..width.saturating_sub(2) {
        text.push('─');
    }
    text.push('┤');
    text
}

/// Bottom border of a framed pane: `╰────────────╯`.
pub fn frame_bottom(width: usize) -> String {
    let mut text = String::from("└");
    for _ in 0..width.saturating_sub(2) {
        text.push('─');
    }
    text.push('┘');
    text
}

/// A body line of a framed pane, padded to the frame width.
pub fn frame_line(body: &str, width: usize) -> String {
    format!("│{}│", fit(body, width.saturating_sub(2)))
}

/// One Braille cell for up to eight samples.
///
/// A Braille cell is a 2x4 dot grid: four height levels per column, two
/// samples side by side. That is eight times the vertical resolution of a
/// block bar, which is what makes a 60-column history readable.
const BRAILLE_BASE: u32 = 0x2800;

/// Braille dot bits: left column top-to-bottom, right column top-to-bottom.
const LEFT_DOTS: [u8; 4] = [0, 1, 2, 6];
const RIGHT_DOTS: [u8; 4] = [3, 4, 5, 7];

/// How many of a Braille column's four dots are filled for `value` out of
/// `max`, rounded up so a non-zero sample always shows.
fn braille_level(value: u64, max: u64) -> usize {
    if max == 0 || value == 0 {
        return 0;
    }
    let scaled = (value.min(max) as u128 * 4).div_ceil(max as u128);
    (scaled as usize).clamp(1, 4)
}

/// Render `samples` as a Braille history string, newest on the right.
///
/// Each output cell covers two samples. `max` scales the history; it is
/// usually the largest sample or a fixed capacity such as 100 %.
pub fn braille_history(samples: &[u64], max: u64) -> String {
    let mut text = String::new();
    let mut index = 0;
    while index < samples.len() {
        let left = braille_level(samples[index], max);
        let right = if index + 1 < samples.len() {
            braille_level(samples[index + 1], max)
        } else {
            0
        };
        let mut pattern = 0u32;
        // Dots fill from the bottom of each column upward.
        for level in 0..left {
            pattern |= 1 << LEFT_DOTS[3 - level];
        }
        for level in 0..right {
            pattern |= 1 << RIGHT_DOTS[3 - level];
        }
        text.push(char::from_u32(BRAILLE_BASE + pattern).unwrap_or(' '));
        index += 2;
    }
    text
}

/// Keep only the last `width * 2` samples, so a history fills the pane.
pub fn history_tail(samples: &[u64], width: usize) -> &[u64] {
    let wanted = width * 2;
    if samples.len() <= wanted {
        samples
    } else {
        &samples[samples.len() - wanted..]
    }
}

/// A column-oriented table.
pub struct Table {
    headers: Vec<String>,
    widths: Vec<usize>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// A table with `headers` and the given column widths.
    pub fn new(headers: &[&str], widths: &[usize]) -> Self {
        Self {
            headers: headers.iter().map(|text| String::from(*text)).collect(),
            widths: widths.to_vec(),
            rows: Vec::new(),
        }
    }

    /// Append a row; extra cells are dropped, missing ones render empty.
    pub fn row(&mut self, cells: &[String]) {
        self.rows.push(cells.to_vec());
    }

    /// The header line.
    pub fn header_line(&self) -> String {
        let mut text = String::new();
        for (index, header) in self.headers.iter().enumerate() {
            if index > 0 {
                text.push(' ');
            }
            text.push_str(&fit(&header.to_uppercase(), self.widths[index]));
        }
        text
    }

    /// The rule under the header.
    pub fn separator(&self) -> String {
        let mut text = String::new();
        for (index, width) in self.widths.iter().enumerate() {
            if index > 0 {
                text.push(' ');
            }
            for _ in 0..*width {
                text.push('─');
            }
        }
        text
    }

    /// Render every row, one string per line.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for row in &self.rows {
            let mut text = String::new();
            for (index, width) in self.widths.iter().enumerate() {
                if index > 0 {
                    text.push(' ');
                }
                text.push_str(&fit(
                    row.get(index).map(String::as_str).unwrap_or(""),
                    *width,
                ));
            }
            lines.push(text);
        }
        lines
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when no rows were added.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// One keystroke.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Key {
    /// A printable character.
    Char(u8),
    /// Up arrow.
    Up,
    /// Down arrow.
    Down,
    /// Left arrow.
    Left,
    /// Right arrow.
    Right,
    /// Home (`^A` on xterm, `ESC [ H` on a serial console).
    Home,
    /// End.
    End,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// `Delete`.
    Delete,
    /// `Insert`.
    Insert,
    /// `Enter`/`Return`.
    Enter,
    /// `Backspace` (0x08 or 0x7f).
    Backspace,
    /// `Tab`.
    Tab,
    /// `Escape` on its own.
    Escape,
    /// Control key: `Ctrl(3)` is `^C`, `Ctrl(17)` is `^Q`.
    Ctrl(u8),
    /// A sequence this decoder does not name.
    Unknown,
}

impl Key {
    /// True for `^C`, the "stop right now" key.
    pub fn is_interrupt(self) -> bool {
        matches!(self, Key::Ctrl(3))
    }
}

/// Read one keystroke from `input`.
///
/// Returns `None` on end of input, which is what a pipe or a closed console
/// gives a program -- the caller should treat it as "quit".
pub fn read_key<R: Read>(input: &mut R) -> Option<Key> {
    let mut byte = [0u8; 1];
    if input.read(&mut byte).ok()? == 0 {
        return None;
    }
    Some(decode_key(input, byte[0]))
}

/// Read one keystroke, waiting at most `timeout`.
///
/// `None` means nothing arrived before `timeout`. When `stdin` is already at
/// end of input (`Ok(0)` / closed pipe), park for `timeout` via [`crate::thread::sleep`]
/// so a full-screen monitor run non-interactively never busy-spins at 100% CPU.
pub fn read_key_timeout(timeout: crate::time::Duration) -> Option<Key> {
    let mut stdin = io::stdin();
    let mut byte = [0u8; 1];
    match stdin.read_timeout(&mut byte, timeout) {
        Ok(0) => {
            crate::thread::sleep(timeout);
            None
        }
        Ok(_) => Some(decode_key(&mut stdin, byte[0])),
        Err(_) => None,
    }
}

fn decode_key<R: Read>(_input: &mut R, first: u8) -> Key {
    match first {
        0x1b => {
            // A bare Escape has nothing immediately following it; an arrow or
            // navigation key arrives as `ESC [ X` (either in one channel packet
            // buffered inside `Stdio` or within 1–2 ticks). Using a short
            // timeout avoids blocking forever when the user presses Esc alone.
            let Some(second) = read_escape_byte() else {
                return Key::Escape;
            };
            if second != b'[' && second != b'O' {
                return Key::Escape;
            }
            let Some(third) = read_escape_byte() else {
                return Key::Escape;
            };
            match third {
                b'A' => Key::Up,
                b'B' => Key::Down,
                b'C' => Key::Right,
                b'D' => Key::Left,
                b'H' => Key::Home,
                b'F' => Key::End,
                b'1' | b'2' | b'3' | b'4' | b'5' | b'6' | b'7' | b'8' => {
                    // `ESC [ <n> ~` ends with a tilde; anything else after the
                    // digit means the sequence is not one we know.
                    let _ = read_escape_byte();
                    match third {
                        b'1' => Key::Home,
                        b'3' => Key::Delete,
                        b'4' => Key::End,
                        b'5' => Key::PageUp,
                        b'6' => Key::PageDown,
                        b'2' => Key::Insert,
                        _ => Key::Unknown,
                    }
                }
                _ => Key::Unknown,
            }
        }
        b'\r' | b'\n' => Key::Enter,
        b'\t' => Key::Tab,
        0x7f | 0x08 => Key::Backspace,
        0x01..=0x1a => Key::Ctrl(first),
        0x20..=0x7e => Key::Char(first),
        _ => Key::Unknown,
    }
}

fn read_escape_byte() -> Option<u8> {
    let mut stdin = io::stdin();
    let mut byte = [0u8; 1];
    match stdin.read_timeout(&mut byte, crate::time::Duration::from_ticks(2)) {
        Ok(1) => Some(byte[0]),
        _ => None,
    }
}

/// Read a line of input with a prompt and a working backspace.
///
/// Returns `None` when the reader hit end of input or `^C`.
pub fn prompt<W: Write, R: Read>(out: &mut W, input: &mut R, label: &str) -> Option<String> {
    let mut line = String::new();
    let _ = io::write_all(out, format!("\r\n {label}: ").as_bytes());
    loop {
        match read_key(input)? {
            Key::Enter => {
                let _ = out.flush();
                return Some(line);
            }
            Key::Backspace if line.pop().is_some() => {
                let _ = io::write_all(out, b"\x08 \x08");
                let _ = out.flush();
            }
            Key::Escape | Key::Ctrl(3) | Key::Ctrl(7) => return None,
            Key::Char(byte) => {
                line.push(char::from(byte));
                let _ = io::write_all(out, &[byte]);
                let _ = out.flush();
            }
            Key::Tab => {
                line.push(' ');
                let _ = io::write_all(out, b" ");
            }
            _ => {}
        }
    }
}

/// A framed output stream: every line ends in `\r\n`, every flush flushes.
pub struct Screen<W: Write> {
    out: W,
}

impl<W: Write> Screen<W> {
    /// Wrap `out`.
    pub fn new(out: W) -> Self {
        Self { out }
    }

    /// Borrow the underlying stream (for a prompt, or for one-off text).
    pub fn out(&mut self) -> &mut W {
        &mut self.out
    }

    /// Clear the screen and park the cursor top-left.
    pub fn clear(&mut self) -> Result<()> {
        let _ = io::write_all(&mut self.out, b"\x1b[2J\x1b[H");
        self.out.flush()
    }

    /// Move the cursor to the top-left without clearing.
    pub fn home(&mut self) -> Result<()> {
        let _ = io::write_all(&mut self.out, b"\x1b[H");
        self.out.flush()
    }

    /// Hide the cursor (the program draws its own).
    pub fn hide_cursor(&mut self) -> Result<()> {
        let _ = io::write_all(&mut self.out, b"\x1b[?25l");
        self.out.flush()
    }

    /// Show the cursor again.
    pub fn show_cursor(&mut self) -> Result<()> {
        let _ = io::write_all(&mut self.out, b"\x1b[?25h");
        self.out.flush()
    }

    /// Write one line.
    pub fn line(&mut self, text: &str) -> Result<()> {
        io::write_all(&mut self.out, text.as_bytes())?;
        io::write_all(&mut self.out, b"\r\n")
    }

    /// Write one line and flush, for a frame that is now complete.
    pub fn line_flushed(&mut self, text: &str) -> Result<()> {
        self.line(text)?;
        self.out.flush()
    }

    /// Write raw text (a prompt, a status fragment) and flush.
    pub fn write_raw(&mut self, text: &str) -> Result<()> {
        io::write_all(&mut self.out, text.as_bytes())?;
        self.out.flush()
    }

    /// Enter full-screen alternate buffer mode and hide the hardware cursor.
    pub fn enter_fullscreen(&mut self) -> Result<()> {
        io::write_all(&mut self.out, b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H")?;
        self.out.flush()
    }

    /// Leave full-screen alternate buffer mode, reset SGR, and show the cursor.
    pub fn leave_fullscreen(&mut self) -> Result<()> {
        io::write_all(&mut self.out, b"\x1b[0m\x1b[?1049l\x1b[?25h")?;
        self.out.flush()
    }
}

/// Active terminal viewport `(cols, rows)` in character cells.
///
/// Queries the UEFI GOP framebuffer geometry via `libcanvas::framebuffer::info()`
/// and applies the exact cell metrics of `terminal/src/screen.rs` (`Cozette6x13`:
/// `advance = 6`, `line_height = 14`, `LEFT_MARGIN = 12`, `TOP_MARGIN = 27`,
/// `FOOTER_HEIGHT = 20`, yielding `166 × 50` on `1024×768`). Falls back to
/// `100 × 30` on serial-only consoles without a framebuffer.
pub fn viewport_size() -> (usize, usize) {
    if let Ok(info) = libcanvas::framebuffer::info() {
        let avail_w = info.width.saturating_sub(24);
        let avail_h = info.height.saturating_sub(51);
        let cols = ((avail_w / 6) as usize).clamp(80, 168);
        let rows = ((avail_h / 14) as usize).clamp(24, 54);
        (cols, rows)
    } else {
        (100, 30)
    }
}

/// Format a 24-bit RGB foreground SGR escape (`\x1b[38;2;r;g;bm`).
pub fn fg_rgb(r: u8, g: u8, b: u8) -> String {
    format!("\x1b[38;2;{r};{g};{b}m")
}

/// Format a 24-bit RGB background SGR escape (`\x1b[48;2;r;g;bm`).
pub fn bg_rgb(r: u8, g: u8, b: u8) -> String {
    format!("\x1b[48;2;{r};{g};{b}m")
}

/// Smooth horizontal meter of `width` cells using 1/8th fractional block glyphs
/// (`█▉▊▋▌▍▎▏`) and `░` track cells.
pub fn smooth_bar(
    used: u64,
    total: u64,
    width: usize,
    fill_fg: (u8, u8, u8),
    track_fg: (u8, u8, u8),
) -> String {
    const EIGHTHS: [char; 8] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    if width == 0 {
        return String::new();
    }
    let total_eighths = width as u128 * 8;
    let filled_eighths = if total == 0 {
        0usize
    } else {
        ((used.min(total) as u128 * total_eighths) / total as u128) as usize
    };
    let full_cells = (filled_eighths / 8).min(width);
    let rem_eighth = filled_eighths % 8;

    let mut out = String::new();
    if full_cells > 0 || rem_eighth > 0 {
        out.push_str(&fg_rgb(fill_fg.0, fill_fg.1, fill_fg.2));
        for _ in 0..full_cells {
            out.push('█');
        }
        if full_cells < width && rem_eighth > 0 {
            out.push(EIGHTHS[rem_eighth]);
        }
    }
    let used_cells = full_cells + usize::from(full_cells < width && rem_eighth > 0);
    if used_cells < width {
        out.push_str(&fg_rgb(track_fg.0, track_fg.1, track_fg.2));
        for _ in used_cells..width {
            out.push('░');
        }
    }
    out.push_str(ansi::RESET);
    out
}

/// Full-screen single-frame string buffer that addresses every row explicitly via
/// `\x1b[{row};1H` so a redraw is emitted in a single `stdout` write without
/// flicker, tearing, or accidental bottom-row auto-wrap scrolling.
pub struct FrameBuffer {
    cols: usize,
    rows: usize,
    buf: String,
}

impl FrameBuffer {
    /// Allocate a frame buffer for `(cols, rows)` cells.
    pub fn new(cols: usize, rows: usize) -> Self {
        Self {
            cols: cols.max(40),
            rows: rows.max(16),
            buf: String::with_capacity(cols.saturating_mul(rows).saturating_mul(3)),
        }
    }

    /// Viewport width in columns.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Viewport height in rows.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Safe printable width on `row` (1-based).
    ///
    /// `terminal/src/screen.rs` uses deferred auto-wrap (`if self.col >= wrap_columns`),
    /// so writing all `cols` cells on any explicitly addressed row (`\x1b[r;1H`)
    /// never triggers `newline()`/`scroll()` unless an extra `(cols + 1)`-th
    /// printable character is emitted on the same row.
    pub fn safe_cols(&self, _row: usize) -> usize {
        self.cols
    }

    /// Place `content` at 1-based `(row, col)` without padding.
    pub fn put_at(&mut self, row: usize, col: usize, content: &str) {
        if row < 1 || row > self.rows || col < 1 || col > self.cols {
            return;
        }
        use core::fmt::Write as _;
        let _ = write!(self.buf, "\x1b[{row};{col}H{content}\x1b[0m");
    }

    /// Place a full-width row at 1-based `row`, fitted/padded to `safe_cols(row)`.
    pub fn put_row(&mut self, row: usize, content: &str) {
        if row < 1 || row > self.rows {
            return;
        }
        let max_w = self.safe_cols(row);
        let fitted = fit(content, max_w);
        use core::fmt::Write as _;
        if row < self.rows {
            let _ = write!(self.buf, "\x1b[{row};1H{fitted}\x1b[0m\x1b[K");
        } else {
            let _ = write!(self.buf, "\x1b[{row};1H{fitted}\x1b[0m");
        }
    }

    /// Place a full-width row painted with a uniform background colour `bg`.
    pub fn put_bar_row(&mut self, row: usize, bg: (u8, u8, u8), content: &str) {
        if row < 1 || row > self.rows {
            return;
        }
        let max_w = self.safe_cols(row);
        let fitted = fit_with_bg(content, max_w, bg);
        use core::fmt::Write as _;
        let _ = write!(self.buf, "\x1b[{row};1H{fitted}\x1b[0m");
    }

    /// Flush the entire assembled frame to `out` in one contiguous write.
    pub fn flush_to<W: Write>(&self, out: &mut W) -> Result<()> {
        io::write_all(out, self.buf.as_bytes())?;
        out.flush()
    }
}

/// Fit `text` to `width` visible columns while keeping `bg` active across resets.
pub fn fit_with_bg(text: &str, width: usize, bg: (u8, u8, u8)) -> String {
    let bg_seq = bg_rgb(bg.0, bg.1, bg.2);
    let mut out = String::new();
    out.push_str(&bg_seq);
    let mut seen = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            let mut esc = String::from("\x1b");
            if chars.peek() == Some(&'[') {
                if let Some(b) = chars.next() {
                    esc.push(b);
                }
                for c in chars.by_ref() {
                    esc.push(c);
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            out.push_str(&esc);
            if esc == "\x1b[0m" || esc == "\x1b[m" {
                out.push_str(&bg_seq);
            }
            continue;
        }
        if seen >= width {
            break;
        }
        out.push(ch);
        seen += 1;
    }
    while seen < width {
        out.push(' ');
        seen += 1;
    }
    out.push_str(ansi::RESET);
    out
}
