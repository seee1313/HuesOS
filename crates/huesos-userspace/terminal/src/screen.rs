//! Framebuffer-backed text screen with dirty-cell tracking, industrial chrome,
//! fast scroll-shift blitting, and a 512-line scrollback ring buffer.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libcanvas::framebuffer::{Canvas, TextFont};
use libcanvas::HandleValue;

const ROWS: usize = 54;
const COLS: usize = 168;
const TAB_WIDTH: usize = 4;
const SCROLLBACK_CAP: usize = 512;

const ALL_ROWS_DIRTY: u64 = (1u64 << ROWS) - 1;
const CLEAN_COLUMN: u16 = COLS as u16;

const LEFT_MARGIN: u32 = 12;
const HEADER_HEIGHT: u32 = 22;
const TOP_MARGIN: u32 = HEADER_HEIGHT + 5;
const FOOTER_HEIGHT: u32 = 20;

/// Covers framebuffers up to 2560x1600 at 32 bits per pixel without heap
/// allocation.
const SHADOW_CAPACITY: usize = 16 * 1024 * 1024;

pub type Color = (u8, u8, u8);

const COLOR_BACKGROUND: Color = (11, 14, 20); // #0B0E14 obsidian workspace
const COLOR_CHROME_BG: Color = (16, 21, 31); // #10151F header / footer
const COLOR_DIVIDER: Color = (30, 38, 54); // #1E2636 1px hairline divider
const COLOR_TEXT: Color = (205, 220, 240);
const COLOR_MUTED: Color = (120, 140, 168);
const COLOR_ACCENT: Color = (95, 225, 185);
const COLOR_AMBER: Color = (255, 195, 90);
const COLOR_CURSOR: Color = (95, 225, 185);

/// Single character cell stored in the screen & shadow grids.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Cell {
    pub ch: char,
    pub fg: Color,
    pub bg: Color,
    pub flags: u8,
}

const DEFAULT_CELL: Cell = Cell {
    ch: ' ',
    fg: COLOR_TEXT,
    bg: COLOR_BACKGROUND,
    flags: 0,
};

static SHADOW_GENERATION: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShadowError {
    AlreadyBorrowed,
}

struct TerminalShadow {
    pixels: UnsafeCell<[u8; SHADOW_CAPACITY]>,
    borrowed: AtomicBool,
}

// SAFETY: Access to `pixels` is serialized by `borrowed`. The atomic guard is
// acquired before constructing a mutable reference and released only after
// the rendering closure has returned.
unsafe impl Sync for TerminalShadow {}

impl TerminalShadow {
    const fn new() -> Self {
        Self {
            pixels: UnsafeCell::new([0; SHADOW_CAPACITY]),
            borrowed: AtomicBool::new(false),
        }
    }

    fn with<R>(
        &self,
        operation: impl FnOnce(&mut [u8; SHADOW_CAPACITY]) -> R,
    ) -> Result<(R, usize), ShadowError> {
        if self
            .borrowed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(ShadowError::AlreadyBorrowed);
        }

        let _guard = ShadowBorrowGuard {
            borrowed: &self.borrowed,
        };

        let generation = SHADOW_GENERATION
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);

        // SAFETY: the atomic guard above guarantees exclusive access for the
        // complete lifetime of the closure.
        let result = unsafe { operation(&mut *self.pixels.get()) };

        Ok((result, generation))
    }
}

struct ShadowBorrowGuard<'a> {
    borrowed: &'a AtomicBool,
}

impl Drop for ShadowBorrowGuard<'_> {
    fn drop(&mut self) {
        self.borrowed.store(false, Ordering::Release);
    }
}

static TERMINAL_SHADOW: TerminalShadow = TerminalShadow::new();

pub(crate) fn with_render_shadow<R>(
    operation: impl FnOnce(&mut [u8; SHADOW_CAPACITY]) -> R,
) -> Result<R, ShadowError> {
    TERMINAL_SHADOW.with(operation).map(|(r, _)| r)
}

fn with_render_shadow_tracked<R>(
    operation: impl FnOnce(&mut [u8; SHADOW_CAPACITY]) -> R,
) -> Result<(R, usize), ShadowError> {
    TERMINAL_SHADOW.with(operation)
}

fn render_shadow_generation() -> usize {
    SHADOW_GENERATION.load(Ordering::Acquire)
}

#[derive(Clone, Copy)]
struct FontMetrics {
    advance: u32,
    glyph_height: u32,
    line_height: u32,
}

fn font_metrics(font: TextFont) -> FontMetrics {
    match font {
        TextFont::Cozette6x13 => FontMetrics {
            advance: 6,
            glyph_height: 13,
            line_height: 14,
        },
        TextFont::Tty8x16 => FontMetrics {
            advance: 8,
            glyph_height: 16,
            line_height: 17,
        },
        TextFont::Compact8x8 => FontMetrics {
            advance: 8,
            glyph_height: 8,
            line_height: 10,
        },
    }
}

#[derive(Clone, Copy)]
struct PixelRect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

impl PixelRect {
    fn right(self) -> u32 {
        self.x.saturating_add(self.width)
    }

    fn bottom(self) -> u32 {
        self.y.saturating_add(self.height)
    }

    fn is_vertically_adjacent_to(self, next: Self) -> bool {
        self.bottom() == next.y
    }

    fn merge_vertical(self, next: Self) -> Self {
        let x = self.x.min(next.x);
        let right = self.right().max(next.right());

        Self {
            x,
            y: self.y,
            width: right.saturating_sub(x),
            height: next.bottom().saturating_sub(self.y),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AnsiState {
    Ground,
    Escape,
    Csi,
    Osc,
    OscEscape,
}

const MAX_CSI_PARAMS: usize = 8;

/// Fixed-capacity text screen backed by a framebuffer `Canvas`.
pub struct Screen {
    canvas: Option<Canvas>,
    cells: Vec<[Cell; COLS]>,
    presented_cells: Vec<[Cell; COLS]>,
    scrollback: Vec<[Cell; COLS]>,
    scrollback_head: usize,
    scrollback_len: usize,
    scroll_offset: usize,

    active_fg: Color,
    active_bg: Color,
    sgr_bold: bool,
    sgr_dim: bool,
    sgr_reverse: bool,
    saved_cursor: (usize, usize),

    ansi_state: AnsiState,
    csi_params: [u16; MAX_CSI_PARAMS],
    csi_len: usize,
    csi_has_digit: bool,
    csi_private: bool,

    utf8_buf: [u8; 4],
    utf8_len: u8,
    utf8_need: u8,

    row: usize,
    col: usize,
    font: TextFont,
    cursor_visible: bool,
    app_cursor_hidden: bool,
    presented_cursor: Option<(usize, usize)>,

    dirty_rows: u64,
    dirty_from: [u16; ROWS],
    dirty_to: [u16; ROWS],
    pending_scroll_lines: usize,
    force_full_render: bool,
    chrome_dirty: bool,

    status_proc: String,
    status_pwd: String,
    status_caps: String,

    rendered_view_top: usize,
    observed_shadow_generation: usize,
}

#[allow(dead_code)]
impl Screen {
    pub fn new() -> Self {
        Self::new_with_cap(None)
    }

    pub fn new_with_cap(frame_draw: Option<HandleValue>) -> Self {
        let canvas = match frame_draw {
            Some(cap) => Canvas::new_fullscreen_with_cap(cap).ok(),
            None => Canvas::new_fullscreen().ok(),
        };
        Self {
            canvas,
            cells: vec![[DEFAULT_CELL; COLS]; ROWS],
            presented_cells: vec![[DEFAULT_CELL; COLS]; ROWS],
            scrollback: vec![[DEFAULT_CELL; COLS]; SCROLLBACK_CAP],
            scrollback_head: 0,
            scrollback_len: 0,
            scroll_offset: 0,
            active_fg: COLOR_TEXT,
            active_bg: COLOR_BACKGROUND,
            sgr_bold: false,
            sgr_dim: false,
            sgr_reverse: false,
            saved_cursor: (0, 0),
            ansi_state: AnsiState::Ground,
            csi_params: [0; MAX_CSI_PARAMS],
            csi_len: 0,
            csi_has_digit: false,
            csi_private: false,
            utf8_buf: [0; 4],
            utf8_len: 0,
            utf8_need: 0,
            row: 0,
            col: 0,
            font: TextFont::Cozette6x13,
            cursor_visible: true,
            app_cursor_hidden: false,
            presented_cursor: None,
            dirty_rows: ALL_ROWS_DIRTY,
            dirty_from: [0; ROWS],
            dirty_to: [COLS as u16; ROWS],
            pending_scroll_lines: 0,
            force_full_render: true,
            chrome_dirty: true,
            status_proc: String::from("hsh.elf"),
            status_pwd: String::from("/"),
            status_caps: String::from("HXFS:RW | BOOTFS:RO"),
            rendered_view_top: 0,
            observed_shadow_generation: render_shadow_generation(),
        }
    }

    pub fn has_framebuffer(&self) -> bool {
        self.canvas.is_some()
    }

    pub fn visible_size(&self) -> (usize, usize) {
        (self.active_columns(), self.active_rows())
    }

    pub fn invalidate(&mut self) {
        self.mark_all_dirty();
    }

    pub fn set_status_info(&mut self, proc_label: &str, pwd: &str, caps: &str) {
        if self.status_proc != proc_label || self.status_pwd != pwd || self.status_caps != caps {
            self.status_proc.clear();
            self.status_proc.push_str(proc_label);
            self.status_pwd.clear();
            self.status_pwd.push_str(pwd);
            self.status_caps.clear();
            self.status_caps.push_str(caps);
            self.chrome_dirty = true;
        }
    }

    pub fn scroll_up(&mut self, lines: usize) {
        let max_off = self.scrollback_len;
        let next = self.scroll_offset.saturating_add(lines).min(max_off);
        if next != self.scroll_offset {
            self.scroll_offset = next;
            self.chrome_dirty = true;
            self.mark_all_rows_dirty_no_clear();
        }
    }

    pub fn scroll_down(&mut self, lines: usize) {
        let next = self.scroll_offset.saturating_sub(lines);
        if next != self.scroll_offset {
            self.scroll_offset = next;
            self.chrome_dirty = true;
            self.mark_all_rows_dirty_no_clear();
        }
    }

    pub fn reset_scrollback(&mut self) {
        if self.scroll_offset != 0 {
            self.scroll_offset = 0;
            self.chrome_dirty = true;
            self.mark_all_rows_dirty_no_clear();
        }
    }

    pub fn clear(&mut self) {
        for r in self.cells.iter_mut() {
            *r = [DEFAULT_CELL; COLS];
        }
        self.scroll_offset = 0;
        self.reset_sgr();
        self.row = 0;
        self.col = 0;
        self.pending_scroll_lines = 0;
        self.chrome_dirty = true;
        self.mark_all_dirty();
    }

    pub fn write_line(&mut self, text: &str) {
        self.write_str(text);
        self.newline();
    }

    pub fn write_str(&mut self, text: &str) {
        self.write_bytes(text.as_bytes());
    }

    pub fn write_colored_bytes(&mut self, bytes: &[u8], color: Color) {
        let prev_fg = self.active_fg;
        let prev_bg = self.active_bg;
        let prev_rev = self.sgr_reverse;
        self.active_fg = color;
        self.active_bg = COLOR_BACKGROUND;
        self.sgr_reverse = false;
        self.write_bytes(bytes);
        self.active_fg = prev_fg;
        self.active_bg = prev_bg;
        self.sgr_reverse = prev_rev;
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_byte(byte);
        }
    }

    pub fn write_byte(&mut self, byte: u8) {
        match self.ansi_state {
            AnsiState::Ground => {
                if self.utf8_need > 0 {
                    if (byte & 0xC0) == 0x80 {
                        let idx = self.utf8_len as usize;
                        if idx < 4 {
                            self.utf8_buf[idx] = byte;
                            self.utf8_len += 1;
                        }
                        if self.utf8_len == self.utf8_need {
                            let len = self.utf8_len as usize;
                            self.utf8_len = 0;
                            self.utf8_need = 0;
                            let ch = core::str::from_utf8(&self.utf8_buf[..len])
                                .ok()
                                .and_then(|s| s.chars().next())
                                .unwrap_or('?');
                            self.write_char(ch);
                        }
                        return;
                    }
                    // Broken UTF-8 sequence: emit replacement and fall through to process `byte`.
                    self.utf8_len = 0;
                    self.utf8_need = 0;
                    self.write_char('?');
                }

                match byte {
                    0x1b => {
                        self.ansi_state = AnsiState::Escape;
                    }
                    b'\n' => self.newline(),
                    b'\r' => self.carriage_return(),
                    b'\t' => self.tab(),
                    0x08 => self.backspace(),
                    0x20..=0x7e => self.write_char(char::from(byte)),
                    0xC2..=0xDF => {
                        self.utf8_buf[0] = byte;
                        self.utf8_len = 1;
                        self.utf8_need = 2;
                    }
                    0xE0..=0xEF => {
                        self.utf8_buf[0] = byte;
                        self.utf8_len = 1;
                        self.utf8_need = 3;
                    }
                    0xF0..=0xF4 => {
                        self.utf8_buf[0] = byte;
                        self.utf8_len = 1;
                        self.utf8_need = 4;
                    }
                    // Ignore NUL, BEL, and other non-printable C0 controls; render invalid high bytes as `?`.
                    0x00..=0x1f | 0x7f => {}
                    _ => self.write_char('?'),
                }
            }
            AnsiState::Escape => match byte {
                b'[' => {
                    self.ansi_state = AnsiState::Csi;
                    self.csi_params = [0; MAX_CSI_PARAMS];
                    self.csi_len = 0;
                    self.csi_has_digit = false;
                    self.csi_private = false;
                }
                b']' => {
                    self.ansi_state = AnsiState::Osc;
                }
                b'7' => {
                    self.saved_cursor = (self.row, self.col);
                    self.ansi_state = AnsiState::Ground;
                }
                b'8' => {
                    let (r, c) = self.saved_cursor;
                    self.set_cursor(r, c);
                    self.ansi_state = AnsiState::Ground;
                }
                b'c' => {
                    self.ansi_state = AnsiState::Ground;
                    self.app_cursor_hidden = false;
                    self.clear();
                }
                _ => {
                    self.ansi_state = AnsiState::Ground;
                }
            },
            AnsiState::Osc => match byte {
                0x07 => self.ansi_state = AnsiState::Ground,
                0x1b => self.ansi_state = AnsiState::OscEscape,
                _ => {}
            },
            AnsiState::OscEscape => {
                self.ansi_state = AnsiState::Ground;
            }
            AnsiState::Csi => match byte {
                b'?' if self.csi_len == 0 && !self.csi_has_digit => {
                    self.csi_private = true;
                }
                b'0'..=b'9' => {
                    if !self.csi_has_digit {
                        self.csi_has_digit = true;
                        if self.csi_len == 0 {
                            self.csi_len = 1;
                        }
                    }
                    let slot = self.csi_len.saturating_sub(1);
                    if slot < MAX_CSI_PARAMS {
                        self.csi_params[slot] = self.csi_params[slot]
                            .saturating_mul(10)
                            .saturating_add(u16::from(byte - b'0'));
                    }
                }
                b';' | b':' => {
                    if !self.csi_has_digit && self.csi_len == 0 {
                        self.csi_len = 1;
                    }
                    if self.csi_len < MAX_CSI_PARAMS {
                        self.csi_len += 1;
                    }
                    self.csi_has_digit = false;
                }
                0x20..=0x2f => {
                    // Intermediate bytes; keep waiting for the final byte.
                }
                0x40..=0x7e => {
                    self.ansi_state = AnsiState::Ground;
                    self.dispatch_csi(byte);
                }
                _ => {
                    self.ansi_state = AnsiState::Ground;
                }
            },
        }
    }

    fn reset_sgr(&mut self) {
        self.active_fg = COLOR_TEXT;
        self.active_bg = COLOR_BACKGROUND;
        self.sgr_bold = false;
        self.sgr_dim = false;
        self.sgr_reverse = false;
    }

    fn effective_colors(&self) -> (Color, Color) {
        let mut fg = self.active_fg;
        let bg = self.active_bg;
        if self.sgr_bold {
            fg = (
                fg.0.saturating_add(36),
                fg.1.saturating_add(36),
                fg.2.saturating_add(36),
            );
        } else if self.sgr_dim {
            fg = (
                ((u16::from(fg.0) * 2) / 3) as u8,
                ((u16::from(fg.1) * 2) / 3) as u8,
                ((u16::from(fg.2) * 2) / 3) as u8,
            );
        }
        if self.sgr_reverse {
            (bg, fg)
        } else {
            (fg, bg)
        }
    }

    fn dispatch_csi(&mut self, final_byte: u8) {
        let p0 = if self.csi_len >= 1 {
            self.csi_params[0]
        } else {
            0
        };
        let p1 = if self.csi_len >= 2 {
            self.csi_params[1]
        } else {
            0
        };

        if self.csi_private {
            match (p0, final_byte) {
                (25, b'l') => {
                    self.app_cursor_hidden = true;
                    if self.scroll_offset == 0 {
                        self.mark_dirty_span(
                            self.row,
                            self.col,
                            self.col.saturating_add(1).min(COLS),
                        );
                    }
                }
                (25, b'h') => {
                    self.app_cursor_hidden = false;
                    if self.scroll_offset == 0 {
                        self.mark_dirty_span(
                            self.row,
                            self.col,
                            self.col.saturating_add(1).min(COLS),
                        );
                    }
                }
                (1049, b'h') | (1049, b'l') | (47, b'h') | (47, b'l') => {
                    self.erase_display(2);
                    self.set_cursor(0, 0);
                }
                _ => {}
            }
            return;
        }

        match final_byte {
            b'H' | b'f' => {
                let row = usize::from(p0.max(1)) - 1;
                let col = usize::from(p1.max(1)) - 1;
                self.set_cursor(row, col);
            }
            b'A' => {
                let n = usize::from(p0.max(1));
                self.set_cursor(self.row.saturating_sub(n), self.col);
            }
            b'B' => {
                let n = usize::from(p0.max(1));
                self.set_cursor(self.row.saturating_add(n), self.col);
            }
            b'C' => {
                let n = usize::from(p0.max(1));
                self.set_cursor(self.row, self.col.saturating_add(n));
            }
            b'D' => {
                let n = usize::from(p0.max(1));
                self.set_cursor(self.row, self.col.saturating_sub(n));
            }
            b'G' => {
                let col = usize::from(p0.max(1)) - 1;
                self.set_cursor(self.row, col);
            }
            b'J' => {
                self.erase_display(p0);
            }
            b'K' => {
                self.erase_line(p0);
            }
            b's' => {
                self.saved_cursor = (self.row, self.col);
            }
            b'u' => {
                let (r, c) = self.saved_cursor;
                self.set_cursor(r, c);
            }
            b'm' => {
                self.apply_sgr();
            }
            _ => {}
        }
    }

    fn erase_display(&mut self, mode: u16) {
        let vis_rows = self.active_rows();
        match mode {
            0 => {
                let r0 = self.row.min(vis_rows.saturating_sub(1));
                let c0 = self.col.min(COLS);
                for r in r0..vis_rows {
                    let from_c = if r == r0 { c0 } else { 0 };
                    for c in from_c..COLS {
                        self.cells[r][c] = DEFAULT_CELL;
                    }
                    self.mark_dirty_span(r, from_c, COLS);
                }
            }
            1 => {
                let r_end = self.row.min(vis_rows.saturating_sub(1));
                for r in 0..=r_end {
                    let to_c = if r == r_end {
                        self.col.saturating_add(1).min(COLS)
                    } else {
                        COLS
                    };
                    for c in 0..to_c {
                        self.cells[r][c] = DEFAULT_CELL;
                    }
                    self.mark_dirty_span(r, 0, to_c);
                }
            }
            2 | 3 => {
                // Erase all visible rows via `mark_dirty_span` (not `force_full_render`)
                // so `presented_cells` diffing only redraws cells that actually changed!
                for r in 0..vis_rows {
                    self.cells[r] = [DEFAULT_CELL; COLS];
                    self.mark_dirty_span(r, 0, COLS);
                }
                self.scroll_offset = 0;
            }
            _ => {}
        }
    }

    fn erase_line(&mut self, mode: u16) {
        let r = self.row.min(ROWS - 1);
        match mode {
            0 => {
                let from_c = self.col.min(COLS);
                for c in from_c..COLS {
                    self.cells[r][c] = DEFAULT_CELL;
                }
                self.mark_dirty_span(r, from_c, COLS);
            }
            1 => {
                let to_c = self.col.saturating_add(1).min(COLS);
                for c in 0..to_c {
                    self.cells[r][c] = DEFAULT_CELL;
                }
                self.mark_dirty_span(r, 0, to_c);
            }
            2 => {
                self.cells[r] = [DEFAULT_CELL; COLS];
                self.mark_dirty_span(r, 0, COLS);
            }
            _ => {}
        }
    }

    fn apply_sgr(&mut self) {
        if self.csi_len == 0 {
            self.reset_sgr();
            return;
        }
        let mut idx = 0usize;
        while idx < self.csi_len {
            let code = self.csi_params[idx];
            match code {
                0 => self.reset_sgr(),
                1 => {
                    self.sgr_bold = true;
                    self.sgr_dim = false;
                }
                2 => {
                    self.sgr_dim = true;
                    self.sgr_bold = false;
                }
                7 => self.sgr_reverse = true,
                22 => {
                    self.sgr_bold = false;
                    self.sgr_dim = false;
                }
                27 => self.sgr_reverse = false,
                30..=37 => self.active_fg = ansi_16_palette((code - 30) as u8),
                39 => self.active_fg = COLOR_TEXT,
                40..=47 => self.active_bg = ansi_16_palette((code - 40) as u8),
                49 => self.active_bg = COLOR_BACKGROUND,
                90..=97 => self.active_fg = ansi_16_palette((code - 90 + 8) as u8),
                100..=107 => self.active_bg = ansi_16_palette((code - 100 + 8) as u8),
                38 | 48 => {
                    let is_fg = code == 38;
                    let mode = if idx + 1 < self.csi_len {
                        self.csi_params[idx + 1]
                    } else {
                        0
                    };
                    if mode == 5 && idx + 2 < self.csi_len {
                        let color = ansi_256_palette(self.csi_params[idx + 2] as u8);
                        if is_fg {
                            self.active_fg = color;
                        } else {
                            self.active_bg = color;
                        }
                        idx += 3;
                        continue;
                    } else if mode == 2 && idx + 4 < self.csi_len {
                        let color = (
                            self.csi_params[idx + 2].min(255) as u8,
                            self.csi_params[idx + 3].min(255) as u8,
                            self.csi_params[idx + 4].min(255) as u8,
                        );
                        if is_fg {
                            self.active_fg = color;
                        } else {
                            self.active_bg = color;
                        }
                        idx += 5;
                        continue;
                    }
                }
                _ => {}
            }
            idx += 1;
        }
    }

    /// Place one character in the grid.
    ///
    /// The font covers ASCII plus the generated box/block/Braille glyphs; a
    /// character outside that set is drawn as `?`, so a program can never
    /// scribble an unrenderable codepoint into the framebuffer.
    pub fn write_char(&mut self, ch: char) {
        let code = ch as u32;
        let supported = (0x20..=0x7e).contains(&code)
            || (0x2500..=0x2593).contains(&code)
            || (0x2800..=0x28ff).contains(&code);
        let glyph = if supported { ch } else { '?' };
        self.write_printable(glyph);
    }

    pub fn backspace(&mut self) {
        if self.col == 0 {
            return;
        }
        let old_col = self.col;
        self.col -= 1;
        self.cells[self.row][self.col] = DEFAULT_CELL;
        self.chrome_dirty = true;
        self.mark_dirty_span(self.row, self.col, old_col.saturating_add(1).min(COLS));
    }

    pub fn carriage_return(&mut self) {
        if self.col == 0 {
            return;
        }
        let old_col = self.col;
        self.col = 0;
        self.chrome_dirty = true;
        self.mark_dirty_span(self.row, 0, old_col.saturating_add(1).min(COLS));
    }

    pub fn newline(&mut self) {
        let old_row = self.row;
        let old_col = self.col;
        self.col = 0;
        self.chrome_dirty = true;

        if self.row + 1 >= self.active_rows() {
            self.scroll();
            return;
        }

        self.row += 1;
        self.mark_dirty_span(old_row, old_col, old_col.saturating_add(1).min(COLS));
        self.mark_dirty_span(self.row, 0, 1);
    }

    pub fn set_fg(&mut self, color: Color) {
        self.active_fg = color;
    }

    pub fn reset_fg(&mut self) {
        self.active_fg = COLOR_TEXT;
    }

    pub fn write_colored(&mut self, text: &str, color: Color) {
        let prev = self.active_fg;
        self.active_fg = color;
        self.write_str(text);
        self.active_fg = prev;
    }

    pub fn current_row(&self) -> usize {
        self.row
    }

    pub fn set_cursor(&mut self, row: usize, col: usize) {
        let old_row = self.row;
        let old_col = self.col;
        let next_row = row.min(self.active_rows().saturating_sub(1));
        let next_col = col.min(COLS - 1);
        if next_row != old_row || next_col != old_col {
            self.chrome_dirty = true;
        }
        self.row = next_row;
        self.col = next_col;
        self.mark_dirty_span(old_row, old_col, old_col.saturating_add(1).min(COLS));
        self.mark_dirty_span(self.row, self.col, self.col.saturating_add(1).min(COLS));
    }

    pub fn clear_from(&mut self, start_row: usize, start_col: usize) {
        let vis_rows = self.active_rows();
        let r0 = start_row.min(vis_rows.saturating_sub(1));
        let c0 = start_col.min(COLS);
        for r in r0..vis_rows {
            let from_c = if r == r0 { c0 } else { 0 };
            for c in from_c..COLS {
                self.cells[r][c] = DEFAULT_CELL;
            }
            self.mark_dirty_span(r, from_c, COLS);
        }
        self.row = r0;
        self.col = c0.min(COLS - 1);
        self.chrome_dirty = true;
    }

    /// Show or hide the cursor. Marks ONLY the single cursor cell dirty so idle
    /// cursor blinking never triggers full-row or chrome redraws.
    pub fn set_cursor_visible(&mut self, visible: bool) {
        if self.cursor_visible == visible {
            return;
        }
        self.cursor_visible = visible;
        if self.scroll_offset == 0 {
            self.mark_dirty_span(self.row, self.col, self.col.saturating_add(1).min(COLS));
        }
    }

    pub fn use_cozette_font(&mut self) {
        self.font = TextFont::Cozette6x13;
        self.chrome_dirty = true;
        self.mark_all_dirty();
    }

    pub fn use_tty_font(&mut self) {
        self.font = TextFont::Tty8x16;
        self.chrome_dirty = true;
        self.mark_all_dirty();
    }

    pub fn use_compact_font(&mut self) {
        self.font = TextFont::Compact8x8;
        self.chrome_dirty = true;
        self.mark_all_dirty();
    }

    pub fn font_name(&self) -> &'static str {
        match self.font {
            TextFont::Cozette6x13 => "cozette 6x13",
            TextFont::Tty8x16 => "tty 8x16",
            TextFont::Compact8x8 => "compact 8x8",
        }
    }

    pub fn render(&mut self) {
        let shared_generation = render_shadow_generation();
        if shared_generation != self.observed_shadow_generation {
            self.mark_all_dirty();
        }

        let view_top = self.viewport_top();
        if view_top != self.rendered_view_top {
            self.mark_all_dirty();
        }

        if self.dirty_rows == 0
            && !self.force_full_render
            && !self.chrome_dirty
            && self.pending_scroll_lines == 0
        {
            return;
        }

        let mut committed_generation = None;
        let rendered = if let Some(canvas) = self.canvas.take() {
            let ok = if canvas.supports_buffered_raster() && canvas.byte_len() <= SHADOW_CAPACITY {
                let dirty_rows = self.dirty_rows;
                let force_full = self.force_full_render;
                let chrome_dirty = self.chrome_dirty;
                let scroll_shift = self.pending_scroll_lines;

                match with_render_shadow_tracked(|shadow| {
                    if force_full {
                        self.render_full_buffered(&canvas, shadow, view_top)
                    } else {
                        let mut ok = true;
                        if scroll_shift > 0 && self.scroll_offset == 0 {
                            ok = self.render_scroll_shifted_buffered(
                                &canvas,
                                shadow,
                                scroll_shift,
                                view_top,
                            );
                        } else if dirty_rows != 0 {
                            ok = self.render_dirty_buffered(&canvas, shadow, dirty_rows, view_top);
                        }
                        if ok && chrome_dirty {
                            ok = self.render_chrome_buffered(&canvas, shadow);
                        }
                        ok
                    }
                }) {
                    Ok((result, generation)) => {
                        committed_generation = Some(generation);
                        result
                    }
                    Err(_) => false,
                }
            } else {
                self.render_full_fallback(&canvas, view_top)
            };
            self.canvas = Some(canvas);
            ok
        } else {
            true
        };

        if rendered {
            self.sync_presented_grid(view_top);
            self.clear_dirty_tracking();
            self.force_full_render = false;
            self.chrome_dirty = false;
            self.pending_scroll_lines = 0;
            self.rendered_view_top = view_top;
            self.observed_shadow_generation =
                committed_generation.unwrap_or_else(render_shadow_generation);
        }
    }

    fn write_printable(&mut self, ch: char) {
        let wrap_columns = self.active_columns();
        if self.col >= wrap_columns || self.col >= COLS {
            self.newline();
        }
        let row = self.row;
        let column = self.col;
        let (fg, bg) = self.effective_colors();
        self.cells[row][column] = Cell {
            ch,
            fg,
            bg,
            flags: 0,
        };
        self.col += 1;
        self.chrome_dirty = true;
        let end = self.col.saturating_add(1).min(COLS);
        self.mark_dirty_span(row, column, end);
    }

    fn tab(&mut self) {
        let columns = self.active_columns();
        if self.col >= columns {
            self.newline();
        }
        let tab_end = ((self.col / TAB_WIDTH) + 1)
            .saturating_mul(TAB_WIDTH)
            .min(columns);
        while self.col < tab_end {
            self.write_printable(' ');
        }
    }

    fn push_scrollback_row(&mut self, row: [Cell; COLS]) {
        self.scrollback[self.scrollback_head] = row;
        self.scrollback_head = (self.scrollback_head + 1) % SCROLLBACK_CAP;
        if self.scrollback_len < SCROLLBACK_CAP {
            self.scrollback_len += 1;
        }
    }

    fn scroll(&mut self) {
        let vis_rows = self.active_rows().min(ROWS);
        self.push_scrollback_row(self.cells[0]);
        for dst in 0..vis_rows.saturating_sub(1) {
            self.cells[dst] = self.cells[dst + 1];
        }
        self.cells[vis_rows.saturating_sub(1)] = [DEFAULT_CELL; COLS];
        self.row = vis_rows.saturating_sub(1);
        self.col = 0;
        self.chrome_dirty = true;

        if self.scroll_offset == 0 {
            self.pending_scroll_lines = self.pending_scroll_lines.saturating_add(1);
            if self.pending_scroll_lines >= vis_rows {
                self.mark_all_dirty();
            } else {
                // Shift dirty flags upward and mark the new bottom row dirty.
                self.dirty_rows >>= 1;
                for r in 0..vis_rows.saturating_sub(1) {
                    self.dirty_from[r] = self.dirty_from[r + 1];
                    self.dirty_to[r] = self.dirty_to[r + 1];
                }
                let last = vis_rows.saturating_sub(1);
                self.dirty_from[last] = CLEAN_COLUMN;
                self.dirty_to[last] = 0;
                self.mark_dirty_span(last, 0, COLS);
            }
        }
    }

    fn active_columns(&self) -> usize {
        self.canvas
            .as_ref()
            .map(|c| self.visible_columns_for(c))
            .unwrap_or(COLS)
    }

    fn active_rows(&self) -> usize {
        self.canvas
            .as_ref()
            .map(|c| self.visible_rows_for(c))
            .unwrap_or(ROWS)
    }

    fn visible_columns_for(&self, canvas: &Canvas) -> usize {
        let metrics = font_metrics(self.font);
        let available = canvas.width().saturating_sub(LEFT_MARGIN * 2);
        (available / metrics.advance).max(1).min(COLS as u32) as usize
    }

    fn visible_rows_for(&self, canvas: &Canvas) -> usize {
        let metrics = font_metrics(self.font);
        let reserved = TOP_MARGIN.saturating_add(FOOTER_HEIGHT + 4);
        let available = canvas.height().saturating_sub(reserved);
        (available / metrics.line_height).max(1).min(ROWS as u32) as usize
    }

    fn viewport_top(&self) -> usize {
        let visible_rows = self.active_rows();
        if self.row < visible_rows {
            0
        } else {
            self.row + 1 - visible_rows
        }
    }

    fn row_for_display(&self, view_top: usize, display_row: usize) -> &[Cell; COLS] {
        let visible_rows = self.active_rows();
        if self.scroll_offset == 0 {
            let mr = (view_top + display_row).min(ROWS - 1);
            return &self.cells[mr];
        }
        // Chronological order: [oldest scrollback .. newest scrollback, live[0..visible_rows]]
        // Total lines = scrollback_len + visible_rows.
        // Visible window ends at `total - scroll_offset`.
        let total = self.scrollback_len + visible_rows;
        let end = total.saturating_sub(self.scroll_offset);
        let start = end.saturating_sub(visible_rows);
        let idx = start + display_row;
        if idx < self.scrollback_len {
            let oldest = if self.scrollback_len == SCROLLBACK_CAP {
                self.scrollback_head
            } else {
                0
            };
            let ring_idx = (oldest + idx) % SCROLLBACK_CAP;
            &self.scrollback[ring_idx]
        } else {
            let live_idx = (idx - self.scrollback_len).min(ROWS - 1);
            &self.cells[live_idx]
        }
    }

    fn mark_dirty_span(&mut self, row: usize, start_column: usize, end_column: usize) {
        if row >= ROWS {
            return;
        }
        let start = start_column.min(COLS);
        let end = end_column.min(COLS);
        if start >= end {
            return;
        }
        self.dirty_rows |= 1u64 << row;
        self.dirty_from[row] = self.dirty_from[row].min(start as u16);
        self.dirty_to[row] = self.dirty_to[row].max(end as u16);
    }

    fn mark_all_rows_dirty_no_clear(&mut self) {
        let vis = self.active_rows().min(ROWS);
        for r in 0..vis {
            self.dirty_rows |= 1u64 << r;
            self.dirty_from[r] = 0;
            self.dirty_to[r] = COLS as u16;
        }
        self.pending_scroll_lines = 0;
    }

    fn mark_all_dirty(&mut self) {
        self.dirty_rows = ALL_ROWS_DIRTY;
        self.dirty_from = [0; ROWS];
        self.dirty_to = [COLS as u16; ROWS];
        self.pending_scroll_lines = 0;
        self.force_full_render = true;
        self.chrome_dirty = true;
    }

    fn clear_dirty_tracking(&mut self) {
        self.dirty_rows = 0;
        self.dirty_from = [CLEAN_COLUMN; ROWS];
        self.dirty_to = [0; ROWS];
    }

    fn sync_presented_grid(&mut self, view_top: usize) {
        let visible_rows = self.active_rows().min(ROWS);
        for display_row in 0..visible_rows {
            let row_data = *self.row_for_display(view_top, display_row);
            self.presented_cells[display_row] = row_data;
        }
        self.presented_cursor =
            if self.cursor_visible && !self.app_cursor_hidden && self.scroll_offset == 0 {
                Some((self.row.saturating_sub(view_top), self.col))
            } else {
                None
            };
    }

    fn render_chrome_to_shadow(&self, canvas: &Canvas, shadow: &mut [u8; SHADOW_CAPACITY]) -> bool {
        let w = canvas.width();
        let h = canvas.height();
        let footer_y = h.saturating_sub(FOOTER_HEIGHT);

        // Top header bar + 1px divider
        if canvas
            .fill_rect_to_shadow(
                shadow,
                0,
                0,
                w,
                HEADER_HEIGHT,
                COLOR_CHROME_BG.0,
                COLOR_CHROME_BG.1,
                COLOR_CHROME_BG.2,
            )
            .is_err()
        {
            return false;
        }
        if canvas
            .fill_rect_to_shadow(
                shadow,
                0,
                HEADER_HEIGHT,
                w,
                1,
                COLOR_DIVIDER.0,
                COLOR_DIVIDER.1,
                COLOR_DIVIDER.2,
            )
            .is_err()
        {
            return false;
        }

        let left_hdr = format!("HuesOS  |  {}", self.status_proc);
        let right_hdr = format!("cwd: {}  |  CAPS: {}", self.status_pwd, self.status_caps);
        let _ = canvas.draw_text_to_shadow(
            shadow,
            LEFT_MARGIN,
            5,
            &left_hdr,
            COLOR_ACCENT.0,
            COLOR_ACCENT.1,
            COLOR_ACCENT.2,
            TextFont::Cozette6x13,
        );
        let right_w = right_hdr.len() as u32 * 6;
        let rx = w.saturating_sub(right_w + LEFT_MARGIN);
        if rx > LEFT_MARGIN + left_hdr.len() as u32 * 6 + 12 {
            let _ = canvas.draw_text_to_shadow(
                shadow,
                rx,
                5,
                &right_hdr,
                COLOR_TEXT.0,
                COLOR_TEXT.1,
                COLOR_TEXT.2,
                TextFont::Cozette6x13,
            );
        }

        // Bottom status bar + 1px divider
        if footer_y > HEADER_HEIGHT + 2 {
            if canvas
                .fill_rect_to_shadow(
                    shadow,
                    0,
                    footer_y - 1,
                    w,
                    1,
                    COLOR_DIVIDER.0,
                    COLOR_DIVIDER.1,
                    COLOR_DIVIDER.2,
                )
                .is_err()
            {
                return false;
            }
            if canvas
                .fill_rect_to_shadow(
                    shadow,
                    0,
                    footer_y,
                    w,
                    FOOTER_HEIGHT,
                    COLOR_CHROME_BG.0,
                    COLOR_CHROME_BG.1,
                    COLOR_CHROME_BG.2,
                )
                .is_err()
            {
                return false;
            }
            let left_ftr = format!(
                "Ln {}, Col {}  |  {}",
                self.row + 1,
                self.col + 1,
                self.font_name()
            );
            let _ = canvas.draw_text_to_shadow(
                shadow,
                LEFT_MARGIN,
                footer_y + 4,
                &left_ftr,
                COLOR_MUTED.0,
                COLOR_MUTED.1,
                COLOR_MUTED.2,
                TextFont::Cozette6x13,
            );

            let (scroll_txt, scroll_col) = if self.scroll_offset > 0 {
                (
                    format!("SCROLLBACK -{}/{}", self.scroll_offset, self.scrollback_len),
                    COLOR_AMBER,
                )
            } else {
                (String::from("LIVE  |  PgUp/PgDn scroll"), COLOR_ACCENT)
            };
            let sw = scroll_txt.len() as u32 * 6;
            let sx = w.saturating_sub(sw + LEFT_MARGIN);
            if sx > LEFT_MARGIN + left_ftr.len() as u32 * 6 + 12 {
                let _ = canvas.draw_text_to_shadow(
                    shadow,
                    sx,
                    footer_y + 4,
                    &scroll_txt,
                    scroll_col.0,
                    scroll_col.1,
                    scroll_col.2,
                    TextFont::Cozette6x13,
                );
            }
        }
        true
    }

    fn render_chrome_buffered(&self, canvas: &Canvas, shadow: &mut [u8; SHADOW_CAPACITY]) -> bool {
        if !self.render_chrome_to_shadow(canvas, shadow) {
            return false;
        }
        let w = canvas.width();
        let h = canvas.height();
        let top_rect = PixelRect {
            x: 0,
            y: 0,
            width: w,
            height: HEADER_HEIGHT + 1,
        };
        if !flush_shadow_rect(canvas, shadow, top_rect) {
            return false;
        }
        let footer_y = h.saturating_sub(FOOTER_HEIGHT);
        if footer_y > HEADER_HEIGHT + 2 {
            let bot_rect = PixelRect {
                x: 0,
                y: footer_y - 1,
                width: w,
                height: FOOTER_HEIGHT + 1,
            };
            if !flush_shadow_rect(canvas, shadow, bot_rect) {
                return false;
            }
        }
        true
    }

    fn render_full_buffered(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        view_top: usize,
    ) -> bool {
        if canvas
            .clear_shadow(
                shadow,
                COLOR_BACKGROUND.0,
                COLOR_BACKGROUND.1,
                COLOR_BACKGROUND.2,
            )
            .is_err()
        {
            return false;
        }
        if !self.render_chrome_to_shadow(canvas, shadow) {
            return false;
        }
        let visible_rows = self.visible_rows_for(canvas);
        for display_row in 0..visible_rows {
            if !self.draw_complete_row_to_shadow(canvas, shadow, view_top, display_row) {
                return false;
            }
        }
        canvas.upload_shadow(shadow).is_ok() && canvas.present().is_ok()
    }

    fn render_scroll_shifted_buffered(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        shift_rows: usize,
        view_top: usize,
    ) -> bool {
        let visible_rows = self.visible_rows_for(canvas);
        let metrics = font_metrics(self.font);
        let pitch = canvas.byte_len() / (canvas.height().max(1) as usize);
        let shift_px = shift_rows as u32 * metrics.line_height;
        let viewport_h = visible_rows as u32 * metrics.line_height;

        if shift_px >= viewport_h {
            return self.render_full_buffered(canvas, shadow, view_top);
        }

        // Erase the previous cursor glyph/bar before shifting pixels if it was visible.
        if let Some((old_dr, old_c)) = self.presented_cursor {
            if old_dr < visible_rows {
                let _ = self.redraw_single_cell_in_shadow(
                    canvas,
                    shadow,
                    &self.presented_cells[old_dr][old_c],
                    old_dr,
                    old_c,
                );
            }
        }

        // Fast block shift upward inside `shadow`.
        let copy_h = viewport_h - shift_px;
        let src_start = (TOP_MARGIN + shift_px) as usize * pitch;
        let dst_start = TOP_MARGIN as usize * pitch;
        let byte_count = copy_h as usize * pitch;
        if dst_start + byte_count <= shadow.len() && src_start + byte_count <= shadow.len() {
            shadow.copy_within(src_start..src_start + byte_count, dst_start);
        }

        // Clear newly revealed bottom lines and draw them + any dirty rows in the shifted band.
        let new_start_row = visible_rows.saturating_sub(shift_rows);
        let clear_y = TOP_MARGIN + new_start_row as u32 * metrics.line_height;
        if canvas
            .fill_rect_to_shadow(
                shadow,
                0,
                clear_y,
                canvas.width(),
                shift_px,
                COLOR_BACKGROUND.0,
                COLOR_BACKGROUND.1,
                COLOR_BACKGROUND.2,
            )
            .is_err()
        {
            return false;
        }

        for dr in 0..visible_rows {
            if dr >= new_start_row {
                if !self.draw_complete_row_to_shadow(canvas, shadow, view_top, dr) {
                    return false;
                }
            } else {
                let mr = view_top + dr;
                if mr < ROWS
                    && (self.dirty_rows & (1u64 << mr)) != 0
                    && self
                        .render_row_region_to_shadow(canvas, shadow, view_top, mr, dr)
                        .is_err()
                {
                    return false;
                }
            }
        }

        // Ensure current cursor is drawn cleanly.
        let visible_cols = self.visible_columns_for(canvas);
        if self.cursor_visible && self.row >= view_top {
            let cur_dr = self.row - view_top;
            if cur_dr < visible_rows && self.col < visible_cols {
                let _ = self.draw_cursor_at_to_shadow(canvas, shadow, cur_dr, self.col);
            }
        }

        let rect = PixelRect {
            x: 0,
            y: TOP_MARGIN,
            width: canvas.width(),
            height: viewport_h.min(canvas.height().saturating_sub(TOP_MARGIN)),
        };
        flush_shadow_rect(canvas, shadow, rect)
    }

    fn render_dirty_buffered(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        dirty_rows: u64,
        view_top: usize,
    ) -> bool {
        let visible_rows = self.visible_rows_for(canvas);
        let view_end = view_top.saturating_add(visible_rows).min(ROWS);
        let mut pending_rect: Option<PixelRect> = None;

        for model_row in view_top..view_end {
            if dirty_rows & (1u64 << model_row) == 0 {
                continue;
            }
            let display_row = model_row - view_top;
            let rect = match self.render_row_region_to_shadow(
                canvas,
                shadow,
                view_top,
                model_row,
                display_row,
            ) {
                Ok(r) => r,
                Err(()) => return false,
            };
            if let Some(rect) = rect {
                match pending_rect {
                    Some(pending) if pending.is_vertically_adjacent_to(rect) => {
                        pending_rect = Some(pending.merge_vertical(rect));
                    }
                    Some(pending) => {
                        if !flush_shadow_rect(canvas, shadow, pending) {
                            return false;
                        }
                        pending_rect = Some(rect);
                    }
                    None => pending_rect = Some(rect),
                }
            }
        }
        if let Some(rect) = pending_rect {
            flush_shadow_rect(canvas, shadow, rect)
        } else {
            true
        }
    }

    fn draw_complete_row_to_shadow(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        view_top: usize,
        display_row: usize,
    ) -> bool {
        let visible_columns = self.visible_columns_for(canvas);
        let row_cells = self.row_for_display(view_top, display_row);
        let len = cell_line_len(row_cells).min(visible_columns);
        let metrics = font_metrics(self.font);
        let y = self.display_row_y(display_row);

        let mut col = 0usize;
        while col < len {
            let color = row_cells[col].fg;
            let bg = row_cells[col].bg;
            let mut end = col + 1;
            while end < len && row_cells[end].fg == color && row_cells[end].bg == bg {
                end += 1;
            }
            let rx = LEFT_MARGIN.saturating_add(col as u32 * metrics.advance);
            if bg != COLOR_BACKGROUND {
                let bg_w =
                    ((end - col) as u32 * metrics.advance).min(canvas.width().saturating_sub(rx));
                let bg_h = metrics.line_height.min(canvas.height().saturating_sub(y));
                if canvas
                    .fill_rect_to_shadow(shadow, rx, y, bg_w, bg_h, bg.0, bg.1, bg.2)
                    .is_err()
                {
                    return false;
                }
            }
            let mut buf = [0u8; COLS * 4];
            let mut used = 0;
            for cell in &row_cells[col..end] {
                used += cell.ch.encode_utf8(&mut buf[used..]).len();
            }
            let Ok(text) = core::str::from_utf8(&buf[..used]) else {
                return false;
            };
            if canvas
                .draw_text_to_shadow(shadow, rx, y, text, color.0, color.1, color.2, self.font)
                .is_err()
            {
                return false;
            }
            col = end;
        }

        if self.scroll_offset == 0
            && self.cursor_visible
            && !self.app_cursor_hidden
            && (view_top + display_row) == self.row
            && self.col < visible_columns
        {
            self.draw_cursor_at_to_shadow(canvas, shadow, display_row, self.col)
        } else {
            true
        }
    }

    fn render_row_region_to_shadow(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        view_top: usize,
        model_row: usize,
        display_row: usize,
    ) -> Result<Option<PixelRect>, ()> {
        let metrics = font_metrics(self.font);
        let visible_columns = self.visible_columns_for(canvas);
        let row_cells = self.row_for_display(view_top, display_row);

        let mut start_column = (self.dirty_from[model_row] as usize).min(visible_columns);
        let mut end_column = (self.dirty_to[model_row] as usize).min(visible_columns);

        // Trim unchanged cells against `presented_cells` (except cursor cell).
        let is_cur_row = self.scroll_offset == 0 && model_row == self.row;
        let old_cur_here = self
            .presented_cursor
            .is_some_and(|(dr, _)| dr == display_row);
        while start_column < end_column {
            let cur_touch = (is_cur_row && start_column == self.col)
                || (old_cur_here
                    && self
                        .presented_cursor
                        .is_some_and(|(_, c)| c == start_column));
            if !cur_touch
                && row_cells[start_column] == self.presented_cells[display_row][start_column]
            {
                start_column += 1;
            } else {
                break;
            }
        }
        while end_column > start_column {
            let c = end_column - 1;
            let cur_touch = (is_cur_row && c == self.col)
                || (old_cur_here && self.presented_cursor.is_some_and(|(_, oc)| oc == c));
            if !cur_touch && row_cells[c] == self.presented_cells[display_row][c] {
                end_column -= 1;
            } else {
                break;
            }
        }

        if start_column >= end_column {
            return Ok(None);
        }

        let x = LEFT_MARGIN.saturating_add(start_column as u32 * metrics.advance);
        let y = self.display_row_y(display_row);
        if x >= canvas.width() || y >= canvas.height() {
            return Ok(None);
        }

        let requested_width = (end_column - start_column) as u32 * metrics.advance;
        let width = requested_width.min(canvas.width().saturating_sub(x));
        let height = metrics.line_height.min(canvas.height().saturating_sub(y));
        if width == 0 || height == 0 {
            return Ok(None);
        }

        canvas
            .fill_rect_to_shadow(
                shadow,
                x,
                y,
                width,
                height,
                COLOR_BACKGROUND.0,
                COLOR_BACKGROUND.1,
                COLOR_BACKGROUND.2,
            )
            .map_err(|_| ())?;

        let text_end = cell_line_len(row_cells).min(end_column);
        let mut col = start_column;
        while col < text_end {
            let color = row_cells[col].fg;
            let bg = row_cells[col].bg;
            let mut run_end = col + 1;
            while run_end < text_end
                && row_cells[run_end].fg == color
                && row_cells[run_end].bg == bg
            {
                run_end += 1;
            }
            let rx = LEFT_MARGIN.saturating_add(col as u32 * metrics.advance);
            if bg != COLOR_BACKGROUND {
                let bg_w = ((run_end - col) as u32 * metrics.advance)
                    .min(canvas.width().saturating_sub(rx));
                canvas
                    .fill_rect_to_shadow(shadow, rx, y, bg_w, height, bg.0, bg.1, bg.2)
                    .map_err(|_| ())?;
            }
            let mut buf = [0u8; COLS * 4];
            let mut used = 0;
            for cell in &row_cells[col..run_end] {
                used += cell.ch.encode_utf8(&mut buf[used..]).len();
            }
            let Ok(text) = core::str::from_utf8(&buf[..used]) else {
                return Err(());
            };
            canvas
                .draw_text_to_shadow(shadow, rx, y, text, color.0, color.1, color.2, self.font)
                .map_err(|_| ())?;
            col = run_end;
        }

        if self.scroll_offset == 0
            && self.cursor_visible
            && !self.app_cursor_hidden
            && model_row == self.row
            && self.col >= start_column
            && self.col < end_column
            && self.col < visible_columns
        {
            self.draw_cursor_at_to_shadow(canvas, shadow, display_row, self.col)
                .then_some(())
                .ok_or(())?;
        }

        Ok(Some(PixelRect {
            x,
            y,
            width,
            height,
        }))
    }

    fn redraw_single_cell_in_shadow(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        cell: &Cell,
        display_row: usize,
        col: usize,
    ) -> bool {
        let metrics = font_metrics(self.font);
        let x = LEFT_MARGIN.saturating_add(col as u32 * metrics.advance);
        let y = self.display_row_y(display_row);
        if x >= canvas.width() || y >= canvas.height() {
            return true;
        }
        let w = metrics.advance.min(canvas.width().saturating_sub(x));
        let h = metrics.line_height.min(canvas.height().saturating_sub(y));
        if canvas
            .fill_rect_to_shadow(shadow, x, y, w, h, cell.bg.0, cell.bg.1, cell.bg.2)
            .is_err()
        {
            return false;
        }
        if cell.ch != ' ' {
            let mut b = [0u8; 4];
            let s = cell.ch.encode_utf8(&mut b);
            let _ = canvas
                .draw_text_to_shadow(shadow, x, y, s, cell.fg.0, cell.fg.1, cell.fg.2, self.font);
        }
        true
    }

    fn draw_cursor_at_to_shadow(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        display_row: usize,
        column: usize,
    ) -> bool {
        let Some(rect) = self.cursor_rect(canvas, display_row, column) else {
            return true;
        };
        canvas
            .fill_rect_to_shadow(
                shadow,
                rect.x,
                rect.y,
                rect.width,
                rect.height,
                COLOR_CURSOR.0,
                COLOR_CURSOR.1,
                COLOR_CURSOR.2,
            )
            .is_ok()
    }

    fn render_full_fallback(&self, canvas: &Canvas, view_top: usize) -> bool {
        if canvas
            .fill_rect(
                0,
                0,
                canvas.width(),
                canvas.height(),
                COLOR_BACKGROUND.0,
                COLOR_BACKGROUND.1,
                COLOR_BACKGROUND.2,
            )
            .is_err()
        {
            return false;
        }
        let visible_rows = self.visible_rows_for(canvas);
        let visible_columns = self.visible_columns_for(canvas);
        for display_row in 0..visible_rows {
            let row_cells = self.row_for_display(view_top, display_row);
            let len = cell_line_len(row_cells).min(visible_columns);
            let metrics = font_metrics(self.font);
            let y = self.display_row_y(display_row);
            let mut col = 0usize;
            while col < len {
                let color = row_cells[col].fg;
                let bg = row_cells[col].bg;
                let mut run_end = col + 1;
                while run_end < len && row_cells[run_end].fg == color && row_cells[run_end].bg == bg
                {
                    run_end += 1;
                }
                let rx = LEFT_MARGIN.saturating_add(col as u32 * metrics.advance);
                if bg != COLOR_BACKGROUND {
                    let bg_w = ((run_end - col) as u32 * metrics.advance)
                        .min(canvas.width().saturating_sub(rx));
                    let bg_h = metrics.line_height.min(canvas.height().saturating_sub(y));
                    if canvas
                        .fill_rect(rx, y, bg_w, bg_h, bg.0, bg.1, bg.2)
                        .is_err()
                    {
                        return false;
                    }
                }
                let mut buf = [0u8; COLS * 4];
                let mut used = 0;
                for cell in &row_cells[col..run_end] {
                    used += cell.ch.encode_utf8(&mut buf[used..]).len();
                }
                let Ok(text) = core::str::from_utf8(&buf[..used]) else {
                    return false;
                };
                if canvas
                    .draw_text_with_font(rx, y, text, color.0, color.1, color.2, self.font)
                    .is_err()
                {
                    return false;
                }
                col = run_end;
            }
        }
        canvas.present().is_ok()
    }

    fn display_row_y(&self, display_row: usize) -> u32 {
        let metrics = font_metrics(self.font);
        TOP_MARGIN.saturating_add(display_row as u32 * metrics.line_height)
    }

    fn cursor_rect(&self, canvas: &Canvas, display_row: usize, column: usize) -> Option<PixelRect> {
        let metrics = font_metrics(self.font);
        let x = LEFT_MARGIN.saturating_add(column as u32 * metrics.advance);
        let row_y = self.display_row_y(display_row);
        let cursor_height = if metrics.line_height >= 4 { 2 } else { 1 };
        let maximum_offset = metrics.line_height.saturating_sub(cursor_height);
        let cursor_offset = metrics.glyph_height.min(maximum_offset);
        let y = row_y.saturating_add(cursor_offset);
        if x >= canvas.width() || y >= canvas.height() {
            return None;
        }
        let width = metrics
            .advance
            .saturating_sub(1)
            .max(1)
            .min(canvas.width().saturating_sub(x));
        let height = cursor_height.min(canvas.height().saturating_sub(y));
        if width == 0 || height == 0 {
            return None;
        }
        Some(PixelRect {
            x,
            y,
            width,
            height,
        })
    }
}

impl Default for Screen {
    fn default() -> Self {
        Self::new()
    }
}

fn flush_shadow_rect(canvas: &Canvas, shadow: &[u8; SHADOW_CAPACITY], rect: PixelRect) -> bool {
    if rect.width == 0 || rect.height == 0 || rect.x >= canvas.width() || rect.y >= canvas.height()
    {
        return true;
    }
    let width = rect.width.min(canvas.width().saturating_sub(rect.x));
    let height = rect.height.min(canvas.height().saturating_sub(rect.y));
    if width == 0 || height == 0 {
        return true;
    }
    canvas
        .upload_shadow_region(shadow, rect.x, rect.y, width, height)
        .is_ok()
        && canvas.present_region(rect.x, rect.y, width, height).is_ok()
}

fn cell_line_len(line: &[Cell; COLS]) -> usize {
    let mut len = COLS;
    while len > 0 && line[len - 1].ch == ' ' && line[len - 1].bg == COLOR_BACKGROUND {
        len -= 1;
    }
    len
}

fn ansi_16_palette(idx: u8) -> Color {
    match idx {
        0 => (24, 30, 42),     // Black
        1 => (235, 95, 105),   // Red
        2 => (95, 225, 165),   // Green
        3 => (245, 200, 95),   // Yellow
        4 => (110, 165, 250),  // Blue
        5 => (205, 135, 245),  // Magenta
        6 => (95, 220, 240),   // Cyan
        7 => (210, 222, 238),  // White
        8 => (105, 120, 145),  // Bright Black / Gray
        9 => (255, 125, 135),  // Bright Red
        10 => (125, 245, 185), // Bright Green
        11 => (255, 220, 125), // Bright Yellow
        12 => (140, 190, 255), // Bright Blue
        13 => (225, 165, 255), // Bright Magenta
        14 => (135, 240, 255), // Bright Cyan
        _ => (245, 250, 255),  // Bright White
    }
}

fn ansi_256_palette(idx: u8) -> Color {
    if idx < 16 {
        return ansi_16_palette(idx);
    }
    if idx < 232 {
        let cube = idx - 16;
        let r = cube / 36;
        let g = (cube / 6) % 6;
        let b = cube % 6;
        let step = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
        return (step(r), step(g), step(b));
    }
    let gray = 8 + (idx - 232) * 10;
    (gray, gray, gray)
}
