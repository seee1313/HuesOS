//! Framebuffer-backed text screen.

use core::cell::UnsafeCell;
use libcanvas::framebuffer::{Canvas, TextFont};

// Terminal layout defaults are sized for the Cozette 6x13 font
// (advance 6px, line box 13px). Row/column counts stay generous so a
// 1024x768 boot display can host ~54 lines × ~168 columns, giving
// contemporary terminals real breathing room instead of the previous
// 96-column classic-VT budget.
const ROWS: usize = 54;
const COLS: usize = 168;
const ALL_ROWS_DIRTY: u64 = (1u64 << ROWS) - 1;
/// Extra pixel of leading between rows to keep descenders (`g`, `p`,
/// `y`, `q`) visually separated from the next line's ascenders.
const LINE_HEIGHT: u32 = 14;
const LEFT_MARGIN: u32 = 12;
const TOP_MARGIN: u32 = 12;
/// Covers up to 2560×1600 at 32 bpp without heap allocation.
const SHADOW_CAPACITY: usize = 16 * 1024 * 1024;

struct TerminalShadow(UnsafeCell<[u8; SHADOW_CAPACITY]>);

// SAFETY: Terminal is a single-threaded process and rendering is synchronous;
// no shadow-buffer borrow can overlap another render call.
unsafe impl Sync for TerminalShadow {}

impl TerminalShadow {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; SHADOW_CAPACITY]))
    }

    fn with<R>(&self, operation: impl FnOnce(&mut [u8; SHADOW_CAPACITY]) -> R) -> R {
        // SAFETY: guaranteed by the single-threaded render invariant above.
        unsafe { operation(&mut *self.0.get()) }
    }
}

static TERMINAL_SHADOW: TerminalShadow = TerminalShadow::new();

/// Borrow the process-wide software framebuffer. Terminal rendering and Snake
/// execute sequentially on the same thread, so their borrows never overlap.
pub(crate) fn with_render_shadow<R>(operation: impl FnOnce(&mut [u8; SHADOW_CAPACITY]) -> R) -> R {
    TERMINAL_SHADOW.with(operation)
}

/// Simple fixed-size text screen backed by a `Canvas`.
pub struct Screen {
    canvas: Option<Canvas>,
    cells: [[u8; COLS]; ROWS],
    row: usize,
    col: usize,
    font: TextFont,
    dirty_rows: u64,
    force_full_render: bool,
}

impl Screen {
    /// Create a screen; serial-only boots keep working with `canvas = None`.
    pub fn new() -> Self {
        Self {
            canvas: Canvas::new_fullscreen().ok(),
            cells: [[b' '; COLS]; ROWS],
            row: 0,
            col: 0,
            font: TextFont::Cozette6x13,
            dirty_rows: ALL_ROWS_DIRTY,
            force_full_render: true,
        }
    }

    /// Clear all cells and reset cursor.
    pub fn clear(&mut self) {
        self.cells = [[b' '; COLS]; ROWS];
        self.row = 0;
        self.col = 0;
        self.mark_all_dirty();
    }

    /// Write a string then a newline.
    pub fn write_line(&mut self, text: &str) {
        self.write_str(text);
        self.newline();
    }

    /// Write a string, handling `\n`.
    pub fn write_str(&mut self, text: &str) {
        for byte in text.bytes() {
            if byte == b'\n' {
                self.newline();
            } else {
                self.write_byte(byte);
            }
        }
    }

    /// Write one printable ASCII byte.
    pub fn write_byte(&mut self, byte: u8) {
        if self.col >= COLS {
            self.newline();
        }
        self.cells[self.row][self.col] = if (0x20..=0x7e).contains(&byte) {
            byte
        } else {
            b'?'
        };
        self.col += 1;
        self.mark_row_dirty(self.row);
    }

    /// Delete one character on the current line.
    pub fn backspace(&mut self) {
        if self.col > 0 {
            self.col -= 1;
            self.cells[self.row][self.col] = b' ';
            self.mark_row_dirty(self.row);
        }
    }

    /// Advance to a new line, scrolling if needed.
    pub fn newline(&mut self) {
        let old_row = self.row;
        self.col = 0;
        if self.row + 1 >= ROWS {
            self.scroll();
        } else {
            self.row += 1;
            // The active input row is highlighted, so both the old and
            // new row must be repainted when the cursor moves vertically.
            self.mark_row_dirty(old_row);
            self.mark_row_dirty(self.row);
        }
    }

    /// Write an unsigned decimal integer.
    pub fn write_usize(&mut self, mut value: usize) {
        let mut buf = [0u8; 20];
        let mut len = 0;
        if value == 0 {
            self.write_byte(b'0');
            return;
        }
        while value > 0 && len < buf.len() {
            buf[len] = b'0' + (value % 10) as u8;
            value /= 10;
            len += 1;
        }
        while len > 0 {
            len -= 1;
            self.write_byte(buf[len]);
        }
    }

    /// Select the default Cozette 6x13 bitmap font.
    pub fn use_cozette_font(&mut self) {
        self.font = TextFont::Cozette6x13;
        self.mark_all_dirty();
    }

    /// Select the legacy TTY-style 8x16 upscaled font.
    pub fn use_tty_font(&mut self) {
        self.font = TextFont::Tty8x16;
        self.mark_all_dirty();
    }

    /// Select the original compact HuesOS 8x8 font.
    pub fn use_compact_font(&mut self) {
        self.font = TextFont::Compact8x8;
        self.mark_all_dirty();
    }

    /// Human-readable active font name.
    pub fn font_name(&self) -> &'static str {
        match self.font {
            TextFont::Cozette6x13 => "cozette 6x13",
            TextFont::Tty8x16 => "tty 8x16",
            TextFont::Compact8x8 => "compact 8x8",
        }
    }

    /// Present dirty text rows to the framebuffer.
    pub fn render(&mut self) {
        if self.dirty_rows == 0 && !self.force_full_render {
            return;
        }

        let rendered = if let Some(canvas) = self.canvas.as_ref() {
            if canvas.supports_buffered_raster() && canvas.byte_len() <= SHADOW_CAPACITY {
                let dirty_rows = self.dirty_rows;
                let force_full = self.force_full_render;
                with_render_shadow(|shadow| {
                    if force_full || dirty_rows == ALL_ROWS_DIRTY {
                        self.render_full_buffered(canvas, shadow)
                    } else {
                        self.render_dirty_buffered(canvas, shadow, dirty_rows)
                    }
                })
            } else {
                // Conservative fallback for unusual non-32-bpp framebuffers.
                self.render_full_fallback(canvas)
            }
        } else {
            true
        };

        if rendered {
            self.dirty_rows = 0;
            self.force_full_render = false;
        }
    }

    fn scroll(&mut self) {
        let mut row = 1;
        while row < ROWS {
            self.cells[row - 1] = self.cells[row];
            row += 1;
        }
        self.cells[ROWS - 1] = [b' '; COLS];
        self.row = ROWS - 1;
        self.mark_all_dirty();
    }

    fn mark_row_dirty(&mut self, row: usize) {
        if row < ROWS {
            self.dirty_rows |= 1u64 << row;
        }
    }

    fn mark_all_dirty(&mut self) {
        self.dirty_rows = ALL_ROWS_DIRTY;
        self.force_full_render = true;
    }

    fn render_full_buffered(&self, canvas: &Canvas, shadow: &mut [u8; SHADOW_CAPACITY]) -> bool {
        if canvas.clear_shadow(shadow, 5, 8, 16).is_err() {
            return false;
        }
        let mut row = 0;
        while row < ROWS {
            if !self.draw_row_text_to_shadow(canvas, shadow, row) {
                return false;
            }
            row += 1;
        }
        canvas.upload_shadow(shadow).is_ok() && canvas.present().is_ok()
    }

    fn render_dirty_buffered(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        dirty_rows: u64,
    ) -> bool {
        let mut row = 0;
        let mut range_start: Option<usize> = None;
        let mut range_end = 0usize;

        while row < ROWS {
            if dirty_rows & (1u64 << row) != 0 {
                if !self.render_row_to_shadow(canvas, shadow, row) {
                    return false;
                }
                match range_start {
                    Some(_) if row == range_end => {
                        range_end += 1;
                    }
                    Some(start) => {
                        if !flush_shadow_rows(canvas, shadow, start, range_end) {
                            return false;
                        }
                        range_start = Some(row);
                        range_end = row + 1;
                    }
                    None => {
                        range_start = Some(row);
                        range_end = row + 1;
                    }
                }
            }
            row += 1;
        }

        if let Some(start) = range_start {
            flush_shadow_rows(canvas, shadow, start, range_end)
        } else {
            true
        }
    }

    fn render_row_to_shadow(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        row: usize,
    ) -> bool {
        let y = row_y(row);
        if canvas
            .fill_rect_to_shadow(shadow, 0, y, canvas.width(), LINE_HEIGHT, 5, 8, 16)
            .is_err()
        {
            return false;
        }
        self.draw_row_text_to_shadow(canvas, shadow, row)
    }

    fn draw_row_text_to_shadow(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        row: usize,
    ) -> bool {
        let len = line_len(&self.cells[row]);
        if len == 0 {
            return true;
        }
        let Ok(text) = core::str::from_utf8(&self.cells[row][..len]) else {
            return true;
        };
        let color = if row == self.row {
            (180, 240, 180)
        } else {
            (180, 220, 255)
        };
        canvas
            .draw_text_to_shadow(
                shadow,
                LEFT_MARGIN,
                row_y(row),
                text,
                color.0,
                color.1,
                color.2,
                self.font,
            )
            .is_ok()
    }

    fn render_full_fallback(&self, canvas: &Canvas) -> bool {
        if canvas
            .fill_rect(0, 0, canvas.width(), canvas.height(), 5, 8, 16)
            .is_err()
        {
            return false;
        }
        let mut row = 0;
        while row < ROWS {
            let len = line_len(&self.cells[row]);
            if len > 0 {
                if let Ok(text) = core::str::from_utf8(&self.cells[row][..len]) {
                    let color = if row == self.row {
                        (180, 240, 180)
                    } else {
                        (180, 220, 255)
                    };
                    if canvas
                        .draw_text_with_font(
                            LEFT_MARGIN,
                            row_y(row),
                            text,
                            color.0,
                            color.1,
                            color.2,
                            self.font,
                        )
                        .is_err()
                    {
                        return false;
                    }
                }
            }
            row += 1;
        }
        canvas.present().is_ok()
    }
}

fn flush_shadow_rows(
    canvas: &Canvas,
    shadow: &[u8; SHADOW_CAPACITY],
    start_row: usize,
    end_row: usize,
) -> bool {
    let y = row_y(start_row);
    if y >= canvas.height() {
        return true;
    }
    let y_end = row_y(end_row).min(canvas.height());
    if y >= y_end {
        return true;
    }
    let height = y_end - y;
    canvas
        .upload_shadow_region(shadow, 0, y, canvas.width(), height)
        .is_ok()
        && canvas.present_region(0, y, canvas.width(), height).is_ok()
}

fn row_y(row: usize) -> u32 {
    TOP_MARGIN + row as u32 * LINE_HEIGHT
}

fn line_len(line: &[u8; COLS]) -> usize {
    let mut len = COLS;
    while len > 0 && line[len - 1] == b' ' {
        len -= 1;
    }
    len
}
