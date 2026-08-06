//! Framebuffer-backed text screen.
//!
//! The terminal keeps a fixed-capacity character buffer and renders through a
//! process-wide software framebuffer. Full-screen applications may reuse the
//! same framebuffer through `with_render_shadow`; a generation counter lets
//! the terminal detect those external renders and restore its complete state
//! on the next presentation.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libcanvas::framebuffer::{Canvas, TextFont};

const ROWS: usize = 54;
const COLS: usize = 168;
const TAB_WIDTH: usize = 4;

const ALL_ROWS_DIRTY: u64 = (1u64 << ROWS) - 1;
const CLEAN_COLUMN: u16 = COLS as u16;

const LEFT_MARGIN: u32 = 12;
const TOP_MARGIN: u32 = 12;

/// Covers framebuffers up to 2560×1600 at 32 bits per pixel without heap
/// allocation.
const SHADOW_CAPACITY: usize = 16 * 1024 * 1024;

type Color = (u8, u8, u8);

const COLOR_BACKGROUND: Color = (5, 8, 16);
const COLOR_TEXT: Color = (180, 220, 255);
const COLOR_ACTIVE_TEXT: Color = (180, 240, 180);
const COLOR_CURSOR: Color = (100, 255, 170);

/// Monotonically identifies the most recent owner of the shared render
/// buffer. A terminal instance records the generation of its last successful
/// render and performs a full redraw when another component has rendered
/// since then.
static SHADOW_GENERATION: AtomicUsize = AtomicUsize::new(0);

/// Failure modes for the [`TerminalShadow::with`] exclusive borrow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShadowError {
    /// A previous closure passed to [`with_render_shadow`] /
    /// [`with_render_shadow_tracked`] is still running. The render
    /// pipeline must never recurse into the shadow from inside its
    /// own callback, so this error indicates a programming bug at
    /// the call site rather than a runtime condition the caller
    /// can recover from. Callers should log it and skip the frame
    /// rather than retry; the recursive borrower will release the
    /// guard on return and subsequent frames will succeed.
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

        // The generation is assigned while exclusive ownership is held. This
        // preserves a total order between terminal and full-screen renders.
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

/// Borrow the process-wide software framebuffer.
///
/// Full-screen applications should use this function when possible. Doing so
/// allows the terminal to detect that its previous framebuffer contents were
/// replaced and restore the complete terminal on the next `Screen::render`.
///
/// Returns [`ShadowError::AlreadyBorrowed`] if a previous closure is still
/// running. Callers should treat this as a skip-this-frame signal: the
/// recursive borrower will release the guard on return and the next call
/// will succeed.
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

/// Fixed-capacity text screen backed by a framebuffer `Canvas`.
pub struct Screen {
    canvas: Option<Canvas>,
    cells: [[u8; COLS]; ROWS],

    row: usize,
    col: usize,
    font: TextFont,
    cursor_visible: bool,

    dirty_rows: u64,
    dirty_from: [u16; ROWS],
    dirty_to: [u16; ROWS],
    force_full_render: bool,

    rendered_view_top: usize,
    observed_shadow_generation: usize,
}

// `Screen` is the public rendering API of the terminal; some of its
// methods (framebuffer introspection, cursor position query, manual
// invalidation) are part of the contract for future drivers and tests
// even when no current in-tree caller exercises them. The `dead_code`
// lint is therefore disabled at the impl block.
#[allow(dead_code)]
impl Screen {
    /// Create a terminal screen. Serial-only boots remain operational when a
    /// framebuffer canvas is unavailable.
    pub fn new() -> Self {
        Self {
            canvas: Canvas::new_fullscreen().ok(),
            cells: [[b' '; COLS]; ROWS],

            row: 0,
            col: 0,
            font: TextFont::Cozette6x13,
            cursor_visible: true,

            dirty_rows: ALL_ROWS_DIRTY,
            dirty_from: [0; ROWS],
            dirty_to: [COLS as u16; ROWS],
            force_full_render: true,

            rendered_view_top: 0,
            observed_shadow_generation: render_shadow_generation(),
        }
    }

    /// Return whether this screen has access to a framebuffer canvas.
    pub fn has_framebuffer(&self) -> bool {
        self.canvas.is_some()
    }

    /// Return the current logical cursor position as `(row, column)`.
    pub fn cursor_position(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// Return the number of text columns and rows currently visible with the
    /// selected font.
    pub fn visible_size(&self) -> (usize, usize) {
        (self.active_columns(), self.active_rows())
    }

    /// Invalidate all previously rendered framebuffer contents.
    ///
    /// Full-screen applications using `with_render_shadow` are detected
    /// automatically. This method is intended for applications that write to
    /// the framebuffer through another path.
    pub fn invalidate(&mut self) {
        self.mark_all_dirty();
    }

    /// Clear all cells and reset the cursor.
    pub fn clear(&mut self) {
        self.cells = [[b' '; COLS]; ROWS];
        self.row = 0;
        self.col = 0;
        self.mark_all_dirty();
    }

    /// Write a string followed by a newline.
    pub fn write_line(&mut self, text: &str) {
        self.write_str(text);
        self.newline();
    }

    /// Write a byte string, including supported ASCII control characters.
    pub fn write_str(&mut self, text: &str) {
        for byte in text.bytes() {
            self.write_byte(byte);
        }
    }

    /// Write one byte.
    ///
    /// Supported control characters:
    ///
    /// - `\n`: newline
    /// - `\r`: carriage return
    /// - `\t`: tab
    /// - `0x08`: backspace
    ///
    /// Bytes outside printable ASCII are rendered as `?`.
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.carriage_return(),
            b'\t' => self.tab(),
            0x08 => self.backspace(),
            0x20..=0x7e => self.write_printable(byte),
            _ => self.write_printable(b'?'),
        }
    }

    /// Delete one character immediately before the cursor.
    pub fn backspace(&mut self) {
        if self.col == 0 {
            return;
        }

        let old_col = self.col;
        self.col -= 1;
        self.cells[self.row][self.col] = b' ';

        // The erased cell and both cursor positions are covered by the same
        // compact range.
        self.mark_dirty_span(self.row, self.col, old_col.saturating_add(1).min(COLS));
    }

    /// Move the cursor to the beginning of the current line.
    pub fn carriage_return(&mut self) {
        if self.col == 0 {
            return;
        }

        let old_col = self.col;
        self.col = 0;

        if self.cursor_visible {
            self.mark_dirty_span(self.row, 0, old_col.saturating_add(1).min(COLS));
        }
    }

    /// Advance to a new line, scrolling the logical buffer when necessary.
    pub fn newline(&mut self) {
        let old_row = self.row;
        let old_col = self.col;
        self.col = 0;

        if self.row + 1 >= ROWS {
            self.scroll();
            return;
        }

        self.row += 1;

        // Moving the active row changes its text color. Both the previous and
        // new active rows must therefore redraw their complete visible text,
        // plus any cursor cell.
        let old_end = line_len(&self.cells[old_row])
            .max(if self.cursor_visible {
                old_col.saturating_add(1)
            } else {
                old_col
            })
            .min(COLS);

        let new_end = line_len(&self.cells[self.row])
            .max(if self.cursor_visible {
                self.col.saturating_add(1)
            } else {
                self.col
            })
            .min(COLS);

        self.mark_dirty_span(old_row, 0, old_end);
        self.mark_dirty_span(self.row, 0, new_end);
    }

    /// Write an unsigned decimal integer without allocating.
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

    /// Show or hide the terminal cursor.
    pub fn set_cursor_visible(&mut self, visible: bool) {
        if self.cursor_visible == visible {
            return;
        }

        let row = self.row;
        let col = self.col;

        self.cursor_visible = visible;
        self.mark_dirty_span(row, col, col.saturating_add(1).min(COLS));
    }

    /// Select the default Cozette 6×13 bitmap font.
    pub fn use_cozette_font(&mut self) {
        self.font = TextFont::Cozette6x13;
        self.mark_all_dirty();
    }

    /// Select the legacy TTY-style 8×16 font.
    pub fn use_tty_font(&mut self) {
        self.font = TextFont::Tty8x16;
        self.mark_all_dirty();
    }

    /// Select the compact HuesOS 8×8 font.
    pub fn use_compact_font(&mut self) {
        self.font = TextFont::Compact8x8;
        self.mark_all_dirty();
    }

    /// Return the human-readable name of the active font.
    pub fn font_name(&self) -> &'static str {
        match self.font {
            TextFont::Cozette6x13 => "cozette 6x13",
            TextFont::Tty8x16 => "tty 8x16",
            TextFont::Compact8x8 => "compact 8x8",
        }
    }

    /// Present all modified terminal regions to the framebuffer.
    pub fn render(&mut self) {
        let shared_generation = render_shadow_generation();

        if shared_generation != self.observed_shadow_generation {
            // Another component, such as Snake, has replaced framebuffer
            // contents since the terminal last presented.
            self.mark_all_dirty();
        }

        let view_top = self.viewport_top();

        if view_top != self.rendered_view_top {
            // A viewport shift changes the model row represented by every
            // screen row, so partial dirty information is no longer valid.
            self.mark_all_dirty();
        }

        if self.dirty_rows == 0 && !self.force_full_render {
            return;
        }

        let mut committed_generation = None;

        let rendered = if let Some(canvas) = self.canvas.as_ref() {
            if canvas.supports_buffered_raster() && canvas.byte_len() <= SHADOW_CAPACITY {
                let dirty_rows = self.dirty_rows;
                let force_full = self.force_full_render;

                // The shadow is borrowed exclusively for the duration of
                // the render closure. A recursive borrow would indicate a
                // programming bug at the call site; the kernel-side
                // surface turns it into a Result instead of a panic so the
                // terminal can keep running. We treat the error as
                // "frame skipped": dirty tracking is left intact so the
                // next call will retry once the recursive borrower has
                // released the guard.
                match with_render_shadow_tracked(|shadow| {
                    if force_full || dirty_rows == ALL_ROWS_DIRTY {
                        self.render_full_buffered(canvas, shadow, view_top)
                    } else {
                        self.render_dirty_buffered(canvas, shadow, dirty_rows, view_top)
                    }
                }) {
                    Ok((result, generation)) => {
                        committed_generation = Some(generation);
                        result
                    }
                    Err(_shadow_error) => false,
                }
            } else {
                // Unusual pixel formats fall back to direct canvas drawing.
                // Partial updates are intentionally disabled here because the
                // direct path cannot guarantee shadow-buffer consistency.
                self.render_full_fallback(canvas, view_top)
            }
        } else {
            true
        };

        if rendered {
            self.clear_dirty_tracking();
            self.force_full_render = false;
            self.rendered_view_top = view_top;

            self.observed_shadow_generation =
                committed_generation.unwrap_or_else(render_shadow_generation);
        }
    }

    fn write_printable(&mut self, byte: u8) {
        let wrap_columns = self.active_columns();

        if self.col >= wrap_columns || self.col >= COLS {
            self.newline();
        }

        let row = self.row;
        let column = self.col;

        self.cells[row][column] = byte;
        self.col += 1;

        // Redraw the written cell and the cursor's new location.
        let end = if self.cursor_visible {
            self.col.saturating_add(1)
        } else {
            self.col
        }
        .min(COLS);

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
            self.write_printable(b' ');
        }
    }

    fn scroll(&mut self) {
        let mut source = 1;

        while source < ROWS {
            self.cells[source - 1] = self.cells[source];
            source += 1;
        }

        self.cells[ROWS - 1] = [b' '; COLS];
        self.row = ROWS - 1;
        self.col = 0;

        // Logical rows have all changed their screen positions. A complete
        // redraw is required even when only the final row is empty.
        self.mark_all_dirty();
    }

    fn active_columns(&self) -> usize {
        self.canvas
            .as_ref()
            .map(|canvas| self.visible_columns_for(canvas))
            .unwrap_or(COLS)
    }

    fn active_rows(&self) -> usize {
        self.canvas
            .as_ref()
            .map(|canvas| self.visible_rows_for(canvas))
            .unwrap_or(ROWS)
    }

    fn visible_columns_for(&self, canvas: &Canvas) -> usize {
        let metrics = font_metrics(self.font);
        let available = canvas.width().saturating_sub(LEFT_MARGIN);

        (available / metrics.advance).max(1).min(COLS as u32) as usize
    }

    fn visible_rows_for(&self, canvas: &Canvas) -> usize {
        let metrics = font_metrics(self.font);
        let available = canvas.height().saturating_sub(TOP_MARGIN);

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

    fn mark_all_dirty(&mut self) {
        self.dirty_rows = ALL_ROWS_DIRTY;
        self.dirty_from = [0; ROWS];
        self.dirty_to = [COLS as u16; ROWS];
        self.force_full_render = true;
    }

    fn clear_dirty_tracking(&mut self) {
        self.dirty_rows = 0;
        self.dirty_from = [CLEAN_COLUMN; ROWS];
        self.dirty_to = [0; ROWS];
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

        let visible_rows = self.visible_rows_for(canvas);
        let view_end = view_top.saturating_add(visible_rows).min(ROWS);

        let mut model_row = view_top;

        while model_row < view_end {
            let display_row = model_row - view_top;

            if !self.draw_complete_row_to_shadow(canvas, shadow, model_row, display_row) {
                return false;
            }

            model_row += 1;
        }

        canvas.upload_shadow(shadow).is_ok() && canvas.present().is_ok()
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
        let mut model_row = view_top;

        while model_row < view_end {
            if dirty_rows & (1u64 << model_row) != 0 {
                let display_row = model_row - view_top;

                let rect = match self.render_row_region_to_shadow(
                    canvas,
                    shadow,
                    model_row,
                    display_row,
                ) {
                    Ok(rect) => rect,
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

            model_row += 1;
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
        model_row: usize,
        display_row: usize,
    ) -> bool {
        let visible_columns = self.visible_columns_for(canvas);
        let len = line_len(&self.cells[model_row]).min(visible_columns);

        if len > 0 {
            let Ok(text) = core::str::from_utf8(&self.cells[model_row][..len]) else {
                return false;
            };

            let color = self.row_color(model_row);

            if canvas
                .draw_text_to_shadow(
                    shadow,
                    LEFT_MARGIN,
                    self.display_row_y(display_row),
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

        self.draw_cursor_to_shadow(canvas, shadow, model_row, display_row, visible_columns)
    }

    fn render_row_region_to_shadow(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        model_row: usize,
        display_row: usize,
    ) -> Result<Option<PixelRect>, ()> {
        let metrics = font_metrics(self.font);
        let visible_columns = self.visible_columns_for(canvas);

        let start_column = (self.dirty_from[model_row] as usize).min(visible_columns);
        let end_column = (self.dirty_to[model_row] as usize).min(visible_columns);

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

        let text_end = line_len(&self.cells[model_row]).min(end_column);

        if text_end > start_column {
            let Ok(text) = core::str::from_utf8(&self.cells[model_row][start_column..text_end])
            else {
                return Err(());
            };

            let color = self.row_color(model_row);

            canvas
                .draw_text_to_shadow(shadow, x, y, text, color.0, color.1, color.2, self.font)
                .map_err(|_| ())?;
        }

        if self.cursor_visible
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

    fn draw_cursor_to_shadow(
        &self,
        canvas: &Canvas,
        shadow: &mut [u8; SHADOW_CAPACITY],
        model_row: usize,
        display_row: usize,
        visible_columns: usize,
    ) -> bool {
        if !self.cursor_visible || model_row != self.row || self.col >= visible_columns {
            return true;
        }

        self.draw_cursor_at_to_shadow(canvas, shadow, display_row, self.col)
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
        let view_end = view_top.saturating_add(visible_rows).min(ROWS);

        let mut model_row = view_top;

        while model_row < view_end {
            let display_row = model_row - view_top;
            let len = line_len(&self.cells[model_row]).min(visible_columns);

            if len > 0 {
                let Ok(text) = core::str::from_utf8(&self.cells[model_row][..len]) else {
                    return false;
                };

                let color = self.row_color(model_row);

                if canvas
                    .draw_text_with_font(
                        LEFT_MARGIN,
                        self.display_row_y(display_row),
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

            if self.cursor_visible && model_row == self.row && self.col < visible_columns {
                if let Some(rect) = self.cursor_rect(canvas, display_row, self.col) {
                    if canvas
                        .fill_rect(
                            rect.x,
                            rect.y,
                            rect.width,
                            rect.height,
                            COLOR_CURSOR.0,
                            COLOR_CURSOR.1,
                            COLOR_CURSOR.2,
                        )
                        .is_err()
                    {
                        return false;
                    }
                }
            }

            model_row += 1;
        }

        canvas.present().is_ok()
    }

    fn row_color(&self, model_row: usize) -> Color {
        if model_row == self.row {
            COLOR_ACTIVE_TEXT
        } else {
            COLOR_TEXT
        }
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
    if rect.width == 0 || rect.height == 0 {
        return true;
    }

    if rect.x >= canvas.width() || rect.y >= canvas.height() {
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

fn line_len(line: &[u8; COLS]) -> usize {
    let mut len = COLS;

    while len > 0 && line[len - 1] == b' ' {
        len -= 1;
    }

    len
}
