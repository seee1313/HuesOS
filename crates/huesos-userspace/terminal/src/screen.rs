//! Framebuffer-backed text screen.

use libcanvas::framebuffer::{Canvas, TextFont};

const ROWS: usize = 44;
const COLS: usize = 96;
const LINE_HEIGHT: u32 = 16;
const LEFT_MARGIN: u32 = 16;
const TOP_MARGIN: u32 = 16;

/// Simple fixed-size text screen backed by a `Canvas`.
pub struct Screen {
    canvas: Option<Canvas>,
    cells: [[u8; COLS]; ROWS],
    row: usize,
    col: usize,
    font: TextFont,
}

impl Screen {
    /// Create a screen; serial-only boots keep working with `canvas = None`.
    pub fn new() -> Self {
        Self {
            canvas: Canvas::new_fullscreen().ok(),
            cells: [[b' '; COLS]; ROWS],
            row: 0,
            col: 0,
            font: TextFont::Tty8x16,
        }
    }

    /// Clear all cells and reset cursor.
    pub fn clear(&mut self) {
        self.cells = [[b' '; COLS]; ROWS];
        self.row = 0;
        self.col = 0;
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
    }

    /// Delete one character on the current line.
    pub fn backspace(&mut self) {
        if self.col > 0 {
            self.col -= 1;
            self.cells[self.row][self.col] = b' ';
        }
    }

    /// Advance to a new line, scrolling if needed.
    pub fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 >= ROWS {
            self.scroll();
        } else {
            self.row += 1;
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

    /// Select the default TTY-style 8x16 font.
    pub fn use_tty_font(&mut self) {
        self.font = TextFont::Tty8x16;
    }

    /// Select the original compact HuesOS 8x8 font.
    pub fn use_compact_font(&mut self) {
        self.font = TextFont::Compact8x8;
    }

    /// Human-readable active font name.
    pub fn font_name(&self) -> &'static str {
        match self.font {
            TextFont::Tty8x16 => "tty 8x16",
            TextFont::Compact8x8 => "compact 8x8",
        }
    }

    /// Present the current text buffer to the framebuffer.
    pub fn render(&self) {
        let Some(canvas) = &self.canvas else {
            return;
        };
        let _ = canvas.fill_rect(0, 0, canvas.width(), canvas.height(), 5, 8, 16);
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
                    let _ = canvas.draw_text_with_font(
                        LEFT_MARGIN,
                        TOP_MARGIN + row as u32 * LINE_HEIGHT,
                        text,
                        color.0,
                        color.1,
                        color.2,
                        self.font,
                    );
                }
            }
            row += 1;
        }
        let _ = canvas.present();
    }

    fn scroll(&mut self) {
        let mut row = 1;
        while row < ROWS {
            self.cells[row - 1] = self.cells[row];
            row += 1;
        }
        self.cells[ROWS - 1] = [b' '; COLS];
        self.row = ROWS - 1;
    }
}

fn line_len(line: &[u8; COLS]) -> usize {
    let mut len = COLS;
    while len > 0 && line[len - 1] == b' ' {
        len -= 1;
    }
    len
}
