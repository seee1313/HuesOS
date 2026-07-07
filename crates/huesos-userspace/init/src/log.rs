//! Init logging helpers.
//!
//! Init writes every message to the kernel debug UART and, while it owns the
//! display, mirrors those messages onto a small framebuffer console. Once the
//! terminal service starts, init deliberately stops framebuffer logging so the
//! terminal owns the screen.

use core::fmt::{self, Write};
use libcanvas::framebuffer::Canvas;

const ROWS: usize = 30;
const COLS: usize = 96;
const LEFT_MARGIN: u32 = 16;
const TOP_MARGIN: u32 = 16;
const LINE_HEIGHT: u32 = 16;

/// Init logger that mirrors UART logs to an optional framebuffer console.
pub struct InitLogger {
    screen: Option<FramebufferLog>,
}

impl InitLogger {
    /// Create a logger. If no framebuffer is available, logging silently
    /// falls back to UART-only output.
    pub fn new() -> Self {
        let mut logger = Self {
            screen: FramebufferLog::new().ok(),
        };
        if let Some(screen) = logger.screen.as_mut() {
            screen.write_line("HuesOS init log");
            screen.write_line("----------------");
            screen.render();
        }
        logger
    }

    /// Write one formatted log line to UART and, if enabled, framebuffer.
    pub fn line(&mut self, args: fmt::Arguments) {
        let _ = self.write_fmt(args);
        let _ = self.write_str("\n");
        if let Some(screen) = self.screen.as_ref() {
            screen.render();
        }
    }

    /// Stop framebuffer mirroring. UART logging continues.
    pub fn release_framebuffer(&mut self) {
        self.screen = None;
    }
}

impl Write for InitLogger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        libcanvas::debug::write_str(s);
        if let Some(screen) = self.screen.as_mut() {
            screen.write_str(s);
        }
        Ok(())
    }
}

struct FramebufferLog {
    canvas: Canvas,
    cells: [[u8; COLS]; ROWS],
    row: usize,
    col: usize,
}

impl FramebufferLog {
    fn new() -> libcanvas::Result<Self> {
        let canvas = Canvas::new_fullscreen()?;
        let mut log = Self {
            canvas,
            cells: [[b' '; COLS]; ROWS],
            row: 0,
            col: 0,
        };
        log.clear();
        Ok(log)
    }

    fn clear(&mut self) {
        self.cells = [[b' '; COLS]; ROWS];
        self.row = 0;
        self.col = 0;
    }

    fn write_line(&mut self, text: &str) {
        self.write_str(text);
        self.newline();
    }

    fn write_str(&mut self, text: &str) {
        for byte in text.bytes() {
            match byte {
                b'\n' => self.newline(),
                0x20..=0x7e => self.write_byte(byte),
                _ => self.write_byte(b'?'),
            }
        }
    }

    fn write_byte(&mut self, byte: u8) {
        if self.col >= COLS {
            self.newline();
        }
        self.cells[self.row][self.col] = byte;
        self.col += 1;
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 >= ROWS {
            self.scroll();
        } else {
            self.row += 1;
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
    }

    fn render(&self) {
        let _ = self
            .canvas
            .fill_rect(0, 0, self.canvas.width(), self.canvas.height(), 4, 6, 14);
        let mut row = 0;
        while row < ROWS {
            let len = line_len(&self.cells[row]);
            if len > 0 {
                if let Ok(text) = core::str::from_utf8(&self.cells[row][..len]) {
                    let color = if row <= 1 {
                        (180, 220, 255)
                    } else {
                        (150, 240, 170)
                    };
                    let _ = self.canvas.draw_text(
                        LEFT_MARGIN,
                        TOP_MARGIN + row as u32 * LINE_HEIGHT,
                        text,
                        color.0,
                        color.1,
                        color.2,
                    );
                }
            }
            row += 1;
        }
        let _ = self.canvas.present();
    }
}

fn line_len(line: &[u8; COLS]) -> usize {
    let mut len = COLS;
    while len > 0 && line[len - 1] == b' ' {
        len -= 1;
    }
    len
}
