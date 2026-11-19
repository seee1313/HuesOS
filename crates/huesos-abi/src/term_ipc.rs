//! Bidirectional binary IPC framing between `terminal` and `/bin/hsh.elf`.
//!
//! All messages fit inside a single 4096-byte `Channel` packet so neither side
//! requires heap allocation to encode or decode control frames.

/// Maximum payload per `HshToTerm::Write` chunk.
pub const MAX_WRITE_CHUNK: usize = 3584;
/// Maximum interactive input line bytes carried in one `Prompt` frame.
pub const MAX_PROMPT_INPUT: usize = 1024;
/// Maximum ghost autosuggestion bytes carried in one `Prompt` frame.
pub const MAX_PROMPT_GHOST: usize = 256;
/// Maximum `pwd` path bytes carried in `Prompt` or `StatusBar`.
pub const MAX_PWD_BYTES: usize = 128;
/// Maximum syntax-highlight spans per `Prompt` frame.
pub const MAX_PROMPT_SPANS: usize = 256;

/// Messages sent from `terminal` to `/bin/hsh.elf` over `stdin`.
pub mod term_to_hsh {
    /// Raw keyboard event packet (`[tag, len, bytes...]`).
    pub const TAG_KEY_EVENT: u8 = 1;
    /// Run Cycle 4 startup smoke verification inside `/bin/hsh.elf`.
    pub const TAG_RUN_SMOKE: u8 = 2;
    /// Full-screen application (`doom` / `snake`) exited; resume shell prompt.
    pub const TAG_UI_DONE: u8 = 3;
    /// Request orderly shutdown (e.g. `soak-shutdown`).
    pub const TAG_SHUTDOWN: u8 = 4;
}

/// Messages sent from `/bin/hsh.elf` to `terminal` over `stdout`.
pub mod hsh_to_term {
    /// Clear workspace screen.
    pub const TAG_CLEAR: u8 = 1;
    /// Write colored UTF-8 output bytes (`[tag, use_custom_fg, r, g, b, len_lo, len_hi, bytes...]`).
    pub const TAG_WRITE: u8 = 2;
    /// Render full prompt line with syntax spans and ghost suggestion.
    pub const TAG_PROMPT: u8 = 3;
    /// Update terminal chrome header & status bar telemetry.
    pub const TAG_STATUS_BAR: u8 = 4;
    /// Delegate fullscreen DOOM launch to `terminal` + `init`.
    pub const TAG_LAUNCH_DOOM: u8 = 5;
    /// Delegate fullscreen Snake launch to `terminal` (`[tag, hard]`).
    pub const TAG_LAUNCH_SNAKE: u8 = 6;
    /// Request orderly system shutdown via `terminal` -> `init`.
    pub const TAG_REQUEST_SHUTDOWN: u8 = 7;
    /// Switch raster font (`[tag, 0|1|2]`).
    pub const TAG_SET_FONT: u8 = 8;
    /// Shell exited cleanly (`[tag, code_i32_le]`).
    pub const TAG_EXIT: u8 = 9;
}

/// Syntax-highlight token color classes matching `huesos_hsh::HighlightKind`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpanKind {
    /// Default identifier / text.
    Default = 0,
    /// Control-flow keyword (`if`, `else`, `for`, `let`, `fn`, `alias`).
    Keyword = 1,
    /// Shell intrinsic (`echo`, `cd`, `cls`, `where`, `select`, ...).
    Builtin = 2,
    /// External executable command.
    Command = 3,
    /// Capability annotation (`@caps(...)`).
    Caps = 4,
    /// Quoted string literal.
    StringLit = 5,
    /// Variable expansion (`$var`).
    Variable = 6,
    /// Operator (`|`, `;`, `&&`, `||`, `>`, `>>`).
    Operator = 7,
    /// `#` comment.
    Comment = 8,
    /// Numeric literal.
    Number = 9,
}

impl SpanKind {
    /// Convert a wire byte into [`SpanKind`].
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Keyword,
            2 => Self::Builtin,
            3 => Self::Command,
            4 => Self::Caps,
            5 => Self::StringLit,
            6 => Self::Variable,
            7 => Self::Operator,
            8 => Self::Comment,
            9 => Self::Number,
            _ => Self::Default,
        }
    }
}

/// Write a `u16` in little-endian at `off`.
pub fn put_u16(buf: &mut [u8], off: usize, val: u16) {
    let b = val.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
}

/// Read a `u16` in little-endian at `off`.
pub fn get_u16(buf: &[u8], off: usize) -> Option<u16> {
    let b0 = *buf.get(off)?;
    let b1 = *buf.get(off + 1)?;
    Some(u16::from_le_bytes([b0, b1]))
}

/// Write an `i32` in little-endian at `off`.
pub fn put_i32(buf: &mut [u8], off: usize, val: i32) {
    let b = val.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
    buf[off + 2] = b[2];
    buf[off + 3] = b[3];
}

/// Read an `i32` in little-endian at `off`.
pub fn get_i32(buf: &[u8], off: usize) -> Option<i32> {
    let b0 = *buf.get(off)?;
    let b1 = *buf.get(off + 1)?;
    let b2 = *buf.get(off + 2)?;
    let b3 = *buf.get(off + 3)?;
    Some(i32::from_le_bytes([b0, b1, b2, b3]))
}
