//! Minimal PS/2 set-1 scancode decoder for terminal input.

/// Decoded key event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Printable ASCII byte.
    Char(u8),
    /// Backspace key.
    Backspace,
    /// Enter key.
    Enter,
}

/// Stateful keyboard decoder.
pub struct KeyboardDecoder {
    shift: bool,
}

impl KeyboardDecoder {
    /// Create a fresh decoder.
    pub const fn new() -> Self {
        Self { shift: false }
    }

    /// Feed one raw set-1 scancode and return a decoded key, if any.
    pub fn feed(&mut self, scancode: u8) -> Option<Key> {
        match scancode {
            0x2a | 0x36 => {
                self.shift = true;
                return None;
            }
            0xaa | 0xb6 => {
                self.shift = false;
                return None;
            }
            _ => {}
        }

        if scancode & 0x80 != 0 {
            return None;
        }

        let table = if self.shift { &SET1_UPPER } else { &SET1_LOWER };
        let byte = table.get(scancode as usize).copied().unwrap_or(0);
        match byte {
            0 => None,
            b'\n' => Some(Key::Enter),
            8 => Some(Key::Backspace),
            byte => Some(Key::Char(byte)),
        }
    }
}

const SET1_LOWER: [u8; 58] = [
    0, 27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8, b'\t', b'q',
    b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', 0, b'a', b's', b'd',
    b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`', 0, b'\\', b'z', b'x', b'c', b'v', b'b',
    b'n', b'm', b',', b'.', b'/', 0, b'*', 0, b' ',
];

const SET1_UPPER: [u8; 58] = [
    0, 27, b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 8, b'\t', b'Q',
    b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', b'\n', 0, b'A', b'S', b'D',
    b'F', b'G', b'H', b'J', b'K', b'L', b':', b'"', b'~', 0, b'|', b'Z', b'X', b'C', b'V', b'B',
    b'N', b'M', b'<', b'>', b'?', 0, b'*', 0, b' ',
];
