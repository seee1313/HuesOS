//! Minimal PS/2 keyboard driver (US QWERTY scancode set 1).
//!
//! This is a small, real driver (not a stub): it decodes scancode set 1
//! into ASCII where possible, tracks shift state, and pushes decoded bytes
//! into a ring buffer that userspace/kernel consumers can drain via
//! [`read_char`].

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

const BUFFER_SIZE: usize = 256;

struct RingBuffer {
    data: [u8; BUFFER_SIZE],
    head: usize,
    tail: usize,
}

impl RingBuffer {
    const fn new() -> Self {
        Self {
            data: [0; BUFFER_SIZE],
            head: 0,
            tail: 0,
        }
    }

    fn push(&mut self, byte: u8) {
        let next = (self.head + 1) % BUFFER_SIZE;
        if next != self.tail {
            self.data[self.head] = byte;
            self.head = next;
        }
    }

    fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail {
            return None;
        }
        let byte = self.data[self.tail];
        self.tail = (self.tail + 1) % BUFFER_SIZE;
        Some(byte)
    }
}

static BUFFER: Mutex<RingBuffer> = Mutex::new(RingBuffer::new());
static SHIFT_HELD: AtomicBool = AtomicBool::new(false);
static BYTES_RECEIVED: AtomicUsize = AtomicUsize::new(0);

// Scancode set 1, unshifted, index = scancode.
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

const LSHIFT_DOWN: u8 = 0x2A;
const LSHIFT_UP: u8 = 0xAA;
const RSHIFT_DOWN: u8 = 0x36;
const RSHIFT_UP: u8 = 0xB6;

/// Called from the IDT keyboard interrupt handler with the raw scancode.
pub fn on_scancode(scancode: u8) {
    match scancode {
        LSHIFT_DOWN | RSHIFT_DOWN => {
            SHIFT_HELD.store(true, Ordering::Relaxed);
            return;
        }
        LSHIFT_UP | RSHIFT_UP => {
            SHIFT_HELD.store(false, Ordering::Relaxed);
            return;
        }
        _ => {}
    }

    // Ignore key-release events (top bit set) for printable keys.
    if scancode & 0x80 != 0 {
        return;
    }

    let idx = scancode as usize;
    let table = if SHIFT_HELD.load(Ordering::Relaxed) {
        &SET1_UPPER
    } else {
        &SET1_LOWER
    };

    if idx < table.len() {
        let ch = table[idx];
        if ch != 0 {
            BUFFER.lock().push(ch);
            BYTES_RECEIVED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Non-blocking read of a single decoded character, if available.
pub fn read_char() -> Option<u8> {
    BUFFER.lock().pop()
}

/// Total bytes decoded since boot (diagnostic counter).
pub fn bytes_received() -> usize {
    BYTES_RECEIVED.load(Ordering::Relaxed)
}
