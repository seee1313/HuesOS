//! USB HID Boot Keyboard & Boot Mouse state machines producing HuesOS input packets.

/// HuesOS terminal/game special key code: Up Arrow (`0x80`).
pub const KEY_ARROW_UP: u8 = 0x80;
/// HuesOS terminal/game special key code: Down Arrow (`0x81`).
pub const KEY_ARROW_DOWN: u8 = 0x81;
/// HuesOS terminal/game special key code: Left Arrow (`0x82`).
pub const KEY_ARROW_LEFT: u8 = 0x82;
/// HuesOS terminal/game special key code: Right Arrow (`0x83`).
pub const KEY_ARROW_RIGHT: u8 = 0x83;
/// HuesOS terminal/game special key code: Home (`0x84`).
pub const KEY_HOME: u8 = 0x84;
/// HuesOS terminal/game special key code: End (`0x85`).
pub const KEY_END: u8 = 0x85;
/// HuesOS terminal/game special key code: Delete (`0x86`).
pub const KEY_DELETE: u8 = 0x86;
/// HuesOS terminal/game special key code: Page Up (`0x87`).
pub const KEY_PAGE_UP: u8 = 0x87;
/// HuesOS terminal/game special key code: Page Down (`0x88`).
pub const KEY_PAGE_DOWN: u8 = 0x88;

// Boot Keyboard modifier bitmask (`report[0]`).
const MOD_LCTRL: u8 = 1 << 0;
const MOD_LSHIFT: u8 = 1 << 1;
const MOD_RCTRL: u8 = 1 << 4;
const MOD_RSHIFT: u8 = 1 << 5;

/// Maximum key press/release transitions emitted by one 8-byte HID Boot Keyboard report.
pub const MAX_HID_KEY_EVENTS: usize = 12;

/// Normalized HuesOS key event (`[b'k', pressed as u8, key]` on wire).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidKeyEvent {
    /// Logical ASCII or `KEY_*` navigation byte.
    pub key: u8,
    /// `true` on key-down, `false` on key-up.
    pub pressed: bool,
}

impl HidKeyEvent {
    /// Encode into the 3-byte HuesOS `keyboard-client` wire message.
    pub const fn to_wire(self) -> [u8; 3] {
        [b'k', self.pressed as u8, self.key]
    }
}

/// Stateful USB HID Boot Keyboard (`8`-byte report) decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidBootKeyboard {
    prev_keys: [u8; 6],
    prev_pressed_wire: [u8; 6],
    caps_lock: bool,
}

impl Default for HidBootKeyboard {
    fn default() -> Self {
        Self::new()
    }
}

impl HidBootKeyboard {
    /// Create an idle Boot Keyboard decoder.
    pub const fn new() -> Self {
        Self {
            prev_keys: [0; 6],
            prev_pressed_wire: [0; 6],
            caps_lock: false,
        }
    }

    /// Feed one 8-byte Boot Keyboard report (`[mods, reserved, k0..k5]`), writing
    /// resulting key-up and key-down transitions into `out` and returning count.
    pub fn feed_report(
        &mut self,
        report: &[u8],
        out: &mut [HidKeyEvent; MAX_HID_KEY_EVENTS],
    ) -> usize {
        if report.len() < 8 {
            return 0;
        }
        let mods = report[0];
        let keys = [
            report[2], report[3], report[4], report[5], report[6], report[7],
        ];
        // HID ErrorRollOver (`0x01` in any slot) indicates phantom state — ignore frame.
        let mut idx = 0usize;
        while idx < 6 {
            if keys[idx] == 0x01 {
                return 0;
            }
            idx += 1;
        }

        let shift = (mods & (MOD_LSHIFT | MOD_RSHIFT)) != 0;
        let ctrl = (mods & (MOD_LCTRL | MOD_RCTRL)) != 0;
        let mut count = 0usize;

        // 1. Emit releases for usages that were held in `prev_keys` and are now absent.
        let mut p = 0usize;
        while p < 6 {
            let old_usage = self.prev_keys[p];
            if old_usage != 0 && !contains_usage(&keys, old_usage) {
                let wire = self.prev_pressed_wire[p];
                if wire != 0 && count < MAX_HID_KEY_EVENTS {
                    out[count] = HidKeyEvent {
                        key: wire,
                        pressed: false,
                    };
                    count += 1;
                }
            }
            p += 1;
        }

        // 2. Build next active state & emit presses for newly appeared usages.
        let mut next_wire = [0u8; 6];
        let mut k = 0usize;
        while k < 6 {
            let usage = keys[k];
            if usage != 0 {
                if let Some(prev_slot) = find_usage(&self.prev_keys, usage) {
                    next_wire[k] = self.prev_pressed_wire[prev_slot];
                } else if usage == 0x39 {
                    // Caps Lock (`0x39`) toggles state without emitting a printable byte.
                    self.caps_lock = !self.caps_lock;
                } else if let Some(mapped) = translate_hid_usage(usage, shift, ctrl, self.caps_lock)
                {
                    next_wire[k] = mapped;
                    if count < MAX_HID_KEY_EVENTS {
                        out[count] = HidKeyEvent {
                            key: mapped,
                            pressed: true,
                        };
                        count += 1;
                    }
                }
            }
            k += 1;
        }

        self.prev_keys = keys;
        self.prev_pressed_wire = next_wire;
        count
    }
}

const fn contains_usage(arr: &[u8; 6], usage: u8) -> bool {
    find_usage(arr, usage).is_some()
}

const fn find_usage(arr: &[u8; 6], usage: u8) -> Option<usize> {
    let mut i = 0usize;
    while i < 6 {
        if arr[i] == usage {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Translate USB HID Keyboard/Keypad Page (`0x07`) usage ID into HuesOS wire byte.
pub const fn translate_hid_usage(
    usage: u8,
    shift: bool,
    ctrl: bool,
    caps_lock: bool,
) -> Option<u8> {
    if usage >= 0x04 && usage <= 0x1D {
        let base_lower = b'a' + (usage - 0x04);
        if ctrl {
            return Some((base_lower - b'a') + 1);
        }
        let upper = shift ^ caps_lock;
        return Some(if upper { base_lower - 32 } else { base_lower });
    }
    let ch = match (usage, shift) {
        (0x1E, false) => b'1',
        (0x1E, true) => b'!',
        (0x1F, false) => b'2',
        (0x1F, true) => b'@',
        (0x20, false) => b'3',
        (0x20, true) => b'#',
        (0x21, false) => b'4',
        (0x21, true) => b'$',
        (0x22, false) => b'5',
        (0x22, true) => b'%',
        (0x23, false) => b'6',
        (0x23, true) => b'^',
        (0x24, false) => b'7',
        (0x24, true) => b'&',
        (0x25, false) => b'8',
        (0x25, true) => b'*',
        (0x26, false) => b'9',
        (0x26, true) => b'(',
        (0x27, false) => b'0',
        (0x27, true) => b')',
        (0x28, _) | (0x58, _) => b'\n',
        (0x29, _) => 0x1B,
        (0x2A, _) => 0x08,
        (0x2B, _) => b'\t',
        (0x2C, _) => b' ',
        (0x2D, false) | (0x56, _) => b'-',
        (0x2D, true) => b'_',
        (0x2E, false) => b'=',
        (0x2E, true) => b'+',
        (0x2F, false) => b'[',
        (0x2F, true) => b'{',
        (0x30, false) => b']',
        (0x30, true) => b'}',
        (0x31, false) => b'\\',
        (0x31, true) => b'|',
        (0x33, false) => b';',
        (0x33, true) => b':',
        (0x34, false) => b'\'',
        (0x34, true) => b'"',
        (0x35, false) => b'`',
        (0x35, true) => b'~',
        (0x36, false) => b',',
        (0x36, true) => b'<',
        (0x37, false) | (0x63, _) => b'.',
        (0x37, true) => b'>',
        (0x38, false) | (0x54, _) => b'/',
        (0x38, true) => b'?',
        (0x55, _) => b'*',
        (0x57, _) => b'+',
        (0x4A, _) => KEY_HOME,
        (0x4B, _) => KEY_PAGE_UP,
        (0x4C, _) => KEY_DELETE,
        (0x4D, _) => KEY_END,
        (0x4E, _) => KEY_PAGE_DOWN,
        (0x4F, _) => KEY_ARROW_RIGHT,
        (0x50, _) => KEY_ARROW_LEFT,
        (0x51, _) => KEY_ARROW_DOWN,
        (0x52, _) => KEY_ARROW_UP,
        _ => return None,
    };
    Some(ch)
}

/// Decoded USB HID Boot Mouse packet (`[b'm', buttons, dx, dy, wheel]` on wire).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidMouseEvent {
    /// Button bitmask (`bit 0` = Left, `bit 1` = Right, `bit 2` = Middle).
    pub buttons: u8,
    /// Relative X motion.
    pub dx: i8,
    /// Relative Y motion.
    pub dy: i8,
    /// Optional wheel motion (`0` for 3-byte reports).
    pub wheel: i8,
}

impl HidMouseEvent {
    /// Decode a 3-byte or 4+-byte USB HID Boot Mouse report.
    pub const fn decode(report: &[u8]) -> Option<Self> {
        if report.len() < 3 {
            return None;
        }
        let wheel = if report.len() >= 4 {
            report[3] as i8
        } else {
            0
        };
        Some(Self {
            buttons: report[0] & 0x07,
            dx: report[1] as i8,
            dy: report[2] as i8,
            wheel,
        })
    }

    /// Encode into 5-byte `mouse-client` wire message.
    pub const fn to_wire(self) -> [u8; 5] {
        [
            b'm',
            self.buttons,
            self.dx as u8,
            self.dy as u8,
            self.wheel as u8,
        ]
    }
}
