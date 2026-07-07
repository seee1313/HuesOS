//! Terminal shell runtime and keyboard event loop.

use crate::commands::execute_line;
use crate::screen::Screen;
use libcanvas::{Channel, ErrorCode};

const INPUT_MAX: usize = 128;

/// Running terminal shell.
pub struct Shell {
    screen: Screen,
    input: [u8; INPUT_MAX],
    input_len: usize,
    keyboard: Channel,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Char(u8),
    Backspace,
    Enter,
}

fn decode_keyboard_event(msg: &[u8]) -> Option<Key> {
    match msg {
        [b'c', byte] => Some(Key::Char(*byte)),
        b"enter" => Some(Key::Enter),
        b"backspace" => Some(Key::Backspace),
        _ => None,
    }
}

impl Shell {
    /// Create shell screen using an already-open keyboard service channel.
    pub fn new(keyboard: Channel) -> Self {
        let mut screen = Screen::new();
        screen.clear();
        screen.write_line("HuesOS Terminal");
        screen.write_line("userspace mini shell: type 'help' and press Enter");
        screen.write_line("keyboard input: userspace Interrupt + Port bridge");
        screen.write_line("");

        let mut shell = Self {
            screen,
            input: [0; INPUT_MAX],
            input_len: 0,
            keyboard,
        };
        shell.prompt();
        shell.screen.render();
        shell
    }

    /// Run the shell forever.
    pub fn run(&mut self) -> ! {
        let mut buf = [0u8; 16];
        loop {
            match self.keyboard.read_into(&mut buf) {
                Ok(n) => {
                    if let Some(key) = decode_keyboard_event(&buf[..n]) {
                        self.handle_key(key);
                    }
                }
                Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
                Err(e) => {
                    self.screen.write_str("terminal: keyboard service error: ");
                    self.screen.write_line(e.as_str());
                    self.screen.render();
                    libcanvas::process::yield_now();
                }
            }
        }
    }

    fn handle_key(&mut self, key: Key) {
        match key {
            Key::Char(byte) => {
                if self.input_len < self.input.len() && (0x20..=0x7e).contains(&byte) {
                    self.input[self.input_len] = byte;
                    self.input_len += 1;
                    self.screen.write_byte(byte);
                }
            }
            Key::Backspace => {
                if self.input_len > 0 {
                    self.input_len -= 1;
                    self.screen.backspace();
                }
            }
            Key::Enter => {
                self.screen.newline();
                let line = core::str::from_utf8(&self.input[..self.input_len]).unwrap_or("");
                execute_line(line, &mut self.screen);
                self.input_len = 0;
                self.prompt();
            }
        }
        self.screen.render();
    }

    fn prompt(&mut self) {
        self.screen.write_str("huesos> ");
    }
}
