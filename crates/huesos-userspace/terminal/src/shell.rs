//! Terminal shell runtime and keyboard event loop.

use crate::commands::execute_line;
use crate::screen::Screen;
use crate::snake;
use libcanvas::{Channel, ErrorCode};

const INPUT_MAX: usize = 128;

/// Running terminal shell.
pub struct Shell {
    screen: Screen,
    input: [u8; INPUT_MAX],
    input_len: usize,
    keyboard: Channel,
    filesystem: Option<Channel>,
    supervisor: Channel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Char(u8),
    Backspace,
    Enter,
    Esc,
}

fn decode_keyboard_event(msg: &[u8]) -> Option<Key> {
    match msg {
        [b'c', byte] => {
            if *byte == 27 {
                Some(Key::Esc)
            } else {
                Some(Key::Char(*byte))
            }
        }
        b"enter" => Some(Key::Enter),
        b"backspace" => Some(Key::Backspace),
        _ => None,
    }
}

impl Shell {
    /// Create shell screen using an already-open keyboard service channel.
    pub fn new(keyboard: Channel, filesystem: Option<Channel>, supervisor: Channel) -> Self {
        let mut screen = Screen::new();
        screen.clear();
        screen.write_line("HuesOS Terminal");
        screen.write_line("userspace mini shell — try 'snake' or 'snake hard'");
        screen.write_line("keyboard: DriverManager keyboard service");
        screen.write_line("");

        let mut shell = Self {
            screen,
            input: [0; INPUT_MAX],
            input_len: 0,
            keyboard,
            filesystem,
            supervisor,
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
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    libcanvas::process::yield_now();
                }
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
            Key::Esc => {
                // Clear current input line.
                while self.input_len > 0 {
                    self.input_len -= 1;
                    self.screen.backspace();
                }
            }
            Key::Enter => {
                self.screen.newline();
                let line = core::str::from_utf8(&self.input[..self.input_len]).unwrap_or("");
                let trimmed = line.trim();
                if trimmed == "snake" || trimmed == "snake hard" {
                    let hard = trimmed.ends_with("hard");
                    snake::run(&self.keyboard, hard);
                    self.redraw_after_game(hard);
                } else if trimmed == "shutdown" {
                    self.request_shutdown();
                } else {
                    execute_line(line, &mut self.screen, self.filesystem.as_ref());
                    self.prompt();
                }
                self.input_len = 0;
            }
        }
        self.screen.render();
    }

    fn request_shutdown(&mut self) {
        self.screen.clear();
        self.screen.write_line("HuesOS orderly shutdown requested");
        self.screen
            .write_line("Waiting for init to quiesce devices and halt all CPUs...");
        self.screen.render();
        if let Err(error) = self.supervisor.write(b"system:shutdown") {
            self.screen.write_str("shutdown request failed: ");
            self.screen.write_line(error.as_str());
            self.prompt();
        }
    }

    fn redraw_after_game(&mut self, hard: bool) {
        self.screen.clear();
        self.screen.write_line("HuesOS Terminal");
        if hard {
            self.screen
                .write_line("back from snake HARD — try 'snake' or 'snake hard'");
        } else {
            self.screen
                .write_line("back from snake — try 'snake' or 'snake hard'");
        }
        self.screen.write_line("");
        self.prompt();
        self.screen.render();
    }

    fn prompt(&mut self) {
        self.screen.write_str("huesos> ");
    }
}
