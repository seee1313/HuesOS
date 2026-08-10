//! Terminal shell runtime and keyboard event loop.

#[cfg(feature = "soak-shutdown")]
use crate::println;
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
        [b'k', 1, 27] => Some(Key::Esc),
        [b'k', 1, b'\n'] => Some(Key::Enter),
        [b'k', 1, 8] => Some(Key::Backspace),
        [b'k', 1, byte] => Some(Key::Char(*byte)),
        // Releases are intentionally ignored by the line editor.
        [b'k', 0, _] => None,
        // Compatibility with an older input host during rolling updates.
        [b'c', byte] => Some(if *byte == 27 {
            Key::Esc
        } else {
            Key::Char(*byte)
        }),
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
        screen.write_line("Type 'help' to list available commands.");
        screen.write_line("Cozette 6x13 font active; use 'font tty' or 'font compact'.");
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
        #[cfg(feature = "soak-shutdown")]
        let mut idle_polls: u32 = 0;
        loop {
            #[cfg(feature = "soak-shutdown")]
            let read = self.keyboard.read_into_timeout(&mut buf, 100);
            #[cfg(not(feature = "soak-shutdown"))]
            let read = self.keyboard.read_into_blocking(&mut buf);
            match read {
                Ok(n) => {
                    #[cfg(feature = "soak-shutdown")]
                    {
                        idle_polls = 0;
                    }
                    self.handle_keyboard_message(&buf[..n]);
                }
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    #[cfg(feature = "soak-shutdown")]
                    {
                        // Soak wiring: after enough idle timeouts (a
                        // few seconds under QEMU TCG at 100 ticks per
                        // read), trigger the orderly userspace
                        // shutdown so the harness can observe the
                        // full halt chain.
                        idle_polls += 1;
                        if idle_polls >= 30 {
                            println!("[terminal] soak-shutdown: auto-triggering orderly shutdown");
                            self.request_shutdown();
                            loop {
                                libcanvas::process::yield_now();
                            }
                        }
                    }
                    libcanvas::process::yield_now();
                }
                Err(e) => self.report_keyboard_error(e),
            }
        }
    }

    fn handle_keyboard_message(&mut self, msg: &[u8]) {
        if let Some(key) = decode_keyboard_event(msg) {
            self.handle_key(key);
        }
    }

    fn report_keyboard_error(&mut self, error: ErrorCode) {
        self.screen.write_str("terminal: keyboard service error: ");
        self.screen.write_line(error.as_str());
        self.screen.render();
        libcanvas::process::yield_now();
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
                if trimmed == "doom" {
                    self.run_doom();
                } else if trimmed == "snake" || trimmed == "snake hard" {
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

    fn run_doom(&mut self) {
        self.screen.clear();
        self.screen
            .write_line("Launching DOOM (Freedoom Phase 1)...");
        self.screen
            .write_line("Controls: WASD move, F fire, E use, Esc menu, Q quit");
        self.screen.render();

        let result = (|| -> libcanvas::Result<()> {
            let keyboard = self.keyboard.duplicate()?;
            self.supervisor
                .write_handle(b"system:launch-doom", keyboard.into_handle())
                .map_err(|(error, _handle)| error)?;
            let mut response = [0u8; 64];
            let n = self.supervisor.read_into_blocking(&mut response)?;
            if !response[..n].starts_with(b"doom:started") {
                return Err(libcanvas::ErrorCode::InvalidArgs);
            }
            // Doom owns the duplicated keyboard endpoint and framebuffer.
            // Block only on the supervisor channel; init polls process state
            // and sends doom:exited after normal menu quit or the Q shortcut.
            loop {
                let n = self.supervisor.read_into_blocking(&mut response)?;
                if response[..n].starts_with(b"doom:exited") {
                    return Ok(());
                }
            }
        })();

        self.screen.clear();
        self.screen.write_line("HuesOS Terminal");
        match result {
            Ok(()) => self.screen.write_line("DOOM exited."),
            Err(error) => {
                self.screen.write_str("DOOM launch failed: ");
                self.screen.write_line(error.as_str());
            }
        }
        self.screen
            .write_line("Type 'help' to list available commands.");
        self.screen.write_line("");
        self.prompt();
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
            self.screen.write_line("Returned from Snake hard mode.");
        } else {
            self.screen.write_line("Returned from Snake.");
        }
        self.screen
            .write_line("Type 'help' to list available commands.");
        self.screen.write_line("");
        self.prompt();
    }

    fn prompt(&mut self) {
        self.screen.write_str("huesos> ");
    }
}
