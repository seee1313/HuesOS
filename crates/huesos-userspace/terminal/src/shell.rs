//! Terminal shell runtime and keyboard event loop.

use crate::commands::execute_line;
use crate::keyboard::{Key, KeyboardDecoder};
use crate::screen::Screen;
use libcanvas::{ErrorCode, Interrupt, Port, PORT_PACKET_INTERRUPT};

const INPUT_MAX: usize = 128;
const KEY_TERMINAL_KEYBOARD: u64 = 0x5445_524d_4b42_4451; // "TERMKBDQ"-ish.

/// Running terminal shell.
pub struct Shell {
    screen: Screen,
    input: [u8; INPUT_MAX],
    input_len: usize,
    keyboard: KeyboardDecoder,
    port: Port,
}

impl Shell {
    /// Create shell screen and bind keyboard IRQ packets to this terminal.
    pub fn new() -> libcanvas::Result<Self> {
        let mut screen = Screen::new();
        screen.clear();
        screen.write_line("HuesOS Terminal");
        screen.write_line("userspace mini shell: type 'help' and press Enter");
        screen.write_line("keyboard input: userspace Interrupt + Port bridge");
        screen.write_line("");

        let port = Port::create()?;
        let keyboard_irq = Interrupt::keyboard()?;
        keyboard_irq.bind_port(&port, KEY_TERMINAL_KEYBOARD)?;
        // Keep the interrupt object alive for this terminal lifetime. Later,
        // DriverManager will own this and hand out a keyboard service channel.
        core::mem::forget(keyboard_irq);

        let mut shell = Self {
            screen,
            input: [0; INPUT_MAX],
            input_len: 0,
            keyboard: KeyboardDecoder::new(),
            port,
        };
        shell.prompt();
        shell.screen.render();
        Ok(shell)
    }

    /// Run the shell forever.
    pub fn run(&mut self) -> ! {
        loop {
            match self.port.read() {
                Ok(packet)
                    if packet.packet_type == PORT_PACKET_INTERRUPT
                        && packet.key == KEY_TERMINAL_KEYBOARD =>
                {
                    if let Some(key) = self.keyboard.feed(packet.data[1] as u8) {
                        self.handle_key(key);
                    }
                }
                Ok(_) => {}
                Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
                Err(e) => {
                    self.screen.write_str("terminal: keyboard port error: ");
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
