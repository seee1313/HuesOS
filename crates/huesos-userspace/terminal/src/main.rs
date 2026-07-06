//! HuesOS framebuffer terminal + built-in mini shell.
//!
//! This terminal is intentionally self-contained for the current migration
//! stage: it consumes keyboard IRQ packets through the userspace
//! Interrupt+Port bridge and runs a small internal command shell. External
//! program execution is deliberately not supported yet.

#![no_std]
#![no_main]

use core::iter::Peekable;
use core::panic::PanicInfo;
use libcanvas::framebuffer::Canvas;
use libcanvas::{println, ErrorCode, Interrupt, Port, PORT_PACKET_INTERRUPT};
use logos::Logos;

const ROWS: usize = 44;
const COLS: usize = 96;
const LINE_HEIGHT: u32 = 16;
const LEFT_MARGIN: u32 = 16;
const TOP_MARGIN: u32 = 16;
const INPUT_MAX: usize = 128;
const MAX_ARGS: usize = 8;
const KEY_TERMINAL_KEYBOARD: u64 = 0x5445_524d_4b42_4451; // "TERMKBDQ"-ish.

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[terminal] started in userspace");

    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"terminal:ready");

    match Shell::new() {
        Ok(mut shell) => shell.run(),
        Err(e) => {
            println!("[terminal] failed to initialize shell: {}", e.as_str());
            loop {
                libcanvas::process::yield_now();
            }
        }
    }
}

struct Shell {
    screen: Screen,
    input: [u8; INPUT_MAX],
    input_len: usize,
    keyboard: KeyboardDecoder,
    port: Port,
}

impl Shell {
    fn new() -> libcanvas::Result<Self> {
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

    fn run(&mut self) -> ! {
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

struct Screen {
    canvas: Option<Canvas>,
    cells: [[u8; COLS]; ROWS],
    row: usize,
    col: usize,
}

impl Screen {
    fn new() -> Self {
        Self {
            canvas: Canvas::new_fullscreen().ok(),
            cells: [[b' '; COLS]; ROWS],
            row: 0,
            col: 0,
        }
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
            if byte == b'\n' {
                self.newline();
            } else {
                self.write_byte(byte);
            }
        }
    }

    fn write_byte(&mut self, byte: u8) {
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

    fn backspace(&mut self) {
        if self.col > 0 {
            self.col -= 1;
            self.cells[self.row][self.col] = b' ';
        }
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
                    let _ = canvas.draw_text(
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
        let _ = canvas.present();
    }
}

fn line_len(line: &[u8; COLS]) -> usize {
    let mut len = COLS;
    while len > 0 && line[len - 1] == b' ' {
        len -= 1;
    }
    len
}

#[derive(Clone, Copy, Debug, PartialEq, Logos)]
#[logos(skip r"[ \t\r\n\f]+")]
enum Token<'src> {
    #[token(";")]
    Semicolon,
    #[regex(r#""[^"\r\n]*""#, |lex| lex.slice())]
    Quoted(&'src str),
    #[regex(r"[^ \t\r\n\f;]+", |lex| lex.slice())]
    Word(&'src str),
}

#[derive(Clone, Copy)]
struct CommandAst<'src> {
    name: &'src str,
    args: [&'src str; MAX_ARGS],
    argc: usize,
}

enum Ast<'src> {
    Empty,
    Command(CommandAst<'src>),
}

struct Parser<'src> {
    tokens: Peekable<logos::Lexer<'src, Token<'src>>>,
}

impl<'src> Parser<'src> {
    fn new(input: &'src str) -> Self {
        Self {
            tokens: Token::lexer(input).peekable(),
        }
    }

    fn parse(mut self) -> Result<Ast<'src>, ParseError> {
        while matches!(self.tokens.peek(), Some(Ok(Token::Semicolon))) {
            let _ = self.tokens.next();
        }

        let Some(first) = self.tokens.next() else {
            return Ok(Ast::Empty);
        };
        let name = match first {
            Ok(Token::Word(word)) | Ok(Token::Quoted(word)) => normalize_atom(word),
            Ok(Token::Semicolon) => return Ok(Ast::Empty),
            Err(_) => return Err(ParseError::InvalidToken),
        };

        let mut command = CommandAst {
            name,
            args: [""; MAX_ARGS],
            argc: 0,
        };

        loop {
            match self.tokens.peek() {
                None => break,
                Some(Ok(Token::Semicolon)) => {
                    let _ = self.tokens.next();
                    break;
                }
                Some(Ok(Token::Word(_))) | Some(Ok(Token::Quoted(_))) => {
                    let token = self.tokens.next().unwrap();
                    let arg = match token {
                        Ok(Token::Word(word)) | Ok(Token::Quoted(word)) => normalize_atom(word),
                        _ => return Err(ParseError::InvalidToken),
                    };
                    if command.argc >= command.args.len() {
                        return Err(ParseError::TooManyArgs);
                    }
                    command.args[command.argc] = arg;
                    command.argc += 1;
                }
                Some(Err(_)) => return Err(ParseError::InvalidToken),
            }
        }

        Ok(Ast::Command(command))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParseError {
    InvalidToken,
    TooManyArgs,
}

fn normalize_atom(atom: &str) -> &str {
    let bytes = atom.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        &atom[1..atom.len() - 1]
    } else {
        atom
    }
}

fn execute_line(line: &str, screen: &mut Screen) {
    match Parser::new(line).parse() {
        Ok(Ast::Empty) => {}
        Ok(Ast::Command(command)) => execute_command(command, screen),
        Err(ParseError::InvalidToken) => screen.write_line("parse error: invalid token"),
        Err(ParseError::TooManyArgs) => screen.write_line("parse error: too many arguments"),
    }
}

fn execute_command(command: CommandAst, screen: &mut Screen) {
    match command.name {
        "help" => {
            screen.write_line("builtins:");
            screen.write_line("  help        show this help");
            screen.write_line("  clear|cls   clear the screen");
            screen.write_line("  echo ...    print arguments");
            screen.write_line("  about       show system shell info");
            screen.write_line("  drivers     show driver migration state");
            screen.write_line("  pwd         show current pseudo-directory");
            screen.write_line("  whoami      show current user identity");
            screen.write_line("  ast ...     parse and print command AST summary");
        }
        "clear" | "cls" => screen.clear(),
        "echo" => {
            write_args(command, screen);
            screen.newline();
        }
        "about" => {
            screen.write_line("HuesOS userspace terminal shell");
            screen.write_line("lexer: logos; parser: Peekable token iterator; AST: Command");
            screen.write_line("program launching is intentionally disabled for now");
        }
        "drivers" => {
            screen.write_line("DriverManager: userspace process");
            screen.write_line("Keyboard: IRQ1 -> Interrupt -> Port -> userspace scancodes");
            screen.write_line("Framebuffer: terminal still uses Canvas/FramebufferBlit bridge");
        }
        "pwd" => screen.write_line("/"),
        "whoami" => screen.write_line("huesos"),
        "ast" => print_ast(command, screen),
        "exit" => screen.write_line("exit: init-supervised shell cannot exit yet"),
        _ => {
            screen.write_str("unknown command: ");
            screen.write_line(command.name);
            screen.write_line("type 'help' for builtins");
        }
    }
}

fn write_args(command: CommandAst, screen: &mut Screen) {
    let mut i = 0;
    while i < command.argc {
        if i > 0 {
            screen.write_byte(b' ');
        }
        screen.write_str(command.args[i]);
        i += 1;
    }
}

fn print_ast(command: CommandAst, screen: &mut Screen) {
    screen.write_str("Ast::Command { name: ");
    screen.write_str(command.name);
    screen.write_str(", argc: ");
    screen.write_usize(command.argc);
    screen.write_line(" }");
}

impl Screen {
    fn write_usize(&mut self, mut value: usize) {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Char(u8),
    Backspace,
    Enter,
}

struct KeyboardDecoder {
    shift: bool,
}

impl KeyboardDecoder {
    const fn new() -> Self {
        Self { shift: false }
    }

    fn feed(&mut self, scancode: u8) -> Option<Key> {
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[terminal] PANIC\n");
    libcanvas::process::exit(-1);
}
