//! Built-in shell command dispatcher.

use crate::ast::{Ast, CommandAst};
use crate::parser::{ParseError, Parser};
use crate::screen::Screen;
use libcanvas::{Channel, ErrorCode};

/// Parse and execute one line.
pub fn execute_line(line: &str, screen: &mut Screen, filesystem: Option<&Channel>) {
    match Parser::new(line).parse() {
        Ok(Ast::Empty) => {}
        Ok(Ast::Command(command)) => execute_command(command, screen, filesystem),
        Err(ParseError::InvalidToken) => screen.write_line("parse error: invalid token"),
        Err(ParseError::TooManyArgs) => screen.write_line("parse error: too many arguments"),
    }
}

fn execute_command(command: CommandAst, screen: &mut Screen, filesystem: Option<&Channel>) {
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
            screen.write_line("  snake       play a simple TUI snake game");
            screen.write_line("  ast ...     parse and print command AST summary");
            screen.write_line("  ls [path]   list BOOTFS files");
            screen.write_line("  cat <path>  print BOOTFS file");
            screen.write_line("  stat <path> show BOOTFS file metadata");
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
        "ls" => fs_request(filesystem, "LIST", if command.argc == 0 { "/" } else { command.args[0] }, screen),
        "cat" => fs_request(filesystem, "CAT", if command.argc == 0 { "" } else { command.args[0] }, screen),
        "stat" => fs_request(filesystem, "STAT", if command.argc == 0 { "" } else { command.args[0] }, screen),
        "pwd" => screen.write_line("/"),
        "whoami" => screen.write_line("huesos"),
        "ast" => print_ast(command, screen),
        "snake" => {
            // Handled in Shell::handle_key before execute_line so we keep
            // the keyboard channel; if someone routes here, say so.
            screen.write_line("snake: launching from shell runtime…");
            screen.write_line("(if you see this, shell routing missed the game)");
        }
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

fn fs_request(filesystem: Option<&Channel>, op: &str, path: &str, screen: &mut Screen) {
    let Some(filesystem) = filesystem else {
        screen.write_line("filesystem service unavailable");
        return;
    };
    if path.is_empty() {
        screen.write_line("filesystem command requires a path");
        return;
    }
    let mut request = [0u8; 128];
    let mut len = 0;
    len = write_part(&mut request, len, op.as_bytes());
    len = write_part(&mut request, len, b" ");
    len = write_part(&mut request, len, path.as_bytes());
    if filesystem.write(&request[..len]).is_err() {
        screen.write_line("filesystem request failed");
        return;
    }
    let mut response = [0u8; 1024];
    loop {
        match filesystem.read_into(&mut response) {
            Ok(n) => {
                if let Ok(text) = core::str::from_utf8(&response[..n]) {
                    for line in text.split('\n') {
                        if !line.is_empty() {
                            screen.write_line(line);
                        }
                    }
                } else {
                    screen.write_line("filesystem returned non-utf8 data");
                }
                return;
            }
            Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
            Err(e) => {
                screen.write_str("filesystem response failed: ");
                screen.write_line(e.as_str());
                return;
            }
        }
    }
}

fn write_part(out: &mut [u8], mut len: usize, part: &[u8]) -> usize {
    for &byte in part {
        if len < out.len() {
            out[len] = byte;
            len += 1;
        }
    }
    len
}
