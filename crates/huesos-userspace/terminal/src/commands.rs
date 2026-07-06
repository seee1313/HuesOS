//! Built-in shell command dispatcher.

use crate::ast::{Ast, CommandAst};
use crate::parser::{ParseError, Parser};
use crate::screen::Screen;

/// Parse and execute one line.
pub fn execute_line(line: &str, screen: &mut Screen) {
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
