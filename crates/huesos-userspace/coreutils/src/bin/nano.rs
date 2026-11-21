//! `/bin/nano.elf` — full-screen text editor.
//!
//! `nano [<path>]`
//!
//! The screen has a status line (file name, line count, byte count, modified
//! flag), a line-number gutter, the text with syntax highlighting for HuesOS
//! shell scripts (`.hsh`), Rust sources (`.rs`) and `key = value` configs, and a
//! two-line key legend.
//!
//! Keys: arrows (and `^A`/`^E` for home/end), `Home`/`End`, `PgUp`/`PgDn`,
//! `Enter`, `Backspace`, `Delete`, `^O`/`^S` save, `^W` search, `^K` cut line,
//! `^U` paste, `^G` go to line, `^X`/`^Q` quit -- refusing to lose an unsaved
//! buffer without a second `^X`.
//!
//! The buffer is one `Vec<char>` per line: an editor over a text file is a
//! line-and-column problem, and a rope buys nothing at the sizes a HuesOS
//! console edits.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;
use huesos_std::tui::{self, Key};

huesos_std::entry!(run);

/// Visible text rows between the status line and the legend.
const TEXT_ROWS: usize = 16;
/// Column the text starts at, after the line-number gutter.
const GUTTER: usize = 6;
/// Visible text columns.
const TEXT_COLS: usize = 74;

/// How a line is coloured.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Class {
    Plain,
    Comment,
    Keyword,
    String,
    Number,
    Key,
}

/// What kind of file this is, for highlighting purposes.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Syntax {
    Plain,
    Shell,
    Rust,
    Config,
}

impl Syntax {
    fn from_path(path: &str) -> Self {
        let name = path::file_name(path).unwrap_or(path);
        if name.ends_with(".hsh") || name.ends_with(".sh") || name == "huesosrc" {
            Syntax::Shell
        } else if name.ends_with(".rs") {
            Syntax::Rust
        } else if name.ends_with(".conf")
            || name.ends_with(".ini")
            || name.ends_with(".toml")
            || name.ends_with(".cfg")
        {
            Syntax::Config
        } else {
            Syntax::Plain
        }
    }

    fn name(self) -> &'static str {
        match self {
            Syntax::Shell => "hsh",
            Syntax::Rust => "rust",
            Syntax::Config => "config",
            Syntax::Plain => "text",
        }
    }
}

struct Editor {
    path: String,
    lines: Vec<Vec<char>>,
    /// Cursor row and column, both zero-based.
    row: usize,
    column: usize,
    /// First visible row.
    top: usize,
    dirty: bool,
    status: String,
    syntax: Syntax,
    /// Cut-line buffer for `^K`/`^U`.
    clipboard: Option<Vec<char>>,
    /// While a search is being typed, the needle; `None` outside `^W`.
    search: Option<String>,
    /// Set when a quit was refused once because the buffer is dirty.
    quit_confirmed: bool,
}

fn run() -> i32 {
    let args = args();
    let path = args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::from)
        .unwrap_or_else(|| String::from("untitled"));
    let mut editor = match load(&path) {
        Ok(editor) => editor,
        Err(error) => {
            eprintln!("nano: {path}: {error}");
            return 1;
        }
    };
    let mut screen = tui::Screen::new(io::stdout());
    let _ = screen.hide_cursor();
    let code = match edit(&mut editor, &mut screen) {
        Ok(()) => 0,
        Err(error) => {
            let _ = screen.show_cursor();
            eprintln!("nano: {error}");
            1
        }
    };
    let _ = screen.show_cursor();
    code
}

fn load(path: &str) -> Result<Editor> {
    let normalized = path::normalize(path);
    let mut lines = if fs::metadata(&normalized)
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        let mut file = fs::File::open(&normalized)?;
        let mut bytes = Vec::new();
        io::read_to_end(&mut file, &mut bytes)?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let mut lines: Vec<Vec<char>> = text
            .split('\n')
            .map(|line| line.chars().collect())
            .collect();
        // A file ending in a newline has a phantom empty last line; drop it so
        // the cursor can never sit below the real end of the text.
        if text.ends_with('\n') {
            lines.pop();
        }
        lines
    } else {
        Vec::new()
    };
    if lines.is_empty() {
        lines.push(Vec::new());
    }
    Ok(Editor {
        syntax: Syntax::from_path(&normalized),
        path: String::from(normalized.as_str()),
        lines,
        row: 0,
        column: 0,
        top: 0,
        dirty: false,
        status: String::new(),
        clipboard: None,
        search: None,
        quit_confirmed: false,
    })
}

fn edit(editor: &mut Editor, screen: &mut tui::Screen<io::Stdout>) -> Result<()> {
    let mut input = io::stdin();
    loop {
        draw(editor, screen)?;
        let Some(key) = tui::read_key(&mut input) else {
            // A closed console is a quit, but never a silent data loss.
            if editor.dirty {
                return Err(fail("input closed with unsaved changes"));
            }
            return Ok(());
        };
        if editor.search.is_some() {
            match key {
                Key::Char(byte) => {
                    if let Some(needle) = editor.search.as_mut() {
                        needle.push(char::from(byte));
                    }
                }
                Key::Backspace => {
                    if let Some(needle) = editor.search.as_mut() {
                        needle.pop();
                    }
                }
                Key::Enter => {
                    let needle = editor.search.take().unwrap_or_default();
                    if !needle.is_empty() && !find(editor, &needle) {
                        editor.status = format!("not found: {needle}");
                    }
                }
                Key::Escape | Key::Ctrl(3) | Key::Ctrl(7) => editor.search = None,
                _ => {}
            }
            continue;
        }
        match key {
            Key::Ctrl(24) | Key::Ctrl(17) => {
                // `^X`/`^Q`: a dirty buffer needs a second press.
                if editor.dirty && !editor.quit_confirmed {
                    editor.quit_confirmed = true;
                    editor.status =
                        String::from("unsaved changes: press ^X again to discard, ^O to save");
                    continue;
                }
                return Ok(());
            }
            Key::Ctrl(15) | Key::Ctrl(19) => save(editor)?,
            Key::Ctrl(23) => {
                editor.search = Some(String::new());
                editor.status = String::from("search: ");
            }
            Key::Ctrl(11) => {
                let line = editor.lines[editor.row].clone();
                editor.clipboard = Some(line);
                if editor.lines.len() > 1 {
                    editor.lines.remove(editor.row);
                    if editor.row >= editor.lines.len() {
                        editor.row = editor.lines.len() - 1;
                    }
                } else {
                    editor.lines[0].clear();
                }
                editor.column = editor.column.min(editor.lines[editor.row].len());
                editor.dirty = true;
                editor.status = String::from("line cut");
            }
            Key::Ctrl(21) => {
                if let Some(line) = editor.clipboard.clone() {
                    editor.lines.insert(editor.row, line);
                    editor.dirty = true;
                    editor.status = String::from("line pasted");
                }
            }
            Key::Ctrl(7) => {
                // `^G`: go to a line.
                editor.status = String::from("go to line: ");
                if let Some(text) = tui::prompt(screen.out(), &mut input, "go to line") {
                    match text.trim().parse::<usize>() {
                        Ok(number) if number >= 1 && number <= editor.lines.len() => {
                            editor.row = number - 1;
                            editor.column = 0;
                            editor.status = format!("line {number}");
                        }
                        _ => editor.status = format!("no such line: {text}"),
                    }
                }
            }
            Key::Up if editor.row > 0 => {
                editor.row -= 1;
                clamp_column(editor);
            }
            Key::Down if editor.row + 1 < editor.lines.len() => {
                editor.row += 1;
                clamp_column(editor);
            }
            Key::Left => {
                if editor.column > 0 {
                    editor.column -= 1;
                } else if editor.row > 0 {
                    editor.row -= 1;
                    editor.column = editor.lines[editor.row].len();
                }
            }
            Key::Right => {
                if editor.column < editor.lines[editor.row].len() {
                    editor.column += 1;
                } else if editor.row + 1 < editor.lines.len() {
                    editor.row += 1;
                    editor.column = 0;
                }
            }
            Key::Home | Key::Ctrl(1) => editor.column = 0,
            Key::End | Key::Ctrl(5) => editor.column = editor.lines[editor.row].len(),
            Key::PageUp => {
                editor.row = editor.row.saturating_sub(TEXT_ROWS);
                clamp_column(editor);
            }
            Key::PageDown => {
                editor.row = (editor.row + TEXT_ROWS).min(editor.lines.len() - 1);
                clamp_column(editor);
            }
            Key::Enter => {
                let tail: Vec<char> = editor.lines[editor.row].split_off(editor.column);
                editor.lines.insert(editor.row + 1, tail);
                editor.row += 1;
                editor.column = 0;
                editor.dirty = true;
            }
            Key::Backspace => {
                if editor.column > 0 {
                    editor.lines[editor.row].remove(editor.column - 1);
                    editor.column -= 1;
                    editor.dirty = true;
                } else if editor.row > 0 {
                    let line = editor.lines.remove(editor.row);
                    editor.row -= 1;
                    editor.column = editor.lines[editor.row].len();
                    editor.lines[editor.row].extend(line);
                    editor.dirty = true;
                }
            }
            Key::Delete => {
                if editor.column < editor.lines[editor.row].len() {
                    editor.lines[editor.row].remove(editor.column);
                    editor.dirty = true;
                } else if editor.row + 1 < editor.lines.len() {
                    let next = editor.lines.remove(editor.row + 1);
                    editor.lines[editor.row].extend(next);
                    editor.dirty = true;
                }
            }
            Key::Tab => {
                for _ in 0..4 {
                    editor.lines[editor.row].insert(editor.column, ' ');
                    editor.column += 1;
                }
                editor.dirty = true;
            }
            Key::Char(byte) if !byte.is_ascii_control() => {
                editor.lines[editor.row].insert(editor.column, char::from(byte));
                editor.column += 1;
                editor.dirty = true;
            }
            _ => {}
        }
        // Scrolling keeps the cursor visible with a two-line margin.
        if editor.row < editor.top {
            editor.top = editor.row;
        } else if editor.row >= editor.top + TEXT_ROWS {
            editor.top = editor.row + 1 - TEXT_ROWS;
        }
        if let Some(needle) = &editor.search {
            editor.status = format!("search: {needle}");
        } else if editor.status.contains("search:") {
            editor.status.clear();
        }
    }
}

/// A failure with a fixed explanation.
fn fail(message: &'static str) -> Error {
    Error::from(Error::invalid(message))
}

fn clamp_column(editor: &mut Editor) {
    let length = editor.lines[editor.row].len();
    if editor.column > length {
        editor.column = length;
    }
}

fn save(editor: &mut Editor) -> Result<()> {
    if editor.path == "untitled" {
        editor.status = String::from("no file name: start nano with a path");
        return Ok(());
    }
    let mut text = String::new();
    for line in &editor.lines {
        for ch in line {
            text.push(*ch);
        }
        text.push('\n');
    }
    fs::write(&editor.path, text.as_bytes())?;
    editor.dirty = false;
    editor.status = format!("wrote {} bytes", text.len());
    Ok(())
}

/// Move the cursor to the first line containing `needle` at or after it.
fn find(editor: &mut Editor, needle: &str) -> bool {
    let needle: Vec<char> = needle.chars().collect();
    for offset in 0..editor.lines.len() {
        let index = (editor.row + offset) % editor.lines.len();
        let line = &editor.lines[index];
        if let Some(position) = line
            .windows(needle.len().max(1))
            .position(|window| window == needle.as_slice())
        {
            editor.row = index;
            editor.column = position;
            editor.status = format!("found at line {}", index + 1);
            return true;
        }
    }
    false
}

fn draw(editor: &mut Editor, screen: &mut tui::Screen<io::Stdout>) -> Result<()> {
    let mut out = String::new();
    out.push_str("\x1b[2J\x1b[H");
    let name = path::file_name(&editor.path).unwrap_or(&editor.path);
    let state = if editor.dirty { " [MODIFIED]" } else { "" };
    let status = format!(
        " HuesOS nano  {name}{state}  lines {}  bytes {}  {}{}",
        editor.lines.len(),
        byte_count(editor),
        editor.syntax.name(),
        if editor.status.is_empty() {
            String::new()
        } else {
            format!("  |  {}", editor.status)
        }
    );
    out.push_str(&format!("\x1b[7m{}\x1b[0m\r\n", tui::fit(&status, 79)));
    let mut gutter = String::from(" ");
    gutter.push_str(&tui::frame_top(&format!("{name} "), 78));
    out.push_str(&gutter);
    out.push_str("\r\n");

    for row in 0..TEXT_ROWS {
        let index = editor.top + row;
        let mut text = String::from("│");
        match editor.lines.get(index) {
            Some(line) => {
                let number = format!("{:>4} ", index + 1);
                text.push_str(&tui::colored(&number, tui::Color::Cyan));
                text.push(' ');
                let rendered = highlight(editor.syntax, line);
                text.push_str(&tui::fit(&rendered, TEXT_COLS));
            }
            None => {
                text.push_str(&tui::fit("", GUTTER - 2 + TEXT_COLS));
            }
        }
        text.push('│');
        out.push_str(&text);
        out.push_str("\r\n");
    }
    out.push_str(&tui::frame_bottom(78));
    out.push_str("\r\n");
    out.push_str(&tui::fit(
        " ^O save   ^W search   ^K cut   ^U paste   ^G goto   ^X quit",
        GUTTER - 2 + TEXT_COLS + 2,
    ));
    out.push_str("\r\n");
    out.push_str(&format!(
        " ln {:<4} col {:<4}",
        editor.row + 1,
        editor.column + 1
    ));
    screen.write_raw(&out)
}

fn byte_count(editor: &Editor) -> usize {
    editor.lines.iter().map(|line| line.len() + 1).sum()
}

/// Colour one line according to the file's syntax.
fn highlight(syntax: Syntax, line: &[char]) -> String {
    let mut out = String::new();
    let mut index = 0;
    let text: String = line.iter().collect();
    while index < line.len() {
        let rest: String = line[index..].iter().collect();
        if syntax != Syntax::Plain {
            let (class, length) = classify(syntax, &rest);
            let chunk: String = line[index..(index + length).min(line.len())]
                .iter()
                .collect();
            if class == Class::Plain {
                out.push_str(&chunk);
            } else {
                out.push_str(&tui::colored(&chunk, class_color(class)));
            }
            index += length.max(1);
        } else {
            out.push(line[index]);
            index += 1;
        }
    }
    let _ = text;
    out
}

fn class_color(class: Class) -> tui::Color {
    match class {
        Class::Comment => tui::Color::Green,
        Class::Keyword => tui::Color::Magenta,
        Class::String => tui::Color::Yellow,
        Class::Number => tui::Color::Cyan,
        Class::Key => tui::Color::Blue,
        Class::Plain => tui::Color::White,
    }
}

/// Classify the token at the start of `text`, returning its class and length.
fn classify(syntax: Syntax, text: &str) -> (Class, usize) {
    let mut chars = text.chars();
    let first = chars.next().unwrap_or(' ');
    // Comments run to end of line in all three syntaxes.
    let comment = match syntax {
        Syntax::Shell => first == '#',
        _ => text.starts_with("//"),
    };
    if comment {
        return (Class::Comment, text.chars().count());
    }
    if first == '"' || first == '\'' {
        let mut length = 1;
        for ch in chars {
            length += 1;
            if ch == first {
                break;
            }
        }
        return (Class::String, length);
    }
    if first.is_ascii_digit() {
        let length = text
            .chars()
            .take_while(|ch| ch.is_ascii_digit() || *ch == '.' || *ch == 'x')
            .count();
        return (Class::Number, length.max(1));
    }
    let word: String = text
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect();
    if word.is_empty() {
        return (Class::Plain, 1);
    }
    let is_keyword = match syntax {
        Syntax::Shell => matches!(
            word.as_str(),
            "if" | "then"
                | "else"
                | "fi"
                | "for"
                | "while"
                | "do"
                | "done"
                | "case"
                | "esac"
                | "in"
                | "fn"
                | "let"
                | "return"
                | "export"
                | "local"
                | "echo"
                | "cd"
                | "exit"
        ),
        Syntax::Rust => matches!(
            word.as_str(),
            "fn" | "let"
                | "mut"
                | "pub"
                | "use"
                | "mod"
                | "struct"
                | "enum"
                | "impl"
                | "match"
                | "if"
                | "else"
                | "for"
                | "while"
                | "loop"
                | "return"
                | "self"
                | "crate"
                | "unsafe"
                | "const"
                | "static"
                | "trait"
                | "where"
        ),
        Syntax::Config => false,
        Syntax::Plain => false,
    };
    if is_keyword {
        return (Class::Keyword, word.len());
    }
    // `key = value` in a config file: colour the key.
    if syntax == Syntax::Config {
        let after: String = text.chars().skip(word.len()).collect();
        if after.trim_start().starts_with('=') {
            return (Class::Key, word.len());
        }
    }
    (Class::Plain, word.len())
}
