//! Production `hsh` interactive shell with Fish-style UX:
//! live syntax highlighting, history ghost autosuggestions, Tab completion,
//! readline/Fish hotkeys, and multi-line `{ ... }` blocks.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_hsh::{highlight_line, EvalAction, HighlightKind, ShellEnv};
use libcanvas::{println, Channel, ErrorCode, Handle, Vmo};

use crate::host::{FontChoice, PendingUiAction, TerminalHost};
use crate::screen::Screen;
use crate::snake;

const HISTORY_MAX: usize = 128;

const BUILTINS: &[&str] = &[
    "help", "clear", "cls", "echo", "pwd", "cd", "whoami", "about", "drivers", "ls", "cat", "stat",
    "touch", "mkdir", "write", "rm", "mv", "pci", "acpi", "ps", "caps", "hxfs", "fdisk", "where",
    "select", "sort", "head", "tail", "count", "grep", "font", "doom", "snake", "shutdown",
];

const FDISK_SUBCMDS: &[&str] = &[
    "list",
    "--list",
    "inspect",
    "verify",
    "gpt-init",
    "add",
    "del",
    "resize",
    "--type",
    "--size",
    "--start",
    "--name",
    "--dry-run",
];

type Rgb = (u8, u8, u8);
const COL_PROMPT_OK: Rgb = (95, 225, 185);
const COL_PROMPT_ERR: Rgb = (255, 115, 115);
const COL_PROMPT_PATH: Rgb = (125, 180, 255);
const COL_KEYWORD: Rgb = (210, 145, 255);
const COL_BUILTIN: Rgb = (95, 225, 255);
const COL_COMMAND: Rgb = (120, 240, 155);
const COL_CAPS: Rgb = (255, 195, 90);
const COL_STRING: Rgb = (180, 235, 140);
const COL_VAR: Rgb = (255, 150, 115);
const COL_OP: Rgb = (235, 240, 250);
const COL_COMMENT: Rgb = (105, 120, 145);
const COL_NUMBER: Rgb = (255, 210, 130);
const COL_DEFAULT: Rgb = (210, 225, 245);
const COL_GHOST: Rgb = (95, 115, 145);
const COL_ERROR: Rgb = (255, 110, 110);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Char(u8),
    Backspace,
    Delete,
    Enter,
    Tab,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    CtrlC,
    CtrlK,
    CtrlL,
    CtrlU,
    CtrlW,
}

fn decode_keyboard_event(msg: &[u8]) -> Option<Key> {
    match msg {
        [b'k', 1, 1] | [b'k', 1, 0x84] => Some(Key::Home),
        [b'k', 1, 3] => Some(Key::CtrlC),
        [b'k', 1, 5] | [b'k', 1, 0x85] => Some(Key::End),
        [b'k', 1, 8] | [b'k', 1, 127] => Some(Key::Backspace),
        [b'k', 1, b'\t'] => Some(Key::Tab),
        [b'k', 1, b'\n'] | [b'k', 1, b'\r'] => Some(Key::Enter),
        [b'k', 1, 11] => Some(Key::CtrlK),
        [b'k', 1, 12] => Some(Key::CtrlL),
        [b'k', 1, 21] => Some(Key::CtrlU),
        [b'k', 1, 23] => Some(Key::CtrlW),
        [b'k', 1, 27] => Some(Key::Esc),
        [b'k', 1, 0x80] => Some(Key::Up),
        [b'k', 1, 0x81] => Some(Key::Down),
        [b'k', 1, 0x82] => Some(Key::Left),
        [b'k', 1, 0x83] => Some(Key::Right),
        [b'k', 1, 0x86] => Some(Key::Delete),
        [b'k', 1, byte] if (0x20..=0x7e).contains(byte) => Some(Key::Char(*byte)),
        [b'k', 0, _] => None,
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

/// Interactive `hsh` terminal shell.
pub struct Shell {
    screen: Screen,
    keyboard: Channel,
    supervisor: Channel,
    host: TerminalHost,
    env: ShellEnv,
    input: String,
    cursor: usize,
    pending_multiline: String,
    history: Vec<String>,
    history_idx: Option<usize>,
    draft_before_history: String,
    prompt_row: usize,
}

impl Shell {
    /// Create the shell screen and runtime host.
    pub fn new(
        keyboard: Channel,
        filesystem: Option<Channel>,
        registry: Channel,
        bootfs: Option<Vmo>,
        supervisor: Channel,
        frame_draw: Option<Handle>,
    ) -> Self {
        let cap_raw = frame_draw.as_ref().map(|h| h.raw());
        let host = TerminalHost::new(registry, filesystem, bootfs, frame_draw);
        let mut screen = Screen::new_with_cap(cap_raw);
        screen.clear();
        screen.write_colored("HuesOS Terminal — hsh v1", COL_PROMPT_OK);
        screen.newline();
        screen.write_line("Type 'help' for builtins, pipes (| where/select/sort), @caps(...), and Tab completion.");
        screen.newline();

        let prompt_row = screen.current_row();
        let mut shell = Self {
            screen,
            keyboard,
            supervisor,
            host,
            env: ShellEnv::new(),
            input: String::new(),
            cursor: 0,
            pending_multiline: String::new(),
            history: Vec::new(),
            history_idx: None,
            draft_before_history: String::new(),
            prompt_row,
        };
        shell.redraw_prompt();
        shell
    }

    /// Run Cycle 3 deterministic serial smoke gates exercising `hsh`,
    /// `/bin/fdisk.elf` over `stdout` pipe, and `@caps(...)` attenuation.
    pub fn run_startup_smokes(&mut self) {
        let mut smoke_env = ShellEnv::new();

        // 1. Chain + `cls` + `fn` + `let` + `if ... contains` + no POSIX word splitting.
        let script = concat!(
            "cls ; ",
            "let msg = \"two  spaces\"; ",
            "fn check_msg(v) { if $v contains \"spaces\" { echo \"ok:$v\" } }; ",
            "check_msg $msg"
        );
        match smoke_env.eval_script(script, &mut self.host) {
            Ok(res)
                if res.status == 0
                    && res.actions.first() == Some(&EvalAction::ClearScreen)
                    && res.render_text() == "ok:two  spaces" =>
            {
                println!("[terminal] hsh core language/cls/fn smoke OK");
            }
            Ok(res) => println!(
                "[terminal] hsh core smoke FAILED status={} text={}",
                res.status,
                res.render_text()
            ),
            Err(err) => println!("[terminal] hsh core smoke ERROR: {}", err),
        }

        // 2. Real dynamic ELF `/bin/fdisk.elf` pipe: `fdisk list | where type == hxfs`
        match smoke_env.eval_script("fdisk list | where type == hxfs", &mut self.host) {
            Ok(res) if res.status == 0 && res.render_text().contains("HxFS-Root") => {
                println!("[terminal] hsh fdisk pipe OK");
            }
            Ok(res) => println!(
                "[terminal] hsh fdisk pipe FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(err) => println!("[terminal] hsh fdisk pipe ERROR: {}", err),
        }

        // 3. `@caps(hxfs=ro)` blocks mutating `/bin/fdisk.elf` subcommands
        match smoke_env.eval_script(
            "@caps(hxfs=ro) fdisk add --type hxfs --size 16M",
            &mut self.host,
        ) {
            Ok(res) if res.status != 0 && res.render_text().contains("AccessDenied") => {
                println!("[terminal] hsh @caps(hxfs=ro) enforcement OK");
            }
            Ok(res) => println!(
                "[terminal] hsh @caps(hxfs=ro) FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(err) => println!("[terminal] hsh @caps(hxfs=ro) ERROR: {}", err),
        }

        // 4. `@caps(hxfs=none, bootfs=none)` blocks `/bin/fdisk.elf` storage access + drops BOOTFS VMO
        match smoke_env.eval_script("@caps(hxfs=none, bootfs=none) fdisk list", &mut self.host) {
            Ok(res) if res.status != 0 && res.render_text().contains("AccessDenied") => {
                println!("[terminal] hsh @caps(hxfs=none,bootfs=none) enforcement OK");
            }
            Ok(res) => println!(
                "[terminal] hsh @caps(hxfs=none,bootfs=none) FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(err) => println!("[terminal] hsh @caps(hxfs=none,bootfs=none) ERROR: {}", err),
        }

        // Restore clean screen banner for interactive user.
        self.screen.clear();
        self.screen
            .write_colored("HuesOS Terminal — hsh v1", COL_PROMPT_OK);
        self.screen.newline();
        self.screen.write_line("Type 'help' for builtins, pipes (| where/select/sort), @caps(...), and Tab completion.");
        self.screen.newline();
        self.prompt_row = self.screen.current_row();
        self.redraw_prompt();
    }

    /// Run the interactive shell loop forever.
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
                Err(e) => {
                    println!("[terminal] keyboard read failed: {}", e.as_str());
                    libcanvas::process::yield_now();
                }
            }
        }
    }

    fn handle_keyboard_message(&mut self, msg: &[u8]) {
        let Some(key) = decode_keyboard_event(msg) else {
            return;
        };
        match key {
            Key::Char(b) => {
                let ch = b as char;
                self.input.insert(self.cursor, ch);
                self.cursor += 1;
                self.history_idx = None;
            }
            Key::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.input.remove(self.cursor);
                    self.history_idx = None;
                }
            }
            Key::Delete => {
                if self.cursor < self.input.len() {
                    self.input.remove(self.cursor);
                    self.history_idx = None;
                }
            }
            Key::Left => {
                self.cursor = self.cursor.saturating_sub(1);
            }
            Key::Right => {
                if self.cursor < self.input.len() {
                    self.cursor += 1;
                } else if let Some(ghost) = self.ghost_suffix().map(String::from) {
                    self.input.push_str(&ghost);
                    self.cursor = self.input.len();
                }
            }
            Key::Home => {
                self.cursor = 0;
            }
            Key::End => {
                if self.cursor == self.input.len() {
                    if let Some(ghost) = self.ghost_suffix().map(String::from) {
                        self.input.push_str(&ghost);
                    }
                }
                self.cursor = self.input.len();
            }
            Key::CtrlW => {
                if self.cursor > 0 {
                    let bytes = self.input.as_bytes();
                    let mut new_cur = self.cursor;
                    while new_cur > 0 && bytes[new_cur - 1] == b' ' {
                        new_cur -= 1;
                    }
                    while new_cur > 0 && bytes[new_cur - 1] != b' ' {
                        new_cur -= 1;
                    }
                    self.input.replace_range(new_cur..self.cursor, "");
                    self.cursor = new_cur;
                }
            }
            Key::CtrlU => {
                self.input.drain(..self.cursor);
                self.cursor = 0;
            }
            Key::CtrlK => {
                self.input.truncate(self.cursor);
            }
            Key::CtrlL => {
                self.screen.clear();
                self.prompt_row = 0;
            }
            Key::CtrlC => {
                self.screen.newline();
                self.screen.write_colored("^C", COL_ERROR);
                self.screen.newline();
                self.input.clear();
                self.cursor = 0;
                self.pending_multiline.clear();
                self.history_idx = None;
                self.prompt_row = self.screen.current_row();
            }
            Key::Esc => {
                self.input.clear();
                self.cursor = 0;
                self.history_idx = None;
            }
            Key::Up => self.history_prev(),
            Key::Down => self.history_next(),
            Key::Tab => self.handle_tab_complete(),
            Key::Enter => {
                self.submit_line();
                return;
            }
        }
        self.redraw_prompt();
    }

    fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let next_idx = match self.history_idx {
            None => {
                self.draft_before_history = self.input.clone();
                self.history.len() - 1
            }
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.history_idx = Some(next_idx);
        self.input = self.history[next_idx].clone();
        self.cursor = self.input.len();
    }

    fn history_next(&mut self) {
        let Some(idx) = self.history_idx else {
            return;
        };
        if idx + 1 >= self.history.len() {
            self.history_idx = None;
            self.input = self.draft_before_history.clone();
        } else {
            self.history_idx = Some(idx + 1);
            self.input = self.history[idx + 1].clone();
        }
        self.cursor = self.input.len();
    }

    fn ghost_suffix(&self) -> Option<&str> {
        if self.input.is_empty() {
            return None;
        }
        for entry in self.history.iter().rev() {
            if entry.len() > self.input.len() && entry.starts_with(&self.input) {
                return Some(&entry[self.input.len()..]);
            }
        }
        None
    }

    fn handle_tab_complete(&mut self) {
        let prefix_slice = &self.input[..self.cursor];
        let token_start = prefix_slice
            .rfind([' ', '\t', ';', '|', '&'])
            .map_or(0, |i| i + 1);
        let token = &prefix_slice[token_start..];

        if token == "@" || token.starts_with("@c") && !token.contains('(') {
            let tpl = "@caps(hxfs=ro, bootfs=ro, fb=ro)";
            self.input.replace_range(token_start..self.cursor, tpl);
            self.cursor = token_start + tpl.len();
            return;
        }

        let before = prefix_slice[..token_start].trim();
        let is_cmd_pos = before.is_empty()
            || before.ends_with(';')
            || before.ends_with('|')
            || before.ends_with("&&")
            || before.ends_with("||")
            || before.ends_with(')');

        let mut matches: Vec<String> = Vec::new();
        if is_cmd_pos && !token.starts_with('/') {
            for &b in BUILTINS {
                if b.starts_with(token) {
                    matches.push(String::from(b));
                }
            }
            for name in self.env.functions().keys() {
                if name.starts_with(token) && !matches.contains(name) {
                    matches.push(name.clone());
                }
            }
            for bin in self.host.list_bootfs_bins() {
                if bin.starts_with(token) && !matches.contains(&bin) {
                    matches.push(bin);
                }
            }
        } else if before.ends_with("fdisk") || before.contains("fdisk ") {
            for &sub in FDISK_SUBCMDS {
                if sub.starts_with(token) {
                    matches.push(String::from(sub));
                }
            }
        }
        if matches.is_empty() || token.starts_with('/') {
            for p in self.host.list_paths_for_completion(token) {
                if !matches.contains(&p) {
                    matches.push(p);
                }
            }
        }

        if matches.is_empty() {
            return;
        }
        if matches.len() == 1 {
            let mut rep = matches[0].clone();
            rep.push(' ');
            self.input.replace_range(token_start..self.cursor, &rep);
            self.cursor = token_start + rep.len();
            return;
        }

        // Complete longest common prefix; if no extension, list options cleanly.
        let lcp = longest_common_prefix(&matches);
        if lcp.len() > token.len() {
            self.input.replace_range(token_start..self.cursor, &lcp);
            self.cursor = token_start + lcp.len();
        } else {
            self.screen.newline();
            self.screen.write_colored(&matches.join("  "), COL_BUILTIN);
            self.screen.newline();
            self.prompt_row = self.screen.current_row();
        }
    }

    fn submit_line(&mut self) {
        self.screen.newline();
        if !self.pending_multiline.is_empty() {
            self.pending_multiline.push('\n');
        }
        self.pending_multiline.push_str(&self.input);
        self.input.clear();
        self.cursor = 0;
        self.history_idx = None;

        if has_unclosed_delims(&self.pending_multiline) {
            self.prompt_row = self.screen.current_row();
            self.redraw_prompt();
            return;
        }

        let script = core::mem::take(&mut self.pending_multiline);
        let trimmed = script.trim();
        if !trimmed.is_empty() {
            if self.history.last().map(String::as_str) != Some(trimmed) {
                if self.history.len() >= HISTORY_MAX {
                    self.history.remove(0);
                }
                self.history.push(String::from(trimmed));
            }
            match self.env.eval_script(trimmed, &mut self.host) {
                Ok(res) => {
                    for act in res.actions {
                        match act {
                            EvalAction::ClearScreen => self.screen.clear(),
                            EvalAction::Output(val) => {
                                let text = val.into_text();
                                if !text.is_empty() {
                                    if res.status != 0 {
                                        self.screen.write_colored(&text, COL_ERROR);
                                    } else {
                                        self.screen.write_str(&text);
                                    }
                                    if !text.ends_with('\n') {
                                        self.screen.newline();
                                    }
                                }
                            }
                            EvalAction::Exit => {}
                        }
                    }
                }
                Err(err) => {
                    self.env.last_status = 2;
                    self.screen.write_colored(&err, COL_ERROR);
                    self.screen.newline();
                }
            }
        }

        if let Some(ui) = self.host.pending_ui.take() {
            match ui {
                PendingUiAction::Doom => self.run_doom(),
                PendingUiAction::Snake { hard } => {
                    snake::run(
                        &self.keyboard,
                        hard,
                        self.host.frame_draw.as_ref().map(|h| h.raw()),
                    );
                    self.redraw_after_game(hard);
                }
                PendingUiAction::Shutdown => {
                    self.request_shutdown();
                    return;
                }
                PendingUiAction::Font(choice) => match choice {
                    FontChoice::Cozette => self.screen.use_cozette_font(),
                    FontChoice::Tty => self.screen.use_tty_font(),
                    FontChoice::Compact => self.screen.use_compact_font(),
                },
            }
        }

        self.prompt_row = self.screen.current_row();
        self.redraw_prompt();
    }

    fn redraw_prompt(&mut self) {
        self.screen.clear_from(self.prompt_row, 0);

        if self.pending_multiline.is_empty() {
            self.screen.write_colored(&self.host.pwd, COL_PROMPT_PATH);
            self.screen.write_str(" ");
            if self.env.last_status != 0 {
                let tag = format!("[{}] ", self.env.last_status);
                self.screen.write_colored(&tag, COL_PROMPT_ERR);
            }
            self.screen.write_colored("hsh> ", COL_PROMPT_OK);
        } else {
            self.screen.write_colored("..> ", COL_PROMPT_PATH);
        }

        let start_row = self.screen.current_row();
        let start_col = self.screen.current_col();

        // Highlight spans over `self.input`.
        let spans = highlight_line(&self.input, BUILTINS);
        let bytes = self.input.as_bytes();
        let mut pos = 0usize;
        for sp in spans {
            if sp.span.start > pos {
                if let Ok(gap) = core::str::from_utf8(&bytes[pos..sp.span.start]) {
                    self.screen.write_colored(gap, COL_DEFAULT);
                }
            }
            let color = match sp.kind {
                HighlightKind::Keyword => COL_KEYWORD,
                HighlightKind::Builtin => COL_BUILTIN,
                HighlightKind::Command => COL_COMMAND,
                HighlightKind::Caps => COL_CAPS,
                HighlightKind::StringLit => COL_STRING,
                HighlightKind::Variable => COL_VAR,
                HighlightKind::Operator => COL_OP,
                HighlightKind::Comment => COL_COMMENT,
                HighlightKind::Number => COL_NUMBER,
                HighlightKind::Default => COL_DEFAULT,
            };
            if let Ok(tok) = core::str::from_utf8(&bytes[sp.span.start..sp.span.end]) {
                self.screen.write_colored(tok, color);
            }
            pos = sp.span.end;
        }
        if pos < bytes.len() {
            if let Ok(tail) = core::str::from_utf8(&bytes[pos..]) {
                self.screen.write_colored(tail, COL_DEFAULT);
            }
        }

        let end_row = self.screen.current_row();
        let end_col = self.screen.current_col();

        if self.pending_multiline.is_empty() {
            if let Some(ghost) = self.ghost_suffix().map(String::from) {
                self.screen.write_colored(&ghost, COL_GHOST);
            }
        }

        let (cols, _) = self.screen.visible_size();
        let cols = cols.max(1);
        let abs = start_col + self.cursor;
        let cur_row = (start_row + abs / cols).min(end_row);
        let cur_col = if self.cursor == self.input.len() {
            end_col
        } else {
            abs % cols
        };
        self.screen.set_cursor(cur_row, cur_col);
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
                return Err(ErrorCode::InvalidArgs);
            }
            loop {
                let n = self.supervisor.read_into_blocking(&mut response)?;
                if response[..n].starts_with(b"doom:exited") {
                    return Ok(());
                }
            }
        })();

        self.screen.clear();
        self.screen
            .write_colored("HuesOS Terminal — hsh v1", COL_PROMPT_OK);
        self.screen.newline();
        match result {
            Ok(()) => self.screen.write_line("DOOM exited."),
            Err(error) => {
                self.screen.write_str("DOOM launch failed: ");
                self.screen.write_line(error.as_str());
            }
        }
        self.screen.newline();
        self.prompt_row = self.screen.current_row();
        self.redraw_prompt();
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
            self.prompt_row = self.screen.current_row();
            self.redraw_prompt();
        }
    }

    fn redraw_after_game(&mut self, hard: bool) {
        self.screen.clear();
        self.screen
            .write_colored("HuesOS Terminal — hsh v1", COL_PROMPT_OK);
        self.screen.newline();
        if hard {
            self.screen.write_line("Returned from Snake hard mode.");
        } else {
            self.screen.write_line("Returned from Snake.");
        }
        self.screen.newline();
        self.prompt_row = self.screen.current_row();
        self.redraw_prompt();
    }
}

fn has_unclosed_delims(s: &str) -> bool {
    let mut braces = 0i32;
    let mut brackets = 0i32;
    let mut in_sq = false;
    let mut in_dq = false;
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_sq {
            if b == b'\'' {
                in_sq = false;
            }
            i += 1;
            continue;
        }
        if in_dq {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_dq = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_sq = true,
            b'"' => in_dq = true,
            b'{' => braces += 1,
            b'}' => braces -= 1,
            b'[' => brackets += 1,
            b']' => brackets -= 1,
            _ => {}
        }
        i += 1;
    }
    braces > 0 || brackets > 0
}

fn longest_common_prefix(items: &[String]) -> String {
    let Some(first) = items.first() else {
        return String::new();
    };
    let mut prefix = first.as_bytes();
    for item in items.iter().skip(1) {
        let b = item.as_bytes();
        let mut len = 0usize;
        while len < prefix.len() && len < b.len() && prefix[len] == b[len] {
            len += 1;
        }
        prefix = &prefix[..len];
    }
    String::from(core::str::from_utf8(prefix).unwrap_or(""))
}
