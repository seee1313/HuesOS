//! `/bin/hsh.elf` — HuesOS dynamic shell executable (`ET_DYN` + `libcanvas.so`).
//!
//! Supports:
//! - `--interactive`: bidirectional IPC shell session hosted by `terminal`.
//! - `-c "<script>"`: evaluate inline script and write plain output to `stdout`/`stderr`.
//! - `<path.hsh>`: read script from `HxFS` or `BOOTFS` and evaluate.

#![no_std]
#![no_main]

extern crate alloc;

mod host;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use host::{DelegatedAction, HshHost};
use huesos_abi::term_ipc::{
    hsh_to_term, put_i32, put_u16, term_to_hsh, SpanKind, MAX_PROMPT_GHOST, MAX_PROMPT_INPUT,
    MAX_PROMPT_SPANS, MAX_PWD_BYTES, MAX_WRITE_CHUNK,
};
use huesos_hsh::{highlight_line, EvalAction, HighlightKind, ShellEnv};
use libcanvas::heap::ScudoHeap;
use libcanvas::stdio::{
    arg_str, args_count, exit, stderr_str, stdin_read, stdout_str, take_cap_handle, CapKind,
};
use libcanvas::{println, Channel, ErrorCode, Vmo};

#[global_allocator]
static ALLOCATOR: ScudoHeap = ScudoHeap;

const HISTORY_MAX: usize = 128;

const KNOWN_COMMANDS: &[&str] = &[
    "help", "clear", "cls", "echo", "pwd", "cd", "history", "caps", "exit", "font", "doom",
    "snake", "shutdown", "where", "select", "sort", "head", "tail", "count", "grep", "ls", "cat",
    "stat", "touch", "mkdir", "rm", "mv", "write", "hxfs", "pci", "acpi", "ps", "fdisk", "sleep",
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
    "--force",
    "--type",
    "--size",
    "--start",
    "--name",
    "--dry-run",
];

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "call {entry}",
        "ud2",
        entry = sym hsh_entry,
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    println!("[hsh] PANIC");
    exit(1)
}

extern "C" fn hsh_entry() -> ! {
    let argc = args_count();
    let mut args: Vec<String> = Vec::new();
    let mut arg_buf = [0u8; 512];
    for i in 1..argc {
        if let Some(s) = arg_str(i, &mut arg_buf) {
            args.push(String::from(s));
        }
    }

    let registry = take_cap_handle(CapKind::Registry).map(Channel::from_handle);
    let bootfs = take_cap_handle(CapKind::BootfsRo).map(Vmo::from_handle);
    let frame_draw = take_cap_handle(CapKind::FrameDraw);

    if args.first().map(String::as_str) == Some("--interactive") {
        let stdin_ch = take_cap_handle(CapKind::Stdin).map(Channel::from_handle);
        let stdout_ch = take_cap_handle(CapKind::Stdout).map(Channel::from_handle);
        let (Some(in_ch), Some(out_ch)) = (stdin_ch, stdout_ch) else {
            let _ = stderr_str("hsh: --interactive requires stdin/stdout IPC channels\n");
            exit(1);
        };
        let mut host = HshHost::new(registry, bootfs, frame_draw, Some(out_ch));
        host.status_hook = Some(send_status_bar);
        run_interactive(in_ch, host);
    }

    // Batch / `-c` / script file mode.
    let mut host = HshHost::new(registry, bootfs, frame_draw, None);
    let mut env = ShellEnv::new();

    let script = if args.first().map(String::as_str) == Some("-c") {
        if args.len() < 2 {
            let _ = stderr_str("usage: hsh -c \"<script>\"\n");
            exit(2);
        }
        args[1..].join(" ")
    } else if let Some(path) = args.first() {
        match host.read_script_file(path) {
            Ok(s) => s,
            Err(e) => {
                let _ = stderr_str(&e);
                let _ = stderr_str("\n");
                exit(1);
            }
        }
    } else {
        // Read stdin script until EOF.
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stdin_read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    };

    match env.eval_script(&script, &mut host) {
        Ok(res) => {
            for act in res.actions {
                if let EvalAction::Output(val) = act {
                    let txt = val.into_text();
                    if !txt.is_empty() {
                        if res.status == 0 {
                            let _ = stdout_str(&txt);
                            if !txt.ends_with('\n') {
                                let _ = stdout_str("\n");
                            }
                        } else {
                            let _ = stderr_str(&txt);
                            if !txt.ends_with('\n') {
                                let _ = stderr_str("\n");
                            }
                        }
                    }
                }
            }
            exit(res.status)
        }
        Err(err) => {
            let _ = stderr_str(&err);
            let _ = stderr_str("\n");
            exit(2)
        }
    }
}

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

fn decode_key(msg: &[u8]) -> Option<Key> {
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

struct InteractiveShell {
    in_ch: Channel,
    host: HshHost,
    env: ShellEnv,
    input: String,
    cursor: usize,
    pending_multiline: String,
    history_idx: Option<usize>,
    draft_before_history: String,
}

impl InteractiveShell {
    fn out_ch(&self) -> Option<&Channel> {
        self.host.ipc_out.as_ref()
    }

    fn send_packet(&self, pkt: &[u8]) {
        let Some(ch) = self.out_ch() else {
            return;
        };
        for _ in 0..200 {
            match ch.write(pkt) {
                Ok(()) => return,
                Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
                Err(_) => return,
            }
        }
    }

    fn send_clear(&self) {
        self.send_packet(&[hsh_to_term::TAG_CLEAR]);
    }

    fn send_write(&self, fg: Option<(u8, u8, u8)>, text: &str) {
        let bytes = text.as_bytes();
        let (use_fg, r, g, b) = match fg {
            Some((r, g, b)) => (1u8, r, g, b),
            None => (0u8, 0, 0, 0),
        };
        let mut pos = 0usize;
        while pos < bytes.len() {
            let take = (bytes.len() - pos).min(MAX_WRITE_CHUNK);
            let mut pkt = [0u8; 7 + MAX_WRITE_CHUNK];
            pkt[0] = hsh_to_term::TAG_WRITE;
            pkt[1] = use_fg;
            pkt[2] = r;
            pkt[3] = g;
            pkt[4] = b;
            put_u16(&mut pkt, 5, take as u16);
            pkt[7..7 + take].copy_from_slice(&bytes[pos..pos + take]);
            self.send_packet(&pkt[..7 + take]);
            pos += take;
        }
    }

    fn send_status(&mut self, active_proc: &str) {
        let caps = self.host.caps_summary();
        if let Some(ch) = self.out_ch() {
            send_status_bar(ch, &self.host.pwd, active_proc, &caps);
        }
    }

    fn send_prompt(&self) {
        let pwd_b = self.host.pwd.as_bytes();
        let pwd_len = pwd_b.len().min(MAX_PWD_BYTES);
        let in_b = self.input.as_bytes();
        let in_len = in_b.len().min(MAX_PROMPT_INPUT);
        let ghost_str = if self.pending_multiline.is_empty() {
            self.ghost_suffix().unwrap_or("")
        } else {
            ""
        };
        let ghost_b = ghost_str.as_bytes();
        let ghost_len = ghost_b.len().min(MAX_PROMPT_GHOST);

        let spans = highlight_line(&self.input[..in_len], KNOWN_COMMANDS);
        let span_count = spans.len().min(MAX_PROMPT_SPANS);

        let hdr_len = 15usize;
        let total = hdr_len + pwd_len + in_len + ghost_len + span_count * 5;
        let mut pkt = alloc::vec![0u8; total];
        pkt[0] = hsh_to_term::TAG_PROMPT;
        pkt[1] = u8::from(!self.pending_multiline.is_empty());
        put_i32(&mut pkt, 2, self.env.last_status);
        put_u16(&mut pkt, 6, self.cursor.min(in_len) as u16);
        pkt[8] = pwd_len as u8;
        put_u16(&mut pkt, 9, in_len as u16);
        put_u16(&mut pkt, 11, ghost_len as u16);
        put_u16(&mut pkt, 13, span_count as u16);

        let mut off = hdr_len;
        pkt[off..off + pwd_len].copy_from_slice(&pwd_b[..pwd_len]);
        off += pwd_len;
        pkt[off..off + in_len].copy_from_slice(&in_b[..in_len]);
        off += in_len;
        pkt[off..off + ghost_len].copy_from_slice(&ghost_b[..ghost_len]);
        off += ghost_len;
        for sp in spans.iter().take(span_count) {
            let k = match sp.kind {
                HighlightKind::Default => SpanKind::Default,
                HighlightKind::Keyword => SpanKind::Keyword,
                HighlightKind::Builtin => SpanKind::Builtin,
                HighlightKind::Command => SpanKind::Command,
                HighlightKind::Caps => SpanKind::Caps,
                HighlightKind::StringLit => SpanKind::StringLit,
                HighlightKind::Variable => SpanKind::Variable,
                HighlightKind::Operator => SpanKind::Operator,
                HighlightKind::Comment => SpanKind::Comment,
                HighlightKind::Number => SpanKind::Number,
            };
            pkt[off] = k as u8;
            put_u16(&mut pkt, off + 1, sp.span.start.min(in_len) as u16);
            put_u16(&mut pkt, off + 3, sp.span.end.min(in_len) as u16);
            off += 5;
        }
        self.send_packet(&pkt);
    }

    fn ghost_suffix(&self) -> Option<&str> {
        if self.input.is_empty() {
            return None;
        }
        for entry in self.host.history_lines.iter().rev() {
            if entry.len() > self.input.len() && entry.starts_with(&self.input) {
                return Some(&entry[self.input.len()..]);
            }
        }
        None
    }

    /// Dispatch one terminal packet. Returns `false` when the shell must exit.
    fn handle_packet(&mut self, packet: &[u8]) -> bool {
        let Some(tag) = packet.first().copied() else {
            return true;
        };
        match tag {
            term_to_hsh::TAG_KEY_EVENT if packet.len() >= 2 => {
                let klen = (packet[1] as usize).min(packet.len() - 2);
                self.handle_key(&packet[2..2 + klen]);
            }
            term_to_hsh::TAG_RUN_SMOKE => {
                self.run_smokes();
            }
            term_to_hsh::TAG_UI_DONE => {
                self.send_status("hsh.elf");
                self.send_prompt();
            }
            term_to_hsh::TAG_SHUTDOWN => {
                self.send_packet(&[hsh_to_term::TAG_REQUEST_SHUTDOWN]);
            }
            _ => {}
        }
        true
    }

    fn handle_key(&mut self, raw: &[u8]) {
        let Some(key) = decode_key(raw) else {
            return;
        };
        match key {
            Key::Char(b) => {
                self.input.insert(self.cursor, b as char);
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
            Key::Left => self.cursor = self.cursor.saturating_sub(1),
            Key::Right => {
                if self.cursor < self.input.len() {
                    self.cursor += 1;
                } else if let Some(ghost) = self.ghost_suffix().map(String::from) {
                    self.input.push_str(&ghost);
                    self.cursor = self.input.len();
                }
            }
            Key::Home => self.cursor = 0,
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
                    let mut nc = self.cursor;
                    while nc > 0 && bytes[nc - 1] == b' ' {
                        nc -= 1;
                    }
                    while nc > 0 && bytes[nc - 1] != b' ' {
                        nc -= 1;
                    }
                    self.input.replace_range(nc..self.cursor, "");
                    self.cursor = nc;
                }
            }
            Key::CtrlU => {
                self.input.drain(..self.cursor);
                self.cursor = 0;
            }
            Key::CtrlK => self.input.truncate(self.cursor),
            Key::CtrlL => self.send_clear(),
            Key::CtrlC => {
                self.send_write(Some((255, 110, 110)), "\n^C\n");
                self.input.clear();
                self.cursor = 0;
                self.pending_multiline.clear();
                self.history_idx = None;
            }
            Key::Esc => {
                self.input.clear();
                self.cursor = 0;
                self.history_idx = None;
            }
            Key::Up => self.history_prev(),
            Key::Down => self.history_next(),
            Key::Tab => self.tab_complete(),
            Key::Enter => {
                self.submit_line();
                return;
            }
        }
        self.send_prompt();
    }

    fn history_prev(&mut self) {
        if self.host.history_lines.is_empty() {
            return;
        }
        let next_idx = match self.history_idx {
            None => {
                self.draft_before_history = self.input.clone();
                self.host.history_lines.len() - 1
            }
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.history_idx = Some(next_idx);
        self.input = self.host.history_lines[next_idx].clone();
        self.cursor = self.input.len();
    }

    fn history_next(&mut self) {
        let Some(idx) = self.history_idx else {
            return;
        };
        if idx + 1 >= self.host.history_lines.len() {
            self.history_idx = None;
            self.input = self.draft_before_history.clone();
        } else {
            self.history_idx = Some(idx + 1);
            self.input = self.host.history_lines[idx + 1].clone();
        }
        self.cursor = self.input.len();
    }

    fn tab_complete(&mut self) {
        let prefix_slice = &self.input[..self.cursor];
        let token_start = prefix_slice
            .rfind([' ', '\t', ';', '|', '&'])
            .map_or(0, |i| i + 1);
        let token = &prefix_slice[token_start..];

        if token == "@" || (token.starts_with("@c") && !token.contains('(')) {
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
            for &b in KNOWN_COMMANDS {
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
        let lcp = longest_common_prefix(&matches);
        if lcp.len() > token.len() {
            self.input.replace_range(token_start..self.cursor, &lcp);
            self.cursor = token_start + lcp.len();
        } else {
            self.send_write(None, "\n");
            self.send_write(Some((95, 225, 255)), &matches.join("  "));
            self.send_write(None, "\n");
        }
    }

    fn submit_line(&mut self) {
        self.send_write(None, "\n");
        if !self.pending_multiline.is_empty() {
            self.pending_multiline.push('\n');
        }
        self.pending_multiline.push_str(&self.input);
        self.input.clear();
        self.cursor = 0;
        self.history_idx = None;

        if has_unclosed_delims(&self.pending_multiline) {
            self.send_prompt();
            return;
        }

        let script = core::mem::take(&mut self.pending_multiline);
        let trimmed = script.trim();
        if !trimmed.is_empty() {
            if self.host.history_lines.last().map(String::as_str) != Some(trimmed) {
                if self.host.history_lines.len() >= HISTORY_MAX {
                    self.host.history_lines.remove(0);
                }
                self.host.history_lines.push(String::from(trimmed));
            }
            match self.env.eval_script(trimmed, &mut self.host) {
                Ok(res) => {
                    let mut should_exit = false;
                    for act in res.actions {
                        match act {
                            EvalAction::ClearScreen => self.send_clear(),
                            EvalAction::Output(val) => {
                                let txt = val.into_text();
                                if !txt.is_empty() {
                                    let fg = if res.status != 0 {
                                        Some((255, 110, 110))
                                    } else {
                                        None
                                    };
                                    self.send_write(fg, &txt);
                                    if !txt.ends_with('\n') {
                                        self.send_write(None, "\n");
                                    }
                                }
                            }
                            EvalAction::Exit => {
                                should_exit = true;
                            }
                        }
                    }
                    if should_exit {
                        let mut pkt = [0u8; 5];
                        pkt[0] = hsh_to_term::TAG_EXIT;
                        put_i32(&mut pkt, 1, res.status);
                        self.send_packet(&pkt);
                        exit(res.status);
                    }
                }
                Err(err) => {
                    self.env.last_status = 2;
                    self.send_write(Some((255, 110, 110)), &err);
                    self.send_write(None, "\n");
                }
            }
        }

        if let Some(act) = self.host.delegated.take() {
            match act {
                DelegatedAction::Doom => {
                    self.send_packet(&[hsh_to_term::TAG_LAUNCH_DOOM]);
                    return;
                }
                DelegatedAction::Snake { hard } => {
                    self.send_packet(&[hsh_to_term::TAG_LAUNCH_SNAKE, u8::from(hard)]);
                    return;
                }
                DelegatedAction::Shutdown => {
                    self.send_packet(&[hsh_to_term::TAG_REQUEST_SHUTDOWN]);
                    return;
                }
                DelegatedAction::Font(f) => {
                    self.send_packet(&[hsh_to_term::TAG_SET_FONT, f]);
                }
            }
        }

        self.send_status("hsh.elf");
        self.send_prompt();
    }

    fn run_smokes(&mut self) {
        let mut smoke_env = ShellEnv::new();

        // 1. Intrinsics + language (`cls`, `let`, `fn`, `if ... contains`)
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
                println!("[hsh] core language/cls/fn smoke OK");
            }
            Ok(res) => println!(
                "[hsh] core language smoke FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(e) => println!("[hsh] core language smoke ERROR: {}", e),
        }

        // 2. External `/bin/ls.elf` pipe
        match smoke_env.eval_script("ls /bin | where name == fdisk.elf | count", &mut self.host) {
            Ok(res) if res.status == 0 && res.render_text().trim() == "1" => {
                println!("[hsh] ls.elf pipe OK");
            }
            Ok(res) => println!(
                "[hsh] ls.elf pipe FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(e) => println!("[hsh] ls.elf pipe ERROR: {}", e),
        }

        // 3. External `/bin/pci.elf` pipe
        match smoke_env.eval_script("pci | count", &mut self.host) {
            Ok(res)
                if res.status == 0
                    && res.render_text().trim().parse::<usize>().unwrap_or(0) > 0 =>
            {
                println!("[hsh] pci.elf pipe OK");
            }
            Ok(res) => println!(
                "[hsh] pci.elf pipe FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(e) => println!("[hsh] pci.elf pipe ERROR: {}", e),
        }

        // 4. External `/bin/hxfs.elf` status
        match smoke_env.eval_script(
            "hxfs status | where property == capability | select value",
            &mut self.host,
        ) {
            Ok(res) if res.status == 0 && !res.render_text().trim().is_empty() => {
                println!("[hsh] hxfs.elf status OK");
            }
            Ok(res) => println!(
                "[hsh] hxfs.elf status FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(e) => println!("[hsh] hxfs.elf status ERROR: {}", e),
        }

        // 5. External `/bin/fdisk.elf` pipe
        match smoke_env.eval_script("fdisk list | where type == hxfs", &mut self.host) {
            Ok(res) if res.status == 0 && res.render_text().contains("HxFS-Root") => {
                println!("[hsh] fdisk.elf pipe OK");
            }
            Ok(res) => println!(
                "[hsh] fdisk.elf pipe FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(e) => println!("[hsh] fdisk.elf pipe ERROR: {}", e),
        }

        // 6. `@caps(hxfs=ro)` enforcement across both `fdisk.elf` and `touch.elf`
        let fdisk_ro = smoke_env.eval_script(
            "@caps(hxfs=ro) fdisk add --type hxfs --size 16M",
            &mut self.host,
        );
        let touch_ro = smoke_env.eval_script("@caps(hxfs=ro) touch /denied.txt", &mut self.host);
        match (fdisk_ro, touch_ro) {
            (Ok(r1), Ok(r2))
                if r1.status != 0
                    && r1.render_text().contains("AccessDenied")
                    && r2.status != 0
                    && r2.render_text().contains("AccessDenied") =>
            {
                println!("[hsh] @caps(hxfs=ro) enforcement OK");
            }
            _ => println!("[hsh] @caps(hxfs=ro) enforcement FAILED"),
        }

        // 7. `@caps(hxfs=none, bootfs=none)` enforcement across `fdisk.elf` and `ls.elf`
        let fdisk_none =
            smoke_env.eval_script("@caps(hxfs=none, bootfs=none) fdisk list", &mut self.host);
        let ls_none = smoke_env.eval_script("@caps(hxfs=none, bootfs=none) ls /", &mut self.host);
        match (fdisk_none, ls_none) {
            (Ok(r1), Ok(r2))
                if r1.status != 0
                    && r1.render_text().contains("AccessDenied")
                    && r2.status != 0
                    && r2.render_text().contains("AccessDenied") =>
            {
                println!("[hsh] @caps(hxfs=none,bootfs=none) enforcement OK");
            }
            _ => println!("[hsh] @caps(hxfs=none,bootfs=none) enforcement FAILED"),
        }

        // 8. Consecutive dynamic ELF spawn stress test (30 spawns: 10 rounds of
        // `/bin/pci.elf`, `/bin/ls.elf`, `/bin/fdisk.elf`) verifying no kernel
        // slab/heap exhaustion or handle/VMAR/channel/process leaks.
        let mut stress_ok = true;
        for round in 0..10 {
            for cmd in ["pci | count", "ls /bin | count", "fdisk list | count"] {
                match smoke_env.eval_script(cmd, &mut self.host) {
                    Ok(res)
                        if res.status == 0
                            && res.render_text().trim().parse::<usize>().unwrap_or(0) > 0 => {}
                    Ok(res) => {
                        println!(
                            "[hsh] consecutive spawn stress FAILED round={} cmd='{}' status={} out={}",
                            round,
                            cmd,
                            res.status,
                            res.render_text()
                        );
                        stress_ok = false;
                        break;
                    }
                    Err(e) => {
                        println!(
                            "[hsh] consecutive spawn stress ERROR round={} cmd='{}': {}",
                            round, cmd, e
                        );
                        stress_ok = false;
                        break;
                    }
                }
            }
            if !stress_ok {
                break;
            }
        }
        if stress_ok {
            println!("[hsh] consecutive spawn stress OK (30 spawns)");
        }

        // 7. Registry capability must survive the spawn storm above: the
        //    DriverManager query pool is only reclaimed once the queued
        //    capabilities are released, so a leaky handshake shows up here and
        //    nowhere else (`pci` works fine before the stress, never after).
        match smoke_env.eval_script("pci | count", &mut self.host) {
            Ok(res)
                if res.status == 0
                    && res.render_text().trim().parse::<usize>().unwrap_or(0) > 0 =>
            {
                println!("[hsh] post-stress query channel OK");
            }
            Ok(res) => println!(
                "[hsh] post-stress query channel FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(e) => println!("[hsh] post-stress query channel ERROR: {}", e),
        }

        // 9. `ProcessTerminate` + `Ctrl-C` child kill.
        //
        //    `sleep` long enough that only the kill can end it; the smoke gate
        //    asks the host for a synthetic interrupt, which drives exactly the
        //    production path (poll for Ctrl-C -> ProcessTerminate -> reap the
        //    child with status 130) minus the keystroke itself. The interactive
        //    behaviour is exercised by typing Ctrl-C at a real `sleep`.
        self.host.auto_interrupts = 1;
        let kill = smoke_env.eval_script("sleep 30", &mut self.host);
        self.host.auto_interrupts = 0;
        let interrupted = self.host.last_child_interrupted;
        match kill {
            Ok(res) if res.status == 130 && interrupted => {
                println!("[hsh] ProcessTerminate smoke OK (ProcessWait woke with 130)");
                println!("[hsh] Ctrl-C child kill smoke OK (child killed, shell alive)");
            }
            Ok(res) => println!(
                "[hsh] ProcessTerminate smoke FAILED status={} interrupted={} out={}",
                res.status,
                interrupted,
                res.render_text()
            ),
            Err(e) => println!("[hsh] ProcessTerminate smoke ERROR: {}", e),
        }

        // 10. `fdisk gpt-init --dry-run` must always be safe, and a real
        //     init/add/del/verify cycle must round-trip on a throw-away image.
        //     With HxFS mounted the cycle runs on a file image (real writes,
        //     real CRC checks); without it, on the seeded in-memory demo disk,
        //     which still covers init and verify code paths.
        let file_image = self.host.hxfs.is_some();
        let image = if file_image { " /disk.img" } else { "" };
        let dry = smoke_env.eval_script(
            &format!("fdisk gpt-init{image} --dry-run --size 64M"),
            &mut self.host,
        );
        match dry {
            Ok(res) if res.status == 0 && res.render_text().contains("gpt-init dry-run") => {
                println!("[hsh] fdisk gpt-init dry-run OK");
            }
            Ok(res) => println!(
                "[hsh] fdisk gpt-init dry-run FAILED status={} out={}",
                res.status,
                res.render_text()
            ),
            Err(e) => println!("[hsh] fdisk gpt-init dry-run ERROR: {}", e),
        }

        let mut gpt_cycle: Vec<String> = Vec::new();
        if file_image {
            gpt_cycle.push(format!("fdisk gpt-init{image} --size 64M"));
            gpt_cycle.push(format!("fdisk add{image} --type hxfs --size 16M"));
            gpt_cycle.push(format!("fdisk verify{image}"));
            gpt_cycle.push(format!("fdisk del 1{image}"));
            gpt_cycle.push(format!("fdisk verify{image}"));
        } else {
            // No filesystem to hold an image: the seeded in-memory GPT still
            // exercises the verification path end to end.
            gpt_cycle.push(String::from("fdisk verify"));
        }
        let mut gpt_ok = true;
        for cmd in &gpt_cycle {
            let expects_verify = cmd.starts_with("fdisk verify");
            match smoke_env.eval_script(cmd, &mut self.host) {
                Ok(res)
                    if res.status == 0
                        && (!expects_verify || res.render_text().contains("ok=true")) => {}
                Ok(res) => {
                    println!(
                        "[hsh] fdisk gpt init/add/del/verify FAILED cmd='{}' status={} out={}",
                        cmd,
                        res.status,
                        res.render_text()
                    );
                    gpt_ok = false;
                    break;
                }
                Err(e) => {
                    println!(
                        "[hsh] fdisk gpt init/add/del/verify ERROR cmd='{}': {}",
                        cmd, e
                    );
                    gpt_ok = false;
                    break;
                }
            }
        }
        if gpt_ok {
            println!("[hsh] fdisk gpt init/add/del/verify OK");
        }

        // 11. Bare `HxFS v7` volume (superfloppy) detection. Only meaningful on
        //     a boot with a block device; the NVMe smoke attaches one.
        if self.host.hxfs.is_some() {
            match smoke_env.eval_script("fdisk list", &mut self.host) {
                Ok(res) if res.status == 0 && res.render_text().contains("raw-hxfs") => {
                    println!("[hsh] fdisk raw-hxfs list OK");
                }
                Ok(res) => println!(
                    "[hsh] fdisk raw-hxfs list FAILED status={} out={}",
                    res.status,
                    res.render_text()
                ),
                Err(e) => println!("[hsh] fdisk raw-hxfs list ERROR: {}", e),
            }
            match smoke_env.eval_script("fdisk gpt-init --size 64M", &mut self.host) {
                Ok(res)
                    if res.status != 0
                        && res.render_text().contains("raw-hxfs")
                        && res.render_text().contains("--force") =>
                {
                    println!("[hsh] fdisk raw-hxfs gpt-init guard OK");
                }
                Ok(res) => println!(
                    "[hsh] fdisk raw-hxfs gpt-init guard FAILED status={} out={}",
                    res.status,
                    res.render_text()
                ),
                Err(e) => println!("[hsh] fdisk raw-hxfs gpt-init guard ERROR: {}", e),
            }
        } else {
            println!("[hsh] fdisk raw-hxfs list SKIP (no block device)");
            println!("[hsh] fdisk raw-hxfs gpt-init guard SKIP (no block device)");
        }

        self.send_clear();
        self.send_write(
            Some((95, 225, 185)),
            "HuesOS Production Terminal // /bin/hsh.elf\n",
        );
        self.send_write(
            None,
            "All system utilities run as isolated dynamic ELFs under @caps(...). Type 'help'.\n\n",
        );
        self.send_status("hsh.elf");
        self.send_prompt();
    }
}

fn send_status_bar(ch: &Channel, pwd: &str, active_proc: &str, caps_summary: &str) {
    let p = pwd.as_bytes();
    let pr = active_proc.as_bytes();
    let c = caps_summary.as_bytes();
    let plen = p.len().min(MAX_PWD_BYTES);
    let prlen = pr.len().min(64);
    let clen = c.len().min(64);
    let mut pkt = [0u8; 4 + MAX_PWD_BYTES + 64 + 64];
    pkt[0] = hsh_to_term::TAG_STATUS_BAR;
    pkt[1] = plen as u8;
    pkt[2] = prlen as u8;
    pkt[3] = clen as u8;
    let mut off = 4usize;
    pkt[off..off + plen].copy_from_slice(&p[..plen]);
    off += plen;
    pkt[off..off + prlen].copy_from_slice(&pr[..prlen]);
    off += prlen;
    pkt[off..off + clen].copy_from_slice(&c[..clen]);
    off += clen;
    for _ in 0..100 {
        match ch.write(&pkt[..off]) {
            Ok(()) => return,
            Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
            Err(_) => return,
        }
    }
}

fn run_interactive(in_ch: Channel, mut host: HshHost) -> ! {
    // The child-wait loop polls a duplicate of the same endpoint so a Ctrl-C
    // typed while a child runs reaches the shell instead of sitting unread
    // until the child finishes (or never does).
    host.key_source = in_ch.duplicate().ok();
    let mut shell = InteractiveShell {
        in_ch,
        host,
        env: ShellEnv::new(),
        input: String::new(),
        cursor: 0,
        pending_multiline: String::new(),
        history_idx: None,
        draft_before_history: String::new(),
    };

    shell.send_status("hsh.elf");
    shell.send_prompt();

    let mut buf = [0u8; 256];
    loop {
        // Packets typed while a child was running were buffered by the host;
        // replay them before blocking again so no keystroke is lost.
        for packet in shell.host.take_pending_packets() {
            if !shell.handle_packet(&packet) {
                exit(0);
            }
        }
        match shell.in_ch.read_into_blocking(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                if !shell.handle_packet(&buf[..n]) {
                    exit(0);
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(ErrorCode::PeerClosed) => exit(0),
            Err(_) => libcanvas::process::yield_now(),
        }
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
