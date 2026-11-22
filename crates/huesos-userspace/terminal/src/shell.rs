//! Terminal UI controller bridging keyboard + `Screen` + `/bin/hsh.elf` IPC.

use alloc::vec::Vec;

use huesos_abi::auxv::caps_mask;
use huesos_abi::term_ipc::{get_u16, hsh_to_term, term_to_hsh, SpanKind};
use libcanvas::process::{spawn_elf_from_vmo_with_caps, SpawnCaps};
use libcanvas::{println, wait_any, Channel, ErrorCode, Handle, Process, Signals, Vmo, WaitItem};

use crate::screen::{Color, Screen};
use crate::snake;

const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";

/// 500 ms cursor blink interval at 100 Hz kernel monotonic ticks.
const BLINK_TICKS: u64 = 50;

const COL_PROMPT_OK: Color = (95, 225, 185);
const COL_PROMPT_ERR: Color = (255, 115, 115);
const COL_PROMPT_PATH: Color = (125, 180, 255);
const COL_KEYWORD: Color = (210, 145, 255);
const COL_BUILTIN: Color = (95, 225, 255);
const COL_COMMAND: Color = (120, 240, 155);
const COL_CAPS: Color = (255, 195, 90);
const COL_STRING: Color = (180, 235, 140);
const COL_VAR: Color = (255, 150, 115);
const COL_OP: Color = (235, 240, 250);
const COL_COMMENT: Color = (105, 120, 145);
const COL_NUMBER: Color = (255, 210, 130);
const COL_DEFAULT: Color = (210, 225, 245);
const COL_GHOST: Color = (95, 115, 145);

const KEY_WAIT_KEY: u64 = 1;
const HSH_WAIT_KEY: u64 = 2;

pub struct TerminalSession {
    screen: Screen,
    keyboard: Channel,
    supervisor: Channel,
    registry: Channel,
    bootfs: Option<Vmo>,
    frame_draw: Option<Handle>,
    hsh_proc: Option<Process>,
    hsh_in: Option<Channel>,
    hsh_out: Option<Channel>,
    prompt_row: usize,
    cursor_visible: bool,
    next_blink_tick: u64,
}

impl TerminalSession {
    pub fn new(
        keyboard: Channel,
        registry: Channel,
        bootfs: Option<Vmo>,
        supervisor: Channel,
        frame_draw: Option<Handle>,
    ) -> Self {
        let cap_raw = frame_draw.as_ref().map(|h| h.raw());
        let mut screen = Screen::new_with_cap(cap_raw);
        screen.clear();
        screen.write_colored("HuesOS Terminal — spawning /bin/hsh.elf...", COL_PROMPT_OK);
        screen.newline();
        screen.render();

        let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
        let mut sess = Self {
            screen,
            keyboard,
            supervisor,
            registry,
            bootfs,
            frame_draw,
            hsh_proc: None,
            hsh_in: None,
            hsh_out: None,
            prompt_row: 0,
            cursor_visible: true,
            next_blink_tick: now.saturating_add(BLINK_TICKS),
        };
        sess.spawn_hsh();
        sess
    }

    fn find_bootfs_entry(vmo: &Vmo, target: &str) -> Option<(u64, u64)> {
        let mut hdr = [0u8; BOOTFS_HEADER_SIZE as usize];
        if vmo.read(0, &mut hdr) != Ok(hdr.len()) || &hdr[..8] != BOOTFS_MAGIC {
            return None;
        }
        let count = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let mut raw = [0u8; BOOTFS_ENTRY_SIZE as usize];
        for idx in 0..count {
            let off = BOOTFS_HEADER_SIZE + u64::from(idx) * BOOTFS_ENTRY_SIZE;
            if vmo.read(off, &mut raw) != Ok(raw.len()) {
                break;
            }
            let plen = raw[..BOOTFS_PATH_SIZE]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(BOOTFS_PATH_SIZE);
            if let Ok(path) = core::str::from_utf8(&raw[..plen]) {
                if path == target {
                    let meta = &raw[BOOTFS_PATH_SIZE..];
                    let eoff = u64::from_le_bytes([
                        meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6], meta[7],
                    ]);
                    let elen = u64::from_le_bytes([
                        meta[8], meta[9], meta[10], meta[11], meta[12], meta[13], meta[14],
                        meta[15],
                    ]);
                    return Some((eoff, elen));
                }
            }
        }
        None
    }

    fn spawn_hsh(&mut self) {
        let Some(bootfs) = self.bootfs.as_ref() else {
            println!("[terminal] cannot spawn /bin/hsh.elf: no BOOTFS VMO");
            return;
        };
        let Some((off, len)) = Self::find_bootfs_entry(bootfs, "/bin/hsh.elf") else {
            println!("[terminal] /bin/hsh.elf missing from BOOTFS");
            return;
        };
        let Ok(elf_vmo) = bootfs.duplicate(
            libcanvas::rights::READ | libcanvas::rights::TRANSFER | libcanvas::rights::DUPLICATE,
        ) else {
            println!("[terminal] failed duplicating BOOTFS VMO for hsh.elf");
            return;
        };
        let Ok(lib_vmo) = bootfs.duplicate(
            libcanvas::rights::READ | libcanvas::rights::TRANSFER | libcanvas::rights::DUPLICATE,
        ) else {
            println!("[terminal] failed duplicating lib_vmo for hsh.elf");
            return;
        };
        let Ok((in_r, in_w)) = Channel::pair() else {
            return;
        };
        let Ok((out_r, out_w)) = Channel::pair() else {
            return;
        };

        let argv = ["/bin/hsh.elf", "--interactive"];
        let mut caps = SpawnCaps::new();
        caps.args = &argv;
        caps.caps_mask = caps_mask::ALL_DEFAULT;
        caps.stdin = Some(&in_r);
        caps.stdout = Some(&out_w);
        caps.registry = Some(&self.registry);
        caps.frame_draw = self.frame_draw.as_ref();

        let res = spawn_elf_from_vmo_with_caps("/bin/hsh.elf", &elf_vmo, off, len, &lib_vmo, &caps);
        drop(in_r);
        drop(out_w);
        drop(elf_vmo);
        drop(lib_vmo);

        match res {
            Ok((proc_handle, _bootstrap)) => {
                println!(
                    "[terminal] spawned /bin/hsh.elf pid={}",
                    proc_handle.handle().raw()
                );
                self.hsh_proc = Some(proc_handle);
                self.hsh_in = Some(in_w);
                self.hsh_out = Some(out_r);
            }
            Err(e) => {
                println!("[terminal] failed spawning /bin/hsh.elf: {}", e.as_str());
            }
        }
    }

    #[cfg(feature = "boot-selftest")]
    pub fn trigger_startup_smokes(&mut self) {
        self.send_to_hsh(&[term_to_hsh::TAG_RUN_SMOKE]);
    }

    fn send_to_hsh(&self, pkt: &[u8]) {
        let Some(ch) = self.hsh_in.as_ref() else {
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

    pub fn run(&mut self) -> ! {
        #[cfg(feature = "soak-shutdown")]
        let mut idle_blinks: u32 = 0;

        loop {
            let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
            if now >= self.next_blink_tick {
                self.cursor_visible = !self.cursor_visible;
                self.screen.set_cursor_visible(self.cursor_visible);
                self.screen.render();
                self.next_blink_tick = now.saturating_add(BLINK_TICKS);

                #[cfg(feature = "soak-shutdown")]
                {
                    idle_blinks += 1;
                    if idle_blinks >= 60 {
                        println!("[terminal] soak-shutdown: auto-triggering orderly shutdown");
                        self.request_shutdown();
                        loop {
                            libcanvas::process::yield_now();
                        }
                    }
                }
            }

            let wait_ticks = self.next_blink_tick.saturating_sub(now).max(1);
            let items_both;
            let items_key;
            let wait_slice: &[WaitItem] = if let Some(hsh_out) = self.hsh_out.as_ref() {
                items_both = [
                    WaitItem::new(
                        self.keyboard.handle().raw(),
                        Signals::READABLE,
                        KEY_WAIT_KEY,
                    ),
                    WaitItem::new(
                        hsh_out.handle().raw(),
                        Signals::READABLE | Signals::PEER_CLOSED,
                        HSH_WAIT_KEY,
                    ),
                ];
                &items_both
            } else {
                items_key = [WaitItem::new(
                    self.keyboard.handle().raw(),
                    Signals::READABLE,
                    KEY_WAIT_KEY,
                )];
                &items_key
            };

            match wait_any(wait_slice, wait_ticks) {
                Ok(outcome) => {
                    for res in outcome.satisfied() {
                        match res.key {
                            KEY_WAIT_KEY => {
                                #[cfg(feature = "soak-shutdown")]
                                {
                                    idle_blinks = 0;
                                }
                                self.drain_keyboard();
                            }
                            HSH_WAIT_KEY => {
                                self.drain_hsh_out();
                            }
                            _ => {}
                        }
                    }
                }
                Err(ErrorCode::TimedOut) => {
                    // Handled by clock check at top of loop.
                }
                Err(_) => {
                    libcanvas::process::yield_now();
                }
            }
        }
    }

    fn drain_keyboard(&mut self) {
        let mut buf = [0u8; 32];
        loop {
            match self.keyboard.read_into(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // Ignore key-release packets (`['k', 0, _]`)
                    if n >= 3 && buf[0] == b'k' && buf[1] == 0 {
                        continue;
                    }
                    // Reset cursor solid on any key press.
                    let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
                    self.cursor_visible = true;
                    self.screen.set_cursor_visible(true);
                    self.next_blink_tick = now.saturating_add(BLINK_TICKS);

                    // Local terminal scrollback hotkeys: PageUp (0x87) / PageDown (0x88)
                    if buf[..n] == [b'k', 1, 0x87] {
                        self.screen.scroll_up(12);
                        self.screen.render();
                        continue;
                    }
                    if buf[..n] == [b'k', 1, 0x88] {
                        self.screen.scroll_down(12);
                        self.screen.render();
                        continue;
                    }

                    self.screen.reset_scrollback();
                    let klen = n.min(28);
                    let mut pkt = [0u8; 30];
                    pkt[0] = term_to_hsh::TAG_KEY_EVENT;
                    pkt[1] = klen as u8;
                    pkt[2..2 + klen].copy_from_slice(&buf[..klen]);
                    self.send_to_hsh(&pkt[..2 + klen]);
                }
            }
        }
    }

    fn drain_hsh_out(&mut self) {
        let mut buf = [0u8; 4096];
        while let Some(ch) = self.hsh_out.as_ref() {
            match ch.read_into(&mut buf) {
                Ok(0) | Err(ErrorCode::ShouldWait) => break,
                Err(ErrorCode::PeerClosed) => {
                    println!("[terminal] /bin/hsh.elf exited, respawning");
                    self.hsh_in = None;
                    self.hsh_out = None;
                    self.hsh_proc = None;
                    self.spawn_hsh();
                    break;
                }
                Err(_) => break,
                Ok(n) => self.handle_hsh_message(&buf[..n]),
            }
        }
        self.screen.render();
    }

    fn handle_hsh_message(&mut self, msg: &[u8]) {
        if msg.is_empty() {
            return;
        }
        match msg[0] {
            hsh_to_term::TAG_CLEAR => {
                self.screen.clear();
                self.prompt_row = self.screen.current_row();
            }
            hsh_to_term::TAG_WRITE if msg.len() >= 7 => {
                let use_fg = msg[1] != 0;
                let color = (msg[2], msg[3], msg[4]);
                let len = get_u16(msg, 5).unwrap_or(0) as usize;
                let end = (7 + len).min(msg.len());
                self.screen.reset_scrollback();
                if use_fg {
                    self.screen.write_colored_bytes(&msg[7..end], color);
                } else {
                    self.screen.write_bytes(&msg[7..end]);
                }
                self.prompt_row = self.screen.current_row();
            }
            hsh_to_term::TAG_STATUS_BAR if msg.len() >= 4 => {
                let plen = msg[1] as usize;
                let prlen = msg[2] as usize;
                let clen = msg[3] as usize;
                let off0 = 4usize;
                let off1 = off0 + plen;
                let off2 = off1 + prlen;
                let off3 = off2 + clen;
                if off3 <= msg.len() {
                    let pwd = core::str::from_utf8(&msg[off0..off1]).unwrap_or("/");
                    let proc_lbl = core::str::from_utf8(&msg[off1..off2]).unwrap_or("hsh.elf");
                    let caps = core::str::from_utf8(&msg[off2..off3]).unwrap_or("");
                    self.screen.set_status_info(proc_lbl, pwd, caps);
                }
            }
            hsh_to_term::TAG_PROMPT if msg.len() >= 15 => {
                self.render_prompt_packet(msg);
            }
            hsh_to_term::TAG_LAUNCH_DOOM => {
                self.run_doom();
                self.send_to_hsh(&[term_to_hsh::TAG_UI_DONE]);
            }
            hsh_to_term::TAG_LAUNCH_SNAKE if msg.len() >= 2 => {
                let hard = msg[1] != 0;
                snake::run(
                    &self.keyboard,
                    hard,
                    self.frame_draw.as_ref().map(|h| h.raw()),
                );
                self.screen.invalidate();
                self.screen.clear();
                self.screen
                    .write_colored("Returned from Snake.", COL_PROMPT_OK);
                self.screen.newline();
                self.prompt_row = self.screen.current_row();
                self.send_to_hsh(&[term_to_hsh::TAG_UI_DONE]);
            }
            hsh_to_term::TAG_REQUEST_SHUTDOWN => {
                self.request_shutdown();
            }
            hsh_to_term::TAG_SET_FONT if msg.len() >= 2 => match msg[1] {
                0 => self.screen.use_cozette_font(),
                1 => self.screen.use_tty_font(),
                _ => self.screen.use_compact_font(),
            },
            hsh_to_term::TAG_EXIT => {
                self.hsh_in = None;
                self.hsh_out = None;
                self.hsh_proc = None;
                self.spawn_hsh();
            }
            _ => {}
        }
    }

    fn render_prompt_packet(&mut self, msg: &[u8]) {
        let multiline = msg[1] != 0;
        let status = i32::from_le_bytes([msg[2], msg[3], msg[4], msg[5]]);
        let cursor = get_u16(msg, 6).unwrap_or(0) as usize;
        let pwd_len = msg[8] as usize;
        let in_len = get_u16(msg, 9).unwrap_or(0) as usize;
        let ghost_len = get_u16(msg, 11).unwrap_or(0) as usize;
        let span_count = get_u16(msg, 13).unwrap_or(0) as usize;

        let mut off = 15usize;
        if off + pwd_len + in_len + ghost_len + span_count * 5 > msg.len() {
            return;
        }
        let pwd = core::str::from_utf8(&msg[off..off + pwd_len]).unwrap_or("/");
        off += pwd_len;
        let input = core::str::from_utf8(&msg[off..off + in_len]).unwrap_or("");
        off += in_len;
        let ghost = core::str::from_utf8(&msg[off..off + ghost_len]).unwrap_or("");
        off += ghost_len;

        let mut spans: Vec<(SpanKind, usize, usize)> = Vec::with_capacity(span_count);
        for _ in 0..span_count {
            let kind = SpanKind::from_u8(msg[off]);
            let s = get_u16(msg, off + 1).unwrap_or(0) as usize;
            let e = get_u16(msg, off + 3).unwrap_or(0) as usize;
            spans.push((kind, s.min(input.len()), e.min(input.len())));
            off += 5;
        }

        self.screen.clear_from(self.prompt_row, 0);
        let prefix_len = if !multiline {
            self.screen.write_colored("hsh ", COL_PROMPT_OK);
            self.screen.write_colored(pwd, COL_PROMPT_PATH);
            let arrow_col = if status == 0 {
                COL_PROMPT_OK
            } else {
                COL_PROMPT_ERR
            };
            self.screen.write_colored(" > ", arrow_col);
            4 + pwd.len() + 3
        } else {
            self.screen.write_colored("... ", COL_PROMPT_PATH);
            4
        };

        let mut idx = 0usize;
        for (kind, s, e) in spans {
            if s > idx {
                self.screen.write_colored(&input[idx..s], COL_DEFAULT);
            }
            if e > s {
                let col = match kind {
                    SpanKind::Keyword => COL_KEYWORD,
                    SpanKind::Builtin => COL_BUILTIN,
                    SpanKind::Command => COL_COMMAND,
                    SpanKind::Caps => COL_CAPS,
                    SpanKind::StringLit => COL_STRING,
                    SpanKind::Variable => COL_VAR,
                    SpanKind::Operator => COL_OP,
                    SpanKind::Comment => COL_COMMENT,
                    SpanKind::Number => COL_NUMBER,
                    SpanKind::Default => COL_DEFAULT,
                };
                self.screen.write_colored(&input[s..e], col);
                idx = e;
            }
        }
        if idx < input.len() {
            self.screen.write_colored(&input[idx..], COL_DEFAULT);
        }
        if !ghost.is_empty() {
            self.screen.write_colored(ghost, COL_GHOST);
        }

        let (cols, rows) = self.screen.visible_size();
        let abs = prefix_len + cursor;
        let row_off = abs / cols.max(1);
        let cur_row = (self.prompt_row + row_off).min(rows.saturating_sub(1));
        let cur_col = if row_off + self.prompt_row >= rows {
            cols.saturating_sub(1)
        } else {
            abs % cols.max(1)
        };
        self.screen.set_cursor(cur_row, cur_col);
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
        match result {
            Ok(()) => self.screen.write_line("DOOM exited."),
            Err(error) => {
                self.screen.write_str("DOOM launch failed: ");
                self.screen.write_line(error.as_str());
            }
        }
        self.prompt_row = self.screen.current_row();
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
            self.screen.render();
        }
    }
}
