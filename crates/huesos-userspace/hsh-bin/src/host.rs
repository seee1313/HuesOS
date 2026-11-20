//! `ShellHost` implementation for `/bin/hsh.elf`.
//!
//! Only true shell intrinsics live inside `hsh.elf`; every file/system/disk
//! utility (`ls`, `cat`, `stat`, `touch`, `mkdir`, `rm`, `mv`, `write`, `hxfs`,
//! `pci`, `acpi`, `ps`, `fdisk`) is spawned as an external dynamic ELF from
//! `HxFS` or `BOOTFS` with full `@caps(...)` attenuation.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_abi::auxv::caps_mask;
use huesos_abi::hxfs::rights as hxfs_rights;
use huesos_abi::term_ipc::term_to_hsh;
use huesos_hsh::{CapsSpec, ExecOutcome, FbAccess, HxfsAccess, ShellHost, Table, Value};
use libcanvas::process::{spawn_elf_from_vmo_with_caps, Process, SpawnCaps};
use libcanvas::{Channel, ErrorCode, Handle, Hxfs, Vmo};

const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";

/// Tick budget for a single registry handshake read.
///
/// `driver-manager` services the registry once per supervision tick, and a tick
/// can be long (it polls NVMe, the volume manager and the file system first).
/// Counting `yield_now()` iterations instead of waiting on the channel made the
/// shell give up while the reply was already on its way.
const HANDSHAKE_WAIT_TICKS: u64 = 150;
/// Reads spent on one handshake before giving up; each read waits up to
/// `HANDSHAKE_WAIT_TICKS`, and stale replies to earlier requests are skipped.
const HANDSHAKE_READS: usize = 6;

/// UI/supervisor action delegated by `hsh.elf` back to `terminal`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegatedAction {
    Doom,
    Snake { hard: bool },
    Shutdown,
    Font(u8),
}

/// Runtime environment owned by `/bin/hsh.elf`.
pub struct HshHost {
    pub registry: Option<Channel>,
    pub hxfs: Option<Hxfs>,
    pub bootfs: Option<Vmo>,
    pub frame_draw: Option<Handle>,
    pub pwd: String,
    pub history_lines: Vec<String>,
    pub delegated: Option<DelegatedAction>,
    pub status_hook: Option<fn(&Channel, &str, &str, &str)>,
    pub ipc_out: Option<Channel>,
    /// Duplicate of the interactive `stdin` channel. A child run polls it for
    /// `Ctrl-C` so the shell can kill a child that will not finish on its own.
    pub key_source: Option<Channel>,
    /// Terminal packets received while a child was running. They are replayed
    /// to the prompt once the shell is idle again, so typing during a child
    /// run is never silently dropped.
    pub pending_packets: Vec<Vec<u8>>,
    /// Remaining child runs to interrupt without a keystroke. Only the smoke
    /// gate uses this; it drives the exact production kill path.
    pub auto_interrupts: usize,
    /// How long a synthetic interrupt waits after the child starts, in
    /// scheduler ticks. A full-screen program needs a frame on the wire before
    /// the kill, or the gate would only ever observe the `^C` echo.
    pub auto_interrupt_after_ticks: u64,
    /// Deadline for the pending synthetic interrupt, latched on the first poll.
    interrupt_deadline: Option<u64>,
    /// Polls spent waiting for that deadline, used when the process has no
    /// clock capability and the tick count cannot advance.
    interrupt_polls: u64,
    /// Whether the most recent child run ended through the `Ctrl-C` path.
    pub last_child_interrupted: bool,
}

/// Most output the shell keeps from one child.
///
/// A full-screen program redraws continuously, and a misbehaving child can
/// print without end. Capturing everything would grow the shell's heap until
/// an allocation failed and took the whole session down with it, so the buffer
/// keeps the most recent half once it passes this bound: the end of a run is
/// what a caller can act on anyway.
const MAX_CAPTURE_BYTES: usize = 256 * 1024;

fn trim_capture(buf: &mut Vec<u8>) {
    if buf.len() > MAX_CAPTURE_BYTES {
        let keep_from = buf.len() - MAX_CAPTURE_BYTES / 2;
        buf.drain(..keep_from);
    }
}

/// Exit status reported for a child killed by `Ctrl-C` (128 + SIGINT).
pub const CTRL_C_EXIT_CODE: i64 = 130;

/// True when a terminal packet carries the `Ctrl-C` key.
///
/// `terminal` sends `[TAG_KEY_EVENT, len, b'k', 1, 0x03]`; the other two
/// shapes are accepted because the ASCII ETX byte and the textual form are
/// both plausible producers (a test harness injecting keys directly, or the
/// shell's own key decoder spelling out the name).
fn packet_is_ctrl_c(packet: &[u8]) -> bool {
    if packet.first() != Some(&term_to_hsh::TAG_KEY_EVENT) || packet.len() < 2 {
        return false;
    }
    let klen = (packet[1] as usize).min(packet.len() - 2);
    let key = &packet[2..2 + klen];
    key == &[b'k', 1, 3][..] || key == &[0x03u8][..] || key == &b"ctrl-c"[..]
}

impl HshHost {
    pub fn new(
        registry: Option<Channel>,
        bootfs: Option<Vmo>,
        frame_draw: Option<Handle>,
        ipc_out: Option<Channel>,
    ) -> Self {
        let mut host = Self {
            registry,
            hxfs: None,
            bootfs,
            frame_draw,
            pwd: String::from("/"),
            history_lines: Vec::new(),
            delegated: None,
            status_hook: None,
            ipc_out,
            key_source: None,
            pending_packets: Vec::new(),
            auto_interrupts: 0,
            auto_interrupt_after_ticks: 0,
            interrupt_deadline: None,
            interrupt_polls: 0,
            last_child_interrupted: false,
        };
        host.try_connect_hxfs();
        host
    }

    pub fn caps_summary(&mut self) -> String {
        self.try_connect_hxfs();
        let hxfs_state = if self.hxfs.is_some() {
            "HXFS:RW"
        } else {
            "HXFS:OFF"
        };
        let bootfs_state = if self.bootfs.is_some() {
            "BOOTFS:RO"
        } else {
            "BOOTFS:NONE"
        };
        format!("{hxfs_state} | {bootfs_state}")
    }

    pub fn try_connect_hxfs(&mut self) {
        if self.hxfs.is_some() {
            return;
        }
        let Some(reg) = self.registry.as_ref() else {
            return;
        };
        self.drain_registry();
        if reg.write(b"open:hxfs").is_err() {
            return;
        }
        let mut buf = [0u8; 64];
        for _ in 0..HANDSHAKE_READS {
            match reg.read_optional_handle_timeout(&mut buf, HANDSHAKE_WAIT_TICKS) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:channel" => {
                    self.hxfs = Some(Hxfs::from_channel(Channel::from_handle(handle)));
                    return;
                }
                Ok((n, None)) if buf[..n].starts_with(b"err:hxfs") => return,
                Ok((_n, Some(handle))) => drop(handle),
                // A late reply to a different handshake: skip it rather than
                // failing this one.
                Ok((_n, None)) => {}
                // The channel read already waited for a full budget.
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                Err(_) => return,
            }
        }
    }

    /// Drop any pending message on the shared registry channel.
    ///
    /// The registry is a single request/response stream shared by every
    /// `open:*` handshake. A reply that arrives after a client gave up stays
    /// queued, and the next handshake would read it as its own answer -- one
    /// late reply permanently shifts the stream by one message. Draining first
    /// keeps every handshake aligned; dropping a queued capability handle also
    /// releases the supplier's side (it sees `PeerClosed`), so leaked query
    /// slots are reclaimed instead of accumulating.
    fn drain_registry(&self) {
        let Some(reg) = self.registry.as_ref() else {
            return;
        };
        let mut buf = [0u8; 64];
        for _ in 0..32 {
            match reg.read_optional_handle(&mut buf) {
                Ok((_n, handle)) => drop(handle),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                Err(_) => break,
            }
        }
    }

    fn open_hxfs_channel_fresh(&self) -> Option<Channel> {
        let reg = self.registry.as_ref()?;
        self.drain_registry();
        reg.write(b"open:hxfs").ok()?;
        let mut buf = [0u8; 64];
        for _ in 0..HANDSHAKE_READS {
            match reg.read_optional_handle_timeout(&mut buf, HANDSHAKE_WAIT_TICKS) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:channel" => {
                    return Some(Channel::from_handle(handle));
                }
                Ok((n, None)) if buf[..n].starts_with(b"err:hxfs") => return None,
                Ok((_n, Some(handle))) => drop(handle),
                // A late reply to a different handshake: skip it rather than
                // giving up on this one.
                Ok((_n, None)) => {}
                // The channel read already waited for a full budget.
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                Err(e) => {
                    libcanvas::println!("[hsh] hxfs handshake read error: {}", e.as_str());
                    return None;
                }
            }
        }
        None
    }

    fn open_block_nvme_fresh(&self) -> Option<Channel> {
        let reg = self.registry.as_ref()?;
        self.drain_registry();
        reg.write(b"open:block:nvme").ok()?;
        let mut buf = [0u8; 64];
        for _ in 0..HANDSHAKE_READS {
            match reg.read_optional_handle_timeout(&mut buf, HANDSHAKE_WAIT_TICKS) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:block:nvme:channel" => {
                    return Some(Channel::from_handle(handle));
                }
                Ok((n, None)) if buf[..n].starts_with(b"err:block") => return None,
                Ok((_n, Some(handle))) => drop(handle),
                // A late reply to a different handshake: skip it rather than
                // giving up on this one.
                Ok((_n, None)) => {}
                // The channel read already waited for a full budget.
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                Err(_) => return None,
            }
        }
        None
    }

    /// Hand the child a fresh DriverManager query channel.
    ///
    /// Transient congestion is normal: a burst of spawns can find every slot
    /// taken until `driver-manager` reaps the clients of the processes that
    /// already exited. Retry a few times instead of silently spawning a child
    /// without a registry capability, which would make `pci`/`ps`/`acpi` fail
    /// with "query channel unavailable".
    fn open_query_fresh(&self) -> Option<Channel> {
        for _ in 0..3 {
            if let Some(channel) = self.open_query_once() {
                return Some(channel);
            }
            for _ in 0..8 {
                libcanvas::process::yield_now();
            }
        }
        None
    }

    fn open_query_once(&self) -> Option<Channel> {
        let reg = self.registry.as_ref()?;
        self.drain_registry();
        reg.write(b"open:query").ok()?;
        let mut buf = [0u8; 64];
        for _ in 0..HANDSHAKE_READS {
            match reg.read_optional_handle_timeout(&mut buf, HANDSHAKE_WAIT_TICKS) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:query:channel" => {
                    return Some(Channel::from_handle(handle));
                }
                Ok((n, None)) if buf[..n].starts_with(b"err:query") => {
                    libcanvas::println!(
                        "[hsh] query handshake refused: {}",
                        String::from_utf8_lossy(&buf[..n])
                    );
                    return None;
                }
                Ok((_n, Some(handle))) => drop(handle),
                // A late reply to a different handshake: skip it rather than
                // giving up on this one.
                Ok((_n, None)) => {}
                // The channel read already waited for a full budget.
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                Err(e) => {
                    libcanvas::println!("[hsh] query handshake read error: {}", e.as_str());
                    return None;
                }
            }
        }
        libcanvas::println!("[hsh] query handshake: no reply after {HANDSHAKE_READS} reads");
        None
    }

    pub fn iter_bootfs_entries(&self) -> Vec<(String, u64, u64)> {
        let mut entries = Vec::new();
        let Some(vmo) = self.bootfs.as_ref() else {
            return entries;
        };
        let mut hdr = [0u8; BOOTFS_HEADER_SIZE as usize];
        if vmo.read(0, &mut hdr) != Ok(hdr.len()) || &hdr[..8] != BOOTFS_MAGIC {
            return entries;
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
            if let Ok(p) = core::str::from_utf8(&raw[..plen]) {
                let meta = &raw[BOOTFS_PATH_SIZE..];
                let eoff = u64::from_le_bytes([
                    meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6], meta[7],
                ]);
                let elen = u64::from_le_bytes([
                    meta[8], meta[9], meta[10], meta[11], meta[12], meta[13], meta[14], meta[15],
                ]);
                entries.push((String::from(p), eoff, elen));
            }
        }
        entries
    }

    pub fn list_bootfs_bins(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (path, _, _) in self.iter_bootfs_entries() {
            if let Some(rest) = path.strip_prefix("/bin/") {
                out.push(String::from(rest));
                if let Some(short) = rest.strip_suffix(".elf") {
                    out.push(String::from(short));
                }
            }
        }
        out
    }

    pub fn list_paths_for_completion(&mut self, prefix: &str) -> Vec<String> {
        let mut candidates = Vec::new();
        for (path, _, _) in self.iter_bootfs_entries() {
            if path.starts_with(prefix) {
                candidates.push(path);
            }
        }
        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            let dir_path = match prefix.rfind('/') {
                Some(0) | None => "/",
                Some(idx) => &prefix[..idx],
            };
            if let Ok(dir) = hxfs.open_dir(dir_path) {
                let mut raw = [0u8; 2048];
                if let Ok(bytes) = dir.list(&mut raw) {
                    if let Ok(text) = core::str::from_utf8(bytes) {
                        for line in text.lines() {
                            let name = line.split_whitespace().next().unwrap_or("");
                            if name.is_empty() {
                                continue;
                            }
                            let full = if dir_path == "/" {
                                format!("/{name}")
                            } else {
                                format!("{dir_path}/{name}")
                            };
                            if full.starts_with(prefix) && !candidates.contains(&full) {
                                candidates.push(full);
                            }
                        }
                    }
                }
            }
        }
        candidates
    }

    pub fn read_script_file(&mut self, path_arg: &str) -> Result<String, String> {
        let path = self.normalize_path(path_arg);
        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            if let Ok(file) = hxfs.open_file(&path) {
                if let Ok(vmo) = file.read_into_vmo() {
                    let size = file.size().unwrap_or(0).min(64 * 1024) as usize;
                    let mut buf = alloc::vec![0u8; size];
                    if vmo.read(0, &mut buf).is_ok() {
                        return Ok(String::from_utf8_lossy(&buf).into_owned());
                    }
                }
            }
        }
        if let Some(vmo) = self.bootfs.as_ref() {
            for (bpath, off, len) in self.iter_bootfs_entries() {
                if bpath == path {
                    let take = len.min(64 * 1024) as usize;
                    let mut buf = alloc::vec![0u8; take];
                    if vmo.read(off, &mut buf) == Ok(take) {
                        return Ok(String::from_utf8_lossy(&buf).into_owned());
                    }
                }
            }
        }
        Err(format!("script '{path}' not found"))
    }

    /// Resolve `raw` against the working directory, lexically.
    ///
    /// `.` and empty elements are dropped and `..` pops a component (never
    /// above `/`), so `cd /bin/..` is `/` rather than `/bin/..`, and
    /// `ls ../bin` from `/bin` names the same directory as `ls /bin`.
    fn normalize_path(&self, raw: &str) -> String {
        let joined = if raw.starts_with('/') {
            String::from(raw)
        } else if self.pwd == "/" {
            format!("/{raw}")
        } else {
            format!("{}/{raw}", self.pwd)
        };
        let mut parts: Vec<&str> = Vec::new();
        for seg in joined.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        let mut out = String::from("/");
        for (idx, part) in parts.iter().enumerate() {
            if idx > 0 {
                out.push('/');
            }
            out.push_str(part);
        }
        out
    }

    /// Whether `abs` names a directory that exists in HxFS or in BOOTFS.
    fn is_directory(&mut self, abs: &str) -> bool {
        if abs == "/" {
            return true;
        }
        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            if hxfs.open_dir(abs).is_ok() {
                return true;
            }
        }
        let dir_prefix = format!("{abs}/");
        self.iter_bootfs_entries()
            .iter()
            .any(|(path, _, _)| path == abs || path.starts_with(&dir_prefix))
    }

    /// Turn one argument into the absolute path an external utility expects.
    ///
    /// External `/bin/*.elf` tools have no notion of a working directory, so
    /// the shell resolves relative names before the spawn: explicit paths
    /// (`./x`, `../x`, `a/b`), home-relative `.`/`..`, and bare names that only
    /// exist relative to the current directory ("`cat welcome.txt`" in `/etc`).
    /// Names that do not exist yet are resolved too (`mkdir sub`, `touch x`):
    /// resolving only existing names would create them in `/` instead of the
    /// working directory.
    fn absolutize_argument(&self, arg: &str) -> Option<String> {
        if arg.is_empty() {
            return None;
        }
        Some(self.normalize_path(arg))
    }

    /// Resolve the path arguments of one external command, leaving data alone.
    ///
    /// The rule is about *meaning*, not position: a bare word is a path only
    /// when it is not a number, a size, a hex literal, a `key=value` pair or a
    /// subcommand of the tool being started. That is what `sleep 30`,
    /// `hexdump -n 128`, `du -d 1`, `mkfs -s 16M` and
    /// `dd if=/dev/zero bs=512` need, and what `cat welcome.txt` also gets.
    fn resolve_arguments(&self, name: &str, args: &[String]) -> Vec<String> {
        /// Tools that take no path arguments at all.
        const NO_PATH_ARGS: &[&str] = &["hxfs", "pci", "acpi", "ps", "sleep", "schedctl"];
        let mut owned: Vec<String> = Vec::with_capacity(args.len() + 1);
        if NO_PATH_ARGS.contains(&name) {
            owned.extend(args.iter().cloned());
            return owned;
        }
        // `write <path> <data>`: the payload is text, not a path.
        let path_budget = if name == "write" { 1 } else { usize::MAX };
        let mut paths_taken = 0usize;
        let mut skip_value = false;
        for arg in args {
            if skip_value {
                skip_value = false;
                owned.push(arg.clone());
                continue;
            }
            if flag_takes_value(name, arg) {
                skip_value = true;
                owned.push(arg.clone());
                continue;
            }
            if arg.starts_with('-') {
                owned.push(arg.clone());
                continue;
            }
            // `if=/dev/zero`, `bs=512`, `of=firmware.bin`: the key is data, the
            // value is a path only for the two keys that name one.
            if let Some((key, value)) = arg.split_once('=') {
                let path_key = matches!(key, "if" | "of");
                if path_key && !value.starts_with('/') && !value.is_empty() {
                    owned.push(format!("{key}={}", self.normalize_path(value)));
                } else {
                    owned.push(arg.clone());
                }
                continue;
            }
            if paths_taken >= path_budget || is_data_word(name, arg) {
                owned.push(arg.clone());
                continue;
            }
            match self.absolutize_argument(arg) {
                Some(abs) => {
                    paths_taken += 1;
                    owned.push(abs);
                }
                None => owned.push(arg.clone()),
            }
        }
        owned
    }

    fn resolve_elf(&mut self, name: &str) -> Option<(Vmo, u64, u64, String)> {
        let mut candidates = Vec::new();
        if name.starts_with('/') {
            candidates.push(String::from(name));
            if !name.ends_with(".elf") {
                candidates.push(format!("{name}.elf"));
            }
        } else {
            candidates.push(format!("/bin/{name}"));
            if !name.ends_with(".elf") {
                candidates.push(format!("/bin/{name}.elf"));
            }
        }

        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            for cand in &candidates {
                if let Ok(file) = hxfs.open_file(cand) {
                    if let Ok(vmo) = file.read_into_vmo() {
                        if let Ok(size) = file.size() {
                            return Some((vmo, 0, size, cand.clone()));
                        }
                    }
                }
            }
        }

        let bootfs_entries = self.iter_bootfs_entries();
        if let Some(bootfs) = self.bootfs.as_ref() {
            for cand in &candidates {
                for (path, off, len) in &bootfs_entries {
                    if path == cand {
                        if let Ok(dup) =
                            bootfs.duplicate(libcanvas::rights::READ | libcanvas::rights::TRANSFER)
                        {
                            return Some((dup, *off, *len, cand.clone()));
                        }
                    }
                }
            }
        }
        None
    }

    fn spawn_external(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
    ) -> ExecOutcome {
        if self.bootfs.is_none() {
            return ExecOutcome::err(1, "no BOOTFS VMO available for dynamic linker");
        }

        let Some((elf_vmo, off, len, resolved)) = self.resolve_elf(name) else {
            return ExecOutcome::err(127, format!("unknown command: {name}"));
        };

        let mask = caps.map_or(caps_mask::ALL_DEFAULT, CapsSpec::to_caps_mask);
        let Ok((stdin_r, stdin_w)) = Channel::pair() else {
            return ExecOutcome::err(1, "failed creating stdin channel");
        };
        let Ok((stdout_r, stdout_w)) = Channel::pair() else {
            return ExecOutcome::err(1, "failed creating stdout channel");
        };
        let Ok((stderr_r, stderr_w)) = Channel::pair() else {
            return ExecOutcome::err(1, "failed creating stderr channel");
        };

        self.try_connect_hxfs();
        let mut dir_holder: Option<libcanvas::HxfsDirectory> = None;
        let mut svc_holder: Option<Channel> = None;
        let mut blk_holder: Option<Channel> = None;
        let mut query_holder: Option<Channel> = None;

        if let Some(spec) = caps {
            if let Some(dir_grant) = &spec.dir {
                if let Some(hxfs) = self.hxfs.as_ref() {
                    let rights = if dir_grant.read_only {
                        hxfs_rights::READ
                    } else {
                        hxfs_rights::ALL
                    };
                    if let Ok(d) = hxfs.open_dir_with_rights(&dir_grant.path, rights) {
                        dir_holder = Some(d);
                    }
                }
            } else if spec.hxfs == HxfsAccess::ReadOnly {
                if let Some(hxfs) = self.hxfs.as_ref() {
                    if let Ok(d) = hxfs.root_with_rights(hxfs_rights::READ) {
                        dir_holder = Some(d);
                    }
                }
            } else if spec.hxfs == HxfsAccess::ReadWrite {
                if let Some(hxfs) = self.hxfs.as_ref() {
                    if let Ok(d) = hxfs.root_with_rights(hxfs_rights::ALL) {
                        dir_holder = Some(d);
                    }
                }
                svc_holder = self.open_hxfs_channel_fresh();
            }
            if spec.block_rw {
                blk_holder = self.open_block_nvme_fresh();
            }
            if (mask & caps_mask::QUERY_RO) != 0 {
                query_holder = self.open_query_fresh();
            }
        } else {
            if let Some(hxfs) = self.hxfs.as_ref() {
                if let Ok(d) = hxfs.root_with_rights(hxfs_rights::ALL) {
                    dir_holder = Some(d);
                }
            }
            svc_holder = self.open_hxfs_channel_fresh();
            blk_holder = self.open_block_nvme_fresh();
            query_holder = self.open_query_fresh();
        }

        // Utilities take paths, not a working directory, so path arguments are
        // resolved here. Everything that is *data* -- numbers, sizes, values
        // after a flag that takes one, `key=value` pairs, subcommand words --
        // has to arrive at the tool exactly as it was typed.
        let mut owned_args = self.resolve_arguments(name, args);
        if name == "ls" && owned_args.is_empty() {
            owned_args.push(self.pwd.clone());
        }

        let fb_allowed = caps.is_none_or(|c| c.fb == FbAccess::ReadOnly);
        let frame_draw = if fb_allowed {
            self.frame_draw.as_ref()
        } else {
            None
        };

        let mut argv_strs: Vec<&str> = Vec::with_capacity(1 + owned_args.len());
        argv_strs.push(&resolved);
        for a in &owned_args {
            argv_strs.push(a.as_str());
        }

        let Some(lib_vmo) = self.bootfs.as_ref() else {
            return ExecOutcome::err(1, "no BOOTFS VMO available for dynamic linker");
        };

        let mut spawn_caps = SpawnCaps::new();
        spawn_caps.args = &argv_strs;
        spawn_caps.caps_mask = mask;
        spawn_caps.stdin = Some(&stdin_r);
        spawn_caps.stdout = Some(&stdout_w);
        spawn_caps.stderr = Some(&stderr_w);
        spawn_caps.hxfs_dir = dir_holder.as_ref().map(|d| d.channel());
        spawn_caps.hxfs_service = svc_holder.as_ref();
        spawn_caps.block_dev = blk_holder.as_ref();
        spawn_caps.frame_draw = frame_draw;
        spawn_caps.registry = query_holder.as_ref();

        let spawned =
            spawn_elf_from_vmo_with_caps(&resolved, &elf_vmo, off, len, lib_vmo, &spawn_caps);
        drop(stdin_r);
        drop(stdout_w);
        drop(stderr_w);
        drop(dir_holder);
        drop(svc_holder);
        drop(blk_holder);
        drop(query_holder);
        drop(elf_vmo);

        let (process, child_bootstrap) = match spawned {
            Ok(pair) => pair,
            Err(e) => {
                return ExecOutcome::err(1, format!("spawn '{resolved}' failed: {}", e.as_str()));
            }
        };
        drop(child_bootstrap);
        let pid = u64::from(process.handle().raw());
        let short_name = resolved.rsplit('/').next().unwrap_or(&resolved);
        let active_label = format!("{short_name} [{pid}]");
        if self.status_hook.is_some() && self.ipc_out.is_some() {
            let caps_txt = self.caps_summary();
            if let (Some(hook), Some(ch)) = (self.status_hook, self.ipc_out.as_ref()) {
                hook(ch, &self.pwd, &active_label, &caps_txt);
            }
        }

        if let Some(in_val) = stdin {
            let bytes = in_val.to_pipe_bytes();
            let mut cursor = 0usize;
            while cursor < bytes.len() {
                let end = (cursor + 4096).min(bytes.len());
                match stdin_w.write(&bytes[cursor..end]) {
                    Ok(()) => cursor = end,
                    Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
                    Err(_) => break,
                }
            }
        }
        drop(stdin_w);

        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut out_open = true;
        let mut err_open = true;
        let mut chunk = [0u8; 4096];
        self.last_child_interrupted = false;
        let mut interrupted = false;
        // After a kill the child's pipes must close; if the teardown is slow we
        // still hand the prompt back rather than spin forever on a dead child.
        let mut interrupt_deadline: Option<u64> = None;
        while out_open || err_open {
            let mut progressed = false;
            if out_open {
                match stdout_r.read_into(&mut chunk) {
                    Ok(n) => {
                        stdout_bytes.extend_from_slice(&chunk[..n]);
                        trim_capture(&mut stdout_bytes);
                        progressed = true;
                    }
                    Err(ErrorCode::PeerClosed) => out_open = false,
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                    Err(_) => out_open = false,
                }
            }
            if err_open {
                match stderr_r.read_into(&mut chunk) {
                    Ok(n) => {
                        stderr_bytes.extend_from_slice(&chunk[..n]);
                        trim_capture(&mut stderr_bytes);
                        progressed = true;
                    }
                    Err(ErrorCode::PeerClosed) => err_open = false,
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                    Err(_) => err_open = false,
                }
            }
            // `Ctrl-C` (or the smoke gate's synthetic interrupt) kills the
            // child through the `ProcessTerminate` capability while the shell
            // stays alive to reap it.
            if !interrupted && self.poll_child_interrupt(&process) {
                interrupted = true;
                self.last_child_interrupted = true;
                let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
                interrupt_deadline = Some(now.saturating_add(300));
            }
            if let Some(deadline) = interrupt_deadline {
                let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
                if now >= deadline {
                    break;
                }
            }
            if !progressed {
                libcanvas::process::yield_now();
            }
        }

        let exit_code = process.wait_exit().unwrap_or(-1) as i32;
        if self.status_hook.is_some() && self.ipc_out.is_some() {
            let caps_txt = self.caps_summary();
            if let (Some(hook), Some(ch)) = (self.status_hook, self.ipc_out.as_ref()) {
                hook(ch, &self.pwd, "hsh.elf", &caps_txt);
            }
        }

        let mut out_str = String::from_utf8_lossy(&stdout_bytes).into_owned();
        let err_str = String::from_utf8_lossy(&stderr_bytes).into_owned();
        if interrupted {
            // Conventional echo: the terminal does not render `^C` itself
            // because the key goes to the shell, not to a foreground process
            // group, so the shell prints it.
            if out_str.is_empty() {
                out_str = String::from("^C\n");
            } else {
                out_str = format!("^C\n{out_str}");
            }
        }

        // A failing child's stdout is usually its report -- `std-smoke` prints
        // one `[std] FAIL` line per broken invariant to stdout and only a
        // marker to stderr -- so a non-zero exit keeps both streams. Dropping
        // stdout here once hid the reason a smoke failed behind a single
        // stderr line.
        let combined = format!("{out_str}{err_str}");
        let output = if exit_code == 0 {
            match Table::from_tsv(&out_str) {
                Some(tbl) => Value::Table(tbl),
                None => Value::Text(combined.trim_end_matches('\n').into()),
            }
        } else {
            Value::Text(combined.trim_end_matches('\n').into())
        };

        ExecOutcome {
            status: exit_code,
            output,
            clear_screen: false,
            exit_requested: false,
            child_pid: Some(pid),
        }
    }

    /// Service terminal input while a child is running.
    ///
    /// Returns `true` when the child must be terminated: either a real
    /// `Ctrl-C` key event arrived, or the smoke gate asked for a synthetic
    /// interrupt. Every other packet is buffered and replayed to the prompt
    /// once the shell is idle, so keystrokes typed during a child run are not
    /// lost.
    fn poll_child_interrupt(&mut self, child: &Process) -> bool {
        let auto = if self.auto_interrupts > 0 {
            // Latch the deadline on the first poll so the wait is measured from
            // the child actually running, not from the request. A process
            // without a clock capability cannot advance the tick count, so the
            // wait also has a poll budget: the loop yields on every iteration,
            // which makes the budget a slower but unconditional backstop.
            let now = libcanvas::system::monotonic_ticks();
            let deadline = *self.interrupt_deadline.get_or_insert_with(|| {
                self.interrupt_polls = 0;
                now.unwrap_or(0)
                    .saturating_add(self.auto_interrupt_after_ticks)
            });
            self.interrupt_polls = self.interrupt_polls.saturating_add(1);
            let expired = match now {
                Ok(ticks) => ticks >= deadline,
                Err(_) => self.interrupt_polls >= self.auto_interrupt_after_ticks.max(1) * 500,
            };
            if expired {
                self.auto_interrupts -= 1;
                self.interrupt_deadline = None;
                true
            } else {
                false
            }
        } else {
            false
        };
        let mut ctrl_c = false;
        let mut received: Vec<Vec<u8>> = Vec::new();
        let mut buf = [0u8; 256];
        if let Some(ch) = self.key_source.as_ref() {
            loop {
                match ch.read_into(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => received.push(buf[..n].to_vec()),
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                    Err(_) => break,
                }
            }
        }
        // Drain into the replay buffer only after the channel borrow above is
        // released: pushing while `ch` is alive is a double borrow of `self`.
        for packet in received {
            if packet_is_ctrl_c(&packet) {
                ctrl_c = true;
            } else {
                self.pending_packets.push(packet);
            }
        }
        if auto || ctrl_c {
            // Best effort by design: if the child exited on its own between
            // the key press and this call, its own status stands (the syscall
            // is idempotent) and there is nothing left to kill.
            let _ = child.terminate(CTRL_C_EXIT_CODE);
            return true;
        }
        false
    }

    /// Take the packets buffered while a child was running.
    pub fn take_pending_packets(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.pending_packets)
    }

    fn cmd_caps(&mut self) -> ExecOutcome {
        self.try_connect_hxfs();
        let mut tbl = Table::new(vec_str(&["capability", "state", "detail"]));
        tbl.rows.push(vec_str(&[
            "hxfs",
            if self.hxfs.is_some() { "rw" } else { "offline" },
            if self.hxfs.is_some() {
                "HxFS v7 mounted"
            } else {
                "no mounted volume"
            },
        ]));
        tbl.rows.push(vec_str(&[
            "bootfs",
            if self.bootfs.is_some() { "ro" } else { "none" },
            "HBOOTFS1 VMO",
        ]));
        tbl.rows.push(vec_str(&[
            "fb",
            if self.frame_draw.is_some() {
                "ro"
            } else {
                "none"
            },
            "FrameDraw resource",
        ]));
        tbl.rows.push(vec_str(&[
            "registry",
            if self.registry.is_some() {
                "rw"
            } else {
                "none"
            },
            "DriverManager service registry",
        ]));
        ExecOutcome::ok(Value::Table(tbl))
    }
}

fn vec_str(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| String::from(*s)).collect()
}

impl ShellHost for HshHost {
    fn exec_command(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
    ) -> ExecOutcome {
        match name {
            "cls" | "clear" => ExecOutcome {
                status: 0,
                output: Value::Empty,
                clear_screen: true,
                exit_requested: false,
                child_pid: None,
            },
            "exit" => ExecOutcome {
                status: args.first().and_then(|s| s.parse::<i32>().ok()).unwrap_or(0),
                output: Value::Empty,
                clear_screen: false,
                exit_requested: true,
                child_pid: None,
            },
            "help" => ExecOutcome::ok_text(concat!(
                "hsh intrinsics:\n",
                "  help | cls | clear | echo | pwd | cd <dir> | caps | history | exit\n",
                "  pipes: | where <col> <op> <val> | select <cols> | sort [--desc] [col] | head [n] | tail [n] | count | grep <pat>\n",
                "  lang:  let x = ...; if ... { ... } else { ... }; for x in [...] { ... }; fn f(a) { ... }; alias a = \"...\"\n",
                "  caps:  @caps(hxfs=none|ro|rw, bootfs=ro|none, fb=none|ro, dir=/sub:ro) <cmd>\n",
                "  apps:  doom | snake [hard] | font <cozette|tty|compact> | shutdown\n",
                "external /bin/*.elf utilities:\n",
                "  ls | cat | stat | touch | mkdir | rm | mv | write | hxfs | pci | acpi | ps | fdisk"
            )),
            "pwd" => ExecOutcome::ok_text(self.pwd.clone()),
            "cd" => {
                let target = args.first().map(String::as_str).unwrap_or("/");
                let abs = self.normalize_path(target);
                if self.is_directory(&abs) {
                    self.pwd = abs;
                    ExecOutcome::ok(Value::Empty)
                } else {
                    ExecOutcome::err(1, format!("cd: {target}: no such directory"))
                }
            }
            "history" => {
                let mut out = String::new();
                for (idx, line) in self.history_lines.iter().enumerate() {
                    out.push_str(&format!("{:>3}  {}\n", idx + 1, line));
                }
                ExecOutcome::ok_text(out.trim_end_matches('\n'))
            }
            "caps" => self.cmd_caps(),
            "font" => match args.first().map(String::as_str) {
                Some("cozette") => {
                    self.delegated = Some(DelegatedAction::Font(0));
                    ExecOutcome::ok_text("font set to cozette 6x13")
                }
                Some("tty") => {
                    self.delegated = Some(DelegatedAction::Font(1));
                    ExecOutcome::ok_text("font set to tty 8x16")
                }
                Some("compact") => {
                    self.delegated = Some(DelegatedAction::Font(2));
                    ExecOutcome::ok_text("font set to compact 8x8")
                }
                _ => ExecOutcome::err(1, "usage: font <cozette|tty|compact>"),
            },
            "doom" => {
                self.delegated = Some(DelegatedAction::Doom);
                ExecOutcome::ok(Value::Empty)
            }
            "snake" => {
                let hard = args.first().is_some_and(|a| a == "hard");
                self.delegated = Some(DelegatedAction::Snake { hard });
                ExecOutcome::ok(Value::Empty)
            }
            "shutdown" => {
                self.delegated = Some(DelegatedAction::Shutdown);
                ExecOutcome::ok(Value::Empty)
            }
            _ => self.spawn_external(caps, name, args, stdin),
        }
    }

    fn write_file(&mut self, path: &str, data: &[u8], append: bool) -> Result<(), String> {
        let abs = self.normalize_path(path);
        self.try_connect_hxfs();
        let Some(hxfs) = self.hxfs.as_ref() else {
            return Err(String::from("redirect failed: hxfs unavailable"));
        };
        let file = match hxfs.open_file(&abs) {
            Ok(f) => f,
            Err(_) => hxfs
                .create_file(&abs)
                .map_err(|e| format!("create '{abs}': {}", e.as_str()))?,
        };
        let offset = if append {
            file.size().unwrap_or(0)
        } else {
            file.truncate(0)
                .map_err(|e| format!("truncate '{abs}': {}", e.as_str()))?;
            0
        };
        let mut written = 0usize;
        while written < data.len() {
            let end = (written + 2048).min(data.len());
            file.write_at(offset + written as u64, &data[written..end])
                .map_err(|e| format!("write '{abs}': {}", e.as_str()))?;
            written = end;
        }
        file.fsync()
            .map_err(|e| format!("fsync '{abs}': {}", e.as_str()))?;
        Ok(())
    }
}

/// Flags whose following argument is a value, never a path.
///
/// Per command, because the same letter means different things: `head -n 5`
/// takes a count while `sort -n` is a switch, and `grep -c` counts while
/// `head -c 16` takes bytes. Values are data by definition, so the shell must
/// not resolve them as paths (`hexdump -n 128` used to become `-n /128`).
fn flag_takes_value(command: &str, flag: &str) -> bool {
    match command {
        "hexdump" => matches!(flag, "-n" | "--length" | "-s" | "--skip"),
        "du" => matches!(flag, "-d" | "--max-depth"),
        "mkfs" => matches!(flag, "-s" | "--size" | "-p" | "--part" | "-t" | "--type"),
        "head" | "tail" => matches!(flag, "-n" | "--lines" | "-c" | "--bytes"),
        "sort" => matches!(flag, "-k" | "--key" | "-t" | "--field-separator"),
        "grep" => matches!(flag, "-e" | "--regexp" | "-m" | "--max-count"),
        "find" => matches!(flag, "-name" | "-type" | "-maxdepth" | "-iname"),
        "fdisk" => matches!(
            flag,
            "--type" | "--size" | "--start" | "--end" | "--name"
        ),
        // `-cf`, `-tf`, `-xf`, `-f`: every archive flag that names the archive.
        "tar" => flag.starts_with('-') && flag.ends_with('f') || matches!(flag, "-C" | "--directory"),
        _ => false,
    }
}

/// True when `word` is data for `command`, not a path.
fn is_data_word(command: &str, word: &str) -> bool {
    if is_number_or_size(word) {
        return true;
    }
    // Subcommands of the multi-command tools.
    let subcommands: &[&str] = match command {
        "fdisk" => &["list", "inspect", "verify", "gpt-init", "add", "del", "resize"],
        "hxfs" => &["status", "stats", "scrub", "snapshot", "sync", "gc"],
        "schedctl" => &["cpus", "tasks", "bench"],
        _ => &[],
    };
    subcommands.contains(&word)
}

/// `128`, `0x1f`, `16M`, `512B`, `4K`, `200G`, `1T`, `+32M`.
fn is_number_or_size(word: &str) -> bool {
    let body = word.strip_prefix('+').unwrap_or(word);
    if body.is_empty() {
        return false;
    }
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    let (digits, suffix) = match body.char_indices().last() {
        Some((idx, last)) if last.is_ascii_alphabetic() => (&body[..idx], &body[idx..]),
        _ => (body, ""),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    matches!(
        suffix,
        "" | "B" | "b" | "K" | "k" | "M" | "m" | "G" | "g" | "T" | "t"
    )
}
