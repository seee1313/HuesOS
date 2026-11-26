//! `ShellHost` implementation for `/bin/hsh.elf`.
//!
//! Only true shell intrinsics live inside `hsh.elf`; every file/system/disk
//! utility (`ls`, `cat`, `stat`, `touch`, `mkdir`, `rm`, `mv`, `write`, `hxfs`,
//! `pci`, `acpi`, `ps`, `fdisk`) is spawned as an external dynamic ELF from
//! `HxFS` or `BOOTFS` with full `@caps(...)` attenuation.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_abi::auxv::caps_mask;
use huesos_abi::hxfs::rights as hxfs_rights;
use huesos_abi::term_ipc::{hsh_to_term, put_u16, term_to_hsh, MAX_WRITE_CHUNK};
use huesos_hsh::{
    CapsSpec, ExecOutcome, FbAccess, HostPathKind, HxfsAccess, NetAccess, PipelineCommand,
    ShellHost, Table, Value, WlanAccess,
};
use libcanvas::process::{spawn_elf_from_vmo_with_caps, Process, SpawnCaps};
use libcanvas::{wait_any, Channel, ErrorCode, Handle, Hxfs, Signals, Vmo, WaitItem};

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

const MAX_PIPELINE_STAGES: usize = 16;
const MAX_PIPELINE_JOBS: usize = 16;
const MAX_PIPE_PENDING_BYTES: usize = 64 * 1024;
const MAX_PENDING_BACKGROUND_OUTPUT_BYTES: usize = 512 * 1024;
const PIPELINE_DRAIN_MESSAGES: usize = 32;

struct SpawnedExternal {
    process: Process,
    pid: u64,
    resolved: String,
    owned_args: Vec<String>,
}

struct PipelineStage {
    process: Process,
    pid: u64,
    stdin_w: Option<Channel>,
    stdout_r: Option<Channel>,
    stderr_r: Option<Channel>,
    exit_code: Option<i32>,
}

struct PipelinePipe {
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    source_closed: bool,
}

struct PipelineRun {
    stages: Vec<PipelineStage>,
    pipes: Vec<PipelinePipe>,
    output: Vec<u8>,
    stderr: Vec<u8>,
    direct_stream: bool,
    background_stream: bool,
    streamed_any: bool,
    last_stream_byte: u8,
}

struct BackgroundJob {
    id: u64,
    pid: u64,
    label: String,
    run: Option<PipelineRun>,
    status: Option<i32>,
    output: Vec<u8>,
    stderr: Vec<u8>,
    notification_queued: bool,
}

struct PendingTerminalOutput {
    fg: Option<(u8, u8, u8)>,
    bytes: Vec<u8>,
    cursor: usize,
}

/// Runtime environment owned by `/bin/hsh.elf`.
pub struct HshHost {
    pub registry: Option<Channel>,
    pub hxfs: Option<Hxfs>,
    pub block_dev: Option<Channel>,
    pub net_svc: Option<Channel>,
    pub wlan_svc: Option<Channel>,
    block_unavailable: bool,
    hxfs_unavailable: bool,
    net_unavailable: bool,
    wlan_unavailable: bool,
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
    /// True when evaluated scripts should stream unpiped foreground commands
    /// directly to `ipc_out` instead of capturing `EvalAction::Output` in RAM.
    pub interactive_stream: bool,
    /// Whether the most recent child run ended through the `Ctrl-C` path.
    pub last_child_interrupted: bool,
    next_job_id: u64,
    background_jobs: Vec<BackgroundJob>,
    pending_background_output: VecDeque<PendingTerminalOutput>,
    pending_background_output_bytes: usize,
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

/// Translate a terminal key packet into VT100 stdin bytes for a foreground child.
fn packet_to_vt100(packet: &[u8]) -> Option<&'static [u8]> {
    if packet.first() != Some(&term_to_hsh::TAG_KEY_EVENT) || packet.len() < 2 {
        return None;
    }
    let klen = (packet[1] as usize).min(packet.len() - 2);
    let key = &packet[2..2 + klen];
    match key {
        [b'k', 0, _] => None,
        [b'k', 1, 0x80] => Some(b"\x1b[A"),
        [b'k', 1, 0x81] => Some(b"\x1b[B"),
        [b'k', 1, 0x82] => Some(b"\x1b[D"),
        [b'k', 1, 0x83] => Some(b"\x1b[C"),
        [b'k', 1, 0x84] => Some(b"\x1b[H"),
        [b'k', 1, 0x85] => Some(b"\x1b[F"),
        [b'k', 1, 0x86] => Some(b"\x1b[3~"),
        [b'k', 1, 0x87] => Some(b"\x1b[5~"),
        [b'k', 1, 0x88] => Some(b"\x1b[6~"),
        b"enter" => Some(b"\r"),
        b"backspace" => Some(b"\x08"),
        _ => None,
    }
}

fn packet_single_byte(packet: &[u8]) -> Option<u8> {
    if packet.first() != Some(&term_to_hsh::TAG_KEY_EVENT) || packet.len() < 2 {
        return None;
    }
    let klen = (packet[1] as usize).min(packet.len() - 2);
    let key = &packet[2..2 + klen];
    match key {
        [b'k', 1, b'\n'] => Some(b'\r'),
        [b'k', 1, byte] if *byte <= 0x7f => Some(*byte),
        [b'c', byte] => Some(*byte),
        [byte] if *byte <= 0x7f => Some(*byte),
        _ => None,
    }
}

fn is_live_process_koid(koid: u64) -> bool {
    if koid == 0 {
        return false;
    }
    if libcanvas::process::Process::current()
        .and_then(|p| p.koid())
        .ok()
        == Some(koid)
    {
        return true;
    }
    let mut found = false;
    let _ = libcanvas::system::for_each_task(|record| {
        if record.process_koid() == koid && record.state < 3 {
            found = true;
        }
    });
    found
}

fn command_uses_block_device(resolved: &str) -> bool {
    let base = resolved.rsplit('/').next().unwrap_or(resolved);
    let stem = base.strip_suffix(".elf").unwrap_or(base);
    matches!(
        stem,
        "fdisk" | "lsblk" | "df" | "fsck" | "mkfs" | "dd" | "btop" | "hsh"
    )
}

fn strip_exec_ext(base: &str) -> &str {
    base.strip_suffix(".elf")
        .or_else(|| base.strip_suffix(".exe"))
        .unwrap_or(base)
}

fn command_uses_query_channel(resolved: &str) -> bool {
    let base = resolved.rsplit('/').next().unwrap_or(resolved);
    let stem = strip_exec_ext(base);
    matches!(
        stem,
        "pci"
            | "lsusb"
            | "acpi"
            | "ps"
            | "btop"
            | "netctl"
            | "wlanctl"
            | "df"
            | "lsblk"
            | "fdisk"
            | "hsh"
            | "std_smoke"
            | "std-smoke"
    )
}

fn arg_touches_usb_mount(arg: &str) -> bool {
    arg == "/"
        || arg == "/mnt"
        || arg.starts_with("/mnt/")
        || arg == "/dev/block/usb0"
        || arg == "/dev/usb0"
}

fn command_uses_net_service(resolved: &str) -> bool {
    let base = resolved.rsplit('/').next().unwrap_or(resolved);
    let stem = strip_exec_ext(base);
    matches!(
        stem,
        "ping" | "curl" | "netctl" | "wlanctl" | "btop" | "hsh" | "std_smoke" | "std-smoke"
    )
}

fn command_uses_wlan_service(resolved: &str) -> bool {
    let base = resolved.rsplit('/').next().unwrap_or(resolved);
    let stem = strip_exec_ext(base);
    matches!(
        stem,
        "wlanctl" | "netctl" | "btop" | "hsh" | "std_smoke" | "std-smoke"
    )
}

/// True when an unpiped interactive run should still capture TSV stdout so
/// `ShellEnv` pretty-prints aligned table headers/dividers instead of raw tabs.
fn command_emits_tsv_table(resolved: &str, args: &[String]) -> bool {
    let base = resolved.rsplit('/').next().unwrap_or(resolved);
    let stem = base.strip_suffix(".elf").unwrap_or(base);
    match stem {
        "ls" | "stat" | "hxfs" | "pci" | "acpi" | "ps" => true,
        "lsusb" => args.is_empty(),
        "fdisk" => matches!(args.first().map(String::as_str), Some("list" | "--list")),
        _ => false,
    }
}

impl HshHost {
    #[allow(dead_code)]
    pub fn new(
        registry: Option<Channel>,
        bootfs: Option<Vmo>,
        frame_draw: Option<Handle>,
        ipc_out: Option<Channel>,
    ) -> Self {
        Self::new_with_caps(registry, None, None, bootfs, frame_draw, ipc_out)
    }

    pub fn new_with_caps(
        registry: Option<Channel>,
        hxfs_svc: Option<Channel>,
        block_dev: Option<Channel>,
        bootfs: Option<Vmo>,
        frame_draw: Option<Handle>,
        ipc_out: Option<Channel>,
    ) -> Self {
        let mut host = Self {
            registry,
            hxfs: hxfs_svc.map(Hxfs::from_channel),
            block_dev,
            net_svc: None,
            wlan_svc: None,
            block_unavailable: false,
            hxfs_unavailable: false,
            net_unavailable: false,
            wlan_unavailable: false,
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
            interactive_stream: false,
            last_child_interrupted: false,
            next_job_id: 1,
            background_jobs: Vec::new(),
            pending_background_output: VecDeque::new(),
            pending_background_output_bytes: 0,
        };
        host.try_connect_hxfs();
        host
    }

    pub fn set_net_wlan_caps(&mut self, net_svc: Option<Channel>, wlan_svc: Option<Channel>) {
        self.net_svc = net_svc;
        self.wlan_svc = wlan_svc;
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
        if self.hxfs.is_some() || self.hxfs_unavailable || self.ipc_out.is_none() {
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
                Ok((n, None)) if buf[..n].starts_with(b"err:hxfs") => {
                    self.hxfs_unavailable = true;
                    return;
                }
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
        self.hxfs.as_ref()?;
        if self.ipc_out.is_none() {
            if let Some(dup) = self
                .hxfs
                .as_ref()
                .and_then(|hxfs| hxfs.channel().duplicate().ok())
            {
                return Some(dup);
            }
        }
        for _ in 0..3 {
            if let Some(ch) = self.open_hxfs_channel_once() {
                return Some(ch);
            }
            for _ in 0..8 {
                libcanvas::process::yield_now();
            }
        }
        self.hxfs
            .as_ref()
            .and_then(|hxfs| hxfs.channel().duplicate().ok())
    }

    fn open_hxfs_channel_once(&self) -> Option<Channel> {
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

    fn open_block_nvme_fresh(&mut self) -> Option<Channel> {
        if self.block_unavailable {
            return None;
        }
        if self.ipc_out.is_none() {
            if let Some(dup) = self.block_dev.as_ref().and_then(|ch| ch.duplicate().ok()) {
                return Some(dup);
            }
        }
        if let Some(reg) = self.registry.as_ref() {
            self.drain_registry();
            if reg.write(b"open:block:nvme").is_ok() {
                let mut buf = [0u8; 64];
                for _ in 0..HANDSHAKE_READS {
                    match reg.read_optional_handle_timeout(&mut buf, HANDSHAKE_WAIT_TICKS) {
                        Ok((n, Some(handle))) if &buf[..n] == b"service:block:nvme:channel" => {
                            return Some(Channel::from_handle(handle));
                        }
                        Ok((n, None)) if buf[..n].starts_with(b"err:block") => {
                            self.block_unavailable = true;
                            break;
                        }
                        Ok((_n, Some(handle))) => drop(handle),
                        Ok((_n, None)) => {}
                        Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                        Err(_) => break,
                    }
                }
            }
        }
        self.block_dev.as_ref().and_then(|ch| ch.duplicate().ok())
    }

    /// Hand the child a fresh DriverManager query channel.
    ///
    /// Transient congestion is normal: a burst of spawns can find every slot
    /// taken until `driver-manager` reaps the clients of the processes that
    /// already exited. Retry a few times instead of silently spawning a child
    /// without a registry capability, which would make `pci`/`ps`/`acpi` fail
    /// with "query channel unavailable".
    fn open_query_fresh(&self) -> Option<Channel> {
        if self.ipc_out.is_none() {
            return self.registry.as_ref().and_then(|ch| ch.duplicate().ok());
        }
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

    fn open_net_fresh(&mut self, read_only: bool) -> Option<Channel> {
        let req: &[u8] = if read_only {
            b"open:net:ro"
        } else {
            b"open:net"
        };
        if !self.net_unavailable {
            if let Some(reg) = self.registry.as_ref() {
                self.drain_registry();
                if reg.write(req).is_ok() {
                    let mut buf = [0u8; 64];
                    for _ in 0..HANDSHAKE_READS {
                        match reg.read_optional_handle_timeout(&mut buf, HANDSHAKE_WAIT_TICKS) {
                            Ok((n, Some(handle))) if &buf[..n] == b"service:net:channel" => {
                                return Some(Channel::from_handle(handle));
                            }
                            Ok((n, None)) if buf[..n].starts_with(b"err:net") => {
                                self.net_unavailable = true;
                                break;
                            }
                            Ok((_n, Some(handle))) => drop(handle),
                            Ok((_n, None)) => {}
                            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
        }
        if read_only {
            None
        } else {
            self.net_svc.as_ref().and_then(|ch| ch.duplicate().ok())
        }
    }

    fn open_wlan_fresh(&mut self, read_only: bool) -> Option<Channel> {
        let req: &[u8] = if read_only {
            b"open:wlan:ro"
        } else {
            b"open:wlan"
        };
        if !self.wlan_unavailable {
            if let Some(reg) = self.registry.as_ref() {
                self.drain_registry();
                if reg.write(req).is_ok() {
                    let mut buf = [0u8; 64];
                    for _ in 0..HANDSHAKE_READS {
                        match reg.read_optional_handle_timeout(&mut buf, HANDSHAKE_WAIT_TICKS) {
                            Ok((n, Some(handle))) if &buf[..n] == b"service:wlan:channel" => {
                                return Some(Channel::from_handle(handle));
                            }
                            Ok((n, None)) if buf[..n].starts_with(b"err:wlan") => {
                                self.wlan_unavailable = true;
                                break;
                            }
                            Ok((_n, Some(handle))) => drop(handle),
                            Ok((_n, None)) => {}
                            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
        }
        if read_only {
            None
        } else {
            self.wlan_svc.as_ref().and_then(|ch| ch.duplicate().ok())
        }
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
                if let Some(short) = rest
                    .strip_suffix(".elf")
                    .or_else(|| rest.strip_suffix(".exe"))
                {
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
        if let Some(rel) = split_usb0_rel(&path) {
            let bytes = self.usb_read_file(&rel)?;
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
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
        let base = name.rsplit('/').next().unwrap_or(name);
        let cmd = strip_exec_ext(base);
        /// Tools that take no path arguments at all.
        const NO_PATH_ARGS: &[&str] = &[
            "hxfs",
            "pci",
            "lsusb",
            "acpi",
            "ps",
            "sleep",
            "schedctl",
            "seq",
            "basename",
            "dirname",
            "ping",
            "curl",
            "netctl",
            "wlanctl",
            "win-hello",
            "win-threads",
            "win-bench",
            "win-crt-smoke",
        ];
        let mut owned: Vec<String> = Vec::with_capacity(args.len() + 1);
        if NO_PATH_ARGS.contains(&cmd) {
            owned.extend(args.iter().cloned());
            return owned;
        }
        // `ln -s <target> <link>`: the symlink target string is stored verbatim
        // (relative or absolute), while `<link>` is resolved against `pwd`.
        if cmd == "ln" {
            let mut operand_idx = 0usize;
            for arg in args {
                if arg.starts_with('-') {
                    owned.push(arg.clone());
                } else {
                    operand_idx += 1;
                    if operand_idx == 1 {
                        owned.push(arg.clone());
                    } else {
                        owned.push(self.normalize_path(arg));
                    }
                }
            }
            return owned;
        }
        // `chmod [-R] <mode> <path>...`: first non-flag operand is the mode spec.
        if cmd == "chmod" {
            let mut mode_seen = false;
            for arg in args {
                if arg.starts_with('-') {
                    owned.push(arg.clone());
                } else if !mode_seen {
                    mode_seen = true;
                    owned.push(arg.clone());
                } else {
                    owned.push(self.normalize_path(arg));
                }
            }
            return owned;
        }
        // `hsh`: `-c <script> [arg0 arg1 ...]` passes everything verbatim;
        // `hsh <script_path> [arg1 arg2 ...]` resolves only `<script_path>`.
        if cmd == "hsh" {
            if args.first().map(String::as_str) == Some("-c") {
                owned.extend(args.iter().cloned());
            } else if let Some((script_path, rest)) = args.split_first() {
                owned.push(self.normalize_path(script_path));
                owned.extend(rest.iter().cloned());
            }
            return owned;
        }
        // `write <path> <data>`: the payload is text, not a path.
        let path_budget = if cmd == "write" { 1 } else { usize::MAX };
        let mut paths_taken = 0usize;
        let mut grep_pattern_seen = false;
        let mut tar_base: Option<String> = None;
        let mut skip_kind = FlagValueKind::None;
        for arg in args {
            match skip_kind {
                FlagValueKind::Data => {
                    skip_kind = FlagValueKind::None;
                    if cmd == "grep" {
                        grep_pattern_seen = true;
                    }
                    owned.push(arg.clone());
                    continue;
                }
                FlagValueKind::Path => {
                    skip_kind = FlagValueKind::None;
                    owned.push(self.normalize_path(arg));
                    continue;
                }
                FlagValueKind::TarDir => {
                    skip_kind = FlagValueKind::None;
                    let abs_dir = self.normalize_path(arg);
                    tar_base = Some(abs_dir.clone());
                    owned.push(abs_dir);
                    continue;
                }
                FlagValueKind::None => {}
            }
            let fk = flag_value_kind(cmd, arg);
            if fk != FlagValueKind::None {
                skip_kind = fk;
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
            if cmd == "grep" && !grep_pattern_seen {
                grep_pattern_seen = true;
                owned.push(arg.clone());
                continue;
            }
            if cmd == "tar" && !arg.starts_with('/') && (tar_base.is_some() || self.pwd != "/") {
                owned.push(arg.clone());
                continue;
            }
            if paths_taken >= path_budget || is_data_word(cmd, arg) {
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
            if !name.ends_with(".elf") && !name.ends_with(".exe") {
                candidates.push(format!("{name}.elf"));
                candidates.push(format!("{name}.exe"));
            }
        } else {
            candidates.push(format!("/bin/{name}"));
            if !name.ends_with(".elf") && !name.ends_with(".exe") {
                candidates.push(format!("/bin/{name}.elf"));
                candidates.push(format!("/bin/{name}.exe"));
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
                        if let Ok(dup) = bootfs.duplicate(
                            libcanvas::rights::READ
                                | libcanvas::rights::TRANSFER
                                | libcanvas::rights::DUPLICATE,
                        ) {
                            return Some((dup, *off, *len, cand.clone()));
                        }
                    }
                }
            }
        }
        None
    }

    fn spawn_prepared_child(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin_r: &Channel,
        stdout_w: &Channel,
        stderr_w: &Channel,
    ) -> Result<SpawnedExternal, ExecOutcome> {
        if self.bootfs.is_none() {
            return Err(ExecOutcome::err(
                1,
                "no BOOTFS VMO available for dynamic linker",
            ));
        }

        let Some((elf_vmo, off, len, resolved)) = self.resolve_elf(name) else {
            return Err(ExecOutcome::err(127, format!("unknown command: {name}")));
        };

        // Utilities take paths, not a working directory, so path arguments are
        // resolved here. Data operands stay exactly as typed. A directory grant
        // makes relative paths meaningful inside the granted subtree.
        let dir_confined = caps.is_some_and(|c| c.dir.is_some());
        let mut owned_args = if dir_confined {
            args.to_vec()
        } else {
            self.resolve_arguments(name, args)
        };
        if name == "ls" && owned_args.is_empty() {
            owned_args.push(if dir_confined {
                String::from(".")
            } else {
                self.pwd.clone()
            });
        }
        let needs_query = command_uses_query_channel(&resolved)
            || (!dir_confined
                && (self.pwd == "/mnt"
                    || self.pwd.starts_with("/mnt/")
                    || owned_args.iter().any(|a| arg_touches_usb_mount(a))));

        let mask = caps.map_or(caps_mask::ALL_DEFAULT, CapsSpec::to_caps_mask);
        self.try_connect_hxfs();
        let mut dir_holder: Option<libcanvas::HxfsDirectory> = None;
        let mut svc_holder: Option<Channel> = None;
        let mut blk_holder: Option<Channel> = None;
        let mut query_holder: Option<Channel> = None;
        let mut net_holder: Option<Channel> = None;
        let mut wlan_holder: Option<Channel> = None;

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
            if spec.block_rw && command_uses_block_device(&resolved) {
                blk_holder = self.open_block_nvme_fresh();
            }
            if (mask & caps_mask::QUERY_RO) != 0 && needs_query {
                query_holder = self.open_query_fresh();
            }
            if spec.net != NetAccess::None && command_uses_net_service(&resolved) {
                net_holder = self.open_net_fresh(spec.net == NetAccess::ReadOnly);
            }
            if spec.wlan != WlanAccess::None && command_uses_wlan_service(&resolved) {
                wlan_holder = self.open_wlan_fresh(spec.wlan == WlanAccess::ReadOnly);
            }
        } else {
            if let Some(hxfs) = self.hxfs.as_ref() {
                if let Ok(d) = hxfs.root_with_rights(hxfs_rights::ALL) {
                    dir_holder = Some(d);
                }
            }
            svc_holder = self.open_hxfs_channel_fresh();
            if command_uses_block_device(&resolved) {
                blk_holder = self.open_block_nvme_fresh();
            }
            if needs_query {
                query_holder = self.open_query_fresh();
            }
            if command_uses_net_service(&resolved) {
                net_holder = self.open_net_fresh(false);
            }
            if command_uses_wlan_service(&resolved) {
                wlan_holder = self.open_wlan_fresh(false);
            }
        }

        let fb_allowed = caps.is_none_or(|c| c.fb == FbAccess::ReadOnly);
        let frame_draw = if fb_allowed {
            self.frame_draw.as_ref()
        } else {
            None
        };

        let mut argv_strs: Vec<&str> = Vec::with_capacity(1 + owned_args.len());
        argv_strs.push(&resolved);
        for arg in &owned_args {
            argv_strs.push(arg.as_str());
        }

        let Some(lib_vmo) = self.bootfs.as_ref() else {
            return Err(ExecOutcome::err(
                1,
                "no BOOTFS VMO available for dynamic linker",
            ));
        };
        let mut spawn_caps = SpawnCaps::new();
        spawn_caps.args = &argv_strs;
        spawn_caps.caps_mask = mask;
        spawn_caps.stdin = Some(stdin_r);
        spawn_caps.stdout = Some(stdout_w);
        spawn_caps.stderr = Some(stderr_w);
        spawn_caps.hxfs_dir = dir_holder.as_ref().map(|dir| dir.channel());
        spawn_caps.hxfs_service = svc_holder.as_ref();
        spawn_caps.block_dev = blk_holder.as_ref();
        spawn_caps.frame_draw = frame_draw;
        spawn_caps.registry = query_holder.as_ref();
        spawn_caps.net_service = net_holder.as_ref();
        spawn_caps.wlan_service = wlan_holder.as_ref();

        let spawned =
            spawn_elf_from_vmo_with_caps(&resolved, &elf_vmo, off, len, lib_vmo, &spawn_caps);
        drop(dir_holder);
        drop(svc_holder);
        drop(blk_holder);
        drop(query_holder);
        drop(net_holder);
        drop(wlan_holder);
        drop(elf_vmo);

        let (process, child_bootstrap) = spawned.map_err(|error| {
            ExecOutcome::err(1, format!("spawn '{resolved}' failed: {}", error.as_str()))
        })?;
        drop(child_bootstrap);
        let pid = match process.koid() {
            Ok(koid) => koid,
            Err(error) => {
                let _ = process.terminate(1);
                return Err(ExecOutcome::err(
                    1,
                    format!("could not read child process KOID: {}", error.as_str()),
                ));
            }
        };

        Ok(SpawnedExternal {
            process,
            pid,
            resolved,
            owned_args,
        })
    }

    fn spawn_external(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
        capture_output: bool,
        separate_stderr: bool,
    ) -> ExecOutcome {
        let Ok((stdin_r, stdin_w)) = Channel::pair() else {
            return ExecOutcome::err(1, "failed creating stdin channel");
        };
        let Ok((stdout_r, stdout_w)) = Channel::pair() else {
            return ExecOutcome::err(1, "failed creating stdout channel");
        };
        let Ok((stderr_r, stderr_w)) = Channel::pair() else {
            return ExecOutcome::err(1, "failed creating stderr channel");
        };

        let spawned = self.spawn_prepared_child(caps, name, args, &stdin_r, &stdout_w, &stderr_w);
        drop(stdin_r);
        drop(stdout_w);
        drop(stderr_w);
        let SpawnedExternal {
            process,
            pid,
            resolved,
            owned_args,
        } = match spawned {
            Ok(child) => child,
            Err(error) => return error,
        };

        let short_name = resolved.rsplit('/').next().unwrap_or(&resolved);
        let active_label = format!("{short_name} [{pid}]");
        if self.status_hook.is_some() && self.ipc_out.is_some() {
            let caps_txt = self.caps_summary();
            if let (Some(hook), Some(ch)) = (self.status_hook, self.ipc_out.as_ref()) {
                hook(ch, &self.pwd, &active_label, &caps_txt);
            }
        }

        let stream_direct = self.interactive_stream
            && !capture_output
            && self.ipc_out.is_some()
            && !command_emits_tsv_table(&resolved, &owned_args);

        let mut live_stdin_w = if let Some(in_val) = stdin {
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
            drop(stdin_w);
            None
        } else if stream_direct {
            Some(stdin_w)
        } else {
            drop(stdin_w);
            None
        };

        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut streamed_any = false;
        let mut last_stream_byte = b'\n';
        let mut out_open = true;
        let mut err_open = true;
        let mut chunk = [0u8; 4096];
        self.last_child_interrupted = false;
        let mut interrupted = false;
        // After a kill the child's pipes must close; if the teardown is slow we
        // still hand the prompt back rather than spin forever on a dead child.
        let mut interrupt_deadline: Option<u64> = None;
        while out_open || err_open {
            self.poll_background_jobs_impl();
            let mut progressed = false;
            if out_open {
                loop {
                    match stdout_r.read_into(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            progressed = true;
                            if stream_direct {
                                self.forward_stream_bytes(None, &chunk[..n]);
                                streamed_any = true;
                                last_stream_byte = chunk[n - 1];
                            } else {
                                stdout_bytes.extend_from_slice(&chunk[..n]);
                                trim_capture(&mut stdout_bytes);
                            }
                        }
                        Err(ErrorCode::PeerClosed) => {
                            out_open = false;
                            break;
                        }
                        Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                        Err(_) => {
                            out_open = false;
                            break;
                        }
                    }
                }
            }
            if err_open {
                loop {
                    match stderr_r.read_into(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            progressed = true;
                            if stream_direct {
                                self.forward_stream_bytes(Some((255, 110, 110)), &chunk[..n]);
                                streamed_any = true;
                                last_stream_byte = chunk[n - 1];
                            } else {
                                stderr_bytes.extend_from_slice(&chunk[..n]);
                                trim_capture(&mut stderr_bytes);
                            }
                        }
                        Err(ErrorCode::PeerClosed) => {
                            err_open = false;
                            break;
                        }
                        Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                        Err(_) => {
                            err_open = false;
                            break;
                        }
                    }
                }
            }
            // `Ctrl-C` (or the smoke gate's synthetic interrupt) kills the
            // child through the `ProcessTerminate` capability while the shell
            // stays alive to reap it. In `stream_direct` mode, non-Ctrl-C keys
            // are forwarded live to the child's `stdin_w` as VT100 sequences.
            if !interrupted && self.poll_child_input(&process, live_stdin_w.as_ref()) {
                interrupted = true;
                self.last_child_interrupted = true;
                live_stdin_w = None;
                let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
                interrupt_deadline = Some(now.saturating_add(300));
            }
            if let Some(deadline) = interrupt_deadline {
                let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
                if now >= deadline {
                    break;
                }
            }
            if !progressed
                && (out_open || err_open)
                && self.wait_for_child_activity(&stdout_r, out_open, &stderr_r, err_open, &process)
            {
                // Child already exited; do one final non-blocking drain of
                // any already-enqueued bytes and do not wait on pipes that
                // deferred process teardown has not dropped yet.
                while let Ok(n) = stdout_r.read_into(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if stream_direct {
                        self.forward_stream_bytes(None, &chunk[..n]);
                        streamed_any = true;
                        last_stream_byte = chunk[n - 1];
                    } else {
                        stdout_bytes.extend_from_slice(&chunk[..n]);
                        trim_capture(&mut stdout_bytes);
                    }
                }
                while let Ok(n) = stderr_r.read_into(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if stream_direct {
                        self.forward_stream_bytes(Some((255, 110, 110)), &chunk[..n]);
                        streamed_any = true;
                        last_stream_byte = chunk[n - 1];
                    } else {
                        stderr_bytes.extend_from_slice(&chunk[..n]);
                        trim_capture(&mut stderr_bytes);
                    }
                }
                break;
            }
        }
        drop(live_stdin_w);

        let exit_code = process.wait_exit().unwrap_or(-1) as i32;
        if self.status_hook.is_some() && self.ipc_out.is_some() {
            let caps_txt = self.caps_summary();
            if let (Some(hook), Some(ch)) = (self.status_hook, self.ipc_out.as_ref()) {
                hook(ch, &self.pwd, "hsh.elf", &caps_txt);
            }
        }

        if stream_direct {
            if interrupted {
                self.forward_stream_bytes(None, b"\x1b[?25h\x1b[0m");
                self.forward_stream_bytes(Some((255, 110, 110)), b"\n^C\n");
            } else {
                self.forward_stream_bytes(None, b"\x1b[?25h\x1b[0m");
                if streamed_any && last_stream_byte != b'\n' {
                    self.forward_stream_bytes(None, b"\n");
                }
            }
            return ExecOutcome {
                status: exit_code,
                output: Value::Empty,
                stderr: String::new(),
                clear_screen: false,
                exit_requested: false,
                child_pid: Some(pid),
            };
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

        // When stderr is redirected (`2>` / `2>>`), keep stdout pure and return
        // `stderr` separately for `ShellEnv` to write into the target file.
        let text_body = if separate_stderr {
            out_str.clone()
        } else {
            format!("{out_str}{err_str}")
        };
        let output = if exit_code == 0 {
            match Table::from_tsv(&out_str) {
                Some(tbl) => Value::Table(tbl),
                None => Value::Text(text_body.trim_end_matches('\n').into()),
            }
        } else {
            Value::Text(text_body.trim_end_matches('\n').into())
        };

        ExecOutcome {
            status: exit_code,
            output,
            stderr: err_str.trim_end_matches('\n').into(),
            clear_screen: false,
            exit_requested: false,
            child_pid: Some(pid),
        }
    }

    fn start_pipeline_run(
        &mut self,
        commands: &[PipelineCommand],
        capture_output: bool,
        background: bool,
    ) -> Result<PipelineRun, ExecOutcome> {
        if commands.is_empty() {
            return Err(ExecOutcome::err(2, "empty pipeline"));
        }
        if commands.len() > MAX_PIPELINE_STAGES {
            return Err(ExecOutcome::err(
                2,
                format!("pipeline exceeds the {MAX_PIPELINE_STAGES}-stage limit"),
            ));
        }
        if background {
            self.prune_background_job_history();
            if self.background_jobs.len() >= MAX_PIPELINE_JOBS {
                return Err(ExecOutcome::err(
                    1,
                    format!("background job table is full ({MAX_PIPELINE_JOBS} jobs)"),
                ));
            }
        }

        let live_stdin = !background
            && self.interactive_stream
            && !capture_output
            && self.ipc_out.is_some()
            && self.key_source.is_some();
        let mut run = PipelineRun {
            stages: Vec::with_capacity(commands.len()),
            pipes: Vec::with_capacity(commands.len().saturating_sub(1)),
            output: Vec::new(),
            stderr: Vec::new(),
            direct_stream: false,
            background_stream: false,
            streamed_any: false,
            last_stream_byte: b'\n',
        };
        let mut last_is_tsv = false;

        for (index, command) in commands.iter().enumerate() {
            let Ok((stdin_r, stdin_w)) = Channel::pair() else {
                for stage in &run.stages {
                    let _ = stage.process.terminate(1);
                }
                return Err(ExecOutcome::err(
                    1,
                    "failed creating pipeline stdin channel",
                ));
            };
            let Ok((stdout_r, stdout_w)) = Channel::pair() else {
                for stage in &run.stages {
                    let _ = stage.process.terminate(1);
                }
                return Err(ExecOutcome::err(
                    1,
                    "failed creating pipeline stdout channel",
                ));
            };
            let Ok((stderr_r, stderr_w)) = Channel::pair() else {
                for stage in &run.stages {
                    let _ = stage.process.terminate(1);
                }
                return Err(ExecOutcome::err(
                    1,
                    "failed creating pipeline stderr channel",
                ));
            };

            let spawned = self.spawn_prepared_child(
                command.caps.as_ref(),
                &command.name,
                &command.args,
                &stdin_r,
                &stdout_w,
                &stderr_w,
            );
            drop(stdin_r);
            drop(stdout_w);
            drop(stderr_w);
            let SpawnedExternal {
                process,
                pid,
                resolved,
                owned_args,
            } = match spawned {
                Ok(child) => child,
                Err(error) => {
                    for stage in &run.stages {
                        let _ = stage.process.terminate(1);
                    }
                    return Err(error);
                }
            };

            let stdin_w = if index == 0 && !live_stdin {
                drop(stdin_w);
                None
            } else {
                Some(stdin_w)
            };
            if index > 0 {
                run.pipes.push(PipelinePipe {
                    pending: VecDeque::new(),
                    pending_bytes: 0,
                    source_closed: false,
                });
            }
            run.stages.push(PipelineStage {
                process,
                pid,
                stdin_w,
                stdout_r: Some(stdout_r),
                stderr_r: Some(stderr_r),
                exit_code: None,
            });
            if index + 1 == commands.len() {
                last_is_tsv = command_emits_tsv_table(&resolved, &owned_args);
            }
        }

        run.direct_stream = !background
            && self.interactive_stream
            && !capture_output
            && self.ipc_out.is_some()
            && !last_is_tsv;
        run.background_stream =
            background && self.interactive_stream && !capture_output && self.ipc_out.is_some();

        let leader_pid = run.stages[0].pid;
        let active_label = format!("pipeline [{leader_pid}]");
        if !background && self.status_hook.is_some() && self.ipc_out.is_some() {
            let caps_txt = self.caps_summary();
            if let (Some(hook), Some(channel)) = (self.status_hook, self.ipc_out.as_ref()) {
                hook(channel, &self.pwd, &active_label, &caps_txt);
            }
        }
        Ok(run)
    }

    fn exec_external_pipeline(
        &mut self,
        commands: &[PipelineCommand],
        background: bool,
        capture_output: bool,
    ) -> ExecOutcome {
        let run = match self.start_pipeline_run(commands, capture_output, background) {
            Ok(run) => run,
            Err(error) => return error,
        };
        let leader_pid = run.stages[0].pid;

        if background {
            self.prune_background_job_history();
            if self.background_jobs.len() >= MAX_PIPELINE_JOBS {
                for stage in &run.stages {
                    let _ = stage.process.terminate(1);
                }
                return ExecOutcome::err(
                    1,
                    format!("background job table is full ({MAX_PIPELINE_JOBS} jobs)"),
                );
            }
            let id = self.next_job_id;
            self.next_job_id = self.next_job_id.wrapping_add(1).max(1);
            let label = pipeline_label(commands);
            self.background_jobs.push(BackgroundJob {
                id,
                pid: leader_pid,
                label: label.clone(),
                run: Some(run),
                status: None,
                output: Vec::new(),
                stderr: Vec::new(),
                notification_queued: false,
            });
            return ExecOutcome {
                status: 0,
                output: Value::Text(format!("[{id}] {leader_pid}")),
                stderr: String::new(),
                clear_screen: false,
                exit_requested: false,
                child_pid: Some(leader_pid),
            };
        }

        self.drive_foreground_pipeline(run)
    }

    fn drive_foreground_pipeline(&mut self, mut run: PipelineRun) -> ExecOutcome {
        self.last_child_interrupted = false;
        let mut interrupted = false;
        loop {
            let (finished, progressed) = self.pump_pipeline_run(&mut run);
            if finished {
                break;
            }
            self.poll_background_jobs_impl();
            if !interrupted {
                let interrupt = {
                    let first = &run.stages[0];
                    self.poll_child_input(&first.process, first.stdin_w.as_ref())
                };
                if interrupt {
                    interrupted = true;
                    self.last_child_interrupted = true;
                    for stage in &run.stages {
                        let _ = stage.process.terminate(CTRL_C_EXIT_CODE);
                    }
                    run.stages[0].stdin_w.take();
                }
            }
            if !progressed {
                self.wait_for_pipeline_activity(&run);
            }
        }
        let outcome = self.finish_pipeline_run(run, interrupted);
        if self.status_hook.is_some() && self.ipc_out.is_some() {
            let caps_txt = self.caps_summary();
            if let (Some(hook), Some(channel)) = (self.status_hook, self.ipc_out.as_ref()) {
                hook(channel, &self.pwd, "hsh.elf", &caps_txt);
            }
        }
        outcome
    }

    /// Drain all connected channels without blocking, applying bounded
    /// backpressure and propagating downstream `PeerClosed` upstream immediately.
    fn pump_pipeline_run(&mut self, run: &mut PipelineRun) -> (bool, bool) {
        let mut progressed = false;
        let mut chunk = [0u8; 4096];

        // Poll stage exits up front so an early consumer exit (e.g. `head -n 5`)
        // immediately closes its stdin and propagates `PeerClosed` upstream.
        for stage in &mut run.stages {
            if stage.exit_code.is_none() {
                stage.exit_code = match stage.process.poll_exit() {
                    Ok(Some(code)) => {
                        stage.stdin_w.take();
                        progressed = true;
                        Some(code as i32)
                    }
                    Ok(None) => None,
                    Err(_) => {
                        stage.stdin_w.take();
                        Some(-1)
                    }
                };
            }
        }

        for edge in (0..run.pipes.len()).rev() {
            if run.stages[edge + 1].stdin_w.is_none() {
                run.pipes[edge].pending.clear();
                run.pipes[edge].pending_bytes = 0;
                run.pipes[edge].source_closed = true;
                if run.stages[edge].stdout_r.take().is_some() {
                    progressed = true;
                }
                continue;
            }

            while let Some(message) = run.pipes[edge].pending.front().cloned() {
                let Some(writer) = run.stages[edge + 1].stdin_w.as_ref() else {
                    break;
                };
                let result = writer.write(&message);
                match result {
                    Ok(()) => {
                        run.pipes[edge].pending.pop_front();
                        run.pipes[edge].pending_bytes =
                            run.pipes[edge].pending_bytes.saturating_sub(message.len());
                        progressed = true;
                    }
                    Err(ErrorCode::ShouldWait) => break,
                    Err(_) => {
                        run.stages[edge + 1].stdin_w.take();
                        run.pipes[edge].pending.clear();
                        run.pipes[edge].pending_bytes = 0;
                        run.pipes[edge].source_closed = true;
                        run.stages[edge].stdout_r.take();
                        progressed = true;
                        break;
                    }
                }
            }

            if run.stages[edge + 1].stdin_w.is_none() {
                continue;
            }

            for _ in 0..PIPELINE_DRAIN_MESSAGES {
                if run.pipes[edge].pending_bytes >= MAX_PIPE_PENDING_BYTES {
                    break;
                }
                let Some(reader) = run.stages[edge].stdout_r.as_ref() else {
                    break;
                };
                match reader.read_into(&mut chunk) {
                    Ok(0) => {
                        progressed = true;
                        continue;
                    }
                    Ok(n) => {
                        progressed = true;
                        if run.stages[edge + 1].stdin_w.is_some() {
                            run.pipes[edge].pending.push_back(chunk[..n].to_vec());
                            run.pipes[edge].pending_bytes =
                                run.pipes[edge].pending_bytes.saturating_add(n);
                        } else {
                            run.stages[edge].stdout_r.take();
                            break;
                        }
                    }
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                        if run.stages[edge].exit_code.is_some() {
                            run.pipes[edge].source_closed = true;
                            run.stages[edge].stdout_r.take();
                        }
                        break;
                    }
                    Err(_) => {
                        run.pipes[edge].source_closed = true;
                        run.stages[edge].stdout_r.take();
                        break;
                    }
                }
            }
            if run.pipes[edge].source_closed
                && run.pipes[edge].pending.is_empty()
                && run.stages[edge + 1].stdin_w.is_some()
            {
                run.stages[edge + 1].stdin_w.take();
                progressed = true;
            }
        }

        let mut all_output_drained = true;
        let last = run.stages.len().saturating_sub(1);
        if let Some(reader) = run.stages[last].stdout_r.as_ref() {
            let mut hit_drain_limit = false;
            for drained in 0..PIPELINE_DRAIN_MESSAGES {
                match reader.read_into(&mut chunk) {
                    Ok(0) => {
                        progressed = true;
                        hit_drain_limit = drained + 1 == PIPELINE_DRAIN_MESSAGES;
                    }
                    Ok(n) => {
                        progressed = true;
                        if run.direct_stream {
                            self.forward_stream_bytes(None, &chunk[..n]);
                            run.streamed_any = true;
                            run.last_stream_byte = chunk[n - 1];
                        } else if run.background_stream {
                            self.enqueue_background_output(None, chunk[..n].to_vec());
                        } else {
                            run.output.extend_from_slice(&chunk[..n]);
                            trim_capture(&mut run.output);
                        }
                        hit_drain_limit = drained + 1 == PIPELINE_DRAIN_MESSAGES;
                    }
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                    Err(_) => {
                        run.stages[last].stdout_r.take();
                        break;
                    }
                }
            }
            if hit_drain_limit {
                all_output_drained = false;
            }
        }

        for index in 0..run.stages.len() {
            if let Some(reader) = run.stages[index].stderr_r.as_ref() {
                let mut hit_drain_limit = false;
                for drained in 0..PIPELINE_DRAIN_MESSAGES {
                    match reader.read_into(&mut chunk) {
                        Ok(0) => {
                            progressed = true;
                            hit_drain_limit = drained + 1 == PIPELINE_DRAIN_MESSAGES;
                        }
                        Ok(n) => {
                            progressed = true;
                            if run.direct_stream {
                                self.forward_stream_bytes(Some((255, 110, 110)), &chunk[..n]);
                                run.streamed_any = true;
                                run.last_stream_byte = chunk[n - 1];
                            } else if run.background_stream {
                                self.enqueue_background_output(
                                    Some((255, 110, 110)),
                                    chunk[..n].to_vec(),
                                );
                            } else {
                                run.stderr.extend_from_slice(&chunk[..n]);
                                trim_capture(&mut run.stderr);
                            }
                            hit_drain_limit = drained + 1 == PIPELINE_DRAIN_MESSAGES;
                        }
                        Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                        Err(_) => {
                            run.stages[index].stderr_r.take();
                            break;
                        }
                    }
                }
                if hit_drain_limit {
                    all_output_drained = false;
                }
            }
            if run.stages[index].exit_code.is_none() {
                run.stages[index].exit_code = match run.stages[index].process.poll_exit() {
                    Ok(Some(code)) => Some(code as i32),
                    Ok(None) => None,
                    Err(_) => Some(-1),
                };
            }
        }

        let all_exited = run.stages.iter().all(|stage| stage.exit_code.is_some());
        if all_exited && all_output_drained {
            // No child can consume any remaining queued input. Output channels
            // were drained above; discard leftovers from stages whose consumer
            // exited early, then release all endpoints with the run.
            for pipe in &mut run.pipes {
                pipe.pending.clear();
                pipe.pending_bytes = 0;
            }
            for stage in &mut run.stages {
                stage.stdin_w.take();
            }
            return (true, progressed);
        }
        (false, progressed)
    }

    fn wait_for_pipeline_activity(&self, run: &PipelineRun) {
        let mut items = [WaitItem::new(0, Signals::NONE, 0); libcanvas::waitset::MAX_ITEMS];
        let mut count = 0usize;

        for stage in &run.stages {
            if let Some(reader) = stage.stdout_r.as_ref() {
                add_wait_item(
                    &mut items,
                    &mut count,
                    reader.handle(),
                    Signals::READABLE | Signals::PEER_CLOSED,
                );
            }
            if let Some(reader) = stage.stderr_r.as_ref() {
                add_wait_item(
                    &mut items,
                    &mut count,
                    reader.handle(),
                    Signals::READABLE | Signals::PEER_CLOSED,
                );
            }
        }
        for (edge, pipe) in run.pipes.iter().enumerate() {
            if !pipe.pending.is_empty() {
                if let Some(writer) = run.stages[edge + 1].stdin_w.as_ref() {
                    add_wait_item(
                        &mut items,
                        &mut count,
                        writer.handle(),
                        Signals::WRITABLE | Signals::PEER_CLOSED,
                    );
                }
            }
        }
        for stage in &run.stages {
            if stage.exit_code.is_none() {
                add_wait_item(
                    &mut items,
                    &mut count,
                    stage.process.handle(),
                    Signals::SIGNALED,
                );
            }
        }
        if let Some(keys) = self.key_source.as_ref() {
            add_wait_item(
                &mut items,
                &mut count,
                keys.handle(),
                Signals::READABLE | Signals::PEER_CLOSED,
            );
        }

        if count == 0 {
            libcanvas::process::yield_now();
        } else {
            let _ = wait_any(&items[..count], 20);
        }
    }

    fn finish_pipeline_run(&self, run: PipelineRun, interrupted: bool) -> ExecOutcome {
        let status = run
            .stages
            .last()
            .and_then(|stage| stage.exit_code)
            .unwrap_or(-1);
        let pid = run.stages.first().map(|stage| stage.pid);
        if run.direct_stream {
            if interrupted {
                self.forward_stream_bytes(None, b"\x1b[?25h\x1b[0m");
                self.forward_stream_bytes(Some((255, 110, 110)), b"\n^C\n");
            } else {
                self.forward_stream_bytes(None, b"\x1b[?25h\x1b[0m");
                if run.streamed_any && run.last_stream_byte != b'\n' {
                    self.forward_stream_bytes(None, b"\n");
                }
            }
            return ExecOutcome {
                status,
                output: Value::Empty,
                stderr: String::new(),
                clear_screen: false,
                exit_requested: false,
                child_pid: pid,
            };
        }

        let mut stdout = String::from_utf8_lossy(&run.output).into_owned();
        let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
        if interrupted {
            stdout = format!("^C\n{stdout}");
        }
        let combined = format!("{stdout}{stderr}");
        let output = if status == 0 && stderr.is_empty() {
            Table::from_tsv(&stdout)
                .map(Value::Table)
                .unwrap_or_else(|| Value::Text(combined.trim_end_matches('\n').into()))
        } else {
            Value::Text(combined.trim_end_matches('\n').into())
        };
        ExecOutcome {
            status,
            output,
            stderr,
            clear_screen: false,
            exit_requested: false,
            child_pid: pid,
        }
    }

    fn prune_background_job_history(&mut self) {
        while self.background_jobs.len() >= MAX_PIPELINE_JOBS {
            let Some(index) = self
                .background_jobs
                .iter()
                .position(|job| job.status.is_some() && job.notification_queued)
            else {
                break;
            };
            self.background_jobs.remove(index);
        }
    }

    fn poll_background_jobs_impl(&mut self) {
        let mut jobs = core::mem::take(&mut self.background_jobs);
        for job in &mut jobs {
            let finished = job
                .run
                .as_mut()
                .is_some_and(|run| self.pump_pipeline_run(run).0);
            if finished {
                if let Some(run) = job.run.take() {
                    job.status = Some(
                        run.stages
                            .last()
                            .and_then(|stage| stage.exit_code)
                            .unwrap_or(-1),
                    );
                    job.output = run.output;
                    job.stderr = run.stderr;
                }
            }
        }
        self.background_jobs = jobs;
        self.queue_completed_job_notifications();
        self.flush_pending_background_output();
    }

    fn queue_completed_job_notifications(&mut self) {
        if self.ipc_out.is_none() {
            return;
        }
        let mut completed = Vec::new();
        for job in &mut self.background_jobs {
            let Some(status) = job.status else {
                continue;
            };
            if job.notification_queued {
                continue;
            }
            job.notification_queued = true;
            completed.push((
                job.id,
                job.pid,
                status,
                job.label.clone(),
                core::mem::take(&mut job.output),
                core::mem::take(&mut job.stderr),
            ));
        }

        for (id, pid, status, label, output, stderr) in completed {
            self.enqueue_background_output(
                None,
                format!("\n[{id}] Done ({status}) {label} [{pid}]\n").into_bytes(),
            );
            self.enqueue_background_output(None, output);
            self.enqueue_background_output(Some((255, 110, 110)), stderr);
        }
    }

    fn enqueue_background_output(&mut self, fg: Option<(u8, u8, u8)>, mut bytes: Vec<u8>) {
        let available = MAX_PENDING_BACKGROUND_OUTPUT_BYTES
            .saturating_sub(self.pending_background_output_bytes);
        if available == 0 || bytes.is_empty() {
            return;
        }
        bytes.truncate(available);
        self.pending_background_output_bytes += bytes.len();
        self.pending_background_output
            .push_back(PendingTerminalOutput {
                fg,
                bytes,
                cursor: 0,
            });
    }

    /// Try a bounded amount of queued job output so idle job polling never
    /// blocks the shell on a slow terminal consumer.
    fn flush_pending_background_output(&mut self) {
        let Some(channel) = self.ipc_out.as_ref() else {
            return;
        };
        for _ in 0..8 {
            let Some(front) = self.pending_background_output.front_mut() else {
                break;
            };
            if front.cursor >= front.bytes.len() {
                self.pending_background_output.pop_front();
                continue;
            }
            let take = (front.bytes.len() - front.cursor).min(MAX_WRITE_CHUNK);
            let (use_fg, r, g, b) = match front.fg {
                Some((r, g, b)) => (1u8, r, g, b),
                None => (0u8, 0, 0, 0),
            };
            let mut packet = [0u8; 7 + MAX_WRITE_CHUNK];
            packet[0] = hsh_to_term::TAG_WRITE;
            packet[1] = use_fg;
            packet[2] = r;
            packet[3] = g;
            packet[4] = b;
            put_u16(&mut packet, 5, take as u16);
            packet[7..7 + take].copy_from_slice(&front.bytes[front.cursor..front.cursor + take]);
            match channel.write(&packet[..7 + take]) {
                Ok(()) => {
                    front.cursor += take;
                    self.pending_background_output_bytes =
                        self.pending_background_output_bytes.saturating_sub(take);
                    if front.cursor == front.bytes.len() {
                        self.pending_background_output.pop_front();
                    }
                }
                Err(ErrorCode::ShouldWait) => break,
                Err(_) => {
                    self.pending_background_output.clear();
                    self.pending_background_output_bytes = 0;
                    break;
                }
            }
        }
    }

    fn shutdown_background_jobs(&mut self) {
        for job in &self.background_jobs {
            if let Some(run) = job.run.as_ref() {
                for stage in &run.stages {
                    let _ = stage.process.terminate(CTRL_C_EXIT_CODE);
                }
            }
        }
        self.background_jobs.clear();
        self.pending_background_output.clear();
        self.pending_background_output_bytes = 0;
    }

    fn cmd_jobs(&self) -> ExecOutcome {
        if self.background_jobs.is_empty() {
            return ExecOutcome::ok_text("no background jobs");
        }
        let mut output = String::new();
        for job in &self.background_jobs {
            match job.status {
                Some(status) => output.push_str(&format!(
                    "[{}] Done({}) {}  {}\n",
                    job.id, status, job.pid, job.label
                )),
                None => output.push_str(&format!(
                    "[{}] Running {}  {}\n",
                    job.id, job.pid, job.label
                )),
            }
        }
        ExecOutcome::ok_text(output.trim_end_matches('\n'))
    }

    fn resolve_job_index(&self, spec: &str) -> Option<usize> {
        if let Some(rest) = spec.strip_prefix('%') {
            let id = rest.parse::<u64>().ok()?;
            return self.background_jobs.iter().position(|job| job.id == id);
        }
        let value = spec.parse::<u64>().ok()?;
        self.background_jobs
            .iter()
            .position(|job| {
                job.pid == value
                    || job
                        .run
                        .as_ref()
                        .is_some_and(|r| r.stages.iter().any(|s| s.pid == value))
            })
            .or_else(|| self.background_jobs.iter().position(|job| job.id == value))
    }

    fn cmd_fg(&mut self, args: &[String]) -> ExecOutcome {
        if args.len() > 1 {
            return ExecOutcome::err(2, "usage: fg [%job-id]");
        }
        self.poll_background_jobs_impl();
        let index = if let Some(spec) = args.first() {
            let Some(idx) = self.resolve_job_index(spec) else {
                return ExecOutcome::err(1, format!("fg: {spec}: no such job"));
            };
            idx
        } else {
            let Some(idx) = self
                .background_jobs
                .iter()
                .rposition(|job| job.run.is_some())
                .or_else(|| self.background_jobs.len().checked_sub(1))
            else {
                return ExecOutcome::err(1, "fg: current: no such job");
            };
            idx
        };

        let mut job = self.background_jobs.remove(index);
        if let Some(mut run) = job.run.take() {
            if self.interactive_stream && self.ipc_out.is_some() {
                self.forward_stream_bytes(None, format!("{}\n", job.label).as_bytes());
                if !run.output.is_empty() {
                    self.forward_stream_bytes(None, &run.output);
                    run.streamed_any = true;
                    run.last_stream_byte = *run.output.last().unwrap_or(&b'\n');
                    run.output.clear();
                }
                if !run.stderr.is_empty() {
                    self.forward_stream_bytes(Some((255, 110, 110)), &run.stderr);
                    run.stderr.clear();
                }
                run.background_stream = false;
                run.direct_stream = true;
            }
            return self.drive_foreground_pipeline(run);
        }

        let status = job.status.unwrap_or(0);
        let stdout = String::from_utf8_lossy(&job.output);
        let stderr = String::from_utf8_lossy(&job.stderr);
        let combined = format!("{stdout}{stderr}");
        ExecOutcome {
            status,
            output: if combined.is_empty() {
                Value::Empty
            } else {
                Value::Text(combined.trim_end_matches('\n').into())
            },
            stderr: String::new(),
            clear_screen: false,
            exit_requested: false,
            child_pid: Some(job.pid),
        }
    }

    fn cmd_kill(&mut self, args: &[String]) -> ExecOutcome {
        if args.is_empty() {
            return ExecOutcome::err(2, "usage: kill <%job-id | koid>");
        }
        // Accept optional signal-like flag (`-9`, `-TERM`, `-INT`) before target.
        let target = if args.len() == 2 && args[0].starts_with('-') {
            args[1].as_str()
        } else if args.len() == 1 {
            args[0].as_str()
        } else {
            return ExecOutcome::err(2, "usage: kill <%job-id | koid>");
        };

        if let Some(rest) = target.strip_prefix('%') {
            let Ok(id) = rest.parse::<u64>() else {
                return ExecOutcome::err(2, format!("kill: invalid job spec '{target}'"));
            };
            let Some(job) = self.background_jobs.iter().find(|job| job.id == id) else {
                return ExecOutcome::err(1, format!("kill: %{id}: no such background job"));
            };
            let Some(run) = job.run.as_ref() else {
                return ExecOutcome::err(1, format!("kill: %{id} has already completed"));
            };
            for stage in &run.stages {
                if let Err(ErrorCode::AccessDenied) = stage.process.terminate(CTRL_C_EXIT_CODE) {
                    return ExecOutcome::err(1, format!("kill: %{id}: PermissionDenied"));
                }
            }
            return ExecOutcome::ok_text(format!("[{id}] {} terminated", job.pid));
        }

        let Ok(num) = target.parse::<u64>() else {
            return ExecOutcome::err(2, "kill: expected %<job-id> or process <koid>");
        };

        if let Some(idx) = self.resolve_job_index(target) {
            let job = &self.background_jobs[idx];
            let id = job.id;
            let koid = job.pid;
            let Some(run) = job.run.as_ref() else {
                return ExecOutcome::err(1, format!("kill: job {id} has already completed"));
            };
            for stage in &run.stages {
                if let Err(ErrorCode::AccessDenied) = stage.process.terminate(CTRL_C_EXIT_CODE) {
                    return ExecOutcome::err(1, format!("kill: koid {koid}: PermissionDenied"));
                }
            }
            return ExecOutcome::ok_text(format!("[{id}] {koid} terminated"));
        }

        if is_live_process_koid(num) {
            return ExecOutcome::err(
                1,
                format!("kill: koid {num}: PermissionDenied (process capability handle not owned)"),
            );
        }

        ExecOutcome::err(1, format!("kill: {num}: no such job or process"))
    }

    fn wait_background_job(&mut self, id: u64) -> Option<ExecOutcome> {
        if !self.background_jobs.iter().any(|job| job.id == id) {
            return None;
        }
        loop {
            self.poll_background_jobs_impl();
            let finished = self
                .background_jobs
                .iter()
                .find(|job| job.id == id)
                .is_some_and(|job| job.status.is_some());
            if finished {
                break;
            }
            let wait_target = self
                .background_jobs
                .iter()
                .position(|job| job.id == id && job.run.is_some());
            if let Some(idx) = wait_target {
                let jobs = core::mem::take(&mut self.background_jobs);
                if let Some(run) = jobs[idx].run.as_ref() {
                    self.wait_for_pipeline_activity(run);
                }
                self.background_jobs = jobs;
            } else {
                libcanvas::process::yield_now();
            }
        }

        let index = self.background_jobs.iter().position(|job| job.id == id)?;
        let job = self.background_jobs.remove(index);
        let status = job.status.unwrap_or(-1);
        let output = if self.ipc_out.is_none() {
            let stdout = String::from_utf8_lossy(&job.output);
            let stderr = String::from_utf8_lossy(&job.stderr);
            Value::Text(format!("{stdout}{stderr}").trim_end_matches('\n').into())
        } else {
            Value::Text(format!("[{id}] {} exited ({status})", job.pid))
        };
        Some(ExecOutcome {
            status,
            output,
            stderr: String::new(),
            clear_screen: false,
            exit_requested: false,
            child_pid: Some(job.pid),
        })
    }

    fn cmd_wait(&mut self, args: &[String]) -> ExecOutcome {
        if args.len() > 1 {
            return ExecOutcome::err(2, "usage: wait [%job-id | koid]");
        }
        if let Some(raw_spec) = args.first() {
            let Some(idx) = self.resolve_job_index(raw_spec) else {
                return ExecOutcome::err(1, format!("wait: no such job: {raw_spec}"));
            };
            let id = self.background_jobs[idx].id;
            return self
                .wait_background_job(id)
                .unwrap_or_else(|| ExecOutcome::err(1, format!("wait: no such job: {raw_spec}")));
        }

        let ids: Vec<u64> = self.background_jobs.iter().map(|job| job.id).collect();
        let mut status = 0;
        let mut output = String::new();
        let mut pid = None;
        for id in ids {
            if let Some(result) = self.wait_background_job(id) {
                status = result.status;
                pid = result.child_pid;
                let text = result.output.into_text();
                if !text.is_empty() {
                    if !output.is_empty() {
                        output.push('\n');
                    }
                    output.push_str(&text);
                }
            }
        }
        ExecOutcome {
            status,
            output: if output.is_empty() {
                Value::Empty
            } else {
                Value::Text(output)
            },
            stderr: String::new(),
            clear_screen: false,
            exit_requested: false,
            child_pid: pid,
        }
    }

    fn forward_stream_bytes(&self, fg: Option<(u8, u8, u8)>, bytes: &[u8]) {
        let Some(ch) = self.ipc_out.as_ref() else {
            return;
        };
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
            loop {
                match ch.write(&pkt[..7 + take]) {
                    Ok(()) => break,
                    Err(ErrorCode::ShouldWait) => {
                        let item = [WaitItem::new(ch.handle().raw(), Signals::PEER_CLOSED, 1)];
                        let _ = wait_any(&item, 1);
                    }
                    Err(_) => return,
                }
            }
            pos += take;
        }
    }

    fn wait_for_child_activity(
        &self,
        stdout_r: &Channel,
        out_open: bool,
        stderr_r: &Channel,
        err_open: bool,
        child: &Process,
    ) -> bool {
        let mut items = [WaitItem::new(0, Signals::NONE, 0); 4];
        let mut count = 0usize;
        if out_open {
            items[count] = WaitItem::new(
                stdout_r.handle().raw(),
                Signals::READABLE | Signals::PEER_CLOSED,
                1,
            );
            count += 1;
        }
        if err_open {
            items[count] = WaitItem::new(
                stderr_r.handle().raw(),
                Signals::READABLE | Signals::PEER_CLOSED,
                2,
            );
            count += 1;
        }
        if let Some(key_ch) = self.key_source.as_ref() {
            items[count] = WaitItem::new(
                key_ch.handle().raw(),
                Signals::READABLE | Signals::PEER_CLOSED,
                3,
            );
            count += 1;
        }
        items[count] = WaitItem::new(child.handle().raw(), Signals::SIGNALED, 4);
        count += 1;

        let wait_ticks = if let Some(deadline) = self.interrupt_deadline {
            let now = libcanvas::system::monotonic_ticks().unwrap_or(0);
            deadline.saturating_sub(now).clamp(1, 20)
        } else if self.auto_interrupts > 0 {
            self.auto_interrupt_after_ticks.clamp(1, 20)
        } else {
            20
        };
        if let Ok(outcome) = wait_any(&items[..count], wait_ticks) {
            return outcome
                .satisfied()
                .iter()
                .any(|r| r.key == 4 && (r.active_signals & Signals::SIGNALED.bits()) != 0);
        }
        false
    }

    /// Service terminal input while a child is running.
    ///
    /// Returns `true` when the child must be terminated: either a real
    /// `Ctrl-C` key event arrived, or the smoke gate asked for a synthetic
    /// interrupt. In foreground streaming mode (`live_stdin.is_some()`), every
    /// other keystroke is translated into VT100 sequences and written to the
    /// child's `stdin`; otherwise packets are buffered for prompt replay.
    fn poll_child_input(&mut self, child: &Process, live_stdin: Option<&Channel>) -> bool {
        let auto = if self.auto_interrupts > 0 {
            let now = libcanvas::system::monotonic_ticks();
            let deadline = *self.interrupt_deadline.get_or_insert_with(|| {
                self.interrupt_polls = 0;
                now.unwrap_or(0)
                    .saturating_add(self.auto_interrupt_after_ticks)
            });
            self.interrupt_polls = self.interrupt_polls.saturating_add(1);
            let expired = match now {
                Ok(ticks) => ticks >= deadline,
                Err(_) => self.interrupt_polls >= self.auto_interrupt_after_ticks.max(1) * 50,
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
        for packet in received {
            if packet_is_ctrl_c(&packet) {
                ctrl_c = true;
            } else if let Some(stdin_w) = live_stdin {
                if let Some(seq) = packet_to_vt100(&packet) {
                    let _ = stdin_w.write(seq);
                } else if let Some(byte) = packet_single_byte(&packet) {
                    let _ = stdin_w.write(&[byte]);
                }
            } else {
                self.pending_packets.push(packet);
            }
        }
        if auto || ctrl_c {
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

fn pipeline_label(commands: &[PipelineCommand]) -> String {
    let mut label = String::new();
    for (index, command) in commands.iter().enumerate() {
        if index != 0 {
            label.push_str(" | ");
        }
        label.push_str(&command.name);
        for arg in &command.args {
            label.push(' ');
            label.push_str(arg);
        }
    }
    label
}

fn add_wait_item(items: &mut [WaitItem], count: &mut usize, handle: &Handle, signals: Signals) {
    if *count < items.len() {
        items[*count] = WaitItem::new(handle.raw(), signals, *count as u64);
        *count += 1;
    }
}

impl ShellHost for HshHost {
    fn exec_command(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
    ) -> ExecOutcome {
        self.exec_command_mode(caps, name, args, stdin, true)
    }

    fn exec_command_mode(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
        capture_output: bool,
    ) -> ExecOutcome {
        self.exec_command_ex(caps, name, args, stdin, capture_output, false)
    }

    fn exec_command_ex(
        &mut self,
        caps: Option<&CapsSpec>,
        name: &str,
        args: &[String],
        stdin: Option<&Value>,
        capture_output: bool,
        separate_stderr: bool,
    ) -> ExecOutcome {
        match name {
            "cls" | "clear" => ExecOutcome {
                status: 0,
                output: Value::Empty,
                stderr: String::new(),
                clear_screen: true,
                exit_requested: false,
                child_pid: None,
            },
            "exit" => ExecOutcome {
                status: args.first().and_then(|s| s.parse::<i32>().ok()).unwrap_or(0),
                output: Value::Empty,
                stderr: String::new(),
                clear_screen: false,
                exit_requested: true,
                child_pid: None,
            },
            "help" => ExecOutcome::ok_text(concat!(
                "hsh intrinsics:\n",
                "  help | cls | clear | echo | printf | test | [ | true | false | export | env | pwd | cd <dir> | caps | history | jobs | fg | wait | kill | exit\n",
                "  pipes: | where <col> <op> <val> | select <cols> | sort [--desc] [col] | head [n] | tail [n] | count | grep <pat>\n",
                "  jobs:  command & | jobs | fg [%job] | wait [%job|koid] | kill <%job|koid>\n",
                "  lang:  let x = ...; x = $((x + 1)); if/elif/else; while ... { break; continue }; for x in [...]; fn f(a) { ... }\n",
                "  caps:  @caps(hxfs=none|ro|rw, bootfs=ro|none, fb=none|ro, net=none|ro|rw, wlan=none|ro|admin, dir=/sub:ro) <cmd>\n",
                "  apps:  doom | snake [hard] | btop | wlanctl | nano <file> | font <cozette|tty|compact> | shutdown\n",
                "external /bin/*.{elf,exe} utilities:\n",
                "  ls | cat | stat | touch | mkdir | rm | mv | cp | ln | chmod | readlink | write | find | grep | head | tail | wc | sort | uniq\n",
                "  seq | tee | basename | dirname | sha256sum | tar | hexdump | dd | df | du | lsblk | fdisk | mkfs | fsck | hxfs | ps | schedctl | pci | acpi | sleep\n",
                "  ping | curl | netctl | wlanctl"
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
            "jobs" => self.cmd_jobs(),
            "fg" => self.cmd_fg(args),
            "wait" => self.cmd_wait(args),
            "kill" => self.cmd_kill(args),
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
            _ => self.spawn_external(caps, name, args, stdin, capture_output, separate_stderr),
        }
    }

    fn exec_pipeline(
        &mut self,
        stages: &[PipelineCommand],
        background: bool,
        capture_output: bool,
    ) -> Option<ExecOutcome> {
        Some(self.exec_external_pipeline(stages, background, capture_output))
    }

    fn poll_background_jobs(&mut self) {
        self.poll_background_jobs_impl();
    }

    fn shutdown_background_jobs(&mut self) {
        HshHost::shutdown_background_jobs(self);
    }

    fn write_file(&mut self, path: &str, data: &[u8], append: bool) -> Result<(), String> {
        let abs = self.normalize_path(path);
        if let Some(rel) = split_usb0_rel(&abs) {
            return self.usb_write_file(&rel, data, append);
        }
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
        let _ = hxfs.checkpoint();
        Ok(())
    }

    fn read_file(&mut self, path: &str) -> Result<Vec<u8>, String> {
        let abs = self.normalize_path(path);
        if let Some(rel) = split_usb0_rel(&abs) {
            return self.usb_read_file(&rel);
        }
        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            if let Ok(file) = hxfs.open_file(&abs) {
                let sz = file.size().unwrap_or(0).min(256 * 1024) as usize;
                let mut out = alloc::vec![0u8; sz];
                let mut pos = 0usize;
                while pos < sz {
                    let take = (sz - pos).min(2048);
                    match file.read_at(pos as u64, &mut out[pos..pos + take]) {
                        Ok([]) => break,
                        Ok(slice) => pos += slice.len(),
                        Err(e) => return Err(format!("read '{abs}': {}", e.as_str())),
                    }
                }
                out.truncate(pos);
                return Ok(out);
            }
        }
        if let Some(vmo) = self.bootfs.as_ref() {
            for (bpath, off, len) in self.iter_bootfs_entries() {
                if bpath == abs {
                    let take = len.min(256 * 1024) as usize;
                    let mut buf = alloc::vec![0u8; take];
                    if vmo.read(off, &mut buf) == Ok(take) {
                        return Ok(buf);
                    }
                }
            }
        }
        Err(format!("'{abs}': not found"))
    }

    fn stat_path(&mut self, path: &str, follow: bool) -> Option<(HostPathKind, u64)> {
        let abs = self.normalize_path(path);
        if abs == "/mnt" {
            return Some((HostPathKind::Dir, 0));
        }
        if let Some(rel) = split_usb0_rel(&abs) {
            return self.usb_stat_path(&rel);
        }
        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            if let Ok(info) = hxfs.stat_path(&abs, follow) {
                let kind = match info.object_type {
                    1 => HostPathKind::File,
                    2 => HostPathKind::Dir,
                    3 => HostPathKind::Symlink,
                    _ => return None,
                };
                return Some((kind, info.size));
            }
        }
        if abs == "/" {
            return Some((HostPathKind::Dir, 0));
        }
        let dir_prefix = format!("{abs}/");
        for (bpath, _off, len) in self.iter_bootfs_entries() {
            if bpath == abs {
                return Some((HostPathKind::File, len));
            }
            if bpath.starts_with(&dir_prefix) {
                return Some((HostPathKind::Dir, 0));
            }
        }
        None
    }

    fn list_dir(&mut self, dir: &str) -> Vec<String> {
        let abs = if dir == "." {
            self.pwd.clone()
        } else {
            self.normalize_path(dir)
        };
        if abs == "/mnt" {
            let mut out = Vec::new();
            if self.usb_stat_path("/").is_some() {
                out.push(String::from("usb0"));
            }
            return out;
        }
        if let Some(rel) = split_usb0_rel(&abs) {
            return self.usb_list_dir(&rel);
        }
        let mut names = Vec::new();
        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            if let Ok(d) = hxfs.open_dir(&abs) {
                let mut raw = [0u8; 4096];
                if let Ok(bytes) = d.list(&mut raw) {
                    if let Ok(text) = core::str::from_utf8(bytes) {
                        for line in text.lines() {
                            if let Some(name) = line.split_whitespace().next() {
                                if !name.is_empty() && !names.iter().any(|x| x == name) {
                                    names.push(String::from(name));
                                }
                            }
                        }
                    }
                }
            }
        }
        if abs == "/" && !names.iter().any(|x| x == "mnt") && self.usb_stat_path("/").is_some() {
            names.push(String::from("mnt"));
        }
        let prefix = if abs == "/" {
            String::from("/")
        } else {
            format!("{abs}/")
        };
        for (bpath, _, _) in self.iter_bootfs_entries() {
            if let Some(rest) = bpath.strip_prefix(&prefix) {
                let leaf = rest.split('/').next().unwrap_or("");
                if !leaf.is_empty() && !names.iter().any(|x| x == leaf) {
                    names.push(String::from(leaf));
                }
            }
        }
        names
    }
}

fn split_usb0_rel(abs: &str) -> Option<String> {
    if abs == "/mnt/usb0" {
        Some(String::from("/"))
    } else {
        abs.strip_prefix("/mnt/usb0/")
            .map(|rest| format!("/{rest}"))
    }
}

struct HshUsbSectorIo {
    dev: core::cell::RefCell<libcanvas::block::BlockDevice>,
}

impl huesos_fat::BlockDevice for HshUsbSectorIo {
    fn read_sector(
        &self,
        sector: u32,
        buf: &mut [u8],
    ) -> core::result::Result<(), huesos_fat::DriverError> {
        if buf.len() != 512 {
            return Err(huesos_fat::DriverError::InvalidSector);
        }
        let mut dev = self
            .dev
            .try_borrow_mut()
            .map_err(|_| huesos_fat::DriverError::ReadError)?;
        dev.read_blocks(u64::from(sector), 1, buf)
            .map_err(|_| huesos_fat::DriverError::ReadError)
    }

    fn write_sector(
        &self,
        sector: u32,
        buf: &[u8],
    ) -> core::result::Result<(), huesos_fat::DriverError> {
        if buf.len() != 512 {
            return Err(huesos_fat::DriverError::InvalidSector);
        }
        let mut dev = self
            .dev
            .try_borrow_mut()
            .map_err(|_| huesos_fat::DriverError::WriteError)?;
        dev.write_blocks(u64::from(sector), 1, buf)
            .map_err(|_| huesos_fat::DriverError::WriteError)
    }

    fn sector_size(&self) -> u32 {
        512
    }
}

impl HshHost {
    fn open_usb_io(&self) -> Option<HshUsbSectorIo> {
        let reg = self.registry.as_ref()?;
        let dev = libcanvas::block::BlockDevice::open_usb(reg).ok()?;
        Some(HshUsbSectorIo {
            dev: core::cell::RefCell::new(dev),
        })
    }

    fn usb_stat_path(&self, rel: &str) -> Option<(HostPathKind, u64)> {
        let io = self.open_usb_io()?;
        let fs = huesos_fat::FatFileSystem::mount_auto(&io).ok()?;
        let info = fs.stat(rel).ok()?;
        let kind = if info.is_dir {
            HostPathKind::Dir
        } else {
            HostPathKind::File
        };
        Some((kind, if info.is_dir { 0 } else { u64::from(info.size) }))
    }

    fn usb_list_dir(&self, rel: &str) -> Vec<String> {
        let Some(io) = self.open_usb_io() else {
            return Vec::new();
        };
        let Ok(fs) = huesos_fat::FatFileSystem::mount_auto(&io) else {
            return Vec::new();
        };
        fs.list_dir(rel)
            .map(|items| items.into_iter().map(|e| e.name).collect())
            .unwrap_or_default()
    }

    fn usb_read_file(&self, rel: &str) -> Result<Vec<u8>, String> {
        let io = self
            .open_usb_io()
            .ok_or_else(|| String::from("redirect failed: /mnt/usb0 unavailable"))?;
        let fs = huesos_fat::FatFileSystem::mount_auto(&io)
            .map_err(|_| String::from("redirect failed: /mnt/usb0 mount error"))?;
        let sz = fs
            .file_size(rel)
            .map_err(|e| format!("stat '/mnt/usb0{rel}': {e:?}"))?
            .min(256 * 1024) as usize;
        let mut out = alloc::vec![0u8; sz];
        let n = fs
            .read_at(rel, 0, &mut out)
            .map_err(|e| format!("read '/mnt/usb0{rel}': {e:?}"))?;
        out.truncate(n);
        Ok(out)
    }

    fn usb_write_file(&self, rel: &str, data: &[u8], append: bool) -> Result<(), String> {
        let io = self
            .open_usb_io()
            .ok_or_else(|| String::from("redirect failed: /mnt/usb0 unavailable"))?;
        let fs = huesos_fat::FatFileSystem::mount_auto(&io)
            .map_err(|_| String::from("redirect failed: /mnt/usb0 mount error"))?;
        match fs.stat(rel) {
            Ok(info) if info.is_dir => return Err(format!("'/mnt/usb0{rel}': is a directory")),
            Ok(_) => {}
            Err(huesos_fat::DriverError::FileNotFound) => {
                fs.create_file(rel)
                    .map_err(|e| format!("create '/mnt/usb0{rel}': {e:?}"))?;
            }
            Err(e) => return Err(format!("stat '/mnt/usb0{rel}': {e:?}")),
        }
        let offset = if append {
            fs.file_size(rel).unwrap_or(0)
        } else {
            fs.truncate(rel, 0)
                .map_err(|e| format!("truncate '/mnt/usb0{rel}': {e:?}"))?;
            0
        };
        fs.write_at(rel, offset, data)
            .map_err(|e| format!("write '/mnt/usb0{rel}': {e:?}"))?;
        if let Ok(mut dev) = io.dev.try_borrow_mut() {
            let _ = dev.flush();
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlagValueKind {
    None,
    Data,
    Path,
    TarDir,
}

/// Classify flags whose following argument is a value, a path, or `-C <dir>`.
///
/// Per command, because the same letter means different things: `head -n 5`
/// takes a count while `sort -n` is a switch, and `grep -c` counts while
/// `head -c 16` takes bytes. Data values must not be resolved as paths
/// (`hexdump -n 128` used to become `-n /128`), while archive/directory flags
/// (`tar -cf out.tar`, `tar -C sub`) *are* paths that must resolve against `pwd`.
fn flag_value_kind(command: &str, flag: &str) -> FlagValueKind {
    match command {
        "hexdump" if matches!(flag, "-n" | "--length" | "-s" | "--skip") => FlagValueKind::Data,
        "du" if matches!(flag, "-d" | "--max-depth") => FlagValueKind::Data,
        "mkfs" if matches!(flag, "-s" | "--size" | "-p" | "--part" | "-t" | "--type") => {
            FlagValueKind::Data
        }
        "head" | "tail" if matches!(flag, "-n" | "--lines" | "-c" | "--bytes") => {
            FlagValueKind::Data
        }
        "sort" if matches!(flag, "-k" | "--key" | "-t" | "--field-separator") => {
            FlagValueKind::Data
        }
        "grep" if matches!(flag, "-e" | "--regexp" | "-m" | "--max-count") => FlagValueKind::Data,
        "hsh" if flag == "-c" => FlagValueKind::Data,
        "find" if matches!(flag, "-name" | "-type" | "-maxdepth" | "-iname") => FlagValueKind::Data,
        "fdisk" if matches!(flag, "--type" | "--size" | "--start" | "--end" | "--name") => {
            FlagValueKind::Data
        }
        "tar" => {
            if matches!(flag, "-C" | "--directory") {
                FlagValueKind::TarDir
            } else if flag.starts_with('-') && flag.ends_with('f') {
                FlagValueKind::Path
            } else {
                FlagValueKind::None
            }
        }
        _ => FlagValueKind::None,
    }
}

/// True when `word` is data for `command`, not a path.
fn is_data_word(command: &str, word: &str) -> bool {
    if is_number_or_size(word) {
        return true;
    }
    // Subcommands of the multi-command tools.
    let subcommands: &[&str] = match command {
        "fdisk" => &[
            "list", "inspect", "verify", "gpt-init", "add", "del", "resize",
        ],
        "hxfs" => &[
            "status", "stats", "scrub", "fsck", "snapshot", "snap", "sync", "gc", "list", "create",
            "delete",
        ],
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
