//! `hsh` host implementation for HuesOS `terminal`.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use huesos_abi::auxv::caps_mask;
use huesos_abi::hxfs::rights as hxfs_rights;
use huesos_hsh::{CapsSpec, ExecOutcome, FbAccess, HxfsAccess, ShellHost, Table, Value};
use libcanvas::process::{spawn_elf_from_vmo_with_caps, SpawnCaps};
use libcanvas::{Channel, ErrorCode, Handle, Hxfs, Vmo};

const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";

/// Special UI actions that must run directly inside `Shell` (DOOM, Snake, Shutdown, Font).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingUiAction {
    Doom,
    Snake { hard: bool },
    Shutdown,
    Font(FontChoice),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FontChoice {
    Cozette,
    Tty,
    Compact,
}

/// Capabilities & services owned by the terminal shell host.
pub struct TerminalHost {
    pub registry: Channel,
    pub filesystem: Option<Channel>,
    pub hxfs: Option<Hxfs>,
    pub bootfs: Option<Vmo>,
    pub frame_draw: Option<Handle>,
    pub pwd: String,
    pub pending_ui: Option<PendingUiAction>,
}

impl TerminalHost {
    pub fn new(
        registry: Channel,
        filesystem: Option<Channel>,
        bootfs: Option<Vmo>,
        frame_draw: Option<Handle>,
    ) -> Self {
        let mut host = Self {
            registry,
            filesystem,
            hxfs: None,
            bootfs,
            frame_draw,
            pwd: String::from("/"),
            pending_ui: None,
        };
        host.try_connect_hxfs();
        host
    }

    pub fn try_connect_hxfs(&mut self) {
        if self.hxfs.is_some() {
            return;
        }
        if self.registry.write(b"open:hxfs").is_err() {
            return;
        }
        let mut buf = [0u8; 64];
        for _ in 0..40 {
            match self.registry.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:channel" => {
                    self.hxfs = Some(Hxfs::from_channel(Channel::from_handle(handle)));
                    return;
                }
                Ok((n, None)) if &buf[..n] == b"err:hxfs:unavailable" => return,
                Ok((_n, Some(handle))) => drop(handle),
                Ok((_n, None)) => return,
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    libcanvas::process::yield_now();
                }
                Err(_) => return,
            }
        }
    }

    fn open_hxfs_channel_fresh(&self) -> Option<Channel> {
        self.registry.write(b"open:hxfs").ok()?;
        let mut buf = [0u8; 64];
        for _ in 0..50 {
            match self.registry.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:hxfs:channel" => {
                    return Some(Channel::from_handle(handle));
                }
                Ok((n, None)) if &buf[..n] == b"err:hxfs:unavailable" => return None,
                Ok((_n, Some(handle))) => drop(handle),
                Ok((_n, None)) => return None,
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    libcanvas::process::yield_now();
                }
                Err(_) => return None,
            }
        }
        None
    }

    fn open_block_nvme_fresh(&self) -> Option<Channel> {
        self.registry.write(b"open:block:nvme").ok()?;
        let mut buf = [0u8; 64];
        for _ in 0..50 {
            match self.registry.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"service:block:nvme:channel" => {
                    return Some(Channel::from_handle(handle));
                }
                Ok((n, None)) if &buf[..n] == b"err:block:nvme-unavailable" => return None,
                Ok((_n, Some(handle))) => drop(handle),
                Ok((_n, None)) => return None,
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    libcanvas::process::yield_now();
                }
                Err(_) => return None,
            }
        }
        None
    }

    fn query_registry_tsv(&self, req: &[u8]) -> Result<Table, String> {
        self.registry
            .write(req)
            .map_err(|e| format!("registry write failed: {}", e.as_str()))?;
        let mut buf = [0u8; 2048];
        for _ in 0..80 {
            match self.registry.read_into(&mut buf) {
                Ok(n) => {
                    let s = core::str::from_utf8(&buf[..n])
                        .map_err(|_| String::from("invalid UTF-8 from registry"))?;
                    return Table::from_tsv(s)
                        .ok_or_else(|| String::from("malformed TSV from registry"));
                }
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                    libcanvas::process::yield_now();
                }
                Err(e) => return Err(format!("registry read failed: {}", e.as_str())),
            }
        }
        Err(String::from("registry query timed out"))
    }

    /// List `/bin/*.elf` names from BOOTFS (for Tab completion).
    pub fn list_bootfs_bins(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (path, _off, _len) in self.iter_bootfs_entries() {
            if let Some(rest) = path.strip_prefix("/bin/") {
                out.push(String::from(rest));
                if let Some(short) = rest.strip_suffix(".elf") {
                    out.push(String::from(short));
                }
            }
        }
        out
    }

    /// List matching entries under `prefix` from HxFS and BOOTFS (for Tab completion).
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

    fn iter_bootfs_entries(&self) -> Vec<(String, u64, u64)> {
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

    fn normalize_path(&self, raw: &str) -> String {
        if raw.is_empty() {
            return self.pwd.clone();
        }
        if raw.starts_with('/') {
            String::from(raw)
        } else if self.pwd == "/" {
            format!("/{raw}")
        } else {
            format!("{}/{raw}", self.pwd)
        }
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

        // 1. Check HxFS first
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

        // 2. Fallback to BOOTFS VMO
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
        let Some(lib_vmo) = self.bootfs.as_ref() else {
            return ExecOutcome::err(1, "no BOOTFS VMO available for dynamic linker");
        };
        let lib_vmo_dup = match lib_vmo.duplicate(
            libcanvas::rights::READ | libcanvas::rights::TRANSFER | libcanvas::rights::DUPLICATE,
        ) {
            Ok(v) => v,
            Err(e) => return ExecOutcome::err(1, format!("bootfs dup: {}", e.as_str())),
        };

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

        // Attenuate capabilities per `@caps(...)`.
        self.try_connect_hxfs();
        let mut dir_holder: Option<libcanvas::HxfsDirectory> = None;
        let mut svc_holder: Option<Channel> = None;
        let mut blk_holder: Option<Channel> = None;

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
        } else {
            if let Some(hxfs) = self.hxfs.as_ref() {
                if let Ok(d) = hxfs.root_with_rights(hxfs_rights::ALL) {
                    dir_holder = Some(d);
                }
            }
            svc_holder = self.open_hxfs_channel_fresh();
            blk_holder = self.open_block_nvme_fresh();
        }

        let fb_allowed = caps.is_none_or(|c| c.fb == FbAccess::ReadOnly);
        let frame_draw = if fb_allowed {
            self.frame_draw.as_ref()
        } else {
            None
        };

        let mut argv_strs: Vec<&str> = Vec::with_capacity(1 + args.len());
        argv_strs.push(&resolved);
        for a in args {
            argv_strs.push(a.as_str());
        }

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

        let spawned =
            spawn_elf_from_vmo_with_caps(&resolved, &elf_vmo, off, len, &lib_vmo_dup, &spawn_caps);
        drop(stdin_r);
        drop(stdout_w);
        drop(stderr_w);
        drop(dir_holder);
        drop(svc_holder);
        drop(blk_holder);
        drop(elf_vmo);
        drop(lib_vmo_dup);

        let (process, _child_bootstrap) = match spawned {
            Ok(pair) => pair,
            Err(e) => {
                return ExecOutcome::err(1, format!("spawn '{resolved}' failed: {}", e.as_str()));
            }
        };
        let pid = u64::from(process.handle().raw());

        // Stream stdin chunks and close `stdin_w` so child sees `PeerClosed` EOF.
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

        // Drain stdout & stderr until both peers close.
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut out_open = true;
        let mut err_open = true;
        let mut chunk = [0u8; 4096];
        while out_open || err_open {
            let mut progressed = false;
            if out_open {
                match stdout_r.read_into(&mut chunk) {
                    Ok(n) => {
                        stdout_bytes.extend_from_slice(&chunk[..n]);
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
                        progressed = true;
                    }
                    Err(ErrorCode::PeerClosed) => err_open = false,
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                    Err(_) => err_open = false,
                }
            }
            if !progressed {
                libcanvas::process::yield_now();
            }
        }

        let exit_code = process.wait_exit().unwrap_or(-1) as i32;
        let out_str = String::from_utf8_lossy(&stdout_bytes).into_owned();
        let err_str = String::from_utf8_lossy(&stderr_bytes).into_owned();

        let output = if exit_code == 0 {
            if let Some(tbl) = Table::from_tsv(&out_str) {
                Value::Table(tbl)
            } else if err_str.is_empty() {
                Value::Text(out_str.trim_end_matches('\n').into())
            } else {
                Value::Text(format!("{out_str}{err_str}").trim_end_matches('\n').into())
            }
        } else if !err_str.is_empty() {
            Value::Text(err_str.trim_end_matches('\n').into())
        } else {
            Value::Text(out_str.trim_end_matches('\n').into())
        };

        ExecOutcome {
            status: exit_code,
            output,
            clear_screen: false,
            exit_requested: false,
            child_pid: Some(pid),
        }
    }

    fn cmd_ls(&mut self, path_arg: Option<&str>) -> ExecOutcome {
        let path = self.normalize_path(path_arg.unwrap_or(""));
        let mut tbl = Table::new(vec![
            String::from("name"),
            String::from("type"),
            String::from("size"),
            String::from("source"),
        ]);

        // 1. Check HxFS directory
        self.try_connect_hxfs();
        let mut found_any = false;
        if let Some(hxfs) = self.hxfs.as_ref() {
            if let Ok(dir) = hxfs.open_dir(&path) {
                found_any = true;
                let mut raw = [0u8; 4096];
                if let Ok(bytes) = dir.list(&mut raw) {
                    if let Ok(text) = core::str::from_utf8(bytes) {
                        for line in text.lines() {
                            let mut parts = line.split_whitespace();
                            let Some(name) = parts.next() else {
                                continue;
                            };
                            let kind = parts.next().unwrap_or("entry");
                            let size = parts.next().unwrap_or("-");
                            tbl.rows.push(vec![
                                String::from(name),
                                String::from(kind),
                                String::from(size),
                                String::from("hxfs"),
                            ]);
                        }
                    }
                }
            }
        }

        // 2. Also list matching BOOTFS entries
        let prefix = if path == "/" {
            String::from("/")
        } else {
            format!("{path}/")
        };
        let mut seen_dirs = Vec::new();
        for (bpath, _off, blen) in self.iter_bootfs_entries() {
            if let Some(rest) = bpath.strip_prefix(&prefix) {
                found_any = true;
                if let Some((dir_name, _)) = rest.split_once('/') {
                    let dname = String::from(dir_name);
                    if !seen_dirs.contains(&dname) {
                        seen_dirs.push(dname.clone());
                        tbl.rows.push(vec![
                            dname,
                            String::from("dir"),
                            String::from("-"),
                            String::from("bootfs"),
                        ]);
                    }
                } else if !rest.is_empty() {
                    tbl.rows.push(vec![
                        String::from(rest),
                        String::from("file"),
                        format!("{blen}"),
                        String::from("bootfs"),
                    ]);
                }
            }
        }

        if !found_any {
            if let Some(fs) = self.filesystem.as_ref() {
                if fs.write(format!("LIST {path}").as_bytes()).is_ok() {
                    let mut buf = [0u8; 2048];
                    if let Ok(n) = fs.read_into_blocking(&mut buf) {
                        if let Ok(s) = core::str::from_utf8(&buf[..n]) {
                            return ExecOutcome::ok_text(s.trim_end_matches('\n'));
                        }
                    }
                }
            }
            return ExecOutcome::err(1, format!("ls: '{path}' not found"));
        }

        ExecOutcome::ok(Value::Table(tbl))
    }

    fn cmd_cat(&mut self, path_arg: &str) -> ExecOutcome {
        let path = self.normalize_path(path_arg);
        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            if let Ok(file) = hxfs.open_file(&path) {
                if let Ok(vmo) = file.read_into_vmo() {
                    let size = file.size().unwrap_or(0).min(32 * 1024) as usize;
                    let mut buf = vec![0u8; size];
                    if vmo.read(0, &mut buf).is_ok() {
                        return ExecOutcome::ok_text(
                            String::from_utf8_lossy(&buf).trim_end_matches('\n'),
                        );
                    }
                }
            }
        }
        if let Some(vmo) = self.bootfs.as_ref() {
            for (bpath, off, len) in self.iter_bootfs_entries() {
                if bpath == path {
                    let take = len.min(32 * 1024) as usize;
                    let mut buf = vec![0u8; take];
                    if vmo.read(off, &mut buf) == Ok(take) {
                        return ExecOutcome::ok_text(
                            String::from_utf8_lossy(&buf).trim_end_matches('\n'),
                        );
                    }
                }
            }
        }
        ExecOutcome::err(1, format!("cat: '{path}' not found"))
    }

    fn cmd_stat(&mut self, path_arg: &str) -> ExecOutcome {
        let path = self.normalize_path(path_arg);
        self.try_connect_hxfs();
        if let Some(hxfs) = self.hxfs.as_ref() {
            if let Ok(file) = hxfs.open_file(&path) {
                let sz = file.size().unwrap_or(0);
                return ExecOutcome::ok_text(format!(
                    "path={path} source=hxfs type=file size={sz}"
                ));
            }
            if hxfs.open_dir(&path).is_ok() {
                return ExecOutcome::ok_text(format!("path={path} source=hxfs type=dir"));
            }
        }
        for (bpath, off, len) in self.iter_bootfs_entries() {
            if bpath == path {
                return ExecOutcome::ok_text(format!(
                    "path={path} source=bootfs type=file size={len} offset={off}"
                ));
            }
        }
        ExecOutcome::err(1, format!("stat: '{path}' not found"))
    }

    fn cmd_caps(&mut self) -> ExecOutcome {
        self.try_connect_hxfs();
        let mut tbl = Table::new(vec![
            String::from("capability"),
            String::from("state"),
            String::from("detail"),
        ]);
        tbl.rows.push(vec![
            String::from("hxfs"),
            String::from(if self.hxfs.is_some() { "rw" } else { "offline" }),
            String::from(if self.hxfs.is_some() {
                "HxFS v7 mounted"
            } else {
                "no mounted volume"
            }),
        ]);
        tbl.rows.push(vec![
            String::from("bootfs"),
            String::from(if self.bootfs.is_some() { "ro" } else { "none" }),
            String::from("HBOOTFS1 VMO"),
        ]);
        tbl.rows.push(vec![
            String::from("fb"),
            String::from(if self.frame_draw.is_some() {
                "ro"
            } else {
                "none"
            }),
            String::from("FrameDraw resource"),
        ]);
        tbl.rows.push(vec![
            String::from("registry"),
            String::from("rw"),
            String::from("DriverManager service registry"),
        ]);
        ExecOutcome::ok(Value::Table(tbl))
    }
}

impl ShellHost for TerminalHost {
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
            "help" => ExecOutcome::ok_text(concat!(
                "hsh builtins & pipelines:\n",
                "  help | cls | clear | echo | pwd | cd <dir> | whoami | about | drivers\n",
                "  ls [path] | cat <path> | stat <path> | touch <p> | mkdir <p> | write <p> <txt> | rm <p> | mv <a b>\n",
                "  pci | acpi | ps | caps | fdisk <subcmd>\n",
                "  pipes: | where <col> <op> <val> | select <cols> | sort [--desc] [col] | head [n] | tail [n] | count | grep <pat>\n",
                "  lang:  let x = ...; if ... { ... } else { ... }; for x in [...] { ... }; fn f(a) { ... }; alias a = \"...\"\n",
                "  caps:  @caps(hxfs=none|ro|rw, bootfs=ro|none, fb=none|ro, dir=/sub:ro) <cmd>\n",
                "  apps:  doom | snake [hard] | font <cozette|tty|compact> | shutdown"
            )),
            "pwd" => ExecOutcome::ok_text(self.pwd.clone()),
            "cd" => {
                let next = self.normalize_path(args.first().map(String::as_str).unwrap_or("/"));
                self.pwd = next;
                ExecOutcome::ok(Value::Empty)
            }
            "whoami" => ExecOutcome::ok_text("huesos:cap-user"),
            "about" => ExecOutcome::ok_text(
                "HuesOS Terminal (hsh v1: Plan9 rc + Rust + Nushell tables + Fish UX + @caps)",
            ),
            "drivers" => ExecOutcome::ok_text(
                "DriverManager: userspace supervisor (input, nvme, hxfs, acpi, pci)",
            ),
            "caps" => self.cmd_caps(),
            "pci" => match self.query_registry_tsv(b"query:pci") {
                Ok(t) => ExecOutcome::ok(Value::Table(t)),
                Err(e) => ExecOutcome::err(1, e),
            },
            "acpi" => match self.query_registry_tsv(b"query:acpi") {
                Ok(t) => ExecOutcome::ok(Value::Table(t)),
                Err(e) => ExecOutcome::err(1, e),
            },
            "ps" => match self.query_registry_tsv(b"query:ps") {
                Ok(t) => ExecOutcome::ok(Value::Table(t)),
                Err(e) => ExecOutcome::err(1, e),
            },
            "ls" => self.cmd_ls(args.first().map(String::as_str)),
            "cat" => match args.first() {
                Some(p) => self.cmd_cat(p),
                None => ExecOutcome::err(1, "usage: cat <path>"),
            },
            "stat" => match args.first() {
                Some(p) => self.cmd_stat(p),
                None => ExecOutcome::err(1, "usage: stat <path>"),
            },
            "touch" => {
                let Some(p) = args.first() else {
                    return ExecOutcome::err(1, "usage: touch <path>");
                };
                let path = self.normalize_path(p);
                self.try_connect_hxfs();
                let Some(hxfs) = self.hxfs.as_ref() else {
                    return ExecOutcome::err(1, "hxfs unavailable");
                };
                match hxfs.create_file(&path) {
                    Ok(_) => ExecOutcome::ok(Value::Empty),
                    Err(e) => ExecOutcome::err(1, format!("touch '{path}': {}", e.as_str())),
                }
            }
            "mkdir" => {
                let Some(p) = args.first() else {
                    return ExecOutcome::err(1, "usage: mkdir <path>");
                };
                let path = self.normalize_path(p);
                self.try_connect_hxfs();
                let Some(hxfs) = self.hxfs.as_ref() else {
                    return ExecOutcome::err(1, "hxfs unavailable");
                };
                match hxfs.mkdir(&path) {
                    Ok(_) => ExecOutcome::ok(Value::Empty),
                    Err(e) => ExecOutcome::err(1, format!("mkdir '{path}': {}", e.as_str())),
                }
            }
            "write" => {
                if args.len() < 2 {
                    return ExecOutcome::err(1, "usage: write <path> <text...>");
                }
                let path = self.normalize_path(&args[0]);
                let mut payload = args[1..].join(" ");
                payload.push('\n');
                match self.write_file(&path, payload.as_bytes(), false) {
                    Ok(()) => ExecOutcome::ok(Value::Empty),
                    Err(e) => ExecOutcome::err(1, e),
                }
            }
            "rm" => {
                let Some(p) = args.first() else {
                    return ExecOutcome::err(1, "usage: rm <path>");
                };
                let path = self.normalize_path(p);
                self.try_connect_hxfs();
                let Some(hxfs) = self.hxfs.as_ref() else {
                    return ExecOutcome::err(1, "hxfs unavailable");
                };
                match hxfs.unlink(&path) {
                    Ok(()) => ExecOutcome::ok(Value::Empty),
                    Err(e) => ExecOutcome::err(1, format!("rm '{path}': {}", e.as_str())),
                }
            }
            "mv" => {
                if args.len() < 2 {
                    return ExecOutcome::err(1, "usage: mv <from> <to>");
                }
                let from = self.normalize_path(&args[0]);
                let to = self.normalize_path(&args[1]);
                self.try_connect_hxfs();
                let Some(hxfs) = self.hxfs.as_ref() else {
                    return ExecOutcome::err(1, "hxfs unavailable");
                };
                match hxfs.rename(&from, &to) {
                    Ok(()) => ExecOutcome::ok(Value::Empty),
                    Err(e) => ExecOutcome::err(1, format!("mv: {}", e.as_str())),
                }
            }
            "hxfs" => match args.first().map(String::as_str) {
                Some("checkpoint") => {
                    self.try_connect_hxfs();
                    let Some(hxfs) = self.hxfs.as_ref() else {
                        return ExecOutcome::err(1, "hxfs unavailable");
                    };
                    match hxfs.checkpoint() {
                        Ok(()) => ExecOutcome::ok_text("hxfs checkpoint published"),
                        Err(e) => ExecOutcome::err(1, format!("checkpoint: {}", e.as_str())),
                    }
                }
                _ => self.cmd_ls(args.get(1).map(String::as_str)),
            },
            "font" => match args.first().map(String::as_str) {
                Some("cozette") => {
                    self.pending_ui = Some(PendingUiAction::Font(FontChoice::Cozette));
                    ExecOutcome::ok_text("font set to cozette 6x13")
                }
                Some("tty") => {
                    self.pending_ui = Some(PendingUiAction::Font(FontChoice::Tty));
                    ExecOutcome::ok_text("font set to tty 8x16")
                }
                Some("compact") => {
                    self.pending_ui = Some(PendingUiAction::Font(FontChoice::Compact));
                    ExecOutcome::ok_text("font set to compact 8x8")
                }
                _ => ExecOutcome::err(1, "usage: font <cozette|tty|compact>"),
            },
            "doom" => {
                self.pending_ui = Some(PendingUiAction::Doom);
                ExecOutcome::ok(Value::Empty)
            }
            "snake" => {
                let hard = args.first().is_some_and(|a| a == "hard");
                self.pending_ui = Some(PendingUiAction::Snake { hard });
                ExecOutcome::ok(Value::Empty)
            }
            "shutdown" => {
                self.pending_ui = Some(PendingUiAction::Shutdown);
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
