//! Process control: exit, yield, and spawning a child program.
//!
//! There is deliberately no `fork` and no `exec`. A program is launched by a
//! parent that hands it a bootstrap channel, and it leaves by exiting with a
//! status; [`Command`] is the standard-library face of that, and it never
//! discovers a program by name — it resolves the name inside the boot
//! filesystem it was given.
//!
//! # What a child inherits
//! Exactly what the parent passes: three standard streams (created as channel
//! pairs, so the parent can read the child's output), the capability mask in
//! [`Command::caps`], and any service channel the parent explicitly hands over
//! with [`Command::service`]. A child with no HxFS channel gets `AccessDenied`
//! from the filesystem, which is the intended shape of the security model: the
//! absence of a capability is not an error to be worked around, it is the
//! answer.

use alloc::string::String;
use alloc::vec::Vec;

use libcanvas::channel::Channel;
use libcanvas::process::{spawn_elf_from_vmo_with_caps, Process, SpawnCaps};
use libcanvas::ErrorCode;

use crate::bootfs::{BootFs, Entry};
use crate::error::{Error, ErrorKind, Result};
use crate::io::{Read, Write};
use crate::time::Duration;

/// Exit the process with `code`.
pub fn exit(code: i32) -> ! {
    libcanvas::process::exit(i64::from(code))
}

/// Give up the rest of the time slice.
pub fn yield_now() {
    libcanvas::process::yield_now();
}

/// The process' own identifier, as the kernel names it.
pub fn id() -> Result<u64> {
    let process = Process::current().map_err(Error::from)?;
    process.koid().map_err(Error::from)
}

/// How a child process finished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitStatus {
    code: i64,
}

impl ExitStatus {
    /// Wrap a raw kernel exit code.
    pub const fn from_code(code: i64) -> Self {
        Self { code }
    }

    /// The exit code, as the program passed it to `exit`.
    pub const fn code(&self) -> i32 {
        self.code as i32
    }

    /// The raw kernel code.
    pub const fn raw(&self) -> i64 {
        self.code
    }

    /// True when the program exited with 0.
    pub fn success(&self) -> bool {
        self.code == 0
    }
}

impl core::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "exit status: {}", self.code)
    }
}

/// A service channel to hand a child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Service {
    /// The filesystem service (`AT_HUESOS_HXFS_SERVICE`).
    HxfsService,
    /// An attenuated filesystem directory (`AT_HUESOS_HXFS_DIR`).
    HxfsDir,
    /// A block device (`AT_HUESOS_BLOCK_DEV`).
    BlockDevice,
    /// The driver registry (`AT_HUESOS_REGISTRY`).
    Registry,
}

/// Builder for a child process, modelled on `std::process::Command`.
pub struct Command {
    program: String,
    args: Vec<String>,
    caps_mask: u64,
    bootfs: Option<BootFs>,
    services: Vec<(Service, Channel)>,
    capture_stdout: bool,
    capture_stderr: bool,
    stdin_bytes: Option<Vec<u8>>,
}

impl Command {
    /// A command that will run `program` — `/bin/ls`, `/bin/ls.elf`, or a bare
    /// `ls`, which is looked up in `/bin`.
    pub fn new(program: &str) -> Self {
        Self {
            program: String::from(program),
            args: Vec::new(),
            caps_mask: crate::env::caps(),
            bootfs: None,
            services: Vec::new(),
            capture_stdout: true,
            capture_stderr: true,
            stdin_bytes: None,
        }
    }

    /// Append one argument.
    pub fn arg(mut self, arg: &str) -> Self {
        self.args.push(String::from(arg));
        self
    }

    /// Append several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for arg in args {
            self.args.push(String::from(arg.as_ref()));
        }
        self
    }

    /// Set the child's capability mask.
    ///
    /// The mask is intersected with the parent's by the loader, so asking for
    /// more than the parent holds grants exactly the parent's authority.
    pub fn caps(mut self, mask: u64) -> Self {
        self.caps_mask = mask;
        self
    }

    /// Set the child's capability mask in place.
    pub fn set_caps_mask(&mut self, mask: u64) -> &mut Self {
        self.caps_mask = mask;
        self
    }

    /// Resolve names against this boot filesystem instead of the process' own
    /// boot filesystem capability.
    pub fn bootfs(mut self, bootfs: BootFs) -> Self {
        self.bootfs = Some(bootfs);
        self
    }

    /// Hand the child a service channel.
    pub fn service(mut self, service: Service, channel: Channel) -> Self {
        self.services.push((service, channel));
        self
    }

    /// Capture the child's stdout (default) instead of discarding it.
    pub fn capture_stdout(mut self, enable: bool) -> Self {
        self.capture_stdout = enable;
        self
    }

    /// Capture the child's stderr (default) instead of discarding it.
    pub fn capture_stderr(mut self, enable: bool) -> Self {
        self.capture_stderr = enable;
        self
    }

    /// Feed `bytes` to the child's standard input.
    pub fn stdin_bytes(mut self, bytes: &[u8]) -> Self {
        self.stdin_bytes = Some(Vec::from(bytes));
        self
    }

    /// Start the child.
    pub fn spawn(self) -> Result<Child> {
        let bootfs = match self.bootfs {
            Some(bootfs) => bootfs,
            None => BootFs::from_capability().ok_or(Error::capability())?,
        };
        let entry: Entry = bootfs
            .resolve(&self.program)
            .cloned()
            .ok_or(Error::new(ErrorKind::NotFound))?;
        let lib_vmo = bootfs.duplicate_image()?;
        let elf_vmo = bootfs
            .image()
            .duplicate(libcanvas::rights::READ | libcanvas::rights::TRANSFER)
            .map_err(Error::from)?;

        let (stdin_read, stdin_write) = Channel::pair().map_err(Error::from)?;
        let (stdout_read, stdout_write) = Channel::pair().map_err(Error::from)?;
        let (stderr_read, stderr_write) = Channel::pair().map_err(Error::from)?;

        let mut argv: Vec<&str> = Vec::with_capacity(self.args.len() + 1);
        argv.push(entry.path.as_str());
        for arg in &self.args {
            argv.push(arg.as_str());
        }

        let mut caps = SpawnCaps::new();
        caps.args = &argv;
        caps.caps_mask = self.caps_mask;
        caps.stdin = Some(&stdin_read);
        caps.stdout = Some(&stdout_write);
        caps.stderr = Some(&stderr_write);
        let mut hxfs_dir: Option<&Channel> = None;
        let mut hxfs_service: Option<&Channel> = None;
        let mut block_dev: Option<&Channel> = None;
        let mut registry: Option<&Channel> = None;
        for (service, channel) in &self.services {
            match service {
                Service::HxfsService => hxfs_service = Some(channel),
                Service::HxfsDir => hxfs_dir = Some(channel),
                Service::BlockDevice => block_dev = Some(channel),
                Service::Registry => registry = Some(channel),
            }
        }
        caps.hxfs_dir = hxfs_dir;
        caps.hxfs_service = hxfs_service;
        caps.block_dev = block_dev;
        caps.registry = registry;

        let spawned = spawn_elf_from_vmo_with_caps(
            entry.path.as_str(),
            &elf_vmo,
            entry.offset,
            entry.length,
            &lib_vmo,
            &caps,
        );
        // The child holds its own copies of the endpoints it was given.
        drop(stdin_read);
        drop(stdout_write);
        drop(stderr_write);
        let (process, bootstrap) = spawned.map_err(Error::from)?;
        drop(bootstrap);
        let koid = process.koid().map_err(Error::from)?;
        Ok(Child {
            process,
            koid,
            stdin: Some(stdin_write),
            stdout: self.capture_stdout.then_some(stdout_read),
            stderr: self.capture_stderr.then_some(stderr_read),
            stdin_bytes: self.stdin_bytes,
        })
    }

    /// Run the child to completion and collect its output.
    pub fn output(mut self) -> Result<Output> {
        self.capture_stdout = true;
        self.capture_stderr = true;
        self.spawn()?.wait_with_output()
    }

    /// Run the child to completion and return its status.
    pub fn status(self) -> Result<ExitStatus> {
        self.spawn()?.wait()
    }
}

/// A running child process.
pub struct Child {
    process: Process,
    koid: u64,
    stdin: Option<Channel>,
    stdout: Option<Channel>,
    stderr: Option<Channel>,
    stdin_bytes: Option<Vec<u8>>,
}

impl Child {
    /// The child's stable kernel object ID (KOID), not its handle value.
    pub fn id(&self) -> u64 {
        self.koid
    }

    /// Write `data` to the child's standard input.
    pub fn write_stdin(&mut self, data: &[u8]) -> Result<()> {
        let channel = match self.stdin.as_ref() {
            Some(channel) => channel,
            None => return Err(Error::new(ErrorKind::InvalidInput)),
        };
        let mut cursor = 0;
        while cursor < data.len() {
            match channel.write(&data[cursor..]) {
                Ok(()) => {
                    // A channel write accepts the whole chunk or reports a full
                    // pipe; either way advance by what is left in this chunk.
                    cursor = data.len();
                }
                Err(ErrorCode::ShouldWait) => yield_now(),
                Err(error) => return Err(Error::from(error)),
            }
        }
        Ok(())
    }

    /// Close the child's standard input, so a reader sees end of input.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Wait for the child and return its exit status.
    pub fn wait(mut self) -> Result<ExitStatus> {
        if let Some(bytes) = self.stdin_bytes.take() {
            self.write_stdin(&bytes)?;
        }
        self.stdin = None;
        self.drain(None, None)?;
        let code = self.process.wait_exit().map_err(Error::from)?;
        Ok(ExitStatus::from_code(code))
    }

    /// Wait for the child, collecting everything it wrote.
    pub fn wait_with_output(mut self) -> Result<Output> {
        if let Some(bytes) = self.stdin_bytes.take() {
            self.write_stdin(&bytes)?;
        }
        self.stdin = None;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        self.drain(Some(&mut stdout), Some(&mut stderr))?;
        let code = self.process.wait_exit().map_err(Error::from)?;
        Ok(Output {
            status: ExitStatus::from_code(code),
            stdout,
            stderr,
        })
    }

    /// Read both pipes until they close, parking on `wait_any` while empty.
    fn drain(
        &mut self,
        mut stdout: Option<&mut Vec<u8>>,
        mut stderr: Option<&mut Vec<u8>>,
    ) -> Result<()> {
        let mut chunk = [0u8; 4096];
        let mut out_open = self.stdout.is_some();
        let mut err_open = self.stderr.is_some();
        while out_open || err_open {
            let mut progressed = false;
            if out_open {
                let channel = match self.stdout.as_ref() {
                    Some(channel) => channel,
                    None => {
                        out_open = false;
                        continue;
                    }
                };
                match channel.read_into(&mut chunk) {
                    Ok(n) => {
                        progressed = true;
                        if let Some(sink) = stdout.as_deref_mut() {
                            sink.extend_from_slice(&chunk[..n]);
                        }
                    }
                    Err(ErrorCode::PeerClosed) => out_open = false,
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                    Err(error) => return Err(Error::from(error)),
                }
            }
            if err_open {
                let channel = match self.stderr.as_ref() {
                    Some(channel) => channel,
                    None => {
                        err_open = false;
                        continue;
                    }
                };
                match channel.read_into(&mut chunk) {
                    Ok(n) => {
                        progressed = true;
                        if let Some(sink) = stderr.as_deref_mut() {
                            sink.extend_from_slice(&chunk[..n]);
                        }
                    }
                    Err(ErrorCode::PeerClosed) => err_open = false,
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
                    Err(error) => return Err(Error::from(error)),
                }
            }
            if !progressed && (out_open || err_open) {
                let mut items = [libcanvas::WaitItem::new(
                    self.process.handle().raw(),
                    libcanvas::Signals::SIGNALED,
                    0,
                ); 3];
                let mut count = 1usize;
                if out_open {
                    if let Some(ch) = self.stdout.as_ref() {
                        items[count] = libcanvas::WaitItem::new(
                            ch.handle().raw(),
                            libcanvas::Signals::READABLE | libcanvas::Signals::PEER_CLOSED,
                            1,
                        );
                        count += 1;
                    }
                }
                if err_open {
                    if let Some(ch) = self.stderr.as_ref() {
                        items[count] = libcanvas::WaitItem::new(
                            ch.handle().raw(),
                            libcanvas::Signals::READABLE | libcanvas::Signals::PEER_CLOSED,
                            2,
                        );
                        count += 1;
                    }
                }
                if let Ok(outcome) = libcanvas::wait_any(&items[..count], 5) {
                    if outcome.satisfied().iter().any(|r| {
                        r.key == 0 && (r.active_signals & libcanvas::Signals::SIGNALED.bits()) != 0
                    }) {
                        if let Some(ch) = self.stdout.as_ref() {
                            while let Ok(n) = ch.read_into(&mut chunk) {
                                if n == 0 {
                                    break;
                                }
                                if let Some(sink) = stdout.as_deref_mut() {
                                    sink.extend_from_slice(&chunk[..n]);
                                }
                            }
                        }
                        if let Some(ch) = self.stderr.as_ref() {
                            while let Ok(n) = ch.read_into(&mut chunk) {
                                if n == 0 {
                                    break;
                                }
                                if let Some(sink) = stderr.as_deref_mut() {
                                    sink.extend_from_slice(&chunk[..n]);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}

impl Write for Child {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.write_stdin(data)?;
        Ok(data.len())
    }
}

impl Read for Child {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        let channel = match self.stdout.as_ref() {
            Some(channel) => channel,
            None => return Ok(0),
        };
        match channel.read_into(out) {
            Ok(n) => Ok(n),
            Err(ErrorCode::PeerClosed) => Ok(0),
            Err(error) => Err(Error::from(error)),
        }
    }
}

/// The captured result of a child process.
pub struct Output {
    /// How the child finished.
    pub status: ExitStatus,
    /// Everything it wrote to standard output.
    pub stdout: Vec<u8>,
    /// Everything it wrote to standard error.
    pub stderr: Vec<u8>,
}

impl Output {
    /// The captured stdout as text, if it is valid UTF-8.
    pub fn stdout_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.stdout).ok()
    }

    /// The captured stderr as text, if it is valid UTF-8.
    pub fn stderr_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.stderr).ok()
    }
}

/// Run `program` with `args` and collect its output.
pub fn run(program: &str, args: &[&str]) -> Result<Output> {
    Command::new(program).args(args.to_vec()).output()
}

/// Give up the CPU for `ticks` scheduler ticks.
pub fn yield_for(ticks: u64) {
    for _ in 0..ticks {
        yield_now();
    }
}

/// Wait for a child process to exit, polling with a bounded budget.
///
/// `timeout` is measured on the monotonic clock; `None` waits forever.
pub fn wait_for(process: &Process, timeout: Option<Duration>) -> Result<Option<ExitStatus>> {
    let deadline = timeout.map(|limit| crate::time::Instant::now() + limit);
    loop {
        match process.poll_exit() {
            Ok(Some(code)) => return Ok(Some(ExitStatus::from_code(code))),
            Ok(None) => {}
            Err(error) => return Err(Error::from(error)),
        }
        if let Some(deadline) = deadline {
            if crate::time::Instant::now() >= deadline {
                return Ok(None);
            }
        }
        yield_now();
    }
}
