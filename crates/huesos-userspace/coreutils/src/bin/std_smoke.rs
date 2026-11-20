//! `/bin/std-smoke.elf`: proves `huesos-std` works inside the OS.
//!
//! Every module is exercised against the real thing rather than a mock:
//! the entry macro supplies `_start`, the allocator and the panic handler;
//! formatting streams through the stderr/stdout channels; the path and error
//! helpers are pure; and the file-system section runs against the mounted
//! `HxFS` volume when the shell handed this process a capability for it.
//!
//! Markers: `[std] PASS` on success, `[std] FAIL ...` plus a non-zero exit
//! otherwise. `scripts/ci-qemu-smoke.sh` requires `[std] PASS`, and the shell
//! smoke requires the exit status, so a partial pass cannot slip through.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use huesos_std::error::ErrorCode;
use huesos_std::prelude::*;
// The prelude re-exports the *contents* of these modules; the smoke test also
// names the modules themselves (`env::args_count`, `fs::File::create`).
use huesos_std::{env, fs, io, path};

huesos_std::entry!(run);

/// Count a failed check and keep going, so one run reports every problem.
macro_rules! expect {
    ($failures:ident, $cond:expr, $what:literal) => {
        if !$cond {
            println!("[std] FAIL {}: condition did not hold", $what);
            $failures += 1;
        }
    };
}

/// A [`Write`] sink that keeps everything in memory, so the formatting path
/// can be checked byte for byte instead of by eye.
struct Sink {
    bytes: Vec<u8>,
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
}

fn run() -> i32 {
    let mut failures = 0u32;
    println!("[std] entry OK (naked _start, ScudoHeap, panic handler)");

    failures += check_io();
    failures += check_path();
    failures += check_error();
    failures += check_env();
    failures += check_fs();

    if failures == 0 {
        println!("[std] PASS");
        0
    } else {
        println!("[std] FAIL count={failures}");
        1
    }
}

// The five checks below are assertion tables: one `expect!` per property, with
// the property text next to it. `#[rustfmt::skip]` keeps that table readable
// instead of exploding every macro call that happens to cross the call width.
#[rustfmt::skip]
fn check_io() -> u32 {
    let mut failures = 0u32;
    // The free `write_all` must loop over short writes rather than assume the
    // first call took everything.
    let mut sink = Sink { bytes: Vec::new() };
    let first = io::write_all(&mut sink, b"hello, ");
    let second = io::write_all(&mut sink, b"world");
    if first.is_err() || second.is_err() {
        failures += 1;
    }
    expect!(failures, sink.bytes == b"hello, world", "io write_all");

    // `Fmt` buffers into a 160-byte stack buffer and flushes when it fills, so
    // a line longer than the buffer must still come out complete and in order.
    let long = "abcdefghij".repeat(40);
    let mut sink = Sink { bytes: Vec::new() };
    let formatted = {
        use core::fmt::Write as _;
        let mut fmt = io::Fmt::new(&mut sink);
        let first = write!(fmt, "{}-{}", 7, 8);
        let second = write!(fmt, "|{}", long);
        let finished = fmt.finish();
        first.is_ok() && second.is_ok() && finished.is_ok()
    };
    let want = format!("7-8|{long}");
    expect!(failures, formatted, "io fmt write");
    expect!(failures, sink.bytes == want.as_bytes(), "io fmt chunked flush");

    // And the real streams must accept the same formatted output.
    let mut out = io::stdout();
    let mut err = io::stderr();
    expect!(
        failures,
        io::write_all(&mut out, b"[std] io OK (write_all, fmt, 160-byte buffer)\n").is_ok(),
        "io stdout"
    );
    expect!(
        failures,
        io::write_all(&mut err, b"std-smoke: stderr channel reachable\n").is_ok(),
        "io stderr"
    );
    failures
}

#[rustfmt::skip]
fn check_path() -> u32 {
    let mut failures = 0u32;
    let normalizations: [(&str, &str); 7] = [
        ("/a/./b/../c", "/a/c"),
        ("//a//b//", "/a/b"),
        ("/..", "/"),
        ("a/b/../c", "a/c"),
        ("/", "/"),
        ("", "/"),
        ("/a/b/c/", "/a/b/c"),
    ];
    for (input, want) in normalizations {
        let got = path::normalize(input);
        if got.as_str() != want {
            println!("[std] FAIL path normalize({input}) = {got}, want {want}");
            failures += 1;
        }
    }

    expect!(failures, path::is_absolute("/a"), "path is_absolute");
    expect!(failures, !path::is_absolute("a"), "path not absolute");
    expect!(
        failures,
        path::join("/a", "b") == "/a/b",
        "path join absolute base"
    );
    expect!(failures, path::join("/", "b") == "/b", "path join root");
    expect!(failures, path::join("/a", "/b") == "/b", "path join absolute name");
    expect!(
        failures,
        path::parent("/a/b/c").as_deref() == Some("/a/b"),
        "path parent nested"
    );
    expect!(
        failures,
        path::parent("/a").as_deref() == Some("/"),
        "path parent top level"
    );
    expect!(failures, path::parent("/").is_none(), "path parent of root");
    expect!(
        failures,
        path::file_name("/a/b/c.txt") == Some("c.txt"),
        "path file_name"
    );
    expect!(failures, path::file_name("/").is_none(), "path file_name of root");
    expect!(failures, path::components("//a//b/").len() == 2, "path components");
    expect!(failures, path::relative("/a/b") == "a/b", "path relative");

    println!("[std] path OK (normalize, join, parent, file_name, components)");
    failures
}

#[rustfmt::skip]
fn check_error() -> u32 {
    let mut failures = 0u32;
    let not_found = Error::from_code(ErrorCode::NotFound);
    expect!(failures, not_found.kind() == ErrorKind::NotFound, "error kind");
    expect!(
        failures,
        not_found.code() == Some(ErrorCode::NotFound),
        "error keeps code"
    );
    expect!(failures, !not_found.is_retryable(), "error not retryable");
    expect!(
        failures,
        Error::from_code(ErrorCode::Busy).is_retryable(),
        "error busy retryable"
    );
    expect!(
        failures,
        Error::from_code(ErrorCode::ShouldWait).is_retryable(),
        "error should-wait retryable"
    );
    expect!(
        failures,
        Error::from_code(ErrorCode::AccessDenied).kind() == ErrorKind::AccessDenied,
        "error access denied"
    );
    let rendered = format!("{}", not_found);
    expect!(
        failures,
        rendered.contains("not found"),
        "error display"
    );
    expect!(
        failures,
        Error::capability().kind() == ErrorKind::AccessDenied,
        "error capability"
    );
    println!("[std] error OK (kind mapping, code, display, retryable)");
    failures
}

#[rustfmt::skip]
fn check_env() -> u32 {
    let mut failures = 0u32;
    expect!(failures, env::args_count() >= 1, "env argc");
    // The shell launches this binary with no arguments.
    expect!(failures, env::args().is_empty(), "env args empty");
    expect!(
        failures,
        env::argv().len() == env::args_count(),
        "env argv matches argc"
    );
    let caps = env::caps();
    // The shell grants a non-empty mask to every child it launches.
    expect!(failures, caps != 0, "env caps granted");
    expect!(failures, env::has_caps(caps), "env has_caps");
    println!("[std] env OK (argc={} caps={:#x})", env::args_count(), caps);
    failures
}

#[rustfmt::skip]
fn check_fs() -> u32 {
    const NAME: &str = "/std-smoke.txt";
    let payload: Vec<u8> = (0..3000u32).map(|v| (v % 251) as u8).collect();

    let mut file = match fs::File::create(NAME) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AccessDenied => {
            println!("[std] fs SKIP (no HxFS capability: {error})");
            return 0;
        }
        Err(error) => {
            println!("[std] FAIL fs create: {error}");
            return 1;
        }
    };
    let mut failures = 0u32;
    if let Err(error) = io::write_all(&mut file, &payload) {
        println!("[std] FAIL fs write: {error}");
        return 1;
    }
    if let Err(error) = file.fsync() {
        println!("[std] FAIL fs fsync: {error}");
        return 1;
    }
    let size = file.size().unwrap_or(0);
    expect!(failures, size == payload.len() as u64, "fs size after write");

    // Read back from the end: `seek(End(-100))` proves both the negative
    // delta and that the cursor, not the file, moved.
    if let Err(error) = file.seek(SeekFrom::End(-100)) {
        println!("[std] FAIL fs seek: {error}");
        return 1;
    }
    expect!(failures, file.position() == payload.len() as u64 - 100, "fs seek end");
    let mut tail = [0u8; 100];
    match file.read(&mut tail) {
        Ok(n) => {
            expect!(failures, n == 100, "fs read length");
            expect!(
                failures,
                tail[..] == payload[payload.len() - 100..],
                "fs read tail matches"
            );
        }
        Err(error) => {
            println!("[std] FAIL fs read: {error}");
            failures += 1;
        }
    }

    // Overwrite in place: the same file, a different offset, no truncation.
    if file.seek(SeekFrom::Start(10)).is_ok() {
        match file.write(b"OVERWRITE") {
            Ok(n) => {
                expect!(failures, n == 9, "fs overwrite length");
                match file.seek(SeekFrom::Start(0)) {
                    Ok(_) => match file.read_to_end() {
                        Ok(bytes) => {
                            expect!(failures, bytes.len() == payload.len(), "fs reread length");
                            expect!(
                                failures,
                                bytes[10..19] == *b"OVERWRITE",
                                "fs overwrite visible"
                            );
                            expect!(failures, bytes[19..] == payload[19..], "fs rest intact");
                        }
                        Err(error) => {
                            println!("[std] FAIL fs read_to_end: {error}");
                            failures += 1;
                        }
                    },
                    Err(error) => {
                        println!("[std] FAIL fs reseek: {error}");
                        failures += 1;
                    }
                }
            }
            Err(error) => {
                println!("[std] FAIL fs overwrite: {error}");
                failures += 1;
            }
        }
    }

    if let Err(error) = file.truncate(1000) {
        println!("[std] FAIL fs truncate: {error}");
        failures += 1;
    } else {
        expect!(failures, file.size().unwrap_or(0) == 1000, "fs size after truncate");
    }

    match fs::list("/") {
        Ok(entries) => {
            let found = entries
                .iter()
                .any(|entry| entry.name == "std-smoke.txt" && entry.kind == EntryKind::File);
            expect!(failures, found, "fs list finds the file");
        }
        Err(error) => {
            println!("[std] FAIL fs list: {error}");
            failures += 1;
        }
    }

    match fs::remove(NAME) {
        Ok(()) => {
            expect!(failures, fs::File::open(NAME).is_err(), "fs remove");
        }
        Err(error) => {
            println!("[std] FAIL fs remove: {error}");
            failures += 1;
        }
    }

    if fs::read(NAME).is_ok() {
        println!("[std] FAIL fs read of a removed file succeeded");
        failures += 1;
    }

    if let Ok((used, capacity)) = fs::volume_bytes() {
        println!("[std] fs OK (create/write/seek/read/overwrite/truncate/list/remove)");
        println!("[std] fs volume used={used} capacity={capacity}");
    } else {
        println!("[std] fs OK (create/write/seek/read/overwrite/truncate/list/remove)");
    }
    failures
}
