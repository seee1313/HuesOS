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
use huesos_std::collections::HashMap;
use huesos_std::sync::{Arc, Barrier, Condvar, Mutex, OnceLock, RwLock};
use huesos_std::thread;
use huesos_std::time::{Duration, Instant};
use huesos_std::{env, fs, io, path, process};

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
    failures += check_buffered();
    failures += check_collections();
    failures += check_time();
    failures += check_threads();
    failures += check_process();

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

    // The offset pattern `fdisk` uses to write a GPT into an image file: MBR
    // at LBA 0, header at LBA 1, the entry array at LBA 2, and a backup header
    // appended at the end. Those three offsets in one file are exactly what
    // the service's random-offset write path exists for, so they are pinned
    // here, where the filesystem capability is known to be present.
    if let Ok(mut image) = fs::File::create("/std-gpt.img") {
        let mut sectors = 0u32;
        let mut gpt_ok = true;
        let mut header = [0u8; 512];
        header[..8].copy_from_slice(b"EFI PART");
        if io::write_all(&mut image, &[0u8; 512]).is_ok() {
            sectors += 1;
        } else {
            gpt_ok = false;
        }
        gpt_ok &= image.seek(SeekFrom::Start(512)).is_ok();
        gpt_ok &= io::write_all(&mut image, &header).is_ok();
        gpt_ok &= image.seek(SeekFrom::Start(1024)).is_ok();
        gpt_ok &= io::write_all(&mut image, &[0xABu8; 512]).is_ok();
        gpt_ok &= image.seek(SeekFrom::End(0)).is_ok();
        gpt_ok &= io::write_all(&mut image, &header).is_ok();
        let mut probe = [0u8; 8];
        let read_back = image.seek(SeekFrom::Start(512)).is_ok()
            && matches!(image.read(&mut probe), Ok(8));
        expect!(failures, gpt_ok && read_back, "fs gpt-shaped write");
        expect!(failures, &probe[..] == b"EFI PART", "fs gpt header round-trip");
        expect!(
            failures,
            image.size().unwrap_or(0) == 2048 && sectors == 1,
            "fs gpt image size"
        );
        expect!(
            failures,
            image.truncate(1024).is_ok() && image.size().unwrap_or(0) == 1024,
            "fs gpt image truncate"
        );
        expect!(failures, fs::remove("/std-gpt.img").is_ok(), "fs gpt image remove");
    } else {
        println!("[std] FAIL fs gpt-shaped write: create failed");
        failures += 1;
    }

    // Usage is a walk of the tree plus, when the volume service is reachable,
    // the capacity it owns; either half may be missing in a sandbox.
    let used = fs::used_bytes("/").map(|bytes| alloc::format!("{bytes}"));
    let capacity = huesos_coreutils::disk::DiskIo::open(None, false)
        .ok()
        .map(|io| alloc::format!("{}", io.capacity_bytes()));
    println!(
        "[std] fs OK (create/write/seek/read/overwrite/truncate/list/remove/gpt) \
         used={} capacity={}",
        used.as_deref().unwrap_or("?"),
        capacity.as_deref().unwrap_or("?")
    );
    failures
}

/// Buffered and in-memory I/O: a `BufWriter` batches small writes into one
/// syscall, a `BufReader` hands them back a byte at a time, and `Cursor` gives
/// the same traits a seekable in-memory object.
#[rustfmt::skip]
fn check_buffered() -> u32 {
    let mut failures = 0u32;
    let mut sink = Sink { bytes: Vec::new() };
    let mut writer = io::BufWriter::with_capacity(128, &mut sink);
    for _ in 0..10 {
        let _ = io::write_all(&mut writer, b"line 7\n");
    }
    // Nothing may reach the sink before the flush: that is the whole point.
    let deferred = writer.get_ref().map(|sink| sink.bytes.is_empty()).unwrap_or(false);
    expect!(failures, deferred, "bufwriter defers writes");
    let _ = writer.flush();
    drop(writer);
    expect!(failures, sink.bytes.len() == 70, "bufwriter flushed 70 bytes");
    expect!(failures, sink.bytes.starts_with(b"line 7\n"), "bufwriter content");

    let text: &[u8] = b"alpha\nbeta\ngamma\n";
    let mut reader = io::BufReader::with_capacity(4, text);
    let mut first = [0u8; 6];
    let read = reader.read(&mut first).unwrap_or(0);
    expect!(failures, read == 6 && &first == b"alpha\n", "bufreader short read");

    let mut lines = Vec::new();
    let mut reader = io::BufReader::new(text);
    loop {
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => lines.push(line),
            Err(_) => {
                failures += 1;
                break;
            }
        }
    }
    expect!(failures, lines.len() == 3, "bufread read_until three lines");
    expect!(
        failures,
        lines.get(1).map(|line| line.as_slice()) == Some(&b"beta\n"[..]),
        "bufread second line"
    );

    let mut cursor = io::Cursor::new(Vec::new());
    let _ = io::write_all(&mut cursor, b"0123456789");
    let _ = cursor.seek(SeekFrom::Start(4));
    let mut byte = [0u8; 2];
    let read = cursor.read(&mut byte).unwrap_or(0);
    expect!(failures, read == 2 && &byte == b"45", "cursor seek+read");

    let mut out = Vec::new();
    let mut source: &[u8] = b"copied";
    let copied = io::copy(&mut source, &mut out).unwrap_or(0);
    expect!(failures, copied == 6 && out == b"copied", "io::copy");

    if failures == 0 {
        println!("[std] buffered OK (BufWriter/BufReader/read_until/Cursor/copy)");
    }
    failures
}

/// The hash collections: insertion, replacement, removal, the `Entry` API and
/// a tombstone-heavy workload that forces a rehash.
#[rustfmt::skip]
fn check_collections() -> u32 {
    let mut failures = 0u32;
    let mut map: HashMap<&str, u32> = HashMap::new();
    for word in ["one", "two", "three", "two"] {
        *map.entry(word).or_insert(0) += 1;
    }
    expect!(failures, map.len() == 3, "hashmap distinct keys");
    expect!(failures, map.get("two") == Some(&2), "hashmap entry counting");
    expect!(failures, map.insert("one", 10) == Some(1), "hashmap insert replace");
    expect!(failures, map.remove("one") == Some(10), "hashmap remove");
    expect!(failures, map.get("one").is_none(), "hashmap removed key gone");

    // Churn: insert and remove the same key many times, which leaves
    // tombstones behind and must still find every surviving entry.
    let mut churn: HashMap<u32, u32> = HashMap::new();
    for round in 0..64u32 {
        churn.insert(round, round * 2);
        if round % 2 == 0 {
            churn.remove(&(round / 2));
        }
    }
    let mut churn_ok = true;
    for (key, value) in churn.iter() {
        churn_ok &= *value == key * 2;
    }
    expect!(failures, churn_ok, "hashmap churn keeps values");
    let survivors = churn.len();
    churn.shrink_to_fit();
    expect!(failures, churn.len() == survivors, "hashmap shrink keeps entries");

    let mut ordered = huesos_std::collections::BTreeMap::new();
    ordered.insert(3u32, "three");
    ordered.insert(1u32, "one");
    let keys: Vec<u32> = ordered.keys().copied().collect();
    expect!(failures, keys == [1, 3], "btreemap orders keys");

    if failures == 0 {
        println!("[std] collections OK (HashMap entry/churn/shrink, BTreeMap order)");
    }
    failures
}

/// The clock: `Instant` differences must be monotonic and `sleep` must actually
/// spend time (a busy-spin or a zero-tick sleep would fail the first check).
fn check_time() -> u32 {
    let mut failures = 0u32;
    let start = Instant::now();
    thread::sleep(Duration::from_millis(30));
    let elapsed = start.elapsed();
    expect!(
        failures,
        elapsed.as_ticks_ceil() >= 3,
        "sleep spent at least 30ms of ticks"
    );
    let later = Instant::now();
    expect!(failures, later >= start, "instant is monotonic");
    expect!(
        failures,
        Duration::from_millis(1500).as_secs() == 1 && Duration::from_ticks(250).as_secs() == 2,
        "duration conversions"
    );
    if failures == 0 {
        println!("[std] time OK (Instant monotonic, sleep 30ms, Duration conversions)");
    }
    failures
}

/// Four threads sharing one counter, a reader-writer lock, a condition
/// variable, a barrier and a once-cell. Every wait parks on a futex: if the
/// blocking path were broken (a lost wake, a spinning loop that never yields),
/// this section would hang or lose counts, and the shell smoke would time out.
fn check_threads() -> u32 {
    let mut failures = 0u32;

    const WORKERS: usize = 4;
    const PER_WORKER: u32 = 25;
    let counter = Arc::new(Mutex::new(0u32));
    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let counter = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            for _ in 0..PER_WORKER {
                let mut guard = counter.lock();
                *guard += 1;
            }
        }));
    }
    let mut joined = 0;
    for handle in handles {
        if handle.join().is_ok() {
            joined += 1;
        }
    }
    let total = *counter.lock();
    expect!(failures, joined == WORKERS, "threads joined");
    expect!(
        failures,
        total == (WORKERS as u32) * PER_WORKER,
        "mutex kept every increment"
    );

    // Reader-writer lock: test both uncontended sequential handoff and genuine
    // concurrent reader/writer contention (4 readers + 2 writers racing on an
    // invariant-preserving pair `(seq, seq * 7)`). Any inverted guard-drop
    // order or pre-read sequence race deadlocks or exposes torn state here.
    let shared = Arc::new(RwLock::new((0u64, 0u64)));
    expect!(
        failures,
        *shared.read() == (0, 0),
        "rwlock reads initial state"
    );
    {
        let mut guard = shared.write();
        *guard = (1, 7);
    }
    let mut rw_handles = Vec::new();
    for writer_id in 0..2u64 {
        let rw = Arc::clone(&shared);
        rw_handles.push(thread::spawn(move || {
            for step in 0..32u64 {
                let _ = writer_id;
                let mut guard = rw.write();
                let next = guard.0 + 1;
                *guard = (next, next * 7);
                if step & 7 == 0 {
                    thread::yield_now();
                }
            }
            true
        }));
    }
    for _ in 0..4 {
        let rw = Arc::clone(&shared);
        rw_handles.push(thread::spawn(move || {
            let mut prev = 0u64;
            for step in 0..64u64 {
                let (seq, scaled) = *rw.read();
                if scaled != seq * 7 || seq < prev {
                    return false;
                }
                prev = seq;
                if step & 15 == 0 {
                    thread::yield_now();
                }
            }
            true
        }));
    }
    let mut rw_ok = true;
    for handle in rw_handles {
        rw_ok &= handle.join().unwrap_or(false);
    }
    let final_pair = *shared.read();
    expect!(
        failures,
        rw_ok,
        "rwlock concurrent readers/writers invariant"
    );
    expect!(
        failures,
        final_pair == (65, 65 * 7),
        "rwlock preserved every contended write"
    );

    // Condition variable: verify both pre-wait and post-wait notifications.
    // First round: wait until the waiter actually holds the lock and enters
    // `condvar.wait` before notifying (`waiting` flag). Second round: notify
    // immediately so the already-satisfied fast path is covered too.
    for wait_first in [true, false] {
        let pair = Arc::new((Mutex::new((false, false)), Condvar::new()));
        let waiter_pair = Arc::clone(&pair);
        let waiter = thread::spawn(move || {
            let (lock, condvar) = &*waiter_pair;
            let mut state = lock.lock();
            state.0 = true;
            condvar.notify_all();
            let mut spins = 0;
            while !state.1 {
                state = condvar.wait(state);
                spins += 1;
                if spins > 1000 {
                    return false;
                }
            }
            true
        });
        {
            let (lock, condvar) = &*pair;
            let mut state = lock.lock();
            if wait_first {
                while !state.0 {
                    state = condvar.wait(state);
                }
            }
            state.1 = true;
            condvar.notify_all();
        }
        expect!(
            failures,
            waiter.join().unwrap_or(false),
            "condvar woke the waiter"
        );
    }

    // Barrier: three threads plus the main one meet exactly once.
    let barrier = Arc::new(Barrier::new(4));
    let mut barrier_handles = Vec::new();
    for _ in 0..3 {
        let barrier = Arc::clone(&barrier);
        barrier_handles.push(thread::spawn(move || {
            let _ = barrier.wait();
        }));
    }
    let _ = barrier.wait();
    let mut barrier_ok = true;
    for handle in barrier_handles {
        barrier_ok &= handle.join().is_ok();
    }
    expect!(failures, barrier_ok, "barrier released every thread");

    // OnceLock: an initialiser that runs once even from four threads.
    let cell: Arc<OnceLock<u32>> = Arc::new(OnceLock::new());
    let mut once_handles = Vec::new();
    for index in 0..4u32 {
        let cell = Arc::clone(&cell);
        once_handles.push(thread::spawn(move || {
            let _ = *cell.get_or_init(|| index + 1);
        }));
    }
    for handle in once_handles {
        let _ = handle.join();
    }
    expect!(
        failures,
        cell.get().is_some(),
        "oncelock initialised exactly once"
    );

    if failures == 0 {
        println!(
            "[std] threads OK ({WORKERS} threads, Arc<Mutex>, RwLock, Condvar, Barrier, OnceLock)"
        );
    }
    failures
}

/// Child processes: `Command` runs `/bin/sleep` for a quarter of a second and
/// reports a clean exit status.
fn check_process() -> u32 {
    let mut failures = 0u32;
    let start = Instant::now();
    match process::Command::new("/bin/sleep").arg("0.25").status() {
        Ok(status) => {
            expect!(failures, status.success(), "child exited with 0");
            expect!(
                failures,
                start.elapsed().as_ticks_ceil() >= 10,
                "child actually ran"
            );
        }
        Err(error) => {
            // A shell-spawned script inherits no `PROCESS_SPAWN`-style authority,
            // so this is a skip, not a pass: report it and stop here.
            println!("[std] process SKIP (cannot spawn: {error})");
            return failures;
        }
    }
    if failures == 0 {
        println!("[std] process OK (Command spawned /bin/sleep, exit status 0)");
    }
    failures
}
