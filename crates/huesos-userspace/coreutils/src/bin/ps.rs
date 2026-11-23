//! `/bin/ps.elf` — list live processes and kernel/user scheduler tasks by real KOID.
//!
//! By default `ps` merges the kernel task table (`SystemTaskQuery`) with
//! DriverManager's supervised service table (`query:ps`), emitting one TSV row
//! per live user Process keyed by its immutable kernel `KOID`.
//!
//! Flags:
//! - `ps`           all live user processes (`koid`, `name`, `state`, `cpu`, `threads`, `supervisor`)
//! - `ps -a` / `-T` all kernel + user threads (`koid`, `task_id`, `name`, `domain`, `state`, `cpu`, `policy`)
//! - `ps -s`        DriverManager supervised-service table (`query:ps`)

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;

use huesos_coreutils as cu;
use huesos_std::sys;
use libcanvas::stdio::{take_cap_handle, CapKind};
use libcanvas::Channel;

cu::coreutil_entry!(run);

struct SupervisedMeta {
    name: String,
    state: String,
    generation: String,
    restarts: String,
}

struct ProcessSummary {
    koid: u64,
    name: String,
    abi: &'static str,
    best_state: u8,
    cpu: u16,
    threads: usize,
}

fn query_supervised() -> BTreeMap<u64, SupervisedMeta> {
    let mut map = BTreeMap::new();
    let Some(handle) = take_cap_handle(CapKind::Registry) else {
        return map;
    };
    let ch = Channel::from_handle(handle);
    if ch.write(b"query:ps").is_err() {
        return map;
    }
    let mut buf = [0u8; 2048];
    if let Ok(n) = ch.read_into_timeout(&mut buf, 20) {
        let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
        for (idx, line) in text.lines().enumerate() {
            if idx == 0 || line.trim().is_empty() {
                continue;
            }
            let mut cols = line.split('\t');
            let Some(koid_str) = cols.next() else {
                continue;
            };
            let Ok(koid) = koid_str.trim().parse::<u64>() else {
                continue;
            };
            let name = String::from(cols.next().unwrap_or(""));
            let state = String::from(cols.next().unwrap_or(""));
            let generation = String::from(cols.next().unwrap_or("0"));
            let restarts = String::from(cols.next().unwrap_or("0"));
            map.insert(
                koid,
                SupervisedMeta {
                    name,
                    state,
                    generation,
                    restarts,
                },
            );
        }
    }
    map
}

fn state_str(state: u8) -> &'static str {
    match state {
        0 => "running",
        1 => "ready",
        2 => "blocked",
        _ => "exited",
    }
}

fn run() -> i32 {
    let args = cu::collect_args();
    let mut show_all_threads = false;
    let mut supervised_only = false;

    for arg in args.iter() {
        match arg.as_str() {
            "-a" | "-e" | "-T" | "--all" | "--threads" => show_all_threads = true,
            "-s" | "--supervised" => supervised_only = true,
            "-h" | "--help" => {
                cu::outln("usage: ps [-a|-T] [-s]");
                cu::outln("  default  all live user processes keyed by real kernel KOID");
                cu::outln("  -a, -T   all kernel and user scheduler threads");
                cu::outln("  -s       DriverManager supervised service table only");
                return 0;
            }
            other => {
                cu::errln(&format!("ps: unknown option '{other}'"));
                return 2;
            }
        }
    }

    if supervised_only {
        return cu::run_registry_query("ps", b"query:ps");
    }

    let records = match sys::tasks() {
        Ok(records) => records,
        Err(_) => return cu::run_registry_query("ps", b"query:ps"),
    };

    if show_all_threads {
        cu::outln("koid\ttask_id\tname\tdomain\tabi\tstate\tcpu\tpolicy");
        for r in &records {
            let koid_col = if r.process_koid() == 0 {
                String::from("0")
            } else {
                format!("{}", r.process_koid())
            };
            let dom = if r.kind == 1 { "user" } else { "kernel" };
            let pol = if r.policy == 1 { "deadline" } else { "fair" };
            cu::outln(&format!(
                "{}\t{:#x}\t{}\t{}\t{}\t{}\t{}\t{}",
                koid_col,
                r.task_id,
                r.name_str(),
                dom,
                r.abi_str(),
                r.state_str(),
                r.cpu,
                pol
            ));
        }
        return 0;
    }

    let supervised = query_supervised();
    let mut procs: BTreeMap<u64, ProcessSummary> = BTreeMap::new();
    for r in &records {
        let koid = r.process_koid();
        if koid == 0 || r.state >= 3 {
            continue;
        }
        let entry = procs.entry(koid).or_insert_with(|| ProcessSummary {
            koid,
            name: String::from(r.name_str()),
            abi: r.abi_str(),
            best_state: r.state,
            cpu: r.cpu,
            threads: 0,
        });
        entry.threads += 1;
        if r.abi_str() == "PE64" {
            entry.abi = "PE64";
        }
        if r.state < entry.best_state {
            entry.best_state = r.state;
            entry.cpu = r.cpu;
        }
    }
    for (&koid, sup) in &supervised {
        procs.entry(koid).or_insert_with(|| ProcessSummary {
            koid,
            name: sup.name.clone(),
            abi: "ELF64",
            best_state: 2,
            cpu: 0,
            threads: 1,
        });
    }

    cu::outln("koid\tname\tabi\tstate\tcpu\tthreads\tsupervisor");
    for (_, proc_row) in procs {
        let (name, sup_col) = if let Some(sup) = supervised.get(&proc_row.koid) {
            (
                sup.name.as_str(),
                format!(
                    "{} (gen={}, restarts={})",
                    sup.state, sup.generation, sup.restarts
                ),
            )
        } else {
            (proc_row.name.as_str(), String::from("-"))
        };
        cu::outln(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            proc_row.koid,
            name,
            proc_row.abi,
            state_str(proc_row.best_state),
            proc_row.cpu,
            proc_row.threads,
            sup_col
        ));
    }
    0
}
