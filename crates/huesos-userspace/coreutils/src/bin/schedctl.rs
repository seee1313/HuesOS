//! `/bin/schedctl.elf` — scheduler state, task table and a quick measurement.
//!
//! `schedctl cpus|tasks|bench`
//!
//! - `cpus` prints the aggregate counters and one line per CPU: runqueue depth,
//!   owned tasks, the full running Task ID, scheduler ticks and admitted CBS
//!   utilization.
//! - `tasks` prints the whole task table with full Task IDs and owning Process
//!   KOIDs, followed by name, class, state, CPU, and weight.
//! - `bench` samples the counters twice, a tenth of a second apart, and reports
//!   what moved: context switches, remote wakes, reschedule IPIs and the
//!   scheduler ticks consumed in the window.
//!
//! Everything comes from `SystemSchedStats` and `SystemTaskQuery`; nothing is
//! inferred from wall-clock guesses.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;

use huesos_coreutils as cu;
use huesos_std::sys;
use huesos_std::thread;
use huesos_std::time::{Duration, Instant};
use huesos_std::tui;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    match args.first().map(String::as_str).unwrap_or("cpus") {
        "cpus" | "--cpus" | "-c" => cpus(),
        "tasks" | "--tasks" | "-t" | "ps" => tasks(),
        "bench" | "--bench" | "-b" => bench(),
        "-h" | "--help" | "help" => {
            usage();
            0
        }
        other => {
            cu::errln(&format!("schedctl: unknown command '{other}'"));
            usage();
            2
        }
    }
}

fn usage() {
    cu::outln("usage: schedctl cpus|tasks|bench");
    cu::outln("  cpus  per-CPU runqueue depth, current task, ticks, admitted CBS");
    cu::outln("  tasks full Task IDs and owning Process KOIDs with scheduler details");
    cu::outln("  bench counters sampled over a short window");
}

fn cpus() -> i32 {
    let snapshot = match sys::snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            cu::errln(&format!(
                "schedctl: scheduler counters unavailable: {error}"
            ));
            return 1;
        }
    };
    let brand = libcanvas::system::cpu_brand_string();
    cu::outln(&format!(
        "scheduler: {} cpu(s) [{}]  context_switches={}  remote_wakes={}  resched_ipis={}",
        snapshot.summary.cpu_count,
        brand.as_str(),
        snapshot.summary.context_switches,
        snapshot.summary.remote_wakes,
        snapshot.summary.resched_ipis
    ));
    cu::outln(&format!(
        "           inbox_drains={}  irq_storm_masks={}  admitted={}.{:02}%",
        snapshot.summary.inbox_drains,
        snapshot.summary.irq_storm_masks,
        snapshot.summary.admitted_ppm / 10_000,
        (snapshot.summary.admitted_ppm % 10_000) / 100
    ));

    let mut table = tui::Table::new(
        &[
            "CPU",
            "ONLINE",
            "RUNQ",
            "TASKS",
            "CURRENT TASK ID",
            "TICKS",
            "CBS",
        ],
        &[3, 6, 4, 5, 16, 9, 6],
    );
    for record in &snapshot.cpus {
        table.row(&[
            format!("{}", record.cpu),
            String::from(if record.online != 0 { "yes" } else { "no" }),
            format!("{}", record.runnable),
            format!("{}", record.tasks),
            if record.current_task == 0 {
                String::from("-")
            } else {
                format!("{:#x}", record.current_task)
            },
            tui::human_count(record.ticks),
            format!(
                "{}.{:02}%",
                record.admitted_ppm / 10_000,
                (record.admitted_ppm % 10_000) / 100
            ),
        ]);
    }
    cu::outln(&table.header_line());
    cu::outln(&table.separator());
    for line in table.lines() {
        cu::outln(&line);
    }
    cu::outln(&format!(
        "totals: runnable={} tasks={} ticks={}",
        snapshot.runnable(),
        snapshot.tasks(),
        tui::human_count(snapshot.ticks())
    ));
    0
}

fn tasks() -> i32 {
    let records = match sys::tasks() {
        Ok(records) => records,
        Err(error) => {
            cu::errln(&format!("schedctl: task table unavailable: {error}"));
            return 1;
        }
    };
    let mut table = tui::Table::new(
        &[
            "TASK-ID",
            "PROCESS-KOID",
            "NAME",
            "ABI",
            "CLASS",
            "STATE",
            "CPU",
            "WEIGHT",
        ],
        &[16, 14, 16, 6, 8, 8, 3, 6],
    );
    for record in &records {
        table.row(&[
            format!("{:#x}", record.task_id),
            if record.process_koid() == 0 {
                String::from("-")
            } else {
                format!("{}", record.process_koid())
            },
            String::from(record.name_str()),
            String::from(record.abi_str()),
            String::from(record.class_str()),
            String::from(record.state_str()),
            format!("{}", record.cpu),
            if record.weight == 0 {
                String::from("-")
            } else {
                format!("{}", record.weight)
            },
        ]);
    }
    cu::outln(&table.header_line());
    cu::outln(&table.separator());
    for line in table.lines() {
        cu::outln(&line);
    }
    cu::outln(&format!("{} task(s)", records.len()));
    0
}

fn bench() -> i32 {
    let before = match sys::snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            cu::errln(&format!(
                "schedctl: scheduler counters unavailable: {error}"
            ));
            return 1;
        }
    };
    let started = Instant::now();
    // Sleep instead of spinning: a busy loop would itself generate the context
    // switches being measured.
    thread::sleep(Duration::from_millis(100));
    let elapsed = started.elapsed();
    let after = match sys::snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            cu::errln(&format!(
                "schedctl: scheduler counters unavailable: {error}"
            ));
            return 1;
        }
    };

    let micros = elapsed.as_micros().max(1) as u64;
    let per_second = |value: u64| -> u64 { value.saturating_mul(1_000_000) / micros };
    cu::outln(&format!(
        "window: {} us   cpus={}",
        micros, after.summary.cpu_count
    ));
    let lines: [(&str, u64); 4] = [
        (
            "context switches",
            after.summary.context_switches - before.summary.context_switches,
        ),
        (
            "remote wakes",
            after.summary.remote_wakes - before.summary.remote_wakes,
        ),
        (
            "resched ipis",
            after.summary.resched_ipis - before.summary.resched_ipis,
        ),
        (
            "inbox drains",
            after.summary.inbox_drains - before.summary.inbox_drains,
        ),
    ];
    for (label, delta) in lines {
        cu::outln(&format!(
            "{label:<17}: {delta:>8}  ({} /s)",
            per_second(delta)
        ));
    }
    cu::outln(&format!(
        "scheduler ticks  : {:>8}",
        after.ticks().saturating_sub(before.ticks())
    ));
    let idle = after
        .cpus
        .iter()
        .filter(|cpu| cpu.current_task == 0)
        .count();
    cu::outln(&format!(
        "idle cpus at end : {idle}/{}",
        after.summary.cpu_count
    ));
    0
}
