//! `/bin/btop.elf` — the system monitor.
//!
//! `btop [-i <milliseconds>]`
//!
//! Three panes, refreshed on a timer:
//!
//! - **cpus**: one bar per CPU showing the share of the processor that is
//!   *reserved* by admitted CBS bandwidth, plus the runqueue depth, the number
//!   of tasks the CPU owns and whether it is running anything. Reserved
//!   bandwidth is a promise the scheduler has made; it is the honest number to
//!   draw, because HuesOS does not bill idle cycles per task.
//! - **rates**: context switches, remote wakes, reschedule IPIs and inbox
//!   drains per second, measured between frames.
//! - **tasks**: how many tasks exist in each state, and the running ones by
//!   name.
//!
//! Keys: `q` quit, `space` pause, `r` refresh now, `+`/`-` slow down or speed
//! up the sampling window, `h` help line.
//!
//! The program never spins: it parks in `read_key_timeout` for exactly the
//! sampling interval, so a monitor left running costs one wakeup per frame.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_coreutils as cu;
use huesos_std::io::Write;
use huesos_std::sys::{self, Snapshot};
use huesos_std::time::{Duration, Instant};
use huesos_std::tui::{self, Color, Key};

cu::coreutil_entry!(run);

/// Width of every pane, in columns.
const WIDTH: usize = 78;
/// Width of a CPU bar.
const BAR: usize = 36;
/// Fastest and slowest sampling windows, in milliseconds.
const MIN_INTERVAL: u64 = 250;
const MAX_INTERVAL: u64 = 5_000;

fn run() -> i32 {
    let args = cu::collect_args();
    let mut interval_ms = 1_000u64;
    // `--frames N` draws N frames and exits. A monitor that can only be stopped
    // by a keypress cannot be driven from a script, and a scripted run that
    // has to kill it cannot tell "drew one frame" from "drew none".
    let mut frames_left: Option<u32> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-i" | "--interval" => {
                index += 1;
                match args.get(index).and_then(|value| value.parse::<u64>().ok()) {
                    Some(value) => interval_ms = value.clamp(MIN_INTERVAL, MAX_INTERVAL),
                    None => {
                        cu::errln("btop: -i needs a millisecond value");
                        return 2;
                    }
                }
            }
            "-n" | "--frames" => {
                index += 1;
                match args.get(index).and_then(|value| value.parse::<u32>().ok()) {
                    Some(0) | None => {
                        cu::errln("btop: -n needs a frame count of at least 1");
                        return 2;
                    }
                    Some(value) => frames_left = Some(value),
                }
            }
            "-h" | "--help" => {
                cu::outln("usage: btop [-i <milliseconds>] [-n <frames>]");
                cu::outln("  q quit   space pause   r refresh   + / - interval");
                return 0;
            }
            other => {
                cu::errln(&format!("btop: unknown argument '{other}'"));
                return 2;
            }
        }
        index += 1;
    }

    let mut screen = tui::Screen::new(huesos_std::io::stdout());
    let _ = screen.clear();
    let _ = screen.hide_cursor();

    let mut paused = false;
    let mut previous: Option<Snapshot> = None;
    loop {
        let started = Instant::now();
        let current = match sys::snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let _ = screen.show_cursor();
                cu::errln(&format!("btop: scheduler counters unavailable: {error}"));
                return 1;
            }
        };
        let task_records = sys::tasks().unwrap_or_default();
        let elapsed = started.elapsed().as_micros().max(1) as u64;
        let rates = match &previous {
            Some(previous) => Rates::between(previous, &current, elapsed),
            None => Rates::default(),
        };

        let _ = screen.clear();
        let _ = draw(
            &mut screen,
            &current,
            &rates,
            &task_records,
            interval_ms,
            paused,
        );
        let _ = screen.out().flush();

        if !paused {
            previous = Some(current);
        }

        // A frame budget is how a scripted run stops; otherwise park for the
        // sampling window, where a key arrives long before it only when the
        // operator presses one.
        if let Some(remaining) = frames_left {
            if remaining <= 1 {
                break;
            }
            frames_left = Some(remaining - 1);
            continue;
        }
        let key = tui::read_key_timeout(Duration::from_millis(interval_ms));
        match key {
            Some(Key::Char(b'q'))
            | Some(Key::Char(b'Q'))
            | Some(Key::Ctrl(3))
            | Some(Key::Escape) => break,
            Some(Key::Char(b' ')) => paused = !paused,
            Some(Key::Char(b'r')) => previous = None,
            Some(Key::Char(b'+')) | Some(Key::Char(b'=')) => {
                interval_ms = (interval_ms + 250).min(MAX_INTERVAL);
            }
            Some(Key::Char(b'-')) => {
                interval_ms = interval_ms.saturating_sub(250).max(MIN_INTERVAL);
            }
            // Every other key is ignored; the frame redraws on schedule.
            None | Some(_) => {}
        }
    }

    let _ = screen.clear();
    let _ = screen.show_cursor();
    let _ = screen.out().flush();
    0
}

/// Counters measured between two samples.
#[derive(Clone, Copy, Debug, Default)]
struct Rates {
    context_switches: u64,
    remote_wakes: u64,
    resched_ipis: u64,
    inbox_drains: u64,
    ticks: u64,
    micros: u64,
}

impl Rates {
    fn between(previous: &Snapshot, current: &Snapshot, micros: u64) -> Self {
        Self {
            context_switches: current
                .summary
                .context_switches
                .saturating_sub(previous.summary.context_switches),
            remote_wakes: current
                .summary
                .remote_wakes
                .saturating_sub(previous.summary.remote_wakes),
            resched_ipis: current
                .summary
                .resched_ipis
                .saturating_sub(previous.summary.resched_ipis),
            inbox_drains: current
                .summary
                .inbox_drains
                .saturating_sub(previous.summary.inbox_drains),
            ticks: current.ticks().saturating_sub(previous.ticks()),
            micros,
        }
    }

    /// Events per second for a counter sampled over `micros`.
    fn per_second(&self, value: u64) -> u64 {
        if self.micros == 0 {
            return 0;
        }
        value.saturating_mul(1_000_000) / self.micros
    }
}

fn draw<W: Write>(
    screen: &mut tui::Screen<W>,
    snapshot: &Snapshot,
    rates: &Rates,
    tasks: &[huesos_abi::TaskRecord],
    interval_ms: u64,
    paused: bool,
) -> huesos_std::Result<()> {
    let title = format!(
        " HuesOS monitor -- {} cpu(s) -- {}.{}s ",
        snapshot.summary.cpu_count,
        interval_ms / 1000,
        (interval_ms % 1000) / 100
    );
    screen.line(&tui::frame_top(&title, WIDTH))?;

    // CPU pane.
    for record in &snapshot.cpus {
        let reserved = u64::from(record.admitted_ppm);
        let bar = bar_for(reserved * 100 / 10_000, 100, BAR);
        let state = if record.current_task == 0 {
            tui::colored("idle", Color::Green)
        } else {
            tui::colored("busy", Color::Yellow)
        };
        let row = format!(
            " cpu{:<2} {} {:>3}.{:02}%  runq {:<2} tasks {:<3} {}",
            record.cpu,
            bar,
            record.admitted_ppm / 10_000,
            (record.admitted_ppm % 10_000) / 100,
            record.runnable,
            record.tasks,
            state
        );
        screen.line(&tui::frame_line(&row, WIDTH))?;
    }
    screen.line(&tui::frame_rule(WIDTH))?;

    // Rate pane.
    screen.line(&tui::frame_line(
        &format!(
            " ctxt/s {:>6}   wakes/s {:>6}   ipi/s {:>5}   inbox/s {:>5}   ticks {}",
            rates.per_second(rates.context_switches),
            rates.per_second(rates.remote_wakes),
            rates.per_second(rates.resched_ipis),
            rates.per_second(rates.inbox_drains),
            tui::human_count(rates.ticks)
        ),
        WIDTH,
    ))?;
    screen.line(&tui::frame_line(
        &format!(
            " total ctxt {}   remote wakes {}   ipi {}   storm masks {}   admitted {}",
            tui::human_count(snapshot.summary.context_switches),
            tui::human_count(snapshot.summary.remote_wakes),
            tui::human_count(snapshot.summary.resched_ipis),
            tui::human_count(snapshot.summary.irq_storm_masks),
            format_ppm(snapshot.summary.admitted_ppm),
        ),
        WIDTH,
    ))?;
    screen.line(&tui::frame_rule(WIDTH))?;

    // Task pane.
    let (mut running, mut ready, mut blocked, mut finished) = (0u32, 0u32, 0u32, 0u32);
    for task in tasks {
        match task.state {
            0 => running += 1,
            1 => ready += 1,
            2 => blocked += 1,
            _ => finished += 1,
        }
    }
    screen.line(&tui::frame_line(
        &format!(
            " tasks {}   running {}   ready {}   blocked {}   finished {}",
            tasks.len(),
            running,
            ready,
            blocked,
            finished
        ),
        WIDTH,
    ))?;
    let mut shown = Vec::new();
    for task in tasks.iter().filter(|task| task.state == 0) {
        shown.push(format!("{}@cpu{}", task.name_str(), task.cpu));
    }
    for task in tasks.iter().filter(|task| task.state == 1) {
        shown.push(format!("{}@cpu{}", task.name_str(), task.cpu));
    }
    let summary = shown.join(", ");
    screen.line(&tui::frame_line(
        &format!(" live: {}", tui::fit(&summary, WIDTH - 8)),
        WIDTH,
    ))?;

    screen.line(&tui::frame_bottom(WIDTH))?;
    screen.line(&format!(
        " {}{}",
        if paused {
            tui::colored("[paused] ", Color::Yellow)
        } else {
            String::new()
        },
        "q quit  space pause  r refresh  +/- interval"
    ))?;
    Ok(())
}

/// A fixed-width bar for `value` out of `total`, coloured by load.
fn bar_for(value: u64, total: u64, width: usize) -> String {
    let filled = tui::bar(value, total, width);
    let color = match (value * 100) / total.max(1) {
        0..=49 => Color::Green,
        50..=79 => Color::Yellow,
        _ => Color::Red,
    };
    tui::colored(&filled, color)
}

/// Render parts-per-million as a percentage with two decimals.
fn format_ppm(ppm: u64) -> String {
    format!("{}.{:02}%", ppm / 10_000, (ppm % 10_000) / 100)
}
