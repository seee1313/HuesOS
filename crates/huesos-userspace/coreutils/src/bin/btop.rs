//! `/bin/btop.elf` — full-screen real-time system, scheduler, storage, and task studio.
//!
//! `btop [-i <milliseconds>] [-n <frames>]`
//!
//! Renders an obsidian truecolor multi-pane telemetry dashboard sized to the
//! full HuesOS framebuffer terminal (`166 × 50` on `1024×768` Cozette6x13, with
//! graceful layout scaling down to `80 × 24` serial consoles):
//!
//! - **Header chrome**: `HuesOS monitor` identity badge, online CPU count,
//!   monotonic uptime clock, refresh cadence, sort/filter indicators, and live
//!   pause badge.
//! - **CPU & Scheduler pane**: dual Braille history sparklines (`load` and
//!   `ctxt/s`), per-CPU 1/8th-block truecolor gradient meters (`█▉▊▋▌▍▎▏`),
//!   CBS reserved bandwidth, runqueue depth, active task per core, and live
//!   rates (`ctxt/s`, `wakes/s`, `ipi/s`, `inbox/s`, IRQ storm quarantine).
//! - **HxFS Storage & Supervisor Services split panes**: live mounted HxFS v7
//!   block & object utilization (`fs::stat_fs`) alongside task state breakdown
//!   and supervised DriverManager services (`query:ps`).
//! - **Interactive Task Studio**: full-height scrollable task table with column
//!   sorting (`s` / `←` / `→`, `v` invert), live substring filter (`/` or `f`),
//!   cursor navigation (`↑`/`↓`/`j`/`k`, `PgUp`/`PgDn`, `Home`/`End`), live
//!   task inspector strip, and `?`/`h` hotkey overlay.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use huesos_abi::hxfs::HxfsStatFsInfo;
use huesos_abi::TaskRecord;
use huesos_coreutils as cu;
use huesos_std::fs;
use huesos_std::io;
use huesos_std::sys::{self, Snapshot};
use huesos_std::time::{Duration, Instant};
use huesos_std::tui::{self, ansi, bg_rgb, fg_rgb, FrameBuffer, Key};
use libcanvas::stdio::{take_cap_handle, CapKind};
use libcanvas::{Channel, ErrorCode};

cu::coreutil_entry!(run);

/// Fastest and slowest sampling windows, in milliseconds.
const MIN_INTERVAL: u64 = 250;
const MAX_INTERVAL: u64 = 5_000;
/// Number of samples retained in Braille history rings (up to 320 samples = 160 cells).
const MAX_HISTORY: usize = 320;

// Truecolor palette tuned to HuesOS `#0B0E14` obsidian chrome.
const BG_HEADER: (u8, u8, u8) = (19, 26, 40);
const BG_FOOTER: (u8, u8, u8) = (16, 22, 34);
const BG_SELECT: (u8, u8, u8) = (32, 54, 82);
const BG_MODAL: (u8, u8, u8) = (15, 21, 33);

const FG_BORDER: (u8, u8, u8) = (56, 78, 112);
const FG_BORDER_HI: (u8, u8, u8) = (88, 196, 220);
const FG_TITLE: (u8, u8, u8) = (120, 238, 200);
const FG_TEXT: (u8, u8, u8) = (214, 226, 244);
const FG_MUTED: (u8, u8, u8) = (118, 138, 168);
const FG_CYAN: (u8, u8, u8) = (95, 222, 245);
const FG_MINT: (u8, u8, u8) = (95, 230, 172);
const FG_AMBER: (u8, u8, u8) = (250, 202, 96);
const FG_CORAL: (u8, u8, u8) = (250, 108, 118);
const FG_VIOLET: (u8, u8, u8) = (198, 146, 252);
const FG_BLUE: (u8, u8, u8) = (122, 176, 255);
const FG_TRACK: (u8, u8, u8) = (38, 49, 68);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SortCol {
    State,
    TaskId,
    Cpu,
    Domain,
    Policy,
    Weight,
    Name,
}

impl SortCol {
    const ALL: [SortCol; 7] = [
        SortCol::State,
        SortCol::TaskId,
        SortCol::Cpu,
        SortCol::Domain,
        SortCol::Policy,
        SortCol::Weight,
        SortCol::Name,
    ];

    fn next(self) -> Self {
        let idx = Self::ALL.iter().position(|&c| c == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    fn prev(self) -> Self {
        let idx = Self::ALL.iter().position(|&c| c == self).unwrap_or(0);
        if idx == 0 {
            Self::ALL[Self::ALL.len() - 1]
        } else {
            Self::ALL[idx - 1]
        }
    }

    fn label(self) -> &'static str {
        match self {
            SortCol::State => "STATE",
            SortCol::TaskId => "TID",
            SortCol::Cpu => "CPU",
            SortCol::Domain => "RING",
            SortCol::Policy => "SCHED",
            SortCol::Weight => "WEIGHT",
            SortCol::Name => "TASK",
        }
    }
}

#[derive(Clone, Debug)]
struct ServiceRow {
    name: String,
    state: String,
    restarts: String,
}

struct MonitorApp {
    interval_ms: u64,
    paused: bool,
    sort_col: SortCol,
    sort_desc: bool,
    selected: usize,
    filter: String,
    editing_filter: bool,
    show_help: bool,
    user_only: bool,
    load_hist: Vec<u64>,
    ctxt_hist: Vec<u64>,
    wake_hist: Vec<u64>,
    peak_ctxt_s: u64,
    peak_wake_s: u64,
    query_ch: Option<Channel>,
    services: Vec<ServiceRow>,
    fs_stats: Option<HxfsStatFsInfo>,
    tick_counter: u64,
}

impl MonitorApp {
    fn new(interval_ms: u64) -> Self {
        let query_ch = take_cap_handle(CapKind::Registry).map(Channel::from_handle);
        Self {
            interval_ms,
            paused: false,
            sort_col: SortCol::State,
            sort_desc: false,
            selected: 0,
            filter: String::new(),
            editing_filter: false,
            show_help: false,
            user_only: false,
            load_hist: Vec::with_capacity(MAX_HISTORY),
            ctxt_hist: Vec::with_capacity(MAX_HISTORY),
            wake_hist: Vec::with_capacity(MAX_HISTORY),
            peak_ctxt_s: 100,
            peak_wake_s: 50,
            query_ch,
            services: Vec::new(),
            fs_stats: None,
            tick_counter: 0,
        }
    }

    fn push_history(&mut self, load_pct: u64, ctxt_s: u64, wake_s: u64) {
        if self.load_hist.len() >= MAX_HISTORY {
            self.load_hist.remove(0);
        }
        self.load_hist.push(load_pct.min(100));

        if self.ctxt_hist.len() >= MAX_HISTORY {
            self.ctxt_hist.remove(0);
        }
        self.ctxt_hist.push(ctxt_s);
        if ctxt_s > self.peak_ctxt_s {
            self.peak_ctxt_s = ctxt_s;
        }

        if self.wake_hist.len() >= MAX_HISTORY {
            self.wake_hist.remove(0);
        }
        self.wake_hist.push(wake_s);
        if wake_s > self.peak_wake_s {
            self.peak_wake_s = wake_s;
        }
    }

    fn refresh_side_telemetry(&mut self) {
        // Refresh storage & service state every 4th frame (and frame 0) so IPC stays featherweight.
        if self.tick_counter.is_multiple_of(4) {
            self.fs_stats = fs::stat_fs().ok();
            self.poll_services();
        }
        self.tick_counter = self.tick_counter.wrapping_add(1);
    }

    fn poll_services(&mut self) {
        let Some(ch) = self.query_ch.as_ref() else {
            return;
        };
        // Drain any stale reply first without blocking.
        let mut stale = [0u8; 1024];
        while let Ok(n) = ch.read_into(&mut stale) {
            if n == 0 {
                break;
            }
        }
        if ch.write(b"query:ps").is_err() {
            return;
        }
        let mut buf = [0u8; 2048];
        match ch.read_into_timeout(&mut buf, 4) {
            Ok(n) if n > 0 => {
                let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
                let mut parsed = Vec::new();
                for (idx, line) in text.lines().enumerate() {
                    if idx == 0 || line.trim().is_empty() {
                        continue;
                    }
                    let mut cols = line.split('\t');
                    let _handle = cols.next().unwrap_or("");
                    let name = cols.next().unwrap_or("");
                    let state = cols.next().unwrap_or("");
                    let _gen = cols.next().unwrap_or("");
                    let restarts = cols.next().unwrap_or("0");
                    if !name.is_empty() {
                        parsed.push(ServiceRow {
                            name: String::from(name),
                            state: String::from(state),
                            restarts: String::from(restarts),
                        });
                    }
                }
                if !parsed.is_empty() {
                    self.services = parsed;
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) | Ok(_) => {}
            Err(_) => {
                self.query_ch = None;
            }
        }
    }
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

    fn per_second(&self, value: u64) -> u64 {
        if self.micros == 0 {
            return 0;
        }
        value.saturating_mul(1_000_000) / self.micros
    }
}

fn run() -> i32 {
    let args = cu::collect_args();
    let mut interval_ms = 1_000u64;
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
                cu::outln("  q/Esc quit   space pause   r refresh   +/- speed   s/Left/Right sort");
                cu::outln(
                    "  v invert     / filter      u user-only Up/Down/PgUp/PgDn select   ? help",
                );
                return 0;
            }
            other => {
                cu::errln(&format!("btop: unknown argument '{other}'"));
                return 2;
            }
        }
        index += 1;
    }

    let scripted_single_shot = frames_left.is_some();
    let mut screen = tui::Screen::new(io::stdout());
    if !scripted_single_shot {
        let _ = screen.enter_fullscreen();
    } else {
        let _ = screen.hide_cursor();
    }

    let mut app = MonitorApp::new(interval_ms);
    let mut previous: Option<(Snapshot, Instant)> = None;

    loop {
        let now = Instant::now();
        let current = match sys::snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                if !scripted_single_shot {
                    let _ = screen.leave_fullscreen();
                } else {
                    let _ = screen.show_cursor();
                }
                cu::errln(&format!("btop: scheduler counters unavailable: {error}"));
                return 1;
            }
        };
        let raw_tasks = sys::tasks().unwrap_or_default();
        let rates = match &previous {
            Some((prev_snap, prev_at)) => {
                let elapsed = prev_at.elapsed().as_micros().max(1) as u64;
                Rates::between(prev_snap, &current, elapsed)
            }
            None => Rates::default(),
        };

        if !app.paused {
            app.refresh_side_telemetry();
            let active_cores = current
                .cpus
                .iter()
                .filter(|c| !cpu_is_idle(&raw_tasks, c.current_task) || c.runnable > 0)
                .count() as u64;
            let cpu_total = u64::from(current.summary.cpu_count.max(1));
            let busy_pct = (active_cores * 100 / cpu_total)
                .max(current.summary.admitted_ppm / 10_000)
                .min(100);
            let ctxt_s = rates.per_second(rates.context_switches);
            let wake_s = rates.per_second(rates.remote_wakes);
            app.push_history(busy_pct, ctxt_s, wake_s);
            previous = Some((current.clone(), now));
        }

        let visible_tasks = filter_and_sort_tasks(&raw_tasks, &app);
        if visible_tasks.is_empty() {
            app.selected = 0;
        } else if app.selected >= visible_tasks.len() {
            app.selected = visible_tasks.len() - 1;
        }

        let (cols, rows) = tui::viewport_size();
        let mut fb = FrameBuffer::new(cols, rows);
        render_dashboard(&mut fb, &app, &current, &rates, &raw_tasks, &visible_tasks);
        let _ = fb.flush_to(screen.out());

        if let Some(remaining) = frames_left {
            if remaining <= 1 {
                break;
            }
            frames_left = Some(remaining - 1);
            if app.interval_ms > 0 {
                huesos_std::thread::sleep(Duration::from_millis(app.interval_ms.min(100)));
            }
            continue;
        }

        let key = tui::read_key_timeout(Duration::from_millis(app.interval_ms));
        if app.show_help {
            if key.is_some() {
                app.show_help = false;
            }
            continue;
        }

        if app.editing_filter {
            match key {
                Some(Key::Enter) | Some(Key::Escape) => {
                    app.editing_filter = false;
                }
                Some(Key::Backspace) => {
                    app.filter.pop();
                    app.selected = 0;
                }
                Some(Key::Ctrl(3)) => break,
                Some(Key::Ctrl(21)) => {
                    // Ctrl-U clear filter
                    app.filter.clear();
                    app.selected = 0;
                }
                Some(Key::Char(b)) if (0x20..=0x7e).contains(&b) && app.filter.len() < 28 => {
                    app.filter.push(char::from(b));
                    app.selected = 0;
                }
                _ => {}
            }
            continue;
        }

        match key {
            Some(Key::Char(b'q')) | Some(Key::Char(b'Q')) | Some(Key::Ctrl(3)) => break,
            Some(Key::Escape) => {
                if !app.filter.is_empty() {
                    app.filter.clear();
                    app.selected = 0;
                } else {
                    break;
                }
            }
            Some(Key::Char(b' ')) => app.paused = !app.paused,
            Some(Key::Char(b'r')) | Some(Key::Char(b'R')) => {
                previous = None;
                app.tick_counter = 0;
            }
            Some(Key::Char(b'+')) | Some(Key::Char(b'=')) => {
                app.interval_ms = (app.interval_ms + 250).min(MAX_INTERVAL);
            }
            Some(Key::Char(b'-')) | Some(Key::Char(b'_')) => {
                app.interval_ms = app.interval_ms.saturating_sub(250).max(MIN_INTERVAL);
            }
            Some(Key::Up) | Some(Key::Char(b'k')) => {
                app.selected = app.selected.saturating_sub(1);
            }
            Some(Key::Down) | Some(Key::Char(b'j')) => {
                if app.selected + 1 < visible_tasks.len() {
                    app.selected += 1;
                }
            }
            Some(Key::PageUp) => {
                app.selected = app.selected.saturating_sub(12);
            }
            Some(Key::PageDown) => {
                if !visible_tasks.is_empty() {
                    app.selected = (app.selected + 12).min(visible_tasks.len() - 1);
                }
            }
            Some(Key::Home) | Some(Key::Char(b'g')) => {
                app.selected = 0;
            }
            Some(Key::End) | Some(Key::Char(b'G')) => {
                if !visible_tasks.is_empty() {
                    app.selected = visible_tasks.len() - 1;
                }
            }
            Some(Key::Char(b's')) | Some(Key::Char(b'S')) | Some(Key::Right) => {
                app.sort_col = app.sort_col.next();
            }
            Some(Key::Left) => {
                app.sort_col = app.sort_col.prev();
            }
            Some(Key::Char(b'v')) | Some(Key::Char(b'V')) | Some(Key::Char(b'I')) => {
                app.sort_desc = !app.sort_desc;
            }
            Some(Key::Char(b'/')) | Some(Key::Char(b'f')) => {
                app.editing_filter = true;
            }
            Some(Key::Char(b'c')) | Some(Key::Char(b'C')) => {
                app.filter.clear();
                app.selected = 0;
            }
            Some(Key::Char(b'u')) | Some(Key::Char(b'U')) => {
                app.user_only = !app.user_only;
                app.selected = 0;
            }
            Some(Key::Char(b'?')) | Some(Key::Char(b'h')) | Some(Key::Char(b'H')) => {
                app.show_help = true;
            }
            None | Some(_) => {}
        }
    }

    if !scripted_single_shot {
        let _ = screen.leave_fullscreen();
        let _ = screen.clear();
    } else {
        let _ = screen.write_raw("\r\n\x1b[0m\x1b[?25h");
    }
    0
}

fn filter_and_sort_tasks(tasks: &[TaskRecord], app: &MonitorApp) -> Vec<TaskRecord> {
    let needle = app.filter.trim().to_ascii_lowercase();
    let mut out: Vec<TaskRecord> = tasks
        .iter()
        .copied()
        .filter(|t| {
            if app.user_only && t.kind != 1 {
                return false;
            }
            if needle.is_empty() {
                return true;
            }
            let name_lc = t.name_str().to_ascii_lowercase();
            let state_lc = state_label(t.state).to_ascii_lowercase();
            let tid_s = format!("{}", t.task_id & 0xFFFF);
            name_lc.contains(&needle) || state_lc.contains(&needle) || tid_s.contains(&needle)
        })
        .collect();

    out.sort_by(|a, b| {
        let ord = match app.sort_col {
            SortCol::State => a
                .state
                .cmp(&b.state)
                .then_with(|| b.kind.cmp(&a.kind))
                .then_with(|| a.task_id.cmp(&b.task_id)),
            SortCol::TaskId => a.task_id.cmp(&b.task_id),
            SortCol::Cpu => a.cpu.cmp(&b.cpu).then_with(|| a.state.cmp(&b.state)),
            SortCol::Domain => b.kind.cmp(&a.kind).then_with(|| a.state.cmp(&b.state)),
            SortCol::Policy => b.policy.cmp(&a.policy).then_with(|| a.state.cmp(&b.state)),
            SortCol::Weight => b
                .weight
                .cmp(&a.weight)
                .then_with(|| a.task_id.cmp(&b.task_id)),
            SortCol::Name => a
                .name_str()
                .cmp(b.name_str())
                .then_with(|| a.task_id.cmp(&b.task_id)),
        };
        if app.sort_desc {
            match ord {
                Ordering::Less => Ordering::Greater,
                Ordering::Greater => Ordering::Less,
                Ordering::Equal => Ordering::Equal,
            }
        } else {
            ord
        }
    });
    out
}

fn render_dashboard(
    fb: &mut FrameBuffer,
    app: &MonitorApp,
    snapshot: &Snapshot,
    rates: &Rates,
    all_tasks: &[TaskRecord],
    tasks: &[TaskRecord],
) {
    let cols = fb.cols();
    let rows = fb.rows();

    // 1. Row 1: Top application title bar (contains "HuesOS monitor" for smoke gate)
    let uptime_ticks = libcanvas::system::monotonic_ticks().unwrap_or_else(|_| snapshot.ticks());
    let uptime_str = format_uptime(uptime_ticks);
    let mode_pill = if app.paused {
        format!(
            "{}{}{}[ PAUSED ]{}",
            bg_rgb(88, 62, 18),
            fg_rgb(255, 215, 110),
            ansi::BOLD,
            ansi::RESET
        )
    } else {
        format!(
            "{}{}{}[ LIVE {}.{:02}s ]{}",
            bg_rgb(18, 64, 54),
            fg_rgb(110, 245, 190),
            ansi::BOLD,
            app.interval_ms / 1000,
            (app.interval_ms % 1000) / 10,
            ansi::RESET
        )
    };
    let filter_pill = if app.editing_filter {
        format!(
            "  {}FILTER: /{}_ {}",
            fg_rgb(255, 210, 100),
            app.filter,
            ansi::RESET
        )
    } else if !app.filter.is_empty() {
        format!(
            "  {}filter='{}'{}",
            fg_rgb(95, 222, 245),
            app.filter,
            ansi::RESET
        )
    } else {
        String::new()
    };

    let left_hdr = format!(
        " {}{}HuesOS monitor{} {}// btop{}   {}{}{} online CPU(s)   {}uptime {}{}{}",
        fg_rgb(110, 245, 195),
        ansi::BOLD,
        ansi::RESET,
        fg_rgb(120, 145, 180),
        ansi::RESET,
        fg_rgb(235, 244, 255),
        snapshot.summary.cpu_count,
        ansi::RESET,
        fg_rgb(150, 175, 208),
        fg_rgb(95, 222, 245),
        uptime_str,
        filter_pill
    );
    let right_hdr = format!(
        "sort:{}{}{} {} ",
        fg_rgb(250, 202, 96),
        app.sort_col.label(),
        if app.sort_desc { "▼" } else { "" },
        mode_pill
    );
    // Note: avoid `▼` (not in font6x13)! Use ASCII `v`/`^`!
    let _ = right_hdr;
    let right_hdr_safe = format!(
        "{}sort:{} {}{}{}  {} ",
        fg_rgb(140, 162, 192),
        ansi::RESET,
        fg_rgb(250, 202, 96),
        app.sort_col.label(),
        if app.sort_desc { "-" } else { "+" },
        mode_pill
    );
    fb.put_bar_row(1, BG_HEADER, &join_lr(&left_hdr, &right_hdr_safe, cols));

    let mut cur_row = 2usize;

    // 2. CPU & Scheduler Box
    let cpu_show = snapshot.cpus.len().clamp(1, 8);
    let cpu_box_rows = 2 + 2 + cpu_show + 2; // top + 2 sparklines + cpus + rule + rates + bottom
    let ctxt_s = rates.per_second(rates.context_switches);
    let wake_s = rates.per_second(rates.remote_wakes);
    let ipi_s = rates.per_second(rates.resched_ipis);
    let inbox_s = rates.per_second(rates.inbox_drains);

    let cpu_title = format!(
        "CPU & CBS Scheduler  [admitted {} | runq {} | total tasks {}]",
        format_ppm(snapshot.summary.admitted_ppm),
        snapshot.runnable(),
        snapshot.tasks()
    );
    fb.put_row(cur_row, &box_top(&cpu_title, cols, FG_BORDER_HI, FG_TITLE));
    cur_row += 1;

    // Sparkline 1: Core Activity / Admitted Load %
    let graph_w = cols.saturating_sub(44).clamp(16, 120);
    let load_tail = pad_history_left(&app.load_hist, graph_w * 2);
    let load_braille = tui::braille_history(&load_tail, 100);
    let latest_load = app.load_hist.last().copied().unwrap_or(0);
    let load_col = load_gradient(latest_load);
    let spark_row_1 = format!(
        " {}Activity{}  {}{}{}  {}{:>3}%{}  {}ctxt total:{} {}{}{}",
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
        fg_rgb(load_col.0, load_col.1, load_col.2),
        load_braille,
        ansi::RESET,
        fg_rgb(load_col.0, load_col.1, load_col.2),
        latest_load,
        ansi::RESET,
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
        fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
        tui::human_count(snapshot.summary.context_switches),
        ansi::RESET,
    );
    fb.put_row(cur_row, &box_line(&spark_row_1, cols, FG_BORDER_HI));
    cur_row += 1;

    // Sparkline 2: Context Switches / sec
    let ctxt_tail = pad_history_left(&app.ctxt_hist, graph_w * 2);
    let ctxt_braille = tui::braille_history(&ctxt_tail, app.peak_ctxt_s.max(10));
    let spark_row_2 = format!(
        " {}Switch/s{}  {}{}{}  {}{:>6}/s{}  {}peak:{} {}{}/s{}",
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
        fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
        ctxt_braille,
        ansi::RESET,
        fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
        tui::human_count(ctxt_s),
        ansi::RESET,
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
        fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
        tui::human_count(app.peak_ctxt_s),
        ansi::RESET,
    );
    fb.put_row(cur_row, &box_line(&spark_row_2, cols, FG_BORDER_HI));
    cur_row += 1;

    // Per-CPU meters
    let meter_w = cols.saturating_sub(82).clamp(16, 68);
    for record in snapshot.cpus.iter().take(cpu_show) {
        let active_name = if record.current_task == 0 {
            String::from("idle")
        } else {
            find_task_name(all_tasks, record.current_task)
        };
        let is_busy = !cpu_is_idle(all_tasks, record.current_task) || record.runnable > 0;
        let ppm_pct = u64::from(record.admitted_ppm / 10_000);
        // Show honest visual bar combining CBS reservation and live core occupancy.
        let visual_units = if record.admitted_ppm > 0 {
            u64::from(record.admitted_ppm).min(1_000_000)
        } else if is_busy {
            (180_000 + u64::from(record.runnable) * 160_000).min(1_000_000)
        } else {
            0
        };
        let fill_color = load_gradient((visual_units / 10_000).max(ppm_pct));
        let bar = tui::smooth_bar(visual_units, 1_000_000, meter_w, fill_color, FG_TRACK);

        let badge = if record.online == 0 {
            format!(
                "{}OFFLINE{}",
                fg_rgb(FG_CORAL.0, FG_CORAL.1, FG_CORAL.2),
                ansi::RESET
            )
        } else if is_busy {
            format!(
                "{}ACTIVE {}",
                fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                ansi::RESET
            )
        } else {
            format!(
                "{}IDLE   {}",
                fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
                ansi::RESET
            )
        };
        let name_col = if is_busy { FG_CYAN } else { FG_MUTED };

        let cpu_line = format!(
            " {}CPU{:<2}{} [{}] {}cbs{} {:>3}.{:02}%  {}runq{} {:>2}  {}owned{} {:>3}  {}ticks{} {:>7}  {}  {}{}{}",
            fg_rgb(FG_BLUE.0, FG_BLUE.1, FG_BLUE.2),
            record.cpu,
            ansi::RESET,
            bar,
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            record.admitted_ppm / 10_000,
            (record.admitted_ppm % 10_000) / 100,
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            record.runnable,
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            record.tasks,
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            tui::human_count(record.ticks),
            badge,
            fg_rgb(name_col.0, name_col.1, name_col.2),
            tui::fit(&active_name, 16),
            ansi::RESET,
        );
        fb.put_row(cur_row, &box_line(&cpu_line, cols, FG_BORDER_HI));
        cur_row += 1;
    }

    fb.put_row(cur_row, &box_rule(cols, FG_BORDER));
    cur_row += 1;

    let rates_line = format!(
        " {}ctxt/s{} {:>7}   {}wakes/s{} {:>7}   {}ipi/s{} {:>6}   {}inbox/s{} {:>6}   {}dticks{} {:>6}   {}remote wakes{} {:>7}   {}ipis{} {:>7}   {}irq storms{} {}",
        fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
        ansi::RESET,
        ctxt_s,
        fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
        ansi::RESET,
        wake_s,
        fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
        ansi::RESET,
        ipi_s,
        fg_rgb(FG_VIOLET.0, FG_VIOLET.1, FG_VIOLET.2),
        ansi::RESET,
        inbox_s,
        fg_rgb(FG_BLUE.0, FG_BLUE.1, FG_BLUE.2),
        ansi::RESET,
        tui::human_count(rates.ticks),
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
        tui::human_count(snapshot.summary.remote_wakes),
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
        tui::human_count(snapshot.summary.resched_ipis),
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
        if snapshot.summary.irq_storm_masks == 0 {
            format!("{}0{}", fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2), ansi::RESET)
        } else {
            format!(
                "{}{}{}",
                fg_rgb(FG_CORAL.0, FG_CORAL.1, FG_CORAL.2),
                snapshot.summary.irq_storm_masks,
                ansi::RESET
            )
        }
    );
    fb.put_row(cur_row, &box_line(&rates_line, cols, FG_BORDER_HI));
    cur_row += 1;

    fb.put_row(cur_row, &box_bottom(cols, FG_BORDER_HI));
    cur_row += 1;
    let _ = cpu_box_rows;

    // 3. Optional middle dual boxes (Storage HxFS + System/Services) when rows >= 34
    if rows.saturating_sub(cur_row) >= 18 {
        let left_w = cols / 2;
        let right_w = cols - left_w;
        let storage_lines = build_storage_box(app.fs_stats.as_ref(), left_w);
        let summary_lines = build_summary_box(all_tasks, &app.services, right_w);
        for (l, r) in storage_lines.iter().zip(summary_lines.iter()) {
            if cur_row >= rows.saturating_sub(8) {
                break;
            }
            fb.put_row(cur_row, &format!("{l}{r}"));
            cur_row += 1;
        }
    }

    // 4. Expanding Tasks & Processes Box down to `rows - 1` (row `rows` = hotkey bar)
    let footer_row = rows;
    let task_bottom_row = footer_row.saturating_sub(1);
    if cur_row + 5 <= task_bottom_row {
        render_tasks_box(
            fb,
            cur_row,
            task_bottom_row,
            cols,
            app,
            snapshot,
            all_tasks,
            tasks,
        );
    }

    // 5. Bottom interactive hotkey bar on `footer_row`
    let footer_w = fb.safe_cols(footer_row);
    let footer_text = if app.editing_filter {
        format!(
            " {}[FILTER]{} Type query: {}/{}{}   {}Enter/Esc{} done   {}Backspace{} erase   {}^U{} clear",
            fg_rgb(250, 202, 96),
            ansi::RESET,
            fg_rgb(110, 245, 195),
            app.filter,
            ansi::RESET,
            fg_rgb(95, 222, 245),
            ansi::RESET,
            fg_rgb(95, 222, 245),
            ansi::RESET,
            fg_rgb(95, 222, 245),
            ansi::RESET,
        )
    } else {
        format!(
            " {} quit  {} pause  {} refresh  {} speed  {} select  {} sort  {} order  {} filter  {} {}  {} help{}",
            key_badge("q"),
            key_badge("spc"),
            key_badge("r"),
            key_badge("+/-"),
            key_badge("j/k"),
            key_badge("s/<-/->"),
            key_badge("v"),
            key_badge("/"),
            key_badge("u"),
            if app.user_only { "all-rings" } else { "user-only" },
            key_badge("?"),
            ansi::RESET,
        )
    };
    let _ = footer_w;
    fb.put_bar_row(footer_row, BG_FOOTER, &footer_text);

    // 6. Optional centered Help overlay modal
    if app.show_help {
        render_help_overlay(fb);
    }
}

fn build_storage_box(stats: Option<&HxfsStatFsInfo>, width: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(6);
    out.push(box_top("HxFS v7 Storage Volume", width, FG_BORDER, FG_CYAN));
    if let Some(st) = stats {
        let total_b = st.total_blocks.saturating_mul(st.block_size);
        let used_b = st.used_blocks.saturating_mul(st.block_size);
        let avail_b = st.avail_blocks.saturating_mul(st.block_size);
        let bar_w = width.saturating_sub(36).clamp(10, 44);
        let pct = (st.used_blocks.saturating_mul(100))
            .checked_div(st.total_blocks.max(1))
            .unwrap_or(0);
        let col = load_gradient(pct);
        let bar = tui::smooth_bar(st.used_blocks, st.total_blocks.max(1), bar_w, col, FG_TRACK);

        let obj_bar_w = width.saturating_sub(36).clamp(10, 44);
        let obj_pct = (st.used_objects.saturating_mul(100))
            .checked_div(st.total_objects.max(1))
            .unwrap_or(0);
        let obj_bar = tui::smooth_bar(
            st.used_objects,
            st.total_objects.max(1),
            obj_bar_w,
            FG_VIOLET,
            FG_TRACK,
        );

        out.push(box_line(
            &format!(
                " {}Blocks{}  [{}] {:>3}%  {}/{}",
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET,
                bar,
                pct,
                tui::human_bytes(used_b),
                tui::human_bytes(total_b)
            ),
            width,
            FG_BORDER,
        ));
        out.push(box_line(
            &format!(
                " {}Objects{} [{}] {:>3}%  {}/{}",
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET,
                obj_bar,
                obj_pct,
                st.used_objects,
                st.total_objects
            ),
            width,
            FG_BORDER,
        ));
        out.push(box_line(
            &format!(
                " {}Free:{} {}{}{}   {}BlkSize:{} {}B   {}Chkpt:{} #{}   {}Fmt:{} v{}",
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET,
                fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
                tui::human_bytes(avail_b),
                ansi::RESET,
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET,
                st.block_size,
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET,
                st.checkpoint_seq,
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET,
                st.format_version,
            ),
            width,
            FG_BORDER,
        ));
        out.push(box_line(
            &format!(
                " {}Status:{} {}MOUNTED COW SNAPSHOT ENGINE{}",
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET,
                fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
                ansi::RESET
            ),
            width,
            FG_BORDER,
        ));
    } else {
        out.push(box_line(
            &format!(
                " {}No mounted HxFS volume (ramdisk / BOOTFS session){}",
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET
            ),
            width,
            FG_BORDER,
        ));
        out.push(box_line(
            &format!(
                " {}Root binaries served from signed HBOOTFS1 VMO{}",
                fg_rgb(FG_BLUE.0, FG_BLUE.1, FG_BLUE.2),
                ansi::RESET
            ),
            width,
            FG_BORDER,
        ));
        out.push(box_line("", width, FG_BORDER));
        out.push(box_line("", width, FG_BORDER));
    }
    out.push(box_bottom(width, FG_BORDER));
    out
}

fn build_summary_box(
    all_tasks: &[TaskRecord],
    services: &[ServiceRow],
    width: usize,
) -> Vec<String> {
    let (mut running, mut ready, mut blocked, mut finished) = (0u32, 0u32, 0u32, 0u32);
    let (mut user_cnt, mut kern_cnt, mut dl_cnt) = (0u32, 0u32, 0u32);
    for t in all_tasks {
        match t.state {
            0 => running += 1,
            1 => ready += 1,
            2 => blocked += 1,
            _ => finished += 1,
        }
        if t.kind == 1 {
            user_cnt += 1;
        } else {
            kern_cnt += 1;
        }
        if t.policy == 1 {
            dl_cnt += 1;
        }
    }

    let mut out = Vec::with_capacity(6);
    out.push(box_top(
        "Kernel Domains & Supervised Services",
        width,
        FG_BORDER,
        FG_VIOLET,
    ));
    out.push(box_line(
        &format!(
            " {}States:{} {}run {}   {}rdy {}   {}blk {}   {}fin {}{}",
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
            running,
            fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
            ready,
            fg_rgb(FG_BLUE.0, FG_BLUE.1, FG_BLUE.2),
            blocked,
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            finished,
            ansi::RESET,
        ),
        width,
        FG_BORDER,
    ));
    out.push(box_line(
        &format!(
            " {}Domains:{} {}user {}   {}kernel {}   {}deadline CBS {}{}",
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
            user_cnt,
            fg_rgb(FG_VIOLET.0, FG_VIOLET.1, FG_VIOLET.2),
            kern_cnt,
            fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
            dl_cnt,
            ansi::RESET,
        ),
        width,
        FG_BORDER,
    ));

    if services.is_empty() {
        out.push(box_line(
            &format!(
                " {}Supervisor:{} capability-isolated userspace active",
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET
            ),
            width,
            FG_BORDER,
        ));
        out.push(box_line("", width, FG_BORDER));
    } else {
        let mut line1 = String::from(" ");
        let mut line2 = String::from(" ");
        for (idx, svc) in services.iter().take(6).enumerate() {
            let dot_col = if svc.state == "online" {
                FG_MINT
            } else {
                FG_AMBER
            };
            let chip = format!(
                "{}█{} {}{} ",
                fg_rgb(dot_col.0, dot_col.1, dot_col.2),
                fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
                svc.name,
                if svc.restarts != "0" {
                    format!("(r:{})", svc.restarts)
                } else {
                    String::new()
                }
            );
            if idx < 3 {
                line1.push_str(&chip);
            } else {
                line2.push_str(&chip);
            }
        }
        out.push(box_line(&line1, width, FG_BORDER));
        out.push(box_line(&line2, width, FG_BORDER));
    }
    out.push(box_bottom(width, FG_BORDER));
    out
}

#[allow(clippy::too_many_arguments)]
fn render_tasks_box(
    fb: &mut FrameBuffer,
    top_row: usize,
    bottom_row: usize,
    cols: usize,
    app: &MonitorApp,
    snapshot: &Snapshot,
    all_tasks: &[TaskRecord],
    tasks: &[TaskRecord],
) {
    let scope = if app.user_only { "user-space" } else { "all" };
    let title = format!(
        "Tasks & Threads  [{}/{} shown | scope: {} | sort: {}]",
        tasks.len(),
        all_tasks.len(),
        scope,
        app.sort_col.label()
    );
    fb.put_row(top_row, &box_top(&title, cols, FG_BORDER_HI, FG_TITLE));

    // Column header row (matches exact data row column widths below)
    let hdr = format!(
        "   {}{:<6} {:>6} {:>10}  {:<5} {:<8} {:<9} {:>7}  {:<22}  {}CORE AFFINITY / ACTIVITY{}",
        ansi::BOLD,
        col_hdr("TID", 6, false, SortCol::TaskId, app.sort_col),
        col_hdr("GEN", 6, true, SortCol::TaskId, SortCol::Name),
        col_hdr("STATE", 10, true, SortCol::State, app.sort_col),
        col_hdr("CPU", 5, false, SortCol::Cpu, app.sort_col),
        col_hdr("DOMAIN", 8, false, SortCol::Domain, app.sort_col),
        col_hdr("POLICY", 9, false, SortCol::Policy, app.sort_col),
        col_hdr("WEIGHT", 7, true, SortCol::Weight, app.sort_col),
        col_hdr("TASK NAME", 22, false, SortCol::Name, app.sort_col),
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
    );
    fb.put_row(top_row + 1, &box_line(&hdr, cols, FG_BORDER_HI));
    fb.put_row(top_row + 2, &box_rule(cols, FG_BORDER));

    // Reserve bottom 3 rows of task box for rule + selected task inspector + bottom border
    let inspector_rule_row = bottom_row.saturating_sub(2);
    let inspector_row = bottom_row.saturating_sub(1);
    let list_start_row = top_row + 3;
    let list_rows = inspector_rule_row.saturating_sub(list_start_row);

    let scroll_top = if list_rows == 0 || app.selected < list_rows {
        0
    } else {
        app.selected + 1 - list_rows
    };

    for idx in 0..list_rows {
        let r = list_start_row + idx;
        if let Some(task) = tasks.get(scroll_top + idx) {
            let is_sel = scroll_top + idx == app.selected;
            let slot = task.task_id & 0xFFFF_FFFF;
            let gen = task.task_id >> 32;
            let (st_lbl, st_col) = state_badge(task.state);
            let dom_lbl = if task.kind == 1 { "user" } else { "kernel" };
            let dom_col = if task.kind == 1 { FG_CYAN } else { FG_VIOLET };
            let pol_lbl = if task.policy == 1 { "deadline" } else { "fair" };
            let pol_col = if task.policy == 1 { FG_AMBER } else { FG_TEXT };
            let on_cpu_now = snapshot
                .cpus
                .iter()
                .any(|c| c.current_task == task.task_id && task.task_id != 0);
            let activity = if on_cpu_now {
                format!("█ executing on CPU{}", task.cpu)
            } else if task.state == 1 {
                format!("▒ queued on CPU{} runq", task.cpu)
            } else if task.state == 2 {
                format!("░ parked / waiting (CPU{})", task.cpu)
            } else {
                String::from("· exited")
            };

            if is_sel {
                let plain = format!(
                    " > {:<6} {:>6} {:>10}  CPU{:<2} {:<8} {:<9} {:>7}  {:<22}  {}",
                    slot,
                    gen,
                    st_lbl,
                    task.cpu,
                    dom_lbl,
                    pol_lbl,
                    task.weight,
                    tui::fit(task.name_str(), 22),
                    activity
                );
                let highlighted = tui::fit_with_bg(
                    &format!("{}{}{}", fg_rgb(255, 255, 255), ansi::BOLD, plain),
                    cols.saturating_sub(2),
                    BG_SELECT,
                );
                let border = fg_rgb(FG_BORDER_HI.0, FG_BORDER_HI.1, FG_BORDER_HI.2);
                fb.put_row(
                    r,
                    &format!(
                        "{border}│{}{highlighted}{border}│{}",
                        ansi::RESET,
                        ansi::RESET
                    ),
                );
            } else {
                let row_str = format!(
                    "   {}{:<6}{} {}{:>6}{} {}{:>10}{}  {}CPU{:<2}{} {}{:<8}{} {}{:<9}{} {}{:>7}{}  {}{:<22}{}  {}{}{}",
                    fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
                    slot,
                    ansi::RESET,
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                    gen,
                    ansi::RESET,
                    fg_rgb(st_col.0, st_col.1, st_col.2),
                    st_lbl,
                    ansi::RESET,
                    fg_rgb(FG_BLUE.0, FG_BLUE.1, FG_BLUE.2),
                    task.cpu,
                    ansi::RESET,
                    fg_rgb(dom_col.0, dom_col.1, dom_col.2),
                    dom_lbl,
                    ansi::RESET,
                    fg_rgb(pol_col.0, pol_col.1, pol_col.2),
                    pol_lbl,
                    ansi::RESET,
                    fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
                    task.weight,
                    ansi::RESET,
                    fg_rgb(235, 243, 255),
                    tui::fit(task.name_str(), 22),
                    ansi::RESET,
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                    activity,
                    ansi::RESET,
                );
                fb.put_row(r, &box_line(&row_str, cols, FG_BORDER_HI));
            }
        } else {
            fb.put_row(r, &box_line("", cols, FG_BORDER_HI));
        }
    }

    fb.put_row(inspector_rule_row, &box_rule(cols, FG_BORDER));
    let inspector_txt = if let Some(sel) = tasks.get(app.selected) {
        let slot = sel.task_id & 0xFFFF_FFFF;
        let gen = sel.task_id >> 32;
        format!(
            " {}Selected:{} {}{}{}   {}raw_id:{} 0x{:016x} (slot {}, gen {})   {}ring:{} {}   {}sched:{} {} (weight {})   {}state:{} {}",
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            fg_rgb(FG_TITLE.0, FG_TITLE.1, FG_TITLE.2),
            sel.name_str(),
            ansi::RESET,
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            sel.task_id,
            slot,
            gen,
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            if sel.kind == 1 { "ring3-user" } else { "ring0-kernel" },
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            if sel.policy == 1 { "CBS-deadline" } else { "EEVDF-fair" },
            sel.weight,
            fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
            ansi::RESET,
            state_label(sel.state),
        )
    } else {
        format!(
            " {}No tasks match current filter ('c' or Esc to clear){}",
            fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
            ansi::RESET
        )
    };
    fb.put_row(inspector_row, &box_line(&inspector_txt, cols, FG_BORDER_HI));
    fb.put_row(bottom_row, &box_bottom(cols, FG_BORDER_HI));
}

fn render_help_overlay(fb: &mut FrameBuffer) {
    let w = 78usize.min(fb.cols().saturating_sub(4));
    let lines = [
        " Navigation & Selection",
        "   Up / Down, j / k       Move task cursor one row",
        "   PgUp / PgDn, Home/End  Jump 12 rows or to top / bottom",
        "",
        " Sorting & Filtering",
        "   s, Left / Right        Cycle sort column (STATE, TID, CPU, RING, ...)",
        "   v                      Invert ascending / descending sort order",
        "   / or f                 Filter tasks live by name, state, or TID",
        "   c or Esc               Clear active filter",
        "   u                      Toggle user-space tasks only vs all tasks",
        "",
        " Sampling & Control",
        "   Space                  Freeze / resume live telemetry sampling",
        "   + / -                  Adjust refresh cadence (250 ms .. 5000 ms)",
        "   r                      Force immediate counter + service refresh",
        "   q / Esc / ^C           Exit btop cleanly",
        "",
        "                 Press any key to close this overlay",
    ];
    let h = lines.len() + 2;
    let start_r = (fb.rows().saturating_sub(h)) / 2 + 1;
    let start_c = (fb.cols().saturating_sub(w)) / 2 + 1;

    fb.put_at(
        start_r,
        start_c,
        &tui::fit_with_bg(
            &box_top("btop Interactive Controls", w, FG_CYAN, FG_TITLE),
            w,
            BG_MODAL,
        ),
    );
    for (i, line) in lines.iter().enumerate() {
        let styled = format!(
            "{}│{}{}{}│{}",
            fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
            fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
            tui::fit(line, w.saturating_sub(2)),
            fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
            ansi::RESET
        );
        fb.put_at(
            start_r + 1 + i,
            start_c,
            &tui::fit_with_bg(&styled, w, BG_MODAL),
        );
    }
    fb.put_at(
        start_r + 1 + lines.len(),
        start_c,
        &tui::fit_with_bg(&box_bottom(w, FG_CYAN), w, BG_MODAL),
    );
}

fn col_hdr(label: &str, width: usize, right_align: bool, col: SortCol, active: SortCol) -> String {
    let raw = if col == active {
        format!("{label}*")
    } else {
        String::from(label)
    };
    let padded = if right_align {
        tui::fit_right(&raw, width)
    } else {
        tui::fit(&raw, width)
    };
    if col == active {
        format!(
            "{}{padded}{}",
            fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
            fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2)
        )
    } else {
        padded
    }
}

fn cpu_is_idle(tasks: &[TaskRecord], task_id: u64) -> bool {
    if task_id == 0 {
        return true;
    }
    tasks
        .iter()
        .find(|t| t.task_id == task_id)
        .is_some_and(|t| t.kind == 0 && t.name_str() == "idle")
}

fn key_badge(k: &str) -> String {
    format!(
        "{}{}{}[{k}]{}{}",
        bg_rgb(32, 45, 68),
        fg_rgb(110, 238, 200),
        ansi::BOLD,
        ansi::RESET,
        fg_rgb(190, 206, 228)
    )
}

fn state_label(state: u8) -> &'static str {
    match state {
        0 => "RUNNING",
        1 => "READY",
        2 => "BLOCKED",
        _ => "FINISHED",
    }
}

fn state_badge(state: u8) -> (&'static str, (u8, u8, u8)) {
    match state {
        0 => ("RUNNING", FG_MINT),
        1 => ("READY", FG_AMBER),
        2 => ("BLOCKED", FG_BLUE),
        _ => ("FINISHED", FG_MUTED),
    }
}

fn find_task_name(tasks: &[TaskRecord], task_id: u64) -> String {
    tasks
        .iter()
        .find(|t| t.task_id == task_id)
        .map(|t| String::from(t.name_str()))
        .unwrap_or_else(|| format!("task#{:x}", task_id & 0xFFFF))
}

fn pad_history_left(samples: &[u64], wanted: usize) -> Vec<u64> {
    if samples.len() >= wanted {
        samples[samples.len() - wanted..].to_vec()
    } else {
        let mut out = alloc::vec![0u64; wanted - samples.len()];
        out.extend_from_slice(samples);
        out
    }
}

fn load_gradient(pct: u64) -> (u8, u8, u8) {
    match pct {
        0..=34 => FG_MINT,
        35..=64 => FG_CYAN,
        65..=84 => FG_AMBER,
        _ => FG_CORAL,
    }
}

fn format_uptime(ticks_100hz: u64) -> String {
    let total_secs = ticks_100hz / 100;
    let hrs = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    format!("{hrs:02}:{mins:02}:{secs:02}")
}

fn format_ppm(ppm: u64) -> String {
    format!("{}.{:02}%", ppm / 10_000, (ppm % 10_000) / 100)
}

fn join_lr(left: &str, right: &str, width: usize) -> String {
    let lw = tui::visible_width(left);
    let rw = tui::visible_width(right);
    if lw + rw + 1 >= width {
        return tui::fit(left, width);
    }
    let mut out = String::from(left);
    for _ in 0..(width - lw - rw) {
        out.push(' ');
    }
    out.push_str(right);
    out
}

fn box_top(title: &str, width: usize, border: (u8, u8, u8), title_col: (u8, u8, u8)) -> String {
    let inner = width.saturating_sub(2);
    let b_seq = fg_rgb(border.0, border.1, border.2);
    let t_seq = fg_rgb(title_col.0, title_col.1, title_col.2);
    if title.trim().is_empty() || inner < 6 {
        let mut s = format!("{b_seq}┌");
        for _ in 0..inner {
            s.push('─');
        }
        s.push('┐');
        s.push_str(ansi::RESET);
        return s;
    }
    let clean = title.trim();
    let max_title = inner.saturating_sub(4);
    let shown: String = clean.chars().take(max_title).collect();
    let shown_len = shown.chars().count();
    let dashes = inner.saturating_sub(shown_len + 3);
    let mut s = format!("{b_seq}┌─ {t_seq}{}{shown}{b_seq} ", ansi::BOLD);
    for _ in 0..dashes {
        s.push('─');
    }
    s.push('┐');
    s.push_str(ansi::RESET);
    s
}

fn box_rule(width: usize, border: (u8, u8, u8)) -> String {
    let mut s = format!("{}├", fg_rgb(border.0, border.1, border.2));
    for _ in 0..width.saturating_sub(2) {
        s.push('─');
    }
    s.push('┤');
    s.push_str(ansi::RESET);
    s
}

fn box_bottom(width: usize, border: (u8, u8, u8)) -> String {
    let mut s = format!("{}└", fg_rgb(border.0, border.1, border.2));
    for _ in 0..width.saturating_sub(2) {
        s.push('─');
    }
    s.push('┘');
    s.push_str(ansi::RESET);
    s
}

fn box_line(body: &str, width: usize, border: (u8, u8, u8)) -> String {
    let b_seq = fg_rgb(border.0, border.1, border.2);
    let fitted = tui::fit(body, width.saturating_sub(2));
    format!("{b_seq}│{}{fitted}{b_seq}│{}", ansi::RESET, ansi::RESET)
}
