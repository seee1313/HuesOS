//! `/bin/sleep.elf` — suspend the calling process for a number of seconds.
//!
//! Exists so the shell has a *long-running child* to interrupt: `Ctrl-C`
//! handling in `hsh` is only meaningful if a child can outlive the keystroke.
//! Implemented by polling the kernel's 100 Hz monotonic clock with
//! `yield_now()`, which keeps the process fully preemptible (a spin on `hlt`
//! would make the shell's terminate path unobservable).
//!
//! Usage: `sleep <seconds>[.fraction]`

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use huesos_coreutils as cu;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let Some(arg) = args.first() else {
        cu::errln("usage: sleep <seconds>");
        return 2;
    };
    let Some(ticks) = seconds_to_ticks(arg) else {
        cu::errln(&format!("sleep: invalid interval '{arg}'"));
        return 2;
    };
    if ticks == 0 {
        return 0;
    }
    let sleep_word = core::sync::atomic::AtomicU32::new(0);
    let start = match libcanvas::system::monotonic_ticks() {
        Ok(t) => t,
        Err(e) => {
            cu::errln(&format!("sleep: clock unavailable: {}", e.as_str()));
            return 1;
        }
    };
    loop {
        let now = match libcanvas::system::monotonic_ticks() {
            Ok(now) => now,
            Err(e) => {
                cu::errln(&format!("sleep: clock unavailable: {}", e.as_str()));
                return 1;
            }
        };
        let elapsed = now.wrapping_sub(start);
        if elapsed >= ticks {
            return 0;
        }
        let remaining = ticks - elapsed;
        let _ = libcanvas::futex::wait(&sleep_word, 0, remaining);
    }
}

/// Convert `"1"`, `"0.5"` or `"2.25"` into 100 Hz ticks, rounding up so a
/// non-zero interval always waits at least one tick.
fn seconds_to_ticks(text: &str) -> Option<u64> {
    let mut parts = text.splitn(2, '.');
    let whole = parts.next()?.parse::<u64>().ok()?;
    let frac = parts.next().unwrap_or("");
    if !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut hundredths = 0u64;
    let mut scale = 100u64;
    for c in frac.chars().take(2) {
        scale /= 10;
        hundredths += u64::from(c as u8 - b'0') * scale;
    }
    let ticks = whole.saturating_mul(100).saturating_add(hundredths);
    if ticks == 0 && (whole != 0 || hundredths != 0) {
        return Some(1);
    }
    Some(ticks)
}
