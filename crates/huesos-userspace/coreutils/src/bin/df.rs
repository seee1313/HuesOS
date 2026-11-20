//! `/bin/df.elf` — free space on the mounted HxFS volume.
//!
//! `df [-h] [-a] [<path>]`
//!
//! Without `-h` the numbers are in 4 KiB blocks, the unit the filesystem's
//! allocator actually works in; `-h` prints the same numbers scaled. The
//! fill bar, the `Use%` column and the checkpoint state are all derived from
//! the service's own counters — `df` never guesses usage from file sizes,
//! because the volume's free-block map is the authority.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;

use huesos_coreutils as cu;
use huesos_coreutils::disk::human_size;

cu::coreutil_entry!(run);

/// Bytes in one `df` block.
const BLOCK: u64 = 4096;
/// Width of the fill bar.
const BAR_WIDTH: usize = 32;

fn run() -> i32 {
    let args = cu::collect_args();
    let mut human = false;
    let mut wide = false;
    let mut path: Option<&str> = None;
    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-h" | "--human-readable" => human = true,
            "-a" | "--all" => wide = true,
            "-H" | "--si" => human = true,
            "-h--help" | "--help" => {
                cu::outln("usage: df [-h] [-a] [<path>]");
                cu::outln("  -h  powers of 1024 instead of 4 KiB blocks");
                cu::outln("  -a  also print the checkpoint and quota lines");
                return 0;
            }
            other if other.starts_with('-') => {
                cu::errln(&format!("df: unknown option '{other}'"));
                return 2;
            }
            other => path = Some(other),
        }
    }

    let (used, capacity) = match huesos_std::fs::volume_bytes() {
        Ok(values) => values,
        Err(error) => {
            cu::errln(&format!("df: no filesystem: {error}"));
            return 1;
        }
    };
    if capacity == 0 {
        cu::errln("df: the volume reports zero capacity");
        return 1;
    }
    let available = capacity.saturating_sub(used);
    let percent = ((used.saturating_mul(100)) / capacity).min(100);
    let mount = path.unwrap_or("/");

    if human {
        cu::outln(&format!(
            "{:<12} {:>8} {:>8} {:>8} {:>4}  Mounted on",
            "Filesystem", "Size", "Used", "Avail", "Use%"
        ));
        cu::outln(&format!(
            "{:<12} {:>8} {:>8} {:>8} {:>3}%  {mount}",
            "hxfs",
            human_size(capacity),
            human_size(used),
            human_size(available),
            percent
        ));
    } else {
        cu::outln(&format!(
            "{:<12} {:>10} {:>10} {:>10} {:>4}  Mounted on",
            "Filesystem", "4K-blocks", "Used", "Available", "Use%"
        ));
        cu::outln(&format!(
            "{:<12} {:>10} {:>10} {:>10} {:>3}%  {mount}",
            "hxfs",
            capacity / BLOCK,
            used / BLOCK,
            available / BLOCK,
            percent
        ));
    }
    cu::outln(&format!(
        "[{}] {percent}% of {}",
        fill_bar(percent),
        human_size(capacity)
    ));

    if wide {
        // The service exposes usage and capacity; quotas and the checkpoint
        // sequence number are not part of its query surface, so the line says
        // so instead of inventing a number.
        cu::outln(&format!(
            "block_size={BLOCK} blocks_total={} blocks_used={} blocks_free={}",
            capacity / BLOCK,
            used / BLOCK,
            available / BLOCK
        ));
        match huesos_std::fs::service() {
            Some(service) => match service.volume_info() {
                Ok((reported_used, reported_capacity)) => cu::outln(&format!(
                    "hxfs_volume_info used={reported_used} capacity={reported_capacity} \
                     epoch=not-exposed checkpoint=not-exposed quota=none"
                )),
                Err(error) => cu::outln(&format!("hxfs_volume_info error={error:?}")),
            },
            None => cu::outln("hxfs_volume_info unavailable (scoped capability only)"),
        }
    }
    0
}

/// `####........` fill bar for `percent`.
fn fill_bar(percent: u64) -> alloc::string::String {
    let filled = ((percent as usize) * BAR_WIDTH) / 100;
    let mut bar = alloc::string::String::with_capacity(BAR_WIDTH);
    for index in 0..BAR_WIDTH {
        bar.push(if index < filled { '#' } else { '.' });
    }
    bar
}
