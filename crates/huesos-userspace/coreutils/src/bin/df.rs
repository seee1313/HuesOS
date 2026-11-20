//! `/bin/df.elf` — free space on the mounted HxFS volume.
//!
//! `df [-h] [-a] [<path>]`
//!
//! Without `-h` the numbers are in 4 KiB blocks, the unit the filesystem's
//! allocator works in; `-h` prints the same numbers scaled.
//!
//! The two halves of the answer come from different places, because HxFS does
//! not publish a free-block map: the *used* figure is a walk of the tree
//! ([`huesos_std::fs::used_bytes`], one round trip per directory, no per-file
//! stat), and the *capacity* is the block range the `Volume` service owns. A
//! process without the registry channel can still report usage; the size
//! columns then say `-` rather than inventing a number.

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

    let mount = path.unwrap_or("/");
    let used = match huesos_std::fs::used_bytes(mount) {
        Ok(bytes) => bytes,
        Err(error) => {
            cu::errln(&format!("df: {mount}: {error}"));
            return 1;
        }
    };
    let capacity = match huesos_std::fs::capacity_bytes() {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            cu::errln("df: volume service unavailable, reporting usage only");
            None
        }
    };

    if human {
        cu::outln(&format!(
            "{:<12} {:>8} {:>8} {:>8} {:>4}  Mounted on",
            "Filesystem", "Size", "Used", "Avail", "Use%"
        ));
    } else {
        cu::outln(&format!(
            "{:<12} {:>10} {:>10} {:>10} {:>4}  Mounted on",
            "Filesystem", "4K-blocks", "Used", "Available", "Use%"
        ));
    }
    match capacity {
        Some(capacity) if capacity > 0 => {
            let available = capacity.saturating_sub(used);
            let percent = ((used.saturating_mul(100)) / capacity).min(100);
            if human {
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
        }
        _ => {
            // Usage without a denominator: still a useful number, and better
            // than a made-up capacity.
            if human {
                cu::outln(&format!(
                    "{:<12} {:>8} {:>8} {:>8} {:>4}  {mount}",
                    "hxfs",
                    "-",
                    human_size(used),
                    "-",
                    "-"
                ));
            } else {
                cu::outln(&format!(
                    "{:<12} {:>10} {:>10} {:>10} {:>4}  {mount}",
                    "hxfs",
                    "-",
                    used / BLOCK,
                    "-",
                    "-"
                ));
            }
        }
    }

    if wide {
        // The service exposes usage and capacity; quotas and the checkpoint
        // sequence number are not part of its query surface, so the line says
        // so instead of inventing a number.
        cu::outln(&format!(
            "block_size={BLOCK} blocks_used={} blocks_total={}",
            used / BLOCK,
            capacity.map_or(alloc::string::String::from("-"), |bytes| format!(
                "{}",
                bytes / BLOCK
            ))
        ));
        match huesos_std::fs::service() {
            Some(service) => match service.volume_info() {
                // `GetInfo` reports the mounted root object and the checkpoint
                // sequence, not usage: say what it is instead of mislabelling
                // it as a byte count.
                Ok((root_object, checkpoint)) => cu::outln(&format!(
                    "hxfs_root_object={root_object} checkpoint={checkpoint} quota=none"
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
