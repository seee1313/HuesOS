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
use alloc::string::String;

use huesos_coreutils as cu;
use huesos_coreutils::disk::{self, human_size};

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
    for arg in args.iter() {
        match arg.as_str() {
            "-h" | "--human-readable" => human = true,
            "-a" | "--all" => wide = true,
            "-H" | "--si" => human = true,
            "--help" => {
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

    // Usage: the sizes the filesystem reports with its listings, added up.
    // A sandbox without the handle cannot answer -- which is a fact about this
    // process, not a failure of the volume, so it becomes a `-` column.
    let used = match huesos_std::fs::used_bytes(mount) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            cu::errln(&format!(
                "df: {mount}: {error} (service={} directory={})",
                huesos_std::fs::service().is_some(),
                huesos_std::fs::directory().is_some()
            ));
            None
        }
    };

    // Capacity: the granted block device is the store the filesystem lives in,
    // it needs no broker, and it is what `fdisk`/`lsblk` already read.
    let capacity = disk::DiskIo::open(None, false)
        .ok()
        .map(|io| io.capacity_bytes())
        .filter(|bytes| *bytes > 0);

    if used.is_none() && capacity.is_none() {
        cu::errln("df: no filesystem and no block device to report on");
        return 1;
    }

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

    let percent = match (used, capacity) {
        (Some(used), Some(capacity)) => Some(((used.saturating_mul(100)) / capacity).min(100)),
        _ => None,
    };
    let number = |bytes: Option<u64>| -> String {
        match bytes {
            Some(bytes) if human => human_size(bytes),
            Some(bytes) => format!("{}", bytes / BLOCK),
            None => String::from("-"),
        }
    };
    let available = match (used, capacity) {
        (Some(used), Some(capacity)) => Some(capacity.saturating_sub(used)),
        _ => None,
    };
    let percent_text = match percent {
        Some(percent) => format!("{percent}%"),
        None => String::from("-"),
    };

    if human {
        cu::outln(&format!(
            "{:<12} {:>8} {:>8} {:>8} {:>4}  {mount}",
            "hxfs",
            number(capacity),
            number(used),
            number(available),
            percent_text
        ));
    } else {
        cu::outln(&format!(
            "{:<12} {:>10} {:>10} {:>10} {:>4}  {mount}",
            "hxfs",
            number(capacity),
            number(used),
            number(available),
            percent_text
        ));
    }
    if let (Some(percent), Some(capacity)) = (percent, capacity) {
        cu::outln(&format!(
            "[{}] {percent}% of {}",
            fill_bar(percent),
            human_size(capacity)
        ));
    }

    if wide {
        // The service exposes usage and capacity; quotas and the checkpoint
        // sequence number are not part of its query surface, so the line says
        // so instead of inventing a number.
        cu::outln(&format!(
            "block_size={BLOCK} blocks_used={} blocks_total={}",
            number(used),
            number(capacity)
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
