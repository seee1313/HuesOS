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
    let normalized_mount = cu::normalize_path(mount);
    if huesos_std::usb_fat::split_usb_mount_path(&normalized_mount).is_some() {
        let Some((cap_b, used_b, avail_b, fs_label)) = huesos_std::usb_fat::stat_fs() else {
            cu::errln("df: /mnt/usb0: no FAT volume mounted");
            return 1;
        };
        let number = |bytes: u64| -> String {
            if human {
                human_size(bytes)
            } else {
                format!("{}", bytes / BLOCK)
            }
        };
        let raw_pct = used_b.saturating_mul(100).checked_div(cap_b).unwrap_or(0);
        let pct = raw_pct.min(100);
        if human {
            cu::outln(&format!(
                "{:<12} {:>8} {:>8} {:>8} {:>4}  Mounted on",
                "Filesystem", "Size", "Used", "Avail", "Use%"
            ));
            cu::outln(&format!(
                "{:<12} {:>8} {:>8} {:>8} {:>4}  /mnt/usb0",
                fs_label,
                number(cap_b),
                number(used_b),
                number(avail_b),
                format!("{pct}%")
            ));
        } else {
            cu::outln(&format!(
                "{:<12} {:>10} {:>10} {:>10} {:>4}  Mounted on",
                "Filesystem", "4K-blocks", "Used", "Available", "Use%"
            ));
            cu::outln(&format!(
                "{:<12} {:>10} {:>10} {:>10} {:>4}  /mnt/usb0",
                fs_label,
                number(cap_b),
                number(used_b),
                number(avail_b),
                format!("{pct}%")
            ));
        }
        return 0;
    }

    // Prefer native `StatFs` from `hxfs-service` (accurate physical block
    // allocation, free space, quota, object counts, and checkpoint sequence).
    // Fall back to directory-walk usage + raw block-device capacity when `StatFs`
    // is unavailable.
    let statfs = huesos_std::fs::stat_fs().ok();

    let (used, capacity, avail_override) = if let Some(sf) = statfs {
        let bsize = if sf.block_size == 0 {
            BLOCK
        } else {
            sf.block_size
        };
        let total = if sf.total_blocks > 0 {
            Some(sf.total_blocks.saturating_mul(bsize))
        } else {
            disk::DiskIo::open(None, false)
                .ok()
                .map(|io| io.capacity_bytes())
                .filter(|bytes| *bytes > 0)
        };
        let used_b = Some(sf.used_blocks.saturating_mul(bsize));
        let avail_b = if sf.total_blocks > 0 {
            Some(sf.avail_blocks.saturating_mul(bsize))
        } else {
            total.map(|cap| cap.saturating_sub(sf.used_blocks.saturating_mul(bsize)))
        };
        (used_b, total, avail_b)
    } else {
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
        let capacity = disk::DiskIo::open(None, false)
            .ok()
            .map(|io| io.capacity_bytes())
            .filter(|bytes| *bytes > 0);
        (used, capacity, None)
    };

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
    let available = avail_override.or(match (used, capacity) {
        (Some(used), Some(capacity)) => Some(capacity.saturating_sub(used)),
        _ => None,
    });
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
    if let (None, Some((u_cap, u_used, u_avail, u_kind))) = (path, huesos_std::usb_fat::stat_fs()) {
        let u_raw = u_used.saturating_mul(100).checked_div(u_cap).unwrap_or(0);
        let u_pct = format!("{}%", u_raw.min(100));
        if human {
            cu::outln(&format!(
                "{:<12} {:>8} {:>8} {:>8} {:>4}  /mnt/usb0",
                u_kind,
                number(Some(u_cap)),
                number(Some(u_used)),
                number(Some(u_avail)),
                u_pct
            ));
        } else {
            cu::outln(&format!(
                "{:<12} {:>10} {:>10} {:>10} {:>4}  /mnt/usb0",
                u_kind,
                number(Some(u_cap)),
                number(Some(u_used)),
                number(Some(u_avail)),
                u_pct
            ));
        }
    }
    if let (Some(percent), Some(capacity)) = (percent, capacity) {
        cu::outln(&format!(
            "[{}] {percent}% of {}",
            fill_bar(percent),
            human_size(capacity)
        ));
    }

    if wide {
        cu::outln(&format!(
            "block_size={BLOCK} blocks_used={} blocks_total={}",
            number(used),
            number(capacity)
        ));
        if let Some(sf) = statfs {
            cu::outln(&format!(
                "objects={}/{} checkpoint={} format_version={}",
                sf.used_objects, sf.total_objects, sf.checkpoint_seq, sf.format_version
            ));
        } else {
            match huesos_std::fs::service() {
                Some(service) => match service.volume_info() {
                    Ok((root_object, checkpoint)) => cu::outln(&format!(
                        "hxfs_root_object={root_object} checkpoint={checkpoint} quota=none"
                    )),
                    Err(error) => cu::outln(&format!("hxfs_volume_info error={error:?}")),
                },
                None => cu::outln("hxfs_volume_info unavailable (scoped capability only)"),
            }
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
