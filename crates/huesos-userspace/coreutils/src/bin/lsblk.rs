//! `/bin/lsblk.elf` — list block devices and their partitions.
//!
//! `lsblk [-f] [-b] [-n] [-p <device>]`
//!
//! The device is read through the shared [`DiskIo`](huesos_coreutils::disk::DiskIo)
//! layer, so the same command works on the granted NVMe channel and on a GPT
//! image file on the mounted volume. Each partition is probed for a bare HxFS
//! volume to fill in the `FSTYPE` column: that probe only looks at the volume
//! header, so listing a disk never walks its filesystem.
//!
//! Output is the usual tree, with box-drawing replaced by ASCII so it stays
//! readable in the serial console and in captured logs.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;

use huesos_std::io::Write;

use huesos_coreutils as cu;
use huesos_coreutils::disk::{self, DiskIo, NOT_MOUNTED, NO_FSTYPE};

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let mut show_filesystems = false;
    let mut bytes = false;
    let mut no_headings = false;
    let mut target: Option<&str> = None;

    for arg in args.iter() {
        match arg.as_str() {
            "-f" | "--fs" => show_filesystems = true,
            "-b" | "--bytes" => bytes = true,
            "-n" | "--noheadings" => no_headings = true,
            "--help" => {
                cu::outln("usage: lsblk [-f] [-b] [-n] [<device|image>]");
                cu::outln("  -f  show FSTYPE and FSVER columns");
                cu::outln("  -b  sizes in bytes instead of human units");
                cu::outln("  -n  omit the heading line");
                return 0;
            }
            other if other.starts_with('-') => {
                cu::errln(&format!("lsblk: unknown option '{other}'"));
                return 2;
            }
            other => target = Some(other),
        }
    }

    let io = match DiskIo::open(target, false) {
        Ok(io) => io,
        Err(error) => {
            // Distinguish "this process was not given the disk" from "the disk
            // itself is unusable": collapsing them into one message is what
            // made `lsblk` look broken on a machine that simply had no storage
            // channel to hand out.
            if target.is_none() && !disk::has_block_device() {
                cu::errln(
                    "lsblk: no block device in this process (the shell grants one only when \
                     the NVMe service is online); pass an image path instead",
                );
                return 1;
            }
            cu::errln(&format!("lsblk: cannot open {error}"));
            return 1;
        }
    };

    let size = |value: u64| -> String {
        if bytes {
            format!("{value}")
        } else {
            disk::human_size(value)
        }
    };
    let name = io.label();

    // The disk line: a raw HxFS volume labels itself, a GPT disk does not.
    let raw_volume = disk::probe_hxfs(&io);
    let header = if show_filesystems {
        format!(
            "{:<16} {:>4} {:>10} {:>3} {:<6} {:<8} {:<6} {}",
            "NAME", "RM", "SIZE", "RO", "TYPE", "FSTYPE", "FSVER", "MOUNTPOINT"
        )
    } else {
        format!(
            "{:<16} {:>4} {:>10} {:>3} {:<6} {}",
            "NAME", "RM", "SIZE", "RO", "TYPE", "MOUNTPOINT"
        )
    };
    if !no_headings {
        cu::outln(&header);
    }
    let disk_fstype = if raw_volume.is_some() {
        "hxfs"
    } else {
        NO_FSTYPE
    };
    let disk_version = raw_volume
        .as_ref()
        .map(|volume| format!("{}", volume.format_version))
        .unwrap_or_else(|| String::from(NO_FSTYPE));
    let disk_mount = if raw_volume.is_some() {
        disk::HXFS_MOUNT_POINT
    } else {
        NOT_MOUNTED
    };
    if show_filesystems {
        cu::outln(&format!(
            "{:<16} {:>4} {:>10} {:>3} {:<6} {:<8} {:<6} {}",
            name,
            0,
            size(io.capacity_bytes()),
            0,
            "disk",
            disk_fstype,
            disk_version,
            disk_mount
        ));
    } else {
        cu::outln(&format!(
            "{:<16} {:>4} {:>10} {:>3} {:<6} {}",
            name,
            0,
            size(io.capacity_bytes()),
            0,
            "disk",
            disk_mount
        ));
    }

    if raw_volume.is_some() {
        // A bare volume has no partition table to walk; the disk line says it all.
        return 0;
    }

    let gpt = match huesos_gpt::GptDisk::read_from(&io) {
        Ok(gpt) => gpt,
        Err(error) => {
            // No table at all is not an error for `lsblk`: an unformatted disk
            // has exactly one line, which we already printed.
            if !error.contains("protective") && !error.contains("signature") {
                cu::errln(&format!("lsblk: {error}"));
            }
            return 0;
        }
    };

    let partitions = gpt.active_partitions();
    for (index, (part_num, entry)) in partitions.iter().enumerate() {
        let last = index + 1 == partitions.len();
        let branch = if last { "`-" } else { "|-" };
        let part_name = format!("{name}p{part_num}");
        let part_bytes = entry.size_lbas() * huesos_gpt::LBA_SIZE as u64;
        let volume = disk::probe_hxfs_at(&io, entry.starting_lba);
        let fstype = if volume.is_some() {
            String::from("hxfs")
        } else {
            entry.type_guid.type_label()
        };
        let version = volume
            .as_ref()
            .map(|volume| format!("{}", volume.format_version))
            .unwrap_or_else(|| String::from(NO_FSTYPE));
        let mount = if volume.is_some() {
            disk::HXFS_MOUNT_POINT
        } else {
            NOT_MOUNTED
        };
        let label = if entry.name.is_empty() {
            String::from(" ")
        } else {
            entry.name.clone()
        };
        if show_filesystems {
            cu::outln(&format!(
                "{:<2}{:<14} {:>4} {:>10} {:>3} {:<6} {:<8} {:<6} {}",
                branch,
                part_name,
                0,
                size(part_bytes),
                0,
                "part",
                fstype,
                version,
                mount
            ));
        } else {
            cu::outln(&format!(
                "{:<2}{:<14} {:>4} {:>10} {:>3} {:<6} {}  {label}",
                branch,
                part_name,
                0,
                size(part_bytes),
                0,
                "part",
                mount
            ));
        }
    }
    let _ = Write::flush(&mut huesos_std::io::stdout());
    0
}
