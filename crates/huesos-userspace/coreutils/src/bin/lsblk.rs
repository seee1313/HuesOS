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

    let primary_io = DiskIo::open(target, false);
    let usb_extra = if target.is_none() {
        DiskIo::open_usb_device().ok()
    } else {
        None
    };

    if let (Err(error), None) = (&primary_io, &usb_extra) {
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

    let header = if show_filesystems {
        format!(
            "{:<16} {:>4} {:>10} {:>3} {:<6} {:<8} {:<6} {:<20} {:<16} {}",
            "NAME", "RM", "SIZE", "RO", "TYPE", "FSTYPE", "FSVER", "MODEL", "SERIAL", "MOUNTPOINT"
        )
    } else {
        format!(
            "{:<16} {:>4} {:>10} {:>3} {:<6} {:<20} {:<16} {}",
            "NAME", "RM", "SIZE", "RO", "TYPE", "MODEL", "SERIAL", "MOUNTPOINT"
        )
    };
    if !no_headings {
        cu::outln(&header);
    }

    if let Ok(io) = &primary_io {
        print_device(io, show_filesystems, bytes);
    }
    if let Some(usb_io) = &usb_extra {
        print_device(usb_io, show_filesystems, bytes);
    }
    let _ = Write::flush(&mut huesos_std::io::stdout());
    0
}

fn print_device(io: &DiskIo, show_filesystems: bool, bytes: bool) {
    let size = |value: u64| -> String {
        if bytes {
            format!("{value}")
        } else {
            disk::human_size(value)
        }
    };
    let name = io.label();
    let is_usb = name == "/dev/block/usb0";
    let rm = u8::from(is_usb);

    let raw_volume = disk::probe_hxfs(io);
    let mbr_parts = disk::read_mbr_partitions(io);
    let raw_fat = if raw_volume.is_none() && mbr_parts.is_empty() {
        disk::probe_fat_at(io, 0)
    } else {
        None
    };

    let disk_fstype = if raw_volume.is_some() {
        "hxfs"
    } else if raw_fat.is_some() {
        "vfat"
    } else {
        NO_FSTYPE
    };
    let disk_version = if let Some(volume) = &raw_volume {
        format!("{}", volume.format_version)
    } else if let Some(fat_ver) = raw_fat {
        String::from(fat_ver)
    } else {
        String::from(NO_FSTYPE)
    };
    let disk_mount = if raw_volume.is_some() {
        disk::HXFS_MOUNT_POINT
    } else if raw_fat.is_some() && is_usb {
        huesos_std::usb_fat::USB0_MOUNT_POINT
    } else {
        NOT_MOUNTED
    };
    let disk_model = if io.model().is_empty() {
        NO_FSTYPE
    } else {
        io.model()
    };
    let disk_serial = if io.serial().is_empty() {
        NO_FSTYPE
    } else {
        io.serial()
    };
    if show_filesystems {
        cu::outln(&format!(
            "{:<16} {:>4} {:>10} {:>3} {:<6} {:<8} {:<6} {:<20} {:<16} {}",
            name,
            rm,
            size(io.capacity_bytes()),
            0,
            "disk",
            disk_fstype,
            disk_version,
            disk_model,
            disk_serial,
            disk_mount
        ));
    } else {
        cu::outln(&format!(
            "{:<16} {:>4} {:>10} {:>3} {:<6} {:<20} {:<16} {}",
            name,
            rm,
            size(io.capacity_bytes()),
            0,
            "disk",
            disk_model,
            disk_serial,
            disk_mount
        ));
    }

    if raw_volume.is_some() || raw_fat.is_some() {
        return;
    }

    if let Ok(gpt) = huesos_gpt::GptDisk::read_from(io) {
        let partitions = gpt.active_partitions();
        let mut mounted_usb = false;
        for (index, (part_num, entry)) in partitions.iter().enumerate() {
            let last = index + 1 == partitions.len();
            let branch = if last { "`-" } else { "|-" };
            let part_name = format!("{name}p{part_num}");
            let part_bytes = entry.size_lbas() * huesos_gpt::LBA_SIZE as u64;
            let volume = disk::probe_hxfs_at(io, entry.starting_lba);
            let fat_ver = if volume.is_none() {
                disk::probe_fat_at(io, entry.starting_lba)
            } else {
                None
            };
            let fstype = if volume.is_some() {
                String::from("hxfs")
            } else if fat_ver.is_some() {
                String::from("vfat")
            } else {
                entry.type_guid.type_label()
            };
            let version = if let Some(vol) = &volume {
                format!("{}", vol.format_version)
            } else if let Some(fv) = fat_ver {
                String::from(fv)
            } else {
                String::from(NO_FSTYPE)
            };
            let mount = if volume.is_some() {
                disk::HXFS_MOUNT_POINT
            } else if fat_ver.is_some() && is_usb && !mounted_usb {
                mounted_usb = true;
                huesos_std::usb_fat::USB0_MOUNT_POINT
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
                    "{:<2}{:<14} {:>4} {:>10} {:>3} {:<6} {:<8} {:<6} {:<20} {:<16} {}",
                    branch,
                    part_name,
                    rm,
                    size(part_bytes),
                    0,
                    "part",
                    fstype,
                    version,
                    "-",
                    "-",
                    mount
                ));
            } else {
                cu::outln(&format!(
                    "{:<2}{:<14} {:>4} {:>10} {:>3} {:<6} {:<20} {:<16} {}  {label}",
                    branch,
                    part_name,
                    rm,
                    size(part_bytes),
                    0,
                    "part",
                    "-",
                    "-",
                    mount
                ));
            }
        }
        return;
    }

    let mut mounted_usb = false;
    for (index, (part_num, start_lba, count_lbas, ptype)) in mbr_parts.iter().enumerate() {
        let last = index + 1 == mbr_parts.len();
        let branch = if last { "`-" } else { "|-" };
        let part_name = format!("{name}p{part_num}");
        let part_bytes = count_lbas * huesos_gpt::LBA_SIZE as u64;
        let fat_ver = disk::probe_fat_at(io, *start_lba);
        let fstype = if fat_ver.is_some() {
            String::from("vfat")
        } else {
            format!("0x{ptype:02x}")
        };
        let version = fat_ver
            .map(String::from)
            .unwrap_or_else(|| String::from(NO_FSTYPE));
        let mount = if fat_ver.is_some() && is_usb && !mounted_usb {
            mounted_usb = true;
            huesos_std::usb_fat::USB0_MOUNT_POINT
        } else {
            NOT_MOUNTED
        };
        if show_filesystems {
            cu::outln(&format!(
                "{:<2}{:<14} {:>4} {:>10} {:>3} {:<6} {:<8} {:<6} {:<20} {:<16} {}",
                branch,
                part_name,
                rm,
                size(part_bytes),
                0,
                "part",
                fstype,
                version,
                "-",
                "-",
                mount
            ));
        } else {
            cu::outln(&format!(
                "{:<2}{:<14} {:>4} {:>10} {:>3} {:<6} {:<20} {:<16} {}",
                branch,
                part_name,
                rm,
                size(part_bytes),
                0,
                "part",
                "-",
                "-",
                mount
            ));
        }
    }
}
