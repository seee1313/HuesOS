//! `/bin/fsck.elf` — check a disk, an image or a partition for damage.
//!
//! `fsck [-n] [-V] [<device|image>]`
//!
//! Two layers are checked and neither of them repairs anything:
//!
//! * the partition table, through `huesos-gpt`'s verifier — protective MBR,
//!   both header CRC32s, the entry-array CRC, overlap and alignment;
//! * each HxFS volume found, through the filesystem's own report-only
//!   structural checker (`FixedHxfsWriter::fsck`), which re-validates the
//!   superblock, the checkpoint, the volume table and the in-memory object
//!   model: root presence, object-id uniqueness, dangling directory entries,
//!   extent monotonicity and record counts.
//!
//! Because mounting a volume may replay a recovering journal, the volume is
//! opened writable by default. `-n` keeps the store read-only and reports the
//! replay as a finding instead of performing it.
//!
//! Exit status follows `fsck(8)`: `0` clean, `1` problems found, `4` nothing to
//! check, `8` the store could not be opened.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;

use huesos_hxfs::fixed_writer::FixedHxfsWriter;

use huesos_coreutils as cu;
use huesos_coreutils::disk::{self, DiskIo, HxfsStore, NO_FSTYPE};

cu::coreutil_entry!(run);

/// Object capacity of the checker's mount. HxFS's structural check is generic
/// over fixed capacities; these match the size of a service-sized volume while
/// keeping the mount's state small enough for a userspace stack.
const MAX_OBJECTS: usize = 32;
const MAX_DIR_ENTRIES: usize = 64;
const MAX_EXTENTS: usize = 64;

fn run() -> i32 {
    let args = cu::collect_args();
    let mut read_only = false;
    let mut verbose = false;
    let mut target: Option<&str> = None;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-n" | "--no" => read_only = true,
            "-y" | "--yes" | "-f" | "--force" => {}
            "-V" | "--verbose" => verbose = true,
            "--help" => {
                cu::outln("usage: fsck [-n] [-V] [<device|image>]");
                cu::outln("  -n  do not write; a pending journal replay is reported, not applied");
                cu::outln("  -V  print every check, not just the summary");
                return 0;
            }
            other if other.starts_with('-') => {
                cu::errln(&format!("fsck: unknown option '{other}'"));
                return 8;
            }
            other => target = Some(other),
        }
    }

    let mut io = match DiskIo::open(target, !read_only) {
        Ok(io) => io,
        Err(error) => {
            cu::errln(&format!("fsck: cannot open store: {error}"));
            return 8;
        }
    };
    cu::outln(&format!(
        "fsck: {} ({} bytes, {} hardware block)",
        io.label(),
        io.capacity_bytes(),
        io.hardware_block_size()
    ));

    let mut checks = 0u64;
    let mut errors = 0u64;
    let mut found_fs = false;

    // A superfloppy volume uses the whole store; there is no table to verify.
    if disk::probe_hxfs(&io).is_some() {
        found_fs = true;
        let (found_checks, found_errors) = check_volume(&mut io, 0, "whole store", verbose);
        checks += found_checks;
        errors += found_errors;
    } else {
        match huesos_gpt::GptDisk::read_from(&io) {
            Ok(gpt) => {
                let report = huesos_gpt::verify_disk_io(&io);
                checks += 1;
                if let Err(error) = write_report(&report) {
                    cu::errln(&format!("fsck: {error}"));
                    errors += 1;
                } else if !report.ok {
                    errors += report.errors.len() as u64;
                }
                if verbose {
                    cu::outln(&format!(
                        "gpt: protective_mbr={} primary_crc={} backup_crc={} entries_crc={} \
                         overlaps={} alignment_warnings={} errors={}",
                        report.protective_mbr,
                        report.primary_crc_ok,
                        report.backup_crc_ok,
                        report.entries_crc_ok,
                        report.overlaps,
                        report.alignment_warnings,
                        report.errors.len()
                    ));
                }
                for (part_num, entry) in gpt.active_partitions() {
                    let name = format!("partition {part_num}");
                    if disk::probe_hxfs_at(&io, entry.starting_lba).is_some() {
                        found_fs = true;
                        let (found_checks, found_errors) =
                            check_volume(&mut io, entry.starting_lba, &name, verbose);
                        checks += found_checks;
                        errors += found_errors;
                    } else if verbose {
                        cu::outln(&format!(
                            "{name}: type={} fstype={NO_FSTYPE} (not an HxFS volume)",
                            entry.type_guid.type_label()
                        ));
                    }
                }
            }
            Err(error) => {
                cu::errln(&format!("fsck: no partition table: {error}"));
                cu::outln("fsck: nothing to check");
                return 4;
            }
        }
    }

    if !found_fs && errors == 0 {
        cu::outln("fsck: no HxFS volume found");
        return 4;
    }

    // Flush only when something may have been written: a read-only pass leaves
    // the store untouched, and a clean pass has nothing to lose either way.
    if !read_only {
        if let Err(error) = io.flush() {
            cu::errln(&format!("fsck: flush: {error}"));
            return 8;
        }
    }

    cu::outln(&format!("fsck: {checks} checks, {errors} errors"));
    if errors == 0 {
        cu::outln("fsck: clean");
        0
    } else {
        cu::outln("fsck: DAMAGED (report only: nothing was repaired)");
        1
    }
}

/// Structurally check the HxFS volume that starts at `lba0`.
fn check_volume(io: &mut DiskIo, lba0: u64, name: &str, verbose: bool) -> (u64, u64) {
    let store = HxfsStore { io, base_lba: lba0 };
    let mut writer =
        match FixedHxfsWriter::<_, MAX_OBJECTS, MAX_DIR_ENTRIES, MAX_EXTENTS>::mount_from_disk(
            store, None,
        ) {
            Ok(writer) => writer,
            Err(error) => {
                cu::outln(&format!("{name}: hxfs: mount failed: {error:?}"));
                return (1, 1);
            }
        };
    let summary = writer.fsck();
    if verbose || summary.errors > 0 {
        cu::outln(&format!(
            "{name}: hxfs: {} checks, {} errors",
            summary.checks, summary.errors
        ));
    } else {
        cu::outln(&format!("{name}: hxfs: clean ({} checks)", summary.checks));
    }
    (summary.checks, summary.errors)
}

/// Print the partition table part of a [`huesos_gpt::VerifyReport`].
fn write_report(
    report: &huesos_gpt::VerifyReport,
) -> core::result::Result<(), alloc::string::String> {
    if report.ok {
        cu::outln("gpt: table clean");
        return Ok(());
    }
    for error in &report.errors {
        cu::errln(&format!("gpt: {error}"));
    }
    if report.overlaps > 0 {
        cu::errln(&format!(
            "gpt: {} overlapping partition pair(s)",
            report.overlaps
        ));
    }
    if report.alignment_warnings > 0 {
        cu::outln(&format!(
            "gpt: {} partition(s) not aligned to 1 MiB",
            report.alignment_warnings
        ));
    }
    Ok(())
}
