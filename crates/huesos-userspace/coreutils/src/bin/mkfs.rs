//! `/bin/mkfs.elf` — create an empty HxFS volume.
//!
//! `mkfs [-t hxfs] [-s <size>] [-F] [-p <n>] <device|image>`
//!
//! The whole store is formatted by default; a partition table is respected
//! only when `-p <n>` names a partition, in which case the volume is written at
//! that partition's first LBA and nothing outside it is touched.
//!
//! An image path that does not exist yet is created at `-s` (default 16 MiB),
//! which is what makes `mkfs image.hxfs` usable as a one-liner. An existing
//! image keeps its size unless `-s` asks for a larger one: shrinking would
//! discard a volume that is still there.
//!
//! Formatting a block device is destructive, so it needs `-F`; formatting a
//! file does not, because the file is the thing being created.
//!
//! HxFS is append-only: an empty volume is a handful of blocks (superblock,
//! volume table, checkpoint) and grows as objects are written. `mkfs` therefore
//! writes those blocks and leaves the rest of the store alone, and it says so —
//! a freshly formatted 512 MiB partition still holds its old bytes past the
//! header, which is exactly what a filesystem that never claims unallocated
//! space is allowed to do.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;

use huesos_hxfs::writer::PersistentHxfsWriter;

use huesos_coreutils as cu;
use huesos_coreutils::disk::{self, DiskIo, HxfsStore};

cu::coreutil_entry!(run);

/// Size used when an image has to be created and `-s` was not given.
const DEFAULT_IMAGE_BYTES: u64 = 16 * 1024 * 1024;

fn run() -> i32 {
    let args = cu::collect_args();
    let mut fstype: Option<&str> = None;
    let mut size: Option<u64> = None;
    let mut force = false;
    let mut part: Option<usize> = None;
    let mut target: Option<&str> = None;

    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "-t" | "--type" => {
                index += 1;
                fstype = args.get(index).map(|value| value.as_str());
            }
            "-s" | "--size" => {
                index += 1;
                match args.get(index).and_then(|value| disk::parse_size(value)) {
                    Some(bytes) => size = Some(bytes),
                    None => {
                        cu::errln("mkfs: -s needs a size (512, 4096, 1M, 1G)");
                        return 2;
                    }
                }
            }
            "-F" | "--force" => force = true,
            "-p" | "--part" => {
                index += 1;
                match args
                    .get(index)
                    .and_then(|value| value.parse::<usize>().ok())
                {
                    Some(number) if number >= 1 => part = Some(number),
                    _ => {
                        cu::errln("mkfs: -p needs a partition number (1-128)");
                        return 2;
                    }
                }
            }
            "--help" => {
                cu::outln("usage: mkfs [-t hxfs] [-s <size>] [-F] [-p <n>] <device|image>");
                cu::outln("  -t hxfs  filesystem type (hxfs is the only one)");
                cu::outln("  -s <size>  size for a new image (default 16M)");
                cu::outln("  -p <n>   format partition n instead of the whole store");
                cu::outln("  -F       allow formatting a block device");
                return 0;
            }
            other if other.starts_with('-') => {
                cu::errln(&format!("mkfs: unknown option '{other}'"));
                return 2;
            }
            other => target = Some(other),
        }
        index += 1;
    }

    if let Some(kind) = fstype {
        if kind != "hxfs" {
            cu::errln(&format!("mkfs: unsupported filesystem type '{kind}'"));
            return 2;
        }
    }
    let Some(path) = target else {
        cu::errln("mkfs: no target given");
        return 2;
    };

    let on_device = path == "/dev/nvme0" || path == "/dev/disk";
    if on_device && !force && part.is_none() {
        cu::errln(
            "mkfs: /dev/nvme0 is a whole device; pass -F to format it or -p <n> for one partition",
        );
        return 2;
    }

    let mut io = if on_device {
        match DiskIo::open(Some(path), true) {
            Ok(io) => io,
            Err(error) => {
                cu::errln(&format!("mkfs: cannot open {path}: {error}"));
                return 8;
            }
        }
    } else {
        match DiskIo::open_image(path, true) {
            Ok(io) => io,
            Err(_) => {
                // No such image: create one at the requested size.
                let bytes = size.unwrap_or(DEFAULT_IMAGE_BYTES);
                if bytes < 1024 * 1024 {
                    cu::errln("mkfs: an HxFS image needs at least 1 MiB");
                    return 2;
                }
                match DiskIo::create_image(path, bytes) {
                    Ok(io) => io,
                    Err(error) => {
                        cu::errln(&format!("mkfs: cannot create {path}: {error}"));
                        return 8;
                    }
                }
            }
        }
    };

    if let Some(bytes) = size {
        if bytes > io.capacity_bytes() {
            if let Err(error) = io.ensure_len(bytes) {
                cu::errln(&format!(
                    "mkfs: cannot grow {path} to {bytes} bytes: {error}"
                ));
                return 8;
            }
        } else if bytes < io.capacity_bytes() && !on_device {
            cu::outln(&format!(
                "mkfs: keeping the existing {} image ({})",
                disk::human_size(io.capacity_bytes()),
                "shrinking would discard data"
            ));
        }
    }

    // Partition mode needs the table; a bare volume cannot be subdivided.
    let base_lba = match part {
        None => 0,
        Some(number) => {
            let gpt = match huesos_gpt::GptDisk::read_from(&io) {
                Ok(gpt) => gpt,
                Err(error) => {
                    cu::errln(&format!("mkfs: no partition table: {error}"));
                    return 4;
                }
            };
            let Some((_, entry)) = gpt
                .active_partitions()
                .into_iter()
                .find(|(part_num, _)| *part_num == number)
            else {
                cu::errln(&format!("mkfs: partition {number} does not exist"));
                return 4;
            };
            entry.starting_lba
        }
    };

    if part.is_none() && disk::probe_hxfs(&io).is_some() && !force {
        cu::errln(&format!(
            "mkfs: {path} already holds an HxFS volume; pass -F to overwrite it"
        ));
        return 1;
    }

    let (instance, volume) = new_uuids();
    let store = HxfsStore {
        io: &mut io,
        base_lba,
    };
    let writer = match PersistentHxfsWriter::new_empty(store, instance, volume) {
        Ok(writer) => writer,
        Err(error) => {
            cu::errln(&format!("mkfs: formatting failed: {error:?}"));
            return 8;
        }
    };
    // `new_empty` already flushed the initial checkpoint; take the store back so
    // the caller can flush the bus and report the resulting volume.
    let store = writer.into_store();
    let io = store.io;

    if let Err(error) = io.flush() {
        cu::errln(&format!("mkfs: flush: {error}"));
        return 8;
    }

    let volume_summary = disk::probe_hxfs_at(io, base_lba);
    cu::outln(&format!(
        "mkfs: created hxfs volume on {} ({}){}",
        io.label(),
        disk::human_size(io.capacity_bytes()),
        if part.is_none() {
            String::new()
        } else {
            format!(" at LBA {base_lba}")
        }
    ));
    if let Some(volume) = volume_summary {
        cu::outln(&format!(
            "mkfs: format_version={} type_system_version={} block_size={} layout={} state={}",
            volume.format_version,
            volume.type_system_version,
            volume.block_size,
            volume.layout_label(),
            volume.root_state
        ));
    } else {
        cu::errln("mkfs: warning: the new volume did not probe back cleanly");
        return 1;
    }
    cu::outln("mkfs: unallocated space beyond the header is left as-is (HxFS is append-only)");
    0
}

/// Two fresh UUIDv4-shaped identifiers: one for the instance, one for the volume.
///
/// There is no entropy device in the capability set, so the seed comes from the
/// clock plus the address of a stack temporary; two volumes formatted in the
/// same nanosecond on the same machine are the only case this cannot separate,
/// and neither of those is a uniqueness guarantee anyone should rely on anyway.
fn new_uuids() -> ([u8; 16], [u8; 16]) {
    let now = huesos_std::time::SystemTime::now()
        .duration_since(huesos_std::time::UNIX_EPOCH)
        .unwrap_or(huesos_std::time::Duration::ZERO);
    let local = 0u64;
    let address = core::ptr::addr_of!(local) as u64;
    let mut seed = now
        .as_secs()
        .wrapping_mul(1_000_000_000)
        .wrapping_add(u64::from(now.subsec_nanos()))
        ^ address.rotate_left(17);
    let mut instance = [0u8; 16];
    for byte in &mut instance {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *byte = (seed >> 33) as u8;
    }
    // RFC 4122 layout: version 4, variant 10.
    instance[6] = (instance[6] & 0x0f) | 0x40;
    instance[8] = (instance[8] & 0x3f) | 0x80;
    let mut volume = instance;
    volume[15] ^= 0xff;
    (instance, volume)
}
