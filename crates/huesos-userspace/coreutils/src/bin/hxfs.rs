#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use huesos_abi::auxv::caps_mask;
use huesos_coreutils as cu;
use libcanvas::stdio::caps_mask as proc_caps_mask;

cu::coreutil_entry!(run);

fn run() -> i32 {
    let args = cu::collect_args();
    let sub = args.first().map(String::as_str).unwrap_or("status");

    match sub {
        "status" => cmd_status(),
        "stats" => cmd_stats(),
        "scrub" => cmd_scrub(),
        "fsck" => cmd_fsck(),
        "snapshot" | "snap" => cmd_snapshot(&args[1..]),
        "sync" | "checkpoint" => cmd_sync(),
        "gc" => cmd_gc(),
        _ => {
            cu::errln(
                "usage: hxfs <status|stats|scrub|fsck|snapshot [list|create <name>|delete <name>]|sync|gc>",
            );
            1
        }
    }
}

fn caps_label(mask: u64) -> &'static str {
    if (mask & caps_mask::HXFS_RO) == 0 {
        "none"
    } else if (mask & caps_mask::HXFS_RW) != 0 {
        "rw"
    } else {
        "ro"
    }
}

fn cmd_status() -> i32 {
    if let Err(code) = cu::check_hxfs_ro() {
        return code;
    }
    let cap = caps_label(proc_caps_mask());
    let hxfs = cu::take_hxfs();
    let hxfs_dir = cu::take_hxfs_dir();

    cu::outln("property\tvalue");
    cu::outln(&format!("capability\t{cap}"));
    if let Some(svc) = hxfs.as_ref() {
        match svc.volume_info() {
            Ok((root_id, seq)) => {
                cu::outln("state\tmounted");
                cu::outln(&format!("root_object_id\t{root_id}"));
                cu::outln(&format!("checkpoint_seq\t{seq}"));
            }
            Err(_) => {
                cu::outln("state\tonline-no-info");
            }
        }
    } else if hxfs_dir.is_some() {
        cu::outln("state\tmounted-ro-dir");
    } else {
        cu::outln("state\toffline");
    }
    0
}

fn cmd_stats() -> i32 {
    if let Err(code) = cu::check_hxfs_ro() {
        return code;
    }
    let hxfs = cu::take_hxfs();
    let hxfs_dir = cu::take_hxfs_dir();
    cu::outln("metric\tvalue");
    if let Some(svc) = hxfs.as_ref() {
        if let Ok(sf) = svc.stat_fs() {
            cu::outln(&format!("block_size\t{}", sf.block_size));
            cu::outln(&format!("total_blocks\t{}", sf.total_blocks));
            cu::outln(&format!("used_blocks\t{}", sf.used_blocks));
            cu::outln(&format!("avail_blocks\t{}", sf.avail_blocks));
            cu::outln(&format!("used_objects\t{}", sf.used_objects));
            cu::outln(&format!("total_objects\t{}", sf.total_objects));
            cu::outln(&format!("checkpoint_seq\t{}", sf.checkpoint_seq));
            cu::outln(&format!("format_version\t{}", sf.format_version));
        } else if let Ok((root_id, seq)) = svc.volume_info() {
            cu::outln(&format!("root_object_id\t{root_id}"));
            cu::outln(&format!("checkpoint_seq\t{seq}"));
        }
        if let Ok(root) = svc.root() {
            let mut buf = [0u8; 4096];
            if let Ok(bytes) = root.list(&mut buf) {
                let count = core::str::from_utf8(bytes)
                    .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                    .unwrap_or(0);
                cu::outln(&format!("root_entries\t{count}"));
            }
        }
        cu::outln("status\tonline");
    } else if let Some(dir) = hxfs_dir {
        let mut buf = [0u8; 4096];
        let count = dir
            .list(&mut buf)
            .ok()
            .and_then(|b| core::str::from_utf8(b).ok())
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        cu::outln(&format!("root_entries\t{count}"));
        cu::outln("status\tread-only");
    } else {
        cu::outln("status\toffline");
    }
    0
}

fn cmd_scrub() -> i32 {
    if let Err(code) = cu::check_hxfs_ro() {
        return code;
    }
    if let Some(svc) = cu::take_hxfs() {
        let mut buf = [0u8; 512];
        if let Ok(line) = svc.scrub_summary(&mut buf) {
            let trimmed = line.trim();
            cu::outln(trimmed);
            let errors = parse_kv_u64(trimmed, "errors=").unwrap_or(0);
            return if errors == 0 { 0 } else { 1 };
        }
    }
    let hxfs_dir = cu::take_hxfs_dir();
    cu::outln("entry\tkind\tverify");
    let Some(dir) = hxfs_dir else {
        cu::outln("volume\tstatus\toffline");
        return 0;
    };
    let mut buf = [0u8; 4096];
    let Ok(bytes) = dir.list(&mut buf) else {
        cu::errln("hxfs scrub: failed listing root directory");
        return 1;
    };
    let Ok(text) = core::str::from_utf8(bytes) else {
        cu::errln("hxfs scrub: invalid utf8 directory listing");
        return 1;
    };
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let kind = parts.next().unwrap_or("entry");
        if kind == "file" {
            match dir.open_file(name) {
                Ok(f) => {
                    let ok = f.size().is_ok();
                    cu::outln(&format!("{name}\tfile\t{}", if ok { "ok" } else { "err" }));
                }
                Err(_) => cu::outln(&format!("{name}\tfile\topen-err")),
            }
        } else {
            cu::outln(&format!("{name}\t{kind}\tok"));
        }
    }
    0
}

fn cmd_fsck() -> i32 {
    if let Err(code) = cu::check_hxfs_ro() {
        return code;
    }
    let Some(svc) = cu::take_hxfs() else {
        cu::errln("hxfs fsck: service capability required");
        return 1;
    };
    let mut buf = [0u8; 512];
    match svc.fsck_summary(&mut buf) {
        Ok(line) => {
            let trimmed = line.trim();
            cu::outln(trimmed);
            let errors = parse_kv_u64(trimmed, "errors=").unwrap_or(0);
            if errors == 0 {
                0
            } else {
                1
            }
        }
        Err(e) => {
            cu::errln(&format!("hxfs fsck failed: {}", e.as_str()));
            1
        }
    }
}

fn cmd_snapshot(args: &[String]) -> i32 {
    let action = args.first().map(String::as_str).unwrap_or("list");
    match action {
        "list" | "ls" => {
            if let Err(code) = cu::check_hxfs_ro() {
                return code;
            }
            let Some(svc) = cu::take_hxfs() else {
                cu::errln("hxfs snapshot: service capability required");
                return 1;
            };
            let mut buf = [0u8; 2048];
            match svc.list_snapshots(&mut buf) {
                Ok(text) => {
                    cu::outln("name\tseq\tlba");
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        let mut parts = line.split('\t');
                        let name = parts.next().unwrap_or("-");
                        let seq = parts
                            .next()
                            .and_then(|p| p.strip_prefix("seq="))
                            .unwrap_or("-");
                        let lba = parts
                            .next()
                            .and_then(|p| p.strip_prefix("lba="))
                            .unwrap_or("-");
                        cu::outln(&format!("{name}\t{seq}\t{lba}"));
                    }
                    0
                }
                Err(e) => {
                    cu::errln(&format!("hxfs snapshot list failed: {}", e.as_str()));
                    1
                }
            }
        }
        "create" | "add" => {
            if let Err(code) = cu::check_hxfs_rw() {
                return code;
            }
            let Some(name) = args.get(1) else {
                cu::errln("usage: hxfs snapshot create <name>");
                return 1;
            };
            let Some(svc) = cu::take_hxfs() else {
                cu::errln("hxfs snapshot: service offline");
                return 1;
            };
            match svc.create_snapshot(name) {
                Ok(seq) => {
                    cu::outln("property\tvalue");
                    cu::outln(&format!("snapshot\t{name}"));
                    cu::outln(&format!("checkpoint_seq\t{seq}"));
                    0
                }
                Err(e) => {
                    cu::errln(&format!(
                        "hxfs snapshot create '{name}' failed: {}",
                        e.as_str()
                    ));
                    1
                }
            }
        }
        "delete" | "rm" | "remove" => {
            if let Err(code) = cu::check_hxfs_rw() {
                return code;
            }
            let Some(name) = args.get(1) else {
                cu::errln("usage: hxfs snapshot delete <name>");
                return 1;
            };
            let Some(svc) = cu::take_hxfs() else {
                cu::errln("hxfs snapshot: service offline");
                return 1;
            };
            match svc.delete_snapshot(name) {
                Ok(()) => {
                    cu::outln("property\tvalue");
                    cu::outln(&format!("deleted_snapshot\t{name}"));
                    0
                }
                Err(e) => {
                    cu::errln(&format!(
                        "hxfs snapshot delete '{name}' failed: {}",
                        e.as_str()
                    ));
                    1
                }
            }
        }
        _ => cmd_sync(),
    }
}

fn parse_kv_u64(line: &str, key: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(key))
        .and_then(|v| v.parse::<u64>().ok())
}

fn cmd_sync() -> i32 {
    if let Err(code) = cu::check_hxfs_rw() {
        return code;
    }
    let Some(svc) = cu::take_hxfs() else {
        cu::errln("hxfs: service offline");
        return 1;
    };
    match svc.checkpoint() {
        Ok(()) => {
            cu::outln("property\tvalue");
            cu::outln("checkpoint\tcommitted");
            if let Ok((_, seq)) = svc.volume_info() {
                cu::outln(&format!("checkpoint_seq\t{seq}"));
            }
            0
        }
        Err(e) => {
            cu::errln(&format!("hxfs checkpoint failed: {}", e.as_str()));
            1
        }
    }
}

fn cmd_gc() -> i32 {
    if let Err(code) = cu::check_hxfs_rw() {
        return code;
    }
    let Some(svc) = cu::take_hxfs() else {
        cu::errln("hxfs: service offline");
        return 1;
    };
    match svc.gc_blobs() {
        Ok(reclaimed) => {
            cu::outln("property\tvalue");
            cu::outln(&format!("gc_reclaimed\t{reclaimed}"));
            0
        }
        Err(e) => {
            cu::errln(&format!("hxfs gc failed: {}", e.as_str()));
            1
        }
    }
}
