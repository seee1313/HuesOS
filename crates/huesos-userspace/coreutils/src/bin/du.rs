//! `/bin/du.elf` — disk usage of a directory tree.
//!
//! `du [-s] [-h] [-d <depth>] [<path>]`
//!
//! The listing comes from the filesystem service one directory at a time, so a
//! deep tree costs one round trip per directory and no more: `du` never stats a
//! file it did not have to, which is what keeps it usable on a volume with
//! thousands of objects.
//!
//! Sizes are the object sizes the service reports; a directory's own entry
//! costs nothing (the volume stores its children, not the directory object), so
//! a directory's total is exactly the sum of what is inside it.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_std::prelude::*;

use huesos_coreutils as cu;
use huesos_coreutils::disk::human_size;

cu::coreutil_entry!(run);

/// One printed line: a path and how many bytes it holds.
struct Usage {
    path: String,
    bytes: u64,
}

fn run() -> i32 {
    let args = cu::collect_args();
    let mut summary_only = false;
    let mut human = false;
    let mut max_depth: u32 = u32::MAX;
    let mut root: Option<&str> = None;

    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "-s" | "--summarize" => summary_only = true,
            "-h" | "--human-readable" => human = true,
            "-a" | "--all" => {}
            "-d" | "--max-depth" => {
                index += 1;
                match args.get(index).and_then(|value| value.parse::<u32>().ok()) {
                    Some(depth) => max_depth = depth,
                    None => {
                        cu::errln("du: -d needs a depth");
                        return 2;
                    }
                }
            }
            "--help" => {
                cu::outln("usage: du [-s] [-h] [-d <depth>] [<path>]");
                return 0;
            }
            other if other.starts_with('-') => {
                cu::errln(&format!("du: unknown option '{other}'"));
                return 2;
            }
            other => root = Some(other),
        }
        index += 1;
    }

    let root = root.unwrap_or("/");
    let mut lines: Vec<Usage> = Vec::new();
    let total = match walk(root, 0, max_depth, summary_only, &mut lines) {
        Ok(total) => total,
        Err(error) => {
            cu::errln(&format!("du: {root}: {error}"));
            return 1;
        }
    };

    for line in &lines {
        if human {
            cu::outln(&format!("{:>8}  {}", human_size(line.bytes), line.path));
        } else {
            cu::outln(&format!("{:>10}  {}", line.bytes / 1024, line.path));
        }
    }
    if human {
        cu::outln(&format!("{:>8}  {root} (total)", human_size(total)));
    } else {
        cu::outln(&format!("{:>10}  {root} (total)", total / 1024));
    }
    0
}

/// Sum `path` and everything under it, appending one line per directory.
fn walk(
    path: &str,
    depth: u32,
    max_depth: u32,
    summary_only: bool,
    lines: &mut Vec<Usage>,
) -> Result<u64> {
    let entries = match huesos_std::fs::list(path) {
        Ok(entries) => entries,
        Err(error) => {
            // A file argument measures the file itself.
            if let Ok(metadata) = huesos_std::fs::metadata(path) {
                return Ok(metadata.len());
            }
            return Err(error);
        }
    };
    let mut total = 0u64;
    for entry in &entries {
        match entry.kind {
            huesos_std::fs::EntryKind::Dir => {
                let child = join(path, &entry.name);
                total += walk(&child, depth + 1, max_depth, summary_only, lines)?;
            }
            _ => total += entry.size.unwrap_or(0),
        }
    }
    if !summary_only && depth <= max_depth {
        lines.push(Usage {
            path: String::from(path),
            bytes: total,
        });
    }
    Ok(total)
}

/// Join a directory and an entry name without doubling the separator.
fn join(directory: &str, name: &str) -> String {
    if directory == "/" || directory.is_empty() {
        format!("/{name}")
    } else {
        format!("{directory}/{name}")
    }
}
