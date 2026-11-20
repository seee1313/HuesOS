//! `/bin/find.elf` — walk a directory tree and print the entries that match.
//!
//! `find [<path>] [-maxdepth <n>] [-name <glob>] [-type f|d]`
//!
//! The walk is depth-first and visits the starting point itself first, the way
//! `find` does. `-name` matches the entry's own name (not the whole path) with
//! `*` and `?` wildcards, `-type` keeps files or directories only.
//!
//! Exit status is `0` when the walk completed (whether or not anything
//! matched), `1` when a directory could not be read, `2` on a usage error.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;

huesos_std::entry!(run);

/// What `-type` keeps.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    File,
    Dir,
}

struct Options {
    root: String,
    max_depth: Option<usize>,
    name: Option<String>,
    kind: Option<Kind>,
}

fn run() -> i32 {
    let args = args();
    let mut options = Options {
        root: String::from("."),
        max_depth: None,
        name: None,
        kind: None,
    };
    let mut index = 0;
    let mut root_seen = false;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-maxdepth" => {
                index += 1;
                match args.get(index).and_then(|value| value.parse::<usize>().ok()) {
                    Some(depth) => options.max_depth = Some(depth),
                    None => {
                        eprintln!("find: -maxdepth needs a non-negative number");
                        return 2;
                    }
                }
            }
            "-name" => {
                index += 1;
                match args.get(index) {
                    Some(pattern) => options.name = Some(String::from(pattern.as_str())),
                    None => {
                        eprintln!("find: -name needs a pattern");
                        return 2;
                    }
                }
            }
            "-type" => {
                index += 1;
                match args.get(index).map(String::as_str) {
                    Some("f") => options.kind = Some(Kind::File),
                    Some("d") => options.kind = Some(Kind::Dir),
                    _ => {
                        eprintln!("find: -type takes f or d");
                        return 2;
                    }
                }
            }
            "-h" | "--help" => {
                println!("usage: find [<path>] [-maxdepth <n>] [-name <glob>] [-type f|d]");
                return 0;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("find: unknown option '{other}'");
                return 2;
            }
            other => {
                if root_seen {
                    eprintln!("find: only one starting path is supported");
                    return 2;
                }
                options.root = String::from(other);
                root_seen = true;
            }
        }
        index += 1;
    }

    let mut failures = 0;
    visit(&options, &options.root, 0, &mut failures);
    if failures > 0 {
        1
    } else {
        0
    }
}

/// Depth-first walk of `current`, one level of `depth` down from the root.
fn visit(options: &Options, current: &str, depth: usize, failures: &mut u32) {
    let normalized = path::normalize(current);
    let metadata = match fs::metadata(&normalized) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("find: {current}: {error}");
            *failures += 1;
            return;
        }
    };
    let is_dir = metadata.is_dir();
    let selected = options
        .kind
        .is_none_or(|kind| (kind == Kind::Dir) == is_dir);
    let name = path::file_name(&normalized).unwrap_or(&normalized);
    if selected && options.name.as_deref().is_none_or(|glob| glob_match(glob, name)) {
        println!("{normalized}");
    }
    if !is_dir {
        return;
    }
    if options.max_depth.is_some_and(|limit| depth >= limit) {
        return;
    }
    let entries = match fs::list(&normalized) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("find: {normalized}: {error}");
            *failures += 1;
            return;
        }
    };
    for entry in entries {
        // `.` and `..` are not entries the service reports, but a future
        // directory listing that did would loop the walk here.
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let child = path::join(&normalized, &entry.name);
        visit(options, &child, depth + 1, failures);
    }
}

/// `*` and `?` wildcards, matched against a whole name.
fn glob_match(pattern: &str, name: &str) -> bool {
    let pattern = pattern.as_bytes();
    let name = name.as_bytes();
    let (mut p, mut n) = (0usize, 0usize);
    let (mut star, mut resume) = (None::<usize>, 0usize);
    while n < name.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some(p);
                resume = n;
                p += 1;
            }
            Some(b'?') => {
                p += 1;
                n += 1;
            }
            Some(byte) if *byte == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                // Backtrack to the last `*` and let it eat one more byte.
                Some(position) => {
                    p = position + 1;
                    resume += 1;
                    n = resume;
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}
