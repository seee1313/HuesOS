//! `/bin/tar.elf` — POSIX `ustar` archives.
//!
//! `tar -cf <archive> [-C <dir>] <path>...`
//! `tar -tf <archive>`
//! `tar -xf <archive> [-C <dir>]`
//!
//! The format is POSIX.1-1988 `ustar`: 512-byte headers, octal size and mode
//! fields, a `ustar\0` magic, and `./`-free member names that a `find`-style
//! walk produces. Directories are stored as `name/` with typeflag `5`, so
//! extraction recreates them before their contents arrive. `-C` applies to the
//! archive's *members*: `-cf` stores paths without their leading directory, and
//! `-xf` extracts into `<dir>`.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use huesos_std::prelude::*;

huesos_std::entry!(run);

/// A malformed archive or member the tool refuses to touch.
fn invalid(message: &'static str) -> Error {
    Error::from(Error::invalid(message))
}

/// Archive blocks are 512 bytes; member data is zero-padded to a block.
const BLOCK: usize = 512;

/// Header field offsets, POSIX ustar.
const OFF_NAME: usize = 0;
const OFF_MODE: usize = 100;
const OFF_UID: usize = 108;
const OFF_GID: usize = 116;
const OFF_SIZE: usize = 124;
const OFF_MTIME: usize = 136;
const OFF_CHECKSUM: usize = 148;
const OFF_TYPEFLAG: usize = 156;
const OFF_MAGIC: usize = 257;
const OFF_UNAME: usize = 265;
const OFF_GNAME: usize = 297;

const TYPE_FILE: u8 = b'0';
const TYPE_DIR: u8 = b'5';

enum Mode {
    Create {
        archive: String,
        base: String,
        paths: Vec<String>,
    },
    List {
        archive: String,
    },
    Extract {
        archive: String,
        base: String,
    },
}

fn run() -> i32 {
    let args = args();
    let Some(flag_word) = args.first() else {
        usage();
        return 2;
    };
    // The classic form is one word: `-cf`, `-tf`, `-xf`.
    let flags: String = flag_word.trim_start_matches('-').into();
    if flags.is_empty() {
        usage();
        return 2;
    }
    let letters: Vec<char> = flags.chars().collect();
    let operation = match letters
        .iter()
        .find(|letter| matches!(letter, 'c' | 't' | 'x'))
    {
        Some('c') => 'c',
        Some('t') => 't',
        Some('x') => 'x',
        _ => {
            eprintln!("tar: one of -c, -t or -x is required");
            return 2;
        }
    };
    let takes_archive = letters.contains(&'f');

    let mut index = 1;
    let mut archive: Option<String> = None;
    if takes_archive {
        match args.get(index) {
            Some(name) => archive = Some(String::from(name.as_str())),
            None => {
                eprintln!("tar: -f needs an archive path");
                return 2;
            }
        }
        index += 1;
    }

    let mut base = String::from(".");
    let mut members: Vec<String> = Vec::new();
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "-C" || arg == "--directory" {
            index += 1;
            match args.get(index) {
                Some(directory) => base = path::normalize(directory),
                None => {
                    eprintln!("tar: -C needs a directory");
                    return 2;
                }
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            eprintln!("tar: unsupported option '{arg}'");
            return 2;
        } else {
            members.push(String::from(arg));
        }
        index += 1;
    }

    let Some(archive) = archive else {
        eprintln!("tar: -f is required (there is no tape device)");
        return 2;
    };

    let mode = match operation {
        'c' => {
            if members.is_empty() {
                eprintln!("tar: nothing to archive");
                return 2;
            }
            Mode::Create {
                archive,
                base,
                paths: members,
            }
        }
        't' => Mode::List { archive },
        _ => Mode::Extract { archive, base },
    };

    let result = match mode {
        Mode::Create {
            archive,
            base,
            paths,
        } => create(&archive, &base, &paths),
        Mode::List { archive } => list(&archive),
        Mode::Extract { archive, base } => extract(&archive, &base),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("tar: {error}");
            1
        }
    }
}

fn usage() {
    println!("usage: tar -cf <archive> [-C <dir>] <path>...");
    println!("       tar -tf <archive>");
    println!("       tar -xf <archive> [-C <dir>]");
}

/// Archive the paths in `paths`, named relative to `base`.
fn create(archive: &str, base: &str, paths: &[String]) -> Result<()> {
    let mut out = fs::File::create(&path::normalize(archive))?;
    for requested in paths {
        let source = if path::is_absolute(requested) {
            path::normalize(requested)
        } else {
            path::join(base, requested)
        };
        let name = member_name(requested);
        append(&mut out, &source, &name)?;
    }
    // Two zero blocks terminate the archive.
    let zeros = [0u8; BLOCK];
    io::write_all(&mut out, &zeros)?;
    io::write_all(&mut out, &zeros)?;
    out.fsync()
}

/// The name stored in the archive: no leading `/`, no `./`.
fn member_name(requested: &str) -> String {
    let trimmed = requested.trim_start_matches("./");
    let trimmed = trimmed.trim_start_matches('/');
    String::from(trimmed)
}

/// Append `source` (and its children) to `out` as `name`.
fn append(out: &mut fs::File, source: &str, name: &str) -> Result<()> {
    let metadata = fs::metadata(source)?;
    if metadata.is_dir() {
        let mut directory_name = String::from(name);
        if !directory_name.ends_with('/') {
            directory_name.push('/');
        }
        write_header(out, &directory_name, metadata.len(), TYPE_DIR, 0o755)?;
        let entries = fs::list(source)?;
        let mut names: Vec<&Entry> = entries.iter().collect();
        names.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        for entry in names {
            let child_source = path::join(source, &entry.name);
            let child_name = format!("{}/{}", name.trim_end_matches('/'), entry.name);
            append(out, &child_source, &child_name)?;
        }
        return Ok(());
    }

    let mut file = fs::File::open(source)?;
    let mut data = Vec::new();
    io::read_to_end(&mut file, &mut data)?;
    write_header(out, name, data.len() as u64, TYPE_FILE, 0o644)?;
    io::write_all(out, &data)?;
    let padding = (BLOCK - data.len() % BLOCK) % BLOCK;
    if padding > 0 {
        let zeros = [0u8; BLOCK];
        io::write_all(out, &zeros[..padding])?;
    }
    Ok(())
}

fn write_header(out: &mut fs::File, name: &str, size: u64, typeflag: u8, mode: u32) -> Result<()> {
    if name.len() > 100 {
        return Err(invalid("member name longer than 100 bytes"));
    }
    let mut header = [0u8; BLOCK];
    header[OFF_NAME..OFF_NAME + name.len()].copy_from_slice(name.as_bytes());
    write_octal(&mut header, OFF_MODE, 8, u64::from(mode));
    write_octal(&mut header, OFF_UID, 8, 0);
    write_octal(&mut header, OFF_GID, 8, 0);
    write_octal(&mut header, OFF_SIZE, 12, size);
    write_octal(&mut header, OFF_MTIME, 12, 0);
    header[OFF_TYPEFLAG] = typeflag;
    header[OFF_MAGIC..OFF_MAGIC + 6].copy_from_slice(b"ustar\0");
    header[OFF_MAGIC + 6..OFF_MAGIC + 8].copy_from_slice(b"00");
    for slot in &mut header[OFF_UNAME..OFF_UNAME + 32] {
        *slot = 0;
    }
    header[OFF_UNAME..OFF_UNAME + 5].copy_from_slice(b"root\0");
    header[OFF_GNAME..OFF_GNAME + 5].copy_from_slice(b"root\0");
    // The checksum is computed with its own field filled with spaces.
    for slot in &mut header[OFF_CHECKSUM..OFF_CHECKSUM + 8] {
        *slot = b' ';
    }
    let sum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    write_octal(&mut header, OFF_CHECKSUM, 8, sum);
    header[OFF_CHECKSUM + 7] = b' ';
    io::write_all(out, &header)
}

/// Write `value` as `width - 1` octal digits followed by NUL.
fn write_octal(header: &mut [u8; BLOCK], offset: usize, width: usize, value: u64) {
    let digits = width - 1;
    let text = format!("{value:0digits$o}");
    let bytes = text.as_bytes();
    let start = offset + digits.saturating_sub(bytes.len());
    for slot in &mut header[offset..offset + digits] {
        *slot = b'0';
    }
    let copy = bytes.len().min(digits);
    header[start..start + copy].copy_from_slice(&bytes[bytes.len() - copy..]);
    header[offset + digits] = 0;
}

fn list(archive: &str) -> Result<()> {
    let mut file = fs::File::open(&path::normalize(archive))?;
    let out = io::stdout();
    let mut sink = out;
    loop {
        let Some(header) = read_header(&mut file)? else {
            return Ok(());
        };
        let name = header_name(&header);
        let size = parse_octal(&header[OFF_SIZE..OFF_SIZE + 12])?;
        let _ = io::write_all(&mut sink, name.as_bytes());
        let _ = io::write_all(&mut sink, b"\n");
        skip(&mut file, size)?;
    }
}

fn extract(archive: &str, base: &str) -> Result<()> {
    let mut file = fs::File::open(&path::normalize(archive))?;
    loop {
        let Some(header) = read_header(&mut file)? else {
            return Ok(());
        };
        let name = header_name(&header);
        let typeflag = header[OFF_TYPEFLAG];
        let size = parse_octal(&header[OFF_SIZE..OFF_SIZE + 12])?;
        if name.contains("..") {
            return Err(invalid("member name escapes the target directory"));
        }
        let target = path::join(base, &name);
        match typeflag {
            TYPE_DIR => {
                ensure_directory(&target)?;
            }
            TYPE_FILE | 0 => {
                if let Some(parent) = path::parent(&target) {
                    ensure_directory(&parent)?;
                }
                let mut created = fs::File::create(&target)?;
                let mut remaining = size;
                let mut chunk = [0u8; BLOCK];
                while remaining > 0 {
                    let want = (remaining as usize).min(BLOCK);
                    read_exact(&mut file, &mut chunk[..want])?;
                    io::write_all(&mut created, &chunk[..want])?;
                    remaining -= want as u64;
                }
                created.fsync()?;
                skip(
                    &mut file,
                    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64,
                )?;
                println!("{name}");
                continue;
            }
            other => {
                // An archive with links or devices in it is not something
                // HuesOS can represent; refuse rather than silently skip.
                let _ = other;
                return Err(invalid("unsupported member type in archive"));
            }
        }
        skip(&mut file, size)?;
        skip(
            &mut file,
            (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64,
        )?;
        println!("{name}");
    }
}

/// Create `directory` and its parents, tolerating an existing directory.
fn ensure_directory(directory: &str) -> Result<()> {
    let normalized = path::normalize(directory);
    if normalized.is_empty() || normalized == "." || normalized == "/" {
        return Ok(());
    }
    if fs::metadata(&normalized)
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        return Ok(());
    }
    if let Some(parent) = path::parent(&normalized) {
        ensure_directory(&parent)?;
    }
    match fs::create_dir(&normalized) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

fn read_header(file: &mut fs::File) -> Result<Option<[u8; BLOCK]>> {
    let mut header = [0u8; BLOCK];
    if !read_exact_or_eof(file, &mut header)? {
        return Ok(None);
    }
    // Two zero blocks mark the end of the archive; one zero block is padding
    // that can also end a truncated (but readable) stream.
    if header.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let stored = parse_octal(&header[OFF_CHECKSUM..OFF_CHECKSUM + 8])?;
    let mut copy = header;
    for slot in &mut copy[OFF_CHECKSUM..OFF_CHECKSUM + 8] {
        *slot = b' ';
    }
    let computed: u64 = copy.iter().map(|byte| u64::from(*byte)).sum();
    if stored != computed {
        return Err(invalid("header checksum mismatch"));
    }
    Ok(Some(header))
}

fn header_name(header: &[u8; BLOCK]) -> String {
    let name_end = header[OFF_NAME..OFF_NAME + 100]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    let mut name = String::from_utf8_lossy(&header[OFF_NAME..OFF_NAME + name_end]).into_owned();
    let prefix_end = header[OFF_MAGIC + 8 + 33..OFF_MAGIC + 8 + 155]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(0);
    let prefix_end = prefix_end.min(155 - 33);
    if prefix_end > 0 {
        // A `prefix` field is only present when the magic actually says
        // `ustar`; a plain v7 header leaves that area zeroed.
        let magic_ok = &header[OFF_MAGIC..OFF_MAGIC + 5] == b"ustar";
        if magic_ok {
            let prefix = String::from_utf8_lossy(
                &header[OFF_MAGIC + 8 + 33..OFF_MAGIC + 8 + 33 + prefix_end],
            )
            .into_owned();
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
    }
    name
}

fn parse_octal(field: &[u8]) -> Result<u64> {
    let mut value = 0u64;
    let mut seen = false;
    for byte in field {
        match byte {
            b'0'..=b'7' => {
                value = value * 8 + u64::from(byte - b'0');
                seen = true;
            }
            b' ' | 0 if !seen => continue,
            b' ' | 0 => break,
            _ => return Err(invalid("bad octal field")),
        }
    }
    Ok(value)
}

fn read_exact(file: &mut fs::File, buffer: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = file.read(&mut buffer[filled..])?;
        if read == 0 {
            return Err(invalid("archive truncated"));
        }
        filled += read;
    }
    Ok(())
}

/// Read a full block, reporting a clean EOF instead of an error.
fn read_exact_or_eof(file: &mut fs::File, buffer: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = file.read(&mut buffer[filled..])?;
        if read == 0 {
            return Ok(false);
        }
        filled += read;
    }
    Ok(true)
}

/// Discard `count` bytes from `file`.
fn skip(file: &mut fs::File, count: u64) -> Result<()> {
    let mut remaining = count;
    let mut scratch = [0u8; BLOCK];
    while remaining > 0 {
        let want = (remaining as usize).min(BLOCK);
        read_exact(file, &mut scratch[..want])?;
        remaining -= want as u64;
    }
    Ok(())
}
