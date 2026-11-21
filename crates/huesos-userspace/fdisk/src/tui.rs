//! Interactive screen mode for `fdisk`.
//!
//! The batch subcommands (`list`, `add`, `del`, ...) exist so scripts and the
//! boot smoke can drive the tool without a terminal. This module is the
//! interactive counterpart: it draws the disk geometry, a proportional map of
//! the sectors and the partition table, then reads keystrokes until the user
//! quits. Edits land in the working `GptDisk`, which is a copy of what was read
//! from the store; `w` is the only command that writes it back.
//!
//! The screen is plain ANSI: the terminal in HuesOS is a serial console, so no
//! cursor-addressing library is involved -- a full redraw (`clear` + text) is
//! both simpler and faster than diffing cells at 115200 baud.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_gpt::{parse_size_lbas, GptDisk, Guid, LBA_SIZE};
use huesos_std::io::{self, Read, Write};
use huesos_std::tui;

use crate::{Backend, BlockIo512, HXFS_BLOCK_SIZE};

/// Write formatted text to the screen and flush it.
///
/// `huesos_std::io::Write` is the byte-level trait (there is no `fmt::Write`
/// for a channel), so formatting goes through `format!` first.
macro_rules! put {
    ($out:expr, $($arg:tt)*) => {{
        let text = alloc::format!($($arg)*);
        let _ = io::write_all($out, text.as_bytes());
        let _ = $out.flush();
    }};
}

/// Width of the sector map, in columns.
const MAP_WIDTH: usize = 64;

/// One keystroke.
enum Key {
    Char(u8),
    Up,
    Down,
    Left,
    Right,
    /// Anything that is not a printable key or a recognised escape sequence.
    Other,
    /// `Ctrl-C`.
    Interrupt,
    Eof,
}

/// Run the interactive screen against `io` until the user quits.
///
/// Returns the process status: `0` for a clean exit, `1` when the store could
/// not be written.
pub fn interactive(io: &mut Backend, label: &str, writable: bool) -> i32 {
    let total_lbas = io.total_lbas();
    let mut disk = GptDisk::read_from(io).ok();
    let mut dirty = false;
    let mut status = if disk.is_some() {
        String::from("GPT read from the store")
    } else {
        String::from("no partition table -- press g to create one")
    };

    let mut out = io::stdout();
    loop {
        draw(&mut out, label, total_lbas, disk.as_ref(), dirty, &status);
        let key = read_key();
        status.clear();
        match key {
            Key::Eof => return 0,
            Key::Interrupt => {
                if dirty {
                    quit_without_saving(&mut out, &mut dirty);
                }
                return 0;
            }
            Key::Other => {}
            Key::Char(b'm') | Key::Char(b'?') => {
                draw_help(&mut out);
                let _ = read_key();
            }
            Key::Char(b'p') => status.push_str("re-read from the store"),
            Key::Char(b'n') => match new_partition(&mut disk, total_lbas, &mut out) {
                Ok(text) => {
                    status = text;
                    dirty = true;
                }
                Err(text) => status = text,
            },
            Key::Char(b'd') => match delete_partition(&mut disk, &mut out) {
                Ok(text) => {
                    status = text;
                    dirty = true;
                }
                Err(text) => status = text,
            },
            Key::Char(b'r') => match resize_partition(&mut disk, &mut out) {
                Ok(text) => {
                    status = text;
                    dirty = true;
                }
                Err(text) => status = text,
            },
            Key::Char(b't') => match retype_partition(&mut disk, &mut out) {
                Ok(text) => {
                    status = text;
                    dirty = true;
                }
                Err(text) => status = text,
            },
            Key::Char(b'c') => match rename_partition(&mut disk, &mut out) {
                Ok(text) => {
                    status = text;
                    dirty = true;
                }
                Err(text) => status = text,
            },
            Key::Char(b'g') | Key::Char(b'i') => {
                match GptDisk::init_empty(total_lbas, 0x4855_4553_0001) {
                    Ok(fresh) => {
                        disk = Some(fresh);
                        dirty = true;
                        status.push_str("new GPT in memory -- press w to write it");
                    }
                    Err(error) => status = error,
                }
            }
            Key::Char(b'v') => {
                let report = huesos_gpt::verify_disk_io(io);
                status = format!(
                    "verify: mbr={} primary_crc={} backup_crc={} entries_crc={} overlaps={} errors={}",
                    report.protective_mbr,
                    report.primary_crc_ok,
                    report.backup_crc_ok,
                    report.entries_crc_ok,
                    report.overlaps,
                    report.errors.len()
                );
            }
            Key::Char(b'w') => {
                let Some(table) = disk.as_mut() else {
                    status = String::from("nothing to write: create a table first (g)");
                    continue;
                };
                if !writable {
                    status = String::from("this store was opened read-only");
                    continue;
                }
                match table.write_to(io, false).and_then(|()| io.flush()) {
                    Ok(()) => {
                        dirty = false;
                        status = String::from("table written and flushed");
                    }
                    Err(error) => {
                        put!(&mut out, "\x1b[2K\rfdisk: {error}\r\n");
                        return 1;
                    }
                }
            }
            Key::Char(b'q') => {
                if dirty {
                    quit_without_saving(&mut out, &mut dirty);
                }
                return 0;
            }
            Key::Char(other) => status = format!("unknown command '{}' -- press m", other as char),
            Key::Up | Key::Down | Key::Left | Key::Right => {}
        }
    }
}

/// Clear the screen and draw one full frame.
fn draw(
    out: &mut impl Write,
    label: &str,
    total_lbas: u64,
    disk: Option<&GptDisk>,
    dirty: bool,
    status: &str,
) {
    let mut text = String::new();
    text.push_str("\x1b[2J\x1b[H");
    text.push_str(&format!(
        "\x1b[7m{}\x1b[0m\r\n",
        tui::fit(" HuesOS fdisk ", 62)
    ));
    text.push_str(&format!(
        " Disk   : {label}\r\n Sectors: {total_lbas} x {} bytes ({})\r\n GPT    : {}\r\n",
        LBA_SIZE,
        human_size(total_lbas * LBA_SIZE as u64),
        if disk.is_some() { "present" } else { "absent" }
    ));
    if dirty {
        text.push_str(&format!(
            " State  : {} (w writes, q discards)\r\n",
            tui::colored("MODIFIED", tui::Color::Yellow)
        ));
    } else {
        text.push_str(" State  : CLEAN\r\n");
    }
    text.push_str("\r\n");
    text.push_str(&sector_map(disk, total_lbas));
    text.push_str("\r\n");
    text.push_str(&partition_table(disk));
    text.push_str("\r\n");
    if !status.is_empty() {
        text.push_str(&format!(" {status}\r\n"));
    }
    text.push_str(" m help   p print   n new   d delete   r resize   t type   c name\r\n");
    text.push_str(" g/i new GPT   v verify   w write   q quit\r\n");
    put!(out, "{text}");
}

/// Proportional bar of the disk: table overhead, every partition, free space.
fn sector_map(disk: Option<&GptDisk>, total_lbas: u64) -> String {
    let mut map = String::new();
    let mut segments: Vec<(u64, u64, String)> = Vec::new();
    // The GPT itself: protective MBR + primary header + entry array.
    let mut first_usable = 34u64;
    if let Some(table) = disk {
        first_usable = table.primary.first_usable_lba.max(34);
        for (num, entry) in table.active_partitions() {
            let len = entry.size_lbas();
            let label = format!(
                " #{} {} {} ",
                num,
                short_type(&entry.type_guid),
                human_size(len * LBA_SIZE as u64)
            );
            segments.push((entry.starting_lba, len, label));
        }
    }
    let _ = HXFS_BLOCK_SIZE;

    let mut bar = String::new();
    bar.push_str(" [MBR+GPT]");
    let mut cursor = first_usable;
    for (start, len, label) in segments {
        if start > cursor {
            let gap = start - cursor;
            let cells = cells_for(gap, total_lbas);
            bar.push_str(&format!(
                "[{}FREE {}]",
                ".".repeat(cells.min(8)),
                human_size(gap * LBA_SIZE as u64)
            ));
        }
        bar.push_str(&label);
        cursor = start.saturating_add(len);
    }
    if cursor < total_lbas {
        let gap = total_lbas - cursor;
        bar.push_str(&format!(
            "[{}FREE {}]",
            ".".repeat(cells_for(gap, total_lbas).min(8)),
            human_size(gap * LBA_SIZE as u64)
        ));
    }
    map.push_str(&format!(" Map    :{bar}\r\n"));
    map.push_str(&format!(
        "        : {} of {} used\r\n",
        human_size(used_lbas(disk, total_lbas) * LBA_SIZE as u64),
        human_size(total_lbas * LBA_SIZE as u64)
    ));
    map
}

/// Columns for `len` out of `total`, at least one so nothing disappears.
fn cells_for(len: u64, total: u64) -> usize {
    if total == 0 {
        return 1;
    }
    let cells = (len as u128 * MAP_WIDTH as u128 / total as u128) as usize;
    cells.max(1)
}

/// LBAs covered by partitions.
fn used_lbas(disk: Option<&GptDisk>, _total: u64) -> u64 {
    match disk {
        Some(table) => table
            .active_partitions()
            .iter()
            .map(|(_, entry)| entry.size_lbas())
            .sum(),
        None => 0,
    }
}

/// The partition table, or a line saying there is none.
fn partition_table(disk: Option<&GptDisk>) -> String {
    let Some(table) = disk else {
        return String::from(" no partitions (no table)\r\n");
    };
    let mut text = String::from(" #  START        END          SIZE      TYPE      NAME\r\n");
    let parts = table.active_partitions();
    if parts.is_empty() {
        text.push_str(" (no partitions)\r\n");
        return text;
    }
    for (num, entry) in parts {
        text.push_str(&format!(
            " {:<2} {:<12} {:<12} {:<9} {:<9} {}\r\n",
            num,
            entry.starting_lba,
            entry.ending_lba,
            human_size(entry.size_lbas() * LBA_SIZE as u64),
            short_type(&entry.type_guid),
            if entry.name.is_empty() {
                "-"
            } else {
                entry.name.as_str()
            }
        ));
    }
    text
}

/// Compact type name for the map and the table.
fn short_type(guid: &Guid) -> &'static str {
    let label = guid.type_label();
    if label.contains("HxFS") {
        "HxFS"
    } else if label.contains("EFI") || label.contains("ESP") {
        "EFI"
    } else if label.contains("Linux") || label.contains("Basic") {
        "data"
    } else if label.contains("Swap") {
        "swap"
    } else {
        "part"
    }
}

fn draw_help(out: &mut impl Write) {
    let text = "\x1b[2J\x1b[H\
        fdisk commands\r\n\
        \r\n\
        \x1b[1mp\x1b[0m  print the sector map and the partition table\r\n\
        \x1b[1mn\x1b[0m  new partition (asks for size, e.g. 16M, 200G or +16M)\r\n\
        \x1b[1md\x1b[0m  delete a partition\r\n\
        \x1b[1mr\x1b[0m  resize a partition\r\n\
        \x1b[1mt\x1b[0m  change a partition type (hxfs, efi, data, swap)\r\n\
        \x1b[1mc\x1b[0m  rename a partition\r\n\
        \x1b[1mg\x1b[0m  create a fresh protective MBR + GPT in memory\r\n\
        \x1b[1mv\x1b[0m  verify the CRCs and the bounds on the store\r\n\
        \x1b[1mw\x1b[0m  write the table and flush\r\n\
        \x1b[1mq\x1b[0m  quit (discards unsaved changes)\r\n\
        \r\n\
        press any key to return\r\n";
    put!(out, "{text}");
}

fn new_partition(
    disk: &mut Option<GptDisk>,
    total_lbas: u64,
    out: &mut impl Write,
) -> Result<String, String> {
    let Some(table) = disk.as_mut() else {
        return Err(String::from("no table: press g to create one"));
    };
    let free = free_lbas(table, total_lbas);
    let default_size = free.max(2048);
    let answer = ask(
        out,
        &format!("size [{}]", human_size(default_size * LBA_SIZE as u64)),
    )?;
    let size_lbas = if answer.trim().is_empty() {
        default_size
    } else {
        parse_size_lbas(answer.trim()).map_err(|error| format!("bad size: {error}"))?
    };
    let name = ask(out, "name [HuesOS]")?;
    let name = if name.trim().is_empty() {
        "HuesOS"
    } else {
        name.trim()
    };
    let num = table.add_partition(
        Guid::parse_type("hxfs").ok_or_else(|| String::from("hxfs is not a known type"))?,
        None,
        size_lbas,
        name,
        0xA11CE,
    )?;
    Ok(format!(
        "partition {num} created: {} {}",
        human_size(size_lbas * LBA_SIZE as u64),
        name
    ))
}

fn delete_partition(disk: &mut Option<GptDisk>, out: &mut impl Write) -> Result<String, String> {
    let Some(table) = disk.as_mut() else {
        return Err(String::from("no table"));
    };
    let answer = ask(out, "partition number")?;
    let num = number(&answer)?;
    table.delete_partition(num)?;
    Ok(format!("partition {num} deleted"))
}

fn resize_partition(disk: &mut Option<GptDisk>, out: &mut impl Write) -> Result<String, String> {
    let Some(table) = disk.as_mut() else {
        return Err(String::from("no table"));
    };
    let num = number(&ask(out, "partition number")?)?;
    let size_lbas = parse_size_lbas(ask(out, "new size")?.trim())
        .map_err(|error| format!("bad size: {error}"))?;
    table.resize_partition(num, size_lbas)?;
    Ok(format!(
        "partition {num} resized to {}",
        human_size(size_lbas * LBA_SIZE as u64)
    ))
}

fn retype_partition(disk: &mut Option<GptDisk>, out: &mut impl Write) -> Result<String, String> {
    let Some(table) = disk.as_mut() else {
        return Err(String::from("no table"));
    };
    let num = number(&ask(out, "partition number")?)?;
    let kind = ask(out, "type (hxfs, efi, data, swap)")?;
    let guid =
        Guid::parse_type(kind.trim()).ok_or_else(|| format!("unknown type '{}'", kind.trim()))?;
    table.set_partition_type(num, guid)?;
    Ok(format!("partition {num} is now {}", kind.trim()))
}

fn rename_partition(disk: &mut Option<GptDisk>, out: &mut impl Write) -> Result<String, String> {
    let Some(table) = disk.as_mut() else {
        return Err(String::from("no table"));
    };
    let num = number(&ask(out, "partition number")?)?;
    let name = ask(out, "new name")?;
    table.set_partition_name(num, name.trim())?;
    Ok(format!("partition {num} renamed to {}", name.trim()))
}

/// Free LBAs between the first usable sector and the end of the disk.
fn free_lbas(table: &GptDisk, total_lbas: u64) -> u64 {
    let last_usable = table
        .primary
        .last_usable_lba
        .min(total_lbas.saturating_sub(34));
    let mut cursor = table.primary.first_usable_lba.max(34);
    for (_, entry) in table.active_partitions() {
        if entry.starting_lba > cursor {
            return entry.starting_lba - cursor;
        }
        cursor = cursor.max(entry.starting_lba + entry.size_lbas());
    }
    last_usable.saturating_sub(cursor)
}

fn number(text: &str) -> Result<usize, String> {
    text.trim()
        .parse::<usize>()
        .map_err(|_| format!("'{}' is not a partition number", text.trim()))
}

/// Ask a question on the prompt line and read one line back.
fn ask(out: &mut impl Write, prompt: &str) -> Result<String, String> {
    let mut stdin = io::stdin();
    tui::prompt(out, &mut stdin, prompt).ok_or_else(|| String::from("cancelled"))
}

fn quit_without_saving(out: &mut impl Write, dirty: &mut bool) {
    put!(
        out,
        "\r\n unsaved changes were discarded (press w before q to keep them)\r\n"
    );
    *dirty = false;
}

/// Read one key, folding the arrow-key escape sequences.
fn read_key() -> Key {
    let mut stdin = io::stdin();
    let mut byte = [0u8; 1];
    match stdin.read(&mut byte) {
        Ok(0) => Key::Eof,
        Ok(_) => match byte[0] {
            0x03 => Key::Interrupt,
            0x1b => {
                // `ESC [ A` .. `ESC [ D` are the arrows; anything else is a
                // lone escape and carries no command.
                let mut seq = [0u8; 2];
                if stdin.read(&mut seq[..1]).unwrap_or(0) == 0 {
                    return Key::Other;
                }
                if seq[0] != b'[' {
                    return Key::Other;
                }
                if stdin.read(&mut seq[1..]).unwrap_or(0) == 0 {
                    return Key::Other;
                }
                match seq[1] {
                    b'A' => Key::Up,
                    b'B' => Key::Down,
                    b'C' => Key::Right,
                    b'D' => Key::Left,
                    _ => Key::Other,
                }
            }
            b'\r' | b'\n' => Key::Char(b'\n'),
            other => Key::Char(other),
        },
        Err(_) => Key::Eof,
    }
}

/// `1.5M`, `96M`, `200G`, `1T` -- the shared size formatter every tool uses.
fn human_size(bytes: u64) -> String {
    tui::human_bytes(bytes)
}
