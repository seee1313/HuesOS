//! Interactive screen mode (`cfdisk` / `fdisk` hybrid) for `/bin/fdisk.elf`.
//!
//! Draws disk geometry, detected layout (`GPT` vs bare `raw-hxfs` superfloppy vs
//! blank), a proportional block-element sector map, and an interactive cursor
//! list of partitions and free-space regions inside a box-drawn `huesos_std::tui`
//! frame. Both arrow-key cursor navigation (`↑`/`↓`, `←`/`→` action bar, `Enter`)
//! and classic `fdisk` single-key commands (`m`/`?`, `p`, `n`, `d`, `r`, `t`,
//! `c`, `i`, `g`, `v`, `l`, `w`, `q`) work side-by-side.
//!
//! Edits mutate an in-memory `GptDisk` copy; nothing touches the underlying
//! block device or image file until the operator confirms `w` (`Write`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_gpt::{
    parse_size_lbas, GptDisk, Guid, ALIGN_1MIB_LBAS, GUID_ESP, GUID_HXFS_V7, GUID_LINUX_FS,
    GUID_LINUX_SWAP, GUID_MS_BASIC_DATA, LBA_SIZE,
};
use huesos_hxfs::BareVolume;
use huesos_std::io::{self, Write};
use huesos_std::tui::{self, Color, Key};

use crate::{probe_raw_hxfs, Backend, BlockIo512, HXFS_BLOCK_SIZE};

const FRAME_WIDTH: usize = 96;
const MAP_INNER_WIDTH: usize = 74;

#[derive(Clone, Debug)]
enum SlotKind {
    Partition {
        part_num: usize,
        type_guid: Guid,
        unique_guid: Guid,
        name: String,
    },
    FreeSpace,
}

#[derive(Clone, Debug)]
struct DiskSlot {
    start_lba: u64,
    end_lba: u64,
    kind: SlotKind,
}

impl DiskSlot {
    fn size_lbas(&self) -> u64 {
        if self.end_lba >= self.start_lba {
            self.end_lba - self.start_lba + 1
        } else {
            0
        }
    }

    fn size_bytes(&self) -> u64 {
        self.size_lbas().saturating_mul(LBA_SIZE as u64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    New,
    Delete,
    Resize,
    Type,
    Name,
    Info,
    InitGpt,
    Verify,
    Write,
    Help,
    Quit,
}

const ACTIONS_PARTITION: &[Action] = &[
    Action::Info,
    Action::Resize,
    Action::Type,
    Action::Name,
    Action::Delete,
    Action::Verify,
    Action::Write,
    Action::Help,
    Action::Quit,
];

const ACTIONS_FREE: &[Action] = &[
    Action::New,
    Action::InitGpt,
    Action::Verify,
    Action::Write,
    Action::Help,
    Action::Quit,
];

const ACTIONS_NO_TABLE: &[Action] = &[Action::InitGpt, Action::Verify, Action::Help, Action::Quit];

impl Action {
    fn label(self) -> &'static str {
        match self {
            Action::New => "n:New",
            Action::Delete => "d:Delete",
            Action::Resize => "r:Resize",
            Action::Type => "t:Type",
            Action::Name => "c:Name",
            Action::Info => "i:Info",
            Action::InitGpt => "g:NewGPT",
            Action::Verify => "v:Verify",
            Action::Write => "w:Write",
            Action::Help => "m:Help",
            Action::Quit => "q:Quit",
        }
    }
}

struct EditorState {
    label: String,
    writable: bool,
    total_lbas: u64,
    disk: Option<GptDisk>,
    raw_hxfs: Option<BareVolume>,
    dirty: bool,
    selected_row: usize,
    selected_action: usize,
    quit_armed: bool,
    status: String,
    status_color: Color,
}

impl EditorState {
    fn active_actions<'a>(&self, slots: &[DiskSlot]) -> &'a [Action] {
        if self.disk.is_none() {
            return ACTIONS_NO_TABLE;
        }
        match slots.get(self.selected_row).map(|s| &s.kind) {
            Some(SlotKind::Partition { .. }) => ACTIONS_PARTITION,
            _ => ACTIONS_FREE,
        }
    }

    fn set_ok(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_color = Color::Green;
        self.quit_armed = false;
    }

    fn set_info(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_color = Color::Cyan;
        self.quit_armed = false;
    }

    fn set_warn(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_color = Color::Yellow;
    }

    fn set_err(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_color = Color::Red;
        self.quit_armed = false;
    }
}

/// Run the interactive partition manager against `io` until the user quits.
pub fn interactive(io: &mut Backend, label: &str, writable: bool) -> i32 {
    let _ = HXFS_BLOCK_SIZE;
    let total_lbas = io.total_lbas();
    let disk = GptDisk::read_from(io).ok();
    let raw_hxfs = if disk.is_none() {
        probe_raw_hxfs(io)
    } else {
        None
    };

    let (init_status, init_color) = if let Some(ref d) = disk {
        let count = d.active_partitions().len();
        (
            format!(
                "GPT loaded ({count} partition(s)) -- Up/Down select, Left/Right/Enter or hotkeys"
            ),
            Color::Green,
        )
    } else if let Some(ref bare) = raw_hxfs {
        (
            format!(
                "Whole-disk {} ({}) mounted without GPT -- press g to initialize GPT",
                bare.layout_tag(),
                bare.layout_label()
            ),
            Color::Yellow,
        )
    } else {
        (
            String::from("No GPT partition table found -- press g to create a fresh GPT"),
            Color::Yellow,
        )
    };

    let initial_slots = build_slots(disk.as_ref(), total_lbas);
    let initial_selected_row = default_selected_row(&initial_slots);

    let mut state = EditorState {
        label: String::from(label),
        writable,
        total_lbas,
        disk,
        raw_hxfs,
        dirty: false,
        selected_row: initial_selected_row,
        selected_action: 0,
        quit_armed: false,
        status: init_status,
        status_color: init_color,
    };

    let mut screen = tui::Screen::new(io::stdout());
    let mut input = io::stdin();
    let _ = screen.hide_cursor();

    let exit_code = loop {
        let slots = build_slots(state.disk.as_ref(), state.total_lbas);
        if !slots.is_empty() && state.selected_row >= slots.len() {
            state.selected_row = slots.len() - 1;
        }
        let actions = state.active_actions(&slots);
        if !actions.is_empty() && state.selected_action >= actions.len() {
            state.selected_action = 0;
        }

        let _ = draw_main(&mut screen, &state, &slots, actions);

        let Some(key) = tui::read_key(&mut input) else {
            break 0;
        };

        match key {
            Key::Ctrl(3) => break 0,
            Key::Up | Key::Char(b'k') => {
                state.quit_armed = false;
                if state.selected_row > 0 {
                    state.selected_row -= 1;
                    state.selected_action = 0;
                }
            }
            Key::Down | Key::Char(b'j') => {
                state.quit_armed = false;
                if state.selected_row + 1 < slots.len() {
                    state.selected_row += 1;
                    state.selected_action = 0;
                }
            }
            Key::Home => {
                state.quit_armed = false;
                state.selected_row = 0;
                state.selected_action = 0;
            }
            Key::End => {
                state.quit_armed = false;
                if !slots.is_empty() {
                    state.selected_row = slots.len() - 1;
                    state.selected_action = 0;
                }
            }
            Key::Left => {
                state.quit_armed = false;
                if !actions.is_empty() {
                    state.selected_action = if state.selected_action == 0 {
                        actions.len() - 1
                    } else {
                        state.selected_action - 1
                    };
                }
            }
            Key::Right | Key::Tab => {
                state.quit_armed = false;
                if !actions.is_empty() {
                    state.selected_action = (state.selected_action + 1) % actions.len();
                }
            }
            Key::Enter => {
                if let Some(&act) = actions.get(state.selected_action) {
                    if let Some(code) =
                        dispatch_action(act, io, &mut state, &slots, &mut screen, &mut input)
                    {
                        break code;
                    }
                }
            }
            Key::Char(b'n') | Key::Char(b'N') => {
                let _ =
                    dispatch_action(Action::New, io, &mut state, &slots, &mut screen, &mut input);
            }
            Key::Char(b'd') | Key::Char(b'D') | Key::Delete => {
                let _ = dispatch_action(
                    Action::Delete,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                );
            }
            Key::Char(b'r') | Key::Char(b'R') => {
                let _ = dispatch_action(
                    Action::Resize,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                );
            }
            Key::Char(b't') | Key::Char(b'T') => {
                let _ = dispatch_action(
                    Action::Type,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                );
            }
            Key::Char(b'c') | Key::Char(b'C') => {
                let _ = dispatch_action(
                    Action::Name,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                );
            }
            Key::Char(b'i') | Key::Char(b'I') => {
                let _ = dispatch_action(
                    Action::Info,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                );
            }
            Key::Char(b'g') | Key::Char(b'G') => {
                let _ = dispatch_action(
                    Action::InitGpt,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                );
            }
            Key::Char(b'v') | Key::Char(b'V') => {
                let _ = dispatch_action(
                    Action::Verify,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                );
            }
            Key::Char(b'w') | Key::Char(b'W') => {
                if let Some(code) = dispatch_action(
                    Action::Write,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                ) {
                    break code;
                }
            }
            Key::Char(b'm') | Key::Char(b'M') | Key::Char(b'?') | Key::Char(b'h') => {
                let _ = dispatch_action(
                    Action::Help,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                );
            }
            Key::Char(b'l') | Key::Char(b'L') => {
                draw_types_modal(&mut screen);
                let _ = tui::read_key(&mut input);
                state.set_info("returned from partition type list");
            }
            Key::Char(b'p') | Key::Char(b'P') => {
                state.disk = GptDisk::read_from(io).ok();
                state.raw_hxfs = if state.disk.is_none() {
                    probe_raw_hxfs(io)
                } else {
                    None
                };
                state.dirty = false;
                let reloaded_slots = build_slots(state.disk.as_ref(), state.total_lbas);
                state.selected_row = default_selected_row(&reloaded_slots);
                state.selected_action = 0;
                state.set_info("re-read partition table from disk (unsaved edits discarded)");
            }
            Key::Char(b'q') | Key::Char(b'Q') | Key::Escape => {
                if let Some(code) = dispatch_action(
                    Action::Quit,
                    io,
                    &mut state,
                    &slots,
                    &mut screen,
                    &mut input,
                ) {
                    break code;
                }
            }
            Key::Char(other) => {
                state.set_warn(format!(
                    "unknown key '{}' -- press m or ? for help, q to quit",
                    other as char
                ));
            }
            _ => {}
        }
    };

    let _ = screen.clear();
    let _ = screen.show_cursor();
    let _ = screen.out().flush();
    exit_code
}

fn dispatch_action<W: Write>(
    act: Action,
    io: &mut Backend,
    state: &mut EditorState,
    slots: &[DiskSlot],
    screen: &mut tui::Screen<W>,
    input: &mut io::Stdin,
) -> Option<i32> {
    match act {
        Action::Help => {
            draw_help_modal(screen);
            let _ = tui::read_key(input);
            state.set_info("ready");
            None
        }
        Action::Quit => {
            if state.dirty && !state.quit_armed {
                state.set_warn(
                    "unsaved changes in memory! press q/Esc again to discard, or w to write",
                );
                state.quit_armed = true;
                None
            } else {
                Some(0)
            }
        }
        Action::InitGpt => {
            if state.raw_hxfs.is_some() || state.disk.is_some() {
                let prompt = if state.raw_hxfs.is_some() {
                    "replace raw-hxfs layout in memory with empty GPT? (yes/no) [no]"
                } else {
                    "create empty GPT in memory, clearing all partitions? (yes/no) [no]"
                };
                let Some(ans) = ask_modal(screen, input, prompt) else {
                    state.set_info("cancelled");
                    return None;
                };
                if !matches!(ans.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    state.set_info("kept existing layout");
                    return None;
                }
            }
            match GptDisk::init_empty(state.total_lbas, 0x4855_4553_0001) {
                Ok(fresh) => {
                    state.disk = Some(fresh);
                    state.dirty = true;
                    state.selected_row = 0;
                    state.selected_action = 0;
                    state.set_ok("created fresh Protective MBR + GPT in memory (press w to write)");
                }
                Err(e) => state.set_err(e),
            }
            None
        }
        Action::New => {
            if state.disk.is_none() {
                state.set_warn("no GPT partition table yet -- press g first to create one");
                return None;
            }
            let target_slot = slots
                .get(state.selected_row)
                .filter(|s| matches!(s.kind, SlotKind::FreeSpace) && usable_free_in_slot(s) > 0)
                .or_else(|| {
                    slots
                        .iter()
                        .filter(|s| {
                            matches!(s.kind, SlotKind::FreeSpace) && usable_free_in_slot(s) > 0
                        })
                        .max_by_key(|s| usable_free_in_slot(s))
                });
            let Some(free_slot) = target_slot else {
                state.set_err("no 1 MiB-aligned unallocated space available on disk");
                return None;
            };

            let aligned_start = align_up(free_slot.start_lba, ALIGN_1MIB_LBAS);
            let usable_free = usable_free_in_slot(free_slot);

            let default_human = human_size(usable_free * LBA_SIZE as u64);
            let Some(size_ans) = ask_modal(
                screen,
                input,
                &format!("Partition size (e.g. 16M, 64M, 1G, LBAs) [{default_human}]"),
            ) else {
                state.set_info("new partition cancelled");
                return None;
            };
            let size_lbas = if size_ans.trim().is_empty() {
                usable_free
            } else {
                let trimmed = size_ans.trim().trim_start_matches('+');
                match parse_size_lbas(trimmed) {
                    Ok(v) if v > 0 => v.min(usable_free),
                    Ok(_) => {
                        state.set_err("partition size must be > 0");
                        return None;
                    }
                    Err(e) => {
                        state.set_err(format!("invalid size: {e}"));
                        return None;
                    }
                }
            };

            let Some(type_ans) = ask_modal(
                screen,
                input,
                "Partition type (1/hxfs, 2/efi, 3/linux, 4/swap, 5/basic, UUID) [hxfs]",
            ) else {
                state.set_info("new partition cancelled");
                return None;
            };
            let Some(type_guid) = parse_type_choice(type_ans.trim()) else {
                state.set_err(format!(
                    "unknown type '{}' (press l to list types)",
                    type_ans.trim()
                ));
                return None;
            };

            let default_name = default_name_for_type(&type_guid);
            let Some(name_ans) =
                ask_modal(screen, input, &format!("Partition label [{default_name}]"))
            else {
                state.set_info("new partition cancelled");
                return None;
            };
            let chosen_name = if name_ans.trim().is_empty() {
                default_name
            } else {
                name_ans.trim()
            };

            if let Some(table) = state.disk.as_mut() {
                let req_start = if free_slot.end_lba >= aligned_start
                    && aligned_start + size_lbas - 1 <= free_slot.end_lba
                {
                    Some(aligned_start)
                } else {
                    None
                };
                match table.add_partition(type_guid, req_start, size_lbas, chosen_name, 0xA11CE) {
                    Ok(num) => {
                        state.dirty = true;
                        let new_slots = build_slots(Some(table), state.total_lbas);
                        if let Some(idx) = new_slots.iter().position(|s| {
                            matches!(s.kind, SlotKind::Partition { part_num, .. } if part_num == num)
                        }) {
                            state.selected_row = idx;
                        }
                        state.selected_action = 0;
                        state.set_ok(format!(
                            "created partition #{num} ({}, {}) in memory",
                            human_size(size_lbas * LBA_SIZE as u64),
                            short_type(&type_guid)
                        ));
                    }
                    Err(e) => state.set_err(e),
                }
            }
            None
        }
        Action::Delete => {
            let part_num = resolve_target_partition(state, slots, screen, input)?;
            if let Some(table) = state.disk.as_mut() {
                match table.delete_partition(part_num) {
                    Ok(()) => {
                        state.dirty = true;
                        state.selected_action = 0;
                        state.set_ok(format!("deleted partition #{part_num} in memory"));
                    }
                    Err(e) => state.set_err(e),
                }
            }
            None
        }
        Action::Resize => {
            let part_num = resolve_target_partition(state, slots, screen, input)?;
            let current_h = state
                .disk
                .as_ref()
                .and_then(|d| {
                    d.active_partitions()
                        .into_iter()
                        .find(|(n, _)| *n == part_num)
                        .map(|(_, e)| human_size(e.size_lbas() * LBA_SIZE as u64))
                })
                .unwrap_or_else(|| String::from("?"));
            let Some(ans) = ask_modal(
                screen,
                input,
                &format!("New size for partition #{part_num} (current {current_h}, e.g. 32M, 1G)"),
            ) else {
                state.set_info("resize cancelled");
                return None;
            };
            let trimmed = ans.trim().trim_start_matches('+');
            let size_lbas = match parse_size_lbas(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    state.set_err(format!("bad size: {e}"));
                    return None;
                }
            };
            if let Some(table) = state.disk.as_mut() {
                match table.resize_partition(part_num, size_lbas) {
                    Ok(()) => {
                        state.dirty = true;
                        state.set_ok(format!(
                            "resized partition #{part_num} to {}",
                            human_size(size_lbas * LBA_SIZE as u64)
                        ));
                    }
                    Err(e) => state.set_err(e),
                }
            }
            None
        }
        Action::Type => {
            let part_num = resolve_target_partition(state, slots, screen, input)?;
            let Some(ans) = ask_modal(
                screen,
                input,
                &format!(
                    "New type for #{part_num} (1/hxfs, 2/efi, 3/linux, 4/swap, 5/basic, UUID)"
                ),
            ) else {
                state.set_info("retype cancelled");
                return None;
            };
            let Some(guid) = parse_type_choice(ans.trim()) else {
                state.set_err(format!(
                    "unknown type '{}' (press l to list types)",
                    ans.trim()
                ));
                return None;
            };
            if let Some(table) = state.disk.as_mut() {
                match table.set_partition_type(part_num, guid) {
                    Ok(()) => {
                        state.dirty = true;
                        state.set_ok(format!(
                            "changed partition #{part_num} type to {}",
                            guid.type_label()
                        ));
                    }
                    Err(e) => state.set_err(e),
                }
            }
            None
        }
        Action::Name => {
            let part_num = resolve_target_partition(state, slots, screen, input)?;
            let Some(ans) = ask_modal(
                screen,
                input,
                &format!("New GPT label for partition #{part_num}"),
            ) else {
                state.set_info("rename cancelled");
                return None;
            };
            if let Some(table) = state.disk.as_mut() {
                match table.set_partition_name(part_num, ans.trim()) {
                    Ok(()) => {
                        state.dirty = true;
                        state.set_ok(format!("renamed partition #{part_num} to '{}'", ans.trim()));
                    }
                    Err(e) => state.set_err(e),
                }
            }
            None
        }
        Action::Info => {
            if let Some(slot) = slots.get(state.selected_row) {
                draw_info_modal(screen, state, slot);
                let _ = tui::read_key(input);
                state.set_info("ready");
            } else {
                state.set_warn("nothing selected");
            }
            None
        }
        Action::Verify => {
            if state.disk.is_none() {
                if let Some(ref bare) = state.raw_hxfs {
                    state.set_ok(format!(
                        "verify OK: {} ({}) superblock CRC valid, v{}, seq={}",
                        bare.layout_tag(),
                        bare.layout_label(),
                        bare.format_version,
                        bare.sequence_number
                    ));
                    return None;
                }
            }
            let report = huesos_gpt::verify_disk_io(io);
            if report.ok {
                state.set_ok(
                    "on-disk GPT verify OK: MBR=protective primary_crc=ok backup_crc=ok entries_crc=ok",
                );
            } else {
                state.set_warn(format!(
                    "on-disk verify: mbr={} primary={} backup={} entries={} errs={}",
                    report.protective_mbr,
                    report.primary_crc_ok,
                    report.backup_crc_ok,
                    report.entries_crc_ok,
                    report.errors.len()
                ));
            }
            None
        }
        Action::Write => {
            let Some(ref table) = state.disk else {
                state.set_warn("nothing to write: press g to initialize a GPT first");
                return None;
            };
            if !state.writable {
                state.set_err("AccessDenied: device was opened read-only");
                return None;
            }
            if state.raw_hxfs.is_some() {
                let Some(ans) = ask_modal(
                    screen,
                    input,
                    "WARNING: disk currently holds a raw-hxfs volume! Type 'yes' to overwrite",
                ) else {
                    state.set_info("write cancelled");
                    return None;
                };
                if ans.trim() != "yes" {
                    state.set_info("write aborted (type exact 'yes' to overwrite raw-hxfs)");
                    return None;
                }
            } else {
                let Some(ans) = ask_modal(
                    screen,
                    input,
                    "Write partition table to disk? Type 'yes' to commit [no]",
                ) else {
                    state.set_info("write cancelled");
                    return None;
                };
                if ans.trim() != "yes" {
                    state.set_info("write aborted (changes remain in memory)");
                    return None;
                }
            }
            let mut copy = table.clone();
            match copy.write_to(io, false).and_then(|()| io.flush()) {
                Ok(()) => {
                    state.disk = Some(copy);
                    state.raw_hxfs = None;
                    state.dirty = false;
                    state.set_ok("partition table written and flushed to disk");
                    None
                }
                Err(error) => {
                    state.set_err(format!("write failed: {error}"));
                    Some(1)
                }
            }
        }
    }
}

fn resolve_target_partition<W: Write>(
    state: &mut EditorState,
    slots: &[DiskSlot],
    screen: &mut tui::Screen<W>,
    input: &mut io::Stdin,
) -> Option<usize> {
    if state.disk.is_none() {
        state.set_warn("no GPT partition table");
        return None;
    }
    if let Some(DiskSlot {
        kind: SlotKind::Partition { part_num, .. },
        ..
    }) = slots.get(state.selected_row)
    {
        return Some(*part_num);
    }
    let active: Vec<usize> = slots
        .iter()
        .filter_map(|s| match s.kind {
            SlotKind::Partition { part_num, .. } => Some(part_num),
            SlotKind::FreeSpace => None,
        })
        .collect();
    if active.is_empty() {
        state.set_warn("table has no partitions yet (press n to create one)");
        return None;
    }
    if active.len() == 1 {
        return Some(active[0]);
    }
    let default_num = active[0];
    let ans = ask_modal(screen, input, &format!("Partition number [{default_num}]"))?;
    if ans.trim().is_empty() {
        return Some(default_num);
    }
    match ans.trim().parse::<usize>() {
        Ok(n) => Some(n),
        Err(_) => {
            state.set_err(format!("'{}' is not a valid partition number", ans.trim()));
            None
        }
    }
}

fn ask_modal<W: Write>(
    screen: &mut tui::Screen<W>,
    input: &mut io::Stdin,
    prompt_label: &str,
) -> Option<String> {
    let _ = screen.write_raw("\r\x1b[2K");
    let _ = screen.show_cursor();
    let res = tui::prompt(screen.out(), input, prompt_label);
    let _ = screen.hide_cursor();
    res
}

fn parse_type_choice(raw: &str) -> Option<Guid> {
    if raw.is_empty() {
        return Some(GUID_HXFS_V7);
    }
    match raw {
        "1" => Some(GUID_HXFS_V7),
        "2" => Some(GUID_ESP),
        "3" => Some(GUID_LINUX_FS),
        "4" => Some(GUID_LINUX_SWAP),
        "5" => Some(GUID_MS_BASIC_DATA),
        other => Guid::parse_type(other),
    }
}

fn default_name_for_type(guid: &Guid) -> &'static str {
    if *guid == GUID_HXFS_V7 {
        "HuesOS-Root"
    } else if *guid == GUID_ESP {
        "EFI-System"
    } else if *guid == GUID_LINUX_SWAP {
        "Swap"
    } else if *guid == GUID_LINUX_FS {
        "Linux-Data"
    } else {
        "Basic-Data"
    }
}

fn build_slots(disk: Option<&GptDisk>, total_lbas: u64) -> Vec<DiskSlot> {
    let Some(table) = disk else {
        return Vec::new();
    };
    let first_usable = table.primary.first_usable_lba.max(34);
    let last_usable = table
        .primary
        .last_usable_lba
        .min(total_lbas.saturating_sub(34));
    if last_usable < first_usable {
        return Vec::new();
    }

    let mut parts: Vec<(usize, u64, u64, Guid, Guid, String)> = table
        .active_partitions()
        .into_iter()
        .map(|(num, e)| {
            (
                num,
                e.starting_lba,
                e.ending_lba,
                e.type_guid,
                e.unique_guid,
                e.name.clone(),
            )
        })
        .collect();
    parts.sort_by_key(|p| p.1);

    let mut slots = Vec::new();
    let mut cursor = first_usable;
    for (num, start, end, type_guid, unique_guid, name) in parts {
        if start > cursor {
            let gap_end = start - 1;
            if gap_end.saturating_sub(cursor) + 1 >= 64 {
                slots.push(DiskSlot {
                    start_lba: cursor,
                    end_lba: gap_end,
                    kind: SlotKind::FreeSpace,
                });
            }
        }
        slots.push(DiskSlot {
            start_lba: start,
            end_lba: end,
            kind: SlotKind::Partition {
                part_num: num,
                type_guid,
                unique_guid,
                name,
            },
        });
        cursor = cursor.max(end.saturating_add(1));
    }
    if cursor <= last_usable && last_usable.saturating_sub(cursor) + 1 >= 64 {
        slots.push(DiskSlot {
            start_lba: cursor,
            end_lba: last_usable,
            kind: SlotKind::FreeSpace,
        });
    }
    slots
}

fn draw_main<W: Write>(
    screen: &mut tui::Screen<W>,
    state: &EditorState,
    slots: &[DiskSlot],
    actions: &[Action],
) -> huesos_std::Result<()> {
    screen.clear()?;

    let mode_tag = if state.writable { "RW" } else { "RO" };
    let title = format!(
        " HuesOS fdisk/cfdisk -- {} [{}] -- {} ",
        state.label,
        mode_tag,
        human_size(state.total_lbas.saturating_mul(LBA_SIZE as u64))
    );
    screen.line(&tui::frame_top(&title, FRAME_WIDTH))?;

    // Header metadata pane
    let label_desc = if let Some(ref d) = state.disk {
        format!("gpt   Disk GUID: {}", d.primary.disk_guid.format_uuid())
    } else if let Some(ref bare) = state.raw_hxfs {
        format!(
            "none (whole-device {} {}, v{}, seq {})",
            bare.layout_tag(),
            bare.layout_label(),
            bare.format_version,
            bare.sequence_number
        )
    } else {
        String::from("none (unpartitioned disk)")
    };
    let dirty_badge = if state.dirty {
        tui::colored("MODIFIED (in memory)", Color::Yellow)
    } else {
        tui::colored("CLEAN", Color::Green)
    };
    screen.line(&tui::frame_line(
        &format!(" Label: {}   State: {}", label_desc, dirty_badge),
        FRAME_WIDTH,
    ))?;
    screen.line(&tui::frame_line(
        &format!(
            " Geometry: {} sectors x {}B = {}   Align: 1 MiB (2048 LBAs)",
            state.total_lbas,
            LBA_SIZE,
            human_size(state.total_lbas.saturating_mul(LBA_SIZE as u64))
        ),
        FRAME_WIDTH,
    ))?;
    screen.line(&tui::frame_rule(FRAME_WIDTH))?;

    // Visual proportional usage bar
    let map_bar = render_visual_bar(state, slots);
    screen.line(&tui::frame_line(&format!(" Map: {map_bar}"), FRAME_WIDTH))?;
    screen.line(&tui::frame_rule(FRAME_WIDTH))?;

    // Partition & free-space table
    screen.line(&tui::frame_line(
        "\x1b[1m   DEVICE           START         END     SECTORS    SIZE  TYPE         NAME\x1b[0m",
        FRAME_WIDTH,
    ))?;

    if state.disk.is_none() {
        screen.line(&tui::frame_line("", FRAME_WIDTH))?;
        if let Some(ref bare) = state.raw_hxfs {
            screen.line(&tui::frame_line(
                &format!(
                    "   Whole device contains a live {} filesystem ({}).",
                    bare.layout_tag(),
                    bare.layout_label()
                ),
                FRAME_WIDTH,
            ))?;
            screen.line(&tui::frame_line(
                "   Press 'g' (or Enter on [g:NewGPT]) to stage a new GPT in memory.",
                FRAME_WIDTH,
            ))?;
        } else {
            screen.line(&tui::frame_line(
                "   Disk does not contain a recognized GPT partition table.",
                FRAME_WIDTH,
            ))?;
            screen.line(&tui::frame_line(
                "   Press 'g' (or Enter on [g:NewGPT]) to initialize a new GPT.",
                FRAME_WIDTH,
            ))?;
        }
        screen.line(&tui::frame_line("", FRAME_WIDTH))?;
    } else if slots.is_empty() {
        screen.line(&tui::frame_line(
            "   (no usable sectors on disk)",
            FRAME_WIDTH,
        ))?;
    } else {
        let max_rows = 10usize;
        let start_idx = if state.selected_row >= max_rows {
            state.selected_row + 1 - max_rows
        } else {
            0
        };
        let end_idx = (start_idx + max_rows).min(slots.len());
        for (idx, slot) in slots[start_idx..end_idx].iter().enumerate() {
            let abs_idx = start_idx + idx;
            let selected = abs_idx == state.selected_row;
            let marker = if selected { ">" } else { " " };
            let row_plain = match &slot.kind {
                SlotKind::Partition {
                    part_num,
                    type_guid,
                    name,
                    ..
                } => {
                    let dev_name = partition_dev_name(&state.label, *part_num);
                    let disp_name = if name.is_empty() { "-" } else { name.as_str() };
                    format!(
                        " {marker} {:<14} {:>9} {:>11} {:>11} {:>7}  {:<12} {}",
                        tui::fit(&dev_name, 14),
                        slot.start_lba,
                        slot.end_lba,
                        slot.size_lbas(),
                        human_size(slot.size_bytes()),
                        tui::fit(short_type(type_guid), 12),
                        tui::fit(disp_name, 20)
                    )
                }
                SlotKind::FreeSpace => {
                    format!(
                        " {marker} {:<14} {:>9} {:>11} {:>11} {:>7}  {:<12} -",
                        "Free space",
                        slot.start_lba,
                        slot.end_lba,
                        slot.size_lbas(),
                        human_size(slot.size_bytes()),
                        "unallocated"
                    )
                }
            };
            let fitted = tui::fit(&row_plain, FRAME_WIDTH - 2);
            let styled = if selected {
                format!("\x1b[7m{fitted}\x1b[0m")
            } else if matches!(slot.kind, SlotKind::FreeSpace) {
                tui::colored(&fitted, Color::Green)
            } else {
                fitted
            };
            screen.line(&format!("│{styled}│"))?;
        }
        // Pad remaining table height slightly so the bottom bar doesn't jump around
        let rendered = end_idx - start_idx;
        for _ in rendered..5 {
            screen.line(&tui::frame_line("", FRAME_WIDTH))?;
        }
    }

    // Selected item detail strip
    screen.line(&tui::frame_rule(FRAME_WIDTH))?;
    if let Some(slot) = slots.get(state.selected_row) {
        match &slot.kind {
            SlotKind::Partition {
                part_num,
                type_guid,
                unique_guid,
                name,
            } => {
                screen.line(&tui::frame_line(
                    &format!(
                        " Part #{part_num}: {}   Label: '{}'",
                        type_guid.type_label(),
                        if name.is_empty() { "-" } else { name.as_str() }
                    ),
                    FRAME_WIDTH,
                ))?;
                screen.line(&tui::frame_line(
                    &format!(" UUID: {}", unique_guid.format_uuid()),
                    FRAME_WIDTH,
                ))?;
            }
            SlotKind::FreeSpace => {
                screen.line(&tui::frame_line(
                    &format!(
                        " Unallocated: LBAs {}..={} ({}) -- press n or Enter to create partition",
                        slot.start_lba,
                        slot.end_lba,
                        human_size(slot.size_bytes())
                    ),
                    FRAME_WIDTH,
                ))?;
                screen.line(&tui::frame_line(
                    " Keys: Up/Down select row, Left/Right select action, l list types",
                    FRAME_WIDTH,
                ))?;
            }
        }
    } else {
        screen.line(&tui::frame_line(
            " Keys: g create GPT, v verify disk, m/? help, l list types, q quit",
            FRAME_WIDTH,
        ))?;
    }

    // Action button bar (`cfdisk`-style)
    screen.line(&tui::frame_rule(FRAME_WIDTH))?;
    let mut bar = String::from(" ");
    for (idx, act) in actions.iter().enumerate() {
        if idx > 0 {
            bar.push(' ');
        }
        let chip = format!("[{}]", act.label());
        if idx == state.selected_action {
            bar.push_str(&format!("\x1b[7m{chip}\x1b[0m"));
        } else {
            bar.push_str(&chip);
        }
    }
    screen.line(&tui::frame_line(&bar, FRAME_WIDTH))?;
    screen.line(&tui::frame_bottom(FRAME_WIDTH))?;

    // Status line below frame
    if !state.status.is_empty() {
        let msg = tui::fit(&format!(" {}", state.status), FRAME_WIDTH);
        screen.write_raw(&tui::colored(&msg, state.status_color))?;
    }
    screen.out().flush()
}

fn render_visual_bar(state: &EditorState, slots: &[DiskSlot]) -> String {
    if state.total_lbas == 0 {
        return String::from("[empty]");
    }
    if state.disk.is_none() {
        if state.raw_hxfs.is_some() {
            let inner = "█".repeat(MAP_INNER_WIDTH);
            return format!("[{}] 100% raw-hxfs", tui::colored(&inner, Color::Cyan));
        }
        let inner = "░".repeat(MAP_INNER_WIDTH);
        return format!("[{inner}] unpartitioned");
    }

    let used_lbas: u64 = slots
        .iter()
        .filter(|s| matches!(s.kind, SlotKind::Partition { .. }))
        .map(DiskSlot::size_lbas)
        .sum();
    let pct = (used_lbas.saturating_mul(100))
        .checked_div(state.total_lbas)
        .unwrap_or(0);

    let mut out = String::from("[");
    let mut used_cols = 0usize;
    for (i, slot) in slots.iter().enumerate() {
        let remaining_cols = MAP_INNER_WIDTH.saturating_sub(used_cols);
        if remaining_cols == 0 {
            break;
        }
        let cols = if i + 1 == slots.len() {
            remaining_cols
        } else {
            let raw = (slot.size_lbas() as u128 * MAP_INNER_WIDTH as u128
                / state.total_lbas as u128) as usize;
            raw.clamp(1, remaining_cols)
        };
        used_cols += cols;
        match &slot.kind {
            SlotKind::Partition { type_guid, .. } => {
                let seg = "█".repeat(cols);
                let color = if *type_guid == GUID_HXFS_V7 {
                    Color::Cyan
                } else if *type_guid == GUID_ESP {
                    Color::Yellow
                } else if *type_guid == GUID_LINUX_SWAP {
                    Color::Magenta
                } else {
                    Color::Blue
                };
                out.push_str(&tui::colored(&seg, color));
            }
            SlotKind::FreeSpace => {
                for _ in 0..cols {
                    out.push('░');
                }
            }
        }
    }
    while used_cols < MAP_INNER_WIDTH {
        out.push('░');
        used_cols += 1;
    }
    out.push_str(&format!("] {pct:>3}% used"));
    out
}

fn draw_help_modal<W: Write>(screen: &mut tui::Screen<W>) {
    let _ = screen.clear();
    let _ = screen.line(&tui::frame_top(
        " fdisk / cfdisk Command Reference ",
        FRAME_WIDTH,
    ));
    let rows = [
        " Navigation:",
        "   Up / Down (or k / j)    Select partition or free-space region",
        "   Left / Right / Tab      Select bottom action button",
        "   Enter                   Execute highlighted action button",
        "",
        " Classic fdisk Keybindings:",
        "   n   Create new GPT partition in free space (aligned to 1 MiB)",
        "   d   Delete selected (or numbered) GPT partition",
        "   r   Resize partition in place",
        "   t   Change partition type GUID (hxfs, efi, linux, swap, basic, UUID)",
        "   c   Change GPT partition UTF-16 name / label",
        "   i   Inspect detailed partition LBA / GUID attributes",
        "   l   List known GPT partition type GUIDs",
        "   g   Create a fresh empty Protective MBR + GPT in memory",
        "   p   Reload partition table from disk (discarding unsaved edits)",
        "   v   Verify Protective MBR + Primary/Backup GPT header & entry CRCs",
        "   w   Write modified GPT to disk and flush",
        "   q   Quit without saving (prompts twice if modified; Esc / ^C)",
        "",
        " Press any key to return to the partition table...",
    ];
    for r in rows {
        let _ = screen.line(&tui::frame_line(r, FRAME_WIDTH));
    }
    let _ = screen.line(&tui::frame_bottom(FRAME_WIDTH));
    let _ = screen.out().flush();
}

fn draw_types_modal<W: Write>(screen: &mut tui::Screen<W>) {
    let _ = screen.clear();
    let _ = screen.line(&tui::frame_top(
        " Known GPT Partition Types (t / n) ",
        FRAME_WIDTH,
    ));
    let types = [
        ("1", "hxfs", "HuesOS HxFS v7", GUID_HXFS_V7),
        ("2", "efi", "EFI System Partition (ESP)", GUID_ESP),
        ("3", "linux", "Linux filesystem data", GUID_LINUX_FS),
        ("4", "swap", "Linux swap partition", GUID_LINUX_SWAP),
        ("5", "basic", "Microsoft Basic Data", GUID_MS_BASIC_DATA),
    ];
    let _ = screen.line(&tui::frame_line(
        " #  ALIAS   DESCRIPTION                  TYPE GUID",
        FRAME_WIDTH,
    ));
    let _ = screen.line(&tui::frame_rule(FRAME_WIDTH));
    for (num, alias, desc, guid) in types {
        let _ = screen.line(&tui::frame_line(
            &format!(
                " {}  {:<6}  {:<27}  {}",
                num,
                alias,
                desc,
                guid.format_uuid()
            ),
            FRAME_WIDTH,
        ));
    }
    let _ = screen.line(&tui::frame_line("", FRAME_WIDTH));
    let _ = screen.line(&tui::frame_line(
        " Custom 36-char RFC 4122 UUIDs are also accepted at the type prompt.",
        FRAME_WIDTH,
    ));
    let _ = screen.line(&tui::frame_line(" Press any key to return...", FRAME_WIDTH));
    let _ = screen.line(&tui::frame_bottom(FRAME_WIDTH));
    let _ = screen.out().flush();
}

fn draw_info_modal<W: Write>(screen: &mut tui::Screen<W>, state: &EditorState, slot: &DiskSlot) {
    let _ = screen.clear();
    let _ = screen.line(&tui::frame_top(
        " Partition / Region Inspector ",
        FRAME_WIDTH,
    ));
    match &slot.kind {
        SlotKind::Partition {
            part_num,
            type_guid,
            unique_guid,
            name,
        } => {
            let dev = partition_dev_name(&state.label, *part_num);
            let lines = [
                format!(" Device        : {dev} (GPT slot #{part_num})"),
                format!(
                    " Partition Name: {}",
                    if name.is_empty() {
                        "<empty>"
                    } else {
                        name.as_str()
                    }
                ),
                format!(" Type          : {}", type_guid.type_label()),
                format!(" Type GUID     : {}", type_guid.format_uuid()),
                format!(" Unique UUID   : {}", unique_guid.format_uuid()),
                format!(" Start LBA     : {}", slot.start_lba),
                format!(" End LBA       : {}", slot.end_lba),
                format!(
                    " Span          : {} sectors ({} bytes / {})",
                    slot.size_lbas(),
                    slot.size_bytes(),
                    human_size(slot.size_bytes())
                ),
            ];
            for line in &lines {
                let _ = screen.line(&tui::frame_line(line, FRAME_WIDTH));
            }
        }
        SlotKind::FreeSpace => {
            let _ = screen.line(&tui::frame_line(
                " Region        : Unallocated free space",
                FRAME_WIDTH,
            ));
            let _ = screen.line(&tui::frame_line(
                &format!(" Start LBA     : {}", slot.start_lba),
                FRAME_WIDTH,
            ));
            let _ = screen.line(&tui::frame_line(
                &format!(" End LBA       : {}", slot.end_lba),
                FRAME_WIDTH,
            ));
            let _ = screen.line(&tui::frame_line(
                &format!(
                    " Capacity      : {} sectors ({})",
                    slot.size_lbas(),
                    human_size(slot.size_bytes())
                ),
                FRAME_WIDTH,
            ));
        }
    }
    let _ = screen.line(&tui::frame_line("", FRAME_WIDTH));
    let _ = screen.line(&tui::frame_line(" Press any key to return...", FRAME_WIDTH));
    let _ = screen.line(&tui::frame_bottom(FRAME_WIDTH));
    let _ = screen.out().flush();
}

fn partition_dev_name(disk_label: &str, part_num: usize) -> String {
    let leaf = disk_label.rsplit('/').next().unwrap_or(disk_label);
    let sep = if leaf.chars().last().is_some_and(|c| c.is_ascii_digit()) {
        "p"
    } else {
        ""
    };
    format!("{disk_label}{sep}{part_num}")
}

fn short_type(guid: &Guid) -> &'static str {
    if *guid == GUID_HXFS_V7 {
        "HuesOS HxFS"
    } else if *guid == GUID_ESP {
        "EFI System"
    } else if *guid == GUID_LINUX_SWAP {
        "Linux swap"
    } else if *guid == GUID_LINUX_FS {
        "Linux fs"
    } else if *guid == GUID_MS_BASIC_DATA {
        "Basic data"
    } else {
        "Custom GPT"
    }
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value.saturating_add(align - rem)
    }
}

fn usable_free_in_slot(slot: &DiskSlot) -> u64 {
    let aligned_start = align_up(slot.start_lba, ALIGN_1MIB_LBAS);
    if slot.end_lba >= aligned_start {
        slot.end_lba - aligned_start + 1
    } else {
        0
    }
}

fn default_selected_row(slots: &[DiskSlot]) -> usize {
    slots
        .iter()
        .position(|s| matches!(s.kind, SlotKind::Partition { .. }))
        .or_else(|| {
            slots
                .iter()
                .enumerate()
                .filter(|(_, s)| matches!(s.kind, SlotKind::FreeSpace))
                .max_by_key(|(_, s)| usable_free_in_slot(s))
                .map(|(idx, _)| idx)
        })
        .unwrap_or(0)
}

fn human_size(bytes: u64) -> String {
    tui::human_bytes(bytes)
}
