//! Full-screen interactive disk & GPT partition studio (`cfdisk` / `fdisk` hybrid)
//! for `/bin/fdisk.elf`.
//!
//! Renders a dual-pane truecolor partition studio across the entire HuesOS
//! framebuffer terminal (`166 × 50` on `1024×768` Cozette6x13, scaling cleanly
//! down to `80 × 24` serial consoles):
//!
//! - **Top header chrome**: device path, `RW`/`RO` capability pill, total
//!   capacity, sector geometry, partition-table type, and `CLEAN` / `MODIFIED`
//!   staging indicator.
//! - **Proportional Disk Layout Map**: 2-row truecolor block ribbon showing
//!   partition proportions, active cursor caret (`^^^`), and partition type
//!   color legend.
//! - **Dual-pane main workspace**:
//!   - **Left pane (~62%)**: interactive scrollable Partition & Free-Space
//!     table (`↑`/`↓`/`k`/`j`, `PgUp`/`PgDn`, `Home`/`End`).
//!   - **Right pane (~38%)**: live Region & GPT/HxFS Telemetry Inspector
//!     (Type GUID, Unique UUID, LBA start/end/span, byte offsets, 1 MiB / 4 KiB
//!     alignment check, Disk GUID, Primary/Backup header LBAs, CRC health).
//! - **Centered modal dialogs**: styled floating input dialogs (`ask_modal`),
//!   interactive Type Catalog (`l`), Region Inspector (`i`), and Command
//!   Reference (`m`/`?`).
//! - **Docked bottom status toast + `cfdisk` action button bar**: arrow/tab
//!   button navigation (`Left`/`Right`/`Tab` + `Enter`) plus classic single-key
//!   `fdisk` hotkeys (`g`, `n`, `d`, `r`, `t`, `c`, `i`, `v`, `l`, `p`, `w`, `q`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_gpt::{
    parse_size_lbas, GptDisk, Guid, VerifyReport, ALIGN_1MIB_LBAS, ALIGN_4KIB_LBAS, GUID_ESP,
    GUID_HXFS_V7, GUID_LINUX_FS, GUID_LINUX_SWAP, GUID_MS_BASIC_DATA, LBA_SIZE,
};
use huesos_hxfs::BareVolume;
use huesos_std::io::{self, Read, Write};
use huesos_std::tui::{self, ansi, bg_rgb, fg_rgb, FrameBuffer, Key};

use crate::{format_uuid, probe_raw_hxfs, Backend, BlockIo512, HXFS_BLOCK_SIZE};

// Obsidian studio truecolor palette.
const BG_HEADER: (u8, u8, u8) = (19, 26, 40);
const BG_ACTION_BAR: (u8, u8, u8) = (16, 22, 34);
const BG_STATUS: (u8, u8, u8) = (13, 18, 28);
const BG_SELECT: (u8, u8, u8) = (32, 56, 86);
const BG_MODAL: (u8, u8, u8) = (15, 22, 35);
const BG_INPUT: (u8, u8, u8) = (10, 14, 22);

const FG_BORDER: (u8, u8, u8) = (56, 78, 112);
const FG_BORDER_HI: (u8, u8, u8) = (88, 196, 220);
const FG_TITLE: (u8, u8, u8) = (120, 238, 200);
const FG_TEXT: (u8, u8, u8) = (214, 226, 244);
const FG_MUTED: (u8, u8, u8) = (118, 138, 168);
const FG_CYAN: (u8, u8, u8) = (95, 222, 245);
const FG_MINT: (u8, u8, u8) = (95, 230, 172);
const FG_AMBER: (u8, u8, u8) = (250, 202, 96);
const FG_CORAL: (u8, u8, u8) = (250, 108, 118);
const FG_VIOLET: (u8, u8, u8) = (198, 146, 252);
const FG_BLUE: (u8, u8, u8) = (122, 176, 255);
const FG_TRACK: (u8, u8, u8) = (44, 56, 76);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusTone {
    Ok,
    Info,
    Warn,
    Err,
}

impl StatusTone {
    fn color(self) -> (u8, u8, u8) {
        match self {
            StatusTone::Ok => FG_MINT,
            StatusTone::Info => FG_CYAN,
            StatusTone::Warn => FG_AMBER,
            StatusTone::Err => FG_CORAL,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            StatusTone::Ok => "OK",
            StatusTone::Info => "INFO",
            StatusTone::Warn => "WARN",
            StatusTone::Err => "ERR",
        }
    }
}

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
    fn key_hint(self) -> &'static str {
        match self {
            Action::New => "n",
            Action::Delete => "d",
            Action::Resize => "r",
            Action::Type => "t",
            Action::Name => "c",
            Action::Info => "i",
            Action::InitGpt => "g",
            Action::Verify => "v",
            Action::Write => "w",
            Action::Help => "m",
            Action::Quit => "q",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Action::New => "New",
            Action::Delete => "Delete",
            Action::Resize => "Resize",
            Action::Type => "Type",
            Action::Name => "Name",
            Action::Info => "Info",
            Action::InitGpt => "NewGPT",
            Action::Verify => "Verify",
            Action::Write => "Write",
            Action::Help => "Help",
            Action::Quit => "Quit",
        }
    }
}

struct EditorState {
    label: String,
    hw_model: String,
    hw_serial: String,
    writable: bool,
    total_lbas: u64,
    disk: Option<GptDisk>,
    raw_hxfs: Option<BareVolume>,
    last_verify: Option<VerifyReport>,
    dirty: bool,
    selected_row: usize,
    selected_action: usize,
    quit_armed: bool,
    status: String,
    status_tone: StatusTone,
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
        self.status_tone = StatusTone::Ok;
        self.quit_armed = false;
    }

    fn set_info(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_tone = StatusTone::Info;
        self.quit_armed = false;
    }

    fn set_warn(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_tone = StatusTone::Warn;
    }

    fn set_err(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_tone = StatusTone::Err;
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
    let last_verify = if disk.is_some() {
        Some(huesos_gpt::verify_disk_io(io))
    } else {
        None
    };

    let (init_status, init_tone) = if let Some(ref d) = disk {
        let count = d.active_partitions().len();
        (
            format!(
                "GPT loaded ({count} partition(s)) -- Up/Down select region, Left/Right/Enter or hotkeys"
            ),
            StatusTone::Ok,
        )
    } else if let Some(ref bare) = raw_hxfs {
        (
            format!(
                "Whole-disk {} ({}) mounted without GPT -- press g to stage a GPT in memory",
                bare.layout_tag(),
                bare.layout_label()
            ),
            StatusTone::Warn,
        )
    } else {
        (
            String::from("No GPT partition table found -- press g to initialize a fresh GPT"),
            StatusTone::Warn,
        )
    };

    let initial_slots = build_slots(disk.as_ref(), total_lbas);
    let initial_selected_row = default_selected_row(&initial_slots);

    let mut state = EditorState {
        label: String::from(label),
        hw_model: String::from(io.hw_model()),
        hw_serial: String::from(io.hw_serial()),
        writable,
        total_lbas,
        disk,
        raw_hxfs,
        last_verify,
        dirty: false,
        selected_row: initial_selected_row,
        selected_action: 0,
        quit_armed: false,
        status: init_status,
        status_tone: init_tone,
    };

    let mut screen = tui::Screen::new(io::stdout());
    let mut input = io::stdin();
    let _ = screen.enter_fullscreen();

    let exit_code = loop {
        let slots = build_slots(state.disk.as_ref(), state.total_lbas);
        if !slots.is_empty() && state.selected_row >= slots.len() {
            state.selected_row = slots.len() - 1;
        }
        let actions = state.active_actions(&slots);
        if !actions.is_empty() && state.selected_action >= actions.len() {
            state.selected_action = 0;
        }

        let _ = draw_studio(&mut screen, &state, &slots, actions, None);

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
            Key::PageUp => {
                state.quit_armed = false;
                state.selected_row = state.selected_row.saturating_sub(10);
                state.selected_action = 0;
            }
            Key::PageDown => {
                state.quit_armed = false;
                if !slots.is_empty() {
                    state.selected_row = (state.selected_row + 10).min(slots.len() - 1);
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
                let _ = draw_studio(
                    &mut screen,
                    &state,
                    &slots,
                    actions,
                    Some(ModalOverlay::Types),
                );
                let _ = tui::read_key(&mut input);
                state.set_info("returned from GPT partition type catalog");
            }
            Key::Char(b'p') | Key::Char(b'P') => {
                state.disk = GptDisk::read_from(io).ok();
                state.raw_hxfs = if state.disk.is_none() {
                    probe_raw_hxfs(io)
                } else {
                    None
                };
                state.last_verify = if state.disk.is_some() {
                    Some(huesos_gpt::verify_disk_io(io))
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

    let _ = screen.leave_fullscreen();
    let _ = screen.clear();
    exit_code
}

#[derive(Clone, Copy)]
enum ModalOverlay<'a> {
    Help,
    Types,
    Info(&'a DiskSlot),
    Prompt {
        title: &'a str,
        prompt: &'a str,
        typed: &'a str,
    },
}

fn dispatch_action<W: Write>(
    act: Action,
    io: &mut Backend,
    state: &mut EditorState,
    slots: &[DiskSlot],
    screen: &mut tui::Screen<W>,
    input: &mut io::Stdin,
) -> Option<i32> {
    let actions = state.active_actions(slots);
    match act {
        Action::Help => {
            let _ = draw_studio(screen, state, slots, actions, Some(ModalOverlay::Help));
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
                    "Replace raw-hxfs layout in memory with empty GPT? (yes/no) [no]"
                } else {
                    "Create empty GPT in memory, clearing all partitions? (yes/no) [no]"
                };
                let Some(ans) = ask_modal(
                    screen,
                    input,
                    state,
                    slots,
                    actions,
                    "Initialize Fresh GPT",
                    prompt,
                ) else {
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
                state,
                slots,
                actions,
                "Create New GPT Partition (1/3: Size)",
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
                state,
                slots,
                actions,
                "Create New GPT Partition (2/3: Type GUID)",
                "Type: 1/hxfs, 2/efi, 3/linux, 4/swap, 5/basic, or RFC4122 UUID [hxfs]",
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
            let Some(name_ans) = ask_modal(
                screen,
                input,
                state,
                slots,
                actions,
                "Create New GPT Partition (3/3: UTF-16 Label)",
                &format!("Partition label [{default_name}]"),
            ) else {
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
            let part_num = resolve_target_partition(state, slots, actions, screen, input)?;
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
            let part_num = resolve_target_partition(state, slots, actions, screen, input)?;
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
                state,
                slots,
                actions,
                "Resize Partition In Place",
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
            let part_num = resolve_target_partition(state, slots, actions, screen, input)?;
            let Some(ans) = ask_modal(
                screen,
                input,
                state,
                slots,
                actions,
                "Change Partition Type GUID",
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
            let part_num = resolve_target_partition(state, slots, actions, screen, input)?;
            let Some(ans) = ask_modal(
                screen,
                input,
                state,
                slots,
                actions,
                "Rename GPT Partition",
                &format!("New UTF-16 GPT label for partition #{part_num}"),
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
                let _ = draw_studio(
                    screen,
                    state,
                    slots,
                    actions,
                    Some(ModalOverlay::Info(slot)),
                );
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
            let ok = report.ok;
            let msg = if ok {
                String::from(
                    "on-disk GPT verify OK: MBR=protective primary_crc=ok backup_crc=ok entries_crc=ok",
                )
            } else {
                format!(
                    "on-disk verify: mbr={} primary={} backup={} entries={} errs={}",
                    report.protective_mbr,
                    report.primary_crc_ok,
                    report.backup_crc_ok,
                    report.entries_crc_ok,
                    report.errors.len()
                )
            };
            state.last_verify = Some(report);
            if ok {
                state.set_ok(msg);
            } else {
                state.set_warn(msg);
            }
            None
        }
        Action::Write => {
            let Some(table_clone) = state.disk.clone() else {
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
                    state,
                    slots,
                    actions,
                    "CONFIRM DESTRUCTIVE OVERWRITE",
                    "WARNING: disk holds a live raw-hxfs volume! Type exact 'yes' to overwrite",
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
                    state,
                    slots,
                    actions,
                    "Commit Partition Table to Disk",
                    "Write Protective MBR + Primary & Backup GPT to disk? Type 'yes' [no]",
                ) else {
                    state.set_info("write cancelled");
                    return None;
                };
                if ans.trim() != "yes" {
                    state.set_info("write aborted (changes remain staged in memory)");
                    return None;
                }
            }
            let mut copy = table_clone;
            match copy.write_to(io, false).and_then(|()| io.flush()) {
                Ok(()) => {
                    state.disk = Some(copy);
                    state.raw_hxfs = None;
                    state.dirty = false;
                    state.last_verify = Some(huesos_gpt::verify_disk_io(io));
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
    actions: &[Action],
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
    let ans = ask_modal(
        screen,
        input,
        state,
        slots,
        actions,
        "Select Target Partition",
        &format!("Partition number [{default_num}]"),
    )?;
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

/// Interactive floating modal prompt rendered cleanly over the full-screen studio.
fn ask_modal<W: Write, R: Read>(
    screen: &mut tui::Screen<W>,
    input: &mut R,
    state: &EditorState,
    slots: &[DiskSlot],
    actions: &[Action],
    title: &str,
    prompt_label: &str,
) -> Option<String> {
    let mut line = String::new();
    loop {
        let _ = draw_studio(
            screen,
            state,
            slots,
            actions,
            Some(ModalOverlay::Prompt {
                title,
                prompt: prompt_label,
                typed: &line,
            }),
        );
        match tui::read_key(input)? {
            Key::Enter => return Some(line),
            Key::Backspace => {
                line.pop();
            }
            Key::Ctrl(21) => {
                line.clear();
            }
            Key::Escape | Key::Ctrl(3) | Key::Ctrl(7) => return None,
            Key::Char(byte) if (0x20..=0x7e).contains(&byte) && line.len() < 64 => {
                line.push(char::from(byte));
            }
            Key::Tab if line.len() < 64 => {
                line.push(' ');
            }
            _ => {}
        }
    }
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

fn draw_studio<W: Write>(
    screen: &mut tui::Screen<W>,
    state: &EditorState,
    slots: &[DiskSlot],
    actions: &[Action],
    overlay: Option<ModalOverlay<'_>>,
) -> huesos_std::Result<()> {
    let (cols, rows) = tui::viewport_size();
    let mut fb = FrameBuffer::new(cols, rows);

    let total_bytes = state.total_lbas.saturating_mul(LBA_SIZE as u64);

    // 1. Row 1: Top Header Bar
    let rw_pill = if state.writable {
        format!(
            "{}{}{}[ RW ]{}",
            bg_rgb(18, 66, 52),
            fg_rgb(110, 245, 190),
            ansi::BOLD,
            ansi::RESET
        )
    } else {
        format!(
            "{}{}{}[ RO ]{}",
            bg_rgb(76, 32, 38),
            fg_rgb(255, 145, 155),
            ansi::BOLD,
            ansi::RESET
        )
    };
    let dirty_pill = if state.dirty {
        format!(
            "{}{}{}[ MODIFIED IN MEMORY ]{}",
            bg_rgb(88, 62, 18),
            fg_rgb(255, 215, 105),
            ansi::BOLD,
            ansi::RESET
        )
    } else {
        format!(
            "{}{}{}[ SYNCED / CLEAN ]{}",
            bg_rgb(24, 52, 76),
            fg_rgb(125, 220, 255),
            ansi::BOLD,
            ansi::RESET
        )
    };

    let layout_kind = if state.disk.is_some() {
        "GPT + Protective MBR"
    } else if state.raw_hxfs.is_some() {
        "Bare HxFS v7 (superfloppy)"
    } else {
        "Unpartitioned"
    };

    let hw_tag = if state.hw_serial == "-" || state.hw_serial.is_empty() {
        format!(" [{}]", state.hw_model)
    } else {
        format!(" [{} S/N {}]", state.hw_model, state.hw_serial)
    };
    let left_hdr = format!(
        " {}{}HuesOS fdisk{} {}// cfdisk studio{}   {}{}{}{} {}   {}capacity:{} {}{}{} ({} LBAs x {}B)",
        fg_rgb(110, 245, 195),
        ansi::BOLD,
        ansi::RESET,
        fg_rgb(120, 145, 180),
        ansi::RESET,
        fg_rgb(255, 255, 255),
        state.label,
        hw_tag,
        ansi::RESET,
        rw_pill,
        fg_rgb(140, 165, 198),
        ansi::RESET,
        fg_rgb(95, 222, 245),
        human_size(total_bytes),
        ansi::RESET,
        state.total_lbas,
        LBA_SIZE,
    );
    let right_hdr = format!(
        "{}{}{}  {} ",
        fg_rgb(198, 146, 252),
        layout_kind,
        ansi::RESET,
        dirty_pill
    );
    fb.put_bar_row(1, BG_HEADER, &join_lr(&left_hdr, &right_hdr, cols));

    // 2. Rows 2..=6: Full-width Proportional Disk Layout Map Box
    let mut cur_row = 2usize;
    let used_lbas: u64 = slots
        .iter()
        .filter(|s| matches!(s.kind, SlotKind::Partition { .. }))
        .map(DiskSlot::size_lbas)
        .sum();
    let free_lbas: u64 = slots
        .iter()
        .filter(|s| matches!(s.kind, SlotKind::FreeSpace))
        .map(DiskSlot::size_lbas)
        .sum();
    let used_pct = (used_lbas.saturating_mul(100))
        .checked_div(state.total_lbas.max(1))
        .unwrap_or(0);

    let map_title = format!(
        "Disk Sector Topology  [allocated {} ({:>2}%) | free {} | align 1 MiB (2048 LBAs)]",
        human_size(used_lbas * LBA_SIZE as u64),
        used_pct,
        human_size(free_lbas * LBA_SIZE as u64),
    );
    fb.put_row(cur_row, &box_top(&map_title, cols, FG_BORDER_HI, FG_TITLE));
    cur_row += 1;

    let ribbon_w = cols.saturating_sub(6).max(20);
    let (bar_line, caret_line) = render_topology_ribbon(state, slots, ribbon_w);
    fb.put_row(
        cur_row,
        &box_line(&format!(" [{bar_line}]"), cols, FG_BORDER_HI),
    );
    cur_row += 1;
    fb.put_row(
        cur_row,
        &box_line(&format!("  {caret_line} "), cols, FG_BORDER_HI),
    );
    cur_row += 1;

    let legend_line = format!(
        " {}Legend:{}  {}██{} HxFS v7   {}██{} EFI System   {}██{} Linux FS   {}██{} Swap   {}██{} Basic Data   {}░░{} Free Space   {}^^{} Selected Region",
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET,
        fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
        ansi::RESET,
        fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
        ansi::RESET,
        fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
        ansi::RESET,
        fg_rgb(FG_VIOLET.0, FG_VIOLET.1, FG_VIOLET.2),
        ansi::RESET,
        fg_rgb(FG_BLUE.0, FG_BLUE.1, FG_BLUE.2),
        ansi::RESET,
        fg_rgb(FG_TRACK.0, FG_TRACK.1, FG_TRACK.2),
        ansi::RESET,
        fg_rgb(255, 255, 255),
        ansi::RESET,
    );
    fb.put_row(cur_row, &box_line(&legend_line, cols, FG_BORDER_HI));
    cur_row += 1;
    fb.put_row(cur_row, &box_bottom(cols, FG_BORDER_HI));
    cur_row += 1;

    // 3. Main Workspace Rows (`cur_row ..= rows - 2`):
    //    Dual-pane when cols >= 112 (Partition Table left + Live Inspector right),
    //    single-pane with bottom detail strip on narrow serial terminals.
    let status_row = rows.saturating_sub(1);
    let action_row = rows;
    let main_bottom = status_row.saturating_sub(1);

    if main_bottom >= cur_row + 6 {
        if cols >= 112 {
            let left_w = (cols * 62) / 100;
            let right_w = cols - left_w;
            let h = main_bottom - cur_row + 1;
            let left_lines = build_partition_table_pane(state, slots, left_w, h);
            let right_lines = build_inspector_pane(state, slots, right_w, h);
            for i in 0..h {
                let l = left_lines.get(i).map(String::as_str).unwrap_or("");
                let r = right_lines.get(i).map(String::as_str).unwrap_or("");
                fb.put_row(cur_row + i, &format!("{l}{r}"));
            }
        } else {
            let h = main_bottom - cur_row + 1;
            let single_lines = build_partition_table_pane(state, slots, cols, h);
            for (i, line) in single_lines.iter().enumerate() {
                fb.put_row(cur_row + i, line);
            }
        }
    }

    // 4. Status / Toast Bar on `status_row`
    let tone_col = state.status_tone.color();
    let status_str = format!(
        " {}{}[{}]{} {}{}{}",
        fg_rgb(tone_col.0, tone_col.1, tone_col.2),
        ansi::BOLD,
        state.status_tone.tag(),
        ansi::RESET,
        fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
        state.status,
        ansi::RESET
    );
    let quick_hint = format!(
        "{}l:types  p:reload  m/?:help{} ",
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET
    );
    fb.put_bar_row(
        status_row,
        BG_STATUS,
        &join_lr(&status_str, &quick_hint, cols),
    );

    // 5. Bottom `cfdisk` Action Button Bar on `action_row`
    let mut act_bar = String::from(" ");
    for (idx, act) in actions.iter().enumerate() {
        if idx > 0 {
            act_bar.push_str("  ");
        }
        if idx == state.selected_action {
            act_bar.push_str(&format!(
                "{}{}{}[ {}:{} ]{}",
                bg_rgb(95, 222, 200),
                fg_rgb(10, 16, 24),
                ansi::BOLD,
                act.key_hint(),
                act.title(),
                ansi::RESET
            ));
        } else {
            act_bar.push_str(&format!(
                "{}[{}{}:{}{}]{}",
                fg_rgb(FG_BORDER_HI.0, FG_BORDER_HI.1, FG_BORDER_HI.2),
                fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                act.key_hint(),
                fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
                act.title(),
                ansi::RESET
            ));
        }
    }
    let nav_hint = format!(
        "{}Up/Dn:region  Left/Right/Enter:action{} ",
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        ansi::RESET
    );
    fb.put_bar_row(
        action_row,
        BG_ACTION_BAR,
        &join_lr(&act_bar, &nav_hint, fb.safe_cols(action_row)),
    );

    // 6. Optional Modal Overlay (Help / Types / Info / Input Prompt)
    if let Some(modal) = overlay {
        render_modal(&mut fb, state, modal);
    }

    fb.flush_to(screen.out())
}

fn render_topology_ribbon(
    state: &EditorState,
    slots: &[DiskSlot],
    width: usize,
) -> (String, String) {
    if state.total_lbas == 0 || width == 0 {
        return (" ".repeat(width), " ".repeat(width));
    }
    if state.disk.is_none() {
        if let Some(ref bare) = state.raw_hxfs {
            let fill = format!(
                "{}{}{}",
                fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                "█".repeat(width),
                ansi::RESET
            );
            let msg = format!(
                "{}Whole-disk {} ({}) -- no GPT partition table{}",
                fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                bare.layout_tag(),
                bare.layout_label(),
                ansi::RESET
            );
            return (fill, tui::fit(&msg, width));
        }
        let empty = format!(
            "{}{}{}",
            fg_rgb(FG_TRACK.0, FG_TRACK.1, FG_TRACK.2),
            "░".repeat(width),
            ansi::RESET
        );
        let msg = format!(
            "{}Unpartitioned blank medium -- press [g] to initialize GPT{}",
            fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
            ansi::RESET
        );
        return (empty, tui::fit(&msg, width));
    }

    if slots.is_empty() {
        return ("░".repeat(width), " ".repeat(width));
    }

    // Compute segment widths summing to `width`.
    let mut seg_widths = alloc::vec![1usize; slots.len()];
    if width >= slots.len() {
        let mut assigned = 0usize;
        for (i, slot) in slots.iter().enumerate() {
            let w = ((slot.size_lbas() as u128 * width as u128) / state.total_lbas.max(1) as u128)
                as usize;
            let clamped = w.max(1);
            seg_widths[i] = clamped;
            assigned += clamped;
        }
        while assigned > width {
            if let Some((idx, _)) = seg_widths
                .iter()
                .enumerate()
                .filter(|(_, &w)| w > 1)
                .max_by_key(|(_, &w)| w)
            {
                seg_widths[idx] -= 1;
                assigned -= 1;
            } else {
                break;
            }
        }
        if assigned < width {
            if let Some((idx, _)) = slots.iter().enumerate().max_by_key(|(_, s)| s.size_lbas()) {
                seg_widths[idx] += width - assigned;
            }
        }
    }

    let mut bar = String::new();
    let mut caret = String::new();
    for (idx, (slot, &seg_w)) in slots.iter().zip(seg_widths.iter()).enumerate() {
        let selected = idx == state.selected_row;
        match &slot.kind {
            SlotKind::Partition {
                part_num,
                type_guid,
                ..
            } => {
                let col = type_color(type_guid);
                bar.push_str(&fg_rgb(col.0, col.1, col.2));
                for c in 0..seg_w {
                    if c + 1 == seg_w && seg_w >= 3 && idx + 1 < slots.len() {
                        bar.push('▉');
                    } else {
                        bar.push('█');
                    }
                }
                bar.push_str(ansi::RESET);

                if selected {
                    let tag = format!("^p{part_num}^");
                    caret.push_str(&fg_rgb(255, 255, 255));
                    caret.push_str(ansi::BOLD);
                    caret.push_str(&center_ascii(&tag, seg_w, '^'));
                    caret.push_str(ansi::RESET);
                } else {
                    let tag = format!("p{part_num}");
                    caret.push_str(&fg_rgb(col.0, col.1, col.2));
                    if seg_w > tag.len() {
                        caret.push_str(&center_ascii(&tag, seg_w, ' '));
                    } else {
                        for _ in 0..seg_w {
                            caret.push(' ');
                        }
                    }
                    caret.push_str(ansi::RESET);
                }
            }
            SlotKind::FreeSpace => {
                let col = if selected { FG_MINT } else { FG_TRACK };
                bar.push_str(&fg_rgb(col.0, col.1, col.2));
                for _ in 0..seg_w {
                    bar.push(if selected { '▒' } else { '░' });
                }
                bar.push_str(ansi::RESET);

                if selected {
                    caret.push_str(&fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2));
                    caret.push_str(ansi::BOLD);
                    caret.push_str(&center_ascii("^FREE^", seg_w, '^'));
                    caret.push_str(ansi::RESET);
                } else {
                    for _ in 0..seg_w {
                        caret.push(' ');
                    }
                }
            }
        }
    }
    (bar, caret)
}

fn build_partition_table_pane(
    state: &EditorState,
    slots: &[DiskSlot],
    width: usize,
    height: usize,
) -> Vec<String> {
    let mut lines = Vec::with_capacity(height);
    let part_count = slots
        .iter()
        .filter(|s| matches!(s.kind, SlotKind::Partition { .. }))
        .count();
    let free_count = slots.len().saturating_sub(part_count);
    let title = format!("Partitions & Free Regions  [{part_count} part | {free_count} free]");
    lines.push(box_top(&title, width, FG_BORDER_HI, FG_TITLE));

    let name_w = width.saturating_sub(78).clamp(8, 28);
    let hdr = format!(
        "   {}{:<15} {:>10} {:>10} {:>10} {:>8}  {:<14} {:<name_w$}{}",
        ansi::BOLD,
        "DEVICE",
        "START LBA",
        "END LBA",
        "SECTORS",
        "SIZE",
        "TYPE",
        "GPT LABEL",
        ansi::RESET,
    );
    lines.push(box_line(&hdr, width, FG_BORDER_HI));
    lines.push(box_rule(width, FG_BORDER));

    let body_rows = height.saturating_sub(4);
    if state.disk.is_none() {
        let mut msg_lines = Vec::new();
        msg_lines.push(String::new());
        if let Some(ref bare) = state.raw_hxfs {
            msg_lines.push(format!(
                "   {}Whole device holds a mounted {} filesystem ({}){}",
                fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                bare.layout_tag(),
                bare.layout_label(),
                ansi::RESET
            ));
            msg_lines.push(format!(
                "   {}Format v{}, checkpoint sequence #{}, block size {}B{}",
                fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
                bare.format_version,
                bare.sequence_number,
                bare.block_size,
                ansi::RESET
            ));
            msg_lines.push(String::new());
            msg_lines.push(format!(
                "   {}Press [g] (or Enter on g:NewGPT) to stage a fresh GPT in memory.{}",
                fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                ansi::RESET
            ));
            msg_lines.push(format!(
                "   {}Nothing touches disk unless you explicitly confirm [w:Write].{}",
                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ansi::RESET
            ));
        } else {
            msg_lines.push(format!(
                "   {}Disk does not contain a recognized GPT partition table.{}",
                fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                ansi::RESET
            ));
            msg_lines.push(format!(
                "   {}Press [g] (or Enter on g:NewGPT) to initialize Protective MBR + GPT.{}",
                fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                ansi::RESET
            ));
        }
        for i in 0..body_rows {
            let txt = msg_lines.get(i).map(String::as_str).unwrap_or("");
            lines.push(box_line(txt, width, FG_BORDER_HI));
        }
    } else {
        let scroll_top = if body_rows == 0 || state.selected_row < body_rows {
            0
        } else {
            state.selected_row + 1 - body_rows
        };
        for i in 0..body_rows {
            if let Some(slot) = slots.get(scroll_top + i) {
                let selected = scroll_top + i == state.selected_row;
                match &slot.kind {
                    SlotKind::Partition {
                        part_num,
                        type_guid,
                        name,
                        ..
                    } => {
                        let dev = partition_dev_name(&state.label, *part_num);
                        let disp_name = if name.is_empty() { "-" } else { name.as_str() };
                        let tcol = type_color(type_guid);
                        if selected {
                            let plain = format!(
                                " > {:<15} {:>10} {:>10} {:>10} {:>8}  █ {:<12} {}",
                                tui::fit(&dev, 15),
                                slot.start_lba,
                                slot.end_lba,
                                slot.size_lbas(),
                                human_size(slot.size_bytes()),
                                tui::fit(short_type(type_guid), 12),
                                tui::fit(disp_name, name_w),
                            );
                            let hi = tui::fit_with_bg(
                                &format!("{}{}{}", fg_rgb(255, 255, 255), ansi::BOLD, plain),
                                width.saturating_sub(2),
                                BG_SELECT,
                            );
                            let b = fg_rgb(FG_BORDER_HI.0, FG_BORDER_HI.1, FG_BORDER_HI.2);
                            lines.push(format!("{b}│{}{hi}{b}│{}", ansi::RESET, ansi::RESET));
                        } else {
                            let row = format!(
                                "   {}{:<15}{} {}{:>10} {:>10} {:>10}{} {}{:>8}{}  {}█ {:<12}{} {}{}{}",
                                fg_rgb(235, 243, 255),
                                tui::fit(&dev, 15),
                                ansi::RESET,
                                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                                slot.start_lba,
                                slot.end_lba,
                                slot.size_lbas(),
                                ansi::RESET,
                                fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
                                human_size(slot.size_bytes()),
                                ansi::RESET,
                                fg_rgb(tcol.0, tcol.1, tcol.2),
                                tui::fit(short_type(type_guid), 12),
                                ansi::RESET,
                                fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
                                tui::fit(disp_name, name_w),
                                ansi::RESET,
                            );
                            lines.push(box_line(&row, width, FG_BORDER_HI));
                        }
                    }
                    SlotKind::FreeSpace => {
                        if selected {
                            let plain = format!(
                                " > {:<15} {:>10} {:>10} {:>10} {:>8}  {:<14} {}",
                                "Free space",
                                slot.start_lba,
                                slot.end_lba,
                                slot.size_lbas(),
                                human_size(slot.size_bytes()),
                                "unallocated",
                                "[press n]",
                            );
                            let hi = tui::fit_with_bg(
                                &format!("{}{}{}", fg_rgb(130, 255, 195), ansi::BOLD, plain),
                                width.saturating_sub(2),
                                BG_SELECT,
                            );
                            let b = fg_rgb(FG_BORDER_HI.0, FG_BORDER_HI.1, FG_BORDER_HI.2);
                            lines.push(format!("{b}│{}{hi}{b}│{}", ansi::RESET, ansi::RESET));
                        } else {
                            let row = format!(
                                "   {}{:<15}{} {}{:>10} {:>10} {:>10}{} {}{:>8}{}  {}{:<14} -{}",
                                fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
                                "Free space",
                                ansi::RESET,
                                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                                slot.start_lba,
                                slot.end_lba,
                                slot.size_lbas(),
                                ansi::RESET,
                                fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
                                human_size(slot.size_bytes()),
                                ansi::RESET,
                                fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                                "unallocated",
                                ansi::RESET,
                            );
                            lines.push(box_line(&row, width, FG_BORDER_HI));
                        }
                    }
                }
            } else {
                lines.push(box_line("", width, FG_BORDER_HI));
            }
        }
    }

    lines.push(box_bottom(width, FG_BORDER_HI));
    lines
}

fn build_inspector_pane(
    state: &EditorState,
    slots: &[DiskSlot],
    width: usize,
    height: usize,
) -> Vec<String> {
    let mut content: Vec<String> = Vec::new();

    if let Some(slot) = slots.get(state.selected_row) {
        let share_pct = (slot.size_lbas().saturating_mul(100))
            .checked_div(state.total_lbas.max(1))
            .unwrap_or(0);
        let align_str = if slot.start_lba % ALIGN_1MIB_LBAS == 0 {
            format!(
                "{}1 MiB optimal{}",
                fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
                ansi::RESET
            )
        } else if slot.start_lba % ALIGN_4KIB_LBAS == 0 {
            format!(
                "{}4 KiB aligned{}",
                fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                ansi::RESET
            )
        } else {
            format!(
                "{}unaligned sector{}",
                fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                ansi::RESET
            )
        };

        match &slot.kind {
            SlotKind::Partition {
                part_num,
                type_guid,
                unique_guid,
                name,
            } => {
                let dev = partition_dev_name(&state.label, *part_num);
                let tcol = type_color(type_guid);
                content.push(section_hdr("SELECTED PARTITION", FG_CYAN));
                content.push(kv_line("Device Node", &dev, FG_TITLE));
                content.push(kv_line("GPT Slot", &format!("#{part_num} of 128"), FG_TEXT));
                content.push(kv_line(
                    "UTF-16 Label",
                    if name.is_empty() {
                        "<empty>"
                    } else {
                        name.as_str()
                    },
                    FG_TEXT,
                ));
                content.push(kv_line("Partition Type", &type_guid.type_label(), tcol));
                content.push(kv_line("Type GUID", &type_guid.format_uuid(), FG_MUTED));
                content.push(kv_line("Unique UUID", &unique_guid.format_uuid(), FG_MUTED));
                content.push(String::new());
                content.push(section_hdr("SECTOR & BYTE GEOMETRY", FG_CYAN));
                content.push(kv_line(
                    "Start LBA",
                    &format!("{}", slot.start_lba),
                    FG_TEXT,
                ));
                content.push(kv_line("End LBA", &format!("{}", slot.end_lba), FG_TEXT));
                content.push(kv_line(
                    "Span",
                    &format!(
                        "{} LBAs ({}, {}%)",
                        slot.size_lbas(),
                        human_size(slot.size_bytes()),
                        share_pct
                    ),
                    FG_TEXT,
                ));
                content.push(kv_line(
                    "Byte Offset",
                    &format!("0x{:010x}", slot.start_lba * LBA_SIZE as u64),
                    FG_MUTED,
                ));
                content.push(format!(
                    " {}Alignment   :{} {}",
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                    ansi::RESET,
                    align_str
                ));
            }
            SlotKind::FreeSpace => {
                let usable = usable_free_in_slot(slot);
                let next_aligned = align_up(slot.start_lba, ALIGN_1MIB_LBAS);
                content.push(section_hdr("SELECTED FREE REGION", FG_MINT));
                content.push(kv_line("Region Kind", "Unallocated space", FG_MINT));
                content.push(kv_line(
                    "Raw Start LBA",
                    &format!("{}", slot.start_lba),
                    FG_TEXT,
                ));
                content.push(kv_line(
                    "Raw End LBA",
                    &format!("{}", slot.end_lba),
                    FG_TEXT,
                ));
                content.push(kv_line(
                    "Raw Capacity",
                    &format!(
                        "{} ({} LBAs)",
                        human_size(slot.size_bytes()),
                        slot.size_lbas()
                    ),
                    FG_TEXT,
                ));
                content.push(kv_line(
                    "1MiB Start",
                    &format!("LBA {next_aligned}"),
                    FG_CYAN,
                ));
                content.push(kv_line(
                    "1MiB Usable",
                    &format!("{} ({} LBAs)", human_size(usable * LBA_SIZE as u64), usable),
                    FG_MINT,
                ));
                content.push(String::new());
                content.push(format!(
                    " {}Tip: press [n] or Enter to allocate{}",
                    fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                    ansi::RESET
                ));
                content.push(format!(
                    " {}a new 1 MiB-aligned GPT partition.{}",
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                    ansi::RESET
                ));
            }
        }
    } else if let Some(ref bare) = state.raw_hxfs {
        content.push(section_hdr("BARE HXFS SUPERFLOPPY", FG_AMBER));
        content.push(kv_line("Layout Tag", bare.layout_tag(), FG_CYAN));
        content.push(kv_line("Volume Label", &bare.layout_label(), FG_TEXT));
        content.push(kv_line(
            "HxFS Version",
            &format!("v{}", bare.format_version),
            FG_MINT,
        ));
        content.push(kv_line(
            "Block Size",
            &format!("{} B", bare.block_size),
            FG_TEXT,
        ));
        content.push(kv_line(
            "Instance UUID",
            &format_uuid(&bare.instance_uuid),
            FG_MUTED,
        ));
        content.push(kv_line(
            "Checkpoint Seq",
            &format!("#{}", bare.sequence_number),
            FG_TEXT,
        ));
        content.push(kv_line(
            "Root State",
            &format!("{}", bare.root_state),
            FG_TEXT,
        ));
    }

    content.push(String::new());
    content.push(section_hdr("DISK & GPT HEADER TELEMETRY", FG_VIOLET));
    if let Some(ref d) = state.disk {
        content.push(kv_line(
            "Disk GUID",
            &d.primary.disk_guid.format_uuid(),
            FG_MUTED,
        ));
        content.push(kv_line(
            "Usable LBAs",
            &format!(
                "{} ..= {}",
                d.primary.first_usable_lba, d.primary.last_usable_lba
            ),
            FG_TEXT,
        ));
        content.push(kv_line(
            "Headers",
            &format!(
                "Pri LBA {} | Bak LBA {}",
                d.primary.my_lba, d.primary.alternate_lba
            ),
            FG_TEXT,
        ));
        content.push(kv_line(
            "Entry Array",
            &format!(
                "LBA {} ({} slots)",
                d.primary.partition_entry_lba, d.primary.num_partition_entries
            ),
            FG_TEXT,
        ));
        if state.dirty {
            content.push(kv_line(
                "On-Disk Sync",
                "Staged edits pending [w]",
                FG_AMBER,
            ));
        } else if let Some(ref rep) = state.last_verify {
            let health = if rep.ok {
                "VALID (PMBR + Pri + Bak CRC)"
            } else {
                "DEGRADED (press v for details)"
            };
            content.push(kv_line(
                "CRC Integrity",
                health,
                if rep.ok { FG_MINT } else { FG_AMBER },
            ));
        }
    } else {
        content.push(kv_line("GPT Table", "Absent", FG_AMBER));
        content.push(kv_line(
            "Total Sectors",
            &format!("{} x {}B", state.total_lbas, LBA_SIZE),
            FG_TEXT,
        ));
    }

    let mut lines = Vec::with_capacity(height);
    lines.push(box_top(
        "Region & GPT Inspector",
        width,
        FG_BORDER,
        FG_VIOLET,
    ));
    let body_rows = height.saturating_sub(2);
    for i in 0..body_rows {
        let txt = content.get(i).map(String::as_str).unwrap_or("");
        lines.push(box_line(txt, width, FG_BORDER));
    }
    lines.push(box_bottom(width, FG_BORDER));
    lines
}

fn render_modal(fb: &mut FrameBuffer, state: &EditorState, modal: ModalOverlay<'_>) {
    match modal {
        ModalOverlay::Prompt {
            title,
            prompt,
            typed,
        } => {
            let w = 86usize.min(fb.cols().saturating_sub(4));
            let inner_box = w.saturating_sub(6);
            let cursor_field = format!("{typed}_");
            let field_rendered = tui::fit_with_bg(
                &format!(" {}{}{}", fg_rgb(110, 245, 195), ansi::BOLD, cursor_field),
                inner_box,
                BG_INPUT,
            );
            let rows_txt = [
                String::new(),
                format!(
                    "  {}{}{}",
                    fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
                    tui::fit(prompt, w.saturating_sub(4)),
                    ansi::RESET
                ),
                String::new(),
                format!("  {field_rendered}"),
                String::new(),
                format!(
                    "  {}Enter{} confirm   {}Esc / ^C{} cancel   {}Backspace{} edit   {}^U{} clear",
                    fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                    fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                    fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                    fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                ),
            ];
            draw_floating_box(fb, title, &rows_txt, w, FG_CYAN);
        }
        ModalOverlay::Help => {
            let w = 88usize.min(fb.cols().saturating_sub(4));
            let rows_txt = [
                String::from("  Navigation"),
                String::from(
                    "    Up / Down (k / j), PgUp/Dn   Select partition or free-space slot",
                ),
                String::from("    Left / Right / Tab           Select bottom cfdisk action button"),
                String::from("    Enter                        Execute highlighted action button"),
                String::new(),
                String::from("  Partition & GPT Operations"),
                String::from("    n   Create new 1 MiB-aligned GPT partition in free space"),
                String::from("    d   Delete selected (or numbered) GPT partition"),
                String::from("    r   Resize partition in place"),
                String::from(
                    "    t   Change partition type GUID (hxfs, efi, linux, swap, basic, UUID)",
                ),
                String::from("    c   Change GPT partition UTF-16 name / label"),
                String::from("    i   Open detailed Partition / Region Inspector modal"),
                String::from("    l   Open known GPT Partition Type GUID catalog"),
                String::from("    g   Stage a fresh empty Protective MBR + GPT in memory"),
                String::from("    p   Reload partition table from disk (discarding unsaved edits)"),
                String::from(
                    "    v   Verify Protective MBR + Primary & Backup GPT header/entry CRCs",
                ),
                String::from("    w   Commit staged GPT to disk and flush"),
                String::from(
                    "    q   Quit cleanly (prompts twice if unsaved edits exist; Esc / ^C)",
                ),
                String::new(),
                format!(
                    "                  {}Press any key to close command reference{}",
                    fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                    ansi::RESET
                ),
            ];
            draw_floating_box(
                fb,
                "fdisk / cfdisk Command Reference",
                &rows_txt,
                w,
                FG_CYAN,
            );
        }
        ModalOverlay::Types => {
            let w = 92usize.min(fb.cols().saturating_sub(4));
            let types = [
                ("1", "hxfs", "HuesOS HxFS v7", GUID_HXFS_V7),
                ("2", "efi", "EFI System Partition (ESP)", GUID_ESP),
                ("3", "linux", "Linux filesystem data", GUID_LINUX_FS),
                ("4", "swap", "Linux swap partition", GUID_LINUX_SWAP),
                ("5", "basic", "Microsoft Basic Data", GUID_MS_BASIC_DATA),
            ];
            let mut rows_txt = Vec::new();
            rows_txt.push(format!(
                "  {}{:<3} {:<8} {:<28} TYPE GUID{}",
                ansi::BOLD,
                "#",
                "ALIAS",
                "DESCRIPTION",
                ansi::RESET
            ));
            rows_txt.push(format!(
                "  {}{}{}",
                fg_rgb(FG_BORDER.0, FG_BORDER.1, FG_BORDER.2),
                "─".repeat(w.saturating_sub(6)),
                ansi::RESET
            ));
            for (num, alias, desc, guid) in types {
                let col = type_color(&guid);
                rows_txt.push(format!(
                    "  {}{:<3}{} {}{:<8}{} {:<28} {}{}{}",
                    fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                    num,
                    ansi::RESET,
                    fg_rgb(col.0, col.1, col.2),
                    alias,
                    ansi::RESET,
                    desc,
                    fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
                    guid.format_uuid(),
                    ansi::RESET
                ));
            }
            rows_txt.push(String::new());
            rows_txt.push(String::from(
                "  Custom 36-char RFC 4122 UUIDs are also accepted at any type prompt.",
            ));
            rows_txt.push(format!(
                "                      {}Press any key to return...{}",
                fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                ansi::RESET
            ));
            draw_floating_box(
                fb,
                "Known GPT Partition Types (t / n)",
                &rows_txt,
                w,
                FG_VIOLET,
            );
        }
        ModalOverlay::Info(slot) => {
            let w = 84usize.min(fb.cols().saturating_sub(4));
            let mut rows_txt = Vec::new();
            match &slot.kind {
                SlotKind::Partition {
                    part_num,
                    type_guid,
                    unique_guid,
                    name,
                } => {
                    let dev = partition_dev_name(&state.label, *part_num);
                    rows_txt.push(kv_line(
                        "Device Node",
                        &format!("{dev} (slot #{part_num})"),
                        FG_TITLE,
                    ));
                    rows_txt.push(kv_line(
                        "Partition Name",
                        if name.is_empty() {
                            "<empty>"
                        } else {
                            name.as_str()
                        },
                        FG_TEXT,
                    ));
                    rows_txt.push(kv_line(
                        "Partition Type",
                        &type_guid.type_label(),
                        type_color(type_guid),
                    ));
                    rows_txt.push(kv_line("Type GUID", &type_guid.format_uuid(), FG_CYAN));
                    rows_txt.push(kv_line("Unique UUID", &unique_guid.format_uuid(), FG_CYAN));
                    rows_txt.push(kv_line(
                        "Start LBA",
                        &format!("{}", slot.start_lba),
                        FG_TEXT,
                    ));
                    rows_txt.push(kv_line("End LBA", &format!("{}", slot.end_lba), FG_TEXT));
                    rows_txt.push(kv_line(
                        "Capacity",
                        &format!(
                            "{} sectors ({} bytes / {})",
                            slot.size_lbas(),
                            slot.size_bytes(),
                            human_size(slot.size_bytes())
                        ),
                        FG_MINT,
                    ));
                }
                SlotKind::FreeSpace => {
                    rows_txt.push(kv_line("Region", "Unallocated free space", FG_MINT));
                    rows_txt.push(kv_line(
                        "Start LBA",
                        &format!("{}", slot.start_lba),
                        FG_TEXT,
                    ));
                    rows_txt.push(kv_line("End LBA", &format!("{}", slot.end_lba), FG_TEXT));
                    rows_txt.push(kv_line(
                        "Capacity",
                        &format!(
                            "{} sectors ({})",
                            slot.size_lbas(),
                            human_size(slot.size_bytes())
                        ),
                        FG_MINT,
                    ));
                }
            }
            rows_txt.push(String::new());
            rows_txt.push(format!(
                "                    {}Press any key to return...{}",
                fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                ansi::RESET
            ));
            draw_floating_box(fb, "Partition / Region Inspector", &rows_txt, w, FG_CYAN);
        }
    }
}

fn draw_floating_box(
    fb: &mut FrameBuffer,
    title: &str,
    rows_txt: &[String],
    w: usize,
    border: (u8, u8, u8),
) {
    let h = rows_txt.len() + 2;
    let start_r = (fb.rows().saturating_sub(h)) / 2 + 1;
    let start_c = (fb.cols().saturating_sub(w)) / 2 + 1;

    fb.put_at(
        start_r,
        start_c,
        &tui::fit_with_bg(&box_top(title, w, border, FG_TITLE), w, BG_MODAL),
    );
    for (i, rline) in rows_txt.iter().enumerate() {
        let body = box_line(rline, w, border);
        fb.put_at(
            start_r + 1 + i,
            start_c,
            &tui::fit_with_bg(&body, w, BG_MODAL),
        );
    }
    fb.put_at(
        start_r + 1 + rows_txt.len(),
        start_c,
        &tui::fit_with_bg(&box_bottom(w, border), w, BG_MODAL),
    );
}

fn section_hdr(title: &str, col: (u8, u8, u8)) -> String {
    format!(
        " {}{}{}{}",
        fg_rgb(col.0, col.1, col.2),
        ansi::BOLD,
        title,
        ansi::RESET
    )
}

fn kv_line(key: &str, val: &str, val_col: (u8, u8, u8)) -> String {
    format!(
        " {}{:<14}:{} {}{}{}",
        fg_rgb(FG_MUTED.0, FG_MUTED.1, FG_MUTED.2),
        key,
        ansi::RESET,
        fg_rgb(val_col.0, val_col.1, val_col.2),
        val,
        ansi::RESET
    )
}

fn type_color(guid: &Guid) -> (u8, u8, u8) {
    if *guid == GUID_HXFS_V7 {
        FG_CYAN
    } else if *guid == GUID_ESP {
        FG_AMBER
    } else if *guid == GUID_LINUX_FS {
        FG_MINT
    } else if *guid == GUID_LINUX_SWAP {
        FG_VIOLET
    } else {
        FG_BLUE
    }
}

fn center_ascii(text: &str, width: usize, pad: char) -> String {
    let tlen = text.chars().count();
    if width == 0 {
        return String::new();
    }
    if tlen >= width {
        return text.chars().take(width).collect();
    }
    let left = (width - tlen) / 2;
    let right = width - tlen - left;
    let mut out = String::with_capacity(width);
    for _ in 0..left {
        out.push(pad);
    }
    out.push_str(text);
    for _ in 0..right {
        out.push(pad);
    }
    out
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

fn join_lr(left: &str, right: &str, width: usize) -> String {
    let lw = tui::visible_width(left);
    let rw = tui::visible_width(right);
    if lw + rw + 1 >= width {
        return tui::fit(left, width);
    }
    let mut out = String::from(left);
    for _ in 0..(width - lw - rw) {
        out.push(' ');
    }
    out.push_str(right);
    out
}

fn box_top(title: &str, width: usize, border: (u8, u8, u8), title_col: (u8, u8, u8)) -> String {
    let inner = width.saturating_sub(2);
    let b_seq = fg_rgb(border.0, border.1, border.2);
    let t_seq = fg_rgb(title_col.0, title_col.1, title_col.2);
    if title.trim().is_empty() || inner < 6 {
        let mut s = format!("{b_seq}┌");
        for _ in 0..inner {
            s.push('─');
        }
        s.push('┐');
        s.push_str(ansi::RESET);
        return s;
    }
    let clean = title.trim();
    let max_title = inner.saturating_sub(4);
    let shown: String = clean.chars().take(max_title).collect();
    let shown_len = shown.chars().count();
    let dashes = inner.saturating_sub(shown_len + 3);
    let mut s = format!("{b_seq}┌─ {t_seq}{}{shown}{b_seq} ", ansi::BOLD);
    for _ in 0..dashes {
        s.push('─');
    }
    s.push('┐');
    s.push_str(ansi::RESET);
    s
}

fn box_rule(width: usize, border: (u8, u8, u8)) -> String {
    let mut s = format!("{}├", fg_rgb(border.0, border.1, border.2));
    for _ in 0..width.saturating_sub(2) {
        s.push('─');
    }
    s.push('┤');
    s.push_str(ansi::RESET);
    s
}

fn box_bottom(width: usize, border: (u8, u8, u8)) -> String {
    let mut s = format!("{}└", fg_rgb(border.0, border.1, border.2));
    for _ in 0..width.saturating_sub(2) {
        s.push('─');
    }
    s.push('┘');
    s.push_str(ansi::RESET);
    s
}

fn box_line(body: &str, width: usize, border: (u8, u8, u8)) -> String {
    let b_seq = fg_rgb(border.0, border.1, border.2);
    let fitted = tui::fit(body, width.saturating_sub(2));
    format!("{b_seq}│{}{fitted}{b_seq}│{}", ansi::RESET, ansi::RESET)
}
