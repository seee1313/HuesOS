//! `/bin/wlanctl.elf` — IEEE 802.11 / WPA2-CCMP / Realtek `rtw88` (`10ec:c821`)
//! CLI and full-screen 168×50 interactive TUI (`HWLN` wire protocol).
//!
//! Modes:
//! - `wlanctl` / `wlanctl tui` / `wlanctl -n 1` — full-screen obsidian TUI
//! - `wlanctl status`
//! - `wlanctl scan`
//! - `wlanctl connect <ssid> [passphrase]`
//! - `wlanctl disconnect`
//! - `wlanctl profiles`
//! - `wlanctl regdomain <WORLD|RU|US|EU|JP|UNLOCKED>`
//! - `wlanctl mac <factory|random>`
//! - `wlanctl ap start <ssid> <passphrase> [channel]`
//! - `wlanctl ap stop`

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_abi::wlan::{
    MacPolicyMode, RegDomainCode, WlanBssInfo, WlanProfileSummary, WlanSecurity, WlanStateCode,
    WlanStatusSnapshot,
};
use huesos_coreutils as cu;
use huesos_std::io;
use huesos_std::net;
use huesos_std::time::Duration;
use huesos_std::tui::{self, ansi, bg_rgb, fg_rgb, FrameBuffer, Key};
use huesos_std::{Error, ErrorKind};

cu::coreutil_entry!(run);

const BG_HEADER: (u8, u8, u8) = (19, 26, 40);
const BG_FOOTER: (u8, u8, u8) = (16, 22, 34);
const BG_SELECT: (u8, u8, u8) = (32, 54, 82);
const FG_BORDER_HI: (u8, u8, u8) = (88, 196, 220);
const FG_BORDER: (u8, u8, u8) = (56, 78, 112);
const FG_TITLE: (u8, u8, u8) = (120, 238, 200);
const FG_TEXT: (u8, u8, u8) = (214, 226, 244);
const FG_MINT: (u8, u8, u8) = (95, 230, 172);
const FG_AMBER: (u8, u8, u8) = (250, 202, 96);
const FG_CYAN: (u8, u8, u8) = (95, 222, 245);
const FG_TRACK: (u8, u8, u8) = (38, 49, 68);

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn parse_reg_domain(s: &str) -> Option<RegDomainCode> {
    if s.eq_ignore_ascii_case("world") || s == "00" {
        Some(RegDomainCode::World)
    } else if s.eq_ignore_ascii_case("ru") {
        Some(RegDomainCode::Ru)
    } else if s.eq_ignore_ascii_case("us") {
        Some(RegDomainCode::Us)
    } else if s.eq_ignore_ascii_case("eu") {
        Some(RegDomainCode::Eu)
    } else if s.eq_ignore_ascii_case("jp") {
        Some(RegDomainCode::Jp)
    } else if s.eq_ignore_ascii_case("unlocked") {
        Some(RegDomainCode::Unlocked)
    } else {
        None
    }
}

fn next_reg_domain(d: RegDomainCode) -> RegDomainCode {
    match d {
        RegDomainCode::World => RegDomainCode::Ru,
        RegDomainCode::Ru => RegDomainCode::Us,
        RegDomainCode::Us => RegDomainCode::Eu,
        RegDomainCode::Eu => RegDomainCode::Jp,
        RegDomainCode::Jp => RegDomainCode::Unlocked,
        RegDomainCode::Unlocked => RegDomainCode::World,
    }
}

fn rssi_quality_pct(rssi_dbm: i8) -> u64 {
    if rssi_dbm <= -95 {
        0
    } else if rssi_dbm >= -35 {
        100
    } else {
        (((i32::from(rssi_dbm) + 95) * 100) / 60) as u64
    }
}

fn describe_wlan_err(err: Error) -> &'static str {
    if err.kind() == ErrorKind::Unsupported {
        match net::wlan_status() {
            Ok(st) if st.state == WlanStateCode::HardwareAbsent => {
                "no Wi-Fi adapter detected (PCIe 10ec:c821 RTL8821CE absent)"
            }
            Ok(st) if !st.firmware_loaded => "rtw8821c_fw.bin firmware unavailable",
            _ => "no Wi-Fi adapter detected (PCIe 10ec:c821 RTL8821CE absent)",
        }
    } else {
        err.kind().as_str()
    }
}

fn cmd_status() -> i32 {
    let st = match net::wlan_status() {
        Ok(s) => s,
        Err(e) => {
            cu::errln(&format!("wlanctl: status failed: {e}"));
            return 1;
        }
    };
    let hw_mode = if st.adapter_present {
        "RTL8821CE PCIe (10ec:c821)"
    } else if st.state == WlanStateCode::HardwareAbsent {
        "none (PCIe 10ec:c821 absent)"
    } else {
        "rtw88 boot-selftest medium"
    };
    cu::outln(&format!(
        "wlan0: state={}  hw=\"{}\"  fw=v{}.{} (loaded={})",
        st.state.as_str(),
        hw_mode,
        st.fw_version[0],
        st.fw_version[1],
        st.firmware_loaded
    ));
    if st.state == WlanStateCode::HardwareAbsent {
        cu::outln(
            "       no physical Realtek RTL8821CE (10ec:c821) Wi-Fi adapter detected on PCIe bus",
        );
        return 0;
    }
    cu::outln(&format!(
        "       mac={} (factory={}, policy={})  regdomain={}  thermal={}C",
        fmt_mac(st.active_mac),
        fmt_mac(st.factory_mac),
        st.mac_policy.as_str(),
        st.reg_domain.as_str(),
        st.thermal_celsius
    ));
    if st.state == WlanStateCode::Connected || st.state == WlanStateCode::SoftAp {
        cu::outln(&format!(
            "       ssid=\"{}\"  bssid={}  ch={} ({} MHz)  rssi={} dBm ({}%)",
            st.ssid_str(),
            fmt_mac(st.bssid),
            st.channel,
            st.width_mhz,
            st.rssi_dbm,
            rssi_quality_pct(st.rssi_dbm)
        ));
    }
    cu::outln(&format!(
        "       tx_mpdu={}  rx_mpdu={}  ccmp_replay_drops={}  saved_profiles={}",
        st.tx_frames, st.rx_frames, st.ccmp_replay_drops, st.saved_profiles
    ));
    0
}

fn cmd_scan() -> i32 {
    let list = match net::wlan_scan() {
        Ok(v) => v,
        Err(e) => {
            cu::errln(&format!("wlanctl: scan failed: {}", describe_wlan_err(e)));
            return 1;
        }
    };
    let mut tbl = tui::Table::new(
        &["SSID", "BSSID", "BAND", "CH", "WIDTH", "RSSI", "SECURITY"],
        &[22, 18, 6, 4, 7, 9, 12],
    );
    for bss in &list {
        tbl.row(&[
            String::from(bss.ssid_str()),
            fmt_mac(bss.bssid),
            String::from(if bss.is_5ghz() { "5GHz" } else { "2.4G" }),
            format!("{}", bss.channel),
            format!("{}MHz", bss.width_mhz),
            format!("{} dBm", bss.rssi_dbm),
            String::from(bss.security.as_str()),
        ]);
    }
    cu::outln(&tbl.header_line());
    cu::outln(&tbl.separator());
    for line in tbl.lines() {
        cu::outln(&line);
    }
    cu::outln(&format!("{} network(s) discovered", list.len()));
    0
}

fn cmd_profiles() -> i32 {
    let list: Vec<WlanProfileSummary> = match net::wlan_list_profiles() {
        Ok(v) => v,
        Err(e) => {
            cu::errln(&format!("wlanctl: list profiles failed: {e}"));
            return 1;
        }
    };
    let mut tbl = tui::Table::new(&["SSID", "AUTOCONNECT", "PMK-FINGERPRINT"], &[26, 12, 16]);
    for p in &list {
        tbl.row(&[
            String::from(p.ssid_str()),
            String::from(if p.autoconnect { "yes" } else { "no" }),
            format!(
                "{:02x}{:02x}{:02x}{:02x}",
                p.pmk_fingerprint[0],
                p.pmk_fingerprint[1],
                p.pmk_fingerprint[2],
                p.pmk_fingerprint[3]
            ),
        ]);
    }
    cu::outln(&tbl.header_line());
    cu::outln(&tbl.separator());
    for line in tbl.lines() {
        cu::outln(&line);
    }
    0
}

// ============================================================================
// Interactive 168×50 Obsidian Wi-Fi Studio TUI (`wlanctl` / `wlanctl -n 1`)
// ============================================================================

struct WlanTui {
    status: Option<WlanStatusSnapshot>,
    scan: Vec<WlanBssInfo>,
    profiles: Vec<WlanProfileSummary>,
    selected: usize,
    typing_psk: bool,
    psk_buf: String,
    banner_msg: String,
}

impl WlanTui {
    fn new() -> Self {
        let mut s = Self {
            status: None,
            scan: Vec::new(),
            profiles: Vec::new(),
            selected: 0,
            typing_psk: false,
            psk_buf: String::new(),
            banner_msg: String::from("Ready — press 's' to rescan, Enter/'c' to connect"),
        };
        s.refresh(true);
        s
    }

    fn refresh(&mut self, do_scan: bool) {
        self.status = net::wlan_status().ok();
        let hw_absent = self
            .status
            .as_ref()
            .is_some_and(|st| st.state == WlanStateCode::HardwareAbsent);
        if hw_absent {
            self.scan.clear();
            self.banner_msg =
                String::from("No Wi-Fi adapter detected (PCIe 10ec:c821 RTL8821CE absent)");
        } else if do_scan {
            if let Ok(list) = net::wlan_scan() {
                self.scan = list;
            }
        }
        if let Ok(p) = net::wlan_list_profiles() {
            self.profiles = p;
        }
        if self.selected >= self.scan.len() && !self.scan.is_empty() {
            self.selected = self.scan.len() - 1;
        }
    }
}

fn box_top(title: &str, width: usize) -> String {
    let b = fg_rgb(FG_BORDER_HI.0, FG_BORDER_HI.1, FG_BORDER_HI.2);
    let t = fg_rgb(FG_TITLE.0, FG_TITLE.1, FG_TITLE.2);
    let head = format!("─ {title} ");
    let used = 2 + tui::visible_width(&head);
    let fill = width.saturating_sub(used);
    let mut bar = String::new();
    for _ in 0..fill {
        bar.push('─');
    }
    format!("{b}╭─{t}{}{title}{b} {bar}╮{}", ansi::BOLD, ansi::RESET)
}

fn box_line(inner: &str, width: usize) -> String {
    let b = fg_rgb(FG_BORDER.0, FG_BORDER.1, FG_BORDER.2);
    let fitted = tui::fit(inner, width.saturating_sub(2));
    format!("{b}│{}{fitted}{b}│{}", ansi::RESET, ansi::RESET)
}

fn box_bottom(width: usize) -> String {
    let b = fg_rgb(FG_BORDER.0, FG_BORDER.1, FG_BORDER.2);
    let mut bar = String::new();
    for _ in 0..width.saturating_sub(2) {
        bar.push('─');
    }
    format!("{b}╰{bar}╯{}", ansi::RESET)
}

fn render_tui_frame(fb: &mut FrameBuffer, app: &WlanTui) {
    let cols = fb.cols().max(80);
    let rows = fb.rows().max(24);
    let hw_absent = app
        .status
        .as_ref()
        .is_some_and(|st| st.state == WlanStateCode::HardwareAbsent);

    let hdr = format!(
        " {}{}HuesOS Wi-Fi Studio{}  │  Realtek RTL8821CE (rtw88 / 802.11ac WPA2-CCMP)  │  {}{}",
        fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
        ansi::BOLD,
        ansi::RESET,
        fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
        app.banner_msg
    );
    fb.put_bar_row(1, BG_HEADER, &hdr);

    let mut row = 2usize;
    fb.put_row(row, &box_top("Radio Telemetry & WPA2-CCMP State", cols));
    row += 1;
    if let Some(st) = app.status.as_ref() {
        if st.state == WlanStateCode::HardwareAbsent {
            fb.put_row(
                row,
                &box_line(
                    &format!(
                        " State: {}{:<15}{}  Adapter: {}none (PCIe 10ec:c821 RTL8821CE not detected){}  FW: v{}.{} (staged={})",
                        fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                        st.state.as_str(),
                        ansi::RESET,
                        fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                        ansi::RESET,
                        st.fw_version[0],
                        st.fw_version[1],
                        st.firmware_loaded,
                    ),
                    cols,
                ),
            );
            row += 1;
            fb.put_row(
                row,
                &box_line(
                    &format!(
                        " RegDomain: {}{:<8}{}  MAC Policy: {}  Saved Profiles: {}",
                        fg_rgb(FG_CYAN.0, FG_CYAN.1, FG_CYAN.2),
                        st.reg_domain.as_str(),
                        ansi::RESET,
                        st.mac_policy.as_str(),
                        st.saved_profiles,
                    ),
                    cols,
                ),
            );
            row += 1;
        } else {
            let qual = rssi_quality_pct(st.rssi_dbm);
            let sig_bar = tui::smooth_bar(qual, 100, 28, FG_MINT, FG_TRACK);
            fb.put_row(
                row,
                &box_line(
                    &format!(
                        " State: {}{:<15}{}  FW: v{}.{}  RegDomain: {}{:<8}{}  MAC: {} ({})  Temp: {}C",
                        fg_rgb(FG_MINT.0, FG_MINT.1, FG_MINT.2),
                        st.state.as_str(),
                        ansi::RESET,
                        st.fw_version[0],
                        st.fw_version[1],
                        fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                        st.reg_domain.as_str(),
                        ansi::RESET,
                        fmt_mac(st.active_mac),
                        st.mac_policy.as_str(),
                        st.thermal_celsius,
                    ),
                    cols,
                ),
            );
            row += 1;
            fb.put_row(
                row,
                &box_line(
                    &format!(
                        " Link:  SSID=\"{}\"  BSSID={}  Ch={} ({}MHz)  Signal=[{}] {} dBm ({}%)  TX/RX={}/{}",
                        if st.ssid_len > 0 { st.ssid_str() } else { "-" },
                        fmt_mac(st.bssid),
                        st.channel,
                        st.width_mhz,
                        sig_bar,
                        st.rssi_dbm,
                        qual,
                        st.tx_frames,
                        st.rx_frames,
                    ),
                    cols,
                ),
            );
            row += 1;
        }
    } else {
        fb.put_row(row, &box_line(" wlan-service capability unavailable", cols));
        row += 1;
    }
    fb.put_row(row, &box_bottom(cols));
    row += 1;

    let footer_row = rows;
    let table_bottom = footer_row.saturating_sub(1);
    fb.put_row(
        row,
        &box_top(
            &format!("Discovered 802.11 Networks ({} BSS)", app.scan.len()),
            cols,
        ),
    );
    row += 1;
    fb.put_row(
        row,
        &box_line(
            &format!(
                "   {:<24} {:<19} {:<6} {:<4} {:<7} {:<10} {:<12}",
                "SSID", "BSSID", "BAND", "CH", "WIDTH", "RSSI", "SECURITY"
            ),
            cols,
        ),
    );
    row += 1;

    let avail_rows = table_bottom.saturating_sub(row);
    for idx in 0..avail_rows {
        let r = row + idx;
        if hw_absent && idx == 1 {
            fb.put_row(
                r,
                &box_line(
                    &format!(
                        "   {}No physical Wi-Fi adapter detected on PCIe bus (expected Realtek RTL8821CE 10ec:c821).{}",
                        fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
                        ansi::RESET,
                    ),
                    cols,
                ),
            );
        } else if let Some(bss) = app.scan.get(idx) {
            let line = format!(
                " {} {:<24} {:<19} {:<6} {:<4} {:<5}M  {:>4} dBm   {:<12}",
                if idx == app.selected { ">" } else { " " },
                tui::fit(bss.ssid_str(), 24),
                fmt_mac(bss.bssid),
                if bss.is_5ghz() { "5GHz" } else { "2.4G" },
                bss.channel,
                bss.width_mhz,
                bss.rssi_dbm,
                bss.security.as_str(),
            );
            if idx == app.selected {
                let hi = tui::fit_with_bg(
                    &format!("{}{}{}", fg_rgb(255, 255, 255), ansi::BOLD, line),
                    cols.saturating_sub(2),
                    BG_SELECT,
                );
                let b = fg_rgb(FG_BORDER.0, FG_BORDER.1, FG_BORDER.2);
                fb.put_row(r, &format!("{b}│{}{hi}{b}│{}", ansi::RESET, ansi::RESET));
            } else {
                fb.put_row(r, &box_line(&line, cols));
            }
        } else {
            fb.put_row(r, &box_line("", cols));
        }
    }
    fb.put_row(table_bottom, &box_bottom(cols));

    let footer = if app.typing_psk {
        let stars = "*".repeat(app.psk_buf.len());
        format!(
            " {}[WPA2 PASSPHRASE]{} {}{}   (Enter=connect, Esc=cancel)",
            fg_rgb(FG_AMBER.0, FG_AMBER.1, FG_AMBER.2),
            ansi::RESET,
            fg_rgb(FG_TEXT.0, FG_TEXT.1, FG_TEXT.2),
            stars
        )
    } else {
        String::from(
            " [q] quit   [j/k/Up/Down] select   [Enter/c] connect   [d] disconnect   [s] scan   [r] regdomain   [m] MAC privacy",
        )
    };
    fb.put_bar_row(footer_row, BG_FOOTER, &footer);
    let _ = bg_rgb(0, 0, 0);
}

fn run_tui(max_frames: Option<u64>) -> i32 {
    let scripted_single_shot = max_frames.is_some();
    let mut screen = tui::Screen::new(io::stdout());
    if !scripted_single_shot {
        let _ = screen.enter_fullscreen();
    } else {
        let _ = screen.hide_cursor();
    }
    let mut app = WlanTui::new();

    let mut frames = 0u64;
    loop {
        let (cols, rows) = tui::viewport_size();
        let mut fb = FrameBuffer::new(cols, rows);
        render_tui_frame(&mut fb, &app);
        let _ = fb.flush_to(screen.out());
        frames += 1;
        if max_frames.is_some_and(|lim| frames >= lim) {
            break;
        }
        match tui::read_key_timeout(Duration::from_millis(500)) {
            Some(key) => {
                if app.typing_psk {
                    match key {
                        Key::Escape => {
                            app.typing_psk = false;
                            app.psk_buf.clear();
                        }
                        Key::Backspace => {
                            let _ = app.psk_buf.pop();
                        }
                        Key::Enter => {
                            app.typing_psk = false;
                            if let Some(bss) = app.scan.get(app.selected).copied() {
                                let psk = app.psk_buf.clone();
                                app.psk_buf.clear();
                                match net::wlan_connect(bss.ssid_str(), &psk) {
                                    Ok(()) => {
                                        app.banner_msg =
                                            format!("Connected to '{}' (WPA2-CCMP)", bss.ssid_str())
                                    }
                                    Err(e) => app.banner_msg = format!("Connect failed: {e}"),
                                }
                                app.refresh(false);
                            }
                        }
                        Key::Char(ch) if (0x20..=0x7e).contains(&ch) && app.psk_buf.len() < 63 => {
                            app.psk_buf.push(char::from(ch));
                        }
                        _ => {}
                    }
                } else {
                    match key {
                        Key::Char(b'q') | Key::Char(b'Q') | Key::Escape | Key::Ctrl(3) => break,
                        Key::Up | Key::Char(b'k') => {
                            app.selected = app.selected.saturating_sub(1);
                        }
                        Key::Down | Key::Char(b'j') => {
                            if app.selected + 1 < app.scan.len() {
                                app.selected += 1;
                            }
                        }
                        Key::Char(b's') => {
                            app.refresh(true);
                            if !app
                                .status
                                .as_ref()
                                .is_some_and(|st| st.state == WlanStateCode::HardwareAbsent)
                            {
                                app.banner_msg =
                                    format!("Scan complete: {} BSS found", app.scan.len());
                            }
                        }
                        Key::Char(b'd') => match net::wlan_disconnect() {
                            Ok(()) => {
                                app.refresh(false);
                                app.banner_msg = String::from("Disconnected from BSS");
                            }
                            Err(e) => {
                                app.banner_msg =
                                    format!("Disconnect failed: {}", describe_wlan_err(e));
                            }
                        },
                        Key::Char(b'r') => {
                            if let Some(st) = app.status {
                                let nxt = next_reg_domain(st.reg_domain);
                                let _ = net::wlan_set_reg_domain(nxt);
                                app.refresh(true);
                                app.banner_msg = format!("Regulatory domain -> {}", nxt.as_str());
                            }
                        }
                        Key::Char(b'm') => {
                            if let Some(st) = app.status {
                                let nxt = if st.mac_policy == MacPolicyMode::Factory {
                                    MacPolicyMode::Random
                                } else {
                                    MacPolicyMode::Factory
                                };
                                let _ = net::wlan_set_mac_policy(nxt, None);
                                app.refresh(false);
                                app.banner_msg = format!("MAC policy -> {}", nxt.as_str());
                            }
                        }
                        Key::Enter | Key::Char(b'c') => {
                            if let Some(bss) = app.scan.get(app.selected).copied() {
                                if bss.security == WlanSecurity::Open {
                                    match net::wlan_connect(bss.ssid_str(), "") {
                                        Ok(()) => {
                                            app.banner_msg =
                                                format!("Connected to '{}'", bss.ssid_str())
                                        }
                                        Err(e) => app.banner_msg = format!("Connect failed: {e}"),
                                    }
                                    app.refresh(false);
                                } else {
                                    app.typing_psk = true;
                                    app.psk_buf.clear();
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            None => app.refresh(false),
        }
    }
    if !scripted_single_shot {
        let _ = screen.leave_fullscreen();
    } else {
        let _ = screen.show_cursor();
    }
    0
}

fn usage() {
    cu::outln("usage: wlanctl [tui|status|scan|connect|disconnect|profiles|regdomain|mac|ap]");
    cu::outln("  (no args) | tui [-n N]                launch 168x50 interactive Wi-Fi Studio TUI");
    cu::outln("  status                                show rtw88 firmware, radio, and WPA2 state");
    cu::outln("  scan                                  perform active 2.4/5 GHz 802.11 scan");
    cu::outln(
        "  connect <ssid> [passphrase]           authenticate, associate, and run 4-way EAPOL",
    );
    cu::outln("  disconnect                            deauthenticate and wipe PTK/GTK keys");
    cu::outln("  profiles                              list non-secret saved PMK fingerprints");
    cu::outln("  regdomain <WORLD|RU|US|EU|JP|UNLOCKED> set regulatory channel policy");
    cu::outln("  mac <factory|random>                  set MAC privacy policy");
    cu::outln("  ap start <ssid> <passphrase> [ch]     start WPA2-CCMP SoftAP");
    cu::outln("  ap stop                               stop SoftAP");
}

fn run() -> i32 {
    let args = cu::collect_args();
    if args.is_empty() {
        return run_tui(None);
    }
    match args[0].as_str() {
        "tui" => {
            let max_f = if args.get(1).map(String::as_str) == Some("-n") {
                args.get(2).and_then(|s| s.parse::<u64>().ok())
            } else {
                None
            };
            run_tui(max_f)
        }
        "-n" => {
            let max_f = args.get(1).and_then(|s| s.parse::<u64>().ok()).or(Some(1));
            run_tui(max_f)
        }
        "status" => cmd_status(),
        "scan" => cmd_scan(),
        "connect" => {
            let Some(ssid) = args.get(1) else {
                usage();
                return 2;
            };
            let psk = args.get(2).map(String::as_str).unwrap_or("");
            match net::wlan_connect(ssid, psk) {
                Ok(()) => {
                    cu::outln(&format!("wlanctl: connected to '{ssid}'"));
                    cmd_status()
                }
                Err(e) => {
                    cu::errln(&format!(
                        "wlanctl: connect to '{ssid}' failed: {}",
                        describe_wlan_err(e)
                    ));
                    1
                }
            }
        }
        "disconnect" => match net::wlan_disconnect() {
            Ok(()) => {
                cu::outln("wlanctl: disconnected");
                0
            }
            Err(e) => {
                cu::errln(&format!(
                    "wlanctl: disconnect failed: {}",
                    describe_wlan_err(e)
                ));
                1
            }
        },
        "profiles" => cmd_profiles(),
        "regdomain" => {
            let Some(d_str) = args.get(1) else {
                usage();
                return 2;
            };
            let Some(dom) = parse_reg_domain(d_str) else {
                cu::errln("wlanctl: unknown regdomain (use WORLD, RU, US, EU, JP, UNLOCKED)");
                return 2;
            };
            match net::wlan_set_reg_domain(dom) {
                Ok(()) => {
                    cu::outln(&format!(
                        "wlanctl: regulatory domain set to {}",
                        dom.as_str()
                    ));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("wlanctl: regdomain failed: {e}"));
                    1
                }
            }
        }
        "mac" => {
            let pol = match args.get(1).map(String::as_str) {
                Some("factory") => MacPolicyMode::Factory,
                Some("random") => MacPolicyMode::Random,
                _ => {
                    usage();
                    return 2;
                }
            };
            match net::wlan_set_mac_policy(pol, None) {
                Ok(()) => {
                    cu::outln(&format!("wlanctl: MAC policy set to {}", pol.as_str()));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("wlanctl: mac policy failed: {e}"));
                    1
                }
            }
        }
        "ap" => match args.get(1).map(String::as_str) {
            Some("start") => {
                let (Some(ssid), Some(psk)) = (args.get(2), args.get(3)) else {
                    usage();
                    return 2;
                };
                let ch = args.get(4).and_then(|s| s.parse::<u8>().ok()).unwrap_or(6);
                match net::wlan_ap_start(ssid, psk, ch) {
                    Ok(()) => {
                        cu::outln(&format!(
                            "wlanctl: SoftAP '{}' active on channel {} (WPA2-CCMP)",
                            ssid, ch
                        ));
                        0
                    }
                    Err(e) => {
                        cu::errln(&format!(
                            "wlanctl: ap start failed: {}",
                            describe_wlan_err(e)
                        ));
                        1
                    }
                }
            }
            Some("stop") => match net::wlan_ap_stop() {
                Ok(()) => {
                    cu::outln("wlanctl: SoftAP stopped");
                    0
                }
                Err(e) => {
                    cu::errln(&format!(
                        "wlanctl: ap stop failed: {}",
                        describe_wlan_err(e)
                    ));
                    1
                }
            },
            _ => {
                usage();
                2
            }
        },
        "-h" | "--help" | "help" => {
            usage();
            0
        }
        other => {
            cu::errln(&format!("wlanctl: unknown command '{other}'"));
            usage();
            2
        }
    }
}
