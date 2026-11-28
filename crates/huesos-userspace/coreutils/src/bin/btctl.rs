//! `/bin/btctl.elf` — Plan 9 `/net/btl` Bluetooth Classic Controller, SSP
//! Pairing, SDP Service Discovery, `btsnoop` Capture, and `RTL8821CE` PTA Coex CLI.

#![no_std]
#![no_main]
#![allow(
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::collapsible_if
)]

extern crate alloc;

use alloc::format;

use huesos_coreutils as cu;
use huesos_std::fs;
use huesos_std::net;

cu::coreutil_entry!(run);

fn print_usage() {
    cu::outln(
        "usage: btctl [status|power <on|off|virtual>|scan|peers|pair <addr>|unpair <addr>|keys|connect <addr>|disconnect <addr>|sdp <addr> [uuid16]|snoop [path]|coex <idle|scan|a2dp|page>]",
    );
}

fn cmd_status() -> i32 {
    match net::btl_status() {
        Ok(st) => {
            let coex_name = match st.coex_profile {
                0 => "idle",
                1 => "inquiry-scan",
                2 => "a2dp-streaming",
                3 => "page-connect",
                _ => "custom",
            };
            cu::outln(&format!(
                "btl0: transport={} state={} fw_loaded={} fw_ver=0x{:08x} usb={:04x}:{:04x}",
                st.transport.as_str(),
                if st.powered { "powered" } else { "down" },
                st.firmware_loaded,
                st.fw_version,
                st.usb_vid,
                st.usb_pid,
            ));
            cu::outln(&format!(
                "  bd_addr={} acl_credits={}/{} mtu={} coex={}({})",
                net::format_bd_addr(&st.local_bd_addr),
                st.acl_max_slots.saturating_sub(st.acl_in_flight),
                st.acl_max_slots,
                st.acl_mtu,
                st.coex_profile,
                coex_name,
            ));
            cu::outln(&format!(
                "  peers={} saved_keys={} l2cap_open={} tx_pkts={} rx_pkts={} snoop_bytes={}",
                st.peer_count,
                st.saved_keys,
                st.open_l2cap_channels,
                st.tx_packets,
                st.rx_packets,
                st.snoop_bytes,
            ));
            0
        }
        Err(e) => {
            cu::errln(&format!("btctl: status failed: {e}"));
            1
        }
    }
}

fn print_peers(peers: &[huesos_abi::btl::BtlPeerInfo]) {
    cu::outln("BD_ADDR            RSSI   PAIRED  CONN   A2DP   NAME");
    for p in peers {
        cu::outln(&format!(
            "{}  {:>4}   {:<6}  {:<5}  {:<5}  {}",
            net::format_bd_addr(&p.bd_addr),
            p.rssi_dbm,
            p.is_paired(),
            p.is_connected(),
            p.is_audio_sink(),
            p.name_str(),
        ));
    }
}

fn parse_uuid16(raw: &str) -> Option<u16> {
    let trimmed = raw
        .trim()
        .strip_prefix("0x")
        .or_else(|| raw.trim().strip_prefix("0X"))
        .unwrap_or(raw.trim());
    u16::from_str_radix(trimmed, 16).ok()
}

fn run() -> i32 {
    let args = cu::collect_args();
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return cmd_status();
    };

    match sub {
        "--help" | "-h" | "help" => {
            print_usage();
            0
        }
        "status" => cmd_status(),
        "power" => {
            let mode = match args.get(1).map(|s| s.as_str()) {
                Some("off" | "0") => 0u8,
                Some("on" | "1") => 1u8,
                Some("virtual" | "airbuds" | "2") => 2u8,
                _ => {
                    cu::errln("btctl: usage: btctl power <on|off|virtual>");
                    return 1;
                }
            };
            match net::btl_set_power(mode) {
                Ok(()) => {
                    let label = match mode {
                        0 => "off",
                        1 => "on",
                        _ => "virtual (HuesOS AirBuds Pro)",
                    };
                    cu::outln(&format!("btctl: power={label}"));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("btctl: power failed: {e}"));
                    1
                }
            }
        }
        "scan" => match net::btl_scan() {
            Ok(peers) => {
                print_peers(&peers);
                0
            }
            Err(e) => {
                cu::errln(&format!("btctl: scan failed: {e}"));
                1
            }
        },
        "peers" => match net::btl_list_peers() {
            Ok(peers) => {
                print_peers(&peers);
                0
            }
            Err(e) => {
                cu::errln(&format!("btctl: peers failed: {e}"));
                1
            }
        },
        "pair" => {
            let Some(addr) = args.get(1).and_then(|s| net::parse_bd_addr(s)) else {
                cu::errln("btctl: usage: btctl pair <AA:BB:CC:DD:EE:FF>");
                return 1;
            };
            match net::btl_pair(addr) {
                Ok(()) => {
                    cu::outln(&format!(
                        "btctl: paired with {} (SSP Link Key stored in HxFS)",
                        net::format_bd_addr(&addr)
                    ));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("btctl: pair failed: {e}"));
                    1
                }
            }
        }
        "unpair" | "delete-key" => {
            let Some(addr) = args.get(1).and_then(|s| net::parse_bd_addr(s)) else {
                cu::errln("btctl: usage: btctl unpair <AA:BB:CC:DD:EE:FF>");
                return 1;
            };
            match net::btl_delete_key(addr) {
                Ok(()) => {
                    cu::outln(&format!(
                        "btctl: deleted Link Key for {}",
                        net::format_bd_addr(&addr)
                    ));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("btctl: unpair failed: {e}"));
                    1
                }
            }
        }
        "keys" => match net::btl_list_keys() {
            Ok(keys) => {
                cu::outln("BD_ADDR            TYPE  SHA256_FP");
                for k in &keys {
                    cu::outln(&format!(
                        "{}  0x{:02x}  {:02x}{:02x}{:02x}{:02x}",
                        net::format_bd_addr(&k.bd_addr),
                        k.key_type,
                        k.key_fingerprint[0],
                        k.key_fingerprint[1],
                        k.key_fingerprint[2],
                        k.key_fingerprint[3],
                    ));
                }
                0
            }
            Err(e) => {
                cu::errln(&format!("btctl: keys failed: {e}"));
                1
            }
        },
        "connect" => {
            let Some(addr) = args.get(1).and_then(|s| net::parse_bd_addr(s)) else {
                cu::errln("btctl: usage: btctl connect <AA:BB:CC:DD:EE:FF>");
                return 1;
            };
            match net::btl_connect_acl(addr) {
                Ok(handle) => {
                    cu::outln(&format!(
                        "btctl: ACL connected to {} (handle=0x{:04x})",
                        net::format_bd_addr(&addr),
                        handle
                    ));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("btctl: connect failed: {e}"));
                    1
                }
            }
        }
        "disconnect" => {
            let Some(addr) = args.get(1).and_then(|s| net::parse_bd_addr(s)) else {
                cu::errln("btctl: usage: btctl disconnect <AA:BB:CC:DD:EE:FF>");
                return 1;
            };
            match net::btl_disconnect_acl(addr) {
                Ok(()) => {
                    cu::outln(&format!(
                        "btctl: disconnected {}",
                        net::format_bd_addr(&addr)
                    ));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("btctl: disconnect failed: {e}"));
                    1
                }
            }
        }
        "sdp" => {
            let Some(addr) = args.get(1).and_then(|s| net::parse_bd_addr(s)) else {
                cu::errln("btctl: usage: btctl sdp <AA:BB:CC:DD:EE:FF> [uuid16_hex]");
                return 1;
            };
            let uuid16 = match args.get(2) {
                Some(raw) => match parse_uuid16(raw) {
                    Some(u) => u,
                    None => {
                        cu::errln("btctl: invalid hex UUID16 (example: 0x110B)");
                        return 1;
                    }
                },
                None => 0x110B,
            };
            match net::btl_sdp_query(addr, uuid16) {
                Ok(res) => {
                    cu::outln(&format!(
                        "btctl: sdp peer={} uuid=0x{:04x} found={} psm=0x{:04x} profile_ver=0x{:04x} attr_bytes={}",
                        net::format_bd_addr(&addr),
                        uuid16,
                        res.found,
                        res.l2cap_psm,
                        res.profile_version,
                        res.raw_attrs.len()
                    ));
                    if res.found {
                        0
                    } else {
                        1
                    }
                }
                Err(e) => {
                    cu::errln(&format!("btctl: sdp query failed: {e}"));
                    1
                }
            }
        }
        "snoop" => match net::btl_read_snoop() {
            Ok(bytes) => {
                let valid_magic = bytes.len() >= 16 && &bytes[0..8] == b"btsnoop\0";
                if let Some(out_path) = args.get(1) {
                    if let Err(e) = fs::write(out_path, &bytes) {
                        cu::errln(&format!("btctl: write '{out_path}' failed: {e}"));
                        return 1;
                    }
                    cu::outln(&format!(
                        "btctl: wrote {} bytes of btsnoop v1 capture (magic_ok={}) to {}",
                        bytes.len(),
                        valid_magic,
                        out_path
                    ));
                } else {
                    cu::outln(&format!(
                        "btctl: btsnoop capture bytes={} magic_ok={} datalink=HCI_H4(1002)",
                        bytes.len(),
                        valid_magic
                    ));
                }
                0
            }
            Err(e) => {
                cu::errln(&format!("btctl: snoop read failed: {e}"));
                1
            }
        },
        "coex" => {
            let profile = match args.get(1).map(|s| s.as_str()) {
                Some("idle" | "0") => 0u8,
                Some("scan" | "1") => 1u8,
                Some("a2dp" | "2") => 2u8,
                Some("page" | "3") => 3u8,
                _ => {
                    cu::errln("btctl: usage: btctl coex <idle|scan|a2dp|page>");
                    return 1;
                }
            };
            match net::btl_set_coex_hint(profile) {
                Ok(()) => {
                    cu::outln(&format!("btctl: PTA coexistence profile set to {profile}"));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("btctl: coex failed: {e}"));
                    1
                }
            }
        }
        other => {
            cu::errln(&format!("btctl: unknown command '{other}'"));
            print_usage();
            1
        }
    }
}
