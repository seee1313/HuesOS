//! `/bin/netctl.elf` — inspect and configure `/services/net.elf` (`HNET`).
//!
//! Commands:
//! - `netctl [status]`
//! - `netctl dhcp [on|off]`
//! - `netctl static <ip/prefix> <gateway>`
//! - `netctl dns <ipv4>`
//! - `netctl resolve <hostname>`

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;

use huesos_abi::net::iface_id;
use huesos_coreutils as cu;
use huesos_std::net;
use huesos_std::tui;

cu::coreutil_entry!(run);

fn usage() {
    cu::outln("usage: netctl [status|dhcp|static|dns|resolve]");
    cu::outln("  status                       show interfaces, addresses, routes, and counters");
    cu::outln("  dhcp [on|off]                renew or toggle DHCPv4 on virtio0");
    cu::outln("  static <ip/prefix> <gateway> configure static IPv4 CIDR on virtio0");
    cu::outln("  dns <ipv4>                   override upstream DNS resolver");
    cu::outln("  resolve <hostname>           resolve an IPv4 A record via net-service");
}

fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn cmd_status() -> i32 {
    let snap = match net::status() {
        Ok(s) => s,
        Err(err) => {
            cu::errln(&format!("netctl: status failed: {err}"));
            return 1;
        }
    };
    let uplink_name = snap
        .ifaces
        .get(usize::from(snap.active_uplink))
        .map(|i| i.name_str())
        .unwrap_or("lo");
    cu::outln(&format!(
        "net-service: uplink={}  dns={}  tcp_sockets={}  udp_sockets={}  pkt_pool={}/{}",
        uplink_name,
        fmt_ip(snap.dns_server),
        snap.active_tcp_sockets,
        snap.active_udp_sockets,
        snap.free_packet_buffers,
        snap.total_packet_buffers
    ));

    let mut tbl = tui::Table::new(
        &[
            "IFACE",
            "STATE",
            "MODE",
            "IPV4/CIDR",
            "GATEWAY",
            "MAC",
            "RX",
            "TX",
        ],
        &[8, 8, 7, 18, 15, 17, 12, 12],
    );
    for iface in &snap.ifaces {
        if !iface.present && iface.name_str() != "virtio0" {
            continue;
        }
        let st = if !iface.present {
            "absent"
        } else if iface.link_up {
            "up"
        } else {
            "down"
        };
        let mode = if iface.name_str() == "lo" {
            "loop"
        } else if iface.dhcp_enabled {
            "dhcp"
        } else {
            "static"
        };
        tbl.row(&[
            String::from(iface.name_str()),
            String::from(st),
            String::from(mode),
            format!("{}/{}", fmt_ip(iface.ipv4), iface.prefix_len),
            fmt_ip(iface.gateway),
            fmt_mac(iface.mac),
            format!("{}p/{}B", iface.rx_packets, iface.rx_bytes),
            format!("{}p/{}B", iface.tx_packets, iface.tx_bytes),
        ]);
    }
    cu::outln(&tbl.header_line());
    cu::outln(&tbl.separator());
    for line in tbl.lines() {
        cu::outln(&line);
    }
    0
}

fn run() -> i32 {
    let args = cu::collect_args();
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => cmd_status(),
        "dhcp" => {
            let enable = args.get(1).map(String::as_str).unwrap_or("on") != "off";
            match net::set_dhcp(iface_id::VIRTIO0, enable) {
                Ok(()) => {
                    cu::outln(if enable {
                        "netctl: DHCPv4 discovery started on virtio0"
                    } else {
                        "netctl: DHCPv4 disabled on virtio0"
                    });
                    0
                }
                Err(e) => {
                    cu::errln(&format!("netctl: dhcp failed: {e}"));
                    1
                }
            }
        }
        "static" => {
            let (Some(cidr), Some(gw_str)) = (args.get(1), args.get(2)) else {
                usage();
                return 2;
            };
            let (ip_s, pfx_s) = cidr.split_once('/').unwrap_or((cidr.as_str(), "24"));
            let (Some(ip), Ok(pfx), Some(gw)) = (
                net::parse_ipv4(ip_s),
                pfx_s.parse::<u8>(),
                net::parse_ipv4(gw_str),
            ) else {
                cu::errln("netctl: invalid static <ip/prefix> <gateway>");
                return 2;
            };
            match net::set_static_ip(iface_id::VIRTIO0, ip, pfx.min(32), gw) {
                Ok(()) => {
                    cu::outln(&format!(
                        "netctl: configured virtio0 {}/{} gw {}",
                        fmt_ip(ip),
                        pfx.min(32),
                        fmt_ip(gw)
                    ));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("netctl: static ip failed: {e}"));
                    1
                }
            }
        }
        "dns" => {
            let Some(ip_str) = args.get(1) else {
                usage();
                return 2;
            };
            let Some(ip) = net::parse_ipv4(ip_str) else {
                cu::errln("netctl: invalid IPv4 address");
                return 2;
            };
            match net::set_dns(ip) {
                Ok(()) => {
                    cu::outln(&format!("netctl: upstream DNS set to {}", fmt_ip(ip)));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("netctl: set dns failed: {e}"));
                    1
                }
            }
        }
        "resolve" => {
            let Some(host) = args.get(1) else {
                usage();
                return 2;
            };
            match net::resolve_host(host) {
                Ok(ip) => {
                    cu::outln(&format!("{} -> {}", host, fmt_ip(ip)));
                    0
                }
                Err(e) => {
                    cu::errln(&format!("netctl: resolve '{}' failed: {}", host, e));
                    1
                }
            }
        }
        "-h" | "--help" | "help" => {
            usage();
            0
        }
        other => {
            cu::errln(&format!("netctl: unknown subcommand '{other}'"));
            usage();
            2
        }
    }
}
