//! `/bin/ping.elf` — ICMPv4 Echo latency & reachability probe over `HNET`.
//!
//! Usage: `ping [-c <count>] [-s <bytes>] [-W <timeout_ms>] <host|ipv4>`

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;

use huesos_coreutils as cu;
use huesos_std::net;
use huesos_std::thread;
use huesos_std::time::Duration;
use huesos_std::ErrorKind;

cu::coreutil_entry!(run);

fn usage() {
    cu::outln("usage: ping [-c count] [-s payload_bytes] [-W timeout_ms] <host|ipv4>");
}

fn run() -> i32 {
    let args = cu::collect_args();
    let mut count: u16 = 4;
    let mut payload_len: u16 = 56;
    let mut timeout_ms: u32 = 2_000;
    let mut target: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                usage();
                return 0;
            }
            "-c" => {
                i += 1;
                let Some(v) = args.get(i).and_then(|s| s.parse::<u16>().ok()) else {
                    cu::errln("ping: invalid -c count");
                    return 2;
                };
                count = v.clamp(1, 100);
            }
            "-s" => {
                i += 1;
                let Some(v) = args.get(i).and_then(|s| s.parse::<u16>().ok()) else {
                    cu::errln("ping: invalid -s size");
                    return 2;
                };
                payload_len = v.clamp(8, 1400);
            }
            "-W" => {
                i += 1;
                let Some(v) = args.get(i).and_then(|s| s.parse::<u32>().ok()) else {
                    cu::errln("ping: invalid -W timeout_ms");
                    return 2;
                };
                timeout_ms = v.clamp(100, 10_000);
            }
            s if s.starts_with('-') => {
                cu::errln(&format!("ping: unknown option '{s}'"));
                return 2;
            }
            s => {
                target = Some(String::from(s));
            }
        }
        i += 1;
    }

    let Some(host) = target else {
        usage();
        return 2;
    };

    let ip = match net::resolve_host(&host) {
        Ok(ip) => ip,
        Err(err) => {
            cu::errln(&format!("ping: {}: {}", host, err));
            return 1;
        }
    };

    cu::outln(&format!(
        "PING {} ({}.{}.{}.{}): {} data bytes",
        host, ip[0], ip[1], ip[2], ip[3], payload_len
    ));

    let ident = 0x4850u16 ^ (u16::from(ip[3]) << 4);
    let mut transmitted = 0u32;
    let mut received = 0u32;
    let mut min_us = u32::MAX;
    let mut max_us = 0u32;
    let mut sum_us = 0u64;

    for seq in 1..=count {
        transmitted += 1;
        match net::ping(ip, ident, seq, timeout_ms, payload_len) {
            Ok(rep) => {
                received += 1;
                min_us = min_us.min(rep.rtt_us);
                max_us = max_us.max(rep.rtt_us);
                sum_us += u64::from(rep.rtt_us);
                cu::outln(&format!(
                    "{} bytes from {}.{}.{}.{}: icmp_seq={} ttl={} time={}.{:02} ms",
                    rep.payload_bytes,
                    rep.responder_ipv4[0],
                    rep.responder_ipv4[1],
                    rep.responder_ipv4[2],
                    rep.responder_ipv4[3],
                    rep.seq,
                    rep.ttl,
                    rep.rtt_us / 1_000,
                    (rep.rtt_us % 1_000) / 10,
                ));
            }
            Err(err) => match err.kind() {
                ErrorKind::NetworkUnreachable => {
                    cu::errln(
                        "ping: sendto: network is unreachable (no active link or IPv4 lease)",
                    );
                    break;
                }
                ErrorKind::HostUnreachable => {
                    cu::outln(&format!(
                        "From local icmp_seq={}: Destination Host Unreachable",
                        seq
                    ));
                }
                ErrorKind::TimedOut => {
                    cu::outln(&format!("Request timeout for icmp_seq {}", seq));
                }
                _ => {
                    cu::outln(&format!("ping: icmp_seq={}: {}", seq, err));
                }
            },
        }
        if seq < count {
            thread::sleep(Duration::from_millis(150));
        }
    }

    let loss_pct = ((transmitted - received) * 100) / transmitted.max(1);
    cu::outln(&format!("\n--- {} ping statistics ---", host));
    cu::outln(&format!(
        "{} packets transmitted, {} packets received, {}% packet loss",
        transmitted, received, loss_pct
    ));
    if received > 0 {
        let avg_us = (sum_us / u64::from(received)) as u32;
        cu::outln(&format!(
            "round-trip min/avg/max = {}.{:02}/{}.{:02}/{}.{:02} ms",
            min_us / 1_000,
            (min_us % 1_000) / 10,
            avg_us / 1_000,
            (avg_us % 1_000) / 10,
            max_us / 1_000,
            (max_us % 1_000) / 10,
        ));
        0
    } else {
        1
    }
}
