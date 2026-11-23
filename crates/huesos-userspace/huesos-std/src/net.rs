//! Capability-first IPv4 networking (`HNET`) and IEEE 802.11 WLAN (`HWLN`)
//! client APIs for HuesOS user-space programs.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

use huesos_abi::auxv::caps_mask;
use huesos_abi::net::{
    self, decode_dns_reply, decode_ping_reply, encode_dns_request, encode_ping_request,
    encode_simple_request, NetOp, NetStatus, NetStatusSnapshot, PingResult,
};
use huesos_abi::wlan::{
    self, MacPolicyMode, RegDomainCode, WlanBssInfo, WlanOp, WlanProfileSummary, WlanStatus,
    WlanStatusSnapshot,
};
use libcanvas::stdio::{take_cap_handle, CapKind};
use libcanvas::{Channel, ErrorCode};

use crate::error::{Error, ErrorKind, Result};
use crate::io::{Read, Write};
use crate::os::huesos::caps_mask as current_caps_mask;

static NET_SERVICE_CH: Mutex<Option<Channel>> = Mutex::new(None);
static WLAN_SERVICE_CH: Mutex<Option<Channel>> = Mutex::new(None);

fn map_net_status(st: NetStatus) -> Error {
    let kind = match st {
        NetStatus::Ok => ErrorKind::Other,
        NetStatus::InvalidRequest => ErrorKind::InvalidInput,
        NetStatus::AccessDenied => ErrorKind::AccessDenied,
        NetStatus::Unreachable => ErrorKind::Io,
        NetStatus::TimedOut => ErrorKind::TimedOut,
        NetStatus::ConnectionRefused => ErrorKind::PeerClosed,
        NetStatus::NameNotFound => ErrorKind::NotFound,
        NetStatus::Busy => ErrorKind::Busy,
    };
    Error::new(kind)
}

fn map_wlan_status(st: WlanStatus) -> Error {
    let kind = match st {
        WlanStatus::Ok => ErrorKind::Other,
        WlanStatus::InvalidRequest | WlanStatus::InvalidPassphrase => ErrorKind::InvalidInput,
        WlanStatus::AccessDenied | WlanStatus::RegulatoryBlocked => ErrorKind::AccessDenied,
        WlanStatus::HardwareAbsent | WlanStatus::FirmwareUnavailable => ErrorKind::Unsupported,
        WlanStatus::AuthFailed => ErrorKind::Io,
    };
    Error::new(kind)
}

fn check_net_cap(write_needed: bool) -> Result<()> {
    let mask = current_caps_mask();
    if (mask & caps_mask::NET_RO) == 0 {
        return Err(Error::capability());
    }
    if write_needed && (mask & caps_mask::NET_RW) == 0 {
        return Err(Error::capability());
    }
    Ok(())
}

fn check_wlan_cap(admin_needed: bool) -> Result<()> {
    let mask = current_caps_mask();
    if (mask & caps_mask::WLAN_RO) == 0 {
        return Err(Error::capability());
    }
    if admin_needed && (mask & caps_mask::WLAN_ADMIN) == 0 {
        return Err(Error::capability());
    }
    Ok(())
}

fn with_net_channel<F, T>(write_needed: bool, f: F) -> Result<T>
where
    F: FnOnce(&Channel) -> Result<T>,
{
    check_net_cap(write_needed)?;
    let mut guard = NET_SERVICE_CH.lock();
    if guard.is_none() {
        if let Some(h) = take_cap_handle(CapKind::NetService) {
            *guard = Some(Channel::from_handle(h));
        }
    }
    let Some(ch) = guard.as_ref() else {
        return Err(Error::capability());
    };
    f(ch)
}

fn with_wlan_channel<F, T>(admin_needed: bool, f: F) -> Result<T>
where
    F: FnOnce(&Channel) -> Result<T>,
{
    check_wlan_cap(admin_needed)?;
    let mut guard = WLAN_SERVICE_CH.lock();
    if guard.is_none() {
        if let Some(h) = take_cap_handle(CapKind::WlanService) {
            *guard = Some(Channel::from_handle(h));
        }
    }
    let Some(ch) = guard.as_ref() else {
        return Err(Error::capability());
    };
    f(ch)
}

/// Parse an ASCII dotted-quad IPv4 literal (`"10.0.2.2"`).
pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut idx = 0usize;
    for part in text.trim().split('.') {
        if idx >= 4 {
            return None;
        }
        out[idx] = part.parse::<u8>().ok()?;
        idx += 1;
    }
    if idx == 4 {
        Some(out)
    } else {
        None
    }
}

/// Query `/services/net.elf` interface status and packet/byte counters.
pub fn status() -> Result<NetStatusSnapshot> {
    with_net_channel(false, |ch| {
        let req = encode_simple_request(NetOp::Status);
        ch.write(&req).map_err(Error::from_code)?;
        let mut buf = [0u8; 320];
        let n = ch
            .read_into_timeout(&mut buf, 200)
            .map_err(Error::from_code)?;
        NetStatusSnapshot::decode_reply(&buf[..n]).map_err(map_net_status)
    })
}

/// Resolve a hostname or dotted-quad IPv4 address via `net-service`.
pub fn resolve_host(hostname: &str) -> Result<[u8; 4]> {
    if let Some(ip) = parse_ipv4(hostname) {
        check_net_cap(false)?;
        return Ok(ip);
    }
    if hostname.eq_ignore_ascii_case("localhost") {
        check_net_cap(false)?;
        return Ok([127, 0, 0, 1]);
    }
    with_net_channel(false, |ch| {
        let mut req = [0u8; 256];
        let len = encode_dns_request(hostname, &mut req)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput))?;
        ch.write(&req[..len]).map_err(Error::from_code)?;
        let mut rep = [0u8; 64];
        let n = ch
            .read_into_timeout(&mut rep, 400)
            .map_err(Error::from_code)?;
        let (ip, _ttl) = decode_dns_reply(&rep[..n]).map_err(map_net_status)?;
        Ok(ip)
    })
}

/// Send one ICMPv4 Echo Request and wait up to `timeout_ms` for its reply.
pub fn ping(
    target_ipv4: [u8; 4],
    ident: u16,
    seq: u16,
    timeout_ms: u32,
    payload_len: u16,
) -> Result<PingResult> {
    with_net_channel(true, |ch| {
        let req = encode_ping_request(target_ipv4, ident, seq, timeout_ms, payload_len);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 64];
        let wait_ticks = u64::from(timeout_ms).div_ceil(10).max(50) + 50;
        let n = ch
            .read_into_timeout(&mut rep, wait_ticks)
            .map_err(Error::from_code)?;
        decode_ping_reply(&rep[..n]).map_err(map_net_status)
    })
}

/// Trigger or toggle DHCPv4 on interface `iface` (`net=rw` required).
pub fn set_dhcp(iface: u8, enable: bool) -> Result<()> {
    with_net_channel(true, |ch| {
        let mut req = [0u8; 10];
        net::write_header(&mut req, NetOp::SetDhcp, NetStatus::Ok);
        req[8] = iface;
        req[9] = u8::from(enable);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 300)
            .map_err(Error::from_code)?;
        let st = net::check_header(&rep[..n], NetOp::SetDhcp).map_err(map_net_status)?;
        if st == NetStatus::Ok {
            Ok(())
        } else {
            Err(map_net_status(st))
        }
    })
}

/// Configure static IPv4 CIDR + gateway on interface `iface` (`net=rw` required).
pub fn set_static_ip(iface: u8, ipv4: [u8; 4], prefix_len: u8, gateway: [u8; 4]) -> Result<()> {
    with_net_channel(true, |ch| {
        let mut req = [0u8; 18];
        net::write_header(&mut req, NetOp::SetStaticIp, NetStatus::Ok);
        req[8] = iface;
        req[9] = prefix_len;
        req[10..14].copy_from_slice(&ipv4);
        req[14..18].copy_from_slice(&gateway);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        let st = net::check_header(&rep[..n], NetOp::SetStaticIp).map_err(map_net_status)?;
        if st == NetStatus::Ok {
            Ok(())
        } else {
            Err(map_net_status(st))
        }
    })
}

/// Override the upstream DNS resolver IPv4 address (`net=rw` required).
pub fn set_dns(dns_ipv4: [u8; 4]) -> Result<()> {
    with_net_channel(true, |ch| {
        let mut req = [0u8; 12];
        net::write_header(&mut req, NetOp::SetDns, NetStatus::Ok);
        req[8..12].copy_from_slice(&dns_ipv4);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        let st = net::check_header(&rep[..n], NetOp::SetDns).map_err(map_net_status)?;
        if st == NetStatus::Ok {
            Ok(())
        } else {
            Err(map_net_status(st))
        }
    })
}

/// Read active ARP entries as `(ipv4, mac)` tuples.
pub fn query_arp() -> Result<Vec<([u8; 4], [u8; 6])>> {
    with_net_channel(false, |ch| {
        let req = encode_simple_request(NetOp::QueryArp);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 256];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        let st = net::check_header(&rep[..n], NetOp::QueryArp).map_err(map_net_status)?;
        if st != NetStatus::Ok {
            return Err(map_net_status(st));
        }
        if n < 9 {
            return Ok(Vec::new());
        }
        let count = usize::from(rep[8]);
        let mut out = Vec::with_capacity(count);
        let mut pos = 9usize;
        for _ in 0..count {
            if pos + 10 > n {
                break;
            }
            let mut ip = [0u8; 4];
            let mut mac = [0u8; 6];
            ip.copy_from_slice(&rep[pos..pos + 4]);
            mac.copy_from_slice(&rep[pos + 4..pos + 10]);
            out.push((ip, mac));
            pos += 10;
        }
        Ok(out)
    })
}

/// Connected IPv4 TCP stream backed by a dedicated per-socket IPC channel.
pub struct TcpStream {
    data_ch: Channel,
    rx_stash: VecDeque<u8>,
    read_timeout_ticks: u64,
}

impl TcpStream {
    /// Dial `remote_ipv4:remote_port` with a default 5-second timeout.
    pub fn connect(remote_ipv4: [u8; 4], remote_port: u16) -> Result<Self> {
        Self::connect_timeout(remote_ipv4, remote_port, 5_000)
    }

    /// Dial `remote_ipv4:remote_port` waiting up to `timeout_ms`.
    pub fn connect_timeout(
        remote_ipv4: [u8; 4],
        remote_port: u16,
        timeout_ms: u32,
    ) -> Result<Self> {
        let data_ch = with_net_channel(true, |ch| {
            let mut req = [0u8; 18];
            net::write_header(&mut req, NetOp::OpenTcp, NetStatus::Ok);
            req[8..12].copy_from_slice(&remote_ipv4);
            req[12..14].copy_from_slice(&remote_port.to_le_bytes());
            req[14..18].copy_from_slice(&timeout_ms.to_le_bytes());
            ch.write(&req).map_err(Error::from_code)?;

            let wait_ticks = u64::from(timeout_ms).div_ceil(10).max(50) + 50;
            let mut rep = [0u8; 32];
            let (n, handle_opt) = ch
                .read_optional_handle_timeout(&mut rep, wait_ticks)
                .map_err(Error::from_code)?;
            let st = net::check_header(&rep[..n], NetOp::OpenTcp).map_err(map_net_status)?;
            if st != NetStatus::Ok {
                return Err(map_net_status(st));
            }
            let handle = handle_opt.ok_or_else(|| Error::new(ErrorKind::Io))?;
            Ok(Channel::from_handle(handle))
        })?;
        Ok(Self {
            data_ch,
            rx_stash: VecDeque::with_capacity(2048),
            read_timeout_ticks: 500,
        })
    }

    /// Configure the per-read timeout in milliseconds.
    pub fn set_read_timeout_ms(&mut self, timeout_ms: u32) {
        self.read_timeout_ticks = u64::from(timeout_ms).div_ceil(10).max(10);
    }

    /// Write all bytes in `buf` to the TCP stream.
    pub fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = self.write(buf)?;
            if n == 0 {
                return Err(Error::new(ErrorKind::PeerClosed));
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    /// Read until clean TCP `FIN` (`EOF`), appending into `out`.
    pub fn read_to_end(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        let start = out.len();
        let mut tmp = [0u8; 2048];
        loop {
            let n = self.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        Ok(out.len() - start)
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.rx_stash.is_empty() {
            let take = buf.len().min(self.rx_stash.len());
            for slot in buf.iter_mut().take(take) {
                *slot = self.rx_stash.pop_front().unwrap_or(0);
            }
            return Ok(take);
        }
        let mut wire = [0u8; 2048];
        match self
            .data_ch
            .read_into_timeout(&mut wire, self.read_timeout_ticks)
        {
            Ok(0) | Err(ErrorCode::PeerClosed) => Ok(0),
            Ok(n) => {
                let take = buf.len().min(n);
                buf[..take].copy_from_slice(&wire[..take]);
                for &b in &wire[take..n] {
                    self.rx_stash.push_back(b);
                }
                Ok(take)
            }
            Err(code) => Err(Error::from_code(code)),
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let chunk = buf.len().min(1460);
        self.data_ch
            .write(&buf[..chunk])
            .map_err(Error::from_code)?;
        Ok(chunk)
    }
}

/// Bound IPv4 UDP socket backed by a dedicated IPC channel.
pub struct UdpSocket {
    ch: Channel,
    local_port: u16,
}

impl UdpSocket {
    /// Bind a UDP socket (`local_port = 0` chooses an ephemeral port).
    pub fn bind(local_port: u16) -> Result<Self> {
        with_net_channel(true, |net_ch| {
            let mut req = [0u8; 10];
            net::write_header(&mut req, NetOp::OpenUdp, NetStatus::Ok);
            req[8..10].copy_from_slice(&local_port.to_le_bytes());
            net_ch.write(&req).map_err(Error::from_code)?;

            let mut rep = [0u8; 16];
            let (n, handle_opt) = net_ch
                .read_optional_handle_timeout(&mut rep, 200)
                .map_err(Error::from_code)?;
            let st = net::check_header(&rep[..n], NetOp::OpenUdp).map_err(map_net_status)?;
            if st != NetStatus::Ok {
                return Err(map_net_status(st));
            }
            if n < 10 {
                return Err(Error::new(ErrorKind::Io));
            }
            let bound = u16::from_le_bytes([rep[8], rep[9]]);
            let handle = handle_opt.ok_or_else(|| Error::new(ErrorKind::Io))?;
            Ok(Self {
                ch: Channel::from_handle(handle),
                local_port: bound,
            })
        })
    }

    pub const fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Send a datagram to `dst_ipv4:dst_port`.
    pub fn send_to(&self, payload: &[u8], dst_ipv4: [u8; 4], dst_port: u16) -> Result<usize> {
        if payload.len() > 1472 {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let mut msg = alloc::vec![0u8; 6 + payload.len()];
        msg[0..4].copy_from_slice(&dst_ipv4);
        msg[4..6].copy_from_slice(&dst_port.to_le_bytes());
        msg[6..].copy_from_slice(payload);
        self.ch.write(&msg).map_err(Error::from_code)?;
        Ok(payload.len())
    }

    /// Receive a datagram, returning `(bytes_copied, src_ipv4, src_port)`.
    pub fn recv_from(&self, out: &mut [u8], timeout_ms: u32) -> Result<(usize, [u8; 4], u16)> {
        let mut msg = [0u8; 1600];
        let wait_ticks = u64::from(timeout_ms).div_ceil(10).max(10);
        let n = self
            .ch
            .read_into_timeout(&mut msg, wait_ticks)
            .map_err(Error::from_code)?;
        if n < 6 {
            return Err(Error::new(ErrorKind::Io));
        }
        let src_ip = [msg[0], msg[1], msg[2], msg[3]];
        let src_port = u16::from_le_bytes([msg[4], msg[5]]);
        let copy_len = (n - 6).min(out.len());
        out[..copy_len].copy_from_slice(&msg[6..6 + copy_len]);
        Ok((copy_len, src_ip, src_port))
    }
}

// ============================================================================
// WLAN Service Client (`HWLN` -> `/services/wlan.elf`)
// ============================================================================

/// Query `/services/wlan.elf` status & hardware telemetry (`wlan=ro`).
pub fn wlan_status() -> Result<WlanStatusSnapshot> {
    with_wlan_channel(false, |ch| {
        let mut req = [0u8; 8];
        wlan::write_header(&mut req, WlanOp::Status, WlanStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 160];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        WlanStatusSnapshot::decode_reply(&rep[..n]).map_err(map_wlan_status)
    })
}

/// Trigger an active 802.11 scan and return discovered APs (`wlan=admin`).
pub fn wlan_scan() -> Result<Vec<WlanBssInfo>> {
    with_wlan_channel(true, |ch| {
        let mut req = [0u8; 8];
        wlan::write_header(&mut req, WlanOp::Scan, WlanStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 1280];
        let n = ch
            .read_into_timeout(&mut rep, 400)
            .map_err(Error::from_code)?;
        let st = wlan::check_header(&rep[..n], WlanOp::Scan).map_err(map_wlan_status)?;
        if st != WlanStatus::Ok {
            return Err(map_wlan_status(st));
        }
        if n < 9 {
            return Ok(Vec::new());
        }
        let count = usize::from(rep[8]);
        let mut out = Vec::with_capacity(count);
        let mut pos = 9usize;
        for _ in 0..count {
            if pos + WlanBssInfo::WIRE_LEN > n {
                break;
            }
            if let Some(bss) = WlanBssInfo::decode(&rep[pos..pos + WlanBssInfo::WIRE_LEN]) {
                out.push(bss);
            }
            pos += WlanBssInfo::WIRE_LEN;
        }
        Ok(out)
    })
}

/// Connect to an Open or WPA2-PSK network (`passphrase = ""` for Open).
pub fn wlan_connect(ssid: &str, passphrase: &str) -> Result<()> {
    let sb = ssid.as_bytes();
    let pb = passphrase.as_bytes();
    if sb.is_empty() || sb.len() > wlan::MAX_SSID_LEN || pb.len() > wlan::MAX_PASSPHRASE_LEN {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    with_wlan_channel(true, |ch| {
        let mut req = [0u8; 112];
        wlan::write_header(&mut req, WlanOp::Connect, WlanStatus::Ok);
        req[8] = sb.len() as u8;
        req[9] = pb.len() as u8;
        req[10..10 + sb.len()].copy_from_slice(sb);
        req[42..42 + pb.len()].copy_from_slice(pb);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 600)
            .map_err(Error::from_code)?;
        let st = wlan::check_header(&rep[..n], WlanOp::Connect).map_err(map_wlan_status)?;
        if st == WlanStatus::Ok {
            Ok(())
        } else {
            Err(map_wlan_status(st))
        }
    })
}

/// Disconnect from the current BSS and wipe transient PTK/GTK keys (`wlan=admin`).
pub fn wlan_disconnect() -> Result<()> {
    with_wlan_channel(true, |ch| {
        let mut req = [0u8; 8];
        wlan::write_header(&mut req, WlanOp::Disconnect, WlanStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        let st = wlan::check_header(&rep[..n], WlanOp::Disconnect).map_err(map_wlan_status)?;
        if st == WlanStatus::Ok {
            Ok(())
        } else {
            Err(map_wlan_status(st))
        }
    })
}

/// List non-secret saved profile summaries (`wlan=ro`).
pub fn wlan_list_profiles() -> Result<Vec<WlanProfileSummary>> {
    with_wlan_channel(false, |ch| {
        let mut req = [0u8; 8];
        wlan::write_header(&mut req, WlanOp::ListProfiles, WlanStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 768];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        let st = wlan::check_header(&rep[..n], WlanOp::ListProfiles).map_err(map_wlan_status)?;
        if st != WlanStatus::Ok {
            return Err(map_wlan_status(st));
        }
        if n < 9 {
            return Ok(Vec::new());
        }
        let count = usize::from(rep[8]);
        let mut out = Vec::with_capacity(count);
        let mut pos = 9usize;
        for _ in 0..count {
            if pos + WlanProfileSummary::WIRE_LEN > n {
                break;
            }
            if let Some(p) =
                WlanProfileSummary::decode(&rep[pos..pos + WlanProfileSummary::WIRE_LEN])
            {
                out.push(p);
            }
            pos += WlanProfileSummary::WIRE_LEN;
        }
        Ok(out)
    })
}

/// Set regulatory domain (`WORLD`, `RU`, `US`, `EU`, `JP`, `UNLOCKED`).
pub fn wlan_set_reg_domain(domain: RegDomainCode) -> Result<()> {
    with_wlan_channel(true, |ch| {
        let mut req = [0u8; 9];
        wlan::write_header(&mut req, WlanOp::SetRegDomain, WlanStatus::Ok);
        req[8] = domain as u8;
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        let st = wlan::check_header(&rep[..n], WlanOp::SetRegDomain).map_err(map_wlan_status)?;
        if st == WlanStatus::Ok {
            Ok(())
        } else {
            Err(map_wlan_status(st))
        }
    })
}

/// Configure MAC privacy policy (`Factory` / `Random` / `Custom`).
pub fn wlan_set_mac_policy(policy: MacPolicyMode, custom_mac: Option<[u8; 6]>) -> Result<()> {
    with_wlan_channel(true, |ch| {
        let mut req = [0u8; 15];
        wlan::write_header(&mut req, WlanOp::SetMacPolicy, WlanStatus::Ok);
        req[8] = policy as u8;
        if let Some(mac) = custom_mac {
            req[9..15].copy_from_slice(&mac);
        }
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        let st = wlan::check_header(&rep[..n], WlanOp::SetMacPolicy).map_err(map_wlan_status)?;
        if st == WlanStatus::Ok {
            Ok(())
        } else {
            Err(map_wlan_status(st))
        }
    })
}

/// Start WPA2-CCMP SoftAP / Hotspot (`wlan=admin`).
pub fn wlan_ap_start(ssid: &str, passphrase: &str, channel: u8) -> Result<()> {
    let sb = ssid.as_bytes();
    let pb = passphrase.as_bytes();
    if sb.is_empty()
        || sb.len() > wlan::MAX_SSID_LEN
        || pb.len() < 8
        || pb.len() > wlan::MAX_PASSPHRASE_LEN
    {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    with_wlan_channel(true, |ch| {
        let mut req = [0u8; 112];
        wlan::write_header(&mut req, WlanOp::ApStart, WlanStatus::Ok);
        req[8] = channel;
        req[9] = sb.len() as u8;
        req[10] = pb.len() as u8;
        req[11..11 + sb.len()].copy_from_slice(sb);
        req[43..43 + pb.len()].copy_from_slice(pb);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 300)
            .map_err(Error::from_code)?;
        let st = wlan::check_header(&rep[..n], WlanOp::ApStart).map_err(map_wlan_status)?;
        if st == WlanStatus::Ok {
            Ok(())
        } else {
            Err(map_wlan_status(st))
        }
    })
}

/// Stop SoftAP / Hotspot mode (`wlan=admin`).
pub fn wlan_ap_stop() -> Result<()> {
    with_wlan_channel(true, |ch| {
        let mut req = [0u8; 8];
        wlan::write_header(&mut req, WlanOp::ApStop, WlanStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 200)
            .map_err(Error::from_code)?;
        let st = wlan::check_header(&rep[..n], WlanOp::ApStop).map_err(map_wlan_status)?;
        if st == WlanStatus::Ok {
            Ok(())
        } else {
            Err(map_wlan_status(st))
        }
    })
}
