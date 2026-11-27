//! Capability-first IPv4 networking (`HNET`) and IEEE 802.11 WLAN (`HWLN`)
//! client APIs for HuesOS user-space programs.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

use huesos_abi::auxv::caps_mask;
use huesos_abi::btl::{self, BtlKeySummary, BtlOp, BtlPeerInfo, BtlStatus, BtlStatusSnapshot};
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
static BTL_SERVICE_CH: Mutex<Option<Channel>> = Mutex::new(None);

fn map_net_status(st: NetStatus) -> Error {
    let kind = match st {
        NetStatus::Ok => ErrorKind::Other,
        NetStatus::InvalidRequest => ErrorKind::InvalidInput,
        NetStatus::AccessDenied => ErrorKind::AccessDenied,
        NetStatus::NetworkDown => ErrorKind::NetworkUnreachable,
        NetStatus::Unreachable => ErrorKind::HostUnreachable,
        NetStatus::TimedOut => ErrorKind::TimedOut,
        NetStatus::ConnectionRefused => ErrorKind::ConnectionRefused,
        NetStatus::NameNotFound => ErrorKind::DnsFailure,
        NetStatus::Busy => ErrorKind::Busy,
    };
    Error::new(kind)
}

fn map_wlan_status(st: WlanStatus) -> Error {
    let kind = match st {
        WlanStatus::Ok => ErrorKind::Other,
        WlanStatus::InvalidRequest => ErrorKind::InvalidInput,
        WlanStatus::InvalidPassphrase => ErrorKind::InvalidPassphrase,
        WlanStatus::AccessDenied => ErrorKind::AccessDenied,
        WlanStatus::RegulatoryBlocked => ErrorKind::RegulatoryBlocked,
        WlanStatus::HardwareAbsent | WlanStatus::FirmwareUnavailable => ErrorKind::Unsupported,
        WlanStatus::SsidNotFound => ErrorKind::SsidNotFound,
        WlanStatus::AuthFailed => ErrorKind::AuthFailed,
        WlanStatus::AssocFailed => ErrorKind::AssocFailed,
        WlanStatus::HandshakeFailed => ErrorKind::HandshakeFailed,
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
            .read_into_timeout(&mut rep, 1_200)
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

// =========================================================================
// Plan 9 `/net/btl` Bluetooth Classic Client (`HBTL` -> `/services/btl.elf`)
// =========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BtlCapLevel {
    ReadOnly,
    ReadWrite,
    Admin,
}

fn map_btl_status(st: BtlStatus) -> Error {
    let kind = match st {
        BtlStatus::Ok => ErrorKind::Other,
        BtlStatus::InvalidRequest => ErrorKind::InvalidInput,
        BtlStatus::AccessDenied => ErrorKind::AccessDenied,
        BtlStatus::HardwareAbsent | BtlStatus::FirmwareFailed => ErrorKind::Unsupported,
        BtlStatus::NotConnected => ErrorKind::HostUnreachable,
        BtlStatus::AuthFailed => ErrorKind::AuthFailed,
        BtlStatus::Refused => ErrorKind::ConnectionRefused,
        BtlStatus::WouldBlock => ErrorKind::ShouldWait,
        BtlStatus::ChannelClosed => ErrorKind::PeerClosed,
        BtlStatus::Congested => ErrorKind::Busy,
    };
    Error::new(kind)
}

fn check_btl_cap(level: BtlCapLevel) -> Result<()> {
    let mask = current_caps_mask();
    if (mask & caps_mask::BTL_RO) == 0 {
        return Err(Error::capability());
    }
    match level {
        BtlCapLevel::ReadOnly => Ok(()),
        BtlCapLevel::ReadWrite => {
            if (mask & caps_mask::BTL_RW) == 0 {
                return Err(Error::capability());
            }
            Ok(())
        }
        BtlCapLevel::Admin => {
            if (mask & caps_mask::BTL_ADMIN) == 0 {
                return Err(Error::capability());
            }
            Ok(())
        }
    }
}

fn with_btl_channel<F, T>(level: BtlCapLevel, f: F) -> Result<T>
where
    F: FnOnce(&Channel) -> Result<T>,
{
    check_btl_cap(level)?;
    let mut guard = BTL_SERVICE_CH.lock();
    if guard.is_none() {
        if let Some(h) = take_cap_handle(CapKind::BtlService) {
            *guard = Some(Channel::from_handle(h));
        }
    }
    let Some(ch) = guard.as_ref() else {
        return Err(Error::capability());
    };
    f(ch)
}

/// Parse a Bluetooth `BD_ADDR` (`"AA:BB:CC:DD:EE:FF"`, display MSB-first) into
/// little-endian HCI byte order (`[FF, EE, DD, CC, BB, AA]`).
pub fn parse_bd_addr(text: &str) -> Option<[u8; 6]> {
    let mut big = [0u8; 6];
    let mut count = 0usize;
    for part in text.trim().split(':') {
        if count >= 6 || part.len() != 2 {
            return None;
        }
        big[count] = u8::from_str_radix(part, 16).ok()?;
        count += 1;
    }
    if count != 6 {
        return None;
    }
    Some([big[5], big[4], big[3], big[2], big[1], big[0]])
}

/// Format a little-endian HCI `BD_ADDR` into canonical `"AA:BB:CC:DD:EE:FF"`.
pub fn format_bd_addr(bd_addr: &[u8; 6]) -> alloc::string::String {
    alloc::format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bd_addr[5],
        bd_addr[4],
        bd_addr[3],
        bd_addr[2],
        bd_addr[1],
        bd_addr[0]
    )
}

/// Query `/services/btl.elf` controller status (`btl=ro`).
pub fn btl_status() -> Result<BtlStatusSnapshot> {
    with_btl_channel(BtlCapLevel::ReadOnly, |ch| {
        let mut req = [0u8; 8];
        btl::write_header(&mut req, BtlOp::Status, BtlStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 128];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        BtlStatusSnapshot::decode_reply(&rep[..n]).map_err(map_btl_status)
    })
}

fn decode_peer_list(rep: &[u8], expected_op: BtlOp) -> Result<Vec<BtlPeerInfo>> {
    let st = btl::check_header(rep, expected_op).map_err(map_btl_status)?;
    if st != BtlStatus::Ok {
        return Err(map_btl_status(st));
    }
    if rep.len() < 12 {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    let count = usize::from(rep[8]).min(btl::MAX_PEERS);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 12 + i * BtlPeerInfo::WIRE_LEN;
        if off + BtlPeerInfo::WIRE_LEN > rep.len() {
            break;
        }
        if let Some(peer) = BtlPeerInfo::decode(&rep[off..off + BtlPeerInfo::WIRE_LEN]) {
            out.push(peer);
        }
    }
    Ok(out)
}

/// Trigger Bluetooth Classic Inquiry + EIR discovery (`btl=admin`).
pub fn btl_scan() -> Result<Vec<BtlPeerInfo>> {
    with_btl_channel(BtlCapLevel::Admin, |ch| {
        let mut req = [0u8; 8];
        btl::write_header(&mut req, BtlOp::Scan, BtlStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 1152];
        let n = ch
            .read_into_timeout(&mut rep, 2500)
            .map_err(Error::from_code)?;
        decode_peer_list(&rep[..n], BtlOp::Scan)
    })
}

/// List cached discovered/connected Bluetooth peers (`btl=ro`).
pub fn btl_list_peers() -> Result<Vec<BtlPeerInfo>> {
    with_btl_channel(BtlCapLevel::ReadOnly, |ch| {
        let mut req = [0u8; 8];
        btl::write_header(&mut req, BtlOp::ListPeers, BtlStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 1152];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        decode_peer_list(&rep[..n], BtlOp::ListPeers)
    })
}

/// Pair with `bd_addr` using SSP Just-Works and persist Link Key on `HxFS` (`btl=admin`).
pub fn btl_pair(bd_addr: [u8; 6]) -> Result<()> {
    with_btl_channel(BtlCapLevel::Admin, |ch| {
        let mut req = [0u8; 14];
        btl::write_header(&mut req, BtlOp::Pair, BtlStatus::Ok);
        req[8..14].copy_from_slice(&bd_addr);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 2500)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::Pair).map_err(map_btl_status)?;
        if st == BtlStatus::Ok {
            Ok(())
        } else {
            Err(map_btl_status(st))
        }
    })
}

/// Open an encrypted ACL baseband link to `bd_addr` (`btl=admin`).
pub fn btl_connect_acl(bd_addr: [u8; 6]) -> Result<u16> {
    with_btl_channel(BtlCapLevel::Admin, |ch| {
        let mut req = [0u8; 14];
        btl::write_header(&mut req, BtlOp::ConnectAcl, BtlStatus::Ok);
        req[8..14].copy_from_slice(&bd_addr);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 2000)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::ConnectAcl).map_err(map_btl_status)?;
        if st != BtlStatus::Ok {
            return Err(map_btl_status(st));
        }
        let handle = if n >= 10 {
            u16::from_le_bytes([rep[8], rep[9]])
        } else {
            0
        };
        Ok(handle)
    })
}

/// Disconnect an active ACL baseband link (`btl=admin`).
pub fn btl_disconnect_acl(bd_addr: [u8; 6]) -> Result<()> {
    with_btl_channel(BtlCapLevel::Admin, |ch| {
        let mut req = [0u8; 14];
        btl::write_header(&mut req, BtlOp::DisconnectAcl, BtlStatus::Ok);
        req[8..14].copy_from_slice(&bd_addr);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 1000)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::DisconnectAcl).map_err(map_btl_status)?;
        if st == BtlStatus::Ok {
            Ok(())
        } else {
            Err(map_btl_status(st))
        }
    })
}

/// List non-secret 4-byte SHA-256 Link Key fingerprints (`btl=ro`).
pub fn btl_list_keys() -> Result<Vec<BtlKeySummary>> {
    with_btl_channel(BtlCapLevel::ReadOnly, |ch| {
        let mut req = [0u8; 8];
        btl::write_header(&mut req, BtlOp::ListKeys, BtlStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 256];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::ListKeys).map_err(map_btl_status)?;
        if st != BtlStatus::Ok {
            return Err(map_btl_status(st));
        }
        if n < 12 {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let count = usize::from(rep[8]).min(btl::MAX_KEY_SUMMARIES);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let off = 12 + i * BtlKeySummary::WIRE_LEN;
            if off + BtlKeySummary::WIRE_LEN > n {
                break;
            }
            if let Some(summary) = BtlKeySummary::decode(&rep[off..off + BtlKeySummary::WIRE_LEN]) {
                out.push(summary);
            }
        }
        Ok(out)
    })
}

/// Delete a stored Link Key for `bd_addr` (`btl=admin`).
pub fn btl_delete_key(bd_addr: [u8; 6]) -> Result<()> {
    with_btl_channel(BtlCapLevel::Admin, |ch| {
        let mut req = [0u8; 14];
        btl::write_header(&mut req, BtlOp::DeleteKey, BtlStatus::Ok);
        req[8..14].copy_from_slice(&bd_addr);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::DeleteKey).map_err(map_btl_status)?;
        if st == BtlStatus::Ok {
            Ok(())
        } else {
            Err(map_btl_status(st))
        }
    })
}

/// Result of a remote Bluetooth SDP service query (`BtlOp::SdpQuery`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtlSdpResult {
    /// True if the requested Service Class UUID was advertised by the peer.
    pub found: bool,
    /// Discovered L2CAP PSM (`0x0019` for AVDTP, `0x0017` for AVRCP, etc.).
    pub l2cap_psm: u16,
    /// Discovered profile version (`0x0103` = v1.3, `0x0104` = v1.4, etc.).
    pub profile_version: u16,
    /// Raw SDP attribute list payload returned by the peer.
    pub raw_attrs: Vec<u8>,
}

/// Query a peer's SDP server (`PSM 0x0001`) for `uuid16` (`btl=rw`).
pub fn btl_sdp_query(bd_addr: [u8; 6], uuid16: u16) -> Result<BtlSdpResult> {
    with_btl_channel(BtlCapLevel::ReadWrite, |ch| {
        let mut req = [0u8; 16];
        btl::write_header(&mut req, BtlOp::SdpQuery, BtlStatus::Ok);
        req[8..14].copy_from_slice(&bd_addr);
        req[14..16].copy_from_slice(&uuid16.to_le_bytes());
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 576];
        let n = ch
            .read_into_timeout(&mut rep, 2000)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::SdpQuery).map_err(map_btl_status)?;
        if st != BtlStatus::Ok {
            return Err(map_btl_status(st));
        }
        if n < 16 {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let found = rep[8] != 0;
        let l2cap_psm = u16::from_le_bytes([rep[10], rep[11]]);
        let profile_version = u16::from_le_bytes([rep[12], rep[13]]);
        let raw_len = usize::from(u16::from_le_bytes([rep[14], rep[15]])).min(n.saturating_sub(16));
        Ok(BtlSdpResult {
            found,
            l2cap_psm,
            profile_version,
            raw_attrs: rep[16..16 + raw_len].to_vec(),
        })
    })
}

/// Open an outbound L2CAP connection-oriented channel (`btl=rw`), returning `(local_cid, peer_mtu)`.
pub fn btl_l2cap_connect(bd_addr: [u8; 6], psm: u16) -> Result<(u16, u16)> {
    with_btl_channel(BtlCapLevel::ReadWrite, |ch| {
        let mut req = [0u8; 16];
        btl::write_header(&mut req, BtlOp::L2capConnect, BtlStatus::Ok);
        req[8..14].copy_from_slice(&bd_addr);
        req[14..16].copy_from_slice(&psm.to_le_bytes());
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 2000)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::L2capConnect).map_err(map_btl_status)?;
        if st != BtlStatus::Ok {
            return Err(map_btl_status(st));
        }
        if n < 16 {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let cid = u16::from_le_bytes([rep[8], rep[9]]);
        let mtu = u16::from_le_bytes([rep[10], rep[11]]);
        Ok((cid, mtu))
    })
}

/// Close an open L2CAP channel (`btl=rw`).
pub fn btl_l2cap_close(local_cid: u16) -> Result<()> {
    with_btl_channel(BtlCapLevel::ReadWrite, |ch| {
        let mut req = [0u8; 10];
        btl::write_header(&mut req, BtlOp::L2capClose, BtlStatus::Ok);
        req[8..10].copy_from_slice(&local_cid.to_le_bytes());
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::L2capClose).map_err(map_btl_status)?;
        if st == BtlStatus::Ok {
            Ok(())
        } else {
            Err(map_btl_status(st))
        }
    })
}

/// Read the complete `btsnoop` v1 (`RFC 1761`) capture buffer (`btl=ro`).
pub fn btl_read_snoop() -> Result<Vec<u8>> {
    with_btl_channel(BtlCapLevel::ReadOnly, |ch| {
        let mut out = Vec::new();
        let mut offset = 0u32;
        loop {
            let mut req = [0u8; 14];
            btl::write_header(&mut req, BtlOp::ReadSnoop, BtlStatus::Ok);
            req[8..12].copy_from_slice(&offset.to_le_bytes());
            req[12..14].copy_from_slice(&960u16.to_le_bytes());
            ch.write(&req).map_err(Error::from_code)?;
            let mut rep = [0u8; 1024];
            let n = ch
                .read_into_timeout(&mut rep, 500)
                .map_err(Error::from_code)?;
            let st = btl::check_header(&rep[..n], BtlOp::ReadSnoop).map_err(map_btl_status)?;
            if st != BtlStatus::Ok {
                return Err(map_btl_status(st));
            }
            if n < 16 {
                break;
            }
            let total = u32::from_le_bytes([rep[8], rep[9], rep[10], rep[11]]) as usize;
            let chunk_len =
                usize::from(u16::from_le_bytes([rep[12], rep[13]])).min(n.saturating_sub(16));
            if chunk_len == 0 {
                break;
            }
            out.extend_from_slice(&rep[16..16 + chunk_len]);
            offset = offset.saturating_add(chunk_len as u32);
            if out.len() >= total || out.len() >= 65_536 {
                break;
            }
        }
        Ok(out)
    })
}

/// Set controller power mode (`0` = off, `1` = on, `2` = virtual `"HuesOS AirBuds Pro"` + on) (`btl=admin`).
pub fn btl_set_power(mode: u8) -> Result<()> {
    with_btl_channel(BtlCapLevel::Admin, |ch| {
        let mut req = [0u8; 9];
        btl::write_header(&mut req, BtlOp::SetPower, BtlStatus::Ok);
        req[8] = mode;
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 1500)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::SetPower).map_err(map_btl_status)?;
        if st == BtlStatus::Ok {
            Ok(())
        } else {
            Err(map_btl_status(st))
        }
    })
}

/// Update `RTL8821CE` 2.4 GHz Wi-Fi/BT PTA coexistence hint (`0..=3`) (`btl=rw`).
pub fn btl_set_coex_hint(profile: u8) -> Result<()> {
    with_btl_channel(BtlCapLevel::ReadWrite, |ch| {
        let mut req = [0u8; 9];
        btl::write_header(&mut req, BtlOp::SetCoexHint, BtlStatus::Ok);
        req[8] = profile;
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        let st = btl::check_header(&rep[..n], BtlOp::SetCoexHint).map_err(map_btl_status)?;
        if st == BtlStatus::Ok {
            Ok(())
        } else {
            Err(map_btl_status(st))
        }
    })
}
