//! Plan 9 `/net`-inspired wire protocol for `net-service` (`/services/net.elf`).
//!
//! Control operations travel over the client's `net` capability channel;
//! stream (`TCP`) and datagram (`UDP`) sockets mint dedicated per-connection
//! `(ctl, data)` channel handles so bulk transfers never head-of-line-block
//! unrelated sockets or control queries.

#![forbid(unsafe_code)]

/// Wire magic `"HNET"` in little-endian.
pub const MAGIC: u32 = 0x5445_4E48;
/// Current protocol version.
pub const VERSION: u16 = 1;
/// Number of logical network interfaces tracked by `net-service` (`lo`, `virtio0`, `wlan0`).
pub const MAX_IFACES: usize = 3;
/// Maximum ARP entries returned in one diagnostic snapshot.
pub const MAX_ARP_RECORDS: usize = 16;
/// Maximum hostname bytes in a DNS query.
pub const MAX_DNS_NAME_LEN: usize = 192;

/// Well-known interface indices inside [`NetStatusSnapshot::ifaces`].
pub mod iface_id {
    /// Loopback interface (`lo`, `127.0.0.1/8`).
    pub const LO: u8 = 0;
    /// Paravirtual Ethernet NIC (`virtio0`, PCI `1af4:1000` / `1af4:1041`).
    pub const VIRTIO0: u8 = 1;
    /// Wireless 802.11 STA/SoftAP uplink (`wlan0`, Realtek `10ec:c821`).
    pub const WLAN0: u8 = 2;
}

/// Request opcodes sent to `net-service`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetOp {
    /// Read interface status, IP/mask/gateway/DNS, and packet/byte counters.
    Status = 1,
    /// Resolve an IPv4 `A` record via `/etc/hosts`, DNS cache, or UDP/53.
    ResolveDns = 2,
    /// Send one ICMPv4 Echo Request and await the matching Echo Reply.
    Ping = 3,
    /// Open a new Plan 9 `/net/tcp` `(ctl, data)` socket pair.
    OpenTcp = 4,
    /// Open and bind a new `/net/udp` socket channel on `local_port` (`0` = ephemeral).
    OpenUdp = 5,
    /// Toggle or renew DHCPv4 on an interface (`net=rw` required).
    SetDhcp = 6,
    /// Configure a static IPv4 CIDR and optional gateway (`net=rw` required).
    SetStaticIp = 7,
    /// Override the upstream DNS resolver IPv4 address (`net=rw` required).
    SetDns = 8,
    /// Read the active ARP neighbor cache.
    QueryArp = 9,
}

impl NetOp {
    /// Convert a wire tag back into a [`NetOp`].
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Status,
            2 => Self::ResolveDns,
            3 => Self::Ping,
            4 => Self::OpenTcp,
            5 => Self::OpenUdp,
            6 => Self::SetDhcp,
            7 => Self::SetStaticIp,
            8 => Self::SetDns,
            9 => Self::QueryArp,
            _ => return None,
        })
    }

    /// True when the operation requires `caps_mask::NET_RW` rather than read-only `NET_RO`.
    pub const fn requires_write(self) -> bool {
        matches!(
            self,
            Self::Ping
                | Self::OpenTcp
                | Self::OpenUdp
                | Self::SetDhcp
                | Self::SetStaticIp
                | Self::SetDns
        )
    }
}

/// Status codes carried in `net-service` replies.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetStatus {
    /// Request succeeded.
    Ok = 0,
    /// Malformed request frame.
    InvalidRequest = 1,
    /// Caller holds only `net=ro` (`NET_RO`) or lacks capability rights.
    AccessDenied = 2,
    /// Target host or route could not be reached.
    Unreachable = 3,
    /// Operation timed out waiting for ARP, DNS, ICMP, or TCP peer.
    TimedOut = 4,
    /// Remote peer refused or reset the TCP connection.
    ConnectionRefused = 5,
    /// DNS name did not resolve (`NXDOMAIN` / no A record).
    NameNotFound = 6,
    /// Socket table or packet pool is full.
    Busy = 7,
}

impl NetStatus {
    /// Decode a wire status byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Ok,
            1 => Self::InvalidRequest,
            2 => Self::AccessDenied,
            3 => Self::Unreachable,
            4 => Self::TimedOut,
            5 => Self::ConnectionRefused,
            6 => Self::NameNotFound,
            7 => Self::Busy,
            _ => return None,
        })
    }
}

/// Snapshot of a single logical network interface (`64` bytes encoded).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IfaceSnapshot {
    /// ASCII interface name NUL-padded (`"lo"`, `"virtio0"`, `"wlan0"`).
    pub name: [u8; 8],
    /// Hardware / driver attached.
    pub present: bool,
    /// L2 carrier / link up.
    pub link_up: bool,
    /// DHCPv4 client enabled on this interface.
    pub dhcp_enabled: bool,
    /// Prefix length in bits (`0..=32`).
    pub prefix_len: u8,
    /// L2 MAC address (`0` on `lo`).
    pub mac: [u8; 6],
    /// Assigned IPv4 address (`0.0.0.0` if unconfigured).
    pub ipv4: [u8; 4],
    /// Default gateway IPv4 address (`0.0.0.0` if none).
    pub gateway: [u8; 4],
    /// Received packet count.
    pub rx_packets: u64,
    /// Transmitted packet count.
    pub tx_packets: u64,
    /// Received payload/frame bytes.
    pub rx_bytes: u64,
    /// Transmitted payload/frame bytes.
    pub tx_bytes: u64,
}

impl IfaceSnapshot {
    /// Encoded wire size of one interface snapshot.
    pub const WIRE_LEN: usize = 60;

    /// Interface name as `&str`.
    pub fn name_str(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).unwrap_or("?")
    }

    /// Encode into a 60-byte slice.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < Self::WIRE_LEN {
            return None;
        }
        out[0..8].copy_from_slice(&self.name);
        out[8] = u8::from(self.present);
        out[9] = u8::from(self.link_up);
        out[10] = u8::from(self.dhcp_enabled);
        out[11] = self.prefix_len;
        out[12..18].copy_from_slice(&self.mac);
        out[18..22].copy_from_slice(&self.ipv4);
        out[22..26].copy_from_slice(&self.gateway);
        out[26..28].fill(0);
        out[28..36].copy_from_slice(&self.rx_packets.to_le_bytes());
        out[36..44].copy_from_slice(&self.tx_packets.to_le_bytes());
        out[44..52].copy_from_slice(&self.rx_bytes.to_le_bytes());
        out[52..60].copy_from_slice(&self.tx_bytes.to_le_bytes());
        Some(Self::WIRE_LEN)
    }

    /// Decode from a 60-byte slice.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_LEN {
            return None;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&bytes[0..8]);
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes[12..18]);
        let mut ipv4 = [0u8; 4];
        ipv4.copy_from_slice(&bytes[18..22]);
        let mut gateway = [0u8; 4];
        gateway.copy_from_slice(&bytes[22..26]);
        Some(Self {
            name,
            present: bytes[8] != 0,
            link_up: bytes[9] != 0,
            dhcp_enabled: bytes[10] != 0,
            prefix_len: bytes[11],
            mac,
            ipv4,
            gateway,
            rx_packets: read_u64(bytes, 28)?,
            tx_packets: read_u64(bytes, 36)?,
            rx_bytes: read_u64(bytes, 44)?,
            tx_bytes: read_u64(bytes, 52)?,
        })
    }
}

/// Complete network stack status snapshot returned by [`NetOp::Status`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetStatusSnapshot {
    /// Active DNS server IPv4 address.
    pub dns_server: [u8; 4],
    /// Active default-route interface index (`iface_id::*`).
    pub active_uplink: u8,
    /// Number of active TCP sockets.
    pub active_tcp_sockets: u8,
    /// Number of active UDP sockets.
    pub active_udp_sockets: u8,
    /// Free buffers remaining in the zero-alloc packet pool.
    pub free_packet_buffers: u16,
    /// Total buffers in the zero-alloc packet pool.
    pub total_packet_buffers: u16,
    /// Per-interface status (`lo`, `virtio0`, `wlan0`).
    pub ifaces: [IfaceSnapshot; MAX_IFACES],
}

impl NetStatusSnapshot {
    /// Wire length of the status payload (excluding the 8-byte reply header).
    pub const PAYLOAD_LEN: usize = 12 + MAX_IFACES * IfaceSnapshot::WIRE_LEN;

    /// Encode reply frame (`8 + PAYLOAD_LEN` bytes).
    pub fn encode_reply(&self, out: &mut [u8]) -> Option<usize> {
        let total = 8 + Self::PAYLOAD_LEN;
        if out.len() < total {
            return None;
        }
        write_header(out, NetOp::Status, NetStatus::Ok);
        out[8..12].copy_from_slice(&self.dns_server);
        out[12] = self.active_uplink;
        out[13] = self.active_tcp_sockets;
        out[14] = self.active_udp_sockets;
        out[15] = 0;
        out[16..18].copy_from_slice(&self.free_packet_buffers.to_le_bytes());
        out[18..20].copy_from_slice(&self.total_packet_buffers.to_le_bytes());
        for (idx, iface) in self.ifaces.iter().enumerate() {
            let off = 20 + idx * IfaceSnapshot::WIRE_LEN;
            iface.encode(&mut out[off..off + IfaceSnapshot::WIRE_LEN])?;
        }
        Some(total)
    }

    /// Decode from a reply frame.
    pub fn decode_reply(bytes: &[u8]) -> Result<Self, NetStatus> {
        let status = check_header(bytes, NetOp::Status)?;
        if status != NetStatus::Ok {
            return Err(status);
        }
        if bytes.len() < 8 + Self::PAYLOAD_LEN {
            return Err(NetStatus::InvalidRequest);
        }
        let mut dns_server = [0u8; 4];
        dns_server.copy_from_slice(&bytes[8..12]);
        let mut ifaces = [IfaceSnapshot::default(); MAX_IFACES];
        for (idx, slot) in ifaces.iter_mut().enumerate() {
            let off = 20 + idx * IfaceSnapshot::WIRE_LEN;
            *slot = IfaceSnapshot::decode(&bytes[off..off + IfaceSnapshot::WIRE_LEN])
                .ok_or(NetStatus::InvalidRequest)?;
        }
        Ok(Self {
            dns_server,
            active_uplink: bytes[12],
            active_tcp_sockets: bytes[13],
            active_udp_sockets: bytes[14],
            free_packet_buffers: read_u16(bytes, 16).ok_or(NetStatus::InvalidRequest)?,
            total_packet_buffers: read_u16(bytes, 18).ok_or(NetStatus::InvalidRequest)?,
            ifaces,
        })
    }
}

/// ICMP Echo reply metadata returned by [`NetOp::Ping`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PingResult {
    /// Responder IPv4 address.
    pub responder_ipv4: [u8; 4],
    /// Sequence number echoed back.
    pub seq: u16,
    /// Echo payload length in bytes.
    pub payload_bytes: u16,
    /// IPv4 TTL from the Echo Reply packet.
    pub ttl: u8,
    /// Measured round-trip latency in microseconds.
    pub rtt_us: u32,
}

/// Commands sent over the `ctl` half of an opened Plan 9 `/net/tcp` socket.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpCtlOp {
    /// Dial `remote_ipv4:remote_port` with a millisecond timeout.
    Connect = 1,
    /// Half-close the outbound stream (`FIN`).
    ShutdownWrite = 2,
    /// Query connection state and local/remote endpoints.
    Info = 3,
}

/// Encode an 8-byte header `[MAGIC:4][VERSION:2][op:1][status:1]`.
pub fn write_header(out: &mut [u8], op: NetOp, status: NetStatus) {
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6] = op as u8;
    out[7] = status as u8;
}

/// Parse an incoming request header, returning `(op, payload_slice)`.
pub fn parse_request(bytes: &[u8]) -> Option<(NetOp, &[u8])> {
    if bytes.len() < 8 {
        return None;
    }
    if read_u32(bytes, 0)? != MAGIC || read_u16(bytes, 4)? != VERSION {
        return None;
    }
    let op = NetOp::from_raw(bytes[6])?;
    Some((op, &bytes[8..]))
}

/// Validate a reply header for `expected_op` and extract its [`NetStatus`].
pub fn check_header(bytes: &[u8], expected_op: NetOp) -> Result<NetStatus, NetStatus> {
    if bytes.len() < 8 {
        return Err(NetStatus::InvalidRequest);
    }
    if read_u32(bytes, 0) != Some(MAGIC) || read_u16(bytes, 4) != Some(VERSION) {
        return Err(NetStatus::InvalidRequest);
    }
    if bytes[6] != expected_op as u8 {
        return Err(NetStatus::InvalidRequest);
    }
    NetStatus::from_raw(bytes[7]).ok_or(NetStatus::InvalidRequest)
}

/// Encode a simple zero-payload request (e.g. [`NetOp::Status`], [`NetOp::OpenTcp`]).
pub fn encode_simple_request(op: NetOp) -> [u8; 8] {
    let mut buf = [0u8; 8];
    write_header(&mut buf, op, NetStatus::Ok);
    buf
}

/// Encode a [`NetOp::ResolveDns`] request into `out`.
pub fn encode_dns_request(hostname: &str, out: &mut [u8]) -> Option<usize> {
    let hb = hostname.as_bytes();
    if hb.is_empty() || hb.len() > MAX_DNS_NAME_LEN || out.len() < 10 + hb.len() {
        return None;
    }
    write_header(out, NetOp::ResolveDns, NetStatus::Ok);
    out[8..10].copy_from_slice(&(hb.len() as u16).to_le_bytes());
    out[10..10 + hb.len()].copy_from_slice(hb);
    Some(10 + hb.len())
}

/// Decode a [`NetOp::ResolveDns`] reply (`ipv4`, `ttl_secs`).
pub fn decode_dns_reply(bytes: &[u8]) -> Result<([u8; 4], u32), NetStatus> {
    let status = check_header(bytes, NetOp::ResolveDns)?;
    if status != NetStatus::Ok {
        return Err(status);
    }
    if bytes.len() < 16 {
        return Err(NetStatus::InvalidRequest);
    }
    let mut ipv4 = [0u8; 4];
    ipv4.copy_from_slice(&bytes[8..12]);
    let ttl = read_u32(bytes, 12).ok_or(NetStatus::InvalidRequest)?;
    Ok((ipv4, ttl))
}

/// Encode a [`NetOp::Ping`] request into a 20-byte frame.
pub fn encode_ping_request(
    target_ipv4: [u8; 4],
    ident: u16,
    seq: u16,
    timeout_ms: u32,
    payload_len: u16,
) -> [u8; 22] {
    let mut buf = [0u8; 22];
    write_header(&mut buf, NetOp::Ping, NetStatus::Ok);
    buf[8..12].copy_from_slice(&target_ipv4);
    buf[12..14].copy_from_slice(&ident.to_le_bytes());
    buf[14..16].copy_from_slice(&seq.to_le_bytes());
    buf[16..20].copy_from_slice(&timeout_ms.to_le_bytes());
    buf[20..22].copy_from_slice(&payload_len.to_le_bytes());
    buf
}

/// Encode a [`NetOp::Ping`] reply into a 22-byte frame.
pub fn encode_ping_reply(status: NetStatus, result: &PingResult) -> [u8; 22] {
    let mut buf = [0u8; 22];
    write_header(&mut buf, NetOp::Ping, status);
    buf[8..12].copy_from_slice(&result.responder_ipv4);
    buf[12..14].copy_from_slice(&result.seq.to_le_bytes());
    buf[14..16].copy_from_slice(&result.payload_bytes.to_le_bytes());
    buf[16] = result.ttl;
    buf[17] = 0;
    buf[18..22].copy_from_slice(&result.rtt_us.to_le_bytes());
    buf
}

/// Decode a [`NetOp::Ping`] reply.
pub fn decode_ping_reply(bytes: &[u8]) -> Result<PingResult, NetStatus> {
    let status = check_header(bytes, NetOp::Ping)?;
    if status != NetStatus::Ok {
        return Err(status);
    }
    if bytes.len() < 22 {
        return Err(NetStatus::InvalidRequest);
    }
    let mut responder_ipv4 = [0u8; 4];
    responder_ipv4.copy_from_slice(&bytes[8..12]);
    Ok(PingResult {
        responder_ipv4,
        seq: read_u16(bytes, 12).ok_or(NetStatus::InvalidRequest)?,
        payload_bytes: read_u16(bytes, 14).ok_or(NetStatus::InvalidRequest)?,
        ttl: bytes[16],
        rtt_us: read_u32(bytes, 18).ok_or(NetStatus::InvalidRequest)?,
    })
}

/// Encode a TCP `ctl` connect command (`[TcpCtlOp::Connect, 0, port:2, ipv4:4, timeout_ms:4]`).
pub fn encode_tcp_connect(remote_ipv4: [u8; 4], remote_port: u16, timeout_ms: u32) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0] = TcpCtlOp::Connect as u8;
    buf[2..4].copy_from_slice(&remote_port.to_le_bytes());
    buf[4..8].copy_from_slice(&remote_ipv4);
    buf[8..12].copy_from_slice(&timeout_ms.to_le_bytes());
    buf
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_ping_round_trip() {
        let mut snap = NetStatusSnapshot {
            dns_server: [10, 0, 2, 3],
            active_uplink: iface_id::VIRTIO0,
            active_tcp_sockets: 2,
            active_udp_sockets: 1,
            free_packet_buffers: 120,
            total_packet_buffers: 128,
            ifaces: [IfaceSnapshot::default(); MAX_IFACES],
        };
        snap.ifaces[1].name[..7].copy_from_slice(b"virtio0");
        snap.ifaces[1].present = true;
        snap.ifaces[1].link_up = true;
        snap.ifaces[1].dhcp_enabled = true;
        snap.ifaces[1].prefix_len = 24;
        snap.ifaces[1].ipv4 = [10, 0, 2, 15];
        snap.ifaces[1].gateway = [10, 0, 2, 2];
        snap.ifaces[1].rx_packets = 42;

        let mut wire = [0u8; 256];
        let n = snap.encode_reply(&mut wire).unwrap_or(0);
        assert_eq!(NetStatusSnapshot::decode_reply(&wire[..n]), Ok(snap));

        let pr = PingResult {
            responder_ipv4: [10, 0, 2, 2],
            seq: 3,
            payload_bytes: 56,
            ttl: 64,
            rtt_us: 415,
        };
        let pwire = encode_ping_reply(NetStatus::Ok, &pr);
        assert_eq!(decode_ping_reply(&pwire), Ok(pr));
    }
}
