//! `#![no_std]`, `#![forbid(unsafe_code)]` TCP/IPv4 stack for HuesOS
//! (`/services/net.elf` and `/services/wlan.elf`).
//!
//! Implements Ethernet II, ARP (with bounded neighbor cache & pending packet
//! queue), IPv4, ICMPv4 Echo client/responder, UDP, DHCPv4 (`DISCOVER -> OFFER
//! -> REQUEST -> ACK`), RFC 1035 DNS stub resolution (with compressed-label
//! pointer decoding & TTL cache), and RFC 793/6298 TCP.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod dhcp_dns;
pub mod tcp;
pub mod wire;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use dhcp_dns::{
    build_dhcp_packet, build_dns_query, parse_dhcp_reply, parse_dns_response, DhcpLease, DhcpState,
    DHCP_ACK, DHCP_CLIENT_PORT, DHCP_DISCOVER, DHCP_NAK, DHCP_OFFER, DHCP_REQUEST,
    DHCP_SERVER_PORT, DNS_SERVER_PORT,
};
use tcp::{OutboundTcp, TcpSocket, TcpState};
use wire::{
    ArpPacket, EthFrame, IcmpEcho, Ipv4Packet, TcpSegment, UdpPacket, ARP_OP_REPLY, ARP_OP_REQUEST,
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, IP_PROTO_ICMP, IP_PROTO_TCP,
    IP_PROTO_UDP, TCP_ACK, TCP_RST,
};

/// 48-bit IEEE 802 MAC address.
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0; 6]);
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// 32-bit IPv4 address in network byte order.
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    pub const LOOPBACK: Self = Self([127, 0, 0, 1]);
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    pub const fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub const fn from_u32(v: u32) -> Self {
        Self(v.to_be_bytes())
    }

    pub const fn is_unspecified(self) -> bool {
        self.to_u32() == 0
    }

    pub const fn is_loopback(self) -> bool {
        self.0[0] == 127
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        let mut octets = [0u8; 4];
        let mut count = 0usize;
        for part in s.trim().split('.') {
            if count >= 4 {
                return None;
            }
            octets[count] = part.parse::<u8>().ok()?;
            count += 1;
        }
        if count == 4 {
            Some(Self(octets))
        } else {
            None
        }
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// IPv4 socket endpoint (`ip:port`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketAddrV4 {
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// Network stack error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetError {
    Truncated,
    Malformed,
    BadChecksum,
    BufferTooSmall,
    Unsupported,
    InvalidInput,
    InvalidState,
    WouldBlock,
    NotFound,
    ConnectionReset,
    TimedOut,
    PortInUse,
}

/// RFC 1071 ones'-complement internet checksum.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (pairs, rem) = data.as_chunks::<2>();
    for &pair in pairs {
        sum += u32::from(u16::from_be_bytes(pair));
    }
    if let &[last] = rem {
        sum += u32::from(last) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// RFC 1071 checksum including the 12-byte IPv4 transport pseudo-header.
pub fn pseudo_header_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, transport: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += u32::from(u16::from_be_bytes([src.0[0], src.0[1]]));
    sum += u32::from(u16::from_be_bytes([src.0[2], src.0[3]]));
    sum += u32::from(u16::from_be_bytes([dst.0[0], dst.0[1]]));
    sum += u32::from(u16::from_be_bytes([dst.0[2], dst.0[3]]));
    sum += u32::from(proto);
    sum += transport.len() as u32;

    let (pairs, rem) = transport.as_chunks::<2>();
    for &pair in pairs {
        sum += u32::from(u16::from_be_bytes(pair));
    }
    if let &[last] = rem {
        sum += u32::from(last) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Active IPv4 interface configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceConfig {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns_server: Ipv4Addr,
    pub dhcp_bound: bool,
    pub link_up: bool,
}

/// Cumulative packet & byte counters for `netctl` and `btop`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_drops: u64,
}

#[derive(Clone)]
struct ArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
    expires_ms: u64,
}

struct PendingArpPacket {
    next_hop: Ipv4Addr,
    queued_ms: u64,
    ip_packet: Vec<u8>,
}

/// Completed or in-flight ICMP Echo measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PingResult {
    pub dst: Ipv4Addr,
    pub ident: u16,
    pub seq: u16,
    pub sent_ms: u64,
    pub rtt_us: Option<u32>,
    pub ttl: u8,
    pub reply_bytes: u16,
}

/// Received UDP datagram queued on a bound UDP socket.
#[derive(Clone, Debug)]
pub struct UdpDatagram {
    pub src: SocketAddrV4,
    pub data: Vec<u8>,
}

/// Bound UDP socket.
pub struct UdpSocket {
    pub id: u32,
    pub local_port: u16,
    pub rx_queue: VecDeque<UdpDatagram>,
}

struct DnsCacheEntry {
    host: String,
    ip: Ipv4Addr,
    expires_ms: u64,
}

struct PendingDns {
    txid: u16,
    host: String,
    sent_ms: u64,
    resolved: Option<Result<Ipv4Addr, NetError>>,
}

/// Self-contained `#![no_std]` Ethernet/ARP/IPv4/ICMP/DHCP/DNS/UDP/TCP engine.
pub struct NetStack {
    pub cfg: InterfaceConfig,
    pub stats: NetStats,
    pub dhcp: DhcpState,
    arp_cache: Vec<ArpEntry>,
    arp_pending: VecDeque<PendingArpPacket>,
    pings: VecDeque<PingResult>,
    udp_sockets: Vec<UdpSocket>,
    tcp_sockets: Vec<TcpSocket>,
    dns_cache: Vec<DnsCacheEntry>,
    dns_pending: Vec<PendingDns>,
    next_socket_id: u32,
    next_ephemeral_port: u16,
    next_ip_ident: u16,
    next_dns_txid: u16,
    iss_counter: u32,
}

impl NetStack {
    pub fn new(mac: MacAddr) -> Self {
        Self {
            cfg: InterfaceConfig {
                mac,
                ip: Ipv4Addr::UNSPECIFIED,
                subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
                gateway: Ipv4Addr::UNSPECIFIED,
                dns_server: Ipv4Addr::UNSPECIFIED,
                dhcp_bound: false,
                link_up: true,
            },
            stats: NetStats::default(),
            dhcp: DhcpState::Idle,
            arp_cache: Vec::with_capacity(32),
            arp_pending: VecDeque::with_capacity(16),
            pings: VecDeque::with_capacity(16),
            udp_sockets: Vec::new(),
            tcp_sockets: Vec::new(),
            dns_cache: Vec::with_capacity(32),
            dns_pending: Vec::new(),
            next_socket_id: 1,
            next_ephemeral_port: 49_152,
            next_ip_ident: 1,
            next_dns_txid: 0x1001,
            iss_counter: 0x4855_4553,
        }
    }

    pub fn configure_static(
        &mut self,
        ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        gateway: Ipv4Addr,
        dns_server: Ipv4Addr,
    ) {
        self.cfg.ip = ip;
        self.cfg.subnet_mask = subnet_mask;
        self.cfg.gateway = gateway;
        self.cfg.dns_server = dns_server;
        self.cfg.dhcp_bound = false;
        self.dhcp = DhcpState::Idle;
    }

    /// Initiate DHCPv4 `DISCOVER` and push the broadcast frame to `tx_frames`.
    pub fn start_dhcp(&mut self, now_ms: u64, tx_frames: &mut VecDeque<Vec<u8>>) {
        let xid = 0x484E_4554u32 ^ (now_ms as u32) ^ u32::from(self.cfg.mac.0[5]);
        self.dhcp = DhcpState::Discovering {
            xid,
            started_ms: now_ms,
            retries: 0,
        };
        let _ = self.emit_dhcp_message(DHCP_DISCOVER, xid, None, None, tx_frames);
    }

    fn emit_dhcp_message(
        &mut self,
        msg_type: u8,
        xid: u32,
        req_ip: Option<Ipv4Addr>,
        srv_id: Option<Ipv4Addr>,
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) -> Result<(), NetError> {
        let mut dhcp_buf = [0u8; 340];
        let dhcp_len =
            build_dhcp_packet(msg_type, xid, self.cfg.mac, req_ip, srv_id, &mut dhcp_buf)?;
        let mut udp_buf = [0u8; 360];
        let udp_len = UdpPacket::emit(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            &dhcp_buf[..dhcp_len],
            &mut udp_buf,
        )?;
        let mut ip_buf = [0u8; 400];
        let ident = self.alloc_ip_ident();
        let ip_len = Ipv4Packet::emit(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            IP_PROTO_UDP,
            64,
            ident,
            &udp_buf[..udp_len],
            &mut ip_buf,
        )?;
        let mut frame = alloc::vec![0u8; wire::ETH_HEADER_LEN + ip_len];
        EthFrame::emit(
            MacAddr::BROADCAST,
            self.cfg.mac,
            ETHERTYPE_IPV4,
            &ip_buf[..ip_len],
            &mut frame,
        )?;
        self.push_tx_frame(frame, tx_frames);
        Ok(())
    }

    fn alloc_ip_ident(&mut self) -> u16 {
        let id = self.next_ip_ident;
        self.next_ip_ident = self.next_ip_ident.wrapping_add(1);
        id
    }

    fn alloc_ephemeral_port(&mut self) -> u16 {
        for _ in 0..16_384 {
            let p = self.next_ephemeral_port;
            self.next_ephemeral_port = if p >= 65_534 { 49_152 } else { p + 1 };
            let used_udp = self.udp_sockets.iter().any(|s| s.local_port == p);
            let used_tcp = self
                .tcp_sockets
                .iter()
                .any(|s| s.state != TcpState::Closed && s.local_port == p);
            if !used_udp && !used_tcp {
                return p;
            }
        }
        49_152
    }

    fn push_tx_frame(&mut self, frame: Vec<u8>, tx_frames: &mut VecDeque<Vec<u8>>) {
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += frame.len() as u64;
        tx_frames.push_back(frame);
    }

    fn next_hop(&self, dst: Ipv4Addr) -> Ipv4Addr {
        if dst == Ipv4Addr::BROADCAST || dst.is_loopback() || self.cfg.ip.is_unspecified() {
            return dst;
        }
        let mask = self.cfg.subnet_mask.to_u32();
        if (dst.to_u32() & mask) == (self.cfg.ip.to_u32() & mask)
            || self.cfg.gateway.is_unspecified()
        {
            dst
        } else {
            self.cfg.gateway
        }
    }

    fn learn_arp(&mut self, ip: Ipv4Addr, mac: MacAddr, now_ms: u64) {
        if ip.is_unspecified() || mac == MacAddr::BROADCAST || mac == MacAddr::ZERO {
            return;
        }
        if let Some(entry) = self.arp_cache.iter_mut().find(|e| e.ip == ip) {
            entry.mac = mac;
            entry.expires_ms = now_ms + 120_000;
            return;
        }
        if self.arp_cache.len() >= 32 {
            let _ = self.arp_cache.remove(0);
        }
        self.arp_cache.push(ArpEntry {
            ip,
            mac,
            expires_ms: now_ms + 120_000,
        });
    }

    fn lookup_arp(&self, ip: Ipv4Addr, now_ms: u64) -> Option<MacAddr> {
        if ip == Ipv4Addr::BROADCAST {
            return Some(MacAddr::BROADCAST);
        }
        self.arp_cache
            .iter()
            .find(|e| e.ip == ip && e.expires_ms > now_ms)
            .map(|e| e.mac)
    }

    fn flush_arp_pending(
        &mut self,
        resolved_ip: Ipv4Addr,
        mac: MacAddr,
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) {
        let mut remaining = VecDeque::with_capacity(self.arp_pending.len());
        while let Some(pkt) = self.arp_pending.pop_front() {
            if pkt.next_hop == resolved_ip {
                let mut frame = alloc::vec![0u8; wire::ETH_HEADER_LEN + pkt.ip_packet.len()];
                if EthFrame::emit(
                    mac,
                    self.cfg.mac,
                    ETHERTYPE_IPV4,
                    &pkt.ip_packet,
                    &mut frame,
                )
                .is_ok()
                {
                    self.push_tx_frame(frame, tx_frames);
                }
            } else {
                remaining.push_back(pkt);
            }
        }
        self.arp_pending = remaining;
    }

    fn send_ipv4_payload(
        &mut self,
        now_ms: u64,
        dst: Ipv4Addr,
        proto: u8,
        payload: &[u8],
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) -> Result<(), NetError> {
        let src = if dst.is_loopback() {
            Ipv4Addr::LOOPBACK
        } else {
            self.cfg.ip
        };
        if src.is_unspecified() && dst != Ipv4Addr::BROADCAST {
            return Err(NetError::InvalidState);
        }
        let ident = self.alloc_ip_ident();
        let mut ip_buf = alloc::vec![0u8; wire::IPV4_MIN_HEADER_LEN + payload.len()];
        let ip_len = Ipv4Packet::emit(src, dst, proto, 64, ident, payload, &mut ip_buf)?;
        ip_buf.truncate(ip_len);

        if dst.is_loopback() || dst == self.cfg.ip {
            let mut lo_frame = alloc::vec![0u8; wire::ETH_HEADER_LEN + ip_len];
            EthFrame::emit(
                self.cfg.mac,
                self.cfg.mac,
                ETHERTYPE_IPV4,
                &ip_buf,
                &mut lo_frame,
            )?;
            self.ingest_frame(now_ms, &lo_frame, tx_frames);
            return Ok(());
        }

        let hop = self.next_hop(dst);
        if let Some(dst_mac) = self.lookup_arp(hop, now_ms) {
            let mut frame = alloc::vec![0u8; wire::ETH_HEADER_LEN + ip_len];
            EthFrame::emit(dst_mac, self.cfg.mac, ETHERTYPE_IPV4, &ip_buf, &mut frame)?;
            self.push_tx_frame(frame, tx_frames);
        } else {
            if self.arp_pending.len() >= 16 {
                let _ = self.arp_pending.pop_front();
            }
            self.arp_pending.push_back(PendingArpPacket {
                next_hop: hop,
                queued_ms: now_ms,
                ip_packet: ip_buf,
            });
            let arp_req = ArpPacket {
                oper: ARP_OP_REQUEST,
                sha: self.cfg.mac,
                spa: self.cfg.ip,
                tha: MacAddr::ZERO,
                tpa: hop,
            };
            let mut frame = alloc::vec![0u8; wire::ETH_HEADER_LEN + wire::ARP_PACKET_LEN];
            arp_req.emit_eth_frame(MacAddr::BROADCAST, self.cfg.mac, &mut frame)?;
            self.push_tx_frame(frame, tx_frames);
        }
        Ok(())
    }

    /// Process a received Ethernet II frame and enqueue any immediate responses.
    pub fn ingest_frame(
        &mut self,
        now_ms: u64,
        raw_frame: &[u8],
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) {
        let Ok(eth) = EthFrame::parse(raw_frame) else {
            self.stats.rx_drops += 1;
            return;
        };
        if eth.dst != self.cfg.mac && eth.dst != MacAddr::BROADCAST {
            return;
        }
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += raw_frame.len() as u64;

        match eth.ethertype {
            ETHERTYPE_ARP => {
                let Ok(arp) = ArpPacket::parse(eth.payload) else {
                    self.stats.rx_drops += 1;
                    return;
                };
                self.learn_arp(arp.spa, arp.sha, now_ms);
                self.flush_arp_pending(arp.spa, arp.sha, tx_frames);
                if arp.oper == ARP_OP_REQUEST
                    && !self.cfg.ip.is_unspecified()
                    && arp.tpa == self.cfg.ip
                {
                    let reply = ArpPacket {
                        oper: ARP_OP_REPLY,
                        sha: self.cfg.mac,
                        spa: self.cfg.ip,
                        tha: arp.sha,
                        tpa: arp.spa,
                    };
                    let mut frame = alloc::vec![0u8; wire::ETH_HEADER_LEN + wire::ARP_PACKET_LEN];
                    if reply
                        .emit_eth_frame(arp.sha, self.cfg.mac, &mut frame)
                        .is_ok()
                    {
                        self.push_tx_frame(frame, tx_frames);
                    }
                }
            }
            ETHERTYPE_IPV4 => {
                let Ok(ip) = Ipv4Packet::parse(eth.payload) else {
                    self.stats.rx_drops += 1;
                    return;
                };
                if eth.src != self.cfg.mac {
                    let mask = self.cfg.subnet_mask.to_u32();
                    if !self.cfg.ip.is_unspecified()
                        && (ip.src.to_u32() & mask) == (self.cfg.ip.to_u32() & mask)
                    {
                        self.learn_arp(ip.src, eth.src, now_ms);
                        self.flush_arp_pending(ip.src, eth.src, tx_frames);
                    }
                }
                let for_us = ip.dst == self.cfg.ip
                    || ip.dst == Ipv4Addr::BROADCAST
                    || ip.dst.is_loopback()
                    || self.cfg.ip.is_unspecified();
                if !for_us {
                    return;
                }
                match ip.proto {
                    IP_PROTO_ICMP => self.handle_icmp(now_ms, &ip, tx_frames),
                    IP_PROTO_UDP => self.handle_udp(now_ms, &ip, tx_frames),
                    IP_PROTO_TCP => self.handle_tcp(now_ms, &ip, tx_frames),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn handle_icmp(&mut self, now_ms: u64, ip: &Ipv4Packet<'_>, tx_frames: &mut VecDeque<Vec<u8>>) {
        let Ok(echo) = IcmpEcho::parse(ip.payload) else {
            return;
        };
        if echo.icmp_type == ICMP_ECHO_REQUEST && !self.cfg.ip.is_unspecified() {
            let mut reply = alloc::vec![0u8; 8 + echo.data.len()];
            if let Ok(len) =
                IcmpEcho::emit(ICMP_ECHO_REPLY, echo.ident, echo.seq, echo.data, &mut reply)
            {
                let _ =
                    self.send_ipv4_payload(now_ms, ip.src, IP_PROTO_ICMP, &reply[..len], tx_frames);
            }
        } else if echo.icmp_type == ICMP_ECHO_REPLY {
            for p in self.pings.iter_mut() {
                if p.ident == echo.ident && p.seq == echo.seq && p.rtt_us.is_none() {
                    let dt_ms = now_ms.saturating_sub(p.sent_ms);
                    p.rtt_us = Some(((dt_ms * 1_000).max(50)).min(u32::MAX as u64) as u32);
                    p.ttl = ip.ttl;
                    p.reply_bytes = ip.payload.len() as u16;
                    break;
                }
            }
        }
    }

    fn handle_udp(&mut self, now_ms: u64, ip: &Ipv4Packet<'_>, tx_frames: &mut VecDeque<Vec<u8>>) {
        let Ok(udp) = UdpPacket::parse(ip.src, ip.dst, ip.payload) else {
            return;
        };
        if udp.dst_port == DHCP_CLIENT_PORT && udp.src_port == DHCP_SERVER_PORT {
            self.handle_dhcp_udp(now_ms, udp.payload, tx_frames);
            return;
        }
        if udp.src_port == DNS_SERVER_PORT {
            for pending in self.dns_pending.iter_mut() {
                if pending.resolved.is_none() {
                    match parse_dns_response(udp.payload, pending.txid) {
                        Ok((addr, ttl)) => {
                            pending.resolved = Some(Ok(addr));
                            if self.dns_cache.len() >= 32 {
                                let _ = self.dns_cache.remove(0);
                            }
                            self.dns_cache.push(DnsCacheEntry {
                                host: pending.host.clone(),
                                ip: addr,
                                expires_ms: now_ms + u64::from(ttl) * 1_000,
                            });
                            return;
                        }
                        Err(NetError::NotFound) => {
                            pending.resolved = Some(Err(NetError::NotFound));
                            return;
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        if let Some(sock) = self
            .udp_sockets
            .iter_mut()
            .find(|s| s.local_port == udp.dst_port)
        {
            if sock.rx_queue.len() < 32 {
                sock.rx_queue.push_back(UdpDatagram {
                    src: SocketAddrV4 {
                        ip: ip.src,
                        port: udp.src_port,
                    },
                    data: udp.payload.to_vec(),
                });
            }
        }
    }

    fn handle_dhcp_udp(&mut self, now_ms: u64, payload: &[u8], tx_frames: &mut VecDeque<Vec<u8>>) {
        match self.dhcp {
            DhcpState::Discovering { xid, .. } => {
                if let Ok(lease) = parse_dhcp_reply(payload, xid, self.cfg.mac) {
                    if lease.msg_type == DHCP_OFFER {
                        self.dhcp = DhcpState::Requesting {
                            xid,
                            offered: lease,
                            started_ms: now_ms,
                            retries: 0,
                        };
                        let _ = self.emit_dhcp_message(
                            DHCP_REQUEST,
                            xid,
                            Some(lease.ip),
                            Some(lease.server_id),
                            tx_frames,
                        );
                    }
                }
            }
            DhcpState::Requesting { xid, offered, .. } => {
                if let Ok(lease) = parse_dhcp_reply(payload, xid, self.cfg.mac) {
                    if lease.msg_type == DHCP_ACK {
                        let bound = DhcpLease {
                            ip: if lease.ip.is_unspecified() {
                                offered.ip
                            } else {
                                lease.ip
                            },
                            ..lease
                        };
                        self.cfg.ip = bound.ip;
                        self.cfg.subnet_mask = bound.subnet_mask;
                        self.cfg.gateway = bound.gateway;
                        self.cfg.dns_server = bound.dns_server;
                        self.cfg.dhcp_bound = true;
                        self.dhcp = DhcpState::Bound(bound);
                    } else if lease.msg_type == DHCP_NAK {
                        self.start_dhcp(now_ms, tx_frames);
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_tcp(&mut self, now_ms: u64, ip: &Ipv4Packet<'_>, tx_frames: &mut VecDeque<Vec<u8>>) {
        let Ok(seg) = TcpSegment::parse(ip.src, ip.dst, ip.payload) else {
            return;
        };
        self.iss_counter = self.iss_counter.wrapping_add(64_000);
        let iss = self.iss_counter ^ (now_ms as u32);
        let mut outbound = VecDeque::new();

        // Prefer exact 4-tuple match before falling back to a LISTEN socket.
        let match_idx = self
            .tcp_sockets
            .iter()
            .position(|s| {
                s.state != TcpState::Closed
                    && s.state != TcpState::Listen
                    && s.local_port == seg.dst_port
                    && s.remote.ip == ip.src
                    && s.remote.port == seg.src_port
            })
            .or_else(|| {
                self.tcp_sockets
                    .iter()
                    .position(|s| s.state == TcpState::Listen && s.local_port == seg.dst_port)
            });

        if let Some(idx) = match_idx {
            self.tcp_sockets[idx].on_segment(ip.src, &seg, iss, now_ms, &mut outbound);
        } else if (seg.flags & TCP_RST) == 0 {
            let rst_seq = if (seg.flags & TCP_ACK) != 0 {
                seg.ack
            } else {
                0
            };
            let rst_ack = seg.seq.wrapping_add(seg.payload.len().max(1) as u32);
            let flags = if (seg.flags & TCP_ACK) != 0 {
                TCP_RST
            } else {
                TCP_RST | TCP_ACK
            };
            outbound.push_back(OutboundTcp::control(
                seg.dst_port,
                SocketAddrV4 {
                    ip: ip.src,
                    port: seg.src_port,
                },
                rst_seq,
                rst_ack,
                flags,
                0,
                None,
            ));
        }

        self.emit_outbound_tcp(now_ms, &mut outbound, tx_frames);
    }

    fn emit_outbound_tcp(
        &mut self,
        now_ms: u64,
        outbound: &mut VecDeque<OutboundTcp>,
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) {
        while let Some(seg) = outbound.pop_front() {
            let src_ip = if seg.remote.ip.is_loopback() {
                Ipv4Addr::LOOPBACK
            } else {
                self.cfg.ip
            };
            let mut tcp_buf = [0u8; 1500];
            if let Ok(tcp_len) = TcpSegment::emit(
                src_ip,
                seg.remote.ip,
                seg.local_port,
                seg.remote.port,
                seg.seq,
                seg.ack,
                seg.flags,
                seg.window,
                seg.mss,
                &seg.payload[..seg.payload_len],
                &mut tcp_buf,
            ) {
                let _ = self.send_ipv4_payload(
                    now_ms,
                    seg.remote.ip,
                    IP_PROTO_TCP,
                    &tcp_buf[..tcp_len],
                    tx_frames,
                );
            }
        }
    }

    /// Periodic housekeeping: DHCP retries, ARP queue expiry, and TCP RTO timers.
    pub fn poll_timers(&mut self, now_ms: u64, tx_frames: &mut VecDeque<Vec<u8>>) {
        match self.dhcp {
            DhcpState::Discovering {
                xid,
                started_ms,
                retries,
            } if now_ms.saturating_sub(started_ms) >= 1_500 => {
                if retries < 4 {
                    self.dhcp = DhcpState::Discovering {
                        xid,
                        started_ms: now_ms,
                        retries: retries + 1,
                    };
                    let _ = self.emit_dhcp_message(DHCP_DISCOVER, xid, None, None, tx_frames);
                }
            }
            DhcpState::Requesting {
                xid,
                offered,
                started_ms,
                retries,
            } if now_ms.saturating_sub(started_ms) >= 1_500 && retries < 4 => {
                self.dhcp = DhcpState::Requesting {
                    xid,
                    offered,
                    started_ms: now_ms,
                    retries: retries + 1,
                };
                let _ = self.emit_dhcp_message(
                    DHCP_REQUEST,
                    xid,
                    Some(offered.ip),
                    Some(offered.server_id),
                    tx_frames,
                );
            }
            _ => {}
        }

        self.arp_pending
            .retain(|p| now_ms.saturating_sub(p.queued_ms) < 3_000);

        let mut outbound = VecDeque::new();
        for sock in &mut self.tcp_sockets {
            sock.on_timer(now_ms, &mut outbound);
        }
        self.emit_outbound_tcp(now_ms, &mut outbound, tx_frames);
        self.tcp_sockets
            .retain(|s| s.state != TcpState::Closed || !s.rx_buf.is_empty());
    }

    // ---- ICMP Echo Client ----

    pub fn ping_send(
        &mut self,
        now_ms: u64,
        dst: Ipv4Addr,
        ident: u16,
        seq: u16,
        payload_len: usize,
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) -> Result<(), NetError> {
        let len = payload_len.clamp(8, 1400);
        let mut payload = alloc::vec![0u8; len];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = 0x20 + ((i as u8) % 64);
        }
        let mut icmp_buf = alloc::vec![0u8; 8 + len];
        let icmp_len = IcmpEcho::emit(ICMP_ECHO_REQUEST, ident, seq, &payload, &mut icmp_buf)?;
        if self.pings.len() >= 16 {
            let _ = self.pings.pop_front();
        }
        self.pings.push_back(PingResult {
            dst,
            ident,
            seq,
            sent_ms: now_ms,
            rtt_us: None,
            ttl: 0,
            reply_bytes: 0,
        });
        self.send_ipv4_payload(now_ms, dst, IP_PROTO_ICMP, &icmp_buf[..icmp_len], tx_frames)
    }

    pub fn ping_poll(&mut self, ident: u16, seq: u16) -> Option<PingResult> {
        let pos = self
            .pings
            .iter()
            .position(|p| p.ident == ident && p.seq == seq && p.rtt_us.is_some())?;
        self.pings.remove(pos)
    }

    // ---- DNS Stub Resolver ----

    pub fn dns_start(
        &mut self,
        now_ms: u64,
        hostname: &str,
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) -> Result<Result<Ipv4Addr, u16>, NetError> {
        if let Some(ip) = Ipv4Addr::parse_str(hostname) {
            return Ok(Ok(ip));
        }
        if hostname.eq_ignore_ascii_case("localhost") {
            return Ok(Ok(Ipv4Addr::LOOPBACK));
        }
        if let Some(hit) = self
            .dns_cache
            .iter()
            .find(|e| e.expires_ms > now_ms && e.host.eq_ignore_ascii_case(hostname))
        {
            return Ok(Ok(hit.ip));
        }
        if self.cfg.dns_server.is_unspecified() {
            return Err(NetError::InvalidState);
        }
        let txid = self.next_dns_txid;
        self.next_dns_txid = self.next_dns_txid.wrapping_add(1);
        let src_port = self.alloc_ephemeral_port();

        let mut qbuf = [0u8; 300];
        let qlen = build_dns_query(txid, hostname, &mut qbuf)?;
        let mut ubuf = [0u8; 320];
        let ulen = UdpPacket::emit(
            self.cfg.ip,
            self.cfg.dns_server,
            src_port,
            DNS_SERVER_PORT,
            &qbuf[..qlen],
            &mut ubuf,
        )?;
        self.dns_pending
            .retain(|p| now_ms.saturating_sub(p.sent_ms) < 5_000);
        self.dns_pending.push(PendingDns {
            txid,
            host: String::from(hostname),
            sent_ms: now_ms,
            resolved: None,
        });
        self.send_ipv4_payload(
            now_ms,
            self.cfg.dns_server,
            IP_PROTO_UDP,
            &ubuf[..ulen],
            tx_frames,
        )?;
        Ok(Err(txid))
    }

    pub fn dns_poll(&mut self, txid: u16) -> Option<Result<Ipv4Addr, NetError>> {
        let pos = self
            .dns_pending
            .iter()
            .position(|p| p.txid == txid && p.resolved.is_some())?;
        self.dns_pending.remove(pos).resolved
    }

    // ---- UDP Socket API ----

    pub fn udp_bind(&mut self, port: u16) -> Result<(u32, u16), NetError> {
        let actual_port = if port == 0 {
            self.alloc_ephemeral_port()
        } else {
            if self.udp_sockets.iter().any(|s| s.local_port == port) {
                return Err(NetError::PortInUse);
            }
            port
        };
        let id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.wrapping_add(1);
        self.udp_sockets.push(UdpSocket {
            id,
            local_port: actual_port,
            rx_queue: VecDeque::with_capacity(8),
        });
        Ok((id, actual_port))
    }

    pub fn udp_send_to(
        &mut self,
        now_ms: u64,
        sock_id: u32,
        dst: SocketAddrV4,
        payload: &[u8],
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) -> Result<usize, NetError> {
        let local_port = self
            .udp_sockets
            .iter()
            .find(|s| s.id == sock_id)
            .map(|s| s.local_port)
            .ok_or(NetError::NotFound)?;
        let src_ip = if dst.ip.is_loopback() {
            Ipv4Addr::LOOPBACK
        } else {
            self.cfg.ip
        };
        let mut ubuf = alloc::vec![0u8; wire::UDP_HEADER_LEN + payload.len()];
        let ulen = UdpPacket::emit(src_ip, dst.ip, local_port, dst.port, payload, &mut ubuf)?;
        self.send_ipv4_payload(now_ms, dst.ip, IP_PROTO_UDP, &ubuf[..ulen], tx_frames)?;
        Ok(payload.len())
    }

    pub fn udp_recv_from(&mut self, sock_id: u32) -> Result<UdpDatagram, NetError> {
        let sock = self
            .udp_sockets
            .iter_mut()
            .find(|s| s.id == sock_id)
            .ok_or(NetError::NotFound)?;
        sock.rx_queue.pop_front().ok_or(NetError::WouldBlock)
    }

    pub fn udp_close(&mut self, sock_id: u32) -> bool {
        if let Some(pos) = self.udp_sockets.iter().position(|s| s.id == sock_id) {
            let _ = self.udp_sockets.remove(pos);
            true
        } else {
            false
        }
    }

    // ---- TCP Socket API ----

    pub fn tcp_connect(
        &mut self,
        now_ms: u64,
        remote: SocketAddrV4,
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) -> Result<u32, NetError> {
        if self.cfg.ip.is_unspecified() && !remote.ip.is_loopback() {
            return Err(NetError::InvalidState);
        }
        let id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.wrapping_add(1);
        let local_port = self.alloc_ephemeral_port();
        self.iss_counter = self.iss_counter.wrapping_add(64_000);
        let iss = self.iss_counter ^ (now_ms as u32);
        let (sock, syn) = TcpSocket::new_connect(id, local_port, remote, iss, now_ms);
        self.tcp_sockets.push(sock);
        let mut outbound = VecDeque::new();
        outbound.push_back(syn);
        self.emit_outbound_tcp(now_ms, &mut outbound, tx_frames);
        Ok(id)
    }

    pub fn tcp_listen(&mut self, local_port: u16) -> Result<u32, NetError> {
        if self
            .tcp_sockets
            .iter()
            .any(|s| s.state == TcpState::Listen && s.local_port == local_port)
        {
            return Err(NetError::PortInUse);
        }
        let id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.wrapping_add(1);
        self.tcp_sockets.push(TcpSocket::new_listen(id, local_port));
        Ok(id)
    }

    pub fn tcp_state(&self, sock_id: u32) -> Option<(TcpState, bool)> {
        self.tcp_sockets
            .iter()
            .find(|s| s.id == sock_id)
            .map(|s| (s.state, s.reset_error))
    }

    pub fn tcp_send(
        &mut self,
        now_ms: u64,
        sock_id: u32,
        data: &[u8],
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) -> Result<usize, NetError> {
        let idx = self
            .tcp_sockets
            .iter()
            .position(|s| s.id == sock_id)
            .ok_or(NetError::NotFound)?;
        let n = self.tcp_sockets[idx].enqueue_send(data)?;
        let mut outbound = VecDeque::new();
        self.tcp_sockets[idx].flush_unsent(now_ms, &mut outbound);
        self.emit_outbound_tcp(now_ms, &mut outbound, tx_frames);
        Ok(n)
    }

    pub fn tcp_recv(&mut self, sock_id: u32, out: &mut [u8]) -> Result<usize, NetError> {
        let sock = self
            .tcp_sockets
            .iter_mut()
            .find(|s| s.id == sock_id)
            .ok_or(NetError::NotFound)?;
        sock.dequeue_recv(out)
    }

    pub fn tcp_close(
        &mut self,
        now_ms: u64,
        sock_id: u32,
        tx_frames: &mut VecDeque<Vec<u8>>,
    ) -> bool {
        let Some(idx) = self.tcp_sockets.iter().position(|s| s.id == sock_id) else {
            return false;
        };
        self.tcp_sockets[idx].initiate_close();
        let mut outbound = VecDeque::new();
        self.tcp_sockets[idx].flush_unsent(now_ms, &mut outbound);
        self.emit_outbound_tcp(now_ms, &mut outbound, tx_frames);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pump_pair(
        now_ms: u64,
        a: &mut NetStack,
        q_a: &mut VecDeque<Vec<u8>>,
        b: &mut NetStack,
        q_b: &mut VecDeque<Vec<u8>>,
    ) {
        for _ in 0..32 {
            if q_a.is_empty() && q_b.is_empty() {
                break;
            }
            while let Some(f) = q_a.pop_front() {
                b.ingest_frame(now_ms, &f, q_b);
            }
            while let Some(f) = q_b.pop_front() {
                a.ingest_frame(now_ms, &f, q_a);
            }
        }
    }

    #[test]
    fn arp_icmp_udp_and_tcp_http_end_to_end_between_two_stacks() {
        let mut client = NetStack::new(MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
        client.configure_static(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 0, 2, 2),
            Ipv4Addr::new(10, 0, 2, 3),
        );
        let mut server = NetStack::new(MacAddr([0x52, 0x55, 0x0A, 0x00, 0x02, 0x02]));
        server.configure_static(
            Ipv4Addr::new(10, 0, 2, 2),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 0, 2, 2),
            Ipv4Addr::new(10, 0, 2, 3),
        );

        let mut qc = VecDeque::new();
        let mut qs = VecDeque::new();

        // 1. ICMP Echo triggers ARP resolution + Echo Reply.
        assert_eq!(
            client.ping_send(100, Ipv4Addr::new(10, 0, 2, 2), 0xBEEF, 1, 32, &mut qc),
            Ok(())
        );
        pump_pair(105, &mut client, &mut qc, &mut server, &mut qs);
        let reply = client.ping_poll(0xBEEF, 1);
        assert!(reply.is_some());

        // 2. TCP 3-way handshake + HTTP GET/200 OK + clean FIN teardown.
        let srv_id = server.tcp_listen(80).unwrap_or(0);
        assert!(srv_id != 0);
        let cli_id = client
            .tcp_connect(
                200,
                SocketAddrV4 {
                    ip: Ipv4Addr::new(10, 0, 2, 2),
                    port: 80,
                },
                &mut qc,
            )
            .unwrap_or(0);
        pump_pair(205, &mut client, &mut qc, &mut server, &mut qs);
        assert_eq!(
            client.tcp_state(cli_id),
            Some((TcpState::Established, false))
        );
        assert_eq!(
            server.tcp_state(srv_id),
            Some((TcpState::Established, false))
        );

        let req = b"GET / HTTP/1.1\r\nHost: 10.0.2.2\r\n\r\n";
        assert_eq!(client.tcp_send(210, cli_id, req, &mut qc), Ok(req.len()));
        pump_pair(215, &mut client, &mut qc, &mut server, &mut qs);

        let mut rbuf = [0u8; 128];
        let got_req = server.tcp_recv(srv_id, &mut rbuf).unwrap_or(0);
        assert_eq!(&rbuf[..got_req], req);

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        assert_eq!(server.tcp_send(220, srv_id, resp, &mut qs), Ok(resp.len()));
        assert!(server.tcp_close(221, srv_id, &mut qs));
        pump_pair(225, &mut client, &mut qc, &mut server, &mut qs);

        let got_resp = client.tcp_recv(cli_id, &mut rbuf).unwrap_or(0);
        assert_eq!(&rbuf[..got_resp], resp);
        // Next recv after peer FIN returns clean EOF (0 bytes).
        assert_eq!(client.tcp_recv(cli_id, &mut rbuf), Ok(0));
    }

    #[test]
    fn dns_compressed_pointer_and_dhcp_offer_ack_parsing() {
        let mut qbuf = [0u8; 128];
        let qlen = build_dns_query(0x4242, "example.com", &mut qbuf).unwrap_or(0);
        assert!(qlen > 16);

        // Craft a DNS response using RFC 1035 0xC00C pointer compression -> 93.184.216.34
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x4242u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
        resp.extend_from_slice(&[0, 0, 0, 0]);
        resp.extend_from_slice(&qbuf[12..qlen]);
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&[93, 184, 216, 34]);

        assert_eq!(
            parse_dns_response(&resp, 0x4242),
            Ok((Ipv4Addr::new(93, 184, 216, 34), 300))
        );
    }
}
