//! Zero-unsafe wire-format parsers and builders for Ethernet II, ARP, IPv4,
//! ICMPv4, UDP, and TCP.

use crate::{internet_checksum, pseudo_header_checksum, Ipv4Addr, MacAddr, NetError};

pub const ETH_HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_EAPOL: u16 = 0x888E;

pub const ARP_PACKET_LEN: usize = 28;
pub const ARP_HTYPE_ETHERNET: u16 = 1;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

pub const IPV4_MIN_HEADER_LEN: usize = 20;
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

pub const UDP_HEADER_LEN: usize = 8;
pub const TCP_MIN_HEADER_LEN: usize = 20;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// Parsed Ethernet II frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthFrame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> EthFrame<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, NetError> {
        if raw.len() < ETH_HEADER_LEN {
            return Err(NetError::Truncated);
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&raw[0..6]);
        src.copy_from_slice(&raw[6..12]);
        let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
        Ok(Self {
            dst: MacAddr(dst),
            src: MacAddr(src),
            ethertype,
            payload: &raw[ETH_HEADER_LEN..],
        })
    }

    pub fn emit(
        dst: MacAddr,
        src: MacAddr,
        ethertype: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, NetError> {
        let total = ETH_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(NetError::BufferTooSmall)?;
        if out.len() < total {
            return Err(NetError::BufferTooSmall);
        }
        out[0..6].copy_from_slice(&dst.0);
        out[6..12].copy_from_slice(&src.0);
        out[12..14].copy_from_slice(&ethertype.to_be_bytes());
        out[ETH_HEADER_LEN..total].copy_from_slice(payload);
        Ok(total)
    }
}

/// Parsed IPv4-over-Ethernet ARP packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpPacket {
    pub oper: u16,
    pub sha: MacAddr,
    pub spa: Ipv4Addr,
    pub tha: MacAddr,
    pub tpa: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(raw: &[u8]) -> Result<Self, NetError> {
        if raw.len() < ARP_PACKET_LEN {
            return Err(NetError::Truncated);
        }
        let htype = u16::from_be_bytes([raw[0], raw[1]]);
        let ptype = u16::from_be_bytes([raw[2], raw[3]]);
        let hlen = raw[4];
        let plen = raw[5];
        if htype != ARP_HTYPE_ETHERNET || ptype != ETHERTYPE_IPV4 || hlen != 6 || plen != 4 {
            return Err(NetError::Malformed);
        }
        let oper = u16::from_be_bytes([raw[6], raw[7]]);
        let mut sha = [0u8; 6];
        let mut spa = [0u8; 4];
        let mut tha = [0u8; 6];
        let mut tpa = [0u8; 4];
        sha.copy_from_slice(&raw[8..14]);
        spa.copy_from_slice(&raw[14..18]);
        tha.copy_from_slice(&raw[18..24]);
        tpa.copy_from_slice(&raw[24..28]);
        Ok(Self {
            oper,
            sha: MacAddr(sha),
            spa: Ipv4Addr(spa),
            tha: MacAddr(tha),
            tpa: Ipv4Addr(tpa),
        })
    }

    pub fn emit(&self, out: &mut [u8]) -> Result<usize, NetError> {
        if out.len() < ARP_PACKET_LEN {
            return Err(NetError::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        out[4] = 6;
        out[5] = 4;
        out[6..8].copy_from_slice(&self.oper.to_be_bytes());
        out[8..14].copy_from_slice(&self.sha.0);
        out[14..18].copy_from_slice(&self.spa.0);
        out[18..24].copy_from_slice(&self.tha.0);
        out[24..28].copy_from_slice(&self.tpa.0);
        Ok(ARP_PACKET_LEN)
    }

    pub fn emit_eth_frame(
        &self,
        dst: MacAddr,
        src: MacAddr,
        out: &mut [u8],
    ) -> Result<usize, NetError> {
        let mut arp_buf = [0u8; ARP_PACKET_LEN];
        self.emit(&mut arp_buf)?;
        EthFrame::emit(dst, src, ETHERTYPE_ARP, &arp_buf, out)
    }
}

/// Parsed IPv4 packet view (unfragmented).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Packet<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub ttl: u8,
    pub ident: u16,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, NetError> {
        if raw.len() < IPV4_MIN_HEADER_LEN {
            return Err(NetError::Truncated);
        }
        let ver_ihl = raw[0];
        if (ver_ihl >> 4) != 4 {
            return Err(NetError::Malformed);
        }
        let ihl = usize::from(ver_ihl & 0x0F) * 4;
        if ihl < IPV4_MIN_HEADER_LEN || raw.len() < ihl {
            return Err(NetError::Malformed);
        }
        let total_len = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
        if total_len < ihl || total_len > raw.len() {
            return Err(NetError::Malformed);
        }
        let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
        // Reject MF=1 or non-zero fragment offset (DF=0x4000 is allowed).
        if (flags_frag & 0x3FFF) != 0 {
            return Err(NetError::Unsupported);
        }
        if internet_checksum(&raw[..ihl]) != 0 {
            return Err(NetError::BadChecksum);
        }
        let mut src = [0u8; 4];
        let mut dst = [0u8; 4];
        src.copy_from_slice(&raw[12..16]);
        dst.copy_from_slice(&raw[16..20]);
        Ok(Self {
            src: Ipv4Addr(src),
            dst: Ipv4Addr(dst),
            proto: raw[9],
            ttl: raw[8],
            ident: u16::from_be_bytes([raw[4], raw[5]]),
            payload: &raw[ihl..total_len],
        })
    }

    pub fn emit(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        ttl: u8,
        ident: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, NetError> {
        let total = IPV4_MIN_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(NetError::BufferTooSmall)?;
        if total > usize::from(u16::MAX) || out.len() < total {
            return Err(NetError::BufferTooSmall);
        }
        out[0] = 0x45;
        out[1] = 0;
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[4..6].copy_from_slice(&ident.to_be_bytes());
        out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        out[8] = ttl;
        out[9] = proto;
        out[10] = 0;
        out[11] = 0;
        out[12..16].copy_from_slice(&src.0);
        out[16..20].copy_from_slice(&dst.0);
        let csum = internet_checksum(&out[..IPV4_MIN_HEADER_LEN]);
        out[10..12].copy_from_slice(&csum.to_be_bytes());
        out[IPV4_MIN_HEADER_LEN..total].copy_from_slice(payload);
        Ok(total)
    }
}

/// Parsed ICMPv4 Echo packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpEcho<'a> {
    pub icmp_type: u8,
    pub code: u8,
    pub ident: u16,
    pub seq: u16,
    pub data: &'a [u8],
}

impl<'a> IcmpEcho<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, NetError> {
        if raw.len() < 8 {
            return Err(NetError::Truncated);
        }
        if internet_checksum(raw) != 0 {
            return Err(NetError::BadChecksum);
        }
        Ok(Self {
            icmp_type: raw[0],
            code: raw[1],
            ident: u16::from_be_bytes([raw[4], raw[5]]),
            seq: u16::from_be_bytes([raw[6], raw[7]]),
            data: &raw[8..],
        })
    }

    pub fn emit(
        icmp_type: u8,
        ident: u16,
        seq: u16,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, NetError> {
        let total = 8usize
            .checked_add(data.len())
            .ok_or(NetError::BufferTooSmall)?;
        if out.len() < total {
            return Err(NetError::BufferTooSmall);
        }
        out[0] = icmp_type;
        out[1] = 0;
        out[2] = 0;
        out[3] = 0;
        out[4..6].copy_from_slice(&ident.to_be_bytes());
        out[6..8].copy_from_slice(&seq.to_be_bytes());
        out[8..total].copy_from_slice(data);
        let csum = internet_checksum(&out[..total]);
        out[2..4].copy_from_slice(&csum.to_be_bytes());
        Ok(total)
    }
}

/// Parsed UDP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpPacket<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn parse(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, raw: &'a [u8]) -> Result<Self, NetError> {
        if raw.len() < UDP_HEADER_LEN {
            return Err(NetError::Truncated);
        }
        let len = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
        if len < UDP_HEADER_LEN || len > raw.len() {
            return Err(NetError::Malformed);
        }
        let csum = u16::from_be_bytes([raw[6], raw[7]]);
        if csum != 0 && pseudo_header_checksum(src_ip, dst_ip, IP_PROTO_UDP, &raw[..len]) != 0 {
            return Err(NetError::BadChecksum);
        }
        Ok(Self {
            src_port: u16::from_be_bytes([raw[0], raw[1]]),
            dst_port: u16::from_be_bytes([raw[2], raw[3]]),
            payload: &raw[UDP_HEADER_LEN..len],
        })
    }

    pub fn emit(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, NetError> {
        let total = UDP_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(NetError::BufferTooSmall)?;
        if total > usize::from(u16::MAX) || out.len() < total {
            return Err(NetError::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
        out[6] = 0;
        out[7] = 0;
        out[UDP_HEADER_LEN..total].copy_from_slice(payload);
        let mut csum = pseudo_header_checksum(src_ip, dst_ip, IP_PROTO_UDP, &out[..total]);
        if csum == 0 {
            csum = 0xFFFF;
        }
        out[6..8].copy_from_slice(&csum.to_be_bytes());
        Ok(total)
    }
}

/// Parsed TCP segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn parse(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, raw: &'a [u8]) -> Result<Self, NetError> {
        if raw.len() < TCP_MIN_HEADER_LEN {
            return Err(NetError::Truncated);
        }
        let data_off = usize::from(raw[12] >> 4) * 4;
        if data_off < TCP_MIN_HEADER_LEN || data_off > raw.len() {
            return Err(NetError::Malformed);
        }
        if pseudo_header_checksum(src_ip, dst_ip, IP_PROTO_TCP, raw) != 0 {
            return Err(NetError::BadChecksum);
        }
        let mut mss = None;
        let opts = &raw[TCP_MIN_HEADER_LEN..data_off];
        let mut idx = 0usize;
        while idx < opts.len() {
            let kind = opts[idx];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                idx += 1;
                continue;
            }
            if idx + 1 >= opts.len() {
                break;
            }
            let opt_len = usize::from(opts[idx + 1]);
            if opt_len < 2 || idx + opt_len > opts.len() {
                break;
            }
            if kind == 2 && opt_len == 4 {
                mss = Some(u16::from_be_bytes([opts[idx + 2], opts[idx + 3]]));
            }
            idx += opt_len;
        }
        Ok(Self {
            src_port: u16::from_be_bytes([raw[0], raw[1]]),
            dst_port: u16::from_be_bytes([raw[2], raw[3]]),
            seq: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            ack: u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
            flags: raw[13],
            window: u16::from_be_bytes([raw[14], raw[15]]),
            mss,
            payload: &raw[data_off..],
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        mss: Option<u16>,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, NetError> {
        let opt_len = if mss.is_some() { 4usize } else { 0usize };
        let hdr_len = TCP_MIN_HEADER_LEN + opt_len;
        let total = hdr_len
            .checked_add(payload.len())
            .ok_or(NetError::BufferTooSmall)?;
        if total > usize::from(u16::MAX) || out.len() < total {
            return Err(NetError::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out[4..8].copy_from_slice(&seq.to_be_bytes());
        out[8..12].copy_from_slice(&ack.to_be_bytes());
        out[12] = ((hdr_len / 4) as u8) << 4;
        out[13] = flags;
        out[14..16].copy_from_slice(&window.to_be_bytes());
        out[16..20].fill(0);
        if let Some(m) = mss {
            out[20] = 2;
            out[21] = 4;
            out[22..24].copy_from_slice(&m.to_be_bytes());
        }
        out[hdr_len..total].copy_from_slice(payload);
        let csum = pseudo_header_checksum(src_ip, dst_ip, IP_PROTO_TCP, &out[..total]);
        out[16..18].copy_from_slice(&csum.to_be_bytes());
        Ok(total)
    }
}
