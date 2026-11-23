//! DHCPv4 client (`DISCOVER -> OFFER -> REQUEST -> ACK`) and RFC 1035 DNS stub
//! resolver with bounded compressed-pointer decoding and TTL cache.

use crate::{Ipv4Addr, MacAddr, NetError};

pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DNS_SERVER_PORT: u16 = 53;

const DHCP_BOOTREQUEST: u8 = 1;
const DHCP_BOOTREPLY: u8 = 2;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;

/// Negotiated IPv4 parameters extracted from DHCP OFFER / ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns_server: Ipv4Addr,
    pub server_id: Ipv4Addr,
    pub lease_secs: u32,
    pub msg_type: u8,
}

/// DHCPv4 client state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhcpState {
    Idle,
    Discovering {
        xid: u32,
        started_ms: u64,
        retries: u8,
    },
    Requesting {
        xid: u32,
        offered: DhcpLease,
        started_ms: u64,
        retries: u8,
    },
    Bound(DhcpLease),
}

/// Build a DHCP DISCOVER or REQUEST UDP payload.
pub fn build_dhcp_packet(
    msg_type: u8,
    xid: u32,
    client_mac: MacAddr,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    out: &mut [u8],
) -> Result<usize, NetError> {
    if out.len() < 300 {
        return Err(NetError::BufferTooSmall);
    }
    out[..300].fill(0);
    out[0] = DHCP_BOOTREQUEST;
    out[1] = 1; // Ethernet
    out[2] = 6; // MAC len
    out[3] = 0;
    out[4..8].copy_from_slice(&xid.to_be_bytes());
    out[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // Broadcast flag
    out[28..34].copy_from_slice(&client_mac.0);
    out[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    let mut pos = 240usize;
    // Option 53: DHCP Message Type
    out[pos] = 53;
    out[pos + 1] = 1;
    out[pos + 2] = msg_type;
    pos += 3;

    // Option 61: Client Identifier
    out[pos] = 61;
    out[pos + 1] = 7;
    out[pos + 2] = 1;
    out[pos + 3..pos + 9].copy_from_slice(&client_mac.0);
    pos += 9;

    if let Some(req_ip) = requested_ip {
        out[pos] = 50;
        out[pos + 1] = 4;
        out[pos + 2..pos + 6].copy_from_slice(&req_ip.0);
        pos += 6;
    }
    if let Some(srv) = server_id {
        out[pos] = 54;
        out[pos + 1] = 4;
        out[pos + 2..pos + 6].copy_from_slice(&srv.0);
        pos += 6;
    }

    // Option 55: Parameter Request List (Subnet Mask, Router, DNS, Domain Name)
    out[pos] = 55;
    out[pos + 1] = 4;
    out[pos + 2..pos + 6].copy_from_slice(&[1, 3, 6, 15]);
    pos += 6;

    // Option 255: End
    out[pos] = 255;
    pos += 1;
    Ok(pos.max(300))
}

/// Parse a DHCP OFFER / ACK / NAK reply matching `expected_xid` and `client_mac`.
pub fn parse_dhcp_reply(
    raw: &[u8],
    expected_xid: u32,
    client_mac: MacAddr,
) -> Result<DhcpLease, NetError> {
    if raw.len() < 240 {
        return Err(NetError::Truncated);
    }
    if raw[0] != DHCP_BOOTREPLY || raw[1] != 1 || raw[2] != 6 {
        return Err(NetError::Malformed);
    }
    let xid = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    if xid != expected_xid || raw[28..34] != client_mac.0 {
        return Err(NetError::Malformed);
    }
    if raw[236..240] != DHCP_MAGIC_COOKIE {
        return Err(NetError::Malformed);
    }

    let yiaddr = Ipv4Addr([raw[16], raw[17], raw[18], raw[19]]);
    let siaddr = Ipv4Addr([raw[20], raw[21], raw[22], raw[23]]);

    let mut msg_type = 0u8;
    let mut subnet_mask = Ipv4Addr([255, 255, 255, 0]);
    let mut gateway = siaddr;
    let mut dns_server = siaddr;
    let mut server_id = siaddr;
    let mut lease_secs = 3600u32;

    let opts = &raw[240..];
    let mut idx = 0usize;
    while idx < opts.len() {
        let code = opts[idx];
        if code == 255 {
            break;
        }
        if code == 0 {
            idx += 1;
            continue;
        }
        if idx + 1 >= opts.len() {
            break;
        }
        let len = usize::from(opts[idx + 1]);
        if idx + 2 + len > opts.len() {
            break;
        }
        let val = &opts[idx + 2..idx + 2 + len];
        match code {
            1 if len >= 4 => subnet_mask = Ipv4Addr([val[0], val[1], val[2], val[3]]),
            3 if len >= 4 => gateway = Ipv4Addr([val[0], val[1], val[2], val[3]]),
            6 if len >= 4 => dns_server = Ipv4Addr([val[0], val[1], val[2], val[3]]),
            51 if len == 4 => {
                lease_secs = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
            }
            53 if len == 1 => msg_type = val[0],
            54 if len == 4 => server_id = Ipv4Addr([val[0], val[1], val[2], val[3]]),
            _ => {}
        }
        idx += 2 + len;
    }

    if msg_type == 0 {
        return Err(NetError::Malformed);
    }
    Ok(DhcpLease {
        ip: yiaddr,
        subnet_mask,
        gateway,
        dns_server,
        server_id,
        lease_secs,
        msg_type,
    })
}

/// Build an RFC 1035 DNS A-record query (`RD = 1`, `QDCOUNT = 1`).
pub fn build_dns_query(txid: u16, hostname: &str, out: &mut [u8]) -> Result<usize, NetError> {
    let trimmed = hostname.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(NetError::InvalidInput);
    }
    if out.len() < 12 + trimmed.len() + 6 {
        return Err(NetError::BufferTooSmall);
    }
    out[0..2].copy_from_slice(&txid.to_be_bytes());
    out[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    out[6..12].fill(0);

    let mut pos = 12usize;
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(NetError::InvalidInput);
        }
        if pos + 1 + bytes.len() + 5 > out.len() {
            return Err(NetError::BufferTooSmall);
        }
        out[pos] = bytes.len() as u8;
        out[pos + 1..pos + 1 + bytes.len()].copy_from_slice(bytes);
        pos += 1 + bytes.len();
    }
    out[pos] = 0; // root label
    out[pos + 1..pos + 3].copy_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    out[pos + 3..pos + 5].copy_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(pos + 5)
}

/// Skip an RFC 1035 domain name starting at `offset`, following compressed
/// pointers safely with a hop limit so cyclic pointers never loop.
fn skip_dns_name(packet: &[u8], start: usize) -> Result<usize, NetError> {
    let mut idx = start;
    let mut end_after_first_jump = None;
    let mut hops = 0usize;
    loop {
        if idx >= packet.len() || hops > 64 {
            return Err(NetError::Malformed);
        }
        let b = packet[idx];
        if b == 0 {
            let next = idx + 1;
            return Ok(end_after_first_jump.unwrap_or(next));
        }
        if (b & 0xC0) == 0xC0 {
            if idx + 1 >= packet.len() {
                return Err(NetError::Truncated);
            }
            if end_after_first_jump.is_none() {
                end_after_first_jump = Some(idx + 2);
            }
            let ptr = usize::from(u16::from_be_bytes([b & 0x3F, packet[idx + 1]]));
            if ptr >= packet.len() {
                return Err(NetError::Malformed);
            }
            idx = ptr;
            hops += 1;
        } else if (b & 0xC0) == 0 {
            let label_len = usize::from(b);
            if idx + 1 + label_len > packet.len() {
                return Err(NetError::Truncated);
            }
            idx += 1 + label_len;
            hops += 1;
        } else {
            return Err(NetError::Malformed);
        }
    }
}

/// Parse an RFC 1035 DNS response matching `expected_txid`, returning the first
/// IPv4 `A` record (`TYPE = 1`, `CLASS = 1`, `RDLENGTH = 4`) and its TTL.
pub fn parse_dns_response(raw: &[u8], expected_txid: u16) -> Result<(Ipv4Addr, u32), NetError> {
    if raw.len() < 12 {
        return Err(NetError::Truncated);
    }
    let txid = u16::from_be_bytes([raw[0], raw[1]]);
    let flags = u16::from_be_bytes([raw[2], raw[3]]);
    if txid != expected_txid || (flags & 0x8000) == 0 {
        return Err(NetError::Malformed);
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(NetError::NotFound);
    }
    let qdcount = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
    let ancount = usize::from(u16::from_be_bytes([raw[6], raw[7]]));

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(raw, pos)?;
        if pos + 4 > raw.len() {
            return Err(NetError::Truncated);
        }
        pos += 4;
    }

    for _ in 0..ancount {
        pos = skip_dns_name(raw, pos)?;
        if pos + 10 > raw.len() {
            return Err(NetError::Truncated);
        }
        let rtype = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let rclass = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]);
        let ttl = u32::from_be_bytes([raw[pos + 4], raw[pos + 5], raw[pos + 6], raw[pos + 7]]);
        let rdlen = usize::from(u16::from_be_bytes([raw[pos + 8], raw[pos + 9]]));
        pos += 10;
        if pos + rdlen > raw.len() {
            return Err(NetError::Truncated);
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let ip = Ipv4Addr([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
            return Ok((ip, ttl.clamp(5, 3600)));
        }
        pos += rdlen;
    }

    Err(NetError::NotFound)
}
