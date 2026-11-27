//! Wire protocol for the Plan 9 `/net/btl` Bluetooth transport service
//! (`/services/btl.elf`) and the `driver-host-xhci` USB-HCI bridge (`UBTH`).
//!
//! Architectural invariant: `/net/btl` is a pure HCI + L2CAP + SDP network
//! transport layer. Audio codecs and media profiles (`AVDTP`, `A2DP`, `SBC`,
//! `AVRCP`) run in `audio-service` over `/net/btl` L2CAP channels. Raw 128-bit
//! Bluetooth Link Keys never leave `btl-service`.

#![forbid(unsafe_code)]

/// Wire magic `"HBTL"` in little-endian.
pub const MAGIC: u32 = 0x4C54_4248;
/// Protocol version.
pub const VERSION: u16 = 1;
/// Maximum Bluetooth peer friendly name bytes carried in one record.
pub const MAX_PEER_NAME_LEN: usize = 48;
/// Maximum peers returned in a single `ListPeers` reply.
pub const MAX_PEERS: usize = 16;
/// Maximum non-secret link-key summaries returned in a single `ListKeys` reply.
pub const MAX_KEY_SUMMARIES: usize = 16;
/// Maximum L2CAP payload bytes carried in a single IPC message (`<= 1200` channel limit).
pub const MAX_L2CAP_IPC_PAYLOAD: usize = 1024;

/// Wire magic `"UBTH"` in little-endian for the internal `driver-host-xhci <-> btl-service` bridge.
pub const USB_BT_MAGIC: u32 = 0x4854_4255;

/// `/net/btl` IPC opcodes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtlOp {
    /// Query local adapter telemetry, firmware version, ACL credits, and coex state.
    Status = 1,
    /// Run Bluetooth Classic Inquiry + Extended Inquiry / Remote Name discovery.
    Scan = 2,
    /// Return discovered and connected peers.
    ListPeers = 3,
    /// Pair (SSP Just-Works) and persist the resulting Link Key on `HxFS`.
    Pair = 4,
    /// Establish an encrypted ACL baseband link to a peer.
    ConnectAcl = 5,
    /// Disconnect an active ACL baseband link.
    DisconnectAcl = 6,
    /// Return non-secret 4-byte SHA-256 fingerprints of stored Link Keys.
    ListKeys = 7,
    /// Delete a stored Link Key for a peer `BD_ADDR`.
    DeleteKey = 8,
    /// Query a remote peer's SDP server for a 16-bit Service Class UUID.
    SdpQuery = 9,
    /// Open an outbound L2CAP connection-oriented channel (`bd_addr`, `psm`).
    L2capConnect = 10,
    /// Register an inbound L2CAP listener for `psm`.
    L2capListen = 11,
    /// Poll for the next accepted inbound L2CAP channel on a registered `psm`.
    L2capAccept = 12,
    /// Transmit an L2CAP SDU on `cid_handle` and return live ACL congestion metrics.
    L2capSend = 13,
    /// Non-blocking receive of the next L2CAP SDU from `cid_handle`.
    L2capRecv = 14,
    /// Close an open `cid_handle`.
    L2capClose = 15,
    /// Read a slice of the `btsnoop` v1 capture buffer (`/net/btl/snoop`).
    ReadSnoop = 16,
    /// Enable/disable the adapter or attach the deterministic virtual headset peer.
    SetPower = 17,
    /// Notify `btl-service` whether latency-sensitive L2CAP streaming is active (for PTA coex).
    SetCoexHint = 18,
}

impl BtlOp {
    /// Decode a raw opcode byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Status,
            2 => Self::Scan,
            3 => Self::ListPeers,
            4 => Self::Pair,
            5 => Self::ConnectAcl,
            6 => Self::DisconnectAcl,
            7 => Self::ListKeys,
            8 => Self::DeleteKey,
            9 => Self::SdpQuery,
            10 => Self::L2capConnect,
            11 => Self::L2capListen,
            12 => Self::L2capAccept,
            13 => Self::L2capSend,
            14 => Self::L2capRecv,
            15 => Self::L2capClose,
            16 => Self::ReadSnoop,
            17 => Self::SetPower,
            18 => Self::SetCoexHint,
            _ => return None,
        })
    }

    /// True when `caps_mask::BTL_ADMIN` (`btl=admin`) is required.
    pub const fn requires_admin(self) -> bool {
        matches!(
            self,
            Self::Scan
                | Self::Pair
                | Self::ConnectAcl
                | Self::DisconnectAcl
                | Self::DeleteKey
                | Self::SetPower
        )
    }

    /// True when `caps_mask::BTL_RW` (`btl=rw` or `btl=admin`) is required.
    pub const fn requires_rw(self) -> bool {
        matches!(
            self,
            Self::SdpQuery
                | Self::L2capConnect
                | Self::L2capListen
                | Self::L2capAccept
                | Self::L2capSend
                | Self::L2capRecv
                | Self::L2capClose
                | Self::SetCoexHint
        )
    }
}

/// Reply status codes from `btl-service`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtlStatus {
    /// Operation succeeded.
    Ok = 0,
    /// Malformed request payload.
    InvalidRequest = 1,
    /// Caller lacks required `BTL_RO` / `BTL_RW` / `BTL_ADMIN` capability rights.
    AccessDenied = 2,
    /// No USB Bluetooth controller (and virtual radio not enabled) is present.
    HardwareAbsent = 3,
    /// Controller firmware (`rtl8821c_fw.bin`) upload failed.
    FirmwareFailed = 4,
    /// Target peer did not respond or ACL link is not connected.
    NotConnected = 5,
    /// Pairing / authentication failed.
    AuthFailed = 6,
    /// Requested SDP service or L2CAP PSM was not found / refused.
    Refused = 7,
    /// Non-blocking `L2capRecv` or `L2capAccept` has no pending packet right now.
    WouldBlock = 8,
    /// L2CAP channel was closed by the remote peer.
    ChannelClosed = 9,
    /// Outbound ACL queue is momentarily full (backpressure).
    Congested = 10,
}

impl BtlStatus {
    /// Decode a wire status byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Ok,
            1 => Self::InvalidRequest,
            2 => Self::AccessDenied,
            3 => Self::HardwareAbsent,
            4 => Self::FirmwareFailed,
            5 => Self::NotConnected,
            6 => Self::AuthFailed,
            7 => Self::Refused,
            8 => Self::WouldBlock,
            9 => Self::ChannelClosed,
            10 => Self::Congested,
            _ => return None,
        })
    }
}

/// Active Bluetooth transport backend attached to `btl-service`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BtlTransportKind {
    /// No Bluetooth controller attached.
    #[default]
    Absent = 0,
    /// Realtek `RTL8821CE` USB Bluetooth HCI (`0bda:c821` / `0bda:b00a` / family) with `btrtl` patch.
    UsbRealtek8821c = 1,
    /// Generic USB Wireless Bluetooth HCI (`0xE0/0x01/0x01`).
    UsbGenericHci = 2,
    /// Deterministic virtual HCI + `"HuesOS AirBuds Pro"` peer (`boot-selftest` / QEMU).
    VirtualLoopback = 3,
}

impl BtlTransportKind {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Absent,
            1 => Self::UsbRealtek8821c,
            2 => Self::UsbGenericHci,
            3 => Self::VirtualLoopback,
            _ => return None,
        })
    }

    /// Canonical backend name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::UsbRealtek8821c => "usb-rtl8821ce",
            Self::UsbGenericHci => "usb-bt-hci",
            Self::VirtualLoopback => "virtual-airbuds",
        }
    }
}

/// Fixed 64-byte status snapshot returned by [`BtlOp::Status`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BtlStatusSnapshot {
    /// Active hardware/virtual transport backend.
    pub transport: BtlTransportKind,
    /// Adapter powered on.
    pub powered: bool,
    /// Vendor firmware (`rtl8821c_fw.bin`) uploaded and verified.
    pub firmware_loaded: bool,
    /// Active `RTL8821CE` PTA coexistence profile (`0..=3`).
    pub coex_profile: u8,
    /// USB Vendor ID (`0x0BDA` for Realtek, `0` if non-USB).
    pub usb_vid: u16,
    /// USB Product ID (`0xC821` / `0xB00A` etc.).
    pub usb_pid: u16,
    /// Local controller `BD_ADDR` in little-endian HCI order (`[0]` = LAP LSB).
    pub local_bd_addr: [u8; 6],
    /// Controller HCI ACL data packet MTU.
    pub acl_mtu: u16,
    /// Total controller ACL packet buffers.
    pub acl_max_slots: u16,
    /// Currently unacknowledged ACL packets in flight.
    pub acl_in_flight: u16,
    /// Number of cached discovered/connected peers.
    pub peer_count: u8,
    /// Number of stored Link Keys on `HxFS`.
    pub saved_keys: u8,
    /// Number of open L2CAP channels.
    pub open_l2cap_channels: u8,
    /// Firmware version stamp (`0x826CA99E` on `rtl8821c_fw.bin`).
    pub fw_version: u32,
    /// Total HCI commands + ACL packets sent.
    pub tx_packets: u64,
    /// Total HCI events + ACL packets received.
    pub rx_packets: u64,
    /// Total bytes available in `/net/btl/snoop` (`btsnoop` v1 format).
    pub snoop_bytes: u32,
}

impl BtlStatusSnapshot {
    /// Wire size including 8-byte `HBTL` header (`64` bytes).
    pub const REPLY_LEN: usize = 64;

    /// Encode reply packet with `HBTL` header.
    pub fn encode_reply(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < Self::REPLY_LEN {
            return None;
        }
        out[..Self::REPLY_LEN].fill(0);
        write_header(out, BtlOp::Status, BtlStatus::Ok);
        out[8] = self.transport as u8;
        out[9] = u8::from(self.powered) | (u8::from(self.firmware_loaded) << 1);
        out[10] = self.coex_profile;
        out[11] = self.peer_count;
        out[12..14].copy_from_slice(&self.usb_vid.to_le_bytes());
        out[14..16].copy_from_slice(&self.usb_pid.to_le_bytes());
        out[16..22].copy_from_slice(&self.local_bd_addr);
        out[22] = self.saved_keys;
        out[23] = self.open_l2cap_channels;
        out[24..26].copy_from_slice(&self.acl_mtu.to_le_bytes());
        out[26..28].copy_from_slice(&self.acl_max_slots.to_le_bytes());
        out[28..30].copy_from_slice(&self.acl_in_flight.to_le_bytes());
        out[32..36].copy_from_slice(&self.fw_version.to_le_bytes());
        out[36..40].copy_from_slice(&self.snoop_bytes.to_le_bytes());
        out[40..48].copy_from_slice(&self.tx_packets.to_le_bytes());
        out[48..56].copy_from_slice(&self.rx_packets.to_le_bytes());
        Some(Self::REPLY_LEN)
    }

    /// Decode reply packet.
    pub fn decode_reply(bytes: &[u8]) -> Result<Self, BtlStatus> {
        let st = check_header(bytes, BtlOp::Status)?;
        if st != BtlStatus::Ok {
            return Err(st);
        }
        if bytes.len() < Self::REPLY_LEN {
            return Err(BtlStatus::InvalidRequest);
        }
        let mut local_bd_addr = [0u8; 6];
        local_bd_addr.copy_from_slice(&bytes[16..22]);
        Ok(Self {
            transport: BtlTransportKind::from_raw(bytes[8]).ok_or(BtlStatus::InvalidRequest)?,
            powered: (bytes[9] & 1) != 0,
            firmware_loaded: (bytes[9] & 2) != 0,
            coex_profile: bytes[10],
            peer_count: bytes[11],
            usb_vid: u16::from_le_bytes([bytes[12], bytes[13]]),
            usb_pid: u16::from_le_bytes([bytes[14], bytes[15]]),
            local_bd_addr,
            saved_keys: bytes[22],
            open_l2cap_channels: bytes[23],
            acl_mtu: u16::from_le_bytes([bytes[24], bytes[25]]),
            acl_max_slots: u16::from_le_bytes([bytes[26], bytes[27]]),
            acl_in_flight: u16::from_le_bytes([bytes[28], bytes[29]]),
            fw_version: u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]),
            snoop_bytes: u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]),
            tx_packets: u64::from_le_bytes([
                bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46],
                bytes[47],
            ]),
            rx_packets: u64::from_le_bytes([
                bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54],
                bytes[55],
            ]),
        })
    }
}

/// Discovered or connected Bluetooth peer summary (`64` bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtlPeerInfo {
    /// Peer `BD_ADDR` in little-endian HCI order.
    pub bd_addr: [u8; 6],
    /// Last observed Inquiry RSSI in dBm.
    pub rssi_dbm: i8,
    /// Bitmask: `bit 0 = paired`, `bit 1 = connected`, `bit 2 = encrypted`, `bit 3 = audio_sink`.
    pub flags: u8,
    /// 24-bit Class of Device (`CoD`).
    pub class_of_device: [u8; 3],
    /// Valid UTF-8/ASCII bytes in `name`.
    pub name_len: u8,
    /// Remote friendly name.
    pub name: [u8; MAX_PEER_NAME_LEN],
}

impl Default for BtlPeerInfo {
    fn default() -> Self {
        Self {
            bd_addr: [0; 6],
            rssi_dbm: -127,
            flags: 0,
            class_of_device: [0; 3],
            name_len: 0,
            name: [0; MAX_PEER_NAME_LEN],
        }
    }
}

impl BtlPeerInfo {
    /// Fixed wire record length (`64` bytes).
    pub const WIRE_LEN: usize = 64;

    /// True if a Link Key is stored for this peer.
    pub const fn is_paired(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// True if an ACL link is currently up.
    pub const fn is_connected(&self) -> bool {
        (self.flags & 0x02) != 0
    }

    /// True if baseband link encryption is enabled.
    pub const fn is_encrypted(&self) -> bool {
        (self.flags & 0x04) != 0
    }

    /// True if EIR or CoD advertises A2DP Audio Sink (`0x110B`).
    pub const fn is_audio_sink(&self) -> bool {
        (self.flags & 0x08) != 0
    }

    /// Peer friendly name as `&str`.
    pub fn name_str(&self) -> &str {
        let len = usize::from(self.name_len).min(MAX_PEER_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<bt-peer>")
    }

    /// Encode into `64` bytes.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < Self::WIRE_LEN {
            return None;
        }
        out[..Self::WIRE_LEN].fill(0);
        out[0..6].copy_from_slice(&self.bd_addr);
        out[6] = self.rssi_dbm as u8;
        out[7] = self.flags;
        out[8..11].copy_from_slice(&self.class_of_device);
        out[11] = self.name_len.min(MAX_PEER_NAME_LEN as u8);
        out[12..12 + MAX_PEER_NAME_LEN].copy_from_slice(&self.name);
        Some(Self::WIRE_LEN)
    }

    /// Decode from `64` bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_LEN {
            return None;
        }
        let mut bd_addr = [0u8; 6];
        bd_addr.copy_from_slice(&bytes[0..6]);
        let mut class_of_device = [0u8; 3];
        class_of_device.copy_from_slice(&bytes[8..11]);
        let mut name = [0u8; MAX_PEER_NAME_LEN];
        name.copy_from_slice(&bytes[12..12 + MAX_PEER_NAME_LEN]);
        Some(Self {
            bd_addr,
            rssi_dbm: bytes[6] as i8,
            flags: bytes[7],
            class_of_device,
            name_len: bytes[11].min(MAX_PEER_NAME_LEN as u8),
            name,
        })
    }
}

/// Non-secret Link Key summary exposed via `/net/btl/keys` (`12` bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BtlKeySummary {
    /// Peer `BD_ADDR` in little-endian HCI order.
    pub bd_addr: [u8; 6],
    /// HCI Link Key type (`0x04` = SSP Unauthenticated, `0x05` = Authenticated, etc.).
    pub key_type: u8,
    /// Reserved alignment byte.
    pub reserved: u8,
    /// Non-invertible 4-byte SHA-256 tag of the 16-byte Link Key.
    pub key_fingerprint: [u8; 4],
}

impl BtlKeySummary {
    /// Fixed wire size (`12` bytes).
    pub const WIRE_LEN: usize = 12;

    /// Encode into `12` bytes.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < Self::WIRE_LEN {
            return None;
        }
        out[0..6].copy_from_slice(&self.bd_addr);
        out[6] = self.key_type;
        out[7] = 0;
        out[8..12].copy_from_slice(&self.key_fingerprint);
        Some(Self::WIRE_LEN)
    }

    /// Decode from `12` bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_LEN {
            return None;
        }
        let mut bd_addr = [0u8; 6];
        bd_addr.copy_from_slice(&bytes[0..6]);
        let mut key_fingerprint = [0u8; 4];
        key_fingerprint.copy_from_slice(&bytes[8..12]);
        Some(Self {
            bd_addr,
            key_type: bytes[6],
            reserved: 0,
            key_fingerprint,
        })
    }
}

/// Internal `driver-host-xhci <-> btl-service` USB Bluetooth HCI bridge opcodes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbBtOp {
    /// Query attached USB Bluetooth controller `(online, vid, pid)`.
    QueryInfo = 1,
    /// Send an HCI Command over USB Control Endpoint 0 (`bmRequestType = 0x20`).
    SendHciCmd = 2,
    /// Send an HCI ACL packet over USB Bulk OUT.
    SendHciAcl = 3,
    /// Non-blocking poll for one received HCI Event (Interrupt IN) or HCI ACL (Bulk IN).
    PollRx = 4,
}

impl UsbBtOp {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::QueryInfo,
            2 => Self::SendHciCmd,
            3 => Self::SendHciAcl,
            4 => Self::PollRx,
            _ => return None,
        })
    }
}

/// Write an 8-byte `HBTL` wire header.
pub fn write_header(out: &mut [u8], op: BtlOp, status: BtlStatus) {
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6] = op as u8;
    out[7] = status as u8;
}

/// Parse an incoming `HBTL` request header into `(op, payload)`.
pub fn parse_request(bytes: &[u8]) -> Option<(BtlOp, &[u8])> {
    if bytes.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let ver = u16::from_le_bytes([bytes[4], bytes[5]]);
    if magic != MAGIC || ver != VERSION {
        return None;
    }
    Some((BtlOp::from_raw(bytes[6])?, &bytes[8..]))
}

/// Validate an `HBTL` reply header against `expected_op`.
pub fn check_header(bytes: &[u8], expected_op: BtlOp) -> Result<BtlStatus, BtlStatus> {
    if bytes.len() < 8 {
        return Err(BtlStatus::InvalidRequest);
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let ver = u16::from_le_bytes([bytes[4], bytes[5]]);
    if magic != MAGIC || ver != VERSION || bytes[6] != expected_op as u8 {
        return Err(BtlStatus::InvalidRequest);
    }
    BtlStatus::from_raw(bytes[7]).ok_or(BtlStatus::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btl_status_and_peer_roundtrip() {
        let snap = BtlStatusSnapshot {
            transport: BtlTransportKind::UsbRealtek8821c,
            powered: true,
            firmware_loaded: true,
            coex_profile: 3,
            usb_vid: 0x0BDA,
            usb_pid: 0xC821,
            local_bd_addr: [0x01, 0x00, 0xB7, 0x00, 0x54, 0x52],
            acl_mtu: 1021,
            acl_max_slots: 8,
            acl_in_flight: 2,
            peer_count: 1,
            saved_keys: 1,
            open_l2cap_channels: 3,
            fw_version: 0x826C_A99E,
            tx_packets: 120,
            rx_packets: 118,
            snoop_bytes: 4096,
        };
        let mut buf = [0u8; 64];
        assert_eq!(snap.encode_reply(&mut buf), Some(64));
        assert_eq!(BtlStatusSnapshot::decode_reply(&buf), Ok(snap));

        let mut peer = BtlPeerInfo {
            bd_addr: [0xD9, 0xA2, 0xB7, 0x00, 0x54, 0x52],
            rssi_dbm: -42,
            flags: 0x0F,
            class_of_device: [0x18, 0x04, 0x24],
            name_len: 18,
            name: [0; MAX_PEER_NAME_LEN],
        };
        peer.name[..18].copy_from_slice(b"HuesOS AirBuds Pro");
        let mut pbuf = [0u8; BtlPeerInfo::WIRE_LEN];
        assert_eq!(peer.encode(&mut pbuf), Some(BtlPeerInfo::WIRE_LEN));
        assert_eq!(BtlPeerInfo::decode(&pbuf), Some(peer));
    }
}
