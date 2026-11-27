//! Bluetooth Classic `L2CAP` Basic Mode (`CID 0x0001` signaling + dynamic `0x0040..0xFFFF`
//! connection-oriented channels) for `/net/btl`.

use crate::hci::BdAddr;
use alloc::vec::Vec;

/// Fixed L2CAP Signaling Channel ID for ACL-U links.
pub const CID_SIGNALING: u16 = 0x0001;
/// Fixed L2CAP Connectionless Channel ID.
pub const CID_CONNECTIONLESS: u16 = 0x0002;
/// First dynamically allocated L2CAP CID on Bluetooth Classic.
pub const DYNAMIC_CID_START: u16 = 0x0040;

// ---- Well-known Protocol/Service Multiplexers (`PSM`) ----
/// Service Discovery Protocol (`SDP`).
pub const PSM_SDP: u16 = 0x0001;
/// RFCOMM (`0x0003`).
pub const PSM_RFCOMM: u16 = 0x0003;
/// Audio/Video Control Transport Protocol (`AVCTP` / `AVRCP`).
pub const PSM_AVCTP: u16 = 0x0017;
/// Audio/Video Distribution Transport Protocol (`AVDTP` / `A2DP`).
pub const PSM_AVDTP: u16 = 0x0019;
/// AVCTP Browsing (`0x001B`).
pub const PSM_AVCTP_BROWSING: u16 = 0x001B;

// ---- L2CAP Signaling Command Codes ----
/// Command Reject (`0x01`).
pub const SIG_CMD_REJECT: u8 = 0x01;
/// Connection Request (`0x02`).
pub const SIG_CONN_REQ: u8 = 0x02;
/// Connection Response (`0x03`).
pub const SIG_CONN_RSP: u8 = 0x03;
/// Configuration Request (`0x04`).
pub const SIG_CONFIG_REQ: u8 = 0x04;
/// Configuration Response (`0x05`).
pub const SIG_CONFIG_RSP: u8 = 0x05;
/// Disconnection Request (`0x06`).
pub const SIG_DISCONN_REQ: u8 = 0x06;
/// Disconnection Response (`0x07`).
pub const SIG_DISCONN_RSP: u8 = 0x07;
/// Echo Request (`0x08`).
pub const SIG_ECHO_REQ: u8 = 0x08;
/// Echo Response (`0x09`).
pub const SIG_ECHO_RSP: u8 = 0x09;
/// Information Request (`0x0A`).
pub const SIG_INFO_REQ: u8 = 0x0A;
/// Information Response (`0x0B`).
pub const SIG_INFO_RSP: u8 = 0x0B;

/// Default local RX MTU advertised during L2CAP configuration (`896` bytes fits comfortably
/// inside a single `1021`-byte `RTL8821CE` ACL slot and holds 6–7 high-bitpool SBC frames).
pub const DEFAULT_LOCAL_MTU: u16 = 896;
/// Bluetooth Classic baseline L2CAP MTU when the peer omits the MTU option (`672` bytes).
pub const BASELINE_REMOTE_MTU: u16 = 672;

/// Lifecycle state of one dynamic L2CAP channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2capChanState {
    /// Outbound `Connection_Request` sent, awaiting `Connection_Response`.
    WaitConnectRsp,
    /// Connected at L2CAP CID level; exchanging `Configuration_Request`/`Response`.
    Config {
        /// Local `ConfigReq` accepted by peer.
        local_cfg_done: bool,
        /// Remote `ConfigReq` received and answered with `Success`.
        remote_cfg_done: bool,
    },
    /// Channel fully open for bidirectional payload transfer.
    Open,
    /// Outbound `Disconnection_Request` sent, awaiting `Disconnection_Response`.
    WaitDisconnectRsp,
    /// Closed / reusable.
    Closed,
}

/// Metadata for a single L2CAP channel tracked by [`L2capEngine`].
#[derive(Clone, Debug)]
pub struct L2capChannel {
    /// Local Channel ID (`>= 0x0040`).
    pub local_cid: u16,
    /// Remote Channel ID (`0` until `Connection_Response` or inbound `Connection_Request`).
    pub remote_cid: u16,
    /// ACL `Connection_Handle`.
    pub conn_handle: u16,
    /// Peer Bluetooth address.
    pub peer_addr: BdAddr,
    /// Negotiated `PSM` (`0x0001` SDP, `0x0019` AVDTP, `0x0017` AVCTP, etc.).
    pub psm: u16,
    /// True if initiated locally; false if accepted from a remote peer.
    pub initiator: bool,
    /// Negotiated local RX MTU.
    pub local_mtu: u16,
    /// Negotiated remote RX MTU (max payload we may send in one L2CAP frame).
    pub remote_mtu: u16,
    /// Channel state.
    pub state: L2capChanState,
}

/// High-level events emitted by [`L2capEngine`] to `/net/btl` & built-in SDP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum L2capEvent {
    /// A channel completed bidirectional configuration and is now `Open`.
    ChannelOpened {
        /// Local CID (`>= 0x0040`).
        local_cid: u16,
        /// ACL `Connection_Handle`.
        conn_handle: u16,
        /// Peer address.
        peer_addr: BdAddr,
        /// PSM (`0x0001`, `0x0019`, `0x0017`, ...).
        psm: u16,
        /// True if initiated locally; false if inbound from peer.
        initiator: bool,
        /// Max payload size accepted by peer.
        remote_mtu: u16,
    },
    /// Payload frame received on an open L2CAP channel.
    DataReceived {
        /// Local CID.
        local_cid: u16,
        /// PSM of the channel.
        psm: u16,
        /// Payload bytes (without 4-byte L2CAP basic header).
        payload: Vec<u8>,
    },
    /// Channel closed (by peer, local request, or underlying ACL link drop).
    ChannelClosed {
        /// Local CID.
        local_cid: u16,
        /// PSM.
        psm: u16,
    },
}

/// Outbound L2CAP frame ready to be segmented onto HCI ACL (`conn_handle`, `l2cap_pdu`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundL2capPdu {
    /// Target ACL `Connection_Handle`.
    pub conn_handle: u16,
    /// Complete L2CAP Basic PDU (`[len_lo, len_hi, dst_cid_lo, dst_cid_hi, payload...]`).
    pub pdu: Vec<u8>,
}

/// Wrap raw payload bytes in a 4-byte L2CAP Basic header targeting `dst_cid`.
pub fn wrap_l2cap_pdu(dst_cid: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&dst_cid.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn wrap_sig_cmd(code: u8, ident: u8, data: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(4 + data.len());
    cmd.push(code);
    cmd.push(ident);
    cmd.extend_from_slice(&(data.len() as u16).to_le_bytes());
    cmd.extend_from_slice(data);
    wrap_l2cap_pdu(CID_SIGNALING, &cmd)
}

fn build_config_req(ident: u8, dst_cid: u16, local_mtu: u16) -> Vec<u8> {
    // [dst_cid(2), flags=0(2), opt_type=0x01(MTU), opt_len=2, mtu(2)]
    let mut data = [0u8; 8];
    data[0..2].copy_from_slice(&dst_cid.to_le_bytes());
    data[2..4].copy_from_slice(&0u16.to_le_bytes());
    data[4] = 0x01;
    data[5] = 0x02;
    data[6..8].copy_from_slice(&local_mtu.to_le_bytes());
    wrap_sig_cmd(SIG_CONFIG_REQ, ident, &data)
}

fn build_config_rsp_ok(ident: u8, src_cid: u16) -> Vec<u8> {
    // [src_cid(2), flags=0(2), result=0x0000(Success)(2)]
    let mut data = [0u8; 6];
    data[0..2].copy_from_slice(&src_cid.to_le_bytes());
    data[2..4].copy_from_slice(&0u16.to_le_bytes());
    data[4..6].copy_from_slice(&0u16.to_le_bytes());
    wrap_sig_cmd(SIG_CONFIG_RSP, ident, &data)
}

/// Pure state-machine multiplexer for Bluetooth Classic L2CAP.
pub struct L2capEngine {
    channels: Vec<L2capChannel>,
    registered_psms: Vec<u16>,
    next_cid: u16,
    next_ident: u8,
    tx_queue: Vec<OutboundL2capPdu>,
    events: Vec<L2capEvent>,
}

impl Default for L2capEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl L2capEngine {
    /// Construct a fresh L2CAP engine with `PSM_SDP` (`0x0001`) always registered.
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            registered_psms: alloc::vec![PSM_SDP],
            next_cid: DYNAMIC_CID_START,
            next_ident: 1,
            tx_queue: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Register an inbound listener for `psm` (e.g. `PSM_AVDTP = 0x0019`, `PSM_AVCTP = 0x0017`).
    pub fn register_psm(&mut self, psm: u16) {
        if !self.registered_psms.contains(&psm) {
            self.registered_psms.push(psm);
        }
    }

    /// Unregister an inbound listener for `psm` (`PSM_SDP` stays registered).
    pub fn unregister_psm(&mut self, psm: u16) {
        if psm != PSM_SDP {
            self.registered_psms.retain(|&p| p != psm);
        }
    }

    fn alloc_ident(&mut self) -> u8 {
        let id = self.next_ident;
        self.next_ident = if self.next_ident == 255 {
            1
        } else {
            self.next_ident + 1
        };
        id
    }

    fn alloc_local_cid(&mut self) -> u16 {
        for _ in 0..1024 {
            let candidate = self.next_cid;
            self.next_cid = if self.next_cid >= 0x7FFF {
                DYNAMIC_CID_START
            } else {
                self.next_cid + 1
            };
            if !self
                .channels
                .iter()
                .any(|c| c.state != L2capChanState::Closed && c.local_cid == candidate)
            {
                return candidate;
            }
        }
        DYNAMIC_CID_START
    }

    /// Initiate an outbound L2CAP channel to `(conn_handle, peer_addr, psm)`, returning `local_cid`.
    pub fn connect(&mut self, conn_handle: u16, peer_addr: BdAddr, psm: u16) -> u16 {
        let local_cid = self.alloc_local_cid();
        let ident = self.alloc_ident();
        self.channels.push(L2capChannel {
            local_cid,
            remote_cid: 0,
            conn_handle,
            peer_addr,
            psm,
            initiator: true,
            local_mtu: DEFAULT_LOCAL_MTU,
            remote_mtu: BASELINE_REMOTE_MTU,
            state: L2capChanState::WaitConnectRsp,
        });
        let mut req = [0u8; 4];
        req[0..2].copy_from_slice(&psm.to_le_bytes());
        req[2..4].copy_from_slice(&local_cid.to_le_bytes());
        self.tx_queue.push(OutboundL2capPdu {
            conn_handle,
            pdu: wrap_sig_cmd(SIG_CONN_REQ, ident, &req),
        });
        local_cid
    }

    /// Queue a payload frame on an open L2CAP channel.
    pub fn send_data(&mut self, local_cid: u16, payload: &[u8]) -> bool {
        let Some(ch) = self
            .channels
            .iter()
            .find(|c| c.local_cid == local_cid && c.state == L2capChanState::Open)
        else {
            return false;
        };
        if payload.len() > usize::from(ch.remote_mtu) {
            return false;
        }
        let pdu = wrap_l2cap_pdu(ch.remote_cid, payload);
        self.tx_queue.push(OutboundL2capPdu {
            conn_handle: ch.conn_handle,
            pdu,
        });
        true
    }

    ///Gracefully disconnect an active L2CAP channel.
    pub fn disconnect(&mut self, local_cid: u16) -> bool {
        let ident = self.alloc_ident();
        let Some(ch) = self
            .channels
            .iter_mut()
            .find(|c| c.local_cid == local_cid && c.state != L2capChanState::Closed)
        else {
            return false;
        };
        let conn_handle = ch.conn_handle;
        let remote_cid = ch.remote_cid;
        ch.state = L2capChanState::WaitDisconnectRsp;
        if remote_cid != 0 {
            let mut req = [0u8; 4];
            req[0..2].copy_from_slice(&remote_cid.to_le_bytes());
            req[2..4].copy_from_slice(&local_cid.to_le_bytes());
            self.tx_queue.push(OutboundL2capPdu {
                conn_handle,
                pdu: wrap_sig_cmd(SIG_DISCONN_REQ, ident, &req),
            });
        }
        true
    }

    /// Tear down all L2CAP channels associated with a disconnected ACL `conn_handle`.
    pub fn on_acl_disconnected(&mut self, conn_handle: u16) {
        for ch in &mut self.channels {
            if ch.conn_handle == conn_handle && ch.state != L2capChanState::Closed {
                ch.state = L2capChanState::Closed;
                self.events.push(L2capEvent::ChannelClosed {
                    local_cid: ch.local_cid,
                    psm: ch.psm,
                });
            }
        }
        self.channels.retain(|c| c.state != L2capChanState::Closed);
    }

    /// Inspect an active channel by `local_cid`.
    pub fn channel(&self, local_cid: u16) -> Option<&L2capChannel> {
        self.channels
            .iter()
            .find(|c| c.local_cid == local_cid && c.state != L2capChanState::Closed)
    }

    /// Drain queued outbound L2CAP PDUs.
    pub fn drain_outbound(&mut self) -> Vec<OutboundL2capPdu> {
        core::mem::take(&mut self.tx_queue)
    }

    /// Drain emitted high-level L2CAP events.
    pub fn drain_events(&mut self) -> Vec<L2capEvent> {
        core::mem::take(&mut self.events)
    }

    /// Feed one reassembled L2CAP PDU `(conn_handle, peer_addr, cid, payload)`.
    pub fn on_reassembled_pdu(
        &mut self,
        conn_handle: u16,
        peer_addr: BdAddr,
        cid: u16,
        payload: &[u8],
    ) {
        if cid == CID_SIGNALING {
            self.handle_signaling(conn_handle, peer_addr, payload);
            self.channels.retain(|c| c.state != L2capChanState::Closed);
            return;
        }
        if cid == CID_CONNECTIONLESS {
            return;
        }
        if let Some(ch) = self.channels.iter().find(|c| {
            c.conn_handle == conn_handle && c.local_cid == cid && c.state == L2capChanState::Open
        }) {
            let psm = ch.psm;
            self.events.push(L2capEvent::DataReceived {
                local_cid: cid,
                psm,
                payload: payload.to_vec(),
            });
        }
    }

    fn handle_signaling(&mut self, conn_handle: u16, peer_addr: BdAddr, mut buf: &[u8]) {
        // One signaling L2CAP frame may pack multiple signaling commands back-to-back!
        while buf.len() >= 4 {
            let code = buf[0];
            let ident = buf[1];
            let dlen = usize::from(u16::from_le_bytes([buf[2], buf[3]]));
            if buf.len() < 4 + dlen {
                break;
            }
            let data = &buf[4..4 + dlen];
            buf = &buf[4 + dlen..];

            match code {
                SIG_INFO_REQ if data.len() >= 2 => {
                    let info_type = u16::from_le_bytes([data[0], data[1]]);
                    match info_type {
                        // Connectionless MTU (`0x0001`) -> 672
                        0x0001 => {
                            let mut rsp = [0u8; 6];
                            rsp[0..2].copy_from_slice(&info_type.to_le_bytes());
                            rsp[2..4].copy_from_slice(&0u16.to_le_bytes()); // Success
                            rsp[4..6].copy_from_slice(&672u16.to_le_bytes());
                            self.tx_queue.push(OutboundL2capPdu {
                                conn_handle,
                                pdu: wrap_sig_cmd(SIG_INFO_RSP, ident, &rsp),
                            });
                        }
                        // Extended Features Mask (`0x0002`) -> Fixed Channels Supported (bit 7 = 0x80)
                        0x0002 => {
                            let mut rsp = [0u8; 8];
                            rsp[0..2].copy_from_slice(&info_type.to_le_bytes());
                            rsp[2..4].copy_from_slice(&0u16.to_le_bytes()); // Success
                            rsp[4..8].copy_from_slice(&0x0000_0080u32.to_le_bytes());
                            self.tx_queue.push(OutboundL2capPdu {
                                conn_handle,
                                pdu: wrap_sig_cmd(SIG_INFO_RSP, ident, &rsp),
                            });
                        }
                        // Fixed Channels Supported (`0x0003`) -> bit 1 (`CID 0x0001` L2CAP Signaling)
                        0x0003 => {
                            let mut rsp = [0u8; 12];
                            rsp[0..2].copy_from_slice(&info_type.to_le_bytes());
                            rsp[2..4].copy_from_slice(&0u16.to_le_bytes()); // Success
                            rsp[4..12].copy_from_slice(&0x0000_0000_0000_0002u64.to_le_bytes());
                            self.tx_queue.push(OutboundL2capPdu {
                                conn_handle,
                                pdu: wrap_sig_cmd(SIG_INFO_RSP, ident, &rsp),
                            });
                        }
                        _ => {
                            let mut rsp = [0u8; 4];
                            rsp[0..2].copy_from_slice(&info_type.to_le_bytes());
                            rsp[2..4].copy_from_slice(&0x0001u16.to_le_bytes()); // Not Supported
                            self.tx_queue.push(OutboundL2capPdu {
                                conn_handle,
                                pdu: wrap_sig_cmd(SIG_INFO_RSP, ident, &rsp),
                            });
                        }
                    }
                }
                SIG_ECHO_REQ => {
                    self.tx_queue.push(OutboundL2capPdu {
                        conn_handle,
                        pdu: wrap_sig_cmd(SIG_ECHO_RSP, ident, data),
                    });
                }
                SIG_CONN_REQ if data.len() >= 4 => {
                    let psm = u16::from_le_bytes([data[0], data[1]]);
                    let src_cid = u16::from_le_bytes([data[2], data[3]]);
                    if self.registered_psms.contains(&psm) {
                        let local_cid = self.alloc_local_cid();
                        let cfg_ident = self.alloc_ident();
                        self.channels.push(L2capChannel {
                            local_cid,
                            remote_cid: src_cid,
                            conn_handle,
                            peer_addr,
                            psm,
                            initiator: false,
                            local_mtu: DEFAULT_LOCAL_MTU,
                            remote_mtu: BASELINE_REMOTE_MTU,
                            state: L2capChanState::Config {
                                local_cfg_done: false,
                                remote_cfg_done: false,
                            },
                        });
                        // Connection Response: [dst_cid=local_cid, src_cid, result=0(OK), status=0]
                        let mut rsp = [0u8; 8];
                        rsp[0..2].copy_from_slice(&local_cid.to_le_bytes());
                        rsp[2..4].copy_from_slice(&src_cid.to_le_bytes());
                        self.tx_queue.push(OutboundL2capPdu {
                            conn_handle,
                            pdu: wrap_sig_cmd(SIG_CONN_RSP, ident, &rsp),
                        });
                        // Proactively send our Configuration Request!
                        self.tx_queue.push(OutboundL2capPdu {
                            conn_handle,
                            pdu: build_config_req(cfg_ident, src_cid, DEFAULT_LOCAL_MTU),
                        });
                    } else {
                        // Result = 0x0002 (PSM not supported)
                        let mut rsp = [0u8; 8];
                        rsp[2..4].copy_from_slice(&src_cid.to_le_bytes());
                        rsp[4..6].copy_from_slice(&0x0002u16.to_le_bytes());
                        self.tx_queue.push(OutboundL2capPdu {
                            conn_handle,
                            pdu: wrap_sig_cmd(SIG_CONN_RSP, ident, &rsp),
                        });
                    }
                }
                SIG_CONN_RSP if data.len() >= 8 => {
                    let dst_cid = u16::from_le_bytes([data[0], data[1]]);
                    let src_cid = u16::from_le_bytes([data[2], data[3]]);
                    let result = u16::from_le_bytes([data[4], data[5]]);
                    if result == 0x0001 {
                        // Connection Pending — wait for final Connection_Response
                        continue;
                    }
                    let cfg_ident = self.alloc_ident();
                    if let Some(ch) = self.channels.iter_mut().find(|c| {
                        c.conn_handle == conn_handle
                            && c.local_cid == src_cid
                            && c.state == L2capChanState::WaitConnectRsp
                    }) {
                        if result == 0x0000 && dst_cid >= DYNAMIC_CID_START {
                            ch.remote_cid = dst_cid;
                            ch.state = L2capChanState::Config {
                                local_cfg_done: false,
                                remote_cfg_done: false,
                            };
                            let local_mtu = ch.local_mtu;
                            self.tx_queue.push(OutboundL2capPdu {
                                conn_handle,
                                pdu: build_config_req(cfg_ident, dst_cid, local_mtu),
                            });
                        } else {
                            let psm = ch.psm;
                            ch.state = L2capChanState::Closed;
                            self.events.push(L2capEvent::ChannelClosed {
                                local_cid: src_cid,
                                psm,
                            });
                        }
                    }
                }
                SIG_CONFIG_REQ if data.len() >= 4 => {
                    let dst_cid = u16::from_le_bytes([data[0], data[1]]);
                    let opts = &data[4..];
                    let mut parsed_mtu: Option<u16> = None;
                    let mut opos = 0usize;
                    while opos + 2 <= opts.len() {
                        let otype = opts[opos] & 0x7F;
                        let olen = usize::from(opts[opos + 1]);
                        if opos + 2 + olen > opts.len() {
                            break;
                        }
                        if otype == 0x01 && olen == 2 {
                            parsed_mtu = Some(u16::from_le_bytes([opts[opos + 2], opts[opos + 3]]));
                        }
                        opos += 2 + olen;
                    }

                    if let Some(ch) = self.channels.iter_mut().find(|c| {
                        c.conn_handle == conn_handle
                            && c.local_cid == dst_cid
                            && matches!(
                                c.state,
                                L2capChanState::Config { .. } | L2capChanState::Open
                            )
                    }) {
                        if let Some(m) = parsed_mtu {
                            ch.remote_mtu = m.max(48);
                        }
                        let remote_cid = ch.remote_cid;
                        self.tx_queue.push(OutboundL2capPdu {
                            conn_handle,
                            pdu: build_config_rsp_ok(ident, remote_cid),
                        });
                        if let L2capChanState::Config {
                            local_cfg_done,
                            ref mut remote_cfg_done,
                        } = ch.state
                        {
                            *remote_cfg_done = true;
                            if local_cfg_done {
                                ch.state = L2capChanState::Open;
                                self.events.push(L2capEvent::ChannelOpened {
                                    local_cid: ch.local_cid,
                                    conn_handle: ch.conn_handle,
                                    peer_addr: ch.peer_addr,
                                    psm: ch.psm,
                                    initiator: ch.initiator,
                                    remote_mtu: ch.remote_mtu,
                                });
                            }
                        }
                    }
                }
                SIG_CONFIG_RSP if data.len() >= 6 => {
                    let src_cid = u16::from_le_bytes([data[0], data[1]]);
                    let result = u16::from_le_bytes([data[4], data[5]]);
                    if let Some(ch) = self
                        .channels
                        .iter_mut()
                        .find(|c| c.conn_handle == conn_handle && c.local_cid == src_cid)
                    {
                        if result == 0x0000 {
                            if let L2capChanState::Config {
                                ref mut local_cfg_done,
                                remote_cfg_done,
                            } = ch.state
                            {
                                *local_cfg_done = true;
                                if remote_cfg_done {
                                    ch.state = L2capChanState::Open;
                                    self.events.push(L2capEvent::ChannelOpened {
                                        local_cid: ch.local_cid,
                                        conn_handle: ch.conn_handle,
                                        peer_addr: ch.peer_addr,
                                        psm: ch.psm,
                                        initiator: ch.initiator,
                                        remote_mtu: ch.remote_mtu,
                                    });
                                }
                            }
                        } else {
                            let psm = ch.psm;
                            ch.state = L2capChanState::Closed;
                            self.events.push(L2capEvent::ChannelClosed {
                                local_cid: src_cid,
                                psm,
                            });
                        }
                    }
                }
                SIG_DISCONN_REQ if data.len() >= 4 => {
                    let dst_cid = u16::from_le_bytes([data[0], data[1]]);
                    let src_cid = u16::from_le_bytes([data[2], data[3]]);
                    let mut rsp = [0u8; 4];
                    rsp[0..2].copy_from_slice(&dst_cid.to_le_bytes());
                    rsp[2..4].copy_from_slice(&src_cid.to_le_bytes());
                    self.tx_queue.push(OutboundL2capPdu {
                        conn_handle,
                        pdu: wrap_sig_cmd(SIG_DISCONN_RSP, ident, &rsp),
                    });
                    if let Some(ch) = self
                        .channels
                        .iter_mut()
                        .find(|c| c.conn_handle == conn_handle && c.local_cid == dst_cid)
                    {
                        let psm = ch.psm;
                        ch.state = L2capChanState::Closed;
                        self.events.push(L2capEvent::ChannelClosed {
                            local_cid: dst_cid,
                            psm,
                        });
                    }
                }
                SIG_DISCONN_RSP if data.len() >= 4 => {
                    let src_cid = u16::from_le_bytes([data[2], data[3]]);
                    if let Some(ch) = self
                        .channels
                        .iter_mut()
                        .find(|c| c.conn_handle == conn_handle && c.local_cid == src_cid)
                    {
                        let psm = ch.psm;
                        ch.state = L2capChanState::Closed;
                        self.events.push(L2capEvent::ChannelClosed {
                            local_cid: src_cid,
                            psm,
                        });
                    }
                }
                _ => {}
            }
        }
    }
}
