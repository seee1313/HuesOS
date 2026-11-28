//! Deterministic virtual Bluetooth Classic controller + simulated wireless
//! headphones (`"HuesOS AirBuds Pro"`, `52:54:00:B7:A2:D9`) speaking real
//! HCI, SSP Just-Works, L2CAP, SDP (`0x110B`), AVDTP 1.3 (`SBC`), and AVRCP.
//!
//! Enables full end-to-end `/net/btl` + `audio-service` A2DP verification in
//! QEMU CI (where no physical USB Bluetooth radio is attached) using the exact
//! same upper-layer protocol state machines that run against `RTL8821CE` on
//! bare metal.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::hci::{
    segment_l2cap_to_acl, AclReassembler, BdAddr, EVT_AUTH_COMPLETE, EVT_CMD_COMPLETE,
    EVT_CMD_STATUS, EVT_CONN_COMPLETE, EVT_DISCONN_COMPLETE, EVT_ENCRYPTION_CHANGE,
    EVT_EXTENDED_INQUIRY_RESULT, EVT_INQUIRY_COMPLETE, EVT_IO_CAP_REQ, EVT_LINK_KEY_NOTIFY,
    EVT_LINK_KEY_REQ, EVT_NUM_COMPLETED_PKTS, EVT_REMOTE_NAME_COMPLETE,
    EVT_SIMPLE_PAIRING_COMPLETE, EVT_USER_CONFIRM_REQ, OP_AUTH_REQUESTED, OP_CREATE_CONN,
    OP_DISCONNECT, OP_INQUIRY, OP_INQUIRY_CANCEL, OP_IO_CAP_REPLY, OP_LINK_KEY_NEG_REPLY,
    OP_LINK_KEY_REPLY, OP_READ_BD_ADDR, OP_READ_BUFFER_SIZE, OP_READ_LOCAL_VERSION,
    OP_REMOTE_NAME_REQ, OP_SET_CONN_ENCRYPTION, OP_USER_CONFIRM_REPLY,
};
use crate::l2cap::{L2capEngine, L2capEvent, PSM_AVCTP, PSM_AVDTP, PSM_SDP};
use crate::sdp::{SDP_SVC_SEARCH_ATTR_REQ, SDP_SVC_SEARCH_ATTR_RSP, UUID_AUDIO_SINK, UUID_AVDTP};

/// Virtual local controller BD_ADDR (`52:54:00:B7:00:01`).
pub const VIRTUAL_LOCAL_ADDR: BdAddr = BdAddr::from_be_bytes([0x52, 0x54, 0x00, 0xB7, 0x00, 0x01]);
/// Virtual wireless headphones BD_ADDR (`52:54:00:B7:A2:D9`).
pub const VIRTUAL_HEADSET_ADDR: BdAddr =
    BdAddr::from_be_bytes([0x52, 0x54, 0x00, 0xB7, 0xA2, 0xD9]);
/// Virtual wireless headphones product name.
pub const VIRTUAL_HEADSET_NAME: &str = "HuesOS AirBuds Pro";
/// Class of Device: Audio + Rendering service, Major Audio/Video (`0x04`), Minor Headphones (`6`).
pub const VIRTUAL_HEADSET_COD: [u8; 3] = [0x18, 0x04, 0x24];

const CONN_HANDLE_HEADSET: u16 = 0x0041;
const HEADSET_SEID_SBC_SINK: u8 = 1;

/// Simulated HCI + remote A2DP Sink medium.
pub struct VirtualBtMedium {
    rx_events: VecDeque<Vec<u8>>,
    rx_acl: VecDeque<Vec<u8>>,
    connected: bool,
    reasm: AclReassembler,
    peer_l2cap: L2capEngine,
    avdtp_sig_cid: Option<u16>,
    avdtp_media_cid: Option<u16>,
    avctp_cid: Option<u16>,
    avdtp_streaming: bool,
    sent_avrcp_vol_up: bool,
    /// Total valid RTP+SBC media packets received by the simulated headphones.
    pub received_sbc_packets: u64,
    /// Total valid `0x9C`-synced SBC frames decoded/verified by the simulated headphones.
    pub received_sbc_frames: u64,
}

impl Default for VirtualBtMedium {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualBtMedium {
    /// Construct a fresh virtual Bluetooth HCI controller + remote A2DP headset.
    pub fn new() -> Self {
        let mut peer_l2cap = L2capEngine::new();
        peer_l2cap.register_psm(PSM_SDP);
        peer_l2cap.register_psm(PSM_AVDTP);
        peer_l2cap.register_psm(PSM_AVCTP);
        Self {
            rx_events: VecDeque::new(),
            rx_acl: VecDeque::new(),
            connected: false,
            reasm: AclReassembler::default(),
            peer_l2cap,
            avdtp_sig_cid: None,
            avdtp_media_cid: None,
            avctp_cid: None,
            avdtp_streaming: false,
            sent_avrcp_vol_up: false,
            received_sbc_packets: 0,
            received_sbc_frames: 0,
        }
    }

    fn push_cmd_complete(&mut self, opcode: u16, status: u8, extra: &[u8]) {
        let mut evt = Vec::with_capacity(6 + extra.len());
        evt.push(EVT_CMD_COMPLETE);
        evt.push((4 + extra.len()) as u8);
        evt.push(1);
        evt.extend_from_slice(&opcode.to_le_bytes());
        evt.push(status);
        evt.extend_from_slice(extra);
        self.rx_events.push_back(evt);
    }

    fn push_cmd_status(&mut self, opcode: u16, status: u8) {
        let op = opcode.to_le_bytes();
        self.rx_events
            .push_back(alloc::vec![EVT_CMD_STATUS, 4, status, 1, op[0], op[1]]);
    }

    /// Submit one Host -> Controller HCI Command (`[op_lo, op_hi, len, params...]`).
    pub fn submit_hci_cmd(&mut self, cmd: &[u8]) {
        if cmd.len() < 3 {
            return;
        }
        let opcode = u16::from_le_bytes([cmd[0], cmd[1]]);
        let plen = usize::from(cmd[2]);
        if cmd.len() < 3 + plen {
            return;
        }
        let p = &cmd[3..3 + plen];

        match opcode {
            OP_READ_LOCAL_VERSION => {
                // HCI 5.1 (0x0A), rev 0x000C, LMP 5.1, Manufacturer 0x005D, subver 0x826C
                self.push_cmd_complete(
                    opcode,
                    0,
                    &[0x0A, 0x0C, 0x00, 0x0A, 0x5D, 0x00, 0x6C, 0x82],
                );
            }
            OP_READ_BD_ADDR => {
                self.push_cmd_complete(opcode, 0, &VIRTUAL_LOCAL_ADDR.0);
            }
            OP_READ_BUFFER_SIZE => {
                // ACL MTU = 1021 (0x03FD), SCO = 64, Total ACL = 8, Total SCO = 4
                self.push_cmd_complete(opcode, 0, &[0xFD, 0x03, 64, 0x08, 0x00, 0x04, 0x00]);
            }
            OP_INQUIRY => {
                self.push_cmd_status(opcode, 0);
                // Emit Extended Inquiry Result (`0x2F`) advertising `"HuesOS AirBuds Pro"` + `0x110B`.
                let mut eir_evt = alloc::vec![0u8; 2 + 255];
                eir_evt[0] = EVT_EXTENDED_INQUIRY_RESULT;
                eir_evt[1] = 255;
                eir_evt[2] = 1; // num_responses = 1
                eir_evt[3..9].copy_from_slice(&VIRTUAL_HEADSET_ADDR.0);
                eir_evt[9] = 1; // Page_Scan_Repetition_Mode R1
                eir_evt[10] = 0;
                eir_evt[11..14].copy_from_slice(&VIRTUAL_HEADSET_COD);
                eir_evt[14..16].copy_from_slice(&0x1234u16.to_le_bytes());
                eir_evt[16] = (-42i8) as u8;
                // EIR AD #1: Complete 16-bit UUIDs `[0x110B (AudioSink), 0x110E (AVRCP)]`
                let eir = &mut eir_evt[17..];
                eir[0] = 5;
                eir[1] = 0x03;
                eir[2..4].copy_from_slice(&0x110Bu16.to_le_bytes());
                eir[4..6].copy_from_slice(&0x110Eu16.to_le_bytes());
                // EIR AD #2: Complete Local Name
                let nb = VIRTUAL_HEADSET_NAME.as_bytes();
                eir[6] = (1 + nb.len()) as u8;
                eir[7] = 0x09;
                eir[8..8 + nb.len()].copy_from_slice(nb);
                self.rx_events.push_back(eir_evt);
                self.rx_events
                    .push_back(alloc::vec![EVT_INQUIRY_COMPLETE, 1, 0x00]);
            }
            OP_INQUIRY_CANCEL => {
                self.push_cmd_complete(opcode, 0, &[]);
            }
            OP_REMOTE_NAME_REQ if p.len() >= 6 => {
                self.push_cmd_status(opcode, 0);
                let mut evt = alloc::vec![0u8; 2 + 1 + 6 + 248];
                evt[0] = EVT_REMOTE_NAME_COMPLETE;
                evt[1] = 255;
                evt[2] = 0; // Success
                evt[3..9].copy_from_slice(&p[0..6]);
                let nb = VIRTUAL_HEADSET_NAME.as_bytes();
                evt[9..9 + nb.len()].copy_from_slice(nb);
                self.rx_events.push_back(evt);
            }
            OP_CREATE_CONN if p.len() >= 6 => {
                let mut target = [0u8; 6];
                target.copy_from_slice(&p[0..6]);
                if BdAddr(target) == VIRTUAL_HEADSET_ADDR {
                    self.push_cmd_status(opcode, 0);
                    self.connected = true;
                    let mut cc = Vec::with_capacity(13);
                    cc.push(EVT_CONN_COMPLETE);
                    cc.push(11);
                    cc.push(0x00); // Success
                    cc.extend_from_slice(&CONN_HANDLE_HEADSET.to_le_bytes());
                    cc.extend_from_slice(&VIRTUAL_HEADSET_ADDR.0);
                    cc.push(0x01); // ACL
                    cc.push(0x00); // Encryption initially off
                    self.rx_events.push_back(cc);
                } else {
                    self.push_cmd_status(opcode, 0x04); // Page Timeout
                }
            }
            OP_DISCONNECT if p.len() >= 3 => {
                self.push_cmd_status(opcode, 0);
                let handle = u16::from_le_bytes([p[0], p[1]]) & 0x0FFF;
                self.connected = false;
                self.avdtp_sig_cid = None;
                self.avdtp_media_cid = None;
                self.avctp_cid = None;
                self.avdtp_streaming = false;
                self.peer_l2cap.on_acl_disconnected(handle);
                let mut dc = Vec::with_capacity(6);
                dc.push(EVT_DISCONN_COMPLETE);
                dc.push(4);
                dc.push(0x00);
                dc.extend_from_slice(&handle.to_le_bytes());
                dc.push(0x16); // Connection Terminated By Local Host
                self.rx_events.push_back(dc);
            }
            OP_AUTH_REQUESTED if p.len() >= 2 => {
                self.push_cmd_status(opcode, 0);
                let mut req = Vec::with_capacity(8);
                req.push(EVT_LINK_KEY_REQ);
                req.push(6);
                req.extend_from_slice(&VIRTUAL_HEADSET_ADDR.0);
                self.rx_events.push_back(req);
            }
            OP_LINK_KEY_REPLY if p.len() >= 22 => {
                let mut ret = Vec::with_capacity(6);
                ret.extend_from_slice(&p[0..6]);
                self.push_cmd_complete(opcode, 0, &ret);
                let mut ac = Vec::with_capacity(5);
                ac.push(EVT_AUTH_COMPLETE);
                ac.push(3);
                ac.push(0x00);
                ac.extend_from_slice(&CONN_HANDLE_HEADSET.to_le_bytes());
                self.rx_events.push_back(ac);
            }
            OP_LINK_KEY_NEG_REPLY if p.len() >= 6 => {
                self.push_cmd_complete(opcode, 0, &p[0..6]);
                // Initiate SSP Just-Works: controller asks host for IO Capability!
                let mut io_req = Vec::with_capacity(8);
                io_req.push(EVT_IO_CAP_REQ);
                io_req.push(6);
                io_req.extend_from_slice(&VIRTUAL_HEADSET_ADDR.0);
                self.rx_events.push_back(io_req);
            }
            OP_IO_CAP_REPLY if p.len() >= 9 => {
                self.push_cmd_complete(opcode, 0, &p[0..6]);
                let mut uc = Vec::with_capacity(12);
                uc.push(EVT_USER_CONFIRM_REQ);
                uc.push(10);
                uc.extend_from_slice(&VIRTUAL_HEADSET_ADDR.0);
                uc.extend_from_slice(&0u32.to_le_bytes());
                self.rx_events.push_back(uc);
            }
            OP_USER_CONFIRM_REPLY if p.len() >= 6 => {
                self.push_cmd_complete(opcode, 0, &p[0..6]);
                let mut spc = Vec::with_capacity(9);
                spc.push(EVT_SIMPLE_PAIRING_COMPLETE);
                spc.push(7);
                spc.push(0x00);
                spc.extend_from_slice(&VIRTUAL_HEADSET_ADDR.0);
                self.rx_events.push_back(spc);

                // Emit generated P-256 Link Key Notification (`0x18`)
                let mut lkn = Vec::with_capacity(25);
                lkn.push(EVT_LINK_KEY_NOTIFY);
                lkn.push(23);
                lkn.extend_from_slice(&VIRTUAL_HEADSET_ADDR.0);
                lkn.extend_from_slice(&[
                    0xA2, 0xD9, 0x48, 0x55, 0x45, 0x53, 0x4F, 0x53, 0x88, 0x21, 0xCE, 0xB7, 0x11,
                    0x22, 0x33, 0x44,
                ]);
                lkn.push(0x04); // Unauthenticated Combination Key generated from P-192
                self.rx_events.push_back(lkn);

                let mut ac = Vec::with_capacity(5);
                ac.push(EVT_AUTH_COMPLETE);
                ac.push(3);
                ac.push(0x00);
                ac.extend_from_slice(&CONN_HANDLE_HEADSET.to_le_bytes());
                self.rx_events.push_back(ac);
            }
            OP_SET_CONN_ENCRYPTION if p.len() >= 3 => {
                self.push_cmd_status(opcode, 0);
                let mut ec = Vec::with_capacity(6);
                ec.push(EVT_ENCRYPTION_CHANGE);
                ec.push(4);
                ec.push(0x00);
                ec.extend_from_slice(&p[0..2]);
                ec.push(p[2]);
                self.rx_events.push_back(ec);
            }
            _ => {
                // Standard housekeeping commands (`Reset`, `Set_Event_Mask`, `Write_Local_Name`, etc.)
                self.push_cmd_complete(opcode, 0, &[]);
            }
        }
    }

    /// Submit one Host -> Controller HCI ACL fragment (`[handle_lo, handle_hi, len_lo, len_hi, ...]`).
    pub fn submit_hci_acl(&mut self, acl: &[u8]) {
        if !self.connected || acl.len() < 4 {
            return;
        }
        // Immediately return `Number_Of_Completed_Packets (0x13)` for 1 ACL credit!
        let mut ncp = Vec::with_capacity(7);
        ncp.push(EVT_NUM_COMPLETED_PKTS);
        ncp.push(5);
        ncp.push(1);
        ncp.extend_from_slice(&CONN_HANDLE_HEADSET.to_le_bytes());
        ncp.extend_from_slice(&1u16.to_le_bytes());
        self.rx_events.push_back(ncp);

        if let Some((conn_handle, cid, payload)) = self.reasm.push_acl(acl) {
            self.peer_l2cap
                .on_reassembled_pdu(conn_handle, VIRTUAL_LOCAL_ADDR, cid, &payload);
            self.process_peer_l2cap();
        }
    }

    fn process_peer_l2cap(&mut self) {
        let events = self.peer_l2cap.drain_events();
        for ev in events {
            match ev {
                L2capEvent::ChannelOpened { local_cid, psm, .. } => match psm {
                    PSM_AVDTP => {
                        if self.avdtp_sig_cid.is_none() {
                            self.avdtp_sig_cid = Some(local_cid);
                        } else if self.avdtp_media_cid.is_none() {
                            self.avdtp_media_cid = Some(local_cid);
                        }
                    }
                    PSM_AVCTP => {
                        self.avctp_cid = Some(local_cid);
                    }
                    _ => {}
                },
                L2capEvent::ChannelClosed { local_cid, .. } => {
                    if self.avdtp_sig_cid == Some(local_cid) {
                        self.avdtp_sig_cid = None;
                        self.avdtp_streaming = false;
                    }
                    if self.avdtp_media_cid == Some(local_cid) {
                        self.avdtp_media_cid = None;
                    }
                    if self.avctp_cid == Some(local_cid) {
                        self.avctp_cid = None;
                    }
                }
                L2capEvent::DataReceived {
                    local_cid,
                    psm,
                    payload,
                } => match psm {
                    PSM_SDP => {
                        if payload.len() >= 5 && payload[0] == SDP_SVC_SEARCH_ATTR_REQ {
                            let tid = [payload[1], payload[2]];
                            // Minimal valid SDP SearchAttributeResponse advertising `0x110B` + `0x0019`
                            let attr_seq: &[u8] = &[
                                0x35,
                                0x0C,
                                0x35,
                                0x0A,
                                0x09,
                                0x00,
                                0x01,
                                0x35,
                                0x03,
                                0x19,
                                (UUID_AUDIO_SINK >> 8) as u8,
                                (UUID_AUDIO_SINK & 0xFF) as u8,
                                0x19,
                                (UUID_AVDTP >> 8) as u8,
                                (UUID_AVDTP & 0xFF) as u8,
                            ];
                            let mut rsp = Vec::new();
                            rsp.push(SDP_SVC_SEARCH_ATTR_RSP);
                            rsp.extend_from_slice(&tid);
                            let plen = (2 + attr_seq.len() + 1) as u16;
                            rsp.extend_from_slice(&plen.to_be_bytes());
                            rsp.extend_from_slice(&(attr_seq.len() as u16).to_be_bytes());
                            rsp.extend_from_slice(attr_seq);
                            rsp.push(0x00);
                            let _ = self.peer_l2cap.send_data(local_cid, &rsp);
                        }
                    }
                    PSM_AVDTP if Some(local_cid) == self.avdtp_sig_cid => {
                        self.handle_headset_avdtp_sig(local_cid, &payload);
                    }
                    PSM_AVDTP if Some(local_cid) == self.avdtp_media_cid => {
                        self.handle_headset_avdtp_media(&payload);
                    }
                    _ => {}
                },
            }
        }
        for out in self.peer_l2cap.drain_outbound() {
            for acl_frag in segment_l2cap_to_acl(out.conn_handle, &out.pdu, 1021) {
                self.rx_acl.push_back(acl_frag);
            }
        }
    }

    fn handle_headset_avdtp_sig(&mut self, sig_cid: u16, pkt: &[u8]) {
        if pkt.len() < 2 {
            return;
        }
        let tx_label_bits = pkt[0] & 0xF0;
        let msg_type = pkt[0] & 0x03;
        if msg_type != 0x00 {
            return; // Only respond to AVDTP Commands (`0x00`)
        }
        let sig_id = pkt[1] & 0x3F;
        let accept_hdr = tx_label_bits | 0x02; // Single packet + Response Accept (`0x02`)

        match sig_id {
            // AVDTP_DISCOVER (`0x01`) -> 1 Audio Sink SEP (`SEID = 1`, `in_use = 0`, `MediaType = Audio`, `TSEP = SNK`)
            0x01 => {
                let rsp = [accept_hdr, 0x01, HEADSET_SEID_SBC_SINK << 2, 0x08];
                let _ = self.peer_l2cap.send_data(sig_cid, &rsp);
            }
            // AVDTP_GET_CAPABILITIES (`0x02`) or GET_ALL_CAPABILITIES (`0x0C`)
            0x02 | 0x0C => {
                // Service Category 0x01 (Media Transport, len 0) +
                // Service Category 0x07 (Media Codec, len 6: Audio=0x00, SBC=0x00,
                //   freq=44.1|48kHz + all modes = 0x3F, blocks=4..16 + subbands=4|8 + alloc=SNR|Loudness = 0xFF,
                //   min_bitpool=2, max_bitpool=53)
                let rsp = [
                    accept_hdr, sig_id, 0x01, 0x00, 0x07, 0x06, 0x00, 0x00, 0x3F, 0xFF, 2, 53,
                ];
                let _ = self.peer_l2cap.send_data(sig_cid, &rsp);
            }
            // AVDTP_SET_CONFIGURATION (`0x03`), OPEN (`0x06`), START (`0x07`), CLOSE (`0x08`), SUSPEND (`0x09`)
            0x03 | 0x06 | 0x07 | 0x08 | 0x09 => {
                if sig_id == 0x07 {
                    self.avdtp_streaming = true;
                } else if sig_id == 0x08 || sig_id == 0x09 {
                    self.avdtp_streaming = false;
                }
                let rsp = [accept_hdr, sig_id];
                let _ = self.peer_l2cap.send_data(sig_cid, &rsp);
            }
            _ => {
                let rsp = [tx_label_bits | 0x03, sig_id, 0x11]; // Reject: Not supported command
                let _ = self.peer_l2cap.send_data(sig_cid, &rsp);
            }
        }
    }

    fn handle_headset_avdtp_media(&mut self, pkt: &[u8]) {
        // RTP header (12 bytes) + 1 byte A2DP SBC payload header + SBC frames (`0x9C` syncword)
        if !self.avdtp_streaming || pkt.len() < 14 {
            return;
        }
        if (pkt[0] >> 6) != 2 {
            return;
        }
        let num_frames = usize::from(pkt[12] & 0x0F);
        if pkt[13] == 0x9C && num_frames >= 1 {
            self.received_sbc_packets = self.received_sbc_packets.saturating_add(1);
            self.received_sbc_frames = self.received_sbc_frames.saturating_add(num_frames as u64);

            // Once real SBC audio arrives, simulate pressing `Volume Up` (`0x41`) on the earbuds!
            if !self.sent_avrcp_vol_up {
                if let Some(avctp_cid) = self.avctp_cid {
                    self.sent_avrcp_vol_up = true;
                    // AVCTP header (tx=1, C/R=0 cmd, PID=0x110E) + AVRCP Pass Through Press `0x41` (Vol Up)
                    let avrcp_press = [
                        0x10, 0x11, 0x0E, // AVCTP Command, PID = 0x110E (A/V Remote Control)
                        0x00, 0x48,
                        0x7C, // ctype=Control(0), subunit=Panel(9<<3), opcode=PassThrough(0x7C)
                        0x41, 0x00, // op_id = 0x41 (Volume Up pressed), data_len = 0
                    ];
                    let _ = self.peer_l2cap.send_data(avctp_cid, &avrcp_press);
                }
            }
        }
    }

    /// Pop next Controller -> Host HCI Event packet.
    pub fn pop_hci_event(&mut self) -> Option<Vec<u8>> {
        self.rx_events.pop_front()
    }

    /// Pop next Controller -> Host HCI ACL packet.
    pub fn pop_hci_acl(&mut self) -> Option<Vec<u8>> {
        self.rx_acl.pop_front()
    }
}
