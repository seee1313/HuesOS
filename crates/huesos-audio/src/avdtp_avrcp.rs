//! Pure-Rust Bluetooth AVDTP 1.3 (`PSM 0x0019` Audio Source state machine) and
//! AVCTP 1.4 / AVRCP 1.6 (`PSM 0x0017` Pass-Through media buttons & Absolute
//! Volume) protocol engines.
//!
//! Runs inside `audio-service` over `/net/btl` L2CAP channels so `btl-service`
//! stays a pure L2CAP/SDP/HCI transport.

use crate::sbc::{SbcAllocMethod, SbcBlocks, SbcChannelMode, SbcConfig, SbcSampleRate, SbcSubbands};

pub const PSM_AVDTP: u16 = 0x0019;
pub const PSM_AVCTP: u16 = 0x0017;

pub const AVDTP_MSG_COMMAND: u8 = 0x00;
pub const AVDTP_MSG_GENERAL_REJECT: u8 = 0x01;
pub const AVDTP_MSG_RESPONSE_ACCEPT: u8 = 0x02;
pub const AVDTP_MSG_RESPONSE_REJECT: u8 = 0x03;

pub const AVDTP_DISCOVER: u8 = 0x01;
pub const AVDTP_GET_CAPABILITIES: u8 = 0x02;
pub const AVDTP_SET_CONFIGURATION: u8 = 0x03;
pub const AVDTP_GET_CONFIGURATION: u8 = 0x04;
pub const AVDTP_RECONFIGURE: u8 = 0x05;
pub const AVDTP_OPEN: u8 = 0x06;
pub const AVDTP_START: u8 = 0x07;
pub const AVDTP_CLOSE: u8 = 0x08;
pub const AVDTP_SUSPEND: u8 = 0x09;
pub const AVDTP_ABORT: u8 = 0x0A;
pub const AVDTP_GET_ALL_CAPABILITIES: u8 = 0x0C;
pub const AVDTP_DELAYREPORT: u8 = 0x0D;

pub const AVDTP_CAT_MEDIA_TRANSPORT: u8 = 0x01;
pub const AVDTP_CAT_MEDIA_CODEC: u8 = 0x07;
pub const AVDTP_CAT_DELAY_REPORTING: u8 = 0x08;

pub const LOCAL_SOURCE_SEID: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvdtpState {
    Idle,
    Discovering,
    GettingCapabilities,
    SettingConfiguration,
    Opening,
    WaitingForMediaChannel,
    Starting,
    Streaming,
    Suspended,
    Failed(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvdtpAction {
    None,
    SendSignaling { len: usize, buf: [u8; 32] },
    OpenMediaL2capChannel,
    StreamReady(SbcConfig),
    StreamSuspended,
    StreamClosed,
}

/// Stateful AVDTP 1.3 Audio Source signaling engine (both Initiator and Acceptor).
#[derive(Clone, Copy, Debug)]
pub struct AvdtpSourceSession {
    state: AvdtpState,
    tx_label: u8,
    acp_seid: u8,
    negotiated_sbc: SbcConfig,
    delay_tenth_ms: u16,
    media_channel_up: bool,
}

impl AvdtpSourceSession {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AvdtpState::Idle,
            tx_label: 1,
            acp_seid: 1,
            negotiated_sbc: SbcConfig::HQ_48K_JOINT_STEREO,
            delay_tenth_ms: 0,
            media_channel_up: false,
        }
    }

    #[must_use]
    pub const fn state(&self) -> AvdtpState {
        self.state
    }

    #[must_use]
    pub const fn negotiated_sbc(&self) -> SbcConfig {
        self.negotiated_sbc
    }

    #[must_use]
    pub const fn delay_tenth_ms(&self) -> u16 {
        self.delay_tenth_ms
    }

    fn alloc_label(&mut self) -> u8 {
        let lbl = self.tx_label & 0x0F;
        self.tx_label = (self.tx_label.wrapping_add(1)) & 0x0F;
        lbl
    }

    fn make_cmd(&mut self, sig_id: u8, payload: &[u8]) -> AvdtpAction {
        let mut buf = [0u8; 32];
        let lbl = self.alloc_label();
        buf[0] = (lbl << 4) | AVDTP_MSG_COMMAND;
        buf[1] = sig_id & 0x3F;
        let copy_len = payload.len().min(30);
        buf[2..2 + copy_len].copy_from_slice(&payload[..copy_len]);
        AvdtpAction::SendSignaling {
            len: 2 + copy_len,
            buf,
        }
    }

    /// Begin initiator setup once the first `PSM 0x0019` L2CAP signaling channel opens.
    pub fn start_discovery(&mut self) -> AvdtpAction {
        self.state = AvdtpState::Discovering;
        self.media_channel_up = false;
        self.make_cmd(AVDTP_DISCOVER, &[])
    }

    /// Notify the state machine that the second `PSM 0x0019` L2CAP media transport channel is open.
    pub fn on_media_channel_opened(&mut self) -> AvdtpAction {
        self.media_channel_up = true;
        if self.state == AvdtpState::WaitingForMediaChannel {
            self.state = AvdtpState::Starting;
            let seid_arg = [self.acp_seid << 2];
            self.make_cmd(AVDTP_START, &seid_arg)
        } else {
            AvdtpAction::None
        }
    }

    /// Issue AVDTP Suspend (`0x09`) while keeping the stream configured.
    pub fn suspend(&mut self) -> AvdtpAction {
        if self.state == AvdtpState::Streaming {
            self.state = AvdtpState::Suspended;
            let seid_arg = [self.acp_seid << 2];
            self.make_cmd(AVDTP_SUSPEND, &seid_arg)
        } else {
            AvdtpAction::None
        }
    }

    /// Resume a suspended AVDTP stream with AVDTP Start (`0x07`).
    pub fn resume(&mut self) -> AvdtpAction {
        if self.state == AvdtpState::Suspended && self.media_channel_up {
            self.state = AvdtpState::Starting;
            let seid_arg = [self.acp_seid << 2];
            self.make_cmd(AVDTP_START, &seid_arg)
        } else {
            AvdtpAction::None
        }
    }

    /// Process an incoming AVDTP signaling PDU from the remote headset.
    pub fn on_signaling_pdu(&mut self, pdu: &[u8]) -> AvdtpAction {
        if pdu.len() < 2 {
            return AvdtpAction::None;
        }
        let tx_bits = pdu[0] & 0xF0;
        let msg_type = pdu[0] & 0x03;
        let sig_id = pdu[1] & 0x3F;
        let body = &pdu[2..];

        match msg_type {
            AVDTP_MSG_COMMAND => self.handle_peer_command(tx_bits, sig_id, body),
            AVDTP_MSG_RESPONSE_ACCEPT => self.handle_response_accept(sig_id, body),
            AVDTP_MSG_RESPONSE_REJECT | AVDTP_MSG_GENERAL_REJECT => {
                // Fall back from GET_ALL_CAPABILITIES (`0x0C`) to legacy GET_CAPABILITIES (`0x02`).
                if sig_id == AVDTP_GET_ALL_CAPABILITIES && self.state == AvdtpState::GettingCapabilities {
                    let arg = [self.acp_seid << 2];
                    return self.make_cmd(AVDTP_GET_CAPABILITIES, &arg);
                }
                let code = body.first().copied().unwrap_or(0xFF);
                self.state = AvdtpState::Failed(code);
                AvdtpAction::None
            }
            _ => AvdtpAction::None,
        }
    }

    fn handle_peer_command(&mut self, tx_bits: u8, sig_id: u8, body: &[u8]) -> AvdtpAction {
        let mut buf = [0u8; 32];
        buf[0] = tx_bits | AVDTP_MSG_RESPONSE_ACCEPT;
        buf[1] = sig_id;

        match sig_id {
            AVDTP_DISCOVER => {
                // Advertise Local SEID 1: Audio Source (`TSEP = 0`), Audio (`0`).
                buf[2] = LOCAL_SOURCE_SEID << 2;
                buf[3] = 0x00;
                AvdtpAction::SendSignaling { len: 4, buf }
            }
            AVDTP_GET_CAPABILITIES | AVDTP_GET_ALL_CAPABILITIES => {
                let caps = [
                    AVDTP_CAT_MEDIA_TRANSPORT,
                    0x00,
                    AVDTP_CAT_MEDIA_CODEC,
                    0x06,
                    0x00,
                    0x00,
                    0x3F,
                    0xFF,
                    2,
                    53,
                ];
                buf[2..2 + caps.len()].copy_from_slice(&caps);
                AvdtpAction::SendSignaling {
                    len: 2 + caps.len(),
                    buf,
                }
            }
            AVDTP_DELAYREPORT => {
                if body.len() >= 3 {
                    self.delay_tenth_ms = u16::from_be_bytes([body[1], body[2]]);
                }
                AvdtpAction::SendSignaling { len: 2, buf }
            }
            AVDTP_SET_CONFIGURATION => {
                if body.len() >= 2 {
                    self.acp_seid = body[1] >> 2;
                    if let Some(cfg) = select_sbc_from_service_caps(&body[2..]) {
                        self.negotiated_sbc = cfg;
                    }
                }
                AvdtpAction::SendSignaling { len: 2, buf }
            }
            AVDTP_OPEN => {
                self.state = AvdtpState::WaitingForMediaChannel;
                AvdtpAction::SendSignaling { len: 2, buf }
            }
            AVDTP_START => {
                self.state = AvdtpState::Streaming;
                AvdtpAction::SendSignaling { len: 2, buf }
            }
            AVDTP_SUSPEND => {
                self.state = AvdtpState::Suspended;
                AvdtpAction::SendSignaling { len: 2, buf }
            }
            AVDTP_CLOSE | AVDTP_ABORT => {
                self.state = AvdtpState::Idle;
                self.media_channel_up = false;
                AvdtpAction::SendSignaling { len: 2, buf }
            }
            _ => {
                buf[0] = tx_bits | AVDTP_MSG_RESPONSE_REJECT;
                buf[2] = 0x11;
                AvdtpAction::SendSignaling { len: 3, buf }
            }
        }
    }

    fn handle_response_accept(&mut self, sig_id: u8, body: &[u8]) -> AvdtpAction {
        match sig_id {
            AVDTP_DISCOVER => {
                // Find first available Audio Sink SEP (`TSEP = 1`, `in_use = 0`, `MediaType = 0`).
                let mut idx = 0usize;
                let mut found_seid = None;
                while idx + 1 < body.len() {
                    let seid = body[idx] >> 2;
                    let in_use = (body[idx] & 0x02) != 0;
                    let media_type = body[idx + 1] >> 4;
                    let tsep = (body[idx + 1] >> 3) & 0x01;
                    if seid != 0 && !in_use && media_type == 0 && tsep == 1 {
                        found_seid = Some(seid);
                        break;
                    }
                    idx += 2;
                }
                let seid = found_seid.unwrap_or(1);
                self.acp_seid = seid;
                self.state = AvdtpState::GettingCapabilities;
                let arg = [seid << 2];
                self.make_cmd(AVDTP_GET_ALL_CAPABILITIES, &arg)
            }
            AVDTP_GET_ALL_CAPABILITIES | AVDTP_GET_CAPABILITIES => {
                if let Some(cfg) = select_sbc_from_service_caps(body) {
                    self.negotiated_sbc = cfg;
                }
                self.state = AvdtpState::SettingConfiguration;
                let ie = encode_sbc_codec_ie(self.negotiated_sbc);
                let cfg_payload = [
                    self.acp_seid << 2,
                    LOCAL_SOURCE_SEID << 2,
                    AVDTP_CAT_MEDIA_TRANSPORT,
                    0x00,
                    AVDTP_CAT_MEDIA_CODEC,
                    0x06,
                    0x00, // Media Type = Audio
                    0x00, // Codec = SBC
                    ie[0],
                    ie[1],
                    ie[2],
                    ie[3],
                ];
                self.make_cmd(AVDTP_SET_CONFIGURATION, &cfg_payload)
            }
            AVDTP_SET_CONFIGURATION => {
                self.state = AvdtpState::Opening;
                let arg = [self.acp_seid << 2];
                self.make_cmd(AVDTP_OPEN, &arg)
            }
            AVDTP_OPEN => {
                if self.media_channel_up {
                    self.state = AvdtpState::Starting;
                    let arg = [self.acp_seid << 2];
                    self.make_cmd(AVDTP_START, &arg)
                } else {
                    self.state = AvdtpState::WaitingForMediaChannel;
                    AvdtpAction::OpenMediaL2capChannel
                }
            }
            AVDTP_START => {
                self.state = AvdtpState::Streaming;
                AvdtpAction::StreamReady(self.negotiated_sbc)
            }
            AVDTP_SUSPEND => {
                self.state = AvdtpState::Suspended;
                AvdtpAction::StreamSuspended
            }
            AVDTP_CLOSE => {
                self.state = AvdtpState::Idle;
                self.media_channel_up = false;
                AvdtpAction::StreamClosed
            }
            _ => AvdtpAction::None,
        }
    }
}

impl Default for AvdtpSourceSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Select the highest-fidelity SBC configuration supported by the Sink's service capabilities.
#[must_use]
pub fn select_sbc_from_service_caps(caps: &[u8]) -> Option<SbcConfig> {
    let mut pos = 0usize;
    while pos + 2 <= caps.len() {
        let cat = caps[pos];
        let len = usize::from(caps[pos + 1]);
        if pos + 2 + len > caps.len() {
            break;
        }
        let val = &caps[pos + 2..pos + 2 + len];
        if cat == AVDTP_CAT_MEDIA_CODEC && val.len() >= 6 && val[0] == 0x00 && val[1] == 0x00 {
            let b0 = val[2];
            let b1 = val[3];
            let min_bp = val[4].max(2);
            let max_bp = val[5].max(min_bp);

            let sample_rate = if (b0 & 0x10) != 0 {
                SbcSampleRate::Hz48000
            } else if (b0 & 0x20) != 0 {
                SbcSampleRate::Hz44100
            } else if (b0 & 0x40) != 0 {
                SbcSampleRate::Hz32000
            } else {
                SbcSampleRate::Hz16000
            };

            let channel_mode = if (b0 & 0x01) != 0 {
                SbcChannelMode::JointStereo
            } else if (b0 & 0x02) != 0 {
                SbcChannelMode::Stereo
            } else if (b0 & 0x04) != 0 {
                SbcChannelMode::DualChannel
            } else {
                SbcChannelMode::Mono
            };

            let blocks = if (b1 & 0x10) != 0 {
                SbcBlocks::B16
            } else if (b1 & 0x20) != 0 {
                SbcBlocks::B12
            } else if (b1 & 0x40) != 0 {
                SbcBlocks::B8
            } else {
                SbcBlocks::B4
            };

            let subbands = if (b1 & 0x04) != 0 {
                SbcSubbands::Sb8
            } else {
                SbcSubbands::Sb4
            };

            let alloc_method = if (b1 & 0x01) != 0 {
                SbcAllocMethod::Loudness
            } else {
                SbcAllocMethod::Snr
            };

            let bitpool = 53u8.clamp(min_bp, max_bp);
            return Some(SbcConfig {
                sample_rate,
                blocks,
                channel_mode,
                alloc_method,
                subbands,
                bitpool,
            });
        }
        pos += 2 + len;
    }
    None
}

/// Encode 4-byte SBC Codec Specific Information Elements for `AVDTP_SET_CONFIGURATION`.
#[must_use]
pub const fn encode_sbc_codec_ie(cfg: SbcConfig) -> [u8; 4] {
    let freq_bit = match cfg.sample_rate {
        SbcSampleRate::Hz16000 => 0x80,
        SbcSampleRate::Hz32000 => 0x40,
        SbcSampleRate::Hz44100 => 0x20,
        SbcSampleRate::Hz48000 => 0x10,
    };
    let mode_bit = match cfg.channel_mode {
        SbcChannelMode::Mono => 0x08,
        SbcChannelMode::DualChannel => 0x04,
        SbcChannelMode::Stereo => 0x02,
        SbcChannelMode::JointStereo => 0x01,
    };
    let blk_bit = match cfg.blocks {
        SbcBlocks::B4 => 0x80,
        SbcBlocks::B8 => 0x40,
        SbcBlocks::B12 => 0x20,
        SbcBlocks::B16 => 0x10,
    };
    let sb_bit = match cfg.subbands {
        SbcSubbands::Sb4 => 0x08,
        SbcSubbands::Sb8 => 0x04,
    };
    let alloc_bit = match cfg.alloc_method {
        SbcAllocMethod::Snr => 0x02,
        SbcAllocMethod::Loudness => 0x01,
    };
    [freq_bit | mode_bit, blk_bit | sb_bit | alloc_bit, 2, cfg.bitpool]
}

// ============================================================================
// AVCTP 1.4 / AVRCP 1.6 (`PSM 0x0017`)
// ============================================================================

pub const AVCTP_PID_AVRCP: u16 = 0x110E;
pub const AVRCP_CTYPE_CONTROL: u8 = 0x00;
pub const AVRCP_CTYPE_NOTIFY: u8 = 0x03;
pub const AVRCP_RSP_NOT_IMPLEMENTED: u8 = 0x08;
pub const AVRCP_RSP_ACCEPTED: u8 = 0x09;
pub const AVRCP_RSP_INTERIM: u8 = 0x0F;
pub const AVRCP_SUBUNIT_PANEL: u8 = 0x48; // Subunit_type = Panel (9 << 3) | ID 0
pub const AVRCP_OP_VENDOR_DEPENDENT: u8 = 0x00;
pub const AVRCP_OP_PASS_THROUGH: u8 = 0x7C;
pub const AVRCP_PDU_SET_ABSOLUTE_VOLUME: u8 = 0x50;
pub const AVRCP_PDU_REGISTER_NOTIFICATION: u8 = 0x31;
pub const AVRCP_EVENT_VOLUME_CHANGED: u8 = 0x0D;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvrcpButton {
    VolumeUp,
    VolumeDown,
    Mute,
    Play,
    Stop,
    Pause,
    NextTrack,
    PrevTrack,
    Unknown(u8),
}

impl AvrcpButton {
    #[must_use]
    pub const fn from_op_id(op_id: u8) -> Self {
        match op_id & 0x7F {
            0x41 => Self::VolumeUp,
            0x42 => Self::VolumeDown,
            0x43 => Self::Mute,
            0x44 => Self::Play,
            0x45 => Self::Stop,
            0x46 => Self::Pause,
            0x4B => Self::NextTrack,
            0x4C => Self::PrevTrack,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvrcpEvent {
    None,
    ButtonPressed(AvrcpButton),
    ButtonReleased(AvrcpButton),
    RemoteVolumeChanged(u8), // 0..=127
}

#[derive(Clone, Copy, Debug)]
pub struct AvrcpOutcome {
    pub event: AvrcpEvent,
    pub reply_len: usize,
    pub reply: [u8; 24],
}

/// Stateful AVRCP Controller/Target handler over AVCTP (`PSM 0x0017`).
#[derive(Clone, Copy, Debug)]
pub struct AvrcpSession {
    tx_label: u8,
    last_abs_volume: u8, // 0..=127 (`127` = 100%)
}

impl AvrcpSession {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tx_label: 1,
            last_abs_volume: 100,
        }
    }

    #[must_use]
    pub const fn last_abs_volume(&self) -> u8 {
        self.last_abs_volume
    }

    /// Encode an outgoing AVRCP `SetAbsoluteVolume` (`0..=127`) command over AVCTP.
    pub fn encode_set_absolute_volume(&mut self, volume_0_127: u8) -> ([u8; 14], usize) {
        let vol = volume_0_127 & 0x7F;
        self.last_abs_volume = vol;
        let lbl = self.tx_label & 0x0F;
        self.tx_label = (self.tx_label.wrapping_add(1)) & 0x0F;
        let pdu = [
            lbl << 4, // C/R = 0 (Command), Single packet
            (AVCTP_PID_AVRCP >> 8) as u8,
            (AVCTP_PID_AVRCP & 0xFF) as u8,
            AVRCP_CTYPE_CONTROL,
            AVRCP_SUBUNIT_PANEL,
            AVRCP_OP_VENDOR_DEPENDENT,
            0x00,
            0x19,
            0x58, // Bluetooth SIG Company ID `0x001958`
            AVRCP_PDU_SET_ABSOLUTE_VOLUME,
            0x00, // Packet Type = Single
            0x00,
            0x01, // Parameter Length = 1
            vol,
        ];
        (pdu, pdu.len())
    }

    /// Process an incoming AVCTP + AVRCP packet from the headset.
    pub fn on_avctp_pdu(&mut self, pdu: &[u8]) -> AvrcpOutcome {
        let mut out = AvrcpOutcome {
            event: AvrcpEvent::None,
            reply_len: 0,
            reply: [0u8; 24],
        };
        if pdu.len() < 6 {
            return out;
        }
        let tx_bits = pdu[0] & 0xF0;
        let is_response = (pdu[0] & 0x02) != 0;
        let pid = u16::from_be_bytes([pdu[1], pdu[2]]);
        if pid != AVCTP_PID_AVRCP {
            return out;
        }

        let ctype = pdu[3] & 0x0F;
        let opcode = pdu[5];

        if !is_response {
            if opcode == AVRCP_OP_PASS_THROUGH && pdu.len() >= 8 {
                let raw_op = pdu[6];
                let released = (raw_op & 0x80) != 0;
                let btn = AvrcpButton::from_op_id(raw_op);
                out.event = if released {
                    AvrcpEvent::ButtonReleased(btn)
                } else {
                    AvrcpEvent::ButtonPressed(btn)
                };

                let copy_len = pdu.len().min(out.reply.len());
                out.reply[..copy_len].copy_from_slice(&pdu[..copy_len]);
                out.reply[0] = tx_bits | 0x02; // AVCTP Response (`C/R = 1`)
                out.reply[3] = AVRCP_RSP_ACCEPTED;
                out.reply_len = copy_len;
                return out;
            }

            if opcode == AVRCP_OP_VENDOR_DEPENDENT && pdu.len() >= 13 {
                let pdu_id = pdu[9];
                if pdu_id == AVRCP_PDU_SET_ABSOLUTE_VOLUME && pdu.len() >= 14 {
                    let vol = pdu[13] & 0x7F;
                    self.last_abs_volume = vol;
                    out.event = AvrcpEvent::RemoteVolumeChanged(vol);
                    out.reply[..14].copy_from_slice(&pdu[..14]);
                    out.reply[0] = tx_bits | 0x02;
                    out.reply[3] = AVRCP_RSP_ACCEPTED;
                    out.reply[13] = vol;
                    out.reply_len = 14;
                    return out;
                }
                if pdu_id == AVRCP_PDU_REGISTER_NOTIFICATION
                    && ctype == AVRCP_CTYPE_NOTIFY
                    && pdu.len() >= 14
                    && pdu[13] == AVRCP_EVENT_VOLUME_CHANGED
                {
                    out.reply[..13].copy_from_slice(&pdu[..13]);
                    out.reply[0] = tx_bits | 0x02;
                    out.reply[3] = AVRCP_RSP_INTERIM;
                    out.reply[11] = 0x00;
                    out.reply[12] = 0x02;
                    out.reply[13] = AVRCP_EVENT_VOLUME_CHANGED;
                    out.reply[14] = self.last_abs_volume;
                    out.reply_len = 15;
                    return out;
                }
            }

            let copy_len = pdu.len().min(10);
            out.reply[..copy_len].copy_from_slice(&pdu[..copy_len]);
            out.reply[0] = tx_bits | 0x02;
            out.reply[3] = AVRCP_RSP_NOT_IMPLEMENTED;
            out.reply_len = copy_len;
        } else if opcode == AVRCP_OP_VENDOR_DEPENDENT && pdu.len() >= 14 {
            let pdu_id = pdu[9];
            if pdu_id == AVRCP_PDU_SET_ABSOLUTE_VOLUME {
                let vol = pdu[13] & 0x7F;
                self.last_abs_volume = vol;
                out.event = AvrcpEvent::RemoteVolumeChanged(vol);
            } else if pdu_id == AVRCP_PDU_REGISTER_NOTIFICATION
                && pdu.len() >= 15
                && pdu[13] == AVRCP_EVENT_VOLUME_CHANGED
            {
                let vol = pdu[14] & 0x7F;
                self.last_abs_volume = vol;
                out.event = AvrcpEvent::RemoteVolumeChanged(vol);
            }
        }
        out
    }
}

impl Default for AvrcpSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avdtp_initiator_negotiates_hq_sbc_stream() {
        let mut src = AvdtpSourceSession::new();
        let act0 = src.start_discovery();
        let AvdtpAction::SendSignaling { len, buf } = act0 else {
            assert_eq!(act0, AvdtpAction::StreamClosed);
            return;
        };
        assert_eq!(len, 2);
        assert_eq!(buf[1], AVDTP_DISCOVER);

        // Simulated Discover Accept (`SEID = 1`, Audio Sink)
        let act1 = src.on_signaling_pdu(&[(buf[0] & 0xF0) | 0x02, AVDTP_DISCOVER, 1 << 2, 0x08]);
        let AvdtpAction::SendSignaling { len: l1, buf: b1 } = act1 else {
            assert_eq!(act1, AvdtpAction::StreamClosed);
            return;
        };
        assert_eq!(l1, 3);
        assert_eq!(b1[1], AVDTP_GET_ALL_CAPABILITIES);

        // Simulated GetAllCapabilities Accept (`48k|44.1k`, `JS`, `16 blk`, `8 sb`, `2..53`)
        let caps_rsp = [
            (b1[0] & 0xF0) | 0x02,
            AVDTP_GET_ALL_CAPABILITIES,
            0x01,
            0x00,
            0x07,
            0x06,
            0x00,
            0x00,
            0x3F,
            0xFF,
            2,
            53,
        ];
        let act2 = src.on_signaling_pdu(&caps_rsp);
        let AvdtpAction::SendSignaling { buf: b2, .. } = act2 else {
            assert_eq!(act2, AvdtpAction::StreamClosed);
            return;
        };
        assert_eq!(b2[1], AVDTP_SET_CONFIGURATION);

        let act3 = src.on_signaling_pdu(&[(b2[0] & 0xF0) | 0x02, AVDTP_SET_CONFIGURATION]);
        let AvdtpAction::SendSignaling { buf: b3, .. } = act3 else {
            assert_eq!(act3, AvdtpAction::StreamClosed);
            return;
        };
        assert_eq!(b3[1], AVDTP_OPEN);

        let act4 = src.on_signaling_pdu(&[(b3[0] & 0xF0) | 0x02, AVDTP_OPEN]);
        assert_eq!(act4, AvdtpAction::OpenMediaL2capChannel);

        let act5 = src.on_media_channel_opened();
        let AvdtpAction::SendSignaling { buf: b5, .. } = act5 else {
            assert_eq!(act5, AvdtpAction::StreamClosed);
            return;
        };
        assert_eq!(b5[1], AVDTP_START);

        let act6 = src.on_signaling_pdu(&[(b5[0] & 0xF0) | 0x02, AVDTP_START]);
        assert_eq!(act6, AvdtpAction::StreamReady(SbcConfig::HQ_48K_JOINT_STEREO));
        assert_eq!(src.state(), AvdtpState::Streaming);
    }

    #[test]
    fn avrcp_pass_through_and_absolute_volume_work() {
        let mut avrcp = AvrcpSession::new();
        let incoming = [0x10, 0x11, 0x0E, 0x00, 0x48, 0x7C, 0x41, 0x00];
        let out = avrcp.on_avctp_pdu(&incoming);
        assert_eq!(out.event, AvrcpEvent::ButtonPressed(AvrcpButton::VolumeUp));
        assert_eq!(out.reply_len, 8);
        assert_eq!(out.reply[0], 0x12);
        assert_eq!(out.reply[3], AVRCP_RSP_ACCEPTED);

        let (vol_cmd, vol_len) = avrcp.encode_set_absolute_volume(96);
        assert_eq!(vol_len, 14);
        assert_eq!(vol_cmd[9], AVRCP_PDU_SET_ABSOLUTE_VOLUME);
        assert_eq!(vol_cmd[13], 96);
    }
}
