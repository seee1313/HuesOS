//! Wire protocol for `audio-service` (`/services/audio.elf`, `/dev/audio/*`)
//! and the isolated zero-heap `VirtIO-Sound` PCIe driver (`driver-host-snd`, `HSND`).
//!
//! Client PCM frames flow through lock-free `HARB` v1 SPSC shared-memory VMOs
//! (`OpenStream` transfers the VMO handle once; steady-state audio rendering
//! performs zero syscalls/IPC per frame).

#![forbid(unsafe_code)]

/// Wire magic `"HAUD"` in little-endian for `audio-service`.
pub const MAGIC: u32 = 0x4455_4148;
/// Protocol version.
pub const VERSION: u16 = 1;
/// Maximum Bluetooth sink name bytes reported in `AudioStatusSnapshot`.
pub const MAX_SINK_NAME_LEN: usize = 32;

/// Wire magic `"HSND"` in little-endian for `driver-host-snd <-> audio-service`.
pub const SND_DRIVER_MAGIC: u32 = 0x444E_5348;

/// Output sink routing policy managed by `audio-service`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AudioRouteMode {
    /// Automatically route to Bluetooth A2DP headphones when connected, falling back to `VirtIO-Sound`.
    #[default]
    Auto = 0,
    /// Force output exclusively through PCIe `VirtIO-Sound` (`driver-host-snd`).
    VirtioOnly = 1,
    /// Force output exclusively through `/net/btl` Bluetooth A2DP (`SBC`).
    BtlOnly = 2,
    /// Simultaneously mirror output to both `VirtIO-Sound` and Bluetooth A2DP with drift sync.
    Mirror = 3,
}

impl AudioRouteMode {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Auto,
            1 => Self::VirtioOnly,
            2 => Self::BtlOnly,
            3 => Self::Mirror,
            _ => return None,
        })
    }

    /// Canonical CLI/VFS mode name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::VirtioOnly => "virtio",
            Self::BtlOnly => "btl",
            Self::Mirror => "mirror",
        }
    }
}

/// `audio-service` IPC opcodes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudioOp {
    /// Query mixer, `VirtIO-Sound`, and Bluetooth A2DP/AVRCP telemetry.
    Status = 1,
    /// Allocate and attach a new lock-free `HARB` SPSC VMO playback stream.
    OpenStream = 2,
    /// Drain/close an existing playback stream by `stream_id`.
    CloseStream = 3,
    /// Set master volume (`0..=100`) and mute flag (syncs AVRCP Absolute Volume).
    SetVolume = 4,
    /// Set active sink routing policy (`auto`, `virtio`, `btl`, `mirror`).
    SetRouteMode = 5,
    /// Connect A2DP (`PSM 0x0019`) + AVRCP (`PSM 0x0017`) to a `/net/btl` peer.
    ConnectBtlSink = 6,
    /// Disconnect active Bluetooth A2DP + AVRCP session.
    DisconnectBtlSink = 7,
    /// Trigger a built-in stereo test tone (`freq_hz`, `duration_ms`).
    PlayTestTone = 8,
}

impl AudioOp {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Status,
            2 => Self::OpenStream,
            3 => Self::CloseStream,
            4 => Self::SetVolume,
            5 => Self::SetRouteMode,
            6 => Self::ConnectBtlSink,
            7 => Self::DisconnectBtlSink,
            8 => Self::PlayTestTone,
            _ => return None,
        })
    }

    /// True when `caps_mask::AUDIO_ADMIN` (`audio=admin`) is required.
    pub const fn requires_admin(self) -> bool {
        matches!(
            self,
            Self::SetVolume | Self::SetRouteMode | Self::ConnectBtlSink | Self::DisconnectBtlSink
        )
    }

    /// True when `caps_mask::AUDIO_RW` (`audio=rw` or `audio=admin`) is required.
    pub const fn requires_rw(self) -> bool {
        matches!(
            self,
            Self::OpenStream | Self::CloseStream | Self::PlayTestTone
        )
    }
}

/// Reply status codes from `audio-service`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudioStatus {
    /// Request succeeded.
    Ok = 0,
    /// Malformed request payload.
    InvalidRequest = 1,
    /// Caller lacks required `AUDIO_RO` / `AUDIO_RW` / `AUDIO_ADMIN` capability rights.
    AccessDenied = 2,
    /// All mixer SPSC stream slots are currently occupied.
    NoFreeStreams = 3,
    /// Target sink (`virtio-snd` or `/net/btl` peer) is unavailable.
    SinkUnavailable = 4,
    /// AVDTP / L2CAP negotiation with the Bluetooth headset failed.
    A2dpFailed = 5,
}

impl AudioStatus {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Ok,
            1 => Self::InvalidRequest,
            2 => Self::AccessDenied,
            3 => Self::NoFreeStreams,
            4 => Self::SinkUnavailable,
            5 => Self::A2dpFailed,
            _ => return None,
        })
    }
}

/// Fixed 96-byte status snapshot returned by [`AudioOp::Status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioStatusSnapshot {
    /// Master volume (`0..=100`).
    pub master_volume_pct: u8,
    /// Master mute flag.
    pub muted: bool,
    /// Configured routing mode (`auto`, `virtio`, `btl`, `mirror`).
    pub route_mode: AudioRouteMode,
    /// Bitmask of currently active hardware sinks (`bit 0 = virtio-snd`, `bit 1 = btl-a2dp`).
    pub active_sinks_mask: u8,
    /// True if `driver-host-snd` (`1af4:1059`) initialized and attached its TX ring.
    pub virtio_online: bool,
    /// True if an A2DP media stream is open and streaming over `/net/btl`.
    pub btl_streaming: bool,
    /// Number of active client PCM streams (`aplay`, `doom`, etc.).
    pub active_streams: u8,
    /// Negotiated SBC bitpool (`2..=250`, typically `53`).
    pub btl_sbc_bitpool: u8,
    /// Mixer & `VirtIO-Sound` output sample rate (`48000` Hz).
    pub mix_sample_rate: u32,
    /// Current SBC bitrate in kbps (`345` kbps for HQ 48 kHz Joint Stereo).
    pub btl_bitrate_kbps: u16,
    /// AVRCP button / volume events processed from headphones.
    pub avrcp_events: u16,
    /// Connected Bluetooth A2DP sink `BD_ADDR` (little-endian HCI order).
    pub btl_peer_addr: [u8; 6],
    /// Valid bytes in `btl_peer_name`.
    pub btl_peer_name_len: u8,
    /// Last AVRCP button code (`0` if none).
    pub last_avrcp_op: u8,
    /// Total stereo frames mixed by `audio-service`.
    pub mixed_frames: u64,
    /// Total `VirtIO-Sound` DMA periods completed by `driver-host-snd`.
    pub virtio_periods: u64,
    /// Total RTP+SBC media packets transmitted over `/net/btl` `PSM 0x0019`.
    pub btl_rtp_packets: u64,
    /// Total ring buffer underruns across sinks.
    pub underruns: u32,
    /// Connected Bluetooth headset product name.
    pub btl_peer_name: [u8; MAX_SINK_NAME_LEN],
}

impl Default for AudioStatusSnapshot {
    fn default() -> Self {
        Self {
            master_volume_pct: 80,
            muted: false,
            route_mode: AudioRouteMode::Auto,
            active_sinks_mask: 0,
            virtio_online: false,
            btl_streaming: false,
            active_streams: 0,
            btl_sbc_bitpool: 0,
            mix_sample_rate: 48_000,
            btl_bitrate_kbps: 0,
            avrcp_events: 0,
            btl_peer_addr: [0; 6],
            btl_peer_name_len: 0,
            last_avrcp_op: 0,
            mixed_frames: 0,
            virtio_periods: 0,
            btl_rtp_packets: 0,
            underruns: 0,
            btl_peer_name: [0; MAX_SINK_NAME_LEN],
        }
    }
}

impl AudioStatusSnapshot {
    /// Fixed wire size including 8-byte `HAUD` header (`96` bytes).
    pub const REPLY_LEN: usize = 96;

    /// Connected Bluetooth sink name as `&str`.
    pub fn btl_peer_name_str(&self) -> &str {
        let len = usize::from(self.btl_peer_name_len).min(MAX_SINK_NAME_LEN);
        core::str::from_utf8(&self.btl_peer_name[..len]).unwrap_or("")
    }

    /// Encode reply packet with `HAUD` header.
    pub fn encode_reply(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < Self::REPLY_LEN {
            return None;
        }
        out[..Self::REPLY_LEN].fill(0);
        write_header(out, AudioOp::Status, AudioStatus::Ok);
        out[8] = self.master_volume_pct;
        out[9] = u8::from(self.muted);
        out[10] = self.route_mode as u8;
        out[11] = self.active_sinks_mask;
        out[12] = u8::from(self.virtio_online) | (u8::from(self.btl_streaming) << 1);
        out[13] = self.active_streams;
        out[14] = self.btl_sbc_bitpool;
        out[15] = self.last_avrcp_op;
        out[16..20].copy_from_slice(&self.mix_sample_rate.to_le_bytes());
        out[20..22].copy_from_slice(&self.btl_bitrate_kbps.to_le_bytes());
        out[22..24].copy_from_slice(&self.avrcp_events.to_le_bytes());
        out[24..30].copy_from_slice(&self.btl_peer_addr);
        out[30] = self.btl_peer_name_len.min(MAX_SINK_NAME_LEN as u8);
        out[32..40].copy_from_slice(&self.mixed_frames.to_le_bytes());
        out[40..48].copy_from_slice(&self.virtio_periods.to_le_bytes());
        out[48..56].copy_from_slice(&self.btl_rtp_packets.to_le_bytes());
        out[56..60].copy_from_slice(&self.underruns.to_le_bytes());
        out[64..64 + MAX_SINK_NAME_LEN].copy_from_slice(&self.btl_peer_name);
        Some(Self::REPLY_LEN)
    }

    /// Decode reply packet.
    pub fn decode_reply(bytes: &[u8]) -> Result<Self, AudioStatus> {
        let st = check_header(bytes, AudioOp::Status)?;
        if st != AudioStatus::Ok {
            return Err(st);
        }
        if bytes.len() < Self::REPLY_LEN {
            return Err(AudioStatus::InvalidRequest);
        }
        let mut btl_peer_addr = [0u8; 6];
        btl_peer_addr.copy_from_slice(&bytes[24..30]);
        let mut btl_peer_name = [0u8; MAX_SINK_NAME_LEN];
        btl_peer_name.copy_from_slice(&bytes[64..64 + MAX_SINK_NAME_LEN]);
        Ok(Self {
            master_volume_pct: bytes[8],
            muted: bytes[9] != 0,
            route_mode: AudioRouteMode::from_raw(bytes[10]).ok_or(AudioStatus::InvalidRequest)?,
            active_sinks_mask: bytes[11],
            virtio_online: (bytes[12] & 1) != 0,
            btl_streaming: (bytes[12] & 2) != 0,
            active_streams: bytes[13],
            btl_sbc_bitpool: bytes[14],
            last_avrcp_op: bytes[15],
            mix_sample_rate: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            btl_bitrate_kbps: u16::from_le_bytes([bytes[20], bytes[21]]),
            avrcp_events: u16::from_le_bytes([bytes[22], bytes[23]]),
            btl_peer_addr,
            btl_peer_name_len: bytes[30].min(MAX_SINK_NAME_LEN as u8),
            mixed_frames: u64::from_le_bytes([
                bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38],
                bytes[39],
            ]),
            virtio_periods: u64::from_le_bytes([
                bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46],
                bytes[47],
            ]),
            btl_rtp_packets: u64::from_le_bytes([
                bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54],
                bytes[55],
            ]),
            underruns: u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]),
            btl_peer_name,
        })
    }
}

/// Internal `audio-service <-> driver-host-snd` IPC opcodes (`HSND`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SndDriverOp {
    /// Query `VirtIO-Sound` hardware state, negotiated sample rate, and completed DMA periods.
    QueryHw = 1,
    /// Attach the shared master `HARB` SPSC VMO handle for DMA TX playback.
    AttachMasterRing = 2,
    /// Set hardware stream active/paused state (`0 = pause`, `1 = run`).
    SetRunning = 3,
}

impl SndDriverOp {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::QueryHw,
            2 => Self::AttachMasterRing,
            3 => Self::SetRunning,
            _ => return None,
        })
    }
}

/// Write an 8-byte `HAUD` wire header.
pub fn write_header(out: &mut [u8], op: AudioOp, status: AudioStatus) {
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6] = op as u8;
    out[7] = status as u8;
}

/// Parse an `HAUD` request header into `(op, payload)`.
pub fn parse_request(bytes: &[u8]) -> Option<(AudioOp, &[u8])> {
    if bytes.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let ver = u16::from_le_bytes([bytes[4], bytes[5]]);
    if magic != MAGIC || ver != VERSION {
        return None;
    }
    Some((AudioOp::from_raw(bytes[6])?, &bytes[8..]))
}

/// Validate an `HAUD` reply header against `expected_op`.
pub fn check_header(bytes: &[u8], expected_op: AudioOp) -> Result<AudioStatus, AudioStatus> {
    if bytes.len() < 8 {
        return Err(AudioStatus::InvalidRequest);
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let ver = u16::from_le_bytes([bytes[4], bytes[5]]);
    if magic != MAGIC || ver != VERSION || bytes[6] != expected_op as u8 {
        return Err(AudioStatus::InvalidRequest);
    }
    AudioStatus::from_raw(bytes[7]).ok_or(AudioStatus::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_status_roundtrip() {
        let mut snap = AudioStatusSnapshot {
            master_volume_pct: 85,
            muted: false,
            route_mode: AudioRouteMode::Mirror,
            active_sinks_mask: 0x03,
            virtio_online: true,
            btl_streaming: true,
            active_streams: 2,
            btl_sbc_bitpool: 53,
            mix_sample_rate: 48_000,
            btl_bitrate_kbps: 345,
            avrcp_events: 1,
            btl_peer_addr: [0xD9, 0xA2, 0xB7, 0x00, 0x54, 0x52],
            btl_peer_name_len: 18,
            last_avrcp_op: 0x41,
            mixed_frames: 48_000,
            virtio_periods: 100,
            btl_rtp_packets: 75,
            underruns: 0,
            btl_peer_name: [0; MAX_SINK_NAME_LEN],
        };
        snap.btl_peer_name[..18].copy_from_slice(b"HuesOS AirBuds Pro");
        let mut buf = [0u8; AudioStatusSnapshot::REPLY_LEN];
        assert_eq!(
            snap.encode_reply(&mut buf),
            Some(AudioStatusSnapshot::REPLY_LEN)
        );
        assert_eq!(AudioStatusSnapshot::decode_reply(&buf), Ok(snap));
    }
}
