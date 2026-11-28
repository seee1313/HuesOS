//! OASIS VirtIO 1.2 §5.14 Sound Device (`virtio-snd`, PCI `1af4:1059`)
//! wire protocol structures, stream capability negotiation, and virtqueue framing.

/// PCI Vendor ID for VirtIO devices (Red Hat / Qumranet).
pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1AF4;
/// Modern VirtIO 1.2 Sound PCI Device ID (`0x1040 + 25`).
pub const VIRTIO_SND_PCI_DEVICE_ID: u16 = 0x1059;

/// Virtqueue 0: synchronous control requests (`PCM_INFO`, `SET_PARAMS`, `PREPARE`, `START`).
pub const VIRTIO_SND_VQ_CONTROL: u16 = 0;
/// Virtqueue 1: asynchronous jack/PCM device events.
pub const VIRTIO_SND_VQ_EVENT: u16 = 1;
/// Virtqueue 2: PCM playback (`Host -> Device`).
pub const VIRTIO_SND_VQ_TX: u16 = 2;
/// Virtqueue 3: PCM capture (`Device -> Host`).
pub const VIRTIO_SND_VQ_RX: u16 = 3;

// ---- Control Request Codes (`virtio_snd_hdr.code`) ----
/// Query jack descriptors (`0x0001`).
pub const VIRTIO_SND_R_JACK_INFO: u32 = 0x0001;
/// Query PCM stream capabilities (`0x0100`).
pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
/// Configure PCM stream parameters (`0x0101`).
pub const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
/// Prepare configured PCM stream for I/O (`0x0102`).
pub const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
/// Release prepared PCM stream (`0x0103`).
pub const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
/// Start PCM stream playback/capture (`0x0104`).
pub const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
/// Stop PCM stream playback/capture (`0x0105`).
pub const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;

// ---- Status Codes (`virtio_snd_hdr.code` in device response) ----
/// Request succeeded (`0x8000`).
pub const VIRTIO_SND_S_OK: u32 = 0x8000;
/// Malformed message (`0x8001`).
pub const VIRTIO_SND_S_BAD_MSG: u32 = 0x8001;
/// Requested feature/format/rate unsupported (`0x8002`).
pub const VIRTIO_SND_S_NOT_SUPP: u32 = 0x8002;
/// Device I/O error (`0x8003`).
pub const VIRTIO_SND_S_IO_ERR: u32 = 0x8003;

// ---- Stream Direction ----
/// Output (playback) stream (`0`).
pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
/// Input (capture) stream (`1`).
pub const VIRTIO_SND_D_INPUT: u8 = 1;

// ---- PCM Sample Formats (`VIRTIO_SND_PCM_FMT_*`) ----
/// Unsigned 8-bit PCM (`1`).
pub const VIRTIO_SND_PCM_FMT_U8: u8 = 1;
/// Signed 16-bit little-endian PCM (`5`).
pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;
/// Signed 24-bit in 32-bit PCM (`7`).
pub const VIRTIO_SND_PCM_FMT_S24: u8 = 7;
/// Signed 32-bit little-endian PCM (`9`).
pub const VIRTIO_SND_PCM_FMT_S32: u8 = 9;

// ---- PCM Sample Rates (`VIRTIO_SND_PCM_RATE_*`) ----
/// `8000 Hz` (`1`).
pub const VIRTIO_SND_PCM_RATE_8000: u8 = 1;
/// `11025 Hz` (`2`).
pub const VIRTIO_SND_PCM_RATE_11025: u8 = 2;
/// `22050 Hz` (`4`).
pub const VIRTIO_SND_PCM_RATE_22050: u8 = 4;
/// `44100 Hz` (`6`).
pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
/// `48000 Hz` (`7`).
pub const VIRTIO_SND_PCM_RATE_48000: u8 = 7;

/// Byte size of one `virtio_snd_pcm_info` entry (`32` bytes).
pub const PCM_INFO_ENTRY_BYTES: usize = 32;
/// Byte size of `virtio_snd_pcm_set_params` request (`24` bytes).
pub const PCM_SET_PARAMS_BYTES: usize = 24;
/// Byte size of `virtio_snd_pcm_hdr` request (`START`/`PREPARE`/`STOP`/`RELEASE`: `8` bytes).
pub const PCM_SIMPLE_HDR_BYTES: usize = 8;
/// Byte size of `virtio_snd_pcm_xfer` header preceding TX audio frames (`4` bytes).
pub const PCM_XFER_HDR_BYTES: usize = 4;
/// Byte size of `virtio_snd_pcm_status` trailer written by device after TX (`8` bytes).
pub const PCM_STATUS_BYTES: usize = 8;

/// Decoded `virtio_snd_config` read from VirtIO `device_cfg` MMIO region (`12` bytes).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioSndConfig {
    /// Total jacks exposed by device.
    pub jacks: u32,
    /// Total PCM streams exposed by device.
    pub streams: u32,
    /// Total channel maps exposed by device.
    pub chmaps: u32,
}

impl VirtioSndConfig {
    /// Decode 12-byte device configuration block.
    pub const fn decode(raw: [u8; 12]) -> Self {
        Self {
            jacks: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
            streams: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
            chmaps: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
        }
    }
}

/// Decoded `virtio_snd_pcm_info` (`32` bytes) for one stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioSndPcmInfo {
    /// HDA function group NID.
    pub hda_fn_nid: u32,
    /// Supported `VIRTIO_SND_PCM_F_*` bitmask.
    pub features: u32,
    /// Bitmask of `(1u64 << VIRTIO_SND_PCM_FMT_*)`.
    pub formats: u64,
    /// Bitmask of `(1u64 << VIRTIO_SND_PCM_RATE_*)`.
    pub rates: u64,
    /// `VIRTIO_SND_D_OUTPUT` (`0`) or `VIRTIO_SND_D_INPUT` (`1`).
    pub direction: u8,
    /// Minimum channel count.
    pub channels_min: u8,
    /// Maximum channel count.
    pub channels_max: u8,
}

impl VirtioSndPcmInfo {
    /// Decode a 32-byte `virtio_snd_pcm_info` record.
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < PCM_INFO_ENTRY_BYTES {
            return None;
        }
        Some(Self {
            hda_fn_nid: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
            features: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
            formats: u64::from_le_bytes([
                raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
            ]),
            rates: u64::from_le_bytes([
                raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
            ]),
            direction: raw[24],
            channels_min: raw[25],
            channels_max: raw[26],
        })
    }

    /// True if this stream is a stereo `S16LE` playback output supporting `48 kHz` or `44.1 kHz`.
    pub const fn supports_stereo_s16_output(&self) -> bool {
        if self.direction != VIRTIO_SND_D_OUTPUT {
            return false;
        }
        if self.channels_min > 2 || self.channels_max < 2 {
            return false;
        }
        let s16_ok = (self.formats & (1u64 << VIRTIO_SND_PCM_FMT_S16)) != 0;
        let rate_ok = (self.rates
            & ((1u64 << VIRTIO_SND_PCM_RATE_48000) | (1u64 << VIRTIO_SND_PCM_RATE_44100)))
            != 0;
        s16_ok && rate_ok
    }

    /// Preferred rate `(virtio_rate_code, hz)` (`48000 Hz` preferred, `44100 Hz` fallback).
    pub const fn preferred_rate(&self) -> Option<(u8, u32)> {
        if (self.rates & (1u64 << VIRTIO_SND_PCM_RATE_48000)) != 0 {
            Some((VIRTIO_SND_PCM_RATE_48000, 48_000))
        } else if (self.rates & (1u64 << VIRTIO_SND_PCM_RATE_44100)) != 0 {
            Some((VIRTIO_SND_PCM_RATE_44100, 44_100))
        } else {
            None
        }
    }
}

/// Encode `virtio_snd_query_info` (`16` bytes) for `VIRTIO_SND_R_PCM_INFO`.
pub fn encode_query_pcm_info(start_id: u32, count: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_INFO.to_le_bytes());
    out[4..8].copy_from_slice(&start_id.to_le_bytes());
    out[8..12].copy_from_slice(&count.to_le_bytes());
    out[12..16].copy_from_slice(&(PCM_INFO_ENTRY_BYTES as u32).to_le_bytes());
    out
}

/// Encode `virtio_snd_pcm_set_params` (`24` bytes).
pub fn encode_pcm_set_params(
    stream_id: u32,
    buffer_bytes: u32,
    period_bytes: u32,
    channels: u8,
    format: u8,
    rate: u8,
) -> [u8; PCM_SET_PARAMS_BYTES] {
    let mut out = [0u8; PCM_SET_PARAMS_BYTES];
    out[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_SET_PARAMS.to_le_bytes());
    out[4..8].copy_from_slice(&stream_id.to_le_bytes());
    out[8..12].copy_from_slice(&buffer_bytes.to_le_bytes());
    out[12..16].copy_from_slice(&period_bytes.to_le_bytes());
    out[16..20].copy_from_slice(&0u32.to_le_bytes()); // features = 0
    out[20] = channels;
    out[21] = format;
    out[22] = rate;
    out[23] = 0;
    out
}

/// Encode `virtio_snd_pcm_hdr` (`8` bytes) for `PREPARE`, `START`, `STOP`, or `RELEASE`.
pub fn encode_pcm_simple_cmd(code: u32, stream_id: u32) -> [u8; PCM_SIMPLE_HDR_BYTES] {
    let mut out = [0u8; PCM_SIMPLE_HDR_BYTES];
    out[0..4].copy_from_slice(&code.to_le_bytes());
    out[4..8].copy_from_slice(&stream_id.to_le_bytes());
    out
}

/// Decode a 4-byte `virtio_snd_hdr` status response (`VIRTIO_SND_S_OK == 0x8000`).
pub fn decode_status_code(raw: &[u8]) -> Option<u32> {
    if raw.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}
