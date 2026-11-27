//! Pure-Rust integer Bluetooth A2DP Subband Codec (`SBC`, A2DP v1.3 Appendix B)
//! encoder, reference decoder, adaptive bitpool controller, and RTP media
//! packetizer (`PSM 0x0019` media transport).
//!
//! Runs strictly in Ring-3 `audio-service` above the transport-only `/net/btl`
//! L2CAP layer (`#! [no_std]`, `#![forbid(unsafe_code)]`, zero heap required).

pub const SBC_SYNCWORD: u8 = 0x9C;
pub const SBC_MAX_SUBBANDS: usize = 8;
pub const SBC_MAX_BLOCKS: usize = 16;
pub const SBC_MAX_CHANNELS: usize = 2;
pub const SBC_MAX_PCM_FRAMES: usize = SBC_MAX_BLOCKS * SBC_MAX_SUBBANDS; // 128 stereo frames
pub const SBC_MAX_FRAME_BYTES: usize = 512;

pub const RTP_VERSION_2: u8 = 0x80;
pub const RTP_PAYLOAD_SBC: u8 = 96;
pub const RTP_HEADER_LEN: usize = 12;
pub const A2DP_SBC_PAYLOAD_HDR_LEN: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbcSampleRate {
    Hz16000 = 0,
    Hz32000 = 1,
    Hz44100 = 2,
    Hz48000 = 3,
}

impl SbcSampleRate {
    #[must_use]
    pub const fn hz(self) -> u32 {
        match self {
            Self::Hz16000 => 16_000,
            Self::Hz32000 => 32_000,
            Self::Hz44100 => 44_100,
            Self::Hz48000 => 48_000,
        }
    }

    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code & 0x03 {
            0 => Self::Hz16000,
            1 => Self::Hz32000,
            2 => Self::Hz44100,
            _ => Self::Hz48000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbcBlocks {
    B4 = 0,
    B8 = 1,
    B12 = 2,
    B16 = 3,
}

impl SbcBlocks {
    #[must_use]
    pub const fn count(self) -> usize {
        match self {
            Self::B4 => 4,
            Self::B8 => 8,
            Self::B12 => 12,
            Self::B16 => 16,
        }
    }

    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code & 0x03 {
            0 => Self::B4,
            1 => Self::B8,
            2 => Self::B12,
            _ => Self::B16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbcChannelMode {
    Mono = 0,
    DualChannel = 1,
    Stereo = 2,
    JointStereo = 3,
}

impl SbcChannelMode {
    #[must_use]
    pub const fn channels(self) -> usize {
        match self {
            Self::Mono => 1,
            Self::DualChannel | Self::Stereo | Self::JointStereo => 2,
        }
    }

    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code & 0x03 {
            0 => Self::Mono,
            1 => Self::DualChannel,
            2 => Self::Stereo,
            _ => Self::JointStereo,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbcAllocMethod {
    Loudness = 0,
    Snr = 1,
}

impl SbcAllocMethod {
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        if (code & 1) == 0 {
            Self::Loudness
        } else {
            Self::Snr
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbcSubbands {
    Sb4 = 0,
    Sb8 = 1,
}

impl SbcSubbands {
    #[must_use]
    pub const fn count(self) -> usize {
        match self {
            Self::Sb4 => 4,
            Self::Sb8 => 8,
        }
    }

    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        if (code & 1) == 0 {
            Self::Sb4
        } else {
            Self::Sb8
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbcError {
    BufferTooSmall,
    InvalidPcmLength,
    InvalidSyncword,
    CrcMismatch,
    TruncatedFrame,
    InvalidBitpool,
}

/// Negotiated SBC configuration (default: High-Quality A2DP 48 kHz Joint Stereo,
/// 16 blocks, 8 subbands, Loudness, bitpool 53 = ~345 kbps).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SbcConfig {
    pub sample_rate: SbcSampleRate,
    pub blocks: SbcBlocks,
    pub channel_mode: SbcChannelMode,
    pub alloc_method: SbcAllocMethod,
    pub subbands: SbcSubbands,
    pub bitpool: u8,
}

impl SbcConfig {
    pub const HQ_48K_JOINT_STEREO: Self = Self {
        sample_rate: SbcSampleRate::Hz48000,
        blocks: SbcBlocks::B16,
        channel_mode: SbcChannelMode::JointStereo,
        alloc_method: SbcAllocMethod::Loudness,
        subbands: SbcSubbands::Sb8,
        bitpool: 53,
    };

    #[must_use]
    pub const fn pcm_frames_per_sbc_frame(self) -> usize {
        self.blocks.count() * self.subbands.count()
    }

    #[must_use]
    pub const fn header_byte1(self) -> u8 {
        ((self.sample_rate as u8) << 6)
            | ((self.blocks as u8) << 4)
            | ((self.channel_mode as u8) << 2)
            | ((self.alloc_method as u8) << 1)
            | (self.subbands as u8)
    }

    /// Exact SBC frame byte length per Bluetooth A2DP v1.3 §12.9.
    #[must_use]
    pub const fn frame_byte_len(self) -> usize {
        let nrof_subbands = self.subbands.count();
        let nrof_blocks = self.blocks.count();
        let nrof_channels = self.channel_mode.channels();
        let bitpool = self.bitpool as usize;
        let base = 4 + (4 * nrof_subbands * nrof_channels) / 8;
        let payload_bits = match self.channel_mode {
            SbcChannelMode::Mono | SbcChannelMode::DualChannel => {
                nrof_blocks * nrof_channels * bitpool
            }
            SbcChannelMode::Stereo => nrof_blocks * bitpool,
            SbcChannelMode::JointStereo => nrof_subbands + nrof_blocks * bitpool,
        };
        base + payload_bits.div_ceil(8)
    }

    /// Nominal bitrate in bits per second.
    #[must_use]
    pub const fn bitrate_bps(self) -> u32 {
        let frame_bits = (self.frame_byte_len() as u64) * 8;
        let num = frame_bits * (self.sample_rate.hz() as u64);
        let den = self.pcm_frames_per_sbc_frame() as u64;
        (num / den) as u32
    }
}

impl Default for SbcConfig {
    fn default() -> Self {
        Self::HQ_48K_JOINT_STEREO
    }
}

/// Bluetooth A2DP v1.3 Table 12.1 4-subband prototype window (`Q31` signed).
const PROTO_4_Q31: [i32; 40] = [
    0x0000_0000_u32 as i32,
    0x0011_94E6_u32 as i32,
    0x0030_E2D3_u32 as i32,
    0x0059_9403_u32 as i32,
    0x007D_BCC8_u32 as i32,
    0x007F_88E4_u32 as i32,
    0x003D_239B_u32 as i32,
    0xFF9B_B9D5_u32 as i32,
    0x0165_9F45_u32 as i32,
    0x029D_BAA3_u32 as i32,
    0x03B2_3341_u32 as i32,
    0x041E_EE40_u32 as i32,
    0x034F_EE2C_u32 as i32,
    0x00C8_F2BC_u32 as i32,
    0xFC4F_91D4_u32 as i32,
    0xF60F_AF37_u32 as i32,
    0x115B_1ED2_u32 as i32,
    0x18F5_5C90_u32 as i32,
    0x1F91_CA46_u32 as i32,
    0x2412_F251_u32 as i32,
    0x25AC_1FF2_u32 as i32,
    0x2412_F251_u32 as i32,
    0x1F91_CA46_u32 as i32,
    0x18F5_5C90_u32 as i32,
    0xEEA4_E12E_u32 as i32,
    0xF60F_AF37_u32 as i32,
    0xFC4F_91D4_u32 as i32,
    0x00C8_F2BC_u32 as i32,
    0x034F_EE2C_u32 as i32,
    0x041E_EE40_u32 as i32,
    0x03B2_3341_u32 as i32,
    0x029D_BAA3_u32 as i32,
    0xFE9A_60BB_u32 as i32,
    0xFF9B_B9D5_u32 as i32,
    0x003D_239B_u32 as i32,
    0x007F_88E4_u32 as i32,
    0x007D_BCC8_u32 as i32,
    0x0059_9403_u32 as i32,
    0x0030_E2D3_u32 as i32,
    0x0011_94E6_u32 as i32,
];

/// Bluetooth A2DP v1.3 Table 12.2 8-subband prototype window (`Q31` signed).
const PROTO_8_Q31: [i32; 80] = [
    0x0000_0000_u32 as i32,
    0x0005_2173_u32 as i32,
    0x000B_3F71_u32 as i32,
    0x0012_2C7D_u32 as i32,
    0x001A_FF89_u32 as i32,
    0x0025_5A62_u32 as i32,
    0x0030_60F4_u32 as i32,
    0x003A_72E7_u32 as i32,
    0x0041_EC6A_u32 as i32,
    0x0044_EF48_u32 as i32,
    0x0041_5B75_u32 as i32,
    0x0034_F8B6_u32 as i32,
    0x001D_8FD2_u32 as i32,
    0xFFFA_2413_u32 as i32,
    0xFFC9_F10E_u32 as i32,
    0xFF8D_6793_u32 as i32,
    0x00B9_7348_u32 as i32,
    0x0107_1B96_u32 as i32,
    0x0156_B3CA_u32 as i32,
    0x01A1_B38B_u32 as i32,
    0x01E0_224C_u32 as i32,
    0x0209_291F_u32 as i32,
    0x0213_8653_u32 as i32,
    0x01F5_F424_u32 as i32,
    0x01A7_ECEF_u32 as i32,
    0x0122_3EBA_u32 as i32,
    0x005F_D0FF_u32 as i32,
    0xFF5E_EB73_u32 as i32,
    0xFE20_435D_u32 as i32,
    0xFCA8_6E7E_u32 as i32,
    0xFAFF_95FC_u32 as i32,
    0xF931_2891_u32 as i32,
    0x08B4_307A_u32 as i32,
    0x0A9F_3E9A_u32 as i32,
    0x0C7D_59B6_u32 as i32,
    0x0E3B_B16F_u32 as i32,
    0x0FC7_21F9_u32 as i32,
    0x110E_CEF0_u32 as i32,
    0x1204_35FA_u32 as i32,
    0x129C_226F_u32 as i32,
    0x12CF_6C75_u32 as i32,
    0x129C_226F_u32 as i32,
    0x1204_35FA_u32 as i32,
    0x110E_CEF0_u32 as i32,
    0x0FC7_21F9_u32 as i32,
    0x0E3B_B16F_u32 as i32,
    0x0C7D_59B6_u32 as i32,
    0x0A9F_3E9A_u32 as i32,
    0xF74B_CF86_u32 as i32,
    0xF931_2891_u32 as i32,
    0xFAFF_95FC_u32 as i32,
    0xFCA8_6E7E_u32 as i32,
    0xFE20_435D_u32 as i32,
    0xFF5E_EB73_u32 as i32,
    0x005F_D0FF_u32 as i32,
    0x0122_3EBA_u32 as i32,
    0x01A7_ECEF_u32 as i32,
    0x01F5_F424_u32 as i32,
    0x0213_8653_u32 as i32,
    0x0209_291F_u32 as i32,
    0x01E0_224C_u32 as i32,
    0x01A1_B38B_u32 as i32,
    0x0156_B3CA_u32 as i32,
    0x0107_1B96_u32 as i32,
    0xFF46_8CB8_u32 as i32,
    0xFF8D_6793_u32 as i32,
    0xFFC9_F10E_u32 as i32,
    0xFFFA_2413_u32 as i32,
    0x001D_8FD2_u32 as i32,
    0x0034_F8B6_u32 as i32,
    0x0041_5B75_u32 as i32,
    0x0044_EF48_u32 as i32,
    0x0041_EC6A_u32 as i32,
    0x003A_72E7_u32 as i32,
    0x0030_60F4_u32 as i32,
    0x0025_5A62_u32 as i32,
    0x001A_FF89_u32 as i32,
    0x0012_2C7D_u32 as i32,
    0x000B_3F71_u32 as i32,
    0x0005_2173_u32 as i32,
];

/// Analysis cosine matrix `cos((k + 0.5) * (i - 4) * pi / 8)` in `Q14` (`16384 = 1.0`).
const ANAL_COS8_Q14: [[i32; 16]; 8] = [
    [
        11585, 13623, 15137, 16069, 16384, 16069, 15137, 13623, 11585, 9102, 6270, 3196, 0, -3196,
        -6270, -9102,
    ],
    [
        -11585, -3196, 6270, 13623, 16384, 13623, 6270, -3196, -11585, -16069, -15137, -9102, 0,
        9102, 15137, 16069,
    ],
    [
        -11585, -16069, -6270, 9102, 16384, 9102, -6270, -16069, -11585, 3196, 15137, 13623, 0,
        -13623, -15137, -3196,
    ],
    [
        11585, -9102, -15137, 3196, 16384, 3196, -15137, -9102, 11585, 13623, -6270, -16069, 0,
        16069, 6270, -13623,
    ],
    [
        11585, 9102, -15137, -3196, 16384, -3196, -15137, 9102, 11585, -13623, -6270, 16069, 0,
        -16069, 6270, 13623,
    ],
    [
        -11585, 16069, -6270, -9102, 16384, -9102, -6270, 16069, -11585, -3196, 15137, -13623, 0,
        13623, -15137, 3196,
    ],
    [
        -11585, 3196, 6270, -13623, 16384, -13623, 6270, 3196, -11585, 16069, -15137, 9102, 0,
        -9102, 15137, -16069,
    ],
    [
        11585, -13623, 15137, -16069, 16384, -16069, 15137, -13623, 11585, -9102, 6270, -3196, 0,
        3196, -6270, 9102,
    ],
];

/// Analysis cosine matrix `cos((k + 0.5) * (i - 2) * pi / 4)` in `Q14`.
const ANAL_COS4_Q14: [[i32; 8]; 4] = [
    [11585, 15137, 16384, 15137, 11585, 6270, 0, -6270],
    [-11585, 6270, 16384, 6270, -11585, -15137, 0, 15137],
    [-11585, -6270, 16384, -6270, -11585, 15137, 0, -15137],
    [11585, -15137, 16384, -15137, 11585, -6270, 0, 6270],
];

/// Synthesis cosine matrix `cos((i + 0.5) * (k + 4) * pi / 8)` in `Q14`.
const SYNTH_COS8_Q14: [[i32; 8]; 16] = [
    [11585, -11585, -11585, 11585, 11585, -11585, -11585, 11585],
    [9102, -16069, 3196, 13623, -13623, -3196, 16069, -9102],
    [6270, -15137, 15137, -6270, -6270, 15137, -15137, 6270],
    [3196, -9102, 13623, -16069, 16069, -13623, 9102, -3196],
    [0, 0, 0, 0, 0, 0, 0, 0],
    [-3196, 9102, -13623, 16069, -16069, 13623, -9102, 3196],
    [-6270, 15137, -15137, 6270, 6270, -15137, 15137, -6270],
    [-9102, 16069, -3196, -13623, 13623, 3196, -16069, 9102],
    [-11585, 11585, 11585, -11585, -11585, 11585, 11585, -11585],
    [-13623, 3196, 16069, 9102, -9102, -16069, -3196, 13623],
    [-15137, -6270, 6270, 15137, 15137, 6270, -6270, -15137],
    [-16069, -13623, -9102, -3196, 3196, 9102, 13623, 16069],
    [
        -16384, -16384, -16384, -16384, -16384, -16384, -16384, -16384,
    ],
    [-16069, -13623, -9102, -3196, 3196, 9102, 13623, 16069],
    [-15137, -6270, 6270, 15137, 15137, 6270, -6270, -15137],
    [-13623, 3196, 16069, 9102, -9102, -16069, -3196, 13623],
];

/// Synthesis cosine matrix `cos((i + 0.5) * (k + 2) * pi / 4)` in `Q14`.
const SYNTH_COS4_Q14: [[i32; 4]; 8] = [
    [11585, -11585, -11585, 11585],
    [6270, -15137, 15137, -6270],
    [0, 0, 0, 0],
    [-6270, 15137, -15137, 6270],
    [-11585, 11585, 11585, -11585],
    [-15137, -6270, 6270, 15137],
    [-16384, -16384, -16384, -16384],
    [-15137, -6270, 6270, 15137],
];

const LOUDNESS_OFFSET_4: [[i32; 4]; 4] =
    [[-1, 0, 0, 0], [-2, 0, 0, 1], [-2, 0, 0, 1], [-2, 0, 0, 1]];

const LOUDNESS_OFFSET_8: [[i32; 8]; 4] = [
    [-2, 0, 0, 0, 0, 0, 0, 1],
    [-3, 0, 0, 0, 0, 0, 1, 2],
    [-4, 0, 0, 0, 0, 0, 1, 2],
    [-4, 0, 0, 0, 0, 0, 1, 2],
];

/// Compute Bluetooth A2DP §12.4 CRC-8 (`x^8 + x^4 + x^3 + x^2 + 1`, `poly = 0x1D`, `init = 0x0F`).
#[must_use]
pub fn sbc_crc8(header_and_scf: &[u8], total_bits: usize) -> u8 {
    let mut crc: u8 = 0x0F;
    let full_bytes = total_bits / 8;
    let rem_bits = total_bits % 8;

    let mut idx = 0;
    while idx < full_bytes && idx < header_and_scf.len() {
        let mut byte = header_and_scf[idx];
        let mut bit = 0;
        while bit < 8 {
            let msb = (crc ^ byte) & 0x80;
            crc <<= 1;
            if msb != 0 {
                crc ^= 0x1D;
            }
            byte <<= 1;
            bit += 1;
        }
        idx += 1;
    }

    if rem_bits > 0 && idx < header_and_scf.len() {
        let mut byte = header_and_scf[idx];
        let mut bit = 0;
        while bit < rem_bits {
            let msb = (crc ^ byte) & 0x80;
            crc <<= 1;
            if msb != 0 {
                crc ^= 0x1D;
            }
            byte <<= 1;
            bit += 1;
        }
    }
    crc
}

fn compute_scale_factor_q15(max_abs_q15: u32) -> u8 {
    let mut scf: u8 = 0;
    while scf < 15 {
        let limit = 0x8000_u32 << scf;
        if max_abs_q15 <= limit {
            break;
        }
        scf += 1;
    }
    scf
}

fn compute_bit_allocation(
    cfg: SbcConfig,
    scale_factors: &[[u8; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS],
    bits_out: &mut [[u8; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS],
) {
    let sb_count = cfg.subbands.count();
    let ch_count = cfg.channel_mode.channels();
    let sr_idx = cfg.sample_rate as usize;
    let bitpool = i32::from(cfg.bitpool);

    let mut bitneed = [[0i32; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS];
    for ch in 0..ch_count {
        for sb in 0..sb_count {
            let scf = i32::from(scale_factors[ch][sb]);
            bitneed[ch][sb] = match cfg.alloc_method {
                SbcAllocMethod::Snr => scf,
                SbcAllocMethod::Loudness => {
                    if scf == 0 {
                        -5
                    } else {
                        let offset = if sb_count == 4 {
                            LOUDNESS_OFFSET_4[sr_idx][sb]
                        } else {
                            LOUDNESS_OFFSET_8[sr_idx][sb]
                        };
                        let loudness = scf - offset;
                        if loudness > 0 {
                            loudness / 2
                        } else {
                            loudness
                        }
                    }
                }
            };
        }
    }

    *bits_out = [[0u8; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS];

    match cfg.channel_mode {
        SbcChannelMode::Mono | SbcChannelMode::DualChannel => {
            for ch in 0..ch_count {
                let mut max_bitneed = 0i32;
                for sb in 0..sb_count {
                    if bitneed[ch][sb] > max_bitneed {
                        max_bitneed = bitneed[ch][sb];
                    }
                }

                let mut bitcount = 0i32;
                let mut slicecount = 0i32;
                let mut bitslice = max_bitneed + 1;
                loop {
                    bitslice -= 1;
                    bitcount += slicecount;
                    slicecount = 0;
                    for sb in 0..sb_count {
                        let diff = bitneed[ch][sb] - bitslice;
                        if diff > 1 && diff < 16 {
                            slicecount += 1;
                        } else if diff == 1 {
                            slicecount += 2;
                        }
                    }
                    if bitcount + slicecount >= bitpool {
                        break;
                    }
                }
                if bitcount + slicecount == bitpool {
                    bitcount += slicecount;
                    bitslice -= 1;
                }

                for sb in 0..sb_count {
                    let b = if bitneed[ch][sb] < bitslice + 2 {
                        0
                    } else {
                        (bitneed[ch][sb] - bitslice).min(16)
                    };
                    bits_out[ch][sb] = b as u8;
                }

                let mut sb = 0usize;
                while bitcount < bitpool && sb < sb_count {
                    let cur = bits_out[ch][sb];
                    if cur >= 2 && cur < 16 {
                        bits_out[ch][sb] = cur + 1;
                        bitcount += 1;
                    } else if bitneed[ch][sb] == bitslice + 1 && bitpool > bitcount + 1 {
                        bits_out[ch][sb] = 2;
                        bitcount += 2;
                    }
                    sb += 1;
                }

                let mut sb2 = 0usize;
                while bitcount < bitpool && sb2 < sb_count {
                    if bits_out[ch][sb2] < 16 {
                        bits_out[ch][sb2] += 1;
                        bitcount += 1;
                    }
                    sb2 += 1;
                }
            }
        }
        SbcChannelMode::Stereo | SbcChannelMode::JointStereo => {
            let mut max_bitneed = 0i32;
            for ch in 0..2 {
                for sb in 0..sb_count {
                    if bitneed[ch][sb] > max_bitneed {
                        max_bitneed = bitneed[ch][sb];
                    }
                }
            }

            let mut bitcount = 0i32;
            let mut slicecount = 0i32;
            let mut bitslice = max_bitneed + 1;
            loop {
                bitslice -= 1;
                bitcount += slicecount;
                slicecount = 0;
                for ch in 0..2 {
                    for sb in 0..sb_count {
                        let diff = bitneed[ch][sb] - bitslice;
                        if diff > 1 && diff < 16 {
                            slicecount += 1;
                        } else if diff == 1 {
                            slicecount += 2;
                        }
                    }
                }
                if bitcount + slicecount >= bitpool {
                    break;
                }
            }
            if bitcount + slicecount == bitpool {
                bitcount += slicecount;
                bitslice -= 1;
            }

            for ch in 0..2 {
                for sb in 0..sb_count {
                    let b = if bitneed[ch][sb] < bitslice + 2 {
                        0
                    } else {
                        (bitneed[ch][sb] - bitslice).min(16)
                    };
                    bits_out[ch][sb] = b as u8;
                }
            }

            let mut sb = 0usize;
            while bitcount < bitpool && sb < sb_count {
                for ch in 0..2 {
                    if bitcount >= bitpool {
                        break;
                    }
                    let cur = bits_out[ch][sb];
                    if cur >= 2 && cur < 16 {
                        bits_out[ch][sb] = cur + 1;
                        bitcount += 1;
                    } else if bitneed[ch][sb] == bitslice + 1 && bitpool > bitcount + 1 {
                        bits_out[ch][sb] = 2;
                        bitcount += 2;
                    }
                }
                sb += 1;
            }

            let mut sb2 = 0usize;
            while bitcount < bitpool && sb2 < sb_count {
                for ch in 0..2 {
                    if bitcount >= bitpool {
                        break;
                    }
                    if bits_out[ch][sb2] < 16 {
                        bits_out[ch][sb2] += 1;
                        bitcount += 1;
                    }
                }
                sb2 += 1;
            }
        }
    }
}

struct MsbBitWriter<'a> {
    buf: &'a mut [u8],
    byte_pos: usize,
    bit_rem: u8,
    cur: u8,
}

impl<'a> MsbBitWriter<'a> {
    fn new(buf: &'a mut [u8], start_pos: usize) -> Self {
        Self {
            buf,
            byte_pos: start_pos,
            bit_rem: 8,
            cur: 0,
        }
    }

    fn push_bits(&mut self, value: u32, mut count: u8) -> Result<(), SbcError> {
        while count > 0 {
            let take = count.min(self.bit_rem);
            let shift = count - take;
            let mask = (1u32 << take) - 1;
            let chunk = ((value >> shift) & mask) as u8;
            self.cur = (self.cur << take) | chunk;
            self.bit_rem -= take;
            count -= take;
            if self.bit_rem == 0 {
                if self.byte_pos >= self.buf.len() {
                    return Err(SbcError::BufferTooSmall);
                }
                self.buf[self.byte_pos] = self.cur;
                self.byte_pos += 1;
                self.cur = 0;
                self.bit_rem = 8;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<usize, SbcError> {
        if self.bit_rem < 8 {
            if self.byte_pos >= self.buf.len() {
                return Err(SbcError::BufferTooSmall);
            }
            self.buf[self.byte_pos] = self.cur << self.bit_rem;
            self.byte_pos += 1;
        }
        Ok(self.byte_pos)
    }
}

struct MsbBitReader<'a> {
    buf: &'a [u8],
    byte_pos: usize,
    bit_rem: u8,
}

impl<'a> MsbBitReader<'a> {
    const fn new(buf: &'a [u8], start_pos: usize) -> Self {
        Self {
            buf,
            byte_pos: start_pos,
            bit_rem: 8,
        }
    }

    fn read_bits(&mut self, mut count: u8) -> Result<u32, SbcError> {
        let mut out = 0u32;
        while count > 0 {
            if self.byte_pos >= self.buf.len() {
                return Err(SbcError::TruncatedFrame);
            }
            let take = count.min(self.bit_rem);
            let shift = self.bit_rem - take;
            let mask = ((1u16 << take) - 1) as u8;
            let chunk = (self.buf[self.byte_pos] >> shift) & mask;
            out = (out << take) | u32::from(chunk);
            self.bit_rem -= take;
            count -= take;
            if self.bit_rem == 0 {
                self.byte_pos += 1;
                self.bit_rem = 8;
            }
        }
        Ok(out)
    }
}

/// Stateful Bluetooth A2DP SBC subband encoder.
pub struct SbcEncoder {
    config: SbcConfig,
    x_hist: [[i16; 80]; SBC_MAX_CHANNELS],
    frames_encoded: u64,
}

impl SbcEncoder {
    #[must_use]
    pub const fn new(config: SbcConfig) -> Self {
        Self {
            config,
            x_hist: [[0i16; 80]; SBC_MAX_CHANNELS],
            frames_encoded: 0,
        }
    }

    #[must_use]
    pub const fn config(&self) -> SbcConfig {
        self.config
    }

    pub fn set_bitpool(&mut self, bitpool: u8) {
        self.config.bitpool = bitpool.clamp(2, 250);
    }

    #[must_use]
    pub const fn frames_encoded(&self) -> u64 {
        self.frames_encoded
    }

    pub fn reset(&mut self) {
        self.x_hist = [[0i16; 80]; SBC_MAX_CHANNELS];
    }

    fn analyze_block_8(&mut self, ch: usize, samples: [i16; 8]) -> [i32; 8] {
        let hist = &mut self.x_hist[ch];
        let mut idx = 79usize;
        while idx >= 8 {
            hist[idx] = hist[idx - 8];
            idx -= 1;
        }
        for j in 0..8 {
            hist[j] = samples[7 - j];
        }

        let mut y = [0i64; 16];
        for i in 0..16 {
            let mut acc = 0i64;
            for j in 0..5 {
                let pos = i + j * 16;
                acc += i64::from(PROTO_8_Q31[pos]) * i64::from(hist[pos]);
            }
            // Scale Q31 * Q0 -> Q16 so cosine Q14 product >> 14 lands in Q15 (`0x8000` = full scale).
            y[i] = acc >> 15;
        }

        let mut sb_out = [0i32; 8];
        for k in 0..8 {
            let mut sum = 0i64;
            for i in 0..16 {
                sum += i64::from(ANAL_COS8_Q14[k][i]) * y[i];
            }
            sb_out[k] = (sum >> 14) as i32;
        }
        sb_out
    }

    fn analyze_block_4(&mut self, ch: usize, samples: [i16; 4]) -> [i32; 4] {
        let hist = &mut self.x_hist[ch];
        let mut idx = 39usize;
        while idx >= 4 {
            hist[idx] = hist[idx - 4];
            idx -= 1;
        }
        for j in 0..4 {
            hist[j] = samples[3 - j];
        }

        let mut y = [0i64; 8];
        for i in 0..8 {
            let mut acc = 0i64;
            for j in 0..5 {
                let pos = i + j * 8;
                acc += i64::from(PROTO_4_Q31[pos]) * i64::from(hist[pos]);
            }
            y[i] = acc >> 15;
        }

        let mut sb_out = [0i32; 4];
        for k in 0..4 {
            let mut sum = 0i64;
            for i in 0..8 {
                sum += i64::from(ANAL_COS4_Q14[k][i]) * y[i];
            }
            sb_out[k] = (sum >> 14) as i32;
        }
        sb_out
    }

    /// Encode one SBC frame from interleaved stereo `[L, R]` S16LE frames
    /// (`config.pcm_frames_per_sbc_frame()`, typically 128 stereo frames = 2.67 ms at 48 kHz).
    /// For `Mono`, left and right are averaged before subband analysis.
    pub fn encode_stereo_frame(
        &mut self,
        pcm_stereo: &[[i16; 2]],
        out_frame: &mut [u8],
    ) -> Result<usize, SbcError> {
        let cfg = self.config;
        if cfg.bitpool < 2 {
            return Err(SbcError::InvalidBitpool);
        }
        let needed_pcm = cfg.pcm_frames_per_sbc_frame();
        if pcm_stereo.len() < needed_pcm {
            return Err(SbcError::InvalidPcmLength);
        }
        let expected_bytes = cfg.frame_byte_len();
        if out_frame.len() < expected_bytes {
            return Err(SbcError::BufferTooSmall);
        }

        let blocks = cfg.blocks.count();
        let subbands = cfg.subbands.count();
        let channels = cfg.channel_mode.channels();

        let mut sb_samples = [[[0i32; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS]; SBC_MAX_BLOCKS];
        for blk in 0..blocks {
            let base = blk * subbands;
            if subbands == 8 {
                if channels == 1 {
                    let mut mono = [0i16; 8];
                    for j in 0..8 {
                        let [l, r] = pcm_stereo[base + j];
                        mono[j] = ((i32::from(l) + i32::from(r)) >> 1) as i16;
                    }
                    sb_samples[blk][0] = self.analyze_block_8(0, mono);
                } else {
                    let mut left = [0i16; 8];
                    let mut right = [0i16; 8];
                    for j in 0..8 {
                        left[j] = pcm_stereo[base + j][0];
                        right[j] = pcm_stereo[base + j][1];
                    }
                    sb_samples[blk][0] = self.analyze_block_8(0, left);
                    sb_samples[blk][1] = self.analyze_block_8(1, right);
                }
            } else if channels == 1 {
                let mut mono = [0i16; 4];
                for j in 0..4 {
                    let [l, r] = pcm_stereo[base + j];
                    mono[j] = ((i32::from(l) + i32::from(r)) >> 1) as i16;
                }
                let s4 = self.analyze_block_4(0, mono);
                sb_samples[blk][0][..4].copy_from_slice(&s4);
            } else {
                let mut left = [0i16; 4];
                let mut right = [0i16; 4];
                for j in 0..4 {
                    left[j] = pcm_stereo[base + j][0];
                    right[j] = pcm_stereo[base + j][1];
                }
                let l4 = self.analyze_block_4(0, left);
                let r4 = self.analyze_block_4(1, right);
                sb_samples[blk][0][..4].copy_from_slice(&l4);
                sb_samples[blk][1][..4].copy_from_slice(&r4);
            }
        }

        let mut scale_factors = [[0u8; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS];
        for ch in 0..channels {
            for sb in 0..subbands {
                let mut max_abs = 0u32;
                for blk in 0..blocks {
                    let v = sb_samples[blk][ch][sb].unsigned_abs();
                    if v > max_abs {
                        max_abs = v;
                    }
                }
                scale_factors[ch][sb] = compute_scale_factor_q15(max_abs);
            }
        }

        let mut join_flags = [0u8; SBC_MAX_SUBBANDS];
        if cfg.channel_mode == SbcChannelMode::JointStereo && subbands >= 2 {
            for sb in 0..(subbands - 1) {
                let mut max_mid = 0u32;
                let mut max_side = 0u32;
                let mut mid_buf = [0i32; SBC_MAX_BLOCKS];
                let mut side_buf = [0i32; SBC_MAX_BLOCKS];
                for blk in 0..blocks {
                    let l = sb_samples[blk][0][sb];
                    let r = sb_samples[blk][1][sb];
                    let mid = (l + r) >> 1;
                    let side = (l - r) >> 1;
                    mid_buf[blk] = mid;
                    side_buf[blk] = side;
                    let am = mid.unsigned_abs();
                    let asd = side.unsigned_abs();
                    if am > max_mid {
                        max_mid = am;
                    }
                    if asd > max_side {
                        max_side = asd;
                    }
                }
                let scf_mid = compute_scale_factor_q15(max_mid);
                let scf_side = compute_scale_factor_q15(max_side);
                if u16::from(scf_mid) + u16::from(scf_side)
                    < u16::from(scale_factors[0][sb]) + u16::from(scale_factors[1][sb])
                {
                    join_flags[sb] = 1;
                    scale_factors[0][sb] = scf_mid;
                    scale_factors[1][sb] = scf_side;
                    for blk in 0..blocks {
                        sb_samples[blk][0][sb] = mid_buf[blk];
                        sb_samples[blk][1][sb] = side_buf[blk];
                    }
                }
            }
        }

        let mut bits = [[0u8; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS];
        compute_bit_allocation(cfg, &scale_factors, &mut bits);

        out_frame[0] = SBC_SYNCWORD;
        out_frame[1] = cfg.header_byte1();
        out_frame[2] = cfg.bitpool;
        out_frame[3] = 0;

        let mut writer = MsbBitWriter::new(out_frame, 4);
        if cfg.channel_mode == SbcChannelMode::JointStereo {
            for sb in 0..(subbands - 1) {
                writer.push_bits(u32::from(join_flags[sb]), 1)?;
            }
            // RFA bit for last subband is always 0.
            writer.push_bits(0, 1)?;
        }

        for ch in 0..channels {
            for sb in 0..subbands {
                writer.push_bits(u32::from(scale_factors[ch][sb]), 4)?;
            }
        }

        for blk in 0..blocks {
            for ch in 0..channels {
                for sb in 0..subbands {
                    let nbits = bits[ch][sb];
                    if nbits > 0 {
                        let scf = scale_factors[ch][sb];
                        let levels = (1u64 << nbits) - 1;
                        // sb_samples is in Q15 where `1 << (scf + 15)` is the subband peak `2^(scf+1)`.
                        let shifted = (i64::from(sb_samples[blk][ch][sb]) >> 15) + (1i64 << scf);
                        let clamped = shifted.max(0) as u64;
                        let quant = ((clamped * levels) >> (scf + 1)).min(levels) as u32;
                        writer.push_bits(quant, nbits)?;
                    }
                }
            }
        }

        let written = writer.finish()?;
        if written < expected_bytes {
            out_frame[written..expected_bytes].fill(0);
        }

        // Compute CRC-8 over byte 1, byte 2, join flags (if JS), and all 4-bit scale factors.
        let mut crc_buf = [0u8; 20];
        crc_buf[0] = out_frame[1];
        crc_buf[1] = out_frame[2];
        let extra_bits = if cfg.channel_mode == SbcChannelMode::JointStereo {
            subbands + 4 * channels * subbands
        } else {
            4 * channels * subbands
        };
        let extra_bytes = extra_bits.div_ceil(8);
        crc_buf[2..2 + extra_bytes].copy_from_slice(&out_frame[4..4 + extra_bytes]);
        out_frame[3] = sbc_crc8(&crc_buf, 16 + extra_bits);

        self.frames_encoded = self.frames_encoded.saturating_add(1);
        Ok(expected_bytes)
    }
}

/// Parse and validate an SBC frame header + CRC-8 without decoding audio.
pub fn parse_and_validate_sbc_frame(frame: &[u8]) -> Result<SbcConfig, SbcError> {
    if frame.len() < 4 {
        return Err(SbcError::TruncatedFrame);
    }
    if frame[0] != SBC_SYNCWORD {
        return Err(SbcError::InvalidSyncword);
    }
    let h1 = frame[1];
    let cfg = SbcConfig {
        sample_rate: SbcSampleRate::from_code(h1 >> 6),
        blocks: SbcBlocks::from_code(h1 >> 4),
        channel_mode: SbcChannelMode::from_code(h1 >> 2),
        alloc_method: SbcAllocMethod::from_code(h1 >> 1),
        subbands: SbcSubbands::from_code(h1),
        bitpool: frame[2],
    };
    if cfg.bitpool < 2 {
        return Err(SbcError::InvalidBitpool);
    }
    let frame_len = cfg.frame_byte_len();
    if frame.len() < frame_len {
        return Err(SbcError::TruncatedFrame);
    }

    let subbands = cfg.subbands.count();
    let channels = cfg.channel_mode.channels();
    let extra_bits = if cfg.channel_mode == SbcChannelMode::JointStereo {
        subbands + 4 * channels * subbands
    } else {
        4 * channels * subbands
    };
    let extra_bytes = extra_bits.div_ceil(8);
    let mut crc_buf = [0u8; 20];
    crc_buf[0] = frame[1];
    crc_buf[1] = frame[2];
    crc_buf[2..2 + extra_bytes].copy_from_slice(&frame[4..4 + extra_bytes]);
    let expected_crc = sbc_crc8(&crc_buf, 16 + extra_bits);
    if frame[3] != expected_crc {
        return Err(SbcError::CrcMismatch);
    }
    Ok(cfg)
}

/// Reference Bluetooth A2DP §12.6.3 SBC synthesis decoder (used for loopback
/// verification, virtual headset decoding, and snoop media inspection).
pub struct SbcDecoder {
    v_hist: [[i32; 160]; SBC_MAX_CHANNELS],
}

impl SbcDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            v_hist: [[0i32; 160]; SBC_MAX_CHANNELS],
        }
    }

    fn synthesize_block_8(&mut self, ch: usize, sb_q15: &[i32; 8]) -> [i16; 8] {
        let v = &mut self.v_hist[ch];
        let mut idx = 159usize;
        while idx >= 16 {
            v[idx] = v[idx - 16];
            idx -= 1;
        }
        for k in 0..16 {
            let mut sum = 0i64;
            for i in 0..8 {
                sum += i64::from(SYNTH_COS8_Q14[k][i]) * i64::from(sb_q15[i]);
            }
            // Keep V in Q13 to prevent overflow before windowing.
            v[k] = (sum >> 16) as i32;
        }

        let mut u = [0i32; 80];
        for i in 0..5 {
            for j in 0..8 {
                u[i * 16 + j] = v[i * 32 + j];
                u[i * 16 + 8 + j] = v[i * 32 + 24 + j];
            }
        }

        let mut out = [0i16; 8];
        for j in 0..8 {
            let mut acc = 0i64;
            for i in 0..10 {
                let pos = j + 8 * i;
                // D[pos] = -8 * C[pos]; combined shift restores PCM S16 amplitude at unity gain.
                acc += i64::from(u[pos]) * (-i64::from(PROTO_8_Q31[pos]));
            }
            let sample = (acc >> 26).clamp(i64::from(i16::MIN), i64::from(i16::MAX));
            out[j] = sample as i16;
        }
        out
    }

    fn synthesize_block_4(&mut self, ch: usize, sb_q15: &[i32; 4]) -> [i16; 4] {
        let v = &mut self.v_hist[ch];
        let mut idx = 79usize;
        while idx >= 8 {
            v[idx] = v[idx - 8];
            idx -= 1;
        }
        for k in 0..8 {
            let mut sum = 0i64;
            for i in 0..4 {
                sum += i64::from(SYNTH_COS4_Q14[k][i]) * i64::from(sb_q15[i]);
            }
            v[k] = (sum >> 16) as i32;
        }

        let mut u = [0i32; 40];
        for i in 0..5 {
            for j in 0..4 {
                u[i * 8 + j] = v[i * 16 + j];
                u[i * 8 + 4 + j] = v[i * 16 + 12 + j];
            }
        }

        let mut out = [0i16; 4];
        for j in 0..4 {
            let mut acc = 0i64;
            for i in 0..10 {
                let pos = j + 4 * i;
                acc += i64::from(u[pos]) * (-i64::from(PROTO_4_Q31[pos]));
            }
            let sample = (acc >> 27).clamp(i64::from(i16::MIN), i64::from(i16::MAX));
            out[j] = sample as i16;
        }
        out
    }

    /// Decode one SBC frame into interleaved stereo PCM frames.
    /// Returns `(config, pcm_frames_written)`.
    pub fn decode_stereo_frame(
        &mut self,
        frame: &[u8],
        out_pcm: &mut [[i16; 2]],
    ) -> Result<(SbcConfig, usize), SbcError> {
        let cfg = parse_and_validate_sbc_frame(frame)?;
        let pcm_frames = cfg.pcm_frames_per_sbc_frame();
        if out_pcm.len() < pcm_frames {
            return Err(SbcError::BufferTooSmall);
        }

        let blocks = cfg.blocks.count();
        let subbands = cfg.subbands.count();
        let channels = cfg.channel_mode.channels();

        let mut reader = MsbBitReader::new(frame, 4);
        let mut join_flags = [0u8; SBC_MAX_SUBBANDS];
        if cfg.channel_mode == SbcChannelMode::JointStereo {
            for sb in 0..(subbands - 1) {
                join_flags[sb] = reader.read_bits(1)? as u8;
            }
            let _rfa = reader.read_bits(1)?;
        }

        let mut scale_factors = [[0u8; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS];
        for ch in 0..channels {
            for sb in 0..subbands {
                scale_factors[ch][sb] = reader.read_bits(4)? as u8;
            }
        }

        let mut bits = [[0u8; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS];
        compute_bit_allocation(cfg, &scale_factors, &mut bits);

        let mut sb_q15 = [[[0i32; SBC_MAX_SUBBANDS]; SBC_MAX_CHANNELS]; SBC_MAX_BLOCKS];
        for blk in 0..blocks {
            for ch in 0..channels {
                for sb in 0..subbands {
                    let nbits = bits[ch][sb];
                    if nbits > 0 {
                        let raw = u64::from(reader.read_bits(nbits)?);
                        let scf = scale_factors[ch][sb];
                        let levels = (1u64 << nbits) - 1;
                        // A2DP §12.6.2 dequantization in Q15 (`1 << 15` = 1.0 * 2^0).
                        let num = ((raw * 2 + 1) << (scf + 15)) / levels;
                        let val = (num as i64) - (1i64 << (scf + 15));
                        sb_q15[blk][ch][sb] = val as i32;
                    }
                }
            }
            if cfg.channel_mode == SbcChannelMode::JointStereo {
                for sb in 0..(subbands - 1) {
                    if join_flags[sb] != 0 {
                        let mid = sb_q15[blk][0][sb];
                        let side = sb_q15[blk][1][sb];
                        sb_q15[blk][0][sb] = mid.saturating_add(side);
                        sb_q15[blk][1][sb] = mid.saturating_sub(side);
                    }
                }
            }
        }

        for blk in 0..blocks {
            let base = blk * subbands;
            if subbands == 8 {
                let l8 = self.synthesize_block_8(0, &sb_q15[blk][0]);
                let r8 = if channels == 2 {
                    self.synthesize_block_8(1, &sb_q15[blk][1])
                } else {
                    l8
                };
                for j in 0..8 {
                    out_pcm[base + j] = [l8[j], r8[j]];
                }
            } else {
                let mut s0 = [0i32; 4];
                s0.copy_from_slice(&sb_q15[blk][0][..4]);
                let l4 = self.synthesize_block_4(0, &s0);
                let r4 = if channels == 2 {
                    let mut s1 = [0i32; 4];
                    s1.copy_from_slice(&sb_q15[blk][1][..4]);
                    self.synthesize_block_4(1, &s1)
                } else {
                    l4
                };
                for j in 0..4 {
                    out_pcm[base + j] = [l4[j], r4[j]];
                }
            }
        }

        Ok((cfg, pcm_frames))
    }
}

impl Default for SbcDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Adaptive A2DP bitpool controller driven by `/net/btl` ACL credit congestion.
#[derive(Clone, Copy, Debug)]
pub struct AdaptiveBitpool {
    min_bitpool: u8,
    max_bitpool: u8,
    current_bitpool: u8,
    clean_windows: u16,
}

impl AdaptiveBitpool {
    #[must_use]
    pub const fn new(min_bitpool: u8, max_bitpool: u8, initial: u8) -> Self {
        let min_b = if min_bitpool < 2 { 2 } else { min_bitpool };
        let max_b = if max_bitpool < min_b {
            min_b
        } else {
            max_bitpool
        };
        let cur = if initial < min_b {
            min_b
        } else if initial > max_b {
            max_b
        } else {
            initial
        };
        Self {
            min_bitpool: min_b,
            max_bitpool: max_b,
            current_bitpool: cur,
            clean_windows: 0,
        }
    }

    #[must_use]
    pub const fn current(&self) -> u8 {
        self.current_bitpool
    }

    /// Observe HCI ACL in-flight packets vs total controller ACL slots (`btl` congestion).
    pub fn observe_acl_load(&mut self, in_flight: u16, max_slots: u16) -> u8 {
        let slots = max_slots.max(1);
        if in_flight * 4 >= slots * 3 {
            // >= 75% ACL queue occupancy -> step down bitpool fast to avoid audio dropouts.
            self.current_bitpool = self.current_bitpool.saturating_sub(6).max(self.min_bitpool);
            self.clean_windows = 0;
        } else if in_flight * 2 < slots {
            self.clean_windows = self.clean_windows.saturating_add(1);
            if self.clean_windows >= 24 && self.current_bitpool < self.max_bitpool {
                self.current_bitpool = (self.current_bitpool + 2).min(self.max_bitpool);
                self.clean_windows = 0;
            }
        } else {
            self.clean_windows = 0;
        }
        self.current_bitpool
    }
}

/// A2DP RTP + SBC media payload packetizer (`PSM 0x0019` transport channel).
#[derive(Clone, Copy, Debug)]
pub struct RtpSbcPacketizer {
    seq: u16,
    timestamp: u32,
    ssrc: u32,
}

impl RtpSbcPacketizer {
    #[must_use]
    pub const fn new(ssrc: u32) -> Self {
        Self {
            seq: 1,
            timestamp: 0,
            ssrc,
        }
    }

    /// Maximum number of identical-length SBC frames that fit in `l2cap_mtu`.
    #[must_use]
    pub const fn max_frames_per_packet(l2cap_mtu: u16, sbc_frame_len: usize) -> usize {
        let mtu = l2cap_mtu as usize;
        if mtu <= RTP_HEADER_LEN + A2DP_SBC_PAYLOAD_HDR_LEN || sbc_frame_len == 0 {
            return 0;
        }
        let avail = mtu - RTP_HEADER_LEN - A2DP_SBC_PAYLOAD_HDR_LEN;
        let count = avail / sbc_frame_len;
        if count > 15 {
            15
        } else {
            count
        }
    }

    /// Wrap `num_frames` concatenated SBC frames into an A2DP RTP media packet.
    pub fn pack_media_packet(
        &mut self,
        sbc_frames_concat: &[u8],
        num_frames: u8,
        pcm_samples_total: u32,
        out_pkt: &mut [u8],
    ) -> Result<usize, SbcError> {
        let total_len = RTP_HEADER_LEN + A2DP_SBC_PAYLOAD_HDR_LEN + sbc_frames_concat.len();
        if out_pkt.len() < total_len {
            return Err(SbcError::BufferTooSmall);
        }

        out_pkt[0] = RTP_VERSION_2;
        out_pkt[1] = RTP_PAYLOAD_SBC;
        out_pkt[2..4].copy_from_slice(&self.seq.to_be_bytes());
        out_pkt[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out_pkt[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        // A2DP v1.3 §4.3.4 Media Payload Header: bits 3..0 = number of non-fragmented SBC frames.
        out_pkt[12] = num_frames & 0x0F;
        out_pkt[13..total_len].copy_from_slice(sbc_frames_concat);

        self.seq = self.seq.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(pcm_samples_total);
        Ok(total_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hq_48k_frame_length_and_crc_validate() {
        let cfg = SbcConfig::HQ_48K_JOINT_STEREO;
        assert_eq!(cfg.pcm_frames_per_sbc_frame(), 128);
        assert_eq!(cfg.frame_byte_len(), 119);
        assert!(cfg.bitrate_bps() > 340_000 && cfg.bitrate_bps() < 350_000);

        let mut enc = SbcEncoder::new(cfg);
        let mut dec = SbcDecoder::new();
        let mut tone_gen = crate::mixer::StereoToneGenerator::new(1000, 48_000, 18_000);

        let mut all_in = [[0i16; 2]; 128 * 12];
        tone_gen.generate(&mut all_in);

        let mut all_out = [[0i16; 2]; 128 * 12];
        let mut frame_buf = [0u8; 160];

        for f in 0..12 {
            let slice_in = &all_in[f * 128..(f + 1) * 128];
            let res_len = enc.encode_stereo_frame(slice_in, &mut frame_buf);
            assert_eq!(res_len, Ok(119));
            assert_eq!(parse_and_validate_sbc_frame(&frame_buf[..119]), Ok(cfg));

            let dec_res =
                dec.decode_stereo_frame(&frame_buf[..119], &mut all_out[f * 128..(f + 1) * 128]);
            assert_eq!(dec_res, Ok((cfg, 128)));
        }

        // Verify steady-state signal-to-noise ratio across the 73-sample filterbank delay!
        let delay = 73usize;
        let mut sig_energy: i64 = 0;
        let mut err_energy: i64 = 0;
        for t in 300..(128 * 11) {
            let orig = i64::from(all_in[t - delay][0]);
            let recon = i64::from(all_out[t][0]);
            let diff = orig - recon;
            sig_energy += orig * orig;
            err_energy += diff * diff;
        }
        // High-quality bitpool=53 SBC yields > 30 dB SNR (sig_energy > 1000 * err_energy).
        assert!(sig_energy > err_energy * 800);
    }

    #[test]
    fn adaptive_bitpool_and_rtp_packer_work() {
        let mut ctrl = AdaptiveBitpool::new(26, 53, 53);
        assert_eq!(ctrl.observe_acl_load(7, 8), 47);
        assert_eq!(ctrl.observe_acl_load(8, 8), 41);
        for _ in 0..24 {
            let _ = ctrl.observe_acl_load(1, 8);
        }
        assert_eq!(ctrl.current(), 43);

        let max_f = RtpSbcPacketizer::max_frames_per_packet(672, 119);
        assert_eq!(max_f, 5);

        let mut rtp = RtpSbcPacketizer::new(0x4855_4553);
        let dummy = [0x9Cu8; 119 * 5];
        let mut pkt = [0u8; 700];
        let n = rtp.pack_media_packet(&dummy, 5, 128 * 5, &mut pkt);
        assert_eq!(n, Ok(13 + 119 * 5));
        assert_eq!(pkt[0], 0x80);
        assert_eq!(pkt[12], 5);
    }
}
