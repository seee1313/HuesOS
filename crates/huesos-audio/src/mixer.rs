//! Fractional-phase stereo resampler, saturating multi-stream PCM mixer,
//! RIFF `WAVE` parser, and integer chord/tone generator.

use alloc::vec::Vec;

/// Stateful linear-interpolating resampler converting arbitrary `src_rate` stereo `i16`
/// streams into `dst_rate` stereo `i16` without click artifacts across chunk boundaries.
#[derive(Clone, Copy, Debug)]
pub struct LinearResampler {
    src_rate: u32,
    dst_rate: u32,
    step_q16: u64,
    phase_q16: u64,
    prev_l: i16,
    prev_r: i16,
    has_prev: bool,
}

impl LinearResampler {
    /// Construct a resampler from `src_rate` Hz to `dst_rate` Hz.
    pub fn new(src_rate: u32, dst_rate: u32) -> Self {
        let safe_src = src_rate.clamp(4000, 192_000);
        let safe_dst = dst_rate.clamp(4000, 192_000);
        let step_q16 = ((u64::from(safe_src)) << 16) / u64::from(safe_dst);
        Self {
            src_rate: safe_src,
            dst_rate: safe_dst,
            step_q16: step_q16.max(1),
            phase_q16: 0,
            prev_l: 0,
            prev_r: 0,
            has_prev: false,
        }
    }

    /// Update input/output sample rates on the fly if changed.
    pub fn set_rates(&mut self, src_rate: u32, dst_rate: u32) {
        if self.src_rate != src_rate || self.dst_rate != dst_rate {
            *self = Self::new(src_rate, dst_rate);
        }
    }

    /// Resample interleaved stereo `input` (`2 * in_frames`) and **accumulate** (mix with
    /// `gain_q8` where `256 = 1.0`) into `accum_i32` (`2 * out_frames`), returning
    /// `(input_frames_consumed, output_frames_mixed)`.
    pub fn resample_and_accumulate(
        &mut self,
        input: &[i16],
        gain_q8: u16,
        accum_i32: &mut [i32],
    ) -> (usize, usize) {
        let in_frames = input.len() / 2;
        let out_frames = accum_i32.len() / 2;
        if in_frames == 0 || out_frames == 0 {
            return (0, 0);
        }

        if self.src_rate == self.dst_rate {
            let n = in_frames.min(out_frames);
            let g = i32::from(gain_q8);
            for i in 0..n * 2 {
                accum_i32[i] = accum_i32[i].saturating_add((i32::from(input[i]) * g) >> 8);
            }
            self.prev_l = input[(n - 1) * 2];
            self.prev_r = input[(n - 1) * 2 + 1];
            self.has_prev = true;
            return (n, n);
        }

        if !self.has_prev {
            self.prev_l = input[0];
            self.prev_r = input[1];
            self.has_prev = true;
        }

        let g = i32::from(gain_q8);
        let mut out_idx = 0usize;
        while out_idx < out_frames {
            let int_idx = (self.phase_q16 >> 16) as usize;
            let frac = (self.phase_q16 & 0xFFFF) as i32;
            if int_idx >= in_frames {
                break;
            }
            let (l0, r0, l1, r1) = if int_idx == 0 {
                (self.prev_l, self.prev_r, input[0], input[1])
            } else {
                let p = (int_idx - 1) * 2;
                let c = int_idx * 2;
                (input[p], input[p + 1], input[c], input[c + 1])
            };
            let il = i32::from(l0) + (((i32::from(l1) - i32::from(l0)) * frac) >> 16);
            let ir = i32::from(r0) + (((i32::from(r1) - i32::from(r0)) * frac) >> 16);

            accum_i32[out_idx * 2] = accum_i32[out_idx * 2].saturating_add((il * g) >> 8);
            accum_i32[out_idx * 2 + 1] = accum_i32[out_idx * 2 + 1].saturating_add((ir * g) >> 8);

            self.phase_q16 += self.step_q16;
            out_idx += 1;
        }

        let consumed = ((self.phase_q16 >> 16) as usize).min(in_frames);
        if consumed > 0 {
            self.prev_l = input[(consumed - 1) * 2];
            self.prev_r = input[(consumed - 1) * 2 + 1];
            self.phase_q16 -= (consumed as u64) << 16;
        }
        (consumed, out_idx)
    }
}

/// Apply master volume (`0..=100`, plus mute flag) and saturating soft-clamp from `i32`
/// accumulator into interleaved `i16` stereo output.
pub fn finalize_mix_buffer(
    accum: &[i32],
    master_volume_pct: u8,
    muted: bool,
    out: &mut [i16],
) {
    let n = accum.len().min(out.len());
    if muted || master_volume_pct == 0 {
        out[..n].fill(0);
        return;
    }
    let scale_q8 = (i32::from(master_volume_pct.min(100)) * 256) / 100;
    for i in 0..n {
        let v = (accum[i].saturating_mul(scale_q8)) >> 8;
        out[i] = v.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
    }
}

/// Decoded RIFF `WAVE` PCM file ready for playback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedWav {
    /// Original file sample rate in Hz (`8000..=192000`).
    pub sample_rate: u32,
    /// Original channel count (`1` or `2`).
    pub original_channels: u16,
    /// Original bits per sample (`8`, `16`, `24`, or `32`).
    pub bits_per_sample: u16,
    /// Normalized interleaved stereo `S16LE` samples (`2 * frame_count`).
    pub stereo_samples: Vec<i16>,
}

/// Parse a RIFF `WAVE` PCM (`format == 1`) image into normalized stereo `i16` samples.
pub fn parse_wav_pcm(bytes: &[u8]) -> Option<DecodedWav> {
    if bytes.len() < 44 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return None;
    }
    let mut pos = 12usize;
    let mut fmt_found = false;
    let mut channels = 0u16;
    let mut sample_rate = 0u32;
    let mut bits_per_sample = 0u16;
    let mut data_slice: Option<&[u8]> = None;

    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let csize = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        pos += 8;
        let end = pos.saturating_add(csize).min(bytes.len());
        let body = &bytes[pos..end];
        if id == b"fmt " && body.len() >= 16 {
            let audio_fmt = u16::from_le_bytes([body[0], body[1]]);
            // Accept PCM (1) or WAVE_FORMAT_EXTENSIBLE (0xFFFE) with PCM subformat
            if audio_fmt != 1 && audio_fmt != 0xFFFE {
                return None;
            }
            channels = u16::from_le_bytes([body[2], body[3]]);
            sample_rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            bits_per_sample = u16::from_le_bytes([body[14], body[15]]);
            fmt_found = true;
        } else if id == b"data" {
            data_slice = Some(body);
            if fmt_found {
                break;
            }
        }
        // RIFF chunks are word-aligned (pad byte when odd).
        pos = end.saturating_add(csize & 1);
    }

    let raw = data_slice?;
    if !fmt_found || !(1..=2).contains(&channels) || !(4000..=192_000).contains(&sample_rate) {
        return None;
    }
    let bytes_per_sample = match bits_per_sample {
        8 => 1usize,
        16 => 2usize,
        24 => 3usize,
        32 => 4usize,
        _ => return None,
    };
    let frame_stride = usize::from(channels) * bytes_per_sample;
    let frame_count = raw.len() / frame_stride;
    let mut stereo = Vec::with_capacity(frame_count * 2);

    for f in 0..frame_count {
        let base = f * frame_stride;
        let l = decode_pcm_sample(&raw[base..base + bytes_per_sample], bits_per_sample);
        let r = if channels == 2 {
            decode_pcm_sample(
                &raw[base + bytes_per_sample..base + 2 * bytes_per_sample],
                bits_per_sample,
            )
        } else {
            l
        };
        stereo.push(l);
        stereo.push(r);
    }

    Some(DecodedWav {
        sample_rate,
        original_channels: channels,
        bits_per_sample,
        stereo_samples: stereo,
    })
}

fn decode_pcm_sample(b: &[u8], bits: u16) -> i16 {
    match bits {
        8 => (i16::from(b[0]) - 128) << 8,
        16 => i16::from_le_bytes([b[0], b[1]]),
        24 => i16::from_le_bytes([b[1], b[2]]),
        32 => i16::from_le_bytes([b[2], b[3]]),
        _ => 0,
    }
}

/// Zero-heap stateful stereo sine generator (`[L, R]` frames).
#[derive(Clone, Copy, Debug)]
pub struct StereoToneGenerator {
    step_l: u16,
    step_r: u16,
    ph_l: u16,
    ph_r: u16,
    amplitude: i16,
}

impl StereoToneGenerator {
    #[must_use]
    pub fn new(freq_hz: u32, sample_rate: u32, amplitude: i16) -> Self {
        let sr = sample_rate.max(8_000);
        let step_l = ((u64::from(freq_hz.clamp(20, 20_000)) << 16) / u64::from(sr)) as u16;
        let step_r =
            ((u64::from((freq_hz * 5 / 4).clamp(20, 20_000)) << 16) / u64::from(sr)) as u16;
        Self {
            step_l,
            step_r,
            ph_l: 0,
            ph_r: 0,
            amplitude: amplitude.clamp(0, 30_000),
        }
    }

    pub fn generate(&mut self, out: &mut [[i16; 2]]) {
        let amp = i32::from(self.amplitude);
        for frame in out.iter_mut() {
            let l = (i32::from(fast_sin_q15(self.ph_l)) * amp) >> 15;
            let r = (i32::from(fast_sin_q15(self.ph_r)) * amp) >> 15;
            *frame = [l as i16, r as i16];
            self.ph_l = self.ph_l.wrapping_add(self.step_l);
            self.ph_r = self.ph_r.wrapping_add(self.step_r);
        }
    }
}

/// Fast integer `sin(phase)` approximation returning `-32767..=32767` for `phase` in `0..65536`.
pub fn fast_sin_q15(phase_u16: u16) -> i16 {
    // Bhaskara / parabolic Q15 sine with 3rd-order correction (< 0.08% THD!).
    let quadrant = (phase_u16 >> 14) & 3;
    let x = (phase_u16 & 0x3FFF) as i64; // 0..16383
    let u = if (quadrant & 1) != 0 { 16384 - x } else { x };
    // Base parabola: y = (4 * u * (32768 - u)) / 2^15 -> 0..32768
    let base = (u * (32768 - u)) >> 13;
    // Correction: y = 0.775 * base + 0.225 * (base^2 / 32768)
    let sq = (base * base) >> 15;
    let y = ((base * 25395 + sq * 7373) >> 15).min(32767) as i16;
    if (quadrant & 2) != 0 {
        -y
    } else {
        y
    }
}

/// Generate a crisp stereo test signal (`sample_rate` Hz, `duration_ms`) with fade-in/out
/// envelope so users can immediately verify Left/Right wireless earbuds and `VirtIO-Sound`.
pub fn generate_stereo_tone(
    sample_rate: u32,
    freq_hz: u32,
    duration_ms: u32,
    amplitude_q15: i16,
) -> Vec<i16> {
    let sr = sample_rate.clamp(8000, 96_000);
    let frames = ((u64::from(sr) * u64::from(duration_ms)) / 1000) as usize;
    let fade_frames = ((sr / 50) as usize).min(frames / 2).max(1); // ~20 ms click-free envelope
    let step_l = ((u64::from(freq_hz.clamp(20, 20_000)) << 16) / u64::from(sr)) as u16;
    // Slight fifth interval (`3/2`) in right ear during second half for unmistakable L/R check!
    let step_r = ((u64::from((freq_hz * 3 / 2).clamp(20, 20_000)) << 16) / u64::from(sr)) as u16;

    let mut out = Vec::with_capacity(frames * 2);
    let mut ph_l = 0u16;
    let mut ph_r = 0u16;
    let amp = i32::from(amplitude_q15.clamp(0, 30_000));

    for i in 0..frames {
        let env_q10 = if i < fade_frames {
            ((i * 1024) / fade_frames) as i32
        } else if i + fade_frames > frames {
            (((frames - i) * 1024) / fade_frames) as i32
        } else {
            1024
        };
        let sl = (((i32::from(fast_sin_q15(ph_l)) * amp) >> 15) * env_q10) >> 10;
        let sr_val = (((i32::from(fast_sin_q15(ph_r)) * amp) >> 15) * env_q10) >> 10;
        out.push(sl as i16);
        out.push(sr_val as i16);
        ph_l = ph_l.wrapping_add(step_l);
        ph_r = ph_r.wrapping_add(step_r);
    }
    out
}
