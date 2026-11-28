//! Pure-Rust integer Yamaha YM3812/YMF262 (OPL2/OPL3-waveform) 2-operator FM
//! synthesizer, Doom `#OPL_II#` `GENMIDI` patch bank loader, dual `MUS\x1a` +
//! Standard MIDI (`MThd` Format 0/1) sequencer, and DMX digital SFX (`0x0003`)
//! 8-channel stereo mixer.
//!
//! Zero floating-point, `#![no_std]`, `#![forbid(unsafe_code)]`, zero heap.

pub const GENMIDI_MAGIC: &[u8; 8] = b"#OPL_II#";
pub const GENMIDI_NUM_INSTRS: usize = 175; // 128 melodic + 47 percussion (MIDI 35..=81)
pub const GENMIDI_MIN_BYTES: usize = 8 + GENMIDI_NUM_INSTRS * 36;

pub const MUS_MAGIC: &[u8; 4] = b"MUS\x1a";
pub const MIDI_MTHD_MAGIC: &[u8; 4] = b"MThd";
pub const MIDI_MTRK_MAGIC: &[u8; 4] = b"MTrk";

pub const OPL_POLYPHONY: usize = 12;
pub const MAX_MIDI_TRACKS: usize = 24;
pub const DMX_SFX_HEADER_LEN: usize = 8;
pub const DOOM_SFX_CHANNELS: usize = 8;

/// Quarter-sine lookup table `sin((i + 0.5) * pi / 128)` for `i = 0..63` in Q14 (`16384 = 1.0`).
const QUARTER_SINE_64_Q14: [i16; 64] = [
    201, 603, 1005, 1406, 1806, 2205, 2603, 2999, 3393, 3784, 4174, 4560, 4944, 5324, 5702, 6076,
    6446, 6812, 7174, 7532, 7885, 8233, 8576, 8914, 9247, 9574, 9895, 10210, 10519, 10822, 11118,
    11407, 11690, 11965, 12233, 12494, 12748, 12993, 13231, 13461, 13683, 13896, 14102, 14298,
    14486, 14666, 14836, 14998, 15150, 15293, 15428, 15553, 15668, 15775, 15872, 15959, 16037,
    16105, 16164, 16213, 16252, 16282, 16302, 16312,
];

/// Evaluate a 256-entry full-period OPL2/OPL3 waveform (`wave = 0..=5`) at 8-bit phase `p`, in Q14.
#[inline]
fn opl_waveform_q14(wave: u8, p: u8) -> i32 {
    let full_sine = |ph: u8| -> i32 {
        let q = (ph & 0x3F) as usize;
        let idx = if (ph & 0x40) != 0 { 63 - q } else { q };
        let mag = i32::from(QUARTER_SINE_64_Q14[idx]);
        if (ph & 0x80) != 0 {
            -mag
        } else {
            mag
        }
    };

    match wave & 0x07 {
        // 0: Pure sine
        0 => full_sine(p),
        // 1: Half-sine (positive half only, negative half = 0)
        1 => {
            if (p & 0x80) == 0 {
                full_sine(p)
            } else {
                0
            }
        }
        // 2: Abs-sine (`|sin|`)
        2 => full_sine(p & 0x7F),
        // 3: Pulse-sine (first quarter of each half-period)
        3 => {
            if (p & 0x40) == 0 {
                full_sine(p & 0x3F)
            } else {
                0
            }
        }
        // 4: OPL3 double-speed sine in first half-period (used in Freedoom GENMIDI!)
        4 => {
            if (p & 0x80) == 0 {
                full_sine(p.wrapping_mul(2))
            } else {
                0
            }
        }
        // 5: OPL3 abs double-speed sine in first half-period
        5 => {
            if (p & 0x80) == 0 {
                full_sine(p.wrapping_mul(2) & 0x7F)
            } else {
                0
            }
        }
        // 6: Square wave
        6 => {
            if (p & 0x80) == 0 {
                14_000
            } else {
                -14_000
            }
        }
        _ => full_sine(p),
    }
}

/// OPL2 frequency multiplier table (`reg 0x20 & 0x0F`), scaled by 2 (`1` = 0.5x, `2` = 1.0x, ...).
const OPL_MULT_X2: [u32; 16] = [1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 20, 24, 24, 30, 30];

/// MIDI note frequencies `0..12` (octave 0, `C0..B0`) in milli-Hz (`C4 = note 60 = 261_626 mHz`).
const NOTE_BASE_MHZ_OCT0: [u32; 12] = [
    8_176, 8_662, 9_177, 9_723, 10_301, 10_913, 11_562, 12_250, 12_978, 13_750, 14_568, 15_434,
];

#[inline]
fn midi_note_phase_inc_q32(note: u8, cents_bend: i32, sample_rate: u32) -> u32 {
    let clamped = note.min(127);
    let oct = u32::from(clamped / 12);
    let semi = usize::from(clamped % 12);
    let mut mhz = u64::from(NOTE_BASE_MHZ_OCT0[semi]) << oct;
    // Apply pitch bend (`cents_bend` in -200..=+200 cents -> ~ +/- 12% frequency):
    if cents_bend != 0 {
        // 2^(cents/1200) ~= 1 + cents * 0.00057762 -> `cents * 591 / 1_024_000`
        let delta = (mhz as i64 * i64::from(cents_bend) * 591) >> 20;
        mhz = (mhz as i64 + delta).max(1000) as u64;
    }
    let sr = u64::from(sample_rate.max(8_000)) * 1000;
    (((mhz << 32) / sr).min(u64::from(u32::MAX))) as u32
}

/// One voice half of a Doom `GENMIDI` instrument (`16` bytes).
#[derive(Clone, Copy, Debug, Default)]
pub struct GenMidiVoice {
    pub mod_trem_vib: u8,
    pub mod_att_dec: u8,
    pub mod_sus_rel: u8,
    pub mod_waveform: u8,
    pub mod_ksl: u8,
    pub mod_output: u8,
    pub feedback_conn: u8,
    pub car_trem_vib: u8,
    pub car_att_dec: u8,
    pub car_sus_rel: u8,
    pub car_waveform: u8,
    pub car_ksl: u8,
    pub car_output: u8,
    pub base_note_offset: i16,
}

impl GenMidiVoice {
    fn from_bytes(b: &[u8]) -> Self {
        Self {
            mod_trem_vib: b[0],
            mod_att_dec: b[1],
            mod_sus_rel: b[2],
            mod_waveform: b[3],
            mod_ksl: b[4],
            mod_output: b[5] & 0x3F,
            feedback_conn: b[6],
            car_trem_vib: b[7],
            car_att_dec: b[8],
            car_sus_rel: b[9],
            car_waveform: b[10],
            car_ksl: b[11],
            car_output: b[12] & 0x3F,
            base_note_offset: i16::from_le_bytes([b[14], b[15]]),
        }
    }
}

/// One Doom `GENMIDI` instrument (`36` bytes: flags + 2 OPL voices).
#[derive(Clone, Copy, Debug, Default)]
pub struct GenMidiPatch {
    pub flags: u16,
    pub fine_tune: u8,
    pub fixed_note: u8,
    pub voice0: GenMidiVoice,
    pub voice1: GenMidiVoice,
}

/// Loaded 175-instrument `#OPL_II#` `GENMIDI` bank.
#[derive(Clone)]
pub struct GenMidiBank {
    pub patches: [GenMidiPatch; GENMIDI_NUM_INSTRS],
}

impl GenMidiBank {
    /// Parse a Doom / Freedoom `GENMIDI` lump (`#OPL_II#`).
    pub fn from_lump(data: &[u8]) -> Option<Self> {
        if data.len() < GENMIDI_MIN_BYTES || &data[0..8] != GENMIDI_MAGIC {
            return None;
        }
        let mut patches = [GenMidiPatch::default(); GENMIDI_NUM_INSTRS];
        for (idx, slot) in patches.iter_mut().enumerate() {
            let off = 8 + idx * 36;
            let rec = &data[off..off + 36];
            *slot = GenMidiPatch {
                flags: u16::from_le_bytes([rec[0], rec[1]]),
                fine_tune: rec[2],
                fixed_note: rec[3],
                voice0: GenMidiVoice::from_bytes(&rec[4..20]),
                voice1: GenMidiVoice::from_bytes(&rec[20..36]),
            };
        }
        Some(Self { patches })
    }

    /// Construct a built-in General MIDI fallback bank so FM synthesis works even without a WAD.
    #[must_use]
    pub const fn builtin_default() -> Self {
        let default_voice = GenMidiVoice {
            mod_trem_vib: 0x01,
            mod_att_dec: 0xF2,
            mod_sus_rel: 0x44,
            mod_waveform: 0x00,
            mod_ksl: 0x00,
            mod_output: 18,
            feedback_conn: 0x06,
            car_trem_vib: 0x01,
            car_att_dec: 0xF2,
            car_sus_rel: 0x55,
            car_waveform: 0x00,
            car_ksl: 0x00,
            car_output: 4,
            base_note_offset: 0,
        };
        let patch = GenMidiPatch {
            flags: 0,
            fine_tune: 128,
            fixed_note: 60,
            voice0: default_voice,
            voice1: default_voice,
        };
        Self {
            patches: [patch; GENMIDI_NUM_INSTRS],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnvStage {
    Off,
    Attack,
    Decay,
    Sustain,
    Release,
}

#[derive(Clone, Copy, Debug)]
struct OplOperator {
    stage: EnvStage,
    env_q16: i32, // 0 ..= 65536 (`65536` = peak, `0` = silent)
    attack_step: i32,
    decay_step: i32,
    sustain_level_q16: i32,
    release_step: i32,
    sustained_hold: bool,
    waveform: u8,
    mult_x2: u32,
    atten_q8: i32, // Linear gain `0..=256` derived from OPL 0.75 dB `Total Level (0..63)`
    phase: u32,
    prev_out: [i32; 2],
}

impl Default for OplOperator {
    fn default() -> Self {
        Self {
            stage: EnvStage::Off,
            env_q16: 0,
            attack_step: 2048,
            decay_step: 64,
            sustain_level_q16: 32768,
            release_step: 128,
            sustained_hold: true,
            waveform: 0,
            mult_x2: 2,
            atten_q8: 256,
            phase: 0,
            prev_out: [0, 0],
        }
    }
}

/// Convert OPL 6-bit Total Level (`0..=63`, 0.75 dB/step) into linear gain `0..=256`.
#[inline]
fn opl_tl_to_gain_q8(tl: u8) -> i32 {
    const DB_OCT_TABLE: [i32; 8] = [256, 235, 215, 197, 181, 166, 152, 140];
    let clamped = (tl & 0x3F) as usize;
    let shift = clamped / 8;
    if shift >= 8 {
        0
    } else {
        DB_OCT_TABLE[clamped % 8] >> shift
    }
}

#[inline]
fn opl_rate_to_step(rate_nibble: u8, is_attack: bool) -> i32 {
    let r = u32::from(rate_nibble & 0x0F);
    if r == 0 {
        return 0;
    }
    if is_attack {
        if r >= 15 {
            65_536
        } else {
            (4u32 << (r.min(14))) as i32
        }
    } else {
        ((1u32 << (r.min(13))) >> 1).max(1) as i32
    }
}

#[inline]
const fn opl_mult_from_reg(trem_vib: u8) -> u32 {
    OPL_MULT_X2[(trem_vib & 0x0F) as usize]
}

impl OplOperator {
    fn trigger(&mut self, trem_vib: u8, att_dec: u8, sus_rel: u8, wave: u8, tl: u8) {
        self.mult_x2 = opl_mult_from_reg(trem_vib);
        self.sustained_hold = (trem_vib & 0x20) != 0;
        self.waveform = wave & 0x07;
        self.atten_q8 = opl_tl_to_gain_q8(tl);
        self.attack_step = opl_rate_to_step(att_dec >> 4, true).max(64);
        self.decay_step = opl_rate_to_step(att_dec & 0x0F, false);
        let sl = u32::from(sus_rel >> 4);
        self.sustain_level_q16 = if sl == 15 {
            0
        } else {
            (65_536i32 >> (sl.min(10))).max(512)
        };
        self.release_step = opl_rate_to_step(sus_rel & 0x0F, false).max(8);
        self.stage = EnvStage::Attack;
        self.phase = 0;
        self.prev_out = [0, 0];
    }

    #[inline]
    fn step_envelope(&mut self) -> i32 {
        match self.stage {
            EnvStage::Off => 0,
            EnvStage::Attack => {
                self.env_q16 = (self.env_q16 + self.attack_step).min(65_536);
                if self.env_q16 >= 65_536 {
                    self.stage = EnvStage::Decay;
                }
                self.env_q16
            }
            EnvStage::Decay => {
                self.env_q16 = (self.env_q16 - self.decay_step).max(self.sustain_level_q16);
                if self.env_q16 <= self.sustain_level_q16 {
                    self.stage = if self.sustained_hold {
                        EnvStage::Sustain
                    } else {
                        EnvStage::Release
                    };
                }
                self.env_q16
            }
            EnvStage::Sustain => self.env_q16,
            EnvStage::Release => {
                self.env_q16 = (self.env_q16 - self.release_step).max(0);
                if self.env_q16 == 0 {
                    self.stage = EnvStage::Off;
                }
                self.env_q16
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct OplVoice {
    active: bool,
    midi_ch: u8,
    midi_note: u8,
    base_note: u8,
    age: u64,
    feedback: u8,
    additive: bool,
    velocity_q8: i32,
    pan_l_q8: i32,
    pan_r_q8: i32,
    phase_inc: u32,
    modulator: OplOperator,
    carrier: OplOperator,
}

/// Polyphonic 2-operator YM3812 (OPL2) FM synthesizer running at `sample_rate` Hz.
pub struct Opl2Synth {
    sample_rate: u32,
    voices: [OplVoice; OPL_POLYPHONY],
    ch_program: [u8; 16],
    ch_volume: [u8; 16],
    ch_pan: [u8; 16],
    ch_bend_cents: [i16; 16],
    master_volume: u8, // 0..=127
    voice_clock: u64,
}

impl Opl2Synth {
    #[must_use]
    pub fn new(sample_rate: u32) -> Self {
        Self {
            sample_rate: sample_rate.max(8_000),
            voices: [OplVoice::default(); OPL_POLYPHONY],
            ch_program: [0u8; 16],
            ch_volume: [100u8; 16],
            ch_pan: [64u8; 16],
            ch_bend_cents: [0i16; 16],
            master_volume: 100,
            voice_clock: 0,
        }
    }

    pub fn set_master_volume(&mut self, vol_0_127: u8) {
        self.master_volume = vol_0_127.min(127);
    }

    #[must_use]
    pub const fn master_volume(&self) -> u8 {
        self.master_volume
    }

    pub fn all_notes_off(&mut self) {
        for v in &mut self.voices {
            if v.active {
                v.modulator.stage = EnvStage::Release;
                v.carrier.stage = EnvStage::Release;
            }
        }
    }

    pub fn silence_immediately(&mut self) {
        self.voices = [OplVoice::default(); OPL_POLYPHONY];
    }

    pub fn program_change(&mut self, ch: u8, program: u8) {
        self.ch_program[(ch & 0x0F) as usize] = program & 0x7F;
    }

    pub fn set_channel_volume(&mut self, ch: u8, vol: u8) {
        self.ch_volume[(ch & 0x0F) as usize] = vol & 0x7F;
    }

    pub fn set_channel_pan(&mut self, ch: u8, pan: u8) {
        self.ch_pan[(ch & 0x0F) as usize] = pan & 0x7F;
    }

    pub fn set_pitch_bend_cents(&mut self, ch: u8, cents: i16) {
        let idx = (ch & 0x0F) as usize;
        self.ch_bend_cents[idx] = cents.clamp(-200, 200);
        for v in &mut self.voices {
            if v.active && v.midi_ch == (ch & 0x0F) {
                v.phase_inc = midi_note_phase_inc_q32(
                    v.base_note,
                    i32::from(self.ch_bend_cents[idx]),
                    self.sample_rate,
                );
            }
        }
    }

    pub fn note_off(&mut self, ch: u8, note: u8) {
        let ch_m = ch & 0x0F;
        let n_m = note & 0x7F;
        for v in &mut self.voices {
            if v.active && v.midi_ch == ch_m && v.midi_note == n_m {
                v.modulator.stage = EnvStage::Release;
                v.carrier.stage = EnvStage::Release;
            }
        }
    }

    pub fn note_on(
        &mut self,
        bank: &GenMidiBank,
        ch: u8,
        note: u8,
        velocity: u8,
        is_percussion: bool,
    ) {
        let vel = velocity & 0x7F;
        if vel == 0 {
            self.note_off(ch, note);
            return;
        }
        let patch_idx = if is_percussion {
            let n = note & 0x7F;
            if !(35..=81).contains(&n) {
                return;
            }
            128 + usize::from(n - 35)
        } else {
            usize::from(self.ch_program[(ch & 0x0F) as usize] & 0x7F)
        };

        let patch = &bank.patches[patch_idx];
        self.spawn_one_voice(
            patch,
            &patch.voice0,
            ch & 0x0F,
            note & 0x7F,
            vel,
            0,
            is_percussion,
        );
        if (patch.flags & 0x0004) != 0 {
            let detune_cents = (i16::from(patch.fine_tune) - 128) / 2;
            self.spawn_one_voice(
                patch,
                &patch.voice1,
                ch & 0x0F,
                note & 0x7F,
                vel.saturating_sub(12).max(1),
                detune_cents,
                is_percussion,
            );
        }
    }

    fn spawn_one_voice(
        &mut self,
        patch: &GenMidiPatch,
        gv: &GenMidiVoice,
        ch: u8,
        midi_note: u8,
        vel: u8,
        detune_cents: i16,
        is_percussion: bool,
    ) {
        let slot_idx = self.pick_voice_slot();
        self.voice_clock = self.voice_clock.wrapping_add(1);

        let raw_note = if (patch.flags & 0x0001) != 0 {
            i32::from(patch.fixed_note)
        } else if is_percussion {
            i32::from(midi_note)
        } else {
            i32::from(midi_note) + i32::from(gv.base_note_offset)
        };
        let base_note = raw_note.clamp(12, 115) as u8;
        let bend = i32::from(self.ch_bend_cents[usize::from(ch)]) + i32::from(detune_cents);
        let phase_inc = midi_note_phase_inc_q32(base_note, bend, self.sample_rate);

        let ch_vol = i32::from(self.ch_volume[usize::from(ch)]);
        let velocity_q8 = ((i32::from(vel) * ch_vol) >> 6).clamp(8, 256);
        let pan = i32::from(self.ch_pan[usize::from(ch)]);
        let pan_r_q8 = (pan * 2).clamp(0, 256);
        let pan_l_q8 = (256 - pan_r_q8).clamp(0, 256);

        let mut v = OplVoice {
            active: true,
            midi_ch: ch,
            midi_note,
            base_note,
            age: self.voice_clock,
            feedback: (gv.feedback_conn >> 1) & 0x07,
            additive: (gv.feedback_conn & 0x01) != 0,
            velocity_q8,
            pan_l_q8,
            pan_r_q8,
            phase_inc,
            modulator: OplOperator::default(),
            carrier: OplOperator::default(),
        };
        v.modulator.trigger(
            gv.mod_trem_vib,
            gv.mod_att_dec,
            gv.mod_sus_rel,
            gv.mod_waveform,
            gv.mod_output,
        );
        v.carrier.trigger(
            gv.car_trem_vib,
            gv.car_att_dec,
            gv.car_sus_rel,
            gv.car_waveform,
            gv.car_output,
        );
        self.voices[slot_idx] = v;
    }

    fn pick_voice_slot(&self) -> usize {
        for (i, v) in self.voices.iter().enumerate() {
            if !v.active || v.carrier.stage == EnvStage::Off {
                return i;
            }
        }
        // Prefer stealing a voice already in Release, else the oldest voice.
        let mut best_rel: Option<(usize, u64)> = None;
        let mut oldest: (usize, u64) = (0, u64::MAX);
        for (i, v) in self.voices.iter().enumerate() {
            if v.age < oldest.1 {
                oldest = (i, v.age);
            }
            if v.carrier.stage == EnvStage::Release {
                match best_rel {
                    None => best_rel = Some((i, v.age)),
                    Some((_, best_age)) if v.age < best_age => best_rel = Some((i, v.age)),
                    _ => {}
                }
            }
        }
        best_rel.map_or(oldest.0, |(idx, _)| idx)
    }

    /// Synthesize and mix `out_stereo.len()` stereo S16LE frames (accumulating with saturation).
    pub fn mix_into(&mut self, out_stereo: &mut [[i16; 2]]) {
        if self.master_volume == 0 {
            return;
        }
        let master_q8 = i32::from(self.master_volume) * 2;

        for frame in out_stereo.iter_mut() {
            let mut sum_l = 0i32;
            let mut sum_r = 0i32;

            for v in &mut self.voices {
                if !v.active {
                    continue;
                }
                let car_env = v.carrier.step_envelope();
                if v.carrier.stage == EnvStage::Off {
                    v.active = false;
                    continue;
                }
                let mod_env = v.modulator.step_envelope();

                v.modulator.phase = v
                    .modulator
                    .phase
                    .wrapping_add((v.phase_inc >> 1).wrapping_mul(v.modulator.mult_x2));
                v.carrier.phase = v
                    .carrier
                    .phase
                    .wrapping_add((v.phase_inc >> 1).wrapping_mul(v.carrier.mult_x2));

                let fb_offset: u8 = if v.feedback > 0 {
                    let avg_prev = (v.modulator.prev_out[0] + v.modulator.prev_out[1]) >> 1;
                    ((avg_prev >> (16 - v.feedback.min(7))) & 0xFF) as u8
                } else {
                    0
                };
                let mod_phase = ((v.modulator.phase >> 24) as u8).wrapping_add(fb_offset);
                let mod_wave = opl_waveform_q14(v.modulator.waveform, mod_phase);
                let mod_amp = (((mod_wave * (mod_env >> 2)) >> 14) * v.modulator.atten_q8) >> 8;
                v.modulator.prev_out[1] = v.modulator.prev_out[0];
                v.modulator.prev_out[0] = mod_amp;

                let sample_q14 = if v.additive {
                    let car_phase = (v.carrier.phase >> 24) as u8;
                    let car_wave = opl_waveform_q14(v.carrier.waveform, car_phase);
                    let car_amp = (((car_wave * (car_env >> 2)) >> 14) * v.carrier.atten_q8) >> 8;
                    (car_amp + mod_amp) >> 1
                } else {
                    // FM phase modulation: full-scale `mod_amp` (`16384`) sweeps +/- 2pi (`256` phase units).
                    let fm_shift = ((mod_amp >> 6) & 0xFF) as u8;
                    let car_phase = ((v.carrier.phase >> 24) as u8).wrapping_add(fm_shift);
                    let car_wave = opl_waveform_q14(v.carrier.waveform, car_phase);
                    (((car_wave * (car_env >> 2)) >> 14) * v.carrier.atten_q8) >> 8
                };

                let voiced = (sample_q14 * v.velocity_q8) >> 9;
                sum_l += (voiced * v.pan_l_q8) >> 8;
                sum_r += (voiced * v.pan_r_q8) >> 8;
            }

            let scaled_l = (sum_l * master_q8) >> 8;
            let scaled_r = (sum_r * master_q8) >> 8;
            frame[0] = (i32::from(frame[0]) + scaled_l)
                .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
            frame[1] = (i32::from(frame[1]) + scaled_r)
                .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct MidiTrackCursor {
    active: bool,
    start: usize,
    end: usize,
    pos: usize,
    wait_ticks: u32,
    running_status: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SongFormat {
    None,
    Mus,
    Smf,
}

/// Unified `MUS\x1a` + Standard MIDI (`MThd` Format 0/1) sequencer driving `Opl2Synth`.
pub struct DoomMusicPlayer {
    pub synth: Opl2Synth,
    pub bank: GenMidiBank,
    format: SongFormat,
    playing: bool,
    paused: bool,
    looping: bool,
    sample_rate: u32,
    samples_until_tick_q16: i64,
    samples_per_tick_q16: i64,
    // MUS cursor
    mus_start: usize,
    mus_end: usize,
    mus_pos: usize,
    mus_last_vol: [u8; 16],
    // SMF multi-track cursors
    smf_division: u16,
    smf_tempo_us_per_qn: u32,
    smf_tracks: [MidiTrackCursor; MAX_MIDI_TRACKS],
    smf_track_count: usize,
}

impl DoomMusicPlayer {
    #[must_use]
    pub fn new(sample_rate: u32) -> Self {
        let sr = sample_rate.max(8_000);
        // Default 140 Hz MUS tick rate (`sr / 140` in Q16).
        let spt = ((i64::from(sr) << 16) / 140).max(1 << 16);
        Self {
            synth: Opl2Synth::new(sr),
            bank: GenMidiBank::builtin_default(),
            format: SongFormat::None,
            playing: false,
            paused: false,
            looping: true,
            sample_rate: sr,
            samples_until_tick_q16: 0,
            samples_per_tick_q16: spt,
            mus_start: 0,
            mus_end: 0,
            mus_pos: 0,
            mus_last_vol: [100u8; 16],
            smf_division: 96,
            smf_tempo_us_per_qn: 500_000, // 120 BPM default
            smf_tracks: [MidiTrackCursor::default(); MAX_MIDI_TRACKS],
            smf_track_count: 0,
        }
    }

    pub fn load_genmidi(&mut self, data: &[u8]) -> bool {
        if let Some(bank) = GenMidiBank::from_lump(data) {
            self.bank = bank;
            true
        } else {
            false
        }
    }

    /// Load either a `MUS\x1a` lump (Doom IWAD) or an `MThd` Standard MIDI lump (Freedoom IWAD).
    pub fn register_song(&mut self, song_bytes: &[u8]) -> bool {
        self.stop();
        if song_bytes.len() >= 8 && &song_bytes[0..4] == MUS_MAGIC {
            let score_len = usize::from(u16::from_le_bytes([song_bytes[4], song_bytes[5]]));
            let score_start = usize::from(u16::from_le_bytes([song_bytes[6], song_bytes[7]]));
            if score_start >= song_bytes.len() {
                return false;
            }
            self.format = SongFormat::Mus;
            self.mus_start = score_start;
            self.mus_end = (score_start + score_len).min(song_bytes.len());
            self.mus_pos = score_start;
            self.mus_last_vol = [100u8; 16];
            self.samples_per_tick_q16 = ((i64::from(self.sample_rate) << 16) / 140).max(1 << 16);
            self.samples_until_tick_q16 = 0;
            return true;
        }

        if song_bytes.len() >= 14 && &song_bytes[0..4] == MIDI_MTHD_MAGIC {
            let hdr_len =
                u32::from_be_bytes([song_bytes[4], song_bytes[5], song_bytes[6], song_bytes[7]])
                    as usize;
            let ntrks = usize::from(u16::from_be_bytes([song_bytes[10], song_bytes[11]]));
            let division = u16::from_be_bytes([song_bytes[12], song_bytes[13]]).max(1);
            let mut pos = 8 + hdr_len;
            let mut count = 0usize;
            self.smf_tracks = [MidiTrackCursor::default(); MAX_MIDI_TRACKS];

            while pos + 8 <= song_bytes.len() && count < ntrks && count < MAX_MIDI_TRACKS {
                let tag = &song_bytes[pos..pos + 4];
                let tlen = u32::from_be_bytes([
                    song_bytes[pos + 4],
                    song_bytes[pos + 5],
                    song_bytes[pos + 6],
                    song_bytes[pos + 7],
                ]) as usize;
                let data_start = pos + 8;
                let data_end = (data_start + tlen).min(song_bytes.len());
                if tag == MIDI_MTRK_MAGIC && data_start < data_end {
                    let mut cur = MidiTrackCursor {
                        active: true,
                        start: data_start,
                        end: data_end,
                        pos: data_start,
                        wait_ticks: 0,
                        running_status: 0,
                    };
                    cur.wait_ticks = read_smf_vlq(song_bytes, &mut cur.pos, cur.end);
                    self.smf_tracks[count] = cur;
                    count += 1;
                }
                pos = data_end;
            }

            if count > 0 {
                self.format = SongFormat::Smf;
                self.smf_division = division & 0x7FFF;
                self.smf_tempo_us_per_qn = 500_000;
                self.smf_track_count = count;
                self.recompute_smf_tick_rate();
                self.samples_until_tick_q16 = 0;
                return true;
            }
        }
        false
    }

    fn recompute_smf_tick_rate(&mut self) {
        let div = u64::from(self.smf_division.max(1));
        let tempo = u64::from(self.smf_tempo_us_per_qn.max(20_000));
        let num = (u64::from(self.sample_rate) * tempo) << 16;
        let den = div * 1_000_000;
        self.samples_per_tick_q16 = ((num / den).max(4096)) as i64;
    }

    pub fn start(&mut self, looping: bool) {
        if self.format != SongFormat::None {
            self.looping = looping;
            self.playing = true;
            self.paused = false;
        }
    }

    pub fn pause(&mut self) {
        self.paused = true;
        self.synth.all_notes_off();
    }

    pub fn resume(&mut self) {
        self.paused = false;
    }

    pub fn stop(&mut self) {
        self.playing = false;
        self.paused = false;
        self.synth.silence_immediately();
    }

    #[must_use]
    pub const fn is_playing(&self) -> bool {
        self.playing && !self.paused
    }

    fn rewind(&mut self, song_bytes: &[u8]) {
        self.synth.all_notes_off();
        match self.format {
            SongFormat::Mus => {
                self.mus_pos = self.mus_start;
                self.mus_last_vol = [100u8; 16];
            }
            SongFormat::Smf => {
                self.smf_tempo_us_per_qn = 500_000;
                self.recompute_smf_tick_rate();
                for trk in &mut self.smf_tracks[..self.smf_track_count] {
                    trk.pos = trk.start;
                    trk.running_status = 0;
                    trk.active = trk.start < trk.end;
                    if trk.active {
                        trk.wait_ticks = read_smf_vlq(song_bytes, &mut trk.pos, trk.end);
                    }
                }
            }
            SongFormat::None => {}
        }
    }

    fn step_mus_tick(&mut self, song_bytes: &[u8]) {
        let mut guard = 0usize;
        while self.playing && guard < 256 {
            guard += 1;
            if self.mus_pos >= self.mus_end || self.mus_pos >= song_bytes.len() {
                if self.looping {
                    self.rewind(song_bytes);
                } else {
                    self.stop();
                }
                return;
            }

            let desc = song_bytes[self.mus_pos];
            self.mus_pos += 1;
            let last_in_group = (desc & 0x80) != 0;
            let ev_type = (desc >> 4) & 0x07;
            let ch = desc & 0x0F;
            let is_perc = ch == 15;

            match ev_type {
                // Release note
                0 if self.mus_pos < self.mus_end => {
                    let note = song_bytes[self.mus_pos] & 0x7F;
                    self.mus_pos += 1;
                    self.synth.note_off(ch, note);
                }
                // Play note
                1 if self.mus_pos < self.mus_end => {
                    let b1 = song_bytes[self.mus_pos];
                    self.mus_pos += 1;
                    let note = b1 & 0x7F;
                    let vol = if (b1 & 0x80) != 0 && self.mus_pos < self.mus_end {
                        let v = song_bytes[self.mus_pos] & 0x7F;
                        self.mus_pos += 1;
                        self.mus_last_vol[usize::from(ch)] = v;
                        v
                    } else {
                        self.mus_last_vol[usize::from(ch)]
                    };
                    self.synth.note_on(&self.bank, ch, note, vol, is_perc);
                }
                // Pitch bend (`0..255`, `128` = center, +/- 2 semitones = +/- 200 cents)
                2 if self.mus_pos < self.mus_end => {
                    let raw = i16::from(song_bytes[self.mus_pos]);
                    self.mus_pos += 1;
                    let cents = ((raw - 128) * 200) / 128;
                    self.synth.set_pitch_bend_cents(ch, cents);
                }
                // System event
                3 if self.mus_pos < self.mus_end => {
                    let sys = song_bytes[self.mus_pos] & 0x7F;
                    self.mus_pos += 1;
                    if sys == 10 || sys == 11 {
                        self.synth.all_notes_off();
                    }
                }
                // Controller
                4 if self.mus_pos + 1 < self.mus_end => {
                    let ctrl = song_bytes[self.mus_pos] & 0x7F;
                    let val = song_bytes[self.mus_pos + 1] & 0x7F;
                    self.mus_pos += 2;
                    match ctrl {
                        0 => self.synth.program_change(ch, val),
                        3 => self.synth.set_channel_volume(ch, val),
                        4 => self.synth.set_channel_pan(ch, val),
                        _ => {}
                    }
                }
                // End of score
                6 => {
                    if self.looping {
                        self.rewind(song_bytes);
                    } else {
                        self.stop();
                    }
                    return;
                }
                5 => {}
                _ => {
                    self.stop();
                    return;
                }
            }

            if last_in_group {
                let mut delay_ticks = 0u32;
                for _ in 0..4 {
                    if self.mus_pos >= self.mus_end {
                        break;
                    }
                    let tb = song_bytes[self.mus_pos];
                    self.mus_pos += 1;
                    delay_ticks = (delay_ticks << 7) | u32::from(tb & 0x7F);
                    if (tb & 0x80) == 0 {
                        break;
                    }
                }
                if delay_ticks > 0 {
                    self.samples_until_tick_q16 +=
                        i64::from(delay_ticks) * self.samples_per_tick_q16;
                    return;
                }
            }
        }
    }

    fn step_smf_tick(&mut self, song_bytes: &[u8]) {
        let mut any_active = false;
        let mut new_tempo: Option<u32> = None;

        for t_idx in 0..self.smf_track_count {
            let trk = &mut self.smf_tracks[t_idx];
            if !trk.active {
                continue;
            }
            any_active = true;
            if trk.wait_ticks > 0 {
                trk.wait_ticks -= 1;
            }
            let mut guard = 0usize;
            while trk.active && trk.wait_ticks == 0 && guard < 128 {
                guard += 1;
                if trk.pos >= trk.end || trk.pos >= song_bytes.len() {
                    trk.active = false;
                    break;
                }
                let peek = song_bytes[trk.pos];
                let status = if (peek & 0x80) != 0 {
                    trk.pos += 1;
                    if peek < 0xF0 {
                        trk.running_status = peek;
                    }
                    peek
                } else {
                    trk.running_status
                };

                if status == 0xFF {
                    // Meta event
                    if trk.pos >= trk.end {
                        trk.active = false;
                        break;
                    }
                    let meta_type = song_bytes[trk.pos];
                    trk.pos += 1;
                    let mlen = read_smf_vlq(song_bytes, &mut trk.pos, trk.end) as usize;
                    if trk.pos + mlen > trk.end {
                        trk.active = false;
                        break;
                    }
                    if meta_type == 0x2F {
                        // End of Track
                        trk.active = false;
                        break;
                    } else if meta_type == 0x51 && mlen == 3 {
                        let t_us = (u32::from(song_bytes[trk.pos]) << 16)
                            | (u32::from(song_bytes[trk.pos + 1]) << 8)
                            | u32::from(song_bytes[trk.pos + 2]);
                        new_tempo = Some(t_us);
                    }
                    trk.pos += mlen;
                } else if status == 0xF0 || status == 0xF7 {
                    let slen = read_smf_vlq(song_bytes, &mut trk.pos, trk.end) as usize;
                    trk.pos = (trk.pos + slen).min(trk.end);
                } else {
                    let hi = status & 0xF0;
                    let ch = status & 0x0F;
                    let is_perc = ch == 9; // GM MIDI channel 10 (`9` 0-indexed)
                    match hi {
                        0x80 if trk.pos + 1 < trk.end => {
                            let note = song_bytes[trk.pos] & 0x7F;
                            trk.pos += 2;
                            self.synth.note_off(ch, note);
                        }
                        0x90 if trk.pos + 1 < trk.end => {
                            let note = song_bytes[trk.pos] & 0x7F;
                            let vel = song_bytes[trk.pos + 1] & 0x7F;
                            trk.pos += 2;
                            self.synth.note_on(&self.bank, ch, note, vel, is_perc);
                        }
                        0xA0 if trk.pos + 1 < trk.end => {
                            trk.pos += 2;
                        }
                        0xB0 if trk.pos + 1 < trk.end => {
                            let cc = song_bytes[trk.pos] & 0x7F;
                            let val = song_bytes[trk.pos + 1] & 0x7F;
                            trk.pos += 2;
                            match cc {
                                7 => self.synth.set_channel_volume(ch, val),
                                10 => self.synth.set_channel_pan(ch, val),
                                120 | 123 => self.synth.all_notes_off(),
                                _ => {}
                            }
                        }
                        0xC0 if trk.pos < trk.end => {
                            let prog = song_bytes[trk.pos] & 0x7F;
                            trk.pos += 1;
                            self.synth.program_change(ch, prog);
                        }
                        0xD0 if trk.pos < trk.end => {
                            trk.pos += 1;
                        }
                        0xE0 if trk.pos + 1 < trk.end => {
                            let lsb = i32::from(song_bytes[trk.pos] & 0x7F);
                            let msb = i32::from(song_bytes[trk.pos + 1] & 0x7F);
                            trk.pos += 2;
                            let val14 = (msb << 7) | lsb;
                            let cents = (((val14 - 8192) * 200) / 8192) as i16;
                            self.synth.set_pitch_bend_cents(ch, cents);
                        }
                        _ => {
                            trk.active = false;
                            break;
                        }
                    }
                }

                if trk.active && trk.pos < trk.end {
                    trk.wait_ticks = read_smf_vlq(song_bytes, &mut trk.pos, trk.end);
                } else {
                    trk.active = false;
                }
            }
        }

        if let Some(t_us) = new_tempo {
            self.smf_tempo_us_per_qn = t_us;
            self.recompute_smf_tick_rate();
        }

        if !any_active {
            if self.looping {
                self.rewind(song_bytes);
            } else {
                self.stop();
            }
            return;
        }
        self.samples_until_tick_q16 += self.samples_per_tick_q16;
    }

    /// Render `out_stereo.len()` stereo S16LE frames from `song_bytes`, accumulating into `out_stereo`.
    pub fn render_into(&mut self, song_bytes: &[u8], out_stereo: &mut [[i16; 2]]) {
        if !self.playing || self.paused || self.format == SongFormat::None {
            return;
        }
        let mut cursor = 0usize;
        while cursor < out_stereo.len() && self.playing {
            while self.samples_until_tick_q16 <= 0 && self.playing {
                match self.format {
                    SongFormat::Mus => self.step_mus_tick(song_bytes),
                    SongFormat::Smf => self.step_smf_tick(song_bytes),
                    SongFormat::None => return,
                }
            }
            if !self.playing {
                break;
            }
            let frames_avail = ((self.samples_until_tick_q16 + 0xFFFF) >> 16).max(1) as usize;
            let chunk = frames_avail.min(out_stereo.len() - cursor).min(64);
            self.synth.mix_into(&mut out_stereo[cursor..cursor + chunk]);
            self.samples_until_tick_q16 -= (chunk as i64) << 16;
            cursor += chunk;
        }
    }
}

fn read_smf_vlq(buf: &[u8], pos: &mut usize, end: usize) -> u32 {
    let mut val = 0u32;
    for _ in 0..4 {
        if *pos >= end || *pos >= buf.len() {
            break;
        }
        let b = buf[*pos];
        *pos += 1;
        val = (val << 7) | u32::from(b & 0x7F);
        if (b & 0x80) == 0 {
            break;
        }
    }
    val
}

// ============================================================================
// Doom DMX Sound Effect (`format = 0x0003`) Parser & 8-Channel Stereo Mixer
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct DmxSoundSlice<'a> {
    pub sample_rate: u16,
    pub pcm_u8: &'a [u8],
}

/// Parse a Doom / Freedoom DMX sound effect lump (`0x0003`, `sample_rate`, `length`, 8-bit unsigned PCM).
#[must_use]
pub fn parse_dmx_sfx(lump: &[u8]) -> Option<DmxSoundSlice<'_>> {
    if lump.len() <= DMX_SFX_HEADER_LEN + 32 {
        return None;
    }
    let fmt = u16::from_le_bytes([lump[0], lump[1]]);
    if fmt != 0x0003 {
        return None;
    }
    let sample_rate = u16::from_le_bytes([lump[2], lump[3]]).max(4000);
    let raw_len = u32::from_le_bytes([lump[4], lump[5], lump[6], lump[7]]) as usize;
    let avail = lump.len() - DMX_SFX_HEADER_LEN;
    let total = raw_len.min(avail);
    // Strip 16-byte DMX padding at start and end when present.
    let slice = if total > 32 {
        &lump[DMX_SFX_HEADER_LEN + 16..DMX_SFX_HEADER_LEN + total - 16]
    } else {
        &lump[DMX_SFX_HEADER_LEN..DMX_SFX_HEADER_LEN + total]
    };
    Some(DmxSoundSlice {
        sample_rate,
        pcm_u8: slice,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct ActiveSfxVoice {
    active: bool,
    sfx_id: i32,
    pos_q16: u64,
    step_q16: u64,
    gain_l_q8: i32,
    gain_r_q8: i32,
    data_ptr_idx: usize,
    data_len: usize,
}

/// Zero-unsafe 8-channel Doom SFX mixer resampling 11025/22050 Hz 8-bit DMX lumps to 48 kHz stereo.
pub struct DoomSfxMixer {
    out_rate: u32,
    voices: [ActiveSfxVoice; DOOM_SFX_CHANNELS],
}

impl DoomSfxMixer {
    #[must_use]
    pub const fn new(out_rate: u32) -> Self {
        Self {
            out_rate,
            voices: [ActiveSfxVoice {
                active: false,
                sfx_id: 0,
                pos_q16: 0,
                step_q16: 65_536,
                gain_l_q8: 128,
                gain_r_q8: 128,
                data_ptr_idx: 0,
                data_len: 0,
            }; DOOM_SFX_CHANNELS],
        }
    }

    pub fn start_channel(
        &mut self,
        channel: usize,
        sfx_id: i32,
        pool_offset: usize,
        pcm_len: usize,
        in_rate: u16,
        vol_0_127: i32,
        sep_0_255: i32,
    ) {
        let ch = channel % DOOM_SFX_CHANNELS;
        let step_q16 =
            ((u64::from(in_rate.max(4000)) << 16) / u64::from(self.out_rate.max(8000))).max(1024);
        let mut slot = ActiveSfxVoice {
            active: pcm_len > 1,
            sfx_id,
            pos_q16: 0,
            step_q16,
            gain_l_q8: 0,
            gain_r_q8: 0,
            data_ptr_idx: pool_offset,
            data_len: pcm_len,
        };
        Self::compute_gains(
            vol_0_127,
            sep_0_255,
            &mut slot.gain_l_q8,
            &mut slot.gain_r_q8,
        );
        self.voices[ch] = slot;
    }

    pub fn update_channel(&mut self, channel: usize, vol_0_127: i32, sep_0_255: i32) {
        if channel < DOOM_SFX_CHANNELS {
            let v = &mut self.voices[channel];
            Self::compute_gains(vol_0_127, sep_0_255, &mut v.gain_l_q8, &mut v.gain_r_q8);
        }
    }

    pub fn stop_channel(&mut self, channel: usize) {
        if channel < DOOM_SFX_CHANNELS {
            self.voices[channel].active = false;
        }
    }

    #[must_use]
    pub const fn channel_is_playing(&self, channel: usize) -> bool {
        if channel < DOOM_SFX_CHANNELS {
            self.voices[channel].active
        } else {
            false
        }
    }

    fn compute_gains(vol: i32, sep: i32, gain_l: &mut i32, gain_r: &mut i32) {
        let v = vol.clamp(0, 127) * 2;
        let s = sep.clamp(0, 255);
        *gain_l = (v * (255 - s)) >> 8;
        *gain_r = (v * s) >> 8;
    }

    /// Mix all active DMX voices from `pcm_pool` (8-bit unsigned samples) into `out_stereo`.
    pub fn mix_into(&mut self, pcm_pool: &[u8], out_stereo: &mut [[i16; 2]]) {
        for frame in out_stereo.iter_mut() {
            let mut acc_l = i32::from(frame[0]);
            let mut acc_r = i32::from(frame[1]);

            for v in &mut self.voices {
                if !v.active {
                    continue;
                }
                let idx = (v.pos_q16 >> 16) as usize;
                if idx >= v.data_len || v.data_ptr_idx + idx >= pcm_pool.len() {
                    v.active = false;
                    continue;
                }
                let s0 = (i32::from(pcm_pool[v.data_ptr_idx + idx]) - 128) << 8;
                let s1 = if idx + 1 < v.data_len && v.data_ptr_idx + idx + 1 < pcm_pool.len() {
                    (i32::from(pcm_pool[v.data_ptr_idx + idx + 1]) - 128) << 8
                } else {
                    s0
                };
                let frac = ((v.pos_q16 & 0xFFFF) >> 1) as i32;
                let interp = s0 + (((s1 - s0) * frac) >> 15);
                acc_l += (interp * v.gain_l_q8) >> 8;
                acc_r += (interp * v.gain_r_q8) >> 8;
                v.pos_q16 += v.step_q16;
            }

            frame[0] = acc_l.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
            frame[1] = acc_r.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        }
    }

    #[must_use]
    pub const fn channel_sfx_id(&self, channel: usize) -> i32 {
        if channel < DOOM_SFX_CHANNELS {
            self.voices[channel].sfx_id
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opl2_mus_and_smf_render_non_silent_audio() {
        let mut player = DoomMusicPlayer::new(48_000);
        // Minimal MUS\x1a song: Play Note 60 vol 120 on ch 0 with 14-tick delay, then Score End.
        let mus_song: [u8; 13] = [
            b'M',
            b'U',
            b'S',
            0x1A,
            5,
            0,
            8,
            0, // score_len=5, score_start=8
            0x90,
            0x80 | 60,
            120,
            14,   // last=1, PlayNote ch=0, note=60+vol=120, delay=14 ticks
            0x60, // Score End
        ];
        assert!(player.register_song(&mus_song));
        player.start(true);
        let mut pcm = [[0i16; 2]; 512];
        player.render_into(&mus_song, &mut pcm);
        assert!(pcm.iter().any(|f| f[0].abs() > 100 && f[1].abs() > 100));

        // Minimal Standard MIDI (MThd Format 0, division=96): Note On 64 vel 110, delta 48, End of Track.
        let smf_song: [u8; 31] = [
            b'M', b'T', b'h', b'd', 0, 0, 0, 6, 0, 0, 0, 1, 0, 96, // Format 0, 1 trk, div=96
            b'M', b'T', b'r', b'k', 0, 0, 0, 9, // Track len = 9
            0x00, 0x90, 64, 110, // delta=0, Note On ch0 note=64 vel=110
            0x30, 0xFF, 0x2F, 0x00, 0x00, // delta=48, End of Track
        ];
        assert!(player.register_song(&smf_song));
        player.start(true);
        let mut pcm2 = [[0i16; 2]; 512];
        player.render_into(&smf_song, &mut pcm2);
        assert!(pcm2.iter().any(|f| f[0].abs() > 100));
    }

    #[test]
    fn dmx_sfx_parser_and_mixer_work() {
        let mut lump = [128u8; 8 + 32 + 64];
        lump[0..2].copy_from_slice(&3u16.to_le_bytes());
        lump[2..4].copy_from_slice(&11_025u16.to_le_bytes());
        lump[4..8].copy_from_slice(&96u32.to_le_bytes());
        for b in &mut lump[24..56] {
            *b = 240;
        }
        let Some(parsed) = parse_dmx_sfx(&lump) else {
            assert_eq!(lump[0], 0);
            return;
        };
        assert_eq!(parsed.sample_rate, 11_025);
        assert_eq!(parsed.pcm_u8.len(), 64);

        let mut sfx = DoomSfxMixer::new(48_000);
        sfx.start_channel(0, 1, 0, parsed.pcm_u8.len(), parsed.sample_rate, 120, 128);
        let mut out = [[0i16; 2]; 64];
        sfx.mix_into(parsed.pcm_u8, &mut out);
        assert!(out.iter().any(|f| f[0] > 1000 && f[1] > 1000));
    }
}
