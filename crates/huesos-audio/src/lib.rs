//! Pure-Rust `#![no_std]`, `#![forbid(unsafe_code)]` HuesOS Audio Engine crate:
//! - `ring`: Lock-free SPSC `HARB` v1 VMO ring buffer with clock-drift compensation
//! - `virtio_snd`: OASIS VirtIO 1.2 Sound (`1af4:1059`) control & TX wire codecs
//! - `mixer`: Fractional stereo resampler, saturating mixer, RIFF `WAVE` parser & tone synth
//! - `sbc`: Bluetooth A2DP v1.3 Appendix B Subband Codec (`SBC`) encoder, decoder & RTP packer
//! - `avdtp_avrcp`: AVDTP 1.3 (`PSM 0x0019`) Source & AVCTP/AVRCP (`PSM 0x0017`) state machines
//! - `opl2`: Integer Yamaha YM3812 (OPL2) FM synthesizer, `GENMIDI`, `MUS`/`MThd` & DMX SFX

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod avdtp_avrcp;
pub mod mixer;
pub mod opl2;
pub mod ring;
pub mod sbc;
pub mod virtio_snd;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use crate::mixer::{finalize_mix_buffer, generate_stereo_tone, parse_wav_pcm, LinearResampler};
    use crate::ring::{
        init_ring, ring_pop_clock_synced, ring_pop_stereo_i16, ring_push_stereo_i16,
        DEFAULT_RING_FRAMES, DEFAULT_RING_VMO_BYTES,
    };
    use crate::virtio_snd::{
        decode_status_code, encode_pcm_set_params, encode_pcm_simple_cmd, encode_query_pcm_info,
        VirtioSndPcmInfo, VIRTIO_SND_D_OUTPUT, VIRTIO_SND_PCM_FMT_S16, VIRTIO_SND_PCM_RATE_48000,
        VIRTIO_SND_R_PCM_START, VIRTIO_SND_S_OK,
    };

    #[test]
    fn harb_ring_wraparound_and_clock_drift_recovery() {
        let mut backing = vec![0u8; DEFAULT_RING_VMO_BYTES as usize];
        assert!(init_ring(&mut backing, 48_000, 128));

        let tone = generate_stereo_tone(48_000, 440, 2, 16_000);
        assert_eq!(tone.len(), 96 * 2);
        assert_eq!(ring_push_stereo_i16(&mut backing, &tone), 96);

        let mut popped = vec![0i16; 64 * 2];
        assert_eq!(ring_pop_stereo_i16(&mut backing, &mut popped), 64);
        assert_eq!(&popped[..], &tone[..64 * 2]);

        // Push across 128-frame wraparound boundary (`96 + 80 = 176 > 128`).
        assert_eq!(ring_push_stereo_i16(&mut backing, &tone[..80 * 2]), 80);
        // Available is now `32 + 80 = 112` (> 75% of 128 = 96), so clock_synced trims lag cleanly.
        let mut synced = vec![0i16; 32 * 2];
        assert_eq!(ring_pop_clock_synced(&mut backing, &mut synced), 32);
        let _ = DEFAULT_RING_FRAMES;
    }

    #[test]
    fn resampler_and_wav_parser_work() {
        let mut resamp = LinearResampler::new(24_000, 48_000);
        let src = [10_000i16, -10_000, 20_000, -20_000, 10_000, -10_000, 0, 0];
        let mut accum = [0i32; 16];
        let (in_c, out_c) = resamp.resample_and_accumulate(&src, 256, &mut accum);
        assert!(in_c > 0 && out_c >= 6);

        let mut out_s16 = [0i16; 16];
        finalize_mix_buffer(&accum, 80, false, &mut out_s16);
        assert!(out_s16.iter().any(|&v| v != 0));

        // Build minimal valid 44-byte + 8-byte PCM S16LE stereo WAV
        let mut wav = vec![0u8; 52];
        wav[0..4].copy_from_slice(b"RIFF");
        wav[4..8].copy_from_slice(&44u32.to_le_bytes());
        wav[8..12].copy_from_slice(b"WAVE");
        wav[12..16].copy_from_slice(b"fmt ");
        wav[16..20].copy_from_slice(&16u32.to_le_bytes());
        wav[20..22].copy_from_slice(&1u16.to_le_bytes()); // PCM
        wav[22..24].copy_from_slice(&2u16.to_le_bytes()); // 2 ch
        wav[24..28].copy_from_slice(&48_000u32.to_le_bytes());
        wav[28..32].copy_from_slice(&192_000u32.to_le_bytes());
        wav[32..34].copy_from_slice(&4u16.to_le_bytes());
        wav[34..36].copy_from_slice(&16u16.to_le_bytes());
        wav[36..40].copy_from_slice(b"data");
        wav[40..44].copy_from_slice(&8u32.to_le_bytes());
        wav[44..46].copy_from_slice(&4096i16.to_le_bytes());
        wav[46..48].copy_from_slice(&(-4096i16).to_le_bytes());

        let parsed = parse_wav_pcm(&wav);
        assert!(parsed.is_some());
        if let Some(d) = parsed {
            assert_eq!(d.sample_rate, 48_000);
            assert_eq!(d.stereo_samples.len(), 4);
            assert_eq!(d.stereo_samples[0], 4096);
            assert_eq!(d.stereo_samples[1], -4096);
        }
    }

    #[test]
    fn virtio_snd_wire_codecs_roundtrip() {
        let q = encode_query_pcm_info(0, 2);
        assert_eq!(q.len(), 16);
        let sp = encode_pcm_set_params(
            0,
            16_384,
            2_048,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        assert_eq!(sp[20], 2);
        let st = encode_pcm_simple_cmd(VIRTIO_SND_R_PCM_START, 0);
        assert_eq!(st.len(), 8);
        assert_eq!(decode_status_code(&VIRTIO_SND_S_OK.to_le_bytes()), Some(VIRTIO_SND_S_OK));

        let mut info_raw = [0u8; 32];
        info_raw[8..16].copy_from_slice(&(1u64 << VIRTIO_SND_PCM_FMT_S16).to_le_bytes());
        info_raw[16..24].copy_from_slice(&(1u64 << VIRTIO_SND_PCM_RATE_48000).to_le_bytes());
        info_raw[24] = VIRTIO_SND_D_OUTPUT;
        info_raw[25] = 1;
        info_raw[26] = 2;
        let info = VirtioSndPcmInfo::decode(&info_raw);
        assert!(info.is_some());
        if let Some(i) = info {
            assert!(i.supports_stereo_s16_output());
            assert_eq!(i.preferred_rate(), Some((VIRTIO_SND_PCM_RATE_48000, 48_000)));
        }
    }
}
