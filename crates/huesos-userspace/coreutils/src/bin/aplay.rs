//! `/bin/aplay.elf` — Zero-copy `HARB` SPSC VMO RIFF/WAVE & Raw PCM Audio Player.
//!
//! Supports uncompressed RIFF/WAVE (`8/16-bit`, `1..=2` channels, `8..96 kHz`),
//! raw `S16LE` streams, and `--synth` / `--gen-wav` test signal synthesis.

#![no_std]
#![no_main]
#![allow(
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::collapsible_if
)]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;

use huesos_coreutils as cu;
use huesos_std::audio;
use huesos_std::fs;

cu::coreutil_entry!(run);

fn print_usage() {
    cu::outln(
        "usage: aplay <file.wav> | aplay --raw [-r <rate>] [-c <1|2>] <file.pcm|-> | aplay --synth [hz] [ms] | aplay --gen-wav <out.wav> [hz] [ms]",
    );
}

/// Deterministic integer sine approximation (`phase` in `0..65536` -> `-32767..32767`).
fn fast_sin_q15(phase: u16) -> i16 {
    let quad = phase >> 14;
    let x = i32::from(phase & 0x3FFF); // 0..16383
    let u = if (quad & 1) != 0 { 16384 - x } else { x }; // 0..16384
                                                         // Bhaskara/parabolic fit: sin(pi/2 * u/16384) ~= u * (32768 - u) / 8192
    let y = ((u * (32768 - u)) >> 13).min(32767);
    if (quad & 2) != 0 {
        -(y as i16)
    } else {
        y as i16
    }
}

fn synth_stereo_chord(sample_rate: u32, freq_hz: u16, duration_ms: u16) -> Vec<i16> {
    let total_frames = ((u64::from(sample_rate) * u64::from(duration_ms)) / 1000).max(64) as usize;
    let mut out = Vec::with_capacity(total_frames * 2);
    let step_root = ((u64::from(freq_hz.max(40)) << 16) / u64::from(sample_rate)) as u16;
    let step_fifth = ((u64::from(freq_hz.max(40)) * 3) << 15) / u64::from(sample_rate);
    let step_fifth = step_fifth as u16;
    let mut ph1 = 0u16;
    let mut ph2 = 0u16;
    let ramp = (total_frames / 8).clamp(1, 1024);

    for i in 0..total_frames {
        let env = if i < ramp {
            (i * 256 / ramp) as i32
        } else if i + ramp > total_frames {
            ((total_frames - i) * 256 / ramp) as i32
        } else {
            256
        };
        let s1 = i32::from(fast_sin_q15(ph1));
        let s2 = i32::from(fast_sin_q15(ph2));
        let left = (((s1 * 3 + s2) / 8) * env / 256) as i16;
        let right = (((s1 + s2 * 3) / 8) * env / 256) as i16;
        out.push(left);
        out.push(right);
        ph1 = ph1.wrapping_add(step_root);
        ph2 = ph2.wrapping_add(step_fifth);
    }
    out
}

fn encode_wav_s16le_stereo(sample_rate: u32, samples: &[i16]) -> Vec<u8> {
    let data_bytes = (samples.len() * 2) as u32;
    let riff_size = 36u32.saturating_add(data_bytes);
    let byte_rate = sample_rate.saturating_mul(4);
    let mut wav = Vec::with_capacity(44 + samples.len() * 2);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&riff_size.to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&2u16.to_le_bytes()); // stereo
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&4u16.to_le_bytes()); // block align
    wav.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_bytes.to_le_bytes());
    for &s in samples {
        wav.extend_from_slice(&s.to_le_bytes());
    }
    wav
}

fn run() -> i32 {
    let args = cu::collect_args();
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h" | "help") {
        print_usage();
        return if args.is_empty() { 1 } else { 0 };
    }

    if args[0] == "--gen-wav" {
        let Some(out_path) = args.get(1) else {
            print_usage();
            return 1;
        };
        let freq = args
            .get(2)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(440);
        let ms = args
            .get(3)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(120);
        let samples = synth_stereo_chord(48_000, freq, ms);
        let wav = encode_wav_s16le_stereo(48_000, &samples);
        if out_path == "-" {
            if let Err(e) = huesos_std::io::write_all(&mut huesos_std::io::stdout(), &wav) {
                cu::errln(&format!("aplay: stdout write failed: {e}"));
                return 1;
            }
            return 0;
        }
        match fs::write(out_path, &wav) {
            Ok(()) => {
                cu::outln(&format!(
                    "aplay: wrote {} bytes ({} frames, 48000Hz S16LE stereo) to {}",
                    wav.len(),
                    samples.len() / 2,
                    out_path
                ));
                return 0;
            }
            Err(e) => {
                cu::errln(&format!("aplay: write '{out_path}' failed: {e}"));
                return 1;
            }
        }
    }

    if args[0] == "--synth" {
        let freq = args
            .get(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(440);
        let ms = args
            .get(2)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(150);
        let samples = synth_stereo_chord(48_000, freq, ms);
        let mut stream = match audio::open_stream(48_000, 2) {
            Ok(s) => s,
            Err(e) => {
                cu::errln(&format!("aplay: open_stream failed: {e}"));
                return 1;
            }
        };
        if let Err(e) = stream.write_all_stereo_i16(&samples) {
            cu::errln(&format!("aplay: stream write failed: {e}"));
            return 1;
        }
        stream.drain(400);
        cu::outln(&format!(
            "aplay: streamed {} stereo frames ({freq}Hz/{ms}ms) on HARB stream #{}",
            samples.len() / 2,
            stream.stream_id()
        ));
        return 0;
    }

    if args[0] == "--raw" {
        let mut rate = 48_000u32;
        let mut channels = 2u8;
        let mut idx = 1usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "-r" => {
                    let Some(v) = args.get(idx + 1).and_then(|s| s.parse::<u32>().ok()) else {
                        print_usage();
                        return 1;
                    };
                    rate = v;
                    idx += 2;
                }
                "-c" => {
                    let Some(v) = args.get(idx + 1).and_then(|s| s.parse::<u8>().ok()) else {
                        print_usage();
                        return 1;
                    };
                    channels = v;
                    idx += 2;
                }
                _ => break,
            }
        }
        let Some(src) = args.get(idx) else {
            print_usage();
            return 1;
        };
        let raw = if src == "-" {
            cu::read_all_stdin()
        } else {
            match fs::read(src) {
                Ok(b) => b,
                Err(e) => {
                    cu::errln(&format!("aplay: read '{src}' failed: {e}"));
                    return 1;
                }
            }
        };
        let mut stream = match audio::open_stream(rate, channels) {
            Ok(s) => s,
            Err(e) => {
                cu::errln(&format!("aplay: open_stream failed: {e}"));
                return 1;
            }
        };
        if let Err(e) = stream.write_pcm_bytes(&raw) {
            cu::errln(&format!("aplay: raw stream write failed: {e}"));
            return 1;
        }
        stream.drain(500);
        cu::outln(&format!(
            "aplay: played {} raw bytes ({rate}Hz, {channels}ch) on HARB stream #{}",
            raw.len(),
            stream.stream_id()
        ));
        return 0;
    }

    let path = &args[0];
    let data = if path == "-" {
        cu::read_all_stdin()
    } else {
        match fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                cu::errln(&format!("aplay: cannot open '{path}': {e}"));
                return 1;
            }
        }
    };

    let Some(hdr) = audio::parse_wav(&data) else {
        cu::errln(&format!(
            "aplay: '{path}' is not a supported uncompressed RIFF/WAVE PCM file"
        ));
        return 1;
    };

    let mut stream = match audio::open_stream(hdr.sample_rate, hdr.channels) {
        Ok(s) => s,
        Err(e) => {
            cu::errln(&format!("aplay: open_stream failed: {e}"));
            return 1;
        }
    };

    let payload = &data[hdr.data_offset..hdr.data_offset + hdr.data_len];
    let res = if hdr.bits_per_sample == 8 {
        let pcm16 = audio::pcm_u8_to_s16le_bytes(payload);
        stream.write_pcm_bytes(&pcm16)
    } else {
        stream.write_pcm_bytes(payload)
    };
    if let Err(e) = res {
        cu::errln(&format!("aplay: playback failed: {e}"));
        return 1;
    }
    stream.drain(600);

    let frame_bytes = usize::from(hdr.channels) * usize::from(hdr.bits_per_sample / 8);
    let frames = hdr.data_len.checked_div(frame_bytes).unwrap_or(0);
    cu::outln(&format!(
        "aplay: played '{}' ({}Hz, {}ch, {}-bit, {} frames) on HARB stream #{}",
        path,
        hdr.sample_rate,
        hdr.channels,
        hdr.bits_per_sample,
        frames,
        stream.stream_id()
    ));
    0
}
