//! Capability-first Audio Subsystem (`HAUD` -> `/services/audio.elf`) and
//! lock-free `HARB` v1 SPSC VMO playback streams for HuesOS user-space programs.

use alloc::vec::Vec;
use spin::Mutex;

use huesos_abi::audio::{self, AudioOp, AudioRouteMode, AudioStatus, AudioStatusSnapshot};
use huesos_abi::auxv::caps_mask;
use huesos_audio::ring::{
    load_header, ring_push_stereo_i16, RingBacking, HARB_FLAG_EOS, HARB_FMT_S16LE,
};
use libcanvas::stdio::{take_cap_handle, CapKind};
use libcanvas::{Channel, Vmo};

use crate::error::{Error, ErrorKind, Result};
use crate::os::huesos::caps_mask as current_caps_mask;

static AUDIO_SERVICE_CH: Mutex<Option<Channel>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AudioCapLevel {
    ReadOnly,
    ReadWrite,
    Admin,
}

fn map_audio_status(st: AudioStatus) -> Error {
    let kind = match st {
        AudioStatus::Ok => ErrorKind::Other,
        AudioStatus::InvalidRequest => ErrorKind::InvalidInput,
        AudioStatus::AccessDenied => ErrorKind::AccessDenied,
        AudioStatus::NoFreeStreams => ErrorKind::Busy,
        AudioStatus::SinkUnavailable => ErrorKind::Unsupported,
        AudioStatus::A2dpFailed => ErrorKind::HostUnreachable,
    };
    Error::new(kind)
}

fn check_audio_cap(level: AudioCapLevel) -> Result<()> {
    let mask = current_caps_mask();
    if (mask & caps_mask::AUDIO_RO) == 0 {
        return Err(Error::capability());
    }
    match level {
        AudioCapLevel::ReadOnly => Ok(()),
        AudioCapLevel::ReadWrite => {
            if (mask & caps_mask::AUDIO_RW) == 0 {
                return Err(Error::capability());
            }
            Ok(())
        }
        AudioCapLevel::Admin => {
            if (mask & caps_mask::AUDIO_ADMIN) == 0 {
                return Err(Error::capability());
            }
            Ok(())
        }
    }
}

fn with_audio_channel<F, T>(level: AudioCapLevel, f: F) -> Result<T>
where
    F: FnOnce(&Channel) -> Result<T>,
{
    check_audio_cap(level)?;
    let mut guard = AUDIO_SERVICE_CH.lock();
    if guard.is_none() {
        if let Some(h) = take_cap_handle(CapKind::AudioService) {
            *guard = Some(Channel::from_handle(h));
        }
    }
    let Some(ch) = guard.as_ref() else {
        return Err(Error::capability());
    };
    f(ch)
}

/// Safe `RingBacking` wrapper around a `libcanvas::Vmo` (`#![forbid(unsafe_code)]`).
pub struct VmoRingBacking {
    vmo: Vmo,
}

impl RingBacking for VmoRingBacking {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> bool {
        self.vmo.read(offset, dst) == Ok(dst.len())
    }

    fn write_at(&mut self, offset: u64, src: &[u8]) -> bool {
        self.vmo.write(offset, src) == Ok(src.len())
    }
}

/// Active lock-free `HARB` v1 SPSC shared-memory audio stream.
pub struct AudioStream {
    stream_id: u32,
    sample_rate: u32,
    channels: u8,
    capacity_frames: u32,
    backing: VmoRingBacking,
    carry: [u8; 4],
    carry_len: usize,
}

impl AudioStream {
    /// Assigned `audio-service` stream slot ID.
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Producer sample rate in Hz.
    pub const fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Producer channel count (`1` = mono, `2` = stereo).
    pub const fn channels(&self) -> u8 {
        self.channels
    }

    /// Ring capacity in stereo frames (`16384`).
    pub const fn capacity_frames(&self) -> u32 {
        self.capacity_frames
    }

    /// Currently queued unread stereo frames in the SPSC VMO ring.
    pub fn queued_frames(&self) -> u32 {
        load_header(&self.backing)
            .map(|h| h.available_read())
            .unwrap_or(0)
    }

    /// Available free stereo frame slots in the SPSC VMO ring.
    pub fn free_frames(&self) -> u32 {
        load_header(&self.backing)
            .map(|h| h.available_write())
            .unwrap_or(0)
    }

    /// Non-blocking push of interleaved stereo `i16` samples (`2 * frames`),
    /// returning the number of stereo frames queued into the VMO ring.
    pub fn try_write_stereo_i16(&mut self, samples: &[i16]) -> usize {
        ring_push_stereo_i16(&mut self.backing, samples)
    }

    /// Blocking/paced push of all interleaved stereo `i16` samples (`2 * frames`).
    pub fn write_all_stereo_i16(&mut self, samples: &[i16]) -> Result<()> {
        let total_frames = samples.len() / 2;
        let mut done_frames = 0usize;
        let mut spins = 0u32;
        while done_frames < total_frames {
            let pushed = self.try_write_stereo_i16(&samples[done_frames * 2..total_frames * 2]);
            if pushed > 0 {
                done_frames += pushed;
                spins = 0;
            } else {
                spins = spins.saturating_add(1);
                if spins > 400 {
                    return Err(Error::new(ErrorKind::TimedOut));
                }
                libcanvas::system::sleep_ms(5);
            }
        }
        Ok(())
    }

    /// Stream raw `S16LE` PCM bytes (`mono` or `stereo` according to `channels`)
    /// into the lock-free `HARB` ring, preserving sub-frame byte alignment across calls.
    pub fn write_pcm_bytes(&mut self, mut data: &[u8]) -> Result<usize> {
        let orig_len = data.len();
        let frame_bytes = if self.channels == 1 { 2usize } else { 4usize };
        let mut stereo_chunk = [0i16; 1024]; // 512 stereo frames per batch

        if self.carry_len > 0 && !data.is_empty() {
            let need = frame_bytes.saturating_sub(self.carry_len).min(data.len());
            self.carry[self.carry_len..self.carry_len + need].copy_from_slice(&data[..need]);
            self.carry_len += need;
            data = &data[need..];
            if self.carry_len == frame_bytes {
                let (l, r) = if frame_bytes == 2 {
                    let s = i16::from_le_bytes([self.carry[0], self.carry[1]]);
                    (s, s)
                } else {
                    (
                        i16::from_le_bytes([self.carry[0], self.carry[1]]),
                        i16::from_le_bytes([self.carry[2], self.carry[3]]),
                    )
                };
                self.carry_len = 0;
                self.write_all_stereo_i16(&[l, r])?;
            }
        }

        let whole_frames = data.len() / frame_bytes;
        let mut idx = 0usize;
        while idx < whole_frames {
            let batch = (whole_frames - idx).min(512);
            for f in 0..batch {
                let off = (idx + f) * frame_bytes;
                let (l, r) = if frame_bytes == 2 {
                    let s = i16::from_le_bytes([data[off], data[off + 1]]);
                    (s, s)
                } else {
                    (
                        i16::from_le_bytes([data[off], data[off + 1]]),
                        i16::from_le_bytes([data[off + 2], data[off + 3]]),
                    )
                };
                stereo_chunk[f * 2] = l;
                stereo_chunk[f * 2 + 1] = r;
            }
            self.write_all_stereo_i16(&stereo_chunk[..batch * 2])?;
            idx += batch;
        }

        let rem_off = whole_frames * frame_bytes;
        let rem = &data[rem_off..];
        if !rem.is_empty() {
            self.carry[..rem.len()].copy_from_slice(rem);
            self.carry_len = rem.len();
        }
        Ok(orig_len)
    }

    /// Mark end-of-stream (`HARB_FLAG_EOS`) and wait up to `timeout_ms` for drain.
    pub fn drain(&self, timeout_ms: u32) {
        if let Some(hdr) = load_header(&self.backing) {
            let flags = hdr.flags | HARB_FLAG_EOS;
            let _ = self.backing.vmo.write(42, &flags.to_le_bytes());
        }
        let mut waited = 0u32;
        while waited < timeout_ms {
            if self.queued_frames() == 0 {
                break;
            }
            libcanvas::system::sleep_ms(5);
            waited = waited.saturating_add(5);
        }
    }
}

impl Drop for AudioStream {
    fn drop(&mut self) {
        if let Some(hdr) = load_header(&self.backing) {
            let flags = hdr.flags | HARB_FLAG_EOS;
            let _ = self.backing.write_at(42, &flags.to_le_bytes());
        }
        let stream_id = self.stream_id;
        let _ = with_audio_channel(AudioCapLevel::ReadWrite, |ch| {
            let mut req = [0u8; 12];
            audio::write_header(&mut req, AudioOp::CloseStream, AudioStatus::Ok);
            req[8..12].copy_from_slice(&stream_id.to_le_bytes());
            let _ = ch.write(&req);
            let mut rep = [0u8; 16];
            let _ = ch.read_into_timeout(&mut rep, 100);
            Ok(())
        });
    }
}

/// Query `/services/audio.elf` mixer, `VirtIO-Sound`, and Bluetooth A2DP status (`audio=ro`).
pub fn status() -> Result<AudioStatusSnapshot> {
    with_audio_channel(AudioCapLevel::ReadOnly, |ch| {
        let mut req = [0u8; 8];
        audio::write_header(&mut req, AudioOp::Status, AudioStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 128];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        AudioStatusSnapshot::decode_reply(&rep[..n]).map_err(map_audio_status)
    })
}

/// Open a new lock-free `HARB` SPSC VMO playback stream (`audio=rw`).
pub fn open_stream(sample_rate: u32, channels: u8) -> Result<AudioStream> {
    if !(8_000..=96_000).contains(&sample_rate) || !(1..=2).contains(&channels) {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    with_audio_channel(AudioCapLevel::ReadWrite, |ch| {
        let mut req = [0u8; 16];
        audio::write_header(&mut req, AudioOp::OpenStream, AudioStatus::Ok);
        req[8..12].copy_from_slice(&sample_rate.to_le_bytes());
        req[12] = channels;
        req[13] = HARB_FMT_S16LE;
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let (n, handle_opt) = ch
            .read_optional_handle_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        let st = audio::check_header(&rep[..n], AudioOp::OpenStream).map_err(map_audio_status)?;
        if st != AudioStatus::Ok {
            return Err(map_audio_status(st));
        }
        if n < 16 {
            return Err(Error::new(ErrorKind::InvalidInput));
        }
        let Some(vmo_handle) = handle_opt else {
            return Err(Error::new(ErrorKind::BadHandle));
        };
        let stream_id = u32::from_le_bytes([rep[8], rep[9], rep[10], rep[11]]);
        let capacity_frames = u32::from_le_bytes([rep[12], rep[13], rep[14], rep[15]]);
        Ok(AudioStream {
            stream_id,
            sample_rate,
            channels,
            capacity_frames,
            backing: VmoRingBacking {
                vmo: Vmo::from_handle(vmo_handle),
            },
            carry: [0; 4],
            carry_len: 0,
        })
    })
}

/// Set master volume (`0..=100`) and mute flag (`audio=admin`).
pub fn set_volume(volume_pct: u8, muted: bool) -> Result<()> {
    with_audio_channel(AudioCapLevel::Admin, |ch| {
        let mut req = [0u8; 10];
        audio::write_header(&mut req, AudioOp::SetVolume, AudioStatus::Ok);
        req[8] = volume_pct.min(100);
        req[9] = u8::from(muted);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        let st = audio::check_header(&rep[..n], AudioOp::SetVolume).map_err(map_audio_status)?;
        if st == AudioStatus::Ok {
            Ok(())
        } else {
            Err(map_audio_status(st))
        }
    })
}

/// Set sink routing policy (`auto`, `virtio`, `btl`, `mirror`) (`audio=admin`).
pub fn set_route_mode(mode: AudioRouteMode) -> Result<()> {
    with_audio_channel(AudioCapLevel::Admin, |ch| {
        let mut req = [0u8; 9];
        audio::write_header(&mut req, AudioOp::SetRouteMode, AudioStatus::Ok);
        req[8] = mode as u8;
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        let st = audio::check_header(&rep[..n], AudioOp::SetRouteMode).map_err(map_audio_status)?;
        if st == AudioStatus::Ok {
            Ok(())
        } else {
            Err(map_audio_status(st))
        }
    })
}

/// Connect `audio-service` A2DP (`PSM 0x0019`) + AVRCP (`PSM 0x0017`) to a `/net/btl`
/// headset (`None` auto-selects the first discovered A2DP Audio Sink) (`audio=admin`).
pub fn connect_btl_sink(bd_addr: Option<[u8; 6]>) -> Result<()> {
    with_audio_channel(AudioCapLevel::Admin, |ch| {
        let mut req = [0u8; 14];
        audio::write_header(&mut req, AudioOp::ConnectBtlSink, AudioStatus::Ok);
        req[8..14].copy_from_slice(&bd_addr.unwrap_or([0; 6]));
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 32];
        let n = ch
            .read_into_timeout(&mut rep, 3000)
            .map_err(Error::from_code)?;
        let st =
            audio::check_header(&rep[..n], AudioOp::ConnectBtlSink).map_err(map_audio_status)?;
        if st == AudioStatus::Ok {
            Ok(())
        } else {
            Err(map_audio_status(st))
        }
    })
}

/// Disconnect active Bluetooth A2DP + AVRCP sink (`audio=admin`).
pub fn disconnect_btl_sink() -> Result<()> {
    with_audio_channel(AudioCapLevel::Admin, |ch| {
        let mut req = [0u8; 8];
        audio::write_header(&mut req, AudioOp::DisconnectBtlSink, AudioStatus::Ok);
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 500)
            .map_err(Error::from_code)?;
        let st =
            audio::check_header(&rep[..n], AudioOp::DisconnectBtlSink).map_err(map_audio_status)?;
        if st == AudioStatus::Ok {
            Ok(())
        } else {
            Err(map_audio_status(st))
        }
    })
}

/// Trigger a built-in stereo test tone (`freq_hz`, `duration_ms`) (`audio=rw`).
pub fn play_test_tone(freq_hz: u16, duration_ms: u16) -> Result<()> {
    with_audio_channel(AudioCapLevel::ReadWrite, |ch| {
        let mut req = [0u8; 12];
        audio::write_header(&mut req, AudioOp::PlayTestTone, AudioStatus::Ok);
        req[8..10].copy_from_slice(&freq_hz.to_le_bytes());
        req[10..12].copy_from_slice(&duration_ms.to_le_bytes());
        ch.write(&req).map_err(Error::from_code)?;
        let mut rep = [0u8; 16];
        let n = ch
            .read_into_timeout(&mut rep, 1000)
            .map_err(Error::from_code)?;
        let st = audio::check_header(&rep[..n], AudioOp::PlayTestTone).map_err(map_audio_status)?;
        if st == AudioStatus::Ok {
            Ok(())
        } else {
            Err(map_audio_status(st))
        }
    })
}

/// Parsed RIFF/WAVE PCM header (`8/16-bit`, `1..=2` channels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WavHeader {
    /// Sample rate in Hz (`8000..=96000`).
    pub sample_rate: u32,
    /// Channels (`1` or `2`).
    pub channels: u8,
    /// Bits per sample (`8` unsigned or `16` signed LE).
    pub bits_per_sample: u16,
    /// Byte offset of PCM payload inside the WAV file.
    pub data_offset: usize,
    /// Byte length of PCM payload.
    pub data_len: usize,
}

/// Parse a standard uncompressed `WAVE_FORMAT_PCM` (`0x0001`) RIFF container.
pub fn parse_wav(bytes: &[u8]) -> Option<WavHeader> {
    if bytes.len() < 44 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return None;
    }
    let mut pos = 12usize;
    let mut fmt_found = false;
    let mut channels = 0u8;
    let mut sample_rate = 0u32;
    let mut bits_per_sample = 0u16;

    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let chunk_len = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        let payload_off = pos + 8;
        if payload_off > bytes.len() {
            return None;
        }
        let avail = bytes.len() - payload_off;
        if id == b"fmt " {
            if chunk_len < 16 || avail < 16 {
                return None;
            }
            let audio_fmt = u16::from_le_bytes([bytes[payload_off], bytes[payload_off + 1]]);
            let ch = u16::from_le_bytes([bytes[payload_off + 2], bytes[payload_off + 3]]);
            sample_rate = u32::from_le_bytes([
                bytes[payload_off + 4],
                bytes[payload_off + 5],
                bytes[payload_off + 6],
                bytes[payload_off + 7],
            ]);
            bits_per_sample =
                u16::from_le_bytes([bytes[payload_off + 14], bytes[payload_off + 15]]);
            if audio_fmt != 1
                || !(1..=2).contains(&ch)
                || (bits_per_sample != 8 && bits_per_sample != 16)
            {
                return None;
            }
            channels = ch as u8;
            fmt_found = true;
        } else if id == b"data" && fmt_found {
            let data_len = chunk_len.min(avail);
            return Some(WavHeader {
                sample_rate,
                channels,
                bits_per_sample,
                data_offset: payload_off,
                data_len,
            });
        }
        let padded = chunk_len.saturating_add(chunk_len & 1);
        pos = payload_off.checked_add(padded)?;
    }
    None
}

/// Convert 8-bit unsigned PCM bytes to 16-bit signed LE bytes for `AudioStream::write_pcm_bytes`.
pub fn pcm_u8_to_s16le_bytes(src_u8: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src_u8.len() * 2);
    for &b in src_u8 {
        let sample = (i16::from(b) - 128) * 256;
        out.extend_from_slice(&sample.to_le_bytes());
    }
    out
}
