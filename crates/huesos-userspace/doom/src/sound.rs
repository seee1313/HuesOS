//! Zero-unsafe Doom SFX (`DMX 0x0003`) + OPL2 FM Music (`#OPL_II#` `GENMIDI` +
//! `MUS\x1a` / `MThd` MIDI) audio engine streaming into `audio-service` over a
//! lock-free `HARB` v1 SPSC shared-memory VMO.

#![allow(
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::manual_range_contains,
    clippy::collapsible_if
)]

use alloc::vec::Vec;
use spin::Mutex;

use huesos_abi::audio::{self, AudioOp, AudioStatus};
use huesos_audio::opl2::{parse_dmx_sfx, DoomMusicPlayer, DoomSfxMixer};
use huesos_audio::ring::{
    load_header, ring_push_stereo_i16, RingBacking, HARB_FLAG_EOS, HARB_FMT_S16LE,
};
use libcanvas::{Channel, Vmo};

const MIX_RATE_HZ: u32 = 48_000;
/// Target fill watermark in the `16384`-frame `HARB` VMO ring (`~85 ms` at `48 kHz`).
const TARGET_BUFFERED_FRAMES: usize = 4_096;
/// Render batch size (`256` stereo frames = `~5.3 ms`).
const BATCH_FRAMES: usize = 256;
const MAX_CACHED_SFX: usize = 128;

struct VmoBacking {
    vmo: Vmo,
}

impl RingBacking for VmoBacking {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> bool {
        self.vmo.read(offset, dst) == Ok(dst.len())
    }

    fn write_at(&mut self, offset: u64, src: &[u8]) -> bool {
        self.vmo.write(offset, src) == Ok(src.len())
    }
}

#[derive(Clone, Copy)]
struct CachedSfxEntry {
    lumpnum: i32,
    pool_offset: usize,
    pcm_len: usize,
    sample_rate: u16,
}

struct DoomSoundState {
    audio_ch: Option<Channel>,
    stream_id: u32,
    ring: Option<VmoBacking>,
    staging_blob: Vec<u8>,
    sfx_pool: Vec<u8>,
    sfx_entries: Vec<CachedSfxEntry>,
    sfx_mixer: DoomSfxMixer,
    music_song: Vec<u8>,
    music_player: Option<DoomMusicPlayer>,
}

impl DoomSoundState {
    const fn new() -> Self {
        Self {
            audio_ch: None,
            stream_id: 0,
            ring: None,
            staging_blob: Vec::new(),
            sfx_pool: Vec::new(),
            sfx_entries: Vec::new(),
            sfx_mixer: DoomSfxMixer::new(MIX_RATE_HZ),
            music_song: Vec::new(),
            music_player: None,
        }
    }

    fn ensure_player(&mut self) -> &mut DoomMusicPlayer {
        if self.music_player.is_none() {
            self.music_player = Some(DoomMusicPlayer::new(MIX_RATE_HZ));
        }
        // Guaranteed `Some` by initialization above.
        match self.music_player.as_mut() {
            Some(p) => p,
            None => loop {
                libcanvas::process::exit(-98);
            },
        }
    }

    fn attach_channel(&mut self, ch: Channel) {
        let mut req = [0u8; 16];
        audio::write_header(&mut req, AudioOp::OpenStream, AudioStatus::Ok);
        req[8..12].copy_from_slice(&MIX_RATE_HZ.to_le_bytes());
        req[12] = 2;
        req[13] = HARB_FMT_S16LE;
        if ch.write(&req).is_err() {
            return;
        }
        let mut rep = [0u8; 32];
        let Ok((n, Some(vmo_h))) = ch.read_optional_handle_timeout(&mut rep, 300) else {
            return;
        };
        if audio::check_header(&rep[..n], AudioOp::OpenStream) != Ok(AudioStatus::Ok) || n < 16 {
            return;
        }
        let stream_id = u32::from_le_bytes([rep[8], rep[9], rep[10], rep[11]]);
        self.stream_id = stream_id;
        self.ring = Some(VmoBacking {
            vmo: Vmo::from_handle(vmo_h),
        });
        self.audio_ch = Some(ch);
        let _ = self.ensure_player();
        libcanvas::println!(
            "[doom] HARB SPSC VMO audio stream #{} opened at {} Hz (DMX SFX + OPL2 GENMIDI)",
            stream_id,
            MIX_RATE_HZ
        );
    }

    fn pump(&mut self) {
        let Some(ring) = self.ring.as_mut() else {
            return;
        };
        let Some(hdr) = load_header(ring) else {
            return;
        };
        let queued = hdr.available_read() as usize;
        if queued >= TARGET_BUFFERED_FRAMES {
            return;
        }
        let free = hdr.available_write() as usize;
        let need = TARGET_BUFFERED_FRAMES.saturating_sub(queued).min(free);
        let mut produced = 0usize;
        let mut stereo_pairs = [[0i16; 2]; BATCH_FRAMES];
        let mut flat = [0i16; BATCH_FRAMES * 2];

        while produced < need {
            let chunk = (need - produced).min(BATCH_FRAMES);
            for slot in &mut stereo_pairs[..chunk] {
                *slot = [0, 0];
            }
            if let Some(player) = self.music_player.as_mut() {
                if player.is_playing() && !self.music_song.is_empty() {
                    player.render_into(&self.music_song, &mut stereo_pairs[..chunk]);
                }
            }
            self.sfx_mixer
                .mix_into(&self.sfx_pool, &mut stereo_pairs[..chunk]);

            for (idx, &[l, r]) in stereo_pairs[..chunk].iter().enumerate() {
                flat[idx * 2] = l;
                flat[idx * 2 + 1] = r;
            }
            let Some(ring_mut) = self.ring.as_mut() else {
                break;
            };
            let pushed = ring_push_stereo_i16(ring_mut, &flat[..chunk * 2]);
            if pushed == 0 {
                break;
            }
            produced += pushed;
        }
    }

    fn shutdown(&mut self) {
        if let Some(ring) = self.ring.as_ref() {
            if let Some(hdr) = load_header(ring) {
                let flags = hdr.flags | HARB_FLAG_EOS;
                let _ = ring.vmo.write(42, &flags.to_le_bytes());
            }
        }
        if let Some(ch) = self.audio_ch.as_ref() {
            if self.stream_id != 0 {
                let mut req = [0u8; 12];
                audio::write_header(&mut req, AudioOp::CloseStream, AudioStatus::Ok);
                req[8..12].copy_from_slice(&self.stream_id.to_le_bytes());
                let _ = ch.write(&req);
            }
        }
        self.ring = None;
        self.audio_ch = None;
    }
}

static SOUND: Mutex<DoomSoundState> = Mutex::new(DoomSoundState::new());

/// Attach the `audio-service` capability received from `init` during `DG_Init`.
pub fn attach_audio_channel(ch: Channel) {
    SOUND.lock().attach_channel(ch);
}

/// Refill the `HARB` SPSC VMO ring buffer.
pub fn pump() {
    SOUND.lock().pump();
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_is_online() -> i32 {
    i32::from(SOUND.lock().ring.is_some())
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_blob_begin() {
    SOUND.lock().staging_blob.clear();
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_blob_push_u64(chunk_le: u64, valid_bytes: u32) {
    let mut guard = SOUND.lock();
    if guard.staging_blob.len() >= 256 * 1024 {
        return;
    }
    let bytes = chunk_le.to_le_bytes();
    let n = (valid_bytes as usize).min(8);
    guard.staging_blob.extend_from_slice(&bytes[..n]);
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_load_genmidi() -> i32 {
    let mut guard = SOUND.lock();
    let blob = core::mem::take(&mut guard.staging_blob);
    let ok = guard.ensure_player().load_genmidi(&blob);
    i32::from(ok)
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_cache_sfx(lumpnum: i32) -> i32 {
    let mut guard = SOUND.lock();
    if guard.sfx_entries.iter().any(|e| e.lumpnum == lumpnum) {
        guard.staging_blob.clear();
        return 1;
    }
    if guard.staging_blob.is_empty() || guard.sfx_entries.len() >= MAX_CACHED_SFX {
        return 0;
    }
    let blob = core::mem::take(&mut guard.staging_blob);
    let Some(dmx) = parse_dmx_sfx(&blob) else {
        return 0;
    };
    if guard.sfx_pool.len().saturating_add(dmx.pcm_u8.len()) > 4 * 1024 * 1024 {
        return 0;
    }
    let pool_offset = guard.sfx_pool.len();
    let pcm_len = dmx.pcm_u8.len();
    let sample_rate = dmx.sample_rate;
    guard.sfx_pool.extend_from_slice(dmx.pcm_u8);
    guard.sfx_entries.push(CachedSfxEntry {
        lumpnum,
        pool_offset,
        pcm_len,
        sample_rate,
    });
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_start_sfx(lumpnum: i32, channel: i32, vol: i32, sep: i32) -> i32 {
    if channel < 0 {
        return -1;
    }
    let mut guard = SOUND.lock();
    let Some(entry) = guard
        .sfx_entries
        .iter()
        .copied()
        .find(|e| e.lumpnum == lumpnum)
    else {
        return -1;
    };
    guard.sfx_mixer.start_channel(
        channel as usize,
        lumpnum,
        entry.pool_offset,
        entry.pcm_len,
        entry.sample_rate,
        vol,
        sep,
    );
    guard.pump();
    channel
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_update_sfx(channel: i32, vol: i32, sep: i32) {
    if channel >= 0 {
        SOUND
            .lock()
            .sfx_mixer
            .update_channel(channel as usize, vol, sep);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_stop_sfx(channel: i32) {
    if channel >= 0 {
        SOUND.lock().sfx_mixer.stop_channel(channel as usize);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_sfx_playing(channel: i32) -> i32 {
    if channel < 0 {
        return 0;
    }
    i32::from(SOUND.lock().sfx_mixer.channel_is_playing(channel as usize))
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_register_song() -> i32 {
    let mut guard = SOUND.lock();
    let song = core::mem::take(&mut guard.staging_blob);
    let ok = guard.ensure_player().register_song(&song);
    if ok {
        guard.music_song = song;
    }
    i32::from(ok)
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_play_song(looping: i32) {
    let mut guard = SOUND.lock();
    guard.ensure_player().start(looping != 0);
    guard.pump();
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_stop_song() {
    let mut guard = SOUND.lock();
    if let Some(p) = guard.music_player.as_mut() {
        p.stop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_pause_song(paused: i32) {
    let mut guard = SOUND.lock();
    if let Some(p) = guard.music_player.as_mut() {
        if paused != 0 {
            p.pause();
        } else {
            p.resume();
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_set_music_volume(vol: i32) {
    let mut guard = SOUND.lock();
    let clamped = vol.clamp(0, 127) as u8;
    guard.ensure_player().synth.set_master_volume(clamped);
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_music_playing() -> i32 {
    let guard = SOUND.lock();
    i32::from(guard.music_player.as_ref().is_some_and(|p| p.is_playing()))
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_pump() {
    SOUND.lock().pump();
}

#[unsafe(no_mangle)]
pub extern "C" fn hues_audio_shutdown() {
    SOUND.lock().shutdown();
}
