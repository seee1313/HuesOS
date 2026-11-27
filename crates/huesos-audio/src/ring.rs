//! Lock-free Single-Producer / Single-Consumer (`SPSC`) VMO Audio Ring Buffer
//! (`HARB` v1) with bounded clock-drift compensation across independent
//! hardware clock domains (`VirtIO-Sound` PCIe DMA vs `Bluetooth A2DP`).

/// Magic bytes at offset `0` of every shared audio ring VMO: ASCII `"HARB"`.
pub const HARB_MAGIC: [u8; 4] = *b"HARB";
/// Current `HARB` header format version.
pub const HARB_VERSION: u16 = 1;
/// Byte size of the fixed `HARB` control header preceding sample frames.
pub const HARB_HEADER_BYTES: usize = 64;
/// Bytes per canonical stereo `S16LE` frame (`2 channels * 2 bytes`).
pub const BYTES_PER_STEREO_FRAME: usize = 4;
/// Default ring capacity in stereo frames (`16384` frames = `64 KiB`, ~`341 ms` at `48 kHz`).
pub const DEFAULT_RING_FRAMES: u32 = 16384;
/// Page-aligned VMO byte size sufficient for [`DEFAULT_RING_FRAMES`] + [`HARB_HEADER_BYTES`].
pub const DEFAULT_RING_VMO_BYTES: u64 = 69_632; // 17 * 4 KiB pages

/// Sample format code (`1` = signed 16-bit little-endian interleaved PCM).
pub const HARB_FMT_S16LE: u8 = 1;

/// Stream flag: producer is actively streaming.
pub const HARB_FLAG_ACTIVE: u16 = 1 << 0;
/// Stream flag: stream is muted.
pub const HARB_FLAG_MUTED: u16 = 1 << 1;
/// Stream flag: producer finished writing and requests drain + close (`EOS`).
pub const HARB_FLAG_EOS: u16 = 1 << 2;

/// Abstract byte-addressable backing store implemented for `libcanvas::Vmo` in userspace
/// and `Vec<u8>` / `[u8]` in `#![forbid(unsafe_code)]` host tests.
pub trait RingBacking {
    /// Read exact slice at `offset` into `dst`.
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> bool;
    /// Write exact slice `src` at `offset`.
    fn write_at(&mut self, offset: u64, src: &[u8]) -> bool;
}

impl RingBacking for alloc::vec::Vec<u8> {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> bool {
        let off = offset as usize;
        let Some(end) = off.checked_add(dst.len()) else {
            return false;
        };
        if end > self.len() {
            return false;
        }
        dst.copy_from_slice(&self[off..end]);
        true
    }

    fn write_at(&mut self, offset: u64, src: &[u8]) -> bool {
        let off = offset as usize;
        let Some(end) = off.checked_add(src.len()) else {
            return false;
        };
        if end > self.len() {
            return false;
        }
        self[off..end].copy_from_slice(src);
        true
    }
}

/// Decoded 64-byte `HARB` SPSC VMO header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HarbHeader {
    /// Channels (`1` = mono, `2` = stereo; ring storage always interleaves stereo frames).
    pub channels: u8,
    /// Format (`HARB_FMT_S16LE`).
    pub format: u8,
    /// Producer sample rate in Hz (`8000..=96000`).
    pub sample_rate: u32,
    /// Power-of-two ring capacity in stereo frames (`4` bytes each).
    pub capacity_frames: u32,
    /// Monotonically increasing count of stereo frames written by producer.
    pub write_pos: u64,
    /// Monotonically increasing count of stereo frames consumed by reader.
    pub read_pos: u64,
    /// Cumulative consumer underrun counter.
    pub underruns: u32,
    /// Cumulative producer overrun/drop counter.
    pub overruns: u32,
    /// Per-stream linear gain in `Q8.8` (`256 = 100%`).
    pub volume_q8: u16,
    /// Bitmask of `HARB_FLAG_*`.
    pub flags: u16,
}

impl HarbHeader {
    /// Construct a new active header with power-of-two `capacity_frames`.
    pub const fn new(sample_rate: u32, capacity_frames: u32) -> Self {
        Self {
            channels: 2,
            format: HARB_FMT_S16LE,
            sample_rate,
            capacity_frames,
            write_pos: 0,
            read_pos: 0,
            underruns: 0,
            overruns: 0,
            volume_q8: 256,
            flags: HARB_FLAG_ACTIVE,
        }
    }

    /// Encode header into 64 bytes.
    pub fn encode(&self, out: &mut [u8; HARB_HEADER_BYTES]) {
        out.fill(0);
        out[0..4].copy_from_slice(&HARB_MAGIC);
        out[4..6].copy_from_slice(&HARB_VERSION.to_le_bytes());
        out[6] = self.channels;
        out[7] = self.format;
        out[8..12].copy_from_slice(&self.sample_rate.to_le_bytes());
        out[12..16].copy_from_slice(&self.capacity_frames.to_le_bytes());
        out[16..24].copy_from_slice(&self.write_pos.to_le_bytes());
        out[24..32].copy_from_slice(&self.read_pos.to_le_bytes());
        out[32..36].copy_from_slice(&self.underruns.to_le_bytes());
        out[36..40].copy_from_slice(&self.overruns.to_le_bytes());
        out[40..42].copy_from_slice(&self.volume_q8.to_le_bytes());
        out[42..44].copy_from_slice(&self.flags.to_le_bytes());
    }

    /// Decode and validate a 64-byte header.
    pub fn decode(raw: &[u8; HARB_HEADER_BYTES]) -> Option<Self> {
        if raw[0..4] != HARB_MAGIC {
            return None;
        }
        let ver = u16::from_le_bytes([raw[4], raw[5]]);
        if ver != HARB_VERSION {
            return None;
        }
        let capacity_frames = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        if capacity_frames < 64 || !capacity_frames.is_power_of_two() {
            return None;
        }
        let sample_rate = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        if !(4000..=192_000).contains(&sample_rate) {
            return None;
        }
        Some(Self {
            channels: raw[6],
            format: raw[7],
            sample_rate,
            capacity_frames,
            write_pos: u64::from_le_bytes([
                raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
            ]),
            read_pos: u64::from_le_bytes([
                raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
            ]),
            underruns: u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]),
            overruns: u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]),
            volume_q8: u16::from_le_bytes([raw[40], raw[41]]),
            flags: u16::from_le_bytes([raw[42], raw[43]]),
        })
    }

    /// Number of unread stereo frames currently buffered in the ring.
    pub const fn available_read(&self) -> u32 {
        let diff = self.write_pos.saturating_sub(self.read_pos);
        if diff > self.capacity_frames as u64 {
            self.capacity_frames
        } else {
            diff as u32
        }
    }

    /// Number of free stereo frame slots available for producer writes.
    pub const fn available_write(&self) -> u32 {
        self.capacity_frames.saturating_sub(self.available_read())
    }
}

/// Format a fresh `HARB` header into `store`.
pub fn init_ring<B: RingBacking>(store: &mut B, sample_rate: u32, capacity_frames: u32) -> bool {
    if capacity_frames < 64 || !capacity_frames.is_power_of_two() {
        return false;
    }
    let hdr = HarbHeader::new(sample_rate, capacity_frames);
    let mut raw = [0u8; HARB_HEADER_BYTES];
    hdr.encode(&mut raw);
    store.write_at(0, &raw)
}

/// Read and validate the `HARB` header from `store`.
pub fn load_header<B: RingBacking>(store: &B) -> Option<HarbHeader> {
    let mut raw = [0u8; HARB_HEADER_BYTES];
    if !store.read_at(0, &mut raw) {
        return None;
    }
    HarbHeader::decode(&raw)
}

/// Push interleaved stereo `i16` samples (`frames.len()` must be even: `2 * num_frames`)
/// into `store`, returning the number of stereo frames written without blocking.
pub fn ring_push_stereo_i16<B: RingBacking>(store: &mut B, samples: &[i16]) -> usize {
    let total_frames = samples.len() / 2;
    if total_frames == 0 {
        return 0;
    }
    let Some(hdr) = load_header(store) else {
        return 0;
    };
    let free = hdr.available_write() as usize;
    let write_frames = total_frames.min(free);
    if write_frames == 0 {
        let new_ovr = hdr.overruns.wrapping_add(1);
        let _ = store.write_at(36, &new_ovr.to_le_bytes());
        return 0;
    }

    let cap = hdr.capacity_frames as usize;
    let mask = cap - 1;
    let start_slot = (hdr.write_pos as usize) & mask;
    let first_frames = write_frames.min(cap - start_slot);
    let second_frames = write_frames - first_frames;

    if !write_frame_span(store, start_slot, &samples[..first_frames * 2]) {
        return 0;
    }
    if second_frames > 0
        && !write_frame_span(
            store,
            0,
            &samples[first_frames * 2..(first_frames + second_frames) * 2],
        )
    {
        return 0;
    }

    let next_write_pos = hdr.write_pos.wrapping_add(write_frames as u64);
    let _ = store.write_at(16, &next_write_pos.to_le_bytes());
    write_frames
}

/// Pop up to `out_samples.len() / 2` stereo `i16` frames from `store`, returning the number
/// of stereo frames read.
pub fn ring_pop_stereo_i16<B: RingBacking>(store: &mut B, out_samples: &mut [i16]) -> usize {
    let want_frames = out_samples.len() / 2;
    if want_frames == 0 {
        return 0;
    }
    let Some(mut hdr) = load_header(store) else {
        return 0;
    };
    // Guard against corrupt lag if producer ever jumped ahead.
    if hdr.write_pos.saturating_sub(hdr.read_pos) > u64::from(hdr.capacity_frames) {
        hdr.read_pos = hdr.write_pos.saturating_sub(u64::from(hdr.capacity_frames));
    }
    let avail = hdr.available_read() as usize;
    let read_frames = want_frames.min(avail);
    if read_frames == 0 {
        if (hdr.flags & HARB_FLAG_ACTIVE) != 0 && (hdr.flags & HARB_FLAG_EOS) == 0 {
            let new_und = hdr.underruns.wrapping_add(1);
            let _ = store.write_at(32, &new_und.to_le_bytes());
        }
        return 0;
    }

    let cap = hdr.capacity_frames as usize;
    let mask = cap - 1;
    let start_slot = (hdr.read_pos as usize) & mask;
    let first_frames = read_frames.min(cap - start_slot);
    let second_frames = read_frames - first_frames;

    if !read_frame_span(store, start_slot, &mut out_samples[..first_frames * 2]) {
        return 0;
    }
    if second_frames > 0
        && !read_frame_span(
            store,
            0,
            &mut out_samples[first_frames * 2..(first_frames + second_frames) * 2],
        )
    {
        return 0;
    }

    let next_read_pos = hdr.read_pos.wrapping_add(read_frames as u64);
    let _ = store.write_at(24, &next_read_pos.to_le_bytes());
    read_frames
}

/// Pop exactly `want_frames` stereo frames for a secondary clock-domain sink (such as
/// Bluetooth A2DP when `VirtIO-Sound` is simultaneously active in `mirror` mode),
/// gently skipping excess lag (`> 75%` full) or zero-filling underruns so the two sinks
/// never deadlock or drift seconds apart.
pub fn ring_pop_clock_synced<B: RingBacking>(store: &mut B, out_samples: &mut [i16]) -> usize {
    let want_frames = out_samples.len() / 2;
    if want_frames == 0 {
        return 0;
    }
    if let Some(hdr) = load_header(store) {
        let high_water = (hdr.capacity_frames * 3) / 4;
        let avail = hdr.available_read();
        if avail > high_water {
            // Secondary sink clock is slightly slower than mixer: advance read_pos to 50% mark.
            let target_keep = hdr.capacity_frames / 2;
            let skip = avail.saturating_sub(target_keep);
            let adjusted = hdr.read_pos.wrapping_add(u64::from(skip));
            let _ = store.write_at(24, &adjusted.to_le_bytes());
        }
    }
    let got = ring_pop_stereo_i16(store, out_samples);
    if got < want_frames {
        out_samples[got * 2..want_frames * 2].fill(0);
    }
    got
}

fn write_frame_span<B: RingBacking>(store: &mut B, slot_offset: usize, samples: &[i16]) -> bool {
    const CHUNK_SAMPLES: usize = 512; // 1024 bytes stack buffer
    let mut byte_off = (HARB_HEADER_BYTES + slot_offset * BYTES_PER_STEREO_FRAME) as u64;
    let mut idx = 0usize;
    let mut raw = [0u8; CHUNK_SAMPLES * 2];
    while idx < samples.len() {
        let take = (samples.len() - idx).min(CHUNK_SAMPLES);
        for (i, &s) in samples[idx..idx + take].iter().enumerate() {
            let b = s.to_le_bytes();
            raw[i * 2] = b[0];
            raw[i * 2 + 1] = b[1];
        }
        if !store.write_at(byte_off, &raw[..take * 2]) {
            return false;
        }
        byte_off += (take * 2) as u64;
        idx += take;
    }
    true
}

fn read_frame_span<B: RingBacking>(store: &B, slot_offset: usize, out_samples: &mut [i16]) -> bool {
    const CHUNK_SAMPLES: usize = 512;
    let mut byte_off = (HARB_HEADER_BYTES + slot_offset * BYTES_PER_STEREO_FRAME) as u64;
    let mut idx = 0usize;
    let mut raw = [0u8; CHUNK_SAMPLES * 2];
    while idx < out_samples.len() {
        let take = (out_samples.len() - idx).min(CHUNK_SAMPLES);
        if !store.read_at(byte_off, &mut raw[..take * 2]) {
            return false;
        }
        for i in 0..take {
            out_samples[idx + i] = i16::from_le_bytes([raw[i * 2], raw[i * 2 + 1]]);
        }
        byte_off += (take * 2) as u64;
        idx += take;
    }
    true
}
