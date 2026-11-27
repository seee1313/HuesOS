//! Zero-heap Ring-3 `VirtIO-Sound` (`1af4:1059` / `1af4:1018`) DriverHost
//! (`/drivers/driver-host-snd.elf`).
//!
//! Responsibilities:
//! - Owns one isolated PCIe `VirtIO-Sound` 1.2 controller (`VT10` modern MMIO
//!   BARs, dedicated `4 MiB` `AUDIO_DMA_OFFSET` `DmaPool`, and `DeviceLease`
//!   under Intel VT-d / AMD-Vi IOMMU).
//! - Runs with zero heap allocations (`ScudoHeap` intentionally left
//!   uninitialised so any accidental heap request fails closed with null) and
//!   zero `unsafe` blocks by using `libcanvas::channel::{mmio_load, mmio_store}`.
//! - Serves `HSND` (`SndDriverOp`) to `/services/audio.elf` and drains the
//!   shared `HARB` SPSC VMO ring buffer directly into VirtIO `txq` DMA periods.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{fence, Ordering};

use huesos_abi::audio::{SndDriverOp, SND_DRIVER_MAGIC, VERSION as SND_ABI_VERSION};
use huesos_abi::pci_manager::DEVICE_LEASE_SND_RO_LABEL;
use huesos_abi::vmar_flags;
use huesos_audio::ring::{ring_pop_stereo_i16, RingBacking};
use huesos_audio::virtio_snd::{
    decode_status_code, encode_pcm_set_params, encode_pcm_simple_cmd, encode_query_pcm_info,
     VirtioSndConfig, VirtioSndPcmInfo, PCM_INFO_ENTRY_BYTES, PCM_STATUS_BYTES, PCM_XFER_HDR_BYTES,
    VIRTIO_SND_PCM_FMT_S16, VIRTIO_SND_R_PCM_PREPARE, VIRTIO_SND_R_PCM_START,
    VIRTIO_SND_R_PCM_STOP, VIRTIO_SND_S_OK, VIRTIO_SND_VQ_CONTROL, VIRTIO_SND_VQ_EVENT,
    VIRTIO_SND_VQ_RX, VIRTIO_SND_VQ_TX,
};
use libcanvas::channel::{mmio_load, mmio_store};
use libcanvas::{println, wait_any, Channel, ErrorCode, Handle, Signals, Vmo, WaitItem};

#[global_allocator]
static ZERO_HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

const DMA_MAP_VA: u64 = 0x0000_7400_0000_0000;
const VIRTIO_BAR_VA_BASE: u64 = 0x0000_7410_0000_0000;
const VIRTIO_BAR_VA_STRIDE: u64 = 0x0000_0010_0000_0000;

// Modern VirtIO 1.0 `virtio_pci_common_cfg` register offsets
const COMMON_DFSELECT: usize = 0x00;
const COMMON_DF: usize = 0x04;
const COMMON_GFSELECT: usize = 0x08;
const COMMON_GF: usize = 0x0C;
const COMMON_STATUS: usize = 0x14;
const COMMON_Q_SELECT: usize = 0x16;
const COMMON_Q_SIZE: usize = 0x18;
const COMMON_Q_ENABLE: usize = 0x1C;
const COMMON_Q_NOTIFY_OFF: usize = 0x1E;
const COMMON_Q_DESCLO: usize = 0x20;
const COMMON_Q_DESCHI: usize = 0x24;
const COMMON_Q_AVAILLO: usize = 0x28;
const COMMON_Q_AVAILHI: usize = 0x2C;
const COMMON_Q_USEDLO: usize = 0x30;
const COMMON_Q_USEDHI: usize = 0x34;

const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

const VIRTIO_F_VERSION_1_HI: u32 = 1 << 0;
const VIRTIO_F_ACCESS_PLATFORM_HI: u32 = 1 << 1;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

/// Stereo frames per DMA period (`480` frames = `10 ms` at `48 kHz`, `1920` bytes).
const PERIOD_FRAMES: usize = 480;
const PERIOD_PCM_BYTES: usize = PERIOD_FRAMES * 4;
const TX_OUT_STRIDE: usize = 2048; // 4-byte `virtio_snd_pcm_xfer` + 1920-byte PCM + alignment pad
const TX_STATUS_STRIDE: usize = 64;
const TX_RING_SLOTS: usize = 4;
const CTRL_REQ_OFF_SIZE: usize = 256;
const CTRL_RESP_OFF_SIZE: usize = 512;

#[derive(Clone, Copy)]
struct MappedWin {
    base: u64,
    len: usize,
}

impl MappedWin {
    fn read8(&self, off: usize) -> u8 {
        if off < self.len {
            mmio_load::<u8>(self.base + (off as u64))
        } else {
            0
        }
    }

    fn read16(&self, off: usize) -> u16 {
        if off.saturating_add(2) <= self.len {
            mmio_load::<u16>(self.base + (off as u64))
        } else {
            0
        }
    }

    fn read32(&self, off: usize) -> u32 {
        if off.saturating_add(4) <= self.len {
            mmio_load::<u32>(self.base + (off as u64))
        } else {
            0
        }
    }

    fn write8(&self, off: usize, val: u8) {
        if off < self.len {
            mmio_store::<u8>(self.base + (off as u64), val);
        }
    }

    fn write16(&self, off: usize, val: u16) {
        if off.saturating_add(2) <= self.len {
            mmio_store::<u16>(self.base + (off as u64), val);
        }
    }

    fn write32(&self, off: usize, val: u32) {
        if off.saturating_add(4) <= self.len {
            mmio_store::<u32>(self.base + (off as u64), val);
        }
    }

    fn write64(&self, off: usize, val: u64) {
        self.write32(off, val as u32);
        self.write32(off.saturating_add(4), (val >> 32) as u32);
    }

    fn zero_range(&self, off: usize, len: usize) {
        if off.saturating_add(len) > self.len {
            return;
        }
        let mut idx = 0usize;
        while idx + 4 <= len {
            self.write32(off + idx, 0);
            idx += 4;
        }
        while idx < len {
            self.write8(off + idx, 0);
            idx += 1;
        }
    }

    fn copy_in(&self, off: usize, src: &[u8]) {
        if off.saturating_add(src.len()) > self.len {
            return;
        }
        let mut idx = 0usize;
        while idx + 4 <= src.len() {
            let word = u32::from_le_bytes([src[idx], src[idx + 1], src[idx + 2], src[idx + 3]]);
            self.write32(off + idx, word);
            idx += 4;
        }
        while idx < src.len() {
            self.write8(off + idx, src[idx]);
            idx += 1;
        }
    }

    fn copy_out(&self, off: usize, dst: &mut [u8]) {
        if off.saturating_add(dst.len()) > self.len {
            return;
        }
        let mut idx = 0usize;
        while idx + 4 <= dst.len() {
            let word = self.read32(off + idx).to_le_bytes();
            dst[idx..idx + 4].copy_from_slice(&word);
            idx += 4;
        }
        while idx < dst.len() {
            dst[idx] = self.read8(off + idx);
            idx += 1;
        }
    }

    fn write_desc(&self, desc_off: usize, slot: usize, addr: u64, len: u32, flags: u16, next: u16) {
        let base = desc_off + slot * 16;
        self.write64(base, addr);
        self.write32(base + 8, len);
        self.write16(base + 12, flags);
        self.write16(base + 14, next);
    }
}

#[derive(Clone, Copy)]
struct Vt10CapInfo {
    common_bar: u8,
    notify_bar: u8,
    isr_bar: u8,
    dev_bar: u8,
    has_dev: bool,
    common_off: u32,
    common_len: u32,
    notify_off: u32,
    notify_len: u32,
    notify_mult: u32,
    isr_off: u32,
    isr_len: u32,
    dev_off: u32,
    dev_len: u32,
    bdf_packed: u32,
}

impl Vt10CapInfo {
    fn decode(raw: &[u8; 48]) -> Option<Self> {
        if &raw[0..4] != b"VT10" {
            return None;
        }
        let rd32 = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
        Some(Self {
            common_bar: raw[4],
            notify_bar: raw[5],
            isr_bar: raw[6],
            dev_bar: raw[7] & 0x7F,
            has_dev: raw[7] != 0xFF,
            common_off: rd32(8),
            common_len: rd32(12),
            notify_off: rd32(16),
            notify_len: rd32(20),
            notify_mult: rd32(24),
            isr_off: rd32(28),
            isr_len: rd32(32),
            dev_off: rd32(36),
            dev_len: rd32(40),
            bdf_packed: rd32(44),
        })
    }
}

#[derive(Clone, Copy)]
struct VirtioQueue {
    q_idx: u16,
    q_size: u16,
    desc_off: usize,
    avail_off: usize,
    used_off: usize,
    notify_win: MappedWin,
    notify_off: usize,
    next_avail_idx: u16,
    last_used_idx: u16,
}

const fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

const fn vring_bytes(qsz: usize) -> (usize, usize) {
    let avail_off = 16 * qsz;
    let used_off = align_up(avail_off + 6 + 2 * qsz, 4096);
    let total = align_up(used_off + 6 + 8 * qsz, 4096);
    (used_off, total)
}

struct VmoRingStore {
    vmo: Vmo,
}

impl RingBacking for VmoRingStore {
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> bool {
        self.vmo.read(offset, dst) == Ok(dst.len())
    }

    fn write_at(&mut self, offset: u64, src: &[u8]) -> bool {
        self.vmo.write(offset, src) == Ok(src.len())
    }
}

struct VirtioSndHw {
    dma: MappedWin,
    dma_pa: u64,
    isr_win: MappedWin,
    isr_off: usize,
    ctrlq: VirtioQueue,
    txq: VirtioQueue,
    ctrl_req_off: usize,
    ctrl_resp_off: usize,
    tx_out_off: usize,
    tx_status_off: usize,
    tx_slot_busy: [bool; TX_RING_SLOTS],
    tx_inflight: usize,
    stream_id: u32,
    sample_rate_hz: u32,
    streams_count: u8,
    stream_started: bool,
    completed_periods: u64,
    bdf_packed: u32,
}

impl VirtioSndHw {
    fn try_init(
        vt10: &Vt10CapInfo,
        mapped_bars: &[Option<MappedWin>; 6],
        dma: MappedWin,
        dma_pa: u64,
    ) -> Option<Self> {
        if dma.len < 256 * 1024 {
            return None;
        }
        let resolve_region = |bar: u8, off: u32, min_len: usize| -> Option<(MappedWin, usize)> {
            let win = (*mapped_bars.get(usize::from(bar))?)?;
            let o = off as usize;
            if o.checked_add(min_len)? <= win.len {
                Some((win, o))
            } else {
                None
            }
        };

        if (vt10.common_len as usize) < 0x38 || (vt10.isr_len as usize) < 1 {
            return None;
        }
        let (common_win, common_off) = resolve_region(vt10.common_bar, vt10.common_off, 0x38)?;
        let (isr_win, isr_off) = resolve_region(vt10.isr_bar, vt10.isr_off, 1)?;
        let notify_win = (*mapped_bars.get(usize::from(vt10.notify_bar))?)?;
        if (vt10.notify_off as usize).saturating_add(2) > notify_win.len {
            return None;
        }

        // 1. Reset VirtIO device -> ACK -> DRIVER
        common_win.write8(common_off + COMMON_STATUS, 0);
        for _ in 0..20_000 {
            if common_win.read8(common_off + COMMON_STATUS) == 0 {
                break;
            }
        }
        common_win.write8(common_off + COMMON_STATUS, VIRTIO_STATUS_ACK);
        common_win.write8(
            common_off + COMMON_STATUS,
            VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER,
        );

        // 2. Negotiate VIRTIO_F_VERSION_1 (+ VIRTIO_F_ACCESS_PLATFORM when offered by IOMMU)
        common_win.write32(common_off + COMMON_DFSELECT, 0);
        let _host_lo = common_win.read32(common_off + COMMON_DF);
        common_win.write32(common_off + COMMON_DFSELECT, 1);
        let host_hi = common_win.read32(common_off + COMMON_DF);
        if (host_hi & VIRTIO_F_VERSION_1_HI) == 0 {
            return None;
        }
        let guest_hi = VIRTIO_F_VERSION_1_HI | (host_hi & VIRTIO_F_ACCESS_PLATFORM_HI);
        common_win.write32(common_off + COMMON_GFSELECT, 0);
        common_win.write32(common_off + COMMON_GF, 0);
        common_win.write32(common_off + COMMON_GFSELECT, 1);
        common_win.write32(common_off + COMMON_GF, guest_hi);

        let st_feat = VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK;
        common_win.write8(common_off + COMMON_STATUS, st_feat);
        if (common_win.read8(common_off + COMMON_STATUS) & VIRTIO_STATUS_FEATURES_OK) == 0 {
            return None;
        }

        // 3. Read `virtio_snd_config` (12 bytes: jacks, streams, chmaps)
        let mut raw_cfg = [0u8; 12];
        if vt10.has_dev && vt10.dev_len >= 12 {
            if let Some((dev_win, dev_off)) = resolve_region(vt10.dev_bar, vt10.dev_off, 12) {
                dev_win.copy_out(dev_off, &mut raw_cfg);
            }
        }
        let cfg = VirtioSndConfig::decode(raw_cfg);
        let streams_total = cfg.streams.clamp(1, 8);

        // 4. Allocate and enable virtqueues (controlq=0, eventq=1, txq=2, rxq=3)
        let mut dma_cursor = 0usize;
        let setup_q = |q_idx: u16, cursor: &mut usize| -> Option<VirtioQueue> {
            common_win.write16(common_off + COMMON_Q_SELECT, q_idx);
            let qsz = common_win.read16(common_off + COMMON_Q_SIZE);
            let q_noff = common_win.read16(common_off + COMMON_Q_NOTIFY_OFF);
            if qsz < 4 || qsz > 1024 {
                return None;
            }
            let notify_rel = (vt10.notify_off as usize)
                .checked_add((usize::from(q_noff)).checked_mul(vt10.notify_mult as usize)?)?;
            if notify_rel.checked_add(2)? > notify_win.len {
                return None;
            }
            let (used_rel, total_bytes) = vring_bytes(usize::from(qsz));
            let ring_off = align_up(*cursor, 4096);
            if ring_off + total_bytes > dma.len {
                return None;
            }
            let desc_pa = dma_pa + (ring_off as u64);
            let avail_pa = desc_pa + (16 * usize::from(qsz)) as u64;
            let used_pa = desc_pa + (used_rel as u64);

            dma.zero_range(ring_off, total_bytes);
            fence(Ordering::SeqCst);
            common_win.write32(common_off + COMMON_Q_DESCLO, desc_pa as u32);
            common_win.write32(common_off + COMMON_Q_DESCHI, (desc_pa >> 32) as u32);
            common_win.write32(common_off + COMMON_Q_AVAILLO, avail_pa as u32);
            common_win.write32(common_off + COMMON_Q_AVAILHI, (avail_pa >> 32) as u32);
            common_win.write32(common_off + COMMON_Q_USEDLO, used_pa as u32);
            common_win.write32(common_off + COMMON_Q_USEDHI, (used_pa >> 32) as u32);
            common_win.write16(common_off + COMMON_Q_ENABLE, 1);

            *cursor = ring_off + total_bytes;
            Some(VirtioQueue {
                q_idx,
                q_size: qsz,
                desc_off: ring_off,
                avail_off: ring_off + 16 * usize::from(qsz),
                used_off: ring_off + used_rel,
                notify_win,
                notify_off: notify_rel,
                next_avail_idx: 0,
                last_used_idx: 0,
            })
        };

        let ctrlq = setup_q(VIRTIO_SND_VQ_CONTROL, &mut dma_cursor)?;
        let _eventq = setup_q(VIRTIO_SND_VQ_EVENT, &mut dma_cursor);
        let txq = setup_q(VIRTIO_SND_VQ_TX, &mut dma_cursor)?;
        let _rxq = setup_q(VIRTIO_SND_VQ_RX, &mut dma_cursor);
        if usize::from(txq.q_size) < TX_RING_SLOTS * 2 {
            return None;
        }

        let ctrl_req_off = align_up(dma_cursor, 64);
        let ctrl_resp_off = ctrl_req_off + CTRL_REQ_OFF_SIZE;
        let tx_out_off = align_up(ctrl_resp_off + CTRL_RESP_OFF_SIZE, 4096);
        let tx_status_off = tx_out_off + TX_RING_SLOTS * TX_OUT_STRIDE;
        let end_off = tx_status_off + TX_RING_SLOTS * TX_STATUS_STRIDE;
        if end_off > dma.len {
            return None;
        }

        fence(Ordering::SeqCst);
        common_win.write8(
            common_off + COMMON_STATUS,
            VIRTIO_STATUS_ACK
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        );
        fence(Ordering::SeqCst);

        let mut hw = Self {
            dma,
            dma_pa,
            isr_win,
            isr_off,
            ctrlq,
            txq,
            ctrl_req_off,
            ctrl_resp_off,
            tx_out_off,
            tx_status_off,
            tx_slot_busy: [false; TX_RING_SLOTS],
            tx_inflight: 0,
            stream_id: 0,
            sample_rate_hz: 48_000,
            streams_count: streams_total as u8,
            stream_started: false,
            completed_periods: 0,
            bdf_packed: vt10.bdf_packed,
        };

        hw.configure_playback_stream(streams_total)?;
        Some(hw)
    }

    fn exec_ctrl(&mut self, req: &[u8], resp: &mut [u8]) -> bool {
        if req.is_empty()
            || req.len() > CTRL_REQ_OFF_SIZE
            || resp.len() < 4
            || resp.len() > CTRL_RESP_OFF_SIZE
        {
            return false;
        }
        self.dma.copy_in(self.ctrl_req_off, req);
        self.dma.zero_range(self.ctrl_resp_off, resp.len());

        let req_pa = self.dma_pa + (self.ctrl_req_off as u64);
        let resp_pa = self.dma_pa + (self.ctrl_resp_off as u64);
        self.dma.write_desc(
            self.ctrlq.desc_off,
            0,
            req_pa,
            req.len() as u32,
            VRING_DESC_F_NEXT,
            1,
        );
        self.dma.write_desc(
            self.ctrlq.desc_off,
            1,
            resp_pa,
            resp.len() as u32,
            VRING_DESC_F_WRITE,
            0,
        );

        let avail_slot = usize::from(self.ctrlq.next_avail_idx % self.ctrlq.q_size);
        self.dma
            .write16(self.ctrlq.avail_off + 4 + avail_slot * 2, 0);
        fence(Ordering::SeqCst);
        self.ctrlq.next_avail_idx = self.ctrlq.next_avail_idx.wrapping_add(1);
        self.dma
            .write16(self.ctrlq.avail_off + 2, self.ctrlq.next_avail_idx);
        fence(Ordering::SeqCst);
        self.ctrlq
            .notify_win
            .write16(self.ctrlq.notify_off, self.ctrlq.q_idx);

        for _ in 0..50_000 {
            fence(Ordering::SeqCst);
            let used_idx = self.dma.read16(self.ctrlq.used_off + 2);
            if used_idx != self.ctrlq.last_used_idx {
                self.ctrlq.last_used_idx = used_idx;
                let _ = self.isr_win.read8(self.isr_off);
                self.dma.copy_out(self.ctrl_resp_off, resp);
                return decode_status_code(resp) == Some(VIRTIO_SND_S_OK);
            }
            libcanvas::process::yield_now();
        }
        false
    }

    fn configure_playback_stream(&mut self, streams_total: u32) -> Option<()> {
        let query = encode_query_pcm_info(0, streams_total);
        let mut resp_buf = [0u8; 4 + 8 * PCM_INFO_ENTRY_BYTES];
        let resp_len = 4 + (streams_total as usize) * PCM_INFO_ENTRY_BYTES;
        if !self.exec_ctrl(&query, &mut resp_buf[..resp_len]) {
            return None;
        }

        let mut chosen_stream = None;
        let mut chosen_rate = (7u8, 48_000u32);
        for idx in 0..(streams_total as usize) {
            let base = 4 + idx * PCM_INFO_ENTRY_BYTES;
            if let Some(info) = VirtioSndPcmInfo::decode(&resp_buf[base..base + PCM_INFO_ENTRY_BYTES])
            {
                if info.supports_stereo_s16_output() {
                    if let Some(r) = info.preferred_rate() {
                        chosen_stream = Some(idx as u32);
                        chosen_rate = r;
                        break;
                    }
                }
            }
        }

        let stream_id = chosen_stream?;
        let (rate_code, rate_hz) = chosen_rate;
        let set_params = encode_pcm_set_params(
            stream_id,
            (PERIOD_PCM_BYTES * TX_RING_SLOTS) as u32,
            PERIOD_PCM_BYTES as u32,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            rate_code,
        );
        let mut st_resp = [0u8; 8];
        if !self.exec_ctrl(&set_params, &mut st_resp) {
            return None;
        }
        let prep = encode_pcm_simple_cmd(VIRTIO_SND_R_PCM_PREPARE, stream_id);
        if !self.exec_ctrl(&prep, &mut st_resp) {
            return None;
        }
        let start = encode_pcm_simple_cmd(VIRTIO_SND_R_PCM_START, stream_id);
        if !self.exec_ctrl(&start, &mut st_resp) {
            return None;
        }

        self.stream_id = stream_id;
        self.sample_rate_hz = rate_hz;
        self.stream_started = true;
        Some(())
    }

    fn set_running(&mut self, want_run: bool) {
        if want_run == self.stream_started {
            return;
        }
        let mut st_resp = [0u8; 8];
        if want_run {
            let prep = encode_pcm_simple_cmd(VIRTIO_SND_R_PCM_PREPARE, self.stream_id);
            let _ = self.exec_ctrl(&prep, &mut st_resp);
            let start = encode_pcm_simple_cmd(VIRTIO_SND_R_PCM_START, self.stream_id);
            if self.exec_ctrl(&start, &mut st_resp) {
                self.stream_started = true;
            }
        } else {
            let stop = encode_pcm_simple_cmd(VIRTIO_SND_R_PCM_STOP, self.stream_id);
            if self.exec_ctrl(&stop, &mut st_resp) {
                self.stream_started = false;
            }
        }
    }

    fn reclaim_tx(&mut self) {
        fence(Ordering::SeqCst);
        let used_idx = self.dma.read16(self.txq.used_off + 2);
        while self.txq.last_used_idx != used_idx {
            let elem_off = self.txq.used_off
                + 4
                + usize::from(self.txq.last_used_idx % self.txq.q_size) * 8;
            let head_desc = self.dma.read32(elem_off) as usize;
            let slot = head_desc / 2;
            if slot < TX_RING_SLOTS && self.tx_slot_busy[slot] {
                self.tx_slot_busy[slot] = false;
                self.tx_inflight = self.tx_inflight.saturating_sub(1);
                self.completed_periods = self.completed_periods.wrapping_add(1);
            }
            self.txq.last_used_idx = self.txq.last_used_idx.wrapping_add(1);
        }
        let _ = self.isr_win.read8(self.isr_off);
    }

    fn pump_from_ring(&mut self, ring: &mut VmoRingStore) {
        self.reclaim_tx();
        if !self.stream_started {
            return;
        }
        while self.tx_inflight < TX_RING_SLOTS {
            let Some(slot) = self.tx_slot_busy.iter().position(|busy| !*busy) else {
                break;
            };
            let mut samples = [0i16; PERIOD_FRAMES * 2];
            let frames = ring_pop_stereo_i16(ring, &mut samples);
            if frames == 0 {
                break;
            }

            let out_off = self.tx_out_off + slot * TX_OUT_STRIDE;
            let st_off = self.tx_status_off + slot * TX_STATUS_STRIDE;
            self.dma.write32(out_off, self.stream_id);
            for (f_idx, &sample) in samples.iter().enumerate() {
                self.dma
                    .write16(out_off + PCM_XFER_HDR_BYTES + f_idx * 2, sample as u16);
            }
            self.dma.zero_range(st_off, PCM_STATUS_BYTES);

            let head_desc = slot * 2;
            let status_desc = head_desc + 1;
            let out_pa = self.dma_pa + (out_off as u64);
            let st_pa = self.dma_pa + (st_off as u64);
            self.dma.write_desc(
                self.txq.desc_off,
                head_desc,
                out_pa,
                (PCM_XFER_HDR_BYTES + PERIOD_PCM_BYTES) as u32,
                VRING_DESC_F_NEXT,
                status_desc as u16,
            );
            self.dma.write_desc(
                self.txq.desc_off,
                status_desc,
                st_pa,
                PCM_STATUS_BYTES as u32,
                VRING_DESC_F_WRITE,
                0,
            );

            let avail_slot = usize::from(self.txq.next_avail_idx % self.txq.q_size);
            self.dma
                .write16(self.txq.avail_off + 4 + avail_slot * 2, head_desc as u16);
            fence(Ordering::SeqCst);
            self.txq.next_avail_idx = self.txq.next_avail_idx.wrapping_add(1);
            self.dma
                .write16(self.txq.avail_off + 2, self.txq.next_avail_idx);
            fence(Ordering::SeqCst);
            self.txq
                .notify_win
                .write16(self.txq.notify_off, self.txq.q_idx);

            self.tx_slot_busy[slot] = true;
            self.tx_inflight += 1;
        }
    }
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.is_empty() {
        return None;
    }
    let mut out = 0u64;
    for b in hex.bytes() {
        let nib = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        out = out.checked_mul(16)?.checked_add(u64::from(nib))?;
    }
    Some(out)
}

fn write_hsnd_header(out: &mut [u8], op: SndDriverOp, status: u8) {
    out[0..4].copy_from_slice(&SND_DRIVER_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&SND_ABI_VERSION.to_le_bytes());
    out[6] = op as u8;
    out[7] = status;
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"driver-host:snd:starting");

    let mut dma_res: Option<(Handle, u64, u64)> = None;
    let mut mmio_bars: [Option<(Handle, u64)>; 6] = [const { None }; 6];
    let mut vt10_info: Option<Vt10CapInfo> = None;
    let mut retained_lease: Option<Handle> = None;
    let mut client_ch: Option<Channel> = None;

    let mut label_buf = [0u8; 128];
    for _ in 0..256 {
        match bootstrap.read_optional_handle_timeout(&mut label_buf, 100) {
            Ok((n, handle_opt)) => {
                if &label_buf[..n] == DEVICE_LEASE_SND_RO_LABEL {
                    retained_lease = handle_opt;
                    continue;
                }
                let msg = core::str::from_utf8(&label_buf[..n]).unwrap_or("");
                if msg == "resource:transfer-complete" {
                    break;
                }
                if msg == "snd-client" {
                    if let Some(h) = handle_opt {
                        client_ch = Some(Channel::from_handle(h));
                    }
                } else if let Some(rest) = msg.strip_prefix("resource:driver-host-snd:") {
                    let mut parts = rest.split(':');
                    let kind = parts.next().unwrap_or("");
                    let base = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    let len = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    let tag_tail = parts.next().unwrap_or("");
                    if let Some(h) = handle_opt {
                        if kind == "dma" && dma_res.is_none() {
                            dma_res = Some((h, base, len));
                        } else if kind == "mmio" && len > 0 {
                            if let Some(bar_s) = tag_tail.strip_prefix("bar") {
                                if let Ok(bidx) = bar_s.parse::<usize>() {
                                    if bidx < 6 && mmio_bars[bidx].is_none() {
                                        mmio_bars[bidx] = Some((h, len));
                                    }
                                }
                            }
                        } else if kind == "virtio1" && vt10_info.is_none() {
                            let vmo = Vmo::from_handle(h);
                            let mut raw = [0u8; 48];
                            if vmo.read(0, &mut raw) == Ok(48) {
                                vt10_info = Vt10CapInfo::decode(&raw);
                            }
                        }
                    }
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => break,
        }
    }

    let mut mapped_dma: Option<(MappedWin, u64)> = None;
    if let Some((dma_h, dma_pa, dma_len)) = dma_res.as_ref() {
        let map_len = (*dma_len).min(4 * 1024 * 1024) & !0xFFF;
        if map_len >= 256 * 1024
            && libcanvas::resource::map_self(
                dma_h,
                0,
                DMA_MAP_VA,
                map_len,
                vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
            )
            .is_ok()
        {
            mapped_dma = Some((
                MappedWin {
                    base: DMA_MAP_VA,
                    len: map_len as usize,
                },
                *dma_pa,
            ));
        }
    }

    let mut mapped_bars: [Option<MappedWin>; 6] = [None; 6];
    for (idx, slot) in mmio_bars.iter().enumerate() {
        if let Some((bar_h, bar_len)) = slot {
            let map_len = (*bar_len + 0xFFF) & !0xFFF;
            let va = VIRTIO_BAR_VA_BASE + (idx as u64) * VIRTIO_BAR_VA_STRIDE;
            if libcanvas::resource::map_self(
                bar_h,
                0,
                va,
                map_len,
                vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
            )
            .is_ok()
            {
                mapped_bars[idx] = Some(MappedWin {
                    base: va,
                    len: map_len as usize,
                });
            }
        }
    }

    let mut snd_hw: Option<VirtioSndHw> = None;
    if let (Some((dma_win, dma_pa)), Some(vt10)) = (mapped_dma, vt10_info.as_ref()) {
        snd_hw = VirtioSndHw::try_init(vt10, &mapped_bars, dma_win, dma_pa);
    }

    if let Some(hw) = snd_hw.as_ref() {
        println!(
            "[driver-host:snd] virtio-snd 1.2 online bdf={:#06x} stream={} rate={}Hz lease={}",
            hw.bdf_packed,
            hw.stream_id,
            hw.sample_rate_hz,
            retained_lease.is_some()
        );
        let _ = bootstrap.write(b"driver-host:snd:ready");
    } else {
        println!("[driver-host:snd] started without virtio-snd PCIe device");
        let _ = bootstrap.write(b"driver-host:snd:degraded");
    }

    let mut master_ring: Option<VmoRingStore> = None;

    loop {
        // 1. Accept freshly wired `snd-client` channel from DriverManager
        for _ in 0..4 {
            let mut bmsg = [0u8; 64];
            match bootstrap.read_optional_handle(&mut bmsg) {
                Ok((n, Some(h))) if &bmsg[..n] == b"snd-client" => {
                    client_ch = Some(Channel::from_handle(h));
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        // 2. Serve `HSND` control RPCs from `audio-service`
        if let Some(ch) = client_ch.as_ref() {
            let mut drop_client = false;
            for _ in 0..8 {
                let mut req = [0u8; 64];
                match ch.read_optional_handle(&mut req) {
                    Ok((n, maybe_h)) => {
                        if n < 8 {
                            continue;
                        }
                        let magic = u32::from_le_bytes([req[0], req[1], req[2], req[3]]);
                        let ver = u16::from_le_bytes([req[4], req[5]]);
                        if magic != SND_DRIVER_MAGIC || ver != SND_ABI_VERSION {
                            continue;
                        }
                        match SndDriverOp::from_raw(req[6]) {
                            Some(SndDriverOp::QueryHw) => {
                                let mut rep = [0u8; 24];
                                if let Some(hw) = snd_hw.as_mut() {
                                    hw.reclaim_tx();
                                    write_hsnd_header(&mut rep, SndDriverOp::QueryHw, 0);
                                    rep[8] = 1;
                                    rep[9] = u8::from(hw.stream_started);
                                    rep[10] = 2;
                                    rep[11] = hw.streams_count;
                                    rep[12..16].copy_from_slice(&hw.sample_rate_hz.to_le_bytes());
                                    rep[16..24]
                                        .copy_from_slice(&hw.completed_periods.to_le_bytes());
                                } else {
                                    write_hsnd_header(&mut rep, SndDriverOp::QueryHw, 1);
                                }
                                let _ = ch.write(&rep);
                            }
                            Some(SndDriverOp::AttachMasterRing) => {
                                let mut rep = [0u8; 8];
                                if let Some(h) = maybe_h {
                                    master_ring = Some(VmoRingStore {
                                        vmo: Vmo::from_handle(h),
                                    });
                                    write_hsnd_header(&mut rep, SndDriverOp::AttachMasterRing, 0);
                                } else {
                                    write_hsnd_header(&mut rep, SndDriverOp::AttachMasterRing, 2);
                                }
                                let _ = ch.write(&rep);
                            }
                            Some(SndDriverOp::SetRunning) => {
                                let want = n >= 9 && req[8] != 0;
                                if let Some(hw) = snd_hw.as_mut() {
                                    hw.set_running(want);
                                }
                                let mut rep = [0u8; 8];
                                write_hsnd_header(
                                    &mut rep,
                                    SndDriverOp::SetRunning,
                                    if snd_hw.is_some() { 0 } else { 1 },
                                );
                                let _ = ch.write(&rep);
                            }
                            None => {}
                        }
                    }
                    Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                    Err(_) => {
                        drop_client = true;
                        break;
                    }
                }
            }
            if drop_client {
                client_ch = None;
            }
        }

        // 3. Pump audio frames from `HARB` master ring into VirtIO `txq`
        let mut active_tx = false;
        if let Some(hw) = snd_hw.as_mut() {
            if let Some(ring) = master_ring.as_mut() {
                hw.pump_from_ring(ring);
            } else {
                hw.reclaim_tx();
            }
            active_tx = hw.tx_inflight > 0;
        }

        // 4. Bounded sleep / channel wait (1 tick = ~1 ms when streaming, 20 ticks idle)
        let awaited = Signals::READABLE | Signals::PEER_CLOSED;
        let mut items = [WaitItem::new(bootstrap.handle().raw(), awaited, 0); 2];
        let mut count = 1usize;
        if let Some(ch) = client_ch.as_ref() {
            items[count] = WaitItem::new(ch.handle().raw(), awaited, 1);
            count += 1;
        }
        let wait_ticks = if active_tx || master_ring.is_some() {
            2
        } else {
            25
        };
        if let Err(err) = wait_any(&items[..count], wait_ticks) {
            if err != ErrorCode::TimedOut {
                libcanvas::system::sleep_ms(5);
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libcanvas::debug::write_str("[driver-host:snd] PANIC\n");
    libcanvas::process::exit(-98);
}
