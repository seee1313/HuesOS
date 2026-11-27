//! `/services/audio.elf` — capability-isolated multi-stream 48 kHz PCM mixer
//! (`HARB` v1 lock-free SPSC shared-memory VMOs), `VirtIO-Sound` 1.2 client
//! (`HSND`), and Bluetooth Classic `A2DP` Source (`AVDTP 1.3`, real-time `SBC`
//! subband encoder, adaptive bitpool, and `AVRCP` Absolute Volume/Pass-Through)
//! running over `/net/btl` L2CAP channels (`HAUD` v1).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use huesos_abi::audio::{
    self, AudioOp, AudioRouteMode, AudioStatus, AudioStatusSnapshot, SndDriverOp,
    MAX_SINK_NAME_LEN, SND_DRIVER_MAGIC, VERSION as AUDIO_ABI_VERSION,
};
use huesos_abi::btl::{self, BtlOp, BtlPeerInfo, BtlStatus, MAX_L2CAP_IPC_PAYLOAD};
use huesos_audio::avdtp_avrcp::{
    AvdtpAction, AvdtpSourceSession, AvdtpState, AvrcpButton, AvrcpEvent, AvrcpSession, PSM_AVCTP,
    PSM_AVDTP,
};
use huesos_audio::mixer::{finalize_mix_buffer, generate_stereo_tone, LinearResampler};
use huesos_audio::ring::{
    init_ring, load_header, ring_pop_stereo_i16, ring_push_stereo_i16, RingBacking,
    DEFAULT_RING_FRAMES, DEFAULT_RING_VMO_BYTES, HARB_FLAG_EOS, HARB_FLAG_MUTED,
};
use huesos_audio::sbc::{
    AdaptiveBitpool, RtpSbcPacketizer, SbcConfig, SbcEncoder, SBC_MAX_FRAME_BYTES,
    SBC_MAX_PCM_FRAMES,
};
use libcanvas::{println, rights, wait_any, Channel, ErrorCode, Handle, Signals, Vmo, WaitItem};

#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

const MAX_CLIENTS: usize = 16;
const MAX_MIX_STREAMS: usize = 8;
const MIX_SAMPLE_RATE_HZ: u32 = 48_000;
const MIX_QUANTUM_FRAMES: usize = 512; // 4 * 128 SBC frames (~10.67 ms at 48 kHz)
const UUID_AUDIO_SINK: u16 = 0x110B;

// ============================================================================
// `RingBacking` Adapter over `libcanvas::Vmo`
// ============================================================================

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

fn monotonic_us() -> u64 {
    libcanvas::system::monotonic_ns()
        .map(|ns| ns / 1_000)
        .unwrap_or_else(|_| {
            libcanvas::system::monotonic_ticks()
                .unwrap_or(0)
                .saturating_mul(10_000)
        })
}

fn monotonic_ms() -> u64 {
    monotonic_us() / 1_000
}

// ============================================================================
// `HSND` (`driver-host-snd`) Client Helpers
// ============================================================================

#[derive(Clone, Copy)]
struct SndHwInfo {
    online: bool,
    sample_rate_hz: u32,
    completed_periods: u64,
}

fn snd_rpc(
    ch: &Channel,
    op: SndDriverOp,
    payload: &[u8],
    attach_handle: Option<Handle>,
    out: &mut [u8],
) -> Option<usize> {
    if 8 + payload.len() > 64 {
        return None;
    }
    let mut req = [0u8; 64];
    req[0..4].copy_from_slice(&SND_DRIVER_MAGIC.to_le_bytes());
    req[4..6].copy_from_slice(&AUDIO_ABI_VERSION.to_le_bytes());
    req[6] = op as u8;
    req[7] = 0;
    req[8..8 + payload.len()].copy_from_slice(payload);
    if let Some(h) = attach_handle {
        ch.write_handle(&req[..8 + payload.len()], h).ok()?;
    } else {
        ch.write(&req[..8 + payload.len()]).ok()?;
    }

    let items = [WaitItem::new(
        ch.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];
    let deadline = monotonic_ms().saturating_add(250);
    for _budget in 0..128u32 {
        match ch.read_into(out) {
            Ok(n) if n >= 8 => {
                let magic = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
                let ver = u16::from_le_bytes([out[4], out[5]]);
                if magic == SND_DRIVER_MAGIC && ver == AUDIO_ABI_VERSION && out[6] == op as u8 {
                    return Some(n);
                }
            }
            Ok(_) => return None,
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                if monotonic_ms() >= deadline {
                    return None;
                }
                let _ = wait_any(&items, 1);
            }
            Err(_) => return None,
        }
    }
    None
}

fn snd_query_hw(ch: &Channel) -> Option<SndHwInfo> {
    let mut rep = [0u8; 32];
    let n = snd_rpc(ch, SndDriverOp::QueryHw, &[], None, &mut rep)?;
    if n < 24 || rep[7] != 0 || rep[8] == 0 {
        return Some(SndHwInfo {
            online: false,
            sample_rate_hz: MIX_SAMPLE_RATE_HZ,
            completed_periods: 0,
        });
    }
    let sr = u32::from_le_bytes([rep[12], rep[13], rep[14], rep[15]]);
    let periods = u64::from_le_bytes([
        rep[16], rep[17], rep[18], rep[19], rep[20], rep[21], rep[22], rep[23],
    ]);
    Some(SndHwInfo {
        online: true,
        sample_rate_hz: if sr >= 8_000 { sr } else { MIX_SAMPLE_RATE_HZ },
        completed_periods: periods,
    })
}

// ============================================================================
// `/net/btl` (`HBTL`) L2CAP Transport Client Helpers
// ============================================================================

fn btl_rpc(
    ch: &Channel,
    op: BtlOp,
    payload: &[u8],
    timeout_ms: u64,
    out: &mut [u8],
) -> Result<usize, BtlStatus> {
    if 8 + payload.len() > 1100 {
        return Err(BtlStatus::InvalidRequest);
    }
    let mut req = [0u8; 1100];
    btl::write_header(&mut req, op, BtlStatus::Ok);
    req[8..8 + payload.len()].copy_from_slice(payload);
    if ch.write(&req[..8 + payload.len()]).is_err() {
        return Err(BtlStatus::HardwareAbsent);
    }

    let items = [WaitItem::new(
        ch.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];
    let deadline = monotonic_ms().saturating_add(timeout_ms);
    for _budget in 0..2048u32 {
        match ch.read_into(out) {
            Ok(n) => {
                let st = btl::check_header(&out[..n], op)?;
                if st == BtlStatus::Ok {
                    return Ok(n);
                }
                return Err(st);
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                if monotonic_ms() >= deadline {
                    return Err(BtlStatus::WouldBlock);
                }
                let _ = wait_any(&items, 1);
            }
            Err(_) => return Err(BtlStatus::HardwareAbsent),
        }
    }
    Err(BtlStatus::WouldBlock)
}

fn btl_l2cap_connect(ch: &Channel, bd_addr: [u8; 6], psm: u16) -> Result<(u16, u16), BtlStatus> {
    let mut payload = [0u8; 8];
    payload[0..6].copy_from_slice(&bd_addr);
    payload[6..8].copy_from_slice(&psm.to_le_bytes());
    let mut rep = [0u8; 32];
    let n = btl_rpc(ch, BtlOp::L2capConnect, &payload, 8_500, &mut rep)?;
    if n < 16 {
        return Err(BtlStatus::InvalidRequest);
    }
    let cid = u16::from_le_bytes([rep[8], rep[9]]);
    let mtu = u16::from_le_bytes([rep[10], rep[11]]);
    Ok((cid, mtu))
}

fn btl_l2cap_send(ch: &Channel, cid: u16, sdu: &[u8]) -> Result<(u16, u8), BtlStatus> {
    if sdu.len() > MAX_L2CAP_IPC_PAYLOAD {
        return Err(BtlStatus::InvalidRequest);
    }
    let mut payload = [0u8; 4 + MAX_L2CAP_IPC_PAYLOAD];
    payload[0..2].copy_from_slice(&cid.to_le_bytes());
    payload[2..4].copy_from_slice(&(sdu.len() as u16).to_le_bytes());
    payload[4..4 + sdu.len()].copy_from_slice(sdu);
    let mut rep = [0u8; 32];
    let n = btl_rpc(ch, BtlOp::L2capSend, &payload[..4 + sdu.len()], 300, &mut rep)?;
    if n < 12 {
        return Err(BtlStatus::InvalidRequest);
    }
    let avail = u16::from_le_bytes([rep[8], rep[9]]);
    let cong = rep[10];
    Ok((avail, cong))
}

fn btl_l2cap_recv(ch: &Channel, cid: u16, out_sdu: &mut [u8]) -> Result<usize, BtlStatus> {
    let max_want = out_sdu.len().min(MAX_L2CAP_IPC_PAYLOAD) as u16;
    let mut payload = [0u8; 4];
    payload[0..2].copy_from_slice(&cid.to_le_bytes());
    payload[2..4].copy_from_slice(&max_want.to_le_bytes());
    let mut rep = [0u8; 1100];
    let n = btl_rpc(ch, BtlOp::L2capRecv, &payload, 50, &mut rep)?;
    if n < 12 {
        return Err(BtlStatus::InvalidRequest);
    }
    let dlen = usize::from(u16::from_le_bytes([rep[8], rep[9]])).min(out_sdu.len());
    if n < 12 + dlen {
        return Err(BtlStatus::InvalidRequest);
    }
    out_sdu[..dlen].copy_from_slice(&rep[12..12 + dlen]);
    Ok(dlen)
}

fn btl_l2cap_close(ch: &Channel, cid: u16) {
    let mut rep = [0u8; 16];
    let _ = btl_rpc(ch, BtlOp::L2capClose, &cid.to_le_bytes(), 200, &mut rep);
}

fn btl_set_coex_hint(ch: &Channel, streaming: bool) {
    let mut rep = [0u8; 16];
    let _ = btl_rpc(
        ch,
        BtlOp::SetCoexHint,
        &[u8::from(streaming)],
        200,
        &mut rep,
    );
}

// ============================================================================
// Runtime Data Structures
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClientPerm {
    ReadOnly,
    ReadWrite,
    Admin,
}

impl ClientPerm {
    const fn allows(self, op: AudioOp) -> bool {
        if op.requires_admin() {
            matches!(self, Self::Admin)
        } else if op.requires_rw() {
            matches!(self, Self::ReadWrite | Self::Admin)
        } else {
            true
        }
    }
}

struct AudioClientConn {
    id: u32,
    ch: Channel,
    perm: ClientPerm,
    disconnected: bool,
}

struct MixerStreamSlot {
    stream_id: u32,
    owner_client_id: u32,
    owner_disconnected: bool,
    ring: VmoRingStore,
    resampler: LinearResampler,
}

struct ActiveBtlA2dpSink {
    peer_addr: [u8; 6],
    peer_name: [u8; MAX_SINK_NAME_LEN],
    peer_name_len: u8,
    sig_cid: u16,
    media_cid: u16,
    media_mtu: u16,
    avctp_cid: Option<u16>,
    avdtp: AvdtpSourceSession,
    avrcp: AvrcpSession,
    encoder: SbcEncoder,
    bitpool_ctrl: AdaptiveBitpool,
    rtp: RtpSbcPacketizer,
    pcm_fifo: VecDeque<[i16; 2]>,
}

struct AudioRuntime {
    snd_ch: Option<Channel>,
    btl_ch: Option<Channel>,

    virtio_online: bool,
    virtio_running: bool,
    virtio_periods: u64,
    master_ring: Option<VmoRingStore>,

    master_volume_pct: u8,
    muted: bool,
    route_mode: AudioRouteMode,
    mix_sample_rate: u32,

    streams: Vec<MixerStreamSlot>,
    next_stream_id: u32,
    tone_samples: VecDeque<[i16; 2]>,

    btl_sink: Option<ActiveBtlA2dpSink>,
    avrcp_events: u16,
    last_avrcp_op: u8,
    mixed_frames: u64,
    btl_rtp_packets: u64,
    underruns: u32,

    next_mix_us: u64,
    last_hw_poll_ms: u64,
}

impl AudioRuntime {
    fn new() -> Self {
        Self {
            snd_ch: None,
            btl_ch: None,
            virtio_online: false,
            virtio_running: false,
            virtio_periods: 0,
            master_ring: None,
            master_volume_pct: 80,
            muted: false,
            route_mode: AudioRouteMode::Auto,
            mix_sample_rate: MIX_SAMPLE_RATE_HZ,
            streams: Vec::new(),
            next_stream_id: 1,
            tone_samples: VecDeque::new(),
            btl_sink: None,
            avrcp_events: 0,
            last_avrcp_op: 0,
            mixed_frames: 0,
            btl_rtp_packets: 0,
            underruns: 0,
            next_mix_us: 0,
            last_hw_poll_ms: 0,
        }
    }

    fn attach_snd_driver(&mut self, ch: Channel) {
        if let Some(info) = snd_query_hw(&ch) {
            self.virtio_online = info.online;
            self.virtio_periods = info.completed_periods;
            if info.online {
                self.mix_sample_rate = info.sample_rate_hz;
                if self.master_ring.is_none() {
                    if let Ok(vmo) = Vmo::create(DEFAULT_RING_VMO_BYTES) {
                        let mut store = VmoRingStore { vmo };
                        if init_ring(&mut store, self.mix_sample_rate, DEFAULT_RING_FRAMES) {
                            self.master_ring = Some(store);
                        }
                    }
                }
                if let Some(ring) = self.master_ring.as_ref() {
                    if let Ok(dup) = ring.vmo.duplicate(
                        rights::READ | rights::WRITE | rights::DUPLICATE | rights::TRANSFER,
                    ) {
                        let mut rep = [0u8; 16];
                        let _ = snd_rpc(
                            &ch,
                            SndDriverOp::AttachMasterRing,
                            &[],
                            Some(dup.into_handle()),
                            &mut rep,
                        );
                    }
                }
            }
        }
        self.snd_ch = Some(ch);
        self.sync_virtio_running();
    }

    fn want_btl_sink(&self) -> bool {
        let streaming = self
            .btl_sink
            .as_ref()
            .is_some_and(|s| s.avdtp.state() == AvdtpState::Streaming);
        streaming
            && matches!(
                self.route_mode,
                AudioRouteMode::Auto | AudioRouteMode::BtlOnly | AudioRouteMode::Mirror
            )
    }

    fn want_virtio_sink(&self) -> bool {
        if !self.virtio_online {
            return false;
        }
        match self.route_mode {
            AudioRouteMode::VirtioOnly | AudioRouteMode::Mirror => true,
            AudioRouteMode::Auto => !self.want_btl_sink(),
            AudioRouteMode::BtlOnly => false,
        }
    }

    fn active_sinks_mask(&self) -> u8 {
        let mut mask = 0u8;
        if self.want_virtio_sink() {
            mask |= 0x01;
        }
        if self.want_btl_sink() {
            mask |= 0x02;
        }
        mask
    }

    fn sync_virtio_running(&mut self) {
        let has_audio_sources = !self.streams.is_empty() || !self.tone_samples.is_empty();
        let should_run = self.want_virtio_sink() && has_audio_sources;
        if should_run == self.virtio_running {
            return;
        }
        if let Some(ch) = self.snd_ch.as_ref() {
            let mut rep = [0u8; 16];
            if snd_rpc(
                ch,
                SndDriverOp::SetRunning,
                &[u8::from(should_run)],
                None,
                &mut rep,
            )
            .is_some()
            {
                self.virtio_running = should_run;
            }
        }
    }

    fn refresh_snd_telemetry(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_hw_poll_ms) < 50 {
            return;
        }
        self.last_hw_poll_ms = now_ms;
        if let Some(ch) = self.snd_ch.as_ref() {
            if let Some(info) = snd_query_hw(ch) {
                self.virtio_online = info.online;
                self.virtio_periods = info.completed_periods;
            }
        }
    }

    fn lookup_btl_peer(&self, target_addr: [u8; 6]) -> Option<([u8; 6], [u8; MAX_SINK_NAME_LEN], u8)> {
        let ch = self.btl_ch.as_ref()?;
        let mut rep = [0u8; 1100];
        let n = btl_rpc(ch, BtlOp::ListPeers, &[], 500, &mut rep).ok()?;
        if n < 12 {
            return None;
        }
        let count = usize::from(rep[8]);
        let want_any = target_addr == [0; 6];
        for i in 0..count {
            let off = 12 + i * BtlPeerInfo::WIRE_LEN;
            if off + BtlPeerInfo::WIRE_LEN > n {
                break;
            }
            if let Some(peer) = BtlPeerInfo::decode(&rep[off..off + BtlPeerInfo::WIRE_LEN]) {
                if (want_any && peer.is_audio_sink()) || (!want_any && peer.bd_addr == target_addr) {
                    let mut name = [0u8; MAX_SINK_NAME_LEN];
                    let take = usize::from(peer.name_len).min(MAX_SINK_NAME_LEN);
                    name[..take].copy_from_slice(&peer.name[..take]);
                    return Some((peer.bd_addr, name, take as u8));
                }
            }
        }
        if want_any {
            None
        } else {
            Some((target_addr, [0u8; MAX_SINK_NAME_LEN], 0))
        }
    }

    fn connect_btl_a2dp(&mut self, requested_addr: [u8; 6]) -> Result<(), AudioStatus> {
        self.disconnect_btl_a2dp();
        let Some((peer_addr, peer_name, peer_name_len)) = self.lookup_btl_peer(requested_addr)
        else {
            return Err(AudioStatus::SinkUnavailable);
        };
        let Some(btl_ch) = self.btl_ch.as_ref() else {
            return Err(AudioStatus::SinkUnavailable);
        };

        // Best-effort SDP check for AudioSink (`0x110B`)
        let mut sdp_req = [0u8; 8];
        sdp_req[0..6].copy_from_slice(&peer_addr);
        sdp_req[6..8].copy_from_slice(&UUID_AUDIO_SINK.to_le_bytes());
        let mut sdp_rep = [0u8; 1100];
        let _ = btl_rpc(btl_ch, BtlOp::SdpQuery, &sdp_req, 2_500, &mut sdp_rep);

        // Open AVDTP signaling L2CAP channel (`PSM 0x0019`)
        let Ok((sig_cid, _sig_mtu)) = btl_l2cap_connect(btl_ch, peer_addr, PSM_AVDTP) else {
            return Err(AudioStatus::SinkUnavailable);
        };

        let mut avdtp = AvdtpSourceSession::new();
        let mut media_cid: Option<u16> = None;
        let mut media_mtu: u16 = 672;
        let mut negotiated_cfg: Option<SbcConfig> = None;

        let mut pending_action = avdtp.start_discovery();
        let deadline = monotonic_ms().saturating_add(4_000);

        for _budget in 0..512u32 {
            match pending_action {
                AvdtpAction::SendSignaling { len, buf } => {
                    if btl_l2cap_send(btl_ch, sig_cid, &buf[..len]).is_err() {
                        break;
                    }
                    pending_action = AvdtpAction::None;
                }
                AvdtpAction::OpenMediaL2capChannel => {
                    match btl_l2cap_connect(btl_ch, peer_addr, PSM_AVDTP) {
                        Ok((mcid, mmtu)) => {
                            media_cid = Some(mcid);
                            media_mtu = mmtu.max(335);
                            pending_action = avdtp.on_media_channel_opened();
                            continue;
                        }
                        Err(_) => break,
                    }
                }
                AvdtpAction::StreamReady(cfg) => {
                    negotiated_cfg = Some(cfg);
                    break;
                }
                AvdtpAction::StreamClosed | AvdtpAction::StreamSuspended => break,
                AvdtpAction::None => {}
            }

            if matches!(avdtp.state(), AvdtpState::Failed(_)) || monotonic_ms() >= deadline {
                break;
            }

            let mut rx_pdu = [0u8; 256];
            match btl_l2cap_recv(btl_ch, sig_cid, &mut rx_pdu) {
                Ok(n) if n > 0 => {
                    pending_action = avdtp.on_signaling_pdu(&rx_pdu[..n]);
                }
                Ok(_) | Err(BtlStatus::WouldBlock) => {
                    libcanvas::system::sleep_ms(4);
                }
                Err(_) => break,
            }
        }

        let (Some(mcid), Some(sbc_cfg)) = (media_cid, negotiated_cfg) else {
            if let Some(mcid) = media_cid {
                btl_l2cap_close(btl_ch, mcid);
            }
            btl_l2cap_close(btl_ch, sig_cid);
            return Err(AudioStatus::A2dpFailed);
        };

        // Best-effort AVRCP control channel (`PSM 0x0017`)
        let mut avrcp = AvrcpSession::new();
        let avctp_cid = btl_l2cap_connect(btl_ch, peer_addr, PSM_AVCTP)
            .ok()
            .map(|(cid, _)| cid);
        if let Some(acid) = avctp_cid {
            let vol_127 = ((u16::from(self.master_volume_pct.min(100)) * 127) / 100) as u8;
            let (pdu, len) = avrcp.encode_set_absolute_volume(vol_127);
            let _ = btl_l2cap_send(btl_ch, acid, &pdu[..len]);
        }

        btl_set_coex_hint(btl_ch, true);

        let initial_bp = sbc_cfg.bitpool.clamp(2, 53);
        let min_bp = 28u8.min(initial_bp);
        self.btl_sink = Some(ActiveBtlA2dpSink {
            peer_addr,
            peer_name,
            peer_name_len,
            sig_cid,
            media_cid: mcid,
            media_mtu,
            avctp_cid,
            avdtp,
            avrcp,
            encoder: SbcEncoder::new(sbc_cfg),
            bitpool_ctrl: AdaptiveBitpool::new(min_bp, initial_bp, initial_bp),
            rtp: RtpSbcPacketizer::new(0x4855_4553),
            pcm_fifo: VecDeque::with_capacity(2048),
        });
        self.sync_virtio_running();
        println!(
            "[audio-service] A2DP streaming active (bitpool={}, mtu={})",
            initial_bp, media_mtu
        );
        Ok(())
    }

    fn disconnect_btl_a2dp(&mut self) {
        let Some(sink) = self.btl_sink.take() else {
            return;
        };
        if let Some(btl_ch) = self.btl_ch.as_ref() {
            btl_set_coex_hint(btl_ch, false);
            if let Some(acid) = sink.avctp_cid {
                btl_l2cap_close(btl_ch, acid);
            }
            btl_l2cap_close(btl_ch, sink.media_cid);
            btl_l2cap_close(btl_ch, sink.sig_cid);
        }
        self.sync_virtio_running();
    }

    fn poll_btl_control_channels(&mut self) {
        let (Some(btl_ch), Some(sink)) = (self.btl_ch.as_ref(), self.btl_sink.as_mut()) else {
            return;
        };
        let mut drop_sink = false;
        let mut rx_buf = [0u8; 256];

        // 1. Poll AVDTP signaling channel (`PSM 0x0019`)
        for _budget in 0..4u32 {
            match btl_l2cap_recv(btl_ch, sink.sig_cid, &mut rx_buf) {
                Ok(n) if n > 0 => match sink.avdtp.on_signaling_pdu(&rx_buf[..n]) {
                    AvdtpAction::SendSignaling { len, buf } => {
                        let _ = btl_l2cap_send(btl_ch, sink.sig_cid, &buf[..len]);
                    }
                    AvdtpAction::StreamClosed => {
                        drop_sink = true;
                        break;
                    }
                    _ => {}
                },
                Ok(_) | Err(BtlStatus::WouldBlock) => break,
                Err(BtlStatus::ChannelClosed) | Err(BtlStatus::HardwareAbsent) => {
                    drop_sink = true;
                    break;
                }
                Err(_) => break,
            }
        }

        // 2. Poll AVRCP (`PSM 0x0017`) for headphone volume/media buttons
        if !drop_sink {
            if let Some(acid) = sink.avctp_cid {
                for _budget in 0..4u32 {
                    match btl_l2cap_recv(btl_ch, acid, &mut rx_buf) {
                        Ok(n) if n > 0 => {
                            let outcome = sink.avrcp.on_avctp_pdu(&rx_buf[..n]);
                            if outcome.reply_len > 0 {
                                let _ = btl_l2cap_send(
                                    btl_ch,
                                    acid,
                                    &outcome.reply[..outcome.reply_len],
                                );
                            }
                            match outcome.event {
                                AvrcpEvent::ButtonPressed(btn) => {
                                    self.avrcp_events = self.avrcp_events.saturating_add(1);
                                    match btn {
                                        AvrcpButton::VolumeUp => {
                                            self.last_avrcp_op = 0x41;
                                            self.master_volume_pct =
                                                (self.master_volume_pct.saturating_add(5)).min(100);
                                        }
                                        AvrcpButton::VolumeDown => {
                                            self.last_avrcp_op = 0x42;
                                            self.master_volume_pct =
                                                self.master_volume_pct.saturating_sub(5);
                                        }
                                        AvrcpButton::Mute => {
                                            self.last_avrcp_op = 0x43;
                                            self.muted = !self.muted;
                                        }
                                        AvrcpButton::Play => self.last_avrcp_op = 0x44,
                                        AvrcpButton::Stop => self.last_avrcp_op = 0x45,
                                        AvrcpButton::Pause => self.last_avrcp_op = 0x46,
                                        AvrcpButton::NextTrack => self.last_avrcp_op = 0x4B,
                                        AvrcpButton::PrevTrack => self.last_avrcp_op = 0x4C,
                                        AvrcpButton::Unknown(code) => self.last_avrcp_op = code,
                                    }
                                }
                                AvrcpEvent::RemoteVolumeChanged(vol_127) => {
                                    self.avrcp_events = self.avrcp_events.saturating_add(1);
                                    self.last_avrcp_op = 0x50;
                                    self.master_volume_pct =
                                        ((u16::from(vol_127.min(127)) * 100 + 63) / 127) as u8;
                                }
                                AvrcpEvent::ButtonReleased(_) | AvrcpEvent::None => {}
                            }
                        }
                        Ok(_) | Err(BtlStatus::WouldBlock) => break,
                        Err(BtlStatus::ChannelClosed) => {
                            sink.avctp_cid = None;
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        if drop_sink {
            self.disconnect_btl_a2dp();
        }
    }

    fn pump_mixer(&mut self, now_us: u64) -> bool {
        let has_work = !self.streams.is_empty() || !self.tone_samples.is_empty();
        if !has_work {
            self.next_mix_us = 0;
            self.sync_virtio_running();
            return false;
        }
        self.sync_virtio_running();

        if self.next_mix_us == 0 {
            self.next_mix_us = now_us;
        }
        if now_us < self.next_mix_us {
            return false;
        }
        let quantum_us =
            (MIX_QUANTUM_FRAMES as u64 * 1_000_000) / u64::from(self.mix_sample_rate.max(8_000));
        self.next_mix_us = self.next_mix_us.saturating_add(quantum_us);
        if now_us > self.next_mix_us.saturating_add(quantum_us * 4) {
            self.next_mix_us = now_us;
        }

        let mut accum_i32 = [0i32; MIX_QUANTUM_FRAMES * 2];
        let mut raw_in = [0i16; MIX_QUANTUM_FRAMES * 4];
        let mut any_samples = false;

        for slot in &mut self.streams {
            let Some(hdr) = load_header(&slot.ring) else {
                continue;
            };
            slot.resampler.set_rates(hdr.sample_rate, self.mix_sample_rate);
            // Pull proportional number of input frames for this quantum
            let want_in = (((MIX_QUANTUM_FRAMES as u64) * u64::from(hdr.sample_rate))
                / u64::from(self.mix_sample_rate.max(8_000)))
            .clamp(1, (MIX_QUANTUM_FRAMES * 2) as u64) as usize;
            let got_in = ring_pop_stereo_i16(&mut slot.ring, &mut raw_in[..want_in * 2]);
            if got_in > 0 {
                any_samples = true;
                if (hdr.flags & HARB_FLAG_MUTED) == 0 {
                    let _ = slot.resampler.resample_and_accumulate(
                        &raw_in[..got_in * 2],
                        hdr.volume_q8,
                        &mut accum_i32,
                    );
                }
            }
        }

        // Reap finished EOS streams or disconnected client streams once drained
        self.streams.retain(|slot| {
            let Some(hdr) = load_header(&slot.ring) else {
                return false;
            };
            let empty = hdr.available_read() == 0;
            if (hdr.flags & HARB_FLAG_EOS) != 0 && empty {
                return false;
            }
            if slot.owner_disconnected && empty {
                return false;
            }
            true
        });

        // Mix built-in stereo test tone
        if !self.tone_samples.is_empty() {
            any_samples = true;
            let take = MIX_QUANTUM_FRAMES.min(self.tone_samples.len());
            for i in 0..take {
                if let Some([l, r]) = self.tone_samples.pop_front() {
                    accum_i32[i * 2] = accum_i32[i * 2].saturating_add(i32::from(l));
                    accum_i32[i * 2 + 1] = accum_i32[i * 2 + 1].saturating_add(i32::from(r));
                }
            }
        }

        if !any_samples {
            return false;
        }

        let mut mixed_i16 = [0i16; MIX_QUANTUM_FRAMES * 2];
        finalize_mix_buffer(
            &accum_i32,
            self.master_volume_pct,
            self.muted,
            &mut mixed_i16,
        );
        self.mixed_frames = self.mixed_frames.saturating_add(MIX_QUANTUM_FRAMES as u64);

        let to_virtio = self.want_virtio_sink();
        let to_btl = self.want_btl_sink();

        if to_virtio {
            if let Some(ring) = self.master_ring.as_mut() {
                let pushed = ring_push_stereo_i16(ring, &mixed_i16);
                if pushed < MIX_QUANTUM_FRAMES {
                    self.underruns = self.underruns.saturating_add(1);
                }
            }
        }

        if to_btl {
            self.push_btl_sbc_frames(&mixed_i16);
        }

        true
    }

    fn push_btl_sbc_frames(&mut self, interleaved_pcm: &[i16]) {
        let (Some(btl_ch), Some(sink)) = (self.btl_ch.as_ref(), self.btl_sink.as_mut()) else {
            return;
        };
        for pair in interleaved_pcm.chunks_exact(2) {
            if sink.pcm_fifo.len() >= 4096 {
                let _ = sink.pcm_fifo.pop_front();
            }
            sink.pcm_fifo.push_back([pair[0], pair[1]]);
        }

        let cfg = sink.encoder.config();
        let pcm_per_sbc = cfg.pcm_frames_per_sbc_frame();
        let sbc_frame_bytes = cfg.frame_byte_len();
        let max_pack = RtpSbcPacketizer::max_frames_per_packet(
            sink.media_mtu.min(MAX_L2CAP_IPC_PAYLOAD as u16),
            sbc_frame_bytes,
        )
        .clamp(1, 5);

        let mut drop_sink = false;
        let mut sbc_concat = [0u8; SBC_MAX_FRAME_BYTES * 5];
        let mut rtp_pkt = [0u8; MAX_L2CAP_IPC_PAYLOAD];
        let mut pcm_block = [[0i16; 2]; SBC_MAX_PCM_FRAMES];

        for _budget in 0..4u32 {
            if sink.pcm_fifo.len() < pcm_per_sbc * max_pack {
                break;
            }
            let mut concat_len = 0usize;
            let mut encoded_count = 0u8;
            for _ in 0..max_pack {
                for slot in pcm_block.iter_mut().take(pcm_per_sbc) {
                    *slot = sink.pcm_fifo.pop_front().unwrap_or([0, 0]);
                }
                if let Ok(flen) = sink
                    .encoder
                    .encode_stereo_frame(&pcm_block[..pcm_per_sbc], &mut sbc_concat[concat_len..])
                {
                    concat_len += flen;
                    encoded_count += 1;
                }
            }
            if encoded_count == 0 {
                break;
            }
            let total_pcm = (usize::from(encoded_count) * pcm_per_sbc) as u32;
            let Ok(pkt_len) = sink.rtp.pack_media_packet(
                &sbc_concat[..concat_len],
                encoded_count,
                total_pcm,
                &mut rtp_pkt,
            ) else {
                break;
            };

            match btl_l2cap_send(btl_ch, sink.media_cid, &rtp_pkt[..pkt_len]) {
                Ok((avail_credits, congestion_pct)) => {
                    self.btl_rtp_packets = self.btl_rtp_packets.saturating_add(1);
                    // Derive synthetic `(in_flight, max_slots)` from `/net/btl` congestion telemetry
                    let max_slots = avail_credits.saturating_add(4).max(8);
                    let in_flight = ((u32::from(max_slots) * u32::from(congestion_pct)) / 100) as u16;
                    let next_bp = sink.bitpool_ctrl.observe_acl_load(in_flight, max_slots);
                    sink.encoder.set_bitpool(next_bp);
                }
                Err(BtlStatus::Congested) => {
                    self.underruns = self.underruns.saturating_add(1);
                    let next_bp = sink.bitpool_ctrl.observe_acl_load(8, 8);
                    sink.encoder.set_bitpool(next_bp);
                    break;
                }
                Err(BtlStatus::ChannelClosed) | Err(BtlStatus::HardwareAbsent) => {
                    drop_sink = true;
                    break;
                }
                Err(_) => break,
            }
        }

        if drop_sink {
            self.disconnect_btl_a2dp();
        }
    }

    fn handle_client_request(
        &mut self,
        client_id: u32,
        perm: ClientPerm,
        req: &[u8],
        rep: &mut [u8],
    ) -> (usize, Option<Handle>) {
        let Some((op, payload)) = audio::parse_request(req) else {
            audio::write_header(rep, AudioOp::Status, AudioStatus::InvalidRequest);
            return (8, None);
        };
        if !perm.allows(op) {
            audio::write_header(rep, op, AudioStatus::AccessDenied);
            return (8, None);
        }

        match op {
            AudioOp::Status => {
                let (btl_streaming, btl_bp, btl_kbps, peer_addr, peer_name, peer_name_len) =
                    if let Some(sink) = self.btl_sink.as_ref() {
                        let cfg = sink.encoder.config();
                        (
                            sink.avdtp.state() == AvdtpState::Streaming,
                            cfg.bitpool,
                            (cfg.bitrate_bps() / 1_000) as u16,
                            sink.peer_addr,
                            sink.peer_name,
                            sink.peer_name_len,
                        )
                    } else {
                        (false, 0, 0, [0; 6], [0; MAX_SINK_NAME_LEN], 0)
                    };

                let snap = AudioStatusSnapshot {
                    master_volume_pct: self.master_volume_pct,
                    muted: self.muted,
                    route_mode: self.route_mode,
                    active_sinks_mask: self.active_sinks_mask(),
                    virtio_online: self.virtio_online,
                    btl_streaming,
                    active_streams: self.streams.len() as u8,
                    btl_sbc_bitpool: btl_bp,
                    mix_sample_rate: self.mix_sample_rate,
                    btl_bitrate_kbps: btl_kbps,
                    avrcp_events: self.avrcp_events,
                    btl_peer_addr: peer_addr,
                    btl_peer_name_len: peer_name_len,
                    last_avrcp_op: self.last_avrcp_op,
                    mixed_frames: self.mixed_frames,
                    virtio_periods: self.virtio_periods,
                    btl_rtp_packets: self.btl_rtp_packets,
                    underruns: self.underruns,
                    btl_peer_name: peer_name,
                };
                let len = snap.encode_reply(rep).unwrap_or_else(|| {
                    audio::write_header(rep, op, AudioStatus::InvalidRequest);
                    8
                });
                (len, None)
            }
            AudioOp::OpenStream => {
                if self.streams.len() >= MAX_MIX_STREAMS {
                    audio::write_header(rep, op, AudioStatus::NoFreeStreams);
                    return (8, None);
                }
                let sample_rate = if payload.len() >= 4 {
                    u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
                        .clamp(8_000, 96_000)
                } else {
                    self.mix_sample_rate
                };
                let channels = payload.get(4).copied().unwrap_or(2).clamp(1, 2);

                let Ok(vmo) = Vmo::create(DEFAULT_RING_VMO_BYTES) else {
                    audio::write_header(rep, op, AudioStatus::NoFreeStreams);
                    return (8, None);
                };
                let mut store = VmoRingStore { vmo };
                if !init_ring(&mut store, sample_rate, DEFAULT_RING_FRAMES) {
                    audio::write_header(rep, op, AudioStatus::NoFreeStreams);
                    return (8, None);
                }
                let _ = store.write_at(6, &[channels]);

                let Ok(client_vmo) = store
                    .vmo
                    .duplicate(rights::READ | rights::WRITE | rights::DUPLICATE | rights::TRANSFER)
                else {
                    audio::write_header(rep, op, AudioStatus::NoFreeStreams);
                    return (8, None);
                };

                let sid = self.next_stream_id;
                self.next_stream_id = self.next_stream_id.wrapping_add(1).max(1);
                self.streams.push(MixerStreamSlot {
                    stream_id: sid,
                    owner_client_id: client_id,
                    owner_disconnected: false,
                    ring: store,
                    resampler: LinearResampler::new(sample_rate, self.mix_sample_rate),
                });
                self.sync_virtio_running();

                rep[..16].fill(0);
                audio::write_header(rep, op, AudioStatus::Ok);
                rep[8..12].copy_from_slice(&sid.to_le_bytes());
                rep[12..16].copy_from_slice(&DEFAULT_RING_FRAMES.to_le_bytes());
                (16, Some(client_vmo.into_handle()))
            }
            AudioOp::CloseStream => {
                if payload.len() < 4 {
                    audio::write_header(rep, op, AudioStatus::InvalidRequest);
                    return (8, None);
                }
                let sid = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                self.streams
                    .retain(|s| !(s.stream_id == sid && s.owner_client_id == client_id));
                self.sync_virtio_running();
                audio::write_header(rep, op, AudioStatus::Ok);
                (8, None)
            }
            AudioOp::SetVolume => {
                let Some(&vol) = payload.first() else {
                    audio::write_header(rep, op, AudioStatus::InvalidRequest);
                    return (8, None);
                };
                self.master_volume_pct = vol.min(100);
                if let Some(&mute_b) = payload.get(1) {
                    self.muted = mute_b != 0;
                }
                if let (Some(btl_ch), Some(sink)) = (self.btl_ch.as_ref(), self.btl_sink.as_mut()) {
                    if let Some(acid) = sink.avctp_cid {
                        let vol_127 =
                            ((u16::from(self.master_volume_pct) * 127 + 50) / 100) as u8;
                        let (pdu, len) = sink.avrcp.encode_set_absolute_volume(vol_127);
                        let _ = btl_l2cap_send(btl_ch, acid, &pdu[..len]);
                    }
                }
                audio::write_header(rep, op, AudioStatus::Ok);
                (8, None)
            }
            AudioOp::SetRouteMode => {
                let Some(mode) = payload.first().copied().and_then(AudioRouteMode::from_raw) else {
                    audio::write_header(rep, op, AudioStatus::InvalidRequest);
                    return (8, None);
                };
                self.route_mode = mode;
                self.sync_virtio_running();
                audio::write_header(rep, op, AudioStatus::Ok);
                (8, None)
            }
            AudioOp::ConnectBtlSink => {
                let mut addr = [0u8; 6];
                if payload.len() >= 6 {
                    addr.copy_from_slice(&payload[0..6]);
                }
                let st = match self.connect_btl_a2dp(addr) {
                    Ok(()) => AudioStatus::Ok,
                    Err(e) => e,
                };
                audio::write_header(rep, op, st);
                (8, None)
            }
            AudioOp::DisconnectBtlSink => {
                self.disconnect_btl_a2dp();
                audio::write_header(rep, op, AudioStatus::Ok);
                (8, None)
            }
            AudioOp::PlayTestTone => {
                let (freq_hz, duration_ms) = if payload.len() >= 4 {
                    let f = u16::from_le_bytes([payload[0], payload[1]]);
                    let d = u16::from_le_bytes([payload[2], payload[3]]);
                    (
                        u32::from(f).clamp(80, 12_000),
                        u32::from(d).clamp(20, 4_000),
                    )
                } else {
                    (440, 250)
                };
                let pcm = generate_stereo_tone(self.mix_sample_rate, freq_hz, duration_ms, 14_000);
                for pair in pcm.chunks_exact(2) {
                    if self.tone_samples.len() >= 192_000 {
                        break;
                    }
                    self.tone_samples.push_back([pair[0], pair[1]]);
                }
                self.sync_virtio_running();
                audio::write_header(rep, op, AudioStatus::Ok);
                (8, None)
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    if !HEAP.init_process_heap() {
        libcanvas::process::exit(-1);
    }
    run_service()
}

fn run_service() -> ! {
    let bootstrap = libcanvas::channel::bootstrap();
    let _ = bootstrap.write(b"service:audio:starting");

    let mut rt = AudioRuntime::new();
    let mut clients: Vec<Option<AudioClientConn>> = Vec::with_capacity(MAX_CLIENTS);
    let mut next_client_id: u32 = 1;

    let boot_deadline = monotonic_ms().saturating_add(40);
    for _budget in 0..32u32 {
        let mut buf = [0u8; 64];
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(h))) => {
                accept_bootstrap_handle(&mut rt, &mut clients, &mut next_client_id, &buf[..n], h);
            }
            Ok(_) => {}
            Err(ErrorCode::ShouldWait) => {
                if (rt.snd_ch.is_some() && rt.btl_ch.is_some()) || monotonic_ms() >= boot_deadline {
                    break;
                }
                libcanvas::process::yield_now();
            }
            Err(_) => break,
        }
    }

    let _ = bootstrap.write(b"service:audio:ready");
    println!(
        "[audio-service] ready (virtio_online={}, rate={}Hz)",
        rt.virtio_online, rt.mix_sample_rate
    );

    let mut req_buf = [0u8; 256];
    let mut rep_buf = [0u8; 128];

    loop {
        let now_us = monotonic_us();
        let now_ms = now_us / 1_000;
        let mut did_work = false;

        // 1. Accept runtime channels from DriverManager
        for _budget in 0..8u32 {
            let mut bmsg = [0u8; 64];
            match bootstrap.read_optional_handle(&mut bmsg) {
                Ok((n, Some(h))) => {
                    did_work = true;
                    accept_bootstrap_handle(
                        &mut rt,
                        &mut clients,
                        &mut next_client_id,
                        &bmsg[..n],
                        h,
                    );
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        // 2. Service HAUD client RPCs
        #[allow(clippy::needless_range_loop)]
        for idx in 0..clients.len() {
            let mut dead_id: Option<u32> = None;
            let mut got_len = 0usize;
            let mut cid = 0u32;
            let mut perm = ClientPerm::ReadOnly;

            if let Some(c) = clients[idx].as_ref() {
                cid = c.id;
                perm = c.perm;
                match c.ch.read_into(&mut req_buf) {
                    Ok(n) => got_len = n,
                    Err(ErrorCode::ShouldWait) => {}
                    Err(_) => dead_id = Some(c.id),
                }
            }
            if let Some(gone_id) = dead_id {
                clients[idx] = None;
                for slot in &mut rt.streams {
                    if slot.owner_client_id == gone_id {
                        slot.owner_disconnected = true;
                    }
                }
                continue;
            }
            if got_len == 0 {
                continue;
            }
            did_work = true;
            let (rep_len, maybe_h) =
                rt.handle_client_request(cid, perm, &req_buf[..got_len], &mut rep_buf);
            if let Some(c) = clients[idx].as_ref() {
                if let Some(h) = maybe_h {
                    let _ = c.ch.write_handle(&rep_buf[..rep_len], h);
                } else {
                    let _ = c.ch.write(&rep_buf[..rep_len]);
                }
            }
        }

        // 3. Poll Bluetooth AVDTP/AVRCP control channels + VirtIO telemetry + pump mixer
        rt.poll_btl_control_channels();
        rt.refresh_snd_telemetry(now_ms);
        if rt.pump_mixer(now_us) {
            did_work = true;
        }

        if did_work {
            continue;
        }

        let mut items = [WaitItem::new(0, Signals::NONE, 0); 24];
        items[0] = WaitItem::new(
            bootstrap.handle().raw(),
            Signals::READABLE | Signals::PEER_CLOSED,
            0,
        );
        let mut item_count = 1usize;
        for c in clients.iter().flatten() {
            if !c.disconnected && item_count < items.len() {
                items[item_count] = WaitItem::new(
                    c.ch.handle().raw(),
                    Signals::READABLE | Signals::PEER_CLOSED,
                    item_count as u64,
                );
                item_count += 1;
            }
        }
        let streaming_active =
            !rt.streams.is_empty() || !rt.tone_samples.is_empty() || rt.btl_sink.is_some();
        let timeout_ticks = if streaming_active { 1 } else { 15 };
        let _ = wait_any(&items[..item_count], timeout_ticks);
    }
}

fn accept_bootstrap_handle(
    rt: &mut AudioRuntime,
    clients: &mut Vec<Option<AudioClientConn>>,
    next_client_id: &mut u32,
    tag: &[u8],
    handle: Handle,
) {
    if tag == b"snd-driver" {
        rt.attach_snd_driver(Channel::from_handle(handle));
    } else if tag == b"btl-transport" {
        rt.btl_ch = Some(Channel::from_handle(handle));
    } else if tag == b"audio-client:ro"
        || tag == b"audio-client:rw"
        || tag == b"audio-client"
        || tag == b"audio-client:admin"
    {
        let perm = if tag == b"audio-client:ro" {
            ClientPerm::ReadOnly
        } else if tag == b"audio-client:rw" {
            ClientPerm::ReadWrite
        } else {
            ClientPerm::Admin
        };
        let id = *next_client_id;
        *next_client_id = next_client_id.wrapping_add(1).max(1);
        let conn = AudioClientConn {
            id,
            ch: Channel::from_handle(handle),
            perm,
            disconnected: false,
        };
        if let Some(slot) = clients.iter_mut().find(|s| s.is_none()) {
            *slot = Some(conn);
        } else if clients.len() < MAX_CLIENTS {
            clients.push(Some(conn));
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::process::exit(-99);
}
