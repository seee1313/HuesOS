//! `/services/btl.elf` — isolated Plan 9 `/net/btl` Bluetooth Classic (`HCI`,
//! Realtek `RTL8821CE` `btrtl` firmware uploader, `SSP` Just-Works pairing,
//! `L2CAP` multiplexer, `SDP` server/client, `btsnoop` capture, and `RTL8821CE`
//! 2.4 GHz PTA Wi-Fi coexistence) transport service speaking `HBTL` v1.
//!
//! Secret isolation guarantee: 128-bit Bluetooth Classic `LinkKey`s reside
//! exclusively in this process's address space (persisted atomically as
//! `/etc/btl/link_keys.bin` via capability-isolated `HxFS` with transparent RAM
//! fallback) and are never serialized over IPC; `/net/btl/keys` (`ListKeys`)
//! exposes only 4-byte SHA-256 fingerprints.

#![no_std]
#![no_main]
#![allow(
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::manual_range_contains,
    clippy::large_enum_variant,
    clippy::type_complexity,
    clippy::collapsible_if,
    clippy::collapsible_else_if,
    clippy::collapsible_match,
    clippy::vec_init_then_push,
    clippy::int_plus_one,
    clippy::single_match
)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use huesos_abi::btl::{
    self, BtlKeySummary, BtlOp, BtlPeerInfo, BtlStatus, BtlStatusSnapshot, BtlTransportKind,
    UsbBtOp, MAX_KEY_SUMMARIES, MAX_L2CAP_IPC_PAYLOAD, MAX_PEERS, MAX_PEER_NAME_LEN, USB_BT_MAGIC,
    VERSION as BTL_ABI_VERSION,
};
use huesos_abi::wlan::{self, BtCoexProfile, WlanOp, WlanStatus};
use huesos_bt::btrtl::{
    cmd_read_rom_version, is_rtl8821ce_usb_id, parse_and_assemble_rtl8821c,
    parse_rom_version_return, LMP_SUBVER_8821C, OP_RTL_DOWNLOAD, OP_RTL_READ_ROM_VERSION,
    REALTEK_MANUFACTURER_ID,
};
use huesos_bt::hci::{
    cmd_accept_connection, cmd_authentication_requested, cmd_create_connection, cmd_disconnect,
    cmd_inquiry_giac, cmd_io_capability_reply_just_works, cmd_link_key_neg_reply,
    cmd_link_key_reply, cmd_pin_code_reply, cmd_read_bd_addr, cmd_read_buffer_size,
    cmd_read_local_version, cmd_remote_name_request, cmd_reset, cmd_set_encryption,
    cmd_set_event_mask_ssp, cmd_user_confirmation_reply, cmd_write_class_of_device,
    cmd_write_default_link_policy, cmd_write_inquiry_mode, cmd_write_local_name,
    cmd_write_page_timeout, cmd_write_scan_enable, cmd_write_simple_pairing_mode, decode_event,
    parse_buffer_size_return, parse_local_version_return, segment_l2cap_to_acl, AclCreditTracker,
    AclReassembler, BdAddr, DecodedHciEvent, DiscoveredPeer, LinkKey, H4_ACL, H4_CMD, H4_EVT,
    LOCAL_COD_COMPUTER_AUDIO_SOURCE, OP_READ_BD_ADDR, OP_READ_BUFFER_SIZE, OP_READ_LOCAL_VERSION,
};
use huesos_bt::l2cap::{L2capEngine, L2capEvent, PSM_AVCTP, PSM_AVDTP, PSM_SDP};
use huesos_bt::sdp::{
    handle_sdp_request, parse_audio_sink_response, SDP_SVC_SEARCH_ATTR_REQ,
    SDP_SVC_SEARCH_ATTR_RSP, UUID_AUDIO_SINK, UUID_AV_REMOTE, UUID_AV_REMOTE_CONTROLLER,
    UUID_AV_REMOTE_TARGET,
};
use huesos_bt::snoop::{BtSnoopLog, SnoopDir};
use huesos_bt::virtual_bt::VirtualBtMedium;
use libcanvas::{println, wait_any, Channel, ErrorCode, Hxfs, Signals, Vmo, WaitItem};

#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";
const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;

const RTL_FW_PATH: &str = "/lib/firmware/rtl_bt/rtl8821c_fw.bin";
const RTL_CFG_PATH: &str = "/lib/firmware/rtl_bt/rtl8821c_config.bin";

const KEYS_DIR_ETC: &str = "/etc";
const KEYS_DIR_BTL: &str = "/etc/btl";
const KEYS_PATH: &str = "/etc/btl/link_keys.bin";
const KEYS_TMP_PATH: &str = "/etc/btl/link_keys.tmp";
const KEYS_MAGIC: &[u8; 8] = b"HBTLK001";
const KEY_RECORD_BYTES: usize = 28; // bd_addr(6) + key_type(1) + pad(1) + fp(4) + key(16)

const MAX_CLIENTS: usize = 16;
const MAX_RX_QUEUE_PER_CID: usize = 32;
const MAX_ACCEPT_QUEUE_PER_PSM: usize = 8;

// ============================================================================
// Pure-Rust FIPS 180-4 SHA-256 (for non-secret 4-byte Link Key Fingerprints)
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let b = i * 4;
        w[i] = u32::from_be_bytes([block[b], block[b + 1], block[b + 2], block[b + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut block = [0u8; 64];
    let mut filled = 0usize;
    let mut total_bytes = 0u64;

    for part in parts {
        for &byte in *part {
            block[filled] = byte;
            filled += 1;
            total_bytes = total_bytes.wrapping_add(1);
            if filled == 64 {
                sha256_compress(&mut state, &block);
                filled = 0;
            }
        }
    }

    block[filled] = 0x80;
    filled += 1;
    if filled > 56 {
        block[filled..64].fill(0);
        sha256_compress(&mut state, &block);
        filled = 0;
    }
    block[filled..56].fill(0);
    let bit_len = total_bytes.wrapping_mul(8);
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());
    sha256_compress(&mut state, &block);

    let mut out = [0u8; 32];
    for (i, &word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn compute_key_fingerprint(addr: BdAddr, key: &LinkKey) -> [u8; 4] {
    let digest = sha256_parts(&[b"huesos-btl-fp", &addr.0, &key.bytes]);
    [digest[0], digest[1], digest[2], digest[3]]
}

// ============================================================================
// Persistent Link Key Store (`HxFS` `/etc/btl/link_keys.bin` + RAM Fallback)
// ============================================================================

#[derive(Clone, Copy)]
struct StoredLinkKey {
    addr: BdAddr,
    key: LinkKey,
    fingerprint: [u8; 4],
}

fn load_keys_from_hxfs(hxfs: &Hxfs) -> Option<Vec<StoredLinkKey>> {
    let file = hxfs.open_file(KEYS_PATH).ok()?;
    let mut raw = [0u8; 8 + MAX_KEY_SUMMARIES * KEY_RECORD_BYTES];
    let data = file.read_at(0, &mut raw).ok()?;
    if data.len() < 8 || &data[..8] != KEYS_MAGIC {
        return None;
    }
    let mut out = Vec::new();
    let mut off = 8usize;
    while off + KEY_RECORD_BYTES <= data.len() && out.len() < MAX_KEY_SUMMARIES {
        let rec = &data[off..off + KEY_RECORD_BYTES];
        off += KEY_RECORD_BYTES;
        let mut addr_bytes = [0u8; 6];
        addr_bytes.copy_from_slice(&rec[0..6]);
        let addr = BdAddr(addr_bytes);
        if addr.is_zero() {
            continue;
        }
        let key_type = rec[6];
        let mut key_bytes = [0u8; 16];
        key_bytes.copy_from_slice(&rec[12..28]);
        let key = LinkKey {
            bytes: key_bytes,
            key_type,
        };
        let fingerprint = compute_key_fingerprint(addr, &key);
        out.push(StoredLinkKey {
            addr,
            key,
            fingerprint,
        });
    }
    Some(out)
}

fn save_keys_to_hxfs(hxfs: &Hxfs, keys: &[StoredLinkKey]) -> bool {
    let _ = hxfs.mkdir(KEYS_DIR_ETC);
    let _ = hxfs.mkdir(KEYS_DIR_BTL);
    let _ = hxfs.unlink(KEYS_TMP_PATH);

    let count = keys.len().min(MAX_KEY_SUMMARIES);
    let mut buf = alloc::vec![0u8; 8 + count * KEY_RECORD_BYTES];
    buf[..8].copy_from_slice(KEYS_MAGIC);
    for (idx, entry) in keys.iter().take(count).enumerate() {
        let base = 8 + idx * KEY_RECORD_BYTES;
        buf[base..base + 6].copy_from_slice(&entry.addr.0);
        buf[base + 6] = entry.key.key_type;
        buf[base + 7] = 0;
        buf[base + 8..base + 12].copy_from_slice(&entry.fingerprint);
        buf[base + 12..base + 28].copy_from_slice(&entry.key.bytes);
    }

    let Ok(tmp) = hxfs.create_file(KEYS_TMP_PATH) else {
        return false;
    };
    if tmp.write_at(0, &buf).is_err() {
        let _ = hxfs.unlink(KEYS_TMP_PATH);
        return false;
    }
    let _ = tmp.fsync();
    drop(tmp);
    let _ = hxfs.unlink(KEYS_PATH);
    hxfs.rename(KEYS_TMP_PATH, KEYS_PATH).is_ok()
}

fn read_bootfs_file(bootfs: &Vmo, target_path: &str) -> Option<Vec<u8>> {
    let mut hdr = [0u8; BOOTFS_HEADER_SIZE as usize];
    if bootfs.read(0, &mut hdr) != Ok(hdr.len()) || &hdr[..8] != BOOTFS_MAGIC {
        return None;
    }
    let count = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let mut raw = [0u8; BOOTFS_ENTRY_SIZE as usize];
    for idx in 0..count {
        let off = BOOTFS_HEADER_SIZE + u64::from(idx) * BOOTFS_ENTRY_SIZE;
        if bootfs.read(off, &mut raw) != Ok(raw.len()) {
            break;
        }
        let plen = raw[..BOOTFS_PATH_SIZE]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(BOOTFS_PATH_SIZE);
        if core::str::from_utf8(&raw[..plen]).ok() == Some(target_path) {
            let meta = &raw[BOOTFS_PATH_SIZE..];
            let eoff = u64::from_le_bytes([
                meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6], meta[7],
            ]);
            let elen = u64::from_le_bytes([
                meta[8], meta[9], meta[10], meta[11], meta[12], meta[13], meta[14], meta[15],
            ]) as usize;
            let mut data = alloc::vec![0u8; elen];
            let mut done = 0usize;
            while done < elen {
                let step = (elen - done).min(16 * 1024);
                match bootfs.read(eoff + done as u64, &mut data[done..done + step]) {
                    Ok(n) if n > 0 => done += n,
                    _ => return None,
                }
            }
            return Some(data);
        }
    }
    None
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
// `UBTH` USB-HCI Bridge Client (`driver-host-xhci <-> btl-service`)
// ============================================================================

#[derive(Clone, Copy)]
struct UsbBtControllerInfo {
    present: bool,
    is_realtek: bool,
    vid: u16,
    pid: u16,
}

fn usb_bt_rpc(ch: &Channel, op: UsbBtOp, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    if 8 + payload.len() > 1064 {
        return None;
    }
    let mut req = [0u8; 1064];
    req[0..4].copy_from_slice(&USB_BT_MAGIC.to_le_bytes());
    req[4..6].copy_from_slice(&BTL_ABI_VERSION.to_le_bytes());
    req[6] = op as u8;
    req[7] = 0;
    req[8..8 + payload.len()].copy_from_slice(payload);
    ch.write(&req[..8 + payload.len()]).ok()?;

    let items = [WaitItem::new(
        ch.handle().raw(),
        Signals::READABLE | Signals::PEER_CLOSED,
        0,
    )];
    let deadline = monotonic_ms().saturating_add(400);
    for _budget in 0..256u32 {
        match ch.read_into(out) {
            Ok(n) if n >= 8 => {
                let magic = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
                let ver = u16::from_le_bytes([out[4], out[5]]);
                if magic == USB_BT_MAGIC && ver == BTL_ABI_VERSION && out[6] == op as u8 {
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

fn usb_bt_query(ch: &Channel) -> Option<UsbBtControllerInfo> {
    let mut rep = [0u8; 32];
    let n = usb_bt_rpc(ch, UsbBtOp::QueryInfo, &[], &mut rep)?;
    if n < 16 || rep[7] != 0 || rep[8] == 0 {
        return Some(UsbBtControllerInfo {
            present: false,
            is_realtek: false,
            vid: 0,
            pid: 0,
        });
    }
    Some(UsbBtControllerInfo {
        present: true,
        is_realtek: rep[9] != 0,
        vid: u16::from_le_bytes([rep[10], rep[11]]),
        pid: u16::from_le_bytes([rep[12], rep[13]]),
    })
}

// ============================================================================
// SDP Query Builder & Parser for Arbitrary UUID16
// ============================================================================

fn build_sdp_uuid_query(tid: u16, uuid16: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.push(SDP_SVC_SEARCH_ATTR_REQ);
    out.extend_from_slice(&tid.to_be_bytes());
    out.extend_from_slice(&12u16.to_be_bytes()); // param len = 12
                                                 // ServiceSearchPattern: Sequence(len=3) { UUID16(uuid16) }
    out.push(0x35);
    out.push(0x03);
    out.push(0x19);
    out.extend_from_slice(&uuid16.to_be_bytes());
    // MaximumAttributeByteCount = 512
    out.extend_from_slice(&512u16.to_be_bytes());
    // AttributeIDList: Sequence(len=5) { uint32(0x0000_FFFF) }
    out.push(0x35);
    out.push(0x05);
    out.push(0x0A);
    out.extend_from_slice(&0x0000_FFFFu32.to_be_bytes());
    // ContinuationState = 0
    out.push(0x00);
    out
}

fn parse_sdp_query_reply(uuid16: u16, rsp: &[u8]) -> (bool, u16, u16) {
    if rsp.len() < 8 || rsp[0] != SDP_SVC_SEARCH_ATTR_RSP {
        return (false, 0, 0);
    }
    let body = &rsp[7..];
    let target_pat = [0x19, (uuid16 >> 8) as u8, (uuid16 & 0xFF) as u8];
    let mut found = body.windows(3).any(|w| w == target_pat);
    if uuid16 == UUID_AUDIO_SINK && parse_audio_sink_response(rsp) {
        found = true;
    }
    if !found {
        return (false, 0, 0);
    }

    // Scan for L2CAP ProtocolDescriptor `[0x19, 0x01, 0x00, 0x09, psm_hi, psm_lo]`
    let mut psm = match uuid16 {
        UUID_AUDIO_SINK => PSM_AVDTP,
        UUID_AV_REMOTE | UUID_AV_REMOTE_TARGET | UUID_AV_REMOTE_CONTROLLER => PSM_AVCTP,
        _ => 0,
    };
    for win in body.windows(6) {
        if win[0] == 0x19 && win[1] == 0x01 && win[2] == 0x00 && win[3] == 0x09 {
            psm = u16::from_be_bytes([win[4], win[5]]);
            break;
        }
    }

    // Scan for Profile version `[0x19, hi, lo, 0x09, ver_hi, ver_lo]`
    let mut version = if uuid16 == UUID_AUDIO_SINK {
        0x0103
    } else {
        0x0104
    };
    for win in body.windows(6) {
        if win[0] == 0x19
            && (u16::from_be_bytes([win[1], win[2]]) == uuid16
                || u16::from_be_bytes([win[1], win[2]]) == 0x110D)
            && win[3] == 0x09
        {
            version = u16::from_be_bytes([win[4], win[5]]);
            break;
        }
    }
    (true, psm, version)
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
    const fn allows(self, op: BtlOp) -> bool {
        if op.requires_admin() {
            matches!(self, Self::Admin)
        } else if op.requires_rw() {
            matches!(self, Self::ReadWrite | Self::Admin)
        } else {
            true
        }
    }
}

struct BtlClientConn {
    id: u32,
    ch: Channel,
    perm: ClientPerm,
    streaming_hint: bool,
}

struct ActiveAclLink {
    addr: BdAddr,
    conn_handle: u16,
    authenticated: bool,
    encrypted: bool,
    reasm: AclReassembler,
}

struct ClientL2capEndpoint {
    owner_client_id: u32,
    local_cid: u16,
    psm: u16,
    remote_mtu: u16,
    open: bool,
    rx_queue: VecDeque<Vec<u8>>,
}

struct AcceptedL2capInfo {
    local_cid: u16,
    remote_mtu: u16,
    peer_addr: BdAddr,
    psm: u16,
}

struct PsmListener {
    owner_client_id: u32,
    psm: u16,
    accept_queue: VecDeque<AcceptedL2capInfo>,
}

struct BtlRuntime {
    bootfs_vmo: Option<Vmo>,
    usb_bt_ch: Option<Channel>,
    hxfs: Option<Hxfs>,
    wlan_coex_ch: Option<Channel>,

    transport: BtlTransportKind,
    powered: bool,
    firmware_loaded: bool,
    usb_vid: u16,
    usb_pid: u16,
    local_bd_addr: BdAddr,
    fw_version: u32,
    local_manufacturer: u16,
    local_lmp_subver: u16,
    rom_version: Option<u8>,

    virtual_bt: Option<VirtualBtMedium>,
    credits: AclCreditTracker,
    l2cap: L2capEngine,
    snoop: BtSnoopLog,

    peers: Vec<DiscoveredPeer>,
    keys: Vec<StoredLinkKey>,
    acl_links: Vec<ActiveAclLink>,
    endpoints: Vec<ClientL2capEndpoint>,
    listeners: Vec<PsmListener>,

    tx_packets: u64,
    rx_packets: u64,
    coex_profile: BtCoexProfile,
    scanning: bool,
    pairing_in_progress: bool,
    streaming_hint_active: bool,
    next_sdp_tid: u16,

    last_cmd_complete: Option<(u16, u8)>,
    last_pairing_status: Option<(BdAddr, u8)>,
}

impl BtlRuntime {
    fn new() -> Self {
        Self {
            bootfs_vmo: None,
            usb_bt_ch: None,
            hxfs: None,
            wlan_coex_ch: None,
            transport: BtlTransportKind::Absent,
            powered: false,
            firmware_loaded: false,
            usb_vid: 0,
            usb_pid: 0,
            local_bd_addr: BdAddr::ZERO,
            fw_version: 0,
            local_manufacturer: 0,
            local_lmp_subver: 0,
            rom_version: None,
            virtual_bt: None,
            credits: AclCreditTracker::default(),
            l2cap: L2capEngine::new(),
            snoop: BtSnoopLog::new(64 * 1024),
            peers: Vec::new(),
            keys: Vec::new(),
            acl_links: Vec::new(),
            endpoints: Vec::new(),
            listeners: Vec::new(),
            tx_packets: 0,
            rx_packets: 0,
            coex_profile: BtCoexProfile::Off,
            scanning: false,
            pairing_in_progress: false,
            streaming_hint_active: false,
            next_sdp_tid: 1,
            last_cmd_complete: None,
            last_pairing_status: None,
        }
    }

    fn attach_hxfs(&mut self, ch: Channel) {
        let hxfs = Hxfs::from_channel(ch);
        if let Some(disk_keys) = load_keys_from_hxfs(&hxfs) {
            for dk in disk_keys {
                if !self.keys.iter().any(|k| k.addr == dk.addr)
                    && self.keys.len() < MAX_KEY_SUMMARIES
                {
                    self.keys.push(dk);
                }
            }
        }
        if !self.keys.is_empty() {
            let _ = save_keys_to_hxfs(&hxfs, &self.keys);
        }
        self.hxfs = Some(hxfs);
    }

    fn persist_keys(&self) {
        if let Some(hxfs) = self.hxfs.as_ref() {
            let _ = save_keys_to_hxfs(hxfs, &self.keys);
        }
    }

    fn upsert_key(&mut self, addr: BdAddr, key: LinkKey) {
        let fingerprint = compute_key_fingerprint(addr, &key);
        if let Some(existing) = self.keys.iter_mut().find(|k| k.addr == addr) {
            existing.key = key;
            existing.fingerprint = fingerprint;
        } else if self.keys.len() < MAX_KEY_SUMMARIES {
            self.keys.push(StoredLinkKey {
                addr,
                key,
                fingerprint,
            });
        }
        self.persist_keys();
    }

    fn sync_coex_profile(&mut self) {
        let desired = if !self.powered || self.transport == BtlTransportKind::Absent {
            BtCoexProfile::Off
        } else if self.scanning || self.pairing_in_progress {
            BtCoexProfile::BtInquiryPair
        } else if self.streaming_hint_active {
            BtCoexProfile::BtA2dpStreaming
        } else {
            BtCoexProfile::BtIdle
        };
        if desired == self.coex_profile {
            return;
        }
        self.coex_profile = desired;
        self.push_coex_to_wlan();
    }

    fn push_coex_to_wlan(&mut self) {
        let Some(ch) = self.wlan_coex_ch.as_ref() else {
            return;
        };
        let mut req = [0u8; 9];
        wlan::write_header(&mut req, WlanOp::SetBtCoexProfile, WlanStatus::Ok);
        req[8] = self.coex_profile as u8;
        if ch.write(&req).is_ok() {
            let mut rep = [0u8; 32];
            for _budget in 0..16u32 {
                match ch.read_into(&mut rep) {
                    Ok(_) => break,
                    Err(ErrorCode::ShouldWait) => libcanvas::process::yield_now(),
                    Err(_) => break,
                }
            }
        }
    }

    // ---- Low-level HCI TX / RX ----

    fn send_hci_cmd(&mut self, cmd: &[u8]) -> bool {
        if cmd.len() < 3 {
            return false;
        }
        self.snoop
            .record(H4_CMD, SnoopDir::HostToController, monotonic_us(), cmd);
        self.tx_packets = self.tx_packets.saturating_add(1);
        match self.transport {
            BtlTransportKind::UsbRealtek8821c | BtlTransportKind::UsbGenericHci => {
                let Some(ch) = self.usb_bt_ch.as_ref() else {
                    return false;
                };
                let mut rep = [0u8; 16];
                matches!(
                    usb_bt_rpc(ch, UsbBtOp::SendHciCmd, cmd, &mut rep),
                    Some(n) if n >= 8 && rep[7] == 0
                )
            }
            BtlTransportKind::VirtualLoopback => {
                if let Some(vbt) = self.virtual_bt.as_mut() {
                    vbt.submit_hci_cmd(cmd);
                    true
                } else {
                    false
                }
            }
            BtlTransportKind::Absent => false,
        }
    }

    fn send_hci_acl_frag(&mut self, acl: &[u8]) -> bool {
        if acl.len() < 4 {
            return false;
        }
        self.snoop
            .record(H4_ACL, SnoopDir::HostToController, monotonic_us(), acl);
        self.tx_packets = self.tx_packets.saturating_add(1);
        match self.transport {
            BtlTransportKind::UsbRealtek8821c | BtlTransportKind::UsbGenericHci => {
                let Some(ch) = self.usb_bt_ch.as_ref() else {
                    return false;
                };
                let mut rep = [0u8; 16];
                matches!(
                    usb_bt_rpc(ch, UsbBtOp::SendHciAcl, acl, &mut rep),
                    Some(n) if n >= 8 && rep[7] == 0
                )
            }
            BtlTransportKind::VirtualLoopback => {
                if let Some(vbt) = self.virtual_bt.as_mut() {
                    vbt.submit_hci_acl(acl);
                    true
                } else {
                    false
                }
            }
            BtlTransportKind::Absent => false,
        }
    }

    fn send_cmd_wait(&mut self, opcode: u16, cmd: &[u8], timeout_ms: u64) -> Option<u8> {
        self.last_cmd_complete = None;
        if !self.send_hci_cmd(cmd) {
            return None;
        }
        let deadline = monotonic_ms().saturating_add(timeout_ms);
        for _budget in 0..512u32 {
            self.pump_transport(16);
            if let Some((done_op, status)) = self.last_cmd_complete {
                if done_op == opcode {
                    self.last_cmd_complete = None;
                    return Some(status);
                }
            }
            if monotonic_ms() >= deadline {
                break;
            }
            libcanvas::system::sleep_ms(1);
        }
        None
    }

    fn pump_transport(&mut self, budget: u32) -> bool {
        let mut progressed = false;
        for _ in 0..budget {
            match self.transport {
                BtlTransportKind::Absent => break,
                BtlTransportKind::VirtualLoopback => {
                    let next_evt = self
                        .virtual_bt
                        .as_mut()
                        .and_then(VirtualBtMedium::pop_hci_event);
                    if let Some(evt) = next_evt {
                        progressed = true;
                        self.on_hci_event(&evt);
                        continue;
                    }
                    let next_acl = self
                        .virtual_bt
                        .as_mut()
                        .and_then(VirtualBtMedium::pop_hci_acl);
                    if let Some(acl) = next_acl {
                        progressed = true;
                        self.on_hci_acl(&acl);
                        continue;
                    }
                    break;
                }
                BtlTransportKind::UsbRealtek8821c | BtlTransportKind::UsbGenericHci => {
                    let Some(ch) = self.usb_bt_ch.as_ref() else {
                        break;
                    };
                    let mut rep = [0u8; 1064];
                    let Some(n) = usb_bt_rpc(ch, UsbBtOp::PollRx, &[], &mut rep) else {
                        break;
                    };
                    if n <= 8 || rep[7] != 0 {
                        break;
                    }
                    progressed = true;
                    let h4_type = rep[8];
                    let body = &rep[9..n];
                    if h4_type == H4_EVT {
                        self.on_hci_event(body);
                    } else if h4_type == H4_ACL {
                        self.on_hci_acl(body);
                    }
                }
            }
        }
        self.flush_l2cap_events_and_tx();
        progressed
    }

    fn on_hci_event(&mut self, evt: &[u8]) {
        self.snoop
            .record(H4_EVT, SnoopDir::ControllerToHost, monotonic_us(), evt);
        self.rx_packets = self.rx_packets.saturating_add(1);
        let Some(decoded) = decode_event(evt) else {
            return;
        };

        let mut follow_up_cmd = [0u8; 64];
        let mut follow_up_len: Option<usize> = None;

        match decoded {
            DecodedHciEvent::CommandComplete {
                opcode,
                status,
                return_params,
                ..
            } => {
                self.last_cmd_complete = Some((opcode, status));
                if status == 0 {
                    match opcode {
                        OP_READ_LOCAL_VERSION => {
                            if let Some(ver) = parse_local_version_return(return_params) {
                                self.local_manufacturer = ver.manufacturer;
                                self.local_lmp_subver = ver.lmp_subver;
                            }
                        }
                        OP_READ_BD_ADDR if return_params.len() >= 6 => {
                            let mut a = [0u8; 6];
                            a.copy_from_slice(&return_params[0..6]);
                            self.local_bd_addr = BdAddr(a);
                        }
                        OP_READ_BUFFER_SIZE => {
                            if let Some((mtu, slots)) = parse_buffer_size_return(return_params) {
                                self.credits.configure(mtu, slots);
                            }
                        }
                        OP_RTL_READ_ROM_VERSION => {
                            self.rom_version = parse_rom_version_return(return_params);
                        }
                        _ => {}
                    }
                }
            }
            DecodedHciEvent::CommandStatus { opcode, status, .. } => {
                if status != 0 {
                    self.last_cmd_complete = Some((opcode, status));
                }
            }
            DecodedHciEvent::InquiryComplete { .. } => {
                self.scanning = false;
            }
            DecodedHciEvent::PeerDiscovered(peer) => {
                if let Some(existing) = self.peers.iter_mut().find(|p| p.addr == peer.addr) {
                    if peer.rssi_dbm != 0 {
                        existing.rssi_dbm = peer.rssi_dbm;
                    }
                    if peer.cod.raw_u24() != 0 {
                        existing.cod = peer.cod;
                    }
                    existing.page_scan_rep_mode = peer.page_scan_rep_mode;
                    existing.clock_offset = peer.clock_offset;
                    if peer.name_len > 0 {
                        existing.name = peer.name;
                        existing.name_len = peer.name_len;
                    }
                    existing.advertises_a2dp_sink |= peer.advertises_a2dp_sink;
                } else if self.peers.len() < MAX_PEERS {
                    self.peers.push(peer);
                }
            }
            DecodedHciEvent::RemoteNameComplete {
                status,
                addr,
                name,
                name_len,
            } => {
                if status == 0 && name_len > 0 {
                    if let Some(existing) = self.peers.iter_mut().find(|p| p.addr == addr) {
                        existing.name = name;
                        existing.name_len = name_len;
                    }
                }
            }
            DecodedHciEvent::ConnectionRequest {
                addr,
                cod,
                link_type,
            } => {
                if link_type == 0x01 {
                    if !self.peers.iter().any(|p| p.addr == addr) && self.peers.len() < MAX_PEERS {
                        self.peers.push(DiscoveredPeer {
                            addr,
                            page_scan_rep_mode: 1,
                            cod,
                            clock_offset: 0,
                            rssi_dbm: -50,
                            name: [0; 64],
                            name_len: 0,
                            advertises_a2dp_sink: cod.is_audio_sink_candidate(),
                        });
                    }
                    follow_up_len = cmd_accept_connection(addr, 0x00, &mut follow_up_cmd);
                }
            }
            DecodedHciEvent::ConnectionComplete {
                status,
                conn_handle,
                addr,
                link_type,
                encryption_enabled,
            } => {
                if status == 0 && link_type == 0x01 {
                    if let Some(link) = self.acl_links.iter_mut().find(|l| l.addr == addr) {
                        link.conn_handle = conn_handle;
                        link.encrypted = encryption_enabled != 0;
                    } else {
                        self.acl_links.push(ActiveAclLink {
                            addr,
                            conn_handle,
                            authenticated: encryption_enabled != 0,
                            encrypted: encryption_enabled != 0,
                            reasm: AclReassembler::default(),
                        });
                    }
                }
            }
            DecodedHciEvent::DisconnectionComplete {
                status,
                conn_handle,
                ..
            } => {
                if status == 0 {
                    self.acl_links.retain(|l| l.conn_handle != conn_handle);
                    self.l2cap.on_acl_disconnected(conn_handle);
                    if self.acl_links.is_empty() {
                        self.credits.reset_in_flight();
                    }
                }
            }
            DecodedHciEvent::AuthenticationComplete {
                status,
                conn_handle,
            } => {
                if let Some(link) = self
                    .acl_links
                    .iter_mut()
                    .find(|l| l.conn_handle == conn_handle)
                {
                    let peer_addr = link.addr;
                    if status == 0 {
                        link.authenticated = true;
                        follow_up_len = cmd_set_encryption(conn_handle, true, &mut follow_up_cmd);
                    }
                    self.last_pairing_status = Some((peer_addr, status));
                }
            }
            DecodedHciEvent::EncryptionChange {
                status,
                conn_handle,
                encryption_enabled,
            } => {
                if status == 0 {
                    if let Some(link) = self
                        .acl_links
                        .iter_mut()
                        .find(|l| l.conn_handle == conn_handle)
                    {
                        link.encrypted = encryption_enabled != 0;
                    }
                }
            }
            DecodedHciEvent::NumberOfCompletedPackets(payload) => {
                self.credits.on_completed_packets(payload);
            }
            DecodedHciEvent::LinkKeyRequest { addr } => {
                if let Some(saved) = self.keys.iter().find(|k| k.addr == addr) {
                    let key_bytes = saved.key.bytes;
                    follow_up_len = cmd_link_key_reply(addr, &key_bytes, &mut follow_up_cmd);
                } else {
                    follow_up_len = cmd_link_key_neg_reply(addr, &mut follow_up_cmd);
                }
            }
            DecodedHciEvent::LinkKeyNotification { addr, key } => {
                self.upsert_key(addr, key);
            }
            DecodedHciEvent::PinCodeRequest { addr } => {
                follow_up_len = cmd_pin_code_reply(addr, b"0000", &mut follow_up_cmd);
            }
            DecodedHciEvent::IoCapabilityRequest { addr } => {
                follow_up_len = cmd_io_capability_reply_just_works(addr, &mut follow_up_cmd);
            }
            DecodedHciEvent::UserConfirmationRequest { addr, .. } => {
                follow_up_len = cmd_user_confirmation_reply(addr, &mut follow_up_cmd);
            }
            DecodedHciEvent::SimplePairingComplete { status, addr } => {
                if status != 0 {
                    self.last_pairing_status = Some((addr, status));
                }
            }
            DecodedHciEvent::Other { .. } => {}
        }

        if let Some(len) = follow_up_len {
            let _ = self.send_hci_cmd(&follow_up_cmd[..len]);
        }
        self.sync_coex_profile();
    }

    fn on_hci_acl(&mut self, acl: &[u8]) {
        self.snoop
            .record(H4_ACL, SnoopDir::ControllerToHost, monotonic_us(), acl);
        self.rx_packets = self.rx_packets.saturating_add(1);
        if acl.len() < 4 {
            return;
        }
        let handle = u16::from_le_bytes([acl[0], acl[1]]) & 0x0FFF;
        let mut completed: Option<(BdAddr, u16, Vec<u8>)> = None;
        if let Some(link) = self.acl_links.iter_mut().find(|l| l.conn_handle == handle) {
            if let Some((_h, cid, payload)) = link.reasm.push_acl(acl) {
                completed = Some((link.addr, cid, payload));
            }
        }
        if let Some((peer_addr, cid, payload)) = completed {
            self.l2cap
                .on_reassembled_pdu(handle, peer_addr, cid, &payload);
        }
    }

    fn flush_l2cap_events_and_tx(&mut self) {
        let events = self.l2cap.drain_events();
        for ev in events {
            match ev {
                L2capEvent::ChannelOpened {
                    local_cid,
                    peer_addr,
                    psm,
                    initiator,
                    remote_mtu,
                    ..
                } => {
                    if initiator {
                        if let Some(ep) =
                            self.endpoints.iter_mut().find(|e| e.local_cid == local_cid)
                        {
                            ep.open = true;
                            ep.remote_mtu = remote_mtu;
                        }
                    } else if psm != PSM_SDP {
                        if let Some(listener) = self.listeners.iter_mut().find(|l| l.psm == psm) {
                            let owner = listener.owner_client_id;
                            if listener.accept_queue.len() < MAX_ACCEPT_QUEUE_PER_PSM {
                                listener.accept_queue.push_back(AcceptedL2capInfo {
                                    local_cid,
                                    remote_mtu,
                                    peer_addr,
                                    psm,
                                });
                            }
                            self.endpoints.push(ClientL2capEndpoint {
                                owner_client_id: owner,
                                local_cid,
                                psm,
                                remote_mtu,
                                open: true,
                                rx_queue: VecDeque::new(),
                            });
                        } else {
                            let _ = self.l2cap.disconnect(local_cid);
                        }
                    }
                }
                L2capEvent::DataReceived {
                    local_cid,
                    psm,
                    payload,
                } => {
                    let is_client_ep = self.endpoints.iter().any(|e| e.local_cid == local_cid);
                    if psm == PSM_SDP && !is_client_ep {
                        if let Some(rsp) = handle_sdp_request(&payload) {
                            let _ = self.l2cap.send_data(local_cid, &rsp);
                        }
                    } else if let Some(ep) =
                        self.endpoints.iter_mut().find(|e| e.local_cid == local_cid)
                    {
                        if ep.rx_queue.len() < MAX_RX_QUEUE_PER_CID {
                            ep.rx_queue.push_back(payload);
                        }
                    }
                }
                L2capEvent::ChannelClosed { local_cid, .. } => {
                    if let Some(ep) = self.endpoints.iter_mut().find(|e| e.local_cid == local_cid) {
                        ep.open = false;
                    }
                }
            }
        }

        let outbound = self.l2cap.drain_outbound();
        for pdu in outbound {
            let frags = segment_l2cap_to_acl(pdu.conn_handle, &pdu.pdu, self.credits.max_acl_len);
            for frag in frags {
                let _ = self.credits.take_credits(1);
                let _ = self.send_hci_acl_frag(&frag);
            }
        }
    }

    // ---- Controller Bring-up (`RTL8821CE` `btrtl` + Standard HCI) ----

    fn bring_up_usb_controller(&mut self) -> Result<(), BtlStatus> {
        let Some(ch) = self.usb_bt_ch.as_ref() else {
            return Err(BtlStatus::HardwareAbsent);
        };
        let Some(info) = usb_bt_query(ch) else {
            return Err(BtlStatus::HardwareAbsent);
        };
        if !info.present {
            return Err(BtlStatus::HardwareAbsent);
        }

        let is_rtk = info.is_realtek || is_rtl8821ce_usb_id(info.vid, info.pid);
        self.transport = if is_rtk {
            BtlTransportKind::UsbRealtek8821c
        } else {
            BtlTransportKind::UsbGenericHci
        };
        self.usb_vid = info.vid;
        self.usb_pid = info.pid;
        self.virtual_bt = None;
        self.credits = AclCreditTracker::default();

        let mut cmd = [0u8; 264];
        if let Some(n) = cmd_read_local_version(&mut cmd) {
            if self.send_cmd_wait(OP_READ_LOCAL_VERSION, &cmd[..n], 500) != Some(0) {
                return Err(BtlStatus::HardwareAbsent);
            }
        }

        if is_rtk
            && (self.local_manufacturer == REALTEK_MANUFACTURER_ID || self.local_manufacturer == 0)
        {
            if self.local_lmp_subver == LMP_SUBVER_8821C {
                let rom_ver = if let Some(n) = cmd_read_rom_version(&mut cmd) {
                    let _ = self.send_cmd_wait(OP_RTL_READ_ROM_VERSION, &cmd[..n], 400);
                    self.rom_version.unwrap_or(1)
                } else {
                    1
                };
                let Some(bootfs) = self.bootfs_vmo.as_ref() else {
                    return Err(BtlStatus::FirmwareFailed);
                };
                let Some(fw_bytes) = read_bootfs_file(bootfs, RTL_FW_PATH) else {
                    println!("[btl-service] missing {}", RTL_FW_PATH);
                    return Err(BtlStatus::FirmwareFailed);
                };
                let cfg_bytes = read_bootfs_file(bootfs, RTL_CFG_PATH);
                let Ok(assembled) =
                    parse_and_assemble_rtl8821c(&fw_bytes, cfg_bytes.as_deref(), rom_ver)
                else {
                    println!("[btl-service] invalid RTL8821CE firmware image");
                    return Err(BtlStatus::FirmwareFailed);
                };
                let total_frags = assembled.fragment_count();
                for frag_idx in 0..total_frags {
                    let Some(clen) = assembled.encode_download_cmd(frag_idx, &mut cmd) else {
                        return Err(BtlStatus::FirmwareFailed);
                    };
                    if self.send_cmd_wait(OP_RTL_DOWNLOAD, &cmd[..clen], 500) != Some(0) {
                        println!(
                            "[btl-service] RTL8821CE patch upload failed at frag {}/{}",
                            frag_idx, total_frags
                        );
                        return Err(BtlStatus::FirmwareFailed);
                    }
                }
                self.fw_version = assembled.fw_version;
                self.firmware_loaded = true;
                println!(
                    "[btl-service] uploaded RTL8821CE Bluetooth patch ({} B, {} frags, fw=0x{:08x})",
                    assembled.payload.len(),
                    total_frags,
                    self.fw_version
                );
            } else {
                // Controller already warm-patched across warm reset
                self.firmware_loaded = true;
                self.fw_version = if let Some(bootfs) = self.bootfs_vmo.as_ref() {
                    read_bootfs_file(bootfs, RTL_FW_PATH)
                        .filter(|b| b.len() >= 12)
                        .map(|b| u32::from_le_bytes([b[8], b[9], b[10], b[11]]))
                        .unwrap_or(u32::from(self.local_lmp_subver))
                } else {
                    u32::from(self.local_lmp_subver)
                };
            }
        } else {
            self.firmware_loaded = true;
            self.fw_version = u32::from(self.local_lmp_subver);
        }

        self.run_standard_hci_init()
    }

    fn bring_up_virtual_controller(&mut self) -> Result<(), BtlStatus> {
        self.transport = BtlTransportKind::VirtualLoopback;
        self.usb_vid = 0;
        self.usb_pid = 0;
        self.virtual_bt = Some(VirtualBtMedium::new());
        self.credits = AclCreditTracker::default();
        self.firmware_loaded = true;
        self.fw_version = 0x826C_A99E;
        self.run_standard_hci_init()
    }

    fn run_standard_hci_init(&mut self) -> Result<(), BtlStatus> {
        let mut cmd = [0u8; 260];
        if let Some(n) = cmd_reset(&mut cmd) {
            if self.send_cmd_wait(0x0C03, &cmd[..n], 500) != Some(0) {
                return Err(BtlStatus::HardwareAbsent);
            }
        }
        if let Some(n) = cmd_read_local_version(&mut cmd) {
            let _ = self.send_cmd_wait(OP_READ_LOCAL_VERSION, &cmd[..n], 300);
        }
        if let Some(n) = cmd_read_bd_addr(&mut cmd) {
            let _ = self.send_cmd_wait(OP_READ_BD_ADDR, &cmd[..n], 300);
        }
        if let Some(n) = cmd_read_buffer_size(&mut cmd) {
            let _ = self.send_cmd_wait(OP_READ_BUFFER_SIZE, &cmd[..n], 300);
        }
        if let Some(n) = cmd_set_event_mask_ssp(&mut cmd) {
            let _ = self.send_cmd_wait(0x0C01, &cmd[..n], 300);
        }
        if let Some(n) = cmd_write_simple_pairing_mode(true, &mut cmd) {
            let _ = self.send_cmd_wait(0x0C56, &cmd[..n], 300);
        }
        if let Some(n) = cmd_write_inquiry_mode(2, &mut cmd) {
            let _ = self.send_cmd_wait(0x0C45, &cmd[..n], 300);
        }
        if let Some(n) = cmd_write_class_of_device(LOCAL_COD_COMPUTER_AUDIO_SOURCE, &mut cmd) {
            let _ = self.send_cmd_wait(0x0C24, &cmd[..n], 300);
        }
        if let Some(n) = cmd_write_local_name("HuesOS Workstation", &mut cmd) {
            let _ = self.send_cmd_wait(0x0C13, &cmd[..n], 300);
        }
        if let Some(n) = cmd_write_page_timeout(0x2000, &mut cmd) {
            let _ = self.send_cmd_wait(0x0C18, &cmd[..n], 300);
        }
        if let Some(n) = cmd_write_default_link_policy(0x0005, &mut cmd) {
            let _ = self.send_cmd_wait(0x080F, &cmd[..n], 300);
        }
        if let Some(n) = cmd_write_scan_enable(0x03, &mut cmd) {
            let _ = self.send_cmd_wait(0x0C1A, &cmd[..n], 300);
        }
        self.powered = true;
        self.sync_coex_profile();
        Ok(())
    }

    fn power_off(&mut self) {
        let handles: Vec<u16> = self.acl_links.iter().map(|l| l.conn_handle).collect();
        let mut cmd = [0u8; 16];
        for h in handles {
            if let Some(n) = cmd_disconnect(h, 0x13, &mut cmd) {
                let _ = self.send_hci_cmd(&cmd[..n]);
            }
        }
        self.pump_transport(32);
        self.acl_links.clear();
        self.endpoints.clear();
        self.credits.reset_in_flight();
        self.powered = false;
        self.scanning = false;
        self.pairing_in_progress = false;
        self.streaming_hint_active = false;
        self.sync_coex_profile();
    }

    // ---- High-level HCI / L2CAP / SDP Operations ----

    fn run_inquiry_scan(&mut self, duration_units: u8) -> Result<(), BtlStatus> {
        if !self.powered || self.transport == BtlTransportKind::Absent {
            return Err(BtlStatus::HardwareAbsent);
        }
        let units = duration_units.clamp(1, 10);
        let mut cmd = [0u8; 16];
        let Some(n) = cmd_inquiry_giac(units, 16, &mut cmd) else {
            return Err(BtlStatus::InvalidRequest);
        };
        self.scanning = true;
        self.sync_coex_profile();
        if !self.send_hci_cmd(&cmd[..n]) {
            self.scanning = false;
            self.sync_coex_profile();
            return Err(BtlStatus::HardwareAbsent);
        }
        let wait_ms = if self.transport == BtlTransportKind::VirtualLoopback {
            50
        } else {
            u64::from(units).saturating_mul(1350).saturating_add(300)
        };
        let deadline = monotonic_ms().saturating_add(wait_ms);
        for _budget in 0..2048u32 {
            self.pump_transport(16);
            if !self.scanning || monotonic_ms() >= deadline {
                break;
            }
            libcanvas::system::sleep_ms(5);
        }
        self.scanning = false;

        // Resolve friendly names for peers whose EIR omitted a local name
        let unnamed: Vec<(BdAddr, u8, u16)> = self
            .peers
            .iter()
            .filter(|p| p.name_len == 0)
            .map(|p| (p.addr, p.page_scan_rep_mode, p.clock_offset))
            .collect();
        for (addr, psrm, clk) in unnamed {
            if let Some(rn_len) = cmd_remote_name_request(addr, psrm, clk, &mut cmd) {
                if self.send_hci_cmd(&cmd[..rn_len]) {
                    let rn_deadline = monotonic_ms().saturating_add(400);
                    for _budget in 0..128u32 {
                        self.pump_transport(8);
                        if self.peers.iter().any(|p| p.addr == addr && p.name_len > 0)
                            || monotonic_ms() >= rn_deadline
                        {
                            break;
                        }
                        libcanvas::system::sleep_ms(4);
                    }
                }
            }
        }
        self.sync_coex_profile();
        Ok(())
    }

    fn ensure_acl_connected(&mut self, addr: BdAddr) -> Result<(u16, bool), BtlStatus> {
        if !self.powered || self.transport == BtlTransportKind::Absent {
            return Err(BtlStatus::HardwareAbsent);
        }
        if let Some(link) = self.acl_links.iter().find(|l| l.addr == addr) {
            return Ok((link.conn_handle, link.encrypted));
        }
        let (psrm, clk) = self
            .peers
            .iter()
            .find(|p| p.addr == addr)
            .map(|p| (p.page_scan_rep_mode, p.clock_offset))
            .unwrap_or((1, 0));

        let mut cmd = [0u8; 32];
        let Some(n) = cmd_create_connection(addr, psrm, clk, true, &mut cmd) else {
            return Err(BtlStatus::InvalidRequest);
        };
        if !self.send_hci_cmd(&cmd[..n]) {
            return Err(BtlStatus::HardwareAbsent);
        }
        let deadline = monotonic_ms().saturating_add(5_500);
        for _budget in 0..1200u32 {
            self.pump_transport(16);
            if let Some(link) = self.acl_links.iter().find(|l| l.addr == addr) {
                return Ok((link.conn_handle, link.encrypted));
            }
            if let Some((0x0405, st)) = self.last_cmd_complete {
                if st != 0 {
                    self.last_cmd_complete = None;
                    return Err(BtlStatus::NotConnected);
                }
            }
            if monotonic_ms() >= deadline {
                break;
            }
            libcanvas::system::sleep_ms(5);
        }
        Err(BtlStatus::NotConnected)
    }

    fn authenticate_and_encrypt(&mut self, addr: BdAddr) -> Result<(u16, bool), BtlStatus> {
        let (conn_handle, already_enc) = self.ensure_acl_connected(addr)?;
        if already_enc {
            return Ok((conn_handle, true));
        }
        let mut cmd = [0u8; 16];
        let Some(n) = cmd_authentication_requested(conn_handle, &mut cmd) else {
            return Err(BtlStatus::InvalidRequest);
        };
        self.pairing_in_progress = true;
        self.last_pairing_status = None;
        self.sync_coex_profile();

        if !self.send_hci_cmd(&cmd[..n]) {
            self.pairing_in_progress = false;
            self.sync_coex_profile();
            return Err(BtlStatus::HardwareAbsent);
        }

        let deadline = monotonic_ms().saturating_add(8_000);
        let mut result = Err(BtlStatus::AuthFailed);
        for _budget in 0..1600u32 {
            self.pump_transport(16);
            if let Some(link) = self.acl_links.iter().find(|l| l.conn_handle == conn_handle) {
                if link.encrypted {
                    result = Ok((conn_handle, true));
                    break;
                }
            }
            if let Some((p_addr, st)) = self.last_pairing_status {
                if p_addr == addr && st != 0 {
                    result = Err(BtlStatus::AuthFailed);
                    break;
                }
            }
            if monotonic_ms() >= deadline {
                break;
            }
            libcanvas::system::sleep_ms(5);
        }
        self.pairing_in_progress = false;
        self.sync_coex_profile();
        result
    }

    fn encode_peers_reply(&self, op: BtlOp, out: &mut [u8]) -> usize {
        let count = self.peers.len().min(MAX_PEERS);
        let total = 12 + count * BtlPeerInfo::WIRE_LEN;
        out[..total].fill(0);
        btl::write_header(out, op, BtlStatus::Ok);
        out[8] = count as u8;
        for (i, p) in self.peers.iter().take(count).enumerate() {
            let paired = self.keys.iter().any(|k| k.addr == p.addr);
            let link = self.acl_links.iter().find(|l| l.addr == p.addr);
            let connected = link.is_some();
            let encrypted = link.is_some_and(|l| l.encrypted);
            let audio_sink = p.advertises_a2dp_sink || p.cod.is_audio_sink_candidate();
            let flags = u8::from(paired)
                | (u8::from(connected) << 1)
                | (u8::from(encrypted) << 2)
                | (u8::from(audio_sink) << 3);

            let mut name_arr = [0u8; MAX_PEER_NAME_LEN];
            let nlen = usize::from(p.name_len).min(MAX_PEER_NAME_LEN);
            name_arr[..nlen].copy_from_slice(&p.name[..nlen]);
            let info = BtlPeerInfo {
                bd_addr: p.addr.0,
                rssi_dbm: p.rssi_dbm,
                flags,
                class_of_device: p.cod.0,
                name_len: nlen as u8,
                name: name_arr,
            };
            let dst = 12 + i * BtlPeerInfo::WIRE_LEN;
            let _ = info.encode(&mut out[dst..dst + BtlPeerInfo::WIRE_LEN]);
        }
        total
    }

    fn cleanup_client(&mut self, client_id: u32) {
        let mut close_cids = Vec::new();
        for ep in &self.endpoints {
            if ep.owner_client_id == client_id && ep.open {
                close_cids.push(ep.local_cid);
            }
        }
        for cid in close_cids {
            let _ = self.l2cap.disconnect(cid);
        }
        self.endpoints.retain(|ep| ep.owner_client_id != client_id);

        let mut removed_psms = Vec::new();
        for l in &self.listeners {
            if l.owner_client_id == client_id {
                removed_psms.push(l.psm);
            }
        }
        self.listeners.retain(|l| l.owner_client_id != client_id);
        for psm in removed_psms {
            if !self.listeners.iter().any(|l| l.psm == psm) {
                self.l2cap.unregister_psm(psm);
            }
        }
        self.flush_l2cap_events_and_tx();
    }

    fn handle_client_request(
        &mut self,
        client_id: u32,
        perm: ClientPerm,
        client_streaming_hint: &mut bool,
        req: &[u8],
        rep: &mut [u8],
    ) -> usize {
        let Some((op, payload)) = btl::parse_request(req) else {
            btl::write_header(rep, BtlOp::Status, BtlStatus::InvalidRequest);
            return 8;
        };
        if !perm.allows(op) {
            btl::write_header(rep, op, BtlStatus::AccessDenied);
            return 8;
        }

        match op {
            BtlOp::Status => {
                let snoop_len = self.snoop.export_bytes().len() as u32;
                let open_cids = self.endpoints.iter().filter(|e| e.open).count() as u8;
                let snap = BtlStatusSnapshot {
                    transport: self.transport,
                    powered: self.powered,
                    firmware_loaded: self.firmware_loaded,
                    coex_profile: self.coex_profile as u8,
                    usb_vid: self.usb_vid,
                    usb_pid: self.usb_pid,
                    local_bd_addr: self.local_bd_addr.0,
                    acl_mtu: self.credits.max_acl_len,
                    acl_max_slots: self.credits.total_credits,
                    acl_in_flight: self.credits.in_flight,
                    peer_count: self.peers.len().min(MAX_PEERS) as u8,
                    saved_keys: self.keys.len().min(MAX_KEY_SUMMARIES) as u8,
                    open_l2cap_channels: open_cids,
                    fw_version: self.fw_version,
                    tx_packets: self.tx_packets,
                    rx_packets: self.rx_packets,
                    snoop_bytes: snoop_len,
                };
                snap.encode_reply(rep).unwrap_or_else(|| {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    8
                })
            }
            BtlOp::Scan => {
                let units = payload.first().copied().unwrap_or(4);
                match self.run_inquiry_scan(units) {
                    Ok(()) => self.encode_peers_reply(BtlOp::Scan, rep),
                    Err(st) => {
                        btl::write_header(rep, op, st);
                        8
                    }
                }
            }
            BtlOp::ListPeers => self.encode_peers_reply(BtlOp::ListPeers, rep),
            BtlOp::Pair => {
                if payload.len() < 6 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let mut a = [0u8; 6];
                a.copy_from_slice(&payload[0..6]);
                let st = match self.authenticate_and_encrypt(BdAddr(a)) {
                    Ok(_) => BtlStatus::Ok,
                    Err(e) => e,
                };
                btl::write_header(rep, op, st);
                8
            }
            BtlOp::ConnectAcl => {
                if payload.len() < 6 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let mut a = [0u8; 6];
                a.copy_from_slice(&payload[0..6]);
                let addr = BdAddr(a);
                let has_key = self.keys.iter().any(|k| k.addr == addr);
                let res = if has_key {
                    self.authenticate_and_encrypt(addr)
                } else {
                    self.ensure_acl_connected(addr)
                };
                match res {
                    Ok((conn_handle, encrypted)) => {
                        rep[..12].fill(0);
                        btl::write_header(rep, op, BtlStatus::Ok);
                        rep[8..10].copy_from_slice(&conn_handle.to_le_bytes());
                        rep[10] = u8::from(encrypted);
                        12
                    }
                    Err(st) => {
                        btl::write_header(rep, op, st);
                        8
                    }
                }
            }
            BtlOp::DisconnectAcl => {
                if payload.len() < 6 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let mut a = [0u8; 6];
                a.copy_from_slice(&payload[0..6]);
                let target = BdAddr(a);
                let handles: Vec<u16> = self
                    .acl_links
                    .iter()
                    .filter(|l| target.is_zero() || l.addr == target)
                    .map(|l| l.conn_handle)
                    .collect();
                let mut cmd = [0u8; 16];
                for h in handles {
                    if let Some(n) = cmd_disconnect(h, 0x13, &mut cmd) {
                        let _ = self.send_hci_cmd(&cmd[..n]);
                    }
                }
                let deadline = monotonic_ms().saturating_add(300);
                for _budget in 0..64u32 {
                    self.pump_transport(8);
                    if self
                        .acl_links
                        .iter()
                        .all(|l| !target.is_zero() && l.addr != target)
                        || monotonic_ms() >= deadline
                    {
                        break;
                    }
                    libcanvas::system::sleep_ms(4);
                }
                btl::write_header(rep, op, BtlStatus::Ok);
                8
            }
            BtlOp::ListKeys => {
                let count = self.keys.len().min(MAX_KEY_SUMMARIES);
                let total = 12 + count * BtlKeySummary::WIRE_LEN;
                rep[..total].fill(0);
                btl::write_header(rep, op, BtlStatus::Ok);
                rep[8] = count as u8;
                for (i, k) in self.keys.iter().take(count).enumerate() {
                    let sum = BtlKeySummary {
                        bd_addr: k.addr.0,
                        key_type: k.key.key_type,
                        reserved: 0,
                        key_fingerprint: k.fingerprint,
                    };
                    let dst = 12 + i * BtlKeySummary::WIRE_LEN;
                    let _ = sum.encode(&mut rep[dst..dst + BtlKeySummary::WIRE_LEN]);
                }
                total
            }
            BtlOp::DeleteKey => {
                if payload.len() < 6 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let mut a = [0u8; 6];
                a.copy_from_slice(&payload[0..6]);
                let addr = BdAddr(a);
                let prev = self.keys.len();
                self.keys.retain(|k| k.addr != addr);
                if self.keys.len() != prev {
                    self.persist_keys();
                }
                btl::write_header(rep, op, BtlStatus::Ok);
                8
            }
            BtlOp::SdpQuery => {
                if payload.len() < 8 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let mut a = [0u8; 6];
                a.copy_from_slice(&payload[0..6]);
                let addr = BdAddr(a);
                let uuid16 = u16::from_le_bytes([payload[6], payload[7]]);
                let (conn_handle, _) = match self.ensure_acl_connected(addr) {
                    Ok(v) => v,
                    Err(st) => {
                        btl::write_header(rep, op, st);
                        return 8;
                    }
                };

                let sdp_cid = self.l2cap.connect(conn_handle, addr, PSM_SDP);
                self.endpoints.push(ClientL2capEndpoint {
                    owner_client_id: 0,
                    local_cid: sdp_cid,
                    psm: PSM_SDP,
                    remote_mtu: 672,
                    open: false,
                    rx_queue: VecDeque::new(),
                });
                self.flush_l2cap_events_and_tx();

                let open_deadline = monotonic_ms().saturating_add(1_500);
                let mut opened = false;
                for _budget in 0..300u32 {
                    self.pump_transport(16);
                    if self
                        .endpoints
                        .iter()
                        .any(|e| e.local_cid == sdp_cid && e.open)
                    {
                        opened = true;
                        break;
                    }
                    if monotonic_ms() >= open_deadline {
                        break;
                    }
                    libcanvas::system::sleep_ms(4);
                }
                if !opened {
                    self.endpoints.retain(|e| e.local_cid != sdp_cid);
                    let _ = self.l2cap.disconnect(sdp_cid);
                    self.flush_l2cap_events_and_tx();
                    btl::write_header(rep, op, BtlStatus::Refused);
                    return 8;
                }

                let tid = self.next_sdp_tid;
                self.next_sdp_tid = self.next_sdp_tid.wrapping_add(1).max(1);
                let sdp_req = build_sdp_uuid_query(tid, uuid16);
                let _ = self.l2cap.send_data(sdp_cid, &sdp_req);
                self.flush_l2cap_events_and_tx();

                let mut raw_rsp: Option<Vec<u8>> = None;
                let rsp_deadline = monotonic_ms().saturating_add(1_500);
                for _budget in 0..300u32 {
                    self.pump_transport(16);
                    if let Some(ep) = self.endpoints.iter_mut().find(|e| e.local_cid == sdp_cid) {
                        if let Some(pkt) = ep.rx_queue.pop_front() {
                            raw_rsp = Some(pkt);
                            break;
                        }
                    }
                    if monotonic_ms() >= rsp_deadline {
                        break;
                    }
                    libcanvas::system::sleep_ms(4);
                }

                self.endpoints.retain(|e| e.local_cid != sdp_cid);
                let _ = self.l2cap.disconnect(sdp_cid);
                self.flush_l2cap_events_and_tx();
                self.pump_transport(8);

                let Some(rsp_bytes) = raw_rsp else {
                    btl::write_header(rep, op, BtlStatus::Refused);
                    return 8;
                };
                let (found, psm, version) = parse_sdp_query_reply(uuid16, &rsp_bytes);
                let raw_take = rsp_bytes.len().min(MAX_L2CAP_IPC_PAYLOAD);
                rep[..16].fill(0);
                btl::write_header(
                    rep,
                    op,
                    if found {
                        BtlStatus::Ok
                    } else {
                        BtlStatus::Refused
                    },
                );
                rep[8] = u8::from(found);
                rep[9] = 0;
                rep[10..12].copy_from_slice(&psm.to_le_bytes());
                rep[12..14].copy_from_slice(&version.to_le_bytes());
                rep[14..16].copy_from_slice(&(raw_take as u16).to_le_bytes());
                rep[16..16 + raw_take].copy_from_slice(&rsp_bytes[..raw_take]);
                16 + raw_take
            }
            BtlOp::L2capConnect => {
                if payload.len() < 8 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let mut a = [0u8; 6];
                a.copy_from_slice(&payload[0..6]);
                let addr = BdAddr(a);
                let psm = u16::from_le_bytes([payload[6], payload[7]]);
                let has_key = self.keys.iter().any(|k| k.addr == addr);
                let conn_res = if has_key {
                    self.authenticate_and_encrypt(addr)
                } else {
                    self.ensure_acl_connected(addr)
                };
                let (conn_handle, _) = match conn_res {
                    Ok(v) => v,
                    Err(st) => {
                        btl::write_header(rep, op, st);
                        return 8;
                    }
                };

                let local_cid = self.l2cap.connect(conn_handle, addr, psm);
                self.endpoints.push(ClientL2capEndpoint {
                    owner_client_id: client_id,
                    local_cid,
                    psm,
                    remote_mtu: 672,
                    open: false,
                    rx_queue: VecDeque::new(),
                });
                self.flush_l2cap_events_and_tx();

                let deadline = monotonic_ms().saturating_add(2_500);
                let mut remote_mtu: Option<u16> = None;
                for _budget in 0..500u32 {
                    self.pump_transport(16);
                    if let Some(ep) = self.endpoints.iter().find(|e| e.local_cid == local_cid) {
                        if ep.open {
                            remote_mtu = Some(ep.remote_mtu);
                            break;
                        }
                        if self.l2cap.channel(local_cid).is_none() {
                            break;
                        }
                    }
                    if monotonic_ms() >= deadline {
                        break;
                    }
                    libcanvas::system::sleep_ms(4);
                }

                let Some(mtu) = remote_mtu else {
                    self.endpoints.retain(|e| e.local_cid != local_cid);
                    let _ = self.l2cap.disconnect(local_cid);
                    self.flush_l2cap_events_and_tx();
                    btl::write_header(rep, op, BtlStatus::Refused);
                    return 8;
                };

                rep[..16].fill(0);
                btl::write_header(rep, op, BtlStatus::Ok);
                rep[8..10].copy_from_slice(&local_cid.to_le_bytes());
                rep[10..12].copy_from_slice(&mtu.to_le_bytes());
                rep[12..14].copy_from_slice(&self.credits.available_credits().to_le_bytes());
                rep[14] = self.credits.congestion_percent();
                16
            }
            BtlOp::L2capListen => {
                if payload.len() < 2 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let psm = u16::from_le_bytes([payload[0], payload[1]]);
                if psm == 0 || psm == PSM_SDP {
                    btl::write_header(rep, op, BtlStatus::Refused);
                    return 8;
                }
                if !self.listeners.iter().any(|l| l.psm == psm) {
                    self.l2cap.register_psm(psm);
                    self.listeners.push(PsmListener {
                        owner_client_id: client_id,
                        psm,
                        accept_queue: VecDeque::new(),
                    });
                }
                btl::write_header(rep, op, BtlStatus::Ok);
                8
            }
            BtlOp::L2capAccept => {
                if payload.len() < 2 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let psm = u16::from_le_bytes([payload[0], payload[1]]);
                self.pump_transport(8);
                let Some(listener) = self
                    .listeners
                    .iter_mut()
                    .find(|l| l.psm == psm && l.owner_client_id == client_id)
                else {
                    btl::write_header(rep, op, BtlStatus::Refused);
                    return 8;
                };
                let Some(acc) = listener.accept_queue.pop_front() else {
                    btl::write_header(rep, op, BtlStatus::WouldBlock);
                    return 8;
                };
                rep[..20].fill(0);
                btl::write_header(rep, op, BtlStatus::Ok);
                rep[8..10].copy_from_slice(&acc.local_cid.to_le_bytes());
                rep[10..12].copy_from_slice(&acc.remote_mtu.to_le_bytes());
                rep[12..18].copy_from_slice(&acc.peer_addr.0);
                rep[18..20].copy_from_slice(&acc.psm.to_le_bytes());
                20
            }
            BtlOp::L2capSend => {
                if payload.len() < 4 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let local_cid = u16::from_le_bytes([payload[0], payload[1]]);
                let dlen = usize::from(u16::from_le_bytes([payload[2], payload[3]]));
                if payload.len() < 4 + dlen || dlen > MAX_L2CAP_IPC_PAYLOAD {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let sdu = &payload[4..4 + dlen];

                let Some(ep) = self
                    .endpoints
                    .iter()
                    .find(|e| e.local_cid == local_cid && e.owner_client_id == client_id)
                else {
                    btl::write_header(rep, op, BtlStatus::ChannelClosed);
                    return 8;
                };
                if !ep.open {
                    btl::write_header(rep, op, BtlStatus::ChannelClosed);
                    return 8;
                }

                let needed_frags =
                    ((4 + sdu.len()).div_ceil(usize::from(self.credits.max_acl_len))).max(1) as u16;
                if self.credits.available_credits() < needed_frags {
                    self.pump_transport(16);
                }
                if self.credits.available_credits() < needed_frags {
                    btl::write_header(rep, op, BtlStatus::Congested);
                    return 8;
                }

                if !self.l2cap.send_data(local_cid, sdu) {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                self.flush_l2cap_events_and_tx();
                self.pump_transport(4);

                rep[..12].fill(0);
                btl::write_header(rep, op, BtlStatus::Ok);
                rep[8..10].copy_from_slice(&self.credits.available_credits().to_le_bytes());
                rep[10] = self.credits.congestion_percent();
                12
            }
            BtlOp::L2capRecv => {
                if payload.len() < 4 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let local_cid = u16::from_le_bytes([payload[0], payload[1]]);
                let max_len = usize::from(u16::from_le_bytes([payload[2], payload[3]]))
                    .min(MAX_L2CAP_IPC_PAYLOAD);
                self.pump_transport(8);

                let Some(ep) = self
                    .endpoints
                    .iter_mut()
                    .find(|e| e.local_cid == local_cid && e.owner_client_id == client_id)
                else {
                    btl::write_header(rep, op, BtlStatus::ChannelClosed);
                    return 8;
                };
                if let Some(pkt) = ep.rx_queue.pop_front() {
                    let take = pkt.len().min(max_len);
                    rep[..12].fill(0);
                    btl::write_header(rep, op, BtlStatus::Ok);
                    rep[8..10].copy_from_slice(&(take as u16).to_le_bytes());
                    rep[10..12].copy_from_slice(&self.credits.available_credits().to_le_bytes());
                    rep[12..12 + take].copy_from_slice(&pkt[..take]);
                    12 + take
                } else if ep.open {
                    btl::write_header(rep, op, BtlStatus::WouldBlock);
                    8
                } else {
                    btl::write_header(rep, op, BtlStatus::ChannelClosed);
                    8
                }
            }
            BtlOp::L2capClose => {
                if payload.len() < 2 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let local_cid = u16::from_le_bytes([payload[0], payload[1]]);
                let owned = self
                    .endpoints
                    .iter()
                    .any(|e| e.local_cid == local_cid && e.owner_client_id == client_id);
                if owned {
                    self.endpoints.retain(|e| e.local_cid != local_cid);
                    let _ = self.l2cap.disconnect(local_cid);
                    self.flush_l2cap_events_and_tx();
                    self.pump_transport(4);
                }
                btl::write_header(rep, op, BtlStatus::Ok);
                8
            }
            BtlOp::ReadSnoop => {
                if payload.len() < 6 {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                }
                let offset =
                    u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                let max_len = usize::from(u16::from_le_bytes([payload[4], payload[5]]))
                    .min(MAX_L2CAP_IPC_PAYLOAD);
                let snoop_blob = self.snoop.export_bytes();
                let total_len = snoop_blob.len();
                let chunk = if offset < total_len {
                    let end = (offset + max_len).min(total_len);
                    &snoop_blob[offset..end]
                } else {
                    &[][..]
                };
                rep[..16].fill(0);
                btl::write_header(rep, op, BtlStatus::Ok);
                rep[8..12].copy_from_slice(&(total_len as u32).to_le_bytes());
                rep[12..14].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
                rep[16..16 + chunk.len()].copy_from_slice(chunk);
                16 + chunk.len()
            }
            BtlOp::SetPower => {
                let Some(&mode) = payload.first() else {
                    btl::write_header(rep, op, BtlStatus::InvalidRequest);
                    return 8;
                };
                let st = match mode {
                    0 => {
                        self.power_off();
                        BtlStatus::Ok
                    }
                    1 => match self.bring_up_usb_controller() {
                        Ok(()) => BtlStatus::Ok,
                        Err(_) if self.transport == BtlTransportKind::VirtualLoopback => {
                            match self.bring_up_virtual_controller() {
                                Ok(()) => BtlStatus::Ok,
                                Err(e) => e,
                            }
                        }
                        Err(e) => e,
                    },
                    2 => match self.bring_up_virtual_controller() {
                        Ok(()) => {
                            let _ = self.run_inquiry_scan(1);
                            BtlStatus::Ok
                        }
                        Err(e) => e,
                    },
                    _ => BtlStatus::InvalidRequest,
                };
                btl::write_header(rep, op, st);
                8
            }
            BtlOp::SetCoexHint => {
                let active = payload.first().copied().unwrap_or(0) != 0;
                *client_streaming_hint = active;
                btl::write_header(rep, op, BtlStatus::Ok);
                8
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
    let _ = bootstrap.write(b"service:btl:starting");

    let mut rt = BtlRuntime::new();
    let mut clients: Vec<Option<BtlClientConn>> = Vec::with_capacity(MAX_CLIENTS);
    let mut next_client_id: u32 = 1;

    // Drain any initial bootstrap handles supplied at spawn
    let boot_deadline = monotonic_ms().saturating_add(40);
    for _budget in 0..32u32 {
        let mut buf = [0u8; 64];
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(h))) => {
                accept_bootstrap_handle(&mut rt, &mut clients, &mut next_client_id, &buf[..n], h);
            }
            Ok(_) => {}
            Err(ErrorCode::ShouldWait) => {
                if rt.bootfs_vmo.is_some() || monotonic_ms() >= boot_deadline {
                    break;
                }
                libcanvas::process::yield_now();
            }
            Err(_) => break,
        }
    }

    // Probe USB-BT if already bridged; under `boot-selftest` fall back to virtual AirBuds Pro
    if rt.usb_bt_ch.is_some() {
        if let Err(st) = rt.bring_up_usb_controller() {
            println!("[btl-service] USB-BT bring-up returned {:?}", st);
        }
    }
    #[cfg(feature = "boot-selftest")]
    if !rt.powered && rt.bring_up_virtual_controller().is_ok() {
        let _ = rt.run_inquiry_scan(1);
        println!("[btl-service] boot-selftest virtual radio online (HuesOS AirBuds Pro)");
    }

    let _ = bootstrap.write(b"service:btl:ready");
    println!(
        "[btl-service] ready (transport={}, powered={})",
        rt.transport.as_str(),
        rt.powered
    );

    let mut req_buf = [0u8; 1100];
    let mut rep_buf = [0u8; 1100];

    loop {
        let mut did_work = rt.pump_transport(16);

        // 1. Accept runtime handles from DriverManager (`usb-bt-hci`, `hxfs:client`, `coex:wlan`, clients)
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

        // 2. Service HBTL client requests
        #[allow(clippy::needless_range_loop)]
        for idx in 0..clients.len() {
            let mut drop_cid: Option<u32> = None;
            let mut got_len = 0usize;
            let mut cid = 0u32;
            let mut perm = ClientPerm::ReadOnly;
            let mut hint = false;

            if let Some(c) = clients[idx].as_ref() {
                cid = c.id;
                perm = c.perm;
                hint = c.streaming_hint;
                match c.ch.read_into(&mut req_buf) {
                    Ok(n) => got_len = n,
                    Err(ErrorCode::ShouldWait) => {}
                    Err(_) => drop_cid = Some(c.id),
                }
            }
            if let Some(dead_id) = drop_cid {
                clients[idx] = None;
                rt.cleanup_client(dead_id);
                recompute_streaming_hint(&mut rt, &clients);
                continue;
            }
            if got_len == 0 {
                continue;
            }
            did_work = true;
            let prev_hint = hint;
            let rep_len =
                rt.handle_client_request(cid, perm, &mut hint, &req_buf[..got_len], &mut rep_buf);
            if let Some(c) = clients[idx].as_mut() {
                c.streaming_hint = hint;
                let _ = c.ch.write(&rep_buf[..rep_len]);
            }
            if hint != prev_hint {
                recompute_streaming_hint(&mut rt, &clients);
            }
        }

        if did_work {
            continue;
        }

        // Wait on bootstrap + active client channels; wake every 1 tick (10 ms) if USB-BT is active
        let mut items = [WaitItem::new(0, Signals::NONE, 0); 24];
        items[0] = WaitItem::new(
            bootstrap.handle().raw(),
            Signals::READABLE | Signals::PEER_CLOSED,
            0,
        );
        let mut item_count = 1usize;
        for c in clients.iter().flatten() {
            if item_count < items.len() {
                items[item_count] = WaitItem::new(
                    c.ch.handle().raw(),
                    Signals::READABLE | Signals::PEER_CLOSED,
                    item_count as u64,
                );
                item_count += 1;
            }
        }
        let timeout_ticks = if rt.powered
            && matches!(
                rt.transport,
                BtlTransportKind::UsbRealtek8821c | BtlTransportKind::UsbGenericHci
            ) {
            1
        } else {
            10
        };
        let _ = wait_any(&items[..item_count], timeout_ticks);
    }
}

fn recompute_streaming_hint(rt: &mut BtlRuntime, clients: &[Option<BtlClientConn>]) {
    rt.streaming_hint_active = clients.iter().flatten().any(|c| c.streaming_hint);
    rt.sync_coex_profile();
}

fn accept_bootstrap_handle(
    rt: &mut BtlRuntime,
    clients: &mut Vec<Option<BtlClientConn>>,
    next_client_id: &mut u32,
    tag: &[u8],
    handle: libcanvas::Handle,
) {
    if tag == b"bootfs-vmo" || tag == b"bootfs:vmo" {
        rt.bootfs_vmo = Some(Vmo::from_handle(handle));
    } else if tag == b"usb-bt-hci" {
        rt.usb_bt_ch = Some(Channel::from_handle(handle));
        if rt.transport == BtlTransportKind::Absent
            || rt.transport == BtlTransportKind::VirtualLoopback
        {
            if rt.bring_up_usb_controller().is_ok() {
                println!(
                    "[btl-service] attached USB Bluetooth HCI ({:04x}:{:04x})",
                    rt.usb_vid, rt.usb_pid
                );
            }
        }
    } else if tag == b"hxfs:client" {
        rt.attach_hxfs(Channel::from_handle(handle));
    } else if tag == b"coex:wlan" {
        rt.wlan_coex_ch = Some(Channel::from_handle(handle));
        rt.push_coex_to_wlan();
    } else if tag == b"btl-client:ro"
        || tag == b"btl-client:rw"
        || tag == b"btl-client"
        || tag == b"btl-client:admin"
    {
        let perm = if tag == b"btl-client:ro" {
            ClientPerm::ReadOnly
        } else if tag == b"btl-client:rw" {
            ClientPerm::ReadWrite
        } else {
            ClientPerm::Admin
        };
        let id = *next_client_id;
        *next_client_id = next_client_id.wrapping_add(1).max(1);
        let conn = BtlClientConn {
            id,
            ch: Channel::from_handle(handle),
            perm,
            streaming_hint: false,
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
