//! `/services/wlan.elf` — isolated IEEE 802.11 + WPA2-PSK CCMP + Realtek
//! RTL8821CE (`10ec:c821`) Wi-Fi service speaking the `HWLN` wire protocol.
//!
//! Secret isolation guarantee: WPA2 passphrases, derived 256-bit `PMK`s, and
//! transient `PTK`/`GTK` keys reside exclusively in this process's address
//! space and are never serialized back over IPC.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

use huesos_abi::vmar_flags;
use huesos_abi::wlan::{
    self, MacPolicyMode, RegDomainCode, WlanBssInfo, WlanOp, WlanProfileSummary, WlanSecurity,
    WlanStateCode, WlanStatus, WlanStatusSnapshot, MAX_SSID_LEN,
};
use huesos_ieee80211::{
    build_assoc_request, build_auth_frame, build_data_frame, build_deauth, build_llc_snap_payload,
    build_probe_request, parse_assoc_response, parse_auth_frame, parse_beacon_or_probe_resp,
    parse_llc_snap_payload, Dot11Header, ScanTable, SecurityMode, FC_FLAG_PROTECTED, FC_TYPE_DATA,
    FC_TYPE_MGMT, MGMT_SUBTYPE_ASSOC_RESP, MGMT_SUBTYPE_AUTH, MGMT_SUBTYPE_BEACON,
    MGMT_SUBTYPE_PROBE_RESP,
};
use huesos_net::wire::{EthFrame, ETHERTYPE_EAPOL};
use huesos_net::{MacAddr, NetStack};
#[cfg(feature = "boot-selftest")]
use huesos_rtw88::VirtualRtw88Medium;
use huesos_rtw88::{
    decode_rx_pkt_desc, encode_pci_bd, encode_tx_pkt_desc, program_hw_bssid_and_ccmp_cam,
    read_hw_mac, Rtw88FirmwareInfo, Rtw88Mmio, REG_BEQ_TXBD_DESA_HI, REG_BEQ_TXBD_DESA_LO,
    REG_BEQ_TXBD_IDX, REG_BEQ_TXBD_NUM, REG_CR, REG_MGQ_TXBD_DESA_HI, REG_MGQ_TXBD_DESA_LO,
    REG_MGQ_TXBD_IDX, REG_RCR, REG_RXQ_RXBD_DESA_HI, REG_RXQ_RXBD_DESA_LO, REG_RXQ_RXBD_IDX,
    REG_RXQ_RXBD_NUM, RTW_RX_DESC_SIZE, RTW_TX_DESC_SIZE,
};
use huesos_wpa::{derive_wpa2_psk, hmac_sha1_parts, CcmpContext, Supplicant4Way};
use libcanvas::{println, Channel, ErrorCode, Handle, Vmo};

#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";
const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const FW_PATH: &str = "/lib/firmware/rtw88/rtw8821c_fw.bin";

const WLAN_MMIO_VA: u64 = 0x0000_7300_0000_0000;
const WLAN_DMA_VA: u64 = 0x0000_7310_0000_0000;

struct PcieBarMmio {
    base_va: usize,
    len: usize,
}

impl Rtw88Mmio for PcieBarMmio {
    fn read8(&self, offset: u32) -> u8 {
        if (offset as usize) < self.len {
            // SAFETY: offset validated within mapped BAR2 MMIO window.
            unsafe { read_volatile((self.base_va + offset as usize) as *const u8) }
        } else {
            0
        }
    }
    fn read16(&self, offset: u32) -> u16 {
        if (offset as usize) + 2 <= self.len {
            // SAFETY: offset validated within mapped BAR2 MMIO window.
            unsafe { read_volatile((self.base_va + offset as usize) as *const u16) }
        } else {
            0
        }
    }
    fn read32(&self, offset: u32) -> u32 {
        if (offset as usize) + 4 <= self.len {
            // SAFETY: offset validated within mapped BAR2 MMIO window.
            unsafe { read_volatile((self.base_va + offset as usize) as *const u32) }
        } else {
            0
        }
    }
    fn write8(&mut self, offset: u32, val: u8) {
        if (offset as usize) < self.len {
            // SAFETY: offset validated within mapped BAR2 MMIO window.
            unsafe { write_volatile((self.base_va + offset as usize) as *mut u8, val) }
        }
    }
    fn write16(&mut self, offset: u32, val: u16) {
        if (offset as usize) + 2 <= self.len {
            // SAFETY: offset validated within mapped BAR2 MMIO window.
            unsafe { write_volatile((self.base_va + offset as usize) as *mut u16, val) }
        }
    }
    fn write32(&mut self, offset: u32, val: u32) {
        if (offset as usize) + 4 <= self.len {
            // SAFETY: offset validated within mapped BAR2 MMIO window.
            unsafe { write_volatile((self.base_va + offset as usize) as *mut u32, val) }
        }
    }
}

struct SavedPmkProfile {
    ssid: [u8; MAX_SSID_LEN],
    ssid_len: u8,
    pmk: [u8; 32],
    fingerprint: [u8; 4],
    autoconnect: bool,
}

struct WlanClientConn {
    ch: Channel,
    admin: bool,
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

fn parse_hex_u64(s: &str) -> Option<u64> {
    let trimmed = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(trimmed, 16).ok()
}

fn channel_allowed(domain: RegDomainCode, ch: u8) -> bool {
    match domain {
        RegDomainCode::Unlocked => (1..=14).contains(&ch) || (36..=165).contains(&ch),
        RegDomainCode::Jp => (1..=14).contains(&ch) || (36..=144).contains(&ch),
        RegDomainCode::Us => (1..=11).contains(&ch) || (36..=165).contains(&ch),
        RegDomainCode::Ru | RegDomainCode::Eu | RegDomainCode::World => {
            (1..=13).contains(&ch) || (36..=165).contains(&ch)
        }
    }
}

const RTW_RING_LEN: usize = 32;
const RTW_BUF_STRIDE: usize = 2048;

struct Rtw88PcieDma {
    dma_va: usize,
    dma_pa: u64,
    tx_idx: u16,
    rx_idx: u16,
}

impl Rtw88PcieDma {
    fn init_rings(
        mmio: &mut PcieBarMmio,
        dma_va: usize,
        dma_pa: u64,
        dma_len: usize,
    ) -> Option<Self> {
        // Layout in mapped DMA window:
        //   0x0000..0x0200: 32 * 16B TX BD ring (BEQ/MGQ shared)
        //   0x1000..0x1200: 32 * 16B RX BD ring
        //   0x2000..0x12000: 32 * 2 KiB TX packet buffers
        //   0x12000..0x22000: 32 * 2 KiB RX packet buffers
        if dma_len < 0x22000 {
            return None;
        }
        for i in 0..RTW_RING_LEN {
            let rx_buf_pa = dma_pa + 0x12000 + (i * RTW_BUF_STRIDE) as u64;
            let bd = encode_pci_bd(rx_buf_pa, RTW_BUF_STRIDE as u16, true);
            let bd_va = dma_va + 0x1000 + i * 16;
            // SAFETY: `bd_va..bd_va+16` lies inside the 0x22000-byte mapped DMA window.
            unsafe {
                core::ptr::copy_nonoverlapping(bd.as_ptr(), bd_va as *mut u8, 16);
            }
        }
        let tx_ring_pa = dma_pa;
        let rx_ring_pa = dma_pa + 0x1000;
        mmio.write32(REG_BEQ_TXBD_DESA_LO, tx_ring_pa as u32);
        mmio.write32(REG_BEQ_TXBD_DESA_HI, (tx_ring_pa >> 32) as u32);
        mmio.write32(REG_MGQ_TXBD_DESA_LO, tx_ring_pa as u32);
        mmio.write32(REG_MGQ_TXBD_DESA_HI, (tx_ring_pa >> 32) as u32);
        mmio.write32(REG_RXQ_RXBD_DESA_LO, rx_ring_pa as u32);
        mmio.write32(REG_RXQ_RXBD_DESA_HI, (rx_ring_pa >> 32) as u32);
        mmio.write16(REG_BEQ_TXBD_NUM, RTW_RING_LEN as u16);
        mmio.write16(REG_RXQ_RXBD_NUM, RTW_RING_LEN as u16);
        mmio.write8(REG_CR, 0x0C); // MACTXEN | MACRXEN
        mmio.write32(REG_RCR, 0x0000_000E); // APM | AM | AB
        Some(Self {
            dma_va,
            dma_pa,
            tx_idx: 0,
            rx_idx: 0,
        })
    }

    fn submit_tx(&mut self, mmio: &mut PcieBarMmio, mpdu: &[u8]) -> bool {
        if RTW_TX_DESC_SIZE + mpdu.len() > RTW_BUF_STRIDE {
            return false;
        }
        let slot = usize::from(self.tx_idx) % RTW_RING_LEN;
        let buf_off = 0x2000 + slot * RTW_BUF_STRIDE;
        let is_mgmt = mpdu.first().is_some_and(|fc0| ((fc0 >> 2) & 0x3) == 0);
        let mut tx_desc = [0u8; RTW_TX_DESC_SIZE];
        encode_tx_pkt_desc(mpdu.len() as u16, is_mgmt, 0x04, &mut tx_desc);
        let total_len = RTW_TX_DESC_SIZE + mpdu.len();
        // SAFETY: `buf_off + total_len <= 0x12000` within mapped DMA buffer, and
        // `slot * 16 + 16 <= 0x0200` within TX BD ring.
        unsafe {
            let dst = (self.dma_va + buf_off) as *mut u8;
            core::ptr::copy_nonoverlapping(tx_desc.as_ptr(), dst, RTW_TX_DESC_SIZE);
            core::ptr::copy_nonoverlapping(mpdu.as_ptr(), dst.add(RTW_TX_DESC_SIZE), mpdu.len());
            let bd = encode_pci_bd(self.dma_pa + buf_off as u64, total_len as u16, true);
            core::ptr::copy_nonoverlapping(bd.as_ptr(), (self.dma_va + slot * 16) as *mut u8, 16);
        }
        self.tx_idx = ((slot + 1) % RTW_RING_LEN) as u16;
        if is_mgmt {
            mmio.write16(REG_MGQ_TXBD_IDX, self.tx_idx);
        } else {
            mmio.write16(REG_BEQ_TXBD_IDX, self.tx_idx);
        }
        true
    }

    fn poll_rx(&mut self, mmio: &mut PcieBarMmio) -> Option<(i8, Vec<u8>)> {
        let slot = usize::from(self.rx_idx) % RTW_RING_LEN;
        let bd_va = self.dma_va + 0x1000 + slot * 16;
        // SAFETY: `bd_va` is 4-byte aligned inside the mapped RX BD ring.
        let dw0 = unsafe { read_volatile(bd_va as *const u32) };
        if (dw0 & (1u32 << 31)) != 0 {
            return None; // Still owned by RTL8821CE DMA engine
        }
        let buf_off = 0x12000 + slot * RTW_BUF_STRIDE;
        let mut raw_desc = [0u8; RTW_RX_DESC_SIZE];
        // SAFETY: `buf_off + RTW_BUF_STRIDE <= 0x22000` within mapped DMA buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.dma_va + buf_off) as *const u8,
                raw_desc.as_mut_ptr(),
                RTW_RX_DESC_SIZE,
            );
        }
        let (pkt_len, drv_info_sz, crc_err, rssi) = decode_rx_pkt_desc(&raw_desc);
        let hdr_skip = RTW_RX_DESC_SIZE + drv_info_sz;
        let mut out = None;
        if !crc_err && pkt_len > 0 && hdr_skip + pkt_len <= RTW_BUF_STRIDE {
            let mut mpdu = alloc::vec![0u8; pkt_len];
            // SAFETY: `hdr_skip + pkt_len <= RTW_BUF_STRIDE` verified above.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.dma_va + buf_off + hdr_skip) as *const u8,
                    mpdu.as_mut_ptr(),
                    pkt_len,
                );
            }
            out = Some((rssi, mpdu));
        }
        let rearm = encode_pci_bd(self.dma_pa + buf_off as u64, RTW_BUF_STRIDE as u16, true);
        // SAFETY: `bd_va..bd_va+16` lies inside the mapped RX BD ring.
        unsafe {
            core::ptr::copy_nonoverlapping(rearm.as_ptr(), bd_va as *mut u8, 16);
        }
        self.rx_idx = ((slot + 1) % RTW_RING_LEN) as u16;
        mmio.write16(REG_RXQ_RXBD_IDX, self.rx_idx);
        out
    }
}

struct WlanRuntime {
    hw_mmio: Option<PcieBarMmio>,
    hw_dma: Option<Rtw88PcieDma>,
    #[cfg(feature = "boot-selftest")]
    medium: VirtualRtw88Medium,
    fw_info: Option<Rtw88FirmwareInfo>,
    factory_mac: [u8; 6],
    active_mac: [u8; 6],
    mac_policy: MacPolicyMode,
    reg_domain: RegDomainCode,
    autoconnect: bool,
    state: WlanStateCode,
    channel: u8,
    width_mhz: u8,
    rssi_dbm: i8,
    bssid: [u8; 6],
    ssid: [u8; MAX_SSID_LEN],
    ssid_len: u8,
    seq_num: u16,
    tx_frames: u64,
    rx_frames: u64,
    ccmp_replay_drops: u64,
    scan_table: ScanTable,
    profiles: Vec<SavedPmkProfile>,
    supp: Option<Supplicant4Way>,
    tx_ccmp: Option<CcmpContext>,
    rx_ccmp: Option<CcmpContext>,
    net: NetStack,
}

impl WlanRuntime {
    fn has_radio(&self) -> bool {
        self.hw_mmio.is_some() || cfg!(feature = "boot-selftest")
    }

    fn next_seq(&mut self) -> u16 {
        let s = self.seq_num;
        self.seq_num = (self.seq_num + 1) & 0x0FFF;
        s
    }

    fn tx_mpdu(&mut self, _now_ms: u64, mpdu: &[u8]) {
        if let (Some(mmio), Some(dma)) = (self.hw_mmio.as_mut(), self.hw_dma.as_mut()) {
            if dma.submit_tx(mmio, mpdu) {
                self.tx_frames += 1;
            }
        } else {
            #[cfg(feature = "boot-selftest")]
            {
                self.tx_frames += 1;
                self.medium.transmit_sta_mpdu(_now_ms, mpdu);
            }
        }
    }

    fn poll_next_rx_mpdu(&mut self) -> Option<(i8, Vec<u8>)> {
        if let (Some(mmio), Some(dma)) = (self.hw_mmio.as_mut(), self.hw_dma.as_mut()) {
            return dma.poll_rx(mmio);
        }
        #[cfg(feature = "boot-selftest")]
        {
            self.medium.poll_rx_mpdu()
        }
        #[cfg(not(feature = "boot-selftest"))]
        {
            None
        }
    }

    fn pump_air(&mut self, now_ms: u64) {
        if !self.has_radio() {
            return;
        }
        while let Some((rssi, mpdu)) = self.poll_next_rx_mpdu() {
            self.rx_frames += 1;
            let Ok(hdr) = Dot11Header::parse(&mpdu) else {
                continue;
            };
            match hdr.frame_type {
                FC_TYPE_MGMT => match hdr.subtype {
                    MGMT_SUBTYPE_BEACON | MGMT_SUBTYPE_PROBE_RESP => {
                        if let Ok(bss) = parse_beacon_or_probe_resp(&mpdu, 1, rssi) {
                            if channel_allowed(self.reg_domain, bss.channel) {
                                self.scan_table.upsert(bss);
                            }
                        }
                    }
                    MGMT_SUBTYPE_AUTH => {
                        if self.state == WlanStateCode::Authenticating {
                            if let Ok((bssid, 0, 2, 0)) = parse_auth_frame(&mpdu) {
                                if bssid == self.bssid {
                                    self.state = WlanStateCode::Associating;
                                    let sec = self
                                        .scan_table
                                        .find_by_ssid(&self.ssid[..self.ssid_len as usize])
                                        .map(|b| b.security)
                                        .unwrap_or(SecurityMode::Open);
                                    let mut buf = [0u8; 192];
                                    let seq = self.next_seq();
                                    if let Ok(n) = build_assoc_request(
                                        self.bssid,
                                        self.active_mac,
                                        &self.ssid[..self.ssid_len as usize],
                                        sec,
                                        seq,
                                        &mut buf,
                                    ) {
                                        self.tx_mpdu(now_ms, &buf[..n]);
                                    }
                                }
                            }
                        }
                    }
                    MGMT_SUBTYPE_ASSOC_RESP if self.state == WlanStateCode::Associating => {
                        if let Ok((bssid, 0, _aid)) = parse_assoc_response(&mpdu) {
                            if bssid == self.bssid {
                                self.rssi_dbm = rssi;
                                if self.supp.is_some() {
                                    self.state = WlanStateCode::Handshaking4Way;
                                } else {
                                    self.state = WlanStateCode::Connected;
                                    self.start_wlan_dhcp(now_ms);
                                }
                            }
                        }
                    }
                    _ => {}
                },
                FC_TYPE_DATA => {
                    let plain = if (hdr.flags & FC_FLAG_PROTECTED) != 0 {
                        let Some(rx_c) = self.rx_ccmp.as_mut() else {
                            continue;
                        };
                        match rx_c.decrypt_mpdu(&mpdu) {
                            Ok(pt) => pt,
                            Err(_) => {
                                self.ccmp_replay_drops += 1;
                                continue;
                            }
                        }
                    } else {
                        hdr.body.to_vec()
                    };
                    let Ok((ethertype, l3)) = parse_llc_snap_payload(&plain) else {
                        continue;
                    };
                    if ethertype == ETHERTYPE_EAPOL {
                        if let Some(supp) = self.supp.as_mut() {
                            if let Ok(reply_eapol) = supp.on_eapol_frame(l3) {
                                let installed = supp.installed_keys().copied();
                                self.send_llc_data(
                                    now_ms,
                                    self.bssid,
                                    ETHERTYPE_EAPOL,
                                    &reply_eapol,
                                    false,
                                );
                                if let Some(keys) = installed {
                                    self.tx_ccmp = Some(CcmpContext::new(keys.ptk.tk, 0));
                                    self.rx_ccmp = Some(CcmpContext::new(keys.ptk.tk, 0));
                                    if let Some(mmio) = self.hw_mmio.as_mut() {
                                        program_hw_bssid_and_ccmp_cam(
                                            mmio,
                                            &self.bssid,
                                            &self.active_mac,
                                            Some(&keys.ptk.tk),
                                        );
                                    }
                                    self.state = WlanStateCode::Connected;
                                    self.start_wlan_dhcp(now_ms);
                                }
                            }
                        }
                    } else {
                        let mut eth = alloc::vec![0u8; 14 + l3.len()];
                        if EthFrame::emit(
                            MacAddr(self.active_mac),
                            MacAddr(hdr.addr3),
                            ethertype,
                            l3,
                            &mut eth,
                        )
                        .is_ok()
                        {
                            let mut tx_eth = VecDeque::new();
                            self.net.ingest_frame(now_ms, &eth, &mut tx_eth);
                            self.flush_net_to_air(now_ms, &mut tx_eth);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn send_llc_data(
        &mut self,
        now_ms: u64,
        dst_eth: [u8; 6],
        ethertype: u16,
        l3: &[u8],
        encrypt: bool,
    ) {
        let mut llc = alloc::vec![0u8; 8 + l3.len()];
        let Ok(llc_len) = build_llc_snap_payload(ethertype, l3, &mut llc) else {
            return;
        };
        let seq = self.next_seq();
        if encrypt {
            let mut hdr = [0u8; 24];
            if build_data_frame(
                true,
                true,
                self.bssid,
                self.active_mac,
                dst_eth,
                seq,
                &[],
                &mut hdr,
            )
            .is_ok()
            {
                if let Some(mpdu) = self
                    .tx_ccmp
                    .as_mut()
                    .and_then(|c| c.encrypt_mpdu(&hdr, &llc[..llc_len]).ok())
                {
                    self.tx_mpdu(now_ms, &mpdu);
                }
            }
        } else {
            let mut mpdu = alloc::vec![0u8; 24 + llc_len];
            if let Ok(n) = build_data_frame(
                true,
                false,
                self.bssid,
                self.active_mac,
                dst_eth,
                seq,
                &llc[..llc_len],
                &mut mpdu,
            ) {
                self.tx_mpdu(now_ms, &mpdu[..n]);
            }
        }
    }

    fn start_wlan_dhcp(&mut self, now_ms: u64) {
        self.net.cfg.mac = MacAddr(self.active_mac);
        let mut tx_eth = VecDeque::new();
        self.net.start_dhcp(now_ms, &mut tx_eth);
        self.flush_net_to_air(now_ms, &mut tx_eth);
    }

    fn flush_net_to_air(&mut self, now_ms: u64, tx_eth: &mut VecDeque<Vec<u8>>) {
        let encrypted = self.tx_ccmp.is_some();
        while let Some(raw_eth) = tx_eth.pop_front() {
            if let Ok(eth) = EthFrame::parse(&raw_eth) {
                self.send_llc_data(now_ms, eth.dst.0, eth.ethertype, eth.payload, encrypted);
            }
        }
    }

    fn run_scan(&mut self, now_ms: u64) {
        self.scan_table.clear();
        if !self.has_radio() {
            return;
        }
        let mut buf = [0u8; 128];
        let seq = self.next_seq();
        if let Ok(n) = build_probe_request(self.active_mac, b"", seq, &mut buf) {
            self.tx_mpdu(now_ms, &buf[..n]);
            self.pump_air(now_ms);
        }
    }

    fn connect_ssid(&mut self, now_ms: u64, ssid: &[u8], passphrase: &[u8]) -> WlanStatus {
        if !self.has_radio() {
            return WlanStatus::HardwareAbsent;
        }
        if self.fw_info.is_none() {
            return WlanStatus::FirmwareUnavailable;
        }
        if self.scan_table.find_by_ssid(ssid).is_none() {
            self.run_scan(now_ms);
        }
        let Some(target) = self.scan_table.find_by_ssid(ssid) else {
            return WlanStatus::AuthFailed;
        };
        if !channel_allowed(self.reg_domain, target.channel) {
            return WlanStatus::RegulatoryBlocked;
        }

        self.supp = None;
        self.tx_ccmp = None;
        self.rx_ccmp = None;

        if target.security == SecurityMode::Wpa2PskCcmp {
            let pmk = if passphrase.is_empty() {
                if let Some(saved) = self
                    .profiles
                    .iter()
                    .find(|p| &p.ssid[..p.ssid_len as usize] == ssid)
                {
                    saved.pmk
                } else {
                    return WlanStatus::InvalidPassphrase;
                }
            } else {
                let Ok(derived) = derive_wpa2_psk(passphrase, ssid) else {
                    return WlanStatus::InvalidPassphrase;
                };
                let tag_full = hmac_sha1_parts(&derived, &[b"huesos-pmk-fingerprint", ssid]);
                let fp = [tag_full[0], tag_full[1], tag_full[2], tag_full[3]];
                if let Some(existing) = self
                    .profiles
                    .iter_mut()
                    .find(|p| &p.ssid[..p.ssid_len as usize] == ssid)
                {
                    existing.pmk = derived;
                    existing.fingerprint = fp;
                } else if self.profiles.len() < wlan::MAX_PROFILE_SUMMARIES {
                    let mut s_arr = [0u8; MAX_SSID_LEN];
                    s_arr[..ssid.len()].copy_from_slice(ssid);
                    self.profiles.push(SavedPmkProfile {
                        ssid: s_arr,
                        ssid_len: ssid.len() as u8,
                        pmk: derived,
                        fingerprint: fp,
                        autoconnect: true,
                    });
                }
                derived
            };
            let snonce = [0x3Cu8; 32];
            self.supp = Some(Supplicant4Way::new(
                pmk,
                target.bssid,
                self.active_mac,
                snonce,
            ));
        }

        self.bssid = target.bssid;
        self.channel = target.channel;
        self.width_mhz = if target.channel >= 36 { 80 } else { 20 };
        self.ssid.fill(0);
        self.ssid[..ssid.len()].copy_from_slice(ssid);
        self.ssid_len = ssid.len() as u8;
        self.state = WlanStateCode::Authenticating;

        let mut buf = [0u8; 64];
        let seq = self.next_seq();
        if let Ok(n) = build_auth_frame(
            target.bssid,
            self.active_mac,
            target.bssid,
            1,
            0,
            seq,
            &mut buf,
        ) {
            self.tx_mpdu(now_ms, &buf[..n]);
        }
        for step in 0..8u64 {
            self.pump_air(now_ms + step);
            if self.state == WlanStateCode::Connected {
                return WlanStatus::Ok;
            }
        }
        self.state = WlanStateCode::Idle;
        WlanStatus::AuthFailed
    }

    fn disconnect(&mut self, now_ms: u64) {
        if self.state == WlanStateCode::Connected || self.state == WlanStateCode::SoftAp {
            let mut buf = [0u8; 64];
            let seq = self.next_seq();
            if let Ok(n) = build_deauth(self.bssid, self.active_mac, self.bssid, 3, seq, &mut buf) {
                self.tx_mpdu(now_ms, &buf[..n]);
            }
        }
        self.supp = None;
        self.tx_ccmp = None;
        self.rx_ccmp = None;
        self.bssid = [0; 6];
        self.ssid.fill(0);
        self.ssid_len = 0;
        self.channel = 0;
        self.rssi_dbm = -127;
        self.state = if self.has_radio() {
            if self.fw_info.is_some() {
                WlanStateCode::Idle
            } else {
                WlanStateCode::FirmwareMissing
            }
        } else {
            WlanStateCode::HardwareAbsent
        };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // SAFETY: called once at startup before any allocations.
    if unsafe { !HEAP.init() } {
        libcanvas::process::exit(-10);
    }

    let bootstrap = libcanvas::channel::bootstrap();
    let mut bootfs_vmo: Option<Vmo> = None;
    let mut mmio_res: Option<(Handle, u64, u64)> = None;
    let mut dma_res: Option<(Handle, u64, u64)> = None;

    let mut label_buf = [0u8; 128];
    for _ in 0..256 {
        match bootstrap.read_optional_handle_timeout(&mut label_buf, 100) {
            Ok((n, handle_opt)) => {
                let msg = core::str::from_utf8(&label_buf[..n]).unwrap_or("");
                if msg == "resource:transfer-complete" {
                    break;
                }
                if msg == "bootfs-vmo" {
                    if let Some(h) = handle_opt {
                        bootfs_vmo = Some(Vmo::from_handle(h));
                    }
                } else if let Some(rest) = msg.strip_prefix("resource:wlan-service:") {
                    let mut parts = rest.split(':');
                    let kind = parts.next().unwrap_or("");
                    let base = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    let len = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    if let Some(h) = handle_opt {
                        if kind == "mmio" && len >= 0x1000 && mmio_res.is_none() {
                            mmio_res = Some((h, base, len));
                        } else if kind == "dma" && dma_res.is_none() {
                            dma_res = Some((h, base, len));
                        }
                    }
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => break,
        }
    }

    let mut mapped_dma: Option<(usize, u64, usize)> = None;
    if let Some((dma_h, pa, len)) = dma_res.as_ref() {
        let map_len = (*len).min(4 * 1024 * 1024) & !0xFFF;
        if map_len >= 0x1000
            && libcanvas::resource::map_self(
                dma_h,
                0,
                WLAN_DMA_VA,
                map_len,
                vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
            )
            .is_ok()
        {
            mapped_dma = Some((WLAN_DMA_VA as usize, *pa, map_len as usize));
        }
    }

    let mut hw_mmio: Option<PcieBarMmio> = None;
    if let Some((mmio_h, _base, len)) = mmio_res {
        let map_len = (len + 0xFFF) & !0xFFF;
        if libcanvas::resource::map_self(
            &mmio_h,
            0,
            WLAN_MMIO_VA,
            map_len,
            vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
        )
        .is_ok()
        {
            hw_mmio = Some(PcieBarMmio {
                base_va: WLAN_MMIO_VA as usize,
                len: map_len as usize,
            });
        }
    }

    let hw_dma = match (hw_mmio.as_mut(), mapped_dma) {
        (Some(mmio), Some((va, pa, len))) => Rtw88PcieDma::init_rings(mmio, va, pa, len),
        _ => None,
    };

    let fw_info = bootfs_vmo
        .as_ref()
        .and_then(|vmo| read_bootfs_file(vmo, FW_PATH))
        .and_then(|blob| Rtw88FirmwareInfo::parse(&blob).ok());

    #[cfg(feature = "boot-selftest")]
    let fallback_mac = [0x00, 0xE0, 0x4C, 0x88, 0x21, 0xCE];
    #[cfg(not(feature = "boot-selftest"))]
    let fallback_mac = [0u8; 6];

    let factory_mac = hw_mmio.as_ref().map(read_hw_mac).unwrap_or(fallback_mac);

    #[cfg(feature = "boot-selftest")]
    let has_radio_at_boot = true;
    #[cfg(not(feature = "boot-selftest"))]
    let has_radio_at_boot = hw_mmio.is_some();

    if let Some(fw) = fw_info {
        if hw_mmio.is_some() {
            println!(
                "[wlan-service] RTL8821CE (10ec:c821) PCIe online: fw sig={:#06x} v{}.{} ({} B)",
                fw.signature, fw.version, fw.subversion, fw.total_len,
            );
        } else {
            #[cfg(feature = "boot-selftest")]
            println!(
                "[wlan-service] rtw8821c_fw.bin loaded: sig={:#06x} v{}.{} ({} B) hw_pcie=false (boot-selftest)",
                fw.signature, fw.version, fw.subversion, fw.total_len,
            );
            #[cfg(not(feature = "boot-selftest"))]
            println!(
                "[wlan-service] no PCIe 10ec:c821 (RTL8821CE) Wi-Fi adapter detected (fw v{}.{} staged)",
                fw.version, fw.subversion,
            );
        }
    } else {
        println!("[wlan-service] warning: rtw8821c_fw.bin unavailable in BOOTFS");
    }

    let initial_state = if !has_radio_at_boot {
        WlanStateCode::HardwareAbsent
    } else if fw_info.is_some() {
        WlanStateCode::Idle
    } else {
        WlanStateCode::FirmwareMissing
    };

    let mut rt = WlanRuntime {
        hw_mmio,
        hw_dma,
        #[cfg(feature = "boot-selftest")]
        medium: VirtualRtw88Medium::new(),
        fw_info,
        factory_mac,
        active_mac: factory_mac,
        mac_policy: MacPolicyMode::Factory,
        reg_domain: RegDomainCode::World,
        autoconnect: true,
        state: initial_state,
        channel: 0,
        width_mhz: 20,
        rssi_dbm: -127,
        bssid: [0; 6],
        ssid: [0; MAX_SSID_LEN],
        ssid_len: 0,
        seq_num: 1,
        tx_frames: 0,
        rx_frames: 0,
        ccmp_replay_drops: 0,
        scan_table: ScanTable::new(),
        profiles: Vec::new(),
        supp: None,
        tx_ccmp: None,
        rx_ccmp: None,
        net: NetStack::new(MacAddr(factory_mac)),
    };

    if rt.has_radio() && rt.fw_info.is_some() {
        rt.run_scan(0);
    }
    let _ = bootstrap.write(b"service:wlan:ready");

    let mut clients: Vec<Option<WlanClientConn>> = Vec::with_capacity(16);
    let mut tick_ms = 10u64;

    loop {
        tick_ms = tick_ms.wrapping_add(1);
        rt.pump_air(tick_ms);

        // 1. Accept client channels from DriverManager
        for _ in 0..8 {
            let mut bmsg = [0u8; 64];
            match bootstrap.read_optional_handle(&mut bmsg) {
                Ok((n, Some(h))) => {
                    let tag = &bmsg[..n];
                    let is_ro = tag == b"wlan-client:ro";
                    if tag == b"wlan-client" || is_ro {
                        let conn = WlanClientConn {
                            ch: Channel::from_handle(h),
                            admin: !is_ro,
                        };
                        if let Some(slot) = clients.iter_mut().find(|s| s.is_none()) {
                            *slot = Some(conn);
                        } else if clients.len() < 16 {
                            clients.push(Some(conn));
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        // 2. Service HWLN client requests
        let mut req_buf = [0u8; 256];
        #[allow(clippy::needless_range_loop)]
        for idx in 0..clients.len() {
            let mut drop_client = false;
            let mut is_admin = false;
            let mut got_len = 0usize;
            if let Some(c) = clients[idx].as_ref() {
                is_admin = c.admin;
                match c.ch.read_into(&mut req_buf) {
                    Ok(n) => got_len = n,
                    Err(ErrorCode::ShouldWait) => {}
                    Err(_) => drop_client = true,
                }
            }
            if drop_client {
                clients[idx] = None;
                continue;
            }
            if got_len == 0 {
                continue;
            }
            let Some((op, payload)) = wlan::parse_request(&req_buf[..got_len]) else {
                if let Some(c) = clients[idx].as_ref() {
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::Status, WlanStatus::InvalidRequest);
                    let _ = c.ch.write(&rep);
                }
                continue;
            };
            if op.requires_admin() && !is_admin {
                if let Some(c) = clients[idx].as_ref() {
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, op, WlanStatus::AccessDenied);
                    let _ = c.ch.write(&rep);
                }
                continue;
            }

            match op {
                WlanOp::Status => {
                    let fw_ver = rt
                        .fw_info
                        .map(|f| [f.version, u16::from(f.subversion)])
                        .unwrap_or([0, 0]);
                    let snap = WlanStatusSnapshot {
                        adapter_present: rt.hw_mmio.is_some(),
                        firmware_loaded: rt.fw_info.is_some(),
                        autoconnect: rt.autoconnect,
                        state: rt.state,
                        reg_domain: rt.reg_domain,
                        mac_policy: rt.mac_policy,
                        channel: rt.channel,
                        width_mhz: rt.width_mhz,
                        rssi_dbm: rt.rssi_dbm,
                        thermal_celsius: if rt.hw_mmio.is_some() { 43 } else { 0 },
                        xtal_cap: if rt.hw_mmio.is_some() { 0x20 } else { 0 },
                        saved_profiles: rt.profiles.len() as u8,
                        pci_bdf: 0,
                        fw_version: fw_ver,
                        factory_mac: rt.factory_mac,
                        active_mac: rt.active_mac,
                        bssid: rt.bssid,
                        ssid_len: rt.ssid_len,
                        ssid: rt.ssid,
                        tx_frames: rt.tx_frames,
                        rx_frames: rt.rx_frames,
                        ccmp_replay_drops: rt.ccmp_replay_drops,
                    };
                    let mut out = [0u8; 128];
                    if let (Some(n), Some(c)) = (snap.encode_reply(&mut out), clients[idx].as_ref())
                    {
                        let _ = c.ch.write(&out[..n]);
                    }
                }
                WlanOp::Scan => {
                    if !rt.has_radio() {
                        let mut rep = [0u8; 8];
                        wlan::write_header(&mut rep, WlanOp::Scan, WlanStatus::HardwareAbsent);
                        if let Some(c) = clients[idx].as_ref() {
                            let _ = c.ch.write(&rep);
                        }
                        continue;
                    }
                    rt.run_scan(tick_ms);
                    let entries = rt.scan_table.entries();
                    let count = entries.len().min(wlan::MAX_SCAN_RESULTS);
                    let mut out = alloc::vec![0u8; 9 + count * WlanBssInfo::WIRE_LEN];
                    wlan::write_header(&mut out, WlanOp::Scan, WlanStatus::Ok);
                    out[8] = count as u8;
                    for (i, b) in entries.iter().take(count).enumerate() {
                        let mut info = WlanBssInfo {
                            bssid: b.bssid,
                            channel: b.channel,
                            width_mhz: if b.channel >= 36 { 80 } else { 20 },
                            rssi_dbm: b.rssi_dbm,
                            security: match b.security {
                                SecurityMode::Open => WlanSecurity::Open,
                                SecurityMode::Wpa2PskCcmp => WlanSecurity::Wpa2Psk,
                            },
                            ht: true,
                            vht: b.channel >= 36,
                            ssid_len: b.ssid_len as u8,
                            ssid: b.ssid,
                        };
                        if info.ssid_len as usize > MAX_SSID_LEN {
                            info.ssid_len = MAX_SSID_LEN as u8;
                        }
                        let pos = 9 + i * WlanBssInfo::WIRE_LEN;
                        let _ = info.encode(&mut out[pos..pos + WlanBssInfo::WIRE_LEN]);
                    }
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&out);
                    }
                }
                WlanOp::Connect => {
                    let st = if payload.len() < 74 {
                        WlanStatus::InvalidRequest
                    } else {
                        let slen = usize::from(payload[0]).min(MAX_SSID_LEN);
                        let plen = usize::from(payload[1]).min(wlan::MAX_PASSPHRASE_LEN);
                        if 34 + plen > payload.len() {
                            WlanStatus::InvalidRequest
                        } else {
                            rt.connect_ssid(tick_ms, &payload[2..2 + slen], &payload[34..34 + plen])
                        }
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::Connect, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::Disconnect => {
                    let st = if !rt.has_radio() {
                        WlanStatus::HardwareAbsent
                    } else {
                        rt.disconnect(tick_ms);
                        WlanStatus::Ok
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::Disconnect, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::ApStart => {
                    let st = if !rt.has_radio() {
                        WlanStatus::HardwareAbsent
                    } else if payload.len() < 40 {
                        WlanStatus::InvalidRequest
                    } else {
                        let ch = payload[0];
                        let slen = usize::from(payload[1]).min(MAX_SSID_LEN);
                        let plen = usize::from(payload[2]).min(wlan::MAX_PASSPHRASE_LEN);
                        if !channel_allowed(rt.reg_domain, ch) {
                            WlanStatus::RegulatoryBlocked
                        } else if 35 + plen > payload.len()
                            || derive_wpa2_psk(&payload[35..35 + plen], &payload[3..3 + slen])
                                .is_err()
                        {
                            WlanStatus::InvalidPassphrase
                        } else {
                            rt.channel = ch;
                            rt.width_mhz = if ch >= 36 { 80 } else { 20 };
                            rt.bssid = rt.active_mac;
                            rt.ssid.fill(0);
                            rt.ssid[..slen].copy_from_slice(&payload[3..3 + slen]);
                            rt.ssid_len = slen as u8;
                            rt.rssi_dbm = -30;
                            rt.state = WlanStateCode::SoftAp;
                            WlanStatus::Ok
                        }
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::ApStart, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::ApStop => {
                    let st = if !rt.has_radio() {
                        WlanStatus::HardwareAbsent
                    } else {
                        rt.disconnect(tick_ms);
                        WlanStatus::Ok
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::ApStop, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::ListProfiles => {
                    let count = rt.profiles.len().min(wlan::MAX_PROFILE_SUMMARIES);
                    let mut out = alloc::vec![0u8; 9 + count * WlanProfileSummary::WIRE_LEN];
                    wlan::write_header(&mut out, WlanOp::ListProfiles, WlanStatus::Ok);
                    out[8] = count as u8;
                    for (i, p) in rt.profiles.iter().take(count).enumerate() {
                        let summary = WlanProfileSummary {
                            ssid_len: p.ssid_len,
                            autoconnect: p.autoconnect,
                            pmk_fingerprint: p.fingerprint,
                            ssid: p.ssid,
                        };
                        let pos = 9 + i * WlanProfileSummary::WIRE_LEN;
                        let _ = summary.encode(&mut out[pos..pos + WlanProfileSummary::WIRE_LEN]);
                    }
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&out);
                    }
                }
                WlanOp::SetMacPolicy => {
                    let st = if let Some(pol) =
                        payload.first().copied().and_then(MacPolicyMode::from_raw)
                    {
                        rt.mac_policy = pol;
                        match pol {
                            MacPolicyMode::Factory => rt.active_mac = rt.factory_mac,
                            MacPolicyMode::Random => {
                                let mix = (tick_ms as u8) ^ 0x5A;
                                rt.active_mac = [0x02, 0x88, 0x21, mix, mix.wrapping_add(17), 0xCE];
                            }
                            MacPolicyMode::Custom if payload.len() >= 7 => {
                                rt.active_mac.copy_from_slice(&payload[1..7]);
                                rt.active_mac[0] = (rt.active_mac[0] | 0x02) & 0xFE;
                            }
                            MacPolicyMode::Custom => {}
                        }
                        WlanStatus::Ok
                    } else {
                        WlanStatus::InvalidRequest
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::SetMacPolicy, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::SetRegDomain => {
                    let st = if let Some(dom) =
                        payload.first().copied().and_then(RegDomainCode::from_raw)
                    {
                        rt.reg_domain = dom;
                        WlanStatus::Ok
                    } else {
                        WlanStatus::InvalidRequest
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::SetRegDomain, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::SetAutoconnect => {
                    rt.autoconnect = payload.first().copied().unwrap_or(1) != 0;
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::SetAutoconnect, WlanStatus::Ok);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
            }
        }

        libcanvas::process::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libcanvas::debug::write_str("[wlan-service] PANIC\n");
    libcanvas::process::exit(-99);
}
