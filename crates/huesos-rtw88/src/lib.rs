//! `#![no_std]`, `#![forbid(unsafe_code)]` Realtek `rtw88` (`RTL8821CE`, PCI ID
//! `10ec:c821`) firmware parser and MAC/DMA descriptor & register state machine.
//!
//! Simulated RF medium (`VirtualRtw88Medium`) is compiled strictly under
//! `#[cfg(any(test, feature = "boot-selftest"))]` and is absent from production
//! builds.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "boot-selftest"))]
extern crate alloc;

pub const PCI_VENDOR_REALTEK: u16 = 0x10EC;
pub const PCI_DEVICE_RTL8821CE: u16 = 0xC821;
pub const RTW8821C_FW_SIGNATURE: u16 = 0x8821;
pub const RTW88_FW_HDR_LEN: usize = 64;

// Realtek RTL8821CE MAC / PCIe / Firmware Download register offsets
pub const REG_SYS_FUNC_EN: u32 = 0x0002;
pub const REG_APS_FSMCO: u32 = 0x0004;
pub const REG_SYS_CLK_CTRL: u32 = 0x0008;
pub const REG_MCUFWDL: u32 = 0x0080;
pub const REG_HIMR0: u32 = 0x00B0;
pub const REG_HISR0: u32 = 0x00B4;
pub const REG_CR: u32 = 0x0100;
pub const REG_TRXDMA_CTRL: u32 = 0x010C;
pub const REG_TRXFF_BNDY: u32 = 0x0114;
pub const REG_BEQ_TXBD_NUM: u32 = 0x0308;
pub const REG_RXQ_RXBD_NUM: u32 = 0x0318;
pub const REG_BEQ_TXBD_DESA_LO: u32 = 0x0320;
pub const REG_BEQ_TXBD_DESA_HI: u32 = 0x0324;
pub const REG_MGQ_TXBD_DESA_LO: u32 = 0x0338;
pub const REG_MGQ_TXBD_DESA_HI: u32 = 0x033C;
pub const REG_RXQ_RXBD_DESA_LO: u32 = 0x0350;
pub const REG_RXQ_RXBD_DESA_HI: u32 = 0x0354;
pub const REG_BEQ_TXBD_IDX: u32 = 0x0380;
pub const REG_MGQ_TXBD_IDX: u32 = 0x038C;
pub const REG_RXQ_RXBD_IDX: u32 = 0x03B4;
pub const REG_MACID: u32 = 0x0610;
pub const REG_BSSID: u32 = 0x0618;
pub const REG_RCR: u32 = 0x0608;
pub const REG_CAMCMD: u32 = 0x0670;
pub const REG_CAMWRITE: u32 = 0x0674;

pub const MCUFWDL_EN: u32 = 1 << 0;
pub const MCUFWDL_RDY: u32 = 1 << 1;
pub const MCUFWDL_CHKSUM_RPT: u32 = 1 << 2;
pub const MCUFWDL_WINTINI_RDY: u32 = 1 << 6;

pub const RTW_TX_DESC_SIZE: usize = 48;
pub const RTW_RX_DESC_SIZE: usize = 24;

/// Driver / firmware error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtwError {
    TruncatedFirmware,
    InvalidFirmwareMagic(u16),
    FirmwareSectionOutOfBounds,
    HardwareTimeout,
    RingFull,
    MalformedDescriptor,
}

/// Parsed `rtw8821c_fw.bin` 64-byte Realtek firmware header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rtw88FirmwareInfo {
    pub signature: u16,
    pub version: u16,
    pub subversion: u8,
    pub subindex: u8,
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub dmem_size: u32,
    pub imem_size: u32,
    pub emem_size: u32,
    pub total_len: usize,
}

impl Rtw88FirmwareInfo {
    pub fn parse(blob: &[u8]) -> Result<Self, RtwError> {
        if blob.len() < RTW88_FW_HDR_LEN {
            return Err(RtwError::TruncatedFirmware);
        }
        let signature = u16::from_le_bytes([blob[0], blob[1]]);
        if signature != RTW8821C_FW_SIGNATURE && signature != 0x8822 && signature != 0x882B {
            return Err(RtwError::InvalidFirmwareMagic(signature));
        }
        let version = u16::from_le_bytes([blob[4], blob[5]]);
        let subversion = blob[6];
        let subindex = blob[7];
        let month = blob[16];
        let day = blob[17];
        let year = u16::from_le_bytes([blob[20], blob[21]]);
        let dmem_size = u32::from_le_bytes([blob[36], blob[37], blob[38], blob[39]]);
        let imem_size = u32::from_le_bytes([blob[48], blob[49], blob[50], blob[51]]);
        let emem_size = u32::from_le_bytes([blob[52], blob[53], blob[54], blob[55]]);

        let payload_sum = (RTW88_FW_HDR_LEN as u64)
            .saturating_add(u64::from(dmem_size))
            .saturating_add(u64::from(imem_size))
            .saturating_add(u64::from(emem_size));
        if payload_sum > blob.len() as u64 {
            return Err(RtwError::FirmwareSectionOutOfBounds);
        }

        Ok(Self {
            signature,
            version,
            subversion,
            subindex,
            year,
            month,
            day,
            dmem_size,
            imem_size,
            emem_size,
            total_len: blob.len(),
        })
    }
}

/// Abstract MMIO register accessor implemented by PCIe BAR2 in `/services/wlan.elf`.
pub trait Rtw88Mmio {
    fn read8(&self, offset: u32) -> u8;
    fn read16(&self, offset: u32) -> u16;
    fn read32(&self, offset: u32) -> u32;
    fn write8(&mut self, offset: u32, val: u8);
    fn write16(&mut self, offset: u32, val: u16);
    fn write32(&mut self, offset: u32, val: u32);
}

/// Encode a 48-byte Realtek `rtw88` TX packet descriptor (`rtw_tx_pkt_info`)
/// ahead of an outbound 802.11 MPDU.
pub fn encode_tx_pkt_desc(
    mpdu_len: u16,
    is_mgmt: bool,
    rate_id: u8,
    out: &mut [u8; RTW_TX_DESC_SIZE],
) {
    out.fill(0);
    // DW0: [15:0]=txpktsize, [23:16]=offset(48), [24]=bmc, [26]=ls, [27]=fs
    let qsel: u32 = if is_mgmt { 0x12 } else { 0x00 }; // QSEL_MGMT vs QSEL_BE
    let dw0 = u32::from(mpdu_len) | (48u32 << 16) | (1u32 << 26) | (1u32 << 27);
    let dw1 = qsel << 8;
    // DW3: [15]=use_rate
    let dw3 = 1u32 << 15;
    // DW4: [6:0]=datarate (e.g. DESC_RATE6M = 0x04 or MCS7 = 0x13)
    let dw4 = u32::from(rate_id & 0x7F);
    out[0..4].copy_from_slice(&dw0.to_le_bytes());
    out[4..8].copy_from_slice(&dw1.to_le_bytes());
    out[12..16].copy_from_slice(&dw3.to_le_bytes());
    out[16..20].copy_from_slice(&dw4.to_le_bytes());
}

/// Decode a 24-byte Realtek `rtw88` RX packet descriptor (`rtw_rx_pkt_stat`),
/// returning `(mpdu_len, drv_info_sz_bytes, crc_err, rssi_dbm)`.
pub fn decode_rx_pkt_desc(raw: &[u8; RTW_RX_DESC_SIZE]) -> (usize, usize, bool, i8) {
    let dw0 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let dw4 = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
    let pkt_len = (dw0 & 0x3FFF) as usize;
    let crc_err = (dw0 & (1 << 14)) != 0;
    let drv_info_sz = (((dw0 >> 16) & 0x0F) as usize) * 8;
    let pwdb = ((dw4 >> 16) & 0xFF) as i16;
    let rssi = (pwdb - 100).clamp(-95, -20) as i8;
    (pkt_len, drv_info_sz, crc_err, rssi)
}

/// Encode a 16-byte PCIe Buffer Descriptor (`rtw_pci_tx_buffer_desc` / `rx`).
pub fn encode_pci_bd(paddr: u64, buf_len: u16, own_hw: bool) -> [u8; 16] {
    let mut bd = [0u8; 16];
    let dw0 = u32::from(buf_len) | if own_hw { 1u32 << 31 } else { 0 };
    bd[0..4].copy_from_slice(&dw0.to_le_bytes());
    bd[8..12].copy_from_slice(&(paddr as u32).to_le_bytes());
    bd[12..16].copy_from_slice(&((paddr >> 32) as u32).to_le_bytes());
    bd
}

/// Read the station factory MAC address from RTL8821CE `REG_MACID` (`0x0610..0x0616`).
pub fn read_hw_mac<M: Rtw88Mmio>(mmio: &M) -> [u8; 6] {
    let lo = mmio.read32(REG_MACID).to_le_bytes();
    let hi = mmio.read16(REG_MACID + 4).to_le_bytes();
    let cand = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    if cand == [0; 6] || cand == [0xFF; 6] {
        [0x00, 0xE0, 0x4C, 0x88, 0x21, 0xCE]
    } else {
        cand
    }
}

/// Program the associated BSSID into `REG_BSSID` (`0x0618`) and install the
/// 128-bit CCMP pairwise Temporal Key into hardware CAM slot 0 (`REG_CAMCMD`).
pub fn program_hw_bssid_and_ccmp_cam<M: Rtw88Mmio>(
    mmio: &mut M,
    bssid: &[u8; 6],
    sta_mac: &[u8; 6],
    tk: Option<&[u8; 16]>,
) {
    let lo = u32::from_le_bytes([bssid[0], bssid[1], bssid[2], bssid[3]]);
    let hi = u16::from_le_bytes([bssid[4], bssid[5]]);
    mmio.write32(REG_BSSID, lo);
    mmio.write16(REG_BSSID + 4, hi);

    if let Some(key) = tk {
        // Realtek Security CAM entry = 8 dwords: [0..1] cfg+mac, [2..5] 16B AES key
        let cfg = (1u32 << 15) | (0x04u32 << 2); // VALID | ALGO_AES
        let m0 = cfg | (u32::from(sta_mac[0]) << 16) | (u32::from(sta_mac[1]) << 24);
        let m1 = u32::from_le_bytes([sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]]);
        let words = [
            m0,
            m1,
            u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
            u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
            u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
            u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
            0,
            0,
        ];
        for (idx, &w) in words.iter().enumerate() {
            mmio.write32(REG_CAMWRITE, w);
            mmio.write32(REG_CAMCMD, (1u32 << 31) | (1u32 << 16) | (idx as u32));
        }
    }
}

// ============================================================================
// Virtual 802.11 + WPA2-PSK CCMP + DHCP/ICMP/TCP Radio Medium (boot-selftest / test ONLY)
// ============================================================================

#[cfg(any(test, feature = "boot-selftest"))]
mod virtual_medium {
    use alloc::collections::VecDeque;
    use alloc::vec::Vec;

    use huesos_ieee80211::{
        build_assoc_response, build_auth_frame, build_beacon_or_probe_resp, build_data_frame,
        build_llc_snap_payload, parse_auth_frame, parse_llc_snap_payload, Dot11Header,
        SecurityMode, FC_FLAG_PROTECTED, FC_TYPE_DATA, FC_TYPE_MGMT, MGMT_SUBTYPE_ASSOC_REQ,
        MGMT_SUBTYPE_AUTH, MGMT_SUBTYPE_DEAUTH, MGMT_SUBTYPE_PROBE_REQ,
    };
    use huesos_net::dhcp_dns::{
        parse_dhcp_reply, DHCP_ACK, DHCP_CLIENT_PORT, DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST,
        DHCP_SERVER_PORT,
    };
    use huesos_net::wire::{
        EthFrame, Ipv4Packet, UdpPacket, ETHERTYPE_EAPOL, ETHERTYPE_IPV4, IP_PROTO_UDP,
    };
    use huesos_net::{Ipv4Addr, MacAddr, NetStack};
    use huesos_wpa::{derive_wpa2_psk, Authenticator4Way, CcmpContext};

    struct VirtualAp {
        bssid: [u8; 6],
        ssid: &'static [u8],
        channel: u8,
        rssi_dbm: i8,
        security: SecurityMode,
        passphrase: &'static [u8],
        gw_ip: Ipv4Addr,
        lease_ip: Ipv4Addr,
        net: NetStack,
        auth_sta: Option<[u8; 6]>,
        assoc_sta: Option<[u8; 6]>,
        wpa_auth: Option<Authenticator4Way>,
        tx_ccmp: Option<CcmpContext>,
        rx_ccmp: Option<CcmpContext>,
        seq_num: u16,
    }

    impl VirtualAp {
        #[allow(clippy::too_many_arguments)]
        fn new(
            bssid: [u8; 6],
            ssid: &'static [u8],
            channel: u8,
            rssi_dbm: i8,
            security: SecurityMode,
            passphrase: &'static [u8],
            gw_ip: Ipv4Addr,
            lease_ip: Ipv4Addr,
        ) -> Self {
            let mut net = NetStack::new(MacAddr(bssid));
            net.configure_static(gw_ip, Ipv4Addr::new(255, 255, 255, 0), gw_ip, gw_ip);
            Self {
                bssid,
                ssid,
                channel,
                rssi_dbm,
                security,
                passphrase,
                gw_ip,
                lease_ip,
                net,
                auth_sta: None,
                assoc_sta: None,
                wpa_auth: None,
                tx_ccmp: None,
                rx_ccmp: None,
                seq_num: 1,
            }
        }

        fn next_seq(&mut self) -> u16 {
            let s = self.seq_num;
            self.seq_num = (self.seq_num + 1) & 0x0FFF;
            s
        }
    }

    /// Deterministic virtual Realtek `rtw88` air medium hosting two APs
    /// (`HuesOS-Lab-5G` WPA2-PSK `"huesos-wifi-2026"` and `HuesOS-Open`) so
    /// `/services/wlan.elf`, `wlanctl`, and `btop` exercise real 802.11 management,
    /// WPA2 4-way EAPOL, AES-128-CCMP data frames, and DHCP/ICMP/TCP inside QEMU.
    pub struct VirtualRtw88Medium {
        aps: [VirtualAp; 2],
        rx_air_queue: VecDeque<(i8, Vec<u8>)>,
    }

    impl Default for VirtualRtw88Medium {
        fn default() -> Self {
            Self::new()
        }
    }

    impl VirtualRtw88Medium {
        pub fn new() -> Self {
            Self {
                aps: [
                    VirtualAp::new(
                        [0x02, 0x88, 0x21, 0xCE, 0x50, 0x01],
                        b"HuesOS-Lab-5G",
                        36,
                        -44,
                        SecurityMode::Wpa2PskCcmp,
                        b"huesos-wifi-2026",
                        Ipv4Addr::new(192, 168, 88, 1),
                        Ipv4Addr::new(192, 168, 88, 42),
                    ),
                    VirtualAp::new(
                        [0x02, 0x88, 0x21, 0xCE, 0x24, 0x06],
                        b"HuesOS-Open",
                        6,
                        -58,
                        SecurityMode::Open,
                        b"",
                        Ipv4Addr::new(192, 168, 89, 1),
                        Ipv4Addr::new(192, 168, 89, 42),
                    ),
                ],
                rx_air_queue: VecDeque::with_capacity(32),
            }
        }

        /// Pop the next `(rssi_dbm, 802.11 MPDU)` arriving at the station antenna.
        pub fn poll_rx_mpdu(&mut self) -> Option<(i8, Vec<u8>)> {
            self.rx_air_queue.pop_front()
        }

        /// Transmit a station 802.11 MPDU onto the simulated RF medium.
        pub fn transmit_sta_mpdu(&mut self, now_ms: u64, mpdu: &[u8]) {
            let Ok(hdr) = Dot11Header::parse(mpdu) else {
                return;
            };
            match hdr.frame_type {
                FC_TYPE_MGMT => self.handle_mgmt(&hdr, mpdu),
                FC_TYPE_DATA => self.handle_data(now_ms, &hdr, mpdu),
                _ => {}
            }
        }

        fn handle_mgmt(&mut self, hdr: &Dot11Header<'_>, mpdu: &[u8]) {
            match hdr.subtype {
                MGMT_SUBTYPE_PROBE_REQ => {
                    for ap in &mut self.aps {
                        let mut buf = [0u8; 256];
                        let seq = ap.next_seq();
                        if let Ok(n) = build_beacon_or_probe_resp(
                            true,
                            hdr.addr2,
                            ap.bssid,
                            ap.ssid,
                            ap.channel,
                            ap.security,
                            seq,
                            &mut buf,
                        ) {
                            self.rx_air_queue
                                .push_back((ap.rssi_dbm, buf[..n].to_vec()));
                        }
                    }
                }
                MGMT_SUBTYPE_AUTH => {
                    let Ok((bssid, alg, auth_seq, _)) = parse_auth_frame(mpdu) else {
                        return;
                    };
                    if alg != 0 || auth_seq != 1 {
                        return;
                    }
                    if let Some(ap) = self.aps.iter_mut().find(|a| a.bssid == bssid) {
                        ap.auth_sta = Some(hdr.addr2);
                        let mut buf = [0u8; 64];
                        let seq = ap.next_seq();
                        if let Ok(n) =
                            build_auth_frame(hdr.addr2, ap.bssid, ap.bssid, 2, 0, seq, &mut buf)
                        {
                            self.rx_air_queue
                                .push_back((ap.rssi_dbm, buf[..n].to_vec()));
                        }
                    }
                }
                MGMT_SUBTYPE_ASSOC_REQ => {
                    let Some(ap) = self.aps.iter_mut().find(|a| a.bssid == hdr.addr1) else {
                        return;
                    };
                    if ap.auth_sta != Some(hdr.addr2) {
                        return;
                    }
                    ap.assoc_sta = Some(hdr.addr2);
                    let mut buf = [0u8; 128];
                    let seq = ap.next_seq();
                    if let Ok(n) = build_assoc_response(hdr.addr2, ap.bssid, 0, 1, seq, &mut buf) {
                        self.rx_air_queue
                            .push_back((ap.rssi_dbm, buf[..n].to_vec()));
                    }
                    if ap.security == SecurityMode::Wpa2PskCcmp {
                        if let Ok(pmk) = derive_wpa2_psk(ap.passphrase, ap.ssid) {
                            let anonce = [0xA5u8; 32];
                            let gtk = [0x5Au8; 16];
                            let mut auth =
                                Authenticator4Way::new(pmk, ap.bssid, hdr.addr2, anonce, gtk);
                            let m1 = auth.build_msg1();
                            ap.wpa_auth = Some(auth);
                            if let Some(frame) = wrap_ap_llc_data(
                                ap,
                                hdr.addr2,
                                ap.bssid,
                                ETHERTYPE_EAPOL,
                                &m1,
                                false,
                            ) {
                                self.rx_air_queue.push_back((ap.rssi_dbm, frame));
                            }
                        }
                    }
                }
                MGMT_SUBTYPE_DEAUTH => {
                    if let Some(ap) = self.aps.iter_mut().find(|a| a.bssid == hdr.addr1) {
                        ap.auth_sta = None;
                        ap.assoc_sta = None;
                        ap.wpa_auth = None;
                        ap.tx_ccmp = None;
                        ap.rx_ccmp = None;
                    }
                }
                _ => {}
            }
        }

        fn handle_data(&mut self, now_ms: u64, hdr: &Dot11Header<'_>, mpdu: &[u8]) {
            let Some(ap) = self.aps.iter_mut().find(|a| a.bssid == hdr.addr1) else {
                return;
            };
            let sta_mac = hdr.addr2;
            if ap.assoc_sta != Some(sta_mac) {
                return;
            }

            let plain_llc = if (hdr.flags & FC_FLAG_PROTECTED) != 0 {
                let Some(rx_ccmp) = ap.rx_ccmp.as_mut() else {
                    return;
                };
                let Ok(pt) = rx_ccmp.decrypt_mpdu(mpdu) else {
                    return;
                };
                pt
            } else {
                if ap.security == SecurityMode::Wpa2PskCcmp && ap.tx_ccmp.is_some() {
                    return; // Require CCMP once 4-way handshake completes
                }
                hdr.body.to_vec()
            };

            let Ok((ethertype, l3_payload)) = parse_llc_snap_payload(&plain_llc) else {
                return;
            };

            if ethertype == ETHERTYPE_EAPOL {
                let Some(auth) = ap.wpa_auth.as_mut() else {
                    return;
                };
                if let Ok(Some(m3)) = auth.on_supplicant_eapol(l3_payload) {
                    if let Some(frame) =
                        wrap_ap_llc_data(ap, sta_mac, ap.bssid, ETHERTYPE_EAPOL, &m3, false)
                    {
                        self.rx_air_queue.push_back((ap.rssi_dbm, frame));
                    }
                } else if auth.is_complete() {
                    if let Some(ptk) = auth.ptk().copied() {
                        ap.tx_ccmp = Some(CcmpContext::new(ptk.tk, 0));
                        ap.rx_ccmp = Some(CcmpContext::new(ptk.tk, 0));
                    }
                }
                return;
            }

            // Bridge 802.11 Data -> Ethernet II -> Virtual AP's DHCP + NetStack
            if ethertype == ETHERTYPE_IPV4 {
                if let Some(dhcp_reply_eth) = maybe_answer_dhcp(ap, sta_mac, l3_payload) {
                    if let Ok(eth) = EthFrame::parse(&dhcp_reply_eth) {
                        let encrypted = ap.security == SecurityMode::Wpa2PskCcmp;
                        if let Some(frame) = wrap_ap_llc_data(
                            ap,
                            sta_mac,
                            eth.src.0,
                            eth.ethertype,
                            eth.payload,
                            encrypted,
                        ) {
                            self.rx_air_queue.push_back((ap.rssi_dbm, frame));
                        }
                    }
                    return;
                }
            }

            let mut eth_in = alloc::vec![0u8; 14 + l3_payload.len()];
            if EthFrame::emit(
                MacAddr(hdr.addr3),
                MacAddr(sta_mac),
                ethertype,
                l3_payload,
                &mut eth_in,
            )
            .is_ok()
            {
                let mut eth_out = VecDeque::new();
                ap.net.ingest_frame(now_ms, &eth_in, &mut eth_out);
                let encrypted = ap.security == SecurityMode::Wpa2PskCcmp;
                while let Some(reply_eth) = eth_out.pop_front() {
                    if let Ok(eth) = EthFrame::parse(&reply_eth) {
                        if let Some(frame) = wrap_ap_llc_data(
                            ap,
                            sta_mac,
                            eth.src.0,
                            eth.ethertype,
                            eth.payload,
                            encrypted,
                        ) {
                            self.rx_air_queue.push_back((ap.rssi_dbm, frame));
                        }
                    }
                }
            }
        }
    }

    fn wrap_ap_llc_data(
        ap: &mut VirtualAp,
        sta_mac: [u8; 6],
        sa_mac: [u8; 6],
        ethertype: u16,
        l3_payload: &[u8],
        encrypt: bool,
    ) -> Option<Vec<u8>> {
        let mut llc = alloc::vec![0u8; 8 + l3_payload.len()];
        let llc_len = build_llc_snap_payload(ethertype, l3_payload, &mut llc).ok()?;
        let seq = ap.next_seq();
        if encrypt {
            let mut hdr = [0u8; 24];
            build_data_frame(false, true, ap.bssid, sta_mac, sa_mac, seq, &[], &mut hdr).ok()?;
            let ccmp = ap.tx_ccmp.as_mut()?;
            ccmp.encrypt_mpdu(&hdr, &llc[..llc_len]).ok()
        } else {
            let mut mpdu = alloc::vec![0u8; 24 + llc_len];
            let n = build_data_frame(
                false,
                false,
                ap.bssid,
                sta_mac,
                sa_mac,
                seq,
                &llc[..llc_len],
                &mut mpdu,
            )
            .ok()?;
            mpdu.truncate(n);
            Some(mpdu)
        }
    }

    fn maybe_answer_dhcp(ap: &VirtualAp, sta_mac: [u8; 6], ipv4_raw: &[u8]) -> Option<Vec<u8>> {
        let ip = Ipv4Packet::parse(ipv4_raw).ok()?;
        if ip.proto != IP_PROTO_UDP {
            return None;
        }
        let udp = UdpPacket::parse(ip.src, ip.dst, ip.payload).ok()?;
        if udp.src_port != DHCP_CLIENT_PORT
            || udp.dst_port != DHCP_SERVER_PORT
            || udp.payload.len() < 244
        {
            return None;
        }
        let xid = u32::from_be_bytes([
            udp.payload[4],
            udp.payload[5],
            udp.payload[6],
            udp.payload[7],
        ]);
        // Inspect client's option 53 message type by reusing reply parser after patching op=2
        let mut probe = udp.payload.to_vec();
        probe[0] = 2;
        let parsed = parse_dhcp_reply(&probe, xid, MacAddr(sta_mac)).ok()?;
        let reply_type = match parsed.msg_type {
            DHCP_DISCOVER => DHCP_OFFER,
            DHCP_REQUEST => DHCP_ACK,
            _ => return None,
        };

        let mut dhcp = [0u8; 300];
        dhcp[0] = 2; // BOOTREPLY
        dhcp[1] = 1;
        dhcp[2] = 6;
        dhcp[4..8].copy_from_slice(&xid.to_be_bytes());
        dhcp[16..20].copy_from_slice(&ap.lease_ip.0); // yiaddr
        dhcp[20..24].copy_from_slice(&ap.gw_ip.0); // siaddr
        dhcp[28..34].copy_from_slice(&sta_mac);
        dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]);

        let mut p = 240usize;
        dhcp[p..p + 3].copy_from_slice(&[53, 1, reply_type]);
        p += 3;
        dhcp[p..p + 2].copy_from_slice(&[54, 4]);
        dhcp[p + 2..p + 6].copy_from_slice(&ap.gw_ip.0);
        p += 6;
        dhcp[p..p + 6].copy_from_slice(&[51, 4, 0, 0, 0x0E, 0x10]); // 3600s
        p += 6;
        dhcp[p..p + 6].copy_from_slice(&[1, 4, 255, 255, 255, 0]);
        p += 6;
        dhcp[p..p + 2].copy_from_slice(&[3, 4]);
        dhcp[p + 2..p + 6].copy_from_slice(&ap.gw_ip.0);
        p += 6;
        dhcp[p..p + 2].copy_from_slice(&[6, 4]);
        dhcp[p + 2..p + 6].copy_from_slice(&ap.gw_ip.0);
        p += 6;
        dhcp[p] = 255;

        let mut ubuf = [0u8; 330];
        let ulen = UdpPacket::emit(
            ap.gw_ip,
            Ipv4Addr::BROADCAST,
            DHCP_SERVER_PORT,
            DHCP_CLIENT_PORT,
            &dhcp,
            &mut ubuf,
        )
        .ok()?;
        let mut ibuf = [0u8; 360];
        let ilen = Ipv4Packet::emit(
            ap.gw_ip,
            Ipv4Addr::BROADCAST,
            IP_PROTO_UDP,
            64,
            1,
            &ubuf[..ulen],
            &mut ibuf,
        )
        .ok()?;
        let mut eth = alloc::vec![0u8; 14 + ilen];
        EthFrame::emit(
            MacAddr::BROADCAST,
            MacAddr(ap.bssid),
            ETHERTYPE_IPV4,
            &ibuf[..ilen],
            &mut eth,
        )
        .ok()?;
        Some(eth)
    }
}

#[cfg(any(test, feature = "boot-selftest"))]
pub use virtual_medium::VirtualRtw88Medium;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_rtl8821c_firmware_header() {
        let fw = include_bytes!("../../../third_party/firmware/rtw88/rtw8821c_fw.bin");
        let info = Rtw88FirmwareInfo::parse(fw);
        assert!(info.is_ok());
        if let Ok(hdr) = info {
            assert_eq!(hdr.signature, 0x8821);
            assert_eq!(hdr.version, 24);
            assert_eq!(hdr.subversion, 11);
            assert_eq!(hdr.dmem_size, 31_976);
            assert_eq!(hdr.imem_size, 63_240);
            assert_eq!(hdr.emem_size, 44_168);
        }
    }

    #[test]
    fn virtual_medium_answers_probe_request() {
        let mut med = VirtualRtw88Medium::new();
        let mut req = [0u8; 64];
        let len = huesos_ieee80211::build_probe_request(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            b"",
            1,
            &mut req,
        )
        .unwrap_or(0);
        med.transmit_sta_mpdu(10, &req[..len]);
        assert!(med.poll_rx_mpdu().is_some());
    }
}
