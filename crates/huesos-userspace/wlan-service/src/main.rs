//! `/services/wlan.elf` — isolated IEEE 802.11 + WPA2-PSK CCMP + Realtek
//! RTL8821CE (`10ec:c821`) Wi-Fi service speaking the `HWLN` wire protocol.
//!
//! Secret isolation guarantee: WPA2 passphrases, derived 256-bit `PMK`s, and
//! transient `PTK`/`GTK` keys reside exclusively in this process's address
//! space (persisted only as `/etc/wlan/profiles.conf` via capability-isolated
//! `HxFS` with transparent RAM fallback) and are never serialized back over IPC.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, AtomicU64, Ordering};

use huesos_abi::vmar_flags;
use huesos_abi::wlan::{
    self, BtCoexProfile, MacPolicyMode, RegDomainCode, WlanBssInfo, WlanOp, WlanProfileSummary,
    WlanSecurity, WlanStateCode, WlanStatus, WlanStatusSnapshot, MAX_SSID_LEN,
};
use huesos_ieee80211::{
    build_assoc_request_for_bss, build_assoc_response, build_auth_frame,
    build_beacon_or_probe_resp, build_data_frame, build_deauth, build_llc_snap_payload,
    build_probe_request, build_probe_request_band, build_rsn_ie_with_group, parse_assoc_response,
    parse_auth_frame, parse_beacon_or_probe_resp, parse_llc_snap_payload, Dot11Header, ScanTable,
    SecurityMode, CIPHER_SUITE_CCMP, CIPHER_SUITE_TKIP, FC_FLAG_FROM_DS, FC_FLAG_PROTECTED,
    FC_FLAG_TO_DS, FC_TYPE_DATA, FC_TYPE_MGMT, IE_SSID, MGMT_SUBTYPE_ASSOC_REQ,
    MGMT_SUBTYPE_ASSOC_RESP, MGMT_SUBTYPE_AUTH, MGMT_SUBTYPE_BEACON, MGMT_SUBTYPE_DEAUTH,
    MGMT_SUBTYPE_DISASSOC, MGMT_SUBTYPE_PROBE_REQ, MGMT_SUBTYPE_PROBE_RESP,
};
use huesos_net::dhcp_dns::{
    parse_dhcp_reply, DHCP_ACK, DHCP_CLIENT_PORT, DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST,
    DHCP_SERVER_PORT,
};
use huesos_net::wire::{
    EthFrame, Ipv4Packet, UdpPacket, ETHERTYPE_EAPOL, ETHERTYPE_IPV4, IP_PROTO_UDP,
};
use huesos_net::{Ipv4Addr, MacAddr, NetStack};
#[cfg(feature = "boot-selftest")]
use huesos_rtw88::VirtualRtw88Medium;
use huesos_rtw88::{Rtl8821ceHw, Rtw88Dma, Rtw88FirmwareInfo, Rtw88Mmio};
use huesos_wpa::{
    decrypt_tkip_group_mpdu, derive_wpa2_psk, hmac_sha1_parts, Authenticator4Way, CcmpContext,
    Supplicant4Way,
};
use libcanvas::{println, Channel, ErrorCode, Handle, Hxfs, Vmo};

#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";
const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const FW_PATH: &str = "/lib/firmware/rtw88/rtw8821c_fw.bin";
const PROFILES_DIR_ETC: &str = "/etc";
const PROFILES_DIR_WLAN: &str = "/etc/wlan";
const PROFILES_PATH: &str = "/etc/wlan/profiles.conf";
const PROFILES_TMP_PATH: &str = "/etc/wlan/profiles.tmp";
const PROFILES_MAGIC: &[u8; 8] = b"HWLP0001";
const PROFILE_RECORD_BYTES: usize = 72; // 1+1+1+1 + 4 + 32 + 32

const WLAN_MMIO_VA: u64 = 0x0000_7300_0000_0000;
const WLAN_DMA_VA: u64 = 0x0000_7310_0000_0000;

// Runtime `uplink:net` <-> `uplink:wlan0` wire opcodes
const UPLINK_OP_STATE: u8 = 0x01;
const UPLINK_OP_ETH_FRAME: u8 = 0x02;

const MAX_SOFTAP_CLIENTS: usize = 8;
const SCAN_CHANNELS_ALL: &[u8] = &[
    1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 36, 40, 44, 48, 149, 153, 157, 161, 165,
];

// ============================================================================
// Hardware CSPRNG (`RDRAND` + `RDTSC` + Monotonic Clock + HMAC-SHA1 Whitening)
// ============================================================================

struct Csprng {
    key: [u8; 32],
    counter: u64,
    has_rdrand: bool,
}

impl Csprng {
    fn new() -> Self {
        let leaf1 = core::arch::x86_64::__cpuid(1);
        let has_rdrand = (leaf1.ecx & (1 << 30)) != 0;
        let mut seed = [0u8; 32];
        for chunk in seed.chunks_mut(8) {
            let hw = if has_rdrand {
                rdrand_u64().unwrap_or_else(rdtsc_u64)
            } else {
                rdtsc_u64()
            };
            let ticks = libcanvas::system::monotonic_ticks().unwrap_or(0);
            chunk.copy_from_slice(&(hw ^ ticks.rotate_left(19)).to_le_bytes());
        }
        Self {
            key: seed,
            counter: 1,
            has_rdrand,
        }
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut pos = 0usize;
        while pos < out.len() {
            let hw_ent = if self.has_rdrand {
                rdrand_u64().unwrap_or_else(rdtsc_u64)
            } else {
                rdtsc_u64()
            };
            let ctr = self.counter;
            self.counter = self.counter.wrapping_add(1);
            let ctr_bytes = ctr.to_le_bytes();
            let ent_bytes = hw_ent.to_le_bytes();
            let digest =
                hmac_sha1_parts(&self.key, &[b"huesos-wlan-csprng", &ctr_bytes, &ent_bytes]);
            // Ratchet internal key forward
            let next_k = hmac_sha1_parts(&self.key, &[&digest, b"ratchet"]);
            self.key[..20].copy_from_slice(&next_k);
            for (dst, &src) in self.key[20..32].iter_mut().zip(&digest[..12]) {
                *dst ^= src;
            }
            let take = (out.len() - pos).min(digest.len());
            out[pos..pos + take].copy_from_slice(&digest[..take]);
            pos += take;
        }
    }

    fn gen_nonce32(&mut self) -> [u8; 32] {
        let mut n = [0u8; 32];
        self.fill_bytes(&mut n);
        n
    }

    fn gen_key16(&mut self) -> [u8; 16] {
        let mut k = [0u8; 16];
        self.fill_bytes(&mut k);
        k
    }
}

fn rdtsc_u64() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdtsc` is an unprivileged x86_64 instruction.
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

fn rdrand_u64() -> Option<u64> {
    for _ in 0..8 {
        let val: u64;
        let ok: u8;
        // SAFETY: Guarded by CPUID.01H:ECX.RDRAND[bit 30] check in `Csprng::new`.
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok != 0 {
            return Some(val);
        }
    }
    None
}

static TSC_CYCLES_PER_US: AtomicU64 = AtomicU64::new(0);

fn calibrated_cycles_per_us() -> u64 {
    let cached = TSC_CYCLES_PER_US.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let fallback = 5_000u64;
    let Ok(t0) = libcanvas::system::monotonic_ticks() else {
        TSC_CYCLES_PER_US.store(fallback, Ordering::Relaxed);
        return fallback;
    };
    // Align to next 100 Hz monotonic tick edge (`10_000 us` per tick)
    let mut t_edge = t0;
    let mut aligned = false;
    for _ in 0..500_000 {
        if let Ok(cur) = libcanvas::system::monotonic_ticks() {
            if cur > t0 {
                t_edge = cur;
                aligned = true;
                break;
            }
        } else {
            break;
        }
        core::hint::spin_loop();
    }
    let measured = if aligned {
        let tsc_start = rdtsc_u64();
        let mut measured_ok = false;
        let mut tsc_end = tsc_start;
        for _ in 0..500_000 {
            if let Ok(cur) = libcanvas::system::monotonic_ticks() {
                if cur > t_edge {
                    tsc_end = rdtsc_u64();
                    measured_ok = true;
                    break;
                }
            } else {
                break;
            }
            core::hint::spin_loop();
        }
        if measured_ok {
            (tsc_end.wrapping_sub(tsc_start) / 10_000).clamp(2_000, 6_500)
        } else {
            fallback
        }
    } else {
        fallback
    };
    TSC_CYCLES_PER_US.store(measured, Ordering::Relaxed);
    measured
}

fn delay_us_spin(us: u32) {
    let cycles_per_us = calibrated_cycles_per_us();
    let start = rdtsc_u64();
    let cycles = u64::from(us).saturating_mul(cycles_per_us);
    while rdtsc_u64().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

// ============================================================================
// Hardware Abstraction Layer (`WlanHal`) + `Rtw88Hal` (`RTL8821CE` `10ec:c821`)
// ============================================================================

trait WlanHal {
    fn is_present(&self) -> bool;
    fn is_hardware_radio(&self) -> bool;
    fn is_firmware_ready(&self) -> bool;
    fn pci_bdf(&self) -> u16;
    fn fw_version(&self) -> [u16; 2];
    fn factory_mac(&self) -> [u8; 6];
    fn thermal_and_xtal(&self) -> (u8, u8);
    fn hw_diag_and_mcufw(&self) -> (u8, u16) {
        (0, 0)
    }
    fn set_mac_addr(&mut self, mac: &[u8; 6]);
    fn set_channel(&mut self, channel: u8, bw_mhz: u8);
    fn configure_sta_link(&mut self, bssid: &[u8; 6], linked: bool);
    fn configure_ap(&mut self, bssid: &[u8; 6], beacon_mpdu: &[u8], beacon_int_tu: u16) -> bool;
    fn install_ccmp_key(
        &mut self,
        slot: u8,
        key_idx: u8,
        peer_mac: &[u8; 6],
        is_group: bool,
        tk: &[u8; 16],
    );
    fn clear_ccmp_key(&mut self, slot: u8);
    fn tx_mpdu(&mut self, now_ms: u64, mpdu: &[u8]) -> bool;
    fn poll_rx_mpdu(&mut self) -> Option<(i8, Vec<u8>)>;
    fn set_bt_coex_profile(&mut self, _profile: BtCoexProfile) {}
}

struct PcieBarMmio {
    base_va: usize,
    len: usize,
}

impl Rtw88Mmio for PcieBarMmio {
    fn read8(&self, offset: u32) -> u8 {
        if (offset as usize) < self.len {
            // SAFETY: `offset < self.len` inside mapped PCIe BAR MMIO window.
            unsafe { read_volatile((self.base_va + offset as usize) as *const u8) }
        } else {
            0
        }
    }
    fn read16(&self, offset: u32) -> u16 {
        if (offset as usize) + 2 <= self.len {
            // SAFETY: `offset + 2 <= self.len` inside mapped PCIe BAR MMIO window.
            unsafe { read_volatile((self.base_va + offset as usize) as *const u16) }
        } else {
            0
        }
    }
    fn read32(&self, offset: u32) -> u32 {
        if (offset as usize) + 4 <= self.len {
            // SAFETY: `offset + 4 <= self.len` inside mapped PCIe BAR MMIO window.
            unsafe { read_volatile((self.base_va + offset as usize) as *const u32) }
        } else {
            0
        }
    }
    fn write8(&mut self, offset: u32, val: u8) {
        if (offset as usize) < self.len {
            // SAFETY: `offset < self.len` inside mapped PCIe BAR MMIO window.
            unsafe { write_volatile((self.base_va + offset as usize) as *mut u8, val) }
        }
    }
    fn write16(&mut self, offset: u32, val: u16) {
        if (offset as usize) + 2 <= self.len {
            // SAFETY: `offset + 2 <= self.len` inside mapped PCIe BAR MMIO window.
            unsafe { write_volatile((self.base_va + offset as usize) as *mut u16, val) }
        }
    }
    fn write32(&mut self, offset: u32, val: u32) {
        if (offset as usize) + 4 <= self.len {
            // SAFETY: `offset + 4 <= self.len` inside mapped PCIe BAR MMIO window.
            unsafe { write_volatile((self.base_va + offset as usize) as *mut u32, val) }
        }
    }
    fn delay_us(&mut self, us: u32) {
        delay_us_spin(us);
    }
}

struct MappedRtwDma {
    va: usize,
    pa: u32,
    len: usize,
}

impl Rtw88Dma for MappedRtwDma {
    fn phys_base(&self) -> u32 {
        self.pa
    }
    fn len(&self) -> usize {
        self.len
    }
    fn read_bytes(&self, offset: usize, dst: &mut [u8]) {
        if offset.saturating_add(dst.len()) <= self.len {
            fence(Ordering::SeqCst);
            let src_ptr = (self.va + offset) as *const u8;
            // SAFETY: Bounds checked within `[self.va .. self.va + self.len)`; volatile
            // reads prevent elision/caching of PCIe bus-master DMA ring completions.
            unsafe {
                for (i, slot) in dst.iter_mut().enumerate() {
                    *slot = read_volatile(src_ptr.add(i));
                }
            }
            fence(Ordering::SeqCst);
        }
    }
    fn write_bytes(&mut self, offset: usize, src: &[u8]) {
        if offset.saturating_add(src.len()) <= self.len {
            let dst_ptr = (self.va + offset) as *mut u8;
            // SAFETY: Bounds checked within `[self.va .. self.va + self.len)`; volatile
            // writes + SeqCst fence publish TX/BCNQ descriptors before MMIO doorbell writes.
            unsafe {
                for (i, &b) in src.iter().enumerate() {
                    write_volatile(dst_ptr.add(i), b);
                }
            }
            fence(Ordering::SeqCst);
        }
    }
    fn zero_range(&mut self, offset: usize, len: usize) {
        if offset.saturating_add(len) <= self.len {
            let dst_ptr = (self.va + offset) as *mut u8;
            // SAFETY: Bounds checked within `[self.va .. self.va + self.len)`.
            unsafe {
                for i in 0..len {
                    write_volatile(dst_ptr.add(i), 0);
                }
            }
            fence(Ordering::SeqCst);
        }
    }
}

struct Rtw88Hal {
    mmio: PcieBarMmio,
    dma: MappedRtwDma,
    hw: Rtl8821ceHw,
    bdf: u16,
    rx_scratch: Vec<u8>,
}

impl Rtw88Hal {
    fn new(mut mmio: PcieBarMmio, mut dma: MappedRtwDma, bdf: u16, fw_blob: Option<&[u8]>) -> Self {
        let mut hw = Rtl8821ceHw::new();
        if let Some(blob) = fw_blob {
            match hw.init_hardware(&mut mmio, &mut dma, blob) {
                Ok(()) => {
                    let m = hw.efuse.mac_addr;
                    let (fw_maj, fw_min) = hw
                        .fw_info
                        .map(|f| (f.version, f.subversion))
                        .unwrap_or((0, 0));
                    println!(
                        "[wlan-service] RTL8821CE (10ec:c821) bdf={:#06x} online: mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rfe={} xtal={:#04x} fw=v{}.{} mcufw={:#06x}",
                        bdf,
                        m[0],
                        m[1],
                        m[2],
                        m[3],
                        m[4],
                        m[5],
                        hw.efuse.rfe_option,
                        hw.efuse.crystal_cap,
                        fw_maj,
                        fw_min,
                        hw.last_mcufw_ctrl
                    );
                }
                Err(e) => {
                    println!(
                        "[wlan-service] RTL8821CE (10ec:c821) bdf={:#06x} hardware bring-up error: {:?} (diag={} mcufw={:#06x})",
                        bdf,
                        e,
                        wlan::hw_diag_code::as_str(hw.last_diag),
                        hw.last_mcufw_ctrl
                    );
                }
            }
        } else {
            hw.last_diag = wlan::hw_diag_code::FW_FILE_MISSING;
            hw.last_mcufw_ctrl = mmio.read16(huesos_rtw88::hw::REG_MCUFW_CTRL);
            println!(
                "[wlan-service] RTL8821CE (10ec:c821) bdf={:#06x} detected, but {} missing",
                bdf, FW_PATH
            );
        }
        Self {
            mmio,
            dma,
            hw,
            bdf,
            rx_scratch: alloc::vec![0u8; 2368],
        }
    }
}

impl WlanHal for Rtw88Hal {
    fn is_present(&self) -> bool {
        true
    }
    fn is_hardware_radio(&self) -> bool {
        true
    }
    fn is_firmware_ready(&self) -> bool {
        self.hw.initialized
    }
    fn pci_bdf(&self) -> u16 {
        self.bdf
    }
    fn fw_version(&self) -> [u16; 2] {
        self.hw
            .fw_info
            .map(|f| [f.version, u16::from(f.subversion)])
            .unwrap_or([0, 0])
    }
    fn factory_mac(&self) -> [u8; 6] {
        self.hw.efuse.mac_addr
    }
    fn thermal_and_xtal(&self) -> (u8, u8) {
        (42, self.hw.efuse.crystal_cap)
    }
    fn hw_diag_and_mcufw(&self) -> (u8, u16) {
        (self.hw.last_diag, self.hw.last_mcufw_ctrl)
    }
    fn set_mac_addr(&mut self, mac: &[u8; 6]) {
        self.hw.program_mac_addr(&mut self.mmio, mac);
    }
    fn set_channel(&mut self, channel: u8, bw_mhz: u8) {
        if self.hw.initialized {
            self.hw.set_channel(&mut self.mmio, channel, bw_mhz);
        }
    }
    fn configure_sta_link(&mut self, bssid: &[u8; 6], linked: bool) {
        if self.hw.initialized {
            self.hw.configure_sta_mode(&mut self.mmio, bssid, linked);
        }
    }
    fn configure_ap(&mut self, bssid: &[u8; 6], beacon_mpdu: &[u8], beacon_int_tu: u16) -> bool {
        if !self.hw.initialized {
            return false;
        }
        self.hw
            .configure_ap_mode(
                &mut self.mmio,
                &mut self.dma,
                bssid,
                beacon_mpdu,
                beacon_int_tu,
            )
            .is_ok()
    }
    fn install_ccmp_key(
        &mut self,
        slot: u8,
        key_idx: u8,
        peer_mac: &[u8; 6],
        is_group: bool,
        tk: &[u8; 16],
    ) {
        if self.hw.initialized {
            self.hw
                .write_sec_cam(&mut self.mmio, slot, key_idx, peer_mac, is_group, tk);
        }
    }
    fn clear_ccmp_key(&mut self, slot: u8) {
        if self.hw.initialized {
            self.hw.clear_sec_cam(&mut self.mmio, slot);
        }
    }
    fn tx_mpdu(&mut self, _now_ms: u64, mpdu: &[u8]) -> bool {
        if !self.hw.initialized {
            return false;
        }
        let is_mgmt = mpdu.first().is_some_and(|fc0| ((fc0 >> 2) & 0x03) == 0);
        self.hw
            .transmit_mpdu(&mut self.mmio, &mut self.dma, mpdu, is_mgmt)
            .is_ok()
    }
    fn poll_rx_mpdu(&mut self) -> Option<(i8, Vec<u8>)> {
        if !self.hw.initialized {
            return None;
        }
        let mut c2h = None;
        let (n, rssi) = self.hw.poll_rx_mpdu(
            &mut self.mmio,
            &mut self.dma,
            &mut self.rx_scratch,
            Some(&mut c2h),
        )?;
        Some((rssi, self.rx_scratch[..n].to_vec()))
    }
    fn set_bt_coex_profile(&mut self, profile: BtCoexProfile) {
        if self.hw.initialized {
            self.hw.set_bt_coex_profile(&mut self.mmio, profile as u8);
        }
    }
}

struct UnsupportedPciWlanHal {
    bdf: u16,
}

impl WlanHal for UnsupportedPciWlanHal {
    fn is_present(&self) -> bool {
        true
    }
    fn is_hardware_radio(&self) -> bool {
        true
    }
    fn is_firmware_ready(&self) -> bool {
        false
    }
    fn pci_bdf(&self) -> u16 {
        self.bdf
    }
    fn fw_version(&self) -> [u16; 2] {
        [0, 0]
    }
    fn factory_mac(&self) -> [u8; 6] {
        [0; 6]
    }
    fn thermal_and_xtal(&self) -> (u8, u8) {
        (0, 0)
    }
    fn set_mac_addr(&mut self, _mac: &[u8; 6]) {}
    fn set_channel(&mut self, _channel: u8, _bw_mhz: u8) {}
    fn configure_sta_link(&mut self, _bssid: &[u8; 6], _linked: bool) {}
    fn configure_ap(&mut self, _bssid: &[u8; 6], _beacon_mpdu: &[u8], _beacon_int_tu: u16) -> bool {
        false
    }
    fn install_ccmp_key(
        &mut self,
        _slot: u8,
        _key_idx: u8,
        _peer_mac: &[u8; 6],
        _is_group: bool,
        _tk: &[u8; 16],
    ) {
    }
    fn clear_ccmp_key(&mut self, _slot: u8) {}
    fn tx_mpdu(&mut self, _now_ms: u64, _mpdu: &[u8]) -> bool {
        false
    }
    fn poll_rx_mpdu(&mut self) -> Option<(i8, Vec<u8>)> {
        None
    }
}

#[cfg(not(feature = "boot-selftest"))]
struct AbsentWlanHal;

#[cfg(not(feature = "boot-selftest"))]
impl WlanHal for AbsentWlanHal {
    fn is_present(&self) -> bool {
        false
    }
    fn is_hardware_radio(&self) -> bool {
        false
    }
    fn is_firmware_ready(&self) -> bool {
        false
    }
    fn pci_bdf(&self) -> u16 {
        0
    }
    fn fw_version(&self) -> [u16; 2] {
        [0, 0]
    }
    fn factory_mac(&self) -> [u8; 6] {
        [0; 6]
    }
    fn thermal_and_xtal(&self) -> (u8, u8) {
        (0, 0)
    }
    fn set_mac_addr(&mut self, _mac: &[u8; 6]) {}
    fn set_channel(&mut self, _channel: u8, _bw_mhz: u8) {}
    fn configure_sta_link(&mut self, _bssid: &[u8; 6], _linked: bool) {}
    fn configure_ap(&mut self, _bssid: &[u8; 6], _beacon_mpdu: &[u8], _beacon_int_tu: u16) -> bool {
        false
    }
    fn install_ccmp_key(
        &mut self,
        _slot: u8,
        _key_idx: u8,
        _peer_mac: &[u8; 6],
        _is_group: bool,
        _tk: &[u8; 16],
    ) {
    }
    fn clear_ccmp_key(&mut self, _slot: u8) {}
    fn tx_mpdu(&mut self, _now_ms: u64, _mpdu: &[u8]) -> bool {
        false
    }
    fn poll_rx_mpdu(&mut self) -> Option<(i8, Vec<u8>)> {
        None
    }
}

#[cfg(feature = "boot-selftest")]
struct SelftestVirtualHal {
    medium: VirtualRtw88Medium,
    fw_ver: [u16; 2],
    mac: [u8; 6],
    ap_mode: bool,
    loopback_rx: VecDeque<(i8, Vec<u8>)>,
}

#[cfg(feature = "boot-selftest")]
impl WlanHal for SelftestVirtualHal {
    fn is_present(&self) -> bool {
        false // Report honest PCIe absence in `adapter_present`, while allowing selftest radio ops
    }
    fn is_hardware_radio(&self) -> bool {
        false
    }
    fn is_firmware_ready(&self) -> bool {
        self.fw_ver != [0, 0]
    }
    fn pci_bdf(&self) -> u16 {
        0
    }
    fn fw_version(&self) -> [u16; 2] {
        self.fw_ver
    }
    fn factory_mac(&self) -> [u8; 6] {
        self.mac
    }
    fn thermal_and_xtal(&self) -> (u8, u8) {
        (0, 0)
    }
    fn set_mac_addr(&mut self, mac: &[u8; 6]) {
        self.mac = *mac;
    }
    fn set_channel(&mut self, _channel: u8, _bw_mhz: u8) {}
    fn configure_sta_link(&mut self, _bssid: &[u8; 6], _linked: bool) {
        self.ap_mode = false;
    }
    fn configure_ap(&mut self, _bssid: &[u8; 6], _beacon_mpdu: &[u8], _beacon_int_tu: u16) -> bool {
        self.ap_mode = true;
        true
    }
    fn install_ccmp_key(
        &mut self,
        _slot: u8,
        _key_idx: u8,
        _peer_mac: &[u8; 6],
        _is_group: bool,
        _tk: &[u8; 16],
    ) {
    }
    fn clear_ccmp_key(&mut self, _slot: u8) {}
    fn tx_mpdu(&mut self, now_ms: u64, mpdu: &[u8]) -> bool {
        if !self.ap_mode {
            self.medium.transmit_sta_mpdu(now_ms, mpdu);
        }
        true
    }
    fn poll_rx_mpdu(&mut self) -> Option<(i8, Vec<u8>)> {
        if let Some(frame) = self.loopback_rx.pop_front() {
            return Some(frame);
        }
        if self.ap_mode {
            None
        } else {
            self.medium.poll_rx_mpdu()
        }
    }
}

// ============================================================================
// Persistent Profile Store (`HxFS` `/etc/wlan/profiles.conf` + RAM Fallback)
// ============================================================================

#[derive(Clone)]
struct SavedPmkProfile {
    ssid: [u8; MAX_SSID_LEN],
    ssid_len: u8,
    security: SecurityMode,
    pmk: [u8; 32],
    fingerprint: [u8; 4],
    autoconnect: bool,
}

fn load_profiles_from_hxfs(hxfs: &Hxfs) -> Option<Vec<SavedPmkProfile>> {
    let file = hxfs.open_file(PROFILES_PATH).ok()?;
    let mut raw = [0u8; 8 + wlan::MAX_PROFILE_SUMMARIES * PROFILE_RECORD_BYTES];
    let data = file.read_at(0, &mut raw).ok()?;
    if data.len() < 8 || &data[..8] != PROFILES_MAGIC {
        return None;
    }
    let mut out = Vec::new();
    let mut off = 8usize;
    while off + PROFILE_RECORD_BYTES <= data.len() && out.len() < wlan::MAX_PROFILE_SUMMARIES {
        let rec = &data[off..off + PROFILE_RECORD_BYTES];
        off += PROFILE_RECORD_BYTES;
        let ssid_len = rec[0].min(MAX_SSID_LEN as u8);
        if ssid_len == 0 {
            continue;
        }
        let autoconnect = rec[1] != 0;
        let security = if rec[2] == 1 {
            SecurityMode::Wpa2PskCcmp
        } else {
            SecurityMode::Open
        };
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&rec[4..8]);
        let mut ssid = [0u8; MAX_SSID_LEN];
        ssid.copy_from_slice(&rec[8..40]);
        let mut pmk = [0u8; 32];
        pmk.copy_from_slice(&rec[40..72]);
        out.push(SavedPmkProfile {
            ssid,
            ssid_len,
            security,
            pmk,
            fingerprint,
            autoconnect,
        });
    }
    Some(out)
}

fn save_profiles_to_hxfs(hxfs: &Hxfs, profiles: &[SavedPmkProfile]) -> bool {
    let _ = hxfs.mkdir(PROFILES_DIR_ETC);
    let _ = hxfs.mkdir(PROFILES_DIR_WLAN);
    let _ = hxfs.unlink(PROFILES_TMP_PATH);

    let count = profiles.len().min(wlan::MAX_PROFILE_SUMMARIES);
    let mut buf = alloc::vec![0u8; 8 + count * PROFILE_RECORD_BYTES];
    buf[..8].copy_from_slice(PROFILES_MAGIC);
    for (idx, p) in profiles.iter().take(count).enumerate() {
        let base = 8 + idx * PROFILE_RECORD_BYTES;
        buf[base] = p.ssid_len;
        buf[base + 1] = u8::from(p.autoconnect);
        buf[base + 2] = match p.security {
            SecurityMode::Open => 0,
            SecurityMode::Wpa2PskCcmp => 1,
        };
        buf[base + 4..base + 8].copy_from_slice(&p.fingerprint);
        buf[base + 8..base + 40].copy_from_slice(&p.ssid);
        buf[base + 40..base + 72].copy_from_slice(&p.pmk);
    }

    let Ok(tmp) = hxfs.create_file(PROFILES_TMP_PATH) else {
        return false;
    };
    if tmp.write_at(0, &buf).is_err() {
        let _ = hxfs.unlink(PROFILES_TMP_PATH);
        return false;
    }
    let _ = tmp.fsync();
    drop(tmp);
    let _ = hxfs.unlink(PROFILES_PATH);
    hxfs.rename(PROFILES_TMP_PATH, PROFILES_PATH).is_ok()
}

// ============================================================================
// Real 802.11 SoftAP Authenticator + Per-Client CCMP + DHCPv4 Server
// ============================================================================

struct SoftApStation {
    mac: [u8; 6],
    authenticated: bool,
    associated: bool,
    aid: u16,
    wpa_auth: Option<Authenticator4Way>,
    tx_ccmp: Option<CcmpContext>,
    rx_ccmp: Option<CcmpContext>,
    leased_ip: Ipv4Addr,
}

struct SoftApState {
    security: SecurityMode,
    pmk: [u8; 32],
    gtk: [u8; 16],
    gw_ip: Ipv4Addr,
    stations: Vec<SoftApStation>,
    last_beacon_ms: u64,
}

impl SoftApState {
    fn new(security: SecurityMode, pmk: [u8; 32], gtk: [u8; 16]) -> Self {
        Self {
            security,
            pmk,
            gtk,
            gw_ip: Ipv4Addr::new(192, 168, 50, 1),
            stations: Vec::with_capacity(MAX_SOFTAP_CLIENTS),
            last_beacon_ms: 0,
        }
    }

    fn connected_count(&self) -> u8 {
        self.stations
            .iter()
            .filter(|s| {
                s.associated && (self.security == SecurityMode::Open || s.tx_ccmp.is_some())
            })
            .count() as u8
    }

    fn upsert_station(&mut self, mac: [u8; 6]) -> Option<(usize, &mut SoftApStation)> {
        if let Some(idx) = self.stations.iter().position(|s| s.mac == mac) {
            return Some((idx, &mut self.stations[idx]));
        }
        if self.stations.len() >= MAX_SOFTAP_CLIENTS {
            return None;
        }
        let idx = self.stations.len();
        let host_octet = 10u8.saturating_add(idx as u8);
        self.stations.push(SoftApStation {
            mac,
            authenticated: false,
            associated: false,
            aid: (idx + 1) as u16,
            wpa_auth: None,
            tx_ccmp: None,
            rx_ccmp: None,
            leased_ip: Ipv4Addr::new(192, 168, 50, host_octet),
        });
        Some((idx, &mut self.stations[idx]))
    }
}

// ============================================================================
// `wlan-service` Runtime State Machine
// ============================================================================

struct WlanClientConn {
    ch: Channel,
    admin: bool,
}

struct WlanRuntime {
    hal: Box<dyn WlanHal>,
    has_virtual_selftest: bool,
    rng: Csprng,
    hxfs: Option<Hxfs>,
    uplink_ch: Option<Channel>,
    factory_mac: [u8; 6],
    active_mac: [u8; 6],
    mac_policy: MacPolicyMode,
    reg_domain: RegDomainCode,
    autoconnect: bool,
    state: WlanStateCode,
    state_deadline_ms: u64,
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
    ap_capab_info: u16,
    group_cipher: [u8; 4],
    gtk_raw: [u8; 16],
    last_fail_status: Option<WlanStatus>,
    supp: Option<Supplicant4Way>,
    tx_ccmp: Option<CcmpContext>,
    rx_ccmp: Option<CcmpContext>,
    rx_gtk_ccmp: Option<CcmpContext>,
    softap: Option<SoftApState>,
    local_net: NetStack,
    last_autoconnect_try_ms: u64,
}

impl WlanRuntime {
    fn radio_operational(&self) -> bool {
        self.hal.is_firmware_ready() || self.has_virtual_selftest
    }

    fn next_seq(&mut self) -> u16 {
        let s = self.seq_num;
        self.seq_num = (self.seq_num + 1) & 0x0FFF;
        s
    }

    fn notify_net_uplink(&self, link_up: bool, start_dhcp: bool, static_ip: Option<Ipv4Addr>) {
        let Some(ch) = self.uplink_ch.as_ref() else {
            return;
        };
        let mut msg = [0u8; 19];
        msg[0] = UPLINK_OP_STATE;
        msg[1] = u8::from(self.hal.is_present() || self.has_virtual_selftest);
        msg[2] = u8::from(link_up);
        msg[3..9].copy_from_slice(&self.active_mac);
        msg[9] = u8::from(start_dhcp);
        if let Some(ip) = static_ip {
            msg[10..14].copy_from_slice(&ip.0);
            msg[14] = 24;
            msg[15..19].copy_from_slice(&ip.0);
        }
        let _ = ch.write(&msg);
    }

    fn forward_eth_to_net(&mut self, now_ms: u64, eth_frame: &[u8]) {
        if let Some(ch) = self.uplink_ch.as_ref() {
            let mut pkt = alloc::vec![0u8; 1 + eth_frame.len()];
            pkt[0] = UPLINK_OP_ETH_FRAME;
            pkt[1..].copy_from_slice(eth_frame);
            if ch.write(&pkt).is_ok() {
                return;
            }
        }
        // Standalone fallback if `net-service` uplink channel is not yet attached
        let mut tx_eth = VecDeque::new();
        self.local_net.ingest_frame(now_ms, eth_frame, &mut tx_eth);
        self.flush_eth_queue_to_air(now_ms, &mut tx_eth);
    }

    fn poll_net_uplink(&mut self, now_ms: u64) {
        let mut rx_frames: Vec<Vec<u8>> = Vec::new();
        if let Some(ch) = self.uplink_ch.as_ref() {
            let mut buf = [0u8; 2048];
            for _ in 0..16 {
                match ch.read_into(&mut buf) {
                    Ok(n) if n > 15 && buf[0] == UPLINK_OP_ETH_FRAME => {
                        rx_frames.push(buf[1..n].to_vec());
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        for raw_eth in rx_frames {
            self.transmit_eth_over_wlan(now_ms, &raw_eth);
        }
    }

    fn transmit_eth_over_wlan(&mut self, now_ms: u64, raw_eth: &[u8]) {
        let Ok(eth) = EthFrame::parse(raw_eth) else {
            return;
        };
        if self.state == WlanStateCode::Connected {
            let encrypted = self.tx_ccmp.is_some();
            self.send_sta_llc_data(now_ms, eth.dst.0, eth.ethertype, eth.payload, encrypted);
        } else if self.state == WlanStateCode::SoftAp {
            self.send_ap_eth_frame(now_ms, eth.dst.0, eth.src.0, eth.ethertype, eth.payload);
        }
    }

    fn tx_mpdu(&mut self, now_ms: u64, mpdu: &[u8]) {
        if self.hal.tx_mpdu(now_ms, mpdu) {
            self.tx_frames += 1;
        }
    }

    fn attach_hxfs(&mut self, ch: Channel) {
        let hxfs = Hxfs::from_channel(ch);
        if let Some(disk_profiles) = load_profiles_from_hxfs(&hxfs) {
            for dp in disk_profiles {
                let s_slice = &dp.ssid[..dp.ssid_len as usize];
                if !self
                    .profiles
                    .iter()
                    .any(|p| &p.ssid[..p.ssid_len as usize] == s_slice)
                    && self.profiles.len() < wlan::MAX_PROFILE_SUMMARIES
                {
                    self.profiles.push(dp);
                }
            }
        } else if !self.profiles.is_empty() {
            let _ = save_profiles_to_hxfs(&hxfs, &self.profiles);
        }
        self.hxfs = Some(hxfs);
    }

    fn persist_profiles(&self) {
        if let Some(hxfs) = self.hxfs.as_ref() {
            let _ = save_profiles_to_hxfs(hxfs, &self.profiles);
        }
    }

    fn upsert_saved_profile(&mut self, ssid: &[u8], security: SecurityMode, pmk: [u8; 32]) {
        let tag_full = hmac_sha1_parts(&pmk, &[b"huesos-pmk-fingerprint", ssid]);
        let fp = [tag_full[0], tag_full[1], tag_full[2], tag_full[3]];
        if let Some(existing) = self
            .profiles
            .iter_mut()
            .find(|p| &p.ssid[..p.ssid_len as usize] == ssid)
        {
            existing.security = security;
            existing.pmk = pmk;
            existing.fingerprint = fp;
        } else if self.profiles.len() < wlan::MAX_PROFILE_SUMMARIES {
            let mut s_arr = [0u8; MAX_SSID_LEN];
            s_arr[..ssid.len()].copy_from_slice(ssid);
            self.profiles.push(SavedPmkProfile {
                ssid: s_arr,
                ssid_len: ssid.len() as u8,
                security,
                pmk,
                fingerprint: fp,
                autoconnect: true,
            });
        }
        self.persist_profiles();
    }

    // -----------------------------------------------------------------------
    // Air RX Pump (Station + SoftAP)
    // -----------------------------------------------------------------------

    fn pump_air(&mut self, now_ms: u64) {
        if !self.radio_operational() {
            return;
        }

        // Emit periodic software Beacons when in SoftAP mode
        if self.state == WlanStateCode::SoftAp {
            let need_bcn = self
                .softap
                .as_ref()
                .is_some_and(|ap| now_ms.saturating_sub(ap.last_beacon_ms) >= 100);
            if need_bcn {
                let sec = self
                    .softap
                    .as_ref()
                    .map(|a| a.security)
                    .unwrap_or(SecurityMode::Wpa2PskCcmp);
                if let Some(ap) = self.softap.as_mut() {
                    ap.last_beacon_ms = now_ms;
                }
                let seq = self.next_seq();
                let mut bcn = [0u8; 256];
                if let Ok(n) = build_beacon_or_probe_resp(
                    false,
                    [0xFF; 6],
                    self.bssid,
                    &self.ssid[..self.ssid_len as usize],
                    self.channel,
                    sec,
                    seq,
                    &mut bcn,
                ) {
                    self.tx_mpdu(now_ms, &bcn[..n]);
                }
            }
        }

        // Check connection handshake timeout on real air
        if matches!(
            self.state,
            WlanStateCode::Authenticating
                | WlanStateCode::Associating
                | WlanStateCode::Handshaking4Way
        ) && self.state_deadline_ms != 0
            && now_ms > self.state_deadline_ms
        {
            self.disconnect(now_ms);
        }

        for _ in 0..32 {
            let Some((rssi, mpdu)) = self.hal.poll_rx_mpdu() else {
                break;
            };
            self.rx_frames += 1;
            let Ok(hdr) = Dot11Header::parse(&mpdu) else {
                continue;
            };
            if self.state == WlanStateCode::SoftAp {
                self.handle_softap_rx(now_ms, rssi, &hdr, &mpdu);
            } else {
                self.handle_sta_rx(now_ms, rssi, &hdr, &mpdu);
            }
        }
    }

    fn handle_sta_rx(&mut self, now_ms: u64, rssi: i8, hdr: &Dot11Header<'_>, mpdu: &[u8]) {
        match hdr.frame_type {
            FC_TYPE_MGMT => match hdr.subtype {
                MGMT_SUBTYPE_BEACON | MGMT_SUBTYPE_PROBE_RESP => {
                    let fallback_ch = if self.channel == 0 { 1 } else { self.channel };
                    if let Ok(bss) = parse_beacon_or_probe_resp(mpdu, fallback_ch, rssi) {
                        if channel_allowed(self.reg_domain, bss.channel) {
                            if self.state == WlanStateCode::Connected && bss.bssid == self.bssid {
                                self.rssi_dbm = rssi;
                            }
                            self.scan_table.upsert(bss);
                        }
                    }
                }
                MGMT_SUBTYPE_AUTH
                    if self.state == WlanStateCode::Authenticating
                        && hdr.addr1 == self.active_mac =>
                {
                    if let Ok((bssid, 0, 2, status)) = parse_auth_frame(mpdu) {
                        if bssid == self.bssid {
                            if status != 0 {
                                self.last_fail_status = Some(WlanStatus::AuthFailed);
                            } else {
                                self.state = WlanStateCode::Associating;
                                self.state_deadline_ms = now_ms + 4_000;
                                let sec = if self.supp.is_some() {
                                    SecurityMode::Wpa2PskCcmp
                                } else {
                                    SecurityMode::Open
                                };
                                let mut buf = [0u8; 224];
                                let seq = self.next_seq();
                                if let Ok(n) = build_assoc_request_for_bss(
                                    self.bssid,
                                    self.active_mac,
                                    &self.ssid[..self.ssid_len as usize],
                                    self.channel,
                                    self.ap_capab_info,
                                    sec,
                                    self.group_cipher,
                                    seq,
                                    &mut buf,
                                ) {
                                    self.tx_mpdu(now_ms, &buf[..n]);
                                }
                            }
                        }
                    }
                }
                MGMT_SUBTYPE_ASSOC_RESP
                    if self.state == WlanStateCode::Associating && hdr.addr1 == self.active_mac =>
                {
                    if let Ok((bssid, status, _aid)) = parse_assoc_response(mpdu) {
                        if bssid == self.bssid {
                            if status != 0 {
                                self.last_fail_status = Some(WlanStatus::AssocFailed);
                            } else {
                                self.rssi_dbm = rssi;
                                // Match Linux `rtw88` (`BSS_CHANGED_ASSOC`): activate `RTW_NET_MGD_LINKED`,
                                // `AID`, and MCU `MEDIA_STATUS_RPT` / `RA_INFO` immediately upon Association
                                // Response so EAPOL 1/4..4/4 frames are ACKed and transmitted cleanly.
                                self.hal.configure_sta_link(&self.bssid, true);
                                if self.supp.is_some() {
                                    self.state = WlanStateCode::Handshaking4Way;
                                    self.state_deadline_ms = now_ms + 4_500;
                                } else {
                                    self.state = WlanStateCode::Connected;
                                    self.state_deadline_ms = 0;
                                    self.on_sta_link_established(now_ms);
                                }
                            }
                        }
                    }
                }
                MGMT_SUBTYPE_DEAUTH | MGMT_SUBTYPE_DISASSOC
                    if hdr.addr2 == self.bssid
                        && (hdr.addr1 == self.active_mac || (hdr.addr1[0] & 1) != 0) =>
                {
                    match self.state {
                        WlanStateCode::Handshaking4Way => {
                            self.last_fail_status = Some(WlanStatus::HandshakeFailed);
                        }
                        WlanStateCode::Associating => {
                            self.last_fail_status = Some(WlanStatus::AssocFailed);
                        }
                        WlanStateCode::Authenticating => {
                            self.last_fail_status = Some(WlanStatus::AuthFailed);
                        }
                        WlanStateCode::Connected => {
                            self.disconnect(now_ms);
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            FC_TYPE_DATA => {
                if (hdr.flags & FC_FLAG_FROM_DS) == 0 || hdr.addr2 != self.bssid {
                    return;
                }
                let is_bmc = (hdr.addr1[0] & 1) != 0;
                if !is_bmc && hdr.addr1 != self.active_mac {
                    return;
                }
                if (hdr.subtype & 0x04) != 0 || hdr.body.is_empty() {
                    return;
                }
                let plain = if (hdr.flags & FC_FLAG_PROTECTED) != 0 {
                    if is_bmc {
                        if self.group_cipher == CIPHER_SUITE_TKIP && self.gtk_raw != [0u8; 16] {
                            match decrypt_tkip_group_mpdu(&self.gtk_raw, mpdu) {
                                Ok(pt) => pt,
                                Err(_) => {
                                    self.ccmp_replay_drops += 1;
                                    return;
                                }
                            }
                        } else {
                            let Some(rx_g) = self.rx_gtk_ccmp.as_mut() else {
                                return;
                            };
                            match rx_g.decrypt_mpdu(mpdu) {
                                Ok(pt) => pt,
                                Err(_) => {
                                    self.ccmp_replay_drops += 1;
                                    return;
                                }
                            }
                        }
                    } else {
                        let Some(rx_c) = self.rx_ccmp.as_mut() else {
                            return;
                        };
                        match rx_c.decrypt_mpdu(mpdu) {
                            Ok(pt) => pt,
                            Err(_) => {
                                self.ccmp_replay_drops += 1;
                                return;
                            }
                        }
                    }
                } else {
                    if self.tx_ccmp.is_some() {
                        // Drop unencrypted non-EAPOL data once WPA2-CCMP session is active
                        let is_eapol = parse_llc_snap_payload(hdr.body)
                            .is_ok_and(|(et, _)| et == ETHERTYPE_EAPOL);
                        if !is_eapol {
                            return;
                        }
                    }
                    hdr.body.to_vec()
                };
                let Ok((ethertype, l3)) = parse_llc_snap_payload(&plain) else {
                    return;
                };
                if ethertype == ETHERTYPE_EAPOL {
                    if let Some(supp) = self.supp.as_mut() {
                        if let Ok(reply_eapol) = supp.on_eapol_frame(l3) {
                            let installed = supp.installed_keys().copied();
                            let bssid = self.bssid;
                            self.send_sta_llc_data(
                                now_ms,
                                bssid,
                                ETHERTYPE_EAPOL,
                                &reply_eapol,
                                false,
                            );
                            if let Some(keys) = installed {
                                let was_connected = self.state == WlanStateCode::Connected;
                                self.tx_ccmp = Some(CcmpContext::new(keys.ptk.tk, 0));
                                self.rx_ccmp = Some(CcmpContext::new(keys.ptk.tk, 0));
                                self.gtk_raw = keys.gtk;
                                self.rx_gtk_ccmp = if keys.gtk != [0u8; 16] {
                                    Some(CcmpContext::new(keys.gtk, keys.gtk_idx))
                                } else {
                                    None
                                };
                                self.state = WlanStateCode::Connected;
                                self.state_deadline_ms = 0;
                                if !was_connected {
                                    self.on_sta_link_established(now_ms);
                                }
                            }
                        }
                    }
                } else if self.state == WlanStateCode::Connected {
                    let dst_mac = if (hdr.addr1[0] & 1) != 0 {
                        hdr.addr1
                    } else {
                        self.active_mac
                    };
                    let mut eth = alloc::vec![0u8; 14 + l3.len()];
                    if EthFrame::emit(
                        MacAddr(dst_mac),
                        MacAddr(hdr.addr3),
                        ethertype,
                        l3,
                        &mut eth,
                    )
                    .is_ok()
                    {
                        self.forward_eth_to_net(now_ms, &eth);
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_softap_rx(&mut self, now_ms: u64, _rssi: i8, hdr: &Dot11Header<'_>, mpdu: &[u8]) {
        match hdr.frame_type {
            FC_TYPE_MGMT => match hdr.subtype {
                MGMT_SUBTYPE_PROBE_REQ => {
                    if !probe_req_matches_ssid(hdr.body, &self.ssid[..self.ssid_len as usize]) {
                        return;
                    }
                    let sec = self
                        .softap
                        .as_ref()
                        .map(|a| a.security)
                        .unwrap_or(SecurityMode::Wpa2PskCcmp);
                    let seq = self.next_seq();
                    let mut resp = [0u8; 256];
                    if let Ok(n) = build_beacon_or_probe_resp(
                        true,
                        hdr.addr2,
                        self.bssid,
                        &self.ssid[..self.ssid_len as usize],
                        self.channel,
                        sec,
                        seq,
                        &mut resp,
                    ) {
                        self.tx_mpdu(now_ms, &resp[..n]);
                    }
                }
                MGMT_SUBTYPE_AUTH => {
                    let Ok((bssid, alg, auth_seq, _)) = parse_auth_frame(mpdu) else {
                        return;
                    };
                    if bssid != self.bssid || alg != 0 || auth_seq != 1 {
                        return;
                    }
                    let Some(ap) = self.softap.as_mut() else {
                        return;
                    };
                    let status_code = if let Some((_idx, sta)) = ap.upsert_station(hdr.addr2) {
                        sta.authenticated = true;
                        sta.associated = false;
                        sta.wpa_auth = None;
                        sta.tx_ccmp = None;
                        sta.rx_ccmp = None;
                        0u16
                    } else {
                        17u16 // AP unable to handle additional associated STAs
                    };
                    let seq = self.next_seq();
                    let mut resp = [0u8; 64];
                    if let Ok(n) = build_auth_frame(
                        hdr.addr2,
                        self.bssid,
                        self.bssid,
                        2,
                        status_code,
                        seq,
                        &mut resp,
                    ) {
                        self.tx_mpdu(now_ms, &resp[..n]);
                    }
                }
                MGMT_SUBTYPE_ASSOC_REQ if hdr.addr1 == self.bssid => {
                    let anonce = self.rng.gen_nonce32();
                    let mut aid_out = 0u16;
                    let mut m1_out: Option<Vec<u8>> = None;
                    let bssid = self.bssid;
                    if let Some(ap) = self.softap.as_mut() {
                        let sec = ap.security;
                        let pmk = ap.pmk;
                        let gtk = ap.gtk;
                        if let Some(sta) = ap.stations.iter_mut().find(|s| s.mac == hdr.addr2) {
                            if sta.authenticated {
                                sta.associated = true;
                                aid_out = sta.aid;
                                if sec == SecurityMode::Wpa2PskCcmp {
                                    let mut auth =
                                        Authenticator4Way::new(pmk, bssid, hdr.addr2, anonce, gtk);
                                    m1_out = Some(auth.build_msg1());
                                    sta.wpa_auth = Some(auth);
                                }
                            }
                        }
                    }
                    if aid_out != 0 {
                        let seq = self.next_seq();
                        let mut resp = [0u8; 128];
                        if let Ok(n) =
                            build_assoc_response(hdr.addr2, self.bssid, 0, aid_out, seq, &mut resp)
                        {
                            self.tx_mpdu(now_ms, &resp[..n]);
                        }
                        if let Some(m1) = m1_out {
                            self.send_ap_unicast_llc(
                                now_ms,
                                hdr.addr2,
                                self.bssid,
                                ETHERTYPE_EAPOL,
                                &m1,
                                false,
                            );
                        }
                    }
                }
                MGMT_SUBTYPE_DEAUTH | MGMT_SUBTYPE_DISASSOC if hdr.addr1 == self.bssid => {
                    let mut cam_slot = None;
                    if let Some(ap) = self.softap.as_mut() {
                        if let Some(idx) = ap.stations.iter().position(|s| s.mac == hdr.addr2) {
                            cam_slot = Some((4 + idx) as u8);
                            ap.stations.remove(idx);
                        }
                    }
                    if let Some(slot) = cam_slot {
                        self.hal.clear_ccmp_key(slot);
                    }
                }
                _ => {}
            },
            FC_TYPE_DATA => {
                if (hdr.flags & FC_FLAG_TO_DS) == 0 || hdr.addr1 != self.bssid {
                    return;
                }
                let sta_mac = hdr.addr2;
                let mut replay_drop = false;
                let plain_opt = if let Some(ap) = self.softap.as_mut() {
                    let sec = ap.security;
                    if let Some(sta) = ap
                        .stations
                        .iter_mut()
                        .find(|s| s.mac == sta_mac && s.associated)
                    {
                        if (hdr.flags & FC_FLAG_PROTECTED) != 0 {
                            if let Some(rx_c) = sta.rx_ccmp.as_mut() {
                                match rx_c.decrypt_mpdu(mpdu) {
                                    Ok(pt) => Some(pt),
                                    Err(_) => {
                                        replay_drop = true;
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        } else if sec == SecurityMode::Wpa2PskCcmp && sta.tx_ccmp.is_some() {
                            None
                        } else {
                            Some(hdr.body.to_vec())
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                if replay_drop {
                    self.ccmp_replay_drops += 1;
                    return;
                }
                let Some(plain) = plain_opt else {
                    return;
                };
                let Ok((ethertype, l3)) = parse_llc_snap_payload(&plain) else {
                    return;
                };

                if ethertype == ETHERTYPE_EAPOL {
                    let mut m3_reply = None;
                    let mut completed_tk = None;
                    if let Some(ap) = self.softap.as_mut() {
                        if let Some((idx, sta)) = ap
                            .stations
                            .iter_mut()
                            .enumerate()
                            .find(|(_, s)| s.mac == sta_mac)
                        {
                            if let Some(auth) = sta.wpa_auth.as_mut() {
                                if let Ok(Some(m3)) = auth.on_supplicant_eapol(l3) {
                                    m3_reply = Some(m3);
                                } else if auth.is_complete() {
                                    if let Some(ptk) = auth.ptk().copied() {
                                        sta.tx_ccmp = Some(CcmpContext::new(ptk.tk, 0));
                                        sta.rx_ccmp = Some(CcmpContext::new(ptk.tk, 0));
                                        completed_tk = Some(((4 + idx) as u8, ptk.tk));
                                    }
                                }
                            }
                        }
                    }
                    if let Some(m3) = m3_reply {
                        self.send_ap_unicast_llc(
                            now_ms,
                            sta_mac,
                            self.bssid,
                            ETHERTYPE_EAPOL,
                            &m3,
                            false,
                        );
                    }
                    if let Some((slot, tk)) = completed_tk {
                        self.hal.install_ccmp_key(slot, 0, &sta_mac, false, &tk);
                    }
                    return;
                }

                // Built-in SoftAP DHCPv4 server (`192.168.50.1/24`)
                if ethertype == ETHERTYPE_IPV4 {
                    let dhcp_ans = self.softap.as_ref().and_then(|ap| {
                        let sta = ap.stations.iter().find(|s| s.mac == sta_mac)?;
                        build_softap_dhcp_reply(ap.gw_ip, sta.leased_ip, self.bssid, sta_mac, l3)
                    });
                    if let Some((eth_ty, dhcp_ip_pkt)) = dhcp_ans {
                        let encrypt = self
                            .softap
                            .as_ref()
                            .is_some_and(|a| a.security == SecurityMode::Wpa2PskCcmp);
                        self.send_ap_unicast_llc(
                            now_ms,
                            sta_mac,
                            self.bssid,
                            eth_ty,
                            &dhcp_ip_pkt,
                            encrypt,
                        );
                        return;
                    }
                }

                // Intra-BSS client-to-client hair-pinning & uplink forwarding
                let dst_eth = hdr.addr3;
                if (dst_eth[0] & 1) != 0 {
                    // Broadcast/multicast -> echo to other SoftAP STAs AND forward to host stack
                    self.send_ap_eth_frame(now_ms, dst_eth, sta_mac, ethertype, l3);
                } else if self
                    .softap
                    .as_ref()
                    .is_some_and(|ap| ap.stations.iter().any(|s| s.mac == dst_eth))
                {
                    self.send_ap_eth_frame(now_ms, dst_eth, sta_mac, ethertype, l3);
                    return;
                }

                let mut eth = alloc::vec![0u8; 14 + l3.len()];
                if EthFrame::emit(MacAddr(dst_eth), MacAddr(sta_mac), ethertype, l3, &mut eth)
                    .is_ok()
                {
                    self.forward_eth_to_net(now_ms, &eth);
                }
            }
            _ => {}
        }
    }

    fn send_sta_llc_data(
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

    fn send_ap_unicast_llc(
        &mut self,
        now_ms: u64,
        sta_mac: [u8; 6],
        sa_mac: [u8; 6],
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
            if build_data_frame(false, true, self.bssid, sta_mac, sa_mac, seq, &[], &mut hdr)
                .is_err()
            {
                return;
            }
            let mpdu_opt = self.softap.as_mut().and_then(|ap| {
                let sta = ap.stations.iter_mut().find(|s| s.mac == sta_mac)?;
                sta.tx_ccmp
                    .as_mut()?
                    .encrypt_mpdu(&hdr, &llc[..llc_len])
                    .ok()
            });
            if let Some(mpdu) = mpdu_opt {
                self.tx_mpdu(now_ms, &mpdu);
            }
        } else {
            let mut mpdu = alloc::vec![0u8; 24 + llc_len];
            if let Ok(n) = build_data_frame(
                false,
                false,
                self.bssid,
                sta_mac,
                sa_mac,
                seq,
                &llc[..llc_len],
                &mut mpdu,
            ) {
                self.tx_mpdu(now_ms, &mpdu[..n]);
            }
        }
    }

    fn send_ap_eth_frame(
        &mut self,
        now_ms: u64,
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        ethertype: u16,
        l3: &[u8],
    ) {
        let targets: Vec<([u8; 6], bool)> = match self.softap.as_ref() {
            Some(ap) => {
                let enc = ap.security == SecurityMode::Wpa2PskCcmp;
                if (dst_mac[0] & 1) != 0 {
                    ap.stations
                        .iter()
                        .filter(|s| {
                            s.associated && s.mac != src_mac && (!enc || s.tx_ccmp.is_some())
                        })
                        .map(|s| (s.mac, enc))
                        .collect()
                } else {
                    ap.stations
                        .iter()
                        .filter(|s| {
                            s.associated && s.mac == dst_mac && (!enc || s.tx_ccmp.is_some())
                        })
                        .map(|s| (s.mac, enc))
                        .collect()
                }
            }
            None => return,
        };
        for (sta_mac, enc) in targets {
            self.send_ap_unicast_llc(now_ms, sta_mac, src_mac, ethertype, l3, enc);
        }
    }

    fn on_sta_link_established(&mut self, now_ms: u64) {
        self.notify_net_uplink(true, true, None);
        if self.uplink_ch.is_none() {
            self.local_net.cfg.mac = MacAddr(self.active_mac);
            let mut tx_eth = VecDeque::new();
            self.local_net.start_dhcp(now_ms, &mut tx_eth);
            self.flush_eth_queue_to_air(now_ms, &mut tx_eth);
        }
    }

    fn flush_eth_queue_to_air(&mut self, now_ms: u64, tx_eth: &mut VecDeque<Vec<u8>>) {
        while let Some(raw_eth) = tx_eth.pop_front() {
            self.transmit_eth_over_wlan(now_ms, &raw_eth);
        }
    }

    // -----------------------------------------------------------------------
    // Multi-Channel Active Scan, Connect, Autoconnect & SoftAP Control
    // -----------------------------------------------------------------------

    fn run_scan(&mut self, now_ms: u64) {
        self.scan_table.clear();
        if !self.radio_operational() {
            return;
        }
        let prev_state = self.state;
        let prev_ch = self.channel;
        let prev_bw = self.width_mhz;
        if prev_state == WlanStateCode::Idle {
            self.state = WlanStateCode::Scanning;
        }

        if self.hal.is_hardware_radio() {
            for &ch in SCAN_CHANNELS_ALL {
                if !channel_allowed(self.reg_domain, ch) {
                    continue;
                }
                self.channel = ch;
                self.hal.set_channel(ch, 20);
                let mut buf = [0u8; 128];
                let seq = self.next_seq();
                if let Ok(n) =
                    build_probe_request_band(self.active_mac, b"", ch > 14, seq, &mut buf)
                {
                    self.tx_mpdu(now_ms, &buf[..n]);
                }
                // Dwell ~45 ms per channel (22 * 45 ms = 990 ms < 4.0 s RPC timeout),
                // sending a second wildcard ProbeRequest at 15 ms and pumping RX ring.
                for step in 0..45u32 {
                    if step == 15 {
                        let seq2 = self.next_seq();
                        if let Ok(n) =
                            build_probe_request_band(self.active_mac, b"", ch > 14, seq2, &mut buf)
                        {
                            self.tx_mpdu(now_ms, &buf[..n]);
                        }
                    }
                    delay_us_spin(1_000);
                    self.pump_air(now_ms);
                }
            }
            if prev_ch != 0 {
                self.channel = prev_ch;
                self.hal.set_channel(prev_ch, prev_bw);
            } else {
                self.channel = 0;
            }
        } else {
            let mut buf = [0u8; 128];
            let seq = self.next_seq();
            if let Ok(n) = build_probe_request(self.active_mac, b"", seq, &mut buf) {
                self.tx_mpdu(now_ms, &buf[..n]);
                self.pump_air(now_ms);
            }
        }

        if self.state == WlanStateCode::Scanning {
            self.state = WlanStateCode::Idle;
        }
    }

    fn connect_ssid(&mut self, now_ms: u64, ssid: &[u8], passphrase: &[u8]) -> WlanStatus {
        if !self.hal.is_present() && !self.has_virtual_selftest {
            return WlanStatus::HardwareAbsent;
        }
        if !self.radio_operational() {
            return WlanStatus::FirmwareUnavailable;
        }
        if self.scan_table.find_by_ssid(ssid).is_none() {
            self.run_scan(now_ms);
        }
        let Some(target) = self.scan_table.find_by_ssid(ssid) else {
            return WlanStatus::SsidNotFound;
        };
        if !channel_allowed(self.reg_domain, target.channel) {
            return WlanStatus::RegulatoryBlocked;
        }

        if self.state == WlanStateCode::SoftAp || self.state == WlanStateCode::Connected {
            self.disconnect(now_ms);
        }

        self.supp = None;
        self.tx_ccmp = None;
        self.rx_ccmp = None;
        self.rx_gtk_ccmp = None;
        self.gtk_raw = [0u8; 16];
        self.last_fail_status = None;
        self.ap_capab_info = target.capab_info;
        self.group_cipher = target.group_cipher;

        // Rotate `active_mac` BEFORE constructing `Supplicant4Way` so PTK/MIC use
        // the exact same STA MAC address transmitted in Auth and AssocReq!
        if self.mac_policy == MacPolicyMode::Random {
            let mut rmac = [0u8; 6];
            self.rng.fill_bytes(&mut rmac);
            rmac[0] = (rmac[0] | 0x02) & 0xFE;
            self.active_mac = rmac;
            self.hal.set_mac_addr(&self.active_mac);
        }

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
                self.upsert_saved_profile(ssid, SecurityMode::Wpa2PskCcmp, derived);
                derived
            };
            let snonce = self.rng.gen_nonce32();
            let rsn_ie = build_rsn_ie_with_group(target.group_cipher);
            self.supp = Some(Supplicant4Way::new_with_rsn_ie(
                pmk,
                target.bssid,
                self.active_mac,
                snonce,
                rsn_ie,
            ));
        } else {
            self.upsert_saved_profile(ssid, SecurityMode::Open, [0u8; 32]);
        }

        self.bssid = target.bssid;
        self.channel = target.channel;
        // Operate on the AP's primary 20 MHz channel matching our non-HT rate set
        // (avoids 80 MHz center-channel / VHT negotiation mismatch on 5 GHz).
        self.width_mhz = 20;
        self.ssid.fill(0);
        self.ssid[..ssid.len()].copy_from_slice(ssid);
        self.ssid_len = ssid.len() as u8;
        self.hal.set_channel(self.channel, self.width_mhz);
        self.hal.configure_sta_link(&self.bssid, false);
        if self.hal.is_hardware_radio() {
            delay_us_spin(2_000);
        }
        self.state = WlanStateCode::Authenticating;
        self.state_deadline_ms = now_ms + 5_000;

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

        // Wait up to ~4.0 s on real RF (or 16 ticks on virtual medium) for Auth+Assoc+4Way,
        // retransmitting Auth / AssocReq every 250 ms if a single frame collided on air.
        let poll_iters = if self.hal.is_hardware_radio() {
            2_000u64
        } else {
            16u64
        };
        for step in 0..poll_iters {
            if self.hal.is_hardware_radio() {
                delay_us_spin(2_000);
            }
            let cur_ms = now_ms + step * 2;
            self.pump_air(cur_ms);
            if self.state == WlanStateCode::Connected {
                return WlanStatus::Ok;
            }
            if self.last_fail_status.is_some() {
                break;
            }
            if self.hal.is_hardware_radio() && step > 0 && (step % 125 == 0) {
                match self.state {
                    WlanStateCode::Authenticating => {
                        let mut abuf = [0u8; 64];
                        let s = self.next_seq();
                        if let Ok(n) = build_auth_frame(
                            self.bssid,
                            self.active_mac,
                            self.bssid,
                            1,
                            0,
                            s,
                            &mut abuf,
                        ) {
                            self.tx_mpdu(cur_ms, &abuf[..n]);
                        }
                    }
                    WlanStateCode::Associating => {
                        let sec = if self.supp.is_some() {
                            SecurityMode::Wpa2PskCcmp
                        } else {
                            SecurityMode::Open
                        };
                        let mut rbuf = [0u8; 224];
                        let s = self.next_seq();
                        if let Ok(n) = build_assoc_request_for_bss(
                            self.bssid,
                            self.active_mac,
                            &self.ssid[..self.ssid_len as usize],
                            self.channel,
                            self.ap_capab_info,
                            sec,
                            self.group_cipher,
                            s,
                            &mut rbuf,
                        ) {
                            self.tx_mpdu(cur_ms, &rbuf[..n]);
                        }
                    }
                    _ => {}
                }
            }
        }
        let fail_st = self.last_fail_status.unwrap_or(match self.state {
            WlanStateCode::Associating => WlanStatus::AssocFailed,
            WlanStateCode::Handshaking4Way => WlanStatus::HandshakeFailed,
            _ => WlanStatus::AuthFailed,
        });
        self.disconnect(now_ms + 4_000);
        fail_st
    }

    fn start_softap(&mut self, now_ms: u64, ch: u8, ssid: &[u8], passphrase: &[u8]) -> WlanStatus {
        if !self.hal.is_present() && !self.has_virtual_selftest {
            return WlanStatus::HardwareAbsent;
        }
        if !self.radio_operational() {
            return WlanStatus::FirmwareUnavailable;
        }
        if ssid.is_empty() || ssid.len() > MAX_SSID_LEN {
            return WlanStatus::InvalidRequest;
        }
        if !channel_allowed(self.reg_domain, ch) {
            return WlanStatus::RegulatoryBlocked;
        }
        let (security, pmk) = if passphrase.is_empty() {
            (SecurityMode::Open, [0u8; 32])
        } else {
            let Ok(derived) = derive_wpa2_psk(passphrase, ssid) else {
                return WlanStatus::InvalidPassphrase;
            };
            (SecurityMode::Wpa2PskCcmp, derived)
        };

        if self.state == WlanStateCode::Connected || self.state == WlanStateCode::SoftAp {
            self.disconnect(now_ms);
        }

        let gtk = self.rng.gen_key16();
        let bw = if ch >= 36 { 80 } else { 20 };
        let ap_bssid = self.active_mac;

        let mut bcn = [0u8; 256];
        let seq = self.next_seq();
        let Ok(bcn_len) = build_beacon_or_probe_resp(
            false, [0xFF; 6], ap_bssid, ssid, ch, security, seq, &mut bcn,
        ) else {
            return WlanStatus::InvalidRequest;
        };

        self.hal.set_channel(ch, bw);
        if !self.hal.configure_ap(&ap_bssid, &bcn[..bcn_len], 100) {
            return WlanStatus::FirmwareUnavailable;
        }
        if security == SecurityMode::Wpa2PskCcmp {
            self.hal.install_ccmp_key(1, 1, &[0xFF; 6], true, &gtk);
        }

        self.channel = ch;
        self.width_mhz = bw;
        self.bssid = ap_bssid;
        self.ssid.fill(0);
        self.ssid[..ssid.len()].copy_from_slice(ssid);
        self.ssid_len = ssid.len() as u8;
        self.rssi_dbm = -28;
        self.state = WlanStateCode::SoftAp;
        self.softap = Some(SoftApState::new(security, pmk, gtk));

        let gw = Ipv4Addr::new(192, 168, 50, 1);
        self.local_net
            .configure_static(gw, Ipv4Addr::new(255, 255, 255, 0), gw, gw);
        self.notify_net_uplink(true, false, Some(gw));
        WlanStatus::Ok
    }

    fn maybe_try_autoconnect(&mut self, now_ms: u64) {
        if !self.autoconnect
            || self.state != WlanStateCode::Idle
            || self.profiles.is_empty()
            || !self.radio_operational()
            || now_ms.saturating_sub(self.last_autoconnect_try_ms) < 5_000
        {
            return;
        }
        self.last_autoconnect_try_ms = now_ms;
        let mut candidate: Option<([u8; MAX_SSID_LEN], usize)> = None;
        for p in &self.profiles {
            if !p.autoconnect {
                continue;
            }
            let s = &p.ssid[..p.ssid_len as usize];
            if self.scan_table.find_by_ssid(s).is_some() {
                candidate = Some((p.ssid, p.ssid_len as usize));
                break;
            }
        }
        if let Some((ssid_arr, slen)) = candidate {
            let _ = self.connect_ssid(now_ms, &ssid_arr[..slen], b"");
        }
    }

    fn disconnect(&mut self, now_ms: u64) {
        if matches!(
            self.state,
            WlanStateCode::Connected | WlanStateCode::Handshaking4Way | WlanStateCode::Associating
        ) {
            if self.state == WlanStateCode::Connected {
                let mut buf = [0u8; 64];
                let seq = self.next_seq();
                if let Ok(n) =
                    build_deauth(self.bssid, self.active_mac, self.bssid, 3, seq, &mut buf)
                {
                    self.tx_mpdu(now_ms, &buf[..n]);
                }
            }
            self.hal.configure_sta_link(&[0; 6], false);
        } else if self.state == WlanStateCode::SoftAp {
            if let Some(ap) = self.softap.take() {
                for sta in &ap.stations {
                    let mut buf = [0u8; 64];
                    let seq = self.next_seq();
                    if let Ok(n) = build_deauth(sta.mac, self.bssid, self.bssid, 3, seq, &mut buf) {
                        self.tx_mpdu(now_ms, &buf[..n]);
                    }
                }
            }
            self.hal.configure_sta_link(&[0; 6], false);
        }
        for slot in 0..12u8 {
            self.hal.clear_ccmp_key(slot);
        }
        self.supp = None;
        self.tx_ccmp = None;
        self.rx_ccmp = None;
        self.rx_gtk_ccmp = None;
        self.gtk_raw = [0u8; 16];
        self.last_fail_status = None;
        self.softap = None;
        self.bssid = [0; 6];
        self.ssid.fill(0);
        self.ssid_len = 0;
        self.channel = 0;
        self.rssi_dbm = -127;
        self.state_deadline_ms = 0;
        self.notify_net_uplink(false, false, None);
        self.state = if self.hal.is_present() || self.has_virtual_selftest {
            if self.radio_operational() {
                WlanStateCode::Idle
            } else {
                WlanStateCode::FirmwareMissing
            }
        } else {
            WlanStateCode::HardwareAbsent
        };
    }
}

fn probe_req_matches_ssid(body: &[u8], ap_ssid: &[u8]) -> bool {
    let mut idx = 0usize;
    while idx + 2 <= body.len() {
        let id = body[idx];
        let len = usize::from(body[idx + 1]);
        if idx + 2 + len > body.len() {
            break;
        }
        if id == IE_SSID {
            let req = &body[idx + 2..idx + 2 + len];
            return req.is_empty() || req == ap_ssid;
        }
        idx += 2 + len;
    }
    true
}

fn build_softap_dhcp_reply(
    gw_ip: Ipv4Addr,
    lease_ip: Ipv4Addr,
    ap_mac: [u8; 6],
    sta_mac: [u8; 6],
    ipv4_raw: &[u8],
) -> Option<(u16, Vec<u8>)> {
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
    dhcp[16..20].copy_from_slice(&lease_ip.0);
    dhcp[20..24].copy_from_slice(&gw_ip.0);
    dhcp[28..34].copy_from_slice(&sta_mac);
    dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]);

    let mut p = 240usize;
    dhcp[p..p + 3].copy_from_slice(&[53, 1, reply_type]);
    p += 3;
    dhcp[p..p + 2].copy_from_slice(&[54, 4]);
    dhcp[p + 2..p + 6].copy_from_slice(&gw_ip.0);
    p += 6;
    dhcp[p..p + 6].copy_from_slice(&[51, 4, 0, 0, 0x0E, 0x10]); // 3600 s
    p += 6;
    dhcp[p..p + 6].copy_from_slice(&[1, 4, 255, 255, 255, 0]);
    p += 6;
    dhcp[p..p + 2].copy_from_slice(&[3, 4]);
    dhcp[p + 2..p + 6].copy_from_slice(&gw_ip.0);
    p += 6;
    dhcp[p..p + 2].copy_from_slice(&[6, 4]);
    dhcp[p + 2..p + 6].copy_from_slice(&gw_ip.0);
    p += 6;
    dhcp[p] = 255;
    let _ = ap_mac;

    let mut ubuf = [0u8; 330];
    let ulen = UdpPacket::emit(
        gw_ip,
        Ipv4Addr::BROADCAST,
        DHCP_SERVER_PORT,
        DHCP_CLIENT_PORT,
        &dhcp,
        &mut ubuf,
    )
    .ok()?;
    let mut ibuf = alloc::vec![0u8; 360];
    let ilen = Ipv4Packet::emit(
        gw_ip,
        Ipv4Addr::BROADCAST,
        IP_PROTO_UDP,
        64,
        1,
        &ubuf[..ulen],
        &mut ibuf,
    )
    .ok()?;
    ibuf.truncate(ilen);
    Some((ETHERTYPE_IPV4, ibuf))
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // SAFETY: called once at startup before any allocations.
    if unsafe { !HEAP.init() } {
        libcanvas::process::exit(-10);
    }

    let boot_tsc = rdtsc_u64();
    let bootstrap = libcanvas::channel::bootstrap();
    let mut bootfs_vmo: Option<Vmo> = None;
    let mut mmio_res: Option<(Handle, u64, u64)> = None;
    let mut dma_res: Option<(Handle, u64, u64)> = None;
    let mut pci_id_meta: Option<(u32, u16)> = None; // (vendor_device_packed, bdf_packed)
    let mut init_hxfs_ch: Option<Channel> = None;
    let mut init_uplink_ch: Option<Channel> = None;
    let mut init_btl_coex_ch: Option<Channel> = None;

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
                } else if msg == "hxfs:client" {
                    if let Some(h) = handle_opt {
                        init_hxfs_ch = Some(Channel::from_handle(h));
                    }
                } else if msg == "uplink:net" {
                    if let Some(h) = handle_opt {
                        init_uplink_ch = Some(Channel::from_handle(h));
                    }
                } else if msg == "coex:btl" {
                    if let Some(h) = handle_opt {
                        init_btl_coex_ch = Some(Channel::from_handle(h));
                    }
                } else if let Some(rest) = msg.strip_prefix("resource:wlan-service:") {
                    let mut parts = rest.split(':');
                    let kind = parts.next().unwrap_or("");
                    let arg0 = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    let arg1 = parts.next().and_then(parse_hex_u64).unwrap_or(0);
                    if let Some(h) = handle_opt {
                        if kind == "mmio" && arg1 >= 0x1000 && mmio_res.is_none() {
                            mmio_res = Some((h, arg0, arg1));
                        } else if kind == "dma" && dma_res.is_none() {
                            dma_res = Some((h, arg0, arg1));
                        } else if kind == "pciid" && pci_id_meta.is_none() {
                            let vmo = Vmo::from_handle(h);
                            let mut meta = [0u8; 16];
                            if vmo.read(0, &mut meta) == Ok(16) {
                                let vd = u64::from_le_bytes([
                                    meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6],
                                    meta[7],
                                ]) as u32;
                                let bdf = u64::from_le_bytes([
                                    meta[8], meta[9], meta[10], meta[11], meta[12], meta[13],
                                    meta[14], meta[15],
                                ]) as u16;
                                pci_id_meta = Some((vd, bdf));
                            } else {
                                pci_id_meta = Some((arg0 as u32, arg1 as u16));
                            }
                        }
                    }
                }
            }
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {}
            Err(_) => break,
        }
    }

    let fw_blob = bootfs_vmo
        .as_ref()
        .and_then(|vmo| read_bootfs_file(vmo, FW_PATH));
    let fw_info = fw_blob
        .as_deref()
        .and_then(|b| Rtw88FirmwareInfo::parse(b).ok());

    let mut mapped_dma: Option<MappedRtwDma> = None;
    if let Some((dma_h, pa, len)) = dma_res.as_ref() {
        let map_len = (*len).min(4 * 1024 * 1024) & !0xFFF;
        if map_len >= (Rtl8821ceHw::MIN_DMA_BYTES as u64)
            && *pa < 0x1_0000_0000
            && libcanvas::resource::map_self(
                dma_h,
                0,
                WLAN_DMA_VA,
                map_len,
                vmar_flags::READ | vmar_flags::WRITE | vmar_flags::USER | vmar_flags::SPECIFIC,
            )
            .is_ok()
        {
            mapped_dma = Some(MappedRtwDma {
                va: WLAN_DMA_VA as usize,
                pa: *pa as u32,
                len: map_len as usize,
            });
        }
    }

    let mut mapped_mmio: Option<PcieBarMmio> = None;
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
            mapped_mmio = Some(PcieBarMmio {
                base_va: WLAN_MMIO_VA as usize,
                len: map_len as usize,
            });
        }
    }

    let (vd_packed, pci_bdf) = pci_id_meta.unwrap_or((0x10EC_C821, 0));
    let vendor_id = (vd_packed >> 16) as u16;
    let device_id = (vd_packed & 0xFFFF) as u16;
    let is_rtl8821ce = vendor_id == 0x10EC && device_id == 0xC821;

    let (hal, has_virtual_selftest): (Box<dyn WlanHal>, bool) = match (mapped_mmio, mapped_dma) {
        (Some(mmio), Some(dma)) if is_rtl8821ce => (
            Box::new(Rtw88Hal::new(mmio, dma, pci_bdf, fw_blob.as_deref())),
            false,
        ),
        (Some(_mmio), _) => {
            println!(
                "[wlan-service] detected PCIe 802.11 adapter {:04x}:{:04x} at bdf={:#06x} (no matching silicon driver; rtw88 supports 10ec:c821)",
                vendor_id, device_id, pci_bdf
            );
            (Box::new(UnsupportedPciWlanHal { bdf: pci_bdf }), false)
        }
        _ => {
            #[cfg(feature = "boot-selftest")]
            {
                let ver = fw_info
                    .map(|f| [f.version, u16::from(f.subversion)])
                    .unwrap_or([0, 0]);
                println!(
                    "[wlan-service] no PCIe 802.11 adapter detected; boot-selftest virtual medium active (fw v{}.{})",
                    ver[0], ver[1]
                );
                (
                    Box::new(SelftestVirtualHal {
                        medium: VirtualRtw88Medium::new(),
                        fw_ver: ver,
                        mac: [0x00, 0xE0, 0x4C, 0x88, 0x21, 0xCE],
                        ap_mode: false,
                        loopback_rx: VecDeque::new(),
                    }),
                    true,
                )
            }
            #[cfg(not(feature = "boot-selftest"))]
            {
                if let Some(fw) = fw_info {
                    println!(
                        "[wlan-service] no PCIe 802.11 Wi-Fi adapter detected (rtw8821c_fw v{}.{} staged)",
                        fw.version, fw.subversion
                    );
                } else {
                    println!("[wlan-service] no PCIe 802.11 Wi-Fi adapter detected");
                }
                (Box::new(AbsentWlanHal), false)
            }
        }
    };

    let factory_mac = hal.factory_mac();
    let initial_state = if !hal.is_present() && !has_virtual_selftest {
        WlanStateCode::HardwareAbsent
    } else if hal.is_firmware_ready() || has_virtual_selftest {
        WlanStateCode::Idle
    } else {
        WlanStateCode::FirmwareMissing
    };

    let mut rt = WlanRuntime {
        hal,
        has_virtual_selftest,
        rng: Csprng::new(),
        hxfs: None,
        uplink_ch: init_uplink_ch,
        factory_mac,
        active_mac: factory_mac,
        mac_policy: MacPolicyMode::Factory,
        reg_domain: RegDomainCode::World,
        autoconnect: true,
        state: initial_state,
        state_deadline_ms: 0,
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
        ap_capab_info: 0,
        group_cipher: CIPHER_SUITE_CCMP,
        gtk_raw: [0u8; 16],
        last_fail_status: None,
        supp: None,
        tx_ccmp: None,
        rx_ccmp: None,
        rx_gtk_ccmp: None,
        softap: None,
        local_net: NetStack::new(MacAddr(factory_mac)),
        last_autoconnect_try_ms: 0,
    };

    if let Some(ch) = init_hxfs_ch {
        rt.attach_hxfs(ch);
    }
    rt.notify_net_uplink(false, false, None);

    if rt.radio_operational() {
        rt.run_scan(0);
        rt.maybe_try_autoconnect(1);
    }
    let _ = bootstrap.write(b"service:wlan:ready");

    let mut clients: Vec<Option<WlanClientConn>> = Vec::with_capacity(16);
    if let Some(coex_ch) = init_btl_coex_ch {
        clients.push(Some(WlanClientConn {
            ch: coex_ch,
            admin: true,
        }));
    }
    let mut active_until_ms = 0u64;

    loop {
        let now_ms = libcanvas::system::monotonic_ns()
            .map(|ns| ns / 1_000_000)
            .unwrap_or_else(|_| rdtsc_u64().saturating_sub(boot_tsc) / 2_000_000);
        let prev_air = rt.tx_frames.wrapping_add(rt.rx_frames);
        let mut did_ipc = false;
        rt.pump_air(now_ms);
        rt.poll_net_uplink(now_ms);
        rt.maybe_try_autoconnect(now_ms);

        // 1. Accept client, HxFS, and net-service uplink channels from DriverManager
        for _ in 0..8 {
            let mut bmsg = [0u8; 64];
            match bootstrap.read_optional_handle(&mut bmsg) {
                Ok((n, Some(h))) => {
                    did_ipc = true;
                    let tag = &bmsg[..n];
                    let is_ro = tag == b"wlan-client:ro";
                    if tag == b"wlan-client" || is_ro || tag == b"coex:btl" {
                        let conn = WlanClientConn {
                            ch: Channel::from_handle(h),
                            admin: !is_ro,
                        };
                        if let Some(slot) = clients.iter_mut().find(|s| s.is_none()) {
                            *slot = Some(conn);
                        } else if clients.len() < 16 {
                            clients.push(Some(conn));
                        }
                    } else if tag == b"hxfs:client" {
                        rt.attach_hxfs(Channel::from_handle(h));
                    } else if tag == b"uplink:net" {
                        rt.uplink_ch = Some(Channel::from_handle(h));
                        let linked =
                            matches!(rt.state, WlanStateCode::Connected | WlanStateCode::SoftAp);
                        let ap_ip = if rt.state == WlanStateCode::SoftAp {
                            Some(Ipv4Addr::new(192, 168, 50, 1))
                        } else {
                            None
                        };
                        rt.notify_net_uplink(linked, rt.state == WlanStateCode::Connected, ap_ip);
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
            did_ipc = true;
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
                    let (therm, xtal) = rt.hal.thermal_and_xtal();
                    let (hw_diag, mcufw_ctrl) = rt.hal.hw_diag_and_mcufw();
                    let profiles_or_clients = if let Some(ap) = rt.softap.as_ref() {
                        ap.connected_count()
                    } else {
                        rt.profiles.len() as u8
                    };
                    let snap = WlanStatusSnapshot {
                        adapter_present: rt.hal.is_present(),
                        firmware_loaded: rt.hal.is_firmware_ready(),
                        autoconnect: rt.autoconnect,
                        state: rt.state,
                        reg_domain: rt.reg_domain,
                        mac_policy: rt.mac_policy,
                        channel: rt.channel,
                        width_mhz: rt.width_mhz,
                        rssi_dbm: rt.rssi_dbm,
                        thermal_celsius: therm,
                        xtal_cap: xtal,
                        saved_profiles: profiles_or_clients,
                        pci_bdf: rt.hal.pci_bdf(),
                        fw_version: rt.hal.fw_version(),
                        factory_mac: rt.factory_mac,
                        active_mac: rt.active_mac,
                        bssid: rt.bssid,
                        ssid_len: rt.ssid_len,
                        ssid: rt.ssid,
                        hw_diag,
                        mcufw_ctrl,
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
                    if !rt.hal.is_present() && !rt.has_virtual_selftest {
                        let mut rep = [0u8; 8];
                        wlan::write_header(&mut rep, WlanOp::Scan, WlanStatus::HardwareAbsent);
                        if let Some(c) = clients[idx].as_ref() {
                            let _ = c.ch.write(&rep);
                        }
                        continue;
                    }
                    if !rt.radio_operational() {
                        let mut rep = [0u8; 8];
                        wlan::write_header(&mut rep, WlanOp::Scan, WlanStatus::FirmwareUnavailable);
                        if let Some(c) = clients[idx].as_ref() {
                            let _ = c.ch.write(&rep);
                        }
                        continue;
                    }
                    rt.run_scan(now_ms);
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
                    let st = if payload.len() < 34 {
                        WlanStatus::InvalidRequest
                    } else {
                        let slen = usize::from(payload[0]).min(MAX_SSID_LEN);
                        let plen = usize::from(payload[1]).min(wlan::MAX_PASSPHRASE_LEN);
                        if slen == 0 || 34 + plen > payload.len() {
                            WlanStatus::InvalidRequest
                        } else {
                            rt.connect_ssid(now_ms, &payload[2..2 + slen], &payload[34..34 + plen])
                        }
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::Connect, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::Disconnect => {
                    let st = if !rt.hal.is_present() && !rt.has_virtual_selftest {
                        WlanStatus::HardwareAbsent
                    } else {
                        rt.disconnect(now_ms);
                        WlanStatus::Ok
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::Disconnect, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::ApStart => {
                    let st = if payload.len() < 35 {
                        WlanStatus::InvalidRequest
                    } else {
                        let ch = payload[0];
                        let slen = usize::from(payload[1]).min(MAX_SSID_LEN);
                        let plen = usize::from(payload[2]).min(wlan::MAX_PASSPHRASE_LEN);
                        if 35 + plen > payload.len() {
                            WlanStatus::InvalidRequest
                        } else {
                            rt.start_softap(
                                now_ms,
                                ch,
                                &payload[3..3 + slen],
                                &payload[35..35 + plen],
                            )
                        }
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::ApStart, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
                WlanOp::ApStop => {
                    let st = if !rt.hal.is_present() && !rt.has_virtual_selftest {
                        WlanStatus::HardwareAbsent
                    } else {
                        rt.disconnect(now_ms);
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
                                let mut rmac = [0u8; 6];
                                rt.rng.fill_bytes(&mut rmac);
                                rmac[0] = (rmac[0] | 0x02) & 0xFE;
                                rt.active_mac = rmac;
                            }
                            MacPolicyMode::Custom if payload.len() >= 7 => {
                                rt.active_mac.copy_from_slice(&payload[1..7]);
                                rt.active_mac[0] = (rt.active_mac[0] | 0x02) & 0xFE;
                            }
                            MacPolicyMode::Custom => {}
                        }
                        rt.hal.set_mac_addr(&rt.active_mac);
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
                WlanOp::SetBtCoexProfile => {
                    let st = if let Some(profile) =
                        payload.first().copied().and_then(BtCoexProfile::from_raw)
                    {
                        rt.hal.set_bt_coex_profile(profile);
                        WlanStatus::Ok
                    } else {
                        WlanStatus::InvalidRequest
                    };
                    let mut rep = [0u8; 8];
                    wlan::write_header(&mut rep, WlanOp::SetBtCoexProfile, st);
                    if let Some(c) = clients[idx].as_ref() {
                        let _ = c.ch.write(&rep);
                    }
                }
            }
        }

        if rt.tx_frames.wrapping_add(rt.rx_frames) != prev_air || did_ipc {
            active_until_ms = now_ms.saturating_add(50);
            continue;
        }
        let handshaking = matches!(
            rt.state,
            WlanStateCode::Authenticating
                | WlanStateCode::Associating
                | WlanStateCode::Handshaking4Way
        );
        if now_ms < active_until_ms || handshaking {
            libcanvas::system::sleep_ms(1);
            continue;
        }
        let awaited = libcanvas::Signals::READABLE | libcanvas::Signals::PEER_CLOSED;
        let mut items = [libcanvas::WaitItem::new(bootstrap.handle().raw(), awaited, 0); 16];
        let mut count = 1usize;
        if let Some(up) = rt.uplink_ch.as_ref() {
            items[count] = libcanvas::WaitItem::new(up.handle().raw(), awaited, 1);
            count += 1;
        }
        for c in clients.iter().flatten() {
            if count >= items.len() {
                break;
            }
            items[count] = libcanvas::WaitItem::new(c.ch.handle().raw(), awaited, count as u64);
            count += 1;
        }
        let timeout_ticks = if matches!(rt.state, WlanStateCode::Connected | WlanStateCode::SoftAp)
        {
            1
        } else {
            20
        };
        if let Err(err) = libcanvas::wait_any(&items[..count], timeout_ticks) {
            if err != libcanvas::ErrorCode::TimedOut {
                libcanvas::system::sleep_ms(10);
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libcanvas::debug::write_str("[wlan-service] PANIC\n");
    libcanvas::process::exit(-99);
}
