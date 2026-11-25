//! Wire protocol for `wlan-service` (`/services/wlan.elf`, Realtek RTL8821CE `10ec:c821`).
//!
//! Enforces strict secret isolation: WPA2 PSK passwords enter `wlan-service`
//! only on [`WlanOp::Connect`] or [`WlanOp::ApStart`], and neither derived
//! `PMK`s nor transient `PTK`/`GTK` session keys are ever serialized back out
//! to callers (`ListProfiles` exposes only a non-invertible 4-byte tag).

#![forbid(unsafe_code)]

/// Wire magic `"HWLN"` in little-endian.
pub const MAGIC: u32 = 0x4E4C_5748;
/// Protocol version.
pub const VERSION: u16 = 1;
/// Maximum IEEE 802.11 SSID byte length.
pub const MAX_SSID_LEN: usize = 32;
/// Maximum WPA2 passphrase length.
pub const MAX_PASSPHRASE_LEN: usize = 63;
/// Maximum BSS scan entries returned in a single scan reply.
pub const MAX_SCAN_RESULTS: usize = 24;
/// Maximum saved PMK profile summaries returned in a single reply.
pub const MAX_PROFILE_SUMMARIES: usize = 16;

/// `wlan-service` IPC opcodes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WlanOp {
    /// Query hardware telemetry, regulatory domain, MAC policy, and STA/SoftAP state.
    Status = 1,
    /// Trigger or read an active/passive 2.4 GHz + 5 GHz scan.
    Scan = 2,
    /// Authenticate, associate, and run WPA2-CCMP 4-way handshake with an AP.
    Connect = 3,
    /// Deauthenticate and wipe active PTK/GTK session keys.
    Disconnect = 4,
    /// Start WPA2-CCMP SoftAP / Hotspot mode.
    ApStart = 5,
    /// Stop SoftAP / Hotspot mode.
    ApStop = 6,
    /// List saved `/etc/wlan/profiles.conf` PMK profile metadata (no raw keys).
    ListProfiles = 7,
    /// Configure MAC privacy policy (`Factory` / `Random` / `Custom`).
    SetMacPolicy = 8,
    /// Set active 802.11 regulatory domain (`WORLD`, `RU`, `US`, `EU`, `JP`, `UNLOCKED`).
    SetRegDomain = 9,
    /// Enable or disable saved-profile autoconnect.
    SetAutoconnect = 10,
}

impl WlanOp {
    /// Decode a raw opcode byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Status,
            2 => Self::Scan,
            3 => Self::Connect,
            4 => Self::Disconnect,
            5 => Self::ApStart,
            6 => Self::ApStop,
            7 => Self::ListProfiles,
            8 => Self::SetMacPolicy,
            9 => Self::SetRegDomain,
            10 => Self::SetAutoconnect,
            _ => return None,
        })
    }

    /// True when `caps_mask::WLAN_ADMIN` (`wlan=admin`) is required.
    pub const fn requires_admin(self) -> bool {
        !matches!(self, Self::Status | Self::ListProfiles)
    }
}

/// Reply status codes from `wlan-service`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WlanStatus {
    /// Request succeeded.
    Ok = 0,
    /// Malformed request payload.
    InvalidRequest = 1,
    /// Caller lacks `wlan=admin` (`WLAN_ADMIN`) capability rights.
    AccessDenied = 2,
    /// No Realtek RTL8821CE (`10ec:c821`) PCIe adapter is attached to this machine/VM.
    HardwareAbsent = 3,
    /// `/lib/firmware/rtw88/rtw8821c_fw.bin` was missing or failed hardware checksum.
    FirmwareUnavailable = 4,
    /// Requested channel/power violates the active regulatory domain.
    RegulatoryBlocked = 5,
    /// Target SSID was not found or authentication/4-way handshake failed.
    AuthFailed = 6,
    /// Passphrase length must be `8..=63` ASCII bytes for WPA2-PSK.
    InvalidPassphrase = 7,
    /// Target SSID was not discovered on any 2.4 GHz or 5 GHz channel.
    SsidNotFound = 8,
    /// Access Point rejected the 802.11 Association Request.
    AssocFailed = 9,
    /// WPA2 4-way EAPOL handshake failed or timed out (commonly wrong password).
    HandshakeFailed = 10,
}

impl WlanStatus {
    /// Decode a wire status byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Ok,
            1 => Self::InvalidRequest,
            2 => Self::AccessDenied,
            3 => Self::HardwareAbsent,
            4 => Self::FirmwareUnavailable,
            5 => Self::RegulatoryBlocked,
            6 => Self::AuthFailed,
            7 => Self::InvalidPassphrase,
            8 => Self::SsidNotFound,
            9 => Self::AssocFailed,
            10 => Self::HandshakeFailed,
            _ => return None,
        })
    }
}

/// Regulatory domain identifier shared across `wlan-service` and `wlanctl`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RegDomainCode {
    /// Safe global 802.11d world roaming intersection (default).
    #[default]
    World = 0,
    /// Russian Federation (`RU`).
    Ru = 1,
    /// United States FCC (`US`).
    Us = 2,
    /// European Union ETSI (`EU`).
    Eu = 3,
    /// Japan MIC (`JP`).
    Jp = 4,
    /// All hardware-supported 2.4 GHz (1–14) & 5 GHz (36–165) channels unlocked.
    Unlocked = 5,
}

impl RegDomainCode {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::World,
            1 => Self::Ru,
            2 => Self::Us,
            3 => Self::Eu,
            4 => Self::Jp,
            5 => Self::Unlocked,
            _ => return None,
        })
    }

    /// Canonical CLI/TUI label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::World => "WORLD",
            Self::Ru => "RU",
            Self::Us => "US",
            Self::Eu => "EU",
            Self::Jp => "JP",
            Self::Unlocked => "UNLOCKED",
        }
    }
}

/// MAC privacy policy mode (`Factory` by default).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MacPolicyMode {
    /// Hardware factory MAC read from RTL8821CE EFUSE (`0x11A`).
    #[default]
    Factory = 0,
    /// Locally-administered unicast random MAC per connection/scan.
    Random = 1,
    /// Explicit user-configured locally-administered unicast MAC.
    Custom = 2,
}

impl MacPolicyMode {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Factory,
            1 => Self::Random,
            2 => Self::Custom,
            _ => return None,
        })
    }

    /// Canonical label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Factory => "factory",
            Self::Random => "random",
            Self::Custom => "custom",
        }
    }
}

/// STA / SoftAP operating state reported by `wlan-service`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WlanStateCode {
    /// No `10ec:c821` PCIe adapter present on the bus.
    #[default]
    HardwareAbsent = 0,
    /// Adapter initialized and idle (disconnected).
    Idle = 1,
    /// Sweeping 2.4 GHz / 5 GHz channels.
    Scanning = 2,
    /// Performing 802.11 Open System authentication.
    Authenticating = 3,
    /// Performing 802.11 Association.
    Associating = 4,
    /// Performing WPA2-PSK 4-Way EAPOL-Key handshake.
    Handshaking4Way = 5,
    /// Associated + PTK/GTK installed in CCMP engine.
    Connected = 6,
    /// Broadcasting WPA2-CCMP SoftAP / Hotspot.
    SoftAp = 7,
    /// Hardware detected, but firmware missing or failed init.
    FirmwareMissing = 8,
}

impl WlanStateCode {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::HardwareAbsent,
            1 => Self::Idle,
            2 => Self::Scanning,
            3 => Self::Authenticating,
            4 => Self::Associating,
            5 => Self::Handshaking4Way,
            6 => Self::Connected,
            7 => Self::SoftAp,
            8 => Self::FirmwareMissing,
            _ => return None,
        })
    }

    /// Human-readable status string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HardwareAbsent => "hardware-absent",
            Self::Idle => "disconnected",
            Self::Scanning => "scanning",
            Self::Authenticating => "authenticating",
            Self::Associating => "associating",
            Self::Handshaking4Way => "4way-handshake",
            Self::Connected => "connected",
            Self::SoftAp => "softap-active",
            Self::FirmwareMissing => "firmware-missing",
        }
    }
}

/// Security suite advertised by a scanned BSS.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WlanSecurity {
    /// Unencrypted Open network.
    #[default]
    Open = 0,
    /// RSN WPA2-PSK with AES-CCMP.
    Wpa2Psk = 1,
    /// RSN WPA2/WPA3 transition or WPA3-SAE.
    Wpa3 = 2,
}

impl WlanSecurity {
    /// Decode from wire byte.
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Wpa2Psk,
            2 => Self::Wpa3,
            _ => Self::Open,
        }
    }

    /// Short display tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Wpa2Psk => "WPA2-CCMP",
            Self::Wpa3 => "WPA3/WPA2",
        }
    }
}

/// Complete telemetry & state snapshot returned by [`WlanOp::Status`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WlanStatusSnapshot {
    /// True if `pci-manager` bound a real `10ec:c821` RTL8821CE PCIe function.
    pub adapter_present: bool,
    /// True if `rtw8821c_fw.bin` passed header & WLCPU checksum boot.
    pub firmware_loaded: bool,
    /// Saved-profile autoconnect enabled.
    pub autoconnect: bool,
    /// Active operating state.
    pub state: WlanStateCode,
    /// Active regulatory domain.
    pub reg_domain: RegDomainCode,
    /// Active MAC privacy policy.
    pub mac_policy: MacPolicyMode,
    /// Active channel (`1..=14` or `36..=165`, `0` when idle).
    pub channel: u8,
    /// Active channel width in MHz (`20`, `40`, or `80`).
    pub width_mhz: u8,
    /// Current RSSI in dBm (`-100..=0`, `-127` when disconnected).
    pub rssi_dbm: i8,
    /// Thermal sensor reading in °C from RTL8821CE RF thermal meter.
    pub thermal_celsius: u8,
    /// Crystal cap value from EFUSE (`0xB9`).
    pub xtal_cap: u8,
    /// Connected SoftAP client count (in `SoftAp` mode) or saved profile count.
    pub saved_profiles: u8,
    /// PCI Bus:Device.Function packed as `(bus << 8) | (dev << 3) | func`.
    pub pci_bdf: u16,
    /// Firmware version `(major, minor)`.
    pub fw_version: [u16; 2],
    /// Hardware factory MAC from RTL8821CE EFUSE.
    pub factory_mac: [u8; 6],
    /// Currently programmed MAC address.
    pub active_mac: [u8; 6],
    /// Connected AP BSSID (or SoftAP BSSID).
    pub bssid: [u8; 6],
    /// Connected SSID length (`0..=32`).
    pub ssid_len: u8,
    /// Connected SSID bytes.
    pub ssid: [u8; MAX_SSID_LEN],
    /// Hardware bring-up diagnostic code (`0` = OK, non-zero = bring-up stage failure).
    pub hw_diag: u8,
    /// Live or last-observed `REG_MCUFW_CTRL` (`0x0080`) register value (`0xC078` when WCPU ready).
    pub mcufw_ctrl: u16,
    /// Transmitted 802.11 MPDU count across the 8 hardware TX rings.
    pub tx_frames: u64,
    /// Received 802.11 MPDU count on the hardware RX ring.
    pub rx_frames: u64,
    /// Frames dropped due to CCMP MIC failure or replay-counter violation.
    pub ccmp_replay_drops: u64,
}

/// Hardware bring-up diagnostic stage codes reported in [`WlanStatusSnapshot::hw_diag`].
pub mod hw_diag_code {
    /// Hardware initialized cleanly (`REG_MCUFW_CTRL == 0xC078`) or no hardware bring-up attempted.
    pub const OK: u8 = 0;
    /// Firmware file `/lib/firmware/rtw88/rtw8821c_fw.bin` missing or header invalid.
    pub const FW_BLOB_INVALID: u8 = 1;
    /// `REG_SYS_CFG1` read `0xFFFF_FFFF` (PCIe MMIO BAR unreachable).
    pub const MMIO_UNREACHABLE: u8 = 2;
    /// `card_enable_flow_8821c` power-sequence poll timed out.
    pub const PWR_SEQ_TIMEOUT: u8 = 3;
    /// Indirect LTECoex register `0x1700` `LTECOEX_READY` poll timed out.
    pub const LTECOEX_TIMEOUT: u8 = 4;
    /// `BCNQ` reserved-page upload timed out polling `BIT_BCN_VALID_V1` (`REG_FIFOPAGE_CTRL_2`).
    pub const RSVD_PAGE_BCN_TIMEOUT: u8 = 5;
    /// Internal IDDMA transfer (`REG_DDMA_CH0CTRL`) timed out.
    pub const IDDMA_TIMEOUT: u8 = 6;
    /// Hardware DDMA firmware section checksum mismatch (`BIT_DDMACH0_CHKSUM_STS`).
    pub const FW_CHECKSUM_BAD: u8 = 7;
    /// WCPU3081 boot timed out polling `FW_READY` in `REG_MCUFW_CTRL`.
    pub const WCPU_BOOT_TIMEOUT: u8 = 8;
    /// TX FIFO `REG_AUTO_LLT_V1` initialization timed out.
    pub const AUTO_LLT_TIMEOUT: u8 = 9;
    /// DMA pool buffer too small or descriptor malformed.
    pub const DMA_RING_INVALID: u8 = 10;
    /// Firmware file `/lib/firmware/rtw88/rtw8821c_fw.bin` not found in initrd/HxFS.
    pub const FW_FILE_MISSING: u8 = 11;

    /// Human-readable short slug for `wlanctl status`.
    pub const fn as_str(code: u8) -> &'static str {
        match code {
            OK => "ok",
            FW_BLOB_INVALID => "fw-blob-invalid",
            MMIO_UNREACHABLE => "mmio-unreachable",
            PWR_SEQ_TIMEOUT => "pwr-seq-timeout",
            LTECOEX_TIMEOUT => "ltecoex-timeout",
            RSVD_PAGE_BCN_TIMEOUT => "rsvd-page-bcn-timeout",
            IDDMA_TIMEOUT => "iddma-timeout",
            FW_CHECKSUM_BAD => "fw-checksum-bad",
            WCPU_BOOT_TIMEOUT => "wcpu-boot-timeout",
            AUTO_LLT_TIMEOUT => "auto-llt-timeout",
            DMA_RING_INVALID => "dma-ring-invalid",
            FW_FILE_MISSING => "fw-file-missing",
            _ => "hw-init-error",
        }
    }
}

impl WlanStatusSnapshot {
    /// Wire payload size in bytes.
    pub const PAYLOAD_LEN: usize = 96;

    /// Connected SSID as UTF-8 `&str`.
    pub fn ssid_str(&self) -> &str {
        let len = (self.ssid_len as usize).min(MAX_SSID_LEN);
        core::str::from_utf8(&self.ssid[..len]).unwrap_or("<binary-ssid>")
    }

    /// Encode full reply (`8 + PAYLOAD_LEN` = `104` bytes).
    pub fn encode_reply(&self, out: &mut [u8]) -> Option<usize> {
        let total = 8 + Self::PAYLOAD_LEN;
        if out.len() < total {
            return None;
        }
        write_header(out, WlanOp::Status, WlanStatus::Ok);
        let p = &mut out[8..total];
        p.fill(0);
        p[0] = u8::from(self.adapter_present);
        p[1] = u8::from(self.firmware_loaded);
        p[2] = u8::from(self.autoconnect);
        p[3] = self.state as u8;
        p[4] = self.reg_domain as u8;
        p[5] = self.mac_policy as u8;
        p[6] = self.channel;
        p[7] = self.width_mhz;
        p[8] = self.rssi_dbm as u8;
        p[9] = self.thermal_celsius;
        p[10] = self.xtal_cap;
        p[11] = self.saved_profiles;
        p[12..14].copy_from_slice(&self.pci_bdf.to_le_bytes());
        p[14..16].copy_from_slice(&self.fw_version[0].to_le_bytes());
        p[16..18].copy_from_slice(&self.fw_version[1].to_le_bytes());
        p[18..24].copy_from_slice(&self.factory_mac);
        p[24..30].copy_from_slice(&self.active_mac);
        p[30..36].copy_from_slice(&self.bssid);
        p[36] = self.ssid_len.min(MAX_SSID_LEN as u8);
        p[37..37 + MAX_SSID_LEN].copy_from_slice(&self.ssid);
        p[69] = self.hw_diag;
        p[70..72].copy_from_slice(&self.mcufw_ctrl.to_le_bytes());
        p[72..80].copy_from_slice(&self.tx_frames.to_le_bytes());
        p[80..88].copy_from_slice(&self.rx_frames.to_le_bytes());
        p[88..96].copy_from_slice(&self.ccmp_replay_drops.to_le_bytes());
        Some(total)
    }

    /// Decode from a reply frame.
    pub fn decode_reply(bytes: &[u8]) -> Result<Self, WlanStatus> {
        let status = check_header(bytes, WlanOp::Status)?;
        if status != WlanStatus::Ok {
            return Err(status);
        }
        if bytes.len() < 8 + Self::PAYLOAD_LEN {
            return Err(WlanStatus::InvalidRequest);
        }
        let p = &bytes[8..8 + Self::PAYLOAD_LEN];
        let mut factory_mac = [0u8; 6];
        factory_mac.copy_from_slice(&p[18..24]);
        let mut active_mac = [0u8; 6];
        active_mac.copy_from_slice(&p[24..30]);
        let mut bssid = [0u8; 6];
        bssid.copy_from_slice(&p[30..36]);
        let mut ssid = [0u8; MAX_SSID_LEN];
        ssid.copy_from_slice(&p[37..37 + MAX_SSID_LEN]);
        Ok(Self {
            adapter_present: p[0] != 0,
            firmware_loaded: p[1] != 0,
            autoconnect: p[2] != 0,
            state: WlanStateCode::from_raw(p[3]).ok_or(WlanStatus::InvalidRequest)?,
            reg_domain: RegDomainCode::from_raw(p[4]).ok_or(WlanStatus::InvalidRequest)?,
            mac_policy: MacPolicyMode::from_raw(p[5]).ok_or(WlanStatus::InvalidRequest)?,
            channel: p[6],
            width_mhz: p[7],
            rssi_dbm: p[8] as i8,
            thermal_celsius: p[9],
            xtal_cap: p[10],
            saved_profiles: p[11],
            pci_bdf: read_u16(p, 12).ok_or(WlanStatus::InvalidRequest)?,
            fw_version: [
                read_u16(p, 14).ok_or(WlanStatus::InvalidRequest)?,
                read_u16(p, 16).ok_or(WlanStatus::InvalidRequest)?,
            ],
            factory_mac,
            active_mac,
            bssid,
            ssid_len: p[36].min(MAX_SSID_LEN as u8),
            ssid,
            hw_diag: p[69],
            mcufw_ctrl: read_u16(p, 70).ok_or(WlanStatus::InvalidRequest)?,
            tx_frames: read_u64(p, 72).ok_or(WlanStatus::InvalidRequest)?,
            rx_frames: read_u64(p, 80).ok_or(WlanStatus::InvalidRequest)?,
            ccmp_replay_drops: read_u64(p, 88).ok_or(WlanStatus::InvalidRequest)?,
        })
    }
}

/// One scanned 802.11 BSS entry (`48` bytes on the wire).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WlanBssInfo {
    /// AP BSSID.
    pub bssid: [u8; 6],
    /// Primary channel (`1..=14` or `36..=165`).
    pub channel: u8,
    /// Channel width in MHz (`20`, `40`, `80`).
    pub width_mhz: u8,
    /// Signal strength in dBm.
    pub rssi_dbm: i8,
    /// Advertised security mode.
    pub security: WlanSecurity,
    /// 802.11n HT capability present.
    pub ht: bool,
    /// 802.11ac VHT capability present.
    pub vht: bool,
    /// SSID length (`0..=32`).
    pub ssid_len: u8,
    /// SSID bytes.
    pub ssid: [u8; MAX_SSID_LEN],
}

impl WlanBssInfo {
    /// Fixed wire size of one BSS record.
    pub const WIRE_LEN: usize = 48;

    /// SSID as UTF-8 `&str`.
    pub fn ssid_str(&self) -> &str {
        let len = (self.ssid_len as usize).min(MAX_SSID_LEN);
        core::str::from_utf8(&self.ssid[..len]).unwrap_or("<hidden>")
    }

    /// True if this BSS is on the 5 GHz band (`channel >= 36`).
    pub const fn is_5ghz(&self) -> bool {
        self.channel >= 36
    }

    /// Encode into `48` bytes.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < Self::WIRE_LEN {
            return None;
        }
        out[..Self::WIRE_LEN].fill(0);
        out[0..6].copy_from_slice(&self.bssid);
        out[6] = self.channel;
        out[7] = self.width_mhz;
        out[8] = self.rssi_dbm as u8;
        out[9] = self.security as u8;
        out[10] = u8::from(self.ht) | (u8::from(self.vht) << 1);
        out[11] = self.ssid_len.min(MAX_SSID_LEN as u8);
        out[12..12 + MAX_SSID_LEN].copy_from_slice(&self.ssid);
        Some(Self::WIRE_LEN)
    }

    /// Decode from `48` bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_LEN {
            return None;
        }
        let mut bssid = [0u8; 6];
        bssid.copy_from_slice(&bytes[0..6]);
        let mut ssid = [0u8; MAX_SSID_LEN];
        ssid.copy_from_slice(&bytes[12..12 + MAX_SSID_LEN]);
        Some(Self {
            bssid,
            channel: bytes[6],
            width_mhz: bytes[7],
            rssi_dbm: bytes[8] as i8,
            security: WlanSecurity::from_raw(bytes[9]),
            ht: (bytes[10] & 1) != 0,
            vht: (bytes[10] & 2) != 0,
            ssid_len: bytes[11].min(MAX_SSID_LEN as u8),
            ssid,
        })
    }
}

/// Non-secret summary of a saved `/etc/wlan/profiles.conf` profile (`40` bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WlanProfileSummary {
    /// SSID length (`0..=32`).
    pub ssid_len: u8,
    /// Autoconnect allowed for this profile.
    pub autoconnect: bool,
    /// Non-invertible 4-byte SHA-256 fingerprint of the stored PMK (for UI display only).
    pub pmk_fingerprint: [u8; 4],
    /// SSID bytes.
    pub ssid: [u8; MAX_SSID_LEN],
}

impl WlanProfileSummary {
    /// Fixed wire size.
    pub const WIRE_LEN: usize = 40;

    /// SSID as `&str`.
    pub fn ssid_str(&self) -> &str {
        let len = (self.ssid_len as usize).min(MAX_SSID_LEN);
        core::str::from_utf8(&self.ssid[..len]).unwrap_or("<binary>")
    }

    /// Encode into `40` bytes.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < Self::WIRE_LEN {
            return None;
        }
        out[..Self::WIRE_LEN].fill(0);
        out[0] = self.ssid_len.min(MAX_SSID_LEN as u8);
        out[1] = u8::from(self.autoconnect);
        out[2..6].copy_from_slice(&self.pmk_fingerprint);
        out[6..6 + MAX_SSID_LEN].copy_from_slice(&self.ssid);
        Some(Self::WIRE_LEN)
    }

    /// Decode from `40` bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_LEN {
            return None;
        }
        let mut pmk_fingerprint = [0u8; 4];
        pmk_fingerprint.copy_from_slice(&bytes[2..6]);
        let mut ssid = [0u8; MAX_SSID_LEN];
        ssid.copy_from_slice(&bytes[6..6 + MAX_SSID_LEN]);
        Some(Self {
            ssid_len: bytes[0].min(MAX_SSID_LEN as u8),
            autoconnect: bytes[1] != 0,
            pmk_fingerprint,
            ssid,
        })
    }
}

/// Write an 8-byte `wlan-service` wire header.
pub fn write_header(out: &mut [u8], op: WlanOp, status: WlanStatus) {
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6] = op as u8;
    out[7] = status as u8;
}

/// Parse a `wlan-service` request header into `(op, payload)`.
pub fn parse_request(bytes: &[u8]) -> Option<(WlanOp, &[u8])> {
    if bytes.len() < 8 {
        return None;
    }
    if read_u32(bytes, 0)? != MAGIC || read_u16(bytes, 4)? != VERSION {
        return None;
    }
    Some((WlanOp::from_raw(bytes[6])?, &bytes[8..]))
}

/// Check a `wlan-service` reply header.
pub fn check_header(bytes: &[u8], expected_op: WlanOp) -> Result<WlanStatus, WlanStatus> {
    if bytes.len() < 8 {
        return Err(WlanStatus::InvalidRequest);
    }
    if read_u32(bytes, 0) != Some(MAGIC) || read_u16(bytes, 4) != Some(VERSION) {
        return Err(WlanStatus::InvalidRequest);
    }
    if bytes[6] != expected_op as u8 {
        return Err(WlanStatus::InvalidRequest);
    }
    WlanStatus::from_raw(bytes[7]).ok_or(WlanStatus::InvalidRequest)
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wlan_status_and_bss_round_trip() {
        let mut snap = WlanStatusSnapshot {
            adapter_present: false,
            firmware_loaded: false,
            autoconnect: true,
            state: WlanStateCode::HardwareAbsent,
            reg_domain: RegDomainCode::Ru,
            mac_policy: MacPolicyMode::Factory,
            channel: 0,
            width_mhz: 20,
            rssi_dbm: -127,
            thermal_celsius: 0,
            xtal_cap: 0x20,
            saved_profiles: 1,
            pci_bdf: 0,
            fw_version: [24, 11],
            factory_mac: [0x00, 0xE0, 0x4C, 0x88, 0x21, 0xCE],
            active_mac: [0x00, 0xE0, 0x4C, 0x88, 0x21, 0xCE],
            bssid: [0; 6],
            ssid_len: 4,
            ssid: [0; MAX_SSID_LEN],
            hw_diag: hw_diag_code::RSVD_PAGE_BCN_TIMEOUT,
            mcufw_ctrl: 0xC078,
            tx_frames: 10,
            rx_frames: 20,
            ccmp_replay_drops: 0,
        };
        snap.ssid[..4].copy_from_slice(b"Hues");

        let mut buf = [0u8; 128];
        let n = snap.encode_reply(&mut buf).unwrap_or(0);
        assert_eq!(WlanStatusSnapshot::decode_reply(&buf[..n]), Ok(snap));

        let mut bss = WlanBssInfo {
            bssid: [0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33],
            channel: 36,
            width_mhz: 80,
            rssi_dbm: -52,
            security: WlanSecurity::Wpa2Psk,
            ht: true,
            vht: true,
            ssid_len: 6,
            ssid: [0; MAX_SSID_LEN],
        };
        bss.ssid[..6].copy_from_slice(b"Lab5G!");
        let mut bwire = [0u8; WlanBssInfo::WIRE_LEN];
        assert_eq!(bss.encode(&mut bwire), Some(WlanBssInfo::WIRE_LEN));
        assert_eq!(WlanBssInfo::decode(&bwire), Some(bss));
        assert!(bss.is_5ghz());
    }
}
