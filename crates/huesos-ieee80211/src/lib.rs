//! `#![no_std]`, `#![forbid(unsafe_code)]` IEEE 802.11 MAC frame parser/builder,
//! Information Element (IE) codec, LLC/SNAP bridge, and Station Management
//! Entity (SME) state machine.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub const IEEE80211_HDR_LEN: usize = 24;
pub const LLC_SNAP_HDR: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
pub const LLC_SNAP_TOTAL_LEN: usize = 8;

pub const FC_TYPE_MGMT: u8 = 0;
pub const FC_TYPE_CTRL: u8 = 1;
pub const FC_TYPE_DATA: u8 = 2;

pub const MGMT_SUBTYPE_ASSOC_REQ: u8 = 0;
pub const MGMT_SUBTYPE_ASSOC_RESP: u8 = 1;
pub const MGMT_SUBTYPE_PROBE_REQ: u8 = 4;
pub const MGMT_SUBTYPE_PROBE_RESP: u8 = 5;
pub const MGMT_SUBTYPE_BEACON: u8 = 8;
pub const MGMT_SUBTYPE_DISASSOC: u8 = 10;
pub const MGMT_SUBTYPE_AUTH: u8 = 11;
pub const MGMT_SUBTYPE_DEAUTH: u8 = 12;

pub const DATA_SUBTYPE_DATA: u8 = 0;
pub const DATA_SUBTYPE_QOS_DATA: u8 = 8;

pub const FC_FLAG_TO_DS: u8 = 0x01;
pub const FC_FLAG_FROM_DS: u8 = 0x02;
pub const FC_FLAG_PROTECTED: u8 = 0x40;

pub const IE_SSID: u8 = 0;
pub const IE_SUPPORTED_RATES: u8 = 1;
pub const IE_DS_PARAM_SET: u8 = 3;
pub const IE_RSN: u8 = 48;
pub const IE_EXT_SUPPORTED_RATES: u8 = 50;
pub const IE_HT_OPERATION: u8 = 61;

pub const CIPHER_SUITE_TKIP: [u8; 4] = [0x00, 0x0F, 0xAC, 0x02];
pub const CIPHER_SUITE_CCMP: [u8; 4] = [0x00, 0x0F, 0xAC, 0x04];

/// Canonical WPA2-PSK (AES-CCMP group + pairwise, PSK AKM `00-0F-AC:02`) RSN IE
/// including element ID `48` (`0x30`) and length `20` (`0x14`).
pub const RSN_IE_WPA2_CCMP: [u8; 22] = [
    0x30, 0x14, // Element ID 48 (RSN), Length 20
    0x01, 0x00, // Version 1
    0x00, 0x0F, 0xAC, 0x04, // Group Cipher: CCMP-128
    0x01, 0x00, // Pairwise Cipher Count: 1
    0x00, 0x0F, 0xAC, 0x04, // Pairwise Cipher: CCMP-128
    0x01, 0x00, // AKM Suite Count: 1
    0x00, 0x0F, 0xAC, 0x02, // AKM: PSK
    0x00, 0x00, // RSN Capabilities
];

/// Build a 22-byte WPA2-PSK RSN IE matching the AP's advertised Group Cipher
/// (`CCMP-128` or `TKIP` on mixed-mode WPA/WPA2 routers) while selecting
/// `CCMP-128` pairwise cipher and `PSK` AKM (`00:0F:AC:02`).
pub const fn build_rsn_ie_with_group(group_cipher: [u8; 4]) -> [u8; 22] {
    let mut ie = RSN_IE_WPA2_CCMP;
    ie[4] = group_cipher[0];
    ie[5] = group_cipher[1];
    ie[6] = group_cipher[2];
    ie[7] = group_cipher[3];
    ie
}

const DEFAULT_RATES: [u8; 8] = [0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24];
const EXT_RATES_2G: [u8; 4] = [0x30, 0x48, 0x60, 0x6C];
const DEFAULT_RATES_5G: [u8; 8] = [0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C];

/// Security suite advertised by a BSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityMode {
    Open,
    Wpa2PskCcmp,
}

/// Errors returned by 802.11 frame parsing/building.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dot11Error {
    Truncated,
    Malformed,
    BufferTooSmall,
    Unsupported,
}

/// Discovered Access Point (BSS) record from Beacon or Probe Response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BssRecord {
    pub bssid: [u8; 6],
    pub ssid: [u8; 32],
    pub ssid_len: usize,
    pub channel: u8,
    pub rssi_dbm: i8,
    pub security: SecurityMode,
    pub capab_info: u16,
    pub group_cipher: [u8; 4],
}

impl BssRecord {
    pub fn ssid_str(&self) -> &str {
        core::str::from_utf8(&self.ssid[..self.ssid_len.min(32)]).unwrap_or("")
    }

    pub fn freq_mhz(&self) -> u16 {
        channel_to_freq_mhz(self.channel)
    }
}

/// Convert an 802.11 2.4 GHz / 5 GHz channel number to center frequency in MHz.
pub const fn channel_to_freq_mhz(ch: u8) -> u16 {
    if ch == 14 {
        2484
    } else if ch >= 1 && ch <= 13 {
        2407 + (ch as u16) * 5
    } else if ch >= 36 {
        5000 + (ch as u16) * 5
    } else {
        2412
    }
}

/// Parsed 24/26-byte 802.11 MAC header view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dot11Header<'a> {
    pub frame_type: u8,
    pub subtype: u8,
    pub flags: u8,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_ctrl: u16,
    pub qos_tid: Option<u8>,
    pub hdr_len: usize,
    pub body: &'a [u8],
}

impl<'a> Dot11Header<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Dot11Error> {
        if raw.len() < IEEE80211_HDR_LEN {
            return Err(Dot11Error::Truncated);
        }
        let fc0 = raw[0];
        let fc1 = raw[1];
        if (fc0 & 0x03) != 0 {
            return Err(Dot11Error::Malformed);
        }
        let frame_type = (fc0 >> 2) & 0x03;
        let subtype = (fc0 >> 4) & 0x0F;
        let is_qos = frame_type == FC_TYPE_DATA && (subtype & 0x08) != 0;
        let hdr_len = if is_qos { 26 } else { 24 };
        if raw.len() < hdr_len {
            return Err(Dot11Error::Truncated);
        }
        let mut addr1 = [0u8; 6];
        let mut addr2 = [0u8; 6];
        let mut addr3 = [0u8; 6];
        addr1.copy_from_slice(&raw[4..10]);
        addr2.copy_from_slice(&raw[10..16]);
        addr3.copy_from_slice(&raw[16..22]);
        let seq_ctrl = u16::from_le_bytes([raw[22], raw[23]]);
        let qos_tid = if is_qos { Some(raw[24] & 0x0F) } else { None };
        Ok(Self {
            frame_type,
            subtype,
            flags: fc1,
            addr1,
            addr2,
            addr3,
            seq_ctrl,
            qos_tid,
            hdr_len,
            body: &raw[hdr_len..],
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn write_mac_hdr(
    frame_type: u8,
    subtype: u8,
    flags: u8,
    addr1: [u8; 6],
    addr2: [u8; 6],
    addr3: [u8; 6],
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    if out.len() < IEEE80211_HDR_LEN {
        return Err(Dot11Error::BufferTooSmall);
    }
    out[0] = ((subtype & 0x0F) << 4) | ((frame_type & 0x03) << 2);
    out[1] = flags;
    out[2..4].copy_from_slice(&0x013Au16.to_le_bytes()); // Duration
    out[4..10].copy_from_slice(&addr1);
    out[10..16].copy_from_slice(&addr2);
    out[16..22].copy_from_slice(&addr3);
    out[22..24].copy_from_slice(&((seq_num & 0x0FFF) << 4).to_le_bytes());
    Ok(IEEE80211_HDR_LEN)
}

/// Build an active scan Probe Request frame (`DA = FF:FF:FF:FF:FF:FF`).
pub fn build_probe_request(
    sta_mac: [u8; 6],
    ssid: &[u8],
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    build_probe_request_band(sta_mac, ssid, false, seq_num, out)
}

/// Build an active scan Probe Request frame with band-appropriate supported rates
/// (CCK+OFDM `1..54 Mbps` on 2.4 GHz, pure OFDM `6..54 Mbps` on 5 GHz).
pub fn build_probe_request_band(
    sta_mac: [u8; 6],
    ssid: &[u8],
    is_5g: bool,
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    let ssid_len = ssid.len().min(32);
    let ext_len = if is_5g { 0 } else { 2 + EXT_RATES_2G.len() };
    let need = IEEE80211_HDR_LEN + 2 + ssid_len + 2 + DEFAULT_RATES.len() + ext_len;
    if out.len() < need {
        return Err(Dot11Error::BufferTooSmall);
    }
    let mut pos = write_mac_hdr(
        FC_TYPE_MGMT,
        MGMT_SUBTYPE_PROBE_REQ,
        0,
        [0xFF; 6],
        sta_mac,
        [0xFF; 6],
        seq_num,
        out,
    )?;
    out[pos] = IE_SSID;
    out[pos + 1] = ssid_len as u8;
    out[pos + 2..pos + 2 + ssid_len].copy_from_slice(&ssid[..ssid_len]);
    pos += 2 + ssid_len;
    let rates = if is_5g {
        &DEFAULT_RATES_5G
    } else {
        &DEFAULT_RATES
    };
    out[pos] = IE_SUPPORTED_RATES;
    out[pos + 1] = rates.len() as u8;
    out[pos + 2..pos + 2 + rates.len()].copy_from_slice(rates);
    pos += 2 + rates.len();
    if !is_5g {
        out[pos] = IE_EXT_SUPPORTED_RATES;
        out[pos + 1] = EXT_RATES_2G.len() as u8;
        out[pos + 2..pos + 2 + EXT_RATES_2G.len()].copy_from_slice(&EXT_RATES_2G);
        pos += 2 + EXT_RATES_2G.len();
    }
    Ok(pos)
}

/// Build a Beacon or Probe Response frame (for AP / virtual-radio testing).
#[allow(clippy::too_many_arguments)]
pub fn build_beacon_or_probe_resp(
    is_probe_resp: bool,
    dst_mac: [u8; 6],
    bssid: [u8; 6],
    ssid: &[u8],
    channel: u8,
    security: SecurityMode,
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    let ssid_len = ssid.len().min(32);
    let rsn_len = if security == SecurityMode::Wpa2PskCcmp {
        RSN_IE_WPA2_CCMP.len()
    } else {
        0
    };
    let need = IEEE80211_HDR_LEN + 12 + 2 + ssid_len + 2 + DEFAULT_RATES.len() + 3 + rsn_len;
    if out.len() < need {
        return Err(Dot11Error::BufferTooSmall);
    }
    let subtype = if is_probe_resp {
        MGMT_SUBTYPE_PROBE_RESP
    } else {
        MGMT_SUBTYPE_BEACON
    };
    let mut pos = write_mac_hdr(
        FC_TYPE_MGMT,
        subtype,
        0,
        dst_mac,
        bssid,
        bssid,
        seq_num,
        out,
    )?;
    // 8-byte TSF + 2-byte beacon interval (100 TU) + 2-byte capability info
    out[pos..pos + 8].fill(0);
    out[pos + 8..pos + 10].copy_from_slice(&100u16.to_le_bytes());
    let cap: u16 = if security == SecurityMode::Wpa2PskCcmp {
        0x0411 // ESS | Privacy | ShortSlotTime
    } else {
        0x0401 // ESS | ShortSlotTime
    };
    out[pos + 10..pos + 12].copy_from_slice(&cap.to_le_bytes());
    pos += 12;

    out[pos] = IE_SSID;
    out[pos + 1] = ssid_len as u8;
    out[pos + 2..pos + 2 + ssid_len].copy_from_slice(&ssid[..ssid_len]);
    pos += 2 + ssid_len;

    out[pos] = IE_SUPPORTED_RATES;
    out[pos + 1] = DEFAULT_RATES.len() as u8;
    out[pos + 2..pos + 2 + DEFAULT_RATES.len()].copy_from_slice(&DEFAULT_RATES);
    pos += 2 + DEFAULT_RATES.len();

    out[pos] = IE_DS_PARAM_SET;
    out[pos + 1] = 1;
    out[pos + 2] = channel;
    pos += 3;

    if security == SecurityMode::Wpa2PskCcmp {
        out[pos..pos + RSN_IE_WPA2_CCMP.len()].copy_from_slice(&RSN_IE_WPA2_CCMP);
        pos += RSN_IE_WPA2_CCMP.len();
    }
    Ok(pos)
}

/// Parse a Beacon or Probe Response frame into a `BssRecord`.
pub fn parse_beacon_or_probe_resp(
    raw: &[u8],
    default_channel: u8,
    rssi_dbm: i8,
) -> Result<BssRecord, Dot11Error> {
    let hdr = Dot11Header::parse(raw)?;
    if hdr.frame_type != FC_TYPE_MGMT
        || (hdr.subtype != MGMT_SUBTYPE_BEACON && hdr.subtype != MGMT_SUBTYPE_PROBE_RESP)
    {
        return Err(Dot11Error::Malformed);
    }
    if hdr.body.len() < 12 {
        return Err(Dot11Error::Truncated);
    }
    let cap = u16::from_le_bytes([hdr.body[10], hdr.body[11]]);
    let mut ssid = [0u8; 32];
    let mut ssid_len = 0usize;
    let mut channel = default_channel;
    let mut has_ds_param = false;
    let mut has_wpa2_ccmp = false;
    let mut group_cipher = CIPHER_SUITE_CCMP;

    let ies = &hdr.body[12..];
    let mut idx = 0usize;
    while idx + 2 <= ies.len() {
        let id = ies[idx];
        let len = usize::from(ies[idx + 1]);
        if idx + 2 + len > ies.len() {
            break;
        }
        let val = &ies[idx + 2..idx + 2 + len];
        match id {
            IE_SSID => {
                ssid_len = len.min(32);
                ssid[..ssid_len].copy_from_slice(&val[..ssid_len]);
            }
            IE_DS_PARAM_SET if len == 1 && val[0] != 0 => {
                channel = val[0];
                has_ds_param = true;
            }
            IE_HT_OPERATION if !has_ds_param && !val.is_empty() && val[0] != 0 => {
                channel = val[0];
            }
            IE_RSN if len >= 8 => {
                let ver = u16::from_le_bytes([val[0], val[1]]);
                if ver == 1 {
                    group_cipher.copy_from_slice(&val[2..6]);
                    let pw_cnt = usize::from(u16::from_le_bytes([val[6], val[7]]));
                    let pw_end = 8usize.saturating_add(pw_cnt.saturating_mul(4));
                    if pw_end + 2 <= val.len() {
                        let akm_cnt =
                            usize::from(u16::from_le_bytes([val[pw_end], val[pw_end + 1]]));
                        let akm_start = pw_end + 2;
                        let akm_end = akm_start
                            .saturating_add(akm_cnt.saturating_mul(4))
                            .min(val.len());
                        let pw_has_ccmp = val[8..pw_end]
                            .chunks_exact(4)
                            .any(|c| c == CIPHER_SUITE_CCMP);
                        let akm_has_psk = val[akm_start..akm_end].chunks_exact(4).any(|a| {
                            a == [0x00, 0x0F, 0xAC, 0x02] || a == [0x00, 0x0F, 0xAC, 0x06]
                        });
                        if pw_has_ccmp && akm_has_psk {
                            has_wpa2_ccmp = true;
                        }
                    } else {
                        has_wpa2_ccmp = true;
                    }
                }
            }
            _ => {}
        }
        idx += 2 + len;
    }

    let security = if has_wpa2_ccmp || (cap & 0x0010) != 0 {
        SecurityMode::Wpa2PskCcmp
    } else {
        SecurityMode::Open
    };
    Ok(BssRecord {
        bssid: hdr.addr3,
        ssid,
        ssid_len,
        channel,
        rssi_dbm,
        security,
        capab_info: cap,
        group_cipher,
    })
}

/// Build an Open System Authentication frame (`auth_alg = 0`, `auth_seq = 1` or `2`).
pub fn build_auth_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    bssid: [u8; 6],
    auth_seq: u16,
    status_code: u16,
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    if out.len() < IEEE80211_HDR_LEN + 6 {
        return Err(Dot11Error::BufferTooSmall);
    }
    let pos = write_mac_hdr(
        FC_TYPE_MGMT,
        MGMT_SUBTYPE_AUTH,
        0,
        dst_mac,
        src_mac,
        bssid,
        seq_num,
        out,
    )?;
    out[pos..pos + 2].copy_from_slice(&0u16.to_le_bytes()); // Open System
    out[pos + 2..pos + 4].copy_from_slice(&auth_seq.to_le_bytes());
    out[pos + 4..pos + 6].copy_from_slice(&status_code.to_le_bytes());
    Ok(pos + 6)
}

/// Parse an Authentication frame, returning `(bssid, auth_alg, auth_seq, status_code)`.
pub fn parse_auth_frame(raw: &[u8]) -> Result<([u8; 6], u16, u16, u16), Dot11Error> {
    let hdr = Dot11Header::parse(raw)?;
    if hdr.frame_type != FC_TYPE_MGMT || hdr.subtype != MGMT_SUBTYPE_AUTH || hdr.body.len() < 6 {
        return Err(Dot11Error::Malformed);
    }
    let alg = u16::from_le_bytes([hdr.body[0], hdr.body[1]]);
    let seq = u16::from_le_bytes([hdr.body[2], hdr.body[3]]);
    let status = u16::from_le_bytes([hdr.body[4], hdr.body[5]]);
    Ok((hdr.addr3, alg, seq, status))
}

/// Build an Association Request frame (`ESS`, optional WPA2-PSK CCMP RSN IE).
pub fn build_assoc_request(
    bssid: [u8; 6],
    sta_mac: [u8; 6],
    ssid: &[u8],
    security: SecurityMode,
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    build_assoc_request_for_bss(
        bssid,
        sta_mac,
        ssid,
        1,
        0x0400,
        security,
        CIPHER_SUITE_CCMP,
        seq_num,
        out,
    )
}

/// Build an IEEE 802.11 Association Request tailored to the target AP's band,
/// capability bits (`ShortPreamble`, `SpectrumMgmt`, `ShortSlotTime`),
/// full 2.4 GHz (`1..54 Mbps` + IE 50) or 5 GHz (`6..54 Mbps`, zero CCK) rates,
/// and exact RSN Group Cipher (`CCMP-128` or mixed-mode `TKIP`).
#[allow(clippy::too_many_arguments)]
pub fn build_assoc_request_for_bss(
    bssid: [u8; 6],
    sta_mac: [u8; 6],
    ssid: &[u8],
    channel: u8,
    ap_capab_info: u16,
    security: SecurityMode,
    group_cipher: [u8; 4],
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    let ssid_len = ssid.len().min(32);
    let is_5g = channel > 14;
    let ext_len = if is_5g { 0 } else { 2 + EXT_RATES_2G.len() };
    let rsn_len = if security == SecurityMode::Wpa2PskCcmp {
        RSN_IE_WPA2_CCMP.len()
    } else {
        0
    };
    let need = IEEE80211_HDR_LEN + 4 + 2 + ssid_len + 2 + DEFAULT_RATES.len() + ext_len + rsn_len;
    if out.len() < need {
        return Err(Dot11Error::BufferTooSmall);
    }
    let mut pos = write_mac_hdr(
        FC_TYPE_MGMT,
        MGMT_SUBTYPE_ASSOC_REQ,
        0,
        bssid,
        sta_mac,
        bssid,
        seq_num,
        out,
    )?;
    // ESS (0x0001) + Privacy (0x0010) + echo AP ShortPreamble (0x0020),
    // SpectrumMgmt (0x0100 on 5 GHz), and ShortSlotTime (0x0400 on 2.4 GHz).
    let mut cap: u16 = 0x0001 | (ap_capab_info & (0x0020 | 0x0100 | 0x0400));
    if !is_5g && ap_capab_info == 0 {
        cap |= 0x0400;
    }
    if security == SecurityMode::Wpa2PskCcmp {
        cap |= 0x0010;
    }
    out[pos..pos + 2].copy_from_slice(&cap.to_le_bytes());
    out[pos + 2..pos + 4].copy_from_slice(&10u16.to_le_bytes()); // Listen interval
    pos += 4;

    out[pos] = IE_SSID;
    out[pos + 1] = ssid_len as u8;
    out[pos + 2..pos + 2 + ssid_len].copy_from_slice(&ssid[..ssid_len]);
    pos += 2 + ssid_len;

    let rates = if is_5g {
        &DEFAULT_RATES_5G
    } else {
        &DEFAULT_RATES
    };
    out[pos] = IE_SUPPORTED_RATES;
    out[pos + 1] = rates.len() as u8;
    out[pos + 2..pos + 2 + rates.len()].copy_from_slice(rates);
    pos += 2 + rates.len();

    if !is_5g {
        out[pos] = IE_EXT_SUPPORTED_RATES;
        out[pos + 1] = EXT_RATES_2G.len() as u8;
        out[pos + 2..pos + 2 + EXT_RATES_2G.len()].copy_from_slice(&EXT_RATES_2G);
        pos += 2 + EXT_RATES_2G.len();
    }

    if security == SecurityMode::Wpa2PskCcmp {
        let rsn_ie = build_rsn_ie_with_group(group_cipher);
        out[pos..pos + rsn_ie.len()].copy_from_slice(&rsn_ie);
        pos += rsn_ie.len();
    }
    Ok(pos)
}

/// Build an Association Response frame (`status_code`, `aid`).
pub fn build_assoc_response(
    sta_mac: [u8; 6],
    bssid: [u8; 6],
    status_code: u16,
    aid: u16,
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    let need = IEEE80211_HDR_LEN + 6 + 2 + DEFAULT_RATES.len();
    if out.len() < need {
        return Err(Dot11Error::BufferTooSmall);
    }
    let mut pos = write_mac_hdr(
        FC_TYPE_MGMT,
        MGMT_SUBTYPE_ASSOC_RESP,
        0,
        sta_mac,
        bssid,
        bssid,
        seq_num,
        out,
    )?;
    out[pos..pos + 2].copy_from_slice(&0x0411u16.to_le_bytes());
    out[pos + 2..pos + 4].copy_from_slice(&status_code.to_le_bytes());
    out[pos + 4..pos + 6].copy_from_slice(&(0xC000 | (aid & 0x3FFF)).to_le_bytes());
    pos += 6;
    out[pos] = IE_SUPPORTED_RATES;
    out[pos + 1] = DEFAULT_RATES.len() as u8;
    out[pos + 2..pos + 2 + DEFAULT_RATES.len()].copy_from_slice(&DEFAULT_RATES);
    Ok(pos + 2 + DEFAULT_RATES.len())
}

/// Parse an Association Response frame, returning `(bssid, status_code, aid)`.
pub fn parse_assoc_response(raw: &[u8]) -> Result<([u8; 6], u16, u16), Dot11Error> {
    let hdr = Dot11Header::parse(raw)?;
    if hdr.frame_type != FC_TYPE_MGMT
        || hdr.subtype != MGMT_SUBTYPE_ASSOC_RESP
        || hdr.body.len() < 6
    {
        return Err(Dot11Error::Malformed);
    }
    let status = u16::from_le_bytes([hdr.body[2], hdr.body[3]]);
    let aid = u16::from_le_bytes([hdr.body[4], hdr.body[5]]) & 0x3FFF;
    Ok((hdr.addr3, status, aid))
}

/// Build a Deauthentication frame (`reason_code`, e.g. `3 = DEAUTH_LEAVING`).
pub fn build_deauth(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    bssid: [u8; 6],
    reason_code: u16,
    seq_num: u16,
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    if out.len() < IEEE80211_HDR_LEN + 2 {
        return Err(Dot11Error::BufferTooSmall);
    }
    let pos = write_mac_hdr(
        FC_TYPE_MGMT,
        MGMT_SUBTYPE_DEAUTH,
        0,
        dst_mac,
        src_mac,
        bssid,
        seq_num,
        out,
    )?;
    out[pos..pos + 2].copy_from_slice(&reason_code.to_le_bytes());
    Ok(pos + 2)
}

/// Wrap an Ethernet payload (`ethertype` + L3 payload) in an 802.11 LLC/SNAP body.
pub fn build_llc_snap_payload(
    ethertype: u16,
    l3_payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    let total = LLC_SNAP_TOTAL_LEN
        .checked_add(l3_payload.len())
        .ok_or(Dot11Error::BufferTooSmall)?;
    if out.len() < total {
        return Err(Dot11Error::BufferTooSmall);
    }
    out[0..6].copy_from_slice(&LLC_SNAP_HDR);
    out[6..8].copy_from_slice(&ethertype.to_be_bytes());
    out[8..total].copy_from_slice(l3_payload);
    Ok(total)
}

/// Parse an 802.11 LLC/SNAP body into `(ethertype, l3_payload)`.
pub fn parse_llc_snap_payload(body: &[u8]) -> Result<(u16, &[u8]), Dot11Error> {
    if body.len() < LLC_SNAP_TOTAL_LEN {
        return Err(Dot11Error::Truncated);
    }
    if body[0..6] != LLC_SNAP_HDR {
        return Err(Dot11Error::Malformed);
    }
    let ethertype = u16::from_be_bytes([body[6], body[7]]);
    Ok((ethertype, &body[8..]))
}

/// Build an 802.11 Data header (`ToDS = 1` for STA->AP or `FromDS = 1` for AP->STA)
/// followed by `body` (either plaintext LLC/SNAP or CCMP header + ciphertext + MIC).
#[allow(clippy::too_many_arguments)]
pub fn build_data_frame(
    to_ap: bool,
    protected: bool,
    bssid: [u8; 6],
    sta_mac: [u8; 6],
    peer_eth_mac: [u8; 6],
    seq_num: u16,
    body: &[u8],
    out: &mut [u8],
) -> Result<usize, Dot11Error> {
    let total = IEEE80211_HDR_LEN
        .checked_add(body.len())
        .ok_or(Dot11Error::BufferTooSmall)?;
    if out.len() < total {
        return Err(Dot11Error::BufferTooSmall);
    }
    let mut flags = if to_ap {
        FC_FLAG_TO_DS
    } else {
        FC_FLAG_FROM_DS
    };
    if protected {
        flags |= FC_FLAG_PROTECTED;
    }
    let (addr1, addr2, addr3) = if to_ap {
        // ToDS=1: Addr1=RA(BSSID), Addr2=TA(STA), Addr3=DA(peer)
        (bssid, sta_mac, peer_eth_mac)
    } else {
        // FromDS=1: Addr1=RA(STA), Addr2=TA(BSSID), Addr3=SA(peer)
        (sta_mac, bssid, peer_eth_mac)
    };
    let pos = write_mac_hdr(
        FC_TYPE_DATA,
        DATA_SUBTYPE_DATA,
        flags,
        addr1,
        addr2,
        addr3,
        seq_num,
        out,
    )?;
    out[pos..total].copy_from_slice(body);
    Ok(total)
}

/// Bounded scan table storing up to 24 distinct APs sorted by RSSI.
pub struct ScanTable {
    entries: Vec<BssRecord>,
}

impl Default for ScanTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(24),
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn upsert(&mut self, bss: BssRecord) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.bssid == bss.bssid) {
            // Preserve non-empty SSID if a hidden-SSID beacon arrives after a ProbeResp
            let keep_ssid = bss.ssid_len == 0 && existing.ssid_len > 0;
            let prev_ssid = existing.ssid;
            let prev_len = existing.ssid_len;
            *existing = bss;
            if keep_ssid {
                existing.ssid = prev_ssid;
                existing.ssid_len = prev_len;
            }
        } else if self.entries.len() < 24 {
            self.entries.push(bss);
        } else if let Some(last) = self.entries.last_mut() {
            if bss.rssi_dbm > last.rssi_dbm {
                *last = bss;
            }
        }
        self.entries.sort_by_key(|a| core::cmp::Reverse(a.rssi_dbm));
    }

    pub fn entries(&self) -> &[BssRecord] {
        &self.entries
    }

    pub fn find_by_ssid(&self, ssid: &[u8]) -> Option<BssRecord> {
        self.entries
            .iter()
            .find(|e| &e.ssid[..e.ssid_len] == ssid)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_auth_assoc_and_llc_snap_round_trip() {
        let bssid = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sta = [0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC];
        let mut buf = [0u8; 256];

        let blen = build_beacon_or_probe_resp(
            false,
            [0xFF; 6],
            bssid,
            b"HuesOS-Lab-5G",
            36,
            SecurityMode::Wpa2PskCcmp,
            7,
            &mut buf,
        )
        .unwrap_or(0);
        let bss = parse_beacon_or_probe_resp(&buf[..blen], 1, -48);
        assert!(bss.is_ok());
        if let Ok(rec) = bss {
            assert_eq!(rec.bssid, bssid);
            assert_eq!(rec.ssid_str(), "HuesOS-Lab-5G");
            assert_eq!(rec.channel, 36);
            assert_eq!(rec.freq_mhz(), 5180);
            assert_eq!(rec.security, SecurityMode::Wpa2PskCcmp);
        }

        let alen = build_auth_frame(bssid, sta, bssid, 1, 0, 8, &mut buf).unwrap_or(0);
        assert_eq!(parse_auth_frame(&buf[..alen]), Ok((bssid, 0, 1, 0)));

        let rlen = build_assoc_response(sta, bssid, 0, 1, 9, &mut buf).unwrap_or(0);
        assert_eq!(parse_assoc_response(&buf[..rlen]), Ok((bssid, 0, 1)));

        let mut snap = [0u8; 32];
        let slen = build_llc_snap_payload(0x888E, &[1, 3, 0, 4], &mut snap).unwrap_or(0);
        assert_eq!(
            parse_llc_snap_payload(&snap[..slen]),
            Ok((0x888E, &[1u8, 3, 0, 4][..]))
        );

        let assoc_len = build_assoc_request_for_bss(
            bssid,
            sta,
            b"HuesOS-Lab-5G",
            36,
            0x0111,
            SecurityMode::Wpa2PskCcmp,
            CIPHER_SUITE_TKIP,
            10,
            &mut buf,
        )
        .unwrap_or(0);
        assert!(assoc_len > IEEE80211_HDR_LEN + 26);
        let cap = u16::from_le_bytes([buf[24], buf[25]]);
        assert_eq!(cap & 0x0111, 0x0111);
        assert_eq!(
            &buf[assoc_len - 22..assoc_len - 14],
            &[0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02]
        );
    }
}
