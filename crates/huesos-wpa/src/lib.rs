//! `#![no_std]`, `#![forbid(unsafe_code)]` WPA2-PSK (IEEE 802.11i / RSN)
//! cryptographic engine:
//! - FIPS 180-4 SHA-1, HMAC-SHA1, PBKDF2-HMAC-SHA1 (4096 iterations)
//! - IEEE 802.11i PRF-384 Pairwise Transient Key (`PTK = KCK || KEK || TK`)
//! - RFC 3394 AES-128 Key Wrap / Key Unwrap (GTK KDE transport)
//! - WPA2 EAPOL-Key 4-Way Handshake (Supplicant & Authenticator)
//! - IEEE 802.11 CCMP-128 (`AES-128-CCM`) data-frame encryption, decryption,
//!   MIC verification, and 48-bit PN replay protection.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;

use huesos_ieee80211::{Dot11Header, FC_FLAG_PROTECTED, FC_TYPE_DATA, RSN_IE_WPA2_CCMP};

pub const EAPOL_VERSION_1: u8 = 1;
pub const EAPOL_VERSION_2: u8 = 2;
pub const EAPOL_TYPE_KEY: u8 = 3;
pub const EAPOL_KEY_DESC_RSN: u8 = 2;
pub const EAPOL_KEY_DESC_WPA: u8 = 254;

pub const KEY_INFO_TYPE_MASK: u16 = 0x0007;
pub const KEY_INFO_TYPE_HMAC_SHA1_AES: u16 = 0x0002;
pub const KEY_INFO_TYPE_AES_128_CMAC: u16 = 0x0003;
pub const KEY_INFO_PAIRWISE: u16 = 0x0008;
pub const KEY_INFO_INSTALL: u16 = 0x0040;
pub const KEY_INFO_ACK: u16 = 0x0080;
pub const KEY_INFO_MIC: u16 = 0x0100;
pub const KEY_INFO_SECURE: u16 = 0x0200;
pub const KEY_INFO_ENCRYPTED_DATA: u16 = 0x1000;

pub const CCMP_HDR_LEN: usize = 8;
pub const CCMP_MIC_LEN: usize = 8;

/// WPA2 / CCMP error codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WpaError {
    InvalidPassphrase,
    InvalidSsid,
    Truncated,
    Malformed,
    BadMic,
    ReplayDetected,
    KeyUnwrapFailed,
    BufferTooSmall,
    UnexpectedHandshakeStep,
}

// ============================================================================
// Pure-Rust FIPS 180-4 SHA-1 + HMAC-SHA1 + PBKDF2-HMAC-SHA1(4096)
// ============================================================================

#[derive(Clone)]
struct Sha1 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_bytes: u64,
}

impl Sha1 {
    const fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A82_7999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9_EBA1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32)
            } else {
                (b ^ c ^ d, 0xCA62_C1D6u32)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut blk = [0u8; 64];
            blk.copy_from_slice(&data[..64]);
            Self::compress(&mut self.state, &blk);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            Self::compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress(&mut self.state, &self.buf);

        let mut out = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Compute HMAC-SHA1 over concatenated slices `parts`.
pub fn hmac_sha1_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha1::new();
        h.update(key);
        let digest = h.finalize();
        k_pad[..20].copy_from_slice(&digest);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5Cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_pad[i];
        opad[i] ^= k_pad[i];
    }

    let mut inner = Sha1::new();
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    let inner_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// Derive a 256-bit WPA2 Pairwise Master Key (`PMK`) from an ASCII passphrase
/// (`8..=63` bytes) and `ssid` (`1..=32` bytes) using PBKDF2-HMAC-SHA1 (4096 rounds).
pub fn derive_wpa2_psk(passphrase: &[u8], ssid: &[u8]) -> Result<[u8; 32], WpaError> {
    if passphrase.len() < 8 || passphrase.len() > 63 {
        return Err(WpaError::InvalidPassphrase);
    }
    if ssid.is_empty() || ssid.len() > 32 {
        return Err(WpaError::InvalidSsid);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5Cu8; 64];
    for (i, &b) in passphrase.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner_base = Sha1::new();
    inner_base.update(&ipad);
    let mut outer_base = Sha1::new();
    outer_base.update(&opad);

    let pbkdf2_block = |block_idx: u32| -> [u8; 20] {
        let idx_be = block_idx.to_be_bytes();
        let mut i_hash = inner_base.clone();
        i_hash.update(ssid);
        i_hash.update(&idx_be);
        let d_in = i_hash.finalize();
        let mut o_hash = outer_base.clone();
        o_hash.update(&d_in);
        let mut u = o_hash.finalize();
        let mut t = u;
        for _ in 1..4096 {
            let mut ih = inner_base.clone();
            ih.update(&u);
            let di = ih.finalize();
            let mut oh = outer_base.clone();
            oh.update(&di);
            u = oh.finalize();
            for j in 0..20 {
                t[j] ^= u[j];
            }
        }
        t
    };

    let b1 = pbkdf2_block(1);
    let b2 = pbkdf2_block(2);
    let mut pmk = [0u8; 32];
    pmk[0..20].copy_from_slice(&b1);
    pmk[20..32].copy_from_slice(&b2[..12]);
    Ok(pmk)
}

/// Derived 384-bit Pairwise Transient Key (`PTK`) for WPA2-CCMP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ptk {
    /// 128-bit EAPOL-Key Confirmation Key (MIC calculation).
    pub kck: [u8; 16],
    /// 128-bit EAPOL-Key Encryption Key (RFC 3394 GTK wrap/unwrap).
    pub kek: [u8; 16],
    /// 128-bit Temporal Key (AES-128-CCMP data encryption).
    pub tk: [u8; 16],
}

/// IEEE 802.11i PRF-384 (`"Pairwise key expansion"`) producing `PTK`.
pub fn derive_ptk(
    pmk: &[u8; 32],
    aa: &[u8; 6],
    spa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> Ptk {
    let mut data = [0u8; 76];
    if aa <= spa {
        data[0..6].copy_from_slice(aa);
        data[6..12].copy_from_slice(spa);
    } else {
        data[0..6].copy_from_slice(spa);
        data[6..12].copy_from_slice(aa);
    }
    if anonce <= snonce {
        data[12..44].copy_from_slice(anonce);
        data[44..76].copy_from_slice(snonce);
    } else {
        data[12..44].copy_from_slice(snonce);
        data[44..76].copy_from_slice(anonce);
    }

    let label = b"Pairwise key expansion\0";
    let mut raw_ptk = [0u8; 60];
    for counter in 0u8..3u8 {
        let ctr = [counter];
        let digest = hmac_sha1_parts(pmk, &[label, &data, &ctr]);
        let start = usize::from(counter) * 20;
        raw_ptk[start..start + 20].copy_from_slice(&digest);
    }
    let mut kck = [0u8; 16];
    let mut kek = [0u8; 16];
    let mut tk = [0u8; 16];
    kck.copy_from_slice(&raw_ptk[0..16]);
    kek.copy_from_slice(&raw_ptk[16..32]);
    tk.copy_from_slice(&raw_ptk[32..48]);
    Ptk { kck, kek, tk }
}

// ============================================================================
// RFC 3394 AES-128 Key Wrap / Key Unwrap
// ============================================================================

/// RFC 3394 AES-128 Key Wrap (`plaintext` must be a multiple of 8 bytes, `>= 16`).
pub fn aes_key_wrap(kek: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, WpaError> {
    if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
        return Err(WpaError::Malformed);
    }
    let n = plaintext.len() / 8;
    let cipher = Aes128::new(kek.into());
    let mut a = [0xA6u8; 8];
    let mut r = plaintext.to_vec();

    for j in 0..=5u64 {
        for i in 1..=n {
            let mut block = [0u8; 16];
            block[0..8].copy_from_slice(&a);
            block[8..16].copy_from_slice(&r[(i - 1) * 8..i * 8]);
            cipher.encrypt_block((&mut block).into());
            let t = ((n as u64) * j + (i as u64)).to_be_bytes();
            for k in 0..8 {
                a[k] = block[k] ^ t[k];
            }
            r[(i - 1) * 8..i * 8].copy_from_slice(&block[8..16]);
        }
    }
    let mut out = Vec::with_capacity(8 + r.len());
    out.extend_from_slice(&a);
    out.extend_from_slice(&r);
    Ok(out)
}

/// RFC 3394 AES-128 Key Unwrap (`wrapped` must be `(n + 1) * 8` bytes, `n >= 2`).
pub fn aes_key_unwrap(kek: &[u8; 16], wrapped: &[u8]) -> Result<Vec<u8>, WpaError> {
    use aes::cipher::BlockDecrypt;
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(WpaError::KeyUnwrapFailed);
    }
    let n = (wrapped.len() / 8) - 1;
    let cipher = Aes128::new(kek.into());
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[0..8]);
    let mut r = wrapped[8..].to_vec();

    for j in (0..=5u64).rev() {
        for i in (1..=n).rev() {
            let t = ((n as u64) * j + (i as u64)).to_be_bytes();
            let mut block = [0u8; 16];
            for k in 0..8 {
                block[k] = a[k] ^ t[k];
            }
            block[8..16].copy_from_slice(&r[(i - 1) * 8..i * 8]);
            cipher.decrypt_block((&mut block).into());
            a.copy_from_slice(&block[0..8]);
            r[(i - 1) * 8..i * 8].copy_from_slice(&block[8..16]);
        }
    }
    if a.ct_eq(&[0xA6u8; 8]).unwrap_u8() != 1 {
        return Err(WpaError::KeyUnwrapFailed);
    }
    Ok(r)
}

// ============================================================================
// WPA2 EAPOL-Key 4-Way Handshake
// ============================================================================

const EAPOL_KEY_FIXED_LEN: usize = 4 + 95; // 4-byte EAPOL hdr + 95-byte Key body

fn dbl_gf128(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        let next = block[i] >> 7;
        out[i] = (block[i] << 1) | carry;
        carry = next;
    }
    if (block[0] & 0x80) != 0 {
        out[15] ^= 0x87;
    }
    out
}

/// RFC 4493 AES-128-CMAC (used when an 802.11w/802.11r AP selects EAPOL-Key descriptor version 3).
fn aes128_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut l = [0u8; 16];
    cipher.encrypt_block((&mut l).into());
    let k1 = dbl_gf128(&l);
    let k2 = dbl_gf128(&k1);

    let n = msg.len().div_ceil(16).max(1);
    let complete = !msg.is_empty() && msg.len().is_multiple_of(16);

    let mut x = [0u8; 16];
    for blk_idx in 0..(n - 1) {
        let off = blk_idx * 16;
        for (xb, &mb) in x.iter_mut().zip(&msg[off..off + 16]) {
            *xb ^= mb;
        }
        cipher.encrypt_block((&mut x).into());
    }

    let mut m_last = [0u8; 16];
    let last_off = (n - 1) * 16;
    let rem = msg.len().saturating_sub(last_off);
    m_last[..rem].copy_from_slice(&msg[last_off..]);
    if complete {
        for (mb, &kb) in m_last.iter_mut().zip(&k1) {
            *mb ^= kb;
        }
    } else {
        m_last[rem] = 0x80;
        for (mb, &kb) in m_last.iter_mut().zip(&k2) {
            *mb ^= kb;
        }
    }
    for (xb, &mb) in x.iter_mut().zip(&m_last) {
        *xb ^= mb;
    }
    cipher.encrypt_block((&mut x).into());
    x
}

fn compute_eapol_mic(kck: &[u8; 16], desc_ver: u16, frame_with_zeroed_mic: &[u8]) -> [u8; 16] {
    if desc_ver == KEY_INFO_TYPE_AES_128_CMAC {
        return aes128_cmac(kck, frame_with_zeroed_mic);
    }
    let full = hmac_sha1_parts(kck, &[frame_with_zeroed_mic]);
    let mut mic = [0u8; 16];
    mic.copy_from_slice(&full[..16]);
    mic
}

fn verify_eapol_mic(kck: &[u8; 16], raw: &[u8]) -> Result<(), WpaError> {
    if raw.len() < EAPOL_KEY_FIXED_LEN {
        return Err(WpaError::Truncated);
    }
    let desc_ver = u16::from_be_bytes([raw[5], raw[6]]) & KEY_INFO_TYPE_MASK;
    let mut copy = raw.to_vec();
    let mut expected = [0u8; 16];
    expected.copy_from_slice(&raw[81..97]);
    copy[81..97].fill(0);
    let calc = compute_eapol_mic(kck, desc_ver, &copy);
    if calc.ct_eq(&expected).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(WpaError::BadMic)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_eapol_key_frame(
    eapol_version: u8,
    key_info: u16,
    key_len: u16,
    replay_counter: u64,
    nonce: &[u8; 32],
    key_data: &[u8],
    kck_for_mic: Option<&[u8; 16]>,
) -> Vec<u8> {
    let body_len = 95 + key_data.len();
    let total_len = 4 + body_len;
    let mut out = alloc::vec![0u8; total_len];
    out[0] = eapol_version;
    out[1] = EAPOL_TYPE_KEY;
    out[2..4].copy_from_slice(&(body_len as u16).to_be_bytes());
    out[4] = EAPOL_KEY_DESC_RSN;
    out[5..7].copy_from_slice(&key_info.to_be_bytes());
    out[7..9].copy_from_slice(&key_len.to_be_bytes());
    out[9..17].copy_from_slice(&replay_counter.to_be_bytes());
    out[17..49].copy_from_slice(nonce);
    // Key IV [49..65], Key RSC [65..73], Reserved [73..81], MIC [81..97] = 0
    out[97..99].copy_from_slice(&(key_data.len() as u16).to_be_bytes());
    out[99..total_len].copy_from_slice(key_data);

    if let Some(kck) = kck_for_mic {
        let mic = compute_eapol_mic(kck, key_info & KEY_INFO_TYPE_MASK, &out);
        out[81..97].copy_from_slice(&mic);
    }
    out
}

/// Completed key material produced once the 4-way handshake finishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledWpa2Keys {
    pub ptk: Ptk,
    pub gtk: [u8; 16],
    pub gtk_idx: u8,
}

/// WPA2-PSK Supplicant (STA) 4-way handshake state machine.
pub struct Supplicant4Way {
    pmk: [u8; 32],
    bssid: [u8; 6],
    sta_mac: [u8; 6],
    snonce: [u8; 32],
    rsn_ie: [u8; 22],
    anonce: [u8; 32],
    last_replay: Option<u64>,
    ptk: Option<Ptk>,
    installed: Option<InstalledWpa2Keys>,
}

impl Supplicant4Way {
    pub fn new(pmk: [u8; 32], bssid: [u8; 6], sta_mac: [u8; 6], snonce: [u8; 32]) -> Self {
        Self::new_with_rsn_ie(pmk, bssid, sta_mac, snonce, RSN_IE_WPA2_CCMP)
    }

    pub fn new_with_rsn_ie(
        pmk: [u8; 32],
        bssid: [u8; 6],
        sta_mac: [u8; 6],
        snonce: [u8; 32],
        rsn_ie: [u8; 22],
    ) -> Self {
        Self {
            pmk,
            bssid,
            sta_mac,
            snonce,
            rsn_ie,
            anonce: [0u8; 32],
            last_replay: None,
            ptk: None,
            installed: None,
        }
    }

    pub fn installed_keys(&self) -> Option<&InstalledWpa2Keys> {
        self.installed.as_ref()
    }

    /// Process an inbound EAPOL-Key frame (Msg 1/4 or Msg 3/4) from the AP and
    /// return the outbound reply EAPOL-Key frame (Msg 2/4 or Msg 4/4).
    pub fn on_eapol_frame(&mut self, raw: &[u8]) -> Result<Vec<u8>, WpaError> {
        if raw.len() < EAPOL_KEY_FIXED_LEN {
            return Err(WpaError::Truncated);
        }
        if raw[1] != EAPOL_TYPE_KEY
            || (raw[4] != EAPOL_KEY_DESC_RSN && raw[4] != EAPOL_KEY_DESC_WPA)
        {
            return Err(WpaError::Malformed);
        }
        let body_len = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
        if body_len < 95 || 4 + body_len > raw.len() {
            return Err(WpaError::Truncated);
        }
        let frame = &raw[..4 + body_len];
        let key_info = u16::from_be_bytes([frame[5], frame[6]]);
        let desc_ver = {
            let v = key_info & KEY_INFO_TYPE_MASK;
            if v == KEY_INFO_TYPE_AES_128_CMAC {
                KEY_INFO_TYPE_AES_128_CMAC
            } else {
                KEY_INFO_TYPE_HMAC_SHA1_AES
            }
        };
        let replay = u64::from_be_bytes([
            frame[9], frame[10], frame[11], frame[12], frame[13], frame[14], frame[15], frame[16],
        ]);
        if let Some(prev) = self.last_replay {
            if replay <= prev {
                return Err(WpaError::ReplayDetected);
            }
        }
        let key_data_len = usize::from(u16::from_be_bytes([frame[97], frame[98]]));
        if 99 + key_data_len > frame.len() {
            return Err(WpaError::Truncated);
        }
        let key_data = &frame[99..99 + key_data_len];

        let has_ack = (key_info & KEY_INFO_ACK) != 0;
        let has_mic = (key_info & KEY_INFO_MIC) != 0;
        let is_pairwise = (key_info & KEY_INFO_PAIRWISE) != 0;
        if !has_ack || !is_pairwise {
            return Err(WpaError::UnexpectedHandshakeStep);
        }

        if !has_mic {
            // Message 1/4: extract ANonce, derive PTK, return signed Message 2/4.
            // Per IEEE 802.11-2020 Table 12-9 (and wpa_supplicant), Key Length in M2/M4 is 0.
            self.anonce.copy_from_slice(&frame[17..49]);
            let ptk = derive_ptk(
                &self.pmk,
                &self.bssid,
                &self.sta_mac,
                &self.anonce,
                &self.snonce,
            );
            self.ptk = Some(ptk);
            self.last_replay = Some(replay);
            let m2_info = desc_ver | KEY_INFO_PAIRWISE | KEY_INFO_MIC;
            Ok(build_eapol_key_frame(
                EAPOL_VERSION_1,
                m2_info,
                0,
                replay,
                &self.snonce,
                &self.rsn_ie,
                Some(&ptk.kck),
            ))
        } else {
            // Message 3/4: verify MIC, unwrap GTK KDE, install keys, return Message 4/4.
            let ptk = self.ptk.ok_or(WpaError::UnexpectedHandshakeStep)?;
            verify_eapol_mic(&ptk.kck, frame)?;
            if frame[17..49].ct_eq(&self.anonce).unwrap_u8() != 1 {
                return Err(WpaError::Malformed);
            }
            let mut gtk = [0u8; 16];
            let mut gtk_idx = 1u8;
            if (key_info & KEY_INFO_ENCRYPTED_DATA) != 0 && !key_data.is_empty() {
                let plain_kde = aes_key_unwrap(&ptk.kek, key_data)?;
                if let Some((idx, parsed_gtk)) = parse_gtk_kde(&plain_kde) {
                    gtk = parsed_gtk;
                    gtk_idx = idx;
                }
            }
            self.last_replay = Some(replay);
            self.installed = Some(InstalledWpa2Keys { ptk, gtk, gtk_idx });
            let m4_info = desc_ver | KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE;
            Ok(build_eapol_key_frame(
                EAPOL_VERSION_1,
                m4_info,
                0,
                replay,
                &[0u8; 32],
                &[],
                Some(&ptk.kck),
            ))
        }
    }
}

fn parse_gtk_kde(kde_stream: &[u8]) -> Option<(u8, [u8; 16])> {
    let mut pos = 0usize;
    while pos + 2 <= kde_stream.len() {
        let tag = kde_stream[pos];
        if tag == 0xDD && pos + 1 == kde_stream.len() {
            break;
        }
        let len = usize::from(kde_stream[pos + 1]);
        if pos + 2 + len > kde_stream.len() {
            break;
        }
        let body = &kde_stream[pos + 2..pos + 2 + len];
        // GTK KDE OUI = 00:0F:AC, data type = 1, 2-byte flags + 16-byte CCMP GTK
        if tag == 0xDD && len >= 22 && body[0..4] == [0x00, 0x0F, 0xAC, 0x01] {
            let key_id = body[4] & 0x03;
            let mut gtk = [0u8; 16];
            gtk.copy_from_slice(&body[6..22]);
            return Some((key_id, gtk));
        }
        pos += 2 + len;
    }
    None
}

/// WPA2-PSK Authenticator (used by `SimulatedRtw88Radio` virtual AP and tests).
pub struct Authenticator4Way {
    pmk: [u8; 32],
    bssid: [u8; 6],
    sta_mac: [u8; 6],
    anonce: [u8; 32],
    gtk: [u8; 16],
    replay_counter: u64,
    ptk: Option<Ptk>,
    complete: bool,
}

impl Authenticator4Way {
    pub fn new(
        pmk: [u8; 32],
        bssid: [u8; 6],
        sta_mac: [u8; 6],
        anonce: [u8; 32],
        gtk: [u8; 16],
    ) -> Self {
        Self {
            pmk,
            bssid,
            sta_mac,
            anonce,
            gtk,
            replay_counter: 1,
            ptk: None,
            complete: false,
        }
    }

    pub fn build_msg1(&mut self) -> Vec<u8> {
        let m1_info = KEY_INFO_TYPE_HMAC_SHA1_AES | KEY_INFO_PAIRWISE | KEY_INFO_ACK;
        build_eapol_key_frame(
            EAPOL_VERSION_2,
            m1_info,
            16,
            self.replay_counter,
            &self.anonce,
            &[],
            None,
        )
    }

    pub fn on_supplicant_eapol(&mut self, raw: &[u8]) -> Result<Option<Vec<u8>>, WpaError> {
        if raw.len() < EAPOL_KEY_FIXED_LEN {
            return Err(WpaError::Truncated);
        }
        let body_len = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
        if body_len < 95 || 4 + body_len > raw.len() {
            return Err(WpaError::Truncated);
        }
        let frame = &raw[..4 + body_len];
        let key_info = u16::from_be_bytes([frame[5], frame[6]]);

        if (key_info & KEY_INFO_SECURE) == 0 {
            // Message 2/4
            let mut snonce = [0u8; 32];
            snonce.copy_from_slice(&frame[17..49]);
            let ptk = derive_ptk(&self.pmk, &self.bssid, &self.sta_mac, &self.anonce, &snonce);
            verify_eapol_mic(&ptk.kck, frame)?;
            self.ptk = Some(ptk);
            self.replay_counter += 1;

            // Build RSN IE + GTK KDE (padded to 8-byte multiple per IEEE 802.11i 8.5.2j)
            let mut kde = Vec::with_capacity(56);
            kde.extend_from_slice(&RSN_IE_WPA2_CCMP);
            kde.extend_from_slice(&[0xDD, 22, 0x00, 0x0F, 0xAC, 0x01, 0x01, 0x00]);
            kde.extend_from_slice(&self.gtk);
            if kde.len() % 8 != 0 {
                kde.push(0xDD);
                while kde.len() % 8 != 0 {
                    kde.push(0x00);
                }
            }
            let wrapped = aes_key_wrap(&ptk.kek, &kde)?;
            let m3_info = KEY_INFO_TYPE_HMAC_SHA1_AES
                | KEY_INFO_PAIRWISE
                | KEY_INFO_INSTALL
                | KEY_INFO_ACK
                | KEY_INFO_MIC
                | KEY_INFO_SECURE
                | KEY_INFO_ENCRYPTED_DATA;
            Ok(Some(build_eapol_key_frame(
                EAPOL_VERSION_2,
                m3_info,
                16,
                self.replay_counter,
                &self.anonce,
                &wrapped,
                Some(&ptk.kck),
            )))
        } else {
            // Message 4/4
            let ptk = self.ptk.ok_or(WpaError::UnexpectedHandshakeStep)?;
            verify_eapol_mic(&ptk.kck, frame)?;
            self.complete = true;
            Ok(None)
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn ptk(&self) -> Option<&Ptk> {
        self.ptk.as_ref()
    }
}

// ============================================================================
// IEEE 802.11 CCMP-128 (AES-128-CCM)
// ============================================================================

/// Stateful CCMP-128 cipher context with monotonic TX PN and per-TID RX anti-replay window.
#[derive(Clone, Debug)]
pub struct CcmpContext {
    tk: [u8; 16],
    key_id: u8,
    tx_pn: u64,
    rx_max_pn: [Option<u64>; 17],
}

impl CcmpContext {
    pub fn new(tk: [u8; 16], key_id: u8) -> Self {
        Self {
            tk,
            key_id: key_id & 0x03,
            tx_pn: 0,
            rx_max_pn: [None; 17],
        }
    }

    /// Encrypt an 802.11 Data frame in-place-style: takes a 24/26-byte 802.11
    /// header (`mac_hdr`, with `FC_FLAG_PROTECTED` set) and `plaintext` (LLC/SNAP
    /// payload), returning the full protected 802.11 frame (`hdr || ccmp_hdr || ct || mic`).
    pub fn encrypt_mpdu(&mut self, mac_hdr: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, WpaError> {
        let hdr = Dot11Header::parse(mac_hdr).map_err(|_| WpaError::Malformed)?;
        if hdr.frame_type != FC_TYPE_DATA {
            return Err(WpaError::Malformed);
        }
        self.tx_pn = (self.tx_pn + 1) & 0x0000_FFFF_FFFF_FFFF;
        let pn = pn_to_6bytes(self.tx_pn);
        let ccmp_hdr = [
            pn[0],
            pn[1],
            0x00,
            0x20 | ((self.key_id & 0x03) << 6), // ExtIV=1
            pn[2],
            pn[3],
            pn[4],
            pn[5],
        ];
        let mut hdr_patched = mac_hdr[..hdr.hdr_len].to_vec();
        hdr_patched[1] |= FC_FLAG_PROTECTED;

        let nonce = build_ccmp_nonce(&hdr, &pn);
        let (aad, aad_len) = build_ccmp_aad(&hdr_patched, hdr.qos_tid);
        let (ct, mic) = ccm_encrypt_and_tag(&self.tk, &nonce, &aad[..aad_len], plaintext);

        let mut out =
            Vec::with_capacity(hdr_patched.len() + CCMP_HDR_LEN + ct.len() + CCMP_MIC_LEN);
        out.extend_from_slice(&hdr_patched);
        out.extend_from_slice(&ccmp_hdr);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&mic);
        Ok(out)
    }

    /// Decrypt and authenticate a protected 802.11 Data MPDU, enforcing strict
    /// 48-bit PN monotonicity and constant-time 8-byte MIC verification.
    pub fn decrypt_mpdu(&mut self, raw_mpdu: &[u8]) -> Result<Vec<u8>, WpaError> {
        let hdr = Dot11Header::parse(raw_mpdu).map_err(|_| WpaError::Malformed)?;
        if hdr.frame_type != FC_TYPE_DATA || (hdr.flags & FC_FLAG_PROTECTED) == 0 {
            return Err(WpaError::Malformed);
        }
        if hdr.body.len() < CCMP_HDR_LEN + CCMP_MIC_LEN {
            return Err(WpaError::Truncated);
        }
        let ch = &hdr.body[..CCMP_HDR_LEN];
        if (ch[3] & 0x20) == 0 {
            return Err(WpaError::Malformed);
        }
        let pn = [ch[0], ch[1], ch[4], ch[5], ch[6], ch[7]];
        let pn_u64 = pn_from_6bytes(&pn);
        let tid_slot = hdr.qos_tid.map_or(16usize, |t| usize::from(t & 0x0F));
        if let Some(prev) = self.rx_max_pn[tid_slot] {
            if pn_u64 <= prev {
                return Err(WpaError::ReplayDetected);
            }
        }
        let ct_end = hdr.body.len() - CCMP_MIC_LEN;
        let ct = &hdr.body[CCMP_HDR_LEN..ct_end];
        let rx_mic = &hdr.body[ct_end..];

        let nonce = build_ccmp_nonce(&hdr, &pn);
        let (aad, aad_len) = build_ccmp_aad(&raw_mpdu[..hdr.hdr_len], hdr.qos_tid);
        let (pt, calc_mic) = ccm_decrypt_and_tag(&self.tk, &nonce, &aad[..aad_len], ct);

        if calc_mic.ct_eq(rx_mic).unwrap_u8() != 1 {
            return Err(WpaError::BadMic);
        }
        self.rx_max_pn[tid_slot] = Some(pn_u64);
        Ok(pt)
    }
}

const TKIP_SBOX: [u16; 256] = [
    0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154, 0x6050, 0x0203, 0xCEA9, 0x567D,
    0xE719, 0xB562, 0x4DE6, 0xEC9A, 0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
    0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B, 0x75C2, 0xE11C, 0x3DAE, 0x4C6A,
    0x6C5A, 0x7E41, 0xF502, 0x834F, 0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
    0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5, 0x0E09, 0x2436, 0x1B9B, 0xDF3D,
    0xCD26, 0x4E69, 0x7FCD, 0xEA9F, 0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
    0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397, 0xA6F5, 0xB968, 0x0000, 0xC12C,
    0x4060, 0xE31F, 0x79C8, 0xB6ED, 0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
    0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194, 0x8ACF, 0xE910, 0x0406, 0xFE81,
    0xA0F0, 0x7844, 0x25BA, 0x4BE3, 0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
    0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D, 0x814C, 0x1814, 0x2635, 0xC32F,
    0xBEE1, 0x35A2, 0x88CC, 0x2E39, 0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
    0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83, 0x8CCA, 0xC729, 0x6BD3, 0x283C,
    0xA779, 0xBCE2, 0x161D, 0xAD76, 0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
    0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B, 0xD532, 0x8B43, 0x6E59, 0xDAB7,
    0x018C, 0xB164, 0x9CD2, 0x49E0, 0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
    0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751, 0xCB23, 0xA17C, 0xE89C, 0x3E21,
    0x96DD, 0x61DC, 0x0D86, 0x0F85, 0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
    0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9, 0xD938, 0xEB13, 0x2BB3, 0x2233,
    0xD2BB, 0xA970, 0x0789, 0x33A7, 0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
    0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8, 0x82C3, 0x29B0, 0x5A77, 0x1E11,
    0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
];

fn tkip_s(v: u16) -> u16 {
    TKIP_SBOX[usize::from(v & 0xFF)] ^ TKIP_SBOX[usize::from((v >> 8) & 0xFF)].swap_bytes()
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Decrypt an inbound WPA/WPA2 mixed-mode broadcast/multicast TKIP group MPDU
/// (IEEE 802.11-2020 Section 12.5.2 Phase 1 + Phase 2 key mixing + RC4 + CRC-32 ICV),
/// returning the inner LLC/SNAP payload stripped of TKIP IV, Michael MIC, and ICV.
pub fn decrypt_tkip_group_mpdu(
    gtk_enc_16: &[u8; 16],
    raw_mpdu: &[u8],
) -> Result<Vec<u8>, WpaError> {
    let hdr = Dot11Header::parse(raw_mpdu).map_err(|_| WpaError::Malformed)?;
    if hdr.frame_type != FC_TYPE_DATA || (hdr.flags & FC_FLAG_PROTECTED) == 0 {
        return Err(WpaError::Malformed);
    }
    // 8-byte Extended IV + payload + 8-byte Michael MIC + 4-byte WEP ICV = 20 bytes overhead
    if hdr.body.len() < 20 {
        return Err(WpaError::Truncated);
    }
    let iv = &hdr.body[..8];
    if (iv[3] & 0x20) == 0 {
        return Err(WpaError::Malformed);
    }
    let tsc1 = iv[0];
    let tsc0 = iv[2];
    let tsc2 = iv[4];
    let tsc3 = iv[5];
    let tsc4 = iv[6];
    let tsc5 = iv[7];
    let iv16 = u16::from(tsc0) | (u16::from(tsc1) << 8);
    let iv32 = u32::from_le_bytes([tsc2, tsc3, tsc4, tsc5]);

    let mut tk = [0u16; 8];
    for (i, slot) in tk.iter_mut().enumerate() {
        *slot = u16::from_le_bytes([gtk_enc_16[i * 2], gtk_enc_16[i * 2 + 1]]);
    }
    let ta = hdr.addr2;

    // Phase 1 key mixing (`tkip_mixing_phase1`)
    let mut ttak = [
        (iv32 & 0xFFFF) as u16,
        (iv32 >> 16) as u16,
        u16::from_le_bytes([ta[0], ta[1]]),
        u16::from_le_bytes([ta[2], ta[3]]),
        u16::from_le_bytes([ta[4], ta[5]]),
    ];
    for step in 0..8usize {
        let j = step & 1;
        ttak[0] = ttak[0].wrapping_add(tkip_s(ttak[4] ^ tk[j]));
        ttak[1] = ttak[1].wrapping_add(tkip_s(ttak[0] ^ tk[2 + j]));
        ttak[2] = ttak[2].wrapping_add(tkip_s(ttak[1] ^ tk[4 + j]));
        ttak[3] = ttak[3].wrapping_add(tkip_s(ttak[2] ^ tk[6 + j]));
        ttak[4] = ttak[4]
            .wrapping_add(tkip_s(ttak[3] ^ tk[j]))
            .wrapping_add(step as u16);
    }

    // Phase 2 key mixing
    let mut ppk = [
        ttak[0],
        ttak[1],
        ttak[2],
        ttak[3],
        ttak[4],
        ttak[4].wrapping_add(iv16),
    ];
    ppk[0] = ppk[0].wrapping_add(tkip_s(ppk[5] ^ tk[0]));
    ppk[1] = ppk[1].wrapping_add(tkip_s(ppk[0] ^ tk[1]));
    ppk[2] = ppk[2].wrapping_add(tkip_s(ppk[1] ^ tk[2]));
    ppk[3] = ppk[3].wrapping_add(tkip_s(ppk[2] ^ tk[3]));
    ppk[4] = ppk[4].wrapping_add(tkip_s(ppk[3] ^ tk[4]));
    ppk[5] = ppk[5].wrapping_add(tkip_s(ppk[4] ^ tk[5]));
    ppk[0] = ppk[0].wrapping_add((ppk[5] ^ tk[6]).rotate_right(1));
    ppk[1] = ppk[1].wrapping_add((ppk[0] ^ tk[7]).rotate_right(1));
    ppk[2] = ppk[2].wrapping_add(ppk[1].rotate_right(1));
    ppk[3] = ppk[3].wrapping_add(ppk[2].rotate_right(1));
    ppk[4] = ppk[4].wrapping_add(ppk[3].rotate_right(1));
    ppk[5] = ppk[5].wrapping_add(ppk[4].rotate_right(1));

    let mut rc4_seed = [0u8; 16];
    rc4_seed[0] = tsc1;
    rc4_seed[1] = (tsc1 | 0x20) & 0x7F;
    rc4_seed[2] = tsc0;
    rc4_seed[3] = ((ppk[5] ^ tk[0]) >> 1) as u8;
    for (i, &w) in ppk.iter().enumerate() {
        let le = w.to_le_bytes();
        rc4_seed[4 + i * 2] = le[0];
        rc4_seed[5 + i * 2] = le[1];
    }

    // RC4 KSA + PRGA over ciphertext || Michael MIC || CRC-32 ICV
    let mut s = [0u8; 256];
    for (idx, slot) in s.iter_mut().enumerate() {
        *slot = idx as u8;
    }
    let mut j = 0u8;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(rc4_seed[i & 15]);
        s.swap(i, usize::from(j));
    }
    let enc_slice = &hdr.body[8..];
    let mut dec = Vec::with_capacity(enc_slice.len());
    let mut ri = 0u8;
    let mut rj = 0u8;
    for &b in enc_slice {
        ri = ri.wrapping_add(1);
        rj = rj.wrapping_add(s[usize::from(ri)]);
        s.swap(usize::from(ri), usize::from(rj));
        let k = s[usize::from(s[usize::from(ri)].wrapping_add(s[usize::from(rj)]))];
        dec.push(b ^ k);
    }

    let payload_plus_mic_len = dec.len() - 4;
    let rx_icv = u32::from_le_bytes([
        dec[payload_plus_mic_len],
        dec[payload_plus_mic_len + 1],
        dec[payload_plus_mic_len + 2],
        dec[payload_plus_mic_len + 3],
    ]);
    if crc32_ieee(&dec[..payload_plus_mic_len]) != rx_icv {
        return Err(WpaError::BadMic);
    }
    dec.truncate(payload_plus_mic_len - 8);
    Ok(dec)
}

fn pn_to_6bytes(pn: u64) -> [u8; 6] {
    let le = pn.to_le_bytes();
    [le[0], le[1], le[2], le[3], le[4], le[5]]
}

fn pn_from_6bytes(pn: &[u8; 6]) -> u64 {
    u64::from_le_bytes([pn[0], pn[1], pn[2], pn[3], pn[4], pn[5], 0, 0])
}

fn build_ccmp_nonce(hdr: &Dot11Header<'_>, pn: &[u8; 6]) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0] = hdr.qos_tid.unwrap_or(0) & 0x0F;
    nonce[1..7].copy_from_slice(&hdr.addr2);
    // Nonce stores PN5..PN0 (big-endian PN order per IEEE 802.11-2020 12.5.3.3.4)
    nonce[7] = pn[5];
    nonce[8] = pn[4];
    nonce[9] = pn[3];
    nonce[10] = pn[2];
    nonce[11] = pn[1];
    nonce[12] = pn[0];
    nonce
}

fn build_ccmp_aad(mac_hdr: &[u8], qos_tid: Option<u8>) -> ([u8; 24], usize) {
    let mut aad = [0u8; 24];
    // Mask subtype bits [4..6], Retry/PwrMgt/MoreData, preserve Protected bit
    aad[0] = mac_hdr[0] & 0x8F;
    aad[1] = (mac_hdr[1] & 0xC7) | 0x40;
    aad[2..20].copy_from_slice(&mac_hdr[4..22]);
    // Mask Sequence Number [4..15], keep Fragment Number [0..3]
    aad[20] = mac_hdr[22] & 0x0F;
    aad[21] = 0;
    if let Some(tid) = qos_tid {
        aad[22] = tid & 0x0F;
        aad[23] = 0;
        (aad, 24)
    } else {
        (aad, 22)
    }
}

fn ccm_cbc_mac(cipher: &Aes128, nonce: &[u8; 13], aad: &[u8], plaintext: &[u8]) -> [u8; 16] {
    // M = 8 -> (M - 2)/2 = 3; L = 2 -> L - 1 = 1; Adata = 1 -> 0x40 | (3 << 3) | 1 = 0x59
    let mut b0 = [0u8; 16];
    b0[0] = 0x59;
    b0[1..14].copy_from_slice(nonce);
    b0[14..16].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());

    let mut x = b0;
    cipher.encrypt_block((&mut x).into());

    // Format AAD with 2-byte length prefix
    let mut aad_buf = [0u8; 32];
    aad_buf[0..2].copy_from_slice(&(aad.len() as u16).to_be_bytes());
    aad_buf[2..2 + aad.len()].copy_from_slice(aad);
    let aad_padded_len = (2 + aad.len() + 15) & !15;
    for blk in aad_buf[..aad_padded_len].as_chunks::<16>().0 {
        for i in 0..16 {
            x[i] ^= blk[i];
        }
        cipher.encrypt_block((&mut x).into());
    }

    for chunk in plaintext.chunks(16) {
        for (i, &b) in chunk.iter().enumerate() {
            x[i] ^= b;
        }
        cipher.encrypt_block((&mut x).into());
    }
    x
}

fn ccm_ctr_stream_block(cipher: &Aes128, nonce: &[u8; 13], counter: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0x01; // L - 1 = 1
    a[1..14].copy_from_slice(nonce);
    a[14..16].copy_from_slice(&counter.to_be_bytes());
    cipher.encrypt_block((&mut a).into());
    a
}

fn ccm_encrypt_and_tag(
    tk: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 8]) {
    let cipher = Aes128::new(tk.into());
    let t_full = ccm_cbc_mac(&cipher, nonce, aad, plaintext);
    let s0 = ccm_ctr_stream_block(&cipher, nonce, 0);
    let mut mic = [0u8; 8];
    for i in 0..8 {
        mic[i] = t_full[i] ^ s0[i];
    }

    let mut ct = plaintext.to_vec();
    for (idx, chunk) in ct.chunks_mut(16).enumerate() {
        let si = ccm_ctr_stream_block(&cipher, nonce, (idx + 1) as u16);
        for (j, b) in chunk.iter_mut().enumerate() {
            *b ^= si[j];
        }
    }
    (ct, mic)
}

fn ccm_decrypt_and_tag(
    tk: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &[u8],
) -> (Vec<u8>, [u8; 8]) {
    let cipher = Aes128::new(tk.into());
    let mut pt = ciphertext.to_vec();
    for (idx, chunk) in pt.chunks_mut(16).enumerate() {
        let si = ccm_ctr_stream_block(&cipher, nonce, (idx + 1) as u16);
        for (j, b) in chunk.iter_mut().enumerate() {
            *b ^= si[j];
        }
    }
    let t_full = ccm_cbc_mac(&cipher, nonce, aad, &pt);
    let s0 = ccm_ctr_stream_block(&cipher, nonce, 0);
    let mut mic = [0u8; 8];
    for i in 0..8 {
        mic[i] = t_full[i] ^ s0[i];
    }
    (pt, mic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_ieee80211::build_data_frame;

    #[test]
    fn ieee_80211i_annex_h_pbkdf2_test_vector() {
        // IEEE Std 802.11i-2004 Annex H.4.3 Test Case 1:
        // Passphrase = "password", SSID = "IEEE"
        let pmk = derive_wpa2_psk(b"password", b"IEEE").unwrap_or([0u8; 32]);
        let expected: [u8; 32] = [
            0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a,
            0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e,
            0x97, 0x10, 0xa1, 0x2e,
        ];
        assert_eq!(pmk, expected);
    }

    #[test]
    fn full_4way_eapol_handshake_and_ccmp_encrypt_decrypt_with_anti_replay() {
        let bssid = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01];
        let sta = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
        let pmk = derive_wpa2_psk(b"huesos-wifi-2026", b"HuesOS-Lab-5G").unwrap_or([0u8; 32]);
        let anonce = [0x11u8; 32];
        let snonce = [0x22u8; 32];
        let gtk = [0x77u8; 16];

        let mut auth = Authenticator4Way::new(pmk, bssid, sta, anonce, gtk);
        let mut supp = Supplicant4Way::new(pmk, bssid, sta, snonce);

        let m1 = auth.build_msg1();
        let m2 = supp.on_eapol_frame(&m1).unwrap_or_default();
        assert!(!m2.is_empty());

        let m3 = auth
            .on_supplicant_eapol(&m2)
            .unwrap_or(None)
            .unwrap_or_default();
        assert!(!m3.is_empty());

        let m4 = supp.on_eapol_frame(&m3).unwrap_or_default();
        assert!(!m4.is_empty());
        assert_eq!(auth.on_supplicant_eapol(&m4), Ok(None));
        assert!(auth.is_complete());

        let installed = supp.installed_keys().copied();
        assert!(installed.is_some());
        if let Some(keys) = installed {
            assert_eq!(keys.gtk, gtk);
            assert_eq!(Some(&keys.ptk), auth.ptk());

            let mut tx_ccmp = CcmpContext::new(keys.ptk.tk, 0);
            let mut rx_ccmp = CcmpContext::new(keys.ptk.tk, 0);

            let mut raw_hdr = [0u8; 24];
            let _ = build_data_frame(true, true, bssid, sta, bssid, 1, &[], &mut raw_hdr);
            let payload = b"\xAA\xAA\x03\x00\x00\x00\x08\x00hello-over-wpa2-ccmp";
            let mpdu = tx_ccmp.encrypt_mpdu(&raw_hdr, payload).unwrap_or_default();
            assert_eq!(mpdu.len(), 24 + CCMP_HDR_LEN + payload.len() + CCMP_MIC_LEN);

            let decrypted = rx_ccmp.decrypt_mpdu(&mpdu);
            assert_eq!(decrypted.as_deref(), Ok(&payload[..]));

            // Replaying the exact same MPDU must fail with ReplayDetected!
            assert_eq!(rx_ccmp.decrypt_mpdu(&mpdu), Err(WpaError::ReplayDetected));

            // Tampering with 1 bit of ciphertext must fail with BadMic!
            let mut mpdu2 = tx_ccmp.encrypt_mpdu(&raw_hdr, payload).unwrap_or_default();
            mpdu2[35] ^= 0x01;
            assert_eq!(rx_ccmp.decrypt_mpdu(&mpdu2), Err(WpaError::BadMic));
        }
    }

    #[test]
    fn rfc4493_aes128_cmac_test_vectors() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let exp0: [u8; 16] = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ];
        assert_eq!(aes128_cmac(&key, &[]), exp0);

        let m16: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let exp16: [u8; 16] = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];
        assert_eq!(aes128_cmac(&key, &m16), exp16);
    }
}
