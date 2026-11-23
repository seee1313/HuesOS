//! Cryptographic primitives for TLS 1.3 (RFC 8446) and X.509v3 (RFC 5280).
//!
//! Pure safe Rust (`#![forbid(unsafe_code)]`, `#![no_std]` + `alloc`):
//! - AEAD record protection: `TLS_AES_128_GCM_SHA256` (`0x1301`) and
//!   `TLS_AES_256_GCM_SHA384` (`0x1302`)
//! - HKDF-SHA256 / HKDF-SHA384 key schedule (`HkdfLabel`, `Derive-Secret`, `Finished`)
//! - ECDHE key exchange: `X25519` (`0x001D`) and `secp256r1` / NIST P-256 (`0x0017`)
//! - Signature verification:
//!   - `ed25519` (`0x0807`)
//!   - `ecdsa_secp256r1_sha256` (`0x0403`)
//!   - `ecdsa_secp384r1_sha384` (`0x0503`)
//!   - `rsa_pss_rsae_sha256` (`0x0804`), `rsa_pss_rsae_sha384` (`0x0805`)
//!   - `rsa_pkcs1_sha256` (`0x0401`), `rsa_pkcs1_sha384` (`0x0501`)

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdVerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

/// Supported TLS 1.3 cipher suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    /// `TLS_AES_128_GCM_SHA256` (`0x1301`).
    Aes128GcmSha256,
    /// `TLS_AES_256_GCM_SHA384` (`0x1302`).
    Aes256GcmSha384,
}

impl CipherSuite {
    pub const fn from_u16(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            _ => None,
        }
    }

    pub const fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
        }
    }

    pub const fn hash_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 32,
            Self::Aes256GcmSha384 => 48,
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 => 32,
        }
    }

    pub const fn iv_len(self) -> usize {
        12
    }

    pub const fn hash_alg(self) -> HashAlg {
        match self {
            Self::Aes128GcmSha256 => HashAlg::Sha256,
            Self::Aes256GcmSha384 => HashAlg::Sha384,
        }
    }
}

/// Hash algorithm selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub const fn out_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Compute `HKDF-Extract(salt, ikm)` for the selected cipher suite.
pub fn hkdf_extract(suite: CipherSuite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match suite {
        CipherSuite::Aes128GcmSha256 => {
            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
            prk.to_vec()
        }
        CipherSuite::Aes256GcmSha384 => {
            let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
            prk.to_vec()
        }
    }
}

/// Compute RFC 8446 §7.1 `HKDF-Expand-Label(Secret, Label, Context, Length)`.
pub fn hkdf_expand_label(
    suite: CipherSuite,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Option<Vec<u8>> {
    let full_label_len = 6usize.checked_add(label.len())?;
    if full_label_len > 255 || context.len() > 255 || length > 0xFFFF {
        return None;
    }
    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    hkdf_label.push(full_label_len as u8);
    hkdf_label.extend_from_slice(b"tls13 ");
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let mut out = vec![0u8; length];
    match suite {
        CipherSuite::Aes128GcmSha256 => {
            let hk = Hkdf::<Sha256>::from_prk(secret).ok()?;
            hk.expand(&hkdf_label, &mut out).ok()?;
        }
        CipherSuite::Aes256GcmSha384 => {
            let hk = Hkdf::<Sha384>::from_prk(secret).ok()?;
            hk.expand(&hkdf_label, &mut out).ok()?;
        }
    }
    Some(out)
}

/// Compute `Derive-Secret(Secret, Label, Messages)` where `transcript_hash = Hash(Messages)`.
pub fn derive_secret_with_hash(
    suite: CipherSuite,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Option<Vec<u8>> {
    hkdf_expand_label(suite, secret, label, transcript_hash, suite.hash_len())
}

/// Compute `HMAC(finished_key, transcript_hash)` for TLS 1.3 `Finished`.
pub fn compute_finished_verify_data(
    suite: CipherSuite,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Option<Vec<u8>> {
    let finished_key = hkdf_expand_label(suite, base_key, b"finished", b"", suite.hash_len())?;
    match suite {
        CipherSuite::Aes128GcmSha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&finished_key).ok()?;
            mac.update(transcript_hash);
            Some(mac.finalize().into_bytes().to_vec())
        }
        CipherSuite::Aes256GcmSha384 => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(&finished_key).ok()?;
            mac.update(transcript_hash);
            Some(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Constant-time equality check over byte slices.
pub fn ct_eq_slices(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

enum AeadEngine {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

/// TLS 1.3 per-direction record AEAD state (`key`, `iv`, 64-bit `seq`).
pub struct TrafficCipher {
    suite: CipherSuite,
    engine: AeadEngine,
    iv: [u8; 12],
    seq: u64,
    secret: Vec<u8>,
}

impl TrafficCipher {
    pub fn from_traffic_secret(suite: CipherSuite, traffic_secret: &[u8]) -> Option<Self> {
        let key = hkdf_expand_label(suite, traffic_secret, b"key", b"", suite.key_len())?;
        let iv_vec = hkdf_expand_label(suite, traffic_secret, b"iv", b"", suite.iv_len())?;
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);
        let engine = match suite {
            CipherSuite::Aes128GcmSha256 => {
                AeadEngine::Aes128(Aes128Gcm::new_from_slice(&key).ok()?)
            }
            CipherSuite::Aes256GcmSha384 => {
                AeadEngine::Aes256(Aes256Gcm::new_from_slice(&key).ok()?)
            }
        };
        Some(Self {
            suite,
            engine,
            iv,
            seq: 0,
            secret: traffic_secret.to_vec(),
        })
    }

    /// Perform RFC 8446 §7.2 `application_traffic_secret_N+1` rotation.
    pub fn key_update(&mut self) -> Option<()> {
        let next = hkdf_expand_label(
            self.suite,
            &self.secret,
            b"traffic upd",
            b"",
            self.suite.hash_len(),
        )?;
        *self = Self::from_traffic_secret(self.suite, &next)?;
        Some(())
    }

    fn next_nonce(&mut self) -> Option<[u8; 12]> {
        let cur = self.seq;
        self.seq = self.seq.checked_add(1)?;
        let mut nonce = self.iv;
        let seq_be = cur.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_be[i];
        }
        Some(nonce)
    }

    /// Encrypt `plaintext || [inner_content_type]` into a full `TLSCiphertext` record.
    pub fn seal_record(&mut self, inner_content_type: u8, plaintext: &[u8]) -> Option<Vec<u8>> {
        if plaintext.len() > 16_384 {
            return None;
        }
        let nonce_bytes = self.next_nonce()?;
        let nonce = Nonce::from(nonce_bytes);
        let enc_len = plaintext.len().checked_add(1)?.checked_add(16)?;
        let aad = [
            0x17u8,
            0x03,
            0x03,
            (enc_len >> 8) as u8,
            (enc_len & 0xFF) as u8,
        ];
        let mut buf = Vec::with_capacity(plaintext.len() + 1);
        buf.extend_from_slice(plaintext);
        buf.push(inner_content_type);
        let tag = match &self.engine {
            AeadEngine::Aes128(c) => c.encrypt_in_place_detached(&nonce, &aad, &mut buf).ok()?,
            AeadEngine::Aes256(c) => c.encrypt_in_place_detached(&nonce, &aad, &mut buf).ok()?,
        };
        let mut record = Vec::with_capacity(5 + buf.len() + 16);
        record.extend_from_slice(&aad);
        record.extend_from_slice(&buf);
        let tag_bytes: [u8; 16] = tag.into();
        record.extend_from_slice(&tag_bytes);
        Some(record)
    }

    /// Decrypt a `TLSCiphertext` payload, returning `(inner_content_type, content)`.
    pub fn open_record(
        &mut self,
        record_hdr: [u8; 5],
        ciphertext_and_tag: &[u8],
    ) -> Option<(u8, Vec<u8>)> {
        if ciphertext_and_tag.len() < 17 || ciphertext_and_tag.len() > 16_640 {
            return None;
        }
        let nonce_bytes = self.next_nonce()?;
        let nonce = Nonce::from(nonce_bytes);
        let ct_len = ciphertext_and_tag.len() - 16;
        let mut buf = ciphertext_and_tag[..ct_len].to_vec();
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(&ciphertext_and_tag[ct_len..]);
        let tag = Tag::from(tag_arr);
        match &self.engine {
            AeadEngine::Aes128(c) => c
                .decrypt_in_place_detached(&nonce, &record_hdr, &mut buf, &tag)
                .ok()?,
            AeadEngine::Aes256(c) => c
                .decrypt_in_place_detached(&nonce, &record_hdr, &mut buf, &tag)
                .ok()?,
        }
        // Strip zero padding and extract TLSInnerPlaintext.type.
        while buf.last().copied() == Some(0) {
            buf.pop();
        }
        let inner_type = buf.pop()?;
        if buf.len() > 16_384 {
            return None;
        }
        Some((inner_type, buf))
    }
}

/// Compute X25519 public key from 32-byte secret scalar.
pub fn x25519_public_key(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

/// Compute X25519 shared secret, rejecting low-order all-zero outputs (RFC 7748 §6.1).
pub fn x25519_diffie_hellman(secret: &[u8; 32], peer_public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = MontgomeryPoint(*peer_public)
        .mul_clamped(*secret)
        .to_bytes();
    if bool::from(shared.ct_eq(&[0u8; 32])) {
        None
    } else {
        Some(shared)
    }
}

/// Verify an Ed25519 signature over `msg`.
pub fn ed25519_verify(pub_key: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let Ok(vk) = EdVerifyingKey::from_bytes(pub_key) else {
        return false;
    };
    let Ok(ed_sig) = EdSignature::from_slice(sig) else {
        return false;
    };
    vk.verify_strict(msg, &ed_sig).is_ok()
}

// ---------------------------------------------------------------------------
// Arbitrary-precision unsigned arithmetic for RSA (1024..=8192) & EC P-256/P-384
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    /// Little-endian 64-bit limbs, normalized (no trailing zero limbs).
    limbs: Vec<u64>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    pub fn from_u64(v: u64) -> Self {
        if v == 0 {
            Self::zero()
        } else {
            Self { limbs: vec![v] }
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_odd(&self) -> bool {
        self.limbs.first().copied().unwrap_or(0) & 1 == 1
    }

    fn normalize(&mut self) {
        while self.limbs.last().copied() == Some(0) {
            self.limbs.pop();
        }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let first_nz = match bytes.iter().position(|&b| b != 0) {
            Some(idx) => idx,
            None => return Self::zero(),
        };
        let trimmed = &bytes[first_nz..];
        let num_limbs = (trimmed.len() + 7) / 8;
        let mut limbs = Vec::with_capacity(num_limbs);
        let mut end = trimmed.len();
        while end > 0 {
            let start = end.saturating_sub(8);
            let mut buf = [0u8; 8];
            let chunk = &trimmed[start..end];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            limbs.push(u64::from_be_bytes(buf));
            end = start;
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    pub fn to_be_bytes_padded(&self, width: usize) -> Vec<u8> {
        let mut out = vec![0u8; width];
        for (i, &limb) in self.limbs.iter().enumerate() {
            let be = limb.to_be_bytes();
            for j in 0..8 {
                let byte_idx_from_right = i * 8 + (7 - j);
                if byte_idx_from_right < width {
                    out[width - 1 - byte_idx_from_right] = be[j];
                }
            }
        }
        out
    }

    pub fn bit_len(&self) -> usize {
        let Some(&top) = self.limbs.last() else {
            return 0;
        };
        (self.limbs.len() - 1) * 64 + (64 - top.leading_zeros() as usize)
    }

    pub fn get_bit(&self, bit: usize) -> bool {
        let limb_idx = bit / 64;
        let bit_idx = bit % 64;
        match self.limbs.get(limb_idx) {
            Some(&w) => ((w >> bit_idx) & 1) != 0,
            None => false,
        }
    }

    pub fn set_bit(&mut self, bit: usize) {
        let limb_idx = bit / 64;
        let bit_idx = bit % 64;
        if self.limbs.len() <= limb_idx {
            self.limbs.resize(limb_idx + 1, 0);
        }
        self.limbs[limb_idx] |= 1u64 << bit_idx;
    }

    pub fn cmp_val(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != other.limbs[i] {
                return self.limbs[i].cmp(&other.limbs[i]);
            }
        }
        Ordering::Equal
    }

    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(max_len + 1);
        let mut carry = 0u128;
        for i in 0..max_len {
            let a = u128::from(self.limbs.get(i).copied().unwrap_or(0));
            let b = u128::from(other.limbs.get(i).copied().unwrap_or(0));
            let sum = a + b + carry;
            limbs.push(sum as u64);
            carry = sum >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    /// Subtract `other` from `self` (`self >= other`).
    pub fn sub(&self, other: &Self) -> Self {
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i128;
        for i in 0..self.limbs.len() {
            let a = i128::from(self.limbs[i]);
            let b = i128::from(other.limbs.get(i).copied().unwrap_or(0));
            let diff = a - b - borrow;
            if diff < 0 {
                limbs.push((diff + (1i128 << 64)) as u64);
                borrow = 1;
            } else {
                limbs.push(diff as u64);
                borrow = 0;
            }
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    pub fn shl1(&mut self) {
        let mut carry = 0u64;
        for w in &mut self.limbs {
            let next_carry = *w >> 63;
            *w = (*w << 1) | carry;
            carry = next_carry;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    pub fn shr1(&mut self) {
        let mut carry = 0u64;
        for w in self.limbs.iter_mut().rev() {
            let next_carry = *w << 63;
            *w = (*w >> 1) | carry;
            carry = next_carry;
        }
        self.normalize();
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut limbs = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let prod = u128::from(a) * u128::from(b) + u128::from(limbs[i + j]) + carry;
                limbs[i + j] = prod as u64;
                carry = prod >> 64;
            }
            limbs[i + other.limbs.len()] = carry as u64;
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    pub fn rem_mod(&self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        if self.cmp_val(modulus) == Ordering::Less {
            return self.clone();
        }
        let mut rem = Self::zero();
        for bit in (0..self.bit_len()).rev() {
            rem.shl1();
            if self.get_bit(bit) {
                if rem.limbs.is_empty() {
                    rem.limbs.push(1);
                } else {
                    rem.limbs[0] |= 1;
                }
            }
            if rem.cmp_val(modulus) != Ordering::Less {
                rem = rem.sub(modulus);
            }
        }
        rem
    }

    pub fn mod_add(&self, other: &Self, m: &Self) -> Self {
        let s = self.add(other);
        if s.cmp_val(m) != Ordering::Less {
            s.sub(m)
        } else {
            s
        }
    }

    pub fn mod_sub(&self, other: &Self, m: &Self) -> Self {
        if self.cmp_val(other) != Ordering::Less {
            self.sub(other)
        } else {
            let diff = other.sub(self);
            m.sub(&diff)
        }
    }

    pub fn mod_mul(&self, other: &Self, m: &Self) -> Self {
        self.mul(other).rem_mod(m)
    }

    /// Compute `self^exp mod m`.
    pub fn mod_pow(&self, exp: &Self, m: &Self) -> Self {
        if m.is_zero() {
            return Self::zero();
        }
        let mut result = Self::one().rem_mod(m);
        let base = self.rem_mod(m);
        for bit in (0..exp.bit_len()).rev() {
            result = result.mod_mul(&result, m);
            if exp.get_bit(bit) {
                result = result.mod_mul(&base, m);
            }
        }
        result
    }

    /// Compute modular inverse `self^-1 mod m` for odd prime/coprime modulus `m`.
    pub fn mod_inv(&self, m: &Self) -> Option<Self> {
        if self.is_zero() || m.is_zero() || !m.is_odd() {
            return None;
        }
        // Binary extended GCD for odd modulus `m`: maintains `u * a == x1 (mod m)`, `v * a == x2 (mod m)`.
        let mut u = self.rem_mod(m);
        if u.is_zero() {
            return None;
        }
        let mut v = m.clone();
        let mut x1 = Self::one();
        let mut x2 = Self::zero();
        let one = Self::one();

        while u != one && v != one {
            while !u.is_zero() && !u.is_odd() {
                u.shr1();
                if !x1.is_odd() {
                    x1.shr1();
                } else {
                    x1 = x1.add(m);
                    x1.shr1();
                }
            }
            while !v.is_zero() && !v.is_odd() {
                v.shr1();
                if !x2.is_odd() {
                    x2.shr1();
                } else {
                    x2 = x2.add(m);
                    x2.shr1();
                }
            }
            if u.cmp_val(&v) != Ordering::Less {
                u = u.sub(&v);
                x1 = x1.mod_sub(&x2, m);
            } else {
                v = v.sub(&u);
                x2 = x2.mod_sub(&x1, m);
            }
        }
        if u == one {
            Some(x1.rem_mod(m))
        } else if v == one {
            Some(x2.rem_mod(m))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Short-Weierstrass EC (a = -3 mod p): NIST P-256 (secp256r1) & P-384 (secp384r1)
// ---------------------------------------------------------------------------

struct WeierstrassCurve {
    p: BigUint,
    b: BigUint,
    n: BigUint,
    gx: BigUint,
    gy: BigUint,
    coord_len: usize,
}

fn p256_curve() -> WeierstrassCurve {
    WeierstrassCurve {
        p: BigUint::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ]),
        b: BigUint::from_be_bytes(&[
            0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98,
            0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E,
            0x27, 0xD2, 0x60, 0x4B,
        ]),
        n: BigUint::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ]),
        gx: BigUint::from_be_bytes(&[
            0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
            0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45,
            0xD8, 0x98, 0xC2, 0x96,
        ]),
        gy: BigUint::from_be_bytes(&[
            0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F,
            0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68,
            0x37, 0xBF, 0x51, 0xF5,
        ]),
        coord_len: 32,
    }
}

fn p384_curve() -> WeierstrassCurve {
    WeierstrassCurve {
        p: BigUint::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        ]),
        b: BigUint::from_be_bytes(&[
            0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8,
            0x2D, 0x19, 0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8F,
            0x50, 0x13, 0x87, 0x5A, 0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85,
            0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF,
        ]),
        n: BigUint::from_be_bytes(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81,
            0xF4, 0x37, 0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC,
            0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,
        ]),
        gx: BigUint::from_be_bytes(&[
            0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20,
            0xAD, 0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0,
            0x82, 0x54, 0x2A, 0x38, 0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54,
            0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7,
        ]),
        gy: BigUint::from_be_bytes(&[
            0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92,
            0xDC, 0x29, 0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13,
            0xB5, 0xF0, 0xB8, 0xC0, 0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43,
            0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F,
        ]),
        coord_len: 48,
    }
}

#[derive(Clone)]
struct JacobianPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    infinity: bool,
}

impl JacobianPoint {
    fn infinity() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::zero(),
            z: BigUint::zero(),
            infinity: true,
        }
    }

    fn from_affine(x: BigUint, y: BigUint) -> Self {
        Self {
            x,
            y,
            z: BigUint::one(),
            infinity: false,
        }
    }

    fn to_affine(&self, curve: &WeierstrassCurve) -> Option<(BigUint, BigUint)> {
        if self.infinity || self.z.is_zero() {
            return None;
        }
        let z_inv = self.z.mod_inv(&curve.p)?;
        let z_inv2 = z_inv.mod_mul(&z_inv, &curve.p);
        let z_inv3 = z_inv2.mod_mul(&z_inv, &curve.p);
        let ax = self.x.mod_mul(&z_inv2, &curve.p);
        let ay = self.y.mod_mul(&z_inv3, &curve.p);
        Some((ax, ay))
    }
}

impl WeierstrassCurve {
    fn decode_uncompressed(&self, encoded: &[u8]) -> Option<(BigUint, BigUint)> {
        if encoded.len() != 1 + 2 * self.coord_len || encoded[0] != 0x04 {
            return None;
        }
        let x = BigUint::from_be_bytes(&encoded[1..1 + self.coord_len]);
        let y = BigUint::from_be_bytes(&encoded[1 + self.coord_len..]);
        if x.cmp_val(&self.p) != Ordering::Less || y.cmp_val(&self.p) != Ordering::Less {
            return None;
        }
        // Check y^2 == x^3 - 3x + b (mod p)
        let y2 = y.mod_mul(&y, &self.p);
        let x2 = x.mod_mul(&x, &self.p);
        let x3 = x2.mod_mul(&x, &self.p);
        let three_x = x.mod_add(&x, &self.p).mod_add(&x, &self.p);
        let rhs = x3.mod_sub(&three_x, &self.p).mod_add(&self.b, &self.p);
        if y2 != rhs {
            return None;
        }
        Some((x, y))
    }

    fn double(&self, pt: &JacobianPoint) -> JacobianPoint {
        if pt.infinity || pt.y.is_zero() {
            return JacobianPoint::infinity();
        }
        let p = &self.p;
        let delta = pt.z.mod_mul(&pt.z, p);
        let gamma = pt.y.mod_mul(&pt.y, p);
        let beta = pt.x.mod_mul(&gamma, p);

        let x_minus_d = pt.x.mod_sub(&delta, p);
        let x_plus_d = pt.x.mod_add(&delta, p);
        let prod = x_minus_d.mod_mul(&x_plus_d, p);
        let alpha = prod.mod_add(&prod, p).mod_add(&prod, p); // 3 * (X - Z^2) * (X + Z^2)

        let two_beta = beta.mod_add(&beta, p);
        let four_beta = two_beta.mod_add(&two_beta, p);
        let eight_beta = four_beta.mod_add(&four_beta, p);

        let x3 = alpha.mod_mul(&alpha, p).mod_sub(&eight_beta, p);
        let yz = pt.y.mod_mul(&pt.z, p);
        let z3 = yz.mod_add(&yz, p);

        let gamma_sq = gamma.mod_mul(&gamma, p);
        let two_g2 = gamma_sq.mod_add(&gamma_sq, p);
        let four_g2 = two_g2.mod_add(&two_g2, p);
        let eight_g2 = four_g2.mod_add(&four_g2, p);

        let y3 = alpha
            .mod_mul(&four_beta.mod_sub(&x3, p), p)
            .mod_sub(&eight_g2, p);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
            infinity: false,
        }
    }

    fn add(&self, p1: &JacobianPoint, p2: &JacobianPoint) -> JacobianPoint {
        if p1.infinity {
            return p2.clone();
        }
        if p2.infinity {
            return p1.clone();
        }
        let p = &self.p;
        let z1z1 = p1.z.mod_mul(&p1.z, p);
        let z2z2 = p2.z.mod_mul(&p2.z, p);
        let u1 = p1.x.mod_mul(&z2z2, p);
        let u2 = p2.x.mod_mul(&z1z1, p);
        let s1 = p1.y.mod_mul(&p2.z, p).mod_mul(&z2z2, p);
        let s2 = p2.y.mod_mul(&p1.z, p).mod_mul(&z1z1, p);

        if u1 == u2 {
            if s1 == s2 {
                return self.double(p1);
            }
            return JacobianPoint::infinity();
        }

        let h = u2.mod_sub(&u1, p);
        let r = s2.mod_sub(&s1, p);
        let hh = h.mod_mul(&h, p);
        let hhh = h.mod_mul(&hh, p);
        let v = u1.mod_mul(&hh, p);
        let two_v = v.mod_add(&v, p);

        let x3 = r.mod_mul(&r, p).mod_sub(&hhh, p).mod_sub(&two_v, p);
        let y3 = r
            .mod_mul(&v.mod_sub(&x3, p), p)
            .mod_sub(&s1.mod_mul(&hhh, p), p);
        let z3 = p1.z.mod_mul(&p2.z, p).mod_mul(&h, p);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
            infinity: false,
        }
    }

    fn scalar_mul(&self, pt: &JacobianPoint, k: &BigUint) -> JacobianPoint {
        let mut acc = JacobianPoint::infinity();
        for bit in (0..k.bit_len()).rev() {
            acc = self.double(&acc);
            if k.get_bit(bit) {
                acc = self.add(&acc, pt);
            }
        }
        acc
    }

    /// Shamir's trick: compute `u1 * G + u2 * Q`.
    fn lincomb_g_q(&self, u1: &BigUint, q: &JacobianPoint, u2: &BigUint) -> JacobianPoint {
        let g = JacobianPoint::from_affine(self.gx.clone(), self.gy.clone());
        let g_plus_q = self.add(&g, q);
        let max_bits = u1.bit_len().max(u2.bit_len());
        let mut acc = JacobianPoint::infinity();
        for bit in (0..max_bits).rev() {
            acc = self.double(&acc);
            match (u1.get_bit(bit), u2.get_bit(bit)) {
                (true, true) => acc = self.add(&acc, &g_plus_q),
                (true, false) => acc = self.add(&acc, &g),
                (false, true) => acc = self.add(&acc, q),
                (false, false) => {}
            }
        }
        acc
    }
}

/// Derive a 65-byte uncompressed `0x04 || X || Y` NIST P-256 public key from 32 random bytes.
pub fn p256_public_key(secret_seed: &[u8; 32]) -> Option<([u8; 32], [u8; 65])> {
    let curve = p256_curve();
    let one = BigUint::one();
    let n_minus_2 = curve.n.sub(&BigUint::from_u64(2));
    // Map seed into [1, n - 1]
    let d = BigUint::from_be_bytes(secret_seed)
        .rem_mod(&n_minus_2)
        .add(&one);
    let g = JacobianPoint::from_affine(curve.gx.clone(), curve.gy.clone());
    let (px, py) = curve.scalar_mul(&g, &d).to_affine(&curve)?;
    let mut scalar_be = [0u8; 32];
    scalar_be.copy_from_slice(&d.to_be_bytes_padded(32));
    let mut pub_out = [0u8; 65];
    pub_out[0] = 0x04;
    pub_out[1..33].copy_from_slice(&px.to_be_bytes_padded(32));
    pub_out[33..65].copy_from_slice(&py.to_be_bytes_padded(32));
    Some((scalar_be, pub_out))
}

/// Perform NIST P-256 ECDH (`d * Q`), returning the 32-byte big-endian X coordinate.
pub fn p256_diffie_hellman(secret_scalar_be: &[u8; 32], peer_encoded: &[u8]) -> Option<[u8; 32]> {
    let curve = p256_curve();
    let d = BigUint::from_be_bytes(secret_scalar_be);
    if d.is_zero() || d.cmp_val(&curve.n) != Ordering::Less {
        return None;
    }
    let (qx, qy) = curve.decode_uncompressed(peer_encoded)?;
    let q = JacobianPoint::from_affine(qx, qy);
    let (sx, _) = curve.scalar_mul(&q, &d).to_affine(&curve)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&sx.to_be_bytes_padded(32));
    Some(out)
}

fn parse_ecdsa_der_sig(sig: &[u8]) -> Option<(BigUint, BigUint)> {
    // SEQUENCE { r INTEGER, s INTEGER }
    if sig.len() < 6 || sig[0] != 0x30 {
        return None;
    }
    let (seq_len, mut pos) = read_der_len(sig, 1)?;
    if pos + seq_len != sig.len() {
        return None;
    }
    let r = read_der_positive_uint(sig, &mut pos)?;
    let s = read_der_positive_uint(sig, &mut pos)?;
    if pos != sig.len() {
        return None;
    }
    Some((r, s))
}

fn read_der_len(buf: &[u8], idx: usize) -> Option<(usize, usize)> {
    let first = *buf.get(idx)?;
    if (first & 0x80) == 0 {
        Some((usize::from(first), idx + 1))
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 || idx + 1 + count > buf.len() {
            return None;
        }
        let mut val = 0usize;
        for &b in &buf[idx + 1..idx + 1 + count] {
            val = (val << 8) | usize::from(b);
        }
        Some((val, idx + 1 + count))
    }
}

fn read_der_positive_uint(buf: &[u8], pos: &mut usize) -> Option<BigUint> {
    if *buf.get(*pos)? != 0x02 {
        return None;
    }
    let (len, start) = read_der_len(buf, *pos + 1)?;
    if len == 0 || start + len > buf.len() {
        return None;
    }
    let raw = &buf[start..start + len];
    if (raw[0] & 0x80) != 0 {
        return None;
    }
    *pos = start + len;
    Some(BigUint::from_be_bytes(raw))
}

fn ecdsa_verify_curve(
    curve: &WeierstrassCurve,
    pub_uncompressed: &[u8],
    digest: &[u8],
    der_sig: &[u8],
) -> bool {
    let Some((qx, qy)) = curve.decode_uncompressed(pub_uncompressed) else {
        return false;
    };
    let Some((r, s)) = parse_ecdsa_der_sig(der_sig) else {
        return false;
    };
    if r.is_zero()
        || s.is_zero()
        || r.cmp_val(&curve.n) != Ordering::Less
        || s.cmp_val(&curve.n) != Ordering::Less
    {
        return false;
    }
    let z = BigUint::from_be_bytes(&digest[..digest.len().min(curve.coord_len)]);
    let Some(w) = s.mod_inv(&curve.n) else {
        return false;
    };
    let u1 = z.mod_mul(&w, &curve.n);
    let u2 = r.mod_mul(&w, &curve.n);
    let q = JacobianPoint::from_affine(qx, qy);
    let Some((rx, _)) = curve.lincomb_g_q(&u1, &q, &u2).to_affine(curve) else {
        return false;
    };
    rx.rem_mod(&curve.n) == r
}

/// Verify `ecdsa_secp256r1_sha256` (`0x0403`) or X.509 `ecdsa-with-SHA256` on P-256.
pub fn p256_ecdsa_verify_sha256(pub_point: &[u8], msg: &[u8], der_sig: &[u8]) -> bool {
    let digest = Sha256::digest(msg);
    ecdsa_verify_curve(&p256_curve(), pub_point, &digest, der_sig)
}

/// Verify `ecdsa_secp256r1` with SHA-384 (occasional cross-hash X.509 certs).
pub fn p256_ecdsa_verify_sha384(pub_point: &[u8], msg: &[u8], der_sig: &[u8]) -> bool {
    let digest = Sha384::digest(msg);
    ecdsa_verify_curve(&p256_curve(), pub_point, &digest, der_sig)
}

/// Verify `ecdsa_secp384r1_sha384` (`0x0503`) or X.509 `ecdsa-with-SHA384` on P-384.
pub fn p384_ecdsa_verify_sha384(pub_point: &[u8], msg: &[u8], der_sig: &[u8]) -> bool {
    let digest = Sha384::digest(msg);
    ecdsa_verify_curve(&p384_curve(), pub_point, &digest, der_sig)
}

/// Verify `ecdsa_secp384r1` with SHA-256 (used by some intermediate CAs).
pub fn p384_ecdsa_verify_sha256(pub_point: &[u8], msg: &[u8], der_sig: &[u8]) -> bool {
    let digest = Sha256::digest(msg);
    ecdsa_verify_curve(&p384_curve(), pub_point, &digest, der_sig)
}

// ---------------------------------------------------------------------------
// RSA Public-Key Verification (PKCS#1 v1.5 & EMSA-PSS, 1024..=8192 bits)
// ---------------------------------------------------------------------------

fn mgf1(hash_alg: HashAlg, seed: &[u8], mask_len: usize) -> Vec<u8> {
    let h_len = hash_alg.out_len();
    let mut out = Vec::with_capacity(mask_len + h_len);
    let mut counter = 0u32;
    while out.len() < mask_len {
        let mut input = Vec::with_capacity(seed.len() + 4);
        input.extend_from_slice(seed);
        input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&hash_alg.digest(&input));
        counter = counter.wrapping_add(1);
    }
    out.truncate(mask_len);
    out
}

fn rsa_raw_public_op(
    modulus_be: &[u8],
    exponent_be: &[u8],
    sig: &[u8],
) -> Option<(usize, Vec<u8>)> {
    let n = BigUint::from_be_bytes(modulus_be);
    let e = BigUint::from_be_bytes(exponent_be);
    let mod_bits = n.bit_len();
    if !(1024..=8192).contains(&mod_bits) || !n.is_odd() || e.bit_len() < 2 || !e.is_odd() {
        return None;
    }
    let k = (mod_bits + 7) / 8;
    if sig.len() != k {
        return None;
    }
    let s = BigUint::from_be_bytes(sig);
    if s.cmp_val(&n) != Ordering::Less {
        return None;
    }
    let m = s.mod_pow(&e, &n);
    Some((mod_bits, m.to_be_bytes_padded(k)))
}

/// Verify RSA PKCS#1 v1.5 signature (`rsa_pkcs1_sha256` / `rsa_pkcs1_sha384`).
pub fn rsa_verify_pkcs1_v15(
    modulus_be: &[u8],
    exponent_be: &[u8],
    hash_alg: HashAlg,
    msg: &[u8],
    sig: &[u8],
) -> bool {
    let Some((_mod_bits, em)) = rsa_raw_public_op(modulus_be, exponent_be, sig) else {
        return false;
    };
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let mut sep_idx = None;
    for (i, &b) in em.iter().enumerate().skip(2) {
        if b == 0x00 {
            sep_idx = Some(i);
            break;
        }
        if b != 0xFF {
            return false;
        }
    }
    let Some(sep) = sep_idx else {
        return false;
    };
    if sep < 10 {
        return false; // At least 8 0xFF padding bytes required by RFC 8017 §9.2
    }
    let digest_info = &em[sep + 1..];
    let digest = hash_alg.digest(msg);

    let (prefix_with_null, prefix_no_null): (&[u8], &[u8]) = match hash_alg {
        HashAlg::Sha256 => (
            &[
                0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            &[
                0x30, 0x2F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x04, 0x20,
            ],
        ),
        HashAlg::Sha384 => (
            &[
                0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            &[
                0x30, 0x3F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x04, 0x30,
            ],
        ),
        HashAlg::Sha512 => (
            &[
                0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
            &[
                0x30, 0x4F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x04, 0x40,
            ],
        ),
    };

    for prefix in [prefix_with_null, prefix_no_null] {
        if digest_info.len() == prefix.len() + digest.len()
            && digest_info.starts_with(prefix)
            && ct_eq_slices(&digest_info[prefix.len()..], &digest)
        {
            return true;
        }
    }
    false
}

/// Verify RSA-PSS signature (`rsa_pss_rsae_sha256` / `rsa_pss_rsae_sha384`).
pub fn rsa_verify_pss(
    modulus_be: &[u8],
    exponent_be: &[u8],
    hash_alg: HashAlg,
    msg: &[u8],
    sig: &[u8],
    require_hlen_salt: bool,
) -> bool {
    let Some((mod_bits, full_em)) = rsa_raw_public_op(modulus_be, exponent_be, sig) else {
        return false;
    };
    let em_bits = mod_bits - 1;
    let em_len = (em_bits + 7) / 8;
    let k = full_em.len();
    if em_len < k {
        if full_em[..k - em_len].iter().any(|&b| b != 0) {
            return false;
        }
    }
    let em = &full_em[k - em_len..];
    let h_len = hash_alg.out_len();
    if em_len < h_len + 2 || em[em_len - 1] != 0xBC {
        return false;
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..em_len - 1];

    let top_zero_bits = 8 * em_len - em_bits;
    if top_zero_bits > 0 {
        let top_mask = 0xFFu8 << (8 - top_zero_bits);
        if (masked_db[0] & top_mask) != 0 {
            return false;
        }
    }

    let db_mask = mgf1(hash_alg, h, db_len);
    let mut db = Vec::with_capacity(db_len);
    for i in 0..db_len {
        db.push(masked_db[i] ^ db_mask[i]);
    }
    if top_zero_bits > 0 {
        db[0] &= 0xFFu8 >> top_zero_bits;
    }

    let Some(sep_pos) = db.iter().position(|&b| b != 0) else {
        return false;
    };
    if db[sep_pos] != 0x01 {
        return false;
    }
    let salt = &db[sep_pos + 1..];
    if require_hlen_salt && salt.len() != h_len {
        return false;
    }

    let m_hash = hash_alg.digest(msg);
    let mut m_prime = Vec::with_capacity(8 + h_len + salt.len());
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(&m_hash);
    m_prime.extend_from_slice(salt);
    let h_prime = hash_alg.digest(&m_prime);
    ct_eq_slices(h, &h_prime)
}
