//! RFC 5280 X.509v3 DER/PEM certificate parsing, SubjectAltName hostname/IP
//! verification, and TrustStore chain validation.

use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::{
    ed25519_verify, p256_ecdsa_verify_sha256, p256_ecdsa_verify_sha384, p384_ecdsa_verify_sha256,
    p384_ecdsa_verify_sha384, rsa_verify_pkcs1_v15, rsa_verify_pss, HashAlg,
};

const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_RSASSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
const OID_RSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_RSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
const OID_RSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];

const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_SECP256R1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const OID_EXT_SAN: &[u8] = &[0x55, 0x1D, 0x11];
const OID_EXT_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];

/// Public key extracted from an X.509 `SubjectPublicKeyInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectPublicKey {
    Rsa {
        modulus_be: Vec<u8>,
        exponent_be: Vec<u8>,
    },
    EcP256(Vec<u8>),
    EcP384(Vec<u8>),
    Ed25519([u8; 32]),
}

impl SubjectPublicKey {
    /// Verify a TLS 1.3 `CertificateVerify` signature (`SignatureScheme` u16).
    pub fn verify_tls13_sig(&self, scheme: u16, msg: &[u8], sig: &[u8]) -> bool {
        match (self, scheme) {
            (Self::Ed25519(pk), 0x0807) => ed25519_verify(pk, msg, sig),
            (Self::EcP256(pt), 0x0403) => p256_ecdsa_verify_sha256(pt, msg, sig),
            (Self::EcP384(pt), 0x0503) => p384_ecdsa_verify_sha384(pt, msg, sig),
            (
                Self::Rsa {
                    modulus_be,
                    exponent_be,
                },
                0x0804,
            ) => rsa_verify_pss(modulus_be, exponent_be, HashAlg::Sha256, msg, sig, true),
            (
                Self::Rsa {
                    modulus_be,
                    exponent_be,
                },
                0x0805,
            ) => rsa_verify_pss(modulus_be, exponent_be, HashAlg::Sha384, msg, sig, true),
            (
                Self::Rsa {
                    modulus_be,
                    exponent_be,
                },
                0x0806,
            ) => rsa_verify_pss(modulus_be, exponent_be, HashAlg::Sha512, msg, sig, true),
            _ => false,
        }
    }

    /// Verify an X.509 certificate signature (`CertSigAlg`).
    pub fn verify_x509_sig(&self, alg: CertSigAlg, tbs_der: &[u8], sig: &[u8]) -> bool {
        match (self, alg) {
            (Self::Ed25519(pk), CertSigAlg::Ed25519) => ed25519_verify(pk, tbs_der, sig),
            (Self::EcP256(pt), CertSigAlg::EcdsaSha256) => {
                p256_ecdsa_verify_sha256(pt, tbs_der, sig)
            }
            (Self::EcP256(pt), CertSigAlg::EcdsaSha384) => {
                p256_ecdsa_verify_sha384(pt, tbs_der, sig)
            }
            (Self::EcP384(pt), CertSigAlg::EcdsaSha384) => {
                p384_ecdsa_verify_sha384(pt, tbs_der, sig)
            }
            (Self::EcP384(pt), CertSigAlg::EcdsaSha256) => {
                p384_ecdsa_verify_sha256(pt, tbs_der, sig)
            }
            (
                Self::Rsa {
                    modulus_be,
                    exponent_be,
                },
                CertSigAlg::RsaPkcs1(hash),
            ) => rsa_verify_pkcs1_v15(modulus_be, exponent_be, hash, tbs_der, sig),
            (
                Self::Rsa {
                    modulus_be,
                    exponent_be,
                },
                CertSigAlg::RsaPss(hash),
            ) => rsa_verify_pss(modulus_be, exponent_be, hash, tbs_der, sig, false),
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertSigAlg {
    RsaPkcs1(HashAlg),
    RsaPss(HashAlg),
    EcdsaSha256,
    EcdsaSha384,
    Ed25519,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X509Error {
    EmptyChain,
    MalformedDer,
    InvalidPem,
    UnsupportedAlgorithm,
    CertificateExpired,
    CertificateNotYetValid,
    HostnameMismatch,
    BasicConstraintsViolation,
    IssuerMismatch,
    InvalidSignature,
    UntrustedRoot,
    ChainTooLong,
}

#[derive(Clone, Debug)]
pub enum SanEntry {
    DnsName(String),
    IpV4([u8; 4]),
}

/// Parsed X.509v3 certificate view.
#[derive(Clone, Debug)]
pub struct ParsedCertificate {
    pub raw_der: Vec<u8>,
    pub tbs_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub subject_der: Vec<u8>,
    pub common_name: Option<String>,
    pub not_before: u64,
    pub not_after: u64,
    pub public_key: SubjectPublicKey,
    pub sig_alg: Option<CertSigAlg>,
    pub sig_val: Vec<u8>,
    pub san_entries: Vec<SanEntry>,
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
    pub key_cert_sign: Option<bool>,
}

/// Trusted root CA anchor.
#[derive(Clone, Debug)]
pub struct TrustAnchor {
    pub subject_der: Vec<u8>,
    pub public_key: SubjectPublicKey,
    pub raw_der: Vec<u8>,
}

/// Collection of trusted X.509 root CA certificates (e.g., `/etc/ssl/certs.pem`).
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    anchors: Vec<TrustAnchor>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Parse a PEM bundle (`-----BEGIN CERTIFICATE-----`) into a `TrustStore`.
    ///
    /// Anchors using legacy/unsupported curves (such as `secp521r1`) are skipped
    /// cleanly so standard WebPKI bundles load cleanly; fails only if no usable
    /// trust anchors exist in `pem_bytes`.
    pub fn from_pem_bytes(pem_bytes: &[u8]) -> Result<Self, X509Error> {
        let ders = decode_pem_certificates(pem_bytes)?;
        if ders.is_empty() {
            return Err(X509Error::InvalidPem);
        }
        let mut store = Self::new();
        for der in ders {
            if let Ok(cert) = parse_x509_der(&der, true) {
                store.anchors.push(TrustAnchor {
                    subject_der: cert.subject_der,
                    public_key: cert.public_key,
                    raw_der: der,
                });
            }
        }
        if store.anchors.is_empty() {
            return Err(X509Error::UnsupportedAlgorithm);
        }
        Ok(store)
    }

    /// Add a single DER-encoded trust anchor certificate.
    pub fn add_der_certificate(&mut self, der: &[u8]) -> Result<(), X509Error> {
        let cert = parse_x509_der(der, true)?;
        self.anchors.push(TrustAnchor {
            subject_der: cert.subject_der,
            public_key: cert.public_key,
            raw_der: der.to_vec(),
        });
        Ok(())
    }

    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }
}

/// Decode one or more `-----BEGIN CERTIFICATE-----` blocks from PEM text.
pub fn decode_pem_certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>, X509Error> {
    let text = core::str::from_utf8(pem).map_err(|_| X509Error::InvalidPem)?;
    let mut out = Vec::new();
    let mut in_cert = false;
    let mut b64_buf = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64_buf.clear();
        } else if line == "-----END CERTIFICATE-----" {
            if !in_cert {
                return Err(X509Error::InvalidPem);
            }
            in_cert = false;
            let der = base64_decode(&b64_buf).ok_or(X509Error::InvalidPem)?;
            if !der.is_empty() {
                out.push(der);
            }
            b64_buf.clear();
        } else if in_cert {
            for &b in line.as_bytes() {
                if !b.is_ascii_whitespace() {
                    b64_buf.push(b);
                }
            }
        }
    }
    if in_cert {
        return Err(X509Error::InvalidPem);
    }
    Ok(out)
}

fn base64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(src: &[u8]) -> Option<Vec<u8>> {
    if !src.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity((src.len() / 4) * 3);
    let mut i = 0usize;
    while i < src.len() {
        let c0 = base64_val(src[i])?;
        let c1 = base64_val(src[i + 1])?;
        let pad2 = src[i + 2] == b'=';
        let pad3 = src[i + 3] == b'=';
        if pad2 && !pad3 {
            return None;
        }
        if (pad2 || pad3) && i + 4 != src.len() {
            return None;
        }
        let c2 = if pad2 { 0 } else { base64_val(src[i + 2])? };
        let c3 = if pad3 { 0 } else { base64_val(src[i + 3])? };

        let triple =
            (u32::from(c0) << 18) | (u32::from(c1) << 12) | (u32::from(c2) << 6) | u32::from(c3);
        out.push((triple >> 16) as u8);
        if !pad2 {
            out.push((triple >> 8) as u8);
        }
        if !pad3 {
            out.push(triple as u8);
        }
        i += 4;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// ASN.1 DER Reader
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn read_tlv(&mut self) -> Option<(u8, &'a [u8], &'a [u8])> {
        let start = self.pos;
        let tag = *self.buf.get(self.pos)?;
        self.pos += 1;
        let first_len = *self.buf.get(self.pos)?;
        self.pos += 1;
        let len = if (first_len & 0x80) == 0 {
            usize::from(first_len)
        } else {
            let count = usize::from(first_len & 0x7F);
            if count == 0 || count > 4 || self.pos + count > self.buf.len() {
                return None;
            }
            let mut v = 0usize;
            for &b in &self.buf[self.pos..self.pos + count] {
                v = (v << 8) | usize::from(b);
            }
            self.pos += count;
            v
        };
        if self.pos.checked_add(len)? > self.buf.len() {
            return None;
        }
        let val = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        let full = &self.buf[start..self.pos];
        Some((tag, val, full))
    }

    fn read_expected(&mut self, expected_tag: u8) -> Option<(&'a [u8], &'a [u8])> {
        let (tag, val, full) = self.read_tlv()?;
        if tag != expected_tag {
            return None;
        }
        Some((val, full))
    }

    fn read_bit_string(&mut self) -> Option<(u8, &'a [u8])> {
        let (val, _) = self.read_expected(0x03)?;
        let unused_bits = *val.first()?;
        if unused_bits > 7 {
            return None;
        }
        Some((unused_bits, &val[1..]))
    }

    fn read_uint_bytes(&mut self) -> Option<&'a [u8]> {
        let (val, _) = self.read_expected(0x02)?;
        if val.is_empty() || (val[0] & 0x80) != 0 {
            return None;
        }
        let stripped = if val.len() > 1 && val[0] == 0 {
            &val[1..]
        } else {
            val
        };
        Some(stripped)
    }
}

fn parse_sig_alg(alg_seq_val: &[u8]) -> Option<CertSigAlg> {
    let mut r = DerReader::new(alg_seq_val);
    let (oid, _) = r.read_expected(0x06)?;
    match oid {
        OID_RSA_SHA256 => Some(CertSigAlg::RsaPkcs1(HashAlg::Sha256)),
        OID_RSA_SHA384 => Some(CertSigAlg::RsaPkcs1(HashAlg::Sha384)),
        OID_RSA_SHA512 => Some(CertSigAlg::RsaPkcs1(HashAlg::Sha512)),
        OID_ECDSA_SHA256 => Some(CertSigAlg::EcdsaSha256),
        OID_ECDSA_SHA384 => Some(CertSigAlg::EcdsaSha384),
        OID_ED25519 => Some(CertSigAlg::Ed25519),
        OID_RSASSA_PSS => {
            // RSASSA-PSS-params ::= SEQUENCE { [0] HashAlgorithm, ... }
            let (params_seq, _) = r.read_expected(0x30)?;
            let mut pr = DerReader::new(params_seq);
            let mut hash_alg = None;
            while !pr.is_empty() {
                let (tag, val, _) = pr.read_tlv()?;
                if tag == 0xA0 {
                    let mut hr = DerReader::new(val);
                    let (h_seq, _) = hr.read_expected(0x30)?;
                    let mut h_inner = DerReader::new(h_seq);
                    let (h_oid, _) = h_inner.read_expected(0x06)?;
                    hash_alg = match h_oid {
                        OID_SHA256 => Some(HashAlg::Sha256),
                        OID_SHA384 => Some(HashAlg::Sha384),
                        OID_SHA512 => Some(HashAlg::Sha512),
                        _ => None,
                    };
                }
            }
            Some(CertSigAlg::RsaPss(hash_alg?))
        }
        _ => None,
    }
}

fn parse_spki(spki_seq_val: &[u8]) -> Result<SubjectPublicKey, X509Error> {
    let mut r = DerReader::new(spki_seq_val);
    let (alg_seq, _) = r.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    let (unused, spk_bytes) = r.read_bit_string().ok_or(X509Error::MalformedDer)?;
    if unused != 0 {
        return Err(X509Error::MalformedDer);
    }

    let mut ar = DerReader::new(alg_seq);
    let (oid, _) = ar.read_expected(0x06).ok_or(X509Error::MalformedDer)?;

    if oid == OID_RSA_ENCRYPTION || oid == OID_RSASSA_PSS {
        let mut kr = DerReader::new(spk_bytes);
        let (rsa_seq, _) = kr.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
        let mut rr = DerReader::new(rsa_seq);
        let modulus = rr.read_uint_bytes().ok_or(X509Error::MalformedDer)?;
        let exponent = rr.read_uint_bytes().ok_or(X509Error::MalformedDer)?;
        if modulus.len() < 128 || exponent.is_empty() {
            return Err(X509Error::UnsupportedAlgorithm);
        }
        Ok(SubjectPublicKey::Rsa {
            modulus_be: modulus.to_vec(),
            exponent_be: exponent.to_vec(),
        })
    } else if oid == OID_EC_PUBLIC_KEY {
        let (curve_oid, _) = ar
            .read_expected(0x06)
            .ok_or(X509Error::UnsupportedAlgorithm)?;
        if curve_oid == OID_SECP256R1 {
            if spk_bytes.len() != 65 || spk_bytes[0] != 0x04 {
                return Err(X509Error::MalformedDer);
            }
            Ok(SubjectPublicKey::EcP256(spk_bytes.to_vec()))
        } else if curve_oid == OID_SECP384R1 {
            if spk_bytes.len() != 97 || spk_bytes[0] != 0x04 {
                return Err(X509Error::MalformedDer);
            }
            Ok(SubjectPublicKey::EcP384(spk_bytes.to_vec()))
        } else {
            Err(X509Error::UnsupportedAlgorithm)
        }
    } else if oid == OID_ED25519 {
        if spk_bytes.len() != 32 {
            return Err(X509Error::MalformedDer);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(spk_bytes);
        Ok(SubjectPublicKey::Ed25519(pk))
    } else {
        Err(X509Error::UnsupportedAlgorithm)
    }
}

fn parse_digits(slice: &[u8]) -> Option<u32> {
    let mut v = 0u32;
    for &b in slice {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(v)
}

fn is_leap_year(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn ymd_hms_to_unix(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<u64> {
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days_in_months = [
        31u32,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let max_day = days_in_months[(month - 1) as usize];
    if day < 1 || day > max_day {
        return None;
    }
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for &dim in days_in_months.iter().take((month - 1) as usize) {
        days += u64::from(dim);
    }
    days += u64::from(day - 1);
    Some(days * 86_400 + u64::from(hour) * 3_600 + u64::from(min) * 60 + u64::from(sec.min(59)))
}

fn parse_asn1_time(tag: u8, val: &[u8]) -> Option<u64> {
    match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ
            if val.len() != 13 || val[12] != b'Z' {
                return None;
            }
            let yy = parse_digits(&val[0..2])?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            let month = parse_digits(&val[2..4])?;
            let day = parse_digits(&val[4..6])?;
            let hour = parse_digits(&val[6..8])?;
            let min = parse_digits(&val[8..10])?;
            let sec = parse_digits(&val[10..12])?;
            ymd_hms_to_unix(year, month, day, hour, min, sec)
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            if val.len() != 15 || val[14] != b'Z' {
                return None;
            }
            let year = parse_digits(&val[0..4])?;
            let month = parse_digits(&val[4..6])?;
            let day = parse_digits(&val[6..8])?;
            let hour = parse_digits(&val[8..10])?;
            let min = parse_digits(&val[10..12])?;
            let sec = parse_digits(&val[12..14])?;
            ymd_hms_to_unix(year, month, day, hour, min, sec)
        }
        _ => None,
    }
}

fn extract_common_name(name_seq_val: &[u8]) -> Option<String> {
    let mut r = DerReader::new(name_seq_val);
    while !r.is_empty() {
        let (rdn_set, _) = r.read_expected(0x31)?;
        let mut sr = DerReader::new(rdn_set);
        while !sr.is_empty() {
            let (atv_seq, _) = sr.read_expected(0x30)?;
            let mut ar = DerReader::new(atv_seq);
            let (oid, _) = ar.read_expected(0x06)?;
            let (_vtag, vbytes, _) = ar.read_tlv()?;
            if oid == OID_COMMON_NAME {
                if let Ok(s) = core::str::from_utf8(vbytes) {
                    return Some(String::from(s));
                }
            }
        }
    }
    None
}

/// Parse an X.509v3 DER certificate.
///
/// When `allow_unknown_sig_alg` is `true` (used for self-signed root anchors),
/// certificates with legacy self-signature OIDs (such as 1999 SHA-1 roots) still
/// parse their `subject` and `subjectPublicKeyInfo`.
pub fn parse_x509_der(
    der: &[u8],
    allow_unknown_sig_alg: bool,
) -> Result<ParsedCertificate, X509Error> {
    let mut top = DerReader::new(der);
    let (cert_seq, _) = top.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    if !top.is_empty() {
        return Err(X509Error::MalformedDer);
    }

    let mut cr = DerReader::new(cert_seq);
    let (tbs_val, tbs_full) = cr.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    let (sig_alg_val, _) = cr.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    let (sig_unused, sig_bytes) = cr.read_bit_string().ok_or(X509Error::MalformedDer)?;
    if sig_unused != 0 || !cr.is_empty() {
        return Err(X509Error::MalformedDer);
    }

    let sig_alg = parse_sig_alg(sig_alg_val);
    if sig_alg.is_none() && !allow_unknown_sig_alg {
        return Err(X509Error::UnsupportedAlgorithm);
    }

    let mut tr = DerReader::new(tbs_val);
    // Optional [0] EXPLICIT Version
    if tr.peek_tag() == Some(0xA0) {
        let _ = tr.read_tlv().ok_or(X509Error::MalformedDer)?;
    }
    // serialNumber INTEGER
    let (st, _, _) = tr.read_tlv().ok_or(X509Error::MalformedDer)?;
    if st != 0x02 {
        return Err(X509Error::MalformedDer);
    }
    // signature AlgorithmIdentifier
    let _ = tr.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    // issuer Name (preserve full TLV for byte-exact issuer==subject check)
    let (_, issuer_full) = tr.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    // validity SEQUENCE { notBefore, notAfter }
    let (val_seq, _) = tr.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    let mut vr = DerReader::new(val_seq);
    let (nb_tag, nb_val, _) = vr.read_tlv().ok_or(X509Error::MalformedDer)?;
    let (na_tag, na_val, _) = vr.read_tlv().ok_or(X509Error::MalformedDer)?;
    let not_before = parse_asn1_time(nb_tag, nb_val).unwrap_or(0);
    let not_after = parse_asn1_time(na_tag, na_val).unwrap_or(u64::MAX);

    // subject Name
    let (subj_val, subj_full) = tr.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    let common_name = extract_common_name(subj_val);

    // subjectPublicKeyInfo
    let (spki_val, _) = tr.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
    let public_key = parse_spki(spki_val)?;

    let mut san_entries = Vec::new();
    let mut is_ca = false;
    let mut path_len_constraint = None;
    let mut key_cert_sign = None;

    while !tr.is_empty() {
        let (tag, val, _) = tr.read_tlv().ok_or(X509Error::MalformedDer)?;
        if tag == 0xA3 {
            // Extensions ::= SEQUENCE OF Extension
            let mut er_outer = DerReader::new(val);
            let (exts_seq, _) = er_outer
                .read_expected(0x30)
                .ok_or(X509Error::MalformedDer)?;
            let mut exts = DerReader::new(exts_seq);
            while !exts.is_empty() {
                let (ext_seq, _) = exts.read_expected(0x30).ok_or(X509Error::MalformedDer)?;
                let mut ext = DerReader::new(ext_seq);
                let (ext_oid, _) = ext.read_expected(0x06).ok_or(X509Error::MalformedDer)?;
                if ext.peek_tag() == Some(0x01) {
                    let _ = ext.read_tlv().ok_or(X509Error::MalformedDer)?;
                }
                let (ext_val, _) = ext.read_expected(0x04).ok_or(X509Error::MalformedDer)?;

                if ext_oid == OID_EXT_SAN {
                    let mut san_outer = DerReader::new(ext_val);
                    let (san_seq, _) = san_outer
                        .read_expected(0x30)
                        .ok_or(X509Error::MalformedDer)?;
                    let mut san = DerReader::new(san_seq);
                    while !san.is_empty() {
                        let (gn_tag, gn_val, _) = san.read_tlv().ok_or(X509Error::MalformedDer)?;
                        if gn_tag == 0x82 {
                            if let Ok(dns) = core::str::from_utf8(gn_val) {
                                san_entries.push(SanEntry::DnsName(String::from(dns)));
                            }
                        } else if gn_tag == 0x87 && gn_val.len() == 4 {
                            let mut ip = [0u8; 4];
                            ip.copy_from_slice(gn_val);
                            san_entries.push(SanEntry::IpV4(ip));
                        }
                    }
                } else if ext_oid == OID_EXT_BASIC_CONSTRAINTS {
                    let mut bc_outer = DerReader::new(ext_val);
                    let (bc_seq, _) = bc_outer
                        .read_expected(0x30)
                        .ok_or(X509Error::MalformedDer)?;
                    let mut bc = DerReader::new(bc_seq);
                    if bc.peek_tag() == Some(0x01) {
                        let (bval, _) = bc.read_expected(0x01).ok_or(X509Error::MalformedDer)?;
                        is_ca = !bval.is_empty() && bval[0] != 0;
                    }
                    if bc.peek_tag() == Some(0x02) {
                        if let Some(pbytes) = bc.read_uint_bytes() {
                            if pbytes.len() <= 4 {
                                let mut pv = 0u32;
                                for &b in pbytes {
                                    pv = (pv << 8) | u32::from(b);
                                }
                                path_len_constraint = Some(pv);
                            }
                        }
                    }
                } else if ext_oid == OID_EXT_KEY_USAGE {
                    let mut ku = DerReader::new(ext_val);
                    if let Some((_unused, bits)) = ku.read_bit_string() {
                        if let Some(&b0) = bits.first() {
                            // keyCertSign is bit 5 (0x04 in ASN.1 MSB-first BIT STRING).
                            key_cert_sign = Some((b0 & 0x04) != 0);
                        }
                    }
                }
            }
        }
    }

    Ok(ParsedCertificate {
        raw_der: der.to_vec(),
        tbs_der: tbs_full.to_vec(),
        issuer_der: issuer_full.to_vec(),
        subject_der: subj_full.to_vec(),
        common_name,
        not_before,
        not_after,
        public_key,
        sig_alg,
        sig_val: sig_bytes.to_vec(),
        san_entries,
        is_ca,
        path_len_constraint,
        key_cert_sign,
    })
}

fn parse_ipv4_literal(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for part in s.split('.') {
        if count >= 4 || part.is_empty() {
            return None;
        }
        let val = part.parse::<u8>().ok()?;
        octets[count] = val;
        count += 1;
    }
    if count == 4 {
        Some(octets)
    } else {
        None
    }
}

/// RFC 6125 DNS hostname matching (exact case-insensitive or leftmost `*.domain.tld`).
pub fn dns_pattern_matches(pattern: &str, host: &str) -> bool {
    let pat = pattern.trim_end_matches('.');
    let h = host.trim_end_matches('.');
    if pat.is_empty() || h.is_empty() || parse_ipv4_literal(h).is_some() {
        return false;
    }
    if let Some(suffix) = pat.strip_prefix("*.") {
        // Wildcard must cover at least a two-label suffix (`*.example.com`) and
        // match exactly one leftmost label in `host`.
        if !suffix.contains('.') || suffix.contains('*') {
            return false;
        }
        let Some((left_label, rest)) = h.split_once('.') else {
            return false;
        };
        !left_label.is_empty() && rest.eq_ignore_ascii_case(suffix)
    } else {
        pat.eq_ignore_ascii_case(h)
    }
}

/// Verify leaf `SubjectAltName` (or `CommonName` fallback) against `server_name`.
pub fn verify_leaf_identity(cert: &ParsedCertificate, server_name: &str) -> bool {
    if let Some(target_ip) = parse_ipv4_literal(server_name) {
        return cert
            .san_entries
            .iter()
            .any(|e| matches!(e, SanEntry::IpV4(ip) if *ip == target_ip));
    }
    if !cert.san_entries.is_empty() {
        return cert.san_entries.iter().any(|e| match e {
            SanEntry::DnsName(pat) => dns_pattern_matches(pat, server_name),
            SanEntry::IpV4(_) => false,
        });
    }
    match cert.common_name.as_deref() {
        Some(cn) => dns_pattern_matches(cn, server_name),
        None => false,
    }
}

/// Validate an X.509 certificate chain (`chain_der[0]` = server leaf) against `trust_store`.
///
/// Returns the leaf certificate's `SubjectPublicKey` for TLS 1.3 `CertificateVerify`.
pub fn verify_server_cert_chain(
    chain_der: &[Vec<u8>],
    server_name: &str,
    now_unix_secs: Option<u64>,
    trust_store: &TrustStore,
) -> Result<SubjectPublicKey, X509Error> {
    if chain_der.is_empty() {
        return Err(X509Error::EmptyChain);
    }
    if chain_der.len() > 10 {
        return Err(X509Error::ChainTooLong);
    }

    let mut certs = Vec::with_capacity(chain_der.len());
    for (idx, der) in chain_der.iter().enumerate() {
        // Allow root-at-end of server chain to have legacy self-sig OID if anchored directly.
        let cert = parse_x509_der(der, idx > 0)?;
        if let Some(now) = now_unix_secs {
            if now > 0 {
                if now < cert.not_before {
                    return Err(X509Error::CertificateNotYetValid);
                }
                if now > cert.not_after {
                    return Err(X509Error::CertificateExpired);
                }
            }
        }
        certs.push(cert);
    }

    if !verify_leaf_identity(&certs[0], server_name) {
        return Err(X509Error::HostnameMismatch);
    }

    // Walk from leaf (`i = 0`) up to a trusted root anchor in `trust_store`.
    for i in 0..certs.len() {
        let cur = &certs[i];

        // 1. Direct match: `cur` itself is byte-identical to a trust anchor in `trust_store`.
        if trust_store
            .anchors()
            .iter()
            .any(|a| a.raw_der == cur.raw_der)
        {
            return Ok(certs[0].public_key.clone());
        }

        // 2. Signed by a trust anchor in `trust_store` whose `subject == cur.issuer`.
        if let Some(sig_alg) = cur.sig_alg {
            for anchor in trust_store.anchors() {
                if anchor.subject_der == cur.issuer_der
                    && anchor
                        .public_key
                        .verify_x509_sig(sig_alg, &cur.tbs_der, &cur.sig_val)
                {
                    return Ok(certs[0].public_key.clone());
                }
            }
        }

        // 3. Otherwise, `cur` must be signed by `certs[i + 1]` in the presented chain.
        let Some(issuer_cert) = certs.get(i + 1) else {
            return Err(X509Error::UntrustedRoot);
        };
        if !issuer_cert.is_ca || issuer_cert.key_cert_sign == Some(false) {
            return Err(X509Error::BasicConstraintsViolation);
        }
        if let Some(max_path) = issuer_cert.path_len_constraint {
            let subordinate_cas = i as u32;
            if subordinate_cas > max_path {
                return Err(X509Error::BasicConstraintsViolation);
            }
        }
        if cur.issuer_der != issuer_cert.subject_der {
            return Err(X509Error::IssuerMismatch);
        }
        let sig_alg = cur.sig_alg.ok_or(X509Error::UnsupportedAlgorithm)?;
        if !issuer_cert
            .public_key
            .verify_x509_sig(sig_alg, &cur.tbs_der, &cur.sig_val)
        {
            return Err(X509Error::InvalidSignature);
        }
    }

    Err(X509Error::UntrustedRoot)
}
