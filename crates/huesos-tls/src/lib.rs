//! `huesos-tls` — Pure-Rust `#![no_std]` RFC 8446 TLS 1.3 + RFC 5280 X.509v3 client.
//!
//! Designed for HuesOS userspace HTTPS clients (`/bin/curl.elf`, Win64 TLS shims)
//! with zero `unsafe` code (`#![forbid(unsafe_code)]`) and deterministic host tests.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod crypto;
pub mod x509;

use alloc::vec::Vec;
use core::fmt;

use crypto::{
    compute_finished_verify_data, ct_eq_slices, derive_secret_with_hash, hkdf_extract,
    p256_diffie_hellman, p256_public_key, x25519_diffie_hellman, x25519_public_key, CipherSuite,
    TrafficCipher,
};
use x509::{parse_x509_der, verify_server_cert_chain};
pub use x509::{TrustStore, X509Error};

/// RFC 8446 §4.1.3 special `ServerHello.random` sentinel indicating `HelloRetryRequest`.
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_REQUEST: u8 = 13;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_KEY_UPDATE: u8 = 24;
const HS_MESSAGE_HASH: u8 = 254;

const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_X25519: u16 = 0x001D;

/// Byte-stream transport underlying a `TlsStream`.
pub trait TlsTransport {
    type Error: fmt::Debug;

    /// Read up to `buf.len()` bytes; `Ok(0)` indicates clean transport EOF.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write all bytes in `buf` to the underlying transport.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
}

/// Certificate verification policy for a TLS 1.3 client connection.
#[derive(Clone, Copy)]
pub enum VerifyMode<'a> {
    /// Full RFC 5280 X.509v3 chain + SAN hostname/IP verification against `TrustStore`.
    Strict(&'a TrustStore),
    /// Skip CA chain & hostname check (`curl -k` / `--insecure`); still verifies
    /// the live TLS 1.3 `CertificateVerify` proof-of-possession signature.
    InsecureSkipVerify,
}

/// Client configuration for `TlsStream::connect`.
#[derive(Clone, Copy)]
pub struct TlsClientConfig<'a> {
    pub verify_mode: VerifyMode<'a>,
    pub now_unix_secs: Option<u64>,
    pub alpn_protocol: Option<&'a [u8]>,
}

/// Errors produced by `huesos-tls`.
#[derive(Debug)]
pub enum TlsError<E> {
    Transport(E),
    UnexpectedEof,
    RecordTooLarge,
    DecryptionFailed,
    AlertReceived { level: u8, description: u8 },
    ProtocolViolation(&'static str),
    UnsupportedVersion,
    UnsupportedCipherSuite,
    KeyExchangeFailed,
    CertificateValidation(X509Error),
    InvalidCertificateVerify,
    InvalidServerFinished,
    CryptoFailure,
}

impl<E: fmt::Display> fmt::Display for TlsError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::UnexpectedEof => write!(f, "unexpected EOF during TLS session"),
            Self::RecordTooLarge => write!(f, "TLS record exceeds maximum length"),
            Self::DecryptionFailed => write!(f, "TLS 1.3 AEAD record authentication failed"),
            Self::AlertReceived { level, description } => {
                write!(f, "peer sent TLS alert (level={level}, code={description})")
            }
            Self::ProtocolViolation(msg) => write!(f, "TLS protocol error: {msg}"),
            Self::UnsupportedVersion => write!(f, "server did not negotiate TLS 1.3"),
            Self::UnsupportedCipherSuite => write!(f, "server selected unsupported cipher suite"),
            Self::KeyExchangeFailed => write!(f, "TLS 1.3 ECDHE key exchange failed"),
            Self::CertificateValidation(err) => write!(f, "X.509 certificate rejected: {err:?}"),
            Self::InvalidCertificateVerify => {
                write!(f, "server TLS 1.3 CertificateVerify signature invalid")
            }
            Self::InvalidServerFinished => write!(f, "server TLS 1.3 Finished MAC invalid"),
            Self::CryptoFailure => write!(f, "internal TLS cryptographic state error"),
        }
    }
}

/// Established TLS 1.3 client stream over transport `T`.
pub struct TlsStream<T> {
    transport: T,
    read_cipher: TrafficCipher,
    write_cipher: TrafficCipher,
    app_rx_buf: Vec<u8>,
    app_rx_pos: usize,
    post_hs_buf: Vec<u8>,
    peer_closed: bool,
    negotiated_suite: CipherSuite,
    negotiated_alpn: Option<Vec<u8>>,
}

impl<T: TlsTransport> TlsStream<T> {
    /// Perform a full TLS 1.3 client handshake with `server_name` over `transport`.
    ///
    /// `entropy` provides 128 bytes of fresh CSPRNG material (`[0..32]` ClientHello.random,
    /// `[32..64]` middlebox session_id, `[64..96]` X25519 ephemeral secret,
    /// `[96..128]` P-256 ephemeral secret).
    pub fn connect(
        mut transport: T,
        server_name: &str,
        entropy: [u8; 128],
        config: &TlsClientConfig<'_>,
    ) -> Result<Self, TlsError<T::Error>> {
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&entropy[0..32]);
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&entropy[32..64]);
        let mut x25519_sec = [0u8; 32];
        x25519_sec.copy_from_slice(&entropy[64..96]);
        let mut p256_seed = [0u8; 32];
        p256_seed.copy_from_slice(&entropy[96..128]);

        let x25519_pub = x25519_public_key(&x25519_sec);
        let (p256_scalar, p256_pub) = p256_public_key(&p256_seed).ok_or(TlsError::CryptoFailure)?;

        let mut transcript = Vec::with_capacity(4096);

        let ch1 = build_client_hello(
            &client_random,
            &session_id,
            server_name,
            Some(&x25519_pub),
            Some(&p256_pub),
            None,
            config.alpn_protocol,
        )?;
        transcript.extend_from_slice(&ch1);
        write_plaintext_record(&mut transport, CONTENT_HANDSHAKE, 0x0301, &ch1)?;

        // Read ServerHello (or HelloRetryRequest).
        let mut sh_msg = read_plaintext_server_hello(&mut transport)?;
        let mut parsed_sh = parse_server_hello(&sh_msg, &session_id)?;

        if parsed_sh.is_hello_retry_request {
            let suite = parsed_sh.suite;
            let ch1_hash = suite.hash_alg().digest(&transcript);
            transcript.clear();
            transcript.push(HS_MESSAGE_HASH);
            transcript.extend_from_slice(&[0x00, 0x00, ch1_hash.len() as u8]);
            transcript.extend_from_slice(&ch1_hash);
            transcript.extend_from_slice(&sh_msg);

            // Middlebox compatibility ChangeCipherSpec before ClientHello2.
            write_plaintext_record(&mut transport, CONTENT_CHANGE_CIPHER_SPEC, 0x0303, &[0x01])?;

            let (send_x25519, send_p256) = match parsed_sh.hrr_selected_group {
                Some(GROUP_X25519) => (Some(&x25519_pub), None),
                Some(GROUP_SECP256R1) => (None, Some(&p256_pub)),
                _ => (Some(&x25519_pub), Some(&p256_pub)),
            };
            let ch2 = build_client_hello(
                &client_random,
                &session_id,
                server_name,
                send_x25519,
                send_p256,
                parsed_sh.cookie.as_deref(),
                config.alpn_protocol,
            )?;
            transcript.extend_from_slice(&ch2);
            write_plaintext_record(&mut transport, CONTENT_HANDSHAKE, 0x0303, &ch2)?;

            sh_msg = read_plaintext_server_hello(&mut transport)?;
            parsed_sh = parse_server_hello(&sh_msg, &session_id)?;
            if parsed_sh.is_hello_retry_request || parsed_sh.suite != suite {
                return Err(TlsError::ProtocolViolation(
                    "invalid second ServerHello after HelloRetryRequest",
                ));
            }
        }

        transcript.extend_from_slice(&sh_msg);
        let suite = parsed_sh.suite;

        // Compute ECDHE shared secret.
        let shared_secret_vec: Vec<u8> = match parsed_sh.key_share_group {
            Some(GROUP_X25519) => {
                if parsed_sh.key_share_bytes.len() != 32 {
                    return Err(TlsError::KeyExchangeFailed);
                }
                let mut peer = [0u8; 32];
                peer.copy_from_slice(&parsed_sh.key_share_bytes);
                let ss =
                    x25519_diffie_hellman(&x25519_sec, &peer).ok_or(TlsError::KeyExchangeFailed)?;
                ss.to_vec()
            }
            Some(GROUP_SECP256R1) => {
                let ss = p256_diffie_hellman(&p256_scalar, &parsed_sh.key_share_bytes)
                    .ok_or(TlsError::KeyExchangeFailed)?;
                ss.to_vec()
            }
            _ => return Err(TlsError::KeyExchangeFailed),
        };

        // Derive Handshake Traffic Secrets (RFC 8446 §7.1).
        let hash_len = suite.hash_len();
        let zero_ikm = alloc::vec![0u8; hash_len];
        let early_secret = hkdf_extract(suite, &zero_ikm, &zero_ikm);
        let empty_hash = suite.hash_alg().digest(&[]);
        let derived_early = derive_secret_with_hash(suite, &early_secret, b"derived", &empty_hash)
            .ok_or(TlsError::CryptoFailure)?;
        let handshake_secret = hkdf_extract(suite, &derived_early, &shared_secret_vec);

        let ch_sh_hash = suite.hash_alg().digest(&transcript);
        let c_hs_traffic =
            derive_secret_with_hash(suite, &handshake_secret, b"c hs traffic", &ch_sh_hash)
                .ok_or(TlsError::CryptoFailure)?;
        let s_hs_traffic =
            derive_secret_with_hash(suite, &handshake_secret, b"s hs traffic", &ch_sh_hash)
                .ok_or(TlsError::CryptoFailure)?;

        let mut server_hs_cipher = TrafficCipher::from_traffic_secret(suite, &s_hs_traffic)
            .ok_or(TlsError::CryptoFailure)?;
        let mut client_hs_cipher = TrafficCipher::from_traffic_secret(suite, &c_hs_traffic)
            .ok_or(TlsError::CryptoFailure)?;

        // Read encrypted server handshake flight:
        // EncryptedExtensions -> [CertificateRequest] -> Certificate -> CertificateVerify -> Finished
        let mut hs_rx_buf = Vec::new();

        // 1. EncryptedExtensions
        let (ee_type, ee_body, ee_raw) =
            read_encrypted_handshake_msg(&mut transport, &mut server_hs_cipher, &mut hs_rx_buf)?;
        if ee_type != HS_ENCRYPTED_EXTENSIONS {
            return Err(TlsError::ProtocolViolation("expected EncryptedExtensions"));
        }
        let negotiated_alpn = parse_encrypted_extensions(&ee_body)?;
        transcript.extend_from_slice(&ee_raw);

        // 2. Optional CertificateRequest, then Certificate
        let (mut next_type, mut next_body, mut next_raw) =
            read_encrypted_handshake_msg(&mut transport, &mut server_hs_cipher, &mut hs_rx_buf)?;
        let mut client_cert_requested = false;
        let mut client_cert_req_ctx = Vec::new();
        if next_type == HS_CERTIFICATE_REQUEST {
            client_cert_requested = true;
            if let Some(&ctx_len) = next_body.first() {
                if usize::from(ctx_len) < next_body.len() {
                    client_cert_req_ctx.extend_from_slice(&next_body[1..1 + usize::from(ctx_len)]);
                }
            }
            transcript.extend_from_slice(&next_raw);
            let nxt = read_encrypted_handshake_msg(
                &mut transport,
                &mut server_hs_cipher,
                &mut hs_rx_buf,
            )?;
            next_type = nxt.0;
            next_body = nxt.1;
            next_raw = nxt.2;
        }

        if next_type != HS_CERTIFICATE {
            return Err(TlsError::ProtocolViolation("expected server Certificate"));
        }
        let cert_ders = parse_certificate_message(&next_body)?;
        let leaf_pubkey = match config.verify_mode {
            VerifyMode::Strict(trust_store) => {
                verify_server_cert_chain(&cert_ders, server_name, config.now_unix_secs, trust_store)
                    .map_err(TlsError::CertificateValidation)?
            }
            VerifyMode::InsecureSkipVerify => {
                let first = cert_ders
                    .first()
                    .ok_or(TlsError::CertificateValidation(X509Error::EmptyChain))?;
                parse_x509_der(first, true)
                    .map_err(TlsError::CertificateValidation)?
                    .public_key
            }
        };
        transcript.extend_from_slice(&next_raw);

        // 3. CertificateVerify (verify over transcript BEFORE appending CertificateVerify)
        let (cv_type, cv_body, cv_raw) =
            read_encrypted_handshake_msg(&mut transport, &mut server_hs_cipher, &mut hs_rx_buf)?;
        if cv_type != HS_CERTIFICATE_VERIFY {
            return Err(TlsError::ProtocolViolation("expected CertificateVerify"));
        }
        let (sig_scheme, sig_bytes) = parse_certificate_verify(&cv_body)?;
        let cv_transcript_hash = suite.hash_alg().digest(&transcript);
        let mut signed_payload = Vec::with_capacity(64 + 34 + cv_transcript_hash.len());
        signed_payload.extend_from_slice(&[0x20u8; 64]);
        signed_payload.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
        signed_payload.extend_from_slice(&cv_transcript_hash);
        if !leaf_pubkey.verify_tls13_sig(sig_scheme, &signed_payload, sig_bytes) {
            return Err(TlsError::InvalidCertificateVerify);
        }
        transcript.extend_from_slice(&cv_raw);

        // 4. Server Finished
        let (fin_type, fin_body, fin_raw) =
            read_encrypted_handshake_msg(&mut transport, &mut server_hs_cipher, &mut hs_rx_buf)?;
        if fin_type != HS_FINISHED {
            return Err(TlsError::ProtocolViolation("expected server Finished"));
        }
        let pre_fin_hash = suite.hash_alg().digest(&transcript);
        let expected_s_fin = compute_finished_verify_data(suite, &s_hs_traffic, &pre_fin_hash)
            .ok_or(TlsError::CryptoFailure)?;
        if !ct_eq_slices(&expected_s_fin, &fin_body) {
            return Err(TlsError::InvalidServerFinished);
        }
        if !hs_rx_buf.is_empty() {
            return Err(TlsError::ProtocolViolation(
                "handshake message spanned key change boundary",
            ));
        }
        transcript.extend_from_slice(&fin_raw);

        // Derive Master Secret & Application Traffic Secrets (RFC 8446 §7.1).
        let server_fin_hash = suite.hash_alg().digest(&transcript);
        let derived_hs = derive_secret_with_hash(suite, &handshake_secret, b"derived", &empty_hash)
            .ok_or(TlsError::CryptoFailure)?;
        let master_secret = hkdf_extract(suite, &derived_hs, &zero_ikm);
        let c_ap_traffic =
            derive_secret_with_hash(suite, &master_secret, b"c ap traffic", &server_fin_hash)
                .ok_or(TlsError::CryptoFailure)?;
        let s_ap_traffic =
            derive_secret_with_hash(suite, &master_secret, b"s ap traffic", &server_fin_hash)
                .ok_or(TlsError::CryptoFailure)?;

        // Send middlebox ChangeCipherSpec + [empty client Certificate] + encrypted Client Finished.
        write_plaintext_record(&mut transport, CONTENT_CHANGE_CIPHER_SPEC, 0x0303, &[0x01])?;

        if client_cert_requested {
            let body_len = 1 + client_cert_req_ctx.len() + 3;
            let mut empty_cert_msg = Vec::with_capacity(4 + body_len);
            empty_cert_msg.push(HS_CERTIFICATE);
            empty_cert_msg.extend_from_slice(&u24_be(body_len));
            empty_cert_msg.push(client_cert_req_ctx.len() as u8);
            empty_cert_msg.extend_from_slice(&client_cert_req_ctx);
            empty_cert_msg.extend_from_slice(&[0x00, 0x00, 0x00]);
            transcript.extend_from_slice(&empty_cert_msg);
            let rec = client_hs_cipher
                .seal_record(CONTENT_HANDSHAKE, &empty_cert_msg)
                .ok_or(TlsError::CryptoFailure)?;
            transport.write_all(&rec).map_err(TlsError::Transport)?;
        }

        let client_fin_hash = suite.hash_alg().digest(&transcript);
        let client_verify_data =
            compute_finished_verify_data(suite, &c_hs_traffic, &client_fin_hash)
                .ok_or(TlsError::CryptoFailure)?;
        let mut client_fin_msg = Vec::with_capacity(4 + client_verify_data.len());
        client_fin_msg.push(HS_FINISHED);
        client_fin_msg.extend_from_slice(&u24_be(client_verify_data.len()));
        client_fin_msg.extend_from_slice(&client_verify_data);
        let fin_rec = client_hs_cipher
            .seal_record(CONTENT_HANDSHAKE, &client_fin_msg)
            .ok_or(TlsError::CryptoFailure)?;
        transport.write_all(&fin_rec).map_err(TlsError::Transport)?;

        let read_cipher = TrafficCipher::from_traffic_secret(suite, &s_ap_traffic)
            .ok_or(TlsError::CryptoFailure)?;
        let write_cipher = TrafficCipher::from_traffic_secret(suite, &c_ap_traffic)
            .ok_or(TlsError::CryptoFailure)?;

        Ok(Self {
            transport,
            read_cipher,
            write_cipher,
            app_rx_buf: Vec::new(),
            app_rx_pos: 0,
            post_hs_buf: Vec::new(),
            peer_closed: false,
            negotiated_suite: suite,
            negotiated_alpn,
        })
    }

    pub const fn cipher_suite(&self) -> CipherSuite {
        self.negotiated_suite
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Encrypt and transmit all bytes in `plaintext` across 16 KiB TLS 1.3 records.
    pub fn write_all(&mut self, plaintext: &[u8]) -> Result<(), TlsError<T::Error>> {
        if plaintext.is_empty() {
            return Ok(());
        }
        for chunk in plaintext.chunks(16_384) {
            let rec = self
                .write_cipher
                .seal_record(CONTENT_APPLICATION_DATA, chunk)
                .ok_or(TlsError::CryptoFailure)?;
            self.transport
                .write_all(&rec)
                .map_err(TlsError::Transport)?;
        }
        Ok(())
    }

    /// Read decrypted application bytes into `out`. Returns `Ok(0)` on clean `close_notify` or EOF.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, TlsError<T::Error>> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.app_rx_pos < self.app_rx_buf.len() {
                let avail = self.app_rx_buf.len() - self.app_rx_pos;
                let n = avail.min(out.len());
                out[..n].copy_from_slice(&self.app_rx_buf[self.app_rx_pos..self.app_rx_pos + n]);
                self.app_rx_pos += n;
                if self.app_rx_pos >= self.app_rx_buf.len() {
                    self.app_rx_buf.clear();
                    self.app_rx_pos = 0;
                }
                return Ok(n);
            }
            if self.peer_closed {
                return Ok(0);
            }

            let Some((hdr, payload)) = read_raw_record_eof_ok(&mut self.transport)? else {
                // Underlying TCP EOF (some HTTP/1.1 `Connection: close` servers close TCP directly).
                self.peer_closed = true;
                return Ok(0);
            };

            match hdr[0] {
                CONTENT_CHANGE_CIPHER_SPEC => continue,
                CONTENT_ALERT => {
                    if payload.len() >= 2 && payload[1] == 0 {
                        self.peer_closed = true;
                        return Ok(0);
                    }
                    let (level, desc) = if payload.len() >= 2 {
                        (payload[0], payload[1])
                    } else {
                        (2, 80)
                    };
                    return Err(TlsError::AlertReceived {
                        level,
                        description: desc,
                    });
                }
                CONTENT_APPLICATION_DATA => {
                    let (inner_type, content) = self
                        .read_cipher
                        .open_record(hdr, &payload)
                        .ok_or(TlsError::DecryptionFailed)?;
                    match inner_type {
                        CONTENT_APPLICATION_DATA => {
                            if !content.is_empty() {
                                self.app_rx_buf = content;
                                self.app_rx_pos = 0;
                            }
                        }
                        CONTENT_ALERT => {
                            if content.len() >= 2 && content[1] == 0 {
                                self.peer_closed = true;
                                return Ok(0);
                            }
                            let (level, desc) = if content.len() >= 2 {
                                (content[0], content[1])
                            } else {
                                (2, 80)
                            };
                            return Err(TlsError::AlertReceived {
                                level,
                                description: desc,
                            });
                        }
                        CONTENT_HANDSHAKE => {
                            self.post_hs_buf.extend_from_slice(&content);
                            self.drain_post_handshake_messages()?;
                        }
                        _ => {
                            return Err(TlsError::ProtocolViolation(
                                "unexpected inner content type",
                            ));
                        }
                    }
                }
                _ => return Err(TlsError::ProtocolViolation("unexpected outer record type")),
            }
        }
    }

    /// Read until `close_notify` or clean transport EOF into `dst`.
    pub fn read_to_end(&mut self, dst: &mut Vec<u8>) -> Result<usize, TlsError<T::Error>> {
        let mut total = 0usize;
        let mut scratch = [0u8; 4096];
        loop {
            let n = self.read(&mut scratch)?;
            if n == 0 {
                break;
            }
            dst.extend_from_slice(&scratch[..n]);
            total += n;
        }
        Ok(total)
    }

    /// Send an encrypted `close_notify` alert (`[1, 0]`).
    pub fn send_close_notify(&mut self) -> Result<(), TlsError<T::Error>> {
        let rec = self
            .write_cipher
            .seal_record(CONTENT_ALERT, &[1, 0])
            .ok_or(TlsError::CryptoFailure)?;
        self.transport.write_all(&rec).map_err(TlsError::Transport)
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    fn drain_post_handshake_messages(&mut self) -> Result<(), TlsError<T::Error>> {
        while self.post_hs_buf.len() >= 4 {
            let msg_type = self.post_hs_buf[0];
            let msg_len = read_u24_be(&self.post_hs_buf[1..4]);
            if msg_len > 65_536 {
                return Err(TlsError::ProtocolViolation(
                    "oversized post-handshake message",
                ));
            }
            if self.post_hs_buf.len() < 4 + msg_len {
                break;
            }
            let body: Vec<u8> = self.post_hs_buf[4..4 + msg_len].to_vec();
            self.post_hs_buf.drain(..4 + msg_len);

            match msg_type {
                HS_NEW_SESSION_TICKET => {
                    // Valid post-handshake session ticket; safe to ignore on stateless connections.
                }
                HS_KEY_UPDATE => {
                    if body.len() != 1 || body[0] > 1 {
                        return Err(TlsError::ProtocolViolation("malformed KeyUpdate"));
                    }
                    if !self.post_hs_buf.is_empty() {
                        return Err(TlsError::ProtocolViolation(
                            "KeyUpdate not aligned to record boundary",
                        ));
                    }
                    self.read_cipher
                        .key_update()
                        .ok_or(TlsError::CryptoFailure)?;
                    if body[0] == 1 {
                        // Peer requested we also rotate our write key (`update_not_requested = 0`).
                        let resp = [HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00];
                        let rec = self
                            .write_cipher
                            .seal_record(CONTENT_HANDSHAKE, &resp)
                            .ok_or(TlsError::CryptoFailure)?;
                        self.transport
                            .write_all(&rec)
                            .map_err(TlsError::Transport)?;
                        self.write_cipher
                            .key_update()
                            .ok_or(TlsError::CryptoFailure)?;
                    }
                }
                _ => {
                    return Err(TlsError::ProtocolViolation(
                        "unsupported post-handshake message",
                    ));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Wire Framing & Handshake Message Builders / Parsers
// ---------------------------------------------------------------------------

fn u24_be(len: usize) -> [u8; 3] {
    [
        ((len >> 16) & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        (len & 0xFF) as u8,
    ]
}

fn read_u24_be(b: &[u8]) -> usize {
    (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

fn push_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn push_ext(exts: &mut Vec<u8>, ext_type: u16, payload: &[u8]) {
    push_u16_be(exts, ext_type);
    push_u16_be(exts, payload.len() as u16);
    exts.extend_from_slice(payload);
}

fn is_ipv4_literal(s: &str) -> bool {
    let mut count = 0usize;
    for part in s.split('.') {
        if part.parse::<u8>().is_err() {
            return false;
        }
        count += 1;
    }
    count == 4
}

fn build_client_hello<E>(
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    server_name: &str,
    x25519_pub: Option<&[u8; 32]>,
    p256_pub: Option<&[u8; 65]>,
    cookie: Option<&[u8]>,
    alpn: Option<&[u8]>,
) -> Result<Vec<u8>, TlsError<E>> {
    let mut exts = Vec::with_capacity(256);

    // 1. SNI (0x0000) — omitted for IPv4 literals per RFC 6066 §3
    if !server_name.is_empty() && !is_ipv4_literal(server_name) && server_name.len() <= 253 {
        let host_bytes = server_name.as_bytes();
        let list_len = 3 + host_bytes.len();
        let mut sni = Vec::with_capacity(2 + list_len);
        push_u16_be(&mut sni, list_len as u16);
        sni.push(0x00); // host_name
        push_u16_be(&mut sni, host_bytes.len() as u16);
        sni.extend_from_slice(host_bytes);
        push_ext(&mut exts, 0x0000, &sni);
    }

    // 2. supported_versions (0x002B) = [TLS 1.3 (0x0304)]
    push_ext(&mut exts, 0x002B, &[0x02, 0x03, 0x04]);

    // 3. supported_groups (0x000A) = [x25519, secp256r1]
    push_ext(&mut exts, 0x000A, &[0x00, 0x04, 0x00, 0x1D, 0x00, 0x17]);

    // 4. signature_algorithms (0x000D)
    let sig_algs: &[u16] = &[
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0807, // ed25519
        0x0804, // rsa_pss_rsae_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0401, // rsa_pkcs1_sha256
        0x0501, // rsa_pkcs1_sha384
        0x0601, // rsa_pkcs1_sha512
    ];
    let mut sa_buf = Vec::with_capacity(2 + sig_algs.len() * 2);
    push_u16_be(&mut sa_buf, (sig_algs.len() * 2) as u16);
    for &alg in sig_algs {
        push_u16_be(&mut sa_buf, alg);
    }
    push_ext(&mut exts, 0x000D, &sa_buf);

    // 5. psk_key_exchange_modes (0x002D) = [psk_dhe_ke (1)]
    push_ext(&mut exts, 0x002D, &[0x01, 0x01]);

    // 6. Optional HRR cookie (0x002C)
    if let Some(c) = cookie {
        let mut cbuf = Vec::with_capacity(2 + c.len());
        push_u16_be(&mut cbuf, c.len() as u16);
        cbuf.extend_from_slice(c);
        push_ext(&mut exts, 0x002C, &cbuf);
    }

    // 7. key_share (0x0033)
    let mut ks_entries = Vec::with_capacity(112);
    if let Some(xpub) = x25519_pub {
        push_u16_be(&mut ks_entries, GROUP_X25519);
        push_u16_be(&mut ks_entries, 32);
        ks_entries.extend_from_slice(xpub);
    }
    if let Some(ppub) = p256_pub {
        push_u16_be(&mut ks_entries, GROUP_SECP256R1);
        push_u16_be(&mut ks_entries, 65);
        ks_entries.extend_from_slice(ppub);
    }
    let mut ks_ext = Vec::with_capacity(2 + ks_entries.len());
    push_u16_be(&mut ks_ext, ks_entries.len() as u16);
    ks_ext.extend_from_slice(&ks_entries);
    push_ext(&mut exts, 0x0033, &ks_ext);

    // 8. Optional ALPN (0x0010)
    if let Some(proto) = alpn {
        if !proto.is_empty() && proto.len() <= 255 {
            let list_len = 1 + proto.len();
            let mut abuf = Vec::with_capacity(2 + list_len);
            push_u16_be(&mut abuf, list_len as u16);
            abuf.push(proto.len() as u8);
            abuf.extend_from_slice(proto);
            push_ext(&mut exts, 0x0010, &abuf);
        }
    }

    let mut body = Vec::with_capacity(80 + exts.len());
    push_u16_be(&mut body, 0x0303); // legacy_version = TLS 1.2
    body.extend_from_slice(client_random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    // cipher_suites = [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384]
    push_u16_be(&mut body, 4);
    push_u16_be(&mut body, CipherSuite::Aes128GcmSha256.id());
    push_u16_be(&mut body, CipherSuite::Aes256GcmSha384.id());
    // legacy_compression_methods = [null]
    body.push(1);
    body.push(0);
    push_u16_be(&mut body, exts.len() as u16);
    body.extend_from_slice(&exts);

    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(HS_CLIENT_HELLO);
    msg.extend_from_slice(&u24_be(body.len()));
    msg.extend_from_slice(&body);
    Ok(msg)
}

fn read_exact_transport<T: TlsTransport>(
    transport: &mut T,
    dst: &mut [u8],
) -> Result<(), TlsError<T::Error>> {
    let mut filled = 0usize;
    while filled < dst.len() {
        let n = transport
            .read(&mut dst[filled..])
            .map_err(TlsError::Transport)?;
        if n == 0 {
            return Err(TlsError::UnexpectedEof);
        }
        filled += n;
    }
    Ok(())
}

type RawTlsRecord = ([u8; 5], Vec<u8>);
type ParsedHandshakeMsg = (u8, Vec<u8>, Vec<u8>);

fn read_raw_record_eof_ok<T: TlsTransport>(
    transport: &mut T,
) -> Result<Option<RawTlsRecord>, TlsError<T::Error>> {
    let mut hdr = [0u8; 5];
    let mut pos = 0usize;
    while pos < 5 {
        let n = transport
            .read(&mut hdr[pos..])
            .map_err(TlsError::Transport)?;
        if n == 0 {
            if pos == 0 {
                return Ok(None);
            }
            return Err(TlsError::UnexpectedEof);
        }
        pos += n;
    }
    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if rec_len > 16_640 {
        return Err(TlsError::RecordTooLarge);
    }
    let mut payload = alloc::vec![0u8; rec_len];
    read_exact_transport(transport, &mut payload)?;
    Ok(Some((hdr, payload)))
}

fn read_raw_record<T: TlsTransport>(
    transport: &mut T,
) -> Result<RawTlsRecord, TlsError<T::Error>> {
    read_raw_record_eof_ok(transport)?.ok_or(TlsError::UnexpectedEof)
}

fn write_plaintext_record<T: TlsTransport>(
    transport: &mut T,
    content_type: u8,
    legacy_version: u16,
    payload: &[u8],
) -> Result<(), TlsError<T::Error>> {
    let mut rec = Vec::with_capacity(5 + payload.len());
    rec.push(content_type);
    rec.extend_from_slice(&legacy_version.to_be_bytes());
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    transport.write_all(&rec).map_err(TlsError::Transport)
}

fn read_plaintext_server_hello<T: TlsTransport>(
    transport: &mut T,
) -> Result<Vec<u8>, TlsError<T::Error>> {
    let mut buf = Vec::new();
    while buf.len() < 4 || buf.len() < 4 + read_u24_be(&buf[1..4]) {
        let (hdr, payload) = read_raw_record(transport)?;
        match hdr[0] {
            CONTENT_CHANGE_CIPHER_SPEC => continue,
            CONTENT_ALERT => {
                let (level, desc) = if payload.len() >= 2 {
                    (payload[0], payload[1])
                } else {
                    (2, 40)
                };
                return Err(TlsError::AlertReceived {
                    level,
                    description: desc,
                });
            }
            CONTENT_HANDSHAKE => {
                buf.extend_from_slice(&payload);
                if buf.len() > 65_536 {
                    return Err(TlsError::RecordTooLarge);
                }
            }
            _ => {
                return Err(TlsError::ProtocolViolation(
                    "expected ServerHello handshake record",
                ));
            }
        }
    }
    let msg_len = 4 + read_u24_be(&buf[1..4]);
    if buf.len() != msg_len {
        return Err(TlsError::ProtocolViolation(
            "coalesced plaintext bytes after ServerHello",
        ));
    }
    Ok(buf)
}

struct ParsedServerHello {
    suite: CipherSuite,
    is_hello_retry_request: bool,
    key_share_group: Option<u16>,
    key_share_bytes: Vec<u8>,
    hrr_selected_group: Option<u16>,
    cookie: Option<Vec<u8>>,
}

fn parse_server_hello<E>(
    msg: &[u8],
    expected_session_id: &[u8; 32],
) -> Result<ParsedServerHello, TlsError<E>> {
    if msg.len() < 4 || msg[0] != HS_SERVER_HELLO {
        return Err(TlsError::ProtocolViolation("expected ServerHello"));
    }
    let body_len = read_u24_be(&msg[1..4]);
    let body = &msg[4..];
    if body.len() != body_len || body.len() < 38 {
        return Err(TlsError::ProtocolViolation("truncated ServerHello"));
    }
    let legacy_ver = u16::from_be_bytes([body[0], body[1]]);
    if legacy_ver != 0x0303 {
        return Err(TlsError::UnsupportedVersion);
    }
    let is_hrr = body[2..34] == HELLO_RETRY_REQUEST_RANDOM;
    let sid_len = usize::from(body[34]);
    if 35 + sid_len + 3 > body.len() {
        return Err(TlsError::ProtocolViolation(
            "malformed ServerHello session_id",
        ));
    }
    if &body[35..35 + sid_len] != expected_session_id.as_slice() {
        return Err(TlsError::ProtocolViolation(
            "ServerHello session_id echo mismatch",
        ));
    }
    let mut pos = 35 + sid_len;
    let suite_id = u16::from_be_bytes([body[pos], body[pos + 1]]);
    let suite = CipherSuite::from_u16(suite_id).ok_or(TlsError::UnsupportedCipherSuite)?;
    let comp = body[pos + 2];
    if comp != 0 {
        return Err(TlsError::ProtocolViolation(
            "non-null ServerHello compression",
        ));
    }
    pos += 3;
    if pos + 2 > body.len() {
        return Err(TlsError::UnsupportedVersion);
    }
    let exts_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + exts_len != body.len() {
        return Err(TlsError::ProtocolViolation(
            "malformed ServerHello extensions",
        ));
    }

    let mut saw_tls13 = false;
    let mut key_share_group = None;
    let mut key_share_bytes = Vec::new();
    let mut hrr_selected_group = None;
    let mut cookie = None;

    let mut epos = pos;
    while epos < body.len() {
        if epos + 4 > body.len() {
            return Err(TlsError::ProtocolViolation("truncated ServerHello ext"));
        }
        let etype = u16::from_be_bytes([body[epos], body[epos + 1]]);
        let elen = u16::from_be_bytes([body[epos + 2], body[epos + 3]]) as usize;
        epos += 4;
        if epos + elen > body.len() {
            return Err(TlsError::ProtocolViolation("overrun in ServerHello ext"));
        }
        let edata = &body[epos..epos + elen];
        epos += elen;

        match etype {
            0x002B => {
                if edata.len() != 2 || u16::from_be_bytes([edata[0], edata[1]]) != 0x0304 {
                    return Err(TlsError::UnsupportedVersion);
                }
                saw_tls13 = true;
            }
            0x0033 => {
                if is_hrr {
                    if edata.len() != 2 {
                        return Err(TlsError::ProtocolViolation("invalid HRR key_share"));
                    }
                    hrr_selected_group = Some(u16::from_be_bytes([edata[0], edata[1]]));
                } else {
                    if edata.len() < 4 {
                        return Err(TlsError::ProtocolViolation("truncated key_share"));
                    }
                    let grp = u16::from_be_bytes([edata[0], edata[1]]);
                    let klen = u16::from_be_bytes([edata[2], edata[3]]) as usize;
                    if 4 + klen != edata.len() {
                        return Err(TlsError::ProtocolViolation("malformed key_share"));
                    }
                    key_share_group = Some(grp);
                    key_share_bytes = edata[4..].to_vec();
                }
            }
            0x002C => {
                if edata.len() < 2 {
                    return Err(TlsError::ProtocolViolation("malformed HRR cookie"));
                }
                let clen = u16::from_be_bytes([edata[0], edata[1]]) as usize;
                if 2 + clen != edata.len() {
                    return Err(TlsError::ProtocolViolation("malformed HRR cookie len"));
                }
                cookie = Some(edata[2..].to_vec());
            }
            _ => {}
        }
    }

    if !saw_tls13 {
        return Err(TlsError::UnsupportedVersion);
    }

    Ok(ParsedServerHello {
        suite,
        is_hello_retry_request: is_hrr,
        key_share_group,
        key_share_bytes,
        hrr_selected_group,
        cookie,
    })
}

fn read_encrypted_handshake_msg<T: TlsTransport>(
    transport: &mut T,
    cipher: &mut TrafficCipher,
    hs_buf: &mut Vec<u8>,
) -> Result<ParsedHandshakeMsg, TlsError<T::Error>> {
    while hs_buf.len() < 4 || hs_buf.len() < 4 + read_u24_be(&hs_buf[1..4]) {
        let (hdr, payload) = read_raw_record(transport)?;
        match hdr[0] {
            CONTENT_CHANGE_CIPHER_SPEC => continue,
            CONTENT_ALERT => {
                let (level, desc) = if payload.len() >= 2 {
                    (payload[0], payload[1])
                } else {
                    (2, 40)
                };
                return Err(TlsError::AlertReceived {
                    level,
                    description: desc,
                });
            }
            CONTENT_APPLICATION_DATA => {
                let (inner_type, content) = cipher
                    .open_record(hdr, &payload)
                    .ok_or(TlsError::DecryptionFailed)?;
                match inner_type {
                    CONTENT_HANDSHAKE => {
                        hs_buf.extend_from_slice(&content);
                        if hs_buf.len() > 262_144 {
                            return Err(TlsError::RecordTooLarge);
                        }
                    }
                    CONTENT_ALERT => {
                        let (level, desc) = if content.len() >= 2 {
                            (content[0], content[1])
                        } else {
                            (2, 40)
                        };
                        return Err(TlsError::AlertReceived {
                            level,
                            description: desc,
                        });
                    }
                    _ => {
                        return Err(TlsError::ProtocolViolation(
                            "unexpected record type during encrypted handshake",
                        ));
                    }
                }
            }
            _ => {
                return Err(TlsError::ProtocolViolation(
                    "expected encrypted handshake record",
                ));
            }
        }
    }

    let msg_type = hs_buf[0];
    let body_len = read_u24_be(&hs_buf[1..4]);
    let raw: Vec<u8> = hs_buf[..4 + body_len].to_vec();
    let body: Vec<u8> = hs_buf[4..4 + body_len].to_vec();
    hs_buf.drain(..4 + body_len);
    Ok((msg_type, body, raw))
}

fn parse_encrypted_extensions<E>(body: &[u8]) -> Result<Option<Vec<u8>>, TlsError<E>> {
    if body.len() < 2 {
        return Err(TlsError::ProtocolViolation("truncated EncryptedExtensions"));
    }
    let exts_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if 2 + exts_len != body.len() {
        return Err(TlsError::ProtocolViolation("malformed EncryptedExtensions"));
    }
    let mut alpn = None;
    let mut pos = 2usize;
    while pos < body.len() {
        if pos + 4 > body.len() {
            return Err(TlsError::ProtocolViolation("truncated EE ext"));
        }
        let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > body.len() {
            return Err(TlsError::ProtocolViolation("overrun EE ext"));
        }
        let edata = &body[pos..pos + elen];
        pos += elen;

        if etype == 0x0010 && edata.len() >= 3 {
            let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
            let plen = usize::from(edata[2]);
            if 2 + list_len == edata.len() && 1 + plen == list_len {
                alpn = Some(edata[3..].to_vec());
            }
        }
    }
    Ok(alpn)
}

fn parse_certificate_message<E>(body: &[u8]) -> Result<Vec<Vec<u8>>, TlsError<E>> {
    let ctx_len = usize::from(
        *body
            .first()
            .ok_or(TlsError::ProtocolViolation("empty Certificate message"))?,
    );
    if 1 + ctx_len + 3 > body.len() {
        return Err(TlsError::ProtocolViolation("truncated Certificate header"));
    }
    let mut pos = 1 + ctx_len;
    let list_len = read_u24_be(&body[pos..pos + 3]);
    pos += 3;
    if pos + list_len != body.len() {
        return Err(TlsError::ProtocolViolation("malformed Certificate list"));
    }
    let mut certs = Vec::new();
    while pos < body.len() {
        if pos + 3 > body.len() {
            return Err(TlsError::ProtocolViolation("truncated CertificateEntry"));
        }
        let cert_len = read_u24_be(&body[pos..pos + 3]);
        pos += 3;
        if cert_len == 0 || pos + cert_len + 2 > body.len() {
            return Err(TlsError::ProtocolViolation(
                "invalid CertificateEntry cert_data",
            ));
        }
        certs.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + ext_len > body.len() {
            return Err(TlsError::ProtocolViolation(
                "invalid CertificateEntry extensions",
            ));
        }
        pos += ext_len;
    }
    if certs.is_empty() {
        return Err(TlsError::CertificateValidation(X509Error::EmptyChain));
    }
    Ok(certs)
}

fn parse_certificate_verify<E>(body: &[u8]) -> Result<(u16, &[u8]), TlsError<E>> {
    if body.len() < 4 {
        return Err(TlsError::ProtocolViolation("truncated CertificateVerify"));
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if 4 + sig_len != body.len() || sig_len == 0 {
        return Err(TlsError::ProtocolViolation(
            "malformed CertificateVerify signature",
        ));
    }
    Ok((scheme, &body[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use ed25519_dalek::{Signer, SigningKey};

    struct DuplexMock {
        rx: VecDeque<u8>,
        tx: Vec<u8>,
    }

    impl TlsTransport for DuplexMock {
        type Error = &'static str;

        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let n = buf.len().min(self.rx.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.rx.pop_front().unwrap_or(0);
            }
            Ok(n)
        }

        fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
            self.tx.extend_from_slice(buf);
            Ok(())
        }
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + content.len());
        out.push(tag);
        let len = content.len();
        if len < 128 {
            out.push(len as u8);
        } else if len <= 0xFF {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xFF) as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn der_name_cn(cn: &str) -> Vec<u8> {
        let mut atv = Vec::new();
        atv.extend_from_slice(&der_tlv(0x06, &[0x55, 0x04, 0x03]));
        atv.extend_from_slice(&der_tlv(0x0C, cn.as_bytes()));
        let rdn = der_tlv(0x31, &der_tlv(0x30, &atv));
        der_tlv(0x30, &rdn)
    }

    /// Build a valid X.509v3 Ed25519 certificate signed by `issuer_sk`.
    fn make_ed25519_x509_cert(
        serial: u8,
        issuer_cn: &str,
        subject_cn: &str,
        dns_san: Option<&str>,
        is_ca: bool,
        subj_vk: &[u8; 32],
        issuer_sk: &SigningKey,
    ) -> Vec<u8> {
        let mut tbs = Vec::new();
        // [0] EXPLICIT v3 (integer 2)
        tbs.extend_from_slice(&der_tlv(0xA0, &der_tlv(0x02, &[0x02])));
        // serialNumber
        tbs.extend_from_slice(&der_tlv(0x02, &[serial]));
        // signature AlgorithmIdentifier: Ed25519 (1.3.101.112)
        let ed_alg = der_tlv(0x30, &der_tlv(0x06, &[0x2B, 0x65, 0x70]));
        tbs.extend_from_slice(&ed_alg);
        // issuer
        tbs.extend_from_slice(&der_name_cn(issuer_cn));
        // validity: 2025-01-01 .. 2035-01-01
        let mut val_body = Vec::new();
        val_body.extend_from_slice(&der_tlv(0x17, b"250101000000Z"));
        val_body.extend_from_slice(&der_tlv(0x17, b"350101000000Z"));
        tbs.extend_from_slice(&der_tlv(0x30, &val_body));
        // subject
        tbs.extend_from_slice(&der_name_cn(subject_cn));
        // subjectPublicKeyInfo
        let mut spki_body = Vec::new();
        spki_body.extend_from_slice(&ed_alg);
        let mut bs = Vec::with_capacity(33);
        bs.push(0x00);
        bs.extend_from_slice(subj_vk);
        spki_body.extend_from_slice(&der_tlv(0x03, &bs));
        tbs.extend_from_slice(&der_tlv(0x30, &spki_body));

        // extensions [3]
        let mut exts = Vec::new();
        let bc_inner = if is_ca {
            der_tlv(0x30, &der_tlv(0x01, &[0xFF]))
        } else {
            der_tlv(0x30, &[])
        };
        let mut bc_ext = Vec::new();
        bc_ext.extend_from_slice(&der_tlv(0x06, &[0x55, 0x1D, 0x13]));
        bc_ext.extend_from_slice(&der_tlv(0x01, &[0xFF]));
        bc_ext.extend_from_slice(&der_tlv(0x04, &bc_inner));
        exts.extend_from_slice(&der_tlv(0x30, &bc_ext));

        if let Some(san) = dns_san {
            let san_seq = der_tlv(0x30, &der_tlv(0x82, san.as_bytes()));
            let mut san_ext = Vec::new();
            san_ext.extend_from_slice(&der_tlv(0x06, &[0x55, 0x1D, 0x11]));
            san_ext.extend_from_slice(&der_tlv(0x04, &san_seq));
            exts.extend_from_slice(&der_tlv(0x30, &san_ext));
        }

        tbs.extend_from_slice(&der_tlv(0xA3, &der_tlv(0x30, &exts)));
        let tbs_der = der_tlv(0x30, &tbs);

        let sig = issuer_sk.sign(&tbs_der);
        let mut sig_bs = Vec::with_capacity(65);
        sig_bs.push(0x00);
        sig_bs.extend_from_slice(&sig.to_bytes());

        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&tbs_der);
        cert_body.extend_from_slice(&ed_alg);
        cert_body.extend_from_slice(&der_tlv(0x03, &sig_bs));
        der_tlv(0x30, &cert_body)
    }

    #[test]
    fn test_webpki_mozilla_bundle_loads_anchors() {
        let pem = include_bytes!("../../../third_party/certs/ca-certificates.pem");
        let store = TrustStore::from_pem_bytes(pem);
        assert!(store.is_ok());
        if let Ok(s) = store {
            assert!(
                s.len() >= 130,
                "expected >= 130 WebPKI roots loaded, got {}",
                s.len()
            );
        }
    }

    #[test]
    fn test_x509_chain_and_hostname_verification() {
        let root_sk = SigningKey::from_bytes(&[0x11; 32]);
        let root_vk = root_sk.verifying_key().to_bytes();
        let inter_sk = SigningKey::from_bytes(&[0x22; 32]);
        let inter_vk = inter_sk.verifying_key().to_bytes();
        let leaf_sk = SigningKey::from_bytes(&[0x33; 32]);
        let leaf_vk = leaf_sk.verifying_key().to_bytes();

        let root_der = make_ed25519_x509_cert(
            1,
            "HuesOS Root CA",
            "HuesOS Root CA",
            None,
            true,
            &root_vk,
            &root_sk,
        );
        let inter_der = make_ed25519_x509_cert(
            2,
            "HuesOS Root CA",
            "HuesOS Intermediate CA",
            None,
            true,
            &inter_vk,
            &root_sk,
        );
        let leaf_der = make_ed25519_x509_cert(
            3,
            "HuesOS Intermediate CA",
            "api.huesos.org",
            Some("*.huesos.org"),
            false,
            &leaf_vk,
            &inter_sk,
        );

        let mut store = TrustStore::new();
        assert!(store.add_der_certificate(&root_der).is_ok());

        let chain = alloc::vec![leaf_der.clone(), inter_der.clone()];
        let ok_res =
            verify_server_cert_chain(&chain, "api.huesos.org", Some(1_795_000_000), &store);
        assert!(ok_res.is_ok());

        // Hostname mismatch must fail closed.
        let bad_host =
            verify_server_cert_chain(&chain, "evil.example.com", Some(1_795_000_000), &store);
        assert_eq!(bad_host, Err(X509Error::HostnameMismatch));

        // Untrusted root must fail closed.
        let empty_store = TrustStore::new();
        let untrusted =
            verify_server_cert_chain(&chain, "api.huesos.org", Some(1_795_000_000), &empty_store);
        assert_eq!(untrusted, Err(X509Error::UntrustedRoot));
    }

    #[test]
    fn test_p256_ecdh_and_rsa_math() {
        let seed_a = [0x41u8; 32];
        let seed_b = [0x79u8; 32];
        let a = p256_public_key(&seed_a);
        let b = p256_public_key(&seed_b);
        assert!(a.is_some() && b.is_some());
        if let (Some((sa, pa)), Some((sb, pb))) = (a, b) {
            let ss1 = p256_diffie_hellman(&sa, &pb);
            let ss2 = p256_diffie_hellman(&sb, &pa);
            assert!(ss1.is_some());
            assert_eq!(ss1, ss2);
        }
    }

    #[test]
    fn test_tls13_end_to_end_handshake_and_https_exchange() {
        let root_sk = SigningKey::from_bytes(&[0x55; 32]);
        let root_vk = root_sk.verifying_key().to_bytes();
        let leaf_sk = SigningKey::from_bytes(&[0x66; 32]);
        let leaf_vk = leaf_sk.verifying_key().to_bytes();

        let root_der = make_ed25519_x509_cert(
            1,
            "HuesOS Root",
            "HuesOS Root",
            None,
            true,
            &root_vk,
            &root_sk,
        );
        let leaf_der = make_ed25519_x509_cert(
            2,
            "HuesOS Root",
            "huesos.dev",
            Some("huesos.dev"),
            false,
            &leaf_vk,
            &root_sk,
        );

        let mut store = TrustStore::new();
        assert!(store.add_der_certificate(&root_der).is_ok());

        // Deterministically pre-derive ClientHello1 using known entropy so we can synthesize a
        // full RFC 8446 server flight (`ServerHello`, `EncryptedExtensions`, `Certificate`,
        // `CertificateVerify`, `Finished`, `NewSessionTicket`, HTTP/1.1 response, `close_notify`).
        let mut entropy = [0u8; 128];
        for (i, b) in entropy.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&entropy[0..32]);
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&entropy[32..64]);
        let mut cli_x_sec = [0u8; 32];
        cli_x_sec.copy_from_slice(&entropy[64..96]);
        let mut cli_p_seed = [0u8; 32];
        cli_p_seed.copy_from_slice(&entropy[96..128]);

        let cli_x_pub = x25519_public_key(&cli_x_sec);
        let p256_pair = p256_public_key(&cli_p_seed);
        assert!(p256_pair.is_some());
        let (_, cli_p_pub) = match p256_pair {
            Some(v) => v,
            None => return,
        };
        let ch_res = build_client_hello::<&'static str>(
            &client_random,
            &session_id,
            "huesos.dev",
            Some(&cli_x_pub),
            Some(&cli_p_pub),
            None,
            Some(b"http/1.1"),
        );
        assert!(ch_res.is_ok());
        let ch = match ch_res {
            Ok(v) => v,
            Err(_) => return,
        };

        // Server ephemeral X25519
        let srv_x_sec = [0x9Au8; 32];
        let srv_x_pub = x25519_public_key(&srv_x_sec);
        let shared = match x25519_diffie_hellman(&srv_x_sec, &cli_x_pub) {
            Some(s) => s,
            None => return,
        };

        let suite = CipherSuite::Aes128GcmSha256;
        let mut sh_exts = Vec::new();
        push_ext(&mut sh_exts, 0x002B, &[0x03, 0x04]);
        let mut ks = Vec::new();
        push_u16_be(&mut ks, GROUP_X25519);
        push_u16_be(&mut ks, 32);
        ks.extend_from_slice(&srv_x_pub);
        push_ext(&mut sh_exts, 0x0033, &ks);

        let mut sh_body = Vec::new();
        push_u16_be(&mut sh_body, 0x0303);
        sh_body.extend_from_slice(&[0xBBu8; 32]);
        sh_body.push(32);
        sh_body.extend_from_slice(&session_id);
        push_u16_be(&mut sh_body, suite.id());
        sh_body.push(0);
        push_u16_be(&mut sh_body, sh_exts.len() as u16);
        sh_body.extend_from_slice(&sh_exts);

        let mut sh_msg = Vec::new();
        sh_msg.push(HS_SERVER_HELLO);
        sh_msg.extend_from_slice(&u24_be(sh_body.len()));
        sh_msg.extend_from_slice(&sh_body);

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&ch);
        transcript.extend_from_slice(&sh_msg);

        let zero_ikm = [0u8; 32];
        let early = hkdf_extract(suite, &zero_ikm, &zero_ikm);
        let empty_h = suite.hash_alg().digest(&[]);
        let derived_early = match derive_secret_with_hash(suite, &early, b"derived", &empty_h) {
            Some(v) => v,
            None => return,
        };
        let hs_sec = hkdf_extract(suite, &derived_early, &shared);
        let ch_sh_h = suite.hash_alg().digest(&transcript);
        let s_hs = match derive_secret_with_hash(suite, &hs_sec, b"s hs traffic", &ch_sh_h) {
            Some(v) => v,
            None => return,
        };
        let mut srv_hs_cipher = match TrafficCipher::from_traffic_secret(suite, &s_hs) {
            Some(c) => c,
            None => return,
        };

        // Server EncryptedExtensions (negotiating ALPN http/1.1)
        let mut ee_exts = Vec::new();
        push_ext(
            &mut ee_exts,
            0x0010,
            &[
                0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
            ],
        );
        let mut ee_body = Vec::new();
        push_u16_be(&mut ee_body, ee_exts.len() as u16);
        ee_body.extend_from_slice(&ee_exts);
        let mut ee_msg = Vec::new();
        ee_msg.push(HS_ENCRYPTED_EXTENSIONS);
        ee_msg.extend_from_slice(&u24_be(ee_body.len()));
        ee_msg.extend_from_slice(&ee_body);
        transcript.extend_from_slice(&ee_msg);

        // Server Certificate
        let mut cert_entry = Vec::new();
        cert_entry.extend_from_slice(&u24_be(leaf_der.len()));
        cert_entry.extend_from_slice(&leaf_der);
        push_u16_be(&mut cert_entry, 0);
        let mut cert_body = Vec::new();
        cert_body.push(0); // context len
        cert_body.extend_from_slice(&u24_be(cert_entry.len()));
        cert_body.extend_from_slice(&cert_entry);
        let mut cert_msg = Vec::new();
        cert_msg.push(HS_CERTIFICATE);
        cert_msg.extend_from_slice(&u24_be(cert_body.len()));
        cert_msg.extend_from_slice(&cert_body);
        transcript.extend_from_slice(&cert_msg);

        // Server CertificateVerify
        let cv_h = suite.hash_alg().digest(&transcript);
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&[0x20u8; 64]);
        to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
        to_sign.extend_from_slice(&cv_h);
        let ed_sig = leaf_sk.sign(&to_sign).to_bytes();
        let mut cv_body = Vec::new();
        push_u16_be(&mut cv_body, 0x0807);
        push_u16_be(&mut cv_body, 64);
        cv_body.extend_from_slice(&ed_sig);
        let mut cv_msg = Vec::new();
        cv_msg.push(HS_CERTIFICATE_VERIFY);
        cv_msg.extend_from_slice(&u24_be(cv_body.len()));
        cv_msg.extend_from_slice(&cv_body);
        transcript.extend_from_slice(&cv_msg);

        // Server Finished
        let pre_fin_h = suite.hash_alg().digest(&transcript);
        let srv_fin_vd = match compute_finished_verify_data(suite, &s_hs, &pre_fin_h) {
            Some(v) => v,
            None => return,
        };
        let mut sfin_msg = Vec::new();
        sfin_msg.push(HS_FINISHED);
        sfin_msg.extend_from_slice(&u24_be(srv_fin_vd.len()));
        sfin_msg.extend_from_slice(&srv_fin_vd);
        transcript.extend_from_slice(&sfin_msg);

        // Server Application cipher
        let sfin_h = suite.hash_alg().digest(&transcript);
        let derived_hs = match derive_secret_with_hash(suite, &hs_sec, b"derived", &empty_h) {
            Some(v) => v,
            None => return,
        };
        let master = hkdf_extract(suite, &derived_hs, &zero_ikm);
        let s_ap = match derive_secret_with_hash(suite, &master, b"s ap traffic", &sfin_h) {
            Some(v) => v,
            None => return,
        };
        let mut srv_ap_cipher = match TrafficCipher::from_traffic_secret(suite, &s_ap) {
            Some(c) => c,
            None => return,
        };

        // Wire up server records into DuplexMock.rx!
        let mut server_wire = Vec::new();
        // Plaintext ServerHello + middlebox CCS
        server_wire.push(CONTENT_HANDSHAKE);
        server_wire.extend_from_slice(&0x0303u16.to_be_bytes());
        server_wire.extend_from_slice(&(sh_msg.len() as u16).to_be_bytes());
        server_wire.extend_from_slice(&sh_msg);
        server_wire.extend_from_slice(&[CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);

        // Encrypted server handshake messages packed across two records
        let mut flight_part1 = Vec::new();
        flight_part1.extend_from_slice(&ee_msg);
        flight_part1.extend_from_slice(&cert_msg);
        let mut flight_part2 = Vec::new();
        flight_part2.extend_from_slice(&cv_msg);
        flight_part2.extend_from_slice(&sfin_msg);

        if let Some(r1) = srv_hs_cipher.seal_record(CONTENT_HANDSHAKE, &flight_part1) {
            server_wire.extend_from_slice(&r1);
        }
        if let Some(r2) = srv_hs_cipher.seal_record(CONTENT_HANDSHAKE, &flight_part2) {
            server_wire.extend_from_slice(&r2);
        }

        // Post-handshake NewSessionTicket + HTTP/1.1 200 OK + close_notify!
        let nst = [
            HS_NEW_SESSION_TICKET,
            0x00,
            0x00,
            0x04,
            0x00,
            0x01,
            0x02,
            0x03,
        ];
        if let Some(rnst) = srv_ap_cipher.seal_record(CONTENT_HANDSHAKE, &nst) {
            server_wire.extend_from_slice(&rnst);
        }
        let http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello TLS1.3";
        if let Some(rapp) = srv_ap_cipher.seal_record(CONTENT_APPLICATION_DATA, http_resp) {
            server_wire.extend_from_slice(&rapp);
        }
        if let Some(rclose) = srv_ap_cipher.seal_record(CONTENT_ALERT, &[1, 0]) {
            server_wire.extend_from_slice(&rclose);
        }

        let mock = DuplexMock {
            rx: VecDeque::from(server_wire),
            tx: Vec::new(),
        };
        let cfg = TlsClientConfig {
            verify_mode: VerifyMode::Strict(&store),
            now_unix_secs: Some(1_795_000_000),
            alpn_protocol: Some(b"http/1.1"),
        };

        let tls_res = TlsStream::connect(mock, "huesos.dev", entropy, &cfg);
        assert!(
            tls_res.is_ok(),
            "TLS 1.3 connect failed: {:?}",
            tls_res.err()
        );
        let mut tls = match tls_res {
            Ok(s) => s,
            Err(_) => return,
        };
        assert_eq!(tls.alpn_protocol(), Some(&b"http/1.1"[..]));
        assert!(tls
            .write_all(b"GET / HTTP/1.1\r\nHost: huesos.dev\r\n\r\n")
            .is_ok());

        let mut received = Vec::new();
        assert!(tls.read_to_end(&mut received).is_ok());
        assert_eq!(received.as_slice(), http_resp);
    }
}
