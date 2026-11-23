//! `/bin/curl.elf` — HTTP/1.1 & HTTPS (TLS 1.3 + X.509v3) client.
//!
//! Usage:
//!   `curl [-I] [-i] [-s] [-k] [-L] [--cacert <pem>] [-X <METHOD>] [-H <Header: val>] [-d <body>] [-o <file>] <http[s]://host[:port]/path>`

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_coreutils as cu;
use huesos_std::error::Error as StdError;
use huesos_std::fs;
use huesos_std::io::{self, Read, Write};
use huesos_std::net::{self, TcpStream};
use huesos_tls::crypto::HashAlg;
use huesos_tls::{TlsClientConfig, TlsError, TlsStream, TlsTransport, TrustStore, VerifyMode};
use libcanvas::stdio::{take_cap_handle, CapKind};
use libcanvas::Vmo;

cu::coreutil_entry!(run);

const BOOTFS_HEADER_SIZE: u64 = 16;
const BOOTFS_ENTRY_SIZE: u64 = 216;
const BOOTFS_PATH_SIZE: usize = 192;
const BOOTFS_MAGIC: &[u8; 8] = b"HBOOTFS1";
const DEFAULT_CA_BUNDLE: &str = "/etc/ssl/certs.pem";
const MAX_REDIRECTS: usize = 5;

fn usage() {
    cu::outln("usage: curl [-I] [-i] [-s] [-k] [-L] [--cacert pem] [-X METHOD] [-H 'Header: v'] [-d data] [-o file] <http[s]://host[:port]/path>");
}

#[derive(Clone, Debug)]
struct ParsedUrl {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(raw: &str) -> Result<ParsedUrl, &'static str> {
    let (https, default_port, rest) = if let Some(r) = raw.strip_prefix("https://") {
        (true, 443u16, r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        (false, 80u16, r)
    } else if raw.contains("://") {
        return Err("unsupported URL scheme (expected http:// or https://)");
    } else {
        (false, 80u16, raw)
    };

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err("empty host in URL");
    }
    let (host, port) = if let Some((h, p_str)) = authority.rsplit_once(':') {
        let p = p_str.parse::<u16>().map_err(|_| "invalid port number")?;
        (h, p)
    } else {
        (authority, default_port)
    };
    if host.is_empty() {
        return Err("empty host in URL");
    }
    Ok(ParsedUrl {
        https,
        host: String::from(host),
        port,
        path: String::from(path),
    })
}

fn resolve_redirect_url(base: &ParsedUrl, location: &str) -> Result<ParsedUrl, &'static str> {
    let loc = location.trim();
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return parse_url(loc);
    }
    if let Some(schemeless) = loc.strip_prefix("//") {
        let scheme = if base.https { "https://" } else { "http://" };
        return parse_url(&format!("{scheme}{schemeless}"));
    }
    let new_path = if loc.starts_with('/') {
        String::from(loc)
    } else {
        let dir = match base.path.rfind('/') {
            Some(idx) => &base.path[..=idx],
            None => "/",
        };
        format!("{dir}{loc}")
    };
    Ok(ParsedUrl {
        https: base.https,
        host: base.host.clone(),
        port: base.port,
        path: new_path,
    })
}

struct TcpTlsAdapter(TcpStream);

impl TlsTransport for TcpTlsAdapter {
    type Error = StdError;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Read::read(&mut self.0, buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.0.write_all(buf)
    }
}

fn bootfs_vmo() -> Option<&'static Vmo> {
    static BOOTFS: spin::Once<Option<Vmo>> = spin::Once::new();
    BOOTFS
        .call_once(|| take_cap_handle(CapKind::BootfsRo).map(Vmo::from_handle))
        .as_ref()
}

fn read_bootfs_file(path: &str) -> Option<Vec<u8>> {
    let vmo = bootfs_vmo()?;
    let mut header = [0u8; BOOTFS_HEADER_SIZE as usize];
    if vmo.read(0, &mut header).ok()? != header.len() || &header[..8] != BOOTFS_MAGIC {
        return None;
    }
    let count = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let wanted = path.as_bytes();
    let mut raw = [0u8; BOOTFS_ENTRY_SIZE as usize];
    for index in 0..count {
        let entry_off = BOOTFS_HEADER_SIZE + u64::from(index) * BOOTFS_ENTRY_SIZE;
        if vmo.read(entry_off, &mut raw).ok()? != raw.len() {
            return None;
        }
        let path_len = raw[..BOOTFS_PATH_SIZE]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(BOOTFS_PATH_SIZE);
        if &raw[..path_len] == wanted {
            let meta = &raw[BOOTFS_PATH_SIZE..];
            let offset = u64::from_le_bytes([
                meta[0], meta[1], meta[2], meta[3], meta[4], meta[5], meta[6], meta[7],
            ]);
            let len = u64::from_le_bytes([
                meta[8], meta[9], meta[10], meta[11], meta[12], meta[13], meta[14], meta[15],
            ]);
            if len == 0 || len > 4 * 1024 * 1024 {
                return None;
            }
            let mut out = alloc::vec![0u8; len as usize];
            if vmo.read(offset, &mut out).ok()? == out.len() {
                return Some(out);
            }
            return None;
        }
    }
    None
}

fn load_trust_store(ca_path: &str) -> Result<TrustStore, (i32, String)> {
    let pem_bytes = match fs::read(ca_path) {
        Ok(bytes) => bytes,
        Err(fs_err) => match read_bootfs_file(ca_path) {
            Some(bytes) => bytes,
            None => {
                return Err((
                    77,
                    format!(
                        "curl: (77) error setting certificate verify locations: '{}' ({})",
                        ca_path, fs_err
                    ),
                ));
            }
        },
    };
    TrustStore::from_pem_bytes(&pem_bytes).map_err(|e| {
        (
            77,
            format!(
                "curl: (77) invalid CA certificate bundle '{}': {:?}",
                ca_path, e
            ),
        )
    })
}

fn generate_tls_entropy(counter: u64) -> [u8; 128] {
    let mut seed_material = Vec::with_capacity(160);
    seed_material.extend_from_slice(&counter.to_le_bytes());
    let ticks = libcanvas::system::monotonic_ticks().unwrap_or(0x9E37_79B9_7F4A_7C15);
    seed_material.extend_from_slice(&ticks.to_le_bytes());
    for i in 0..16u64 {
        let r = libcanvas::memory::random_u64()
            .unwrap_or_else(|_| ticks.wrapping_mul(6364136223846793005).wrapping_add(i));
        seed_material.extend_from_slice(&r.to_le_bytes());
    }
    let mut out = [0u8; 128];
    for block in 0..4u32 {
        let mut blk_in = Vec::with_capacity(seed_material.len() + 4);
        blk_in.extend_from_slice(&seed_material);
        blk_in.extend_from_slice(&block.to_be_bytes());
        let digest = HashAlg::Sha256.digest(&blk_in);
        let off = (block as usize) * 32;
        out[off..off + 32].copy_from_slice(&digest);
    }
    out
}

fn decode_chunked_body(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        let Some(rel_end) = raw[pos..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = core::str::from_utf8(&raw[pos..pos + rel_end]).unwrap_or("");
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        pos += rel_end + 2;
        if chunk_len == 0 {
            break;
        }
        let avail = raw.len().saturating_sub(pos);
        let take = chunk_len.min(avail);
        out.extend_from_slice(&raw[pos..pos + take]);
        pos += take;
        if pos + 2 <= raw.len() && &raw[pos..pos + 2] == b"\r\n" {
            pos += 2;
        }
    }
    out
}

fn parse_status_and_location(hdr_str: &str) -> (u16, Option<String>) {
    let mut lines = hdr_str.lines();
    let status_code = lines
        .next()
        .and_then(|first| first.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut location = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("location") {
                location = Some(String::from(val.trim()));
                break;
            }
        }
    }
    (status_code, location)
}

fn perform_single_exchange(
    target: &ParsedUrl,
    verb: &str,
    custom_headers: &[String],
    body_data: Option<&str>,
    insecure_tls: bool,
    trust_store: Option<&TrustStore>,
    hop: u64,
) -> Result<Vec<u8>, (i32, String)> {
    let ip = net::resolve_host(&target.host).map_err(|err| {
        (
            6,
            format!(
                "curl: (6) Could not resolve host '{}': {}",
                target.host, err
            ),
        )
    })?;

    let mut stream = TcpStream::connect_timeout(ip, target.port, 8_000).map_err(|err| {
        (
            7,
            format!(
                "curl: (7) Failed to connect to {} ({}.{}.{}.{}) port {}: {}",
                target.host, ip[0], ip[1], ip[2], ip[3], target.port, err
            ),
        )
    })?;

    let default_port = if target.https { 443 } else { 80 };
    let host_hdr = if target.port == default_port {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };

    let mut req = format!(
        "{verb} {} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: HuesOS-curl/1.3\r\nAccept: */*\r\nConnection: close\r\n",
        target.path
    );
    for h in custom_headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    if let Some(body) = body_data {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    if let Some(body) = body_data {
        req.push_str(body);
    }

    if target.https {
        let verify_mode = if insecure_tls {
            VerifyMode::InsecureSkipVerify
        } else {
            let Some(store) = trust_store else {
                return Err((
                    77,
                    String::from("curl: (77) missing X.509 trust store for HTTPS"),
                ));
            };
            VerifyMode::Strict(store)
        };
        let tls_cfg = TlsClientConfig {
            verify_mode,
            now_unix_secs: None,
            alpn_protocol: Some(b"http/1.1"),
        };
        let entropy = generate_tls_entropy(hop);
        let mut tls = TlsStream::connect(TcpTlsAdapter(stream), &target.host, entropy, &tls_cfg)
            .map_err(|err| match err {
                TlsError::CertificateValidation(_) | TlsError::InvalidCertificateVerify => {
                    (60, format!("curl: (60) SSL certificate problem: {err}"))
                }
                _ => (35, format!("curl: (35) TLS 1.3 handshake failed: {err}")),
            })?;

        tls.write_all(req.as_bytes())
            .map_err(|err| (55, format!("curl: (55) TLS send failed: {err}")))?;

        let mut raw_resp = Vec::new();
        if let Err(err) = tls.read_to_end(&mut raw_resp) {
            if raw_resp.is_empty() {
                return Err((56, format!("curl: (56) TLS recv failed: {err}")));
            }
        }
        let _ = tls.send_close_notify();
        Ok(raw_resp)
    } else {
        stream
            .write_all(req.as_bytes())
            .map_err(|err| (55, format!("curl: send failed: {err}")))?;

        let mut raw_resp = Vec::new();
        if let Err(err) = stream.read_to_end(&mut raw_resp) {
            if raw_resp.is_empty() {
                return Err((56, format!("curl: recv failed: {err}")));
            }
        }
        Ok(raw_resp)
    }
}

fn run() -> i32 {
    let args = cu::collect_args();
    let mut head_only = false;
    let mut include_headers = false;
    let mut silent = false;
    let mut insecure_tls = false;
    let mut follow_redirects = false;
    let mut cacert_path: Option<String> = None;
    let mut method: Option<String> = None;
    let mut custom_headers: Vec<String> = Vec::new();
    let mut body_data: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut url_arg: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                usage();
                return 0;
            }
            "-I" | "--head" => {
                head_only = true;
                include_headers = true;
            }
            "-i" | "--include" => include_headers = true,
            "-s" | "--silent" => silent = true,
            "-k" | "--insecure" => insecure_tls = true,
            "-L" | "--location" => follow_redirects = true,
            "--cacert" => {
                i += 1;
                let Some(p) = args.get(i) else {
                    cu::errln("curl: --cacert requires a PEM file path");
                    return 2;
                };
                cacert_path = Some(p.clone());
            }
            "-X" | "--request" => {
                i += 1;
                let Some(m) = args.get(i) else {
                    cu::errln("curl: -X requires a method");
                    return 2;
                };
                method = Some(m.clone());
            }
            "-H" | "--header" => {
                i += 1;
                let Some(h) = args.get(i) else {
                    cu::errln("curl: -H requires a header");
                    return 2;
                };
                custom_headers.push(h.clone());
            }
            "-d" | "--data" => {
                i += 1;
                let Some(d) = args.get(i) else {
                    cu::errln("curl: -d requires payload data");
                    return 2;
                };
                body_data = Some(d.clone());
            }
            "-o" | "--output" => {
                i += 1;
                let Some(p) = args.get(i) else {
                    cu::errln("curl: -o requires an output path");
                    return 2;
                };
                out_path = Some(p.clone());
            }
            s if s.starts_with('-') => {
                cu::errln(&format!("curl: unknown option '{s}'"));
                return 2;
            }
            s => url_arg = Some(String::from(s)),
        }
        i += 1;
    }

    let Some(raw_url) = url_arg else {
        usage();
        return 2;
    };
    let mut target = match parse_url(&raw_url) {
        Ok(u) => u,
        Err(msg) => {
            if !silent {
                cu::errln(&format!("curl: {msg}"));
            }
            return 2;
        }
    };

    let mut loaded_store: Option<TrustStore> = None;
    let mut current_verb = String::from(method.as_deref().unwrap_or(if head_only {
        "HEAD"
    } else if body_data.is_some() {
        "POST"
    } else {
        "GET"
    }));
    let mut current_body = body_data;

    let mut raw_resp = Vec::new();
    for hop in 0..=MAX_REDIRECTS {
        if target.https && !insecure_tls && loaded_store.is_none() {
            let ca_file = cacert_path.as_deref().unwrap_or(DEFAULT_CA_BUNDLE);
            match load_trust_store(ca_file) {
                Ok(s) => loaded_store = Some(s),
                Err((code, msg)) => {
                    if !silent {
                        cu::errln(&msg);
                    }
                    return code;
                }
            }
        }

        match perform_single_exchange(
            &target,
            &current_verb,
            &custom_headers,
            current_body.as_deref(),
            insecure_tls,
            loaded_store.as_ref(),
            hop as u64,
        ) {
            Ok(resp) => raw_resp = resp,
            Err((code, msg)) => {
                if !silent {
                    cu::errln(&msg);
                }
                return code;
            }
        }

        if !follow_redirects {
            break;
        }
        let Some(split_idx) = raw_resp.windows(4).position(|w| w == b"\r\n\r\n") else {
            break;
        };
        let hdr_str = core::str::from_utf8(&raw_resp[..split_idx + 4]).unwrap_or("");
        let (status, loc_opt) = parse_status_and_location(hdr_str);
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if let Some(loc) = loc_opt {
                if hop == MAX_REDIRECTS {
                    if !silent {
                        cu::errln("curl: (47) Maximum redirects followed");
                    }
                    return 47;
                }
                match resolve_redirect_url(&target, &loc) {
                    Ok(next_url) => {
                        if matches!(status, 301 | 302 | 303)
                            && !current_verb.eq_ignore_ascii_case("GET")
                            && !current_verb.eq_ignore_ascii_case("HEAD")
                        {
                            current_verb = String::from("GET");
                            current_body = None;
                        }
                        target = next_url;
                        continue;
                    }
                    Err(msg) => {
                        if !silent {
                            cu::errln(&format!("curl: bad redirect URL: {msg}"));
                        }
                        return 2;
                    }
                }
            }
        }
        break;
    }

    let split_pos = raw_resp.windows(4).position(|w| w == b"\r\n\r\n");
    let (hdr_bytes, raw_body) = match split_pos {
        Some(idx) => (&raw_resp[..idx + 4], &raw_resp[idx + 4..]),
        None => (&[][..], &raw_resp[..]),
    };

    let hdr_str = core::str::from_utf8(hdr_bytes).unwrap_or("");
    let is_chunked = hdr_str.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });

    let decoded_chunked;
    let body: &[u8] = if head_only {
        &[]
    } else if is_chunked {
        decoded_chunked = decode_chunked_body(raw_body);
        &decoded_chunked
    } else {
        raw_body
    };

    if let Some(path) = out_path {
        if let Err(err) = fs::write(&path, body) {
            if !silent {
                cu::errln(&format!("curl: failed writing '{}': {}", path, err));
            }
            return 23;
        }
        if !silent {
            cu::outln(&format!("saved {} byte(s) -> {}", body.len(), path));
        }
        return 0;
    }

    let mut stdout = io::Stdout;
    if include_headers && !hdr_bytes.is_empty() {
        let _ = stdout.write(hdr_bytes);
    }
    if !body.is_empty() {
        let mut off = 0usize;
        while off < body.len() {
            match stdout.write(&body[off..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => off += n,
            }
        }
    }
    0
}
