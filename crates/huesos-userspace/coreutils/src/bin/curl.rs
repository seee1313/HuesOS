//! `/bin/curl.elf` — HTTP/1.1 client over `huesos_std::net::TcpStream`.
//!
//! Usage: `curl [-I] [-i] [-s] [-X <METHOD>] [-H <Header: val>] [-d <body>] [-o <file>] <http://host[:port]/path>`

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use huesos_coreutils as cu;
use huesos_std::fs;
use huesos_std::io::{self, Write};
use huesos_std::net::{self, TcpStream};

cu::coreutil_entry!(run);

fn usage() {
    cu::outln("usage: curl [-I] [-i] [-s] [-X METHOD] [-H 'Header: v'] [-d data] [-o file] <http://host[:port]/path>");
}

struct ParsedUrl<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_http_url(raw: &str) -> Result<ParsedUrl<'_>, &'static str> {
    let rest = if let Some(r) = raw.strip_prefix("http://") {
        r
    } else if raw.contains("://") {
        return Err("only http:// scheme is supported without TLS");
    } else {
        raw
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
        (authority, 80u16)
    };
    if host.is_empty() {
        return Err("empty host in URL");
    }
    Ok(ParsedUrl { host, port, path })
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

fn run() -> i32 {
    let args = cu::collect_args();
    let mut head_only = false;
    let mut include_headers = false;
    let mut silent = false;
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
    let parsed = match parse_http_url(&raw_url) {
        Ok(u) => u,
        Err(msg) => {
            if !silent {
                cu::errln(&format!("curl: {msg}"));
            }
            return 2;
        }
    };

    let ip = match net::resolve_host(parsed.host) {
        Ok(ip) => ip,
        Err(err) => {
            if !silent {
                cu::errln(&format!(
                    "curl: (6) Could not resolve host '{}': {}",
                    parsed.host, err
                ));
            }
            return 6;
        }
    };

    let mut stream = match TcpStream::connect_timeout(ip, parsed.port, 5_000) {
        Ok(s) => s,
        Err(err) => {
            if !silent {
                cu::errln(&format!(
                    "curl: (7) Failed to connect to {} ({}.{}.{}.{}) port {}: {}",
                    parsed.host, ip[0], ip[1], ip[2], ip[3], parsed.port, err
                ));
            }
            return 7;
        }
    };

    let verb = method.as_deref().unwrap_or(if head_only {
        "HEAD"
    } else if body_data.is_some() {
        "POST"
    } else {
        "GET"
    });
    let host_hdr = if parsed.port == 80 {
        String::from(parsed.host)
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };

    let mut req = format!(
        "{verb} {} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: HuesOS-curl/1.0\r\nAccept: */*\r\nConnection: close\r\n",
        parsed.path
    );
    for h in &custom_headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    if let Some(body) = body_data.as_ref() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    if let Some(body) = body_data.as_ref() {
        req.push_str(body);
    }

    if let Err(err) = stream.write_all(req.as_bytes()) {
        if !silent {
            cu::errln(&format!("curl: send failed: {err}"));
        }
        return 55;
    }

    let mut raw_resp = Vec::new();
    if let Err(err) = stream.read_to_end(&mut raw_resp) {
        if raw_resp.is_empty() {
            if !silent {
                cu::errln(&format!("curl: recv failed: {err}"));
            }
            return 56;
        }
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
