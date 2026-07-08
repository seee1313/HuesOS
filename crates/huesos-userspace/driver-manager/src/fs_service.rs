//! FileSystemService backed by BOOTFS.

use crate::bootfs::BootFs;
use crate::protocol;
use libcanvas::{println, Channel, ErrorCode, Vmo};

const RESPONSE_MAX: usize = 1024;

/// DriverManager-owned filesystem service.
pub struct FileSystemService {
    bootfs: Option<BootFs>,
    client: Option<Channel>,
}

impl FileSystemService {
    pub const fn new() -> Self {
        Self {
            bootfs: None,
            client: None,
        }
    }

    pub fn install_bootfs(&mut self, vmo: Vmo) {
        match BootFs::new(vmo) {
            Ok(bootfs) => {
                println!("[driver-manager] BOOTFS mounted");
                self.bootfs = Some(bootfs);
            }
            Err(e) => println!("[driver-manager] invalid BOOTFS image: {}", e.as_str()),
        }
    }

    pub fn bootfs(&self) -> Option<&BootFs> {
        self.bootfs.as_ref()
    }

    pub fn vmo(&self) -> Option<&Vmo> {
        self.bootfs.as_ref().map(|b| &b.vmo)
    }

    pub fn open_for_registry(&mut self, registry: &Channel) {
        match Channel::pair() {
            Ok((client_end, server_end)) => {
                if let Err(e) = registry.write_handle(protocol::FILESYSTEM_CHANNEL.as_bytes(), client_end.into_handle()) {
                    println!("[driver-manager] failed to return filesystem channel: {}", e.as_str());
                    return;
                }
                self.client = Some(server_end);
                println!("[driver-manager] opened filesystem service channel for client");
            }
            Err(e) => println!("[driver-manager] failed to create filesystem channel: {}", e.as_str()),
        }
    }

    pub fn poll(&mut self) {
        let mut request = [0u8; 128];
        loop {
            let Some(client) = self.client.as_ref() else {
                return;
            };
            match client.read_into(&mut request) {
                Ok(n) => self.handle_request(&request[..n]),
                Err(ErrorCode::ShouldWait) => return,
                Err(e) => {
                    println!("[driver-manager] filesystem request read failed: {}", e.as_str());
                    return;
                }
            }
        }
    }

    fn handle_request(&mut self, request: &[u8]) {
        let mut response = [0u8; RESPONSE_MAX];
        let len = match self.dispatch(request, &mut response) {
            Ok(n) => n,
            Err(ErrorCode::NotFound) => write_bytes(&mut response, b"err:not-found\n"),
            Err(ErrorCode::InvalidArgs) => write_bytes(&mut response, b"err:invalid-args\n"),
            Err(_) => write_bytes(&mut response, b"err:fs\n"),
        };
        if let Some(client) = self.client.as_ref() {
            let _ = client.write(&response[..len]);
        }
    }

    fn dispatch(&self, request: &[u8], response: &mut [u8]) -> libcanvas::Result<usize> {
        let Some(bootfs) = self.bootfs.as_ref() else {
            return Ok(write_bytes(response, b"err:not-ready\n"));
        };
        if let Some(path) = strip_prefix(request, b"LIST ") {
            return bootfs.list_text(as_str(path)?, response);
        }
        if let Some(path) = strip_prefix(request, b"CAT ") {
            return bootfs.read_file(as_str(path)?, response);
        }
        if let Some(path) = strip_prefix(request, b"STAT ") {
            return bootfs.stat_text(as_str(path)?, response);
        }
        Err(ErrorCode::InvalidArgs)
    }
}

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.starts_with(prefix) {
        Some(&bytes[prefix.len()..])
    } else {
        None
    }
}

fn as_str(bytes: &[u8]) -> libcanvas::Result<&str> {
    core::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidArgs)
}

fn write_bytes(out: &mut [u8], bytes: &[u8]) -> usize {
    let len = bytes.len().min(out.len());
    out[..len].copy_from_slice(&bytes[..len]);
    len
}
