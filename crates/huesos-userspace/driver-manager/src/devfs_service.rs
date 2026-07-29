//! DevFS runtime handle namespace.
//!
//! DevFS is not a disk filesystem. It is a small, runtime namespace that
//! resolves paths to typed HuesOS handles. Stage F keeps it NVMe/SSD-system
//! focused: `/dev/block/system` is the system Volume handle backed by the raw
//! NVMe namespace.

use crate::protocol;
use crate::volume_service::VolumeManagerService;
use libcanvas::{println, Channel, ErrorCode};

const MAX_DEVFS_CLIENTS: usize = 4;
const LISTING: &[u8] = b"/dev\n/dev/nvme0\n/dev/nvme0/ns1\n/dev/block\n/dev/block/system\n/dev/input\n/dev/input/keyboard0\n/dev/fb0\n/dev/drivers\n/dev/drivers/nvme-host\n";

/// DriverManager-owned DevFS service.
pub struct DevFsService {
    clients: [Option<Channel>; MAX_DEVFS_CLIENTS],
}

impl DevFsService {
    /// Empty DevFS service.
    pub const fn new() -> Self {
        Self {
            clients: [const { None }; MAX_DEVFS_CLIENTS],
        }
    }

    /// Open DevFS through the DriverManager registry.
    pub fn open_for_registry(&mut self, registry: &Channel) {
        let Some(slot) = self.clients.iter_mut().find(|slot| slot.is_none()) else {
            let _ = registry.write(protocol::DEVFS_UNAVAILABLE.as_bytes());
            println!("[driver-manager] DevFS client table full");
            return;
        };
        match Channel::pair() {
            Ok((client_end, server_end)) => {
                if let Err((error, _handle)) = registry
                    .write_handle(protocol::DEVFS_CHANNEL.as_bytes(), client_end.into_handle())
                {
                    println!(
                        "[driver-manager] failed to return DevFS channel: {}",
                        error.as_str()
                    );
                    return;
                }
                *slot = Some(server_end);
                println!("[driver-manager] opened DevFS service channel");
            }
            Err(error) => {
                println!(
                    "[driver-manager] failed to create DevFS channel: {}",
                    error.as_str()
                );
                let _ = registry.write(protocol::DEVFS_UNAVAILABLE.as_bytes());
            }
        }
    }

    /// Poll all DevFS clients.
    pub fn poll(
        &mut self,
        volume: &mut VolumeManagerService,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
    ) {
        let mut index = 0usize;
        while index < self.clients.len() {
            self.poll_client(index, volume, nvme_bootstrap, nvme_online);
            index += 1;
        }
    }

    fn poll_client(
        &mut self,
        index: usize,
        volume: &mut VolumeManagerService,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
    ) {
        let mut request = [0u8; 128];
        loop {
            let Some(client) = self.clients[index].as_ref() else {
                return;
            };
            match client.read_into(&mut request) {
                Ok(n) => {
                    self.handle_request(index, volume, nvme_bootstrap, nvme_online, &request[..n])
                }
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.clients[index] = None;
                    return;
                }
                Err(error) => {
                    println!("[driver-manager] DevFS read failed: {}", error.as_str());
                    return;
                }
            }
        }
    }

    fn handle_request(
        &mut self,
        index: usize,
        volume: &mut VolumeManagerService,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
        request: &[u8],
    ) {
        if request == b"LIST /dev" || request == b"LIST /" {
            self.write(index, LISTING);
            return;
        }
        if request == b"OPEN /dev/block/system" {
            let Some(client) = self.clients[index].as_ref() else {
                return;
            };
            volume.open_system_volume(client, nvme_bootstrap, nvme_online);
            return;
        }
        if request == b"OPEN /dev/nvme0/ns1" {
            let Some(client) = self.clients[index].as_ref() else {
                return;
            };
            volume.open_fs_candidate_for_devfs(client, nvme_bootstrap, nvme_online);
            return;
        }
        if request == b"OPEN /dev/input/keyboard0"
            || request == b"OPEN /dev/fb0"
            || request == b"OPEN /dev/drivers/nvme-host"
        {
            self.write(index, b"err:devfs-not-supported\n");
            return;
        }
        self.write(index, b"err:devfs-not-found\n");
    }

    fn write(&self, index: usize, bytes: &[u8]) {
        if let Some(client) = self.clients[index].as_ref() {
            let _ = client.write(bytes);
        }
    }
}
