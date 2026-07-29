//! VolumeManager service.
//!
//! Stage D is intentionally NVMe/SSD-specific: one raw whole-namespace system
//! volume is exposed over handle protocols. There is no attempt to optimize for
//! rotational or generic block devices.

use crate::protocol;
use libcanvas::{println, Channel, ErrorCode, Port};

use huesos_abi::block::{
    completion_data, decode_completion_data, AsyncBlockInfo, AsyncBlockOp, AsyncBlockRequest,
    AsyncBlockStatus, ASYNC_INFO_RESPONSE_BYTES,
};
use huesos_abi::volume::{
    VolumeInfo, VolumeOp, VolumeRequest, SYSTEM_VOLUME_ID, VOLUME_FLAG_NVME,
    VOLUME_FLAG_RAW_NAMESPACE, VOLUME_FLAG_SSD_OPTIMIZED, VOLUME_FLAG_SYSTEM, VOLUME_INFO_BYTES,
    VOLUME_KIND_RAW_NVME_NAMESPACE,
};
use huesos_abi::{rights, PORT_PACKET_BLOCK_COMPLETION};

const MAX_VOLUME_CLIENTS: usize = 4;
const MAX_BLOCK_RANGE_PROXIES: usize = 4;
const BACKEND_INFO_REQUEST_ID: u64 = u64::MAX - 1;

/// DriverManager-owned VolumeManager.
pub struct VolumeManagerService {
    system: Option<VolumeInfo>,
    clients: [Option<VolumeClient>; MAX_VOLUME_CLIENTS],
    proxies: [Option<BlockRangeProxy>; MAX_BLOCK_RANGE_PROXIES],
}

struct VolumeClient {
    channel: Channel,
}

struct BlockRangeProxy {
    client: Channel,
    backend: Channel,
    backend_completion: Port,
    client_completion: Option<Port>,
    start_block: u64,
    block_count: u64,
    block_size: u32,
    max_request_bytes: u32,
}

struct BackendAttachment {
    channel: Channel,
    completion: Port,
}

impl VolumeManagerService {
    /// Empty service.
    pub const fn new() -> Self {
        Self {
            system: None,
            clients: [const { None }; MAX_VOLUME_CLIENTS],
            proxies: [const { None }; MAX_BLOCK_RANGE_PROXIES],
        }
    }

    /// Open the system volume through the DriverManager registry.
    pub fn open_system_volume(
        &mut self,
        registry: &Channel,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
    ) {
        if !nvme_online {
            let _ = registry.write(protocol::VOLUME_SYSTEM_UNAVAILABLE.as_bytes());
            println!("[driver-manager] system volume requested before NVMe online");
            return;
        }
        let Some(nvme_bootstrap) = nvme_bootstrap else {
            let _ = registry.write(protocol::VOLUME_SYSTEM_UNAVAILABLE.as_bytes());
            return;
        };
        if self.ensure_system_volume(nvme_bootstrap).is_err() {
            let _ = registry.write(protocol::VOLUME_SYSTEM_UNAVAILABLE.as_bytes());
            return;
        }
        let Some(slot) = self.clients.iter_mut().find(|slot| slot.is_none()) else {
            let _ = registry.write(protocol::VOLUME_SYSTEM_UNAVAILABLE.as_bytes());
            println!("[driver-manager] volume client table full");
            return;
        };
        match Channel::pair() {
            Ok((client_end, server_end)) => {
                if let Err((error, _handle)) = registry.write_handle(
                    protocol::VOLUME_SYSTEM_CHANNEL.as_bytes(),
                    client_end.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to return system volume channel: {}",
                        error.as_str()
                    );
                    return;
                }
                *slot = Some(VolumeClient {
                    channel: server_end,
                });
                println!("[driver-manager] opened system volume handle");
            }
            Err(error) => {
                println!(
                    "[driver-manager] failed to create volume channel: {}",
                    error.as_str()
                );
                let _ = registry.write(protocol::VOLUME_SYSTEM_UNAVAILABLE.as_bytes());
            }
        }
    }

    /// Open the filesystem-candidate block range for DevFS.
    pub fn open_fs_candidate_for_devfs(
        &mut self,
        target: &Channel,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
    ) {
        let Some(nvme_bootstrap) = nvme_bootstrap else {
            let _ = target.write(b"err:volume");
            return;
        };
        match self.open_fs_candidate_channel(nvme_bootstrap, nvme_online) {
            Ok(channel) => {
                if let Err((error, _handle)) = target.write_handle(
                    protocol::VOLUME_FS_CANDIDATE_CHANNEL.as_bytes(),
                    channel.into_handle(),
                ) {
                    println!(
                        "[driver-manager] failed to return DevFS fs-candidate: {}",
                        error.as_str()
                    );
                }
            }
            Err(_) => {
                let _ = target.write(b"err:volume");
            }
        }
    }

    /// Open the filesystem-candidate block range for an internal service.
    pub fn open_fs_candidate_channel(
        &mut self,
        nvme_bootstrap: &Channel,
        nvme_online: bool,
    ) -> Result<Channel, ErrorCode> {
        if !nvme_online {
            return Err(ErrorCode::ShouldWait);
        }
        self.ensure_system_volume(nvme_bootstrap)?;
        let Some(info) = self.system else {
            return Err(ErrorCode::InvalidArgs);
        };
        self.create_range_channel(nvme_bootstrap, 0, info.block_count, true)
    }

    /// Poll volume clients and block-range proxies.
    pub fn poll(&mut self, nvme_bootstrap: Option<&Channel>, nvme_online: bool) {
        let mut index = 0usize;
        while index < self.clients.len() {
            self.poll_volume_client(index, nvme_bootstrap, nvme_online);
            index += 1;
        }
        let mut proxy = 0usize;
        while proxy < self.proxies.len() {
            self.poll_proxy(proxy);
            proxy += 1;
        }
    }

    fn ensure_system_volume(&mut self, nvme_bootstrap: &Channel) -> Result<(), ErrorCode> {
        if self.system.is_some() {
            return Ok(());
        }
        let backend = attach_backend(nvme_bootstrap)?;
        let request = AsyncBlockRequest {
            op: AsyncBlockOp::Info,
            request_id: BACKEND_INFO_REQUEST_ID,
            namespace_id: 1,
            lba: 0,
            block_count: 0,
            buffer_id: 0,
        };
        backend.channel.write(&request.encode())?;
        wait_completion(&backend.completion, BACKEND_INFO_REQUEST_ID)?;
        let mut bytes = [0u8; ASYNC_INFO_RESPONSE_BYTES];
        read_exact_channel(&backend.channel, &mut bytes)?;
        let Some(info) = AsyncBlockInfo::decode(&bytes) else {
            return Err(ErrorCode::InvalidArgs);
        };
        self.system = Some(VolumeInfo {
            volume_id: SYSTEM_VOLUME_ID,
            kind: VOLUME_KIND_RAW_NVME_NAMESPACE,
            flags: VOLUME_FLAG_NVME
                | VOLUME_FLAG_SSD_OPTIMIZED
                | VOLUME_FLAG_RAW_NAMESPACE
                | VOLUME_FLAG_SYSTEM,
            block_size: info.block_size,
            reserved0: 0,
            block_count: info.block_count,
            max_request_bytes: info.max_request_bytes,
        });
        println!(
            "[driver-manager] VolumeManager system volume: raw NVMe namespace blocks={} block_size={}",
            info.block_count, info.block_size
        );
        Ok(())
    }

    fn poll_volume_client(
        &mut self,
        index: usize,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
    ) {
        let mut request = [0u8; huesos_abi::volume::VOLUME_REQUEST_BYTES];
        loop {
            let Some(client) = self.clients[index].as_ref() else {
                return;
            };
            match client.channel.read_into(&mut request) {
                Ok(n) => {
                    self.handle_volume_request(index, nvme_bootstrap, nvme_online, &request[..n])
                }
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.clients[index] = None;
                    return;
                }
                Err(error) => {
                    println!(
                        "[driver-manager] volume client read failed: {}",
                        error.as_str()
                    );
                    return;
                }
            }
        }
    }

    fn handle_volume_request(
        &mut self,
        index: usize,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
        bytes: &[u8],
    ) {
        let Some(request) = VolumeRequest::decode(bytes) else {
            self.write_volume_error(index);
            return;
        };
        match request.op {
            VolumeOp::GetInfo => self.write_volume_info(index),
            VolumeOp::OpenBlockRange => self.open_range(
                index,
                nvme_bootstrap,
                nvme_online,
                request.start_block,
                request.block_count,
                false,
            ),
            VolumeOp::OpenFsCandidate => {
                let Some(info) = self.system else {
                    self.write_volume_error(index);
                    return;
                };
                self.open_range(
                    index,
                    nvme_bootstrap,
                    nvme_online,
                    0,
                    info.block_count,
                    true,
                )
            }
        }
    }

    fn write_volume_info(&self, index: usize) {
        let Some(info) = self.system else {
            self.write_volume_error(index);
            return;
        };
        let Some(client) = self.clients[index].as_ref() else {
            return;
        };
        let bytes = info.encode();
        if bytes.len() != VOLUME_INFO_BYTES {
            return;
        }
        let _ = client.channel.write(&bytes);
    }

    fn open_range(
        &mut self,
        index: usize,
        nvme_bootstrap: Option<&Channel>,
        nvme_online: bool,
        start_block: u64,
        block_count: u64,
        fs_candidate: bool,
    ) {
        if !nvme_online {
            self.write_volume_error(index);
            return;
        }
        let Some(info) = self.system else {
            self.write_volume_error(index);
            return;
        };
        let Some(end) = start_block.checked_add(block_count) else {
            self.write_volume_error(index);
            return;
        };
        if block_count == 0 || end > info.block_count {
            self.write_volume_error(index);
            return;
        }
        let Some(nvme_bootstrap) = nvme_bootstrap else {
            self.write_volume_error(index);
            return;
        };
        let label = if fs_candidate {
            protocol::VOLUME_FS_CANDIDATE_CHANNEL.as_bytes()
        } else {
            protocol::VOLUME_BLOCK_RANGE_CHANNEL.as_bytes()
        };
        let range =
            self.create_range_channel(nvme_bootstrap, start_block, block_count, fs_candidate);
        let Ok(client_end) = range else {
            self.write_volume_error(index);
            return;
        };
        let Some(client) = self.clients[index].as_ref() else {
            return;
        };
        if let Err((error, _handle)) = client.channel.write_handle(label, client_end.into_handle())
        {
            println!(
                "[driver-manager] failed to return volume block range: {}",
                error.as_str()
            );
            self.write_volume_error(index);
        }
    }

    fn create_range_channel(
        &mut self,
        nvme_bootstrap: &Channel,
        start_block: u64,
        block_count: u64,
        fs_candidate: bool,
    ) -> Result<Channel, ErrorCode> {
        let Some(info) = self.system else {
            return Err(ErrorCode::InvalidArgs);
        };
        let Some(proxy_index) = self.proxies.iter().position(Option::is_none) else {
            println!("[driver-manager] volume block-range proxy table full");
            return Err(ErrorCode::NoMemory);
        };
        let backend = attach_backend(nvme_bootstrap)?;
        let (client_end, proxy_client) = Channel::pair()?;
        self.proxies[proxy_index] = Some(BlockRangeProxy {
            client: proxy_client,
            backend: backend.channel,
            backend_completion: backend.completion,
            client_completion: None,
            start_block,
            block_count,
            block_size: info.block_size,
            max_request_bytes: info.max_request_bytes,
        });
        println!(
            "[driver-manager] opened volume block range start={} count={} fs_candidate={}",
            start_block, block_count, fs_candidate as u8
        );
        Ok(client_end)
    }

    fn write_volume_error(&self, index: usize) {
        if let Some(client) = self.clients[index].as_ref() {
            let _ = client.channel.write(b"err:volume");
        }
    }

    fn poll_proxy(&mut self, index: usize) {
        self.drain_backend_completions(index);
        let mut buf = [0u8; 96];
        loop {
            let Some(proxy) = self.proxies[index].as_mut() else {
                return;
            };
            match proxy.client.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"block:completion-port" => {
                    proxy.client_completion = Some(Port::from_handle(handle));
                }
                Ok((n, Some(handle))) if buf[..n].starts_with(b"block:buffer:0x") => {
                    if let Err((error, handle)) = proxy.backend.write_handle(&buf[..n], handle) {
                        println!(
                            "[driver-manager] failed to forward volume buffer handle: {}",
                            error.as_str()
                        );
                        drop(handle);
                    }
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((n, None)) => self.handle_proxy_request(index, &buf[..n]),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.proxies[index] = None;
                    return;
                }
                Err(error) => {
                    println!(
                        "[driver-manager] volume proxy read failed: {}",
                        error.as_str()
                    );
                    return;
                }
            }
        }
    }

    fn drain_backend_completions(&self, index: usize) {
        let Some(proxy) = self.proxies[index].as_ref() else {
            return;
        };
        loop {
            match proxy.backend_completion.read() {
                Ok(packet) => {
                    if let Some(client_port) = proxy.client_completion.as_ref() {
                        let _ = client_port.queue(&packet);
                    }
                }
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(_) => return,
            }
        }
    }

    fn handle_proxy_request(&mut self, index: usize, bytes: &[u8]) {
        let Some(request) = AsyncBlockRequest::decode(bytes) else {
            self.complete_proxy(index, 0, AsyncBlockStatus::InvalidArgs, 0);
            return;
        };
        let Some(proxy) = self.proxies[index].as_ref() else {
            return;
        };
        match request.op {
            AsyncBlockOp::Info => {
                let info = AsyncBlockInfo {
                    namespace_id: 1,
                    block_size: proxy.block_size,
                    block_count: proxy.block_count,
                    max_request_bytes: proxy.max_request_bytes,
                };
                let _ = proxy.client.write(&info.encode());
                self.complete_proxy(
                    index,
                    request.request_id,
                    AsyncBlockStatus::Ok,
                    ASYNC_INFO_RESPONSE_BYTES as u64,
                );
            }
            AsyncBlockOp::Read | AsyncBlockOp::Write => self.forward_ranged_request(index, request),
            AsyncBlockOp::Flush => {
                let _ = proxy.backend.write(&request.encode());
            }
        }
    }

    fn forward_ranged_request(&self, index: usize, request: AsyncBlockRequest) {
        let Some(proxy) = self.proxies[index].as_ref() else {
            return;
        };
        let Some(end) = u64::from(request.block_count).checked_add(request.lba) else {
            self.complete_proxy(index, request.request_id, AsyncBlockStatus::InvalidArgs, 0);
            return;
        };
        if end > proxy.block_count {
            self.complete_proxy(index, request.request_id, AsyncBlockStatus::InvalidArgs, 0);
            return;
        }
        let Some(backing_lba) = proxy.start_block.checked_add(request.lba) else {
            self.complete_proxy(index, request.request_id, AsyncBlockStatus::InvalidArgs, 0);
            return;
        };
        let forwarded = AsyncBlockRequest {
            lba: backing_lba,
            ..request
        };
        if proxy.backend.write(&forwarded.encode()).is_err() {
            self.complete_proxy(index, request.request_id, AsyncBlockStatus::IoError, 0);
        }
    }

    fn complete_proxy(&self, index: usize, request_id: u64, status: AsyncBlockStatus, bytes: u64) {
        let Some(proxy) = self.proxies[index].as_ref() else {
            return;
        };
        let Some(port) = proxy.client_completion.as_ref() else {
            return;
        };
        let packet = libcanvas::PortPacket {
            key: request_id,
            packet_type: PORT_PACKET_BLOCK_COMPLETION,
            status: 0,
            data: completion_data(request_id, status, bytes, 0),
        };
        let _ = port.queue(&packet);
    }
}

fn attach_backend(nvme_bootstrap: &Channel) -> Result<BackendAttachment, ErrorCode> {
    let (client_end, server_end) = Channel::pair()?;
    nvme_bootstrap
        .write_handle(
            protocol::ATTACH_BLOCK_NVME_CLIENT.as_bytes(),
            server_end.into_handle(),
        )
        .map_err(|(error, _handle)| error)?;
    let completion = Port::create()?;
    let completion_for_backend = completion.handle().duplicate(rights::SAME_RIGHTS)?;
    client_end
        .write_handle(b"block:completion-port", completion_for_backend)
        .map_err(|(error, _handle)| error)?;
    Ok(BackendAttachment {
        channel: client_end,
        completion,
    })
}

fn wait_completion(port: &Port, request_id: u64) -> Result<(), ErrorCode> {
    let mut attempts = 0u32;
    while attempts < 200_000 {
        match port.read() {
            Ok(packet) if packet.packet_type == PORT_PACKET_BLOCK_COMPLETION => {
                let Some((id, status, _bytes, _nvme)) = decode_completion_data(packet.data) else {
                    return Err(ErrorCode::InvalidArgs);
                };
                if id == request_id {
                    return match status {
                        AsyncBlockStatus::Ok => Ok(()),
                        AsyncBlockStatus::InvalidArgs => Err(ErrorCode::InvalidArgs),
                        AsyncBlockStatus::IoError => Err(ErrorCode::Internal),
                        AsyncBlockStatus::Timeout => Err(ErrorCode::TimedOut),
                        AsyncBlockStatus::NoResources => Err(ErrorCode::NoMemory),
                    };
                }
            }
            Ok(_) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(error) => return Err(error),
        }
        attempts = attempts.saturating_add(1);
    }
    Err(ErrorCode::TimedOut)
}

fn read_exact_channel(channel: &Channel, out: &mut [u8]) -> Result<(), ErrorCode> {
    let mut attempts = 0u32;
    while attempts < 200_000 {
        match channel.read_into(out) {
            Ok(n) if n == out.len() => return Ok(()),
            Ok(_) => return Err(ErrorCode::InvalidArgs),
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(error) => return Err(error),
        }
        attempts = attempts.saturating_add(1);
    }
    Err(ErrorCode::TimedOut)
}
