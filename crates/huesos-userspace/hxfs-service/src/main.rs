//! Fixed-capacity Hxfs userspace service.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_abi::hxfs::{
    response_flags, rights as hxfs_rights, HxfsHandleKind, HxfsOp, HxfsRequest, HxfsResponse,
    HxfsStatus, HXFS_MAX_INLINE_WRITE_BYTES, HXFS_REQUEST_BYTES, HXFS_RESPONSE_BYTES,
};
use huesos_hxfs::fixed_writer::FixedHxfsWriter;
use huesos_hxfs::format::{DirectoryHandle, FileHandle};
use huesos_hxfs::reader::BlockReader;
use huesos_hxfs::recovery::{replay_journal, BlockStore, ReplayOutcome};
use huesos_hxfs::HxfsError;
use libcanvas::{println, Channel, ErrorCode, Vmo};

const MAX_CLIENTS: usize = 4;
const MAX_FILE_HANDLES: usize = 8;
const MAX_DIR_HANDLES: usize = 8;
const MAX_READ_BYTES: usize = 4096;
const MAX_NATIVE_REQUEST_BYTES: usize = HXFS_REQUEST_BYTES + HXFS_MAX_INLINE_WRITE_BYTES;
// `poll_client` / `poll_file` / `poll_dir` allocate a scratch
// buffer on the stack every time they are entered. The full
// `MAX_NATIVE_REQUEST_BYTES` (4 KiB) is enough to overflow the 64
// KiB `USER_STACK_SIZE` once `mount_from_bootstrap` and
// `FixedHxfsWriter::mount` are on the same call chain, which is
// the chain that runs on the first `runtime.poll` after
// `[hxfs] service started`. The hxfs service is a single-process
// loop and the largest request it actually services in qemu-nvme-boot
// is a directory `OPEN_FILE <name>` whose name is at most
// `MAX_NAME_BYTES` (255) bytes; 256 bytes is plenty. The
// `MAX_NATIVE_REQUEST_BYTES` ABI constant is preserved for
// `write_response_to_channel` (which only runs once per request).
const POLL_BUF_BYTES: usize = 256;
// Sized to fit the `mount_from_bootstrap` -> `FixedHxfsWriter::mount`
// stack frame inside `USER_STACK_SIZE` (64 KiB). The previous
// 32/64/64 capacities put roughly 30 KiB of fixed `[Option<T>; N]`
// arrays on the stack in a single frame, which overflowed the
// guard page (`user-fault rip=0x403f4d address=0x7ffffefef688` in
// the qemu-nvme-boot smoke). The seed v5 image uses only a handful
// of objects/entries/extents, so 16/16/16 leaves comfortable headroom.
const SERVICE_MAX_OBJECTS: usize = 16;
const SERVICE_MAX_DIR_ENTRIES: usize = 16;
const SERVICE_MAX_EXTENTS: usize = 16;
// The qemu-nvme-boot namespace is exposed with a 512-byte LBA while
// Hxfs internally works in 4 KiB blocks. The
// `libcanvas::block::BlockDevice` wire protocol speaks 512-byte LBAs,
// so a single hxfs 4 KiB block transfer is 8 LBAs. Translate the
// hxfs-side (lba, blocks) into NVMe-side (lba * 8, blocks * 8)
// before forwarding; otherwise the first 512 bytes of each hxfs
// read are valid and the remaining 3584 are uninitialised VMO
// memory, which fails the superblock/object-table CRC check with
// `BadBlock` immediately after `[hxfs] service started`.
const HXFS_LBA_FACTOR: u32 = 8;

struct BlockDeviceReader {
    device: libcanvas::block::BlockDevice,
}

impl BlockReader for BlockDeviceReader {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        let lbas = lba
            .checked_mul(u64::from(HXFS_LBA_FACTOR))
            .ok_or(HxfsError::OutOfRange)?;
        let total = u64::from(blocks)
            .checked_mul(u64::from(HXFS_LBA_FACTOR))
            .ok_or(HxfsError::OutOfRange)?;
        let total = u32::try_from(total).map_err(|_| HxfsError::OutOfRange)?;
        self.device
            .read_blocks(lbas, total, out)
            .map_err(|_| HxfsError::Io)
    }
}

impl BlockStore for BlockDeviceReader {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        let lbas = lba
            .checked_mul(u64::from(HXFS_LBA_FACTOR))
            .ok_or(HxfsError::OutOfRange)?;
        let total = u64::from(blocks)
            .checked_mul(u64::from(HXFS_LBA_FACTOR))
            .ok_or(HxfsError::OutOfRange)?;
        let total = u32::try_from(total).map_err(|_| HxfsError::OutOfRange)?;
        self.device
            .write_blocks(lbas, total, input)
            .map_err(|_| HxfsError::Io)
    }

    fn flush(&mut self) -> Result<(), HxfsError> {
        self.device.flush().map_err(|_| HxfsError::Io)
    }
}

type MountedHxfs = FixedHxfsWriter<
    BlockDeviceReader,
    SERVICE_MAX_OBJECTS,
    SERVICE_MAX_DIR_ENTRIES,
    SERVICE_MAX_EXTENTS,
>;

#[derive(Clone, Copy)]
struct ResponseMeta {
    status: HxfsStatus,
    handle_kind: HxfsHandleKind,
    handle_id: u64,
    rights: u64,
    object_id: u64,
    value: u64,
    flags: u32,
}

struct FileEndpoint {
    channel: Channel,
    handle: FileHandle,
}

struct DirEndpoint {
    channel: Channel,
    handle: DirectoryHandle,
}

struct HxfsRuntime {
    fs: MountedHxfs,
    clients: [Option<Channel>; MAX_CLIENTS],
    files: [Option<FileEndpoint>; MAX_FILE_HANDLES],
    dirs: [Option<DirEndpoint>; MAX_DIR_HANDLES],
}

impl HxfsRuntime {
    fn new(fs: MountedHxfs) -> Self {
        Self {
            fs,
            clients: [const { None }; MAX_CLIENTS],
            files: [const { None }; MAX_FILE_HANDLES],
            dirs: [const { None }; MAX_DIR_HANDLES],
        }
    }

    fn poll(&mut self, bootstrap: &Channel) {
        self.poll_bootstrap(bootstrap);
        let mut index = 0usize;
        while index < self.clients.len() {
            self.poll_client(index);
            index += 1;
        }
        let mut file = 0usize;
        while file < self.files.len() {
            self.poll_file(file);
            file += 1;
        }
        let mut dir = 0usize;
        while dir < self.dirs.len() {
            self.poll_dir(dir);
            dir += 1;
        }
    }

    fn poll_bootstrap(&mut self, bootstrap: &Channel) {
        let mut buf = [0u8; 64];
        loop {
            match bootstrap.read_optional_handle(&mut buf) {
                Ok((n, Some(handle))) if &buf[..n] == b"hxfs-client" => {
                    self.attach_client(Channel::from_handle(handle));
                }
                Ok((_n, Some(handle))) => drop(handle),
                Ok((_n, None)) => {}
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(_) => return,
            }
        }
    }

    fn attach_client(&mut self, channel: Channel) {
        let Some(slot) = self.clients.iter_mut().find(|slot| slot.is_none()) else {
            println!("[hxfs] client table full");
            drop(channel);
            return;
        };
        *slot = Some(channel);
    }

    fn poll_client(&mut self, index: usize) {
        let mut buf = [0u8; POLL_BUF_BYTES];
        loop {
            let Some(client) = self.clients[index].as_ref() else {
                return;
            };
            match client.read_into(&mut buf) {
                Ok(n) => self.handle_client_request(index, &buf[..n]),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.clients[index] = None;
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn handle_client_request(&mut self, index: usize, request: &[u8]) {
        if let Some((native, payload)) = decode_native_message(request) {
            self.handle_client_native(index, native, payload);
            return;
        }
        if request == b"ROOT" || request == b"OPEN_DIR /" {
            self.return_dir(index, self.fs.root_directory());
            return;
        }
        if let Some(path) = strip_prefix(request, b"OPEN_FILE ") {
            self.open_file_path(index, path);
            return;
        }
        if let Some(path) = strip_prefix(request, b"OPEN_DIR ") {
            self.open_dir_path(index, path);
            return;
        }
        self.write_client(index, b"err:hxfs-invalid");
    }

    fn handle_client_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        match request.op {
            HxfsOp::GetInfo => self.write_client_response(
                index,
                request,
                HxfsStatus::Ok,
                HxfsHandleKind::Volume,
                0,
                hxfs_rights::ALL,
                self.fs.volume_info().root_object_id,
                self.fs.superblock().sequence_number,
            ),
            HxfsOp::OpenRoot => {
                self.return_dir_abi_to_client(index, request, self.fs.root_directory())
            }
            HxfsOp::OpenPath => self.client_open_native(index, request, payload),
            HxfsOp::Mkdir => self.client_mkdir_native(index, request, payload),
            HxfsOp::CreateFile => self.client_create_file_native(index, request, payload),
            HxfsOp::Rename => self.client_rename_native(index, request, payload),
            HxfsOp::Unlink => self.client_unlink_native(index, request, payload),
            HxfsOp::Fsync | HxfsOp::Checkpoint => self.client_checkpoint_native(index, request),
            _ => self.write_client_status(index, request, HxfsStatus::Unsupported),
        }
    }

    fn client_open_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Ok(path) = core::str::from_utf8(payload) else {
            self.write_client_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match request.handle_kind {
            HxfsHandleKind::File => match self.fs.open_path(path) {
                Ok(file) => self.return_file_abi_to_client(index, request, file),
                Err(error) => self.write_client_status(index, request, status_for_error(error)),
            },
            HxfsHandleKind::Directory => match self.fs.open_directory_path(path) {
                Ok(dir) => self.return_dir_abi_to_client(index, request, dir),
                Err(error) => self.write_client_status(index, request, status_for_error(error)),
            },
            _ => self.write_client_status(index, request, HxfsStatus::Invalid),
        }
    }

    fn client_mkdir_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Ok(path) = core::str::from_utf8(payload) else {
            self.write_client_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match self.fs.mkdir_path(path) {
            Ok(dir) => self.return_dir_abi_to_client(index, request, dir),
            Err(error) => self.write_client_status(index, request, status_for_error(error)),
        }
    }

    fn client_create_file_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Ok(path) = core::str::from_utf8(payload) else {
            self.write_client_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match self.fs.create_file_path(path) {
            Ok(file) => self.return_file_abi_to_client(index, request, file),
            Err(error) => self.write_client_status(index, request, status_for_error(error)),
        }
    }

    fn client_rename_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Some((from, to)) = split_two_strings(payload) else {
            self.write_client_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match self.fs.rename_path(from, to) {
            Ok(()) => self.write_client_response(
                index,
                request,
                HxfsStatus::Ok,
                HxfsHandleKind::None,
                0,
                0,
                0,
                0,
            ),
            Err(error) => self.write_client_status(index, request, status_for_error(error)),
        }
    }

    fn client_unlink_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Ok(path) = core::str::from_utf8(payload) else {
            self.write_client_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match self.fs.unlink_path(path) {
            Ok(()) => self.write_client_response(
                index,
                request,
                HxfsStatus::Ok,
                HxfsHandleKind::None,
                0,
                0,
                0,
                0,
            ),
            Err(error) => self.write_client_status(index, request, status_for_error(error)),
        }
    }

    fn client_checkpoint_native(&mut self, index: usize, request: HxfsRequest) {
        match self.fs.publish_checkpoint() {
            Ok(sequence) => self.write_client_response(
                index,
                request,
                HxfsStatus::Ok,
                HxfsHandleKind::Volume,
                0,
                hxfs_rights::SYNC,
                self.fs.volume_info().root_object_id,
                sequence,
            ),
            Err(error) => self.write_client_status(index, request, status_for_error(error)),
        }
    }

    fn open_file_path(&mut self, index: usize, path: &[u8]) {
        let Ok(path) = core::str::from_utf8(path) else {
            self.write_client(index, b"err:hxfs-bad-name");
            return;
        };
        match self.fs.open_path(path) {
            Ok(file) => self.return_file(index, file),
            Err(_) => self.write_client(index, b"err:hxfs-not-found"),
        }
    }

    fn open_dir_path(&mut self, index: usize, path: &[u8]) {
        let Ok(path) = core::str::from_utf8(path) else {
            self.write_client(index, b"err:hxfs-bad-name");
            return;
        };
        match self.fs.open_directory_path(path) {
            Ok(dir) => self.return_dir(index, dir),
            Err(_) => self.write_client(index, b"err:hxfs-not-found"),
        }
    }

    fn return_file(&mut self, index: usize, file: FileHandle) {
        let Some(slot) = self.files.iter_mut().find(|slot| slot.is_none()) else {
            self.write_client(index, b"err:hxfs-file-table-full");
            return;
        };
        let Ok((client_end, server_end)) = Channel::pair() else {
            self.write_client(index, b"err:hxfs-channel");
            return;
        };
        let Some(client) = self.clients[index].as_ref() else {
            return;
        };
        if client
            .write_handle(b"service:hxfs:file:channel", client_end.into_handle())
            .is_err()
        {
            return;
        }
        *slot = Some(FileEndpoint {
            channel: server_end,
            handle: file,
        });
    }

    fn return_dir(&mut self, index: usize, dir: DirectoryHandle) {
        let Some(slot) = self.dirs.iter_mut().find(|slot| slot.is_none()) else {
            self.write_client(index, b"err:hxfs-dir-table-full");
            return;
        };
        let Ok((client_end, server_end)) = Channel::pair() else {
            self.write_client(index, b"err:hxfs-channel");
            return;
        };
        let Some(client) = self.clients[index].as_ref() else {
            return;
        };
        if client
            .write_handle(b"service:hxfs:dir:channel", client_end.into_handle())
            .is_err()
        {
            return;
        }
        *slot = Some(DirEndpoint {
            channel: server_end,
            handle: dir,
        });
    }

    fn write_client(&self, index: usize, bytes: &[u8]) {
        if let Some(client) = self.clients[index].as_ref() {
            let _ = client.write(bytes);
        }
    }

    fn write_client_status(&self, index: usize, request: HxfsRequest, status: HxfsStatus) {
        self.write_client_response_meta(index, request, error_meta(status), &[]);
    }

    #[allow(clippy::too_many_arguments)]
    fn write_client_response(
        &self,
        index: usize,
        request: HxfsRequest,
        status: HxfsStatus,
        handle_kind: HxfsHandleKind,
        handle_id: u64,
        rights: u64,
        object_id: u64,
        value: u64,
    ) {
        self.write_client_response_meta(
            index,
            request,
            ResponseMeta {
                status,
                handle_kind,
                handle_id,
                rights,
                object_id,
                value,
                flags: 0,
            },
            &[],
        );
    }

    fn write_client_response_meta(
        &self,
        index: usize,
        request: HxfsRequest,
        meta: ResponseMeta,
        payload: &[u8],
    ) {
        if let Some(client) = self.clients[index].as_ref() {
            write_response_to_channel(client, request, meta, payload);
        }
    }

    fn return_file_abi_to_client(&mut self, index: usize, request: HxfsRequest, file: FileHandle) {
        let Some(slot) = self.files.iter_mut().find(|slot| slot.is_none()) else {
            self.write_client_status(index, request, HxfsStatus::NoSpace);
            return;
        };
        let Ok((client_end, server_end)) = Channel::pair() else {
            self.write_client_status(index, request, HxfsStatus::NoSpace);
            return;
        };
        let Some(client) = self.clients[index].as_ref() else {
            return;
        };
        let response = make_response(
            request,
            ResponseMeta {
                status: HxfsStatus::Ok,
                handle_kind: HxfsHandleKind::File,
                handle_id: file.object_id,
                rights: hxfs_rights::READ | hxfs_rights::WRITE | hxfs_rights::SYNC,
                object_id: file.object_id,
                value: file.size,
                flags: response_flags::HANDLE_TRANSFERRED,
            },
            0,
        );
        if client
            .write_handle(&response, client_end.into_handle())
            .is_err()
        {
            return;
        }
        *slot = Some(FileEndpoint {
            channel: server_end,
            handle: file,
        });
    }

    fn return_dir_abi_to_client(
        &mut self,
        index: usize,
        request: HxfsRequest,
        dir: DirectoryHandle,
    ) {
        let Some(slot) = self.dirs.iter_mut().find(|slot| slot.is_none()) else {
            self.write_client_status(index, request, HxfsStatus::NoSpace);
            return;
        };
        let Ok((client_end, server_end)) = Channel::pair() else {
            self.write_client_status(index, request, HxfsStatus::NoSpace);
            return;
        };
        let Some(client) = self.clients[index].as_ref() else {
            return;
        };
        let response = make_response(
            request,
            ResponseMeta {
                status: HxfsStatus::Ok,
                handle_kind: HxfsHandleKind::Directory,
                handle_id: dir.object_id,
                rights: hxfs_rights::READ
                    | hxfs_rights::CREATE
                    | hxfs_rights::MODIFY_DIRECTORY
                    | hxfs_rights::SYNC,
                object_id: dir.object_id,
                value: 0,
                flags: response_flags::HANDLE_TRANSFERRED,
            },
            0,
        );
        if client
            .write_handle(&response, client_end.into_handle())
            .is_err()
        {
            return;
        }
        *slot = Some(DirEndpoint {
            channel: server_end,
            handle: dir,
        });
    }

    fn poll_file(&mut self, index: usize) {
        let mut buf = [0u8; POLL_BUF_BYTES];
        loop {
            let Some(endpoint) = self.files[index].as_ref() else {
                return;
            };
            match endpoint.channel.read_into(&mut buf) {
                Ok(n) if decode_native_message(&buf[..n]).is_some() => {
                    let Some((native, payload)) = decode_native_message(&buf[..n]) else {
                        return;
                    };
                    self.handle_file_native(index, native, payload);
                }
                Ok(n) if &buf[..n] == b"INFO" => self.file_info(index),
                Ok(n) if &buf[..n] == b"READ" => self.file_read_inline(index),
                Ok(n) if &buf[..n] == b"READ_VMO" => self.file_read_vmo(index),
                Ok(_) => self.write_file(index, b"err:hxfs-file-invalid"),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.files[index] = None;
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn file_info(&self, index: usize) {
        let Some(endpoint) = self.files[index].as_ref() else {
            return;
        };
        let mut out = [0u8; 48];
        let len = write_size_info(&mut out, endpoint.handle.size);
        let _ = endpoint.channel.write(&out[..len]);
    }

    fn file_read_inline(&mut self, index: usize) {
        let Some(endpoint) = self.files[index].as_ref() else {
            return;
        };
        if endpoint.handle.size as usize > MAX_READ_BYTES {
            self.write_file(index, b"err:hxfs-too-large");
            return;
        }
        let handle = endpoint.handle;
        let mut out = [0u8; MAX_READ_BYTES];
        match self.fs.read_file(handle, &mut out) {
            Ok(n) => self.write_file(index, &out[..n]),
            Err(_) => self.write_file(index, b"err:hxfs-read"),
        }
    }

    fn file_read_vmo(&mut self, index: usize) {
        let Some(endpoint) = self.files[index].as_ref() else {
            return;
        };
        let Ok(mut size) = usize::try_from(endpoint.handle.size) else {
            self.write_file(index, b"err:hxfs-too-large");
            return;
        };
        if size == 0 {
            size = 1;
        }
        let Ok(vmo) = Vmo::create(size as u64) else {
            self.write_file(index, b"err:hxfs-vmo");
            return;
        };
        let mut scratch = [0u8; MAX_READ_BYTES];
        if endpoint.handle.size as usize > scratch.len() {
            self.write_file(index, b"err:hxfs-too-large");
            return;
        }
        let handle = endpoint.handle;
        match self
            .fs
            .read_file(handle, &mut scratch[..endpoint.handle.size as usize])
        {
            Ok(n) => {
                if vmo.write(0, &scratch[..n]).ok() != Some(n) {
                    self.write_file(index, b"err:hxfs-vmo-write");
                    return;
                }
                let duplicate =
                    match vmo.duplicate(libcanvas::rights::READ | libcanvas::rights::TRANSFER) {
                        Ok(vmo) => vmo,
                        Err(_) => {
                            self.write_file(index, b"err:hxfs-vmo-dup");
                            return;
                        }
                    };
                if let Some(endpoint) = self.files[index].as_ref() {
                    let _ = endpoint
                        .channel
                        .write_handle(b"service:hxfs:file-vmo", duplicate.into_handle());
                }
            }
            Err(_) => self.write_file(index, b"err:hxfs-read"),
        }
    }

    fn write_file_status(&self, index: usize, request: HxfsRequest, status: HxfsStatus) {
        if let Some(endpoint) = self.files[index].as_ref() {
            write_response_to_channel(&endpoint.channel, request, error_meta(status), &[]);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_file_response(
        &self,
        index: usize,
        request: HxfsRequest,
        status: HxfsStatus,
        file: FileHandle,
        value: u64,
        flags: u32,
        payload: &[u8],
    ) {
        if let Some(endpoint) = self.files[index].as_ref() {
            write_response_to_channel(
                &endpoint.channel,
                request,
                ResponseMeta {
                    status,
                    handle_kind: HxfsHandleKind::File,
                    handle_id: file.object_id,
                    rights: hxfs_rights::READ | hxfs_rights::WRITE | hxfs_rights::SYNC,
                    object_id: file.object_id,
                    value,
                    flags,
                },
                payload,
            );
        }
    }

    fn handle_file_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        match request.op {
            HxfsOp::GetInfo => self.file_info_native(index, request),
            HxfsOp::ReadAt => self.file_read_native(index, request),
            HxfsOp::WriteAt => self.file_write_native(index, request, payload),
            HxfsOp::Truncate => self.file_truncate_native(index, request),
            HxfsOp::Fsync | HxfsOp::Checkpoint => self.file_checkpoint_native(index, request),
            _ => self.write_file_status(index, request, HxfsStatus::Unsupported),
        }
    }

    fn file_info_native(&self, index: usize, request: HxfsRequest) {
        let Some(endpoint) = self.files[index].as_ref() else {
            return;
        };
        self.write_file_response(
            index,
            request,
            HxfsStatus::Ok,
            endpoint.handle,
            endpoint.handle.size,
            0,
            &[],
        );
    }

    fn file_read_native(&mut self, index: usize, request: HxfsRequest) {
        let Some(endpoint) = self.files[index].as_ref() else {
            return;
        };
        let requested = if request.arg1 == 0 {
            MAX_READ_BYTES
        } else {
            match usize::try_from(request.arg1) {
                Ok(value) => value.min(MAX_READ_BYTES),
                Err(_) => {
                    self.write_file_status(index, request, HxfsStatus::Invalid);
                    return;
                }
            }
        };
        let mut out = [0u8; MAX_READ_BYTES];
        match self
            .fs
            .read_file_at(endpoint.handle, request.arg0, &mut out[..requested])
        {
            Ok(n) => self.write_file_response(
                index,
                request,
                HxfsStatus::Ok,
                endpoint.handle,
                n as u64,
                response_flags::INLINE_PAYLOAD,
                &out[..n],
            ),
            Err(error) => self.write_file_status(index, request, status_for_error(error)),
        }
    }

    fn file_write_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Some(handle) = self.files[index].as_ref().map(|endpoint| endpoint.handle) else {
            return;
        };
        match self.fs.write_file_at(handle, request.arg0, payload) {
            Ok(new_handle) => {
                if let Some(endpoint) = self.files[index].as_mut() {
                    endpoint.handle = new_handle;
                }
                self.write_file_response(
                    index,
                    request,
                    HxfsStatus::Ok,
                    new_handle,
                    payload.len() as u64,
                    response_flags::DIRTY,
                    &[],
                );
            }
            Err(error) => self.write_file_status(index, request, status_for_error(error)),
        }
    }

    fn file_truncate_native(&mut self, index: usize, request: HxfsRequest) {
        let Some(handle) = self.files[index].as_ref().map(|endpoint| endpoint.handle) else {
            return;
        };
        match self.fs.truncate_file(handle, request.arg0) {
            Ok(new_handle) => {
                if let Some(endpoint) = self.files[index].as_mut() {
                    endpoint.handle = new_handle;
                }
                self.write_file_response(
                    index,
                    request,
                    HxfsStatus::Ok,
                    new_handle,
                    new_handle.size,
                    response_flags::DIRTY,
                    &[],
                );
            }
            Err(error) => self.write_file_status(index, request, status_for_error(error)),
        }
    }

    fn file_checkpoint_native(&mut self, index: usize, request: HxfsRequest) {
        let Some(handle) = self.files[index].as_ref().map(|endpoint| endpoint.handle) else {
            return;
        };
        match self.fs.publish_checkpoint() {
            Ok(sequence) => {
                self.write_file_response(index, request, HxfsStatus::Ok, handle, sequence, 0, &[])
            }
            Err(error) => self.write_file_status(index, request, status_for_error(error)),
        }
    }

    fn write_file(&self, index: usize, bytes: &[u8]) {
        if let Some(endpoint) = self.files[index].as_ref() {
            let _ = endpoint.channel.write(bytes);
        }
    }

    fn poll_dir(&mut self, index: usize) {
        let mut buf = [0u8; POLL_BUF_BYTES];
        loop {
            let Some(endpoint) = self.dirs[index].as_ref() else {
                return;
            };
            match endpoint.channel.read_into(&mut buf) {
                Ok(n) if decode_native_message(&buf[..n]).is_some() => {
                    let Some((native, payload)) = decode_native_message(&buf[..n]) else {
                        return;
                    };
                    self.handle_dir_native(index, native, payload);
                }
                Ok(n) if &buf[..n] == b"LIST" => self.dir_list(index),
                Ok(n) if buf[..n].starts_with(b"OPEN_FILE ") => {
                    let name = &buf[b"OPEN_FILE ".len()..n];
                    self.dir_open_file(index, name);
                }
                Ok(_) => self.write_dir(index, b"err:hxfs-dir-invalid"),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => return,
                Err(ErrorCode::PeerClosed) => {
                    self.dirs[index] = None;
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn dir_list(&mut self, index: usize) {
        let Some(endpoint) = self.dirs[index].as_ref() else {
            return;
        };
        let handle = endpoint.handle;
        let mut out = [0u8; MAX_READ_BYTES];
        match self.fs.list_directory(handle, &mut out) {
            Ok(n) => self.write_dir(index, &out[..n]),
            Err(_) => self.write_dir(index, b"err:hxfs-list"),
        }
    }

    fn dir_open_file(&mut self, index: usize, name: &[u8]) {
        let Some(endpoint) = self.dirs[index].as_ref() else {
            return;
        };
        let Ok(name) = core::str::from_utf8(name) else {
            self.write_dir(index, b"err:hxfs-bad-name");
            return;
        };
        match self.fs.open_child_file(endpoint.handle, name) {
            Ok(file) => self.return_file_to_dir(index, file),
            Err(_) => self.write_dir(index, b"err:hxfs-not-found"),
        }
    }

    fn return_file_to_dir(&mut self, index: usize, file: FileHandle) {
        let Some(slot) = self.files.iter_mut().find(|slot| slot.is_none()) else {
            self.write_dir(index, b"err:hxfs-file-table-full");
            return;
        };
        let Ok((client_end, server_end)) = Channel::pair() else {
            self.write_dir(index, b"err:hxfs-channel");
            return;
        };
        let Some(endpoint) = self.dirs[index].as_ref() else {
            return;
        };
        if endpoint
            .channel
            .write_handle(b"service:hxfs:file:channel", client_end.into_handle())
            .is_err()
        {
            return;
        }
        *slot = Some(FileEndpoint {
            channel: server_end,
            handle: file,
        });
    }

    fn write_dir_status(&self, index: usize, request: HxfsRequest, status: HxfsStatus) {
        if let Some(endpoint) = self.dirs[index].as_ref() {
            write_response_to_channel(&endpoint.channel, request, error_meta(status), &[]);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_dir_response(
        &self,
        index: usize,
        request: HxfsRequest,
        status: HxfsStatus,
        dir: DirectoryHandle,
        value: u64,
        flags: u32,
        payload: &[u8],
    ) {
        if let Some(endpoint) = self.dirs[index].as_ref() {
            write_response_to_channel(
                &endpoint.channel,
                request,
                ResponseMeta {
                    status,
                    handle_kind: HxfsHandleKind::Directory,
                    handle_id: dir.object_id,
                    rights: hxfs_rights::READ
                        | hxfs_rights::CREATE
                        | hxfs_rights::MODIFY_DIRECTORY
                        | hxfs_rights::SYNC,
                    object_id: dir.object_id,
                    value,
                    flags,
                },
                payload,
            );
        }
    }

    fn return_file_abi_to_dir(&mut self, index: usize, request: HxfsRequest, file: FileHandle) {
        let Some(slot) = self.files.iter_mut().find(|slot| slot.is_none()) else {
            self.write_dir_status(index, request, HxfsStatus::NoSpace);
            return;
        };
        let Ok((client_end, server_end)) = Channel::pair() else {
            self.write_dir_status(index, request, HxfsStatus::NoSpace);
            return;
        };
        let Some(endpoint) = self.dirs[index].as_ref() else {
            return;
        };
        let response = make_response(
            request,
            ResponseMeta {
                status: HxfsStatus::Ok,
                handle_kind: HxfsHandleKind::File,
                handle_id: file.object_id,
                rights: hxfs_rights::READ | hxfs_rights::WRITE | hxfs_rights::SYNC,
                object_id: file.object_id,
                value: file.size,
                flags: response_flags::HANDLE_TRANSFERRED,
            },
            0,
        );
        if endpoint
            .channel
            .write_handle(&response, client_end.into_handle())
            .is_err()
        {
            return;
        }
        *slot = Some(FileEndpoint {
            channel: server_end,
            handle: file,
        });
    }

    fn return_dir_abi_to_dir(&mut self, index: usize, request: HxfsRequest, dir: DirectoryHandle) {
        let Some(slot_index) = self.dirs.iter().position(|slot| slot.is_none()) else {
            self.write_dir_status(index, request, HxfsStatus::NoSpace);
            return;
        };
        let Ok((client_end, server_end)) = Channel::pair() else {
            self.write_dir_status(index, request, HxfsStatus::NoSpace);
            return;
        };
        let Some(endpoint) = self.dirs[index].as_ref() else {
            return;
        };
        let response = make_response(
            request,
            ResponseMeta {
                status: HxfsStatus::Ok,
                handle_kind: HxfsHandleKind::Directory,
                handle_id: dir.object_id,
                rights: hxfs_rights::READ
                    | hxfs_rights::CREATE
                    | hxfs_rights::MODIFY_DIRECTORY
                    | hxfs_rights::SYNC,
                object_id: dir.object_id,
                value: 0,
                flags: response_flags::HANDLE_TRANSFERRED,
            },
            0,
        );
        if endpoint
            .channel
            .write_handle(&response, client_end.into_handle())
            .is_err()
        {
            return;
        }
        self.dirs[slot_index] = Some(DirEndpoint {
            channel: server_end,
            handle: dir,
        });
    }

    fn handle_dir_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        match request.op {
            HxfsOp::GetInfo => self.dir_info_native(index, request),
            HxfsOp::ListDirectory => self.dir_list_native(index, request),
            HxfsOp::OpenPath => self.dir_open_native(index, request, payload),
            HxfsOp::CreateFile => self.dir_create_file_native(index, request, payload),
            HxfsOp::Mkdir => self.dir_mkdir_native(index, request, payload),
            HxfsOp::Rename => self.dir_rename_native(index, request, payload),
            HxfsOp::Unlink => self.dir_unlink_native(index, request, payload),
            HxfsOp::Fsync | HxfsOp::Checkpoint => self.dir_checkpoint_native(index, request),
            _ => self.write_dir_status(index, request, HxfsStatus::Unsupported),
        }
    }

    fn dir_info_native(&self, index: usize, request: HxfsRequest) {
        let Some(endpoint) = self.dirs[index].as_ref() else {
            return;
        };
        self.write_dir_response(
            index,
            request,
            HxfsStatus::Ok,
            endpoint.handle,
            endpoint.handle.object_id,
            0,
            &[],
        );
    }

    fn dir_list_native(&mut self, index: usize, request: HxfsRequest) {
        let Some(endpoint) = self.dirs[index].as_ref() else {
            return;
        };
        let mut out = [0u8; MAX_READ_BYTES];
        match self.fs.list_directory(endpoint.handle, &mut out) {
            Ok(n) => self.write_dir_response(
                index,
                request,
                HxfsStatus::Ok,
                endpoint.handle,
                n as u64,
                response_flags::INLINE_PAYLOAD,
                &out[..n],
            ),
            Err(error) => self.write_dir_status(index, request, status_for_error(error)),
        }
    }

    fn dir_open_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Some(endpoint) = self.dirs[index].as_ref() else {
            return;
        };
        let Ok(name) = core::str::from_utf8(payload) else {
            self.write_dir_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match request.handle_kind {
            HxfsHandleKind::File => match self.fs.open_child_file(endpoint.handle, name) {
                Ok(file) => self.return_file_abi_to_dir(index, request, file),
                Err(error) => self.write_dir_status(index, request, status_for_error(error)),
            },
            HxfsHandleKind::Directory => match self.fs.open_child_dir(endpoint.handle, name) {
                Ok(dir) => self.return_dir_abi_to_dir(index, request, dir),
                Err(error) => self.write_dir_status(index, request, status_for_error(error)),
            },
            _ => self.write_dir_status(index, request, HxfsStatus::Invalid),
        }
    }

    fn dir_create_file_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Some(parent) = self.dirs[index].as_ref().map(|endpoint| endpoint.handle) else {
            return;
        };
        let Ok(name) = core::str::from_utf8(payload) else {
            self.write_dir_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match self.fs.create_file_child(parent, name) {
            Ok(file) => self.return_file_abi_to_dir(index, request, file),
            Err(error) => self.write_dir_status(index, request, status_for_error(error)),
        }
    }

    fn dir_mkdir_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Some(parent) = self.dirs[index].as_ref().map(|endpoint| endpoint.handle) else {
            return;
        };
        let Ok(name) = core::str::from_utf8(payload) else {
            self.write_dir_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match self.fs.mkdir_child(parent, name) {
            Ok(dir) => self.return_dir_abi_to_dir(index, request, dir),
            Err(error) => self.write_dir_status(index, request, status_for_error(error)),
        }
    }

    fn dir_rename_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Some(parent) = self.dirs[index].as_ref().map(|endpoint| endpoint.handle) else {
            return;
        };
        let Some((from, to)) = split_two_strings(payload) else {
            self.write_dir_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match self.fs.rename_child(parent, from, parent, to) {
            Ok(()) => self.write_dir_response(
                index,
                request,
                HxfsStatus::Ok,
                parent,
                0,
                response_flags::DIRTY,
                &[],
            ),
            Err(error) => self.write_dir_status(index, request, status_for_error(error)),
        }
    }

    fn dir_unlink_native(&mut self, index: usize, request: HxfsRequest, payload: &[u8]) {
        let Some(parent) = self.dirs[index].as_ref().map(|endpoint| endpoint.handle) else {
            return;
        };
        let Ok(name) = core::str::from_utf8(payload) else {
            self.write_dir_status(index, request, HxfsStatus::Invalid);
            return;
        };
        match self.fs.unlink_child(parent, name) {
            Ok(()) => self.write_dir_response(
                index,
                request,
                HxfsStatus::Ok,
                parent,
                0,
                response_flags::DIRTY,
                &[],
            ),
            Err(error) => self.write_dir_status(index, request, status_for_error(error)),
        }
    }

    fn dir_checkpoint_native(&mut self, index: usize, request: HxfsRequest) {
        let Some(parent) = self.dirs[index].as_ref().map(|endpoint| endpoint.handle) else {
            return;
        };
        match self.fs.publish_checkpoint() {
            Ok(sequence) => {
                self.write_dir_response(index, request, HxfsStatus::Ok, parent, sequence, 0, &[])
            }
            Err(error) => self.write_dir_status(index, request, status_for_error(error)),
        }
    }

    fn write_dir(&self, index: usize, bytes: &[u8]) {
        if let Some(endpoint) = self.dirs[index].as_ref() {
            let _ = endpoint.channel.write(bytes);
        }
    }
}

fn mount_from_bootstrap(bootstrap: &Channel) -> Option<MountedHxfs> {
    let mut buf = [0u8; 64];
    loop {
        match bootstrap.read_optional_handle(&mut buf) {
            Ok((n, Some(handle))) if &buf[..n] == b"hxfs:block-device" => {
                let channel = Channel::from_handle(handle);
                let Ok(device) = libcanvas::block::BlockDevice::from_channel(channel) else {
                    return None;
                };
                let mut reader = BlockDeviceReader { device };
                match replay_journal(&mut reader) {
                    Ok(ReplayOutcome::Clean) => {}
                    Ok(ReplayOutcome::Replayed {
                        sequence_number,
                        records,
                        final_checkpoint_lba,
                    }) => {
                        println!(
                            "[hxfs] replayed journal seq={} records={} checkpoint_lba={}",
                            sequence_number, records, final_checkpoint_lba
                        );
                    }
                    Err(error) => {
                        println!("[hxfs] journal replay failed: {:?}", error);
                        return None;
                    }
                }
                match FixedHxfsWriter::mount(reader) {
                    Ok(fs) => return Some(fs),
                    Err(error) => {
                        println!("[hxfs] mount failed: {:?}", error);
                        return None;
                    }
                }
            }
            Ok((_n, Some(handle))) => drop(handle),
            Ok((_n, None)) => {}
            Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => {
                libcanvas::process::yield_now();
            }
            Err(_) => return None,
        }
    }
}

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.starts_with(prefix) {
        Some(&bytes[prefix.len()..])
    } else {
        None
    }
}

fn decode_native_message(bytes: &[u8]) -> Option<(HxfsRequest, &[u8])> {
    if bytes.len() < HXFS_REQUEST_BYTES {
        return None;
    }
    let request = HxfsRequest::decode(&bytes[..HXFS_REQUEST_BYTES])?;
    let payload_len = request.payload_len as usize;
    if bytes.len() != HXFS_REQUEST_BYTES.checked_add(payload_len)? {
        return None;
    }
    Some((request, &bytes[HXFS_REQUEST_BYTES..]))
}

fn make_response(
    request: HxfsRequest,
    meta: ResponseMeta,
    payload_len: u32,
) -> [u8; HXFS_RESPONSE_BYTES] {
    HxfsResponse {
        version: huesos_abi::hxfs::HXFS_PROTOCOL_VERSION,
        reserved0: 0,
        status: meta.status,
        flags: meta.flags,
        request_id: request.request_id,
        handle_id: meta.handle_id,
        handle_kind: meta.handle_kind,
        rights: meta.rights,
        object_id: meta.object_id,
        value: meta.value,
        payload_len,
        reserved1: 0,
    }
    .encode()
}

fn write_response_to_channel(
    channel: &Channel,
    request: HxfsRequest,
    meta: ResponseMeta,
    payload: &[u8],
) {
    let mut out = [0u8; MAX_NATIVE_REQUEST_BYTES];
    let payload_len = payload.len().min(HXFS_MAX_INLINE_WRITE_BYTES);
    let response = make_response(request, meta, payload_len as u32);
    out[..HXFS_RESPONSE_BYTES].copy_from_slice(&response);
    out[HXFS_RESPONSE_BYTES..HXFS_RESPONSE_BYTES + payload_len]
        .copy_from_slice(&payload[..payload_len]);
    let _ = channel.write(&out[..HXFS_RESPONSE_BYTES + payload_len]);
}

fn error_meta(status: HxfsStatus) -> ResponseMeta {
    ResponseMeta {
        status,
        handle_kind: HxfsHandleKind::None,
        handle_id: 0,
        rights: 0,
        object_id: 0,
        value: 0,
        flags: 0,
    }
}

fn status_for_error(error: HxfsError) -> HxfsStatus {
    match error {
        HxfsError::NotFound => HxfsStatus::NotFound,
        HxfsError::AlreadyExists => HxfsStatus::AlreadyExists,
        HxfsError::WrongType | HxfsError::DirectoryNotEmpty => HxfsStatus::WrongType,
        HxfsError::NeedsRecovery | HxfsError::BadJournal => HxfsStatus::NeedsRecovery,
        HxfsError::Io => HxfsStatus::IoError,
        HxfsError::NoSpace => HxfsStatus::NoSpace,
        HxfsError::Unsupported | HxfsError::UnsupportedFormat => HxfsStatus::Unsupported,
        HxfsError::EncryptedVolumeKeyUnavailable
        | HxfsError::EncryptedPolicyUnknown
        | HxfsError::EncryptedPolicyInvalid => HxfsStatus::EncryptedUnavailable,
        HxfsError::BufferTooSmall
        | HxfsError::OutOfRange
        | HxfsError::BadChecksum
        | HxfsError::BadBlock
        | HxfsError::BadTree
        | HxfsError::BadName => HxfsStatus::Invalid,
    }
}

fn split_two_strings(bytes: &[u8]) -> Option<(&str, &str)> {
    let split = bytes.iter().position(|&byte| byte == 0)?;
    let left = core::str::from_utf8(&bytes[..split]).ok()?;
    let right = core::str::from_utf8(&bytes[split + 1..]).ok()?;
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some((left, right))
}

fn write_size_info(out: &mut [u8], size: u64) -> usize {
    let prefix = b"size=";
    let mut len = prefix.len().min(out.len());
    out[..len].copy_from_slice(&prefix[..len]);
    let mut tmp = [0u8; 20];
    let mut value = size;
    let mut idx = tmp.len();
    if value == 0 {
        idx -= 1;
        tmp[idx] = b'0';
    }
    while value != 0 {
        idx -= 1;
        tmp[idx] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    for &byte in &tmp[idx..] {
        if len >= out.len() {
            break;
        }
        out[len] = byte;
        len += 1;
    }
    if len < out.len() {
        out[len] = b'\n';
        len += 1;
    }
    len
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[hxfs] service started");
    let bootstrap = libcanvas::channel::bootstrap();
    let Some(fs) = mount_from_bootstrap(&bootstrap) else {
        // Send the explicit unavailable marker, then exit so
        // DriverManager observes PeerClosed on the bootstrap
        // channel and stops polling for a service that will
        // never become ready. Without the exit the hxfs
        // process would spin in a yield-only loop holding the
        // bootstrap channel open, and any retry from a client
        // (e.g. terminal's open_service) would also spin on the
        // registry channel and spam the serial log.
        let _ = bootstrap.write(b"service:hxfs:unavailable");
        println!("[hxfs] service exiting: mount failed");
        libcanvas::process::exit(-1);
    };
    let _ = bootstrap.write(b"service:hxfs:ready");
    let mut runtime = HxfsRuntime::new(fs);
    loop {
        runtime.poll(&bootstrap);
        libcanvas::process::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::debug::write_str("[hxfs] PANIC\n");
    libcanvas::process::exit(-1);
}
