//! Fixed-capacity Hxfs userspace service.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use core::panic::PanicInfo;
use huesos_abi::hxfs::{
    request_flags, response_flags, rights as hxfs_rights, HxfsHandleKind, HxfsOp, HxfsRequest,
    HxfsStatus,
};
use huesos_hxfs::fixed_writer::FixedHxfsWriter;
use huesos_hxfs::format::{DirectoryHandle, FileHandle};
use huesos_hxfs::reader::BlockReader;
use huesos_hxfs::recovery::{replay_journal, BlockStore, ReplayOutcome};
use huesos_hxfs::HxfsError;
use huesos_hxfs_proto::{
    decode_native_message, encode_response, make_response, split_two_strings, status_for_error,
    write_size_info, ResponseMeta, MAX_NATIVE_REQUEST_BYTES, POLL_BUF_BYTES,
};
use libcanvas::{println, Channel, ErrorCode, Vmo};

/// A.6 live mount: the hxfs-service is the production
/// mount process. It needs a global allocator so the
/// `mount_with_policies` entry point on `huesos_hxfs` (which
/// allocates a `Vec<CompressionPolicy>` to hold the
/// per-volume policy table) can resolve compression
/// policies at read time. The heap is 256 KiB for the MVP
/// service profile; the kernel reserves the higher half
/// of the user address space for the heap and the
/// allocator grows into that region.
#[global_allocator]
static HEAP: libcanvas::heap::ScudoHeap = libcanvas::heap::ScudoHeap::new();

/// Initialise the hardened heap.
///
/// The allocator (`huesos-scudo`) grows the process's reserved heap
/// window on demand through `VmarHeapExtend`, so nothing but the
/// kernel's small bootstrap prefix is committed until the service
/// actually allocates. Its chunk-header cookie comes from kernel
/// entropy; if that is unavailable the heap stays uninitialised and
/// every allocation returns null, which the caller reports rather
/// than running with forgeable heap metadata.
fn init_heap() -> bool {
    // SAFETY: called exactly once, before the first allocation, and
    // before any additional thread could exist in this process.
    unsafe { HEAP.init() }
}

const MAX_CLIENTS: usize = 4;
const MAX_FILE_HANDLES: usize = 8;
const MAX_DIR_HANDLES: usize = 8;
const MAX_READ_BYTES: usize = 4096;
// `MAX_NATIVE_REQUEST_BYTES` and `POLL_BUF_BYTES` live in
// `huesos-hxfs-proto`, where the sizing rule that keeps a channel
// from wedging is unit tested on the host.
// Sized to fit the `mount_from_bootstrap` -> `FixedHxfsWriter::mount`
// stack frame inside `USER_STACK_SIZE` (128 KiB since the
// follow-up that added the boot write self-check; 64 KiB before,
// which the write path's crypto frames overflowed at ~62 KiB
// depth). The previous 32/64/64 capacities put roughly 30 KiB of
// fixed `[Option<T>; N]` arrays on the stack in a single frame,
// which overflowed the guard page (`user-fault rip=0x403f4d
// address=0x7ffffefef688` in the qemu-nvme-boot smoke). The seed
// v5 image uses only a handful of objects/entries/extents, so
// 16/16/16 leaves comfortable headroom.
// Stage E: raised so the on-target soak can exercise multi-block
// extent trees. The writer's fixed arrays live INSIDE the
// MountedHxfs value, which the service keeps on the stack; 512
// extents x ~64 B = ~32 KiB BSS is the largest that still leaves
// the 128 KiB stack safe alongside the crypto frames. A 1 MiB
// soak file (256 extents -> 3 leaves) exercises the tree; larger
// files need the writer to move off the stack (a Box/heap-based
// service runtime), tracked separately.
const SERVICE_MAX_OBJECTS: usize = 32;
const SERVICE_MAX_DIR_ENTRIES: usize = 32;
const SERVICE_MAX_EXTENTS: usize = 4200;
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

// `ResponseMeta` comes from `huesos-hxfs-proto`.

struct FileEndpoint {
    channel: Channel,
    handle: FileHandle,
}

struct DirEndpoint {
    channel: Channel,
    handle: DirectoryHandle,
}

struct HxfsRuntime {
    fs: Box<MountedHxfs>,
    /// Receive buffer shared by every poll loop. Heap-resident (this
    /// whole struct is boxed) so a full ABI-sized message can be
    /// received without putting 4 KiB on the stack.
    poll_buf: Box<[u8; POLL_BUF_BYTES]>,
    clients: [Option<Channel>; MAX_CLIENTS],
    files: [Option<FileEndpoint>; MAX_FILE_HANDLES],
    dirs: [Option<DirEndpoint>; MAX_DIR_HANDLES],
    // Stage E (Production polish): runtime knobs (sysctl-like).
    stats_interval_ticks: u32,
    stats_since: u32,
}

impl HxfsRuntime {
    fn new(fs: Box<MountedHxfs>) -> Self {
        Self {
            fs,
            poll_buf: Box::new([0u8; POLL_BUF_BYTES]),
            clients: [const { None }; MAX_CLIENTS],
            files: [const { None }; MAX_FILE_HANDLES],
            dirs: [const { None }; MAX_DIR_HANDLES],
            stats_interval_ticks: 0,
            stats_since: 0,
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
        // Borrow the heap buffer out of `self` for the duration of
        // the loop so the `&mut self` handler calls stay legal, and
        // put it back on every exit path.
        let mut buf = core::mem::replace(&mut self.poll_buf, Box::new([0u8; POLL_BUF_BYTES]));
        while let Some(client) = self.clients[index].as_ref() {
            match client.read_into(buf.as_mut_slice()) {
                Ok(n) => self.handle_client_request(index, &buf[..n]),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                Err(ErrorCode::PeerClosed) => {
                    self.clients[index] = None;
                    break;
                }
                Err(error) => {
                    // The buffer is ABI-sized, so `BytesTooSmall`
                    // means the peer sent something larger than the
                    // ABI permits. The kernel leaves such a message
                    // queued, so simply returning would wedge this
                    // channel forever. Drop the client instead: the
                    // peer violated the protocol and the endpoint
                    // cannot be drained.
                    println!("[hxfs] client {index} dropped: {error:?}");
                    self.clients[index] = None;
                    break;
                }
            }
        }
        self.poll_buf = buf;
    }

    fn handle_client_request(&mut self, index: usize, request: &[u8]) {
        if let Some((native, payload)) = decode_native_message(request) {
            self.handle_client_native(index, native, payload);
            return;
        }
        #[cfg(feature = "synthetic-key")]
        if self.handle_blob_command(index, request) {
            return;
        }
        if request == b"ROOT" || request == b"OPEN_DIR /" {
            self.return_dir(index, self.fs.root_directory());
            return;
        }
        if request == b"STATS" {
            // Stage E (Operations): observation surface. Prints a
            // one-line JSON-ish summary so an operator (or the
            // soak harness) can see mount-time health: bad extents
            // marked, scrub result, quota limits.
            let scrub = self.fs.scrub().map(|s| s.errors).unwrap_or(u64::MAX);
            let fsck = self.fs.fsck();
            println!(
                "[hxfs] stats bad_extents={} scrub_errors={} fsck_checks={} fsck_errors={}",
                self.fs.bad_extent_count(),
                scrub,
                fsck.checks,
                fsck.errors
            );
            self.write_client(index, b"stats-ok");
            return;
        }
        if let Some(rest) = strip_prefix(request, b"SET_KNOB ") {
            if let Some(eq) = rest.iter().position(|&b| b == b'=') {
                let name = &rest[..eq];
                let value = &rest[eq + 1..];
                let mut applied = false;
                if name == b"stats_interval" {
                    if let Ok(text) = core::str::from_utf8(value) {
                        if let Ok(ticks) = text.parse::<u32>() {
                            self.stats_interval_ticks = ticks;
                            self.stats_since = 0;
                            applied = true;
                        }
                    }
                }
                if applied {
                    self.write_client(index, b"knob-ok");
                } else {
                    self.write_client(index, b"err:knob");
                }
            } else {
                self.write_client(index, b"err:knob");
            }
            return;
        }
        if request == b"GET_KNOBS" {
            let mut reply = alloc::vec![0u8; 64];
            let text = alloc::format!("stats_interval={}\n", self.stats_interval_ticks);
            reply[..text.len()].copy_from_slice(text.as_bytes());
            self.write_client(index, &reply[..text.len()]);
            return;
        }
        if is_odirect_deny(request) {
            // Stage B.4: text-protocol equivalent of the
            // native `request_flags::O_DIRECT` deny. The
            // text protocol is a debug-only path used by the
            // qemu-nvme-soak harness; an O_DIRECT request
            // here gets the same `err:hxfs-unsupported`
            // reply as the native path so the harness can
            // assert on the deny end-to-end.
            self.write_client(index, b"err:hxfs-unsupported");
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
        // Stage B.4: deny O_DIRECT. The page cache is not
        // yet production-grade, the kernel-side direct-IO
        // alignment path is not in place, and the ROADMAP
        // exit criterion is "O_DIRECT returns Unsupported".
        // We reject the request up-front rather than
        // silently falling back to a cached read/write so
        // a Linux client that expects the flag to be
        // honoured gets an honest error.
        if request.flags & request_flags::O_DIRECT != 0 {
            self.write_client_status(index, request, HxfsStatus::Unsupported);
            return;
        }
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
        // Stage B.4: deny O_DIRECT on create as well. The
        // page cache is the only path for reading the new
        // file's data, so an O_DIRECT create would hand the
        // caller back a handle that the kernel cannot
        // service.
        if request.flags & request_flags::O_DIRECT != 0 {
            self.write_client_status(index, request, HxfsStatus::Unsupported);
            return;
        }
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
        let mut buf = core::mem::replace(&mut self.poll_buf, Box::new([0u8; POLL_BUF_BYTES]));
        while let Some(endpoint) = self.files[index].as_ref() {
            match endpoint.channel.read_into(buf.as_mut_slice()) {
                Ok(n) if decode_native_message(&buf[..n]).is_some() => {
                    let Some((native, payload)) = decode_native_message(&buf[..n]) else {
                        break;
                    };
                    self.handle_file_native(index, native, payload);
                }
                Ok(n) if &buf[..n] == b"INFO" => self.file_info(index),
                Ok(n) if &buf[..n] == b"READ" => self.file_read_inline(index),
                Ok(n) if &buf[..n] == b"READ_VMO" => self.file_read_vmo(index),
                Ok(_) => self.write_file(index, b"err:hxfs-file-invalid"),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                Err(ErrorCode::PeerClosed) => {
                    self.files[index] = None;
                    break;
                }
                Err(error) => {
                    // See `poll_client`: an undrainable message would
                    // wedge this endpoint permanently.
                    println!("[hxfs] file {index} dropped: {error:?}");
                    self.files[index] = None;
                    break;
                }
            }
        }
        self.poll_buf = buf;
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
        let mut buf = core::mem::replace(&mut self.poll_buf, Box::new([0u8; POLL_BUF_BYTES]));
        while let Some(endpoint) = self.dirs[index].as_ref() {
            match endpoint.channel.read_into(buf.as_mut_slice()) {
                Ok(n) if decode_native_message(&buf[..n]).is_some() => {
                    let Some((native, payload)) = decode_native_message(&buf[..n]) else {
                        break;
                    };
                    self.handle_dir_native(index, native, payload);
                }
                Ok(n) if &buf[..n] == b"LIST" => self.dir_list(index),
                Ok(n) if buf[..n].starts_with(b"OPEN_FILE ") => {
                    let name_end = n;
                    let name_start = b"OPEN_FILE ".len();
                    // Copy the name out before calling back into
                    // `&mut self`: `buf` is borrowed from the same
                    // struct the handler mutates.
                    let mut name = [0u8; 256];
                    let len = (name_end - name_start).min(name.len());
                    name[..len].copy_from_slice(&buf[name_start..name_start + len]);
                    self.dir_open_file(index, &name[..len]);
                }
                Ok(_) => self.write_dir(index, b"err:hxfs-dir-invalid"),
                Err(ErrorCode::ShouldWait) | Err(ErrorCode::TimedOut) => break,
                Err(ErrorCode::PeerClosed) => {
                    self.dirs[index] = None;
                    break;
                }
                Err(error) => {
                    println!("[hxfs] dir {index} dropped: {error:?}");
                    self.dirs[index] = None;
                    break;
                }
            }
        }
        self.poll_buf = buf;
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

fn mount_from_bootstrap(bootstrap: &Channel) -> Option<Box<MountedHxfs>> {
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
                // A.6 live mount: the production path is
                // mount_with_policies so the volume's encryption
                // and compression policy tables (resolved from
                // the on-disk volume table at mount time) are
                // honored at every read and write. The MVP
                // hxfs-service does not yet plumb those tables
                // through its bootstrap channel, so it passes
                // empty tables and accepts only plain volumes;
                // a future revision (Track D.2, TPM-backed key
                // provider) will read the tables from the
                // volume descriptor and pass them here. The
                // synthetic-key (Stage B.5) build passes the
                // matching test-only policy tables so the soak
                // image mounts and the self-check can read it.
                let mounted = {
                    #[cfg(feature = "synthetic-key")]
                    {
                        // Stage D key handoff: the volume key comes
                        // from the kernel's bootloader blob
                        // (VolumeKeyGet), not from baked-in
                        // userspace material. When the kernel has no
                        // key, an encrypted volume is rejected with
                        // EncryptedVolumeKeyUnavailable — the
                        // security gate working as intended.
                        let key = libcanvas::system::get_volume_key().ok().flatten();
                        let enc = [huesos_hxfs::synthetic_key::encryption_policy()];
                        let comp = [huesos_hxfs::synthetic_key::compression_policy()];
                        FixedHxfsWriter::mount_with_policies(reader, &enc, &comp, key.as_ref())
                    }
                    #[cfg(not(feature = "synthetic-key"))]
                    {
                        FixedHxfsWriter::mount_with_policies(reader, &[], &[], None)
                    }
                };
                match mounted {
                    Ok(fs) => return Some(Box::new(fs)),
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

/// Stage B.4 + B.5: text-protocol O_DIRECT deny predicate.
///
/// `handle_client_request` replies `err:hxfs-unsupported` when it
/// matches; the boot self-check drives the same predicate so the
/// soak can assert the deny on target without a client channel.
fn is_odirect_deny(request: &[u8]) -> bool {
    strip_prefix(request, b"OPEN_FILE O_DIRECT ").is_some()
}

fn write_response_to_channel(
    channel: &Channel,
    request: HxfsRequest,
    meta: ResponseMeta,
    payload: &[u8],
) {
    let mut out = [0u8; MAX_NATIVE_REQUEST_BYTES];
    if let Some(total) = encode_response(request, meta, payload, &mut out) {
        let _ = channel.write(&out[..total]);
    }
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("[hxfs] service started");
    // A.6 live mount: the production mount path
    // (mount_with_policies) allocates a Vec to hold the
    // per-volume compression policy table, so the heap has
    // to be live before mount_from_bootstrap runs.
    //
    // Initialisation can only fail if the kernel entropy pool is
    // unavailable, which would leave the allocator's header
    // checksum keyed by a predictable cookie. Refuse to run rather
    // than serve a filesystem on an unhardened heap: every
    // allocation would return null immediately afterwards anyway.
    if !init_heap() {
        println!("[hxfs] fatal: heap init failed (no kernel entropy)");
        libcanvas::process::exit(-1);
    }
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
    // Stage B.5: boot self-check (synthetic-key build only). It
    // drives the O_DIRECT deny probe and reads the seeded file;
    // a corrupted encrypted extent is detected and reported as
    // `bad-gcm-tag-marked` while the service keeps serving.
    #[cfg(feature = "synthetic-key")]
    let mut fs = fs;
    #[cfg(feature = "synthetic-key")]
    run_boot_self_check(&mut fs);
    let _ = bootstrap.write(b"service:hxfs:ready");
    // The runtime (and the stack-resident MountedHxfs with its
    // fixed extent array) lives on the HEAP: at Stage E capacities
    // the writer is ~32 KiB and the 128 KiB user stack must stay
    // free for the crypto read/write frames (several 4 KiB scratch
    // buffers per frame on the mount call chain). The 256 KiB
    // userspace heap fits it comfortably.
    let mut runtime = Box::new(HxfsRuntime::new(fs));
    loop {
        runtime.poll(&bootstrap);
        runtime.stats_since = runtime.stats_since.wrapping_add(1);
        if runtime.stats_interval_ticks != 0 && runtime.stats_since >= runtime.stats_interval_ticks
        {
            runtime.stats_since = 0;
            let scrub = runtime.fs.scrub().map(|s| s.errors).unwrap_or(u64::MAX);
            println!(
                "[hxfs] periodic-stats bad_extents={} scrub_errors={}",
                runtime.fs.bad_extent_count(),
                scrub
            );
        }
        libcanvas::process::yield_now();
    }
}

/// Stage B.5 boot self-check (synthetic-key test wiring only).
///
/// 1. O_DIRECT text-protocol deny predicate:
///    prints `[hxfs] odirect-deny-ok`.
/// 2. A read of the seeded file through the normal mount API: a
///    clean volume prints `[hxfs] self-check ok (N bytes)`; a
///    volume whose encrypted extent was corrupted
///    (`--inject-bad-gcm-tag`) prints
///    `[hxfs] bad-gcm-tag-marked` and the service continues
///    serving.
/// 3. Phase-1 follow-up: the on-target WRITE path. Two probe files
///    are created, written, checkpointed, reopened and read back
///    byte-for-byte through the real mount: a compressible file
///    (`[hxfs] write-roundtrip-ok`) and an incompressible full
///    4 KiB block that exercises the two-slot extent path on an
///    encrypted volume (`[hxfs] multi-slot-write-ok`).
///
/// The AEAD IKM is the documented developer placeholder derived
/// from the volume's instance UUID (see `Hxfs::mount_with_keys`);
/// the Stage D TPM-backed KeyProvider replaces this entire path.
/// The seeded file is 3584 bytes (one extent), within the
/// service's fixed-capacity read API.
#[cfg(feature = "synthetic-key")]
fn run_boot_self_check(fs: &mut MountedHxfs) {
    if is_odirect_deny(b"OPEN_FILE O_DIRECT seed.bin") {
        println!("[hxfs] odirect-deny-ok");
    }
    let root = fs.root_directory();
    match fs.open_child_file(root, huesos_hxfs::synthetic_key::SEED_FILE_NAME) {
        Ok(file) => {
            let mut buf = [0u8; 4096];
            match fs.read_file(file, &mut buf) {
                Ok(n) => println!("[hxfs] self-check ok ({} bytes)", n),
                Err(HxfsError::Compression) => {
                    // The seeded extent's integrity check failed.
                    // On an encrypted volume the failure is the GCM
                    // tag (--inject-bad-gcm-tag); on a plain volume
                    // it is the compressed-payload CRC32C
                    // (--inject-bad-crc). The volume type
                    // discriminates the two; the extent was marked
                    // bad and the service keeps serving.
                    if fs.encryption().is_some() {
                        println!("[hxfs] bad-gcm-tag-marked");
                    } else {
                        println!("[hxfs] bad-checksum-marked");
                    }
                }
                Err(error) => println!("[hxfs] self-check failed: {:?}", error),
            }
        }
        Err(error) => println!("[hxfs] self-check: seed file absent ({:?})", error),
    }
    if fs.bad_extent_count() > 0 {
        println!("[hxfs] extent-bad-marked ({})", fs.bad_extent_count());
    }
    write_roundtrip_check(fs);
    // Stage F (Phase-2 A): Hxblob round-trip through the object
    // store on target. A small payload is stored by content hash
    // and read back byte-for-byte; this exercises put_blob /
    // get_blob (and the SHA-256 hashing) in the production service.
    {
        let payload = b"Hxblob on-target object store round-trip 0123456789\n".repeat(8);
        match fs.put_blob(&payload) {
            Ok(hash) => match fs.get_blob(&hash) {
                Ok(got) if got == payload => {
                    println!("[hxfs] stage-f-blob-ok");
                }
                Ok(_) => println!("[hxfs] stage-f-blob: mismatch"),
                Err(error) => println!("[hxfs] stage-f-blob: get failed ({:?})", error),
            },
            Err(error) => println!("[hxfs] stage-f-blob: put failed ({:?})", error),
        }
    }
    // Phase-2 packages: a package-sized blob round-trips through
    // put_blob / get_blob. A full 4096-byte single-block blob used
    // to fault on target (the userspace allocator reused a too-small
    // freed block for the read buffer and the chunked fill wrote
    // past it); the Scudo port serves it from a validated size
    // class, so 4096 bytes - the full single-block size - is the probe.
    {
        let mut payload = alloc::vec![0u8; 4096];
        let mut i = 0usize;
        while i < payload.len() {
            payload[i] = (i as u8).wrapping_mul(7).wrapping_add(3);
            i += 1;
        }
        match fs.put_blob(&payload) {
            Ok(hash) => match fs.get_blob(&hash) {
                Ok(full) => {
                    let mut match_ok = full.len() == payload.len();
                    if match_ok {
                        let mut k = 0usize;
                        while k < full.len() {
                            if full[k] != payload[k] {
                                match_ok = false;
                                break;
                            }
                            k += 1;
                        }
                    }
                    if match_ok {
                        println!("[hxfs] stage-f-blob-big-ok");
                    } else {
                        println!("[hxfs] stage-f-blob-big: mismatch");
                    }
                }
                Err(error) => println!("[hxfs] stage-f-blob-big: get failed ({:?})", error),
            },
            Err(error) => println!("[hxfs] stage-f-blob-big: put failed ({:?})", error),
        }
    }
    // Phase-2 packages (step 3): WAD content delivery from the
    // object store. The seed stored a WAD header blob and recorded
    // its hash in 'wad.hash'; we fetch the blob chunked and verify
    // the IWAD magic - proving package-style content is delivered
    // from Hxblob on target.
    {
        let root = fs.root_directory();
        if let Ok(file) = fs.open_child_file(root, "wad.hash") {
            let mut hash_text = [0u8; 128];
            match fs.read_file(file, &mut hash_text) {
                Ok(n) => {
                    let text = hash_text[..n]
                        .iter()
                        .take_while(|&&b| b != b'\n' && b != b' ')
                        .copied()
                        .collect::<alloc::vec::Vec<u8>>();
                    if let Some(hash) = hex_decode(&text) {
                        if hash.len() == 32 {
                            let mut hash_bytes = [0u8; 32];
                            hash_bytes.copy_from_slice(&hash);
                            match fs.get_blob(&hash_bytes) {
                                Ok(wad) => {
                                    let is_wad = wad.len() >= 4
                                        && wad[0] == b'I'
                                        && wad[1] == b'W'
                                        && wad[2] == b'A'
                                        && wad[3] == b'D';
                                    println!(
                                        "[hxfs] stage-f-wad: {} bytes magic={}",
                                        wad.len(),
                                        if is_wad { "IWAD" } else { "bad" }
                                    );
                                    if is_wad {
                                        println!("[hxfs] stage-f-wad-ok");
                                    }
                                }
                                Err(error) => {
                                    println!("[hxfs] stage-f-wad: get failed ({:?})", error)
                                }
                            }
                        }
                    }
                }
                Err(error) => println!("[hxfs] stage-f-wad: read hash failed ({:?})", error),
            }
        }
    }

    run_reliability_checks(fs);
}

/// Stage C: live scrub, structural fsck and quota enforcement
/// probes, all through the production write/read paths.
#[cfg(feature = "synthetic-key")]
fn run_reliability_checks(fs: &mut MountedHxfs) {
    // Live scrub: re-validates every metadata tree block and reads
    // every data extent through the full verify path.
    match fs.scrub() {
        Ok(summary) => println!(
            "[hxfs] scrub complete ({} blocks, {} errors)",
            summary.metadata_blocks + summary.data_blocks,
            summary.errors
        ),
        Err(error) => println!("[hxfs] scrub failed: {:?}", error),
    }
    // Structural fsck: persisted roots + object model.
    let fsck = fs.fsck();
    if fsck.errors == 0 {
        println!("[hxfs] fsck clean ({} checks)", fsck.checks);
    } else {
        println!("[hxfs] fsck findings ({} errors)", fsck.errors);
    }
    // Quota enforcement on the production write path: set the
    // volume limit to exactly one block above the current usage,
    // then attempt two 4 KiB writes. The first must pass, the
    // second must be rejected. Both the writer's volume check
    // (QuotaExceeded) and the allocator gate (NoSpace, which is
    // the user-visible "quota breach" error per the roadmap) prove
    // enforcement, so either is accepted.
    //
    //
    // The headroom is exactly one block. It used to be two, which
    // happened to work only because `committed_physical_bytes` then
    // reported the append high-water mark and so already counted a
    // block the probe had not written yet. Now that the figure
    // counts live extents (the quota-leak fix), two blocks of
    // headroom admit both writes and the probe never sees the
    // limit. Derive the headroom from the block size rather than
    // hardcoding it, so this cannot drift again.
    use huesos_hxfs::format::BLOCK_SIZE_U64;
    let base = fs.committed_physical_bytes();
    if fs.set_quota_limits(base + BLOCK_SIZE_U64, 0).is_err() {
        println!("[hxfs] quota-probe-failed (set_quota_limits)");
        return;
    }
    let root = fs.root_directory();
    match fs.create_file_child(root, "probe-quota.bin") {
        Ok(file) => {
            let mut chunk = [0u8; 4096];
            let line: &[u8] = b"HuesOS quota probe 0123456789\n";
            let mut pos = 0usize;
            while pos < chunk.len() {
                let n = (chunk.len() - pos).min(line.len());
                chunk[pos..pos + n].copy_from_slice(&line[..n]);
                pos += n;
            }
            let first = fs.write_file_at(file, 0, &chunk);
            let second = fs.write_file_at(file, 4096, &chunk);
            if first.is_ok()
                && matches!(
                    second,
                    Err(HxfsError::QuotaExceeded) | Err(HxfsError::NoSpace)
                )
            {
                println!("[hxfs] quota-enforced-ok");
            } else {
                println!(
                    "[hxfs] quota-probe-failed (first={:?} second={:?})",
                    first, second
                );
            }
        }
        Err(error) => println!("[hxfs] quota-probe-failed (create {:?})", error),
    }
    // Lift the probe quota so later checks (Hxblob) are not capped
    // by the temporary 8 KiB limit.
    let _ = fs.set_quota_limits(0, 0);
}

/// Phase-1 follow-up: prove the write pipeline on target.
///
/// The Stage B soak proved only the read side of the
/// encrypted+compressed I/O pipeline. This creates two probe
/// files, writes them through `FixedHxfsWriter` (the same code the
/// native request handlers call), publishes a checkpoint, reopens
/// them with fresh handles and reads them back byte-for-byte:
///
/// - `probe-compress.bin`: 2048 bytes of a repeated pattern, which
///   must take the compressed (single-slot) write path;
/// - `probe-random.bin`: a full 4 KiB pseudo-random block, which
///   is incompressible and must take the two-slot extent path
///   ([`huesos_hxfs::format::EXTENT_FLAG_MULTI_SLOT`]) on an
///   encrypted volume.
///
/// Both files fit the service's fixed capacities (16 objects /
/// 32 dir entries / 16 extents).
#[cfg(feature = "synthetic-key")]
fn write_roundtrip_check(fs: &mut MountedHxfs) {
    // Each phase runs in its own scope so the compiler can reuse
    // the stack slots: the crypto write/read frames already keep
    // several 4 KiB scratch buffers live on the same call chain as
    // mount_from_bootstrap, and holding all probe buffers at once
    // overflowed the 64 KiB stack (the stack is now 128 KiB, but
    // keeping the probe footprint small is still the right habit).
    const LINE: &[u8] = b"HuesOS on-target write roundtrip probe 0123456789\n";
    let root = fs.root_directory();
    // Phase A: compressible probe (512 bytes of a repeated line).
    {
        let mut compressible = [0u8; 512];
        let mut pos = 0usize;
        while pos < compressible.len() {
            let n = (compressible.len() - pos).min(LINE.len());
            compressible[pos..pos + n].copy_from_slice(&LINE[..n]);
            pos += n;
        }
        match fs.create_file_child(root, "probe-compress.bin") {
            Ok(file) => {
                if let Err(error) = fs.write_file_at(file, 0, &compressible) {
                    println!("[hxfs] write-roundtrip: write failed ({:?})", error);
                }
            }
            Err(error) => println!("[hxfs] write-roundtrip: create failed ({:?})", error),
        }
    }
    // Phase B: incompressible probe — a full 4 KiB pseudo-random
    // block (deterministic xorshift64; incompressibility, not
    // randomness, is what matters). It must take the two-slot
    // extent path on the encrypted volume.
    {
        let mut random = [0u8; 4096];
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut pos = 0usize;
        while pos < random.len() {
            let mut x = state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            state = x;
            let bytes = x.to_le_bytes();
            let n = (random.len() - pos).min(8);
            random[pos..pos + n].copy_from_slice(&bytes[..n]);
            pos += n;
        }
        match fs.create_file_child(root, "probe-random.bin") {
            Ok(file) => {
                if let Err(error) = fs.write_file_at(file, 0, &random) {
                    println!("[hxfs] multi-slot-write: write failed ({:?})", error);
                }
            }
            Err(error) => println!("[hxfs] multi-slot-write: create failed ({:?})", error),
        }
    }
    // Persist both writes, then reopen with fresh handles.
    match fs.publish_checkpoint() {
        Ok(_) => {}
        Err(error) => {
            println!("[hxfs] write-roundtrip: checkpoint failed ({:?})", error);
            return;
        }
    }
    // Phase C: read back the compressible probe.
    {
        let mut cbuf = [0u8; 512];
        let expected = {
            let mut buf = [0u8; 512];
            let mut pos = 0usize;
            while pos < buf.len() {
                let n = (buf.len() - pos).min(LINE.len());
                buf[pos..pos + n].copy_from_slice(&LINE[..n]);
                pos += n;
            }
            buf
        };
        match fs.open_child_file(root, "probe-compress.bin") {
            Ok(file) => match fs.read_file(file, &mut cbuf) {
                Ok(n) if n == 512 && cbuf[..n] == expected[..] => {
                    println!("[hxfs] write-roundtrip-ok");
                }
                Ok(n) => println!("[hxfs] write-roundtrip: mismatch (n={n}, expected 512)"),
                Err(error) => println!("[hxfs] write-roundtrip: read failed ({:?})", error),
            },
            Err(error) => println!("[hxfs] write-roundtrip: reopen failed ({:?})", error),
        }
    }
    // Phase D: read back the incompressible probe.
    {
        let mut rbuf = [0u8; 4096];
        let mut expected = [0u8; 4096];
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut pos = 0usize;
        while pos < expected.len() {
            let mut x = state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            state = x;
            let bytes = x.to_le_bytes();
            let n = (expected.len() - pos).min(8);
            expected[pos..pos + n].copy_from_slice(&bytes[..n]);
            pos += n;
        }
        match fs.open_child_file(root, "probe-random.bin") {
            Ok(file) => match fs.read_file(file, &mut rbuf) {
                Ok(n) if n == 4096 && rbuf[..n] == expected[..] => {
                    println!("[hxfs] multi-slot-write-ok");
                }
                Ok(n) => println!("[hxfs] multi-slot-write: mismatch (n={n}, expected 4096)"),
                Err(error) => println!("[hxfs] multi-slot-write: read failed ({:?})", error),
            },
            Err(error) => println!("[hxfs] multi-slot-write: reopen failed ({:?})", error),
        }
    }
    // Phase E (Stage E): a 4 MiB file with a compressible pattern,
    // written and read back in 4 KiB chunks through the real mount
    // API. 1024 extents exercise the multi-block extent tree (11
    // leaves) on target; the 16 MiB host test covers a deeper tree.
    // The size is bounded by the service's writer, which is created
    // on the mount call stack (SERVICE_MAX_EXTENTS = 1024 -> ~64 KiB
    // of fixed arrays) and then moved into the heap-backed runtime;
    // a larger on-target file needs the O(n^2) extent sort replaced.
    {
        const BIG_CHUNKS: usize = 4096;
        const BIG_FILE: &str = "probe-big.bin";
        match fs.create_file_child(root, BIG_FILE) {
            Ok(file) => {
                let mut chunk = [0u8; 4096];
                let line: &[u8] = b"HuesOS 16MiB Stage E probe 0123456789\n";
                let mut chunk_index = 0usize;
                while chunk_index < BIG_CHUNKS {
                    chunk[0..8].copy_from_slice(&chunk_index.to_le_bytes());
                    let mut pos = 8usize;
                    while pos < chunk.len() {
                        let n = (chunk.len() - pos).min(line.len());
                        chunk[pos..pos + n].copy_from_slice(&line[..n]);
                        pos += n;
                    }
                    if let Err(error) = fs.write_file_at(file, (chunk_index * 4096) as u64, &chunk)
                    {
                        println!("[hxfs] stage-e-write: write failed ({:?})", error);
                        break;
                    }
                    chunk_index += 1;
                }
                if chunk_index == BIG_CHUNKS {
                    // Reopen with a fresh handle and read back in
                    // chunks, verifying the first 8 bytes of each.
                    if let Ok(file) = fs.open_child_file(root, BIG_FILE) {
                        let mut rbuf = [0u8; 4096];
                        let mut ok = true;
                        let mut index = 0usize;
                        while index < BIG_CHUNKS {
                            match fs.read_file_at(file, (index * 4096) as u64, &mut rbuf) {
                                Ok(_) => {
                                    let expect = index.to_le_bytes();
                                    if rbuf[..8] != expect[..] {
                                        println!(
                                            "[hxfs] stage-e-write: chunk {index} got {:?} want {:?}",
                                            &rbuf[..8],
                                            expect
                                        );
                                        ok = false;
                                        break;
                                    }
                                }
                                _ => {
                                    ok = false;
                                    break;
                                }
                            }
                            index += 1;
                        }
                        if ok {
                            println!("[hxfs] stage-e-16mib-ok");
                        } else {
                            println!("[hxfs] stage-e-write: verify failed at {index}");
                        }
                    } else {
                        println!("[hxfs] stage-e-write: reopen failed");
                    }
                }
            }
            Err(error) => println!("[hxfs] stage-e-write: create failed ({:?})", error),
        }
    }
    // Stage E (Production polish, soak inject=4): stress phase.
    // Sustained NVMe/page-cache churn without growing the extent
    // array: each cycle reads the 16 MiB probe file end-to-end
    // (verify pattern) and rewrites a small file. A single failure
    // fails the phase.
    {
        const STRESS_CYCLES: usize = 3;
        const STRESS_FILE: &str = "probe-big.bin";
        const TOUCH_FILE: &str = "probe-touch.bin";
        let mut ok = true;
        let mut cycle = 0usize;
        while cycle < STRESS_CYCLES {
            // 1) Full read of the 16 MiB file (chunked).
            match fs.open_child_file(root, STRESS_FILE) {
                Ok(file) => {
                    let mut rbuf = [0u8; 4096];
                    let mut probe = 0usize;
                    while probe < 4096 {
                        if let Err(error) = fs.read_file_at(file, (probe * 4096) as u64, &mut rbuf)
                        {
                            println!("[hxfs] stress: read failed at {} ({:?})", probe, error);
                            ok = false;
                            break;
                        }
                        if rbuf[..8] != probe.to_le_bytes()[..] {
                            println!("[hxfs] stress: verify failed at {}", probe);
                            ok = false;
                            break;
                        }
                        probe += 1;
                    }
                }
                Err(error) => {
                    println!("[hxfs] stress: open failed ({:?})", error);
                    ok = false;
                }
            }
            // 2) Rewrite a small file (1 block) to churn the write path.
            if ok {
                match fs.open_child_file(root, TOUCH_FILE) {
                    Ok(file) => {
                        let mut chunk = [0u8; 4096];
                        chunk[0..8].copy_from_slice(&cycle.to_le_bytes());
                        if let Err(error) = fs.write_file_at(file, 0, &chunk) {
                            println!("[hxfs] stress: touch write failed ({:?})", error);
                            ok = false;
                        }
                    }
                    Err(_) => {
                        // First cycle: create it.
                        if let Ok(file) = fs.create_file_child(root, TOUCH_FILE) {
                            let mut chunk = [0u8; 4096];
                            chunk[0..8].copy_from_slice(&cycle.to_le_bytes());
                            if let Err(error) = fs.write_file_at(file, 0, &chunk) {
                                println!("[hxfs] stress: touch create write failed ({:?})", error);
                                ok = false;
                            }
                        } else {
                            println!("[hxfs] stress: touch create failed");
                            ok = false;
                        }
                    }
                }
            }
            if !ok {
                break;
            }
            cycle += 1;
        }
        if ok {
            println!(
                "[hxfs] stress-ok ({} cycles x 16MiB read + touch)",
                STRESS_CYCLES
            );
        } else {
            println!("[hxfs] stress-failed at cycle {}", cycle);
        }
    }
}
// Stage F (Phase-2 A): Hxblob object-store commands over the text
// protocol. PUT_BLOB <hex> stores the decoded bytes and replies
// with the hex content hash; GET_BLOB <hex-hash> replies with the
// hex payload; LIST_BLOBS replies with the hex hashes, one per
// line. The blob API is host-tested; these commands make it usable
// from userspace (and from the soak harness).
#[cfg(feature = "synthetic-key")]
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(feature = "synthetic-key")]
fn hex_decode(input: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    let mut out = alloc::vec::Vec::with_capacity(input.len() / 2);
    let mut index = 0usize;
    while index < input.len() {
        let hi = hex_value(input[index])?;
        let lo = hex_value(input[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Some(out)
}

#[cfg(feature = "synthetic-key")]
fn hex_encode(bytes: &[u8]) -> alloc::string::String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = alloc::string::String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

impl HxfsRuntime {
    /// Stage F (Phase-2 A): handle one Hxblob text command.
    #[cfg(feature = "synthetic-key")]
    fn handle_blob_command(&mut self, index: usize, request: &[u8]) -> bool {
        if let Some(rest) = strip_prefix(request, b"PUT_BLOB ") {
            let Some(data) = hex_decode(rest) else {
                self.write_client(index, b"err:bad-hex");
                return true;
            };
            match self.fs.put_blob(&data) {
                Ok(hash) => {
                    let reply = hex_encode(&hash);
                    println!("[hxfs] blob-put hash={}", reply);
                    self.write_client(index, reply.as_bytes());
                }
                Err(e) => {
                    println!("[hxfs] blob-put failed: {:?}", e);
                    self.write_client(index, b"err:blob-put");
                }
            }
            return true;
        }
        if let Some(rest) = strip_prefix(request, b"GET_BLOB ") {
            let Some(hash) = hex_decode(rest) else {
                self.write_client(index, b"err:bad-hex");
                return true;
            };
            if hash.len() != 32 {
                self.write_client(index, b"err:bad-hash");
                return true;
            }
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&hash);
            match self.fs.get_blob(&hash_bytes) {
                Ok(data) => {
                    let reply = hex_encode(&data);
                    println!("[hxfs] blob-get bytes={}", data.len());
                    self.write_client(index, reply.as_bytes());
                }
                Err(e) => {
                    println!("[hxfs] blob-get failed: {:?}", e);
                    self.write_client(index, b"err:not-found");
                }
            }
            return true;
        }
        if let Some(rest) = strip_prefix(request, b"GET_BLOB_CHUNK ") {
            // GET_BLOB_CHUNK <hash-hex> <offset-dec>: returns a hex
            // chunk of up to 2048 payload bytes starting at offset,
            // or an empty reply past the end. Enables streaming
            // large blobs (ELF/WAD) through the text protocol.
            let mut parts = rest.splitn(2, |&b| b == b' ');
            let Some(hash_hex) = parts.next() else {
                self.write_client(index, b"err:bad-args");
                return true;
            };
            let Some(offset_str) = parts.next() else {
                self.write_client(index, b"err:bad-args");
                return true;
            };
            let Some(hash) = hex_decode(hash_hex) else {
                self.write_client(index, b"err:bad-hex");
                return true;
            };
            if hash.len() != 32 {
                self.write_client(index, b"err:bad-hash");
                return true;
            }
            let Ok(offset_text) = core::str::from_utf8(offset_str) else {
                self.write_client(index, b"err:bad-offset");
                return true;
            };
            let Ok(offset) = offset_text.parse::<usize>() else {
                self.write_client(index, b"err:bad-offset");
                return true;
            };
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&hash);
            match self.fs.get_blob(&hash_bytes) {
                Ok(data) => {
                    const CHUNK: usize = 2048;
                    let start = offset.min(data.len());
                    let end = (start + CHUNK).min(data.len());
                    let reply = hex_encode(&data[start..end]);
                    println!(
                        "[hxfs] blob-get-chunk offset={} bytes={}",
                        start,
                        end - start
                    );
                    self.write_client(index, reply.as_bytes());
                }
                Err(e) => {
                    println!("[hxfs] blob-get-chunk failed: {:?}", e);
                    self.write_client(index, b"err:not-found");
                }
            }
            return true;
        }
        if request == b"LIST_BLOBS" {
            let mut reply = alloc::string::String::new();
            for hash in self.fs.list_blobs() {
                reply.push_str(&hex_encode(&hash));
                reply.push('\n');
            }
            self.write_client(index, reply.as_bytes());
            return true;
        }
        false
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write;
    // Full panic info (message + source location) to the debug
    // console: the soak harness needs to see WHY the service died,
    // not just that it did.
    let _ = writeln!(libcanvas::debug::DebugWriter, "[hxfs] PANIC: {info:?}");
    // Allocator diagnostics: on an OOM panic this shows how much the
    // heap was actually holding, and a non-zero corruption count
    // points at a bad free rather than genuine exhaustion.
    if let Some(stats) = HEAP.stats() {
        let _ = writeln!(
            libcanvas::debug::DebugWriter,
            "[hxfs] heap: live={} allocs={} frees={} oom={} corruption={}",
            stats.live_bytes,
            stats.allocations,
            stats.deallocations,
            stats.oom_failures,
            stats.corruption_failures
        );
    } else {
        let _ = writeln!(libcanvas::debug::DebugWriter, "[hxfs] heap: uninitialised");
    }
    libcanvas::process::exit(-1);
}
