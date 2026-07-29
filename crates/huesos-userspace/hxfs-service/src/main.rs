//! Read-only Hxfs userspace service.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use huesos_hxfs::format::{DirectoryHandle, FileHandle};
use huesos_hxfs::reader::BlockReader;
use huesos_hxfs::{Hxfs, HxfsError};
use libcanvas::{println, Channel, ErrorCode, Vmo};

const MAX_CLIENTS: usize = 4;
const MAX_FILE_HANDLES: usize = 8;
const MAX_DIR_HANDLES: usize = 8;
const MAX_READ_BYTES: usize = 4096;

struct BlockDeviceReader {
    device: libcanvas::block::BlockDevice,
}

impl BlockReader for BlockDeviceReader {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        self.device
            .read_blocks(lba, blocks, out)
            .map_err(|_| HxfsError::Io)
    }
}

type MountedHxfs = Hxfs<BlockDeviceReader>;

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
        let mut buf = [0u8; 320];
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

    fn poll_file(&mut self, index: usize) {
        let mut buf = [0u8; 64];
        loop {
            let Some(endpoint) = self.files[index].as_ref() else {
                return;
            };
            match endpoint.channel.read_into(&mut buf) {
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

    fn write_file(&self, index: usize, bytes: &[u8]) {
        if let Some(endpoint) = self.files[index].as_ref() {
            let _ = endpoint.channel.write(bytes);
        }
    }

    fn poll_dir(&mut self, index: usize) {
        let mut buf = [0u8; 320];
        loop {
            let Some(endpoint) = self.dirs[index].as_ref() else {
                return;
            };
            match endpoint.channel.read_into(&mut buf) {
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
                let reader = BlockDeviceReader { device };
                match Hxfs::mount(reader) {
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
        let _ = bootstrap.write(b"service:hxfs:unavailable");
        loop {
            libcanvas::process::yield_now();
        }
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
