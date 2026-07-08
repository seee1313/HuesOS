//! BOOTFS parser backed by a VMO.

use libcanvas::Vmo;

const MAGIC: &[u8; 8] = b"HBOOTFS1";
const HEADER_SIZE: u64 = 16;
const ENTRY_SIZE: u64 = 216;
const PATH_SIZE: usize = 192;

/// BOOTFS archive backed by a transferred VMO.
pub struct BootFs {
    pub vmo: Vmo,
    file_count: u32,
}

#[derive(Clone, Copy)]
pub struct Entry {
    pub offset: u64,
    pub len: u64,
}

impl BootFs {
    /// Parse BOOTFS header from `vmo`.
    pub fn new(vmo: Vmo) -> libcanvas::Result<Self> {
        let mut header = [0u8; HEADER_SIZE as usize];
        let read = vmo.read(0, &mut header)?;
        if read != header.len() || &header[0..8] != MAGIC {
            return Err(libcanvas::ErrorCode::InvalidArgs);
        }
        let file_count = read_u32(&header[8..12]);
        Ok(Self { vmo, file_count })
    }

    /// Read a file into `out`, returning bytes copied.
    pub fn read_file(&self, path: &str, out: &mut [u8]) -> libcanvas::Result<usize> {
        let Some(entry) = self.get_entry(path)? else {
            return Err(libcanvas::ErrorCode::NotFound);
        };
        let to_read = (entry.len as usize).min(out.len());
        self.vmo.read(entry.offset, &mut out[..to_read])
    }

    /// Write a text stat response for `path` into `out`.
    pub fn stat_text(&self, path: &str, out: &mut [u8]) -> libcanvas::Result<usize> {
        let Some(entry) = self.get_entry(path)? else {
            return Err(libcanvas::ErrorCode::NotFound);
        };
        let mut writer = ByteWriter::new(out);
        writer.write_str("path=");
        writer.write_str(path);
        writer.write_str(" size=");
        writer.write_u64(entry.len);
        writer.write_byte(b'\n');
        Ok(writer.len())
    }

    /// Write a newline-separated listing of files under `prefix` into `out`.
    pub fn list_text(&self, prefix: &str, out: &mut [u8]) -> libcanvas::Result<usize> {
        let mut writer = ByteWriter::new(out);
        let mut idx = 0;
        while idx < self.file_count {
            let entry = self.read_raw_entry(idx)?;
            let path_len = entry_path_len(&entry);
            let path = &entry[..path_len];
            if path_matches_prefix(path, prefix.as_bytes()) {
                writer.write_bytes(path);
                writer.write_byte(b'\n');
            }
            idx += 1;
        }
        Ok(writer.len())
    }

    /// Find a file's offset and length in the archive.
    pub fn get_entry(&self, path: &str) -> libcanvas::Result<Option<Entry>> {
        let needle = path.as_bytes();
        let mut idx = 0;
        while idx < self.file_count {
            let raw = self.read_raw_entry(idx)?;
            let path_len = entry_path_len(&raw);
            if &raw[..path_len] == needle {
                let meta = &raw[PATH_SIZE..];
                return Ok(Some(Entry {
                    offset: read_u64(&meta[0..8]),
                    len: read_u64(&meta[8..16]),
                }));
            }
            idx += 1;
        }
        Ok(None)
    }

    fn read_raw_entry(&self, index: u32) -> libcanvas::Result<[u8; ENTRY_SIZE as usize]> {
        let mut raw = [0u8; ENTRY_SIZE as usize];
        let offset = HEADER_SIZE + index as u64 * ENTRY_SIZE;
        let read = self.vmo.read(offset, &mut raw)?;
        if read != raw.len() {
            return Err(libcanvas::ErrorCode::InvalidArgs);
        }
        Ok(raw)
    }
}

fn entry_path_len(entry: &[u8; ENTRY_SIZE as usize]) -> usize {
    let mut len = 0;
    while len < PATH_SIZE && entry[len] != 0 {
        len += 1;
    }
    len
}

fn path_matches_prefix(path: &[u8], prefix: &[u8]) -> bool {
    if prefix == b"/" || prefix.is_empty() {
        return true;
    }
    path == prefix || (path.len() > prefix.len() && path.starts_with(prefix) && path[prefix.len()] == b'/')
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

struct ByteWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> ByteWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }
    fn len(&self) -> usize {
        self.len
    }
    fn write_byte(&mut self, byte: u8) {
        if self.len < self.buf.len() {
            self.buf[self.len] = byte;
            self.len += 1;
        }
    }
    fn write_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_byte(byte);
        }
    }
    fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }
    fn write_u64(&mut self, mut value: u64) {
        let mut digits = [0u8; 20];
        let mut len = 0;
        if value == 0 {
            self.write_byte(b'0');
            return;
        }
        while value > 0 && len < digits.len() {
            digits[len] = b'0' + (value % 10) as u8;
            value /= 10;
            len += 1;
        }
        while len > 0 {
            len -= 1;
            self.write_byte(digits[len]);
        }
    }
}
