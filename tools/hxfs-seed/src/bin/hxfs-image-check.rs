//! Destructive host gate for freshly generated images, never an installed disk.
use huesos_hxfs::fixed_writer::FixedHxfsWriter;
use huesos_hxfs::format::{BLOCK_SIZE, FORMAT_VERSION, LEGACY_FORMAT_VERSION};
use huesos_hxfs::reader::BlockReader;
use huesos_hxfs::recovery::BlockStore;
use huesos_hxfs::HxfsError;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

type Fs = FixedHxfsWriter<FileStore, 16, 32, 128>;
struct FileStore {
    file: File,
    bytes: u64,
}
impl FileStore {
    fn open(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        let bytes = file.metadata().map_err(|e| e.to_string())?.len();
        Ok(Self { file, bytes })
    }
    fn range(&self, lba: u64, blocks: u32, len: usize) -> Result<(u64, usize), HxfsError> {
        let bytes = (blocks as usize)
            .checked_mul(BLOCK_SIZE)
            .ok_or(HxfsError::OutOfRange)?;
        let offset = lba
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(HxfsError::OutOfRange)?;
        let end = offset
            .checked_add(bytes as u64)
            .ok_or(HxfsError::OutOfRange)?;
        if bytes > len || end > self.bytes {
            return Err(HxfsError::OutOfRange);
        }
        Ok((offset, bytes))
    }
}
impl BlockReader for FileStore {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        let (offset, bytes) = self.range(lba, blocks, out.len())?;
        self.file
            .read_exact_at(&mut out[..bytes], offset)
            .map_err(|_| HxfsError::Io)
    }
}
impl BlockStore for FileStore {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        let (offset, bytes) = self.range(lba, blocks, input.len())?;
        self.file
            .write_all_at(&input[..bytes], offset)
            .map_err(|_| HxfsError::Io)
    }
    fn flush(&mut self) -> Result<(), HxfsError> {
        self.file.sync_all().map_err(|_| HxfsError::Io)
    }
}
fn hx<T>(result: Result<T, HxfsError>) -> Result<T, String> {
    result.map_err(|e| format!("{e:?}"))
}
fn mount(path: &Path) -> Result<Fs, String> {
    hx(Fs::mount_from_disk(FileStore::open(path)?, None))
}
fn check(path: &Path, legacy: bool) -> Result<(), String> {
    let mut fs = mount(path)?;
    let expected = if legacy {
        LEGACY_FORMAT_VERSION
    } else {
        FORMAT_VERSION
    };
    if fs.superblock().format_version != expected || fs.is_legacy_read_only() != legacy {
        return Err(format!(
            "unexpected format/read-only state: {:?}",
            fs.superblock().format_version
        ));
    }
    let mut names = [0u8; 4096];
    if hx(fs.list_directory(fs.root_directory(), &mut names))? != 0 {
        return Err("fresh image root is not empty".into());
    }
    if legacy {
        let result = fs.create_file_path("/image-gate.bin");
        if !matches!(result, Err(HxfsError::LegacyReadOnly)) {
            return Err("legacy mutation did not return LegacyReadOnly".into());
        }
        if fs.publish_checkpoint() != Err(HxfsError::LegacyReadOnly) {
            return Err("legacy checkpoint publication was not rejected".into());
        }
        println!("legacy read-only gate OK (v{expected})");
        return Ok(());
    }
    if fs.encryption().is_some() || fs.volume_info().compression_policy_id != 0 {
        return Err("unseeded image contains a volume policy".into());
    }
    let checkpoint = fs.checkpoint();
    if checkpoint.encryption_policy_tree_lba == 0 || checkpoint.compression_policy_tree_lba == 0 {
        return Err("current image has unpublished policy roots".into());
    }
    let data: Vec<u8> = (0..(2 * BLOCK_SIZE + 17))
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect();
    let file = hx(fs.create_file_path("/image-gate.bin"))?;
    for (index, chunk) in data.chunks(BLOCK_SIZE).enumerate() {
        hx(fs.write_file_at(file, (index * BLOCK_SIZE) as u64, chunk))?;
    }
    hx(fs.publish_checkpoint())?;
    hx(fs.into_store().flush())?;
    let mut fs = mount(path)?; // close + reopen the actual file; no cached metadata
    let file = hx(fs.open_path("/image-gate.bin"))?;
    let mut actual = vec![0u8; data.len() + 1];
    let n = hx(fs.read_file(file, &mut actual))?;
    if n != data.len() || actual[..n] != data {
        return Err("payload changed after remount".into());
    }
    hx(fs.unlink_path("/image-gate.bin"))?;
    hx(fs.publish_checkpoint())?;
    hx(fs.into_store().flush())?;
    let fs = mount(path)?;
    if hx(fs.list_directory(fs.root_directory(), &mut names))? != 0 {
        return Err("cleanup did not survive remount".into());
    }
    println!("current image write/checkpoint/remount gate OK (v{expected})");
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--format-version"] {
        println!("{FORMAT_VERSION}");
        return;
    }
    let (path, legacy) = match args.as_slice() {
        [path] => (path, false),
        [flag, path] if flag == "--legacy-read-only" => (path, true),
        _ => {
            eprintln!(
                "usage: hxfs-image-check [--legacy-read-only] FRESH-TEST-IMAGE | --format-version"
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = check(Path::new(path), legacy) {
        eprintln!("hxfs-image-check: {e}");
        std::process::exit(1);
    }
}
