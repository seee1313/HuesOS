use huesos_hxfs::compression::{CompressionPolicy, COMPRESSION_LZ4, COMPRESSION_ZSTD};
use huesos_hxfs::crypto::{EncryptionPolicy, KeyProvider, ALGORITHM_AES_XTS, DATA_UNIT_BYTES_4K};
use huesos_hxfs::fixed_writer::FixedHxfsWriter;
use huesos_hxfs::recovery::BlockStore;
use huesos_hxfs::format::{BLOCK_SIZE, FORMAT_VERSION, LEGACY_FORMAT_VERSION};
use huesos_hxfs::reader::BlockReader;
use huesos_hxfs::HxfsError;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

const MAX_OBJECTS: usize = 256;
const MAX_DIR_ENTRIES: usize = 1024;
const MAX_EXTENTS: usize = 8192;
const MIGRATION_STACK_BYTES: usize = 32 * 1024 * 1024;

type MigratingHxfs = FixedHxfsWriter<FileStore, MAX_OBJECTS, MAX_DIR_ENTRIES, MAX_EXTENTS>;

struct Options {
    image: PathBuf,
    commit: bool,
    key: Option<[u8; 32]>,
    encryption: Vec<EncryptionPolicy>,
    compression: Vec<CompressionPolicy>,
}

struct FileStore {
    file: File,
}

impl FileStore {
    fn open(path: &PathBuf, write: bool) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .open(path)
            .map_err(|error| format!("open {}: {error}", path.display()))?;
        Ok(Self { file })
    }

    fn transfer(&mut self, lba: u64, blocks: u32, bytes: &mut [u8]) -> Result<(), HxfsError> {
        let length = blocks as usize * BLOCK_SIZE;
        if bytes.len() < length {
            return Err(HxfsError::BufferTooSmall);
        }
        let offset = lba
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(HxfsError::OutOfRange)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| HxfsError::Io)?;
        self.file
            .read_exact(&mut bytes[..length])
            .map_err(|_| HxfsError::Io)
    }
}

impl BlockReader for FileStore {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        self.transfer(lba, blocks, out)
    }
}

impl BlockStore for FileStore {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        let length = blocks as usize * BLOCK_SIZE;
        let bytes = input.get(..length).ok_or(HxfsError::BufferTooSmall)?;
        let offset = lba
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(HxfsError::OutOfRange)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| HxfsError::Io)?;
        self.file.write_all(bytes).map_err(|_| HxfsError::Io)
    }

    fn flush(&mut self) -> Result<(), HxfsError> {
        self.file.sync_all().map_err(|_| HxfsError::Io)
    }
}

fn main() {
    let options = match parse_options() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("hxfs-migrate: {error}");
            usage();
            std::process::exit(2);
        }
    };
    let result = std::thread::Builder::new()
        .name("hxfs-v5-v6-migration".to_string())
        .stack_size(MIGRATION_STACK_BYTES)
        .spawn(move || migrate(options))
        .and_then(|thread| {
            thread
                .join()
                .map_err(|_| std::io::Error::other("migration thread panicked"))?
                .map_err(std::io::Error::other)
        });
    if let Err(error) = result {
        eprintln!("hxfs-migrate: {error}");
        std::process::exit(1);
    }
}

fn migrate(mut options: Options) -> Result<(), String> {
    let version = read_format_version(&options.image)?;
    if version == FORMAT_VERSION {
        println!("{} is already HxFS v{FORMAT_VERSION}", options.image.display());
        clear_optional_key(&mut options.key);
        return Ok(());
    }
    if version != LEGACY_FORMAT_VERSION {
        clear_optional_key(&mut options.key);
        return Err(format!("unsupported source format v{version}"));
    }
    if !options.commit {
        println!(
            "validated migration request for {}: v{} -> v{} (dry run; pass --commit)",
            options.image.display(),
            LEGACY_FORMAT_VERSION,
            FORMAT_VERSION
        );
        clear_optional_key(&mut options.key);
        return Ok(());
    }

    let store = FileStore::open(&options.image, true)?;
    let mut mounted = MigratingHxfs::mount_with_policies(
        store,
        &options.encryption,
        &options.compression,
        options.key.as_ref(),
    )
    .map_err(|error| format!("mount legacy volume: {error:?}"))?;
    if !mounted.is_legacy_read_only() {
        clear_optional_key(&mut options.key);
        return Err("source changed format during migration".to_string());
    }
    let sequence = mounted
        .migrate_legacy_to_v6(&options.encryption, &options.compression)
        .map_err(|error| format!("journaled migration: {error:?}"))?;
    let mut store = mounted.into_store();
    store.flush().map_err(|error| format!("final flush: {error:?}"))?;
    clear_optional_key(&mut options.key);
    println!(
        "migrated {} to HxFS v{} at checkpoint sequence {}",
        options.image.display(),
        FORMAT_VERSION,
        sequence
    );
    Ok(())
}

fn read_format_version(path: &PathBuf) -> Result<u32, String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)
        .map_err(|error| format!("read superblock: {error}"))?;
    let header_bytes = u16::from_le_bytes([header[6], header[7]]) as usize;
    let offset = header_bytes
        .checked_add(16)
        .ok_or_else(|| "superblock offset overflow".to_string())?;
    let raw = header
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated superblock".to_string())?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn parse_options() -> Result<Options, String> {
    let mut args = env::args().skip(1);
    let image = PathBuf::from(args.next().ok_or_else(|| "missing IMAGE".to_string())?);
    let mut options = Options {
        image,
        commit: false,
        key: None,
        encryption: Vec::new(),
        compression: Vec::new(),
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--commit" => options.commit = true,
            "--volume-key-hex" => {
                let value = args.next().ok_or_else(|| "missing key hex".to_string())?;
                options.key = Some(parse_key(&value)?);
            }
            "--encryption-policy" => {
                let id = parse_u32(&args.next().ok_or_else(|| "missing policy id".to_string())?)?;
                options.encryption.push(EncryptionPolicy {
                    policy_id: id,
                    algorithm: ALGORITHM_AES_XTS,
                    data_unit_bytes: DATA_UNIT_BYTES_4K,
                    provider: KeyProvider::TpmOrBootloader,
                });
            }
            "--compression-policy" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing compression policy".to_string())?;
                options.compression.push(parse_compression_policy(&value)?);
            }
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    Ok(options)
}

fn parse_compression_policy(text: &str) -> Result<CompressionPolicy, String> {
    let mut fields = text.split(':');
    let policy_id = parse_u32(fields.next().ok_or_else(|| "missing policy id".to_string())?)?;
    let algorithm = match fields.next() {
        Some("lz4") => COMPRESSION_LZ4,
        Some("zstd") => COMPRESSION_ZSTD,
        _ => return Err("compression algorithm must be lz4 or zstd".to_string()),
    };
    let min_size_bytes = parse_u32(
        fields
            .next()
            .ok_or_else(|| "missing minimum size".to_string())?,
    )?;
    if fields.next().is_some() {
        return Err("too many compression-policy fields".to_string());
    }
    Ok(CompressionPolicy {
        policy_id,
        algorithm,
        min_size_bytes,
    })
}

fn parse_u32(text: &str) -> Result<u32, String> {
    text.parse::<u32>()
        .map_err(|_| format!("invalid integer {text}"))
}

fn parse_key(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("volume key must be exactly 64 hex digits".to_string());
    }
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid key hex".to_string())?;
    }
    Ok(key)
}

fn clear_optional_key(key: &mut Option<[u8; 32]>) {
    if let Some(bytes) = key.as_mut() {
        for byte in bytes.iter_mut() {
            *byte = 0;
            let _ = std::hint::black_box(*byte);
        }
    }
    *key = None;
}

fn usage() {
    eprintln!(
        "usage: hxfs-migrate IMAGE [--commit] [--volume-key-hex HEX] \\\n         [--encryption-policy ID] [--compression-policy ID:lz4|zstd:MIN_BYTES]"
    );
}
