//! Host-side Hxfs volume seeder for the qemu-nvme soak (Stage B.5).
//!
//! Builds a sparse Hxfs volume image that contains one seeded file
//! (`seed.bin`, default 3.5 KiB of compressible data) written
//! through the same `FixedHxfsWriter` the production `hxfs-service`
//! uses, with the synthetic encryption policy (AES-256-GCM
//! envelope) and the LZ4 compression policy. The service boots
//! against the resulting image, mounts it with the matching policy
//! table, and verifies the seed file with its boot self-check.
//!
//! `--inject-bad-gcm-tag` flips one bit inside the encrypted
//! envelope of the seed file's first data extent before the
//! checkpoint is published, so the on-target self-check hits a
//! bad GCM tag and must report `[hxfs] bad-gcm-tag-marked` while
//! the service keeps serving.
//!
//! The volume is sparse: only metadata and the seed extents are
//! materialised; the rest of the image is implicitly zero-filled,
//! which Hxfs treats as unwritten.
//!
//! Run via `tools/hxfs-seed.sh` (or `mkhxfs.py --seed-file ...`,
//! which delegates here) so the host target is pinned explicitly.

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use huesos_hxfs::fixed_writer::FixedHxfsWriter;
use huesos_hxfs::reader::BlockReader;
use huesos_hxfs::recovery::BlockStore;
use huesos_hxfs::synthetic_key;
use huesos_hxfs::synthetic_image::BOOT_IMAGE_BLOCKS;
use huesos_hxfs::HxfsError;

/// Maximum seed file size: the writer's extent table is a single
/// block; with v2 records the payload holds
/// `(4056 - 16) / 40 = 101` records, i.e. 100 full 4 KiB extents
/// plus a final partial block (~404 KiB).
const MAX_SEED_BYTES: usize = 100 * 4096 + 4096;

struct Args {
    output: PathBuf,
    blocks: u64,
    instance_uuid: [u8; 16],
    volume_uuid: [u8; 16],
    seed_file: String,
    seed_size: usize,
    inject_bad_gcm_tag: bool,
    inject_bad_crc: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: huesos-hxfs-seed --output PATH [--blocks N] [--instance-uuid HEX] \
         [--volume-uuid HEX] [--seed-file NAME] [--seed-size BYTES] \
         [--inject-bad-gcm-tag] [--inject-bad-crc]"
    );
    std::process::exit(2);
}

fn parse_hex_uuid(text: &str) -> Option<[u8; 16]> {
    let cleaned: String = text.chars().filter(|c| *c != '-').collect();
    if cleaned.len() != 32 {
        return None;
    }
    let mut uuid = [0u8; 16];
    let mut index = 0usize;
    while index < 16 {
        uuid[index] = u8::from_str_radix(&cleaned[index * 2..index * 2 + 2], 16).ok()?;
        index += 1;
    }
    Some(uuid)
}

fn parse_args() -> Args {
    let mut output = None;
    let mut blocks = 1_048_576u64; // 4 GiB default, matching the soak image
    let mut instance_uuid = [0x11; 16];
    let mut volume_uuid = [0x22; 16];
    let mut seed_file = String::from(synthetic_key::SEED_FILE_NAME);
    let mut seed_size = 3584usize;
    let mut inject_bad_gcm_tag = false;
    let mut inject_bad_crc = false;
    let mut index = 1usize;
    let args: Vec<String> = std::env::args().collect();
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(args.get(index).unwrap_or_else(|| {
                    eprintln!("--output requires a path");
                    std::process::exit(2);
                })));
            }
            "--blocks" => {
                index += 1;
                blocks = args
                    .get(index)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--blocks requires an integer");
                        std::process::exit(2);
                    });
            }
            "--instance-uuid" => {
                index += 1;
                instance_uuid = args
                    .get(index)
                    .and_then(|v| parse_hex_uuid(v))
                    .unwrap_or_else(|| {
                        eprintln!("--instance-uuid requires 32 hex chars");
                        std::process::exit(2);
                    });
            }
            "--volume-uuid" => {
                index += 1;
                volume_uuid = args
                    .get(index)
                    .and_then(|v| parse_hex_uuid(v))
                    .unwrap_or_else(|| {
                        eprintln!("--volume-uuid requires 32 hex chars");
                        std::process::exit(2);
                    });
            }
            "--seed-file" => {
                index += 1;
                seed_file = args.get(index).cloned().unwrap_or_else(|| {
                    eprintln!("--seed-file requires a name");
                    std::process::exit(2);
                });
            }
            "--seed-size" => {
                index += 1;
                seed_size = args
                    .get(index)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--seed-size requires an integer");
                        std::process::exit(2);
                    });
            }
            "--inject-bad-gcm-tag" => inject_bad_gcm_tag = true,
            "--inject-bad-crc" => inject_bad_crc = true,
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
        index += 1;
    }
    let output = output.unwrap_or_else(|| {
        eprintln!("--output is required");
        usage();
    });
    if seed_size == 0 || seed_size > MAX_SEED_BYTES {
        eprintln!(
            "--seed-size must be in 1..={MAX_SEED_BYTES} (single-block extent table limit)"
        );
        std::process::exit(2);
    }
    if inject_bad_gcm_tag && inject_bad_crc {
        eprintln!("--inject-bad-gcm-tag and --inject-bad-crc are mutually exclusive");
        std::process::exit(2);
    }
    Args {
        output,
        blocks,
        instance_uuid,
        volume_uuid,
        seed_file,
        seed_size,
        inject_bad_gcm_tag,
        inject_bad_crc,
    }
}

/// Block store over a sparse host file.
struct FileStore {
    file: File,
}

impl FileStore {
    fn open_with(
        path: &std::path::Path,
        blocks: u64,
        truncate: bool,
    ) -> Result<Self, String> {
        use std::fs::OpenOptions;
        // read+write: the writer both writes the boot image and
        // reads blocks back at mount; File::create alone is
        // write-only and read_at would fail with EBADF.
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        if truncate {
            options.truncate(true);
        }
        let file = options
            .open(path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        file.set_len(blocks * 4096)
            .map_err(|e| format!("set_len: {e}"))?;
        Ok(Self { file })
    }

    fn create(path: &std::path::Path, blocks: u64) -> Result<Self, String> {
        Self::open_with(path, blocks, true)
    }
}

impl BlockReader for FileStore {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        let offset = lba
            .checked_mul(4096)
            .ok_or(HxfsError::OutOfRange)?;
        let want = (blocks as u64)
            .checked_mul(4096)
            .ok_or(HxfsError::OutOfRange)?;
        let want = usize::try_from(want).map_err(|_| HxfsError::OutOfRange)?;
        if want > out.len() {
            return Err(HxfsError::OutOfRange);
        }
        let got = self.file.read_at(&mut out[..want], offset).map_err(|_| HxfsError::Io)?;
        if got < want {
            out[got..want].fill(0);
        }
        Ok(())
    }
}

impl BlockStore for FileStore {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        let expected = (blocks as u64)
            .checked_mul(4096)
            .ok_or(HxfsError::OutOfRange)?;
        if expected != input.len() as u64 {
            return Err(HxfsError::OutOfRange);
        }
        let offset = lba.checked_mul(4096).ok_or(HxfsError::OutOfRange)?;
        self.file.write_all_at(input, offset).map_err(|_| HxfsError::Io)
    }

    fn flush(&mut self) -> Result<(), HxfsError> {
        self.file.flush().map_err(|_| HxfsError::Io)
    }
}

/// Records data-block write ranges while recording is enabled, so
/// the seed tool can locate the seed file's extents for the
/// bad-GCM-tag injection.
struct RecordingStore {
    inner: FileStore,
    recording: bool,
    ranges: Vec<(u64, u32)>,
}

impl RecordingStore {
    fn start_recording(&mut self) {
        self.recording = true;
    }

    fn stop_recording(&mut self) -> Vec<(u64, u32)> {
        self.recording = false;
        std::mem::take(&mut self.ranges)
    }
}

impl BlockReader for RecordingStore {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), HxfsError> {
        self.inner.read_blocks(lba, blocks, out)
    }
}

impl BlockStore for RecordingStore {
    fn write_blocks(&mut self, lba: u64, blocks: u32, input: &[u8]) -> Result<(), HxfsError> {
        if self.recording {
            self.ranges.push((lba, blocks));
        }
        self.inner.write_blocks(lba, blocks, input)
    }

    fn flush(&mut self) -> Result<(), HxfsError> {
        self.inner.flush()
    }
}

/// Deterministic compressible block fill.
fn fill_compressible_chunk(chunk: &mut [u8; 4096], index: usize) {
    const LINE: &[u8] =
        b"HuesOS Stage B.5 soak seed - encrypted+compressed pipeline verification 0123456789\n";
    let mut pos = 0usize;
    while pos < chunk.len() {
        let n = (chunk.len() - pos).min(LINE.len());
        chunk[pos..pos + n].copy_from_slice(&LINE[..n]);
        pos += n;
    }
    chunk[0..8].copy_from_slice(&index.to_le_bytes());
}

fn fail(message: &str) -> ! {
    eprintln!("[hxfs-seed] {message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use huesos_hxfs::reader::SliceBlockReader;
    use huesos_hxfs::Hxfs;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum InjectMode {
        None,
        Gcm,
        Crc,
    }

    fn build_test_image(inject: InjectMode) -> Vec<u8> {
        let path = std::env::temp_dir().join(format!(
            "huesos-seed-test-{}-{inject:?}.img",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = FileStore::create(&path, 1024).expect("create store");
        let mut store = RecordingStore {
            inner: store,
            recording: false,
            ranges: Vec::new(),
        };
        // CRC injection needs a plain volume (the corruption must
        // surface as a payload CRC failure, not a GCM tag failure).
        let encrypted = inject != InjectMode::Crc;
        let boot_image = huesos_hxfs::synthetic_image::build_boot_image(
            [0x11; 16],
            [0x22; 16],
            encrypted,
            if encrypted {
                synthetic_key::POLICY_ID
            } else {
                0
            },
            synthetic_key::COMPRESSION_POLICY_ID,
        );
        store
            .write_blocks(0, BOOT_IMAGE_BLOCKS as u32, &boot_image)
            .expect("boot write");
        let policies = [synthetic_key::encryption_policy()];
        let comps = [synthetic_key::compression_policy()];
        let mut writer = FixedHxfsWriter::<RecordingStore, 16, 32, 128>::mount_with_policies(
            store,
            &policies,
            &comps,
            Some(&synthetic_key::VOLUME_KEY),
        )
        .expect("mount");
        let root = writer.root_directory();
        let file = writer
            .open_child_file(root, synthetic_key::SEED_FILE_NAME)
            .expect("open seed");
        writer.store_mut().start_recording();
        let mut chunk = [0u8; 4096];
        fill_compressible_chunk(&mut chunk, 0);
        writer
            .write_file_at(file, 0, &chunk[..3584])
            .expect("write seed");
        let ranges = writer.store_mut().stop_recording();
        match inject {
            InjectMode::Gcm => {
                let mut block = [0u8; 4096];
                writer
                    .store_mut()
                    .read_blocks(ranges[0].0, 1, &mut block)
                    .expect("read for injection");
                block[12 + 40] ^= 0x01;
                writer
                    .store_mut()
                    .write_blocks(ranges[0].0, 1, &block)
                    .expect("inject");
            }
            InjectMode::Crc => {
                let mut block = [0u8; 4096];
                writer
                    .store_mut()
                    .read_blocks(ranges[0].0, 1, &mut block)
                    .expect("read for injection");
                block[8] ^= 0x01;
                writer
                    .store_mut()
                    .write_blocks(ranges[0].0, 1, &block)
                    .expect("inject");
            }
            InjectMode::None => {}
        }
        writer.publish_checkpoint().expect("publish");
        let mut store = writer.into_store();
        store.flush().expect("flush");
        std::fs::read(&path).expect("read image back")
    }

    #[test]
    fn seeded_image_mounts_and_seed_file_round_trips() {
        let image = build_test_image(InjectMode::None);
        let policies = [synthetic_key::encryption_policy()];
        let comps = [synthetic_key::compression_policy()];

        // Read-side remount (the host-test path).
        let reader = SliceBlockReader::new(&image);
        let mut fs = Hxfs::mount_with_policies(reader, &policies, &comps, Some(&synthetic_key::VOLUME_KEY)).expect("mount");
        let file = fs.open_path("/seed.bin").expect("open seed.bin");
        let mut buf = [0u8; 4096];
        let n = fs.read_file(file, &mut buf).expect("read seed.bin");
        assert_eq!(n, 3584, "seed file length must match");
        let mut expected = [0u8; 4096];
        fill_compressible_chunk(&mut expected, 0);
        assert_eq!(&buf[..3584], &expected[..3584], "seed bytes must round-trip");

        // Writer-side remount of the PUBLISHED image: this is
        // exactly the path the hxfs-service takes at boot (mount
        // the encrypted+compressed volume, open the seed file, read
        // it back). It exercises the writer's v6 metadata
        // decryption and encrypted-dirent-name decryption at mount
        // time, which no other host test covers.
        let remount_path =
            std::env::temp_dir().join(format!("huesos-seed-remount-{}.img", std::process::id()));
        let store = FileStore::create(&remount_path, 1024).expect("create remount store");
        let mut store = RecordingStore {
            inner: store,
            recording: false,
            ranges: Vec::new(),
        };
        let blocks = (image.len() / 4096) as u32;
        store
            .write_blocks(0, blocks, &image)
            .expect("copy published image into remount store");
        let mut writer = FixedHxfsWriter::<RecordingStore, 16, 32, 128>::mount_with_policies(
            store,
            &policies,
            &comps,
            Some(&synthetic_key::VOLUME_KEY),
        )
        .expect("writer remount of published image");
        let root = writer.root_directory();
        let file = writer
            .open_child_file(root, synthetic_key::SEED_FILE_NAME)
            .expect("writer open seed.bin");
        let mut buf = [0u8; 4096];
        let n = writer.read_file(file, &mut buf).expect("writer read seed.bin");
        assert_eq!(n, 3584, "writer seed file length must match");
        assert_eq!(
            &buf[..3584],
            &expected[..3584],
            "writer seed bytes must round-trip"
        );
    }

    #[test]
    fn injected_image_still_mounts_and_bad_tag_surfaces_precisely() {
        let image = build_test_image(InjectMode::Gcm);
        let reader = SliceBlockReader::new(&image);
        let policies = [synthetic_key::encryption_policy()];
        let comps = [synthetic_key::compression_policy()];
        // Metadata is intact: the volume must still mount.
        let mut fs = Hxfs::mount_with_policies(reader, &policies, &comps, Some(&synthetic_key::VOLUME_KEY)).expect("mount");
        let file = fs.open_path("/seed.bin").expect("open seed.bin");
        let mut buf = [0u8; 4096];
        assert_eq!(
            fs.read_file(file, &mut buf).err(),
            Some(HxfsError::Compression),
            "the injected bad GCM tag must surface as the precise error"
        );
        assert_eq!(
            fs.bad_extents().len(),
            1,
            "the bad extent must be marked"
        );
    }

    #[test]
    fn injected_crc_image_still_mounts_and_checksum_fails_precisely() {
        let image = build_test_image(InjectMode::Crc);
        let policies: [huesos_hxfs::crypto::EncryptionPolicy; 0] = [];
        let comps = [synthetic_key::compression_policy()];
        // Plain volume: metadata is intact, so it must still mount.
        let reader = SliceBlockReader::new(&image);
        let mut fs =
            Hxfs::mount_with_policies(reader, &policies, &comps, None).expect("mount");
        let file = fs.open_path("/seed.bin").expect("open seed.bin");
        let mut buf = [0u8; 4096];
        assert_eq!(
            fs.read_file(file, &mut buf).err(),
            Some(HxfsError::Compression),
            "the injected bad CRC must surface as the precise error"
        );
        assert_eq!(
            fs.bad_extents().len(),
            1,
            "the bad extent must be marked"
        );
    }
}

fn main() {
    // Stage D: single source of truth for the synthetic volume key.
    // The soak harness feeds this hex to the kernel build
    // (HUESOS_VOLUME_KEY_HEX) so the bootloader key blob in the
    // kernel matches the key the volume was seeded with.
    if std::env::args().any(|arg| arg == "--print-volume-key-hex") {
        let mut hex = String::with_capacity(64);
        for byte in synthetic_key::VOLUME_KEY {
            hex.push_str(&format!("{byte:02x}"));
        }
        println!("{hex}");
        return;
    }
    let args = parse_args();
    let store = match FileStore::create(&args.output, args.blocks) {
        Ok(store) => store,
        Err(e) => fail(&e),
    };
    let mut store = RecordingStore {
        inner: store,
        recording: false,
        ranges: Vec::new(),
    };

    // Boot image: encrypted volume (synthetic policy id 7) with the
    // LZ4 volume compression policy and a pre-existing empty seed
    // file entry. Stage C: the bad-CRC mode builds a PLAIN volume
    // (also with the LZ4 policy) so the seeded-file corruption is
    // detected by the compressed-payload CRC32C instead of the GCM
    // tag.
    let encrypted = !args.inject_bad_crc;
    let boot_image = huesos_hxfs::synthetic_image::build_boot_image(
        args.instance_uuid,
        args.volume_uuid,
        encrypted,
        if encrypted {
            synthetic_key::POLICY_ID
        } else {
            0
        },
        synthetic_key::COMPRESSION_POLICY_ID,
    );
    if let Err(e) = store.write_blocks(0, BOOT_IMAGE_BLOCKS as u32, &boot_image) {
        fail(&format!("boot image write failed: {e:?}"));
    }

    let policies = [synthetic_key::encryption_policy()];
    let comps = [synthetic_key::compression_policy()];
    let mut writer = match FixedHxfsWriter::<RecordingStore, 16, 32, 128>::mount_with_policies(
        store,
        &policies,
        &comps,
        Some(&synthetic_key::VOLUME_KEY),
    ) {
        Ok(writer) => writer,
        Err(e) => fail(&format!("mount failed: {e:?}")),
    };
    let root = writer.root_directory();
    let file = match writer.open_child_file(root, &args.seed_file) {
        Ok(f) => f,
        Err(e) => fail(&format!("open seed file failed: {e:?}")),
    };

    writer.store_mut().start_recording();
    let mut offset = 0usize;
    let mut chunk_index = 0usize;
    while offset < args.seed_size {
        let remaining = args.seed_size - offset;
        let n = remaining.min(4096);
        let mut chunk = [0u8; 4096];
        fill_compressible_chunk(&mut chunk, chunk_index);
        if let Err(e) = writer.write_file_at(file, offset as u64, &chunk[..n]) {
            fail(&format!("write at offset {offset} failed: {e:?}"));
        }
        offset += n;
        chunk_index += 1;
    }
    let ranges = writer.store_mut().stop_recording();
    if ranges.is_empty() {
        fail("no data extents recorded");
    }

    let first_extent_lba = ranges[0].0;
    if args.inject_bad_gcm_tag {
        // Flip one bit inside the GCM ciphertext of the seed file's
        // first data extent (byte 40 of the ciphertext region,
        // after the 12-byte nonce). The metadata stays intact, so
        // the volume still mounts; the self-check read must hit the
        // bad tag and report `bad-gcm-tag-marked`.
        let mut block = [0u8; 4096];
        if let Err(e) = writer.store_mut().read_blocks(first_extent_lba, 1, &mut block) {
            fail(&format!("read for injection failed: {e:?}"));
        }
        block[12 + 40] ^= 0x01;
        if let Err(e) = writer.store_mut().write_blocks(first_extent_lba, 1, &block) {
            fail(&format!("injection write failed: {e:?}"));
        }
        println!(
            "[hxfs-seed] injected bad GCM tag at LBA {first_extent_lba} (offset {})",
            12 + 40
        );
    } else if args.inject_bad_crc {
        // Stage C: flip one byte of the compressed payload of the
        // seed file's first data extent on a PLAIN volume. There is
        // no envelope (payload starts at block offset 0), so the
        // descriptor CRC32C fails on read and the service reports
        // `bad-checksum-marked`.
        let mut block = [0u8; 4096];
        if let Err(e) = writer.store_mut().read_blocks(first_extent_lba, 1, &mut block) {
            fail(&format!("read for injection failed: {e:?}"));
        }
        block[8] ^= 0x01;
        if let Err(e) = writer.store_mut().write_blocks(first_extent_lba, 1, &block) {
            fail(&format!("injection write failed: {e:?}"));
        }
        println!("[hxfs-seed] injected bad CRC at LBA {first_extent_lba} (offset 8)");
    }

    if let Err(e) = writer.publish_checkpoint() {
        fail(&format!("publish_checkpoint failed: {e:?}"));
    }
    let mut store = writer.into_store();
    if let Err(e) = store.flush() {
        fail(&format!("flush failed: {e:?}"));
    }
    let mode = if args.inject_bad_gcm_tag {
        " with bad-GCM injection"
    } else if args.inject_bad_crc {
        " with bad-CRC injection (plain volume)"
    } else if encrypted {
        " encrypted+compressed"
    } else {
        " plain"
    };
    println!(
        "[hxfs-seed] wrote {} ({} blocks, seed file '{}' = {} bytes across {} extent(s){})",
        args.output.display(),
        args.blocks,
        args.seed_file,
        args.seed_size,
        ranges.len(),
        mode,
    );
}
