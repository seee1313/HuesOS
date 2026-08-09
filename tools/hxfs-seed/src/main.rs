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
}

fn usage() -> ! {
    eprintln!(
        "usage: huesos-hxfs-seed --output PATH [--blocks N] [--instance-uuid HEX] \
         [--volume-uuid HEX] [--seed-file NAME] [--seed-size BYTES] [--inject-bad-gcm-tag]"
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
    Args {
        output,
        blocks,
        instance_uuid,
        volume_uuid,
        seed_file,
        seed_size,
        inject_bad_gcm_tag,
    }
}

/// Block store over a sparse host file.
struct FileStore {
    file: File,
}

impl FileStore {
    fn create(path: &std::path::Path, blocks: u64) -> Result<Self, String> {
        use std::fs::OpenOptions;
        // read+write: the writer both writes the boot image and
        // reads blocks back at mount; File::create alone is
        // write-only and read_at would fail with EBADF.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        file.set_len(blocks * 4096)
            .map_err(|e| format!("set_len: {e}"))?;
        Ok(Self { file })
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

    fn build_test_image(inject: bool) -> Vec<u8> {
        let path = std::env::temp_dir().join(format!(
            "huesos-seed-test-{}-{inject}.img",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = FileStore::create(&path, 1024).expect("create store");
        let mut store = RecordingStore {
            inner: store,
            recording: false,
            ranges: Vec::new(),
        };
        let boot_image = huesos_hxfs::synthetic_image::build_boot_image(
            [0x11; 16],
            [0x22; 16],
            true,
            synthetic_key::POLICY_ID,
            synthetic_key::COMPRESSION_POLICY_ID,
        );
        store
            .write_blocks(0, BOOT_IMAGE_BLOCKS as u32, &boot_image)
            .expect("boot write");
        let policies = [synthetic_key::encryption_policy()];
        let comps = [synthetic_key::compression_policy()];
        let mut writer = FixedHxfsWriter::<RecordingStore, 16, 32, 128>::mount_with_policies(
            store, &policies, &comps,
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
        if inject {
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
        writer.publish_checkpoint().expect("publish");
        let mut store = writer.into_store();
        store.flush().expect("flush");
        std::fs::read(&path).expect("read image back")
    }

    #[test]
    fn seeded_image_mounts_and_seed_file_round_trips() {
        let image = build_test_image(false);
        let reader = SliceBlockReader::new(&image);
        let policies = [synthetic_key::encryption_policy()];
        let comps = [synthetic_key::compression_policy()];
        let mut fs = Hxfs::mount_with_policies(reader, &policies, &comps).expect("mount");
        let file = fs.open_path("/seed.bin").expect("open seed.bin");
        let mut buf = [0u8; 4096];
        let n = fs.read_file(file, &mut buf).expect("read seed.bin");
        assert_eq!(n, 3584, "seed file length must match");
        let mut expected = [0u8; 4096];
        fill_compressible_chunk(&mut expected, 0);
        assert_eq!(&buf[..3584], &expected[..3584], "seed bytes must round-trip");
    }

    #[test]
    fn injected_image_still_mounts_and_bad_tag_surfaces_precisely() {
        let image = build_test_image(true);
        let reader = SliceBlockReader::new(&image);
        let policies = [synthetic_key::encryption_policy()];
        let comps = [synthetic_key::compression_policy()];
        // Metadata is intact: the volume must still mount.
        let mut fs = Hxfs::mount_with_policies(reader, &policies, &comps).expect("mount");
        let file = fs.open_path("/seed.bin").expect("open seed.bin");
        let mut buf = [0u8; 4096];
        assert_eq!(
            fs.read_file(file, &mut buf).err(),
            Some(HxfsError::Compression),
            "the injected bad GCM tag must surface as the precise error"
        );
    }
}

fn main() {
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
    // file entry.
    let boot_image = huesos_hxfs::synthetic_image::build_boot_image(
        args.instance_uuid,
        args.volume_uuid,
        true,
        synthetic_key::POLICY_ID,
        synthetic_key::COMPRESSION_POLICY_ID,
    );
    if let Err(e) = store.write_blocks(0, BOOT_IMAGE_BLOCKS as u32, &boot_image) {
        fail(&format!("boot image write failed: {e:?}"));
    }

    let policies = [synthetic_key::encryption_policy()];
    let comps = [synthetic_key::compression_policy()];
    let mut writer = match FixedHxfsWriter::<RecordingStore, 16, 32, 128>::mount_with_policies(
        store, &policies, &comps,
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
    }

    if let Err(e) = writer.publish_checkpoint() {
        fail(&format!("publish_checkpoint failed: {e:?}"));
    }
    let mut store = writer.into_store();
    if let Err(e) = store.flush() {
        fail(&format!("flush failed: {e:?}"));
    }
    println!(
        "[hxfs-seed] wrote {} ({} blocks, seed file '{}' = {} bytes across {} extent(s), encrypted+compressed{})",
        args.output.display(),
        args.blocks,
        args.seed_file,
        args.seed_size,
        ranges.len(),
        if args.inject_bad_gcm_tag { " with bad-GCM injection" } else { "" },
    );
}
