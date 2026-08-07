# Stage B Implementation Plan

User-approved decisions for PR `huesos-dev/hxfs-stage-b-io-pipeline`.

## Scope
Four tracks, five commits, one PR.

## Architectural decisions (locked)

### B.1 — Encrypted metadata I/O
- **What to encrypt**: full 4 KiB metadata block payload, **after** the
  `BlockHeader` (40 bytes). Header stays in plaintext so the layer
  can route by `block_type` without holding a key. **Block type and
  owner_id are still visible to a reader without a key**; the
  payload (dirent bodies, extent table rows, allocator tree nodes,
  quota records) is encrypted.
- **Crypto primitive**: AES-256-GCM via the `aes-gcm` crate
  (RustCrypto), behind a new `crypto-aes-gcm` Cargo feature.
- **Key derivation**:
  `metadata_key = HKDF-SHA256(volume_key, salt=volume_id, info=b"hxfs-metadata-v1")`.
  Same metadata key for all metadata blocks on a volume; the per-block
  nonce provides domain separation.
- **Per-block nonce** (12 bytes, GCM standard):
  - layout: `B0..=B3` = `block_lba` as u32 little-endian,
    `B4..=B11` = `volume_uuid[0..8]`. Volume UUID gives per-volume
    uniqueness; LBA gives per-block uniqueness.
  - **Rationale**: `(volume_id, block_lba)` is already known to the
    storage layer; reusing it avoids storing a per-block nonce
    on disk. B.2 will use a *different* nonce scheme
    (`parent_dir_id || file_id`) because dirents need to be
    decryptable from their parent context.
- **Wire format (v6 metadata block)**:
  - `BlockHeader` (40 B) — same shape as v5.
  - `EncryptedMetadata` (4056 B) — `nonce(12) || ciphertext(N) ||
    tag(16)` where N = 4056 - 12 - 16 = **4028 bytes** of plaintext.
  - Existing v5 plaintext payload stays in the same BlockHeader
    layout when `type_version == 5`.
- **Format version gate**: `FORMAT_VERSION` is **not** bumped. We
  introduce a new block type discriminator: `type_version` in
  the BlockHeader carries the metadata payload format (5 = plaintext
  v5, 6 = encrypted v6). The superblock's `format_version` remains
  at 5; readers see a v5 superblock but a v6 metadata block means
  "this volume is encrypted, you need a key."
  - **Rationale**: avoids changing FORMAT_VERSION and breaks no
    v5 reader that ignores unknown type_versions (it does not,
    currently — see risk).
  - **Risk acknowledged**: existing v5 readers will choke on a
    v6 type_version. We add a new incompatible feature bit
    `FEATURE_INCOMPAT_V6_ENCRYPTED_METADATA` so v5 readers reject
    the volume with `UnsupportedFormat`.

### B.2 — Encrypted filenames
- **Per-dirent wire format** (in the dirent record, instead of plaintext
  name):
  - The on-disk record layout becomes:
    `object_id(8) || name_len(2) || encrypted_flag(1) || body(N)`
    where `body` is either `name(N)` (plaintext) or
    `nonce(12) || ciphertext(N-28) || tag(16)` (encrypted, 28 B
    overhead).
  - Plaintext dirent records keep their shape for `policy_id == 0`
    volumes (no encryption).
  - **Detection**: a new `is_encrypted` byte (0=plaintext,
    1=encrypted). The `parent_object_id` is already known in the
    caller (it is `dir.object_id` in `lookup_in_directory` /
    `for_each_directory_entry`), so it does not need to live in
    the record.
  - If the parent is plaintext but the dirent claims to be
    encrypted, the volume is corrupt.
- **Lookup semantics**: lookup uses the *plaintext* name. The fixed
  writer holds the metadata key in RAM and decrypts each name on
  lookup. For plain volumes, lookup is unchanged.
- **Name-display side index** (B.2 mentions a `(dir_id, file_id) →
  encrypted name` index so the terminal can list names without the
  dir key in userspace): **deferred to Stage D**. The user explicitly
  requested the on-disk encrypted bytes; the userspace display path
  will land when userspace holds a key handle.

### B.3 — Encrypted data extents
- **Wire format**: existing `CompressedExtent` payload, with
  `encryption_policy_id != 0` getting a `crypto: CompressionOutcome
  + EncryptionKey` envelope:
  - `EncryptedExtent { nonce(12), compressed_ciphertext(N), tag(16) }`
  - `N = extent_bytes - 28`
  - **Read order**: decrypt → decompress. A bad GCM tag returns
    `CryptoError::BadKey`; a bad compression checksum returns
    `CompressionError::BadChecksum`. Both mark the extent bad.
- **Key derivation for extents**:
  `extent_key = HKDF-SHA256(volume_key, salt=volume_id, info=b"hxfs-extent-v1")`.
  Different info string from metadata key to maintain cryptographic
  separation.

### B.4 — O_DIRECT deny  (landed as PR `hxfs-stage-b4-odirect-deny`)
- **Where**: userspace syscall handler that opens Hxfs files
  (the `huesos-hxfs-service` `client_open_native` and
  `client_create_file_native` paths). Returns
  `HxfsStatus::Unsupported` when the O_DIRECT bit is set
  on `request.flags`.
- **No kernel changes**. Document the deny in
  `docs/PRODUCTION_ROADMAP.md` and in the syscall handler.
  The kernel-side VFS is unchanged: the deny happens in
  userspace before the request ever reaches the kernel.

## Commit breakdown

5 commits, ordered so each commit is independently buildable.

1. **commit 1 — `feat(hxfs): introduce v6 encrypted metadata wire
   format with aes-gcm`**:
   - Add `crypto-aes-gcm` feature, depend on `aes-gcm` crate.
   - Implement `crypto_aes_gcm.rs` with
     `encrypt_block(metadata_key, lba, volume_uuid, plaintext) -> [u8; BLOCK_SIZE]`
     and matching `decrypt_block` (returns `BadKey` on tag failure).
   - Implement `hkdf.rs` with `derive_metadata_key(volume_key, volume_uuid) -> [u8; 32]`.
   - Add `FEATURE_INCOMPAT_V6_ENCRYPTED_METADATA` to `format.rs`.
   - Add `is_v6_encrypted_metadata(header)` helper.
   - Add host tests for HKDF determinism, encrypt/decrypt round-trip,
     and `BadKey` on tampered ciphertext.
   - **This commit does not yet change the I/O path**: the API
     is in place but no production code calls it. Compile-only.

2. **commit 2 — `feat(hxfs): wire metadata + dirent encryption on
   read/write paths`** (B.1 I/O wiring + B.2 dirent names):
   - `read_metadata_block` in `lib.rs`: when
     `FEATURE_INCOMPAT_V6_ENCRYPTED_METADATA` is set and the volume
     has a non-zero `encryption_policy_id`, decrypt the payload
     after `validate_metadata_block`.
   - `FixedHxfsWriter::publish_*`: for the encrypted case, encrypt
     the payload before writing the BlockHeader.
   - **Scope of "metadata blocks encrypted"**: the volume
     encryption policy applies to **dirent blocks, extent table
     blocks, allocation tree blocks, refcount tree blocks, backref
     tree blocks, quota tree blocks**. Block pointer / extent
     physical LBA values stored in extents remain plaintext because
     the allocator needs to find free extents without a key
     (per ROADMAP B.1 third bullet).
   - **Superblock, checkpoint, volume table, object table**: NOT
     encrypted in B.1 (those carry global state needed to find
     the encryption key). Encrypting them is Stage D.
   - **Dirent names (B.2)**: `parse_dir_record` branches on
     `is_encrypted` byte. `FixedHxfsWriter::insert_dir_entry`
     encrypts the name when the parent is encrypted.
   - Host tests for round-trip: a directory with a child file
     written on an encrypted volume survives a remount and the
     child is findable by plaintext name.

3. **commit 3 — `feat(hxfs): encrypt data extents after compression,
   decrypt before decompression`** (B.3):
   - In `lib.rs::copy_extent` (read path) and the writer's
     extent-write path, when the extent carries a non-zero
     `encryption_policy_id`, decrypt-then-decompress (read) or
     compress-then-encrypt (write).
   - The `extent_key` is derived per-volume (HKDF with
     `info=b"hxfs-extent-v1"`), the same as the metadata key but
     with a different info string for cryptographic separation.
   - `PageCache` (from Stage A) is keyed on the **decrypted,
     decompressed** block, so cache hits return plaintext and the
     encryption layer is below the cache.
   - Host test: a file with both compression and encryption
     survives a remount; a single-byte ciphertext corruption is
     rejected with `BadKey`; a compressed-but-not-encrypted file
     still works.

4. **commit 4 — `feat(userspace): deny O_DIRECT for Hxfs open()`**
   (B.4):
   - In the userspace syscall dispatcher / hxfs-service, branch on
     the O_DIRECT bit and return `Unsupported`.
   - Document the deny in `docs/PRODUCTION_ROADMAP.md` under
     Stage B.4 with a clear "supported in a later stage" note.
   - Host test: opening with O_DIRECT returns Unsupported; opening
     without O_DIRECT works.

5. **commit 5 — `test(hxfs): full Stage B end-to-end
   encrypted+compressed volume host test`**:
   - Single end-to-end test:
     `write_then_read_encrypted_compressed_volume` that writes a
     4 MiB file with both encryption and compression enabled,
     remounts, and reads it back byte-for-byte.
   - Soak marker: `qemu-nvme-soak` gets a new injection
     flag `--inject-bad-gcm-tag` that flips one bit of an encrypted
     extent; the on-target trace must show `bad-gcm-tag-marked` and
     continue to mount.

## Safety budget

Bump expectations, justified:
- `unsafe_functions` +1: `derive_metadata_key` and
  `derive_extent_key` use `Zeroizing` for output; both end up
  behind `#[cfg(feature = "crypto-aes-gcm")]` so they don't count
  in the default build. The HKDF function itself takes `&[u8]` and
  returns a stack-allocated `[u8; 32]`, no unsafe.
- `unsafe_impls` +0: `Zeroizing` doesn't add an impl.
- `panic_macros` +0: every test uses `assert!(false, "...")`
  pattern from Stage A.
- `expect_calls` +0: HKDF on fixed-size input can't fail.
- `unwrap_calls` +0: `from_slice` is the only call site and
  matches the existing pattern.

## Known risks and follow-ups

- **Block pointer in extents is plaintext** (per ROADMAP B.1). An
  attacker with disk access learns which physical blocks belong
  to which file. Stage D / a future hardening track can address
  this with a block-mapping cipher.
- **No userspace key provider** yet. hxfs-service currently boots
  with `[]` encryption policies, so the encrypted metadata path
  is unreachable from production. Stage D wires the real key
  provider. The host tests in B.1-B.3 cover the path with a
  synthetic key.
- **v5 reader rejection of v6 metadata**: when an encrypted
  volume is mounted by a v5 reader, the reader will see a v5
  superblock (we don't bump FORMAT_VERSION) but a v6 metadata
  block. The new `FEATURE_INCOMPAT_V6_ENCRYPTED_METADATA` bit
  rejects this at mount time. **We need to add the feature bit
  read in `read_superblock`** to honor it.

## Out of scope (Stage C and beyond)

- Media error handling (C.1)
- Online fsck (C.2)
- Scrub (C.3)
- Quota enforcement at every write (C.4) — A.5 already handles
  the host-test path; C.4 wires the kernel path.
- Error injection (C.5) — except the single `--inject-bad-gcm-tag`
  flag listed in commit 5.
- TPM key provider (D.2-D.3)
- Signed manifests (D.4-D.5, D.7)
