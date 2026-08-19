# HxFS v6: policy roots and 64-bit generations

Status: **implemented; host migration and QEMU encrypted-volume gates active**.

## Why v6 exists

HxFS v5 stored only the low 32 bits of an extent generation. AES-GCM derives a
nonce from physical location and generation, so truncating a long-lived
checkpoint sequence made eventual `(key, nonce)` reuse possible. v5 also kept
concrete encryption/compression policy descriptors outside the image, allowing
a test feature configuration to differ from the production mount path.

v6 closes both boundaries:

- extent records are 48 bytes and persist the complete `u64` generation;
- the checkpoint's existing `encryption_policy_tree_lba` and
  `compression_policy_tree_lba` fields point at authoritative versioned policy
  blocks;
- production and test binaries use `mount_from_disk`; build features enable
  probes/engines but cannot select a volume policy;
- the production HxFS service always contains AES-GCM, LZ4 and Hxblob support.

## Extent record

```text
0x00  u64 logical_block
0x08  u64 physical_block
0x10  u32 block_count
0x14  u32 flags
0x18  u32 compression_algorithm
0x1c  u32 compressed_bytes
0x20  u32 payload_crc32c
0x24  u32 reserved (must be zero)
0x28  u64 generation
size: 48 bytes
```

A tree leaf holds 83 records. `83 * 48 = 3984`, leaving room inside the
4028-byte encrypted metadata envelope.

## GCM nonce domain

The v6 nonce is:

```text
low 32 bits of physical LBA || complete 64-bit generation
```

The full LBA, generation and volume UUID are authenticated as AAD. The per-volume
key is derived with HKDF using the UUID, so different volumes use different
keys. Spending all generation bits deliberately caps an encrypted HxFS volume
at `2^32` 4-KiB blocks (16 TiB); encryption/decryption above that LBA returns
`NonceDomainExceeded` rather than truncating.

## Policy tree wire format

Both policy roots use an ordinary checksummed metadata block and a 16-byte
header:

```text
u32 magic
u16 schema_version = 1
u16 record_bytes
u32 record_count (max 32)
u32 reserved = 0
```

Encryption records contain policy id, algorithm, data-unit size and key-provider
tag. Compression records contain policy id, algorithm and minimum file size.
Unknown versions, duplicate/zero ids, unsupported algorithms and non-zero
reserved fields fail closed.

The two roots are part of checkpoint transaction geometry and the replay
journal. A crash can therefore expose either the complete old policy set or the
complete new one, never a volume descriptor referring to a partially-written
policy table.

## v5 compatibility and explicit migration

A v5 volume is accepted for compatibility but `FixedHxfsWriter` marks it
read-only. Mutation APIs return `LegacyReadOnly`; there is no implicit
"upgrade on first write".

Dry-run and migrate explicitly:

```bash
cargo run --manifest-path tools/hxfs-migrate/Cargo.toml \
  --target x86_64-unknown-linux-gnu -Z build-std= -- disk.img

cargo run --manifest-path tools/hxfs-migrate/Cargo.toml \
  --target x86_64-unknown-linux-gnu -Z build-std= -- disk.img --commit
```

For a legacy encrypted/compressed volume, supply the descriptors and key used
by that volume:

```bash
... --volume-key-hex <64-hex-digits> \
    --encryption-policy 7 \
    --compression-policy 1:lz4:4096 --commit
```

The migration is a normal journaled checkpoint publication. The tool defaults
to dry-run, uses a dedicated 32-MiB host thread stack for bounded migration
state, and clears the supplied key buffer before returning.

CI runs `make migration-check`, which creates a v5 fixture, proves ordinary
mutation is denied, performs the migration and requires non-zero policy roots
in the resulting v6 checkpoint.

## Verification

- default HxFS host suite;
- combined `crypto-aes-gcm,compression-engines,hxblob` suite;
- explicit v5 -> v6 migration smoke;
- encrypted QEMU NVMe mount through KeyBroker and on-disk policy roots;
- GCM corruption injection and power-fail/replay gates.
