# HxFS v6 extent generations and AES-GCM nonce safety

Status: **implemented and gated**.

## Invariant

A physical block may be reclaimed and encrypted again only if the new tenancy
uses a `(key, nonce)` pair that has never been used before. Reusing a GCM nonce
under one key leaks plaintext relationships and can permit authentication-tag
forgery.

## Why v5 was insufficient

v5 added a generation to the reserved tail of a 40-byte extent record, but the
wire field and nonce retained only 32 generation bits. The full checkpoint
sequence existed in memory/AAD, but AAD does not make GCM nonce reuse safe.
After generation wrap, a reclaimed LBA could repeat a nonce.

## v6 record

v6 uses a 48-byte extent record:

```text
logical_block       u64
physical_block      u64
block_count         u32
flags               u32
compression         u32
compressed_bytes    u32
payload_crc32c      u32
reserved            u32 = 0
generation          u64
```

The generation assigned to a new tenancy is the checkpoint sequence being
built. Freed blocks are quarantined until the checkpoint that removed their
last reference is durable, so one transaction cannot free and reissue a block
under the same generation.

## Nonce layout

```text
[0..4)   physical LBA, u32 little-endian
[4..12)  complete generation, u64 little-endian
```

The complete `(u64 LBA, u64 generation, 16-byte volume UUID)` is authenticated
as AAD. Cross-volume separation comes from the per-volume HKDF subkey derived
with the UUID as salt.

The full generation is more important than supporting encrypted volumes beyond
`2^32` blocks. Therefore an encrypted LBA above `u32::MAX` is rejected with
`NonceDomainExceeded`; it is never truncated. At 4 KiB per block the explicit
encrypted-volume ceiling is 16 TiB. Plain volumes are not subject to this AEAD
nonce-domain limit.

## Metadata

Encrypted metadata uses the same generation discipline. Copy-on-write metadata
normally moves to a fresh LBA; reclaimed metadata additionally receives the new
checkpoint generation. Extent-tree roots/leaves and allocation/refcount/backref
multi-block roots are included in the encrypted metadata block set.

## v5 migration

v5 is read-compatible but mutable mounts return `LegacyReadOnly`. Only
`tools/hxfs-migrate` may publish v6:

1. mount v5 with explicitly supplied legacy policy descriptors/key;
2. build authoritative encryption/compression policy roots;
3. rewrite extent records with 64-bit generations;
4. publish through the normal RECOVERING → CLEAN journal protocol.

There is no implicit upgrade-on-write path.

## Regression coverage

- nonce uniqueness across multiple LBAs and generations including `u64::MAX`;
- same LBA under adjacent generations produces different nonces;
- prior-generation ciphertext fails authentication;
- LBA `u32::MAX` is accepted and `u32::MAX + 1` fails closed;
- reclaimed encrypted blocks do not reveal the previous tenancy;
- v5 mutation is denied until explicit migration;
- encrypted QEMU NVMe and GCM corruption-injection gates.
