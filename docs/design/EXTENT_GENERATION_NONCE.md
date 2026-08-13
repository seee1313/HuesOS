# Extent generations: making a reclaimed block safe to re-encrypt

Status: complete (Scope D). Generation-bound nonces plus block reclaim.

## The problem this solves

Hxfs never reuses a physical block. `FixedHxfsWriter` allocates by
bumping `next_lba`, and deleting a file drops its extent records
without returning the blocks to any allocator. A create/delete cycle
therefore grows the volume forever:

```
create+delete x6, charged bytes: 24576 28672 32768 36864 40960 45056
after the churn:                 charged = 40960, live extents = 0
```

That is the defect Scope D exists to fix. The obvious fix — reuse
freed blocks — is **unsafe on an encrypted volume as the format
stands**, and that is why this document exists before any reclaim
code.

## Why naive reuse breaks the encryption

Data extents are sealed with AES-256-GCM under one per-volume extent
subkey. The nonce is derived from position alone:

```rust
fn build_nonce(lba: u64, volume_uuid: &[u8; 16]) -> [u8; 12] {
    nonce[..4]  = lba.to_le_bytes()[..4];   // low 32 bits of the LBA
    nonce[4..]  = volume_uuid[..8];
}
```

With `next_lba` monotonically increasing, every physical block is
encrypted at most once per volume lifetime, so each (key, nonce) pair
is used exactly once. That invariant is what currently makes the
scheme sound — and it is held up only by the allocator never going
backwards.

Reusing a freed LBA would encrypt different plaintext under the *same*
(key, nonce). In GCM that is catastrophic, not merely weak:

- XOR of two ciphertexts under one keystream reveals the XOR of the
  plaintexts;
- worse, a nonce repeat leaks the GHASH authentication key `H`, which
  lets an attacker forge valid tags for arbitrary blocks. Integrity is
  lost, not just confidentiality.

So the reclaim work cannot start with the allocator. It has to start
by making the nonce unique across reuses.

Metadata is **not** exempt. There are two metadata paths, and only one
of them is XTS: `crypto.rs` is tweak-based and safe to rewrite in
place, but `encrypted_metadata.rs` is GCM with a nonce derived from the
LBA, exactly like the extent path. Both GCM callers therefore take a
generation. Metadata blocks source it from `BlockHeader.generation`,
which the header CRC already covers.

## The fix: an explicit generation counter

Each extent record carries a `generation`. The nonce and the AAD are
derived from `(physical_block, generation, volume_uuid)` instead of
`(physical_block, volume_uuid)`. Every time a block is handed out by
the allocator its generation is strictly greater than any previous
tenancy of that block, so the (key, nonce) pair is never repeated even
though the LBA is.

This makes "a block may be reused" a *structural* property of the
format rather than a side effect of an allocator that only counts
upwards.

### Nonce layout (12 bytes)

Current:

```
[0..4)   LBA, low 32 bits      <-- silently truncated
[4..12)  volume UUID, 8 bytes
```

New:

```
[0..6)   physical block, low 48 bits
[6..10)  generation, low 32 bits
[10..12) volume UUID, 2 bytes
```

Two things worth calling out:

- The old layout truncates the LBA to 32 bits, so any volume beyond
  2^32 blocks (16 TiB) would silently alias nonces between block N and
  block N + 2^32. Widening the block field to 48 bits (256 TiB) fixes
  a latent bug that has nothing to do with reclaim.
- The UUID contribution shrinks from 8 bytes to 2. This is safe: the
  UUID is *not* a secret and not an anti-replay measure — cross-volume
  separation comes from the key, which is derived per volume via HKDF.
  The full 16-byte UUID stays in the AAD, so a ciphertext still cannot
  be transplanted between volumes.

### AAD layout

The AAD binds the full tuple, and gains the generation:

```
[0..8)    physical block (full 64 bits)
[8..24)   volume UUID (full 16 bytes)
[24..32)  generation (full 64 bits)
```

`decrypt_block` rebuilds the nonce from `(lba, generation, uuid)` and
compares it against the nonce stored on disk, exactly as today, so a
record whose generation does not match its block fails the tag check
instead of returning wrong plaintext.

## On-disk format

The v2 extent record is 40 bytes but only 36 are used:

```
[0..8)    logical_block
[8..16)   physical_block
[16..20)  block_count
[20..24)  flags
[24..28)  compression algorithm
[28..32)  compressed_bytes
[32..36)  payload_crc32c
[36..40)  ZERO - never written, never read
```

The generation goes in the reserved `[36..40)` tail. Verified by
inspection that both writers (`build_extent_table_block` and
`serialize_extent_record`) start from a zeroed payload and write only
through offset 36, and that `parse_extent_record_v2` stops at 36. So:

- **no change to the record size**, no change to records-per-block,
  no change to any tree geometry;
- **existing volumes stay readable**: an old record reads back
  `generation == 0`, which is exactly the generation the current
  encryption scheme implicitly uses;
- a v1 (32-byte) record likewise yields generation 0.

That last point is what makes this backward compatible rather than a
migration: generation 0 *is* the status quo, so every block written
before this change decrypts unchanged.

Forward compatibility is not claimed: a volume that has reused a block
(generation > 0) will not decrypt correctly on an older build. That is
the intended direction — an old reader must not silently accept a
reused block.

## How reclaim uses this

The allocator recycles blocks in two places, and both are bounded by
the same rule: a block freed by the transaction now being built is
*quarantined*, not reused, until the checkpoint that dropped its last
reference is durable.

- `clear_extents` quarantines the data blocks of a deleted or
  rewritten object.
- `publish_checkpoint` quarantines the metadata region it just
  superseded. The checkpoint is copy-on-write and rewrites that whole
  region every time, so on a churning volume it, not the file data,
  dominates growth. It stays claimed for one further checkpoint
  because `backup_checkpoint_lba` still points at it; quarantining it
  means it is released exactly when it stops being the rollback
  target, so the format's one-checkpoint retention is unchanged.

`publish_checkpoint` then places the *new* metadata region in a
reclaimed run when one is large enough, and only extends the volume
when none is. Without that the high-water mark still climbed linearly
even though data blocks were being recycled.

The generation of a newly issued block is `sequence_number + 1`: the
checkpoint it is being written under. The quarantine is what makes
that sound. A block cannot be freed and re-issued inside one
checkpoint, so two tenancies of a block always fall under different
sequence numbers and (key, nonce) never repeats.

Two invariants the reclaim path must respect, both learned from tests
that caught the violation:

- The retired metadata region can contain live data extents (a volume
  seeded by `HxfsWriter` puts file data below the checkpoint). Live
  extents are punched out of the range before it is quarantined;
  freeing it wholesale destroyed an untouched file.
- A non-zero generation forces the 40-byte v2 extent record, since
  bytes `[36..40)` do not exist in the v1 layout. Selecting the record
  on the compression policy alone silently dropped the generation of
  an encrypted volume that compresses nothing, and the block then
  failed its tag check on read.

Free space is **not** persisted as a free list. It is rebuilt at mount
from the live extent table: everything below the metadata region that
no live extent claims is free. A torn free list can therefore never
hand out a block that is still in use, and blocks leaked by a crash
between a free and its checkpoint are recovered automatically.

## Scope boundary

Snapshot-deletion reclaim (gate item 6) is still open: snapshots pin
extents through a separate refcount path that this work does not
touch. Freeing a snapshotted block would need the refcount tree
consulted before quarantine, and is deliberately left out.
