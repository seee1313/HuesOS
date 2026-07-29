# Hxfs — HuesOS File System design (Stage G)

Status: **Stage G design baseline**. No Hxfs code is introduced by this file.
Implementation must not start until this design is reviewed/accepted.

Hxfs is the primary mutable user filesystem for HuesOS. It is designed for the
HuesOS storage model:

- userspace drivers and filesystems;
- NVMe/SSD systems as the optimized target;
- handle-first APIs;
- BOOTFS retained as immutable boot/recovery fallback;
- BlobFS role replaced in the long term by an Hxfs subsystem/view named
  **Hxblob**.

Hxfs is **not POSIX internally** and is **not optimized for HDD/rotational
storage**. POSIX compatibility, if needed, is an external translation layer.

---

## 0. Architectural warnings / corrections

These are decisions that need strict wording so the on-disk format does not
paint HuesOS into a corner.

### 0.1 No ASCII binary magic, but a stable format identifier is mandatory

The design does not use an ASCII magic string like `HXFSv1` as the authority.
However, an on-disk filesystem still needs an unambiguous format identifier.
Hxfs therefore uses a **128-bit Format GUID** in the superblock/root-store area.
This is not a POSIX-style magic number; it is the stable type identity for the
format.

Rejecting any identifier entirely would be a bad architectural decision because
mount code could not safely distinguish Hxfs from random/corrupt data.

### 0.2 Rust dynamic typing must not leak directly into disk

The implementation may use Rust enums/traits internally, but the disk format
must not depend on Rust vtables, compiler `TypeId`, symbol names, or layout of
Rust types. Hxfs uses stable on-disk **type GUIDs / type ids + type versions**.
Rust maps those stable ids into implementation types.

Relying on Rust dynamic typing as the actual disk schema would be unsafe across
compiler versions and impossible to mount from tools written in another language.

### 0.3 Handles are never persisted

Hxfs never stores live HuesOS handles on disk. Handles are runtime capabilities
created in memory and destroyed when processes/services close them. Device and
service references belong to DevFS, not Hxfs.

### 0.4 Hardware encryption is a policy backend, not the filesystem identity

Hxfs has an encryption policy layer. It can use hardware/NVMe inline crypto when
available, but the format must remain mountable with software AES-XTS fallback
when a valid key source exists. If no TPM/bootloader/passphrase key provider is
available, encrypted volumes are unavailable; Hxfs must not silently mount them
as plaintext.

### 0.5 Multiple path names vs hardlinks

A single file object with multiple directory names is a hardlink. The selected
design says “no hardlinks”, so Hxfs v1 does **not** allow multiple normal
directory entries to point at the same file object. Path-level symlinks are
allowed and are the compatibility escape hatch.

---

## 1. Hxfs role

Hxfs performs three major jobs:

1. **Virtual volume management** — replaces the role FVM would otherwise play.
2. **Safe storage for mutable data** — user files, directories, application
   state, and future user volumes.
3. **Fast system package serving** — replaces standalone BlobFS in production via
   the Hxblob subsystem.

Hxfs is the only planned primary user filesystem for HuesOS. The architecture
should not prevent alternative filesystems, but HuesOS itself is optimized around
Hxfs + BOOTFS + DevFS + Hxblob.

---

## 2. API model: path resolver, then handles

Hxfs uses a mixed external model:

```text
path -> resolver only -> typed handle -> all further operations
```

Examples:

```text
open_volume(uuid)                         -> VolumeHandle
Volume.OpenPath("/home/user/readme.txt")  -> FileHandle
Directory.Open("packages")                -> DirectoryHandle
File.ReadAt(...)                          -> bytes / VMO
```

Rules:

- paths are only lookup syntax;
- operations after lookup are handle-based;
- POSIX file descriptors are not native Hxfs concepts;
- POSIX calls may later be translated by a compatibility layer;
- kernel does not implement path resolution.

Native handles:

```text
VolumeHandle
DirectoryHandle
FileHandle
SnapshotHandle
BlobViewHandle
```

---

## 3. Media target: NVMe/SSD only

Hxfs assumes NVMe/SSD behavior:

- cheap random reads;
- high queue depth;
- parallel I/O;
- erase/write amplification concerns handled mainly by the SSD controller;
- no seek minimization;
- no HDD elevator/layout policy;
- async parallel read-ahead;
- later async/batched TRIM/discard;
- future NVMe write streams / hints.

This is intentional. Hxfs must not grow HDD-specific policy unless HuesOS later
adds a separate storage profile.

---

## 4. Disk identity and versioning

Hxfs uses **linear format versions**.

Superblock/root-store identity fields:

```text
format_guid:     u128   // identifies Hxfs, replaces ASCII magic
format_version:  u32    // linear version, v1 for Stage G prototype
type_system_ver: u32    // on-disk type registry version
instance_uuid:   u128   // this filesystem instance
sequence_number: u64    // monotonic publish/checkpoint generation
```

Unknown future format version or unknown incompatible type version:

```text
reject mount
```

Rationale: safety over best-effort compatibility.

Hxfs cooperates with GPT rules. The system volume is located by boot metadata,
with UUID duplicated in the Hxfs volume table.

Timestamps use Unix nanoseconds where persisted.

---

## 5. Fundamental limits and units

Selected baseline:

```text
block size:          4 KiB
metadata block size: 4 KiB
data block size:     4 KiB
addressing:          u64 block numbers
max file size goal:  8 EiB
max FS size goal:    16 EiB
allocation groups:   16 GiB zones
```

4 KiB is chosen because it matches page-sized VMAR/VMO handling, common NVMe
logical/physical granularity, DMA buffers, and metadata node sizing.

Sparse files, preallocation, and clone/reflink-style operations are architectural
requirements, but reflink implementation is not part of the Stage G parser.

ZNS support is future work and should be recorded as a storage-profile extension,
not baked into the v1 MVP.

---

## 6. Physical layout overview

Hxfs is composed of:

```text
Primary root-store ring        // beginning of device/volume
Journal/checkpoint log         // dynamic sequential chain in allocated space
Virtual volume payload zones   // per-volume metadata/data allocation groups
Backup root-store ring         // end of device/volume
```

The root-store ring contains enough unencrypted metadata to locate and validate
the current checkpoint and volume table descriptor. Most actual volume metadata
and all encrypted volume contents live under per-volume policies.

Primary and backup rings are mirrors. They are not independent histories; they
are redundant entry points to the same published filesystem generations.

---

## 7. Root store, superblock rings, and checkpoint choice

### 7.1 Rings

Hxfs maintains:

```text
primary ring at beginning of disk
backup ring at end of disk
```

Each ring contains root-store records with:

```text
format_guid
format_version
instance_uuid
sequence_number
checkpoint_root_lba
journal_start_lba
journal_end_lba
volume_table_root
root_store_crc32c
```

### 7.2 Dynamic checkpoint/journal chain

The selected model is a dynamic sequential journal/checkpoint chain:

- transactions are appended to free space as a log chain;
- checkpoints reference roots produced by COW transactions;
- when the chain reaches a size threshold in MiB, Hxfs performs a global commit
  and publishes an updated root-store record into both rings;
- clean unmount writes a final checkpoint/root-store state with an empty journal
  range.

This is closer to the safety pattern of ZFS uberblocks + transaction groups and
APFS checkpointing than to an in-place journal. Hxfs must never use the journal
to make unsafe in-place metadata updates.

### 7.3 Mount selection

Mount validation scans both rings:

1. validate format GUID/version;
2. validate root-store checksum;
3. validate checkpoint root checksum;
4. group candidates by `sequence_number`;
5. choose the highest valid sequence.

Tie handling:

- same sequence in **primary + backup rings** is clean and expected; choose
  primary by convention;
- same sequence in **two different slots of one ring** indicates duplicated or
  misdirected writes and is treated as critical media/controller inconsistency.
  The safe action is fail read-write mount and require validation/repair mode.

`Needs_fsck` is not persisted as a normal state bit. It is the result of mount
validation detecting repeated checksum/tree inconsistencies.

---

## 8. Filesystem states

Hxfs observable mount states:

```text
Clean
Recovering
NeedsFsck
```

### Clean

Final checkpoint/root-store was published and `journal_start_lba` is empty or at
journal end. Mount can proceed without replay.

### Recovering

Last root-store/checkpoint is valid, but journal range is non-empty. Mount runs
journal replay to reconstruct the intended new state. Replay is bounded and must
produce either:

```text
old checkpoint valid
or new checkpoint valid
never a mixed state
```

### NeedsFsck

Validation detects corrupt rings, corrupt metadata blocks, impossible duplicate
sequence conflicts, tree shape violations, or checksum failures. Normal mount
fails. A future offline repair tool may inspect; Hxfs runtime does not silently
repair arbitrary corruption.

---

## 9. COW transaction model

Policy:

```text
data:     COW
metadata: COW
```

Transaction flow:

1. reserve allocation from per-zone allocator;
2. write new data extents;
3. write new metadata blocks/trees bottom-up;
4. append transaction/checkpoint record to journal chain;
5. publish new checkpoint/root-store when threshold/fsync/checkpoint requires.

Transactions are:

```text
global
batchable
ordered by transaction id / generation
```

Required atomic operations:

- atomic rename;
- atomic directory update;
- fsync/checkpoint explicit publication;
- buffered writeback before checkpoint.

Every metadata block includes the transaction generation that produced it.

No classic block-address backpointer is required in every metadata block. Instead
metadata records carry owner identity (`VolumeUuid`, `ObjectId`, tree kind,
generation) sufficient for validation and fsck/scrub.

---

## 10. Object model

Core identity:

```text
ObjectId = u64
VolumeId = UUID/u128
```

Objects are dynamically typed by stable on-disk type ids and versions, not Rust
compiler internals. Rust implementation maps those ids to native structs.

Object types:

```text
File
Directory
Volume
Snapshot
Symlink
BlobView
```

Explicitly not Hxfs object types:

```text
live Handle
Device reference
Service reference
```

Those belong to runtime systems and DevFS.

Object attributes for v1 design:

```text
size
modified_time_unix_ns
encryption_policy_id
compression_policy_id
object_type_id
object_type_version
```

Not in v1 native metadata:

```text
owner uid/gid
Unix permission bits
created_time
changed_time
allocated_size public field
xattrs
```

Permissions are capability/handle based.

---

## 11. Paths, directories, hardlinks, and symlinks

Directories map:

```text
UTF-8 name -> ObjectId
```

Rules:

```text
max name length: 255 bytes
encoding:        UTF-8 only
case:            sensitive
normalization:   none in v1
listing order:   lexicographic
```

Directory structure combines:

- log-structured entry updates for COW write efficiency;
- sorted-array/index representation at checkpoints for fast lookup/listing.

No hardlinks in v1. Path-level symlinks are allowed. A symlink stores a path
string and resolves through the filesystem server path resolver.

Root path `/` is the root of a virtual volume, not a global OS namespace.

---

## 12. Virtual volumes

Virtual volumes are mountable object namespaces. They replace FVM-like logical
volume management inside Hxfs.

Volume identity:

```text
VolumeUuid = u128
```

Each volume has:

```text
uuid
root_object_id
quota policy
encryption policy
compression policy
metadata tree roots
allocation state
```

Not supported:

- nested volumes;
- moving objects between volumes;
- snapshot policy field in v1 volume descriptor.

Supported by design:

- per-volume snapshots later;
- per-volume encryption/compression;
- system volume found by boot metadata and duplicated in volume table;
- user home as a separate virtual volume with independent UUID and optional
  independent encryption key.

Hxblob is a separate virtual volume, not an overlay on encrypted user data.

---

## 13. Allocation model for huge NVMe/SSD storage

Hxfs uses per-zone allocation groups:

```text
zone size: 16 GiB
```

Allocator design:

```text
per-zone allocator
hybrid free-space tracking:
  - bitmap for dense small free regions
  - extent tree for large ranges
extent trees for files
async/batched TRIM later
NVMe stream/write-hint support later
```

No online defrag in v1. Delayed allocation is allowed and expected for buffered
writeback.

---

## 14. File extent model

File layout is hybrid:

- inline data for small files up to 1 KiB;
- extent tree for ordinary files;
- sparse holes supported;
- preallocation supported;
- extents strictly sorted by logical block offset.

Extent record fields:

```text
logical_block: u64
physical_block: u64
block_count: u32/varint in final schema
flags: u32
```

Not in v1 extent record:

```text
checksum
refcount
```

Reflink/extent sharing and refcount tree are roadmap items, not Stage G code.

---

## 15. Metadata trees

Hxfs uses separate per-volume trees. Initial design trees:

```text
Object tree          ObjectId -> object descriptor
Directory tree       DirectoryObjectId + name -> ObjectId
Extent tree          FileObjectId + logical range -> physical extents
Allocation tree      per-zone free-space state
Quota tree           physical bytes + object count accounting
Policy tree          encryption/compression policy descriptors
Backref tree         validation/scrub/fsck assistance
Hxblob index tree    hash -> ObjectId, for Hxblob volumes
```

Tree node size:

```text
4 KiB
```

Keys and values are not globally fixed-size; each tree type has a stable schema
version. Prefix compression for names is not in v1 and is a roadmap item.

Every metadata tree node is checksummed.

No parent pointer is required in every node; validation uses owner ids,
generation, and optional backref tree.

---

## 16. Snapshots roadmap

Snapshots are in design/roadmap only for Stage G, not code.

Policy:

```text
snapshot granularity: per virtual volume
identity:             snapshot id + name + timestamp + source generation
visibility:           management API only
writable snapshots:   no
```

Snapshot deletion is allowed by future design, but v1 avoids refcount-tree
implementation until snapshots/reflinks are implemented.

---

## 17. Encryption model

Encryption is per virtual volume.

Hierarchy:

```text
TPM / bootloader / key provider
  -> master key
    -> decrypts root-store volume table / wrapped keys
      -> volume key in RAM
        -> AES-XTS for 4 KiB blocks
```

Wrapped keys are stored in volume descriptors inside the Volume Table / Root
Store metadata.

Policy:

- AES-XTS only for mutable volume encryption;
- metadata encrypted except the lowest root-store layer needed to locate/decrypt;
- filenames encrypted;
- directory structure encrypted;
- if hardware crypto exists, policy layer may use it;
- software AES-XTS fallback is mandatory when a valid key source exists;
- if no key provider exists, encrypted volumes cannot mount;
- no “locked volume with visible metadata” mode in v1.

BlobFS/Hxblob system package volume lives next to encrypted user volumes, not on
top of them.

---

## 18. Integrity model

Metadata integrity:

```text
CRC32C in each metadata block header
checksum covers:
  - block type
  - type version
  - owner ObjectId / VolumeUuid
  - generation
  - logical block / tree position
  - payload
```

Normal mutable file data does not carry a v1 per-extent checksum in the extent
record. Future data-integrity policy may add a checksum side tree.

Hxblob immutable package data uses content hashes and Merkle tree verification.

Replay protection can be added by including generation/owner/type in checksums
and using checkpoint sequence monotonicity. Strong anti-replay with sealed state
is future security work.

Scrub service is required later. Online fsck is not in v1.

---

## 19. Hxblob subsystem

Hxblob replaces standalone BlobFS in production while preserving the useful
BlobFS semantics:

```text
blob id = hash(content)
hash -> ObjectId index
immutable / write-once
GC later
dedup by hash
per Hxblob virtual volume
```

Hxblob is a view/subsystem over Hxfs objects and extents. It is not an on-disk
format that makes all of Hxfs “pretend to be BlobFS”.

Hxblob is used for packages/system components. Hxfs ordinary volumes are used for
mutable user data.

---

## 20. Security and quotas

Permissions are capability-only. Hxfs does not understand Unix users/groups in
native metadata.

Quotas are mandatory per virtual volume:

```text
physical bytes: yes
object count:   yes
logical bytes:  no in v1
snapshot count: no in v1
```

Audit logging is required as a surrounding service, not inside the core on-disk
filesystem implementation.

---

## 21. Cache and I/O model

Hxfs is a userspace filesystem server with its own cache.

Policy:

- async API first;
- sync wrappers only on client side;
- async parallel read-ahead for NVMe/SSD;
- buffered writeback;
- explicit fsync/checkpoint;
- direct I/O supported;
- mmap supported later via VMOs/VMAR with FS server maintaining coherency.

Kernel does not grow a filesystem-specific page cache for Hxfs.

---

## 22. Crash consistency

Atomicity unit:

```text
COW transaction -> journal/checkpoint record -> published checkpoint
```

Mount behavior:

- validate root-store rings;
- select highest valid checkpoint;
- replay journal if needed;
- never expose mixed metadata state;
- either old checkpoint or new checkpoint is used;
- validation failure yields NeedsFsck.

Journal replay is the recovery mechanism; the journal replaces a narrower
intent-log concept. Superblock/root-store generation and checksum are mandatory.

Last-known-good checkpoint is retained. Checkpoint verification chain is not
required in v1.

---

## 23. Stage G read-only prototype scope

The implementation crate will be:

```text
crates/huesos-hxfs
```

It must provide:

```rust
Hxfs::mount(reader)
Hxfs::volume_info(...)
Hxfs::root_directory(...)
Hxfs::open_path("/hello.txt")
Hxfs::read_file(...)
```

Storage abstraction:

```rust
trait BlockReader {
    fn read_blocks(&mut self, lba: u64, blocks: u32, out: &mut [u8]) -> Result<(), Error>;
}
```

The prototype may use a byte-slice BlockReader for host tests and a BlockDevice
adapter later. It must not be hardcoded to byte slices.

Prototype image:

```text
one filesystem instance
one virtual volume
root directory
one file /hello.txt
one or more extents
metadata CRC32C validation
encryption policy parsed but encrypted volumes rejected
```

No write/COW implementation in Stage G code.

---

## 24. Integration plan

Hxfs runs as a separate isolated userspace process.

Potential launch owner:

- DriverManager can launch it initially;
- a future FileSystemManager may own BlobFS/Hxfs mounting once component model
  grows.

Hxfs opens storage through VolumeManager / DevFS, not directly through NVMe.

Hxfs service exports directory/file handles over async channels. BOOTFS remains
immutable fallback. BlobFS/Hxblob is for packages; Hxfs ordinary volumes are for
mutable user data.

---

## 25. Stage G implementation sequence after design approval

Recommended commits:

1. `docs(hxfs): add design baseline` — this document.
2. `feat(hxfs): define on-disk v1 structs` — constants, GUIDs, headers.
3. `feat(hxfs): add block reader and metadata CRC` — trait + CRC32C.
4. `feat(hxfs): parse superblock and checkpoint` — reject bad roots.
5. `feat(hxfs): parse volume and object trees` — minimal read-only trees.
6. `feat(hxfs): read root directory and file extents` — `/hello.txt` image.
7. `test(hxfs): build and mount tiny image` — host image builder/tests.

No write path, snapshots, encryption execution, Hxblob implementation, or mmap
coherency should be added in Stage G code without another design review.
