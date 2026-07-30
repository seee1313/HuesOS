# HuesOS Storage / NVMe / FS Roadmap

Дата обновления: **2026-07-30**
Текущая база HuesOS: `main` / `fix/critical-medium-audit` = `259c3ba2ae8b9ef6d780081b20f319bee48248cf`
Последний compare: <https://github.com/seee1313/HuesOS/compare/99c81e0...259c3ba>

Этот документ фиксирует storage/NVMe/FS направление HuesOS и оставшиеся стадии до production-ready состояния.

---

## 0. Короткий честный статус

Мы **не** закончили production filesystem целиком.

Сейчас уже есть:

```text
NVMe userspace driver foundation             DONE
MSI-X/MSI interrupt route                     DONE
Async BlockDevice over Channel + Port         DONE
VolumeManager system volume                   DONE
BlobFS read-only                              DONE
DevFS runtime namespace                       DONE
Hxfs design baseline                          DONE
Hxfs read-only parser/service                 DONE
Hxfs host-tested COW writer/snapshots          DONE
Hxfs advanced policy modules                  DONE
```

Но production Hxfs ещё требует:

```text
persistent mutable hxfs-service over BlockDevice
journal replay / recovery
production allocator and free-space persistence
snapshot block reclaim / refcount/backref integration
real AES-XTS encryption path and key provider
real compression path
production Hxblob service/package path
quota enforcement in write path
scrub/fsck tooling
mmap/direct I/O/cache integration
target QEMU/NVMe and bare-metal validation
```

Правильная формулировка текущего результата:

> HuesOS имеет production-oriented storage architecture foundation и Hxfs format/service/policy foundation, но ещё не имеет полной production mutable Hxfs.

---

### 0.1 Follow-up implementation status — J/K/L

After the original Stage I roadmap update, the first production-mutable slice was implemented:

```text
Stage J — canonical Hxfs service ABI in huesos-abi             DONE
Stage L — Hxfs v2 root-store feature flags + journal replay    DONE FOUNDATION
Stage K — no-heap fixed-capacity write dispatcher              DONE FOUNDATION
```

Important limitation: the on-target write dispatcher is now enabled through a
fixed-capacity no-heap state model, but general unaligned overlapping extent
surgery/reclaim is still deferred to allocator/refcount stages.

---

## 1. Целевая философия

Главный принцип HuesOS storage:

```text
Не «всё есть файл», а «всё есть Handle».
```

Путь — это только resolver. После открытия процесс работает с typed capability handle:

```text
VolumeHandle
DirectoryHandle
FileHandle
SnapshotHandle
BlobViewHandle
BlockDeviceHandle
DeviceHandle
DriverHandle
ResourceHandle
SignalHandle
PortHandle
ChannelHandle
```

Жёсткие правила:

- handles **никогда** не пишутся на SSD;
- Hxfs не хранит device/service references — это зона DevFS;
- kernel не делает path resolution;
- POSIX не является native FS ABI;
- POSIX, если нужен, будет отдельным compatibility translation layer;
- Hxfs оптимизируется строго под **NVMe/SSD**, не под HDD.

---

## 2. Целевая storage architecture

```text
Bootloader
  ↓
HBI .img
  ├── init
  ├── driver-manager
  ├── storage-critical driverhosts
  │   └── driver-host-nvme
  ├── services
  │   └── hxfs-service
  ├── manifests
  └── boot resources metadata

Kernel
  ├── Resource capabilities
  │   ├── Mmio
  │   ├── Irq
  │   ├── DmaPool
  │   └── future PowerControl / IommuResource
  ├── handle/object model
  ├── VMAR/VMO/process/thread
  ├── Port/Channel IPC
  └── minimal syscalls only

Userspace
  ├── DriverManager / future DeviceManager
  ├── NVMe DriverHost
  ├── BlockDevice service
  ├── VolumeManager
  ├── Hxfs service
  ├── Hxblob package/blob service
  ├── DevFS runtime namespace
  └── applications
```

Storage stack:

```text
NVMe Controller
  ↓ userspace driver-host-nvme
Async BlockDevice protocol
  ↓
VolumeManager
  ↓
FS layer
  ├── BOOTFS      immutable boot/recovery image
  ├── Hxfs        primary mutable user filesystem + virtual volumes
  ├── Hxblob      Hxfs-backed immutable package/blob subsystem
  └── DevFS       runtime handle/device namespace, not disk FS
```

BOOTFS остаётся неизменяемым boot/recovery fallback. Hxfs не должен становиться частью kernel.

---

## 3. Filesystem roles

### 3.1 BOOTFS

Status: **production role retained**.

Purpose:

- bootstrapping;
- init;
- DriverManager;
- storage-critical driverhosts;
- emergency/recovery tools;
- fallback if persistent storage fails.

Properties:

```text
immutable
small
simple
trusted by boot chain
not the user filesystem
```

---

### 3.2 Hxfs

Status: **foundation implemented, production mutable path pending**.

Roles:

1. Virtual volume management instead of FVM.
2. Safe mutable data storage.
3. Fast system package serving through Hxblob.
4. User home/personal files/application state.

Hxfs is:

```text
object/volume store with path views
handle-first externally
COW internally
NVMe/SSD-oriented
not POSIX internally
```

Native handles:

```text
VolumeHandle
DirectoryHandle
FileHandle
SnapshotHandle
BlobViewHandle
```

---

### 3.3 Hxblob

Status: **policy/index foundation implemented, production service pending**.

Purpose:

- immutable content-addressed blobs;
- package serving;
- system component loading;
- dedup by content hash;
- Merkle verification.

Core identity:

```text
blob_id = hash(content)
hash -> object id index
```

Hxblob is a separate virtual volume/view beside encrypted user volumes, not layered over a user encrypted data volume.

---

### 3.4 Legacy standalone BlobFS

Status: **read-only fallback/prototype implemented**.

BlobFS can remain useful as a simple bootstrapping/fallback package format, but production direction is Hxblob inside Hxfs.

---

### 3.5 DevFS

Status: **runtime namespace implemented at foundation level**.

DevFS is not a disk filesystem.

Examples:

```text
/dev/nvme0
/dev/nvme0/ns1
/dev/block/system
/dev/input/keyboard0
/dev/fb0
/dev/drivers/nvme-host
```

Opening entries returns typed handles/capabilities.

---

## 4. Completed stages A–I

### Stage A — NVMe hardware plumbing — DONE

Implemented:

- NVMe PCI discovery;
- BAR0 metadata;
- boot DMA pool;
- storage boot metadata ABI;
- HBI packaging of `driver-host-nvme`;
- init mints Mmio/Irq/DmaPool resources;
- DriverManager launches HBI NVMe host;
- DriverHost validates required resources.

Representative commits:

```text
5d19da1 feat(storage): define boot metadata and DMA allocation
0cd18d2 feat(storage): discover NVMe boot hardware
4fb1d09 feat(hbi): package NVMe boot driver
5a4de81 feat(init): mint NVMe boot resources
842e9b9 feat(driver-manager): launch HBI NVMe host
777dd29 feat(nvme-host): validate Stage A resources
```

---

### Stage B — NVMe DriverHost production queue bring-up — DONE FOUNDATION

Implemented:

- userspace ResourceMap syscall;
- MMIO mapping policy;
- controller disable/enable sequence;
- admin queue;
- identify controller/namespace;
- per-CPU queue planning/creation;
- PRP support up to 1 MiB;
- userspace host validates namespace.

Representative commits:

```text
9ec44a5 feat(resource): map hardware resources into userspace
936e3c4 feat(nvme): bring up production controller queues
57ae8be feat(nvme-host): identify mapped controller
43260fe docs(nvme): record Stage B status
```

Remaining for final production: deeper queue-slot concurrency, fault injection, full QEMU/bare-metal soak, power-management/error-reset policy.

---

### Stage C — Async BlockDevice service — DONE FOUNDATION

Implemented:

- canonical `huesos_abi::block` protocol;
- Channel request + Port completion path;
- `PortQueue` syscall;
- DriverManager exposes `service:block:nvme:channel`;
- VMO buffer registration;
- info/read/write/flush operations;
- libcanvas `BlockDevice` client.

Representative commits:

```text
4f11a4c feat(ipc): add block protocol port completions
e7cd67b feat(nvme): expose async block service
0c06bf9 docs(nvme): close Stage C block service
```

Remaining for final production: high-depth async issue/completion, cancellation/timeout policy, reset handling.

---

### Stage D — VolumeManager — DONE FOUNDATION

Implemented:

- `huesos_abi::volume`;
- system volume open path;
- range-relative BlockDevice proxy;
- libcanvas `Volume` helpers.

Representative commits:

```text
c555980 feat(volume): define NVMe system volume ABI
e679ace feat(driver-manager): serve NVMe system volume
0f9ff0e feat(libcanvas): add volume client helpers
920ffb5 docs(volume): record Stage D status
```

Remaining for final production: GPT integration, Hxfs virtual volume table as first-class source, installer/image tooling.

---

### Stage E — BlobFS read-only — DONE FOUNDATION

Implemented:

- `crates/huesos-blobfs`;
- read-only v1 parser;
- superblock/blob table validation;
- SHA-256 validation;
- overlap/reserved range checks;
- DriverManager BlobFS service;
- libcanvas BlobFS client.

Representative commits:

```text
387e882 feat(blobfs): add read-only BlobFS parser
6ca3e56 feat(driver-manager): serve BlobFS and DevFS handles
0480fa1 docs(storage): record BlobFS and DevFS stages
```

Production direction: standalone BlobFS becomes fallback/compat; Hxblob becomes main package blob path.

---

### Stage F — DevFS — DONE FOUNDATION

Implemented:

- runtime `/dev` listing/open service;
- `/dev/block/system` returns Volume handle;
- `/dev/nvme0/ns1` returns BlockDevice handle;
- no persistent handles on disk.

Representative commits:

```text
6ca3e56 feat(driver-manager): serve BlobFS and DevFS handles
0480fa1 docs(storage): record BlobFS and DevFS stages
```

Remaining for final production: dynamic device lifecycle, hotplug/reset events, stronger rights/namespace filtering.

---

### Stage G — Hxfs design + read-only parser/service — DONE FOUNDATION

Implemented:

- `docs/HXFS_DESIGN.md`;
- `crates/huesos-hxfs` parser;
- BlockReader trait;
- metadata CRC32C validation;
- superblock/checkpoint/volume/object/directory/extent parsing;
- read file/list directory/open child;
- encrypted volume rejection;
- `hxfs-service` read-only userspace service;
- DriverManager launch/open integration;
- libcanvas Hxfs handles.

Representative commits:

```text
51a3b97 docs(hxfs): define Stage G design baseline
bf3e7c5 feat(hxfs): add read-only prototype
721413f feat(hxfs): expose read-only directory handles
c0e6a88 feat(hxfs): launch read-only userspace service
1ed776c feat(libcanvas): add Hxfs client handles
```

---

### Stage H — Hxfs host COW writer + snapshots — DONE PROTOTYPE

Implemented:

- feature-gated writer module;
- append-only image mutation model;
- mkdir/create/symlink/overwrite/truncate/sparse/rename/unlink;
- checkpoint publish;
- snapshot create/delete/snapshot mount;
- encrypted writer rejects mutation;
- host tests.

Representative commit:

```text
99c81e0 feat(hxfs): add COW writer and snapshots
```

Important limitation: this is **not yet** the production on-target mutable `hxfs-service` path.

---

### Stage I — Hxfs advanced policy modules — DONE FOUNDATION

Implemented:

- hybrid 16 GiB zone allocator model;
- quota model;
- encryption policy model;
- AES-XTS-only policy selection;
- wrapped volume key descriptors;
- compression descriptors;
- Hxblob hash index and Merkle planning;
- read-ahead/direct I/O helpers;
- scrub/checksum helpers.

Representative commit:

```text
259c3ba feat(hxfs): add advanced storage policy modules
```

Important limitation: these are policy/model foundations, not final production engines.

---

# 5. Remaining production stages J–Z

The stages below are the remaining roadmap to final production storage/FS. They should be implemented as small auditable commits. Any architecture-sensitive implementation step must be confirmed before code.

---

## Stage J — Production contract freeze before real disk mutation — DONE

Goal:

Before Hxfs starts mutating a real BlockDevice, freeze the minimum production contracts for ABI, disk compatibility, and test images.

Why this stage exists:

Wiring the current host writer directly into `hxfs-service` without a reviewed persistent contract would be a bad architecture decision. The writer must be adapted into a crash-consistent service path, not copied blindly.

Tasks:

1. Define native Hxfs service ABI for write-capable handles:
   - `OPEN_VOLUME`;
   - `OPEN_DIR`;
   - `OPEN_FILE`;
   - `CREATE_FILE`;
   - `MKDIR`;
   - `SYMLINK`;
   - `RENAME`;
   - `UNLINK`;
   - `TRUNCATE`;
   - `WRITE_AT`;
   - `FSYNC`;
   - `CHECKPOINT`;
   - `CREATE_SNAPSHOT`;
   - `DELETE_SNAPSHOT`.
2. Define rights bits for mutable handles.
3. Define request/response ABI versioning and append-only extension rules.
4. Define stable on-disk feature flags:
   - incompatible features;
   - read-only-compatible features;
   - compatible optional features.
5. Define image builder/test image format path.
6. Add crash/fault test harness design before production mutation.

Exit criteria:

```text
No real disk mutation yet.
Hxfs write ABI is documented and host-tested at encode/decode level.
On-disk feature negotiation is explicit.
```

Architecture checkpoint with owner required before implementation:

```text
YES — ABI and persistent format flags are architecture-sensitive.
```

Recommended commit split:

```text
J1 docs(hxfs): define production write service contract
J2 feat(abi): add Hxfs write protocol records
J3 feat(hxfs): add on-disk feature flag validation
J4 test(hxfs): add format/ABI compatibility tests
```

---

## Stage K — Persistent mutable `hxfs-service` over BlockDevice — NO-HEAP FOUNDATION DONE

Goal:

Turn Hxfs from read-only service + host writer into a real userspace mutable filesystem service over the BlockDevice protocol.

Tasks:

1. Add BlockDevice-backed writer adapter.
2. Keep write transaction state inside `hxfs-service`, not kernel.
3. Implement handle-first mutation API:
   - directory handle creates children;
   - file handle writes/truncates/fsyncs;
   - volume handle creates snapshots/checkpoints.
4. Enforce rights on every handle operation.
5. Implement explicit commit/checkpoint path.
6. Keep sync wrappers only client-side.
7. Add host BlockDevice mock integration tests.
8. Add read-after-write service tests.
9. Add failure injection around partial write/commit boundary.

Exit criteria:

```text
A userspace client can create/write/rename/unlink data through hxfs-service,
commit it, remount, and read it back from the BlockDevice-backed image.
```

Non-goal:

```text
No encryption/compression/reclaim yet unless explicitly staged.
```

Architecture checkpoint:

```text
YES — this is the first stage that mutates persistent storage from the service.
```

Recommended commit split:

```text
K1 feat(hxfs-service): open mutable volume state over BlockDevice
K2 feat(hxfs-service): add write-capable directory/file handles
K3 feat(hxfs-service): implement create/write/truncate operations
K4 feat(hxfs-service): implement rename/unlink/symlink operations
K5 feat(hxfs-service): implement explicit fsync/checkpoint publication
K6 test(hxfs): add BlockDevice-backed mutable service tests
K7 docs(hxfs): record mutable service safety boundary
```

---

## Stage L — Journal replay, recovery, and root-store validation — FOUNDATION DONE

Goal:

Make mount recovery production-safe: old checkpoint or new checkpoint, never corrupt mixed state.

Tasks:

1. Implement root-store ring selection:
   - primary ring;
   - backup ring;
   - sequence comparison;
   - checksum validation;
   - duplicate same-ring sequence detection.
2. Implement checkpoint chain validation.
3. Implement journal range validation.
4. Implement journal replay for Recovering state.
5. Reject unsafe/corrupt unknown states.
6. Keep last-known-good checkpoint available.
7. Add crash matrix tests:
   - before data write;
   - after data before metadata;
   - after metadata before checkpoint;
   - after checkpoint before root-store publish;
   - primary ring lost;
   - backup ring lost;
   - both rings disagree.
8. Record `Needs_fsck` as mount result, not blindly persisted flag.

Exit criteria:

```text
Mount either returns a valid current filesystem, replays a valid journal,
falls back to last-known-good checkpoint, or rejects with Needs_fsck.
```

Architecture checkpoint:

```text
YES — recovery rules define long-term data safety semantics.
```

Recommended commit split:

```text
L1 feat(hxfs): implement root-store ring selection
L2 feat(hxfs): validate checkpoint chain and journal descriptors
L3 feat(hxfs): implement journal replay skeleton
L4 test(hxfs): add crash-point recovery matrix
L5 docs(hxfs): document recovery semantics and failure classes
```

---

## Stage M — Production allocator, free-space persistence, and TRIM

Goal:

Replace append-only/no-reclaim prototype behavior with persistent NVMe/SSD-oriented allocation.

Tasks:

1. Persist allocation tree per virtual volume.
2. Persist free-space structures per 16 GiB allocation group.
3. Integrate hybrid allocator with transaction commits.
4. Implement delayed allocation policy.
5. Implement extent preallocation.
6. Implement async/batched TRIM queue.
7. Add allocator invariant checks.
8. Add ENOSPC behavior without corruption.
9. Add per-zone statistics for debugging/performance.

Exit criteria:

```text
Hxfs can allocate, free, remount, and reuse blocks safely under repeated mutation.
```

Non-goal:

```text
No HDD seek optimization. No online defrag in v1.
```

Architecture checkpoint:

```text
YES — persistent allocator layout affects future scalability and fsck.
```

Recommended commit split:

```text
M1 feat(hxfs): persist per-volume allocation tree
M2 feat(hxfs): integrate hybrid zone allocator with transactions
M3 feat(hxfs): add delayed allocation and preallocation accounting
M4 feat(hxfs): add batched TRIM/discard queue model
M5 test(hxfs): add allocator persistence and ENOSPC tests
```

---

## Stage N — Refcount/backref, snapshot reclaim, and future reflinks

Goal:

Make snapshots production-grade by tracking shared blocks and reclaiming deleted snapshot data safely.

Tasks:

1. Add persistent refcount tree or equivalent ownership accounting.
2. Add backref tree for scrub/fsck validation.
3. Connect snapshots to refcount updates.
4. Implement snapshot deletion reclaim.
5. Prevent reclaim of blocks still visible from any checkpoint/snapshot.
6. Prepare format for future clone/reflink without enabling it prematurely.
7. Add tests for:
   - file overwritten after snapshot;
   - snapshot delete frees only unreferenced extents;
   - nested snapshot timelines per volume;
   - crash during snapshot deletion.

Exit criteria:

```text
Snapshot deletion reclaims space correctly and cannot free live blocks.
```

Architecture warning:

If snapshot delete remains logical-only, that is acceptable only as a prototype. It is not production because storage usage can grow forever.

Architecture checkpoint:

```text
YES — refcount/backref layout is a core on-disk design decision.
```

Recommended commit split:

```text
N1 docs(hxfs): freeze refcount/backref tree invariants
N2 feat(hxfs): add persistent refcount metadata
N3 feat(hxfs): update refcounts during COW transactions
N4 feat(hxfs): reclaim blocks on snapshot deletion
N5 test(hxfs): add snapshot reclaim and crash tests
```

---

## Stage O — Persistent quotas and enforcement

Goal:

Move quotas from policy model into real per-volume enforcement.

Selected quota types:

```text
physical bytes: yes
object count:   yes
logical bytes:  no
snapshot count: no
```

Tasks:

1. Persist quota tree per virtual volume.
2. Charge allocations before commit.
3. Roll back charges on failed transaction.
4. Enforce object-count limits on create/mkdir/symlink/blob ingest.
5. Expose quota info through VolumeHandle.
6. Add tests for quota denial, rollback, remount persistence.

Exit criteria:

```text
Writes cannot exceed physical byte/object quotas, including after remount.
```

Architecture checkpoint:

```text
MEDIUM — quota policy was already selected, but ABI exposure should be reviewed.
```

Recommended commit split:

```text
O1 feat(hxfs): persist quota tree descriptors
O2 feat(hxfs): enforce physical-byte quota in allocator path
O3 feat(hxfs): enforce object-count quota in object creation path
O4 test(hxfs): add quota persistence and rollback tests
```

---

## Stage P — Production encryption path

Goal:

Implement real per-volume encryption according to the selected hierarchy.

Selected design:

```text
TPM/bootloader master key -> unwrap volume table keys
wrapped volume keys in metadata
volume keys kept only in RAM
AES-XTS only for mutable volumes
software fallback mandatory if keys exist
no key provider => encrypted volumes unavailable
metadata encrypted except lowest root-store layer
filenames and directory structure encrypted
```

Tasks:

1. Define KeyProvider interface for TPM/bootloader source.
2. Implement wrapped volume key load/unseal path.
3. Implement AES-XTS block encryption/decryption for 4 KiB data units.
4. Integrate crypto layer below metadata/data block read/write.
5. Encrypt filenames/directory entries for encrypted volumes.
6. Ensure plaintext metadata is limited to root-store minimum.
7. Reject encrypted volumes if provider unavailable.
8. Add software fallback path.
9. Add tests with deterministic test keys/vectors.
10. Add audit docs for key lifetime and memory zeroization.

Exit criteria:

```text
Encrypted mutable volume can be created, mounted with key provider,
read/written/remounted, and is rejected without keys.
```

Architecture warnings:

- Mounting encrypted metadata while leaving filenames plaintext would violate the selected design.
- Treating hardware encryption as mandatory would be wrong; software AES-XTS fallback is required when valid keys exist.

Architecture checkpoint:

```text
YES — security boundary and key hierarchy require owner confirmation.
```

Recommended commit split:

```text
P1 docs(hxfs): freeze encryption data path and key lifecycle
P2 feat(hxfs): add KeyProvider and wrapped-key loading path
P3 feat(hxfs): add AES-XTS block crypto backend
P4 feat(hxfs): integrate crypto with metadata/data block I/O
P5 feat(hxfs): encrypt directory names for encrypted volumes
P6 test(hxfs): add encrypted mount/write/remount/reject tests
P7 docs(audit): record encryption safety boundary
```

---

## Stage Q — Production compression path

Goal:

Move compression from descriptors to actual read/write integration.

Tasks:

1. Confirm initial codecs before implementation.
2. Implement per-volume/per-object compression policy resolution.
3. Add compressed extent descriptors.
4. Add write path compression with incompressible fallback.
5. Add read path decompression and checksum validation.
6. Ensure direct I/O bypass/deny semantics are explicit.
7. Add tests for sparse + compressed + overwrite behavior.

Exit criteria:

```text
Compressed files survive write/read/remount and corruption is detected.
```

Architecture checkpoint:

```text
YES for codec choices and extent encoding.
```

Recommended commit split:

```text
Q1 docs(hxfs): define compressed extent encoding
Q2 feat(hxfs): implement compression policy resolution
Q3 feat(hxfs): add compression/decompression pipeline
Q4 test(hxfs): add compressed sparse/overwrite/remount tests
```

---

## Stage R — Production Hxblob package/blob subsystem

Goal:

Replace standalone BlobFS production role with Hxfs/Hxblob.

Selected design:

```text
blob id = hash(content)
hash -> ObjectId index
immutable / write-once
Merkle verification
dedup by hash
GC later, but format must allow it
separate virtual volume beside encrypted user volume
```

Tasks:

1. Implement Hxblob virtual volume creation/open.
2. Implement write-once blob ingest.
3. Implement hash -> object id persistent index.
4. Implement Merkle tree generation/storage.
5. Verify chunks on read path.
6. Deduplicate identical blobs.
7. Expose BlobViewHandle/Hxblob service API.
8. Connect package resolver/DriverManager to Hxblob.
9. Keep BOOTFS fallback for storage failure.
10. Add GC design, then implementation if approved.

Exit criteria:

```text
System packages can be served from Hxblob with hash/Merkle validation,
while BOOTFS remains fallback.
```

Architecture checkpoint:

```text
YES — package boot path and GC policy are architecture-sensitive.
```

Recommended commit split:

```text
R1 docs(hxblob): define production Hxblob service contract
R2 feat(hxfs): add persistent Hxblob index tree
R3 feat(hxblob): implement write-once blob ingest
R4 feat(hxblob): implement Merkle verification on read
R5 feat(driver-manager): resolve noncritical packages from Hxblob
R6 test(hxblob): add dedup/corruption/remount tests
```

---

## Stage S — Cache, mmap, direct I/O, and read/write performance

Goal:

Make Hxfs performant on NVMe/SSD without compromising handle/capability semantics.

Selected design:

```text
userspace FS server cache
async parallel read-ahead
buffered writeback + explicit fsync/checkpoint
mmap later
direct I/O yes
sync wrappers only client-side
```

Tasks:

1. Add userspace block/object cache in hxfs-service.
2. Implement async parallel read-ahead planner in real read path.
3. Implement buffered writeback with explicit fsync/checkpoint barriers.
4. Define mmap handle/protocol semantics.
5. Implement mmap VMO path for files where safe.
6. Implement direct I/O alignment checks and bypass path.
7. Add cache invalidation rules after mutation/snapshot.
8. Benchmark random/sequential read/write on NVMe QEMU.

Exit criteria:

```text
Hxfs supports cached read/write, explicit fsync, mmap where enabled,
and direct I/O with correct alignment/consistency rules.
```

Architecture checkpoint:

```text
YES for mmap consistency semantics.
```

Recommended commit split:

```text
S1 feat(hxfs-service): add userspace metadata/data cache
S2 feat(hxfs-service): wire parallel read-ahead into read path
S3 feat(hxfs-service): add buffered writeback and fsync barriers
S4 docs(hxfs): define mmap/direct-I/O consistency rules
S5 feat(hxfs-service): implement file mmap VMO path
S6 feat(hxfs-service): implement direct I/O path
S7 bench(hxfs): add NVMe-oriented performance smoke tests
```

---

## Stage T — VolumeManager, GPT, and virtual volume production

Goal:

Make volumes production-grade: GPT cooperation, Hxfs virtual volumes, system/user/hxblob volume discovery.

Tasks:

1. Implement GPT parser/writer integration where needed.
2. Locate system Hxfs by boot metadata and duplicate UUID in Hxfs volume table.
3. Implement Hxfs virtual volume table persistence.
4. Expose VolumeHandle operations for virtual volumes.
5. Create separate user home volume with optional independent encryption key.
6. Create separate Hxblob volume.
7. Enforce no nested volumes.
8. Enforce no moving objects between volumes.
9. Add volume quota/encryption/compression policy roots.

Exit criteria:

```text
System, user-home, and Hxblob virtual volumes are discoverable,
mountable, policy-isolated, and stable across remount.
```

Architecture checkpoint:

```text
YES — virtual volume table is equivalent to Hxfs replacing FVM.
```

Recommended commit split:

```text
T1 feat(volume): add GPT-backed system volume discovery
T2 feat(hxfs): persist virtual volume table
T3 feat(hxfs): expose virtual VolumeHandle operations
T4 feat(hxfs): create system/user/hxblob volume roles
T5 test(hxfs): add virtual volume policy/remount tests
```

---

## Stage U — NVMe production performance and reliability

Goal:

Finish the NVMe/block layer as production substrate for Hxfs.

Tasks:

1. Implement deeper async queue-slot tracking.
2. Keep one queue pair per CPU where controller supports it.
3. Add robust timeout handling per command.
4. Add controller reset/recovery path.
5. Add namespace re-identification after reset.
6. Add MSI-X/MSI/polling fallback soak tests.
7. Add Flush/FUA semantics mapping.
8. Add write zeroes/discard support if useful for TRIM path.
9. Add telemetry counters:
   - submitted/completed;
   - timeouts;
   - resets;
   - queue full;
   - average latency buckets.
10. Run QEMU with real `-device nvme` and validate logs.

Exit criteria:

```text
BlockDevice remains correct under high queue depth, reset/failure tests,
and long QEMU NVMe soak.
```

Non-goal:

```text
No HDD elevator. No rotational media policy.
```

Architecture checkpoint:

```text
MEDIUM — queue/reset behavior affects storage-wide reliability.
```

Recommended commit split:

```text
U1 feat(nvme): implement multi-slot async completion tracking
U2 feat(nvme): add command timeout and reset policy
U3 feat(nvme): map flush/discard/write-zeroes operations
U4 test(nvme): add MSI-X/MSI/polling fallback tests
U5 bench(nvme): add high-queue-depth block benchmarks
U6 docs(nvme): record production reliability contract
```

---

## Stage V — Image builder, installer, migration, and recovery tooling

Goal:

Make Hxfs usable as an installed OS filesystem, not only tests/manual images.

Tasks:

1. Build `mkhxfs` image creation tool.
2. Build Hxfs volume/partition initializer.
3. Add package ingestion into Hxblob.
4. Add user/home volume creation path.
5. Add recovery mount mode.
6. Add offline inspect tool.
7. Add migration policy for future format versions.
8. Add backup/export path for development use.

Exit criteria:

```text
A HuesOS disk image can be created with BOOTFS + Hxfs system/user/Hxblob volumes,
booted, mounted, and inspected/recovered by tools.
```

Architecture checkpoint:

```text
MEDIUM — migration policy and install layout should be reviewed.
```

Recommended commit split:

```text
V1 feat(tools): add mkhxfs image builder
V2 feat(tools): add Hxfs inspector
V3 feat(tools): add Hxblob package ingestion
V4 feat(installer): create system/user/hxblob volume layout
V5 docs(storage): document install/recovery layout
```

---

## Stage W — Scrub, fsck, and repair

Goal:

Turn scrub helpers/backref model into actual validation and repair tooling.

Tasks:

1. Walk all metadata trees.
2. Validate metadata checksums.
3. Validate extent ownership.
4. Validate refcount/backref consistency.
5. Validate directory tree/object tree consistency.
6. Validate Hxblob hashes/Merkle roots.
7. Validate quota accounting.
8. Provide read-only report mode.
9. Provide conservative repair mode only after owner review.
10. Ensure encrypted volumes require keys for deep scrub.

Exit criteria:

```text
fsck/scrub can detect metadata corruption, lost/unreferenced extents,
quota mismatches, Hxblob corruption, and unsafe checkpoint states.
```

Architecture warning:

Automatic repair can destroy data if policy is wrong. Start with report-only scrub and explicit repair confirmation.

Architecture checkpoint:

```text
YES before repair mode. Report-only scrub can start earlier.
```

Recommended commit split:

```text
W1 feat(hxfs): add metadata tree scrub walker
W2 feat(hxfs): validate extent ownership and backrefs
W3 feat(hxblob): validate blob hashes and Merkle roots
W4 feat(tools): add read-only hxfs-scrub tool
W5 docs(hxfs): define repair policy before implementation
```

---

## Stage X — Security hardening and capability policy

Goal:

Make FS/device/service handles safe under multi-process use.

Tasks:

1. Define exact rights for all Hxfs handles.
2. Ensure rights monotonicity on handle transfer/duplication.
3. Add capability checks on every request.
4. Deny path traversal outside volume root.
5. Bound symlink resolution depth.
6. Enforce no hardlinks.
7. Enforce UTF-8/255-byte names and case-sensitive lexical rules.
8. Add resource limits for outstanding requests, dirty cache, open handles.
9. Add service crash/restart behavior.
10. Add fuzzing for ABI request decoding and path resolution.

Exit criteria:

```text
Untrusted clients cannot escalate FS rights, escape volume roots,
exhaust service memory unchecked, or corrupt state through malformed requests.
```

Architecture checkpoint:

```text
MEDIUM — mostly enforcement of already selected capability model.
```

Recommended commit split:

```text
X1 feat(abi): define Hxfs handle rights
X2 feat(hxfs-service): enforce rights and request quotas
X3 feat(hxfs): harden path/symlink/name validation
X4 fuzz(hxfs): add ABI/path resolver fuzz targets
X5 docs(audit): record Hxfs service security boundary
```

---

## Stage Y — Observability, benchmarks, and fault injection

Goal:

Make production readiness measurable.

Tasks:

1. Add structured serial markers for storage boot.
2. Add Hxfs counters:
   - reads/writes;
   - commits;
   - journal replays;
   - cache hit/miss;
   - allocator ENOSPC;
   - snapshot reclaim;
   - crypto/compression counts.
3. Add fault injection:
   - dropped write;
   - reordered write;
   - failed flush;
   - corrupt metadata checksum;
   - lost primary root-store ring;
   - lost backup root-store ring.
4. Add benchmarks for NVMe/SSD target profiles:
   - random 4 KiB read/write;
   - sequential large read/write;
   - package blob open/read;
   - metadata-heavy directory operations;
   - snapshot create/delete.
5. Add long-running QEMU soak scripts.

Exit criteria:

```text
Storage regressions can be caught with repeatable tests, counters, and benchmarks.
```

Architecture checkpoint:

```text
LOW — instrumentation should not change storage semantics.
```

Recommended commit split:

```text
Y1 feat(storage): add structured storage boot markers
Y2 feat(hxfs): add service and filesystem counters
Y3 test(hxfs): add block fault-injection harness
Y4 bench(storage): add NVMe/Hxfs benchmark suite
Y5 scripts: add long-running QEMU NVMe soak
```

---

## Stage Z — Production release gate and on-disk format v1 freeze

Goal:

Declare storage production-ready only after format, recovery, security, and target tests pass.

Required release gates:

```text
fmt clean
clippy clean
host tests clean
safety budget clean
lock policy clean
policy crate checks clean
hues-async noalloc clean
huesos-object lock policy clean
git diff --check clean
QEMU NVMe boot/read/write/remount clean
QEMU crash-recovery matrix clean
long soak clean
fsck/scrub report clean
format v1 compatibility tests clean
```

Production definition of done:

1. Fresh disk image can be created.
2. HuesOS boots from BOOTFS and mounts Hxfs.
3. Hxfs can create system/user/Hxblob virtual volumes.
4. Hxfs can read/write/rename/unlink/remount safely.
5. Crash during mutation recovers old or new checkpoint, never corrupt mix.
6. Snapshots preserve old state and deletion reclaims space safely.
7. Encrypted volumes work only with valid key provider and are rejected otherwise.
8. Hxblob serves packages with hash/Merkle validation.
9. Quotas are enforced and persistent.
10. Scrub/fsck detects corruption and unsafe checkpoint states.
11. NVMe block service survives high queue depth and reset/fallback tests.
12. BOOTFS fallback remains usable if persistent storage fails.
13. On-disk format v1 is documented and frozen.

Architecture checkpoint:

```text
YES — final v1 freeze requires explicit owner approval.
```

Recommended commit split:

```text
Z1 docs(storage): define production release checklist
Z2 test(storage): add final QEMU NVMe production gate
Z3 docs(hxfs): freeze Hxfs on-disk format v1
Z4 docs(release): mark storage production readiness after gates pass
```

---

## 6. Suggested immediate next stage

Recommended next work is **Stage J**, not direct production mutation.

Reason:

```text
Stage J freezes the write ABI and persistent feature compatibility rules before
Stage K starts real mutable hxfs-service writes over BlockDevice.
```

Suggested next coding sequence:

```text
1. docs(hxfs): define production write service contract
2. feat(abi): add Hxfs write protocol records
3. feat(hxfs): add on-disk feature flag validation
4. test(hxfs): add ABI/format compatibility tests
```

That is **4 commits for Stage J** if we keep it tight.

---

## 7. Hard rules going forward

- Do not simplify code without asking if simplification is not required.
- Before architecture-sensitive changes, ask the owner first.
- Before push, run at least fmt + clippy; for code changes also run the full storage safety gate.
- Report GitHub compare links after pushes.
- Push both `main` and `fix/critical-medium-audit` when finalizing repo work.
- No heap allocation in NVMe I/O submit/completion hot path after driver init unless explicitly designed.
- No filesystem logic inside NVMe driver.
- No path-first API as primary contract.
- Handles/capabilities are runtime-only and never persisted by Hxfs.
- All public ABI changes are append-only or explicitly versioned.
- All hardware-facing unsafe blocks need audit entries.
- Every boot-storage step needs serial markers so hangs are localizable.
- Hxfs remains NVMe/SSD-oriented; do not add HDD optimization policy.
- If an accepted design is bad, explicitly call it out instead of silently implementing it.

---

## 8. Known non-production gaps tracked by this roadmap

```text
on-target QEMU/bare-metal NVMe soak not completed
hxfs-service is still read-only in current pushed code
host writer is not yet persistent service writer
journal replay is not implemented as runtime recovery
free-space/refcount/reclaim is not production
AES-XTS/key management is not production
compression engine is not production
Hxblob service is not production
quotas are not enforced in write path
scrub/fsck is not production
mmap/direct I/O/cache are not production
installer/image tooling is not production
```
