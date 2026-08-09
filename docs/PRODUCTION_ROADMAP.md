# HuesOS Production-Readiness Roadmap

This document replaces the versioned `STORAGE_NVME_FS_ROADMAP.md` for
the current push toward a production-grade system. Stages here are
**producers of production behaviour**, not feature families; a stage
ends only when the system can serve real workloads without operator
intervention, not when a feature compiles.

Each stage is split into **tracks** that can ship as independent PRs
when their scope is small enough to review, and as multi-PR efforts
when the scope is large. A stage is **CLOSED** when every track under
it has a closed exit criterion.

## Goal

A real, deployable HuesOS that boots on a bare-metal x86_64 box with
NVMe storage and a framebuffer, mounts an Hxfs production volume, runs
a long-lived userspace workload (terminal, doom, hxfs-service) without
manual recovery, and survives a graceful shutdown initiated from
userspace. Boot must work; mount must work; recovery must work;
encryption must be available when keys exist; quotas must hold; media
errors must not panic.

## Non-goals (for this roadmap)

- Server / multi-tenant workloads
- Container orchestration / process migration
- Networking stack beyond the local kernel control plane
- Graphical compositor / desktop environment beyond the existing
  framebuffer text terminal
- Symmetric multi-core scalability beyond what the existing SMP
  bring-up already delivers
- Cross-architecture portability beyond x86_64

## Stage index

| Stage | Theme | Exit signal |
|-------|-------|-------------|
| **A. Mount path wired** | crypto gate, journal replay, recovery, mount-time validation all reachable from the live mount path; previously-feature-complete APIs become part of the real boot sequence | `qemu-nvme-soak` boots, recovers, mounts, and exits with the on-target trace the same way a stock NVMe install would |
| **B. I/O pipeline complete** | compression and encryption are part of the read/write data path, not test-only utilities; the on-disk extent layout reflects what the policy tables say | a file written through the host-test `write_then_read` round-trip survives a remount and produces the same bytes; a compressed extent that is corrupted on disk fails the read with `CompressionError::BadChecksum`, not a panic |
| **C. Reliability surface** | scrub, online fsck, quota enforcement, error injection, panic-free recovery — the system detects and survives media errors without operator intervention | `qemu-nvme-soak` with a corrupted LBA at a known offset logs the corruption, marks the extent bad, and continues; `qemu-extable-smoke` proves the recoverable-copy path actually recovers |
| **D. Security gate** | TPM-backed key provider, capability-gated display, signed manifests, secure boot chain — the system refuses to mount encrypted volumes without a key context, refuses to blit from non-graphics processes, refuses to boot a tampered image | the `qemu-nvme-soak` QEMU with no TPM attached still mounts a plain volume; an encrypted volume without a key context is rejected with the new `Encrypted*` variants; `FRAMEBUFFER_POLICY.md` exit criteria are all green |
| **E. Operations** | sysctl-like runtime knobs, observation surfaces, structured logging, benchmarks, soak harnesses — what an operator needs to keep the system healthy in production | `tools/storage-bench.py` produces a reproducible throughput report; `qemu-nvme-soak` runs to 24 h with the trace envelope green the whole time |
| **F. Service foundation** | Hxblob block object store, persistent service directory, hxfs-service production wiring — the storage layer supports a real workload, not a host test | a host test that writes an Hxblob object, mounts the volume, and reads the object back produces the same bytes; the on-target `hxfs-service` boots, mounts the volume, and survives a remount |

Stages A–D are the **production gate**; together they make the system
deployable. Stages E–F are the **production polish**; together they
make the system operable.

---

## Stage A — Mount path wired

**Why this stage exists.** PRs #153 (Stage P) and #154 (Stage Q) left
the production storage layer with **feature-complete foundations**
but **no live mount wiring**: encryption validation sat in the
host-test suite only; compression sat beside the read/write path
but was not in the read/write path; the journal replay was feature-
complete but not reached from the live mount; the mount-time quota
enforcement was a documentation paragraph.

A drive that does not get mounted, or that mounts but cannot read
or write, is not a production system. Stage A exists to make every
"feature-complete" API actually reachable from the live boot path.

### Track A.1 — Encryption mount gate  (landed as PR `hxfs-p3-mount-gate`)

- `Hxfs::mount_with_keys` / `FixedHxfsWriter::mount_with_keys` take
  a per-volume `EncryptionPolicy` table; `mount` becomes a thin
  wrapper that passes an empty table.
- `resolve_encryption_policy(policy_id, table)` is the policy-lookup
  helper that mirrors `resolve_compression_policy`.
- The legacy `HxfsError::EncryptedVolume` is replaced by three
  precise variants: `EncryptedVolumeKeyUnavailable`,
  `EncryptedPolicyUnknown`, `EncryptedPolicyInvalid`.
- `Hxfs::encryption()` accessor for downstream readers.

**Exit criterion.** An encrypted volume is rejected with one of the
new `Encrypted*` error variants; a plain volume mounts unchanged;
host tests in `cargo test -p huesos-hxfs` cover all three failure
modes plus the success path.

### Track A.2 — Journal replay on mount

- `recovery::replay_journal` runs before the read path resolves the
  object tree; an unclean root state is recovered, not rejected.
- A replay crash is **recoverable**: a second mount continues from
  the last committed checkpoint.

**Exit criterion.** A volume that was force-killed mid-write mounts
on the next boot with the data the journal recorded; a volume that
crashed mid-replay mounts on the third boot with the same data.

### Track A.3 — Compression read/write path  (next PR `hxfs-q3-readwrite-pipeline`)

- `read_extent` calls `decompress_block` when the extent carries
  a `CompressedExtent` descriptor; the result is a transparent
  byte buffer at the call site.
- `write_extent` calls `compress_block`; the codec's
  `Incompressible` fallback to `Plain` is a normal completion,
  not an error.
- A corruption in the compressed payload surfaces as
  `CompressionError::BadChecksum`; the read is aborted and the
  extent is marked bad so a retry does not re-visit the same
  bytes.

**Exit criterion.** A round-trip of a compressible file
survives a remount; a round-trip of a random file
(Incompressible fallback) also survives; a corrupted compressed
extent is rejected with the precise error.

### Track A.4 — Per-extent lazy cache for compressed extents

- A bounded cache holds the most recent `N` decompressed extents
  (default `4` extents = `16 MiB` at 4 MiB extent size).
- Cache is **per-volume**, not global, so different mounts do not
  share state.
- Invalidation is on extent overwrite, not on time.

**Exit criterion.** A `cargo test -p huesos-hxfs` benchmark of
1000 random reads of the same compressed extent shows the cache
hits at the expected rate; cache miss path still returns correct
data.

### Track A.5 — Production quota enforcement

- The quota tree is consulted on **every** write path
  (file write, dir entry, extents, allocation tree), not only on
  the host-test path.
- A quota breach returns `QuotaError::Exceeded`; the kernel
  returns `NoSpace` to userspace; the work that exceeded the
  quota is rolled back.

**Exit criterion.** A process that exceeds its Job quota gets
`NoSpace`; the volume is left consistent; the next write within
the quota succeeds.

### Track A.6 — Live mount in hxfs-service

- `hxfs-service` actually mounts the system volume at boot, not
  the host-test driver.
- Recovery runs on first boot if the root state is dirty.
- A real key provider is wired for encrypted volumes (Stage D
  track); for plain volumes the `[]` table path is used.

**Exit criterion.** `qemu-nvme-soak` boots, recovers a forced
crash, mounts, and runs the terminal.

---

## Stage B — I/O pipeline complete  (**CLOSED**)

**Why this stage exists.** Stage A wires the mount; Stage B makes
the data path match the on-disk policy. Without Stage B, the
system mounts a volume but reads it as if it were plain,
silently losing any encrypted or compressed bytes.

### Track B.1 — Encrypted metadata I/O  (landed as PRs `hxfs-stage-b-io-pipeline` + `hxfs-stage-b2-wiring`)

- Metadata blocks (dirent, extent table, allocation tree,
  refcount tree, backref tree, quota tree) on an encrypted volume
  are stored as v6 blocks: the 40-byte `BlockHeader` stays in
  plaintext (so the layer can route by `block_type` without a
  key), the payload is AES-256-GCM ciphertext under the per-volume
  metadata subkey. Block pointers stay plain so the allocator can
  find free extents without a key.
- `FEATURE_INCOMPAT_V6_ENCRYPTED_METADATA` (bit 7) is checked at
  `read_superblock`, so a reader without the feature rejects the
  volume with `UnsupportedFormat` instead of mis-parsing.
- The fixed writer's mount paths decrypt v6 metadata, so an
  encrypted volume can be mounted into mutable state.

**Exit criterion.** A file written to an encrypted volume
survives a remount and reads back identically; metadata
checksums match the decrypted bytes. **Met** by
`b1_b2_encrypted_volume_write_then_read_round_trip`.

### Track B.2 — Encrypted filenames  (landed as PR `hxfs-stage-b2-wiring`)

- Dirent name bodies on an encrypted volume are encrypted under
  the per-volume metadata subkey (`nonce(12) || ciphertext ||
  tag(16)` inside the v5 name region); lookup uses the plaintext
  name after decryption. On-disk dirent bytes contain no
  recognisable filename.
- The `(dir_id, file_id)` → encrypted-name display side index is
  **deferred to Stage D** (the plan's explicitly deferred item);
  userspace display of names on encrypted volumes lands with the
  Stage D key-handle work.

**Exit criterion.** `ls` on an encrypted-volume directory shows
the plaintext names; the encrypted bytes on disk do not contain a
recognisable filename. **Met** by the B.1/B.2 round-trip test.

### Track B.3 — Encrypted data extents  (landed as PR `hxfs-stage-b3-encrypted-extents` + Stage B.3 completion in PR `hxfs-stage-b5-e2e-gcm-inject`)

- A data extent on an encrypted volume is stored as the
  AES-256-GCM envelope of the (compressed) payload:
  `nonce(12) || ciphertext(4028) || tag(16) || 40-byte zero-pad`,
  exactly filling the 4 KiB extent slot. Read order is
  **decrypt → decompress** (the page cache sits below the
  encryption layer and holds plaintext).
- **Write-side compression (Stage B.3 completion).** The merged
  B.3 wired only the read side; the writer never compressed and no
  on-disk descriptor existed, so the Stage B exit signal was
  unreachable. The completion commit wires the full write path:
  `FixedHxfsWriter` resolves the object's compression policy,
  pads the plaintext to a full block, runs `compress_block`, and
  emits **v2 extent-table records** (`BLOCK_TYPE_EXTENT_TABLE_V2`,
  40 bytes: v1 fields + algorithm + compressed_bytes + CRC32C;
  `EXTENT_FLAG_COMPRESSED` marks a compressed record). A v2 block
  is emitted whenever the object's resolved policy selects a
  codec — including incompressible fallback records stored plain
  with the flag clear — so the read path never mis-decodes a
  plain block under an LZ4 policy. Old volumes (v1 blocks) read
  exactly as before; a v1 reader rejects a v2 block with
  `BadBlock` (same idiom as the v6 metadata gate).
- A corruption in either step surfaces as the precise error
  (`CompressionError::BadChecksum` via the descriptor CRC for a
  corrupted compressed payload, `CryptoError::BadKey` for a bad
  GCM tag) at the read boundary as `HxfsError::Compression`, so
  the higher layer can mark the extent bad.

**Exit criterion.** A file written with both compression and
encryption survives a remount; a single-byte corruption in the
on-disk extent is rejected with the precise error. **Met** by
`write_then_read_encrypted_compressed_volume` (400 KiB, the
single-block extent-table limit) and
`corrupted_compressed_plain_volume_fails_read_with_precise_error`.

### Track B.4 — Direct I/O bypass semantics  (landed as PR `hxfs-stage-b4-odirect-deny`)

- A `O_DIRECT` open flag on a userspace VMO bypasses the page
  cache; the kernel returns a buffer that is read/written
  directly to the device.
- The flag is **deny-by-default** for the MVP because the page
  cache is not yet in production; deny is the safe default.

**Exit criterion.** `O_DIRECT` returns `Unsupported`; the
non-direct path works; the documentation explains when
`O_DIRECT` will be supported. **Met** by host tests plus an
on-target probe (see Track B.5).

### Track B.5 — End-to-end proof and on-target fault injection  (landed as PR `hxfs-stage-b5-e2e-gcm-inject`)

- `write_then_read_encrypted_compressed_volume`: a 400 KiB file
  (100 extents — the maximum the single-block extent table
  supports with v2 records) written through `FixedHxfsWriter`
  with encryption + LZ4 policies survives a remount and reads
  back byte-for-byte; the on-disk layout is asserted (v2 extent
  table, v6 header, GCM envelope with no plaintext leak); a
  single-byte ciphertext flip is rejected with the precise
  error. `incompressible_fallback_round_trips_on_plain_volume`
  covers the random-data fallback.
- `tools/hxfs-seed` (standalone host tool, same `FixedHxfsWriter`
  the service uses) seeds a sparse encrypted+compressed volume
  with a `seed.bin` file; `mkhxfs.py --seed-file ...` delegates
  to it so the format is never reimplemented in Python.
- `hxfs-service` gains a feature-gated (`synthetic-key`) boot
  self-check: it mounts the seeded volume, exercises the O_DIRECT
  deny predicate (`[hxfs] odirect-deny-ok`) and reads the seed
  file (`[hxfs] self-check ok (N bytes)`); a corrupted encrypted
  extent is detected and reported as `[hxfs] bad-gcm-tag-marked`
  while the service keeps serving.
- `ci-qemu-nvme-soak.sh` gains an injection mode (4th positional
  arg `1`): `--inject-bad-gcm-tag` flips one bit of the seed
  file's GCM ciphertext; the harness requires the two Stage B.5
  markers. Wired into CI as the `qemu-nvme-gcm-inject` job.

**Exit criterion.** The on-target trace shows `bad-gcm-tag-marked`
and the mount continues. **Met** by the CI injection job.

### Known limitations (documented, tracked)

- **Single-block extent tables**: a file is capped at 101 v2
  records (~404 KiB) because the writer's extent table is one
  block per object. Multi-block extent trees are a Stage C+
  item. This is why the E2E file is 400 KiB, not the 4 MiB the
  original plan sketched.
- **Two-slot extents for incompressible data on encrypted
  volumes**: the GCM envelope holds at most 4028 plaintext bytes,
  so an incompressible plaintext larger than that (a full 4 KiB
  block, or a near-full partial block) is stored as two envelopes
  in two consecutive physical slots (`EXTENT_FLAG_MULTI_SLOT`,
  `block_count = 2`, ~2x physical overhead for those blocks).
  Media files, archives and already-compressed data are therefore
  writable on encrypted volumes; the previous loud `Unsupported`
  failure is gone. Both slot shapes are covered by host tests and
  by the on-target `multi-slot-write-ok` soak marker.
- **Synthetic key on target (superseded by the Stage D kernel
  key blob)**: the soak's on-target encrypted mount uses the
  explicit `synthetic_key::VOLUME_KEY`, baked into the KERNEL as
  the bootloader key blob (`HUESOS_VOLUME_KEY_HEX`) and served
  via the `VolumeKeyGet` syscall; the library itself has no
  implicit key material (an encrypted volume without a key
  context is rejected). The `synthetic-key` feature remains
  test-only wiring until the real TPM provider lands.
- **Soft crypto on the no-SIMD userspace target**: the `aes` /
  `polyval` x86 fast paths cannot codegen without SSE2 (the
  kernel context switch does not save XMM state), so the
  synthetic-key build compiles them with `aes_force_soft` /
  `polyval_force_soft`. Correct, slower; revisit with Stage D.

---
---

## Stage C — Reliability surface

**Why this stage exists.** Storage devices fail. The on-disk
layout is fixed-capacity and a single bad LBA is recoverable
only if the system notices it, marks the bad extent, and
continues. Without Stage C, a single media error turns into a
panic or, worse, a silent corruption.

### Track C.1 — Media error handling

- Every block read that returns a transport error marks the
  extent bad, returns `Io` to the caller, and continues with
  the next extent.
- Every block write that returns a transport error is retried
  once; if the retry fails, the write is rolled back at the
  journal layer.
- A read of a marked-bad extent returns `Io` without retrying;
  the caller can reallocate around the bad extent.

**Exit criterion.** A QEMU disk with a known-bad LBA at a known
offset produces the on-target trace `bad-extent-marked` and
continues to mount; `tools/hxfs-scrub.py --inject-bad-lba` covers
the same path from userspace.

### Track C.2 — Online fsck

- `tools/hxfs-fsck.py` walks the on-disk tree and reports
  inconsistencies.
- An online `fsck --fix` path applies the obvious safe fixes
  (re-orphaned dir entries, stale refcount bumps) and reports
  the rest for human review.

**Exit criterion.** A volume with a known inconsistency
(orphaned dir entry, stale refcount) fsck-fixes to a clean
state; the same inconsistency without `--fix` produces a
precise report.

### Track C.3 — Scrub

- `huesos-fsck scrub` walks the volume and reads every block;
  a bad block is reported and the surrounding extent is
  reallocated from spare.
- A `tools/hxfs-scrub.py` tool runs the same pass from userspace
  for operator convenience.

**Exit criterion.** A volume with a known-bad LBA inside an
extent gets the extent reallocated; the reallocation is
journaled; a remount sees the reallocated extent.

### Track C.4 — Quota enforcement at every write

- Quota is enforced on the **write path** of the in-kernel
  fixed-capacity dispatcher, not only on the host-test path.
- A Job that exceeds its quota is throttled; the throttling
  is observable in the Job's per-CPU tick counter.

**Exit criterion.** A Job at the quota edge gets
`QuotaError::Exceeded` and the kernel returns `NoSpace` to
userspace; the volume stays consistent; a second Job in the
same Job tree with a lower quota gets the same outcome.

### Track C.5 — Error injection for tests

- `qemu-nvme-soak --inject` flags inject a known-bad LBA at a
  known offset, a known-corrupted extent, or a known-stale
  checkpoint.
- The injection is one-shot; the next boot is clean.

**Exit criterion.** Every Stage C track has a `--inject` test
in `qemu-nvme-soak` that exercises the failure path.

---

## Stage D — Security gate

**Why this stage exists.** Production storage that allows a
plaintext mount when an encrypted volume was requested is not
secure. The capability-gated display already exists
(`docs/FRAMEBUFFER_POLICY.md`); the encryption mount gate is
landed in Track A.1; what remains is the key-provider chain.

### Track D.1 — KeyProvider interface (landed as P2 in PR #153)

- `KeyProvider` enum with `TpmOrBootloader` and `None` variants.
- The MVP key provider is the software AES-XTS engine linked
  into `huesos-hxfs`; a future TPM backend (Track D.2) threads
  the same interface.

**Exit criterion.** A custom `KeyProvider` implementation can
be wired into `mount_with_keys` without changing the kernel
syscall surface.

### Track D.2 — Key provider (bootloader key blob landed; TPM open)

- **Bootloader key blob (landed, PR `hxfs-stage-d-key-provider`).**
  The kernel bakes a 32-byte volume key into the image at build
  time (`HUESOS_VOLUME_KEY_HEX`, emitted by `huesos-kernel/build.rs`
  as `boot_key.rs`), installs it in `huesos_object::boot_key` at
  init, and serves it through the new `VolumeKeyGet` syscall
  (`NotFound` when no blob). The hxfs-service fetches it via
  `libcanvas::system::get_volume_key` and passes it to
  `mount_with_keys`; the mount gate now REQUIRES a key context
  for encrypted volumes (`EncryptedVolumeKeyUnavailable` when
  absent) — the implicit instance-uuid placeholder IKM is gone.
  This is the kernel->service handoff shape a real TPM provider
  will reuse (measure/seal/unseal into the same slot).
- A `huesos-tpm-provider` userspace DriverHost holds the TPM
  Resource and serves volume-key unseal requests over a
  Channel.
- The kernel-side `KeyProvider::Tpm` path asks the DriverHost
  to unseal; the DriverHost returns the unwrapped key in a
  sealed channel.
- A software fallback path is kept for systems without a TPM
  (e.g. `qemu-nvme-soak`).

**Exit criterion.** `qemu-nvme-soak` with `swtpm` attached
mounts an encrypted volume; the same soak without `swtpm`
mounts a plain volume and rejects the encrypted one with
`EncryptedVolumeKeyUnavailable`.

### Track D.3 — TPM PCR policy (Stage 2)

- The sealed volume key is bound to specific PCR values: the
  boot loader hash, the kernel hash, and the command line.
- A `swtpm` with PCR-12 set to the kernel hash unseals
  successfully; a `swtpm` with PCR-12 set to a different hash
  fails to unseal and the mount is rejected.

**Exit criterion.** A `swtpm` test that flips PCR-12 between
two kernel builds accepts the new key and rejects the old one.

### Track D.4 — Signed HBI image (Stage 3)

- The HBI image is signed by a build-time key; the kernel
  verifies the signature at boot.
- A tampered HBI image is rejected at boot with a precise
  error, not a panic.

**Exit criterion.** A `qemu-nvme-soak` with a signed HBI boots
green; the same soak with a single-byte-tampered HBI boots
red with a precise marker.

### Track D.5 — Secure boot chain (Stage 4)

- The boot loader verifies the kernel signature; the kernel
  verifies the init signature; the init verifies the
  DriverManager signature; the DriverManager verifies every
  DriverHost signature.
- A tampered binary at any layer prevents the next layer from
  loading.

**Exit criterion.** A `qemu-nvme-soak` with a fully signed
chain boots green; a tampered kernel, init, or DriverManager
fails the boot at the next layer.

### Track D.6 — Display surface hardening (landed as PR-G)

- `Syscall::FramebufferBlit` is gated on the `FrameDraw`
  capability; see `docs/FRAMEBUFFER_POLICY.md`.
- A future PR hardens `Syscall::FramebufferInfo` with the
  same pattern; that hardening is **not** part of this
  roadmap cycle.

### Track D.7 — Process manifest signature

- A `.cm` file is signed by the build-time key; the loader
  verifies the signature before granting the manifest's
  capability set.
- A tampered manifest is rejected with a precise error; the
  rest of the system keeps running.

**Exit criterion.** A `qemu-nvme-soak` with a signed manifest
boots green; a tampered manifest is rejected.

---

## Stage E — Operations

**Why this stage exists.** A production system needs runtime
knobs, observation surfaces, and soak coverage so an operator
can keep it healthy. The bones of this exist (`tools/`, the
soak harness, the bench harness); Stage E is about making them
production-grade.

### Track E.1 — Runtime knobs

- A `sysctl`-style syscall reads/writes a fixed set of runtime
  knobs (scrub frequency, recovery retry count, log verbosity).
- The kernel-side state lives in a `RuntimeKnobs` struct that
  is read-mostly and `Mutex`-guarded on writes.

**Exit criterion.** A user can change a knob at runtime and see
the effect in the on-target trace.

### Track E.2 — Structured observation

- A `sys_observation_read` syscall returns a `Vec<u8>` of
  structured records (boot, mount, recovery, error).
- The on-target trace is plain text; the structured records
  are an additional channel for off-target log aggregation.

**Exit criterion.** A `qemu-nvme-soak` with `OBSERVATION_DEST=`
produces a single log file with both the on-target text and
the structured records.

### Track E.3 — Long-haul soak

- A 24 h `qemu-nvme-soak` runs the on-target workload (terminal
  + doom) and records throughput, error counts, and recovery
  events.
- A flaky test fails the soak harness on a regression.

**Exit criterion.** A 24 h soak completes with the on-target
trace envelope green; a regression in any of throughput, error
counts, or recovery events fails the harness.

### Track E.4 — Reproducible benchmarks

- `tools/storage-bench.py` produces a JSON report of read /
  write / mixed throughput, sorted by compression policy and
  encryption policy.
- The numbers are stable across runs of the same commit; a
  >5% regression in any number fails the CI gate.

**Exit criterion.** The bench harness produces a JSON report
that is bit-identical across two runs of the same commit on the
same hardware; the report is small enough to attach to a PR.

---

## Stage F — Service foundation

**Why this stage exists.** A production filesystem is not a
host-test toy; it has to host a real workload. Stage F wires the
service layer that the userland actually depends on.

### Track F.1 — Hxblob minimal (no GC)

- A simple block object store with write-once semantics and
  fixed-capacity root; no refcount, no GC.
- An object handle is a `(bucket, offset, size)` triple; the
  bucket is a fixed-capacity array of objects.

**Exit criterion.** A host test that writes an Hxblob object
through the kernel interface, mounts the volume, and reads the
object back produces the same bytes.

### Track F.2 — Hxblob refcount

- Each object has a refcount; the refcount is updated on every
  handle open / close.
- An object with refcount 0 is reclaimable.

**Exit criterion.** A refcount regression test (close without
open, double-close, open after free) is rejected with a precise
error; the volume stays consistent.

### Track F.3 — Hxblob garbage collection

- A periodic GC pass walks the object graph and reclaims
  unreachable objects.
- A GC pass is journaled; a crash mid-GC is recoverable.

**Exit criterion.** A QEMU with a forced mid-GC crash
recovers to the same on-disk state as a clean GC pass.

### Track F.4 — Persistent service directory

- A persistent directory of service names and capabilities is
  stored on the system volume.
- The init process reads the directory at boot and starts the
  listed services.

**Exit criterion.** A `qemu-nvme-soak` with two custom services
in the directory starts both at boot; a tampered directory is
rejected.

### Track F.5 — hxfs-service production wiring

- `hxfs-service` is the production mount process; it holds the
  root volume's mount context and serves reads/writes to
  other processes.
- The service is a critical process; a crash halts the system
  with a precise trace.

**Exit criterion.** A 24 h soak with `hxfs-service` running
the system volume completes with the on-target trace envelope
green.

---

## Cross-stage invariants

A PR that lands a track must, before requesting review:

- `python3 tools/fmt-all.py --check` is green
- `python3 tools/check-safety-budget.py` is green
- `bash scripts/clippy.sh` is green (i.e. `cargo clippy
  --workspace --lib --bins -- -D warnings` plus the
  standalone userspace crates with build-time env)
- `cargo test -p huesos-hxfs --target x86_64-unknown-linux-gnu
  -Z build-std=` is green
- `qemu-nvme-soak` runs to completion (or to its 120 s
  timeout) with the on-target trace envelope green

A PR that lands a track must, in its commit message, name:

- the track ID (e.g. `Track A.3`)
- the exit criterion (in past tense — what is now true)
- any cross-track dependency (e.g. "depends on Track A.1
  landed as `hxfs-p3-mount-gate`")

A PR that lands a track must, in its body, list the on-target
trace markers the soak harness expects to see (or, for a PR
that does not touch the soak path, the CI markers that confirm
the build is still green).

## Open questions

- Stage B track 4 (`O_DIRECT`) is **deny-by-default** today.
  When the page cache lands, the policy will be reviewed.
  See `docs/STORAGE_NVME_FS_ROADMAP.md` for the deferred
  work.
- Stage D track 5 (secure boot chain) depends on Track D.4
  (signed HBI). The order is: signed HBI first, then
  secure boot chain on top of it.
- Stage F tracks 2 and 3 (refcount and GC) are interdependent;
  a single PR for both is acceptable if the diff is small
  enough to review, otherwise two PRs.

## See also

- `docs/STORAGE_NVME_FS_ROADMAP.md` — the versioned predecessor
  for Stages P and Q. Closed when P3 + Q3 land.
- `docs/ARCHITECTURE_ROADMAP.md` — the long-term HueOS component
  framework direction. Not replaced by this document; this
  document zooms in on the storage / security / operations
  slice needed to make the system deployable.
- `docs/FRAMEBUFFER_POLICY.md` — the capability-gated display
  surface (Track D.6). Closed.
- `docs/MICROKERNEL_MIGRATION.md` — the driver/userspace
  migration. Closed: every driver in the current tree is
  either a kernel platform service (PCI, HAL, IOAPIC, ACPI
  parser, framebuffer, ELF, PMM) or a userspace driver
  (NVMe, input). No further driver migrations are planned
  in this roadmap.
