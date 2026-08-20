# HuesOS Storage Production Gate

Status: **not production-ready / not format-frozen**.

This document is the Stage Z gate checklist. It deliberately does **not** mark
HxFS v6 or the storage stack as production-ready. The current implementation is
a strong production-oriented foundation, but several runtime gates remain.

## Required gates before production-ready

Mandatory static gates:

```text
python3 tools/fmt-all.py --check
CARGO_BUILD_JOBS=1 make clippy
CARGO_BUILD_JOBS=1 make test
python3 tools/check-safety-budget.py
python3 tools/check-lock-policy.py
python3 tools/check-policy-crates.py
python3 tools/check-hues-async-noalloc.py
python3 tools/check-huesos-object-lock-policy.py
python3 tools/check-poll-budgets.py
git diff --check
```

Mandatory storage gates:

```text
python3 tools/check-storage-production-gate.py
python3 tools/storage-bench.py --iterations 10
bash scripts/ci-qemu-nvme-soak.sh release 300
bash scripts/ci-qemu-nvme-soak.sh release 300 /tmp/qemu-nvme-gcm-inject.log 1
python3 tools/hxfs-scrub.py <installed-hxfs-image>
bash scripts/ci-qemu-nvme-soak.sh release 180 /tmp/qemu-nvme-no-tpm.log 6
bash scripts/ci-qemu-powerfail.sh release ci-artifacts 2
```

(Mode 6 is the no-TPM gate: a plain volume on a machine with no TPM
and no key must mount and serve normally. Most real hardware looks
like this, so a build that only mounts when a key is available would
refuse to boot on it.)

(`ci-qemu-powerfail.sh` is the crash-consistency gate: SIGKILL QEMU
mid-write, inspect the dirty image offline, then require the same
image to boot again unattended with `fsck clean` and `scrub complete`.
An fsck finding after a power cut means the committed state was not
crash-consistent. The kill instant is randomised per cycle so the gate
samples different interleavings -- mid-checkpoint, between journal
write and superblock update -- rather than re-proving one of them. The
seed is printed on every run and forced with `POWERFAIL_SEED=<seed>`,
so a failure is replayable instead of being written off as flake.)

### Checkpoint journal geometry invariant

`FixedHxfsWriter` plans the target area and journal as one checked
transaction shape. The declared record count must equal the number of
records actually emitted; a cursor reserves the declared last slot for
the `FINAL_SUPERBLOCK` record and refuses both early finalization and
extra records. The actual LBA layout is compared with the planned target
and total spans before any journal record is emitted.

This is a correctness boundary, not bookkeeping. The previous handwritten
counts omitted the Hxblob index and Merkle records when the `hxblob` feature
was enabled. A clean checkpoint appeared healthy, but a power loss after the
`RECOVERING` root became durable made replay stop at the Merkle record and
return `BadJournal`. The same handwritten layout also under-reserved reclaimed
transaction space and counted allocation/refcount/backref leaves both as an
early gap and at their real positions.

Host regressions now cut the final clean-superblock write after the recovering
root has been flushed, replay the resulting image, remount it, and verify both
a plain file and an Hxblob payload. The Hxblob case crosses the single-leaf
index capacity so root-plus-leaves geometry is covered. This focused host proof
complements, but does not replace, the QEMU power-fail gate above.

### Atomic checkpoint publication boundary

Hxfs uses the strict old-before-`RECOVERING` contract. Copy-on-write targets and
all journal metadata/data copies are written and flushed while LBA 0 remains the
old clean root. The new clean superblock is present only as the final journal
payload at this stage; it is deliberately not applied through the ordinary
target-write path. Publication order is:

```text
write fresh COW targets + complete journal (final clean root is journal data only)
flush
write RECOVERING root pointing to the old checkpoint and complete journal
flush
write new CLEAN root
flush
```

Therefore a failure before the `RECOVERING` write leaves the old version
reachable. A persisted `RECOVERING` root replays to the complete new version,
and a persisted new clean root exposes the complete new version directly. A
host crash matrix fails before every individual checkpoint write and flush,
then replays/remounts the resulting image and requires one complete version:
unchanged file plus either all old mutations or all new mutations, never a
mixture. A separate root-write trace requires the only publication sequence to
be exactly `RECOVERING -> CLEAN`; the historical premature `CLEAN -> RECOVERING
-> CLEAN` sequence is rejected.

(The second soak invocation is the Stage B.5 fault-injection gate:
seeded encrypted+compressed volume with a flipped GCM bit; the
trace must show `[hxfs] bad-gcm-tag-marked` and
`[hxfs] odirect-deny-ok` with the service still serving.)

Mandatory release-approval gates still open:

```text
independent security review of KeyBroker and HxFS v6
owner-approved HxFS v6 format freeze
two-vendor disposable-NVMe bare-metal matrix
real-hardware TPM PCR success/mismatch evidence
```

These cannot be closed by QEMU or by the author reviewing their own PR.

Closed since the last revision:

```text
full allocator free-space reuse and reclaim
QEMU NVMe high queue-depth soak
NVMe timeout/reset runtime path wired into driver-host-nvme
Hxfs fixed cache wired into hxfs-service
coherent writable mmap or explicit decision to keep writable mmap disabled
snapshot deletion reclaim through refcount/backref
BlobView native service operations
DriverManager package resolving from Hxblob
TPM/bootloader KeyProvider integration
no-heap Zstd backend audit or final rejection
full report-only scrub over every tree
separately reviewed repair policy before destructive fsck repair
```

Two of those close as reasoned rejections rather than
implementations, each with an ADR that states what would have to
change for the answer to differ:

* coherent writable mmap -- `docs/design/ADR_WRITABLE_MMAP.md`
* no-heap Zstd backend -- `docs/design/ADR_ZSTD_BACKEND.md`

Evidence for the runtime gates is the on-target trace, not a host
unit test. Under the queue-depth soak with error injection
(`scripts/ci-qemu-nvme-soak.sh <profile> 300 <log> 5`), on both the
debug and release profiles:

```text
[driver-host:nvme] telemetry submitted=20479 completed=20479
  timeouts=0 resets=0 queue-full=0 state=Online
[hxfs] page-cache slots=256 repeat-read-hits=1
[hxfs] blob-view-native-ok bytes=204
[hxfs] tree-scrub complete (6 blocks, 0 errors)
[hxfs] fsck clean (8 checks)
[tpm] TPM present, no sealed volume key in this image
[driver-manager] package-resolve-ok bytes=52 hash=ff0bb32e86c6b311
```

Closing these gates does NOT by itself make storage production
ready: the freeze flags below are unchanged and remain the owner's
call.

Freed data blocks and retired checkpoint metadata regions are both
returned to the allocator and handed out again, so physical usage on a
create/delete workload settles into a fixed band instead of growing
without bound. Blocks are quarantined until the checkpoint that
released them is durable, and the free pool is rebuilt from the live
extent table at mount rather than persisted, so a crash leaks space at
worst and never leases out a referenced block. Reuse is made safe on
encrypted volumes by binding the AEAD nonce to a per-block generation
(`docs/design/EXTENT_GENERATION_NONCE.md`).

Snapshot deletion reclaim is now closed on top of that work: a
refcount barrier consults the snapshot refcount tree before any
extent range is returned to the allocator, so a block referenced by
a snapshot is never handed out while that snapshot lives.

## Format status

Current format: **HxFS v6 foundation** (v5 read-only; explicit migration).

Freeze status:

```text
v5 foundation schema: documented
v5 production freeze: not approved
storage production-ready: false
```

No code or documentation should claim storage production readiness until this
document is updated in an explicit owner-approved release commit.
