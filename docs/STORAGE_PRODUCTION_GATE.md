# HuesOS Storage Production Gate

Status: **not production-ready / not format-frozen**.

This document is the Stage Z gate checklist. It deliberately does **not** mark
Hxfs v5 or the storage stack as production-ready. The current implementation is
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

(The second soak invocation is the Stage B.5 fault-injection gate:
seeded encrypted+compressed volume with a flipped GCM bit; the
trace must show `[hxfs] bad-gcm-tag-marked` and
`[hxfs] odirect-deny-ok` with the service still serving.)

Mandatory runtime/architecture gates still open:

```text
(none)
```

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

Current format: **Hxfs v5 foundation**.

Freeze status:

```text
v5 foundation schema: documented
v5 production freeze: not approved
storage production-ready: false
```

No code or documentation should claim storage production readiness until this
document is updated in an explicit owner-approved release commit.
