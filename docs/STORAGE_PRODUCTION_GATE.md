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
git diff --check
```

Mandatory storage gates:

```text
python3 tools/check-storage-production-gate.py
python3 tools/storage-bench.py --iterations 10
bash scripts/ci-qemu-nvme-soak.sh release 300
python3 tools/hxfs-scrub.py <installed-hxfs-image>
```

Mandatory runtime/architecture gates still open:

```text
QEMU NVMe high queue-depth soak
NVMe timeout/reset runtime path wired into driver-host-nvme
Hxfs fixed cache wired into hxfs-service
coherent writable mmap or explicit decision to keep writable mmap disabled
full allocator free-space reuse and reclaim
snapshot deletion reclaim through refcount/backref
BlobView native service operations
DriverManager package resolving from Hxblob
TPM/bootloader KeyProvider integration
no-heap Zstd backend audit or final rejection
full report-only scrub over every tree
separately reviewed repair policy before destructive fsck repair
```

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
