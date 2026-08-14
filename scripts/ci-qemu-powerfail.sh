#!/usr/bin/env bash
# Power-fail / crash-consistency gate for Hxfs on NVMe.
#
# What this proves
# ----------------
# Every other soak mode shuts the guest down politely (or lets
# timeout(1) kill an idle, quiesced system). That never exercises the
# case real machines actually hit: the power goes away in the middle
# of a write, with dirty data in the page cache, an open transaction
# and NVMe commands still in flight.
#
# The gate runs in three phases against ONE image:
#
#   1. CRASH    -- boot, wait for the guest to report it is writing,
#                  then SIGKILL QEMU. No flush, no unmount, no
#                  shutdown path. The image is left dirty on purpose.
#   2. OFFLINE  -- inspect the image from the host. The superblock and
#                  checkpoint roots must still be readable: a torn
#                  update that leaves no valid checkpoint at all is a
#                  format bug, not a recovery scenario.
#   3. RECOVER  -- boot the SAME image again and require a normal,
#                  unattended mount: self-check ok, fsck clean, scrub
#                  clean, and no panic. Recovery must not need an
#                  operator and must not silently mount a broken tree.
#
# The pass condition is deliberately strict. "It booted" is not
# enough -- an fsck that reports findings after a power cut means the
# committed state was not actually crash-consistent, and Hxfs commits
# via checkpoint precisely so that it is.
#
# Usage: scripts/ci-qemu-powerfail.sh [profile] [log-dir] [cycles]
set -euo pipefail

profile="${1:-debug}"
logdir="${2:-build}"
cycles="${3:-1}"
inject="${POWERFAIL_MODE:-4}"
img="${NVME_IMG:-build/nvme-powerfail.img}"

mkdir -p "$logdir"
export NVME_IMG="$img"

# Each cycle starts from a freshly seeded volume so a failure is
# always attributable to one crash, not to damage accumulated over
# several. Within a cycle the crash boot and the recovery boot share
# the image -- that sharing is the whole test.
overall=0
for cycle in $(seq 1 "$cycles"); do
    crash_log="$logdir/powerfail-${cycle}-crash.log"
    recover_log="$logdir/powerfail-${cycle}-recover.log"

    echo "=== power-fail cycle ${cycle}/${cycles} (mode=${inject}, profile=${profile}) ==="
    rm -f "$img" "$img.mode"

    # Phase 1: crash. Kill shortly after the guest confirms the write
    # path is live, so the kill lands inside the 16 MiB stage rather
    # than on a quiescent volume.
    echo "--- phase 1: crash boot"
    SOAK_KILL_AFTER="${POWERFAIL_MARKER:-[hxfs] write-roundtrip-ok}" \
    SOAK_KILL_DELAY="${POWERFAIL_DELAY:-3}" \
        bash scripts/ci-qemu-nvme-soak.sh "$profile" 240 "$crash_log" "$inject"

    # Phase 2: offline inspection. hxfs-scrub exits 1 when it finds
    # something; "needs journal replay" is a legitimate post-crash
    # state, so it is reported but not failed on here -- phase 3 is
    # what decides whether recovery actually works.
    echo "--- phase 2: offline image inspection"
    set +e
    scrub_out="$(python3 tools/hxfs-scrub.py "$img" 2>&1)"
    scrub_status=$?
    set -e
    echo "$scrub_out"
    if grep -q '"kind": "bad_feature_set"' <<<"$scrub_out"; then
        echo "[powerfail] superblock feature set destroyed by the crash" >&2
        overall=1
        continue
    fi
    if [[ "$scrub_status" != 0 && "$scrub_status" != 1 ]]; then
        echo "[powerfail] image is unreadable after the crash" >&2
        overall=1
        continue
    fi

    # Phase 3: recovery boot on the same image. The soak harness
    # reuses an image whose .mode marker matches, so this boot sees
    # exactly the bytes the crash left behind.
    echo "--- phase 3: recovery boot"
    set +e
    bash scripts/ci-qemu-nvme-soak.sh "$profile" 180 "$recover_log" "$inject"
    recover_status=$?
    set -e
    if [[ "$recover_status" != 0 ]]; then
        echo "[powerfail] cycle ${cycle}: recovery boot FAILED" >&2
        overall=1
        continue
    fi
    # The soak harness already asserts self-check/fsck/scrub markers
    # for this mode. Re-assert the two that define crash consistency
    # so the intent is visible in this script and a future change to
    # the mode's marker list cannot quietly weaken the gate.
    for marker in "[hxfs] self-check ok" "[hxfs] fsck clean" "[hxfs] scrub complete"; do
        if ! grep -Fq "$marker" "$recover_log"; then
            echo "[powerfail] cycle ${cycle}: missing '$marker' after recovery" >&2
            overall=1
        fi
    done
    if grep -Fq "[hxfs] fsck findings" "$recover_log"; then
        echo "[powerfail] cycle ${cycle}: fsck reported findings after recovery" >&2
        grep -F "[hxfs] fsck findings" "$recover_log" >&2
        overall=1
    fi
    if [[ "$overall" == 0 ]]; then
        echo "[powerfail] cycle ${cycle}: clean recovery"
    fi
done

if [[ "$overall" != 0 ]]; then
    echo "[powerfail] GATE FAILED" >&2
    exit 1
fi
echo "[powerfail] gate passed: ${cycles} crash/recovery cycle(s), every recovery clean"
