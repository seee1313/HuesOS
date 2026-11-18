#!/usr/bin/env bash
# Crash KeyBroker after generation one and prove both sides of the lifecycle:
# the already-mounted encrypted HxFS keeps using its derived keys, while the
# next generation cannot obtain the master key before reboot.
set -euo pipefail
profile="${1:-debug}"
seconds="${2:-180}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
log="$artifact_dir/qemu-key-broker-fail-${profile}.log"
rm -f build/nvme-soak.img build/nvme-soak.img.mode "$log"
HUESOS_KEY_BROKER_FEATURES=fail-after-first-grant \
NVME_IMG_SIZE="${NVME_IMG_SIZE:-512M}" \
    bash scripts/ci-qemu-nvme-soak.sh "$profile" "$seconds" "$log" 4
grep -Fq '[key-broker] injected post-grant exit; future generations denied until reboot' "$log"
grep -Fq '[hxfs] accepted generation-bound key grant 1 (key)' "$log"
grep -Fq '[hxfs] self-check ok' "$log"
grep -Fq '[hxfs] write-roundtrip-ok' "$log"
grep -Fq '[driver-manager] Hxfs service ready' "$log"
grep -Fq '[driver-manager] new encrypted Hxfs generation 2 denied after KeyBroker exit' "$log"
! grep -Fq 'KeyBroker crash probe FAILED' "$log"
echo "KeyBroker fail-closed lifecycle smoke passed: generation 1 survived; generation 2 denied"
