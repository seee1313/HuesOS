#!/usr/bin/env bash
# Long-duration soak runner (Stage E production polish).
#
# GitHub Actions caps jobs at 6 h, so a literal 24 h CI job is not
# possible; this runner performs `cycles` full soak passes (each
# pass = gcm-inject + stress + shutdown-cycle) and can be driven to
# any wall-clock duration locally:
#
#   bash scripts/soak-long.sh 12    # 12 passes (~1-2 h each locally)
#
# On CI we run a bounded 2 h job (qemu-nvme-long-soak) as the
# practical gate; the full 24 h run is an operator-triggered local
# gate (documented in PRODUCTION_ROADMAP Stage E).
set -euo pipefail

CYCLES="${1:-1}"
PROFILE="${2:-release}"
LOG_DIR="${3:-build/long-soak}"

mkdir -p "$LOG_DIR"
total=0
failed=0
for ((i = 1; i <= CYCLES; i++)); do
  echo "== long-soak pass $i/$CYCLES =="
  for mode in 1 4 3; do
    log="$LOG_DIR/pass${i}-mode${mode}.log"
    if bash scripts/ci-qemu-nvme-soak.sh "$PROFILE" 150 "$log" "$mode" >/tmp/long-soak-pass.out 2>&1; then
      echo "  pass $i mode $mode: OK"
      total=$((total + 1))
    else
      echo "  pass $i mode $mode: FAILED (see $log)"
      failed=$((failed + 1))
    fi
  done
done
echo "== long-soak done: $total ok, $failed failed =="
test "$failed" -eq 0
