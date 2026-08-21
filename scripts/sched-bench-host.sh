#!/usr/bin/env bash
# Host-side Scheduler v2 benchmark/verification harness.
#
# Runs the full huesos-sched policy suite (invariant + randomized tests),
# the kernel scheduler host tests, and prints an aggregate summary that can
# be attached to PRs as host evidence. This is NOT bare-metal evidence; see
# docs/BARE_METAL_SECURITY_EVIDENCE.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="$HOME/.cargo/bin:$PATH"

echo "== huesos-sched policy suite =="
cargo test --target x86_64-unknown-linux-gnu -p huesos-sched 2>&1 | \
    grep -E "^test result|running [0-9]+ tests" | head -4

echo
echo "== kernel scheduler host tests =="
cargo test --target x86_64-unknown-linux-gnu -p huesos-kernel scheduler --no-fail-fast 2>&1 | \
    grep -E "^test result" | head -2

echo
echo "== gates =="
python3 tools/check-safety-budget.py
python3 tools/check-policy-crates.py
python3 tools/fmt-all.py --check >/dev/null 2>&1 && echo "fmt: OK"

echo
echo "== git head =="
git rev-parse HEAD
echo "host benchmark complete"
