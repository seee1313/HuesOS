#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
image="build/hxfs-migrate-v6-smoke.img"
mkdir -p build
python3 tools/mkhxfs.py --output "$image" --blocks 4096 >/dev/null
python3 - "$image" <<'PY'
import json
import subprocess
import sys

report = json.loads(subprocess.check_output([
    sys.executable, "tools/hxfs-inspect.py", sys.argv[1]
]))
assert report["superblock"]["format_version"] == 6, report["superblock"]
assert report["superblock"]["type_system_version"] == 6, report["superblock"]
PY

cargo run --quiet --manifest-path tools/hxfs-migrate/Cargo.toml \
    --target x86_64-unknown-linux-gnu -Z build-std= -- "$image" --commit
python3 - "$image" <<'PY'
import json
from pathlib import Path
import subprocess
import sys

report = json.loads(subprocess.check_output([
    sys.executable, "tools/hxfs-inspect.py", sys.argv[1]
]))
assert report["superblock"]["format_version"] == 7
assert report["superblock"]["type_system_version"] == 7
assert report["checkpoint_roots"]["encryption_policy_tree_lba"] != 0
assert report["checkpoint_roots"]["compression_policy_tree_lba"] != 0
print("HxFS v6 -> v7 migration smoke OK")
PY
