#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
image="build/hxfs-migrate-v5-smoke.img"
mkdir -p build
python3 tools/mkhxfs.py --output "$image" --blocks 4096 >/dev/null
python3 - "$image" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, "tools")
from hxfs_image import BLOCK_SIZE, metadata_crc32c

path = Path(sys.argv[1])
with path.open("r+b") as handle:
    block = bytearray(handle.read(BLOCK_SIZE))
    block[56:60] = (5).to_bytes(4, "little")
    block[60:64] = (5).to_bytes(4, "little")
    features = int.from_bytes(block[144:152], "little") & ~(1 << 8)
    block[144:152] = features.to_bytes(8, "little")
    block[32:36] = b"\0" * 4
    block[32:36] = metadata_crc32c(block).to_bytes(4, "little")
    handle.seek(0)
    handle.write(block)
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
assert report["superblock"]["format_version"] == 6
assert report["superblock"]["type_system_version"] == 6
assert report["checkpoint_roots"]["encryption_policy_tree_lba"] != 0
assert report["checkpoint_roots"]["compression_policy_tree_lba"] != 0
print("HxFS v5 -> v6 migration smoke OK")
PY
