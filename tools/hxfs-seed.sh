#!/usr/bin/env bash
# Run the hxfs-seed host tool with the host target pinned.
#
# The repo-root .cargo/config.toml forces the freestanding kernel
# target for every cargo invocation under the repo root; the seed
# tool is a std host program, so the target and build-std must be
# overridden explicitly (same pattern as `make test`).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

exec cargo run --quiet --manifest-path "$ROOT/tools/hxfs-seed/Cargo.toml" \
    --target x86_64-unknown-linux-gnu -Z build-std= -- "$@"
