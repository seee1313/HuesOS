#!/usr/bin/env bash
# Run the hxfs-seed host tool with the host target pinned.
#
# The repo-root .cargo/config.toml forces the freestanding kernel
# target for every cargo invocation under the repo root; the seed
# tool is a std host program, so the host target is pinned explicitly
# (same pattern as `make test`).  The toolchain ships a precompiled
# std for x86_64-unknown-linux-gnu, so no `-Z build-std` is needed --
# and asking for one would rebuild std from source, which a vendored
# build cannot do without std's own crate graph on disk.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$HOME/.cargo/bin:$PATH"

exec cargo run --quiet --manifest-path "$ROOT/tools/hxfs-seed/Cargo.toml" \
    --bin huesos-hxfs-seed --target x86_64-unknown-linux-gnu -- "$@"
