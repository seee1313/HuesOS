#!/usr/bin/env bash
# Generate HuesOS Boot Image (HBI) using hbi-gen.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PROFILE="${1:-debug}"
KERNEL="target/x86_64-huesos/${PROFILE}/huesos-boot"
OUTPUT_DIR="build"
OUTPUT_HBI="${OUTPUT_DIR}/huesos.hbi"

mkdir -p "${OUTPUT_DIR}"

# 1. Compile hbi-gen
echo "[HBI] Building hbi-gen..."
if [ -f ".cargo/config.toml" ]; then
    mv .cargo/config.toml .cargo/config.toml.bak
fi

# Always restore config.toml even if compilation fails
trap 'if [ -f ".cargo/config.toml.bak" ]; then mv .cargo/config.toml.bak .cargo/config.toml; fi' EXIT

cargo build --manifest-path tools/hbi-gen/Cargo.toml --target x86_64-unknown-linux-gnu --release

if [ -f ".cargo/config.toml.bak" ]; then
    mv .cargo/config.toml.bak .cargo/config.toml
fi

# 2. Locate generated bootfs
echo "[HBI] Locating bootfs..."
BOOTFS_PATH=$(find target -name "huesos.bootfs" | head -n 1)

if [ -z "${BOOTFS_PATH}" ] || [ ! -f "${BOOTFS_PATH}" ]; then
    echo "error: bootfs not found. Run 'make build' first." >&2
    exit 1
fi

# 3. Create cmdline and platform dummy files if they don't exist
CMDLINE_TXT="${OUTPUT_DIR}/cmdline.txt"
if [ ! -f "${CMDLINE_TXT}" ]; then
    echo "init_args=foo" > "${CMDLINE_TXT}"
fi

PLATFORM_BIN="${OUTPUT_DIR}/platform.bin"
if [ ! -f "${PLATFORM_BIN}" ]; then
    echo -n -e "\x01\x02\x03\x04" > "${PLATFORM_BIN}"
fi

# 4. Run hbi-gen
echo "[HBI] Generating HBI image at ${OUTPUT_HBI}..."
./tools/hbi-gen/target/x86_64-unknown-linux-gnu/release/hbi-gen \
    --kernel "${KERNEL}" \
    --bootfs "${BOOTFS_PATH}" \
    --cmdline "${CMDLINE_TXT}" \
    --platform "${PLATFORM_BIN}" \
    --output "${OUTPUT_HBI}"

echo "[HBI] Done!"
