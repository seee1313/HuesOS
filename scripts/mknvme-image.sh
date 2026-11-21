#!/usr/bin/env bash
# Create the NVMe disk image the interactive `make run` boots with.
#
# The image is a plain GPT disk: protective MBR, a single HxFS v7 partition
# that fills it, and a backup GPT in the tail. It is what `lsblk`, `df`,
# `fdisk`, `mkfs` and `fsck` operate on when the OS runs with storage, so the
# default boot is not a diskless one.
#
# Usage: scripts/mknvme-image.sh [size] [output]
#   size    disk size, e.g. 96M (default), 200G, 1T; a bare number is MiB
#   output  image path (default build/nvme.img)
#
# Set HUESOS_NVME_FORCE=1 to rebuild an image that already exists.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

size="${1:-${HUESOS_NVME_SIZE:-96M}}"
output="${2:-${HUESOS_NVME_IMAGE:-build/nvme.img}}"

# Normalise to 4 KiB blocks. `200G`/`1T` produce a sparse file, so a large
# disk costs nothing on the host; only the GPT head and tail are materialised.
case "$size" in
    *[Kk]) bytes=$(( ${size%[Kk]} * 1024 )) ;;
    *[Mm]|'') bytes=$(( ${size%[Mm]} * 1024 * 1024 )) ;;
    *[Gg]) bytes=$(( ${size%[Gg]} * 1024 * 1024 * 1024 )) ;;
    *[Tt]) bytes=$(( ${size%[Tt]} * 1024 * 1024 * 1024 * 1024 )) ;;
    *) echo "mknvme-image: unsupported size '$size'" >&2; exit 2 ;;
esac
blocks=$(( bytes / 4096 ))
if (( blocks < 128 )); then
    echo "mknvme-image: '$size' is too small for a GPT + HxFS disk (need >= 512 KiB)" >&2
    exit 2
fi

stamp="$output.stamp"
if [[ -f "$output" && -f "$stamp" && "${HUESOS_NVME_FORCE:-0}" != "1" ]]; then
    if [[ "$(cat "$stamp")" == "$blocks" ]]; then
        echo "[nvme] reusing $output (${blocks} x 4 KiB blocks)"
        exit 0
    fi
fi

mkdir -p "$(dirname "$output")"
rm -f "$output"
echo "[nvme] creating $output: GPT + HxFS v7, ${blocks} x 4 KiB blocks"
python3 tools/mkhxfs.py --output "$output" --blocks "$blocks" --gpt
printf '%s\n' "$blocks" > "$stamp"
