#!/usr/bin/env python3
"""Create a minimal Hxfs v5 development image.

Plain empty images are built in-process (memory-resident for small
images, sparse-streaming for large ones). A seeded image (an
encrypted + compressed volume with a `seed.bin` file, used by the
qemu-nvme soak) is delegated to the `huesos-hxfs-seed` Rust tool so
the on-disk format and the crypto are produced by the same code the
product uses — never reimplemented in Python.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from hxfs_image import build_empty_image, build_empty_image_stream


# Memory-resident builder is only used for tiny development images
# (loopback smoke, single-block unit tests). Anything bigger than this
# is built via the streaming variant so a developer or CI runner does
# not need to allocate the whole image in Python heap.
IN_MEMORY_BLOCK_LIMIT = 1024

# Seed mode defaults: 3.5 KiB compressible file (one extent) with
# the synthetic key context of huesos-hxfs/src/synthetic_key.rs.
SEED_DEFAULT_SIZE = 3584
SEED_FILE_NAME = "seed.bin"


def parse_uuid(text: str) -> bytes:
    cleaned = text.replace("-", "")
    raw = bytes.fromhex(cleaned)
    if len(raw) != 16:
        raise argparse.ArgumentTypeError("UUID must be 16 bytes / 32 hex chars")
    return raw


def run_seed_tool(args: argparse.Namespace) -> int:
    """Delegate a seeded image to the Rust hxfs-seed tool.

    Single source of truth for the v6-encrypted + compressed volume
    format: the tool uses the same FixedHxfsWriter and the same
    synthetic key module as the on-target service.
    """
    root = Path(__file__).resolve().parents[1]
    tool = root / "tools" / "hxfs-seed.sh"
    command = [
        str(tool),
        "--output",
        str(args.output),
        "--blocks",
        str(args.blocks),
        "--instance-uuid",
        args.instance_uuid.hex(),
        "--volume-uuid",
        args.volume_uuid.hex(),
        "--seed-file",
        args.seed_file,
        "--seed-size",
        str(args.seed_size),
    ]
    if args.inject_bad_gcm_tag:
        command.append("--inject-bad-gcm-tag")
    if args.inject_bad_crc:
        command.append("--inject-bad-crc")
    if args.seed_blob_file:
        command.append("--seed-blob-file")
        command.append(str(args.seed_blob_file))
    env = dict(os.environ)
    env.setdefault("PATH", os.defpath)
    result = subprocess.run(command, cwd=root, env=env, check=False)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Output image path")
    parser.add_argument("--blocks", type=int, default=256, help="Image size in 4 KiB blocks")
    parser.add_argument(
        "--instance-uuid",
        type=parse_uuid,
        default=bytes.fromhex("11111111111111111111111111111111"),
        help="Filesystem instance UUID as hex",
    )
    parser.add_argument(
        "--volume-uuid",
        type=parse_uuid,
        default=bytes.fromhex("22222222222222222222222222222222"),
        help="System virtual volume UUID as hex",
    )
    parser.add_argument(
        "--seed-file",
        type=str,
        default=None,
        help=f"Seed mode: file name written into the image (default {SEED_FILE_NAME})",
    )
    parser.add_argument(
        "--seed-size",
        type=int,
        default=SEED_DEFAULT_SIZE,
        help="Seed mode: seed file size in bytes (default 3584)",
    )
    parser.add_argument(
        "--inject-bad-gcm-tag",
        action="store_true",
        help="Seed mode: flip one bit in the seed file's first encrypted extent",
    )
    parser.add_argument(
        "--inject-bad-crc",
        action="store_true",
        help="Seed mode (plain volume): flip one byte of the seed file's first compressed payload",
    )
    parser.add_argument(
        "--seed-blob-file",
        type=Path,
        default=None,
        help="Seed mode: store this file (ELF/WAD) as an Hxblob object",
    )
    args = parser.parse_args()
    if args.seed_file is not None:
        return run_seed_tool(args)
    if args.blocks <= IN_MEMORY_BLOCK_LIMIT:
        image = build_empty_image(args.blocks, args.instance_uuid, args.volume_uuid)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(image)
        print(f"wrote {args.output} ({len(image)} bytes)")
    else:
        build_empty_image_stream(
            args.output, args.blocks, args.instance_uuid, args.volume_uuid
        )
        size_bytes = args.blocks * 4096
        print(f"wrote {args.output} ({size_bytes} bytes, streaming)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
