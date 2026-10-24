#!/usr/bin/env python3
"""Create a current-format HxFS image, or an explicit legacy-v6 fixture.

Current empty and seeded images are published by the Rust FixedHxfsWriter.
Only --legacy-v6 uses the frozen Python bootstrap builders, for migration tests.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from hxfs_image import build_legacy_v6_image, build_legacy_v6_image_stream


# The legacy-only memory-resident builder is used for tiny fixtures
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
    """Delegate current empty or seeded generation to the Rust image tool.

    Single source of truth for the current encrypted + compressed volume
    format: the tool uses the same FixedHxfsWriter and the same
    synthetic key module as the on-target service.
    """
    root = Path(__file__).resolve().parents[1]
    tool = root / "tools" / "hxfs-seed.sh"
    command = [
        "bash",
        str(tool),
        "--output",
        str(args.output),
        "--blocks",
        str(args.blocks),
        "--instance-uuid",
        args.instance_uuid.hex(),
        "--volume-uuid",
        args.volume_uuid.hex(),
    ]
    if args.seed_file is None:
        command.append("--empty")
    else:
        seed_size = SEED_DEFAULT_SIZE if args.seed_size is None else args.seed_size
        command.extend(["--seed-file", args.seed_file, "--seed-size", str(seed_size)])
    if args.inject_bad_gcm_tag:
        command.append("--inject-bad-gcm-tag")
    if args.inject_bad_crc:
        command.append("--inject-bad-crc")
    if args.plain:
        command.append("--plain")
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
        default=None,
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
        "--plain",
        action="store_true",
        help="Seed mode: build a clean unencrypted volume (no-TPM gate)",
    )
    parser.add_argument(
        "--seed-blob-file",
        type=Path,
        default=None,
        help="Seed mode: store this file (ELF/WAD) as an Hxblob object",
    )
    parser.add_argument(
        "--legacy-v6", action="store_true",
        help="Create a read-only legacy v6 fixture for explicit migration tests",
    )
    args = parser.parse_args()
    if not 8 <= args.blocks <= (2**63 - 1) // 4096:
        parser.error("--blocks must describe an image of at least 8 blocks within host file limits")
    seed_options = (
        args.seed_size is not None or args.inject_bad_gcm_tag
        or args.inject_bad_crc or args.plain or args.seed_blob_file is not None
    )
    if args.seed_file is None and seed_options:
        parser.error("seed options require --seed-file")
    if args.legacy_v6 and args.seed_file is not None:
        parser.error("--legacy-v6 cannot be combined with seeded generation")
    # Build next to the destination and publish only after successful formatting.
    # A small/invalid image must not truncate an existing disk image.
    destination = args.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".mkhxfs-", dir=destination.parent)
    os.close(fd)
    args.output = Path(temporary)
    try:
        if args.legacy_v6:
            if args.blocks <= IN_MEMORY_BLOCK_LIMIT:
                args.output.write_bytes(build_legacy_v6_image(
                    args.blocks, args.instance_uuid, args.volume_uuid,
                ))
            else:
                build_legacy_v6_image_stream(
                    args.output, args.blocks, args.instance_uuid, args.volume_uuid,
                )
        else:
            status = run_seed_tool(args)
            if status:
                return status
        os.replace(args.output, destination)
        print(f"wrote {destination} ({args.blocks * 4096} bytes)")
    finally:
        args.output.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
