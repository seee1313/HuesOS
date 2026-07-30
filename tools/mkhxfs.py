#!/usr/bin/env python3
"""Create a minimal Hxfs v5 development image."""

from __future__ import annotations

import argparse
from pathlib import Path

from hxfs_image import build_empty_image


def parse_uuid(text: str) -> bytes:
    cleaned = text.replace("-", "")
    raw = bytes.fromhex(cleaned)
    if len(raw) != 16:
        raise argparse.ArgumentTypeError("UUID must be 16 bytes / 32 hex chars")
    return raw


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
    args = parser.parse_args()
    image = build_empty_image(args.blocks, args.instance_uuid, args.volume_uuid)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)
    print(f"wrote {args.output} ({len(image)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
