#!/usr/bin/env python3
"""Pack TPM2B_PUBLIC/TPM2B_PRIVATE into a signed-HBI sealed-key module."""

from __future__ import annotations

import argparse
from pathlib import Path

MAGIC = b"HSEALV1\0"
VERSION = 1
MAX_AREA = 1024


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent", required=True, type=lambda text: int(text, 0))
    parser.add_argument("--public", required=True, type=Path)
    parser.add_argument("--private", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    public = args.public.read_bytes()
    private = args.private.read_bytes()
    for name, area in (("public", public), ("private", private)):
        if len(area) < 3 or len(area) > MAX_AREA + 2:
            raise SystemExit(f"TPM2B {name} area is empty or exceeds 1024 payload bytes")
        declared = int.from_bytes(area[:2], "big")
        if declared == 0 or declared != len(area) - 2:
            raise SystemExit(
                f"TPM2B {name} size prefix {declared} does not match {len(area) - 2} bytes"
            )
    image = bytearray()
    image += MAGIC
    image += VERSION.to_bytes(4, "little")
    image += args.parent.to_bytes(4, "little")
    image += len(public).to_bytes(4, "little")
    image += len(private).to_bytes(4, "little")
    image += bytes(8)
    image += public
    image += private
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)
    print(f"sealed-key module: {args.output} ({len(image)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
