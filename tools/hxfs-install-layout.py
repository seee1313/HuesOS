#!/usr/bin/env python3
"""Emit a HuesOS BOOTFS + Hxfs virtual-volume install layout plan."""

from __future__ import annotations

import argparse
import json


GIB = 1024 * 1024 * 1024
BLOCK = 4096


def blocks(bytes_value: int) -> int:
    return (bytes_value + BLOCK - 1) // BLOCK


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk-gib", type=int, default=16)
    parser.add_argument("--bootfs-mib", type=int, default=128)
    args = parser.parse_args()
    disk_blocks = blocks(args.disk_gib * GIB)
    bootfs_blocks = blocks(args.bootfs_mib * 1024 * 1024)
    hxfs_start = 2048 + bootfs_blocks
    hxfs_blocks = max(0, disk_blocks - hxfs_start - 33)
    plan = {
        "block_size": BLOCK,
        "disk_blocks": disk_blocks,
        "partitions": [
            {
                "name": "BOOTFS",
                "start_lba": 2048,
                "block_count": bootfs_blocks,
                "role": "immutable boot/recovery fallback",
            },
            {
                "name": "HXFS",
                "start_lba": hxfs_start,
                "block_count": hxfs_blocks,
                "role": "primary Hxfs physical volume",
                "virtual_volumes": [
                    {"role": "system", "uuid_hint": "found by boot metadata + Hxfs volume table"},
                    {"role": "user-home", "uuid_hint": "independent user data volume"},
                    {"role": "hxblob", "uuid_hint": "immutable package/blob volume"},
                ],
            },
        ],
    }
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
