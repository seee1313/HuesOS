#!/usr/bin/env python3
"""Inspect an Hxfs v5 image and print root metadata as JSON."""

from __future__ import annotations

import argparse
from pathlib import Path

from hxfs_image import inspect_image, print_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    print_json(inspect_image(args.image))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
