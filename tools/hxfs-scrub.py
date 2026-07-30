#!/usr/bin/env python3
"""Report-only Hxfs image scrub for root/checkpoint metadata."""

from __future__ import annotations

import argparse
from pathlib import Path

from hxfs_image import BASE_INCOMPAT_FEATURES, inspect_image, print_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    report = inspect_image(args.image)
    findings: list[dict[str, object]] = []
    features = int(report["superblock"]["incompatible_features"])
    if features & BASE_INCOMPAT_FEATURES != BASE_INCOMPAT_FEATURES:
        findings.append({"kind": "bad_feature_set", "features": features})
    if int(report["superblock"]["root_state"]) != 1:
        findings.append({"kind": "needs_journal_replay"})
    roots = report["checkpoint_roots"]
    if int(roots["volume_table_lba"]) == 0:
        findings.append({"kind": "missing_root", "root": "volume_table"})
    print_json({"image": str(args.image), "findings": findings, "clean": not findings})
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
