#!/usr/bin/env python3
"""Report HuesOS Rust safety and panic-surface metrics.

This tool is intentionally dependency-free so CI and reviewers can run it on a
fresh checkout. It does not claim that counting `unsafe` proves safety; it makes
changes to the audited surface visible and lists locations for manual review.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

PATTERNS = {
    "unsafe_blocks": re.compile(r"\bunsafe\s*\{"),
    "unsafe_functions": re.compile(r"\bunsafe\s+fn\b"),
    "unsafe_impls": re.compile(r"\bunsafe\s+impl\b"),
    "unwrap_calls": re.compile(r"\.unwrap\s*\("),
    "expect_calls": re.compile(r"\.expect\s*\("),
    "panic_macros": re.compile(r"\bpanic!\s*\("),
    "todo_markers": re.compile(r"\b(?:TODO|FIXME|HACK)\b"),
}


def rust_files(root: Path) -> list[Path]:
    return sorted(path for path in (root / "crates").rglob("*.rs") if "target" not in path.parts)


def audit(root: Path) -> dict[str, object]:
    totals: Counter[str] = Counter()
    unsafe_by_file: dict[str, int] = {}
    lines = 0
    files = rust_files(root)
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines += len(text.splitlines())
        counts = {name: len(pattern.findall(text)) for name, pattern in PATTERNS.items()}
        totals.update(counts)
        unsafe_total = counts["unsafe_blocks"] + counts["unsafe_functions"] + counts["unsafe_impls"]
        if unsafe_total:
            unsafe_by_file[str(path.relative_to(root))] = unsafe_total
    return {
        "rust_files": len(files),
        "rust_lines": lines,
        "totals": dict(totals),
        "unsafe_by_file": dict(sorted(unsafe_by_file.items(), key=lambda item: (-item[1], item[0]))),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    report = audit(args.root.resolve())
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"Rust files: {report['rust_files']}")
    print(f"Rust lines: {report['rust_lines']}")
    for name, count in report["totals"].items():
        print(f"{name}: {count}")
    print("\nUnsafe surface by file:")
    for path, count in report["unsafe_by_file"].items():
        print(f"{count:4}  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
