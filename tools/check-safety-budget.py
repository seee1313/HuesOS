#!/usr/bin/env python3
"""Reject growth of HuesOS unsafe and panic-prone Rust surface."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

REGRESSION_KEYS = (
    "unsafe_blocks",
    "unsafe_functions",
    "unsafe_impls",
    "static_mut",
    "unwrap_calls",
    "expect_calls",
    "panic_macros",
)


def load_auditor(root: Path):
    path = root / "tools" / "audit-safety.py"
    spec = importlib.util.spec_from_file_location("huesos_audit_safety", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--baseline", type=Path, default=Path("safety-budget.json"))
    args = parser.parse_args()
    root = args.root.resolve()
    baseline_path = args.baseline if args.baseline.is_absolute() else root / args.baseline
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = load_auditor(root).audit(root)

    failures: list[str] = []
    expected_totals = baseline["totals"]
    current_totals = current["totals"]
    for key in REGRESSION_KEYS:
        expected = int(expected_totals.get(key, 0))
        actual = int(current_totals.get(key, 0))
        if actual > expected:
            failures.append(f"{key}: {actual} exceeds budget {expected}")

    expected_files = baseline["unsafe_by_file"]
    current_files = current["unsafe_by_file"]
    for path, actual_value in current_files.items():
        actual = int(actual_value)
        expected = int(expected_files.get(path, 0))
        if actual > expected:
            failures.append(f"{path}: unsafe surface {actual} exceeds budget {expected}")

    if failures:
        print("Safety regression budget failed:")
        for failure in failures:
            print(f"  - {failure}")
        print("Reduce the surface or update the audited baseline in a dedicated review.")
        return 1

    print("Safety regression budget OK")
    for key in REGRESSION_KEYS:
        print(f"  {key}: {current_totals.get(key, 0)}/{expected_totals.get(key, 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
