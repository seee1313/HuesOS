#!/usr/bin/env python3
"""Reject heap allocation in the hues-async executor crate.

Project rule (HuesOS Dev, PR #4): `crates/hues-async/**` must remain strictly
allocation-free. The executor stores futures inline in a fixed-capacity table,
uses a `u64` ready bitmask, and a pointer-based no-alloc waker. Any of the
identifiers below (or an `alloc` import) implies a heap and defeats the design.

The rule applies to production and test code alike: `#[cfg(test)]` blocks
inside hues-async also count. Tests that need collections belong in a
downstream crate or must be reworked to use fixed-size arrays.

This gate is dependency-free so CI and reviewers can run it on a fresh
checkout. It scans the raw text of every .rs file under `crates/hues-async/`.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CRATE_ROOT = "crates/hues-async"

# Each rule is (name, compiled regex, short reason). Order is stable so the
# output for CI reviewers is deterministic.
#
# We match on identifiers with word boundaries where possible so, e.g.,
# `MyString` inside hues-async will not trigger the `String` rule and a
# variable named `stringly_typed` will not trigger it either. Type
# constructors are matched with a trailing `<` to avoid catching an
# identifier that merely *ends* in `Box`.
FORBIDDEN = [
    ("use alloc",          re.compile(r"\buse\s+alloc\b"),                    "alloc crate import"),
    ("extern crate alloc", re.compile(r"\bextern\s+crate\s+alloc\b"),         "alloc crate import"),
    ("alloc::",            re.compile(r"\balloc\s*::"),                       "alloc:: path"),
    ("Box<",               re.compile(r"\bBox\s*<"),                          "heap-owning smart pointer"),
    ("Vec<",               re.compile(r"\bVec\s*<"),                          "growable heap collection"),
    ("Vec::",              re.compile(r"\bVec\s*::"),                         "growable heap collection"),
    ("String",             re.compile(r"\bString\b"),                         "heap-backed string"),
    ("Arc<",               re.compile(r"\bArc\s*<"),                          "atomic ref-counted heap pointer"),
    ("Rc<",                re.compile(r"\bRc\s*<"),                           "ref-counted heap pointer"),
    ("Weak<",              re.compile(r"\bWeak\s*<"),                         "companion of Arc/Rc"),
    ("BTreeMap",           re.compile(r"\bBTreeMap\b"),                       "heap-backed map"),
    ("BTreeSet",           re.compile(r"\bBTreeSet\b"),                       "heap-backed set"),
    ("HashMap",            re.compile(r"\bHashMap\b"),                        "heap-backed map"),
    ("HashSet",            re.compile(r"\bHashSet\b"),                        "heap-backed set"),
    ("VecDeque",           re.compile(r"\bVecDeque\b"),                       "heap-backed deque"),
    ("LinkedList",         re.compile(r"\bLinkedList\b"),                     "heap-backed list"),
    ("BinaryHeap",         re.compile(r"\bBinaryHeap\b"),                     "heap-backed heap"),
]


def rust_sources(crate_root: Path) -> list[Path]:
    if not crate_root.exists():
        return []
    return sorted(crate_root.rglob("*.rs"))


def scan_file(path: Path) -> list[tuple[int, str, str, str]]:
    """Return (line_number, rule_name, reason, line_text) for each violation."""
    violations: list[tuple[int, str, str, str]] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), 1):
        for name, pattern, reason in FORBIDDEN:
            if pattern.search(line):
                violations.append((line_no, name, reason, line.strip()))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to auto-detect)",
    )
    args = parser.parse_args()
    crate = args.root / CRATE_ROOT
    sources = rust_sources(crate)

    if not sources:
        # No hues-async crate? That itself is suspicious — the workspace
        # declares it — but the gate is defensive and simply reports it.
        print(f"warning: no .rs files under {crate}; nothing to check", file=sys.stderr)
        return 0

    total_violations = 0
    for source in sources:
        violations = scan_file(source)
        if not violations:
            continue
        rel = source.relative_to(args.root)
        for line_no, name, reason, text in violations:
            print(f"{rel}:{line_no}: forbidden `{name}` ({reason})")
            print(f"    {text}")
            total_violations += 1

    if total_violations > 0:
        print()
        print(f"hues-async alloc-free gate failed: {total_violations} violation(s) "
              f"across {sum(1 for _ in sources)} file(s).")
        print("Rule: `crates/hues-async/**` must not use the `alloc` crate or any "
              "heap-backed collection/smart-pointer. Rework the code to use "
              "fixed-size arrays and inline storage, or move the logic to a "
              "downstream crate. See docs/ASYNC_RUNTIME.md for the rationale.")
        return 1

    print(f"hues-async alloc-free gate OK: {len(sources)} file(s) scanned, "
          f"no forbidden identifier or `alloc` import.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
