#!/usr/bin/env python3
"""Reject bare `spin::Mutex` in `huesos-object`; require `IrqSafeMutex`.

Project rule: every shared-state field or static in `crates/huesos-object`
must go through `crate::irq_guard::IrqSafeMutex`, not a raw `spin::Mutex`.

## Why

`huesos-object`'s kernel objects (the global registry, `Port`, `Interrupt`,
`WaitQueue`, `Channel`, ...) are reachable both from ordinary syscall-context
code (interrupts enabled) and from the keyboard IRQ1 / timer IRQ handlers on
the same CPU. A plain `spin::Mutex` taken by syscall-context code can be
retaken by an IRQ handler that fires before the guard drops, self-deadlocking
the CPU forever (the IRQ handler spins on a lock its own interrupted context
holds, and that context can never resume to release it). This has already
caused two real incidents in this crate (see `docs/UNSAFE_AUDIT.md` §
"huesos-object IRQ-guard boundary"), the second one specifically because a
manually-guarded ad-hoc fix missed a lock that "did not look like" part of
the same IRQ-reachable graph.

`IrqSafeMutex` closes this by construction: there is no way to `.lock()` one
without disabling local interrupts for the critical section, so a future
call site cannot reintroduce the bug by omission. This gate makes that a
hard requirement instead of a convention: no file under
`crates/huesos-object/src/` may name `spin::Mutex` as a field/static type or
construct one with `Mutex::new`, except:

- `crates/huesos-object/src/irq_guard.rs` itself, which implements
  `IrqSafeMutex` on top of `spin::Mutex` and is exactly the one place that
  legitimately needs the raw primitive;
- `#[cfg(test)]` blocks, which run only on the host and are never reachable
  from a hardware IRQ handler (there is no hardware IRQ handler on the host
  test target at all).

This gate is dependency-free and scans raw text, matching the style of
`tools/check-hues-async-noalloc.py` and `tools/check-lock-policy.py`.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

CRATE_ROOT = "crates/huesos-object"
EXEMPT_FILE = "irq_guard.rs"

# Matches `spin::Mutex` used as a type (field/static declaration) or
# constructor (`Mutex::new`), and a bare `use spin::Mutex;` import outside
# the exempt file. Deliberately conservative (word-boundaried) to avoid
# false positives on unrelated identifiers, and skips doc-comment lines
# (`///` / `//!`) so this module and others may discuss `spin::Mutex` in
# prose without tripping the gate.
MUTEX_TYPE_OR_CTOR = re.compile(r"\bspin::Mutex\b|\bMutex\s*<|\bMutex::new\s*\(")
USE_SPIN_MUTEX = re.compile(r"\buse\s+spin::Mutex\b")
DOC_COMMENT = re.compile(r"^\s*(///|//!)")


def scan_file(path: Path, root: Path) -> list[str]:
    violations: list[str] = []
    in_test_mod = False
    test_mod_depth = 0
    brace_depth = 0
    relative = path.relative_to(root)
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw_line.strip()

        if not in_test_mod and re.match(r"#\[cfg\(test\)\]", stripped):
            in_test_mod = True
            test_mod_depth = brace_depth
            # The #[cfg(test)] attribute line itself never matches the
            # patterns below, so it's safe to just track state and continue.

        brace_depth += raw_line.count("{") - raw_line.count("}")
        if in_test_mod and brace_depth <= test_mod_depth and "{" not in stripped and "}" in stripped:
            in_test_mod = False

        if in_test_mod:
            continue

        if DOC_COMMENT.match(raw_line):
            continue

        if MUTEX_TYPE_OR_CTOR.search(raw_line) or USE_SPIN_MUTEX.search(raw_line):
            violations.append(f"{relative}:{number}: {stripped}")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    violations: list[str] = []
    for source in sorted((args.root / CRATE_ROOT / "src").rglob("*.rs")):
        if source.name == EXEMPT_FILE:
            continue
        violations.extend(scan_file(source, args.root))

    if violations:
        print("huesos-object IRQ-safe lock policy failed:")
        for violation in violations:
            print(f"  - {violation}")
        print()
        print(
            "Every shared-state field/static in huesos-object must use "
            "crate::irq_guard::IrqSafeMutex, not spin::Mutex directly. "
            "See crates/huesos-object/src/irq_guard.rs and "
            "docs/UNSAFE_AUDIT.md."
        )
        return 1

    print("huesos-object IRQ-safe lock policy OK: no bare spin::Mutex outside irq_guard.rs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
