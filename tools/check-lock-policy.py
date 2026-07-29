#!/usr/bin/env python3
"""Reject unranked blocking locks in privileged HuesOS crates.

Object/userspace migration is tracked separately because those crates are also
built by host tests and cannot execute the x86 interrupt-masking lock wrapper.
The kernel, architecture layer, and in-kernel uACPI boundary must use the
all-build ranked lock API exclusively.
"""

from __future__ import annotations

import argparse
from pathlib import Path

PRIVILEGED_CRATES = (
    "crates/huesos-arch/src",
    "crates/huesos-kernel/src",
    "crates/huesos-uacpi/src",
)
FORBIDDEN = ("spin::Mutex", "use spin::Mutex")
STEALER_FORBIDDEN = (
    "crate::process::",
    "PENDING_USER_ENTRIES",
    "VMAR_MUTATION_LOCK",
)


def check_scheduler_stealer(root: Path, violations: list[str]) -> None:
    path = root / "crates/huesos-kernel/src/scheduler.rs"
    lines = path.read_text(encoding="utf-8").splitlines()
    in_body = False
    brace_depth = 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not in_body and "fn take_stealable_task" in line:
            in_body = True
        if not in_body:
            continue
        brace_depth += line.count("{")
        brace_depth -= line.count("}")
        for token in STEALER_FORBIDDEN:
            if token in line:
                rel = path.relative_to(root)
                violations.append(
                    f"{rel}:{number}: scheduler stealer must not call lower-rank process helpers: {stripped}"
                )
        if in_body and brace_depth == 0:
            break


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    violations: list[str] = []
    for relative in PRIVILEGED_CRATES:
        for source in sorted((args.root / relative).rglob("*.rs")):
            for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
                if any(token in line for token in FORBIDDEN):
                    path = source.relative_to(args.root)
                    violations.append(f"{path}:{number}: {line.strip()}")

    check_scheduler_stealer(args.root, violations)

    if violations:
        print("Unranked privileged lock policy failed:")
        for violation in violations:
            print(f"  - {violation}")
        return 1

    print("Privileged lock policy OK: kernel, arch, and uACPI use ranked locks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
