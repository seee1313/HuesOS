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

    if violations:
        print("Unranked privileged lock policy failed:")
        for violation in violations:
            print(f"  - {violation}")
        return 1

    print("Privileged lock policy OK: kernel, arch, and uACPI use ranked locks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
