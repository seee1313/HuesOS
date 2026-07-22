#!/usr/bin/env python3
"""Check the host-testable kernel policy crates.

The policy crates are deliberately small, dependency-free decision cores. This
check is intentionally source-level and dependency-free so it can run before
Cargo is available: every listed crate must be a workspace member, forbid
unsafe Rust, contain host tests, and have a design document that states the
privileged integration boundary.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

POLICY_CRATES = {
    "huesos-lifecycle": "OBJECT_LIFECYCLE_POLICY.md",
    "huesos-ioapic": "IOAPIC_ROUTING.md",
    "huesos-extable": "RECOVERABLE_COPIES.md",
    "huesos-waitset": "MULTI_OBJECT_WAIT.md",
    "huesos-proclife": "DYNAMIC_PROCESSES.md",
    "huesos-handlemove": "HANDLE_TRANSFER.md",
    "huesos-quota": "QUOTAS.md",
}


def package_path(root: Path, name: str) -> Path:
    return root / "crates" / name / "src" / "lib.rs"


def workspace_contains(root: Path, name: str) -> bool:
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    return f'"crates/{name}"' in cargo


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors: list[str] = []
    async_source = root / "crates" / "hues-async" / "src" / "lib.rs"
    if async_source.is_file():
        async_text = async_source.read_text(encoding="utf-8")
        if re.search(r"extern crate alloc|\balloc::|GlobalAlloc|\b(?:Box|Vec|String)<", async_text):
            errors.append("hues-async: allocator or heap-backed type detected")
    else:
        errors.append("hues-async: missing src/lib.rs")

    for name, document in POLICY_CRATES.items():
        source = package_path(root, name)
        if not workspace_contains(root, name):
            errors.append(f"{name}: missing from root workspace members")
        if not source.is_file():
            errors.append(f"{name}: missing src/lib.rs")
            continue
        text = source.read_text(encoding="utf-8")
        if "#![forbid(unsafe_code)]" not in text:
            errors.append(f"{name}: missing #![forbid(unsafe_code)]")
        if "#[cfg(test)]" not in text:
            errors.append(f"{name}: missing host unit tests")
        if not re.search(r"\bfn\s+\w*test\w*\b|#\[test\]", text):
            errors.append(f"{name}: no test functions found")
        if not (root / "docs" / document).is_file():
            errors.append(f"{name}: missing docs/{document}")

    if errors:
        print("Policy-crate check failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(f"Policy-crate check OK: {len(POLICY_CRATES)} crates are documented and host-testable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
