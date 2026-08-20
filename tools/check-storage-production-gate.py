#!/usr/bin/env python3
"""Check Stage-Z storage production-gate metadata.

Default mode validates that the gate/checklist exists and that HuesOS is not
accidentally marked production-ready. Use --enforce-production only for a future
release candidate; it intentionally fails today until runtime gates are closed.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = [
    Path("docs/STORAGE_PRODUCTION_GATE.md"),
    Path("docs/PRODUCTION_ROADMAP.md"),
    Path("tools/mkhxfs.py"),
    Path("tools/hxfs-inspect.py"),
    Path("tools/hxfs-scrub.py"),
    Path("tools/storage-bench.py"),
    Path("scripts/ci-qemu-nvme-soak.sh"),
]
RUNTIME_BLOCKERS = [
    "independent security review of KeyBroker and HxFS v6",
    "owner-approved HxFS v6 format freeze",
    "two-vendor disposable-NVMe bare-metal matrix",
    "real-hardware TPM PCR success/mismatch evidence",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enforce-production", action="store_true")
    args = parser.parse_args()
    errors: list[str] = []
    for rel in REQUIRED_PATHS:
        path = ROOT / rel
        if not path.exists():
            errors.append(f"missing {rel}")
    gate = ROOT / "docs" / "STORAGE_PRODUCTION_GATE.md"
    if gate.exists():
        text = gate.read_text(encoding="utf-8").lower()
        if "storage production-ready: true" in text:
            errors.append("gate document claims production-ready=true")
        if "not production-ready" not in text:
            errors.append("gate document must explicitly state not production-ready")
    if errors:
        print("Storage production gate metadata failed:")
        for error in errors:
            print(f"  - {error}")
        return 1
    if args.enforce_production:
        approved = os.environ.get("HUESOS_STORAGE_PRODUCTION_APPROVED") == "1"
        if not approved:
            print("Storage production gate is intentionally not approved yet.")
            for blocker in RUNTIME_BLOCKERS:
                print(f"  - {blocker}")
            return 1
    print("Storage production gate metadata OK: foundation is tracked, production freeze is not claimed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
