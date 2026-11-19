#!/usr/bin/env python3
"""Reject direct kernel PCI enumeration, BAR sizing, or NVMe boot descriptors.

Stage J.3 invariant (AP-22):
1. `crates/huesos-kernel/src` must not reintroduce PCI CF8/CFC config space
   scans, BAR sizing, MSI/MSI-X programming, or `NvmeBootFunction` bootstrap
   logic (only the test-only `irq_test=1` `edu` probe in `boot/irq_probe.rs`
   and the `0xCF8..=0xCFF` sacred I/O deny list in `boot/acpi_policy.rs` are
   exempt).
2. `crates/huesos-abi/src/storage_boot.rs` must not expose NVMe PCI descriptor
   types (`NvmeBootFunction`, `MAX_NVME_FUNCTIONS`, `nvme_count`).
3. `crates/huesos-userspace/init/src/main.rs` must not mint NVMe `MMIO` or
   `IRQ` Resource capabilities directly.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

KERNEL_FORBIDDEN = [
    re.compile(r"\bLEGACY_CONFIG_ADDRESS_PORT\b"),
    re.compile(r"\bLEGACY_CONFIG_DATA_PORT\b"),
    re.compile(r"\bLegacyConfigPlan\b"),
    re.compile(r"0x[cC][fF]8\b"),
    re.compile(r"0x[cC][fF][cC]\b"),
    re.compile(r"\bNvmeBootFunction\b"),
    re.compile(r"\bsize_bar0\b"),
    re.compile(r"\bNVME_MSI_VECTOR_BASE\b"),
    re.compile(r"\bdiscover_nvme_functions\b"),
]

KERNEL_EXEMPT = {
    Path("crates/huesos-kernel/src/boot/irq_probe.rs"),
    Path("crates/huesos-kernel/src/boot/acpi_policy.rs"),
}

ABI_FORBIDDEN = [
    re.compile(r"\bNvmeBootFunction\b"),
    re.compile(r"\bMAX_NVME_FUNCTIONS\b"),
    re.compile(r"\bnvme_count\b"),
]

INIT_FORBIDDEN = [
    re.compile(r"\bsend_nvme_boot_grants\b"),
]


def scan_file(path: Path, patterns: list[re.Pattern[str]], violations: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        for pat in patterns:
            if pat.search(line):
                violations.append(
                    f"{path.relative_to(ROOT)}:{lineno}: forbidden pattern `{pat.pattern}`"
                )


def main() -> int:
    violations: list[str] = []

    kernel_src = ROOT / "crates/huesos-kernel/src"
    for rs in sorted(kernel_src.rglob("*.rs")):
        rel = rs.relative_to(ROOT)
        if rel in KERNEL_EXEMPT:
            continue
        scan_file(rs, KERNEL_FORBIDDEN, violations)

    storage_boot = ROOT / "crates/huesos-abi/src/storage_boot.rs"
    scan_file(storage_boot, ABI_FORBIDDEN, violations)

    init_main = ROOT / "crates/huesos-userspace/init/src/main.rs"
    scan_file(init_main, INIT_FORBIDDEN, violations)

    if violations:
        print("Kernel PCI shim / NVMe boot ABI gate FAILED:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    print("Kernel PCI shim removal gate OK: no direct kernel PCI scan or NVMe boot ABI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
