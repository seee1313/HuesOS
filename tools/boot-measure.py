#!/usr/bin/env python3
"""Reproduce the HuesOS PCR 12 digest used before TPM unseal."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

DOMAIN = b"HuesOS-PCR12-v1\0"
PT_LOAD = 1
PF_X = 1
PHDR_BYTES = 56


def component(hasher: "hashlib._Hash", label: bytes, data: bytes) -> None:
    hasher.update(len(label).to_bytes(2, "little"))
    hasher.update(label)
    hasher.update(len(data).to_bytes(8, "little"))
    hasher.update(data)


def executable_segments(path: Path) -> list[bytes]:
    elf = path.read_bytes()
    if len(elf) < 64 or elf[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("kernel is not little-endian ELF64 v1")
    phoff = int.from_bytes(elf[32:40], "little")
    phentsize = int.from_bytes(elf[54:56], "little")
    phnum = int.from_bytes(elf[56:58], "little")
    if phnum == 0 or phentsize != PHDR_BYTES or phoff + phnum * phentsize > len(elf):
        raise ValueError("invalid program-header geometry")
    result: list[bytes] = []
    for index in range(phnum):
        base = phoff + index * phentsize
        kind = int.from_bytes(elf[base : base + 4], "little")
        flags = int.from_bytes(elf[base + 4 : base + 8], "little")
        if kind != PT_LOAD or not flags & PF_X:
            continue
        offset = int.from_bytes(elf[base + 8 : base + 16], "little")
        size = int.from_bytes(elf[base + 32 : base + 40], "little")
        if offset + size > len(elf):
            raise ValueError("executable segment exceeds kernel file")
        result.append(elf[offset : offset + size])
    if not result:
        raise ValueError("kernel has no executable PT_LOAD")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--bootfs", required=True, type=Path)
    parser.add_argument("--cmdline", required=True, type=Path)
    parser.add_argument("--platform", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    digest = hashlib.sha256()
    digest.update(DOMAIN)
    for segment in executable_segments(args.kernel):
        component(digest, b"kernel.text", segment)
    component(digest, b"bootfs", args.bootfs.read_bytes())
    component(digest, b"cmdline", args.cmdline.read_bytes())
    component(digest, b"platform", args.platform.read_bytes())
    value = digest.hexdigest()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(value + "\n", encoding="ascii")
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
