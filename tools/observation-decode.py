#!/usr/bin/env python3
"""Decode HuesOS structured observation records (Stage E.2).

The kernel keeps a ring of fixed-size binary records alongside the plain
text trace. This tool turns those bytes into something a human or a log
aggregator can read.

Input is either a raw binary dump of records (``--binary``) or a serial
log containing hex-encoded record lines emitted by the on-target dumper,
which look like::

    [observe] 0102030405060708...

Records are 32 bytes, little-endian, laid out as:

    offset  size  field
         0     8  sequence
         8     8  timestamp
        16     4  class
        20     4  code
        24     8  detail

Stdlib only, matching the rest of ``tools/``.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

RECORD_SIZE = 32
RECORD_STRUCT = struct.Struct("<QQIIQ")

# Mirrors huesos_object::observation::ObservationClass.
CLASSES = {
    1: "boot",
    2: "mount",
    3: "recovery",
    4: "error",
}

# Mirrors huesos_kernel::observation_code. Codes are namespaced by class,
# so the same number can mean different things under different classes.
CODES = {
    ("boot", 1): "kernel-ready",
    ("recovery", 2): "extable-probe-recovered",
    ("error", 3): "extable-probe-failed",
}

HEX_LINE = re.compile(r"\[observe\]\s+([0-9a-fA-F]+)\s*$")


def decode_records(blob: bytes) -> list[dict[str, object]]:
    """Decode as many whole records as the blob holds.

    A trailing partial record is ignored rather than fatal: a dump taken
    while the kernel was writing is a normal thing to encounter, and
    losing the last record is better than losing the whole file.
    """
    out: list[dict[str, object]] = []
    count = len(blob) // RECORD_SIZE
    for i in range(count):
        chunk = blob[i * RECORD_SIZE : (i + 1) * RECORD_SIZE]
        sequence, timestamp, class_raw, code, detail = RECORD_STRUCT.unpack(chunk)
        class_name = CLASSES.get(class_raw, f"unknown({class_raw})")
        out.append(
            {
                "sequence": sequence,
                "timestamp": timestamp,
                "class": class_name,
                "code": code,
                "code_name": CODES.get((class_name, code), f"code-{code}"),
                "detail": detail,
            }
        )
    return out


def extract_hex_from_log(text: str) -> bytes:
    """Pull hex-encoded record payloads out of a serial log."""
    blob = bytearray()
    for line in text.splitlines():
        match = HEX_LINE.search(line)
        if not match:
            continue
        hex_text = match.group(1)
        # An odd-length run means the line was truncated mid-byte by the
        # serial capture; keep the whole bytes and drop the tail.
        if len(hex_text) % 2:
            hex_text = hex_text[:-1]
        blob.extend(bytes.fromhex(hex_text))
    return bytes(blob)


def find_gaps(records: list[dict[str, object]]) -> list[tuple[int, int]]:
    """Sequence ranges that are missing between consecutive records.

    A gap means the ring wrapped before anyone read it. Reporting it is
    the whole reason records carry sequence numbers: a silent gap would
    look identical to a quiet system.
    """
    gaps: list[tuple[int, int]] = []
    for previous, current in zip(records, records[1:]):
        expected = int(previous["sequence"]) + 1
        actual = int(current["sequence"])
        if actual > expected:
            gaps.append((expected, actual - 1))
    return gaps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="serial log, or raw dump with --binary")
    parser.add_argument(
        "--binary",
        action="store_true",
        help="treat the input as a raw record dump rather than a log",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--class",
        dest="class_filter",
        choices=sorted(set(CLASSES.values())),
        help="only show records of this class",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"observation-decode: no such file: {args.input}", file=sys.stderr)
        return 2

    if args.binary:
        blob = args.input.read_bytes()
    else:
        blob = extract_hex_from_log(args.input.read_text(errors="replace"))

    records = decode_records(blob)
    if args.class_filter:
        records = [r for r in records if r["class"] == args.class_filter]

    if args.json:
        print(
            json.dumps(
                {"records": records, "gaps": find_gaps(records)},
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if not records:
        print("no observation records found")
        return 0

    for record in records:
        print(
            f"{record['sequence']:>6}  t={record['timestamp']:<10} "
            f"{record['class']:<9} {record['code_name']:<26} detail={record['detail']}"
        )
    for start, end in find_gaps(records):
        span = "record" if start == end else "records"
        print(f"warning: missing {span} {start}..{end} (ring wrapped)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
