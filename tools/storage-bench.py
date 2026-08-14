#!/usr/bin/env python3
"""Run deterministic HuesOS storage/Hxfs development benchmarks.

This is a host-side benchmark harness for regression tracking. It
intentionally uses stdlib only and does not claim hardware truth;
QEMU/NVMe soak remains the runtime performance gate.

## Why the report has two halves

Stage E.4 asks for a report that is reproducible across runs of the same
commit. Wall-clock timings can never satisfy that literally — the same
binary on the same machine varies by percent between runs, and on a
shared CI runner by rather more. Pretending otherwise produces a gate
that either never fires or fires constantly, and a gate that fires
constantly gets disabled.

So the report is split:

``deterministic``
    Counters, sizes, and content digests. These are bit-identical across
    runs of the same commit, and any change is a real functional change:
    an image that got bigger, an extent count that moved, a tool whose
    output digest shifted. Compared byte-exactly against a committed
    baseline (``--check`` / ``--baseline``).

``timings``
    Wall-clock milliseconds. Compared with a percentage tolerance, and
    best compared against a second run in the same job rather than
    against a number recorded on different hardware.

The exit criterion is therefore honoured in the only way it can be
honoured: the part of the report that *can* be bit-identical is required
to be, and the part that cannot is bounded instead.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path("/tmp/huesos-storage-bench.img")

# Default tolerance for the timing half, in percent. Deliberately wide:
# a shared CI runner's noise floor is larger than most real regressions,
# so a tight bound here would only teach people to ignore the gate.
DEFAULT_TOLERANCE_PCT = 25.0


def run(cmd: list[str]) -> float:
    start = time.perf_counter()
    subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return time.perf_counter() - start


def digest(path: Path) -> str:
    """SHA-256 of a file, or "missing" if the tool did not produce it."""
    if not path.exists():
        return "missing"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_report(path: Path, text: str) -> None:
    """Write a report, creating the parent directory if needed.

    The default output lands in ``build/``, which does not exist on a
    fresh checkout — CI clones the repo and runs the gate before
    anything has created a build directory. Failing there reports a
    Python traceback about a missing path instead of a benchmark
    result, which is a confusing way to learn that nothing was built
    yet.
    """
    parent = path.parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n")


def capture(cmd: list[str]) -> str:
    """SHA-256 of a tool's stdout, for output-shape regressions."""
    result = subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True)
    return hashlib.sha256(result.stdout).hexdigest()


def average_ms(values: list[float]) -> float:
    return round((sum(values) / max(1, len(values))) * 1000.0, 3)


def bench_hxfs_tools(iterations: int, blocks: int) -> tuple[dict[str, object], dict[str, object]]:
    """Time the Hxfs host tools and fingerprint what they produce.

    Returns ``(timings, deterministic)``.
    """
    mk: list[float] = []
    inspect: list[float] = []
    scrub: list[float] = []
    seed: list[float] = []
    for _ in range(iterations):
        mk.append(run(["python3", "tools/mkhxfs.py", "--output", str(TMP), "--blocks", str(blocks)]))
        inspect.append(run(["python3", "tools/hxfs-inspect.py", str(TMP)]))
        scrub.append(run(["python3", "tools/hxfs-scrub.py", str(TMP)]))
        # Stage E (Operations): the encrypted+compressed seed path
        # (mkhxfs --seed-file delegates to the Rust hxfs-seed tool),
        # the exact pipeline the soak volume uses.
        seed.append(
            run(
                [
                    "python3",
                    "tools/mkhxfs.py",
                    "--output",
                    str(TMP),
                    "--blocks",
                    str(max(blocks, 512)),
                    "--seed-file",
                    "seed.bin",
                    "--seed-size",
                    "3584",
                ]
            )
        )

    timings = {
        "mkhxfs_avg_ms": average_ms(mk),
        "inspect_avg_ms": average_ms(inspect),
        "scrub_avg_ms": average_ms(scrub),
        "seed_image_avg_ms": average_ms(seed),
    }

    # Rebuild a plain image one final time so the digest describes the
    # unseeded layout rather than whichever image the loop left behind.
    subprocess.run(
        ["python3", "tools/mkhxfs.py", "--output", str(TMP), "--blocks", str(blocks)],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    deterministic = {
        "iterations": iterations,
        "blocks": blocks,
        "image_bytes": TMP.stat().st_size if TMP.exists() else 0,
        "image_sha256": digest(TMP),
        "inspect_stdout_sha256": capture(["python3", "tools/hxfs-inspect.py", str(TMP)]),
        "scrub_stdout_sha256": capture(["python3", "tools/hxfs-scrub.py", str(TMP)]),
    }
    return timings, deterministic


def synthetic_nvme_queue(iterations: int, depth: int) -> dict[str, object]:
    """Deterministic synthetic slot churn.

    Mirrors the Stage-U policy shape without depending on QEMU or a live
    NVMe controller. Every field here is a pure function of the inputs,
    so it belongs entirely in the deterministic half.
    """
    active = 0
    submitted = 0
    completed = 0
    queue_full = 0
    for i in range(iterations):
        if active >= depth:
            queue_full += 1
            active -= 1
            completed += 1
        active += 1
        submitted += 1
        if i % 3 == 0 and active > 0:
            active -= 1
            completed += 1
    return {
        "iterations": iterations,
        "depth": depth,
        "submitted": submitted,
        "completed": completed,
        "queue_full": queue_full,
    }


def build_report(iterations: int, blocks: int, queue_depth: int) -> dict[str, object]:
    tool_timings, tool_deterministic = bench_hxfs_tools(iterations, blocks)
    return {
        "deterministic": {
            "hxfs_tools": tool_deterministic,
            "synthetic_nvme_queue": synthetic_nvme_queue(iterations * queue_depth, queue_depth),
        },
        "timings": {
            "hxfs_tools": tool_timings,
        },
    }


def flatten(prefix: str, value: object, out: dict[str, float]) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            flatten(f"{prefix}.{key}" if prefix else str(key), inner, out)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out[prefix] = float(value)


def compare_deterministic(current: dict, baseline: dict) -> list[str]:
    """Byte-exact comparison. Any difference is a real change."""
    failures: list[str] = []
    current_text = json.dumps(current, indent=2, sort_keys=True)
    baseline_text = json.dumps(baseline, indent=2, sort_keys=True)
    if current_text == baseline_text:
        return failures

    flat_current: dict[str, float] = {}
    flat_baseline: dict[str, float] = {}
    flatten("", current, flat_current)
    flatten("", baseline, flat_baseline)
    for key in sorted(set(flat_current) | set(flat_baseline)):
        got = flat_current.get(key)
        want = flat_baseline.get(key)
        if got != want:
            failures.append(f"deterministic {key}: baseline {want}, got {got}")

    # Digests are strings, so they do not survive flatten(); diff them
    # explicitly or a changed image would be reported as "no numeric
    # difference" while the texts plainly differ.
    def walk_strings(prefix: str, value: object, out: dict[str, str]) -> None:
        if isinstance(value, dict):
            for key, inner in value.items():
                walk_strings(f"{prefix}.{key}" if prefix else str(key), inner, out)
        elif isinstance(value, str):
            out[prefix] = value

    string_current: dict[str, str] = {}
    string_baseline: dict[str, str] = {}
    walk_strings("", current, string_current)
    walk_strings("", baseline, string_baseline)
    for key in sorted(set(string_current) | set(string_baseline)):
        got_s = string_current.get(key)
        want_s = string_baseline.get(key)
        if got_s != want_s:
            failures.append(f"deterministic {key}: baseline {want_s}, got {got_s}")

    if not failures:
        failures.append("deterministic section differs from baseline in shape")
    return failures


def compare_timings(current: dict, baseline: dict, tolerance_pct: float) -> list[str]:
    """Percentage comparison, tolerant by design."""
    failures: list[str] = []
    flat_current: dict[str, float] = {}
    flat_baseline: dict[str, float] = {}
    flatten("", current, flat_current)
    flatten("", baseline, flat_baseline)
    for key in sorted(flat_baseline):
        want = flat_baseline[key]
        got = flat_current.get(key)
        if got is None:
            failures.append(f"timing {key}: missing from current report")
            continue
        if want <= 0:
            continue
        delta_pct = (got - want) / want * 100.0
        if delta_pct > tolerance_pct:
            failures.append(
                f"timing {key}: {got:.3f}ms is {delta_pct:.1f}% slower than "
                f"baseline {want:.3f}ms (tolerance {tolerance_pct:.1f}%)"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--blocks", type=int, default=256)
    parser.add_argument("--queue-depth", type=int, default=256)
    parser.add_argument("--output", type=Path, help="write the report here as well as stdout")
    parser.add_argument(
        "--baseline",
        type=Path,
        help="baseline report to compare against (implies --check)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the report regresses against the baseline",
    )
    parser.add_argument(
        "--self-compare",
        action="store_true",
        help=(
            "run the benchmark twice and compare the two runs, which "
            "removes cross-machine variance from the timing half"
        ),
    )
    parser.add_argument(
        "--baseline-timings",
        action="store_true",
        help=(
            "also compare the timing half against the baseline file. Off "
            "by default: a committed baseline was recorded on different "
            "hardware, and the first run on a cold checkout pays for "
            "building the Rust seed tool, which dwarfs any real "
            "regression. Use --self-compare for timings instead."
        ),
    )
    parser.add_argument(
        "--tolerance-pct",
        type=float,
        default=DEFAULT_TOLERANCE_PCT,
        help=f"timing tolerance in percent (default {DEFAULT_TOLERANCE_PCT})",
    )
    parser.add_argument(
        "--update-baseline",
        type=Path,
        help="write the report to this path as the new baseline and exit 0",
    )
    args = parser.parse_args()

    report = build_report(args.iterations, args.blocks, args.queue_depth)
    text = json.dumps(report, indent=2, sort_keys=True)

    if args.update_baseline:
        write_report(args.update_baseline, text)
        print(f"baseline written to {args.update_baseline}", file=sys.stderr)
        print(text)
        return 0

    print(text)
    if args.output:
        write_report(args.output, text)

    failures: list[str] = []

    if args.self_compare:
        # Same commit, same machine, back to back: this is the
        # comparison the exit criterion actually describes.
        second = build_report(args.iterations, args.blocks, args.queue_depth)
        failures += compare_deterministic(second["deterministic"], report["deterministic"])
        failures += compare_timings(second["timings"], report["timings"], args.tolerance_pct)

    if args.baseline:
        if not args.baseline.exists():
            print(f"storage-bench: no baseline at {args.baseline}", file=sys.stderr)
            return 2
        baseline = json.loads(args.baseline.read_text())
        # The deterministic half is compared byte-exactly: it is a pure
        # function of the commit, so any difference is a real change.
        failures += compare_deterministic(report["deterministic"], baseline["deterministic"])
        if args.baseline_timings:
            failures += compare_timings(
                report["timings"], baseline["timings"], args.tolerance_pct
            )

    if failures and (args.check or args.baseline or args.self_compare):
        print("", file=sys.stderr)
        for failure in failures:
            print(f"storage-bench: {failure}", file=sys.stderr)
        print(
            "\nIf this change is intentional, refresh the baseline with "
            "--update-baseline and commit it.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
