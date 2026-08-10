#!/usr/bin/env python3
"""Run deterministic HuesOS storage/Hxfs development benchmarks.

This is a host-side benchmark harness for regression tracking. It intentionally
uses stdlib only and does not claim hardware truth; QEMU/NVMe soak remains the
runtime performance gate.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path("/tmp/huesos-storage-bench.img")


def run(cmd: list[str]) -> float:
    start = time.perf_counter()
    subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return time.perf_counter() - start


def bench_hxfs_tools(iterations: int, blocks: int) -> dict[str, object]:
    mk = []
    inspect = []
    scrub = []
    seed = []
    for _ in range(iterations):
        mk.append(run(["python3", "tools/mkhxfs.py", "--output", str(TMP), "--blocks", str(blocks)]))
        inspect.append(run(["python3", "tools/hxfs-inspect.py", str(TMP)]))
        scrub.append(run(["python3", "tools/hxfs-scrub.py", str(TMP)]))
        # Stage E (Operations): the encrypted+compressed seed path
        # (mkhxfs --seed-file delegates to the Rust hxfs-seed tool),
        # the exact pipeline the soak volume uses.
        seed.append(run([
            "python3", "tools/mkhxfs.py", "--output", str(TMP),
            "--blocks", str(max(blocks, 512)), "--seed-file", "seed.bin",
            "--seed-size", "3584",
        ]))
    return {
        "iterations": iterations,
        "blocks": blocks,
        "mkhxfs_avg_ms": average_ms(mk),
        "inspect_avg_ms": average_ms(inspect),
        "scrub_avg_ms": average_ms(scrub),
        "seed_image_avg_ms": average_ms(seed),
    }


def average_ms(values: list[float]) -> float:
    return round((sum(values) / max(1, len(values))) * 1000.0, 3)


def synthetic_nvme_queue(iterations: int, depth: int) -> dict[str, object]:
    # Deterministic synthetic slot churn: this mirrors the Stage-U policy shape
    # without depending on QEMU or a live NVMe controller.
    active = 0
    submitted = 0
    completed = 0
    queue_full = 0
    start = time.perf_counter()
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
    elapsed = time.perf_counter() - start
    return {
        "iterations": iterations,
        "depth": depth,
        "submitted": submitted,
        "completed": completed,
        "queue_full": queue_full,
        "elapsed_ms": round(elapsed * 1000.0, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--blocks", type=int, default=256)
    parser.add_argument("--queue-depth", type=int, default=256)
    args = parser.parse_args()
    result = {
        "hxfs_tools": bench_hxfs_tools(args.iterations, args.blocks),
        "synthetic_nvme_queue": synthetic_nvme_queue(args.iterations * args.queue_depth, args.queue_depth),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
