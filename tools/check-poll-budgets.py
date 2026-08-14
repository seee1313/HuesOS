#!/usr/bin/env python3
"""Reject unbounded receive drains in the single-threaded service loops.

Why this gate exists
--------------------
DriverManager owns the boot main loop and hxfs-service owns the
filesystem service loop. Both are single-threaded and cooperative:
every peer -- each driver host, the registry, every client, file,
directory and blob view -- is serviced by one pass over a `poll_*`
function. Neither loop preempts itself.

The classic shape of these functions is "drain the channel until it
returns ShouldWait":

    loop {
        match chan.read_into(&mut buf) {
            Ok(n)  => handle(&buf[..n]),
            Err(ShouldWait) => return,
            ...
        }
    }

That is only correct against a peer that eventually goes quiet. Under
the high queue-depth NVMe soak the driver host produces completions
continuously, so the drain never observes ShouldWait, `poll_nvme_host`
never returns, and every later stage in the same pass -- including the
Hxblob package probe -- is starved for the entire run. The failure does
not look like a fairness bug from the outside: it looks like an
unrelated service hanging, which is why it cost a full debugging cycle
to find (see docs/STORAGE_PRODUCTION_GATE.md, gate 7).

The fix is a per-tick budget: serve at most N messages, then return and
let the loop come back around. This gate makes that structural rather
than a thing reviewers have to remember, so a newly added `poll_*` in
these crates cannot reintroduce the bug.

What is checked
---------------
For every function in the watched files whose body contains an
unconditional `loop {` together with a receive call (`read_into`,
`read_optional_handle`, `read_handle`, `recv`), the body must also
mention `budget`. Functions that only use `while let` / `for` are
bounded by their own iterator and are not flagged.

Exemptions live in `EXEMPT` below and each carries a written reason.
The gate is dependency-free so CI and reviewers can run it on a fresh
checkout.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Files whose functions drive a shared cooperative loop.
WATCHED = [
    "crates/huesos-userspace/driver-manager/src/supervisor.rs",
    "crates/huesos-userspace/hxfs-service/src/main.rs",
]

# Receive calls that can block a drain open indefinitely.
RECV = re.compile(r"\b(read_into|read_optional_handle|read_handle|recv)\s*\(")

# An unconditional `loop {`. `while let` and `for` are bounded by their
# own condition, so they are not the shape this gate is about.
UNBOUNDED_LOOP = re.compile(r"^\s*(\}\s*)?loop\s*\{", re.MULTILINE)

# A per-tick budget of any spelling (`budget`, `POLL_BUDGET_PER_TICK`,
# `remaining_budget`, ...). We deliberately match loosely: the point is
# that the author thought about boundedness, not a specific identifier.
BUDGET = re.compile(r"\bbudget\b", re.IGNORECASE)

# (file suffix, function name) -> reason. Each exemption is a claim that
# the loop is bounded by something other than a budget; state why.
EXEMPT = {
    (
        "hxfs-service/src/main.rs",
        "mount_from_bootstrap",
    ): (
        "one-shot mount handshake run before the service loop starts, not a "
        "steady-state poll: it must block until the volume handle arrives or "
        "there is nothing to serve at all."
    ),
}

FN_START = re.compile(r"^([ \t]*)(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)", re.MULTILINE)


def function_bodies(text: str):
    """Yield (name, line_number, body) for every function in `text`.

    Bodies are sliced by brace balance starting at the function's opening
    brace, which is accurate enough here and keeps the gate dependency-free.
    String and char literals are not parsed; a stray brace inside a literal
    would only ever end a body early, which cannot create a false failure
    (a truncated body simply loses the loop we were looking for).
    """
    for match in FN_START.finditer(text):
        name = match.group(2)
        brace = text.find("{", match.end())
        if brace == -1:
            continue
        depth = 0
        end = None
        for index in range(brace, len(text)):
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end is None:
            continue
        line_no = text.count("\n", 0, match.start()) + 1
        yield name, line_no, text[brace : end + 1]


def check_file(root: Path, rel: str) -> list[str]:
    path = root / rel
    if not path.exists():
        return [f"{rel}: watched file is missing; update WATCHED in this gate"]

    failures: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for name, line_no, body in function_bodies(text):
        if not UNBOUNDED_LOOP.search(body) or not RECV.search(body):
            continue
        exempt_key = next(
            (key for key in EXEMPT if rel.endswith(key[0]) and key[1] == name), None
        )
        if exempt_key is not None:
            continue
        if BUDGET.search(body):
            continue
        failures.append(
            f"{rel}:{line_no}: `{name}` drains a channel in an unbounded "
            f"`loop` with no per-tick budget"
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to auto-detect)",
    )
    args = parser.parse_args()

    failures: list[str] = []
    checked = 0
    for rel in WATCHED:
        result = check_file(args.root, rel)
        failures.extend(result)
        checked += 1

    if failures:
        for failure in failures:
            print(failure)
        print()
        print(f"poll-budget gate failed: {len(failures)} unbounded drain(s).")
        print(
            "Rule: a `poll_*` in a shared cooperative loop must serve at most "
            "POLL_BUDGET_PER_TICK messages and then return, so the other "
            "endpoints in the same pass are not starved by one talkative peer. "
            "Copy the `budget = match budget.checked_sub(1)` prologue from "
            "`poll_nvme_host`. If the loop really is bounded some other way, "
            "add it to EXEMPT in tools/check-poll-budgets.py with a reason."
        )
        return 1

    print(
        f"poll-budget gate OK: {checked} service-loop file(s) scanned, "
        f"every unbounded channel drain is budgeted."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
