#!/usr/bin/env python3
"""Format (or check formatting of) every Rust crate in the HuesOS repository.

The workspace `cargo fmt --all` covers the crates declared in the root
`Cargo.toml`, but the standalone userspace binaries under
`crates/huesos-userspace/` are intentionally excluded from the workspace (they
target ring-3 with a separate linker script and are built by
`huesos-kernel/build.rs`). Without this helper it is trivial to land a PR that
looks formatted locally but leaves a userspace crate untouched, and CI's fmt
check then fails on a completely unrelated PR.

This script does two things and nothing else:

  1. Runs `cargo fmt --all` (or `--check`) on the kernel workspace.
  2. For every standalone crate under `crates/huesos-userspace/`, runs
     `cargo fmt -p <name>` (or `--check`) in that crate directory.

Usage
-----

    python3 tools/fmt-all.py             # format everything in place
    python3 tools/fmt-all.py --check     # exit 1 if anything would change (CI)
    python3 tools/fmt-all.py --list      # print the crates that would be formatted

Design notes
------------

- Dependency-free (stdlib only), matches the style of the other four gates
  under `tools/`.
- Discovers standalone userspace crates by scanning for `Cargo.toml` files
  under `crates/huesos-userspace/`; no hard-coded list to keep in sync when
  a new userspace program lands. (This is exactly the failure mode that
  bit `scripts/clippy.sh` when `acpi-manager` was added — the gate silently
  missed it. The auto-discovery here removes the same class of drift.)
- Skips `libcanvas` because it lives inside the userspace tree but is *only*
  a library dependency of the other userspace crates; running its formatter
  as a separate `cargo fmt` invocation would just repeat work already done
  by each binary crate's own `--all`. The scan below still catches it if it
  ever needs its own invocation.
- Uses the toolchain selected by `rust-toolchain.toml` (nightly rustfmt with
  the project's style), i.e. we invoke plain `cargo fmt`, not
  `cargo +stable fmt`.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

USERSPACE_DIR = Path("crates/huesos-userspace")


def discover_standalone_crates(root: Path) -> list[Path]:
    """Return a sorted list of standalone (non-workspace) userspace crate roots.

    A userspace crate is any subdirectory of `crates/huesos-userspace` that
    contains its own `Cargo.toml`. The workspace `Cargo.toml` at the repo
    root does not list these crates, so they need their own `cargo fmt`
    invocation.
    """
    userspace = root / USERSPACE_DIR
    if not userspace.is_dir():
        return []
    crates = []
    for cargo_toml in sorted(userspace.glob("*/Cargo.toml")):
        crates.append(cargo_toml.parent)
    return crates


def run(command: list[str], cwd: Path) -> int:
    """Run `command` in `cwd`, streaming output. Returns the exit code."""
    rel = cwd.name or str(cwd)
    print(f"  ==> {' '.join(command)}  (in {rel})", flush=True)
    result = subprocess.run(command, cwd=cwd)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write files. Exit non-zero if any file would change (CI mode).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print the crates that would be formatted and exit.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root (defaults to auto-detect).",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    if shutil.which("cargo") is None:
        print("error: `cargo` not found in PATH", file=sys.stderr)
        print("       install rustup and let rust-toolchain.toml select the pinned nightly",
              file=sys.stderr)
        return 2

    standalone = discover_standalone_crates(root)

    if args.list:
        print("Workspace root:")
        print(f"  {root} (cargo fmt --all)")
        print(f"Standalone userspace crates ({len(standalone)}):")
        for path in standalone:
            print(f"  {path.relative_to(root)}")
        return 0

    fmt_flags = ["--check"] if args.check else []

    print("Formatting kernel workspace...")
    failures: list[str] = []
    if run(["cargo", "fmt", "--all", "--"] + fmt_flags, cwd=root) != 0:
        failures.append("workspace (cargo fmt --all)")

    if standalone:
        print(f"\nFormatting {len(standalone)} standalone userspace crate(s)...")
    for crate in standalone:
        # `cargo fmt --all` inside a crate directory formats that crate's
        # library + binaries. We rely on the crate directory itself to select
        # the right Cargo.toml because the userspace crates use their own
        # non-workspace target spec.
        if run(["cargo", "fmt", "--all", "--"] + fmt_flags, cwd=crate) != 0:
            failures.append(str(crate.relative_to(root)))

    if failures:
        print()
        if args.check:
            print(
                f"fmt-all: {len(failures)} crate group(s) would reformat:",
                file=sys.stderr,
            )
        else:
            print(
                f"fmt-all: {len(failures)} crate group(s) failed to format:",
                file=sys.stderr,
            )
        for path in failures:
            print(f"  - {path}", file=sys.stderr)
        if args.check:
            print(
                "\nRun `python3 tools/fmt-all.py` (without --check) to fix.",
                file=sys.stderr,
            )
        return 1

    covered = 1 + len(standalone)
    verb = "checked" if args.check else "formatted"
    print(f"\nfmt-all: {verb} kernel workspace + {len(standalone)} standalone crate(s) "
          f"({covered} groups) — all clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
