#!/usr/bin/env python3
"""Fail when a relative Markdown link points at a missing workspace path."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def main() -> int:
    documents = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    failures: list[str] = []
    for document in documents:
        text = document.read_text(encoding="utf-8")
        for raw in LINK.findall(text):
            destination = raw.strip().split(maxsplit=1)[0].strip("<>")
            if (
                not destination
                or destination.startswith("#")
                or "://" in destination
                or destination.startswith("mailto:")
            ):
                continue
            relative = unquote(destination.split("#", 1)[0])
            if not relative:
                continue
            target = (document.parent / relative).resolve()
            if not target.exists():
                failures.append(
                    f"{document.relative_to(ROOT)}: {destination} -> missing {target}"
                )
    if failures:
        print("Broken relative Markdown links:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"Markdown link gate OK: {len(documents)} document(s) checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
