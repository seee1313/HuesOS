#!/usr/bin/env python3
"""Exercise real image CLIs and production mount/write/checkpoint/remount APIs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hxfs_image import (
    build_legacy_v6_image,
    build_legacy_v6_image_stream,
    inspect_image,
)

ROOT = Path(__file__).resolve().parents[1]


class ImageGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        result = subprocess.run(
            [os.environ.get("CARGO", "cargo"), "build", "--locked", "--manifest-path",
             str(ROOT / "tools/hxfs-seed/Cargo.toml"), "--bins", "--message-format=json",
             "--target", "x86_64-unknown-linux-gnu", "-Z", "build-std="],
            cwd=ROOT, capture_output=True, text=True,
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        executables = {}
        for line in result.stdout.splitlines():
            entry = json.loads(line)
            if entry.get("executable"):
                executables[entry["target"]["name"]] = entry["executable"]
        cls.checker = executables["hxfs-image-check"]
        cls.current = int(subprocess.check_output([cls.checker, "--format-version"], text=True))

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="hxfs-image-gate-")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)

    def mk(self, image: Path, blocks: int, *options: str, success: bool = True) -> subprocess.CompletedProcess:
        command = [sys.executable, str(ROOT / "tools/mkhxfs.py"), "--output", str(image),
                   "--blocks", str(blocks), *options]
        result = subprocess.run(command, cwd=self.base, capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, str(command))
        return result

    def check(self, image: Path, *options: str) -> None:
        result = subprocess.run([self.checker, *options, str(image)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(result.stdout.strip(), flush=True)

    def test_current_images_are_empty_writable_and_sparse(self) -> None:
        for blocks in (256, 4096, 1_048_576):
            with self.subTest(blocks=blocks):
                image = self.base / f"nested path {blocks}" / "volume.img"
                self.mk(image, blocks, "--instance-uuid", "ab" * 16, "--volume-uuid", "cd" * 16)
                report = inspect_image(image)
                self.assertEqual(report["bytes"], blocks * 4096)
                self.assertEqual(report["superblock"]["format_version"], self.current)
                self.assertEqual(report["superblock"]["type_system_version"], self.current)
                self.assertEqual(report["superblock"]["instance_uuid"], "ab" * 16)
                self.check(image)
                self.assertEqual(image.stat().st_size, blocks * 4096)
                if blocks == 1_048_576:
                    self.assertLess(image.stat().st_blocks * 512, 8 * 1024 * 1024)

    def test_explicit_legacy_fixtures_remain_read_only(self) -> None:
        for blocks in (256, 4096):
            with self.subTest(blocks=blocks):
                image = self.base / f"legacy-{blocks}.img"
                self.mk(image, blocks, "--legacy-v6")
                self.assertEqual(inspect_image(image)["superblock"]["format_version"], 6)
                before = hashlib.sha256(image.read_bytes()).digest()
                self.check(image, "--legacy-read-only")
                self.assertEqual(hashlib.sha256(image.read_bytes()).digest(), before)

    def test_legacy_builders_are_byte_identical(self) -> None:
        image = self.base / "legacy-stream.img"
        build_legacy_v6_image_stream(image, 256, bytes([0x11]) * 16, bytes([0x22]) * 16)
        self.assertEqual(image.read_bytes(), build_legacy_v6_image(256, bytes([0x11]) * 16, bytes([0x22]) * 16))

    def test_seeded_modes_still_generate_current_format(self) -> None:
        for mode in ((), ("--plain",), ("--inject-bad-crc",), ("--inject-bad-gcm-tag",)):
            with self.subTest(mode=mode):
                image = self.base / "seeded.img"
                self.mk(image, 512, "--seed-file", "seed.bin", *mode)
                self.assertEqual(inspect_image(image)["superblock"]["format_version"], self.current)
                self.assertEqual(image.stat().st_size, 512 * 4096)

    def test_invalid_requests_preserve_destination_and_clean_temporary_files(self) -> None:
        image = self.base / "existing.img"
        for blocks, options in (
            (7, ()), (8, ()), (2**63, ()), (256, ("--seed-size", "12")),
            (256, ("--seed-file", "seed.bin", "--seed-size", "0")),
            (256, ("--legacy-v6", "--seed-file", "seed.bin")),
            (256, ("--inject-bad-gcm-tag",)),
            (256, ("--seed-file", "seed.bin", "--seed-blob-file", str(self.base / "missing.bin"))),
        ):
            with self.subTest(blocks=blocks, options=options):
                image.write_bytes(b"existing image must survive")
                self.mk(image, blocks, *options, success=False)
                self.assertEqual(image.read_bytes(), b"existing image must survive")
                self.assertFalse(list(self.base.glob(".mkhxfs-*")))

    def test_repeated_generation_is_deterministic(self) -> None:
        first, second = self.base / "a.img", self.base / "b.img"
        self.mk(first, 256)
        self.mk(second, 256)
        self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
