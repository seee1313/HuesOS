#!/usr/bin/env python3
"""Verify the protective-MBR + GPT disk image written by `tools/gpt_image.py`.

This is the host-side half of the GPT contract: the guest-side half is
`hxfs-service`'s mount probe (`gpt_hxfs_partition`), which has to find the very
same partition from the very same bytes with its own no-heap parser. The checks
below read raw offsets and recompute CRCs with `zlib`, so a mistake in the
writer cannot be "verified" by calling the writer's own helpers again.

The layout itself is exercised with synthetic volumes, so the file runs on a
machine without a Rust toolchain; the `mkhxfs.py --gpt` wiring is a separate
test that is skipped when `cargo` is unavailable.
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LBA = 512
ENTRY_SIZE = 128
ENTRY_COUNT = 128
HXFS_GUID = bytes.fromhex("534658480700554845534f5356374750")
TOTAL_BLOCKS = 1000
VOLUME_BLOCKS = TOTAL_BLOCKS - 256 - 34
FIRST_LBA = 2048
TOTAL_LBA = TOTAL_BLOCKS * 8

sys.path.insert(0, str(ROOT / "tools"))
import gpt_image  # noqa: E402


def crc32(payload: bytes) -> int:
    return zlib.crc32(payload) & 0xFFFFFFFF


class GptImageGate(unittest.TestCase):
    """Raw-offset checks on the image `gpt_image.wrap_volume` produces."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="gpt-image-gate-")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.volume = self.base / "volume.img"
        # A recognisable first block plus a 1 KiB tail marker: enough to prove
        # where the payload landed without dragging in the real formatter.
        self.volume_head = bytes(range(256)) * 16
        self.volume_tail = b"HXFS-TAIL-MARKER!"
        with self.volume.open("wb") as handle:
            handle.truncate(VOLUME_BLOCKS * 4096)
            handle.seek(0)
            handle.write(self.volume_head)
            handle.seek(VOLUME_BLOCKS * 4096 - len(self.volume_tail))
            handle.write(self.volume_tail)
        self.image = self.base / "disk.img"
        self.layout = gpt_image.wrap_volume(self.volume, self.image, TOTAL_BLOCKS)

    def read(self, offset: int, length: int) -> bytes:
        with self.image.open("rb") as handle:
            handle.seek(offset)
            return handle.read(length)

    def test_layout_record(self) -> None:
        self.assertEqual(self.layout["total_blocks_4k"], TOTAL_BLOCKS)
        self.assertEqual(self.layout["volume_blocks_4k"], VOLUME_BLOCKS)
        self.assertEqual(self.layout["first_lba"], FIRST_LBA)
        self.assertEqual(self.layout["last_lba"], FIRST_LBA + VOLUME_BLOCKS * 8 - 1)
        self.assertEqual(self.image.stat().st_size, TOTAL_BLOCKS * 4096)

    def test_protective_mbr(self) -> None:
        mbr = self.read(0, LBA)
        self.assertEqual(mbr[510:512], b"\x55\xaa", "boot signature")
        entry = mbr[446:462]
        self.assertEqual(entry[0], 0x00, "not bootable")
        self.assertEqual(entry[1:4], b"\x00\x02\x00", "CHS start: head 0, sector 2")
        self.assertEqual(entry[4], 0xEE, "protective type 0xEE")
        self.assertEqual(entry[5:8], b"\xff\xff\xff", "CHS end sentinel")
        first_lba, count = struct.unpack_from("<II", entry, 8)
        self.assertEqual(first_lba, 1, "protective partition starts at LBA 1")
        self.assertEqual(count, min(TOTAL_LBA - 1, 0xFFFFFFFF), "protective length")
        self.assertEqual(mbr[462:510], bytes(48), "no other MBR entry is used")

    def test_primary_header(self) -> None:
        header = self.read(LBA, LBA)
        self.assertEqual(header[0:8], b"EFI PART", "signature")
        revision, header_size, header_crc, reserved = struct.unpack_from("<IIII", header, 8)
        self.assertEqual(revision, 0x00010000, "revision 1.0")
        self.assertEqual(header_size, 92, "UEFI header size")
        self.assertEqual(reserved, 0, "reserved field")
        self.assertEqual(struct.unpack_from("<Q", header, 24)[0], 1, "my_lba")
        self.assertEqual(struct.unpack_from("<Q", header, 32)[0], TOTAL_LBA - 1, "alternate_lba")
        first_usable, last_usable = struct.unpack_from("<QQ", header, 40)
        self.assertEqual(first_usable, 34, "entries end at LBA 33")
        self.assertGreater(last_usable, first_usable)
        entries_lba, count, size, entries_crc = struct.unpack_from("<QIII", header, 72)
        self.assertEqual(entries_lba, 2, "primary entry array at LBA 2")
        self.assertEqual(count, ENTRY_COUNT)
        self.assertEqual(size, ENTRY_SIZE)
        zeroed = bytearray(header[:header_size])
        zeroed[16:20] = bytes(4)
        self.assertEqual(crc32(bytes(zeroed)), header_crc, "header CRC")
        entries = self.read(entries_lba * LBA, count * size)
        self.assertEqual(crc32(entries), entries_crc, "entry array CRC")

    def test_hxfs_partition_entry(self) -> None:
        entries = self.read(2 * LBA, ENTRY_COUNT * ENTRY_SIZE)
        used = [
            index
            for index in range(ENTRY_COUNT)
            if entries[index * ENTRY_SIZE : index * ENTRY_SIZE + 16] != bytes(16)
        ]
        self.assertEqual(used, [0], "exactly one partition, and it is partition 1")
        entry = entries[:ENTRY_SIZE]
        self.assertEqual(entry[0:16], HXFS_GUID, "HxFS v7 type GUID")
        self.assertNotEqual(entry[16:32], bytes(16), "unique GUID is set")
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        self.assertEqual(first_lba, FIRST_LBA, "1 MiB aligned start")
        self.assertEqual(first_lba % 8, 0, "4 KiB aligned start")
        self.assertEqual((last_lba - first_lba + 1) // 8, VOLUME_BLOCKS)
        self.assertLessEqual(last_lba, TOTAL_LBA - 34, "stays inside the usable range")
        name = entry[56:128].decode("utf-16-le").rstrip("\x00")
        self.assertEqual(name, "HxFS v7", "UTF-16 partition name")

    def test_payload_lands_at_the_partition_start(self) -> None:
        start = FIRST_LBA * LBA
        self.assertEqual(start, 1024 * 1024)
        self.assertEqual(self.read(start, len(self.volume_head)), self.volume_head)
        tail_offset = start + VOLUME_BLOCKS * 4096 - len(self.volume_tail)
        self.assertEqual(self.read(tail_offset, len(self.volume_tail)), self.volume_tail)
        # Nothing of the volume may leak into the GPT head or the tail reserve.
        self.assertNotIn(self.volume_head[:16], self.read(0, start))
        self.assertNotIn(self.volume_tail, self.read(start + VOLUME_BLOCKS * 4096, 34 * 4096))

    def test_backup_header_mirrors_the_primary(self) -> None:
        primary = self.read(LBA, LBA)
        backup = self.read((TOTAL_LBA - 1) * LBA, LBA)
        self.assertEqual(backup[0:8], b"EFI PART", "backup signature")
        self.assertEqual(struct.unpack_from("<Q", backup, 24)[0], TOTAL_LBA - 1, "backup my_lba")
        self.assertEqual(struct.unpack_from("<Q", backup, 32)[0], 1, "backup alternate_lba")
        header_size = struct.unpack_from("<I", backup, 12)[0]
        zeroed = bytearray(backup[:header_size])
        zeroed[16:20] = bytes(4)
        self.assertEqual(crc32(bytes(zeroed)), struct.unpack_from("<I", backup, 16)[0])
        self.assertEqual(primary[8:16], backup[8:16], "revision and header size match")
        self.assertNotEqual(primary[16:20], backup[16:20], "the CRCs differ by design")
        self.assertEqual(primary[20:24], backup[20:24], "reserved field is zero in both")
        self.assertEqual(struct.unpack_from("<Q", backup, 72)[0], TOTAL_LBA - 33, "backup entries")
        self.assertEqual(
            self.read((TOTAL_LBA - 33) * LBA, ENTRY_COUNT * ENTRY_SIZE),
            self.read(2 * LBA, ENTRY_COUNT * ENTRY_SIZE),
            "backup entry array is byte-identical",
        )

    def test_image_is_sparse(self) -> None:
        size = self.image.stat().st_size
        allocated = self.image.stat().st_blocks * LBA
        self.assertEqual(size, TOTAL_BLOCKS * 4096, "the file is the whole disk")
        self.assertLess(allocated, size // 4, "the uncopied volume body stays a hole")

    def test_too_small_disk_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            gpt_image.wrap_volume(self.volume, self.base / "tiny.img", 256 + 34 + 64)


class GptRoundTrip(unittest.TestCase):
    def test_rewrap_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gpt-repeat-") as name:
            base = Path(name)
            volume = base / "volume.img"
            with volume.open("wb") as handle:
                handle.truncate(VOLUME_BLOCKS * 4096)
                handle.write(b"\xa5" * 4096)
            # The disk and partition GUIDs are derived from the output file
            # name, so wrapping the same volume to the same *name* in two
            # directories must produce byte-identical images: a table that
            # changed on every run would make `fdisk verify` useless.
            first = base / "a" / "disk.img"
            second = base / "b" / "disk.img"
            gpt_image.wrap_volume(volume, first, TOTAL_BLOCKS)
            gpt_image.wrap_volume(volume, second, TOTAL_BLOCKS)
            self.assertEqual(first.read_bytes(), second.read_bytes())


@unittest.skipUnless(shutil.which("cargo") or os.environ.get("CARGO"), "cargo is required")
class MkhxfsGptWiring(unittest.TestCase):
    """`mkhxfs.py --gpt` must subtract the GPT blocks and wrap the volume."""

    def test_mkhxfs_gpt_image(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gpt-mkhxfs-") as name:
            base = Path(name)
            image = base / "disk.img"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/mkhxfs.py"),
                    "--output",
                    str(image),
                    "--blocks",
                    str(TOTAL_BLOCKS),
                    "--gpt",
                ],
                cwd=base,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("gpt", result.stdout.lower(), "the layout is printed")
            self.assertEqual(image.stat().st_size, TOTAL_BLOCKS * 4096)
            with image.open("rb") as handle:
                head = handle.read(4096)
            self.assertEqual(head[510:512], b"\x55\xaa")
            self.assertEqual(head[512 + 0 : 512 + 8], b"EFI PART")
            self.assertEqual(head[446 + 4], 0xEE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
