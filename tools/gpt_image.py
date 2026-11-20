#!/usr/bin/env python3
"""Protective-MBR + GPT wrapping for HxFS volume images.

HuesOS does not invent a container format: a disk that carries an HxFS volume
is a normal GPT disk whose partition has the HxFS v7 type GUID. This module is
the *generator* half of that contract — it takes a formatted HxFS volume image
and places it inside a partitioned image:

    LBA 0            protective MBR (one 0xEE entry covering the whole disk)
    LBA 1            primary GPT header
    LBA 2..33        primary partition-entry array (128 x 128 B)
    LBA 2048..       the HxFS v7 partition (1 MiB aligned, 4 KiB aligned)
    LBA last-33..-2  backup partition-entry array
    LBA last         backup GPT header

The reader half lives in `hxfs-service` (`gpt_hxfs_partition`) and `/bin/fdisk`
(`huesos-gpt`). All three must agree on two things, so both are stated once
here and mirrored by named constants in Rust:

* the HxFS v7 partition type GUID is
  `48584653-0007-4855-4553-4f5356374750`, on-disk bytes
  `53 46 58 48 07 00 55 48 45 53 4f 53 56 37 47 50`
  (`huesos_gpt::GUID_HXFS_V7` / `GUID_HXFS_V7_BYTES`);
* partition LBAs are 512-byte units, because that is what the GPT standard,
  `fdisk`, and QEMU's NVMe namespace all speak. The HxFS mount path converts
  to its own 4 KiB blocks, which is why the partition must stay 4 KiB aligned.

Nothing here allocates the whole image: the output is written sparse (GPT
structures at both ends, partition data copied from the volume's *data*
extents with `SEEK_DATA`), so a 4 GiB disk image that holds a 20 MiB volume
costs 20 MiB of disk, not 4 GiB.
"""

from __future__ import annotations

import os
import struct
import uuid
import zlib
from pathlib import Path

LBA_SIZE = 512
BLOCK_4K = 4096
LBA_PER_BLOCK = BLOCK_4K // LBA_SIZE

GPT_SIGNATURE = b"EFI PART"
GPT_REVISION = 0x0001_0000
GPT_HEADER_BYTES = 92
GPT_ENTRY_BYTES = 128
GPT_ENTRY_COUNT = 128
GPT_ENTRY_LBAS = (GPT_ENTRY_COUNT * GPT_ENTRY_BYTES) // LBA_SIZE  # 32

# 4 KiB blocks reserved at each end of the disk: 1 MiB of headroom (1 MiB
# alignment is the usual modern choice and keeps the partition 4 KiB aligned)
# and 34 blocks for the backup entries + backup header.
GPT_HEAD_4K = 256
GPT_TAIL_4K = 34

# HuesOS's own partition type: "HXFS" / version 7 / "HUESOS" "V7" "GP".
HXFS_PARTITION_TYPE = bytes.fromhex("534658480700554845534f5356374750")
HXFS_PARTITION_NAME = "HxFS v7"


def protective_mbr(total_lba: int) -> bytes:
    """A one-entry protective MBR covering the whole disk.

    MBR partition entry layout, which the offsets below follow exactly:
    status(0) | CHS first(1..4) | type(4) | CHS last(5..8) | first LBA(8..12)
    | sector count(12..16). The UEFI spec calls for StartingCHS = 0x000200 and
    EndingCHS = 0xFFFFFF on a protective entry; the LBA fields are what tools
    actually read, but getting the CHS bytes wrong shifts every field after
    them and silently writes into the next entry.
    """
    sector = bytearray(LBA_SIZE)
    entry = 446
    sector[entry] = 0x00  # status: not bootable
    sector[entry + 1 : entry + 4] = b"\x00\x02\x00"  # CHS start: head 0, sector 2
    sector[entry + 4] = 0xEE  # type: GPT protective
    sector[entry + 5 : entry + 8] = b"\xff\xff\xff"  # CHS last: sentinel
    struct.pack_into("<I", sector, entry + 8, 1)  # first LBA: the GPT header
    struct.pack_into(
        "<I", sector, entry + 12, min(total_lba - 1, 0xFFFF_FFFF)
    )  # sector count: the rest of the disk
    sector[510] = 0x55
    sector[511] = 0xAA
    return bytes(sector)


def partition_entries(partitions: list[dict], entry_count: int = GPT_ENTRY_COUNT) -> bytes:
    """Encode `partitions` into a zero-padded GPT entry array."""
    array = bytearray(entry_count * GPT_ENTRY_BYTES)
    for index, part in enumerate(partitions):
        if index >= entry_count:
            raise ValueError("more partitions than GPT entries")
        offset = index * GPT_ENTRY_BYTES
        name = part["name"].encode("utf-16-le")[:72]
        array[offset : offset + 16] = part["type_guid"]
        array[offset + 16 : offset + 32] = part["unique_guid"]
        struct.pack_into("<Q", array, offset + 32, part["first_lba"])
        struct.pack_into("<Q", array, offset + 40, part["last_lba"])
        struct.pack_into("<Q", array, offset + 48, part.get("attributes", 0))
        array[offset + 56 : offset + 56 + len(name)] = name
    return bytes(array)


def gpt_header(
    my_lba: int,
    alternate_lba: int,
    first_usable_lba: int,
    last_usable_lba: int,
    disk_guid: uuid.UUID,
    entries_lba: int,
    entries_crc32: int,
    entry_count: int = GPT_ENTRY_COUNT,
) -> bytes:
    """Encode one GPT header sector (512 B, header CRC computed here)."""
    header = bytearray(LBA_SIZE)
    header[0:8] = GPT_SIGNATURE
    struct.pack_into("<I", header, 8, GPT_REVISION)
    struct.pack_into("<I", header, 12, GPT_HEADER_BYTES)
    struct.pack_into("<I", header, 20, 0)  # reserved
    struct.pack_into("<Q", header, 24, my_lba)
    struct.pack_into("<Q", header, 32, alternate_lba)
    struct.pack_into("<Q", header, 40, first_usable_lba)
    struct.pack_into("<Q", header, 48, last_usable_lba)
    header[56:72] = disk_guid.bytes_le
    struct.pack_into("<Q", header, 72, entries_lba)
    struct.pack_into("<I", header, 80, entry_count)
    struct.pack_into("<I", header, 84, GPT_ENTRY_BYTES)
    struct.pack_into("<I", header, 88, entries_crc32)
    struct.pack_into("<I", header, 16, zlib.crc32(bytes(header[:GPT_HEADER_BYTES])) & 0xFFFF_FFFF)
    return bytes(header)


def copy_sparse(src: Path, dst, dst_offset: int) -> None:
    """Copy `src` to `dst` at `dst_offset`, skipping holes.

    The volume images produced by `tools/hxfs-seed.sh` are sparse: metadata at
    the front, nothing else. A chunked copy would materialise gigabytes of
    zeros for a large `--blocks` value, so the copy walks the source's data
    extents when the filesystem supports `SEEK_DATA`/`SEEK_HOLE` and falls
    back to "write only the non-zero chunks" where it does not.
    """
    size = src.stat().st_size
    with open(src, "rb") as handle:
        fd = handle.fileno()
        seek_data = hasattr(os, "SEEK_DATA") and hasattr(os, "SEEK_HOLE")
        if seek_data:
            pos = 0
            while pos < size:
                try:
                    data_start = os.lseek(fd, pos, os.SEEK_DATA)
                except OSError:
                    break  # no more data extents
                if data_start >= size:
                    break
                hole_start = os.lseek(fd, data_start, os.SEEK_HOLE)
                os.lseek(fd, data_start, os.SEEK_SET)
                remaining = hole_start - data_start
                dst.seek(dst_offset + data_start)
                while remaining > 0:
                    chunk = handle.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    dst.write(chunk)
                    remaining -= len(chunk)
                pos = hole_start
            return
        # Portable fallback: write every chunk that is not all zeros.
        pos = 0
        while pos < size:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            if chunk.count(0) != len(chunk):
                dst.seek(dst_offset + pos)
                dst.write(chunk)
            pos += len(chunk)


def wrap_volume(
    volume_path: Path,
    out_path: Path,
    total_blocks_4k: int,
    *,
    disk_guid: uuid.UUID | None = None,
    part_guid: uuid.UUID | None = None,
    entry_count: int = GPT_ENTRY_COUNT,
) -> dict:
    """Write a partitioned image at `out_path` holding `volume_path`.

    Returns the layout actually used (start/end LBAs, block counts) so callers
    can print it and tests can assert on it.
    """
    if total_blocks_4k <= GPT_HEAD_4K + GPT_TAIL_4K + 64:
        raise ValueError("image is too small for a GPT plus an HxFS volume")
    volume_blocks_4k = total_blocks_4k - GPT_HEAD_4K - GPT_TAIL_4K
    total_bytes = total_blocks_4k * BLOCK_4K
    total_lba = total_bytes // LBA_SIZE

    first_lba = GPT_HEAD_4K * LBA_PER_BLOCK  # 2048
    last_lba = first_lba + volume_blocks_4k * LBA_PER_BLOCK - 1
    if last_lba >= total_lba - GPT_TAIL_4K * LBA_PER_BLOCK:
        raise ValueError("partition does not fit before the backup GPT")

    disk_guid = disk_guid or uuid.uuid5(uuid.NAMESPACE_OID, f"huesos-gpt:{out_path.name}")
    part_guid = part_guid or uuid.uuid5(uuid.NAMESPACE_OID, f"huesos-hxfs:{out_path.name}")

    entries = partition_entries(
        [
            {
                "type_guid": HXFS_PARTITION_TYPE,
                "unique_guid": part_guid.bytes_le,
                "first_lba": first_lba,
                "last_lba": last_lba,
                "name": HXFS_PARTITION_NAME,
            }
        ],
        entry_count,
    )
    entries_crc = zlib.crc32(entries) & 0xFFFF_FFFF
    first_usable = 2 + (entry_count * GPT_ENTRY_BYTES) // LBA_SIZE
    last_usable = total_lba - 1 - (entry_count * GPT_ENTRY_BYTES) // LBA_SIZE - 1

    primary = gpt_header(
        my_lba=1,
        alternate_lba=total_lba - 1,
        first_usable_lba=first_usable,
        last_usable_lba=last_usable,
        disk_guid=disk_guid,
        entries_lba=2,
        entries_crc32=entries_crc,
        entry_count=entry_count,
    )
    backup_entries_lba = total_lba - 1 - (entry_count * GPT_ENTRY_BYTES) // LBA_SIZE
    backup = gpt_header(
        my_lba=total_lba - 1,
        alternate_lba=1,
        first_usable_lba=first_usable,
        last_usable_lba=last_usable,
        disk_guid=disk_guid,
        entries_lba=backup_entries_lba,
        entries_crc32=entries_crc,
        entry_count=entry_count,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as out:
        out.truncate(total_bytes)
        out.seek(0)
        out.write(protective_mbr(total_lba))
        out.write(primary)
        out.write(entries)  # LBA 2..33
        out.seek(backup_entries_lba * LBA_SIZE)
        out.write(entries)
        out.seek((total_lba - 1) * LBA_SIZE)
        out.write(backup)
        copy_sparse(volume_path, out, first_lba * LBA_SIZE)
        out.flush()
        os.fsync(out.fileno())

    return {
        "total_blocks_4k": total_blocks_4k,
        "volume_blocks_4k": volume_blocks_4k,
        "first_lba": first_lba,
        "last_lba": last_lba,
        "part_start_block_4k": GPT_HEAD_4K,
    }
