#!/usr/bin/env python3
"""Small dependency-free helpers for HxFS v6 development images/tools."""

from __future__ import annotations

import json
from pathlib import Path

BLOCK_SIZE = 4096
FORMAT_GUID = bytes([
    0x48, 0x78, 0x66, 0x73, 0x2D, 0x48, 0x75, 0x65,
    0x73, 0x4F, 0x53, 0x2D, 0x76, 0x31, 0x00, 0x01,
])
FORMAT_VERSION = 6
TYPE_SYSTEM_VERSION = 6
BLOCK_TYPE_SUPERBLOCK = 1
BLOCK_TYPE_CHECKPOINT = 2
BLOCK_TYPE_VOLUME_TABLE = 3
BLOCK_TYPE_OBJECT_TABLE = 4
BLOCK_TYPE_DIRECTORY = 5
OBJECT_TYPE_DIRECTORY = 2
VOLUME_FLAG_SYSTEM = 1
BASE_INCOMPAT_FEATURES = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 8)
ROOT_STATE_CLEAN = 1


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
            crc &= 0xFFFFFFFF
    return (~crc) & 0xFFFFFFFF


def metadata_crc32c(block: bytearray | bytes) -> int:
    data = bytearray(block)
    data[32:36] = b"\x00\x00\x00\x00"
    return crc32c(bytes(data))


def le16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def le32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def le64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def make_block(block_type: int, owner: int, lba: int, payload: bytes) -> bytes:
    if len(payload) > BLOCK_SIZE - 40:
        raise ValueError("metadata payload too large")
    block = bytearray(BLOCK_SIZE)
    block[0:4] = le32(block_type)
    block[4:6] = le16(1)
    block[6:8] = le16(40)
    block[8:16] = le64(1)
    block[16:24] = le64(owner)
    block[24:32] = le64(lba)
    block[36:40] = le32(len(payload))
    block[40:40 + len(payload)] = payload
    block[32:36] = le32(metadata_crc32c(block))
    return bytes(block)


def build_empty_image(size_blocks: int, instance_uuid: bytes, volume_uuid: bytes) -> bytes:
    if size_blocks < 8:
        raise ValueError("Hxfs image needs at least 8 blocks")
    if len(instance_uuid) != 16 or len(volume_uuid) != 16:
        raise ValueError("UUIDs must be exactly 16 bytes")
    image = bytearray(size_blocks * BLOCK_SIZE)

    super_payload = bytearray(120)
    super_payload[0:16] = FORMAT_GUID
    super_payload[16:20] = le32(FORMAT_VERSION)
    super_payload[20:24] = le32(TYPE_SYSTEM_VERSION)
    super_payload[24:40] = instance_uuid
    super_payload[40:48] = le64(1)
    super_payload[48:52] = le32(BLOCK_SIZE)
    super_payload[56:64] = le64(1)
    super_payload[104:112] = le64(BASE_INCOMPAT_FEATURES)
    super_payload[112:116] = le32(ROOT_STATE_CLEAN)
    image[0:BLOCK_SIZE] = make_block(BLOCK_TYPE_SUPERBLOCK, 0, 0, bytes(super_payload))

    checkpoint_payload = bytearray(128)
    checkpoint_payload[0:8] = le64(1)
    checkpoint_payload[8:16] = le64(2)
    checkpoint_payload[16:20] = le32(1)
    checkpoint_payload[24:40] = volume_uuid
    image[BLOCK_SIZE:BLOCK_SIZE * 2] = make_block(BLOCK_TYPE_CHECKPOINT, 0, 1, bytes(checkpoint_payload))

    volume_payload = bytearray(16 + 96)
    volume_payload[0:4] = le32(1)
    record = 16
    volume_payload[record:record + 16] = volume_uuid
    volume_payload[record + 16:record + 24] = le64(1)
    volume_payload[record + 24:record + 32] = le64(3)
    volume_payload[record + 32:record + 36] = le32(1)
    volume_payload[record + 36:record + 40] = le32(VOLUME_FLAG_SYSTEM)
    image[BLOCK_SIZE * 2:BLOCK_SIZE * 3] = make_block(BLOCK_TYPE_VOLUME_TABLE, 0, 2, bytes(volume_payload))

    object_payload = bytearray(16 + 64)
    object_payload[0:4] = le32(1)
    offset = 16
    object_payload[offset:offset + 8] = le64(1)
    object_payload[offset + 8:offset + 12] = le32(OBJECT_TYPE_DIRECTORY)
    object_payload[offset + 12:offset + 16] = le32(1)
    object_payload[offset + 40:offset + 48] = le64(4)
    image[BLOCK_SIZE * 3:BLOCK_SIZE * 4] = make_block(BLOCK_TYPE_OBJECT_TABLE, 1, 3, bytes(object_payload))

    dir_payload = bytearray(16)
    dir_payload[0:8] = le64(1)
    dir_payload[8:12] = le32(0)
    image[BLOCK_SIZE * 4:BLOCK_SIZE * 5] = make_block(BLOCK_TYPE_DIRECTORY, 1, 4, bytes(dir_payload))
    return bytes(image)


def build_empty_image_stream(
    out_path: Path,
    size_blocks: int,
    instance_uuid: bytes,
    volume_uuid: bytes,
) -> None:
    """Write an HxFS v6 empty image to `out_path` without buffering the full
    file in memory.

    The original `build_empty_image` materializes the entire image as a
    `bytearray`, which fails with `MemoryError` for any realistic NVMe
    target (a 4 GiB QEMU image needs 4 GiB of resident Python heap, far
    beyond the budget a developer or CI runner is willing to spend on a
    tooling step). This streaming variant writes the metadata blocks at
    the head of the file and then extends the file with zeroed blocks via
    sparse allocation, so the on-disk size matches `size_blocks` while
    peak Python memory stays at a single metadata block (~4 KiB).

    The resulting image is bit-for-bit identical to the in-memory builder
    for the metadata region; only the trailing region differs in that
    it is implicitly zero-filled by the filesystem instead of explicitly
    zero-filled in Python. Hxfs treats unwritten blocks as zero-filled by
    design, so this is safe.
    """
    if size_blocks < 8:
        raise ValueError("Hxfs image needs at least 8 blocks")
    if len(instance_uuid) != 16 or len(volume_uuid) != 16:
        raise ValueError("UUIDs must be exactly 16 bytes")

    super_payload = bytearray(120)
    super_payload[0:16] = FORMAT_GUID
    super_payload[16:20] = le32(FORMAT_VERSION)
    super_payload[20:24] = le32(TYPE_SYSTEM_VERSION)
    super_payload[24:40] = instance_uuid
    super_payload[40:48] = le64(1)
    super_payload[48:52] = le32(BLOCK_SIZE)
    super_payload[56:64] = le64(1)
    super_payload[104:112] = le64(BASE_INCOMPAT_FEATURES)
    super_payload[112:116] = le32(ROOT_STATE_CLEAN)
    superblock = make_block(BLOCK_TYPE_SUPERBLOCK, 0, 0, bytes(super_payload))

    checkpoint_payload = bytearray(128)
    checkpoint_payload[0:8] = le64(1)
    checkpoint_payload[8:16] = le64(2)
    checkpoint_payload[16:20] = le32(1)
    checkpoint_payload[24:40] = volume_uuid
    checkpoint = make_block(BLOCK_TYPE_CHECKPOINT, 0, 1, bytes(checkpoint_payload))

    volume_payload = bytearray(16 + 96)
    volume_payload[0:4] = le32(1)
    record = 16
    volume_payload[record:record + 16] = volume_uuid
    volume_payload[record + 16:record + 24] = le64(1)
    volume_payload[record + 24:record + 32] = le64(3)
    volume_payload[record + 32:record + 36] = le32(1)
    volume_payload[record + 36:record + 40] = le32(VOLUME_FLAG_SYSTEM)
    volume_table = make_block(BLOCK_TYPE_VOLUME_TABLE, 0, 2, bytes(volume_payload))

    object_payload = bytearray(16 + 64)
    object_payload[0:4] = le32(1)
    offset = 16
    object_payload[offset:offset + 8] = le64(1)
    object_payload[offset + 8:offset + 12] = le32(OBJECT_TYPE_DIRECTORY)
    object_payload[offset + 12:offset + 16] = le32(1)
    object_payload[offset + 40:offset + 48] = le64(4)
    object_table = make_block(BLOCK_TYPE_OBJECT_TABLE, 1, 3, bytes(object_payload))

    dir_payload = bytearray(16)
    dir_payload[0:8] = le64(1)
    dir_payload[8:12] = le32(0)
    directory = make_block(BLOCK_TYPE_DIRECTORY, 1, 4, bytes(dir_payload))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = size_blocks * BLOCK_SIZE
    metadata_bytes = 5 * BLOCK_SIZE
    with open(out_path, "wb") as f:
        f.write(superblock)
        f.write(checkpoint)
        f.write(volume_table)
        f.write(object_table)
        f.write(directory)
        if total_bytes > metadata_bytes:
            # Use sparse allocation: seek past the metadata region and
            # let the kernel extend the file with implicit zero blocks.
            # `truncate` afterwards ensures the file size matches the
            # requested image size even on filesystems that do not
            # honour sparse seeks (e.g. CI tmpfs with strict quota).
            f.seek(total_bytes - 1)
            f.write(b"\x00")
            f.truncate(total_bytes)


def parse_superblock(image: bytes) -> dict[str, object]:
    if len(image) < BLOCK_SIZE:
        raise ValueError("image too small")
    block = image[:BLOCK_SIZE]
    if int.from_bytes(block[32:36], "little") != metadata_crc32c(block):
        raise ValueError("bad superblock checksum")
    base = int.from_bytes(block[6:8], "little")
    return {
        "format_guid": block[base:base + 16].hex(),
        "format_version": int.from_bytes(block[base + 16:base + 20], "little"),
        "type_system_version": int.from_bytes(block[base + 20:base + 24], "little"),
        "instance_uuid": block[base + 24:base + 40].hex(),
        "sequence_number": int.from_bytes(block[base + 40:base + 48], "little"),
        "block_size": int.from_bytes(block[base + 48:base + 52], "little"),
        "checkpoint_lba": int.from_bytes(block[base + 56:base + 64], "little"),
        "journal_start_lba": int.from_bytes(block[base + 72:base + 80], "little"),
        "journal_end_lba": int.from_bytes(block[base + 80:base + 88], "little"),
        "incompatible_features": int.from_bytes(block[base + 104:base + 112], "little"),
        "root_state": int.from_bytes(block[base + 112:base + 116], "little"),
    }


def inspect_image(path: Path) -> dict[str, object]:
    # Read the two blocks we need by seeking, never the whole file.
    # Soak and power-fail images are multi-gigabyte and the previous
    # `path.read_bytes()` raised MemoryError on any normal machine --
    # which meant the offline inspection step could not run against
    # exactly the images it exists to inspect.
    size = path.stat().st_size
    if size < BLOCK_SIZE:
        raise ValueError("image too small")
    with path.open("rb") as handle:
        superblock = parse_superblock(handle.read(BLOCK_SIZE))
        checkpoint_lba = int(superblock["checkpoint_lba"])
        start = checkpoint_lba * BLOCK_SIZE
        if start + BLOCK_SIZE > size:
            raise ValueError(
                f"checkpoint LBA {checkpoint_lba} lies past the end of the image"
            )
        handle.seek(start)
        checkpoint = handle.read(BLOCK_SIZE)
    if int.from_bytes(checkpoint[32:36], "little") != metadata_crc32c(checkpoint):
        raise ValueError("bad checkpoint checksum")
    base = int.from_bytes(checkpoint[6:8], "little")
    roots = {
        "volume_table_lba": int.from_bytes(checkpoint[base + 8:base + 16], "little"),
        "allocation_tree_lba": int.from_bytes(checkpoint[base + 40:base + 48], "little"),
        "refcount_tree_lba": int.from_bytes(checkpoint[base + 48:base + 56], "little"),
        "backref_tree_lba": int.from_bytes(checkpoint[base + 56:base + 64], "little"),
        "quota_tree_lba": int.from_bytes(checkpoint[base + 64:base + 72], "little"),
        "encryption_policy_tree_lba": int.from_bytes(
            checkpoint[base + 72:base + 80], "little"
        ),
        "compression_policy_tree_lba": int.from_bytes(
            checkpoint[base + 80:base + 88], "little"
        ),
        "virtual_volume_tree_lba": int.from_bytes(checkpoint[base + 104:base + 112], "little"),
        "gpt_summary_lba": int.from_bytes(checkpoint[base + 112:base + 120], "little"),
        "install_manifest_lba": int.from_bytes(checkpoint[base + 120:base + 128], "little"),
    }
    return {"path": str(path), "bytes": size, "superblock": superblock, "checkpoint_roots": roots}


def print_json(data: object) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))
