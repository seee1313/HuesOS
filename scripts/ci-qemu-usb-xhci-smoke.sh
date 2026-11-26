#!/usr/bin/env bash
# End-to-end Asynchronous Ring-3 USB 3.x (`xHCI`) + Hub + HID + BOT + VT-d smoke.
#
# Boots Q35 under hardware Intel VT-d (`intel-iommu,intremap=off,caching-mode=on`)
# with `qemu-xhci` (`xhci0`), a downstream `usb-hub` (`port=1`) hosting both
# `usb-kbd` (`port=1.1`, `id=usbkbd0`) and `usb-mouse` (`port=1.2`), plus a
# SuperSpeed `usb-storage` Bulk-Only disk (`port=2`) seeded with
# `HUESOS-USB3-BOT-SMOKE` in LBA 0.
#
# Once `driver-host-xhci` and interactive `/bin/hsh.elf` report ready, a QMP
# client injects `lsusb -v --bot-smoke --log-serial\n` exclusively through the
# Hub-attached `usbkbd0` device and verifies:
#   - VT-d second-stage DMA isolation (`iommu=isolated`, zero DMAR faults)
#   - MSI-X vector `0xE0` binding & `HUSB v1` zero-bus-traffic VMO snapshot
#   - Root-port + Hub downstream enumeration (`usb-hub`, `usb-hid-kbd`,
#     `usb-hid-mouse`, `usb-storage-bot`)
#   - Live USB HID keystrokes multiplexed through `driver-manager` -> `terminal`
#     -> `hsh` -> `/bin/lsusb.elf`
#   - Live Ring-3 `open:block:usb` `AsyncBlockOp::Info` + `AsyncBlockOp::Read`
#     (`LBA 0`) matching `HUESOS-USB3-BOT-SMOKE`
#
# Usage: ci-qemu-usb-xhci-smoke.sh [profile=release] [cpus=2] [timeout=150]
set -euo pipefail

profile="${1:-release}"
cpus="${2:-2}"
timeout_seconds="${3:-150}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
mkdir -p "$artifact_dir" build

log="$artifact_dir/qemu-usb-xhci-${profile}-smp${cpus}.log"
nvme_img="build/nvme-usb-xhci.img"
usb_img="build/usb-bot-smoke.img"
qmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/huesos-usb-qmp.XXXXXX")"
qmp_socket="$qmp_dir/monitor.sock"
rm -f "$log" "$nvme_img" "$usb_img"
qemu_pid=""

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill -TERM "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$qmp_dir"
    echo "init_args=foo" > build/cmdline.txt
}
trap cleanup EXIT

echo "log=verbose" > build/cmdline.txt

annotate_failure() {
    local reason="${1//$'\n'/ }"
    printf '::error::ci-qemu-usb-xhci-smoke: %s (profile=%s smp=%s)\n' \
        "$reason" "$profile" "$cpus"
    while IFS= read -r line; do
        printf '::error::usb| %s\n' "$line"
    done < <(grep -E '(xhci|HUSB|lsusb|USB_BOT|usb)' "$log" 2>/dev/null | tail -n 5 || true)
    while IFS= read -r line; do
        printf '::error::serial| %s\n' "$line"
    done < <(tail -n 4 "$log" 2>/dev/null || true)
}

build_log="build/usb-xhci-smoke-build.log"
set +e
case "$profile" in
    debug)   CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug >"$build_log" 2>&1 ;;
    release) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release >"$build_log" 2>&1 ;;
    *) echo "unsupported profile: $profile" >&2; exit 2 ;;
esac
build_status=$?
set -e
if [[ "$build_status" != 0 ]]; then
    cat "$build_log" >&2 || true
    while IFS= read -r line; do
        printf '::error::build| %s\n' "$line"
    done < <(grep -E 'error(\[E[0-9]+\])?:|-->' "$build_log" | head -n 25 || tail -n 20 "$build_log")
    exit "$build_status"
fi

python3 tools/mkhxfs.py --output "$nvme_img" --blocks 16384 >/dev/null
python3 - "$usb_img" <<'PY'
import struct
import sys

path = sys.argv[1]
TOTAL_SECTORS = 73728  # 36 MiB (73728 x 512B blocks -> >= 65525 FAT32 clusters)
PART_START = 64
PART_SECTORS = TOTAL_SECTORS - PART_START
RESERVED = 32
NUM_FATS = 2
FAT_SECTORS = 576  # 576 * 128 = 73728 FAT32 entries
SPC = 1

img = bytearray(TOTAL_SECTORS * 512)

# LBA 0: preserve BOT smoke marker in boot-code bytes + MBR partition 1 (0x0C FAT32 LBA).
tag = b"HUESOS-USB3-BOT-SMOKE\n"
img[: len(tag)] = tag
part_entry = struct.pack("<BBBBBBBBII", 0x80, 0, 1, 0, 0x0C, 0xFE, 0xFF, 0xFF, PART_START, PART_SECTORS)
img[446 : 446 + 16] = part_entry
img[510:512] = b"\x55\xAA"

# FAT32 BPB at PART_START.
bpb = bytearray(512)
bpb[0:3] = b"\xEB\x58\x90"
bpb[3:11] = b"HUESFAT3"
struct.pack_into("<HBHBHHBHHHII", bpb, 11, 512, SPC, RESERVED, NUM_FATS, 0, 0, 0xF8, 0, 63, 255, PART_START, PART_SECTORS)
struct.pack_into("<IHHIHH", bpb, 36, FAT_SECTORS, 0, 0, 2, 1, 6)
bpb[64] = 0x80
bpb[66] = 0x29
struct.pack_into("<I", bpb, 67, 0x20261123)
bpb[71:82] = b"HUESOS USB0"
bpb[82:90] = b"FAT32   "
bpb[510:512] = b"\x55\xAA"
img[PART_START * 512 : (PART_START + 1) * 512] = bpb

# FSInfo at PART_START + 1.
fsinfo = bytearray(512)
struct.pack_into("<I", fsinfo, 0, 0x41615252)
struct.pack_into("<I", fsinfo, 484, 0x61417272)
struct.pack_into("<II", fsinfo, 488, 0xFFFFFFFF, 5)
fsinfo[510:512] = b"\x55\xAA"
img[(PART_START + 1) * 512 : (PART_START + 2) * 512] = fsinfo


def set_fat(cl: int, val: int) -> None:
    for copy in range(NUM_FATS):
        off = (PART_START + RESERVED + copy * FAT_SECTORS) * 512 + cl * 4
        struct.pack_into("<I", img, off, val & 0x0FFFFFFF)


def cl_off(cl: int) -> int:
    first_data = PART_START + RESERVED + NUM_FATS * FAT_SECTORS
    return (first_data + (cl - 2) * SPC) * 512


def lfn_checksum(short11: bytes) -> int:
    s = 0
    for b in short11:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def make_lfn_entries(long_name: str, short11: bytes, attr: int, cluster: int, size: int) -> bytes:
    chk = lfn_checksum(short11)
    u16 = [ord(c) for c in long_name]
    chunks = []
    for i in range(0, len(u16), 13):
        part = u16[i : i + 13]
        if len(part) < 13:
            part = part + [0x0000] + [0xFFFF] * (12 - len(part))
        chunks.append(part)
    out = bytearray()
    total = len(chunks)
    for seq_rev, part in enumerate(reversed(chunks)):
        seq = total - seq_rev
        ord_byte = seq | (0x40 if seq_rev == 0 else 0)
        ent = bytearray(32)
        ent[0] = ord_byte
        for idx, ch in enumerate(part[:5]):
            struct.pack_into("<H", ent, 1 + idx * 2, ch)
        ent[11] = 0x0F
        ent[12] = 0
        ent[13] = chk
        for idx, ch in enumerate(part[5:11]):
            struct.pack_into("<H", ent, 14 + idx * 2, ch)
        struct.pack_into("<H", ent, 26, 0)
        for idx, ch in enumerate(part[11:13]):
            struct.pack_into("<H", ent, 28 + idx * 2, ch)
        out.extend(ent)
    sfn = bytearray(32)
    sfn[0:11] = short11
    sfn[11] = attr
    struct.pack_into("<H", sfn, 20, (cluster >> 16) & 0xFFFF)
    struct.pack_into("<H", sfn, 26, cluster & 0xFFFF)
    struct.pack_into("<I", sfn, 28, size)
    out.extend(sfn)
    return bytes(out)


set_fat(0, 0x0FFFFFF8)
set_fat(1, 0x0FFFFFFF)
set_fat(2, 0x0FFFFFFF)  # root dir
set_fat(3, 0x0FFFFFFF)  # HelloFromHost.txt
set_fat(4, 0x0FFFFFFF)  # smoke.hsh

hello_bytes = b"FAT32-LFN-HOST-SEED-OK\n"
smoke_script = (
    b"mkdir /tmp\n"
    b"ls /mnt/usb0 > /mnt/usb0/ls_root.txt\n"
    b"cat /mnt/usb0/HelloFromHost.txt > /tmp/from_usb.txt\n"
    b"mkdir /mnt/usb0/sub\n"
    b"cp /tmp/from_usb.txt /mnt/usb0/sub/CopiedLongName.txt\n"
    b"write /mnt/usb0/sub/tmp_rm.txt DELETE-ME\n"
    b"rm /mnt/usb0/sub/tmp_rm.txt\n"
    b"lsblk -f /dev/block/usb0 > /mnt/usb0/sub/lsblk.txt\n"
    b"df -h /mnt/usb0 > /mnt/usb0/sub/df.txt\n"
    b"write /mnt/usb0/sub/done.txt USB-FAT32-E2E-OK\n"
)

img[cl_off(3) : cl_off(3) + len(hello_bytes)] = hello_bytes
img[cl_off(4) : cl_off(4) + len(smoke_script)] = smoke_script

root_entries = bytearray()
root_entries.extend(make_lfn_entries("HelloFromHost.txt", b"HELLOF~1TXT", 0x20, 3, len(hello_bytes)))
root_entries.extend(make_lfn_entries("smoke.hsh", b"SMOKE   HSH", 0x20, 4, len(smoke_script)))
img[cl_off(2) : cl_off(2) + len(root_entries)] = root_entries

with open(path, "wb") as f:
    f.write(img)
PY

qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp "$cpus" -m 512M \
    -device intel-iommu,intremap=off,caching-mode=on \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -drive "id=nvme0,if=none,format=raw,file=${nvme_img}" \
    -device nvme,serial=huesosnvme,id=nvme-ctrl \
    -device nvme-ns,drive=nvme0,bus=nvme-ctrl,nsid=1 \
    -device qemu-xhci,id=xhci0 \
    -device usb-hub,bus=xhci0.0,port=1,id=hub0 \
    -device usb-kbd,bus=xhci0.0,port=1.1,id=usbkbd0 \
    -device usb-mouse,bus=xhci0.0,port=1.2,id=usbmouse0 \
    -drive "id=usbdisk0,if=none,format=raw,file=${usb_img}" \
    -device usb-storage,bus=xhci0.0,port=2,drive=usbdisk0,id=usbmsd0 \
    -net none -display none -serial "file:$log" \
    -qmp "unix:$qmp_socket,server=on,wait=off" \
    -no-reboot -no-shutdown &
qemu_pid=$!

set +e
python3 - "$qmp_socket" "$log" "$usb_img" "$timeout_seconds" "$qmp_dir/py_err.txt" <<'PY'
import json
import socket
import struct
import sys
import time

qmp_path, serial_path, usb_img_path, timeout_text, err_path = sys.argv[1:]
deadline = time.monotonic() + float(timeout_text)


def fail(msg: str) -> "NoReturn":
    try:
        with open(err_path, "w", encoding="utf-8") as ef:
            ef.write(msg)
    except OSError:
        pass
    raise SystemExit(msg)


def wait_serial(marker: str) -> str:
    while time.monotonic() < deadline:
        try:
            with open(serial_path, "r", encoding="utf-8", errors="replace") as f:
                contents = f.read()
            if "KERNEL PANIC" in contents or "[driver-host:xhci] PANIC" in contents:
                fail(f"panic observed while waiting for {marker!r}")
            if marker in contents:
                return contents
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    fail(f"timed out waiting for serial marker {marker!r}")


while time.monotonic() < deadline:
    try:
        qmp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        qmp.settimeout(5.0)
        qmp.connect(qmp_path)
        break
    except OSError:
        try:
            qmp.close()
        except Exception:
            pass
        time.sleep(0.1)
else:
    fail("timed out waiting for QEMU QMP socket")

stream = qmp.makefile("rwb", buffering=0)
greeting = json.loads(stream.readline())
if "QMP" not in greeting:
    fail(f"unexpected QMP greeting: {greeting!r}")

req_seq = 0


def qmp_cmd(execute: str, arguments=None):
    global req_seq
    req_seq += 1
    req_id = f"r{req_seq}"
    payload = {"execute": execute, "id": req_id}
    if arguments is not None:
        payload["arguments"] = arguments
    stream.write(json.dumps(payload).encode() + b"\r\n")
    while True:
        line = stream.readline()
        if not line:
            fail(f"EOF waiting for QMP {execute}")
        msg = json.loads(line)
        if msg.get("id") == req_id:
            if "error" in msg:
                fail(f"QMP {execute} failed: {msg['error']}")
            return msg.get("return")


qmp_cmd("qmp_capabilities")
wait_serial("[driver-host:xhci] controller online")
wait_serial("[driver-host:xhci] BOT storage online")
wait_serial("[driver-host:xhci] attached keyboard client")
wait_serial("[hsh] interactive prompt ready")
time.sleep(0.25)

QCODE_MAP = {
    " ": "spc",
    "-": "minus",
    "/": "slash",
    ".": "dot",
    "_": "minus",
    "\n": "ret",
}


def send_line(text: str) -> None:
    for ch in text:
        qcode = QCODE_MAP.get(ch, ch)
        qmp_cmd(
            "input-send-event",
            {
                "events": [
                    {
                        "type": "key",
                        "data": {"down": True, "key": {"type": "qcode", "data": qcode}},
                    }
                ]
            },
        )
        time.sleep(0.04)
        qmp_cmd(
            "input-send-event",
            {
                "events": [
                    {
                        "type": "key",
                        "data": {"down": False, "key": {"type": "qcode", "data": qcode}},
                    }
                ]
            },
        )
        time.sleep(0.04)


send_line("lsusb -v --bot-smoke --log-serial\n")
wait_serial('USB_BOT_SMOKE_OK block_size=512 blocks=73728 xfer=512 lba0_tag="HUESOS-USB3-BOT-SMOKE"')
time.sleep(0.3)

send_line("hsh /mnt/usb0/smoke.hsh\n")
while time.monotonic() < deadline:
    with open(usb_img_path, "rb") as uf:
        blob = uf.read()
    if b"USB-FAT32-E2E-OK" in blob:
        break
    with open(serial_path, "r", encoding="utf-8", errors="replace") as sf:
        sc = sf.read()
    if "KERNEL PANIC" in sc or "[driver-host:xhci] PANIC" in sc:
        fail("panic observed while running /mnt/usb0/smoke.hsh")
    time.sleep(0.2)
else:
    fail("timed out waiting for /mnt/usb0/smoke.hsh to persist USB-FAT32-E2E-OK on usb-storage")

try:
    qmp_cmd("quit")
except Exception:
    pass
qmp.close()
time.sleep(0.2)

with open(usb_img_path, "rb") as uf:
    disk = uf.read()

if disk[:22] != b"HUESOS-USB3-BOT-SMOKE\n":
    fail("LBA 0 BOT smoke tag was overwritten")

PART_START = 64
RESERVED = 32
NUM_FATS = 2
FAT_SECTORS = 576
FIRST_DATA = PART_START + RESERVED + NUM_FATS * FAT_SECTORS


def fat_next(cl: int) -> int:
    off = (PART_START + RESERVED) * 512 + cl * 4
    return struct.unpack_from("<I", disk, off)[0] & 0x0FFFFFFF


def read_chain(start_cl: int) -> bytes:
    if start_cl < 2:
        return b""
    out = bytearray()
    cl = start_cl
    seen = set()
    while 2 <= cl < 0x0FFFFFF8 and cl not in seen:
        seen.add(cl)
        off = (FIRST_DATA + (cl - 2)) * 512
        out.extend(disk[off : off + 512])
        cl = fat_next(cl)
    return bytes(out)


def parse_dir(raw: bytes) -> dict:
    entries = {}
    lfn_parts = {}
    for off in range(0, len(raw), 32):
        ent = raw[off : off + 32]
        if ent[0] == 0x00:
            break
        if ent[0] == 0xE5:
            lfn_parts.clear()
            continue
        if ent[11] == 0x0F:
            seq = ent[0] & 0x1F
            chars = []
            for p in (1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30):
                u = struct.unpack_from("<H", ent, p)[0]
                if u in (0x0000, 0xFFFF):
                    break
                chars.append(chr(u))
            lfn_parts[seq] = "".join(chars)
            continue
        if ent[11] & 0x08:
            lfn_parts.clear()
            continue
        if lfn_parts:
            name = "".join(lfn_parts[k] for k in sorted(lfn_parts))
        else:
            stem = ent[0:8].decode("ascii", errors="replace").rstrip(" ")
            ext = ent[8:11].decode("ascii", errors="replace").rstrip(" ")
            name = f"{stem}.{ext}" if ext else stem
        lfn_parts.clear()
        if name in (".", ".."):
            continue
        hi = struct.unpack_from("<H", ent, 20)[0]
        lo = struct.unpack_from("<H", ent, 26)[0]
        cl = (hi << 16) | lo
        sz = struct.unpack_from("<I", ent, 28)[0]
        is_dir = bool(ent[11] & 0x10)
        entries[name] = (is_dir, cl, sz)
    return entries


root = parse_dir(read_chain(2))
if "ls_root.txt" not in root or "sub" not in root:
    fail(f"expected ls_root.txt and sub in FAT32 root, got: {sorted(root)}")

ls_root_text = read_chain(root["ls_root.txt"][1])[: root["ls_root.txt"][2]].decode("utf-8", errors="replace")
if "HelloFromHost.txt" not in ls_root_text or "smoke.hsh" not in ls_root_text:
    fail(f"unexpected /mnt/usb0 ls output: {ls_root_text!r}")

sub = parse_dir(read_chain(root["sub"][1]))
if "tmp_rm.txt" in sub:
    fail("rm /mnt/usb0/sub/tmp_rm.txt did not remove FAT32 entry")
for expected in ("CopiedLongName.txt", "lsblk.txt", "df.txt", "done.txt"):
    if expected not in sub:
        fail(f"missing /mnt/usb0/sub/{expected} in FAT32 subdir: {sorted(sub)}")

copied = read_chain(sub["CopiedLongName.txt"][1])[: sub["CopiedLongName.txt"][2]]
if copied != b"FAT32-LFN-HOST-SEED-OK\n":
    fail(f"CopiedLongName.txt content mismatch: {copied!r}")

lsblk_txt = read_chain(sub["lsblk.txt"][1])[: sub["lsblk.txt"][2]].decode("utf-8", errors="replace")
for tok in ("/dev/block/usb0", "vfat", "FAT32", "/mnt/usb0"):
    if tok not in lsblk_txt:
        fail(f"lsblk.txt missing {tok!r}: {lsblk_txt!r}")

df_txt = read_chain(sub["df.txt"][1])[: sub["df.txt"][2]].decode("utf-8", errors="replace")
for tok in ("fat32", "/mnt/usb0"):
    if tok not in df_txt:
        fail(f"df.txt missing {tok!r}: {df_txt!r}")

done_txt = read_chain(sub["done.txt"][1])[: sub["done.txt"][2]].decode("utf-8", errors="replace")
if "USB-FAT32-E2E-OK" not in done_txt:
    fail(f"done.txt mismatch: {done_txt!r}")
PY
py_status=$?
set -e

if [[ "$py_status" != 0 ]]; then
    py_reason="$(cat "$qmp_dir/py_err.txt" 2>/dev/null || echo "QMP USB HID / BOT smoke failed")"
    annotate_failure "$py_reason"
    tail -200 "$log" >&2 || true
    exit 1
fi

if grep -Fq 'KERNEL PANIC' "$log" || grep -Fq '[iommu] FAULT' "$log"; then
    annotate_failure "kernel panic or VT-d DMAR fault detected"
    tail -200 "$log" >&2 || true
    exit 1
fi

required_markers=(
    '[iommu] Intel VT-d active:'
    '[pci-manager] obs xhci'
    'status=handed-off'
    '[driver-manager] attached DmaPool to DeviceLease for driver-host-xhci'
    '[driver-host:xhci] controller online'
    '[driver-host:xhci] first USB HID keyboard report delivered'
    'iommu=true'
    'HUSB v1'
    'iommu=isolated msi=true'
    'drv usb-hub'
    'drv usb-hid-kbd'
    'drv usb-hid-mouse'
    'drv usb-storage-bot'
    'USB_BOT_SMOKE_OK block_size=512 blocks=73728 xfer=512 lba0_tag="HUESOS-USB3-BOT-SMOKE"'
)

for marker in "${required_markers[@]}"; do
    if ! grep -Fq "$marker" "$log"; then
        annotate_failure "missing marker: $marker"
        tail -200 "$log" >&2 || true
        exit 1
    fi
done

echo "[usb-xhci-smoke] PASS ($log)"
