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
    local reason="$1"
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
import sys

path = sys.argv[1]
img = bytearray(4 * 1024 * 1024)  # 8192 x 512B blocks
tag = b"HUESOS-USB3-BOT-SMOKE\n"
img[: len(tag)] = tag
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
python3 - "$qmp_socket" "$log" "$timeout_seconds" "$qmp_dir/py_err.txt" <<'PY'
import json
import socket
import sys
import time

qmp_path, serial_path, timeout_text, err_path = sys.argv[1:]
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
    "\n": "ret",
}

cmd_line = "lsusb -v --bot-smoke --log-serial\n"
for ch in cmd_line:
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
    time.sleep(0.05)
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
    time.sleep(0.05)

wait_serial('USB_BOT_SMOKE_OK block_size=512 blocks=8192 xfer=512 lba0_tag="HUESOS-USB3-BOT-SMOKE"')
qmp.close()
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
    'USB_BOT_SMOKE_OK block_size=512 blocks=8192 xfer=512 lba0_tag="HUESOS-USB3-BOT-SMOKE"'
)

for marker in "${required_markers[@]}"; do
    if ! grep -Fq "$marker" "$log"; then
        annotate_failure "missing marker: $marker"
        tail -200 "$log" >&2 || true
        exit 1
    fi
done

echo "[usb-xhci-smoke] PASS ($log)"
