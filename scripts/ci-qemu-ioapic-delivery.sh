#!/usr/bin/env bash
# QEMU end-to-end check that a real PS/2 edge interrupt traverses the
# IOAPIC/IDT bridge, kernel IRQ registry, Port, and userspace input DriverHost.
set -euo pipefail

profile="${1:-debug}"
cpus="${2:-2}"
timeout_seconds="${3:-120}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
mkdir -p "$artifact_dir"
log="$artifact_dir/qemu-ioapic-delivery-${profile}-smp${cpus}.log"
qmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/huesos-ioapic-qmp.XXXXXX")"
qmp_socket="$qmp_dir/monitor.sock"
rm -f "$log"
qemu_pid=""

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill -TERM "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$qmp_dir"
}
trap cleanup EXIT

case "$profile" in
    debug) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug ;;
    release) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release ;;
    *) echo "unsupported profile: $profile" >&2; exit 2 ;;
esac

qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp "$cpus" -m 512M \
    -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
    -net none -display none -serial "file:$log" \
    -qmp "unix:$qmp_socket,server=on,wait=off" \
    -no-reboot -no-shutdown &
qemu_pid=$!

python3 - "$qmp_socket" "$log" "$timeout_seconds" <<'PY'
import json
import socket
import sys
import time

qmp_path, serial_path, timeout_text = sys.argv[1:]
timeout = float(timeout_text)
deadline = time.monotonic() + timeout


def wait_serial(marker):
    while time.monotonic() < deadline:
        try:
            with open(serial_path, "r", encoding="utf-8", errors="replace") as log:
                contents = log.read()
            if marker in contents:
                return contents
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    tail = ""
    try:
        with open(serial_path, "r", encoding="utf-8", errors="replace") as log:
            tail = "".join(log.readlines()[-100:])
    except FileNotFoundError:
        pass
    raise SystemExit(f"timed out waiting for serial marker {marker!r}\n{tail}")


while time.monotonic() < deadline:
    try:
        qmp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        qmp.settimeout(2.0)
        qmp.connect(qmp_path)
        break
    except OSError:
        try:
            qmp.close()
        except UnboundLocalError:
            pass
        time.sleep(0.1)
else:
    raise SystemExit("timed out waiting for QEMU QMP socket")

stream = qmp.makefile("rwb", buffering=0)
greeting = json.loads(stream.readline())
if "QMP" not in greeting:
    raise SystemExit(f"invalid QMP greeting: {greeting!r}")


def command(name, arguments=None, request_id="request"):
    request = {"execute": name, "id": request_id}
    if arguments is not None:
        request["arguments"] = arguments
    stream.write(json.dumps(request).encode() + b"\r\n")
    while True:
        response = json.loads(stream.readline())
        if response.get("id") == request_id:
            if "error" in response:
                raise SystemExit(f"QMP {name} failed: {response['error']}")
            return response.get("return")


command("qmp_capabilities", request_id="capabilities")
wait_serial("[driver-host:input] keyboard IRQ bound to Port")
# QEMU's HMP sendkey drives the emulated PS/2 keyboard. The make code for
# the 'a' key is 0x1e; the driver logs it only after reading the IRQ packet
# from its userspace Port.
command(
    "human-monitor-command",
    {"command-line": "sendkey a 200"},
    request_id="send-a",
)
wait_serial("[driver-host:input] PS/2 make code 0x1e delivered to Port")
qmp.close()
PY

if grep -Fq 'KERNEL PANIC' "$log"; then
    echo "kernel panic detected" >&2
    tail -200 "$log" >&2 || true
    exit 1
fi
if ! grep -Fq '[IOAPIC] routed keyboard IRQ1' "$log"; then
    echo "IOAPIC keyboard route was not installed" >&2
    tail -200 "$log" >&2 || true
    exit 1
fi
if ! grep -Fq '[driver-host:input] PS/2 make code 0x1e delivered to Port' "$log"; then
    echo "PS/2 IRQ packet did not reach the userspace Port" >&2
    tail -200 "$log" >&2 || true
    exit 1
fi

echo "QEMU IOAPIC edge delivery OK (SMP${cpus}); log: $log"
