#!/usr/bin/env python3
"""HuesOS QEMU lab driver (QMP controlled, no display required).

Subcommands:
  boot [--smp N] [--mem M] [--tag T] [--iso PATH] [--disk PATH]
  stop
  wait <pattern> [timeout]        grep the serial log for a literal string
  log [tail]                     print the tail of the serial log
  key <name> [--hold MS]         press a key (ctrl-c, ret, esc, tab, up, ...)
  text <string> [--delay MS] [--hold MS]
  line <string> [--delay MS] [--hold MS]
  shot <name>                    screendump -> .lab/shots/<name>.png
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, ".lab")
QEMU = os.path.join(LAB, "qemu", "bin", "qemu-system-x86_64")
SHARE = os.path.join(LAB, "qemu", "share", "qemu")
SHIM = os.path.join(LAB, "qemu", "lib", "libglibc238shim.so")
QEMU_LIB = os.path.join(LAB, "qemu", "lib")
LOGS = os.path.join(LAB, "logs")
SHOTS = os.path.join(LAB, "shots")
RUN = os.path.join(LAB, "run")
OVMF_CODE = os.path.join(SHARE, "edk2-x86_64-code.fd")
OVMF_VARS = os.path.join(SHARE, "edk2-i386-vars.fd")

QCODES = {
    " ": "spc", "-": "minus", "=": "equal", "/": "slash", ".": "dot", ",": "comma",
    ";": "semicolon", "'": "apostrophe", "\\": "backslash", "[": "bracket_left",
    "]": "bracket_right", "`": "grave_accent", "\n": "ret", "\t": "tab",
    "_": "minus", ":": "semicolon", "\"": "apostrophe", "|": "backslash",
    "<": "comma", ">": "dot", "?": "slash", "~": "grave_accent", "!": "1",
    "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8",
    "(": "9", ")": "0", "+": "equal", "{": "bracket_left", "}": "bracket_right",
}
SHIFTED = set('_:"|<>?~!@#$%^&*()+{}')

NAMED_KEYS = {
    "ctrl-c": ["ctrl", "c"],
    "ctrl-u": ["ctrl", "u"],
    "ctrl-a": ["ctrl", "a"],
    "ctrl-e": ["ctrl", "e"],
    "ctrl-k": ["ctrl", "k"],
    "ctrl-l": ["ctrl", "l"],
    "ctrl-w": ["ctrl", "w"],
    "ctrl-d": ["ctrl", "d"],
    "ret": ["ret"],
    "enter": ["ret"],
    "esc": ["esc"],
    "tab": ["tab"],
    "backspace": ["backspace"],
    "space": ["spc"],
    "up": ["up"],
    "down": ["down"],
    "left": ["left"],
    "right": ["right"],
    "home": ["home"],
    "end": ["end"],
    "delete": ["delete"],
    "f1": ["f1"],
}


def tag_paths(tag):
    return (
        os.path.join(LOGS, f"{tag}.log"),
        os.path.join(RUN, f"{tag}.sock"),
        os.path.join(RUN, f"{tag}.pid"),
        os.path.join(RUN, f"{tag}-vars.fd"),
    )


class Qmp:
    def __init__(self, sock_path, timeout=20.0):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(sock_path)
                break
            except OSError as exc:  # socket not ready yet
                last = exc
                time.sleep(0.2)
        else:
            raise SystemExit(f"cannot connect to QMP socket {sock_path}: {last}")
        self.buf = b""
        self._read_message()  # greeting
        self.cmd("qmp_capabilities")

    def _read_message(self):
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line, self.buf = self.buf[:nl], self.buf[nl + 1 :]
                return json.loads(line.decode())
            chunk = self.sock.recv(65536)
            if not chunk:
                raise SystemExit("QMP connection closed")
            self.buf += chunk

    def cmd(self, name, **arguments):
        payload = {"execute": name}
        if arguments:
            payload["arguments"] = arguments
        self.sock.sendall((json.dumps(payload) + "\n").encode())
        while True:
            msg = self._read_message()
            if "event" in msg:
                continue
            if "error" in msg:
                raise SystemExit(f"QMP {name} failed: {msg['error']}")
            return msg.get("return")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def cmd_boot(args):
    os.makedirs(LOGS, exist_ok=True)
    os.makedirs(RUN, exist_ok=True)
    iso = args.iso or os.path.join(ROOT, "build", "huesos.iso")
    if not os.path.exists(iso):
        raise SystemExit(f"ISO not found: {iso}")
    log, sock, pidfile, vars_fd = tag_paths(args.tag)
    if os.path.exists(sock):
        os.unlink(sock)
    with open(OVMF_VARS, "rb") as src, open(vars_fd, "wb") as dst:
        dst.write(src.read())
    if os.path.exists(log):
        os.unlink(log)

    qemu = [
        QEMU, "-L", SHARE,
        "-machine", "q35", "-cpu", "qemu64",
        "-smp", str(args.smp), "-m", args.mem,
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={vars_fd}",
        "-cdrom", iso,
        "-vga", "std", "-display", "none",
        "-net", "none",
        "-serial", f"file:{log}",
        "-qmp", f"unix:{sock},server=on,wait=off",
        "-no-reboot", "-no-shutdown",
    ]
    if args.disk:
        qemu += [
            "-drive", f"id=nvme0,if=none,format=raw,file={args.disk}",
            "-device", "nvme,serial=huesosnvme,drive=nvme0",
        ]
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = QEMU_LIB + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    env["LD_PRELOAD"] = SHIM
    proc = subprocess.Popen(qemu, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                            start_new_session=True)
    with open(pidfile, "w") as fh:
        fh.write(str(proc.pid))
    Qmp(sock).close()
    print(f"[lab] booted pid={proc.pid} log={log} sock={sock}")


def cmd_stop(args):
    log, sock, pidfile, _ = tag_paths(args.tag)
    try:
        qmp = Qmp(sock, timeout=3)
        qmp.cmd("quit")
        qmp.close()
    except SystemExit:
        pass
    if os.path.exists(pidfile):
        pid = int(open(pidfile).read().strip())
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.1)
        else:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        os.unlink(pidfile)
    print("[lab] stopped")


def cmd_wait(args):
    log, _, _, _ = tag_paths(args.tag)
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if os.path.exists(log):
            with open(log, "r", errors="replace") as fh:
                if args.pattern in fh.read():
                    print(f"[lab] found: {args.pattern}")
                    return
        time.sleep(0.25)
    raise SystemExit(f"timeout waiting for {args.pattern!r} in {log}")


def cmd_log(args):
    log, _, _, _ = tag_paths(args.tag)
    with open(log, "r", errors="replace") as fh:
        text = fh.read()
    sys.stdout.write("\n".join(text.splitlines()[-args.tail:]) + "\n")


def send_keys(qmp, keys, hold):
    qmp.cmd("send-key", keys=[{"type": "qcode", "data": k} for k in keys],
            **({"hold-time": hold} if hold else {}))


def type_text(qmp, text, delay, hold):
    for ch in text:
        if ch == "\n":
            send_keys(qmp, ["ret"], hold)
        else:
            keys = []
            if ch in SHIFTED:
                keys.append("shift")
            code = QCODES.get(ch, ch.lower())
            keys.append(code)
            send_keys(qmp, keys, hold)
        if delay:
            time.sleep(delay / 1000.0)


def cmd_key(args):
    _, sock, _, _ = tag_paths(args.tag)
    qmp = Qmp(sock)
    if args.name in NAMED_KEYS:
        keys = NAMED_KEYS[args.name]
    elif len(args.name) == 1:
        keys = [QCODES.get(args.name, args.name)]
    else:
        raise SystemExit(f"unknown key {args.name}")
    send_keys(qmp, keys, args.hold)
    qmp.close()


def cmd_text(args):
    _, sock, _, _ = tag_paths(args.tag)
    qmp = Qmp(sock)
    type_text(qmp, args.string, args.delay, args.hold)
    qmp.close()


def cmd_line(args):
    cmd_text(argparse.Namespace(tag=args.tag, string=args.string + "\n",
                                delay=args.delay, hold=args.hold))


def ppm_to_png(ppm_path, png_path):
    with open(ppm_path, "rb") as fh:
        data = fh.read()
    if not data.startswith(b"P6"):
        raise SystemExit("unexpected screendump format")
    fields = []
    idx = 2
    while len(fields) < 3:
        while idx < len(data) and data[idx : idx + 1].isspace():
            idx += 1
        if data[idx : idx + 1] == b"#":
            while data[idx : idx + 1] != b"\n":
                idx += 1
            continue
        start = idx
        while idx < len(data) and not data[idx : idx + 1].isspace():
            idx += 1
        fields.append(int(data[start:idx]))
    idx += 1
    width, height = fields[0], fields[1]
    pixels = data[idx : idx + width * height * 3]

    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)
        raw.extend(pixels[y * stride : (y + 1) * stride])

    def chunk(kind, payload):
        body = kind + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")
    with open(png_path, "wb") as fh:
        fh.write(png)


def cmd_shot(args):
    os.makedirs(SHOTS, exist_ok=True)
    _, sock, _, _ = tag_paths(args.tag)
    ppm = os.path.join(SHOTS, f"{args.name}.ppm")
    png = os.path.join(SHOTS, f"{args.name}.png")
    qmp = Qmp(sock)
    qmp.cmd("screendump", filename=ppm)
    qmp.close()
    for _ in range(40):
        if os.path.exists(ppm) and os.path.getsize(ppm) > 1000:
            break
        time.sleep(0.1)
    ppm_to_png(ppm, png)
    os.unlink(ppm)
    print(f"[lab] {png}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default="run", help="instance tag (default: run)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    boot = sub.add_parser("boot")
    boot.add_argument("--smp", default="2")
    boot.add_argument("--mem", default="512M")
    boot.add_argument("--tag", default=None)
    boot.add_argument("--iso", default=None)
    boot.add_argument("--disk", default=None)
    boot.set_defaults(func=cmd_boot)

    stop = sub.add_parser("stop")
    stop.set_defaults(func=cmd_stop)

    wait = sub.add_parser("wait")
    wait.add_argument("pattern")
    wait.add_argument("timeout", nargs="?", type=float, default=120.0)
    wait.set_defaults(func=cmd_wait)

    log = sub.add_parser("log")
    log.add_argument("tail", nargs="?", type=int, default=40)
    log.set_defaults(func=cmd_log)

    key = sub.add_parser("key")
    key.add_argument("name")
    key.add_argument("--hold", type=int, default=40)
    key.set_defaults(func=cmd_key)

    text = sub.add_parser("text")
    text.add_argument("string")
    text.add_argument("--delay", type=int, default=12)
    text.add_argument("--hold", type=int, default=12)
    text.set_defaults(func=cmd_text)

    line = sub.add_parser("line")
    line.add_argument("string")
    line.add_argument("--delay", type=int, default=12)
    line.add_argument("--hold", type=int, default=12)
    line.set_defaults(func=cmd_line)

    shot = sub.add_parser("shot")
    shot.add_argument("name")
    shot.set_defaults(func=cmd_shot)

    args = parser.parse_args()
    if getattr(args, "tag", None) is None:
        args.tag = "run"
    args.func(args)


if __name__ == "__main__":
    main()
