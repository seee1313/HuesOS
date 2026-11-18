#!/usr/bin/env bash
# Real swtpm + tpm2-tools provisioning, PCR7+PCR12 unseal success and mismatch.
set -euo pipefail

profile="${1:-debug}"
seconds="${2:-180}"
artifact_dir="${ARTIFACT_DIR:-ci-artifacts}"
root="$(pwd)"
work="build/tpm-e2e"
state="$work/state"
probe_log="$artifact_dir/qemu-tpm-probe-${profile}.log"
success_log="$artifact_dir/qemu-tpm-unseal-${profile}.log"
mismatch_log="$artifact_dir/qemu-tpm-mismatch-${profile}.log"
parent=0x81000001
mkdir -p "$work" "$artifact_dir"
rm -rf "$state" "$work"/*.ctx "$work"/*.dat "$work"/*.pub "$work"/*.priv \
    "$work"/*.bin "$work"/*.pid "$work"/*.sock* "$probe_log" "$success_log" "$mismatch_log"
mkdir -p "$state"

for command in swtpm swtpm_setup tpm2_createpolicy tpm2_createprimary \
    tpm2_evictcontrol tpm2_create python3 qemu-system-x86_64; do
    command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }
done

start_qemu_tpm() {
    local ctrl="$1"
    local pidfile="$2"
    rm -f "$ctrl" "$pidfile"
    swtpm socket --tpmstate "dir=$root/$state" \
        --ctrl "type=unixio,path=$ctrl" --tpm2 \
        --flags not-need-init,startup-clear >"$work/swtpm-qemu.log" 2>&1 &
    echo $! > "$pidfile"
    for _ in $(seq 1 100); do
        [[ -S "$ctrl" ]] && return 0
        sleep 0.05
    done
    echo "swtpm control socket did not appear" >&2
    return 1
}

run_guest() {
    local ctrl="$1" log="$2" nvme="${3:-}"
    local storage=()
    if [[ -n "$nvme" ]]; then
        storage=(
            -drive "id=nvme0,if=none,format=raw,file=$nvme"
            -device nvme,serial=huesosnvme,id=nvme-ctrl
            -device nvme-ns,drive=nvme0,bus=nvme-ctrl,nsid=1
        )
    fi
    set +e
    timeout "$seconds" qemu-system-x86_64 \
        -machine q35 -cpu qemu64 -smp 2 -m 512M \
        -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
        "${storage[@]}" -net none -display none -serial "file:$log" \
        -no-reboot -no-shutdown \
        -chardev "socket,id=chrtpm,path=$ctrl" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0
    local status=$?
    set -e
    [[ "$status" == 0 || "$status" == 124 ]]
}

stop_qemu_tpm() {
    local pidfile="$1"
    if [[ -f "$pidfile" ]]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
        wait "$(cat "$pidfile")" 2>/dev/null || true
    fi
}

# Probe exactly the final kernel/BOOTFS/cmdline/platform set, but without a
# sealed-key HBI module. The kernel prints the resulting PCR values.
rm -f build/cmdline.txt
printf 'init_args=foo\n' > build/cmdline.txt
HUESOS_HXFS_SERVICE_FEATURES=synthetic-key CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
    make iso PROFILE="$profile"
swtpm_setup --tpmstate "$root/$state" --tpm2 >/dev/null
start_qemu_tpm "$root/$work/probe.ctrl" "$work/probe.pid"
run_guest "$root/$work/probe.ctrl" "$probe_log"
stop_qemu_tpm "$work/probe.pid"
pcr7="$(sed -n 's/.*\[tpm\] PCR7=\([0-9a-f]\{64\}\).*/\1/p' "$probe_log" | tail -1)"
pcr12="$(sed -n 's/.*\[tpm\] PCR12=\([0-9a-f]\{64\}\).*/\1/p' "$probe_log" | tail -1)"
[[ ${#pcr7} == 64 && ${#pcr12} == 64 ]] || {
    echo "probe did not publish PCR7/PCR12" >&2
    tail -200 "$probe_log" >&2
    exit 1
}
printf '%s%s' "$pcr7" "$pcr12" | python3 -c \
    'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))' > "$work/pcr.bin"

# Provision a fresh persistent parent and a keyed-hash sealed object against
# the observed deterministic OVMF PCR7 plus HuesOS PCR12 value.
rm -f "$work/provision.sock" "$work/provision.sock.ctrl" "$work/provision.pid"
swtpm socket --tpmstate "dir=$root/$state" \
    --server "type=unixio,path=$root/$work/provision.sock" \
    --ctrl "type=unixio,path=$root/$work/provision.sock.ctrl" \
    --tpm2 --flags not-need-init,startup-clear \
    --pid "file=$root/$work/provision.pid" --daemon
export TPM2TOOLS_TCTI="swtpm:path=$root/$work/provision.sock"
tpm2_createpolicy --policy-pcr -l sha256:7,12 -f "$work/pcr.bin" -L "$work/policy.dat" >/dev/null
tpm2_createprimary -C o -g sha256 -G rsa -c "$work/primary.ctx" >/dev/null
tpm2_evictcontrol -C o -c "$work/primary.ctx" "$parent" >/dev/null
tpm2_flushcontext -t
volume_key="$(bash tools/hxfs-seed.sh --print-volume-key-hex)"
printf '%s' "$volume_key" | python3 -c \
    'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))' > "$work/volume-key.bin"
tpm2_create -C "$parent" -u "$work/seal.pub" -r "$work/seal.priv" \
    -i "$work/volume-key.bin" -L "$work/policy.dat" \
    -a 'fixedtpm|fixedparent|adminwithpolicy|noda' >/dev/null
python3 tools/make-sealed-key-module.py --parent "$parent" \
    --public "$work/seal.pub" --private "$work/seal.priv" \
    --output "$work/sealed-key.bin" >/dev/null
tpm2_shutdown -c || true
kill "$(cat "$work/provision.pid")" 2>/dev/null || true
unset TPM2TOOLS_TCTI

# Seed an encrypted HxFS volume with the same key. The final kernel has no raw
# HUESOS_VOLUME_KEY_HEX; it can mount only if TPM unseal succeeds.
head -c 3072 third_party/freedoom/freedoom1.wad > build/wad-header.bin
python3 tools/mkhxfs.py --output "$work/nvme.img" --blocks 131072 \
    --seed-file seed.bin --seed-size 3584 \
    --seed-blob-file build/wad-header.bin >/dev/null
HUESOS_SEALED_KEY_MODULE="$work/sealed-key.bin" \
HUESOS_HXFS_SERVICE_FEATURES=synthetic-key \
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE="$profile"
start_qemu_tpm "$root/$work/success.ctrl" "$work/success.pid"
run_guest "$root/$work/success.ctrl" "$success_log" "$work/nvme.img"
stop_qemu_tpm "$work/success.pid"
for marker in \
    '[tpm] volume key unsealed (PCR policy satisfied)' \
    '[key-broker] kernel key moved; state=available' \
    '[hxfs] self-check ok' \
    '[driver-manager] Hxfs service ready'; do
    grep -Fq "$marker" "$success_log" || { echo "missing success marker: $marker" >&2; tail -250 "$success_log" >&2; exit 1; }
done

# Change only the signed command line. Signature remains valid, PCR12 changes,
# and the same sealed object must refuse unseal.
printf 'init_args=foo measurement_mismatch=1\n' > build/cmdline.txt
HUESOS_SEALED_KEY_MODULE="$work/sealed-key.bin" \
HUESOS_HXFS_SERVICE_FEATURES=synthetic-key \
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE="$profile"
start_qemu_tpm "$root/$work/mismatch.ctrl" "$work/mismatch.pid"
run_guest "$root/$work/mismatch.ctrl" "$mismatch_log" "$work/nvme.img"
stop_qemu_tpm "$work/mismatch.pid"
grep -Fq '[tpm] unseal refused: PCR policy mismatch (boot chain changed)' "$mismatch_log"
grep -Fq '[key-broker] kernel key moved; state=plain-only' "$mismatch_log"
! grep -Fq '[hxfs] self-check ok' "$mismatch_log"
rm -f build/cmdline.txt
# Do not leave plaintext key material in build artifacts.
python3 - "$work/volume-key.bin" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
if p.exists():
    p.write_bytes(bytes(p.stat().st_size))
    p.unlink()
PY
echo "TPM PCR7+PCR12 sealed-key success/mismatch smoke passed"
