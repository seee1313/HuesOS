#!/usr/bin/env bash
set -euo pipefail

profile="${1:-release}"
seconds="${2:-300}"
log="${3:-build/qemu-nvme-soak.log}"
inject="${4:-0}"
nvme_img="${NVME_IMG:-build/nvme-soak.img}"
nvme_size="${NVME_IMG_SIZE:-4G}"
ovmf="${OVMF_PATH:-third_party/ovmf/OVMF.fd}"
nvme_layout="${QEMU_NVME_LAYOUT:-split}"

mkdir -p build "$(dirname "$log")" "$(dirname "$nvme_img")"
rm -f "$log"

echo "[soak] profile=${profile} seconds=${seconds} log=${log} nvme_img=${nvme_img} layout=${nvme_layout} inject=${inject}"
echo "[soak] building ISO before NVMe soak"
# Injection modes build the ISO with the synthetic-key feature so
# the embedded hxfs-service mounts the seeded volume and runs its
# boot self-check. Production builds (and the plain soak mode)
# leave the variable unset and the test wiring stays out of the
# binary.
seed_args=()
if [[ "$inject" == "1" ]]; then
    export HUESOS_HXFS_SERVICE_FEATURES=synthetic-key
    seed_args=(--inject-bad-gcm-tag)
elif [[ "$inject" == "2" ]]; then
    export HUESOS_HXFS_SERVICE_FEATURES=synthetic-key
    seed_args=(--inject-bad-crc)
elif [[ "$inject" == "3" ]]; then
    # Mode 3: graceful-shutdown cycle. A clean encrypted volume
    # (no corruption); the service self-check runs, then the
    # terminal auto-triggers an orderly userspace shutdown and the
    # harness waits for the halt marker instead of a timeout kill.
    export HUESOS_HXFS_SERVICE_FEATURES=synthetic-key
    export HUESOS_TERMINAL_FEATURES=soak-shutdown
    seed_args=()
elif [[ "$inject" == "4" ]]; then
    # Mode 4: stress soak. A clean encrypted volume; the service
    # runs its self-check plus repeated 16 MiB write/read cycles
    # (stress-ok) for sustained NVMe/page-cache load.
    export HUESOS_HXFS_SERVICE_FEATURES=synthetic-key
    seed_args=()
elif [[ "$inject" == "5" ]]; then
    # Mode 5: high queue-depth soak (production gate). Same workload
    # as mode 4, but QEMU exposes a multi-queue NVMe controller and
    # the guest gets more vCPUs, so the driver plans and drives one
    # I/O queue per CPU with a deep submission queue instead of the
    # single shallow queue the other modes exercise. This is the mode
    # that can surface doorbell/phase bugs and queue-full handling.
    export HUESOS_HXFS_SERVICE_FEATURES=synthetic-key
    seed_args=()
fi
if [[ "$inject" == "1" || "$inject" == "2" || "$inject" == "3" || "$inject" == "4" || "$inject" == "5" ]]; then
    # Stage D: the synthetic volume key is baked into the KERNEL as
    # the bootloader key blob (single source of truth: the seed
    # tool's --print-volume-key-hex). The service receives it via
    # the VolumeKeyGet syscall; without it an encrypted volume
    # cannot mount, which is the security gate.
    export HUESOS_VOLUME_KEY_HEX="$(bash tools/hxfs-seed.sh --print-volume-key-hex)"
    # Phase-2 packages (step 3): every seeded mode also stores a WAD
    # header (first 3072 bytes of freedoom1.wad) as an Hxblob object
    # and records its hash in 'wad.hash' on the volume, so the boot
    # self-check can verify IWAD magic delivery from the object
    # store (marker: stage-f-wad-ok).
    seed_args+=(--seed-blob-file build/wad-header.bin)
fi
case "$profile" in
    release) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release >/tmp/huesos-nvme-soak-build.log ;;
    debug) CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso PROFILE=debug >/tmp/huesos-nvme-soak-build.log ;;
    *) echo "[soak] unsupported profile: $profile" >&2; exit 2 ;;
esac

# This script is a production-gate harness. It is intentionally conservative:
# it records the command shape and validates storage markers when QEMU is
# available in the runner. Local sandboxes may not have qemu-system-x86_64.
if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "[soak] qemu-system-x86_64 unavailable; skipping runtime soak" | tee "$log"
    exit 0
fi

if [[ ! -f "$ovmf" ]]; then
    echo "[soak] OVMF firmware missing at $ovmf" >&2
    echo "[soak] set OVMF_PATH=/path/to/OVMF.fd if your distro uses another path" >&2
    exit 1
fi

# The image is only valid for the inject mode that created it: an
# encrypted (gcm) image must not be reused by a plain run (the
# service would reject it with EncryptedPolicyUnknown) and vice
# versa. A mode marker next to the image records its creator; the
# image is (re)created when missing OR when the marker differs.
mode_file="$nvme_img.mode"
need_create=0
if [[ ! -f "$nvme_img" ]]; then
    need_create=1
elif [[ ! -f "$mode_file" ]] || [[ "$(cat "$mode_file" 2>/dev/null)" != "$inject" ]]; then
    echo "[soak] image mode mismatch (marker=$(cat "$mode_file" 2>/dev/null || echo none), want=$inject); recreating"
    need_create=1
fi
if [[ "$need_create" == "1" ]]; then
    rm -f "$nvme_img"
    echo "[soak] creating Hxfs v5 image: $nvme_img ($nvme_size)"
    # The QEMU NVMe namespace exposes a 512-byte LBA, so the on-disk
    # size in bytes is also the number of LBAs. Hxfs uses 4 KiB
    # internal blocks, so the Hxfs block count is on-disk bytes
    # divided by 4096. We use the streaming mkhxfs builder so a
    # multi-GiB image does not need to be materialised in Python
    # heap; the resulting file is sparse on disk and the data
    # region is implicitly zero-filled by the filesystem, which
    # Hxfs treats as unwritten.
    nvme_bytes="${nvme_size%G}"
    if [[ "$nvme_bytes" != "$nvme_size" ]]; then
        bytes=$((nvme_bytes * 1024 * 1024 * 1024))
    else
        nvme_bytes="${nvme_size%M}"
        if [[ "$nvme_bytes" != "$nvme_size" ]]; then
            bytes=$((nvme_bytes * 1024 * 1024))
        else
            bytes="$nvme_size"
        fi
    fi
    hxfs_blocks=$((bytes / 4096))
    if (( hxfs_blocks < 8 )); then
        echo "[soak] image too small for Hxfs (need >= 32 KiB)" >&2
        exit 1
    fi
    if [[ "$inject" == "1" || "$inject" == "2" || "$inject" == "3" || "$inject" == "4" || "$inject" == "5" ]]; then
        # Seeded modes: an encrypted+compressed volume with a
        # seed.bin file. Modes 1/2 corrupt the seed data block;
        # mode 3 leaves it intact for the shutdown cycle.
        echo "[soak] creating seeded Hxfs image (inject=${inject}): $nvme_img"
        # Phase-2 packages (step 3): materialise the WAD header blob
        # source next to the image so mkhxfs.py can seed it.
        head -c 3072 third_party/freedoom/freedoom1.wad > build/wad-header.bin
        python3 tools/mkhxfs.py --output "$nvme_img" --blocks "$hxfs_blocks" \
            --seed-file seed.bin --seed-size 3584 "${seed_args[@]}" >/dev/null
    else
        python3 tools/mkhxfs.py --output "$nvme_img" --blocks "$hxfs_blocks" >/dev/null
    fi
    echo "$inject" > "$mode_file"
fi

# High queue-depth mode needs more vCPUs than the default soak: the
# driver plans one I/O queue per CPU, so a 2-vCPU guest can never
# exercise more than two queues no matter what the controller offers.
soak_smp=2
soak_mem=512M
if [[ "$inject" == "5" ]]; then
    soak_smp="${SOAK_SMP:-4}"
    soak_mem="${SOAK_MEM:-768M}"
fi

qemu_common=(
    -machine q35
    -cpu qemu64
    -smp "$soak_smp"
    -m "$soak_mem"
    -bios "$ovmf"
    -cdrom build/huesos.iso
    -drive id=nvme0,if=none,format=raw,file="$nvme_img"
    -net none
    -display none
    -serial "file:$log"
    -no-reboot -no-shutdown
)
# Mode 3 attaches a QEMU monitor over a Unix socket so the harness
# can quit QEMU after observing the halt marker.
qemu_monitor=()
if [[ "$inject" == "3" ]]; then
    qemu_monitor=(-monitor "unix:build/qemu-monitor.sock,server=on,wait=off")
fi

# A software TPM, when the host has one. The kernel's KeyProvider
# unseals the volume key from PCR-bound storage, and that path can only
# be exercised against a real TPM 2.0 command interface -- a stub would
# validate the stub. Absence is not fatal: the guest falls back to the
# build-time key and says so, which is also a case worth soaking.
qemu_tpm=()
swtpm_pid=""
if [[ "${SOAK_TPM:-1}" == "1" ]] && command -v swtpm >/dev/null 2>&1; then
    tpm_state="build/swtpm-state"
    tpm_sock="build/swtpm-sock"
    rm -rf "$tpm_state" "$tpm_sock"
    mkdir -p "$tpm_state"
    swtpm socket \
        --tpmstate "dir=$tpm_state" \
        --ctrl "type=unixio,path=$tpm_sock" \
        --tpm2 \
        --flags not-need-init,startup-clear \
        >build/swtpm.log 2>&1 &
    swtpm_pid=$!
    # Wait for the control socket rather than sleeping a fixed time:
    # QEMU fails to start outright if the socket is not there yet.
    for _ in $(seq 1 50); do
        [[ -S "$tpm_sock" ]] && break
        sleep 0.1
    done
    if [[ -S "$tpm_sock" ]]; then
        qemu_tpm=(
            -chardev "socket,id=chrtpm,path=$tpm_sock"
            -tpmdev emulator,id=tpm0,chardev=chrtpm
            -device tpm-crb,tpmdev=tpm0
        )
        echo "[soak] swtpm attached (tpm-crb)"
    else
        echo "[soak] swtpm did not expose its socket; continuing without a TPM"
        kill "$swtpm_pid" 2>/dev/null || true
        swtpm_pid=""
    fi
else
    echo "[soak] no swtpm on this host; continuing without a TPM"
fi
cleanup_swtpm() {
    if [[ -n "$swtpm_pid" ]]; then
        kill "$swtpm_pid" 2>/dev/null || true
        wait "$swtpm_pid" 2>/dev/null || true
    fi
}
trap cleanup_swtpm EXIT

qemu_nvme=()
case "$nvme_layout" in
    split)
        # Modern QEMU model: create controller and namespace explicitly. This
        # avoids booting a controller with no active namespace on hosts where
        # the legacy `drive=` shortcut is not accepted as a namespace.
        if [[ "$inject" == "5" ]]; then
            # High queue-depth: advertise one I/O queue per vCPU plus
            # headroom, MSI-X vectors to match, and a deep submission
            # queue. `max_ioqpairs` is what lets the driver's per-CPU
            # queue plan actually create more than one pair.
            qemu_nvme=(
                -device "nvme,serial=huesosnvme,id=nvme-ctrl,max_ioqpairs=${SOAK_IOQPAIRS:-8},msix_qsize=${SOAK_MSIX_QSIZE:-16},mdts=7"
                -device nvme-ns,drive=nvme0,bus=nvme-ctrl,nsid=1
            )
        else
            qemu_nvme=(-device nvme,serial=huesosnvme,id=nvme-ctrl -device nvme-ns,drive=nvme0,bus=nvme-ctrl,nsid=1)
        fi
        ;;
    legacy)
        qemu_nvme=(-device nvme,serial=huesosnvme,drive=nvme0)
        ;;
    *)
        echo "[soak] unsupported QEMU_NVME_LAYOUT=$nvme_layout (use split or legacy)" >&2
        exit 2
        ;;
esac

set +e
if [[ "$inject" == "3" ]]; then
    rm -f build/qemu-monitor.sock
    qemu-system-x86_64 "${qemu_common[@]}" "${qemu_nvme[@]}" "${qemu_tpm[@]}" "${qemu_monitor[@]}" &
    qemu_pid=$!
    status=124
    waited=0
    while [[ $waited -lt "$seconds" ]]; do
        if grep -Fq "[shutdown] all CPUs halted" "$log" 2>/dev/null; then
            status=0
            break
        fi
        sleep 2
        waited=$((waited + 2))
    done
    if [[ -S build/qemu-monitor.sock ]]; then
        printf 'quit\n' | timeout 5 socat - UNIX-CONNECT:build/qemu-monitor.sock 2>/dev/null || true
    fi
    kill "$qemu_pid" 2>/dev/null
    wait "$qemu_pid" 2>/dev/null
else
    timeout "${seconds}s" qemu-system-x86_64 "${qemu_common[@]}" "${qemu_nvme[@]}" "${qemu_tpm[@]}"
    status=$?
fi
set -e

# A healthy OS intentionally keeps running, so timeout(1)'s 124 is expected.
if [[ "$status" != 0 && "$status" != 124 ]]; then
    echo "[soak] QEMU exited unexpectedly with status $status" >&2
    wc -l "$log" >&2; head -2000 "$log" >&2 || true
    exit 1
fi

if grep -Fq 'KERNEL PANIC' "$log" || grep -Fq '[hxfs] PANIC' "$log"; then
    echo "[soak] panic marker detected" >&2
    wc -l "$log" >&2; head -2000 "$log" >&2 || true
    exit 1
fi

required=(
    "[driver-host:nvme] identified"
    "[driver-manager] registered identified block:nvme namespace"
    "[hxfs] service started"
)
if [[ "$inject" == "1" || "$inject" == "2" ]]; then
    # Injection modes: the boot self-check must have detected the
    # seeded corruption with the precise marker (mode 1: GCM tag on
    # an encrypted volume; mode 2: payload CRC on a plain volume),
    # marked the extent bad, exercised the O_DIRECT deny probe and
    # the on-target write path, and run the Stage C reliability
    # probes (live scrub, structural fsck, quota enforcement) — all
    # while the service kept serving.
    bad_marker="[hxfs] bad-gcm-tag-marked"
    if [[ "$inject" == "2" ]]; then
        bad_marker="[hxfs] bad-checksum-marked"
    fi
    required+=(
        "$bad_marker"
        "[hxfs] extent-bad-marked"
        "[hxfs] odirect-deny-ok"
        "[hxfs] write-roundtrip-ok"
        "[hxfs] multi-slot-write-ok"
        "[hxfs] scrub complete"
        "[hxfs] fsck clean"
        "[hxfs] quota-enforced-ok"
        "[hxfs] stage-e-16mib-ok"
        "[hxfs] stage-f-blob-ok"
        "[hxfs] stage-f-blob-big-ok"
        "[hxfs] stage-f-wad-ok"
    )
elif [[ "$inject" == "4" ]]; then
    # Stress soak: encrypted volume, self-check, write path,
    # 16 MiB file, blob round-trip and the repeated stress cycles.
    required+=(
        "[hxfs] self-check ok"
        "[hxfs] write-roundtrip-ok"
        "[hxfs] multi-slot-write-ok"
        "[hxfs] stage-e-16mib-ok"
        "[hxfs] stage-f-blob-ok"
        "[hxfs] stage-f-blob-big-ok"
        "[hxfs] stage-f-wad-ok"
        "[hxfs] stress-ok"
        "[hxfs] scrub complete"
        "[hxfs] fsck clean"
        "[hxfs] quota-enforced-ok"
    )
elif [[ "$inject" == "5" ]]; then
    # High queue-depth soak: the same workload as mode 4, but the
    # controller must have come up with more than one I/O queue and
    # the reliability counters must show a clean run -- no timeouts
    # and no controller resets under sustained multi-queue load.
    required+=(
        "[hxfs] self-check ok"
        "[hxfs] write-roundtrip-ok"
        "[hxfs] stage-e-16mib-ok"
        "[hxfs] stress-ok"
        "[hxfs] scrub complete"
        "[hxfs] fsck clean"
        "[hxfs] blob-view-native-ok"
        "[driver-manager] package-resolve-ok"
        "[driver-host:nvme] telemetry"
    )
elif [[ "$inject" == "3" ]]; then
    # Graceful-shutdown cycle: the encrypted volume must mount and
    # self-check cleanly, then the userspace shutdown chain must
    # reach the final atomic halt.
    required+=(
        "[hxfs] self-check ok"
        "[hxfs] write-roundtrip-ok"
        "[hxfs] stage-e-16mib-ok"
        "[hxfs] stage-f-blob-ok"
        "[hxfs] stage-f-blob-big-ok"
        "[hxfs] stage-f-wad-ok"
        "[init] terminal requested orderly shutdown"
        "[shutdown-broker] 8042 quiesced; invoking hard_halt"
        "[shutdown] all CPUs halted"
    )
fi
# The high queue-depth gate is only meaningful if the controller
# actually came up multi-queue. A run that silently fell back to a
# single I/O queue would satisfy every marker above while testing
# nothing the other modes do not already cover, so assert on the
# reported queue count and on clean reliability counters.
if [[ "$inject" == "5" ]]; then
    queues="$(sed -n 's/.*\[driver-host:nvme\] identified .*queues=\([0-9]*\).*/\1/p' "$log" | tail -1)"
    if [[ -z "$queues" ]]; then
        echo "[soak] could not read the I/O queue count from the log" >&2
        exit 1
    fi
    if (( queues < 2 )); then
        echo "[soak] high queue-depth mode came up with only $queues I/O queue(s)" >&2
        exit 1
    fi
    echo "[soak] high queue-depth: $queues I/O queues"
    if grep -Fq "[driver-host:nvme] controller-reset-failed" "$log"; then
        echo "[soak] controller reset failed during the high queue-depth soak" >&2
        exit 1
    fi
    telemetry="$(grep -F '[driver-host:nvme] telemetry' "$log" | tail -1)"
    echo "[soak] $telemetry"
    if [[ "$telemetry" != *"state=Online"* ]]; then
        echo "[soak] controller did not end the soak Online: $telemetry" >&2
        exit 1
    fi
    # The boot-time snapshot always reads submitted=0. Requiring a
    # non-trivial submitted count is what makes this a load gate
    # rather than a "the driver printed a line" gate.
    submitted="$(sed -n 's/.*telemetry submitted=\([0-9]*\).*/\1/p' <<<"$telemetry")"
    if [[ -z "$submitted" ]] || (( submitted < 512 )); then
        echo "[soak] high queue-depth soak did not drive enough I/O (submitted=${submitted:-none})" >&2
        exit 1
    fi
    completed="$(sed -n 's/.*completed=\([0-9]*\).*/\1/p' <<<"$telemetry")"
    timeouts="$(sed -n 's/.*timeouts=\([0-9]*\).*/\1/p' <<<"$telemetry")"
    if [[ -n "$timeouts" ]] && (( timeouts > 0 )); then
        echo "[soak] $timeouts command timeout(s) under multi-queue load" >&2
        exit 1
    fi
    echo "[soak] high queue-depth: submitted=$submitted completed=$completed timeouts=${timeouts:-0}"
fi

# The hxfs page cache is only a gate if the service's own mount is
# the thing being hit. The service prints its counters after two
# reads of the same file; require a hit on the repeat read, so a
# cache that is present but never consulted fails the gate.
cache_line="$(grep -F '[hxfs] page-cache' "$log" | tail -1)"
if [[ -n "$cache_line" ]]; then
    echo "[soak] $cache_line"
    repeat_hits="$(sed -n 's/.*repeat-read-hits=\([0-9]*\).*/\1/p' <<<"$cache_line")"
    if [[ -z "$repeat_hits" ]] || (( repeat_hits < 1 )); then
        echo "[soak] hxfs page cache did not serve the repeat read: $cache_line" >&2
        exit 1
    fi
    cache_slots="$(sed -n 's/.*page-cache slots=\([0-9]*\).*/\1/p' <<<"$cache_line")"
    if [[ -z "$cache_slots" ]] || (( cache_slots < 1 )); then
        echo "[soak] hxfs mounted without a page cache: $cache_line" >&2
        exit 1
    fi
else
    echo "[soak] hxfs page-cache marker absent" >&2
    exit 1
fi

for marker in "${required[@]}"; do
    if ! grep -Fq "$marker" "$log"; then
        echo "[soak] missing marker: $marker" >&2
        echo "[soak] last 200 serial lines:" >&2
        wc -l "$log" >&2; head -2000 "$log" >&2 || true
        exit 1
    fi
done

# Negative markers that must NOT appear. The mount path against an
# Hxfs image must succeed; \`journal replay failed: BadBlock\` would
# mean the smoke is back to using a raw namespace instead of the
# Hxfs image, so we fail fast. \`[hxfs] service exiting: mount
# failed\` and \`[driver-manager] Hxfs service channel failed\`
# would mean the on-target trace left behind by the now-fixed
# yield-spin-on-failure regression in the hxfs service or the
# DriverManager service-channel poll.
for regression in \
    '[hxfs] journal replay failed: BadBlock' \
    '[hxfs] superblock checksum mismatch' \
    '[hxfs] service exiting: mount failed' \
    '[driver-manager] Hxfs service channel failed' \
    '[user-fault] process=hxfs-service'; do
    if grep -Fq "$regression" "$log"; then
        echo "[soak] regression marker present: $regression" >&2
        wc -l "$log" >&2; head -2000 "$log" >&2
        exit 1
    fi
done

echo "[soak] markers present"
