#!/usr/bin/env bash
# Collect an immutable-ish review bundle around a physical machine serial log.
# This script never claims the machine is bare metal; the operator/reviewer must
# identify and verify the system represented by the supplied log.
set -euo pipefail
out="${1:-}"
serial="${2:-}"
case_name="${EVIDENCE_CASE:-success}"
[[ -n "$out" && -n "$serial" ]] || {
    echo "usage: EVIDENCE_CASE=success|pcr-mismatch|keybroker-crash|unsigned|migration $0 OUT_DIR SERIAL_LOG" >&2
    exit 2
}
[[ -f "$serial" ]] || { echo "serial log not found: $serial" >&2; exit 1; }
mkdir -p "$out"
cp -- "$serial" "$out/serial.log"
{
    echo "collected_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "case=$case_name"
    echo "operator=${SUDO_USER:-${USER:-unknown}}"
    echo "hostname=$(hostname 2>/dev/null || echo unknown)"
    echo "kernel=$(uname -a 2>/dev/null || echo unavailable)"
    echo "release_image_sha256=${RELEASE_IMAGE_SHA256:-not-supplied}"
    echo "notes=${EVIDENCE_NOTES:-none}"
} > "$out/metadata.txt"

capture() {
    local name="$1"; shift
    if command -v "$1" >/dev/null 2>&1; then
        "$@" > "$out/$name.txt" 2>&1 || true
    else
        printf 'command unavailable: %s\n' "$1" > "$out/$name.txt"
    fi
}
capture lscpu lscpu
capture lspci lspci -nnvv
capture nvme-list nvme list
capture nvme-id-ctrl nvme id-ctrl /dev/nvme0
capture tpm-cap-fixed tpm2_getcap properties-fixed
capture tpm-persistent tpm2_getcap handles-persistent
capture dmidecode dmidecode

summary="$out/marker-summary.txt"
: > "$summary"
require() {
    local marker="$1"
    if grep -Fq "$marker" "$out/serial.log"; then
        printf 'PASS  %s\n' "$marker" >> "$summary"
    else
        printf 'FAIL  %s\n' "$marker" >> "$summary"
        return 1
    fi
}
forbid() {
    local marker="$1"
    if grep -Fq "$marker" "$out/serial.log"; then
        printf 'FAIL  forbidden: %s\n' "$marker" >> "$summary"
        return 1
    else
        printf 'PASS  absent: %s\n' "$marker" >> "$summary"
    fi
}
failed=0
case "$case_name" in
    success)
        for marker in \
            '[HuesOS] Bootloader handed over control' \
            '[HBI] Ed25519 signature verified (v2.2)' \
            '[tpm] PCR7=' '[tpm] PCR12=' \
            '[tpm] volume key unsealed (PCR policy satisfied)' \
            '[key-broker] ambient/wrong-type key take denied' \
            '[driver-manager] BOOTFS hash manifest verified and mounted' \
            '[hxfs] self-check ok'; do require "$marker" || failed=1; done
        ;;
    pcr-mismatch)
        require '[tpm] unseal refused: PCR policy mismatch (boot chain changed)' || failed=1
        forbid '[tpm] volume key unsealed (PCR policy satisfied)' || failed=1
        forbid '[hxfs] self-check ok' || failed=1
        ;;
    keybroker-crash)
        require '[key-broker] injected post-grant exit; future generations denied until reboot' || failed=1
        require '[hxfs] self-check ok' || failed=1
        require '[hxfs] write-roundtrip-ok' || failed=1
        require '[driver-manager] new encrypted Hxfs generation 2 denied after KeyBroker exit' || failed=1
        ;;
    unsigned)
        require 'Access Denied' || failed=1
        forbid '[HuesOS] Bootloader handed over control' || failed=1
        ;;
    migration)
        # Migration harnesses may use platform-specific markers; retain the raw
        # log and require the operator to supply the final complete-state line.
        require 'migration recovery: complete v5 or v6' || failed=1
        ;;
    *) echo "unknown EVIDENCE_CASE: $case_name" >&2; exit 2 ;;
esac

(
    cd "$out"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum > SHA256SUMS
)
cat "$summary"
if [[ "$failed" == 1 ]]; then
    echo "evidence bundle collected, but required markers failed" >&2
    exit 1
fi
echo "evidence bundle: $out"
