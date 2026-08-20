#!/usr/bin/env bash
# Build a production-key probe or final ISO for operator-run physical testing.
set -euo pipefail
mode="${1:-}"
out_dir="${2:-bare-metal-artifacts}"
case "$mode" in probe|final) ;; *) echo "usage: $0 probe|final [OUT_DIR]" >&2; exit 2 ;; esac
for name in HUESOS_HBI_SIGNING_KEY_FILE HUESOS_HBI_VERIFY_KEY_HEX HUESOS_UEFI_DB_KEY HUESOS_UEFI_DB_CERT; do
    [[ -n "${!name:-}" ]] || { echo "$name is required" >&2; exit 1; }
done
[[ -f "$HUESOS_HBI_SIGNING_KEY_FILE" && -f "$HUESOS_UEFI_DB_KEY" && -f "$HUESOS_UEFI_DB_CERT" ]] || {
    echo "one or more production key/certificate paths do not exist" >&2; exit 1;
}
if [[ "$mode" == final ]]; then
    [[ -n "${HUESOS_SEALED_KEY_MODULE:-}" && -f "$HUESOS_SEALED_KEY_MODULE" ]] || {
        echo "final mode requires HUESOS_SEALED_KEY_MODULE" >&2; exit 1;
    }
else
    unset HUESOS_SEALED_KEY_MODULE
fi
mkdir -p "$out_dir"
HUESOS_HBI_REQUIRE_PRODUCTION_KEY=1 HUESOS_SECURE_BOOT=1 \
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" make iso-release
image="$out_dir/huesos-security-${mode}.iso"
cp build/huesos.iso "$image"
sha256sum "$image" > "$image.sha256"
{
    echo "mode=$mode"
    echo "built_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unavailable)"
    echo "hbi_verify_key=$HUESOS_HBI_VERIFY_KEY_HEX"
    echo "uefi_db_cert_sha256=$(sha256sum "$HUESOS_UEFI_DB_CERT" | awk '{print $1}')"
    if [[ "$mode" == final ]]; then
        echo "sealed_module_sha256=$(sha256sum "$HUESOS_SEALED_KEY_MODULE" | awk '{print $1}')"
    fi
} > "$image.manifest"
echo "bare-metal $mode image: $image"
cat "$image.sha256"
