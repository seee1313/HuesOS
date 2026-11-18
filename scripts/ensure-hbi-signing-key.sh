#!/usr/bin/env bash
# Select an external production Ed25519 key or create a local development key.
# Private keys are written only under ignored build/ or remain at the external
# owner-provided path; they are never copied into the repository.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p build

DEV_KEY="build/dev-hbi-signing-key.pem"
KEY_FILE="${HUESOS_HBI_SIGNING_KEY_FILE:-$DEV_KEY}"
if [[ "$KEY_FILE" == "$DEV_KEY" && "${HUESOS_HBI_REQUIRE_PRODUCTION_KEY:-0}" == "1" ]]; then
    echo "production-key mode refuses the generated development HBI key" >&2
    exit 1
fi
if [[ ! -f "$KEY_FILE" ]]; then
    if [[ "$KEY_FILE" != "$DEV_KEY" ]]; then
        echo "external HBI signing key not found: $KEY_FILE" >&2
        exit 1
    fi
    echo "[trust] generating ephemeral development Ed25519 HBI key"
    openssl genpkey -algorithm ED25519 -out "$KEY_FILE"
fi
chmod 600 "$KEY_FILE"

# SubjectPublicKeyInfo DER for Ed25519 ends with the raw 32-byte public key.
PUBLIC_HEX="$(openssl pkey -in "$KEY_FILE" -pubout -outform DER \
    | tail -c 32 | od -An -v -tx1 | tr -d ' \n')"
if [[ ${#PUBLIC_HEX} -ne 64 ]]; then
    echo "could not derive a 32-byte Ed25519 public key" >&2
    exit 1
fi
if [[ -n "${HUESOS_HBI_VERIFY_KEY_HEX:-}" \
      && "${HUESOS_HBI_VERIFY_KEY_HEX,,}" != "$PUBLIC_HEX" ]]; then
    echo "HBI signing key does not match HUESOS_HBI_VERIFY_KEY_HEX" >&2
    exit 1
fi
printf '%s\n' "$PUBLIC_HEX" > build/hbi-verify-key.hex
printf '%s\n' "$KEY_FILE" > build/hbi-signing-key.path
if [[ "$KEY_FILE" == "$DEV_KEY" ]]; then
    echo "[trust] development HBI key active (not for release distribution)"
else
    echo "[trust] external production HBI key active"
fi
