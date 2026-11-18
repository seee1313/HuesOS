#!/usr/bin/env bash
# HuesOS development environment bootstrap.
#
# Installs the pinned Rust toolchain (from rust-toolchain.toml) plus the
# host tooling needed to run the gates described in CONTRIBUTING.md §10:
#
#   make audit-check   -> python3
#   make clippy        -> cargo clippy (pinned toolchain)
#   make test          -> cargo test with -Z build-std=
#   make run           -> QEMU boot smoke (qemu-system-x86_64 + xorriso)
#
# The script is idempotent: re-running it only installs what is missing.
# It never sudo-installs without asking unless HUESOS_SETUP_YES=1 is set.
#
# Usage:
#   bash scripts/dev-setup.sh              # toolchain + verify, prompt for system pkgs
#   HUESOS_SETUP_YES=1 bash scripts/dev-setup.sh
#   bash scripts/dev-setup.sh --no-qemu    # skip the QEMU smoke dependencies
#   bash scripts/dev-setup.sh --check      # report state, install nothing

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WANT_QEMU=1
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --no-qemu) WANT_QEMU=0 ;;
        --check)   CHECK_ONLY=1 ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

info() { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[fail ]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[ ok  ]\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------- toolchain --

# The pinned channel is the single source of truth. Parse it rather than
# duplicating the version string here, so this script cannot drift from
# rust-toolchain.toml.
if [[ ! -f rust-toolchain.toml ]]; then
    fail "rust-toolchain.toml not found; run this from the HuesOS checkout"
    exit 1
fi
CHANNEL="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml)"
if [[ -z "$CHANNEL" ]]; then
    fail "could not parse channel from rust-toolchain.toml"
    exit 1
fi
info "pinned toolchain: $CHANNEL"

export PATH="$HOME/.cargo/bin:$PATH"

if ! command -v rustup >/dev/null 2>&1; then
    if [[ "$CHECK_ONLY" == 1 ]]; then
        warn "rustup: MISSING"
    else
        info "installing rustup (profile=minimal, no default toolchain)"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain none
        export PATH="$HOME/.cargo/bin:$PATH"
        ok "rustup installed"
    fi
else
    ok "rustup present: $(rustup --version 2>/dev/null | head -1)"
fi

if command -v rustup >/dev/null 2>&1 && [[ "$CHECK_ONLY" == 0 ]]; then
    # rustup honours rust-toolchain.toml automatically, including the
    # components/targets it lists (rust-src, llvm-tools-preview, rustfmt,
    # clippy, x86_64-unknown-none). A bare `rustup show` in the repo root
    # triggers the install of exactly that set.
    info "syncing pinned toolchain and components (this may take a few minutes)"
    if ! rustup show >/dev/null; then
        fail "rustup could not materialise the pinned toolchain ($CHANNEL)"
        exit 1
    fi
    # rust-src is what -Z build-std needs; assert it explicitly because a
    # partially-installed toolchain fails later with a confusing error.
    # Report the failure instead of swallowing it: a missing rust-src turns
    # into an unreadable build-std error thousands of lines later.
    if ! rustup component add rust-src clippy rustfmt --toolchain "$CHANNEL" >/dev/null 2>&1; then
        warn "could not add rust-src/clippy/rustfmt to $CHANNEL; verification below will say if it matters"
    fi

    # Do not announce success on the strength of rustup's exit code alone.
    # A toolchain can be registered and still be unusable — the cargo shim
    # loses its +x bit, ~/.rustup/toolchains gets pruned — and the earlier
    # version of this block reported `[ ok ] toolchain ready:` with an empty
    # version string and exited 0, because the failing `$(cargo --version)`
    # was a command substitution inside an argument, which `set -e` does not
    # catch. Run the probe as its own statement and check it.
    if ! CARGO_VERSION="$(cargo --version 2>&1)"; then
        fail "toolchain is registered but cargo is not runnable: $CARGO_VERSION"
        fail "typically a lost +x bit: chmod +x ~/.cargo/bin/* and re-run"
        exit 1
    fi
    ok "toolchain ready: $CARGO_VERSION"
fi

# ------------------------------------------------------------ system tools --

# python3 drives every gate in `make audit-check`; QEMU + xorriso are only
# needed for `make run` (the boot smoke).
REQUIRED=(python3)
QEMU_PKGS=()
MISSING=()

for tool in "${REQUIRED[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then MISSING+=("$tool"); fi
done

if [[ "$WANT_QEMU" == 1 ]]; then
    command -v qemu-system-x86_64 >/dev/null 2>&1 || QEMU_PKGS+=(qemu-system-x86)
    command -v xorriso           >/dev/null 2>&1 || QEMU_PKGS+=(xorriso)
    # Limine's ISO path also wants mtools for the EFI system partition.
    command -v mformat           >/dev/null 2>&1 || QEMU_PKGS+=(mtools)
fi

detect_pm() {
    if   command -v apt-get >/dev/null 2>&1; then echo apt
    elif command -v dnf     >/dev/null 2>&1; then echo dnf
    elif command -v pacman  >/dev/null 2>&1; then echo pacman
    elif command -v apk     >/dev/null 2>&1; then echo apk
    elif command -v brew    >/dev/null 2>&1; then echo brew
    else echo none; fi
}

install_pkgs() {
    local pm="$1"; shift
    local pkgs=("$@")
    [[ ${#pkgs[@]} -eq 0 ]] && return 0
    local sudo=""
    [[ "$(id -u)" != "0" ]] && command -v sudo >/dev/null 2>&1 && sudo="sudo"
    case "$pm" in
        apt)    $sudo apt-get update -qq && $sudo apt-get install -y "${pkgs[@]}" ;;
        dnf)    $sudo dnf install -y "${pkgs[@]}" ;;
        pacman) $sudo pacman -Sy --noconfirm "${pkgs[@]}" ;;
        apk)    $sudo apk add --no-cache "${pkgs[@]}" ;;
        brew)   brew install "${pkgs[@]}" ;;
        *)      return 1 ;;
    esac
}

ALL_MISSING=("${MISSING[@]}" "${QEMU_PKGS[@]}")
if [[ ${#ALL_MISSING[@]} -gt 0 ]]; then
    PM="$(detect_pm)"
    warn "missing host packages: ${ALL_MISSING[*]}"
    if [[ "$CHECK_ONLY" == 1 ]]; then
        :
    elif [[ "$PM" == "none" ]]; then
        warn "no supported package manager detected; install manually: ${ALL_MISSING[*]}"
    elif [[ "${HUESOS_SETUP_YES:-0}" == "1" ]]; then
        install_pkgs "$PM" "${ALL_MISSING[@]}" || warn "package install failed; continuing"
    else
        read -r -p "install them with $PM? [y/N] " reply
        case "$reply" in
            [yY]*) install_pkgs "$PM" "${ALL_MISSING[@]}" || warn "package install failed" ;;
            *)     warn "skipped; 'make run' will not work without them" ;;
        esac
    fi
else
    ok "host packages present"
fi

# ------------------------------------------------------------------ report --

echo
info "environment report"
printf '  %-22s %s\n' "rustc"   "$(command -v rustc   >/dev/null 2>&1 && rustc --version   || echo MISSING)"
printf '  %-22s %s\n' "cargo"   "$(command -v cargo   >/dev/null 2>&1 && cargo --version   || echo MISSING)"
printf '  %-22s %s\n' "clippy"  "$(command -v cargo-clippy >/dev/null 2>&1 && cargo clippy --version 2>/dev/null || echo MISSING)"
printf '  %-22s %s\n' "rustfmt" "$(command -v rustfmt >/dev/null 2>&1 && rustfmt --version || echo MISSING)"
printf '  %-22s %s\n' "python3" "$(command -v python3 >/dev/null 2>&1 && python3 --version || echo MISSING)"
printf '  %-22s %s\n' "qemu"    "$(command -v qemu-system-x86_64 >/dev/null 2>&1 && qemu-system-x86_64 --version | head -1 || echo MISSING)"
printf '  %-22s %s\n' "xorriso" "$(command -v xorriso >/dev/null 2>&1 && xorriso --version 2>&1 | head -1 || echo MISSING)"

echo

# --------------------------------------------------------------- verify --

# The report above only proves the binaries answer `--version`. The thing
# that actually breaks in practice is `-Z build-std=`, which needs rust-src
# present for the pinned channel and a working x86_64-unknown-none target.
# Prove it on a throwaway crate rather than letting the first real
# `make test` be the discovery.
VERIFY_FAILED=0
if [[ "$CHECK_ONLY" == 0 ]] && command -v cargo >/dev/null 2>&1; then
    info "verifying the toolchain can actually build (-Z build-std=)"
    PROBE="$(mktemp -d)"
    trap 'rm -rf "$PROBE"' EXIT
    mkdir -p "$PROBE/src"
    cat > "$PROBE/Cargo.toml" <<'PROBE_EOF'
[package]
name = "huesos-setup-probe"
version = "0.0.0"
edition = "2021"

[workspace]
PROBE_EOF
    echo '#![no_std] pub fn probe() -> u32 { 1 }' > "$PROBE/src/lib.rs"
    if (cd "$PROBE" && cargo build \
            --target x86_64-unknown-none \
            -Z build-std=core \
            >/dev/null 2>&1); then
        ok "build-std probe compiled for x86_64-unknown-none"
    else
        VERIFY_FAILED=1
        fail "the pinned toolchain cannot build for x86_64-unknown-none"
        fail "check: rustup component add rust-src --toolchain $CHANNEL"
        fail "       rustup target add x86_64-unknown-none --toolchain $CHANNEL"
    fi
    rm -rf "$PROBE"
    trap - EXIT
fi

echo
if command -v qemu-system-x86_64 >/dev/null 2>&1; then
    info "gates available:  make audit-check | make clippy | make test | make run"
else
    info "gates available:  make audit-check | make clippy | make test"
    warn "'make run' (QEMU boot smoke) unavailable — mark on-target work UNVERIFIED per CONTRIBUTING §6"
fi

# Exit non-zero when the environment cannot run the gates, so this script is
# usable as a CI precondition and in `&&` chains. Previously it returned 0
# unconditionally, which is what let a broken setup look healthy.
MISSING_CORE=()
for tool in cargo rustc python3; do
    command -v "$tool" >/dev/null 2>&1 || MISSING_CORE+=("$tool")
done

if [[ ${#MISSING_CORE[@]} -gt 0 ]]; then
    echo
    fail "missing tools required by the gates: ${MISSING_CORE[*]}"
    exit 1
fi

if [[ "$VERIFY_FAILED" == 1 ]]; then
    echo
    fail "environment is incomplete: the build-std probe did not compile"
    exit 1
fi

echo
ok "environment ready"

