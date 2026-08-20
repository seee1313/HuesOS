#!/usr/bin/env bash
# Restore every non-persistent dependency needed to build/test HuesOS in a
# fresh Arena workspace snapshot. Safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="nightly-2026-03-01"
BASE_SHA="${HUESOS_BASE_SHA:-84c677ccca5f70bf5953758e7c6d3aa9d28bb424}"
BRANCH="${HUESOS_BRANCH:-huesos-dev/verified-boot-tpm-smep-hardening}"
REMOTE="${HUESOS_REMOTE:-https://github.com/seee1313/HuesOS.git}"
INSTALL_SYSTEM_DEPS="${INSTALL_SYSTEM_DEPS:-1}"
INSTALL_CARGO_TOOLS="${INSTALL_CARGO_TOOLS:-1}"

log() { printf '[restore-dev-env] %s\n' "$*"; }

restore_rust() {
    # Snapshot transports preserve the rustup binary bytes but may flatten its
    # executable bit. Repair it before the first invocation.
    if [[ -d "$HOME/.cargo/bin" ]]; then
        find "$HOME/.cargo/bin" -maxdepth 1 -type f -exec chmod +x {} +
    fi
    if [[ ! -s "$HOME/.cargo/env" ]]; then
        log "installing rustup bootstrap"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            -o /tmp/huesos-rustup-init.sh
        sh /tmp/huesos-rustup-init.sh -y --profile minimal --default-toolchain none
    fi
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
    log "ensuring $TOOLCHAIN + rust-src/rustfmt/clippy/llvm-tools"
    rustup toolchain install "$TOOLCHAIN" --profile minimal \
        --component rust-src,rustfmt,clippy,llvm-tools-preview
    rustup default "$TOOLCHAIN"
}

restore_system_deps() {
    [[ "$INSTALL_SYSTEM_DEPS" == "1" ]] || return 0
    local missing=0
    for command in gcc xorriso qemu-system-x86_64 swtpm socat tpm2_createpolicy openssl \
        sbsign virt-fw-vars mcopy; do
        command -v "$command" >/dev/null 2>&1 || missing=1
    done
    [[ "$missing" == "1" ]] || return 0
    log "installing QEMU/ISO/TPM host packages"
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        gcc xorriso qemu-system-x86 swtpm swtpm-tools tpm2-tools \
        openssl sbsigntool socat ovmf mtools python3-virt-firmware efitools
}

restore_cargo_tools() {
    [[ "$INSTALL_CARGO_TOOLS" == "1" ]] || return 0
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
    if ! cargo audit --version 2>/dev/null | grep -Fq '0.22.2'; then
        log "installing cargo-audit 0.22.2"
        cargo install cargo-audit --locked --version 0.22.2
    fi
    if ! cargo fuzz --version 2>/dev/null | grep -Fq '0.13.2'; then
        log "installing cargo-fuzz 0.13.2"
        cargo install cargo-fuzz --locked --version 0.13.2
    fi
}

restore_git_metadata() {
    cd "$ROOT"
    # Arena snapshots may discard `.git` as credential-bearing metadata. Keep a
    # shallow, credential-free Git dir under `.repo`, then recreate the pointer.
    if [[ ! -d .repo/objects ]]; then
        log "rebuilding shallow Git metadata at base $BASE_SHA"
        rm -rf .repo
        git init --bare .repo >/dev/null
        git --git-dir=.repo --work-tree=. config core.bare false
        git --git-dir=.repo --work-tree=. config core.worktree ..
        git --git-dir=.repo --work-tree=. remote add origin "$REMOTE"
        git --git-dir=.repo --work-tree=. fetch --depth=1 origin "$BASE_SHA"
        git --git-dir=.repo --work-tree=. update-ref "refs/heads/$BRANCH" FETCH_HEAD
        git --git-dir=.repo --work-tree=. symbolic-ref HEAD "refs/heads/$BRANCH"
        # Reset the index only. Never overwrite the preserved working tree.
        git --git-dir=.repo --work-tree=. reset --mixed HEAD >/dev/null
    fi
    printf 'gitdir: .repo\n' > .git
    mkdir -p .repo/info
    {
        printf '.repo/\n'
        printf 'ci-artifacts/qemu-key-broker-gcm.log\n'
    } > .repo/info/exclude

    # Snapshot transports may flatten mode bits. Restore every executable bit
    # recorded by the base tree, plus this newly-added recovery script.
    while IFS= read -r -d '' path; do
        chmod +x "$path"
    done < <(git ls-tree -rz HEAD | awk -v RS='\0' '$1 == "100755" {sub(/^[^\t]*\t/, ""); printf "%s%c", $0, 0}')
    chmod +x scripts/restore-dev-env.sh scripts/test-hxfs-migration.sh 2>/dev/null || true
    log "Git worktree restored on $BRANCH"
}

verify() {
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
    cd "$ROOT"
    rustc --version
    cargo --version
    command -v qemu-system-x86_64 >/dev/null 2>&1 && qemu-system-x86_64 --version | head -1 || true
    git status --short | sed -n '1,20p'
    log "ready; for an interactive shell run: source \"$HOME/.cargo/env\""
}

restore_rust
restore_system_deps
restore_cargo_tools
restore_git_metadata
verify
