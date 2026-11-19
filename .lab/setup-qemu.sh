#!/usr/bin/env bash
# Bring up a portable QEMU for the HuesOS lab inside this sandbox.
#
# The sandbox has no apt access to qemu-system-x86 and no access to GitHub
# release assets, so QEMU comes from the `qemu-portable-linux-x64` npm package
# (static-ish build + bundled glib, pixman, OVMF edk2 images).  That build was
# made against glibc 2.38 while the sandbox ships 2.36, so we also build a tiny
# versioned shim exporting GLIBC_2.38 for the handful of newer symbols.
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QDIR="$LAB/qemu"
TGZ="$LAB/dl/qp.tgz"
NPM_URL="https://registry.npmjs.org/qemu-portable-linux-x64/-/qemu-portable-linux-x64-0.2.1.tgz"

mkdir -p "$LAB/dl"

if [ ! -x "$QDIR/bin/qemu-system-x86_64" ]; then
    echo "[lab] fetching vendored qemu"
    if [ ! -s "$TGZ" ]; then
        curl -sSL -o "$TGZ" "$NPM_URL"
    fi
    rm -rf "$QDIR"
    mkdir -p "$QDIR"
    tar xzf "$TGZ" -C "$QDIR" --strip-components=1
fi

if [ ! -f "$QDIR/lib/libglibc238shim.so" ]; then
    echo "[lab] building glibc 2.38 compatibility shim"
    gcc -O2 -fPIC -shared -o "$QDIR/lib/libglibc238shim.so" \
        "$LAB/shim/glibc238.c" \
        -Wl,--version-script="$LAB/shim/glibc238.map" \
        -Wl,-soname,libglibc238shim.so
fi

# QEMU looks for its firmware/keymaps next to the binary by default; force the
# vendored share directory instead.
cat > "$QDIR/env.sh" <<EOF
export LD_LIBRARY_PATH="$QDIR/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
export LD_PRELOAD="$QDIR/lib/libglibc238shim.so"
export QEMU_DATA_DIR="$QDIR/share/qemu"
EOF

# shellcheck disable=SC1091
. "$QDIR/env.sh"
"$QDIR/bin/qemu-system-x86_64" -L "$QDIR/share/qemu" --version
