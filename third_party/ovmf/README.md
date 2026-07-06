# Vendored OVMF UEFI firmware

`OVMF.fd` is the combined (CODE+VARS) OVMF UEFI firmware image from the
Debian `ovmf` package (edk2 2025.02), used by `scripts/run.sh` to boot
HuesOS in QEMU without depending on the host distro's OVMF package layout
(paths and CODE/VARS splitting vary significantly between Debian/Ubuntu,
Arch, Fedora, and macOS Homebrew).

Source: https://github.com/tianocore/edk2 (Debian `ovmf` package,
version 2025.02-8+deb13u1)

License: BSD-2-Clause-Patent (see `LICENSE` in this directory, copied from
the Debian package's copyright file).

To refresh with a different OVMF build:

```bash
cp /usr/share/ovmf/OVMF.fd third_party/ovmf/OVMF.fd   # Debian/Ubuntu path
```

Or override at run time without replacing the vendored copy:

```bash
OVMF_PATH=/path/to/OVMF.fd make run
```
