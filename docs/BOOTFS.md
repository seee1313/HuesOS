# BOOTFS

BOOTFS (`HBOOTFS1`) is HuesOS's immutable RAM-resident bootstrap archive. It is
assembled at build time (`crates/huesos-kernel/build.rs`), packaged as a module
inside the Ed25519-signed **HBI v2.2** image (`tools/hbi-gen`), validated by the
kernel at boot, and handed to `init` as a read-only VMO (`INIT_BOOTFS_HANDLE`
with `READ | DUPLICATE | TRANSFER` rights).

While mutable persistent files live on `HxFS v7` (`hxfs-service` over
`driver-host-nvme`), `BOOTFS` remains the trusted, block-device-independent
source of core supervisors, drivers, shared libraries, shell utilities, firmware
blobs, and root certificates — allowing HuesOS to boot cleanly even with
`STORAGE_OFF=1` or before an NVMe volume is formatted.

## Archive format (`HBOOTFS1`)

All fields are little-endian:

```text
BootFsHeader (16 bytes)
  magic[8]    = "HBOOTFS1"
  file_count  = u32
  reserved    = u32

BootFsEntry[file_count] (216 bytes)
  path[192]   = UTF-8 absolute path, NUL-padded
  offset      = u64, byte offset from start of image
  len         = u64, payload length in bytes
  flags       = u32
  reserved    = u32

payload bytes...
```

## Current BOOTFS namespace layout

- `/services/*` — `acpi-manager.elf`, `pci-manager.elf`, `hxfs.elf`,
  `shutdown-broker.elf`, `net.elf`, `wlan.elf` (plus `pci-hotplug-test.elf` in
  `boot-selftest` builds)
- `/drivers/*`, `/manifests/*` & `/storage/*` — `input-host.elf`,
  `driver-host-nvme.elf`, `driver-host-xhci.elf`, `.hdriver` manifests,
  `/storage/boot-drivers.manifest`, and `/manifests/bootfs.sha256`
- `/lib/*` — `/lib/ld-huesos.so`, `/lib/libcanvas.so`, `/lib/ld-pe.so`, and
  native Win64 PE32+ system DLLs (`ntdll.dll`, `kernel32.dll`, `ucrtbase.dll`,
  `msvcrt.dll`, `ws2_32.dll`, `bcrypt.dll`, `bcryptprimitives.dll`,
  `advapi32.dll`; see [EXECUTABLE_LOADERS.md](EXECUTABLE_LOADERS.md))
- `/bin/*` — `terminal.elf`, `hsh.elf`, `fdisk.elf`, `doom.elf`, and the 45
  user-facing `coreutils` binaries (`ls`, `cat`, `grep`, `tar`, `pci`, `lsusb`,
  `acpi`, `btop`, `nano`, `netctl`, `wlanctl`, `ping`, `curl`, ..., plus
  `/bin/std-smoke.elf` in `boot-selftest`; see [SHELL_AND_STD.md](SHELL_AND_STD.md))
- `/lib/firmware/rtw88/rtw8821c_fw.bin` — Realtek `RTL8821CE` Wi-Fi firmware blob
- `/etc/ssl/certs.pem` — Mozilla TLS 1.3 root CA bundle
- `/data/freedoom1.wad` — Freedoom Phase 1 asset streamed via read-only VMO slice

## Access model

- `driver-manager` exposes read-only `BOOTFS` directory/file access and library
  sub-VMOs without copying payloads into per-client heaps.
- `huesos-std::fs` and `hsh` expose `BOOTFS` seamlessly alongside `HxFS v7` (and
  allow `@caps(bootfs=none)` attenuation when spawning untrusted children).
