# Vendored Limine binaries

These files come from the Limine bootloader's `v9.x-binary` prebuilt binary
branch (Limine 9.6.7), used to build a bootable ISO for HuesOS without
requiring a separate download/build step:

- `BOOTX64.EFI`, `BOOTIA32.EFI` — UEFI bootloader executables
- `limine-bios.sys`, `limine-bios-cd.bin` — BIOS boot stages
- `limine-uefi-cd.bin` — UEFI El Torito boot image for CD/ISO media
- `LICENSE` — Limine's own license (BSD-2-Clause)

Source: https://github.com/limine-bootloader/limine (branch `v9.x-binary`)

To refresh these with a newer Limine release:

```bash
git clone --branch v9.x-binary --depth 1 \
    https://github.com/limine-bootloader/limine.git /tmp/limine-bin
cp /tmp/limine-bin/{BOOTX64.EFI,BOOTIA32.EFI,limine-bios.sys,limine-bios-cd.bin,limine-uefi-cd.bin,LICENSE} \
    third_party/limine/
```

Limine itself is not part of HuesOS's own codebase; it is used unmodified
as the bootloader per its own license (see `LICENSE` in this directory).
