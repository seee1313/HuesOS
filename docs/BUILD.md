# Building HuesOS

## Prerequisites

- **Rust nightly** with `rust-src` and `llvm-tools-preview` components
  (pinned via `rust-toolchain.toml`, so `rustup` will fetch the right
  version automatically once you run any `cargo`/`rustc` command in this
  repo)
- **QEMU** with UEFI support
- **OVMF** UEFI firmware
- **xorriso** and **mtools** for ISO generation

### Install Rust nightly

```bash
rustup toolchain install nightly
rustup component add rust-src llvm-tools-preview rustfmt --toolchain nightly
```

(The pinned `rust-toolchain.toml` in this repo will select the right
toolchain automatically inside the project directory.)

### Install QEMU & OVMF

**Debian/Ubuntu:**
```bash
sudo apt install qemu-system-x86 ovmf xorriso mtools
```

**Arch Linux:**
```bash
sudo pacman -S qemu-full edk2-ovmf xorriso mtools
```

**macOS:**
```bash
brew install qemu xorriso mtools
```
(OVMF firmware images need to be sourced separately on macOS, e.g. via the
`qemu` formula's bundled EDK2 or a manual download.)

### Fetch Limine

The build scripts expect a binary Limine release checked out at
`~/limine-bin` (override with `LIMINE_BIN=/path/to/limine`):

```bash
git clone --branch v9.x-binary --depth 1 \
    https://github.com/limine-bootloader/limine.git ~/limine-bin
```

## Build

```bash
# Debug build (also builds+embeds the userspace init binary automatically)
make build

# Release build
make build PROFILE=release
```

Under the hood, `huesos-kernel`'s `build.rs` invokes a **separate** `cargo
build` for `crates/huesos-userspace/init` (it targets ring3 userspace with
a different linker script/load address than the kernel) and embeds the
resulting ELF binary into the kernel image via `include_bytes!`. This means
the very first `cargo build` will look like it's compiling two independent
projects — that's expected.

## Create a Bootable ISO

```bash
make iso            # debug
make iso-release    # release
```

Output: `build/huesos.iso` — a hybrid BIOS+UEFI bootable ISO built with
Limine.

## Run in QEMU

```bash
make run             # builds + packages + boots (debug)
make run PROFILE=release
```

This launches QEMU with:
- Q35 chipset, OVMF UEFI firmware
- 256 MB RAM
- Serial console on stdio (you'll see kernel + userspace `init` output
  directly in your terminal)

## Run on Real Hardware

1. Burn `build/huesos.iso` to a USB drive (e.g. `dd if=build/huesos.iso
   of=/dev/sdX bs=4M status=progress`), or
2. Copy the ISO's `EFI/BOOT/BOOTX64.EFI` + `boot/` tree onto a FAT32 ESP.

HuesOS itself makes no BIOS/legacy assumptions, but real hardware obviously
carries more risk than QEMU — expect to debug driver gaps (this MVP only
has a PS/2 keyboard, serial, and PIT).

## Troubleshooting

### `linker rust-lld not found`
Ensure the `llvm-tools-preview` component is installed for the active
toolchain: `rustup component add llvm-tools-preview`.

### `.json target specs require -Zjson-target-spec`
This is handled automatically by `.cargo/config.toml`'s `[unstable]`
section — make sure you're not overriding `RUSTFLAGS`/`CARGO_*` env vars in
a way that strips it out.

### `error: current package believes it's in a workspace when it's not`
This is expected/handled for `crates/huesos-userspace/init` (it has its own
`[workspace]` table to keep it out of the main workspace, since it needs a
different target). If you see this for a *different* crate, check that
crate's `Cargo.toml`.

### QEMU shows no serial output
Check that OVMF was actually found — `scripts/run.sh` searches a few common
paths and will print an error naming which ones it tried if none exist.
