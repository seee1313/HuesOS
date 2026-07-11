# Building HuesOS

## Prerequisites

- **Rust nightly** with `rust-src` and `llvm-tools-preview` components
  (pinned via `rust-toolchain.toml`, so `rustup` will fetch the right
  version automatically once you run any `cargo`/`rustc` command in this
  repo)
- **QEMU** (`qemu-system-x86_64`)
- **xorriso** and **mtools** for ISO generation
- **GCC** (freestanding C objects for the separate DoomGeneric userspace port)

Note: **you do not need to separately install OVMF UEFI firmware** — a
known-good OVMF build is vendored in this repo (see
[Vendored dependencies](#vendored-dependencies) below), specifically to
avoid the "which of the five different paths/filenames does my distro use
for OVMF" problem across Debian/Ubuntu/Arch/Fedora/macOS.

### Install Rust nightly

```bash
rustup toolchain install nightly
rustup component add rust-src llvm-tools-preview rustfmt --toolchain nightly
```

(The pinned `rust-toolchain.toml` in this repo will select the right
toolchain automatically inside the project directory.)

### Install QEMU

**Debian/Ubuntu:**
```bash
sudo apt install qemu-system-x86 xorriso mtools gcc
```

**Arch Linux:**
```bash
sudo pacman -S qemu-full xorriso mtools gcc
```

**macOS:**
```bash
brew install qemu xorriso mtools gcc
```

## Vendored dependencies

Two small third-party binary dependencies are vendored directly in this
repository so that `make build`, `make iso`, and `make run` all work
immediately after `git clone`, with no extra downloads and no dependence
on how any particular OS distribution packages them:

- [`third_party/limine/`](../third_party/limine) — prebuilt Limine
  bootloader binaries (BSD-licensed)
- [`third_party/ovmf/`](../third_party/ovmf) — a combined OVMF UEFI
  firmware image (BSD-2-Clause-Patent licensed)

Both directories have their own `README.md` documenting provenance,
license, and how to refresh them with a newer version. Both can be
overridden without touching the vendored copies: `LIMINE_BIN=/path` for
Limine, `OVMF_PATH=/path/to/OVMF.fd` for the firmware.

### Limine

The prebuilt Limine binaries needed to make a bootable ISO (bootloader
stages, `BOOTX64.EFI`, etc.) are **vendored directly in this repository**
under [`third_party/limine/`](../third_party/limine), so there is nothing
to download separately — `make iso` works right after cloning.

If you want to use a different/newer Limine release instead, point
`LIMINE_BIN` at it:

```bash
git clone --branch v9.x-binary --depth 1 \
    https://github.com/limine-bootloader/limine.git /tmp/limine-bin
LIMINE_BIN=/tmp/limine-bin make iso
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

`make iso` also builds `tools/hbi-gen` and packages `build/huesos.hbi`
(HBI v2.1) via `scripts/mkhbi.sh`, then embeds kernel + HBI into the ISO
per `scripts/limine.conf` (`module_path` for the HBI).

Output: `build/huesos.iso` — a hybrid BIOS+UEFI bootable ISO built with
Limine.

## Run in QEMU

```bash
make run             # builds + packages + boots (debug)
make run PROFILE=release
```

This launches QEMU with:
- Q35 chipset, OVMF UEFI firmware
- **2 CPUs** (`-smp 2` in `scripts/run.sh`) — SMP path is the default
- 256 MB RAM
- Serial console on stdio (kernel + userspace `init` / driver-manager /
  terminal output)

To force uniprocessor for comparison:

```bash
qemu-system-x86_64 -machine q35 -cpu qemu64 -smp 1 -m 512M \
  -bios third_party/ovmf/OVMF.fd -cdrom build/huesos.iso \
  -serial stdio -display none -no-reboot -no-shutdown
```

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
This shouldn't happen with the vendored OVMF image, but if you set
`OVMF_PATH` to a custom firmware file, double check it actually exists —
`scripts/run.sh` will print a clear error naming the missing path
otherwise, rather than silently falling back to something else.
