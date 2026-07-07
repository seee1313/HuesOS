# HuesOS hardware compatibility notes

This document records real-machine smoke tests reported by developers/users.
It is not a certification matrix yet; it is a lightweight compatibility log so
we can track which firmware/GPU/CPU combinations have booted beyond QEMU.

## Successful smoke tests

### MSI Modern 15 B5M

- **Report date**: 2026-07-07
- **Result**: HuesOS booted and all tested functionality reportedly worked
  normally, including PS/2 keyboard input.
- **Machine**: Micro-Star International Modern 15 B5M, revision 1.0
- **Mainboard**: Micro-Star MS-15HK, revision 1.0
- **Firmware**: American Megatrends UEFI `E15HKAMS.109`, dated 2023-09-22
- **CPU**: AMD Ryzen 5 5625U with Radeon Graphics, 6 cores / 12 threads
- **Graphics**: AMD/ATI Barcelo / Radeon integrated graphics
- **Memory**: 8 GiB installed, approximately 7.13 GiB available to the host OS
- **Internal storage**: Phison 256GB NVMe (`EM280256GYTCTAS-E13T2MS`)
- **Boot media used in report**: Silicon Power USB 2.0 8 GiB flash drive
- **Network device**: MediaTek MT7921K Wi-Fi 6E
- **Bluetooth device**: MediaTek USB Bluetooth
- **Reference host OS used for collecting hardware info**: EndeavourOS,
  Linux `7.1.2-arch3-1`, KDE Plasma 6.7.2

Observed HuesOS-relevant coverage from this report:

- UEFI firmware can load the Limine/HuesOS boot path.
- Limine framebuffer handoff is usable on this AMD integrated GPU laptop.
- The current boot-to-userspace path is not QEMU-only.
- No failure was reported for the init / DriverManager / terminal smoke flow.
- PS/2 keyboard input worked on real hardware, including the current keyboard
  driver / IRQ bridge path used by the terminal shell.

Unknown / not yet recorded for this machine:

- Secure Boot state.
- Exact HuesOS framebuffer mode selected by Limine.
- Whether repeated warm/cold boots were tested.

When adding another hardware result, include firmware version, CPU/GPU,
RAM, boot media, HuesOS commit/branch, and what was actually exercised.
