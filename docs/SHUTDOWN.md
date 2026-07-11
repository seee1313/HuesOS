# Orderly Software Shutdown

## Hardware semantics

The classic 8042 PS/2 controller has no command that removes system power.
Command `0xFE`, sometimes incorrectly described as shutdown, pulses the reset
line and reboots the computer. HuesOS deliberately does not use it for the
`shutdown` command.

The approved non-ACPI shutdown performs a safe software halt:

1. Terminal sends `system:shutdown` to its init bootstrap Channel.
2. Init, the root userspace supervisor, invokes `SystemShutdown`.
3. The kernel verifies that the caller KOID is the registered init process.
4. The framebuffer displays a final dark shutdown screen.
5. 8042 commands `0xAD` and `0xA7` disable the first and second PS/2 ports.
6. The local LAPIC timer is stopped.
7. A shutdown-stop IPI (`0xF2`) halts every peer CPU.
8. The requesting CPU enters a permanent `cli`/`hlt` loop.

No ACPI tables, ACPI PM registers, QEMU debug-exit ports, or reset commands are
used. Physical power remains on, and the screen explicitly says that it is now
safe to switch the computer off.

## Authorization

`SystemShutdown` is not an unrestricted syscall. At boot, the kernel records
the KOID of the init process. Calls from any other process return
`AccessDenied`. Init launches a negative boot probe and requires:

```text
[init] shutdown authorization OK (unprivileged caller denied)
```

Terminal therefore cannot directly halt the machine. Its built-in `shutdown`
command sends an IPC request to init; init owns the shutdown policy and calls
the syscall. This preserves the capability-oriented architecture and leaves a
natural place for future confirmation, policy, or session management.

## Controller quiescing

Before writing each 8042 command, the kernel waits for status bit 1 (input
buffer full) to clear. Polling is bounded so absent or broken PS/2 hardware
cannot hang the shutdown path. Failure to observe readiness does not prevent
CPU halt.

The commands are:

| Command | Meaning |
|---|---|
| `0xAD` to port `0x64` | Disable first PS/2 interface (keyboard) |
| `0xA7` to port `0x64` | Disable second PS/2 interface (mouse) |

These are quiesce commands, not power-control commands.

## QEMU integration test

The test boots a release SMP image, injects the keys `shutdown` and Enter
through QEMU's virtual PS/2 keyboard, and verifies serial output:

```text
[init] terminal requested orderly shutdown
[shutdown] orderly non-ACPI shutdown requested by init
[shutdown] all CPUs halted; power remains on
```

A QEMU screendump is checked for the dark `(5, 10, 20)` background and visible
cyan/white text. QEMU remains alive until the test harness explicitly quits,
which proves HuesOS halted rather than rebooted or using a hypervisor-specific
power-off mechanism.
