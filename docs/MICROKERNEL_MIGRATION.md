# HuesOS microkernel migration plan

This file records the user-approved direction for the driver/userspace
migration so implementation work stays explicit and reviewable.

## Approved direction

- Start from the hard-microkernel foundation first, not from a large terminal-only patch.
- Add dynamic userspace launching via `ProcessSpawn` from an ELF image supplied by `init`.
- Keep only kernel IRQ bridge/stubs in the kernel for early migration; driver policy/state machines live in userspace.
- The first terminal is a framebuffer text terminal with keyboard input.
- `init` is responsible for launching programs and services.
- Userspace drivers are managed by a separate `DriverManager`, not directly supervised by `init`.
- Work must be split into small commits.

## Immediate open decisions before code changes

These are intentionally left unresolved until the project owner approves them:

1. Exact `ProcessSpawn` ABI shape and which handles the child receives.
2. How `init` discovers/embeds child ELF images.
3. `DriverManager` launch order, service protocol, and restart policy.
4. Exact kernel IRQ bridge API.
5. Framebuffer handoff model for a userspace framebuffer driver.
6. Terminal command/input protocol.
