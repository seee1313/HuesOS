# HuesOS microkernel migration plan

This file records the user-approved direction for the driver/userspace
migration so implementation work stays explicit and reviewable.

## Approved direction

- Start from the hard-microkernel foundation first, not from a large terminal-only patch.
- Add dynamic userspace launching through a Zircon-like split model: `ProcessCreate`, VMAR mapping, `ThreadCreate`, and `ThreadStart`.
- Keep only kernel IRQ bridge/stubs in the kernel for early migration; driver policy/state machines live in userspace.
- The first terminal is a framebuffer text terminal with keyboard input.
- `init` is responsible for launching programs and services.
- `DriverManager` owns userspace driver lifecycle and service discovery; terminal waits for keyboard/framebuffer services from `DriverManager`.
- Child processes receive only one bootstrap capability at startup: handle 1 is the bootstrap channel endpoint.
- Process exit observation is part of the launch ABI via `ProcessWait`/exit-code query semantics.
- IRQ delivery will be modeled with interrupt objects plus ports.
- The framebuffer driver will move to userspace through a mapped framebuffer capability, not through permanent kernel blit logic.
- Initial VMAR map flags are `READ`, `WRITE`, `EXECUTE`, `USER`, and `SPECIFIC`.
- Root VMAR uses a 64 KiB low guard and spans `[0x0000_0000_0001_0000, 0x0000_8000_0000_0000)`.
- First VMAR implementation is root-VMAR mapping only; child VMAR allocation/tree APIs come later.
- `VmarMap` is strict fixed-address mapping only: callers must set `SPECIFIC`.
- Process runtime state is stored behind `Process.address_space` as a kernel-side `ProcessRuntime` via `Box<dyn Any>`.
- Work must be split into small commits.

## Immediate open decisions before code changes

These are intentionally left unresolved until the project owner approves them:

1. How `init` discovers/embeds child ELF images.
2. `DriverManager` service protocol and concrete driver restart policy.
3. Exact Port/Interrupt syscall set and packet layout.
4. Exact framebuffer mapping rights and handoff lifetime rules.
5. Terminal command/input protocol.
