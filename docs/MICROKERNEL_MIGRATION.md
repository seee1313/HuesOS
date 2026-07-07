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
- `VmarMap` is strict fixed-address mapping only: callers must set `SPECIFIC`; the MVP implementation is page-aligned, root-VMAR-only, user-only, non-W+X, and maps existing VMO frames into the target process address space.
- Process runtime state is stored behind `Process.address_space` as a kernel-side `ProcessRuntime` via `Box<dyn Any>`.
- `ProcessCreate` returns current `Rights::DEFAULT` handles for both the process and root VMAR.
- Empty process names are allowed and become `process`; non-empty names are UTF-8 and capped at 64 bytes.
- `ProcessWait` remains `NotSupported` until the Port/blocking wait model is implemented.
- `ThreadCreate` creates suspended thread objects associated with a process.
- `ThreadStart` installs the child bootstrap channel endpoint at handle 1, returns the parent endpoint, and schedules the new user task.
- `libcanvas::process::spawn_elf` is the userspace static-ELF launcher used by init.
- Kernel build now builds `driver-manager` and `terminal`, embeds their ELF bytes into init, and embeds only init into the kernel.
- DriverManager sends a ready message, binds keyboard IRQ1 to a userspace Port via an Interrupt object, and logs raw scancode packets.
- Terminal now runs a built-in framebuffer mini shell with internal commands only. Lexing uses `logos`, parsing uses a `Peekable` token iterator, and the shell builds an AST before dispatch.
- First Port/Interrupt ABI is non-blocking: `PortCreate`, `PortRead`, `InterruptCreate`, and `InterruptBindPort`.
- The first IRQ bridge supports keyboard IRQ1 only; packets use `PORT_PACKET_INTERRUPT` with data `[irq, scancode, count, 0]`.
- During the migration window, IRQ bridge interrupts fan out to multiple userspace consumers so DriverManager diagnostics and the temporary terminal keyboard consumer can coexist. The next cleanup step is replacing terminal's direct IRQ consumer with a DriverManager keyboard-service IPC protocol.
- DriverManager now owns a static Rust manifest table and launches an `input-host` DriverHost process.
- `input-host` owns the current keyboard IRQ binding, reports `service:keyboard:ready`, and sends heartbeat messages back to DriverManager over its bootstrap channel.
- DriverManager registers the `keyboard` service from DriverHost readiness messages and reports ready to init only after the mandatory input service comes online.
- Work must be split into small commits.

## Immediate open decisions before code changes

These are intentionally left unresolved until the project owner approves them:

1. How `init` discovers/embeds child ELF images.
2. `DriverManager` service protocol and concrete driver restart policy.
3. Exact Port/Interrupt syscall set and packet layout.
4. Exact framebuffer mapping rights and handoff lifetime rules.
5. Terminal command/input protocol.
