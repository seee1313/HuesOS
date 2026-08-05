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
- The framebuffer driver will move to userspace through a mapped framebuffer capability, not through permanent kernel blit logic. **(superseded — see update below.)**
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
- `input-host` owns the DriverManager-managed keyboard IRQ binding, reports `service:keyboard:ready`, and sends heartbeat messages back to DriverManager over its bootstrap channel.
- DriverManager registers the `keyboard` service from DriverHost readiness messages and reports ready to init only after the mandatory input service comes online.
- DriverManager now mounts BOOTFS as a FileSystemService and terminal can use `ls`, `cat`, and `stat` through DriverManager's service registry.
- Work must be split into small commits.

## Update — framebuffer stays in kernel, but is capability-gated

The line above ("the framebuffer driver will move to userspace through
a mapped framebuffer capability, not through permanent kernel blit
logic") is **superseded by the PR-G `fb-frame-draw-capability`
decision**. The framebuffer driver (`huesos-fb`) stays in the kernel
for three concrete reasons:

1. The kernel panic screen, the boot splash, and the shutdown screen
   all need to be renderable even after every userspace process has
   crashed. A userspace framebuffer driver-host cannot be relied on to
   be alive at those moments, so the kernel needs its own draw path
   to the real framebuffer.
2. A userspace framebuffer driver-host that maps raw video memory
   would give every graphics client direct write access to that
   memory, which is a strictly worse security model than the
   capability-gated kernel blit path. The narrower syscall is the
   safer design.
3. Moving the driver does not buy much — `huesos-fb` is small, has
   no per-frame timing requirements, and is only invoked from a
   handful of places (panic, init splash, shutdown, libcanvas
   `present`/`present_at`).

What **did** change is the access control: `Syscall::FramebufferBlit`
is now gated on a `FrameDraw` capability (`ResourceKind::FrameDraw =
6`, install slot `INIT_FRAME_DRAW_HANDLE = 6`). Only the init
process can mint the capability (mint is gated on the root
supervisor KOID predicate), and init transfers the handle to
legitimate graphics consumers (`terminal`, `doom`, `canvas-hell`)
over channels using the same `write_handle` pattern
`shutdown-broker` uses for `PowerControl` and `IoPort`. A
non-graphics process that tries to blit gets `ErrorCode::AccessDenied`
and no information about the caller's address space or the kernel's
framebuffer geometry (the capability check runs before the
`*const FramebufferBlitArgs` is dereferenced). See
[`docs/FRAMEBUFFER_POLICY.md`](FRAMEBUFFER_POLICY.md) for the full
threat model, ABI delta, and tests.

## Immediate open decisions before code changes

These are intentionally left unresolved until the project owner approves them:

1. How `init` discovers/embeds child ELF images.
2. `DriverManager` service protocol and concrete driver restart policy.
3. Exact Port/Interrupt syscall set and packet layout.
4. Exact framebuffer mapping rights and handoff lifetime rules.
5. Terminal command/input protocol.
