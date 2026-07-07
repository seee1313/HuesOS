# HuesOS modularity map

This document records the current split after the first large modularization
pass. The goal is to keep growing code out of monolithic `lib.rs` / `main.rs`
files and make future driver, shell, and syscall work land in focused modules.

## Kernel object crate

`crates/huesos-object/src/` is split by object responsibility:

- `koid.rs` — KOID allocation and `Koid`.
- `object.rs` — `KernelObject`, downcasting helper, and `ObjectType`.
- `handle.rs` — rights, handles, and per-process handle tables.
- `registry.rs` — global object/process/interrupt registries and current process state.
- `vmo.rs` — physical-frame backed VMOs.
- `vmar.rs` — VMAR range/mapping bookkeeping.
- `channel.rs` — channel IPC endpoints/messages.
- `port.rs` — Port event queues.
- `interrupt.rs` — userspace IRQ bridge objects.
- `job.rs`, `process.rs`, `thread.rs` — process hierarchy/execution objects.

`lib.rs` is now a facade: it wires root initialization and re-exports the
public object API.

## Syscall crate

`crates/huesos-syscalls/src/` is split by syscall family:

- `callbacks.rs` — callbacks registered by `huesos-kernel`.
- `util.rs` — shared current-process helpers.
- `handle.rs`, `vmo.rs`, `channel.rs` — object syscall families.
- `process.rs` — process/thread/VMAR launch, yield, and exit syscalls.
- `port_interrupt.rs` — Port and Interrupt bridge syscalls.
- `framebuffer.rs` — framebuffer info/blit syscalls.
- `debug.rs` — debug serial output syscall.

`lib.rs` now owns only the public setter re-exports, result type, and the
central syscall dispatch table.

## Userspace terminal

`crates/huesos-userspace/terminal/src/` is split into shell subsystems:

- `main.rs` — ring3 entrypoint and panic handler.
- `shell.rs` — shell event loop and keyboard Port binding.
- `screen.rs` — framebuffer text screen.
- `keyboard.rs` — PS/2 set-1 scancode decoder.
- `lexer.rs` — `logos` token definitions.
- `parser.rs` — `Peekable` token iterator parser.
- `ast.rs` — AST structs/enums.
- `commands.rs` — built-in command dispatcher.

## libcanvas process module

`crates/huesos-userspace/libcanvas/src/process/` now separates:

- `objects.rs` — typed `Process`, `Thread`, and `Vmar` handle wrappers.
- `elf.rs` — minimal static ELF parser.
- `launcher.rs` — `spawn_elf` userspace process launcher.
- `lifecycle.rs` — `exit` and `yield_now`.

The top-level `process.rs` remains a facade so existing userspace code can
keep using `libcanvas::process::*`.

## Userspace driver stack

`crates/huesos-userspace/driver-manager/src/` is split into:

- `main.rs` — DriverManager entrypoint and init bootstrap response.
- `manifest.rs` — static DriverHost/service/capability manifest table.
- `registry.rs` — fixed-size service registry and service state.
- `protocol.rs` — bootstrap/status/heartbeat message constants.
- `supervisor.rs` — DriverHost launch and heartbeat/status polling.

`crates/huesos-userspace/driver-host-input/` is the first DriverHost process.
It hosts the DriverManager-managed MVP keyboard service, binds IRQ1 to a Port, and reports
readiness/heartbeats to DriverManager.
