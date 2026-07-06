# Writing Userspace Programs for HuesOS

This guide explains how userspace programs work on HuesOS, and how to
write your own. If you just want to see a complete, working example,
read `crates/huesos-userspace/init/src/main.rs` first — this guide
explains *why* it's written the way it is.

## The one rule: never call `syscall` yourself

**Every** interaction with the kernel must go through
[`libcanvas`](../crates/huesos-userspace/libcanvas) — HuesOS's safe
syscall library, the equivalent of `ntdll.dll` on Windows or `libc`'s
syscall wrappers on Linux. Application code should contain **zero**
instances of `asm!("syscall", ...)`. `libcanvas::raw` is the single,
audited place that instruction is allowed to appear in this entire
codebase.

This isn't a style preference — it's a real safety boundary:

- The `syscall` calling convention (which registers, that `rcx`/`r11` get
  clobbered, argument order) is easy to get subtly wrong in a way that
  corrupts state instead of crashing loudly. One correct implementation,
  reused everywhere, beats every program re-deriving it from scratch.
- Syscall numbers and error codes live in `huesos-abi`, shared by the
  kernel's dispatcher and `libcanvas`. If you hand-roll your own syscall
  numbers instead of using `libcanvas`, they *will* eventually drift out
  of sync with the kernel as the ABI grows.
- Resource safety (handles closing themselves, VMOs/Channels being
  RAII-wrapped) only works if you go through the wrapper types instead of
  holding raw handle values yourself.

## What a HuesOS userspace program actually is

- A **freestanding, `no_std` ELF64 executable** (`ET_EXEC`, non-PIE,
  statically linked at a fixed load address — see
  `crates/huesos-userspace/user_linker.ld`).
- Its entry point is a function named `_start` with C calling convention,
  taking no arguments and never returning (`-> !`).
- It runs at **ring3** (CPL=3), in its own isolated address space, with no
  access to kernel memory, no access to other processes' memory, and no
  direct hardware access — everything happens through syscalls, mediated
  by `libcanvas`.
- There is currently **no dynamic process spawning syscall** — see
  [Adding a new program](#adding-a-new-program-to-the-build) below for how
  a program actually gets onto a booted system today.

## Minimal example

```rust
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::println;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("hello from HuesOS userspace!");
    libcanvas::process::exit(0);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::process::exit(-1);
}
```

Two non-negotiable requirements for any HuesOS program:

1. A `#[panic_handler]` — there's no `std`, so you must supply one. Most
   programs should just call `libcanvas::process::exit(-1)` (optionally
   after printing something via `libcanvas::debug::write_str`, which is
   safe to call from a panic handler since it doesn't allocate).
2. Your `_start` must eventually call `libcanvas::process::exit(code)` —
   falling off the end of `_start` is impossible since it returns `!`, but
   make sure every code path actually reaches an `exit` call rather than
   looping forever unintentionally.

## What `libcanvas` gives you

| Module | Purpose |
|---|---|
| `libcanvas::vmo::Vmo` | Anonymous memory blocks: `create`, `read`, `write`. |
| `libcanvas::channel::Channel` | IPC: `pair()`, `write`, `read`/`read_into`. |
| `libcanvas::handle::Handle` | The RAII base every handle-owning type builds on. Closes itself on `Drop`. |
| `libcanvas::framebuffer::Canvas` | Off-screen drawing surface + `present()` to blit to the real screen. |
| `libcanvas::debug` / `println!`/`print!` | Write to the kernel's serial debug console (the only "stdout" today). |
| `libcanvas::process` | `exit(code)`, `yield_now()`. |
| `libcanvas::ErrorCode` | The error type every fallible call returns. |

Every fallible function returns `libcanvas::Result<T>` (`Result<T,
ErrorCode>`) — handle it with `?`, `match`, or at minimum acknowledge it
with `let _ =` if you genuinely don't care about failure in some spot (the
example program above only ignores results in the framebuffer test where
failing to draw isn't fatal to the program's purpose).

### Memory (VMOs)

```rust
use libcanvas::Vmo;

let vmo = Vmo::create(4096)?;         // zero-filled, at least 4096 bytes
vmo.write(0, b"hello")?;
let mut buf = [0u8; 5];
vmo.read(0, &mut buf)?;
assert_eq!(&buf, b"hello");
```

VMOs are the only memory-sharing primitive right now: there is no `mmap`
that maps a VMO directly into your address space (that's on the kernel's
roadmap). You interact with a VMO's contents by reading/writing byte
ranges through syscalls, the same way you'd `pread`/`pwrite` a file.

### IPC (Channels)

```rust
use libcanvas::Channel;

let (tx, rx) = Channel::pair()?;
tx.write(b"ping")?;
let (buf, n) = rx.read()?;
assert_eq!(&buf[..n], b"ping");
```

`Channel::read`/`read_into` are **non-blocking**: if no message is queued
yet, they return `Err(ErrorCode::ShouldWait)` immediately rather than
blocking the calling thread. There is no blocking wait primitive yet
(see the kernel's `Port` object in the roadmap) — if you need to wait for
a message, poll with `libcanvas::process::yield_now()` between attempts
for now.

### Graphics (the framebuffer)

You never get direct access to video memory. Instead:

1. Create a `Canvas` — an ordinary VMO-backed drawing surface matching the
   real framebuffer's pixel format.
2. Draw into it with `set_pixel`/`fill_rect`/`draw_text` (all pure
   userspace-side operations against your own VMO — no syscall per pixel).
3. Call `canvas.present()` to ask the kernel to blit your VMO's contents
   onto the real screen in one syscall.

```rust
use libcanvas::framebuffer::Canvas;

let canvas = Canvas::new_fullscreen()?;
canvas.fill_rect(0, 0, canvas.width(), canvas.height(), 20, 20, 40)?;
canvas.draw_text(16, 16, "Hello, HuesOS!", 255, 255, 255)?;
canvas.present()?;
```

`draw_text` only supports printable ASCII (0x20–0x7E) via a built-in 8x8
bitmap font — no Unicode shaping, no other scripts. Unsupported characters
render as a solid placeholder box rather than silently vanishing, so a bug
is visible instead of invisible.

If the system has no framebuffer (e.g. serial-only), `Canvas::new*`
returns `Err(ErrorCode::NoFramebuffer)` — always handle that case rather
than assuming a display exists.

### Console output

```rust
libcanvas::println!("value = {}", 42);
```

This writes to the kernel's serial debug console via the `DebugWrite`
syscall — there's no real terminal/stdout device yet, so this is what
you'll see in `make run`'s output.

## Building your program

Every userspace program needs:

1. `#![no_std]`, `#![no_main]`, a `_start` function, a `#[panic_handler]`.
2. Its own `Cargo.toml` depending on `libcanvas` by path, with `[workspace]`
   as an empty table (keeps it out of the main kernel workspace, which
   would otherwise conflict over target/profile settings — see
   `crates/huesos-userspace/init/Cargo.toml` for the exact shape).
3. A `.cargo/config.toml` pointing at the shared userspace target spec and
   linker script (copy `crates/huesos-userspace/init/.cargo/config.toml`
   verbatim if your program lives alongside `init/` at the same directory
   depth).

To build and check it compiles standalone:

```bash
cd crates/huesos-userspace/init   # or your own program's directory
cargo build --release
```

## Adding a new program to the build

There is currently **one** embedded userspace program: `huesos-init`,
built by `huesos-kernel`'s `build.rs` and baked into the kernel image via
`include_bytes!` (see that file's doc comment for exactly how). This is
intentional MVP scope — there's no dynamic process-spawning syscall yet
(no `ProcessSpawn`/`ProcessCreate`), so "the kernel embeds one binary and
runs it" is the whole story today.

To experiment with your own program, you have two options:

- **Easiest: edit `huesos-init` directly.** Its `_start` is exactly the
  kind of code you'd write for any other HuesOS program — replace its
  body with your own logic.
- **Cleaner: add a sibling crate and point `build.rs` at it.** Create
  `crates/huesos-userspace/your-program/` with the same shape as `init/`
  (`Cargo.toml`, `.cargo/config.toml`, `src/main.rs`), then edit
  `crates/huesos-kernel/build.rs` to build and `include_bytes!` your
  binary instead of (or in addition to — you'd need a second
  `include_bytes!` and a way to pick which one `spawn_init_process`
  loads) `huesos-init`'s.

Real multi-process support (a `ProcessSpawn` syscall, a way to load
arbitrary VMO-backed ELF images at runtime rather than only at kernel
build time) is tracked in `docs/ROADMAP.md`.

## Common mistakes (and what happens when you make them)

- **Forgetting `#![no_std]`/`#![no_main]` or a panic handler** — compile
  error, caught immediately.
- **A corrupted or hand-assembled ELF with an out-of-bounds `PT_LOAD`
  segment** — the kernel's ELF loader rejects this cleanly
  (`ElfLoadError::SegmentOutOfBounds`) rather than crashing; see
  `crates/huesos-elf`'s tests for exactly what's checked.
- **Requesting a VMO way bigger than available memory** — `Vmo::create`
  returns `Err(ErrorCode::NoMemory)`, it does not panic or crash the
  kernel (this used to be a real bug — see the git history for
  `huesos-object`'s `Vmo::new`).
- **Reading a `Channel` before anything's been sent** — returns
  `Err(ErrorCode::ShouldWait)` immediately; this is expected, not a bug.
- **Calling `Canvas::present()` with coordinates or a size beyond the real
  screen** — the kernel's blit clips to the real framebuffer bounds; you
  won't corrupt memory, you'll just not see the out-of-bounds part drawn.
