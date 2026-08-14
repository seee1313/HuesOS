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
- Dynamic process launch is available through `libcanvas::process::spawn_elf`,
  backed by `ProcessCreate`, `VmarMap`, `ThreadCreate`, and `ThreadStart`.
  There is still no filesystem-backed program namespace: init embeds child
  ELF bytes at build time and launches them explicitly.

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
| `libcanvas::port::Port` | Queue for interrupt / user packets. |
| `libcanvas::handle::Handle` | The RAII base every handle-owning type builds on. Closes itself on `Drop`. |
| `libcanvas::framebuffer::Canvas` | Off-screen drawing surface + `present()` to blit to the real screen. |
| `libcanvas::waitset::{wait_any, wait_all}` | Multiplex a single block across several handles (Channel/Port/Process) with an optional tick timeout — use this instead of busy-polling. |
| `libcanvas::debug` / `println!`/`print!` | Write to the kernel's serial debug console (the only "stdout" today). |
| `libcanvas::process` | `exit(code)`, `yield_now()`. |
| `libcanvas::ErrorCode` | The error type every fallible call returns. |

### Multiplexed waits — the driver event loop

A driver that listens on both a control Channel and a device Port used to
`sys_yield` in a loop, burning CPU while both endpoints were quiet. The
`wait_any` / `wait_all` wrappers block once until any (or all) of the given
handles have their awaited signals active, with an optional
scheduler-tick timeout. Every handle must carry `rights::READ`; up to
`libcanvas::waitset::MAX_ITEMS` (16) handles per call.

```ignore
use libcanvas::{wait_any, Signals, WaitItem};

const CTRL_KEY: u64 = 0;
const PORT_KEY: u64 = 1;

let items = [
    WaitItem::new(ctrl.handle_value(), Signals::READABLE | Signals::PEER_CLOSED, CTRL_KEY),
    WaitItem::new(port.handle_value(), Signals::READABLE,                       PORT_KEY),
];

loop {
    let outcome = wait_any(&items, /* timeout_ticks */ 0)?;
    for result in outcome.satisfied() {
        match result.key {
            CTRL_KEY => { /* drain ctrl */ }
            PORT_KEY => { /* drain port */ }
            _ => {}
        }
    }
}
```

Every fallible function returns `libcanvas::Result<T>` (`Result<T,
ErrorCode>`) — handle it with `?`, `match`, or at minimum acknowledge it
with `let _ =` if you genuinely don't care about failure in some spot (the
example program above only ignores results in the framebuffer test where
failing to draw isn't fatal to the program's purpose).

### Pointer safety and transfer limits

`libcanvas` passes pointers to userspace buffers as part of the syscall ABI,
but the kernel never trusts or directly dereferences them. It validates the
complete lower-half address range and effective page-table permissions, then
copies through its audited user-memory layer. Invalid, unmapped, read-only
output, overflowing, and kernel-half ranges return `ErrorCode::InvalidArgs`
instead of faulting the kernel.

Calls are intentionally bounded: one VMO read/write transfers at most 1 MiB;
a Channel message carries at most 64 KiB and 64 handles; debug writes carry at
most 4 KiB. Split larger application transfers into multiple calls. See
[USER_MEMORY.md](USER_MEMORY.md) for the kernel-side contract.

An unhandled CPU exception in an application (for example dereferencing an
unmapped pointer or executing an invalid opcode) terminates the complete
process, not the kernel. A supervisor receives a stable negative status from
`Process::wait_exit`; see [FAULTS_AND_PANIC.md](FAULTS_AND_PANIC.md).

Canvas text defaults to `TextFont::Cozette6x13`; callers that require the
legacy TTY-style or original compact glyphs can use
`draw_text_with_font(..., TextFont::Tty8x16)` or
`draw_text_with_font(..., TextFont::Compact8x8)`. Software renderers can upload
packed frames with `Canvas::write_bytes` before a single `present_at`.

`libcanvas::system::monotonic_ticks()` returns the kernel's 100 Hz monotonic
clock. It is suitable for deadlines and animation pacing; do not calibrate
`RDTSC` for portable timing. `libcanvas::system::shutdown()` exists for init,
but ordinary applications receive `AccessDenied` and should request policy
through their supervisor.

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

Process launch code receives a root VMAR from `Process::create`. `Vmar::map`
installs fixed page-aligned VMO mappings inside that VMAR, and
`Vmar::create_child` can reserve nested VMAR ranges for loaders that want
separate address-space regions. `Vmar::unmap` / `Vmar::protect` accept covered
subranges and split mapping metadata transactionally; old exact-range callers
remain valid.

### IPC (Channels)

```rust
use libcanvas::Channel;

let (tx, rx) = Channel::pair()?;
tx.write(b"ping")?;
let (buf, n) = rx.read()?;
assert_eq!(&buf[..n], b"ping");
```

`Channel::read`/`read_into` are **non-blocking**: if no message is queued,
they return `Err(ErrorCode::ShouldWait)`. Use `read_into_blocking` to park the
current task until a message arrives, or `read_into_timeout` for a scheduler-
tick deadline. Ports likewise provide `read`, `read_blocking`, and
`read_timeout`; blocking waits do not require a userspace yield-spin loop.

The kernel stores small channel messages inline: payloads up to 64 bytes and up
to two transferred handles avoid per-message heap allocation in the queued
`ChannelMessage`. Larger messages keep the existing bounded heap-backed path and
the same ABI limits.

### Signals

`libcanvas::Signal` is a level-triggered waitable object. `set()` makes
`Signals::SIGNALED` active until `clear()`; `wait_any` / `wait_all` can wait on
its handle alongside Channels, Ports, and Processes.

```rust
use libcanvas::{Signal, Signals, WaitItem, wait_any};

let signal = Signal::create()?;
signal.set()?;
let items = [WaitItem::new(signal.handle().raw(), Signals::SIGNALED, 1)];
let ready = wait_any(&items, 0)?;
assert_eq!(ready.satisfied()[0].key, 1);
```

### Graphics (the framebuffer)

You never get direct access to video memory. Instead:

1. Create a `Canvas` — an ordinary VMO-backed drawing surface matching the
   real framebuffer's pixel format.
2. Draw into it with `set_pixel`/`fill_rect`/`draw_text` (all pure
   userspace-side operations against your own VMO — no syscall per pixel).
3. Call `canvas.present()` to ask the kernel to blit your VMO's contents
   onto the real screen in one syscall. Dirty renderers can instead use
   `upload_shadow_region` plus `present_region` to update only changed
   rectangles; full-width stripes upload through contiguous bounded VMO chunks.

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

The kernel still embeds only `huesos-init` directly. `huesos-kernel`'s
`build.rs` now also builds child userspace programs such as
`huesos-driver-manager` and `huesos-terminal`, then passes their ELF paths
into init at compile time. Init embeds those bytes and launches them with
`libcanvas::process::spawn_elf`.

To add a program today:

1. Create `crates/huesos-userspace/your-program/` with the same shape as
   `driver-manager/` or `terminal/`.
2. Teach `crates/huesos-kernel/build.rs` to build it and pass its binary
   path to init.
3. Add an `include_bytes!(env!("...") )` in init and call
   `libcanvas::process::spawn_elf`.

Filesystem-backed discovery/loading is still future work.

## Reporting boot progress from a service

Init draws a boot splash and advances a progress bar as services come
up. A service participates through the bootstrap channel it already
has — there is no progress syscall, and none is wanted: a syscall
would have to be capability-gated, and it would let any service move
the global bar. On the channel, a service can only influence its own
band.

Three messages are understood, all plain ASCII:

```text
<name>:ready              // done; the stage fills and turns green
<name>:degraded           // up, but with reduced function
<name>:progress:<0..100>  // optional, any number of times
```

`progress` is what keeps a long stage from looking hung. If your
service takes several seconds — enumerating a bus, mounting a volume —
send it as you go:

```rust
let bootstrap = libcanvas::channel::bootstrap();
let _ = bootstrap.write(b"storage:progress:40");
// ... more work ...
let _ = bootstrap.write(b"storage:ready");
```

Points worth knowing:

* **Progress is monotonic per stage.** A lower value than one already
  reported is ignored. A bar that goes backwards reads as a fault even
  when nothing is wrong.
* **`degraded` is not a failure.** Use it when the service is usable
  but something is missing — DriverManager sends it when it comes up
  without a keyboard. The boot continues, the summary says `degraded`
  rather than `all ok`, and no red banner appears.
* **Silence is not free.** Every stage has a wall-clock deadline from
  `/etc/init.conf`. Miss it and the stage is marked failed, the
  indicator turns red, and init prints which stage did not answer. The
  boot then continues to the next stage.
* **A stage can have two reporters.** `storage` is the live example:
  init owns 0-25% (it hands the boot VMO and the PCI grants to
  DriverManager and steps the bar itself), then DriverManager takes
  over from 35% with milestones tied to observable events — NVMe host
  starting (35), Stage-A resources registered (45), namespace
  identified (60), Hxfs mounted (100). Because both write into the
  same monotonic high-water mark, the split needs no coordination
  beyond not overlapping the ranges. Tie milestones to events, never
  to elapsed time: a percentage that advances on a timer is a
  progress-shaped animation, not progress.
* **Report from the poll loop, not from the work.** DriverManager
  records the milestone where the event happens and flushes it once
  per iteration of its main loop, so a blocked or full channel can
  never stall the bring-up path. Write errors are dropped on purpose:
  the bar is cosmetic, the boot is not.
* **If the peer will never exist, settle the stage.** When init finds
  no NVMe function it marks `storage` skipped immediately instead of
  letting the stage sit until its deadline expires — a diskless or
  serial-only boot should not pay 30 seconds for a device that was
  never there.
* **Your stage must exist in the config** for any of this to show up.
  Stages are data, not code: adding `stage.mything=20` to
  `/etc/init.conf` is enough for init to give your service a band, a
  label, and a deadline without touching init's source.

Full configuration reference: `docs/design/INIT_BOOT_UX.md`.

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
- **Draining a channel "until `ShouldWait`" in a shared service loop** —
  this is the fairness bug that is hardest to recognise from the
  symptom. DriverManager and hxfs-service are single-threaded and
  cooperative: one pass serves every host, client, file, dir and blob.
  A drain loop is only bounded if the peer eventually goes quiet, and
  under load (the high queue-depth NVMe soak, for one) it does not —
  so `poll_*` never returns and everything scheduled after it in the
  same pass is starved for the life of the run. It does not look like
  a fairness bug; it looks like some unrelated service hanging.
  Give each `poll_*` a per-tick budget:

  ```rust
  let mut budget = POLL_BUDGET_PER_TICK;
  loop {
      budget = match budget.checked_sub(1) {
          Some(remaining) => remaining,
          None => return, // resume on the next tick
      };
      // ... read_into / handle ...
  }
  ```

  Watch the early-exit path: if the function took ownership of state
  (`Option::take`, `core::mem::replace` on a buffer), it must put it
  back before returning, so leave via `break` rather than `return`
  where a tail restores it. `tools/check-poll-budgets.py` enforces
  the rule in CI.

  A `while let Some(x) = <slot>` loop is the same hazard wearing a
  different hat: the condition tests a service slot that stays
  occupied for the whole connection, so it ends only when the peer
  goes quiet — which is the thing you cannot assume. Budget it too.
- **Blocking "until the handle arrives" with no time limit** — a
  one-shot handshake such as `mount_from_bootstrap` is allowed to
  block; it has nothing to serve yet. What it must not do is block
  *forever*: a peer that connects and then dies, or a device that
  never enumerates, would park the service in `yield_now()` for the
  life of the machine with no message and no exit. Arm a deadline
  against `libcanvas::system::monotonic_ticks()` (100 Hz), report
  what did not arrive, and give up:

  ```rust
  let mut deadline: Option<u64> = None;
  // ... in the ShouldWait arm:
  match libcanvas::system::monotonic_ticks() {
      Ok(now) => match deadline {
          Some(limit) if now >= limit => return None, // say why first
          Some(_) => {}
          None => deadline = Some(now.saturating_add(BUDGET_TICKS)),
      },
      Err(_) => {} // no clock: wait rather than fail a healthy mount
  }
  ```

  A retry *count* is the wrong unit for this: the loop yields, so it
  spins as fast as the scheduler allows and a fixed iteration count
  expires in milliseconds while the device is legitimately still
  coming up. Use wall time.
