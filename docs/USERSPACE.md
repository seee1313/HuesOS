# Writing Userspace Programs for HuesOS

This guide explains how Ring-3 programs are structured on HuesOS and which SDK
layer to choose. For shell/CLI details see [SHELL_AND_STD.md](SHELL_AND_STD.md);
for dynamic ELF (`/lib/ld-huesos.so`) and native Win64 PE32+ (`/lib/ld-pe.so`)
execution see [EXECUTABLE_LOADERS.md](EXECUTABLE_LOADERS.md).

---

## 1. The golden rule: never issue `syscall` yourself

Application and driver crates must contain **zero** raw `asm!("syscall", ...)`
instructions. All kernel crossings go through [`libcanvas`](../crates/huesos-userspace/libcanvas)
(`libcanvas::raw` is the sole audited Ring-3 syscall site for native HuesOS
binaries, while `/lib/ld-pe.so` bridges Win64 DLLs through `libcanvas`).

Going through `libcanvas` (or `huesos-std` on top of it) guarantees:

- exact register/clobber (`rcx`/`r11`) ABI compliance and shared `huesos-abi`
  syscall/error discriminants;
- RAII handle ownership (`Handle` closes itself on `Drop`);
- zero drift when kernel capability checks or wire records evolve.

---

## 2. Choosing the right layer: `huesos-std` vs `libcanvas`

HuesOS provides two Ring-3 Rust layers depending on what you are building:

| Target | Recommended crate | Heap / runtime | Typical examples |
|---|---|---|---|
| CLI utilities, TUI apps, file/network tools (`/bin/*.elf`) | [`huesos-std`](../crates/huesos-userspace/huesos-std) | `ScudoHeap` + `huesos_std::entry!` + streaming `auxv` stdio/VFS/net handles | `coreutils` (`ls`, `grep`, `tar`, `curl`, `pci`, `btop`), `fdisk` |
| Bootstrap supervisors, DriverHosts, low-level daemons (`/services/*.elf`, `/drivers/*.elf`) | [`libcanvas`](../crates/huesos-userspace/libcanvas) directly (optionally no-`alloc`) | Explicit `_start`, raw `Channel`/`Port`/`WaitSet`/`Vmo`/`Vmar`/`Resource`/`DeviceLease` | `init`, `driver-manager`, `pci-manager`, `acpi-manager`, `driver-host-nvme` |

---

## 3. Writing a `/bin` program with `huesos-std`

`huesos-std` gives `/bin` programs ergonomic `io`, `fs`, `net`, `path`, `env`,
`process`, `thread`, `sync` (futex `Mutex`/`Condvar`/`Once`), `time`, and `tui`
modules without POSIX ambient authority — every operation uses the capability
handles passed to the process in `huesos_abi::auxv` (respecting `hsh` `@caps`
attenuation):

```rust
#![no_std]
#![no_main]

use huesos_std::{env, fs, prelude::*};

huesos_std::entry!(run);

fn run() -> i32 {
    let args = env::args();
    println!("argc = {}", args.len());
    if let Err(err) = fs::write("/tmp/hello.txt", b"hello from huesos-std\n") {
        eprintln!("write failed: {err}");
        return 1;
    }
    0
}
```

`println!` and `eprintln!` stream over the process's `AT_HUESOS_STDOUT` /
`AT_HUESOS_STDERR` `Channel` handles (connected to `terminal` or an `hsh`
pipeline stage), rather than writing directly to the kernel debug UART.

---

## 4. Writing a low-level service or DriverHost with `libcanvas`

Services that do not use `huesos-std` are freestanding `#![no_std]`, `#![no_main]`
ELF64 binaries supplying `_start` and a `#[panic_handler]`:

```rust
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libcanvas::debug;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    debug::write_str("[my-service] started\n");
    libcanvas::process::exit(0);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libcanvas::process::exit(-1);
}
```

### Core `libcanvas` modules

| Module | Purpose |
|---|---|
| `libcanvas::handle::Handle` | RAII capability handle wrapper (`Drop` invokes `HandleClose`) |
| `libcanvas::vmo::Vmo` | Page-backed memory objects (`create`, `read`, `write`, `set_size`) |
| `libcanvas::process::{Process, Thread, Vmar, launcher}` | Child process creation, static/dynamic ELF & PE32+ launch, nested `Vmar` map/unmap/protect, `ProcessTerminate`, 256-CPU affinity |
| `libcanvas::channel::Channel` | Bidirectional message + handle-transfer IPC (`pair`, non-blocking `read_into`, `read_into_blocking`, `read_into_timeout`) |
| `libcanvas::port::Port` | Packet queue for IRQs, exit notifications, quota events, and `PORT_PACKET_DEVICE_GONE` |
| `libcanvas::signal::Signal` | Level-triggered waitable user signals (`set`, `clear`) |
| `libcanvas::waitset::{wait_any, wait_all}` | Multiplexed blocking wait over up to 48 handles (`Channel`, `Port`, `Process`, `Signal`) with tick timeout |
| `libcanvas::resource` & `pci` | `Resource` (`IoPort`, `Mmio`, `Irq`, `DmaPool`, `PciConfigMint`) and `DeviceLease` wrappers |
| `libcanvas::framebuffer::Canvas` | VMO-backed drawing surface (`TextFont::Cozette6x13` default, `Tty8x16`, `Compact8x8`, dirty-region `upload_shadow_region` + `present_region`) |
| `libcanvas::system` | `monotonic_ticks()` (100 Hz), `monotonic_ns()`, `sched_stats()`, `task_query()`, `set_sched_policy()`, `shutdown()` (`init` only) |

### Multiplexed driver event loops

DriverHosts and single-threaded services use `wait_any` instead of yield-spin
loops, and enforce per-tick receive budgets (`tools/check-poll-budgets.py`) so a
chatty peer cannot starve sibling channels:

```ignore
use libcanvas::{wait_any, Signals, WaitItem};

let items = [
    WaitItem::new(ctrl.handle_value(), Signals::READABLE | Signals::PEER_CLOSED, 0),
    WaitItem::new(port.handle_value(), Signals::READABLE, 1),
];
let outcome = wait_any(&items, /* timeout_ticks */ 0)?;
for ready in outcome.satisfied() {
    // Drain up to a fixed message budget per tick.
    let _ = ready.key;
}
```

---

## 5. Transfer limits, VMAR mappings, and fault isolation

- **Audited user-copy caps:** `VmoRead`/`VmoWrite` transfer at most 1 MiB per
  call; `Channel` messages carry at most 64 KiB and 64 handles (messages ≤64 B
  and ≤2 handles use an inline kernel fast path); `DebugWrite` is capped at
  4 KiB. Invalid, unmapped, overflowing, or kernel-half pointers return
  `ErrorCode::InvalidArgs` ([USER_MEMORY.md](USER_MEMORY.md)).
- **Direct VMAR mapping:** processes holding their own `Vmar` handle can map,
  split-unmap, and `VmarProtect` page-aligned VMOs with strict W^X enforcement
  ([VMAR_TRANSACTIONS.md](VMAR_TRANSACTIONS.md)).
- **Fault containment:** an unhandled Ring-3 exception (`#PF`, `#GP`, `#UD`,
  `#DE`, `#AC`) terminates the faulting process cleanly and reports a negative
  exit code to `ProcessWait` / bound exit ports without panicking the kernel
  ([FAULTS_AND_PANIC.md](FAULTS_AND_PANIC.md)).
