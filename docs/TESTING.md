# Testing HuesOS

## Unit Tests (Host)

The policy-crate gate is independent of Cargo and checks that every policy
crate is a workspace member, forbids unsafe Rust, has host tests, and has a
current design document:

```bash
make policy-check
```

Crates with hardware-independent logic have host unit tests:

```bash
make test
```

This runs, e.g.:

- `huesos-pmm`: allocate/free frames against a fake physical backing buffer,
  OOM behavior, `reserve_range`.
- `huesos-elf`: malformed input, alignment helpers, optional real init ELF.
- `huesos-object`: VMO R/W, OOM without panic, handle tables, channel peer
  delivery regression.
- `huesos-fat` / `huesos-alloc`: exercised in the same pinned-toolchain host
  command. The custom kernel target is overridden explicitly and workspace
  `build-std` is disabled for that invocation; the repository Cargo config is
  never renamed or mutated.
- `huesos-syscalls::user_memory`: address-boundary arithmetic tests cover the
  null guard, kernel half, overflow, upper-bound crossing, and a legal range
  crossing a 4 KiB boundary. Page-table permission tests require QEMU because
  they inspect the active CR3.
- `huesos-object`: bounded Channel/Port queue admission, batch handle-move
  validation, and quota exhaustion are host-tested; the kernel scheduler also
  carries a pending-wake handshake for SMP enqueue-to-park races.
- `huesos-hxfs`: checkpoint geometry is checked against the actual target and
  journal LBA spans. Plain and Hxblob-enabled regressions simulate power loss
  after the `RECOVERING` root is durable but before the final clean root,
  replay the journal, remount, and verify payload bytes. The Hxblob case uses a
  multi-leaf index so its two extra journal records and leaf geometry cannot be
  omitted by a clean-path-only test.
- The host-testable **policy crates** (`huesos-lifecycle`, `huesos-ioapic`,
  `huesos-extable`, `huesos-waitset`, `huesos-proclife`, `huesos-handlemove`)
  are pure decision/encoding models with focused host suites: lifecycle
  reaping + collection accounting, redirection-entry round-trip + MADT source
  override parsing + vector allocation + GSI routing, fixup-table lookup,
  multi-object wait dispatch (Any/All/cancel/timeout), the process lifecycle
  state machine, and all-or-nothing transactional handle transfer.
  `huesos-decoder-fuzz` is a randomized ACPI-decoder harness.

Crates tied to real hardware (`huesos-arch`, SMP, full process/scheduler)
are validated by QEMU boots rather than host mocks.

## Static gates (`make audit-check`)

Seven dependency-free checks run before every PR and in CI. They exist
because each one encodes a rule that a reviewer had already failed to
enforce by reading:

```bash
make audit-check     # all seven
make fmt-check       # the last one on its own
```

| Gate | Rule it enforces |
|------|------------------|
| `check-safety-budget.py` | `unsafe` count per crate may not exceed the pinned budget in `safety-budget.json`; raising it is a deliberate, reviewed act |
| `check-lock-policy.py` | kernel, arch and uACPI use ranked locks, so lock order stays checkable |
| `check-policy-crates.py` | every policy crate is a workspace member, forbids `unsafe`, has host tests and a current design doc |
| `check-hues-async-noalloc.py` | `crates/hues-async/**` never allocates — no `alloc`, no heap collection, tests included |
| `check-huesos-object-lock-policy.py` | no bare `spin::Mutex` outside `irq_guard.rs` |
| `check-poll-budgets.py` | every channel-draining loop in a shared service is bounded (see below) |
| `fmt-all.py --check` | formatting across the kernel workspace **and** the 11 standalone userspace crates, which plain `cargo fmt --all` does not reach |

### The poll-budget gate

DriverManager owns the boot main loop; hxfs-service owns the filesystem
service loop. Both are single-threaded and cooperative, so one pass
serves every host, client, file, dir and blob view. A loop that drains
a channel "until `ShouldWait`" is only bounded if the peer eventually
goes quiet — and under the high queue-depth NVMe soak it does not. The
result is not recognisable as a fairness bug: it looks like some
unrelated service hanging.

The gate requires one of two shapes, read from **code with comments
stripped** (an early version accepted a comment mentioning a budget,
which made it worthless):

- steady-state `poll_*`: a `POLL_BUDGET_PER_TICK` counter, then return;
- one-shot handshake (`mount_from_bootstrap`): a wall-clock deadline
  against `monotonic_ticks()`, reporting what never arrived.

`while let Some(x) = <slot>` counts as unbounded here — the slot stays
occupied for the whole connection, so the loop ends only when the peer
stops talking, which is the assumption being forbidden.

When changing this gate, verify it still **fails**: reintroduce an
unbounded drain, confirm it is caught by name, then revert. A gate that
cannot fail is worse than no gate, because it is trusted.

## Integration Test: Full Boot (QEMU)

```bash
make run          # default scripts/run.sh uses -smp 2
```

### Expected serial (abbreviated, multi-core)

```text
[HuesOS] Bootloader handed over control
[PMM] Reserved HBI image: phys_addr=0x..., length=...
[SMP] MADT parsed 2 CPUs found
[SMP] LAPIC timer count=...
[SMP] Booting AP 1
[SMP] AP 1 online (waiting for release)
[SMP] AP 1 ready
[SMP] bringup done, APs ready=1
HBI v2.1 parsed. Entries: 0x4
[SMP] APs released to run
[SMP] AP 1 scheduling
HuesOS v0.1.0 on CPU 0
PMM: ... frames (... MiB)
[init] hello from ring3 userspace, via libcanvas
[init] user pointer guard smoke OK
[init] VMO read/write round-trip OK
[init] channel IPC round-trip OK
[fault-probe] triggering page
[user-fault] process=fault-probe ... reason=PAGE FAULT ... code=-4097
[fault-probe] triggering opcode
[fault-probe] triggering gpf
[fault-probe] triggering divide
[init] user fault isolation OK (#PF/#UD/#GP/#DE contained)
[init] launched driver-manager
...
[terminal] started in userspace
[init] terminal says terminal:ready
[init] service launch complete; parking as init supervisor
```

Single-core (`-smp 1`) still works: MADT reports 1 CPU, no AP boot lines,
same userspace pipeline.

### Failure signals

| Symptom | Likely area |
|---------|-------------|
| `PAGE FAULT` right after PMM/HBI reserve | HHDM mapping (ACPI/RSDP) or paging |
| `PAGE FAULT` at `0xfee00xxx` | LAPIC not mapped / not UC |
| AP never `ready` / TIMEOUT | trampoline stack, identity map, INIT-SIPI |
| `INVALID OPCODE` in userspace under `-smp 2` | syscall MSRs not programmed on AP |
| Triple fault after AP start | IDTR zero, stack=0 in trampoline, missing NXE |
| VMO/channel FAILED | object/syscall regression |
| Bad user pointer causes kernel `PAGE FAULT` | syscall bypassed `user_memory` validation/copy layer |

### Adversarial user-pointer matrix

The feature-gated `libcanvas::diagnostics` probe runs automatically in init and
currently verifies three hardware-backed cases on every QEMU boot: a kernel-
half input, an unmapped low-userspace output, and a mapped read-only text page
used as an output. Success is reported as `user pointer guard smoke OK`; because
execution continues, the probe also proves these cases return `InvalidArgs`
rather than raising a fatal kernel page fault.

The complete regression matrix to retain and expand is:

- address zero and the low 64 KiB guard;
- the last valid byte and a range crossing `USER_ASPACE_END`;
- arithmetic overflow in `address + length`;
- an unmapped userspace page;
- a supervisor-only/kernel higher-half page;
- a readable but non-writable page used as an output;
- a valid range crossing two pages with different permissions;
- a valid unaligned ABI structure;
- a zero-length optional buffer;
- transfer lengths immediately below, at, and above each documented limit.

All invalid cases must return `InvalidArgs` without a kernel exception or
consuming a queued message/event. See [USER_MEMORY.md](USER_MEMORY.md).

## ProcessWait lifecycle regression

Before the fault-isolation probes, init launches `fault-probe` with the `wait`
command and calls the blocking `ProcessWait` wrapper. The child yields 32 times
before exiting with code zero, giving init an opportunity to park. A successful
boot must contain:

```text
[init] ProcessWait lifecycle OK (blocked wake)
```

This covers the scheduler-visible lifecycle path: waiter registration, park,
exit publication, wake, and exit-code delivery. `scripts/ci-qemu-smoke.sh`
requires this marker for debug/release and SMP 1/2 matrix boots. It does not
prove an arbitrary-duration SMP soak; that remains a separate lifecycle stress
requirement.

## Monotonic Clock, Snake, and Shutdown Tests

Init verifies that a 10-tick blocking wait measures 9–12 hardware monotonic
ticks. This catches time accidentally advancing on `yield` or once per CPU.
Expected output:

```text
[init] monotonic clock OK (10-tick wait measured 10 ticks)
```

The Snake visual test injects `snake` through QEMU's PS/2 keyboard and captures
two PPM frames 500 ms apart. It checks a fullscreen board, cyan border, visible
head, movement between frames, and substantial framebuffer change.

Init first verifies that an unprivileged child receives `AccessDenied`. The
shutdown test then injects `shutdown` and Enter. It checks terminal → init IPC,
privileged syscall authorization, PS/2 quiescing, SMP halt messages, absence of
Kernel Panic, and the final dark/cyan/white framebuffer. See
[SHUTDOWN.md](SHUTDOWN.md) and [SNAKE.md](SNAKE.md).

## TTY Font and Doom Tests

The terminal boot screen must show `Type 'help' to list available commands.` in
the default 8×16 TTY mode. `font compact` switches to the original 8×8 glyphs
without changing cursor/scrollback state.

The Doom release test boots QEMU with 512 MiB, injects `doom`, waits for
DoomGeneric/Freedoom initialization, presses Enter and movement/fire/use keys,
and captures title/game PPM frames. Assertions:

- serial contains Doom startup, WAD initialization and `I_InitGraphics`;
- no `user-fault process=doom` and no kernel panic;
- captured frame contains more than 100 colors and Doom pixels cover the full
  framebuffer rather than only a centered 640×400 rectangle;
- title and gameplay captures differ substantially;
- terminal does not consume the transferred keyboard Channel.

The recorded release soak produced 156, 164, and 149 colors in title/game/late
frames, with more than 500,000 changed bytes between gameplay captures. The
font switch integration produced 9,615 changed framebuffer bytes between TTY
and compact modes.

See [DOOM.md](DOOM.md) and [TTY_FONT.md](TTY_FONT.md).

The post-game repaint regression launches Doom, exits with Q, captures Terminal
after two seconds, and requires its small text palette with no panic. Buffered
render validation measured 6–8 ticks under QEMU TCG. See
[TERMINAL_RENDERING.md](TERMINAL_RENDERING.md).

## Recoverable-copy smoke test

To exercise the actual linker exception table and ring-0 page-fault fixup,
build an HBI command-line module containing `extable_test=1`. The kernel then
calls its bounded assembly copy primitive against an intentionally unmapped
user address. It must return through the fixup path and print:

```text
[extable] recoverable copy smoke OK
```

A missing or malformed extable must not be treated as a successful test; the
kernel stops in the test image before launching userspace.

## Storage soak and fault injection

`scripts/ci-qemu-nvme-soak.sh <profile> <seconds> <log> <mode>` boots the
system against a real QEMU NVMe controller with an Hxfs v5 image. The
mode selects what is seeded and which markers are required:

| Mode | What it proves |
|------|----------------|
| `0` | Base boot: production build, blank volume, no `synthetic-key`. Has **no** boot self-check, so the page-cache gate does not apply to it |
| `1` | Encrypted volume with a flipped GCM tag → `bad-gcm-tag-marked`, service keeps serving |
| `2` | Plain volume with a corrupted payload CRC → `bad-checksum-marked` |
| `3` | Graceful shutdown cycle through to `all CPUs halted` |
| `4` | Stress: repeated 16 MiB write/read cycles |
| `5` | High queue-depth: multi-queue controller, asserts queue count and clean reliability counters |
| `6` | **No TPM**: plain volume, `SOAK_TPM=0`, no key handed to the guest |

Mode 6 asserts the *ordinary* markers — self-check, write path, scrub,
fsck, object store. "Works without a TPM" has to mean the same
filesystem, not a reduced one. It also fails if a volume key appears
from anywhere, since that would pass the gate for the wrong reason.
Most real hardware has no TPM, so a build that only mounts when a key
exists would refuse to boot on it.

The image is reused between runs only when `<img>.mode` matches the
requested mode. After changing seeding logic, delete both:

```bash
rm -f build/nvme-soak.img build/nvme-soak.img.mode
```

### Power-fail (crash consistency)

```bash
bash scripts/ci-qemu-powerfail.sh <profile> <log-dir> <cycles>
```

Every other QEMU job shuts the guest down politely or kills an idle
one. This one cuts power the way a real machine loses it — SIGKILL
mid-write, dirty cache, open transaction, NVMe commands in flight —
then requires the same image to boot again unattended:

1. **crash** — kill some seconds after the write path is confirmed live;
2. **offline** — inspect the dirty image from the host; no readable
   superblock or checkpoint at all is a format bug, not a recovery case;
3. **recover** — boot the same image: `self-check ok`, `fsck clean`,
   `scrub complete`, no panic.

"It booted" is not the pass condition. An fsck finding after a power
cut means the committed state was not crash-consistent.

The kill instant is randomised per cycle so successive cycles sample
different interleavings rather than re-proving one. Delays are a
shuffle of the range, not independent draws — independent draws
collide, and a repeated instant buys nothing. The seed is printed on
every run and every failure prints the seed and delay:

```bash
POWERFAIL_SEED=<seed> bash scripts/ci-qemu-powerfail.sh debug build 2
```

Reproducing a failure exactly is the difference between a bug and
"CI was flaky once".

## Kernel Panic Screen Test

Normal images never panic intentionally. To exercise the fatal path, build an
HBI whose command-line module contains `panic_test=1`, boot it with QEMU, and
capture serial plus a monitor `screendump`. The assertions are:

- serial contains `HuesOS KERNEL PANIC`, the intentional panic message, CPU,
  CR3, `Stopped peer CPUs: 1` under `-smp 2`, and
  `system halted; no automatic reboot`;
- no userspace process starts;
- QEMU remains running until the external test timeout/quit;
- the captured framebuffer is predominantly RGB `(150, 0, 0)` and contains
  white text pixels.

The exact safety model and expected output are documented in
[FAULTS_AND_PANIC.md](FAULTS_AND_PANIC.md).

## Real Hardware Smoke Tests

See [HARDWARE.md](HARDWARE.md). First recorded laptop success: MSI Modern 15
B5M (AMD Ryzen 5 5625U).

### GDB Debugging

```bash
make build && make iso
qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -smp 2 -m 512M \
    -bios third_party/ovmf/OVMF.fd \
    -cdrom build/huesos.iso \
    -serial stdio -s -S

# In another terminal:
gdb target/x86_64-huesos/debug/huesos-boot
(gdb) target remote :1234
(gdb) break kmain
(gdb) continue
```

Kernel is higher-half (`0xffffffff80000000`+). For AP issues, QEMU
`-d int,cpu_reset -D qemu.log` is invaluable (triple-fault dumps show ESP,
CR3, EFER).

## CI Workflow

CI is `.github/workflows/hardening.yml` (plus `sanitizers.yml` for the
address-sanitizer run). It is the source of truth; this list is a map,
not a spec:

| Job | What it runs |
|-----|--------------|
| `static-safety` | `make audit-check`, Clippy, the ordinary host suite, and `make test-hxfs-features` for the combined encryption + compression + Hxblob storage build |
| `qemu-boot` | boot smoke, 1 and 2 CPUs |
| `qemu-nvme-boot` | base NVMe soak, mode 0 |
| `qemu-nvme-gcm-inject` | mode 1 |
| `qemu-nvme-crc-inject` | mode 2 |
| `qemu-nvme-no-tpm` | mode 6, debug **and** release |
| `qemu-nvme-powerfail` | crash/recovery cycles, debug **and** release |
| `qemu-nvme-shutdown-cycle` | mode 3 |
| `qemu-nvme-stress` | mode 4 |
| `qemu-nvme-long-soak` | one bounded pass of `scripts/soak-long.sh` (~2 h) |
| `qemu-extable-smoke` | recoverable-copy fixup path |

`swtpm` and `swtpm-tools` are installed in every QEMU job, so the
TPM-backed key path is exercised rather than silently skipped. Mode 6
still runs without a TPM by configuration (`SOAK_TPM=0`), which is the
point: it must prove the guest ignores an available TPM deliberately,
not that the runner happened to lack one.

The full 24 h soak of Stage E.3 is **not** a CI job — GitHub caps jobs
at 6 h. It is an operator-triggered local gate via
`scripts/soak-long.sh`.

### Before opening a PR

```bash
python3 tools/fmt-all.py --check
CARGO_BUILD_JOBS=1 make clippy      # -D warnings
CARGO_BUILD_JOBS=1 make test
make audit-check
git diff --check
```

Note `CARGO_BUILD_JOBS=1`: a parallel kernel build needs more RAM than
a small machine has, and the OOM kill surfaces as an unrelated-looking
failure. Also note that a userspace-binary compile error is reported by
Cargo as `failed to run custom build command for huesos-kernel` — the
real error is further down the log, so capture it to a file and search
for `^error`.

## Performance Notes

No formal benchmarking yet. Rough QEMU/TCG observations:

- Boot to first userspace syscall: under a second on typical hosts.
- Scheduler tick ~100 Hz via calibrated LAPIC timer (Div16).
- Under TCG, long MMIO spin loops (e.g. unbounded ICR DS wait) can look
  like hangs — keep delivery-status polls capped.
