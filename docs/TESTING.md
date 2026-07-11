# Testing HuesOS

## Unit Tests (Host)

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

Crates tied to real hardware (`huesos-arch`, SMP, full process/scheduler)
are validated by QEMU boots rather than host mocks.

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
    -machine q35 -cpu qemu64 -smp 2 -m 256M \
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

## CI Workflow (suggested)

```yaml
name: Test
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: rustup toolchain install nightly --component rust-src,llvm-tools-preview
      - run: sudo apt-get update && sudo apt-get install -y qemu-system-x86 xorriso mtools
      # OVMF + Limine are vendored in third_party/
      - run: make build
      - run: make test
      - run: make iso
      - name: Boot smoke test (2 CPUs)
        run: |
          timeout 45 qemu-system-x86_64 \
            -machine q35 -cpu qemu64 -smp 2 -m 256M \
            -bios third_party/ovmf/OVMF.fd \
            -cdrom build/huesos.iso \
            -net none -serial stdio -display none \
            -no-reboot -no-shutdown 2>/tmp/huesos.log || true
          grep -q "channel IPC round-trip OK" /tmp/huesos.log
          grep -q "APs ready=1" /tmp/huesos.log || grep -q "MADT parsed 1" /tmp/huesos.log
```

## Performance Notes

No formal benchmarking yet. Rough QEMU/TCG observations:

- Boot to first userspace syscall: under a second on typical hosts.
- Scheduler tick ~100 Hz via calibrated LAPIC timer (Div16).
- Under TCG, long MMIO spin loops (e.g. unbounded ICR DS wait) can look
  like hangs — keep delivery-status polls capped.
