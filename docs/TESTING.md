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
- `huesos-fat` / `huesos-alloc`: exercised via the Makefile host-test path
  (workspace `build-std` is temporarily bypassed — see `Makefile` `test`
  target).

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
[init] VMO read/write round-trip OK
[init] channel IPC round-trip OK
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
