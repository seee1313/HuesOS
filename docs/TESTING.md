# Testing HuesOS

## Unit Tests (Host)

Crates with hardware-independent logic (`huesos-pmm`, `huesos-elf`) have
real unit tests that run on the host, not just in QEMU:

```bash
make test
```

This runs, e.g.:
- `huesos-pmm`: allocates/frees frames against a fake "physical memory"
  backing buffer, verifies out-of-memory behavior, verifies `reserve_range`.
- `huesos-elf`: parses malformed input (expects a clean error, not a panic),
  verifies alignment helpers, and — if `crates/huesos-userspace/init` has
  been built at least once — loads the *real* `huesos-init` ELF binary and
  checks its entry point and mapped pages.

Crates that are fundamentally tied to real hardware state (`huesos-arch`,
`huesos-kernel`, `huesos-object`'s VMO physical-frame paths) are exercised
live by booting in QEMU instead (see below) rather than mocked on the host.

## Integration Test: Full Boot (QEMU)

```bash
make run
```

Expected serial output (abbreviated), demonstrating the full pipeline
working end to end:

```
[HuesOS] Bootloader handed over control
HuesOS v0.1.0 up and running on CPU 0
PMM: NNNNN / NNNNN frames free (... MiB / ... MiB)
Framebuffer: WxH @ NN bpp (pitch N)
spawn_init_process: begin, elf size = 0x....
spawn_init_process: elf loaded, entry=0x400050 rsp=0x... cr3=0x...
spawn_init_process: task spawned, id=0x1
[kernel] entering userspace: rip=0x400050 rsp=0x... cs=0x23 ss=0x1b
[init] hello from ring3 userspace!
[init] VMO read/write round-trip OK
[init] channel IPC round-trip OK
[init] all checks complete, exiting cleanly
```

If you see `[init] VMO read/write round-trip FAILED` or `channel IPC
round-trip FAILED`, that's a real regression in the syscall/object-system
path, not a flaky test — investigate immediately.

If you see nothing at all after the framebuffer line, or a `[idt] ...
FAULT` message, the kernel crashed before or during the ring3 transition —
check recent changes to `huesos-arch::gdt`/`paging`/`syscall`/`context_switch`
or `huesos-kernel::process`/`scheduler` first, since that's the most fragile
part of the pipeline.

### GDB Debugging

```bash
make build && make iso
qemu-system-x86_64 \
    -machine q35 -cpu qemu64 -m 256M \
    -bios third_party/ovmf/OVMF.fd \
    -cdrom build/huesos.iso \
    -serial stdio -s -S

# In another terminal:
gdb target/x86_64-huesos/debug/huesos-boot
(gdb) target remote :1234
(gdb) break kmain
(gdb) continue
```

Note the kernel is loaded in the higher half (`0xffffffff80000000`+) by
Limine — symbols should resolve correctly against the debug build's ELF.

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
      # Note: no OVMF or Limine install/clone step needed — both are
      # vendored in third_party/, see docs/BUILD.md#vendored-dependencies.
      - run: make build
      - run: make test
      - run: make iso
      - name: Boot smoke test
        run: |
          timeout 20 make run | tee /tmp/huesos.log || true
          grep -q "channel IPC round-trip OK" /tmp/huesos.log
```

## Performance Notes

No formal benchmarking has been done yet (see roadmap). Rough
observations from manual QEMU runs:
- Boot to first userspace `syscall`: well under a second under QEMU/TCG.
- The scheduler ticks at 100 Hz (10ms quantum) via the PIT; this is
  intentionally conservative for debuggability, not tuned for throughput.
