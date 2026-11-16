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
- `huesos-abi::pci_manager`: fixed hello/ready/heartbeat messages reject short,
  unknown, and zero-generation inputs. QEMU smoke requires both the isolated
  service's no-root fail-closed marker and DriverManager's matching supervised
  readiness marker.
- `huesos-abi::hmcf`: the validated config-window snapshot (`HMCF`, AP-7).
  Seventeen host tests cover multiple segments and non-zero start buses,
  adjacent windows, the encode-time overlap rejection, empty/oversized record
  sets (0 and 65+ windows), the 64-record maximum round-trip, canonical
  ordering on encode and its requirement on the wire, duplicate ordering
  keys, reserved fields and flags, count/size agreement, wrapping byte-sum
  checksum provenance (including the checksum field), physical-span
  overflow, binding to the firmware snapshot and producer generation
  (`StaleGeneration`/`SnapshotMismatch`), deterministic encoding, and the
  declared-size two-phase read helper. The MCFG decoder's own coverage
  (multiple allocations, non-zero start bus, overlap rejection, checksum)
  remains in `huesos-pci`.
- `huesos-uacpi-runtime`: AP-3 compiles the full pinned interpreter in a
  separate userspace crate; AP-4 activates only process-local allocation,
  time, mutex, event, and dispatch callbacks. From a temporary directory (so
  the bare-metal Cargo config is not selected), run
  `cargo test --manifest-path <repo>/crates/huesos-userspace/uacpi-runtime/Cargo.toml`
  for the primitive plus archive-translation tests (twenty-two: timeout trio
  zero/finite/infinite, recursion rejection, event signal-before-wait,
  multiple-signal, reset, saturation, teardown and slot-reuse races,
  monotonicity/overflow, allocation-failure points, registry exhaustion,
  dispatch nesting, synthetic RSDP→XSDT→FADT/DSDT/FACS translation graph,
  unaligned and full-table boundaries, page-boundary-in-record, adjacent-record
  and gap rejection, and a deterministic 2000-iteration translator fuzz). The
  suites are serialized because the callbacks and fixtures share process-global
  registries. Run `bash scripts/test-uacpi-runtime.sh` to link every callback
  and execute the remaining privileged-denial smoke under
  ASan/UBSan. Decoder-side ASan coverage for the v2 wire format runs through
  `cargo test -p huesos-decoder-fuzz` (wired into the sanitizer CI job). This
  does not claim namespace/AML readiness.
- `huesos-hxfs`: checkpoint geometry is checked against the actual target and
  journal LBA spans. Plain and Hxblob-enabled regressions simulate power loss
  after the `RECOVERING` root is durable but before the final clean root,
  replay the journal, remount, and verify payload bytes. The Hxblob case uses a
  multi-leaf index so its two extra journal records and leaf geometry cannot be
  omitted by a clean-path-only test. The root publication trace must be exactly
  `RECOVERING -> CLEAN`, and an exhaustive host matrix fails before every
  checkpoint write/flush operation, then requires a complete old or complete
  new filesystem state after replay — never mixed metadata.
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

## Syscall transaction failure regressions

`make test` exercises invalid output ranges and excessive sizes through actual
syscall dispatch where rejection precedes CR3/current-process access. It also
injects commit failures into real handle-table helpers and tests closed-peer,
queue-full and undersized-receive IPC paths. The object suite uses its existing
serialized PMM fixture to require exact frame reclamation after VMO publication
failure and exact preservation of free frames after VMO allocation OOM.
No test replaces active page-table permissions with a host mock. Invalid pointer
ranges are limited to ABI-bound rejection; fault recovery still needs QEMU.


## Static gates (`make audit-check`)

Eight repository checks run before every PR and in CI. They exist because
each one encodes a rule that a reviewer had already failed to enforce by
reading:

```bash
make audit-check     # all eight
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
| `check-doc-links.py` | every relative Markdown link in the README and `docs/` resolves to an existing workspace path |
| `fmt-all.py --check` | formatting across the kernel workspace **and every standalone userspace crate**, which plain `cargo fmt --all` does not reach |

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

AP-6 adds two generation/restart gates:

```bash
bash scripts/ci-qemu-acpi-restart-smoke.sh release 2 120 restart
bash scripts/ci-qemu-acpi-restart-smoke.sh release 2 120 budget
```

`restart` (the default, also handled by plain `bash scripts/ci-qemu-acpi-restart-smoke.sh release 2 120`) boots an injected crash cascade: generation one exits before readiness (crash-before-archive-accept), generation two becomes ready and then exits right after readiness (crash-after-ready), and generation three becomes ready and emits one foreign-generation heartbeat that DriverManager must ignore (stale control bytes). The gate requires the frozen restart scheduling markers, readiness of generations two and three, the stale-generation-ignored marker, a live input DriverHost, and no kernel panic. `budget` exits every generation before readiness until the bounded restart budget trips into the explicit degraded state; the gate requires the exhaustion marker, a completed degraded boot, a live input DriverHost, and that no ACPI readiness marker appears. Both keep AML/PCI authority disabled. The ordinary QEMU smoke separately proves the no-injection happy path. The CI `qemu-acpi-restart` job runs both scenarios on release SMP2.

AP-9 extends the plain QEMU smoke with four required markers and seven regression markers: a healthy boot must show `[init] delegated unique PciConfigMint authority to DriverManager` (the unique AP-8 mint authority left `init` for DriverManager, exactly once), `[driver-manager] received unique PciConfigMint authority`, `[pci-manager] read-only config authority ready` (PCI Manager independently decoded the HMCF image, matched one read-only ECAM capability per record in canonical order, mapped every window read-only at private VAs, and upgraded its readiness report), and `[driver-manager] PCI manager ready (read-only config authority`. Must never appear: `[init] config mint authority transfer failed`, `[driver-manager] duplicate PciConfigMint authority rejected`, `[driver-manager] config capability mint rejected`, `[driver-manager] config authority transfer failed`, `[pci-manager] HMCF rejected`, `[pci-manager] no firmware snapshot`, `[pci-manager] read-only config authority map rejected`. Both readiness phases print on the happy path (`ready without root descriptors; fail-closed` at startup, then the config-authority upgrade once ACPI/HMCF settles); a degraded ACPI path leaves PCI Manager fail-closed forever with `no firmware snapshot`. No PCI configuration byte is ever read — AML mediation is AP-10.

AP-10 wires a separate mediation gate (`scripts/ci-qemu-pci-mediation-smoke.sh`, CI job `qemu-pci-mediation`) instead of extending the plain smoke — the mediation markers cannot be mandatory in scenarios where ACPI degrades fail-closed. A healthy mediation boot (default `ecam` scenario) shows `[driver-manager] mediation channel pair established`, `[pci-manager] obs backend=ecam`, `[acpi-manager] pci-mediation self-test: read=ok vendor-nonzero=true`, and `[acpi-manager] pci-mediation self-test: write=denied`, on top of the AP-8/AP-9 markers. The conformance-only forced-legacy scenario (`HUESOS_PCI_FORCE_LEGACY=1`, builds both managers with the legacy backend) requires `[driver-manager] PCI manager ready (legacy CF8/CFC backend)`, `[driver-manager] minted legacy CF8/CFC capability for PCI manager generation`, `[pci-manager] legacy CF8/CFC config reads ready`, and `[pci-manager] obs backend=legacy-cf8-cfc` instead of the ECAM markers. Must never appear in either scenario: `[acpi-manager] pci-mediation self-test: read=timeout`, `[acpi-manager] pci-mediation self-test: read=peer_closed`, `[pci-manager] obs mediation peer-closed`, and any panic marker; the legacy scenario must never show `obs backend=ecam`. The self-test is one bounded probe through the mediated channel — AML itself is not executed yet (AP-13) and no inventory is published. This smoke has not been run in the implementation environment; its markers are verified only by the CI `qemu-pci-mediation` job.

AP-8 extends the plain QEMU smoke with two required markers and two regression markers: a healthy boot must show `[acpi] config mint authority installed: snapshot` (the kernel independently re-decoded the archive-v2 MCFG at boot, pinned it to the archive snapshot identity, and stashed the bounded window set and usable-RAM map — any inconsistency leaves the authority uninstalled and the mint syscall answers `NotSupported`) and `[init] installed PciConfigMint capability (handle 8)` (the unique boot-minted `PciConfigMint` authority for the root supervisor; it is a binary capability, cannot be created through `sys_resource_create`, carries no `DUPLICATE` right, and alone authorizes `Syscall::PciConfigMint`). Must never appear: `[acpi] config mint authority disabled:` and `[init] failed to install PciConfigMint capability`. The mint itself is not exercised by the smoke — AP-8 ships the mechanism with no consumer; DriverManager receives generation-bound authority in AP-9 and AML reads land in AP-10. HMCF bytes are checksum-protected for consistency only, not authentication; minted ECAM capabilities are `READ|TRANSFER` (mappings of Mmio resources are always `NO_CACHE` and resource mappings reject `EXECUTE`), so this PR still enables no write-capable config path.

AP-7 extends the plain QEMU smoke with two required markers and one regression marker: a healthy boot must show `[acpi-manager] published HMCF` (the MCFG-decode produced a bounded immutable snapshot) and `[driver-manager] retained HMCF` (the envelope/size/generation were validated and the snapshot retained for the current generation); `[driver-manager] HMCF rejected` must never appear. The restart scenario re-uses the plain gate, so the injected cascade also proves the generation-2 snapshot is dropped when DriverManager schedules the restart (stale snapshots cannot outlive their generation) and generation 3 publishes a fresh one. The HMCF bytes are checksum-protected for consistency only; they are not authentication, and no ECAM mapping or PCI config authority is enabled — the mint path lands with AP-8/AP-9.

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
HBI v2.2 parsed. Entries: 0x4
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

### IOAPIC live keyboard delivery

```bash
bash scripts/ci-qemu-ioapic-delivery.sh debug 2 120
```

The test boots q35/UEFI with SMP2, waits for the input DriverHost to bind its
keyboard Port, injects the `a` key through QMP, and requires the PS/2 make code
`0x1e` to be read from an IRQ packet in userspace. This validates the physical
keyboard edge route through the IOAPIC, IDT, kernel IRQ bridge, Port, and
DriverHost; it is not a test of arbitrary PCI GSI delivery or level-triggered
ACK/re-enable. Use `release` as the first argument to exercise a release image.

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

Init runs a bounded blocking `ProcessWait` stress probe before fault isolation.
Each `fault-probe` child receives `wait`, yields once, then exits with code
zero. The parent invokes the blocking-capable wait API and receives that code.
Scheduling determines whether any particular call actually parks.

The kernel build passes only the whitelisted build setting
`HUESOS_LIFECYCLE_WAIT_STRESS=32|256` to init; any missing or invalid value
falls back to 32. This is a test-build input, not a userspace-visible kernel
cmdline or a new syscall ABI.

- The normal `qemu-boot` matrix runs 32 exits and requires:

  ```text
  [init] ProcessWait lifecycle smoke OK (32 blocked wakes)
  ```

- A dedicated test build with `HUESOS_LIFECYCLE_WAIT_STRESS=256` runs 256
  exits and emits:

  ```text
  [init] ProcessWait lifecycle soak OK (256 blocked wakes)
  ```

The first wait invokes the blocking-capable API, but scheduling determines
whether each call actually parks: the marker wording does not establish
32 or 256 blocked wakes. The latter emits progress every 32 exits. It does not prove the graveyard
fills or evicts: deferred reaping may remove each observed record immediately.
The committed QEMU script defaults to 120 seconds; callers can pass 360 for
slow TCG boot. No dedicated qemu-lifecycle-soak job exists in the reviewed
workflow. Longer 256-exit runs need an explicit build and timeout. This remains a
bounded regression/soak test rather than a proof of an unbounded-duration SMP
run.

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
system against a real QEMU NVMe controller with an HxFS development image. The
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

## Raw-GSI level interrupt smoke

`scripts/ci-qemu-irq-level-smoke.sh <profile> <cpus> <timeout>` boots with the
HBI command line `irq_test=1` and QEMU `-device edu`. The `edu` device raises a
level-triggered INTx line when software writes its raise register. The kernel
probe (`boot/irq_probe.rs`) then requires these markers, in order:

```text
[irq-test] edu INTx pin 1 -> GSI 11
[irq-test] raw GSI route acquired and bound to Port
[irq-test] level IRQ delivered to Port
[irq-test] level route stayed masked until acknowledge
[irq-test] level re-enable after acknowledge OK
[irq-test] raw GSI level route self-test OK
```

A `[irq-test] FAILED:` line or a kernel panic fails the script. The probe runs
on the BSP after interrupts are enabled and has a 3-second delivery timeout. It
exercises the kernel Port path only. The userspace raw-GSI syscalls are not yet
covered (see `docs/IOAPIC_ROUTING.md`).

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

## Storage kill-switch smoke

```bash
bash scripts/ci-qemu-storage-off-smoke.sh release 2 120
```

QEMU is given a real `-device nvme` backed by a fresh raw image, and the
HBI command line contains `init.storage=off`. The guest must print the
kernel and init disable markers, must not print `[storage] nvme0` or
`[driver-host:nvme] identified`, must still launch the terminal, and the
image SHA-256 must be unchanged. CI runs this as `qemu-storage-off`.

## Real Hardware Smoke Tests

See [HARDWARE.md](HARDWARE.md). One guest-laptop report exists (MSI Modern 15
B5M, AMD Ryzen 5 5625U). First boots of a disk that already holds another OS
must use `STORAGE_OFF=1`.

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
| `qemu-boot` | boot smoke across SMP 1/2/4/8 |
| `qemu-ioapic-live` | QMP-injected PS/2 edge IRQ reaches a userspace Port on SMP2 |
| `qemu-acpi-restart` | AP-6 lifecycle gates: injected restart cascade (pre-ready, post-ready, stale heartbeat) and restart-budget exhaustion into degraded mode, both release SMP2 |
| `qemu-nvme-boot` | base NVMe soak, mode 0 |
| `qemu-nvme-gcm-inject` | mode 1 |
| `qemu-nvme-crc-inject` | mode 2 |
| `qemu-nvme-no-tpm` | mode 6, debug **and** release |
| `qemu-nvme-powerfail` | crash/recovery cycles, debug **and** release |
| `qemu-nvme-shutdown-cycle` | mode 3 |
| `qemu-nvme-stress` | mode 4 |
| `qemu-nvme-long-soak` | one bounded pass of `scripts/soak-long.sh` (~2 h) |
| `qemu-storage-off` | NVMe present, `init.storage=off`, image hash unchanged |
| `qemu-extable-smoke` | recoverable-copy fixup path |
| `qemu-irq-level-smoke` | raw-GSI level route masked/acknowledged/redelivered (`irq_test=1`) |

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

## Typed user-copy host gates

`make test` includes sealed-record trait rejection assertions (bool, char,
enums, references, nonzero integers, fat pointers, unlisted records and arrays
of disallowed fields). Approved records have compile-time x86-64 size,
alignment and field-offset assertions. Output tests cover WaitSetResult tail
padding and the complete 256-byte, 16-result array boundary. These are host
checks, not proof of an on-target pointer fault or hardware behavior.

## Repeated ProcessWait observation gate

Host and on-target regression boundaries are documented in
[PROCESS_LIFECYCLE_REGRESSIONS.md](PROCESS_LIFECYCLE_REGRESSIONS.md).
Init now repeats `wait_exit` and `poll_exit` on each still-live process handle
after the first successful exit observation. The default QEMU smoke also
requires `[init] ProcessWait repeated observation OK`.

The first wait may take the blocking path; a yielding child alone does not
prove that the parent parked on every iteration. Repeated wait/query must
observe the original status without consuming it. This gate does not run or
prove a 256-exit graveyard-eviction soak; the script's default timeout remains
120 seconds unless overridden by the caller.
