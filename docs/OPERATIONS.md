# Operating a running HuesOS system

Stage E of `docs/PRODUCTION_ROADMAP.md` is about what an operator needs
once the machine is up and something is wrong with it. Two surfaces
exist for that: **runtime knobs**, which change behaviour without a
rebuild, and **structured observation**, which reports what happened in
a form a machine can read.

Both are deliberately small. A knob you cannot explain is a knob nobody
will dare turn during an incident.

---

## Runtime knobs

A knob is a named `u64` with a fixed range, living in the kernel. The
set is closed — knobs are an enum, not a registry — so there is nothing
to enumerate at runtime and no way for a process to invent one.

| Knob | Default | Range | What it does |
|------|---------|-------|--------------|
| `scrub.interval_secs` | 3600 | 0–604800 | How often the background scrubber walks the filesystem. `0` turns scrubbing off, which is a legitimate setting while diagnosing a drive whose media errors you are already collecting. |
| `recovery.retry_count` | 3 | 1–16 | Retries before a recoverable read is given up on and the extent is marked bad. |
| `log.verbosity` | 1 | 0–4 | 0 quiet, 1 errors and lifecycle, 4 per-extent trace. Leave at 1 outside an investigation. |
| `nvme.max_queue_depth` | 256 | 1–65536 | Caps the NVMe queue depth actually used. The response to a controller that misbehaves at full depth. |

### Disabling storage on a live disk

```text
init.storage=off
```

Exact whitespace-delimited token, baked into the HBI command-line
module (`STORAGE_OFF=1 make iso`, or write it into `build/cmdline.txt`
before `make iso`). When present the kernel **does not** scan PCI for
NVMe, size BARs, program MSI/MSI-X, or enable bus-master. Init then
skips NVMe resource grants and DriverManager never launches
`driver-host-nvme`. Use this for the first USB boot of a machine whose
internal NVMe holds another OS.

This is not a runtime knob: it has to win before Stage-A discovery
writes config space. A typo (`init.storage=offx`, bare `storage=off`)
does not match and storage stays on.

### Setting a knob at boot

```text
init.knob.nvme.max_queue_depth=32
```

Pass that on the kernel command line. init mints the `SystemControl`
capability, applies each `init.knob.*` token, and logs the outcome:

```text
[init] knob nvme.max_queue_depth = 32 (requested 32)
[init] knob log.verbosity = 4 (requested 99)
[init] knob: unknown knob bogus.knob
[init] knob: bad value for recovery.retry_count
```

Note the second line. **Writes clamp; they do not fail.** A request of
99 for a knob that tops out at 4 applies 4 and tells you so. A knob is
usually turned under pressure, often through a one-liner typed from
memory, and refusing the whole operation because the value was one over
the maximum is a worse outcome than applying the maximum and reporting
it. Compare the two numbers in the log if the difference matters.

A typo is logged and skipped. It never stops the boot — the same rule
the rest of the config parser follows.

### Setting a knob from a program

```rust
use libcanvas::system::{knob_get, knob_set, KnobId};

let current = knob_get(KnobId::LogVerbosity)?;         // no capability needed
let applied = knob_set(KnobId::LogVerbosity, 3, cap)?; // cap required
```

Reads are unrestricted: a process is already subject to these values,
and refusing to let it read them protects nothing while guaranteeing
that the diagnostic tooling which most needs to run during an incident
is the tooling that cannot.

Writes need a live `ResourceKind::SystemControl` handle. A knob write is
global — setting `log.verbosity` to zero blinds every subsystem at once,
which is an effective way to hide an intrusion — so it is an authority.
It is deliberately **not** `PowerControl`: a service trusted to tune the
system should not thereby be trusted to halt it.

### Adding a knob

1. Add the variant to `KnobId` in `crates/huesos-object/src/knobs.rs`
   with a default, bounds, and name. Append; never renumber.
2. Mirror it in `KnobIdAbi` in `crates/huesos-abi/src/lib.rs`.
3. Add the translation arm in `crates/huesos-syscalls/src/observe.rs`.
4. Add the name to the `KNOBS` table in init's `apply_cmdline_knobs`.
5. Read it where it matters, and **log the effective value** — a knob
   whose effect is invisible in the trace cannot be verified by the
   person who turned it.

The existing tests already enforce that defaults sit inside their own
bounds, that ids round-trip, and that names are unique.

---

## Structured observation

The text trace is for a human at a serial console. It is the wrong
format for everything else: an aggregator asking "how many recovery
events happened during this soak" would have to scrape prose that was
never promised to be stable.

So the kernel keeps a second channel: a ring of fixed-size binary
records, alongside the text, never replacing it.

### Record format

32 bytes, little-endian:

| Offset | Size | Field | Meaning |
|--------|------|-------|---------|
| 0 | 8 | `sequence` | Monotonic, starts at 1. Gaps mean dropped records. |
| 8 | 8 | `timestamp` | Monotonic ticks when recorded. |
| 16 | 4 | `class` | 1 boot, 2 mount, 3 recovery, 4 error. |
| 20 | 4 | `code` | Class-specific event code. |
| 24 | 8 | `detail` | Class-specific payload: an LBA, an error code, a count. |

`recovery` and `error` are separate classes on purpose. A soak with
recoveries is a healthy system doing its job; a soak with errors is a
failing one, and collapsing the two would hide the difference.

### Reading them

init dumps the ring to the UART at the end of boot, so one capture holds
both channels:

```text
[observe] 0100000000000000000000000000000001000000010000000200000000000000
[init] observation records dumped: 1
```

Decode with:

```bash
python3 tools/observation-decode.py ci-artifacts/qemu-debug-smp2.log
python3 tools/observation-decode.py --binary dump.bin --json
python3 tools/observation-decode.py serial.log --class error
```

```text
     1  t=0          boot      kernel-ready               detail=2
```

The decoder reports gaps on stderr:

```text
warning: missing records 3..4 (ring wrapped)
```

That warning is the reason records carry sequence numbers. A silent gap
would be indistinguishable from a quiet system.

### Design constraints worth knowing

- **The ring never allocates.** It is a 256-entry static array. The
  moments worth observing are disproportionately the moments when memory
  is short, and an allocation failure inside the code that records
  failures is a diagnostic dead end.
- **Recording cannot fail.** `record()` returns nothing and has no error
  path, so observability can never change the behaviour of the thing it
  is observing.
- **Oldest records are overwritten, and the drops are counted.** A
  consumer can always distinguish "nothing happened" from "I missed
  it".
- **An unknown class is preserved, not rejected.** A decoder running
  against a newer kernel reads what it understands and skips the rest.

### Adding an event

Add a code to `huesos_kernel::observation_code`, record it where the
event actually happens, and add the `(class, code)` pair to `CODES` in
`tools/observation-decode.py`. Codes are namespaced by class, so the
same number may mean different things under `boot` and `recovery`.

---

## Benchmarks and regression gating

`tools/storage-bench.py` produces a JSON report in two halves, because
the two halves can be checked in different ways and pretending otherwise
produces a gate nobody trusts.

```bash
make bench-check      # what CI runs
python3 tools/storage-bench.py --iterations 3 --blocks 256
```

**`deterministic`** — counters, image sizes, SHA-256 digests of tool
output. Bit-identical across runs of the same commit, compared
byte-exactly against `tools/baselines/storage-bench.json`. Any
difference is a real functional change: an image that got bigger, an
extent count that moved.

**`timings`** — wall-clock milliseconds, compared with a percentage
tolerance (default 25%). By default these are compared only against a
second run in the same invocation (`--self-compare`), which removes
machine-to-machine variance. Comparing them against the committed
baseline is opt-in (`--baseline-timings`) and mostly useful locally: on
a cold checkout the first run pays to build the Rust seed tool, which
dwarfs any real regression.

When a change legitimately moves the deterministic numbers:

```bash
python3 tools/storage-bench.py --update-baseline tools/baselines/storage-bench.json
```

Commit the result. It lands as a visible diff in the PR that caused it,
which is the point — a baseline that updates itself silently is not a
baseline.
