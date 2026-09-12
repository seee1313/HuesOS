# Init boot UX: splash, progress, and log policy

Status: implemented
Scope: `crates/huesos-userspace/init`, `crates/huesos-abi`,
`crates/huesos-kernel` (cmdline handoff + BOOTFS entry)

## Why

Init used to mirror every log line onto the framebuffer. That was
right when init was a syscall smoke-test harness and the screen was
the only way to see what the kernel did. It is wrong now: the
machine boots real services, and a wall of `[init]` lines is both
ugly and useless to anyone who is not debugging init itself.

The serial UART, meanwhile, is the opposite case. It is not a user
surface; it is the only channel that survives a machine that dies
before the terminal starts, and the CI soak gates grep it for
markers. So the split is:

* **UART** — always on, always complete. Never gated by config.
  Silencing it would blind post-mortem debugging and break the soak
  harness, which is a bad trade for a cosmetic win.
* **Screen** — a splash by default. Technical text appears only when
  the config asks for it.

## Configuration

Two sources, in increasing priority:

1. `/etc/init.conf` in BOOTFS. Init already reads BOOTFS for driver
   manifests, so this needs no new plumbing and is editable by
   rebuilding the image.
2. The HBI kernel command line, via `init.*` keys. The kernel now
   installs the cmdline bytes into the init process as a read-only
   VMO at `INIT_CMDLINE_HANDLE`, the same mechanism already used for
   BOOTFS and the ACPI archive. This is what you want at 03:00 when
   a machine will not boot: change one word in the bootloader entry
   instead of rebuilding an ISO.

Unknown keys are ignored and counted, not fatal. A typo in a splash
colour must never stop a machine from booting; the count is logged
to UART so the typo is still discoverable.

### Keys

```text
log.screen      = off | on        # technical log text on screen
splash          = on | off        # off implies log.screen=on
splash.top      = RRGGBB          # gradient start
splash.bottom   = RRGGBB          # gradient end
splash.accent   = RRGGBB          # bar fill
splash.spinner  = on | off        # legacy key, ignored by the renderer
splash.version  = <text>          # brand line; default is the build's
                                  # CARGO_PKG_VERSION
stage.<id>      = <weight>        # progress weight, any positive int
stage.<id>.label= <text>          # fallback name in the status list
timeout.default = <seconds>
timeout.<id>    = <seconds>
```

Command-line form is the same key prefixed with `init.`, e.g.
`init.splash=off`, `init.log.screen=on`.

`splash=off` forces `log.screen=on`. A blank screen with no
diagnostics is the one outcome nobody ever wants; if you turn the
pretty thing off, you get the useful thing instead.

## Progress model

The requirement was that this not need redesigning later, so the
stage table is **data, not code**. Init holds a fixed-capacity array
of stages, each with an id, a weight, a label, and a timeout. Adding
a service to the boot sequence means adding a `stage.` line to the
config; init itself does not change.

Progress is weighted, not "n of m", because the stages differ by an
order of magnitude in duration — NVMe enumeration plus Hxfs mount
dominates everything else, and an unweighted bar would sit at 40%
for most of the boot and then jump. Weights are relative, so they
do not have to sum to 100.

Three levels of feedback, each optional per stage:

* **Started** — init marks the stage active before launching it. The
  bar advances to the stage's floor and the label changes.
* **Progress** — a service may send `name:progress:NN` (NN = 0..100)
  on its bootstrap channel any number of times. Init interpolates
  within that stage's weight band. This is what makes the bar move
  during a long mount instead of freezing.
* **Ready** — the existing `name:ready` message. The stage fills and
  is marked done.

The intermediate message is an extension of the existing string
protocol on a channel init already reads, so no new syscall and no
new ABI surface. Services that never send progress still work; they
simply jump from floor to full. Old services are unaffected, which
is why this was preferred over a dedicated progress syscall — a
syscall would have to be capability-gated and would let any service
lie about global boot state, whereas here a service can only move
its own band.

The bar is monotonic: a stage that reports 60 then 40 stays at 60. A
progress bar that goes backwards reads as a fault even when nothing
is wrong.

## Look

The splash is a systemd-style boot console: a status line per
service, not a logo composition. Default layout, top to bottom:

* **Brand line** — "HuesOS <version>" in the top-left corner: the
  product name in title colour, the version dimmed (overridable with
  `splash.version`, defaulting to the build's `CARGO_PKG_VERSION`).
* **Status list** — one line per stage, left-aligned, shown as soon as
  the stage starts (pending stages have no line at all, exactly like
  systemd):
  * `Starting HuesOS Storage Service...` — stage running, no tag;
  * `[  OK  ] Started HuesOS Storage Service.` — green, settled;
  * `[WARN  ] Started HuesOS Storage Service (degraded).` — amber;
  * `[FAILED] Failed to start HuesOS Storage Service.` — red;
  * `[SKIP  ] HuesOS Storage Service not started.` — dim.
* **Target lines** — once every stage has reported, two closing
  lines: `[  OK  ] Reached target HuesOS Shell.` (or `[FAILED]`
  "Failed to reach …" / `[WARN  ]` "… (degraded)" when applicable)
  and the untagged `Startup complete.`.
* **Progress bar** — a thin (2–5 px) centred bar in the bottom
  margin (88% of height), the overall weighted progress.

Stage ids map to human unit names ("HuesOS Kernel Self-Test",
"HuesOS Driver Manager", "HuesOS Storage Service", "HuesOS Power
Control", "HuesOS Terminal", "HuesOS Key Broker"); custom stages use
their configured label. All line formats live in `huesos-bootux`
(`paint::tag_text`, `line_prefix`, `line_suffix`) and are unit-tested
on the host, so the console format cannot drift silently.

`splash.spinner` remains a parsed (ignored) key for config
compatibility: the status list's `Starting …` lines carry the
"the machine is alive" signal.

The gradient and the brand line are painted once at startup and never
re-uploaded. The frame is split into two independently presented
bands: the status list (repainted only on a stage *state* change —
a few times per boot) and the progress bar (repainted when the
permille moves), so a long `Starting …` phase re-uploads the list
once and then just moves the bar.

## Rendering

`Canvas` already draws into a process-owned VMO and blits with
`present()`, so double buffering is inherent — userspace never
touches video memory, and a partially drawn frame is never visible.
The VMO *is* the back buffer; the splash keeps no shadow copy.

What matters for flicker is the *upload*: each band restores the
gradient across its rows (a handful of `fill_rect` calls) and uploads
only those scanlines with `present_region`. A list repaint is a few
hundred rows of text; a bar tick is a few rows. A full screen is
uploaded exactly once, at startup.

The gradient is computed per scanline with integer arithmetic —
there is no FPU state guarantee in init and no soft-float dependency
worth adding for a background.

## Failure UX

The old code polled a fixed 8000 iterations for a ready message and
then continued silently. That is the worst possible behaviour: the
screen keeps its animation, the boot is already broken, and nothing
says so.

Now each stage has a wall-clock deadline from `monotonic_ticks()`
(iteration counts are meaningless here — the loop yields, so it
spins as fast as the scheduler allows). On expiry the stage is
marked failed: its line in the status list turns into a red
`[FAILED] Failed to start …`, and the splash draws a diagnostic
line under the list — `stage '<id>' did not report ready` —
regardless of `log.screen`. The boot continues to the next stage,
because a missing optional service is not a reason to refuse to
boot, but it continues *visibly*.

A clock read failure leaves the deadline unarmed and falls back to
waiting — refusing to boot because the clock syscall misbehaved
would be worse than the hang it protects against.
