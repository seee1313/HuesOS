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
splash.accent   = RRGGBB          # bar fill, spinner, ok marks
splash.spinner  = on | off
stage.<id>      = <weight>        # progress weight, any positive int
stage.<id>.label= <text>          # shown under the bar
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

## Rendering

`Canvas` already draws into a process-owned VMO and blits with
`present()`, so double buffering is inherent — userspace never
touches video memory, and a partially drawn frame is never visible.
What matters for flicker is not the buffer but the *upload*: the
splash composes a full frame into a static shadow buffer and uploads
only the dirty region.

The shadow is a `static` byte array, not a heap allocation, because
init is `no_std` with no allocator. The terminal already does this
(`SHADOW_CAPACITY`, 16 MiB, covers 2560x1600x4); the splash uses the
same size for the same reason.

Cost control: the gradient is the expensive part (every pixel, every
frame) and it never changes, so it is painted once into the shadow
at startup. Animation frames repaint only the bar, spinner, and
label rows, then upload just those scanlines with
`upload_shadow_region` + `present_region`. A spinner tick is a few
thousand pixels, not a full screen.

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
marked failed, its indicator turns red, and the splash switches to
diagnostic mode: it prints the failed stage and the tail of the init
log on screen, regardless of `log.screen`. The boot continues to the
next stage, because a missing optional service is not a reason to
refuse to boot, but it continues *visibly*.

A clock read failure leaves the deadline unarmed and falls back to
waiting — refusing to boot because the clock syscall misbehaved
would be worse than the hang it protects against.
