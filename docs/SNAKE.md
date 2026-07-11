# Full-Screen Snake

## Deterministic timing

Snake no longer reads or calibrates `RDTSC`. Raw TSC pacing produced different
speeds under turbo boost, power-saving states, virtual machines, and processors
whose TSC frequency did not match the fallback assumptions.

The game now uses `ClockGetMonotonic`, a 100 Hz kernel clock driven only by CPU
0's calibrated LAPIC timer. Cooperative yields and the number of online CPUs do
not advance this clock. A normal step is 10 ticks (100 ms) and gradually falls
to a minimum of 6 ticks (60 ms) as the score increases.

Keyboard messages may wake a Channel timeout early, but the game always checks
the monotonic deadline before advancing simulation. Input latency therefore
remains low without making rapid key presses increase game speed.

Init performs a boot smoke test: a 10-tick wait must measure 9–12 monotonic
ticks. This catches accidental coupling of time to yields, scheduler activity,
or CPU count.

## Full-screen layout

The logical collision grid remains 32×18, preserving gameplay and fixed-size
`no_std` storage. Pixel layout is dynamic:

```text
cell = min((screen_width - edge_padding) / 32,
           (screen_height - HUD_height) / 18)
```

The board is centered and consumes the largest rectangle that fits below the
HUD. At the default 1280×800 mode it occupies almost the complete screen
instead of the previous fixed 512×288 region.

Visual changes include:

- layered dark full-screen background;
- dedicated HUD panel with cyan separator;
- bright outer board border and inset frame;
- sparse grid guides suitable for large cells;
- resolution-independent cell padding;
- highlights on body, food, projectiles, bombs, and rockets;
- larger centered game-over overlay;
- preserved classic and hard-mode color distinctions.

Every size calculation uses saturating arithmetic, so unusually small
framebuffers degrade without unsigned underflow.

## QEMU visual/timing test

The release SMP test injects `snake`, captures two PPM frames 500 ms apart, and
checks:

- 1280×800 framebuffer;
- more than half the screen occupied by board background;
- visible cyan border;
- a detectable green snake head;
- head movement between frames;
- substantial pixel difference between frames;
- successful monotonic-clock boot smoke test;
- no kernel panic.

In the recorded test the head moved four 39-pixel cells between captures; HMP
screenshot latency accounts for the difference from the nominal five steps per
500 ms.
