# Terminal Fonts

HuesOS Terminal starts with a custom TTY-style 8×16 bitmap font. It derives
from the project's existing permitted glyph data by expanding each 8-pixel row
to two scanlines, giving classic VGA/Linux-console proportions without copying
the GPL font tables from the Linux kernel.

The original HuesOS 8×8 font remains available:

```text
font tty       # default 8×16
font compact   # original 8×8
font           # show active mode
```

The terminal uses a 16-pixel line pitch in both modes, so changing fonts does
not invalidate scrollback/cursor geometry. Other Canvas users receive the TTY
font from `draw_text` by default and may explicitly request
`TextFont::Compact8x8` through `draw_text_with_font`.
