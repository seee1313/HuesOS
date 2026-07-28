# Terminal Fonts

HuesOS Terminal starts with the Cozette 6×13 bitmap font (MIT), giving a
1024×768 boot display roughly 54 rows × 168 columns without using Linux kernel
font tables.

The legacy HuesOS fonts remain available at runtime:

```text
font cozette   # default Cozette 6×13
font tty       # TTY-style 8×16, derived from permitted project glyph data
font compact   # original HuesOS 8×8
font           # show active mode
```

The terminal grid is sized for Cozette with a 14-pixel line pitch. Font changes
mark the full terminal dirty and repaint through the same buffered renderer;
ordinary typing after that goes back to dirty-row uploads. Other Canvas users
receive Cozette from `draw_text` by default and may explicitly request
`TextFont::Tty8x16` or `TextFont::Compact8x8` through `draw_text_with_font`.
