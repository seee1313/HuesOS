# Font generator

`generate_font.py` regenerates the 8x8 bitmap font baked into both
`crates/huesos-fb/src/font8x8.rs` (kernel-side framebuffer driver) and
`crates/huesos-userspace/libcanvas/src/font8x8.rs` (userspace `Canvas`
text rendering).

Requires Python 3 + Pillow (`pip install pillow`) and a DejaVu Sans Mono
font (`fonts-dejavu-core`/`fonts-dejavu` on most Linux distros).

```bash
python3 generate_font.py > glyphs.rs
# then paste the array into both font8x8.rs files' `FONT_8X8` const

python3 generate_font.py --preview
# also writes font_check_preview.png, a visual sanity-check sheet of
# every glyph scaled up 4x
```

`qemu_screenshot.png` is a real screenshot (via QEMU's `screendump` QMP
command) of the framebuffer test pattern `huesos-init` draws on boot,
kept here as visual proof the framebuffer driver + `FramebufferBlit`
syscall + `libcanvas::framebuffer::Canvas` actually work end to end, not
just "compiles and doesn't crash".
