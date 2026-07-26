# Font generators

Two independent bitmap-font pipelines feed HuesOS's on-screen text:

* **`bdf2rs.py`** — the current default. Converts an upstream BDF
  bitmap font to the Rust `FONT_6X13: [[u8; 13]; 95]` array shipped
  by both `crates/huesos-fb/src/font6x13.rs` (kernel framebuffer
  driver, currently unused) and
  `crates/huesos-userspace/libcanvas/src/font6x13.rs` (userspace
  `Canvas` text rendering). The default userspace terminal uses
  Cozette 6×13 through this pipeline.
* **`generate_font.py`** — legacy. Regenerates the 8×8 bitmap font
  baked into `font8x8.rs` on both sides. Retained because
  `TextFont::Tty8x16` (an upscaled 8×8) and `TextFont::Compact8x8`
  still use those tables, and shutdown / panic banners render at
  2× scale where the compact font reads better than 6×13.

## Regenerating Cozette (default userspace font)

The shipped font is [Cozette](https://github.com/slavfox/Cozette) (MIT).

```sh
curl -L -o /tmp/cozette.bdf \
    https://github.com/slavfox/Cozette/releases/latest/download/cozette.bdf
python3 tools/fontgen/bdf2rs.py /tmp/cozette.bdf \
    crates/huesos-userspace/libcanvas/src/font6x13.rs
python3 tools/fontgen/bdf2rs.py /tmp/cozette.bdf \
    crates/huesos-fb/src/font6x13.rs
```

Then append the `glyph()` accessor to the bottom of each generated
file (the current copies keep it inline). Every change to the
shipped font must be reflected in both copies — the kernel must be
able to render shutdown / panic banners without depending on
userspace, and userspace must be able to render text into a shadow
buffer without a syscall.

### Cell geometry

* Width: 6 pixels (advance). Bit 0 (LSB) is the leftmost visible pixel.
* Height: 13 pixels total (10 above baseline + 2 descender rows).
* Row 0 is the top of the ascender box; row 10 is the baseline; rows
  11–12 are descender rows used by `g`, `p`, `y`, etc.

### Swapping the font

Drop a new BDF into your working directory, run `bdf2rs.py`, and
review the output. The script only extracts ASCII 0x20..0x7E; if
a glyph is missing (e.g. non-monospaced high-Unicode-only fonts)
the corresponding row is emitted as all zeros. `bdf2rs.py` assumes
single-byte-per-row glyphs (width ≤ 8), which is true for every
compact terminal font commonly shipped as BDF.

## Regenerating the 8×8 font (legacy)

Requires Python 3 + Pillow (`pip install pillow`) and a DejaVu Sans
Mono font (`fonts-dejavu-core`/`fonts-dejavu` on most Linux
distros).

```bash
python3 generate_font.py > glyphs.rs
# then paste the array into both font8x8.rs files' `FONT_8X8` const

python3 generate_font.py --preview
# also writes font_check_preview.png, a visual sanity-check sheet of
# every glyph scaled up 4x
```

## Screenshots

`qemu_screenshot.png` is a real screenshot (via QEMU's `screendump`
QMP command) of the framebuffer test pattern `huesos-init` draws on
boot, kept here as visual proof the framebuffer driver +
`FramebufferBlit` syscall + `libcanvas::framebuffer::Canvas` actually
work end to end, not just "compiles and doesn't crash".
