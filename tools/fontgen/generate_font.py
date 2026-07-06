#!/usr/bin/env python3
"""Generate the 8x8 bitmap font used by huesos-fb and libcanvas.

Renders each printable ASCII character (0x20 '.  ' through 0x7E '~') with
DejaVu Sans Mono Bold at 8px, thresholds to 1 bit per pixel, and emits a
Rust source file with a `FONT_8X8: [[u8; 8]; 95]` array plus a `glyph()`
lookup function.

Usage:
    python3 generate_font.py > font8x8.rs

Then copy the generated body (everything after the header comment) into
both:
    crates/huesos-fb/src/font8x8.rs
    crates/huesos-userspace/libcanvas/src/font8x8.rs
(kept as two independent copies on purpose — see those files' own module
docs for why: the kernel-side and userspace-side drivers must not share a
crate dependency just for a font.)
"""
import sys
from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FONT_SIZE = 8
THRESHOLD = 90


def generate_glyphs():
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    glyphs = {}
    for code in range(0x20, 0x7F):
        ch = chr(code)
        img = Image.new("L", (8, 8), 0)
        draw = ImageDraw.Draw(img)
        draw.text((0, -1), ch, font=font, fill=255)
        px = img.load()
        rows = []
        for y in range(8):
            bits = 0
            for x in range(8):
                if px[x, y] > THRESHOLD:
                    bits |= 1 << x
            rows.append(bits)
        glyphs[code] = rows
    return glyphs


def emit_rust(glyphs, out=sys.stdout):
    out.write("// Auto-generated 8x8 bitmap font, ASCII 0x20..0x7E, rendered from\n")
    out.write("// DejaVu Sans Mono Bold at 8px and thresholded to 1bpp.\n")
    out.write("// Each row is a const [u8; 8]; bit 0 (LSB) = leftmost pixel.\n")
    out.write("// Regenerate with tools/fontgen/generate_font.py.\n")
    out.write("pub const FONT_8X8: [[u8; 8]; 95] = [\n")
    for code in range(0x20, 0x7F):
        bits = glyphs[code]
        row_str = ", ".join(f"0b{b:08b}" for b in bits)
        out.write(f"    [{row_str}], // {code:#04x} {chr(code)!r}\n")
    out.write("];\n")


def save_preview(glyphs, path):
    cols = 16
    rows_count = (0x7F - 0x20 + cols - 1) // cols
    sheet = Image.new("L", (cols * 9 * 4, rows_count * 9 * 4), 0)
    for i, code in enumerate(range(0x20, 0x7F)):
        cx = (i % cols) * 9 * 4
        cy = (i // cols) * 9 * 4
        bits = glyphs[code]
        for y in range(8):
            for x in range(8):
                if bits[y] & (1 << x):
                    for dy in range(4):
                        for dx in range(4):
                            sheet.putpixel((cx + x * 4 + dx, cy + y * 4 + dy), 255)
    sheet.save(path)


if __name__ == "__main__":
    glyphs = generate_glyphs()
    emit_rust(glyphs)
    if len(sys.argv) > 1 and sys.argv[1] == "--preview":
        save_preview(glyphs, "font_check_preview.png")
