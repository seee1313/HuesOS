# Terminal Buffered Rendering

## Root cause of post-game stalls

Snake and Doom both remained smooth while running, but returning to Terminal
could take several seconds. Keyboard IRQs and scancode delivery continued, and
queued characters appeared together after the pause. This isolated the problem
to synchronous Terminal repaint rather than either game.

The old path cleared the Canvas one scanline at a time and rendered each glyph
pixel through `Canvas::set_pixel`. Because Canvas storage is a VMO, every one of
those operations crossed the syscall boundary. A single Full HD repaint could
produce thousands of `VmoWrite` calls, followed by a full framebuffer present.
The 8×16 TTY font increased that work further. Snake also invoked an unnecessary
second render after returning to the shell.

## Buffered path

Terminal now owns a fixed 16 MiB shadow framebuffer, sufficient for up to
2560×1600 at 32 bpp. Rendering proceeds as follows:

1. Clear the shadow memory locally.
2. Rasterize all visible glyphs directly into that memory.
3. Upload the packed image in bounded 1 MiB VMO writes.
4. Issue one framebuffer present.

For 1920×1080 this replaces thousands of tiny syscalls with eight uploads and
one present. Unusual non-32-bpp modes retain the conservative old fallback.
The shadow is static BSS: there is no per-frame heap allocation or allocator
fragmentation.

The redundant render inside `redraw_after_game` was removed; the shell's normal
end-of-input render is the single presentation point.

## Regression result

The release SMP QEMU test launches Doom, exits with Q, waits two seconds and
captures the framebuffer. Terminal is already restored with its expected
three-color palette. Instrumentation during validation measured buffered frames
at 6–8 scheduler ticks (60–80 ms under QEMU TCG), well below the previous
multi-second pause. Production code omits per-frame logging.

The same path is used after Snake, Doom, font changes, clear, and ordinary shell
input, so the fix targets the shared rendering bottleneck rather than either
game.
