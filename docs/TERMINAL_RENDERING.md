# Terminal Buffered Rendering

## Root cause of terminal stalls

Snake and Doom both remained smooth while running, but returning to Terminal
could take several seconds. Keyboard IRQs and scancode delivery continued, and
queued characters appeared together after the pause. This isolated the problem
to synchronous Terminal repaint rather than either game.

The first Terminal path cleared the Canvas one scanline at a time and rendered
each glyph pixel through `Canvas::set_pixel`. Because Canvas storage is a VMO,
every one of those operations crossed the syscall boundary. A single Full HD
repaint could produce thousands of `VmoWrite` calls, followed by a full
framebuffer present.

The later buffered path fixed whole-screen repaint by drawing into a fixed
16 MiB shadow framebuffer and uploading the packed image in bounded 1 MiB VMO
writes. That solved multi-second post-game stalls, but ordinary line editing
still repainted and re-presented the entire display for every key press.

## Buffered full repaint

Terminal owns a fixed 16 MiB shadow framebuffer, sufficient for up to 2560×1600
at 32 bpp. Full repaint proceeds as follows:

1. Clear the shadow memory locally.
2. Rasterize all visible glyphs directly into that memory.
3. Upload the packed image in bounded 1 MiB VMO writes.
4. Issue one framebuffer present.

For 1920×1080 this replaces thousands of tiny syscalls with eight uploads and
one present. Unusual non-32-bpp modes retain the conservative old fallback. The
shadow is static BSS: there is no per-frame heap allocation or allocator
fragmentation.

Full repaint is still used for initial draw, clear, scroll, font changes, and
other changes that invalidate the whole text grid.

## Dirty-row line editing

Ordinary terminal input now tracks dirty rows in the `Screen` object. Character
insert, backspace, cursor-row movement, command output, and scroll mark exactly
the rows whose visible cells or active-row highlight changed.

On 32-bpp framebuffers, a non-full render:

1. Clears only each dirty text row in the process-local shadow buffer.
2. Rasterizes only those rows' text.
3. Coalesces adjacent dirty rows into one stripe.
4. Uploads each full-width stripe into the Canvas VMO.
5. Presents only that stripe with `FramebufferBlit`.

A typical printable key therefore transfers roughly one text-row stripe instead
of the complete framebuffer. At 1024×768×32 bpp, the hot path drops from about
3 MiB of VMO upload plus a full-screen blit per key to about 56 KiB plus one
row-height blit. Enter repaints the previous and new active rows; scroll and
`clear` intentionally fall back to a full repaint.

`Canvas::upload_shadow_region` also special-cases full-width stripes so a dirty
terminal row is uploaded as one contiguous VMO write instead of one write per
scanline. Very large full-width stripes are split into the same bounded 1 MiB
chunks used by full-screen upload. Narrower rectangles keep the safe row-wise
path used by Snake.

## Input wait policy

The shell keyboard loop now uses `Channel::read_into_blocking` instead of a
`ShouldWait`/`yield_now` poll loop. The terminal parks when idle and wakes only
when the keyboard service queues a message, removing scheduler churn from the
keypress path without changing the keyboard service ABI.

## Regression result

The release SMP QEMU test launches Doom, exits with Q, waits two seconds and
captures the framebuffer. Terminal is already restored with its expected
three-color palette. Instrumentation during validation measured buffered frames
at 6–8 scheduler ticks (60–80 ms under QEMU TCG), well below the previous
multi-second pause. Production code omits per-frame logging.

The dirty-row path is the shared fast path for ordinary shell typing; the full
buffered path remains the safe fallback for large invalidations and unusual
framebuffer formats.
