# Dirty-region framebuffer and Snake rendering

## Motivation

The framebuffer syscall originally accepted only tightly packed source rectangles. A `Canvas` backed by a fullscreen VMO could therefore present either the complete display or no subregion at all: rows inside a dirty rectangle are separated by the fullscreen pitch. Snake compounded this by clearing and rebuilding the board, HUD, every hazard, and every body segment on each step. The amount of framebuffer work grew with snake length.

## Strided blit ABI

`FramebufferBlitArgs` now contains `src_stride`, the byte distance between adjacent source rows. Fullscreen callers pass the canvas pitch, which equals the row size. Dirty callers pass the same full-canvas pitch while selecting a smaller `src_width` and a `vmo_offset` at the rectangle origin.

The kernel validates before making any visible write:

- non-zero width and height;
- checked `width * bytes_per_pixel`;
- `src_stride >= row_bytes`;
- configured row, packed-transfer, and stride caps;
- checked last-row offset and final source byte;
- the complete strided source range is inside the VMO;
- VMO type and read rights.

Packed sources retain the bounded bulk-copy fast path. Strided sources are gathered row by row into the existing 64 KiB kernel scratch buffer, then passed to the framebuffer driver as packed pixels. Kernel temporary memory therefore remains bounded independently of display size and dirty-region pitch.

## Safe userspace API

`Canvas` adds:

- `fill_rect_to_shadow`: clipped, syscall-free 32-bpp rasterization;
- `upload_shadow_region`: row-wise VMO upload for one rectangle;
- `present_region`: same-coordinate dirty present;
- `present_region_at`: dirty present with an explicit destination.

Every rectangle uses checked coordinate addition and must fit inside the canvas. The API does not expose the framebuffer mapping.

## Snake renderer

Snake reuses Terminal's process-wide 16 MiB software framebuffer. Terminal and Snake execute sequentially on one userspace thread, which is the synchronization invariant behind the shared `UnsafeCell`; there are no overlapping borrows and no additional 16 MiB static allocation.

Each board cell is represented by a compact `CellVisual` snapshot:

- background layer: normal or imminent blast radius;
- foreground layer: food, gold food, bomb state, bullet, rocket, body, or head.

Hazards and the snake are folded into a fixed 32×18 snapshot in O(board + snake + hazards) CPU work. Body color is stable rather than index-gradient-based, so moving does not mark every segment dirty. A normal step changes only old/new head and tail cells.

Rendering policy:

1. Initialization and Playing/GameOver transitions render and upload one complete frame.
2. The HUD is rasterized locally and uploaded as one 58-pixel-high region.
3. Changed board cells are detected against the previous snapshot.
4. Only adjacent dirty cells on the same row are coalesced. Head and tail are intentionally not merged across a long row or across rows, avoiding a bounding rectangle that grows with snake length.
5. Each run is rerasterized completely (base, guides, blast layer, foreground), uploaded, and presented.

The renderer tracks frame, dirty-cell, and present counters internally so a later diagnostics syscall can expose them without changing the rendering contract.

## Failure and fallback behavior

Dirty software rasterization requires a 32-bpp canvas and a framebuffer no larger than the shared shadow capacity. This is the normal HuesOS boot contract (current tested modes include 1280×800). If upload or present fails, the game continues and may retain the previous visible frame; no unchecked memory access occurs. Supporting unusual pixel formats should be implemented as a separate typed raster backend rather than adding format-dependent unsafe code.

## Complexity

Before:

- board raster/syscall work: O(snake length + hazards + full display) each step;
- present bytes: full display each step.

After:

- snapshot computation: O(snake length + fixed board/hazard limits), entirely in userspace memory;
- board raster and transferred bytes: O(changed cells), independent of snake length for ordinary movement;
- HUD transfer: fixed O(display width × 58 rows);
- kernel allocation: at most the existing 64 KiB blit chunk plus bounded VMO read machinery.

## Validation matrix

Required checks for this stage:

- host unit suite and Clippy with warnings denied;
- release ISO build;
- QEMU SMP=2 boot through Terminal;
- classic and hard Snake movement, food, blast warning, death overlay, restart, and Esc;
- long-snake soak confirming dirty-cell count stays constant during ordinary movement;
- framebuffer edge rectangles and malformed stride/range rejection;
- Terminal repaint after Snake to confirm shared-shadow reuse does not preserve game pixels.
