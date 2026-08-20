# HuesOS Framebuffer Access Policy

Status: landed. Defines who can touch the real framebuffer and how.

## Threat model

`huesos-fb` is a kernel-side driver that owns the physical framebuffer
memory handed off by the Limine bootloader. Userspace never gets a
mapping of that memory; the only way it can present pixels is the
narrow, bounds-checked [`Syscall::FramebufferBlit`] path, which copies
a validated rectangle out of a VMO the caller already owns.

Before this PR, **`sys_framebuffer_blit` was reachable from any
process** that owned a VMO with `Rights::READ`. A compromised graphics
process, a buggy Doom port, or any process that had been tricked into
loading hostile assets could blit arbitrary rectangles onto the
display at any time, with no way for init to revoke that authority
without killing the process.

## What changed

1. New immutable capability kind
   [`ResourceKind::FrameDraw`](../crates/huesos-abi/src/lib.rs),
   wire value `6`, kernel kind value `6`. Binary capability, no
   meaningful `base`/`len` (force `(0, 1)` at mint time, mirroring
   `PowerControl`).
2. New ABI constant
   [`huesos_abi::INIT_FRAME_DRAW_HANDLE = 6`](../crates/huesos-abi/src/lib.rs).
   The kernel installs a freshly-minted `FrameDraw` Resource at this
   slot in the initial process's handle table during boot, in the same
   step that installs `INIT_BOOTFS_HANDLE`, `INIT_ACPI_BROKER_HANDLE`,
   and `INIT_STORAGE_BOOT_INFO_HANDLE`.
3. `Syscall::FramebufferBlit = 13` now takes a `HandleValue` capability
   handle in `a1` and a `*const FramebufferBlitArgs` in `a2`. The
   kernel-side handler calls
   [`require_resource_of_kind(a1, ResourceKind::FrameDraw)`](../crates/huesos-syscalls/src/resource.rs)
   **before** it dereferences `a2`, so a forged or stale handle cannot
   leak information about the caller's address space or about the
   kernel's framebuffer geometry.
4. `libcanvas::Canvas` now carries a `cap: HandleValue` field, set at
   construction time. The default `new_fullscreen` / `new` constructors
   use `INIT_FRAME_DRAW_HANDLE` (the canonical slot init owns);
   processes that received a transferred capability handle from init
   over a channel should call `new_fullscreen_with_cap` /
   `new_with_cap` with the handle value they received.

## Minting policy

`sys_resource_create` is gated on the **root supervisor KOID
predicate** (the kernel keeps a function pointer registered during
`spawn_init_process`; only the init process's KOID matches). The
`FrameDraw` kind is therefore mintable exclusively by init, exactly
like `PowerControl`. No driver-host, graphics process, or any other
userspace process can mint its own `FrameDraw` capability.

The kernel's `require_resource_of_kind` helper accepts a `FrameDraw`
handle as authority to call `FramebufferBlit`, regardless of which
process owns it. A handle transferred over a channel from init to a
graphics process keeps its authority: the kernel does not track
"intended" owners, only that *some* live caller-owned handle names a
live `FrameDraw` resource.

## Transfer policy

Init mints the capability at boot and, when it spawns a legitimate
graphics process (`terminal`, `doom`, `canvas-hell`, future Doom
ports, …), transfers the handle over the bootstrap channel using the
same `write_handle` pattern the shutdown-broker launch uses for
`PowerControl` and `IoPort`. The receiving process reads the handle
into its own handle table, looks up the value, and passes it to
`Canvas::new_fullscreen_with_cap`.

A graphics process that never received a `FrameDraw` handle cannot
manufacture one (mint is gated), cannot steal one (mint is exclusive
and the slot is taken by init), and cannot use a foreign handle
(handles are not transferable cross-process except via channels, and
the channel transfer path requires the sender to hold a handle with
`Rights::TRANSFER` — which the kernel mints onto the `FrameDraw`
resource in the install step). The kernel therefore denies every blit
from a non-graphics process with `ErrorCode::AccessDenied`.

## What's left public

`Syscall::FramebufferInfo` (number 12) stays public because geometry
is not sensitive:

- any process that can see a Canvas rendering on screen can already
  learn the resolution from the visible image;
- pixel format (bpp, channel masks) is dictated by the hardware and
  is not process-specific.

If a future hardened profile needs even the geometry to be
capability-gated, the same pattern (new `ResourceKind` + capability
check in `sys_framebuffer_info`) applies. It is intentionally out of
scope for this PR.

## Why not move the driver to userspace?

`docs/MICROKERNEL_MIGRATION.md` covers the broader direction. The
framebuffer driver is the **one** graphics device that does not move
to a userspace driver-host because:

- it is the only graphics output the kernel panic screen, the
  shutdown screen, and the boot splash can render to — moving it out
  of the kernel would require a fallback (serial + legacy VGA text
  mode) to keep those screens visible when every userspace process
  has crashed;
- raw framebuffer access from a userspace driver-host would have to
  re-expose the same `Mmio` resource model NVMe already uses, but
  the cost (every graphics client gets direct video memory access,
  the kernel can no longer draw its own screens without going
  through a process) is not justified by the small code-size win;
- the capability check added in this PR is the **strict** version of
  "only the graphics stack can write pixels": kernel code can still
  write, init and the graphics stack can write, and no one else.

## ABI stability

`FramebufferBlit = 13` is a re-used syscall number, but its signature
changed (added `a1: HandleValue`). The change is mandatory and
breaking at the source level because the syscall handler now reads
two arguments instead of one. Every libcanvas consumer
(`terminal`, `doom`, `canvas-hell`, any future `tui-*` package) is
rebuilt against the new `Canvas` API and now calls `syscall2` with
the capability handle and the args pointer. Direct callers of the
raw syscall that did not go through libcanvas would need to be
updated by their owners; there are none in the current tree.

`FrameDraw = 6` is a new `ResourceKind` value. The kind-ABI is
append-only by the same rule that governs the syscall table, so
adding a new variant is non-breaking for existing callers and any
unknown value reads as `None` from `ResourceKindAbi::from_raw`.

## Tests

- `crates/huesos-abi/src/lib.rs::resource_kind_abi_round_trip` —
  exercises the new `FrameDraw` value through `from_raw` and locks
  the wire value `6`.
- `crates/huesos-abi/src/lib.rs::framebuffer_blit_is_capability_gated` —
  locks the `FramebufferBlit = 13` and `INIT_FRAME_DRAW_HANDLE = 6`
  ABI slots so a stealth renumber fails before it can ship.
- `crates/huesos-syscalls/src/framebuffer.rs::framebuffer_blit_signature_takes_capability_handle` —
  locks the public signature of `sys_framebuffer_blit` as
  `(HandleValue, *const FramebufferBlitArgs)`; refactors that flip
  the argument order or drop the capability parameter fail this test
  before the kernel can boot with the wrong handler.
- `docs/ARCHITECTURE_ROADMAP.md` — this PR is the entry for
  "framebuffer capability" in the capability-primitive roadmap.
