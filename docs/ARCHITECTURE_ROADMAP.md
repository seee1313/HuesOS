# HuesOS Architecture Roadmap — Component Framework Evolution

This document captures the **long-term architectural direction** for HuesOS
capability distribution, driver management, and system lifecycle. It exists so
we do not lose the shape of the target while shipping incremental PRs against
it. Every PR chain listed under "Immediate cascade" below should visibly move
toward the endpoint described here.

Status: **planning document, not implemented**. Individual sections cross-link
to concrete work items in `ROADMAP.md` §7 and the Immediate list.

The **production-readiness push** that is currently in flight is tracked in
[`PRODUCTION_ROADMAP.md`](PRODUCTION_ROADMAP.md), which organises the
remaining work into Stages A through F (mount path wired, I/O pipeline
complete, reliability surface, security gate, operations, service
foundation). That document is the live to-do; this one is the long-term
direction. The two coexist because they answer different questions:
*this* document says **what the system is**; *that* document says
**what still has to ship to make the system deployable**.

The PCI/PCIe subsystem now has its own approved normative architecture and
production delivery plan:
[PCI_MANAGER_ARCHITECTURE.md](PCI_MANAGER_ARCHITECTURE.md) defines the
userspace PCI Manager, configuration authority, DeviceLease, DMA, hotplug, and
rebalance model; [PCI_PRODUCTION_ROADMAP.md](PCI_PRODUCTION_ROADMAP.md) defines
the staged implementation and release gates. Those documents supersede any
older PCI-specific sketch in this general roadmap.

---

## 1. The endpoint (target architecture)

HuesOS will run a **Fuchsia-style component framework** in userspace on top of
a small, deny-by-default microkernel that never blocks on userspace lifecycle.

### 1.1 Component Framework layer

- **HML** (HuesOS Manifest Language): human-authored JSON-shaped source,
  extension `.hml`. Declares a component's identity, capabilities it
  requires, capabilities it exposes, its lifecycle policy (including
  criticality), and its HIDL interface bindings.
- **HMC** (HuesOS Manifest Compiler): standalone build-time tool.
  Compiles `.hml` → `.cm` (compact binary component manifest). Validates
  cross-references between HIDL interface names and capabilities.
- **`.cm`**: binary component manifest format, serialized via HIDL. Compact
  (no text parsing at runtime), forward-compatible (versioned), verifiable
  (schema-checked at load).
- **HIDL** (HuesOS Interface Definition Language): IDL for IPC contracts
  between components. Analogous to Fuchsia FIDL. Compiles to Rust
  bindings for both server and client sides. Every channel-based service
  is described by a HIDL interface; `.cm` files reference HIDL interfaces
  by fully-qualified name.
- **`component_manager`**: root userspace process, spawned by init after
  BOOTFS mounts. Reads `.cm` files, builds the *component topology*
  (parent → child tree), computes each child's *namespace* (the set of
  channels/handles it can see) declaratively from the manifest, spawns
  the child with exactly those handles in its handle table, and no more.
  DriverManager becomes one of `component_manager`'s children (or its
  functionality migrates in).

### 1.2 Manifest is not universal

Not every process needs a full `.cm`. The framework recognises three tiers:

1. **Bare process** — no manifest, no declared capabilities. Started only
   by explicit parent transfer; gets exactly the handles the parent
   passes in bootstrap. Suitable for `hello-world`-class programs,
   short-lived test helpers, and internal parent-owned children. This
   keeps the "no manifest for every pun" principle explicit.
2. **Ambient-capability process** — small manifest, e.g. terminal-class
   apps that only need stdio-equivalent capabilities. Manifest declares
   `capabilities.use: [stdio]` and nothing else.
3. **Full component** — driver, subsystem service, or privileged
   application. Manifest declares every IRQ, every I/O port range, every
   MMIO region, every child component it may launch, every service it
   exposes, and its criticality. Runtime denials on undeclared access.

The compiler-and-namespace-derived flow means the *scope of trust* for each
process is visible in a single artifact and reviewable in code review before
it ever runs.

### 1.3 Kernel role

The kernel stays **small and mechanism-only**:

- Provides `KernelObject`s: `Process`, `Thread`, `Job`, `Channel`, `Port`,
  `Vmo`, `Vmar`, `Interrupt`, `Resource`, `PlatformBroker`, and future
  additions.
- Enforces handle rights on every syscall.
- Never parses manifests, never reads BOOTFS, never orchestrates
  shutdown, never blocks on userspace liveness (see §3).
- Provides one privileged escape hatch — `sys_hard_halt()` — that any
  process holding the appropriate capability may call once to
  atomically stop the machine.

---

## 2. Capability primitives (kernel layer)

The kernel exposes capabilities through immutable **`Resource`** objects,
inspired by Zircon's `zx_resource_t`. A `Resource` is:

```rust
pub struct Resource {
    kind:      ResourceKind,   // IoPort | Mmio | Irq (extensible)
    base:      u64,
    len:       u64,
    exclusive: bool,           // exclusive vs shared allocation
    koid:      Koid,
}
```

Design rules, all mirrored from Zircon `zircon/kernel/object/resource_dispatcher.cc`:

- **Immutable** after `Resource::try_create`. Ranges cannot be widened,
  kind cannot be changed.
- **Exclusive vs shared**: exclusive create walks the per-kind registry
  and fails on any intersection with any existing resource of the same
  kind; shared create fails on intersection with any *exclusive*
  resource of the same kind, permits sharing with other `shared`
  resources.
- **Objects created through a resource do not hold a reference** to it:
  once an `Interrupt` object is bound via a `Resource{Irq, N}` handle,
  the resource handle may be closed and the `Interrupt` continues to
  function. Matches Zircon.
- **No root resource** (see §5).
- **No user syscall for `Resource::create` in MVP.** All resources are
  minted kernel-side inside trusted spawn paths driven by manifests
  (§4). When a userspace `component_manager` matures, an intra-kernel
  helper `spawn_with_grants(...)` gains a parent-scoped `resource_split`
  primitive (Zircon-style, parent contains child).

Cross-kind mergers (e.g. unifying the existing `Interrupt` object under
`Resource{Irq, N}`) are separate follow-ups; both may coexist during
migration.

---

## 3. Lifecycle: inversion of control for shutdown

We adopt Fuchsia's rule verbatim: **kernel never blocks on userspace
for lifecycle events**. Source: `src/power/shutdown-shim/main.cc`.

### 3.1 The pattern

- `sys_hard_halt() -> !`: kernel syscall. `disable interrupts →
  render halt screen → stop LAPIC timer → broadcast stop-IPI → hlt loop`.
  No message. No timeout. No wait. Only the process holding the
  appropriate capability (per manifest) may call it.
- Userspace `shutdown-broker` (a component): declares I/O-port capability
  for the 8042 command port (0x64) and criticality in its manifest.
  Listens on a channel. On `shutdown` message: performs 8042 quiesce
  (`out 0x64, 0xAD; out 0x64, 0xA7`), then calls `sys_hard_halt()`.
- Fallback via *criticality*: if `shutdown-broker` crashes without
  issuing `sys_hard_halt` (marked critical in its manifest), the kernel
  scheduler exit-hook triggers `sys_hard_halt` automatically on abnormal
  exit. Never through channel-read-with-timeout; always through
  process-death event.
- Fallback via *manual drive* (Fuchsia's `drive_shutdown_manually`):
  a future `shutdown-shim` component sitting between `init` and
  `shutdown-broker` may attempt orderly shutdown through other
  channels if the primary broker is unresponsive, then `exit(1)`
  itself (which triggers its own criticality path). Out of scope for
  the immediate PR chain.

### 3.2 What kernel never does

- Read from a userspace channel with a timeout on the halt path.
- Poll a userspace process for a response.
- Own knowledge of any device-specific quiesce protocol (PS/2, ACPI reset,
  virtio power). All such knowledge lives in the corresponding
  userspace driver.
- Preserve any legacy "prepare_shutdown" kernel helper for a specific
  device after that device has a userspace driver.

---

## 4. Manifest-driven capability grants

`component_manager` (initially: today's `driver-manager`, evolving) is the
sole reader of manifests at runtime. Kernel enforces the grants, never
parses the file.

### 4.1 Runtime flow

```
BOOTFS → HML/.cm files under /manifests/*.cm
              ↓
     component_manager (reads .cm)
              ↓ syscall: sys_process_spawn_with_grants(elf_vmo, &ResourceGrants)
     kernel: verify caller is component_manager (KOID check),
             mint immutable Resource kernel-objects for each grant
             (fails if any exclusive-conflict with existing resources),
             install them at declared handle slots in the new process's
             handle table, mark critical if manifest requested,
             start the process
              ↓
     driver process starts with its exact capability set,
     no ambient authority
```

### 4.2 Kernel surface added

- `sys_process_spawn_with_grants(elf_vmo, grants: &[ResourceGrant]) -> Result<Handle, ErrorCode>`
- `ResourceGrant { kind, base, len, exclusive, target_handle_slot }` —
  pure data, no pointers, `#[repr(C)]`.
- Caller check: only `component_manager` KOID (`INIT_KOID` in the
  proto phase) may call this syscall. Everyone else gets `AccessDenied`.
- `critical: bool` field in `Process`; immutable after spawn. Set from
  manifest at spawn time only. No syscall to mutate later (Zircon
  learned the hard way — mutable critical is a shantage vector).

### 4.3 Kernel surface **not** added

- No manifest parser in kernel.
- No BOOTFS reader in kernel.
- No HIDL codec in kernel.
- No signed-manifest verification in kernel (deferred until secure
  boot; today's build treats BOOTFS as trusted input).

---

## 5. Explicitly not doing: root resource

Zircon shipped `ZX_RSRC_KIND_ROOT` — a single "does anything" capability
originally handed to userboot. Fuchsia has been *removing* it for years,
splitting it into `system resource` with sub-bases (`ZX_RSRC_SYSTEM_HYPERVISOR_BASE`,
`ZX_RSRC_SYSTEM_POWER_BASE`, etc.).

HuesOS learns from that history: **no root resource, ever**. Every
capability is fine-grained from day one. `component_manager`'s power comes
from being the exclusive caller of `sys_process_spawn_with_grants`, not
from holding a super-key. If we ever add a `system resource`-shaped
concept, it will be per-purpose sub-bases from inception, not a
retrofit split.

---

## 6. Immediate cascade of PRs (visible progress toward §1)

The following PR chain implements the *minimum bridge* between today's
`AcpiBroker`-only capability system and the target above. Each PR is
independently reviewable, land-mergeable, and CI-verified.

**PR-A** — `arch-remove-dead-ps2-driver` — **merged as #119**. Kernel PS/2
driver body removed; only `prepare_shutdown` remains kernel-side, tagged
for removal.

**PR-B** — `resource-object-primitive`. Introduce `KernelObject::Resource`
with full shared/exclusive semantics (all kinds `IoPort|Mmio|Irq`
declared, only IoPort used in MVP). No syscalls. Host-testable
containment, kind equality, overlap detection.

**PR-C** — `manifest-driven-resource-grants`. Extend `.hdriver` proto-manifest
with `resource_kind=... base=... len=... exclusive=...` grammar (this
is proto-.cm; when HMC exists it will *emit* this format, then evolve).
Add `sys_process_spawn_with_grants` syscall gated on init KOID. Add
`critical=true` manifest field, immutable after spawn. `driver-manager`
(proto-component_manager) reads the manifest, calls the syscall,
kernel mints Resources and installs them at declared handle slots.

**PR-D** — `userspace-shutdown-broker` + `sys-hard-halt` + `critical-process`.
New `shutdown-broker` component with `resource_kind=ioport base=0x64
len=1 exclusive=true critical=true` manifest. `sys_hard_halt() -> !`
syscall added, gated on capability held by shutdown-broker only. Old
`SystemShutdown` syscall + kernel-side `shutdown::request` orchestration
removed. Terminal `shutdown` message flows: terminal → init →
shutdown-broker → 8042 quiesce → `sys_hard_halt()`. Fallback: critical
flag triggers kernel hard-halt on abnormal broker exit.

**PR-E** — `arch-drop-ps2-module`. Delete `crates/huesos-arch/src/x86_64/keyboard.rs`
entirely; no one references it after PR-D. Micropatch.

**PR-F (deferred)** — `acpi-broker-uses-resources`. Refactor `AcpiBroker`
`system_io: Vec<SystemIoGrant>` into `Vec<Koid>` referencing Resources.
`AcpiBroker` becomes a thin authorization wrapper over the primitive
Resource layer. Does not block H3.

**PR-G** — `fb-frame-draw-capability` — **landed**. Gate the
`Syscall::FramebufferBlit` syscall on a new `FrameDraw` capability
(`ResourceKind::FrameDraw = 6`, install at `INIT_FRAME_DRAW_HANDLE = 6`
in the initial process). Kernel-side `require_resource_of_kind` runs
the capability check **before** the caller's `*const FramebufferBlitArgs`
is dereferenced, so a forged or stale handle cannot leak address-space
or framebuffer-geometry information. Mint is gated on the root
supervisor KOID predicate (the same predicate that gates
`sys_resource_create`), so only init can produce a `FrameDraw`
resource. Transfer path uses the existing `write_handle` channel
mechanism with `Rights::TRANSFER` on the source handle; the kernel
rejects any blit from a process that does not own a live
`FrameDraw` resource with `ErrorCode::AccessDenied`. `FramebufferInfo`
(geometry query) stays public because resolution is observable from
the visible image and pixel format is hardware-fixed. See
[`docs/FRAMEBUFFER_POLICY.md`](FRAMEBUFFER_POLICY.md) for the threat
model, ABI delta, and the rationale for keeping the framebuffer
driver inside the kernel (panic screen, shutdown screen, boot
splash) instead of moving it to a userspace driver-host.

---

## 7. Long-term cascade (post immediate, months of work)

Each of these becomes its own multi-PR effort with its own architecture
review. They are listed here so future work is anchored in the same
target picture.

**LT-1 — HuesOS Manifest Compiler (HMC).** Standalone Rust tool that
parses `.hml` (JSON-flavoured) and emits `.cm`. Schema versioned.
Cross-validates HIDL references. Runs at build time, output committed
alongside source or generated by build.rs.

**LT-2 — HIDL codec.** IDL parser + Rust code generator. Emits
`server::` and `client::` trait pairs plus wire-format serializers.
Integrated into HMC for interface-name validation and into build.rs for
per-crate codegen.

**LT-3 — `.cm` binary format.** Compact serialization (HIDL-defined
struct). Versioned header. Loader in userspace, validated against the
current supported version at load time.

**LT-4 — `component_manager` (userspace root).** Replaces or absorbs
today's `driver-manager`. Reads `.cm`. Builds component topology.
Computes namespaces declaratively. Uses `sys_process_spawn_with_grants`.
Owns the runtime lifecycle graph.

**LT-5 — Namespace-based service discovery.** Each child sees only the
services its manifest declared. No ambient `/svc` for anyone; every path
is a manifest-declared capability route.

**LT-6 — Resource split-syscall.** Once `component_manager` matures,
introduce `sys_resource_split(parent, child_base, child_len, exclusive)`
so `component_manager` can carve a big incoming resource (from
platform-bus enumeration) into per-driver slices without kernel needing
to know the driver taxonomy. Zircon-parity.

**LT-7 — Signed manifests.** Cryptographic verification of `.cm` at load
time, tied to secure-boot chain. Deferred until crypto primitives land
in the kernel/HAL layer.

---

## 8. Explicit non-goals for the MVP path

- Root resource (§5).
- Kernel-side manifest parsing.
- Kernel-side channel read with timeout on halt path.
- Mutable criticality after spawn.
- Multi-tenant driver-manager (one kernel-trusted `component_manager` for
  now; nested trusted managers are LT-4 topic).
- Compatibility with Fuchsia FIDL or component manifests. HIDL/`.cm` are
  HuesOS-native, inspired but not compatible.
