//! # HuesOS ABI
//!
//! The single source of truth for the kernel<->userspace syscall boundary:
//! syscall numbers, error codes, and any plain-old-data structs passed by
//! value across `syscall`/`sysret`.
//!
//! This crate is deliberately tiny, `no_std`, `#![no_builtins]`-friendly,
//! and has **zero dependencies** on either `huesos-kernel` or any
//! userspace runtime. Both `huesos-syscalls` (the kernel-side dispatcher)
//! and `libcanvas` (the userspace-side safe wrapper library) depend on
//! this crate instead of hand-copying magic numbers into two places that
//! could silently drift out of sync — which is exactly the kind of bug
//! that would otherwise show up as "works until someone reorders an enum".

#![no_std]
#![warn(missing_docs)]

/// Ring-3 ACPI manager broker and immutable table-archive protocol.
pub mod acpi_broker;

/// Async BlockDevice wire protocol.
pub mod block;

/// VolumeManager wire protocol.
pub mod volume;

/// Native Hxfs handle-first service wire protocol.
pub mod hxfs;

/// Immutable ACPI table-archive decoding and physical-address index.
///
/// Used by both the kernel archive builder and the Ring-3 `acpi-manager` to
/// agree on one decoded view and to consult the deny-by-default physical
/// range index before any userspace mapping.
pub mod acpi_archive;

/// Boot-time storage hardware metadata shared from the kernel to init and
/// DriverManager.
pub mod storage_boot;

/// HBI boot-driver manifest ABI.
pub mod hbi_boot {
    /// Magic for `/storage/boot-drivers.manifest`.
    pub const MAGIC: u32 = 0x4844_5242;
    /// Current manifest version.
    pub const VERSION: u16 = 1;
    /// Maximum number of boot-critical drivers described by one manifest.
    pub const MAX_BOOT_DRIVERS: usize = 8;
    /// Fixed path storage per manifest entry.
    pub const PATH_BYTES: usize = 64;

    /// Header for the boot-driver manifest.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct BootDriverManifestHeader {
        /// [`MAGIC`].
        pub magic: u32,
        /// [`VERSION`].
        pub version: u16,
        /// Number of following [`BootDriverManifestEntry`] records.
        pub entry_count: u16,
    }

    /// One storage-critical DriverHost entry.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct BootDriverManifestEntry {
        /// NUL-padded DriverHost ELF path inside HBI BOOTFS.
        pub elf_path: [u8; PATH_BYTES],
        /// NUL-padded `.hdriver` manifest path inside HBI BOOTFS.
        pub manifest_path: [u8; PATH_BYTES],
        /// Reserved for future boot policy flags. Must be zero for v1.
        pub flags: u32,
    }

    impl Default for BootDriverManifestEntry {
        fn default() -> Self {
            Self {
                elf_path: [0; PATH_BYTES],
                manifest_path: [0; PATH_BYTES],
                flags: 0,
            }
        }
    }

    /// Validate a manifest header without dereferencing entry paths.
    pub const fn validate_header(header: BootDriverManifestHeader) -> bool {
        header.magic == MAGIC
            && header.version == VERSION
            && (header.entry_count as usize) <= MAX_BOOT_DRIVERS
    }
}

/// Deny-by-default policy primitives for the Ring-3 ACPI broker: an
/// append-only audit ring and a fixed-window rate limiter. Pure, `no_std`,
/// and exercised directly by host tests.
pub mod broker_policy;

/// Syscall number enumeration. The numeric value (not the variant name) is
/// what actually crosses the ABI boundary in `rax`, so **never remove or
/// reorder a variant** — only ever append new ones. Removing a syscall
/// that shipped means leaving its number permanently retired (turn it
/// into `Reserved`-style dead entry in the dispatcher) rather than reusing
/// it for something else.
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Syscall {
    /// No-op; always succeeds. Useful for latency measurement / liveness
    /// checks.
    Nop = 0,
    /// Create a VMO (a block of anonymous memory) of a given size.
    VmoCreate = 1,
    /// Close a handle, releasing this process's reference to whatever
    /// object it named.
    HandleClose = 2,
    /// Duplicate a handle, optionally with reduced rights.
    HandleDuplicate = 3,
    /// Yield the current thread's remaining time slice cooperatively.
    Yield = 4,
    /// Read bytes from a VMO.
    VmoRead = 5,
    /// Write bytes to a VMO.
    VmoWrite = 6,
    /// Create a connected pair of channel endpoints.
    ChannelCreate = 7,
    /// Write a message to a channel.
    ChannelWrite = 8,
    /// Read a message from a channel. `arg5 != 0` requests blocking wait.
    ChannelRead = 9,
    /// Exit the current process with a status code. Never returns.
    ProcessExit = 10,
    /// Write raw bytes to the kernel debug log (serial console). An MVP
    /// substitute for a real console/VFS-backed stdout.
    DebugWrite = 11,
    /// Query framebuffer geometry (width/height/pitch/bpp/color masks).
    FramebufferInfo = 12,
    /// Copy (blit) a rectangular region from a VMO into the real
    /// framebuffer. This is the *only* way userspace ever touches actual
    /// video memory — it never gets a mapping of the framebuffer itself,
    /// only this narrow, bounds-checked copy operation.
    ///
    /// Capability check: the caller must present a live `FrameDraw`
    /// [`Resource`](../../huesos_object/struct.Resource.html) handle in
    /// `a1`. The kernel will reject the call with `AccessDenied` if
    /// `a1` does not name a `FrameDraw` resource owned by the caller
    /// (or names any other object, including a VMO). `a2` points to a
    /// [`FramebufferBlitArgs`] with the source VMO and rectangle
    /// geometry. This is the only framebuffer syscall requiring a
    /// capability; [`Self::FramebufferInfo`] stays public because
    /// geometry (resolution, pixel format) is not sensitive.
    ///
    /// Policy: the `FrameDraw` resource is minted by the root userspace
    /// supervisor (`init`) and transferred to the legitimate graphics
    /// stack (`libcanvas`-using processes) over a channel. See
    /// `docs/ARCHITECTURE_ROADMAP.md` § framebuffer.
    FramebufferBlit = 13,
    /// Create a suspended userspace process object and its root VMAR.
    ///
    /// Skeleton ABI for the approved Zircon-like launch path: the process is
    /// created first, memory is mapped into its root VMAR separately, then a
    /// thread is created and started explicitly.
    ProcessCreate = 14,
    /// Wait for a process exit code (blocking). Writes `i64` at `arg2`.
    /// Legacy note: older kernels returned `ShouldWait` while
    /// the process is still running.
    ProcessWait = 15,
    /// Create a suspended thread object in an existing process.
    ThreadCreate = 16,
    /// Start a suspended thread at an entry point/stack pointer. The kernel
    /// creates the child bootstrap channel endpoint as handle 1 in the child
    /// process and returns the parent endpoint to the caller.
    ThreadStart = 17,
    /// Map a VMO into a VMAR. Arguments are passed via `VmarMapArgs` because
    /// the operation needs more fields than the 5-register syscall ABI can
    /// comfortably carry.
    VmarMap = 18,
    /// Create a Port object, a non-blocking userspace-visible event queue.
    PortCreate = 19,
    /// Read one packet from a Port. `arg3 != 0` blocks. Returns `ShouldWait`
    /// if no packet is queued.
    PortRead = 20,
    /// Create an Interrupt object for a kernel IRQ bridge. The first
    /// implementation supports IRQ1 (keyboard) only.
    InterruptCreate = 21,
    /// Bind an Interrupt object to a Port so IRQ events enqueue Port packets.
    InterruptBindPort = 22,
    /// Read channel bytes and receive transferred handles.
    ChannelReadEtc = 23,
    /// Read the monotonic scheduler clock in 100 Hz ticks.
    ClockGetMonotonic = 24,
    /// Request an orderly system shutdown. Kernel policy restricts this to
    /// the root userspace supervisor.
    SystemShutdown = 25,
    /// Query a process exit code without blocking. Returns `ShouldWait` while
    /// the process is still running.
    ProcessGetExitCode = 26,
    /// Submit one structurally validated request through an ACPI broker
    /// capability and write an [`acpi_broker::Response`].
    AcpiBrokerCall = 27,
    /// Create a VMO with explicit mapping rights. `a1` is the size, `a2` is
    /// [`vmo_create_flags`], and `a3` is the output handle pointer. This is
    /// the capability-safe successor to [`Syscall::VmoCreate`] for executable
    /// ELF segments.
    VmoCreateEx = 28,
    /// Remove a page-aligned mapping range from a VMAR. Subranges split the
    /// original mapping metadata transactionally. `a1` points to
    /// [`VmarOpArgs`].
    VmarUnmap = 29,
    /// Change permissions on a page-aligned VMAR mapping range. Subranges split
    /// the original mapping metadata transactionally. `a1` points to
    /// [`VmarOpArgs`].
    VmarProtect = 30,
    /// Peek at the next channel message without dequeueing it. `a1` points
    /// to [`ChannelPeekArgs`]. Returns the message's byte size, handle
    /// count, and an opaque cookie that [`Syscall::ChannelConsume`] uses to
    /// dequeue the exact same message.
    ChannelPeek = 31,
    /// Dequeue and copy out the message identified by a cookie from
    /// [`Syscall::ChannelPeek`]. `a1` points to [`ChannelConsumeArgs`].
    /// This is the second half of the peek/consume split that replaces the
    /// legacy truncating [`Syscall::ChannelRead`].
    ChannelConsume = 32,
    /// Multiplexed wait on multiple objects. `a1` points to
    /// [`WaitSetWaitArgs`]. Returns when any (or all, per `mode`)
    /// of the specified objects have the awaited signals active.
    WaitSetWait = 33,
    /// Mint an immutable [`Resource`](../../huesos_object/struct.Resource.html)
    /// capability object and install its handle in the caller's handle
    /// table. `a1` is the [`ResourceKindAbi`] tag, `a2` is `base`, `a3`
    /// is `len`, `a4 != 0` means exclusive, `a5` is a
    /// `*mut HandleValue` output pointer. Kernel policy currently
    /// restricts this call to the root userspace supervisor (init
    /// KOID); see `docs/ARCHITECTURE_ROADMAP.md` §4.
    ResourceCreate = 34,
    /// Mark the target process as critical: its abnormal exit will
    /// trigger a kernel-driven hard halt. Immutable after the first
    /// successful call; caller must be the root userspace supervisor.
    /// `a1` is a process handle owned by the caller.
    ProcessMarkCritical = 35,
    /// Atomic system halt. Never returns. Caller must hold a
    /// `PowerControl` [`Resource`] handle passed in `a1`. Inspired by
    /// Fuchsia's inversion-of-control shutdown model
    /// (`src/power/shutdown-shim/main.cc`); see
    /// `docs/ARCHITECTURE_ROADMAP.md` §3.
    HardHalt = 36,
    /// Write one byte to an x86 I/O port. `a1` is an `IoPort`
    /// [`Resource`] handle owned by the caller, `a2` is the port
    /// number (must fall inside the resource's `[base, base+len)`
    /// range), `a3` is the byte value.
    IoPortWrite8 = 37,
    /// Read one byte from an x86 I/O port. Same handle/port contract
    /// as [`Self::IoPortWrite8`]; the read byte is returned in the
    /// low 8 bits of the syscall's `Ok(i64)` value.
    IoPortRead8 = 38,
    /// Set a process's default CPU affinity (dense CPU index) before its
    /// initial thread starts. `a1` is a process handle, `a2` is the CPU index.
    ProcessSetAffinity = 39,
    /// Number of online CPUs (dense CPU count, not LAPIC IDs).
    SystemCpuCount = 40,
    /// Current dense CPU index.
    SystemCurrentCpu = 41,
    /// Set a process affinity mask before its initial thread starts. `a1` is a
    /// process handle, `a2` is the CPU mask, `a3` is the home CPU.
    ProcessSetAffinityMask = 42,
    /// Query process affinity. `a1` process handle, `a2=*mut u64 mask`,
    /// `a3=*mut u64 home_cpu`.
    ProcessGetAffinity = 43,
    /// Reserve a child VMAR inside an existing VMAR. `a1` points to
    /// [`VmarCreateChildArgs`].
    VmarCreateChild = 44,
    /// Create a level-triggered signal object. `a1` is `*mut HandleValue`.
    SignalCreate = 45,
    /// Set a signal object. `a1` is a Signal handle with WRITE rights.
    SignalSet = 46,
    /// Clear a signal object. `a1` is a Signal handle with WRITE rights.
    SignalClear = 47,
    /// Bind a Port to receive one process-exit packet when the process exits.
    /// `a1` points to [`ProcessBindExitPortArgs`].
    ProcessBindExitPort = 48,
    /// Set scheduler flags on a process before its initial thread starts.
    /// `a1` is a process handle, `a2` is a [`scheduler_flags`] mask.
    ProcessSetSchedulerFlags = 49,
    /// Return a handle to the caller's current Job. `a1=*mut HandleValue`.
    JobDefault = 50,
    /// Create a child Job. `a1` points to [`JobCreateArgs`].
    JobCreate = 51,
    /// Replace a Job's limits. `a1` points to [`JobSetLimitsArgs`].
    JobSetLimits = 52,
    /// Bind a Port for quota-exhaustion packets. `a1` points to
    /// [`JobBindQuotaPortArgs`].
    JobBindQuotaPort = 53,
    /// Create a process inside an explicit Job. `a1` points to
    /// [`ProcessCreateInJobArgs`].
    ProcessCreateInJob = 54,
    /// Set a Job diagnostic name. `a1` points to [`JobSetNameArgs`].
    JobSetName = 55,
    /// Map an `Mmio` or `DmaPool` Resource into the caller's root VMAR at a
    /// fixed userspace address. `a1` points to [`ResourceMapArgs`].
    ResourceMap = 56,
    /// Create an Interrupt object authorized by an `Irq` Resource. `a1` is the
    /// Resource handle, `a2` is the IRQ/vector, `a3=*mut HandleValue`.
    InterruptCreateForResource = 57,
    /// Queue one packet to a Port. `a1` is a Port handle with WRITE rights,
    /// `a2=*const PortPacket`.
    PortQueue = 58,
    /// Copy the bootloader/kernel volume key blob into `a1`
    /// (`*mut [u8; 32]`). Returns `NotFound` when no key blob was
    /// baked into this kernel build (plain-volume deployments).
    /// Stage D bootloader KeyProvider handoff.
    VolumeKeyGet = 59,
}

impl Syscall {
    /// Total number of defined syscalls (i.e. one past the highest
    /// currently-assigned number). The dispatcher uses this to reject
    /// obviously-out-of-range numbers before a `match`.
    pub const COUNT: u64 = 60;

    /// Convert a raw syscall number back into a [`Syscall`], if valid.
    pub const fn from_raw(n: u64) -> Option<Self> {
        Some(match n {
            0 => Self::Nop,
            1 => Self::VmoCreate,
            2 => Self::HandleClose,
            3 => Self::HandleDuplicate,
            4 => Self::Yield,
            5 => Self::VmoRead,
            6 => Self::VmoWrite,
            7 => Self::ChannelCreate,
            8 => Self::ChannelWrite,
            9 => Self::ChannelRead,
            10 => Self::ProcessExit,
            11 => Self::DebugWrite,
            12 => Self::FramebufferInfo,
            13 => Self::FramebufferBlit,
            14 => Self::ProcessCreate,
            15 => Self::ProcessWait,
            16 => Self::ThreadCreate,
            17 => Self::ThreadStart,
            18 => Self::VmarMap,
            19 => Self::PortCreate,
            20 => Self::PortRead,
            21 => Self::InterruptCreate,
            22 => Self::InterruptBindPort,
            23 => Self::ChannelReadEtc,
            24 => Self::ClockGetMonotonic,
            25 => Self::SystemShutdown,
            26 => Self::ProcessGetExitCode,
            27 => Self::AcpiBrokerCall,
            28 => Self::VmoCreateEx,
            29 => Self::VmarUnmap,
            30 => Self::VmarProtect,
            31 => Self::ChannelPeek,
            32 => Self::ChannelConsume,
            33 => Self::WaitSetWait,
            34 => Self::ResourceCreate,
            35 => Self::ProcessMarkCritical,
            36 => Self::HardHalt,
            37 => Self::IoPortWrite8,
            38 => Self::IoPortRead8,
            39 => Self::ProcessSetAffinity,
            40 => Self::SystemCpuCount,
            41 => Self::SystemCurrentCpu,
            42 => Self::ProcessSetAffinityMask,
            43 => Self::ProcessGetAffinity,
            44 => Self::VmarCreateChild,
            45 => Self::SignalCreate,
            46 => Self::SignalSet,
            47 => Self::SignalClear,
            48 => Self::ProcessBindExitPort,
            49 => Self::ProcessSetSchedulerFlags,
            50 => Self::JobDefault,
            51 => Self::JobCreate,
            52 => Self::JobSetLimits,
            53 => Self::JobBindQuotaPort,
            54 => Self::ProcessCreateInJob,
            55 => Self::JobSetName,
            56 => Self::ResourceMap,
            57 => Self::InterruptCreateForResource,
            58 => Self::PortQueue,
            59 => Self::VolumeKeyGet,
            _ => return None,
        })
    }
}

/// Wire-format resource kind for [`Syscall::ResourceCreate`].
///
/// Values match `huesos_object::ResourceKind` numerically so the
/// syscall handler can round-trip the tag without a lookup table.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKindAbi {
    /// x86 port I/O space.
    IoPort = 1,
    /// Physical memory-mapped I/O region.
    Mmio = 2,
    /// Physical interrupt vector / IRQ line.
    Irq = 3,
    /// Authority to invoke the atomic-halt / reboot / (future)
    /// mexec/suspend syscalls. Holding this handle is the
    /// capability check for [`Syscall::HardHalt`]; a `PowerControl`
    /// resource has no meaningful `base`/`len`, so both are fixed to
    /// zero at mint time. See
    /// `docs/ARCHITECTURE_ROADMAP.md` §3.
    PowerControl = 4,
    /// Preallocated physically pinned DMA pool for userspace DriverHosts.
    ///
    /// The `base`/`len` range names the device-visible physical DMA window.
    /// The kernel is responsible for reserving and mapping the backing pages;
    /// the handle is the authority to use the range, not the mapping itself.
    DmaPool = 5,
    /// Authority to invoke [`Syscall::FramebufferBlit`]. Holding this
    /// handle is the capability check that lets a userspace process
    /// copy (blit) a rectangle from a VMO it owns onto the real
    /// framebuffer. The handle has no meaningful `base`/`len` — both
    /// are forced to zero at mint time, exactly like
    /// [`Self::PowerControl`]. A `FrameDraw` resource is a single
    /// binary authority, not a per-rectangle range, so a single
    /// mint-then-transfer is enough to onboard a graphics process.
    ///
    /// Minted exclusively by the root userspace supervisor (`init`) and
    /// transferred to legitimate graphics-stack processes (`libcanvas`
    /// consumers such as `terminal`, `doom`, and `canvas-hell`) over a
    /// channel. No process can mint its own `FrameDraw` capability
    /// because `sys_resource_create` is gated on the root-supervisor
    /// KOID predicate.
    FrameDraw = 6,
}

impl ResourceKindAbi {
    /// Decode a wire value without constructing an invalid Rust enum.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            1 => Self::IoPort,
            2 => Self::Mmio,
            3 => Self::Irq,
            4 => Self::PowerControl,
            5 => Self::DmaPool,
            6 => Self::FrameDraw,
            _ => return None,
        })
    }
}

/// Syscall error codes (subset of the `zx_status_t` design: small negative
/// integers, `0` reserved for "not an error"/success at the raw ABI
/// level).
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    /// Invalid argument (null pointer, zero length where one is required,
    /// value out of the accepted range, etc).
    InvalidArgs = -10,
    /// The handle value does not name any object owned by this process.
    BadHandle = -11,
    /// The handle names an object, but not of the type this syscall
    /// expects (e.g. passing a Channel handle to a VMO syscall).
    WrongType = -12,
    /// The handle's rights don't permit this operation.
    AccessDenied = -13,
    /// Out of memory (physical frames exhausted, or a requested size
    /// exceeds an enforced limit).
    NoMemory = -14,
    /// The resource is busy; try again.
    Busy = -15,
    /// A non-blocking call would have to block to complete (e.g. reading
    /// an empty channel) — not a real error, just "nothing to do yet".
    ShouldWait = -16,
    /// A timed wait expired without the condition becoming true.
    TimedOut = -20,
    /// Not found.
    NotFound = -17,
    /// No framebuffer is available on this system.
    NoFramebuffer = -18,
    /// This syscall number is not recognized by this kernel build.
    NotSupported = -19,
    /// A required kernel subsystem was unavailable or violated its state
    /// contract; callers must not retry without an external state change.
    Internal = -21,
    /// The peer endpoint is closed and no queued message remains.
    PeerClosed = -22,
}

impl ErrorCode {
    /// Convert a raw (negative) return value back into an [`ErrorCode`],
    /// if it matches a known code. Positive/zero values are successful
    /// results, not errors — callers should check sign before calling this.
    pub const fn from_raw(n: i64) -> Option<Self> {
        Some(match n {
            -10 => Self::InvalidArgs,
            -11 => Self::BadHandle,
            -12 => Self::WrongType,
            -13 => Self::AccessDenied,
            -14 => Self::NoMemory,
            -15 => Self::Busy,
            -16 => Self::ShouldWait,
            -20 => Self::TimedOut,
            -17 => Self::NotFound,
            -18 => Self::NoFramebuffer,
            -19 => Self::NotSupported,
            -21 => Self::Internal,
            -22 => Self::PeerClosed,
            _ => return None,
        })
    }

    /// Human-readable description, safe to print from either kernel or
    /// userspace context (`no_std`, no allocation).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgs => "invalid arguments",
            Self::BadHandle => "bad handle",
            Self::WrongType => "wrong handle type",
            Self::AccessDenied => "access denied",
            Self::NoMemory => "out of memory",
            Self::Busy => "resource busy",
            Self::ShouldWait => "would block",
            Self::TimedOut => "timed out",
            Self::NotFound => "not found",
            Self::NoFramebuffer => "no framebuffer available",
            Self::NotSupported => "syscall not supported",
            Self::Internal => "internal kernel state error",
            Self::PeerClosed => "channel peer closed",
        }
    }
}

/// Encode a `Result<i64, ErrorCode>` into the raw `u64` value the kernel
/// writes back to `SyscallFrame::num` for `sysret` to deliver to the
/// caller. This is the **single point** in the codebase that decides the
/// syscall wire format:
///
/// - `Ok(v)` is delivered as the raw bit pattern of `v` treated as `u64`.
///   The caller (see `libcanvas::raw::decode`) re-reads it as `i64` and
///   observes a non-negative value.
/// - `Err(e)` is delivered as the raw bit pattern of `e as i32`
///   sign-extended to `i64` and reinterpreted as `u64`. The caller reads
///   `i64`, sees a negative value, and passes it to
///   [`ErrorCode::from_raw`] to recover the original error.
///
/// The `as i32 as i64 as u64` chain looks noisy but is intentional and
/// correct exactly for these three casts:
///
/// - `e as i32` reads the discriminant of a `#[repr(i32)]` enum.
/// - `as i64` sign-extends (Rust guarantees this for signed-integer casts).
/// - `as u64` is a bitwise reinterpretation with no numeric change.
///
/// Extracting the encoder here means every syscall handler goes through
/// the same audited translation and a host test locks the exact bit
/// pattern for each variant. If `#[repr(i32)]` were ever removed from
/// [`ErrorCode`] (e.g. a well-meaning refactor to `#[repr(u32)]`), the
/// numeric value of `e as i32` would still be the negative discriminant
/// but the reinterpretation cost would be zero and the sign-extension
/// would silently propagate a wrong upper half. The unit test in this
/// module catches that class of regression.
#[inline]
pub const fn encode_syscall_result(result: Result<i64, ErrorCode>) -> u64 {
    match result {
        Ok(v) => v as u64,
        Err(e) => (e as i32) as i64 as u64,
    }
}

/// Userspace handle value (an opaque index into the calling process's
/// handle table — meaningless outside that process).
pub type HandleValue = u32;
/// Reserved value meaning "no handle" / invalid handle.
pub const INVALID_HANDLE: HandleValue = 0;
/// Initial bootstrap channel handle number installed in a newly-started
/// child process by `Syscall::ThreadStart`.
pub const BOOTSTRAP_HANDLE: HandleValue = 1;
/// Read-only HBI BOOTFS VMO installed by the kernel in the initial process.
pub const INIT_BOOTFS_HANDLE: HandleValue = 2;
/// Immutable validated ACPI table archive installed in the initial process.
pub const INIT_ACPI_TABLES_HANDLE: HandleValue = 3;
/// Deny-by-default privileged ACPI broker capability for the initial process.
pub const INIT_ACPI_BROKER_HANDLE: HandleValue = 4;
/// Kernel-produced storage boot-info VMO installed in the initial process.
pub const INIT_STORAGE_BOOT_INFO_HANDLE: HandleValue = 5;
/// `FrameDraw` [`Resource`](../../huesos_object/struct.Resource.html)
/// capability installed in the initial process. `init` mints this once
/// at boot (via [`Syscall::ResourceCreate`]) and transfers it to
/// legitimate graphics-stack processes (`libcanvas` consumers such as
/// `terminal`, `doom`, and `canvas-hell`) over a channel. The handle
/// is the only authority that lets a process call
/// [`Syscall::FramebufferBlit`]; the kernel rejects any blit whose
/// `a1` is not a live caller-owned `FrameDraw` resource.
pub const INIT_FRAME_DRAW_HANDLE: HandleValue = 6;

/// Stable process exit codes used when the kernel terminates a process after
/// an unhandled ring-3 CPU exception.
pub mod fault_exit {
    /// User page fault (#PF).
    pub const PAGE_FAULT: i64 = -0x1001;
    /// User general-protection fault (#GP).
    pub const GENERAL_PROTECTION: i64 = -0x1002;
    /// User invalid opcode (#UD).
    pub const INVALID_OPCODE: i64 = -0x1003;
    /// User divide error (#DE).
    pub const DIVIDE_ERROR: i64 = -0x1004;
    /// User alignment check (#AC).
    pub const ALIGNMENT_CHECK: i64 = -0x1005;
    /// Kernel could not recover the task's validated startup record.
    pub const STARTUP_FAILED: i64 = -0x10ff;
}

/// Rights bitmask, mirrored from `huesos-object::Rights` numerically (kept
/// here too so userspace doesn't need to depend on the kernel-only object
/// crate just to duplicate a handle with reduced rights).
pub mod rights {
    /// May duplicate this handle.
    pub const DUPLICATE: u32 = 1 << 0;
    /// May transfer this handle to another process via a channel.
    pub const TRANSFER: u32 = 1 << 1;
    /// May read from the underlying object.
    pub const READ: u32 = 1 << 2;
    /// May write to the underlying object.
    pub const WRITE: u32 = 1 << 3;
    /// May execute/map-executable the underlying object.
    pub const EXECUTE: u32 = 1 << 4;
    /// May map the underlying object into an address space.
    pub const MAP: u32 = 1 << 5;
    /// Duplicate with the exact same rights as the source handle.
    pub const SAME_RIGHTS: u32 = 1 << 31;

    /// Return the rights required to perform a VMAR mapping with `flags`.
    ///
    /// `MAP` is always required. Read/write/execute permissions are separate
    /// capabilities so reducing a VMO handle's rights cannot be bypassed by
    /// requesting a stronger page-table mapping.
    pub const fn mapping_required(flags: u32) -> u32 {
        let mut required = MAP;
        if flags & super::vmar_flags::READ != 0 {
            required |= READ;
        }
        if flags & super::vmar_flags::WRITE != 0 {
            required |= WRITE;
        }
        if flags & super::vmar_flags::EXECUTE != 0 {
            required |= EXECUTE;
        }
        required
    }
}

/// Flags accepted by [`Syscall::VmoCreateEx`].
pub mod vmo_create_flags {
    /// Grant the returned VMO capability the right to create executable
    /// mappings. The page mapping still remains subject to W^X.
    pub const EXECUTABLE: u32 = 1 << 0;
}

/// Lowest userspace virtual address accepted by the root VMAR. The first
/// 64 KiB stay unmapped as a low/null-pointer guard.
pub const USER_ASPACE_BASE: u64 = 0x0000_0000_0001_0000;
/// Exclusive upper bound of the canonical lower-half userspace address
/// space used by HuesOS root VMARs.
pub const USER_ASPACE_END: u64 = 0x0000_8000_0000_0000;
/// Size of the root userspace VMAR.
pub const USER_ASPACE_SIZE: u64 = USER_ASPACE_END - USER_ASPACE_BASE;

/// Top of the initial stack used by the userspace process launcher.
pub const USER_STACK_TOP: u64 = 0x0000_7fff_ff00_0000;
/// Size of the initial userspace stack mapped by the userspace process launcher.
///
/// 128 KiB: the original 64 KiB overflowed for services that do
/// real work on the boot call chain. The hxfs-service's
/// encrypted+compressed write/read path needs deep frames (the
/// writer's `write_data_blocks` and `copy_extent` keep several
/// 4 KiB crypto scratch buffers live, and the boot self-check adds
/// probe buffers on top of the mount chain); its first on-target
/// write round-trip faulted ~62 KiB deep. The mapping is virtual
/// reservation, so 128 KiB is cheap for every process.
pub const USER_STACK_SIZE: u64 = 4096 * 256;
// 1 MiB: the hxfs-service mount frame constructs the writer (4096
// extents ~ 262 KiB) on the stack before moving it to the heap, and
// the load/crypto frames sit on top; 512 KiB overflowed on target.
// Virtual reservation, cheap for every process.
// 512 KiB: the hxfs-service mount frame carries the writer's fixed
// arrays (~80 KiB at 1024 extents) plus the crypto read/write
// frames on the boot call chain; 256 KiB overflowed on target
// (user-fault ~264 KiB deep). Virtual reservation, cheap.

/// Base of the userspace heap region mapped by the process launcher.
///
/// Every user process gets this fixed RW, non-executable region so
/// a process that installs a `#[global_allocator]` (the hxfs-service
/// does) can allocate from boot without a mapping syscall. The
/// region is raw-mapped alongside the stack and the ELF segments,
/// outside the VMAR bookkeeping, and is inert for processes that
/// never touch it.
pub const USER_HEAP_BASE: u64 = 0x0000_7000_0000;
/// Size of the userspace heap region mapped by the process launcher.
pub const USER_HEAP_SIZE: u64 = 18 * 1024 * 1024;
// 18 MiB: the hxfs-service bump allocator holds the runtime, the
// package-sized blob payloads, AND the live scrub's whole-object
// buffer (the 16 MiB probe file is buffered by scrub()). A bump
// allocator with no free() must be sized for the worst single
// allocation chain; chunked scrub (a known follow-up) will let this
// shrink again.

/// Scheduler flags for [`Syscall::ProcessSetSchedulerFlags`].
pub mod scheduler_flags {
    /// User tasks in this process may be moved by token-based idle stealing,
    /// within the process affinity mask. Disabled by default.
    pub const STEAL_OPT_IN: u32 = 1 << 0;
}

/// VMAR mapping flags for [`Syscall::VmarMap`].
pub mod vmar_flags {
    /// Map pages readable from userspace.
    pub const READ: u32 = 1 << 0;
    /// Map pages writable from userspace.
    pub const WRITE: u32 = 1 << 1;
    /// Map pages executable from userspace.
    pub const EXECUTE: u32 = 1 << 2;
    /// Mapping is user-accessible. This is explicit even though VMARs are
    /// userspace address-space objects, so the permission contract is clear
    /// at the ABI boundary.
    pub const USER: u32 = 1 << 3;
    /// Use the exact virtual address in `VmarMapArgs.addr`. The first VMAR
    /// implementation requires this flag for every mapping.
    pub const SPECIFIC: u32 = 1 << 4;
}

/// Framebuffer geometry and pixel format, as returned by
/// [`Syscall::FramebufferInfo`]. `#[repr(C)]` and plain-old-data so it can
/// be copied byte-for-byte across the syscall boundary via a pointer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FramebufferInfo {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per scanline (may be larger than `width * bytes_per_pixel`
    /// due to alignment padding — always use this, never assume tightly
    /// packed rows).
    pub pitch: u32,
    /// Bits per pixel (typically 32).
    pub bpp: u16,
    /// Number of bits in the red channel.
    pub red_mask_size: u8,
    /// Bit position of the red channel's least significant bit.
    pub red_mask_shift: u8,
    /// Number of bits in the green channel.
    pub green_mask_size: u8,
    /// Bit position of the green channel's least significant bit.
    pub green_mask_shift: u8,
    /// Number of bits in the blue channel.
    pub blue_mask_size: u8,
    /// Bit position of the blue channel's least significant bit.
    pub blue_mask_shift: u8,
}

/// Arguments for [`Syscall::FramebufferBlit`], passed by pointer (the
/// syscall ABI only has 5 register-sized argument slots, and this needs
/// more fields than that comfortably fits).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FramebufferBlitArgs {
    /// Handle to a VMO containing source pixels in the same pixel format
    /// described by [`FramebufferInfo`]. Row spacing is given by
    /// [`FramebufferBlitArgs::src_stride`].
    pub vmo: HandleValue,
    /// Byte offset into the VMO where pixel data starts.
    pub vmo_offset: u64,
    /// Width, in pixels, of the source rectangle within the VMO.
    pub src_width: u32,
    /// Height, in pixels, of the source rectangle within the VMO.
    pub src_height: u32,
    /// Bytes between the starts of adjacent source rows. This may exceed the
    /// rectangle's row size when presenting a dirty region of a larger VMO.
    pub src_stride: u32,
    /// Destination X coordinate on the real framebuffer.
    pub dst_x: u32,
    /// Destination Y coordinate on the real framebuffer.
    pub dst_y: u32,
}

/// Arguments for [`Syscall::ChannelReadEtc`], passed by pointer because the
/// syscall needs byte and handle buffers plus actual-count outputs.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ChannelReadEtcArgs {
    /// Channel handle to read from.
    pub channel: HandleValue,
    /// Destination byte buffer.
    pub bytes: *mut u8,
    /// Capacity of `bytes`.
    pub bytes_capacity: u32,
    /// Actual number of bytes copied.
    pub out_bytes: *mut u32,
    /// Destination handle buffer.
    pub handles: *mut HandleValue,
    /// Capacity of `handles`.
    pub handles_capacity: u32,
    /// Actual number of handles received.
    pub out_handles: *mut u32,
}

/// Arguments for [`Syscall::ChannelPeek`]: inspect the next queued message
/// without dequeueing it. The returned cookie identifies the message for a
/// subsequent [`Syscall::ChannelConsume`] call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ChannelPeekArgs {
    /// Channel handle to peek into.
    pub channel: HandleValue,
    /// Output: byte size of the next message.
    pub out_byte_size: *mut u32,
    /// Output: number of transferred handles in the next message.
    pub out_handle_count: *mut u32,
    /// Output: opaque cookie for [`Syscall::ChannelConsume`].
    pub out_cookie: *mut u64,
    /// Wait mode: 0 = non-blocking, 1 = blocking, >= 2 = timeout in ticks.
    pub wait_mode: u64,
}

/// Arguments for [`Syscall::ChannelConsume`]: dequeue and copy out the
/// message identified by a cookie from [`Syscall::ChannelPeek`].
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ChannelConsumeArgs {
    /// Channel handle to consume from.
    pub channel: HandleValue,
    /// Opaque cookie from [`Syscall::ChannelPeek`].
    pub cookie: u64,
    /// Destination byte buffer.
    pub bytes: *mut u8,
    /// Capacity of `bytes`.
    pub bytes_capacity: u32,
    /// Destination handle buffer.
    pub handles: *mut HandleValue,
    /// Capacity of `handles`.
    pub handles_capacity: u32,
    /// Output: actual bytes copied.
    pub out_bytes: *mut u32,
    /// Output: actual handles transferred.
    pub out_handles: *mut u32,
}

/// Signal bits used by [`Syscall::WaitSetWait`]. Kept in the ABI crate as
/// plain `u32` constants (rather than pulled from `huesos-waitset`) so
/// userspace does not need to depend on the kernel-side policy crate.
/// The numeric values must match `huesos_waitset::Signals::*` bit for bit;
/// a host test in this crate locks that contract in.
pub mod signals {
    /// No signals set.
    pub const NONE: u32 = 0;
    /// Object is readable (e.g. a channel has queued messages).
    pub const READABLE: u32 = 1 << 0;
    /// Object is writable (e.g. a channel has buffer space).
    pub const WRITABLE: u32 = 1 << 1;
    /// Object was canceled (e.g. its handle was closed).
    pub const CANCELED: u32 = 1 << 2;
    /// The peer end was closed.
    pub const PEER_CLOSED: u32 = 1 << 3;
    /// Generic user signal (events, process exit, ...).
    pub const SIGNALED: u32 = 1 << 4;
}

/// Wait-completion mode passed to [`Syscall::WaitSetWait`] via
/// [`WaitSetWaitArgs::mode`]. Must match `huesos_waitset::WaitMode`.
pub mod wait_mode {
    /// Return when any item's awaited signals become active.
    pub const ANY: u32 = 0;
    /// Return only when every item's awaited signals become active.
    pub const ALL: u32 = 1;
}

/// One item in a [`Syscall::WaitSetWait`] request: a handle and the
/// signals the caller is waiting for, tagged with a user key.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WaitSetItem {
    /// Handle to the object to wait on (channel, port, process).
    pub handle: HandleValue,
    /// Signal bits awaited (e.g. READABLE, SIGNALED, PEER_CLOSED).
    pub awaited_signals: u32,
    /// User-defined key returned in the result to identify this item.
    pub key: u64,
}

/// One result entry from [`Syscall::WaitSetWait`]: which items are
/// satisfied and with which signals.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WaitSetResult {
    /// User key from the matching [`WaitSetItem`].
    pub key: u64,
    /// Active signals that satisfy the awaited mask.
    pub active_signals: u32,
}

/// Arguments for [`Syscall::WaitSetWait`]: multiplexed wait on multiple
/// objects with Any/All semantics.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WaitSetWaitArgs {
    /// Pointer to array of [`WaitSetItem`] (caller-controlled memory).
    pub items: *const WaitSetItem,
    /// Number of items in the array (max 16).
    pub item_count: u32,
    /// Wait mode: 0 = Any (return when any item satisfied),
    /// 1 = All (return when all items satisfied).
    pub mode: u32,
    /// Timeout in scheduler ticks. 0 = wait forever.
    pub timeout_ticks: u64,
    /// Output: array of [`WaitSetResult`] (capacity >= item_count).
    pub out_results: *mut WaitSetResult,
    /// Output: number of results written.
    pub out_count: *mut u32,
}

/// Port packet type for interrupt notifications.
pub const PORT_PACKET_INTERRUPT: u32 = 1;
/// Port packet type for process-exit notifications.
pub const PORT_PACKET_PROCESS_EXIT: u32 = 2;
/// Port packet type for quota-exhaustion notifications.
pub const PORT_PACKET_QUOTA_EXHAUSTED: u32 = 3;
/// Port packet type for async BlockDevice completions.
pub const PORT_PACKET_BLOCK_COMPLETION: u32 = 4;

/// Fixed-size event packet returned by [`Syscall::PortRead`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PortPacket {
    /// User-supplied key associated with the event source when it was bound
    /// to the Port.
    pub key: u64,
    /// Packet type. See `PORT_PACKET_*` constants.
    pub packet_type: u32,
    /// Status code associated with the packet source. Zero means success.
    pub status: i32,
    /// Source-specific payload words.
    pub data: [u64; 4],
}

/// Job quota limits for public Job syscalls. `u64::MAX` means unlimited.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobLimitsAbi {
    /// Maximum charged memory bytes.
    pub max_memory: u64,
    /// Maximum live handles.
    pub max_handles: u64,
    /// Maximum charged CPU ticks.
    pub max_cpu_ticks: u64,
}

/// Arguments for [`Syscall::JobCreate`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobCreateArgs {
    /// Parent Job handle.
    pub parent: HandleValue,
    /// Limits for the child Job.
    pub limits: JobLimitsAbi,
    /// Output child Job handle.
    pub out_job: *mut HandleValue,
}

/// Arguments for [`Syscall::JobSetLimits`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobSetLimitsArgs {
    /// Job handle.
    pub job: HandleValue,
    /// Replacement limits.
    pub limits: JobLimitsAbi,
}

/// Arguments for [`Syscall::JobSetName`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobSetNameArgs {
    /// Job handle.
    pub job: HandleValue,
    /// Pointer to UTF-8 name bytes.
    pub name: *const u8,
    /// Name length in bytes.
    pub name_len: u64,
}

/// Arguments for [`Syscall::JobBindQuotaPort`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobBindQuotaPortArgs {
    /// Job handle to observe.
    pub job: HandleValue,
    /// Port handle receiving quota packets.
    pub port: HandleValue,
    /// User key copied into queued packets.
    pub key: u64,
    /// Reserved for future flags. Must be zero.
    pub flags: u32,
}

/// Arguments for [`Syscall::ProcessCreateInJob`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessCreateInJobArgs {
    /// Job handle that will own the process.
    pub job: HandleValue,
    /// Pointer to process name bytes.
    pub name: *const u8,
    /// Name length.
    pub name_len: u64,
    /// Output process handle.
    pub out_process: *mut HandleValue,
    /// Output root VMAR handle.
    pub out_root_vmar: *mut HandleValue,
}

/// Arguments for [`Syscall::ProcessBindExitPort`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessBindExitPortArgs {
    /// Process handle to observe.
    pub process: HandleValue,
    /// Port handle receiving the exit packet.
    pub port: HandleValue,
    /// User key copied into the queued packet.
    pub key: u64,
    /// Reserved for future one-shot/repeating policy flags. Must be zero.
    pub flags: u32,
}

/// Arguments for [`Syscall::VmarCreateChild`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VmarCreateChildArgs {
    /// Parent VMAR handle.
    pub parent: HandleValue,
    /// Child VMAR base address. Must be page-aligned and inside `parent`.
    pub addr: u64,
    /// Child VMAR size in bytes. Must be non-zero and page-aligned.
    pub len: u64,
    /// Reserved for future placement/policy flags. Must be zero.
    pub flags: u32,
    /// Output handle for the new child VMAR.
    pub out_child: *mut HandleValue,
}

/// Arguments for [`Syscall::VmarMap`], passed by pointer because mapping a
/// VMO needs more than the syscall ABI's five register-sized arguments.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VmarMapArgs {
    /// Handle to the target VMAR.
    pub vmar: HandleValue,
    /// Handle to the VMO being mapped.
    pub vmo: HandleValue,
    /// Byte offset into the VMO.
    pub vmo_offset: u64,
    /// Requested destination virtual address. The first implementation is
    /// strict fixed-address mapping: callers must set `vmar_flags::SPECIFIC`
    /// and provide a page-aligned address inside the target VMAR.
    pub addr: u64,
    /// Mapping length in bytes.
    pub len: u64,
    /// Mapping options/permissions from [`vmar_flags`].
    pub flags: u32,
}

/// Arguments for [`Syscall::VmarUnmap`] and [`Syscall::VmarProtect`].
///
/// The range must be page-aligned and covered by one mapping in the target
/// VMAR. Subranges split the mapping into the remaining left/right pieces
/// (and a protected middle piece for `VmarProtect`). `flags` is zero for unmap
/// and contains [`vmar_flags`] permissions for protect.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VmarOpArgs {
    /// Handle to the target VMAR.
    pub vmar: HandleValue,
    /// Exact mapping base address.
    pub addr: u64,
    /// Exact mapping length.
    pub len: u64,
    /// New permissions for protect; zero for unmap.
    pub flags: u32,
}

/// Arguments for [`Syscall::ResourceMap`].
///
/// The kernel maps a page-aligned subrange of an `Mmio` or `DmaPool` Resource
/// into the caller's root VMAR. The mapping is fixed-address only and must use
/// ordinary [`vmar_flags`] permissions (`USER | SPECIFIC | READ/WRITE`, never
/// executable). The Resource handle remains the authority for the physical
/// range; no general physical-memory mapping is exposed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceMapArgs {
    /// Resource handle owned by the caller.
    pub resource: HandleValue,
    /// Offset from the Resource base. Must be page-aligned.
    pub resource_offset: u64,
    /// Requested destination virtual address. Must be page-aligned.
    pub addr: u64,
    /// Mapping length in bytes. Must be non-zero and page-aligned.
    pub len: u64,
    /// Mapping options/permissions from [`vmar_flags`].
    pub flags: u32,
}

#[cfg(test)]
mod tests {
    use super::{
        hbi_boot, rights, vmar_flags, ErrorCode, ResourceKindAbi, ResourceMapArgs, Syscall,
    };

    #[test]
    fn boot_driver_manifest_header_validates() {
        assert!(hbi_boot::validate_header(
            hbi_boot::BootDriverManifestHeader {
                magic: hbi_boot::MAGIC,
                version: hbi_boot::VERSION,
                entry_count: 1,
            }
        ));
        assert!(!hbi_boot::validate_header(
            hbi_boot::BootDriverManifestHeader {
                magic: 0,
                version: hbi_boot::VERSION,
                entry_count: 1,
            }
        ));
        assert!(!hbi_boot::validate_header(
            hbi_boot::BootDriverManifestHeader {
                magic: hbi_boot::MAGIC,
                version: hbi_boot::VERSION,
                entry_count: (hbi_boot::MAX_BOOT_DRIVERS + 1) as u16,
            }
        ));
    }

    #[test]
    fn mapping_rights_include_each_requested_permission() {
        let flags = vmar_flags::USER
            | vmar_flags::SPECIFIC
            | vmar_flags::READ
            | vmar_flags::WRITE
            | vmar_flags::EXECUTE;
        let required = rights::mapping_required(flags);
        assert_eq!(
            required,
            rights::MAP | rights::READ | rights::WRITE | rights::EXECUTE
        );
    }

    #[test]
    fn mapping_rights_always_include_map_but_not_unrequested_permissions() {
        let required = rights::mapping_required(vmar_flags::USER | vmar_flags::SPECIFIC);
        assert_eq!(required, rights::MAP);
    }

    #[test]
    fn syscall_numbers_remain_append_only() {
        assert_eq!(Syscall::VmoCreateEx as u64, 28);
        assert_eq!(Syscall::VmarUnmap as u64, 29);
        assert_eq!(Syscall::VmarProtect as u64, 30);
        assert_eq!(Syscall::ChannelPeek as u64, 31);
        assert_eq!(Syscall::ChannelConsume as u64, 32);
        assert_eq!(Syscall::WaitSetWait as u64, 33);
        assert_eq!(Syscall::ResourceCreate as u64, 34);
        assert_eq!(Syscall::ProcessMarkCritical as u64, 35);
        assert_eq!(Syscall::HardHalt as u64, 36);
        assert_eq!(Syscall::IoPortWrite8 as u64, 37);
        assert_eq!(Syscall::IoPortRead8 as u64, 38);
        assert_eq!(Syscall::ProcessSetAffinity as u64, 39);
        assert_eq!(Syscall::SystemCpuCount as u64, 40);
        assert_eq!(Syscall::SystemCurrentCpu as u64, 41);
        assert_eq!(Syscall::ProcessSetAffinityMask as u64, 42);
        assert_eq!(Syscall::ProcessGetAffinity as u64, 43);
        assert_eq!(Syscall::VmarCreateChild as u64, 44);
        assert_eq!(Syscall::SignalCreate as u64, 45);
        assert_eq!(Syscall::SignalSet as u64, 46);
        assert_eq!(Syscall::SignalClear as u64, 47);
        assert_eq!(Syscall::ProcessBindExitPort as u64, 48);
        assert_eq!(Syscall::ProcessSetSchedulerFlags as u64, 49);
        assert_eq!(Syscall::JobDefault as u64, 50);
        assert_eq!(Syscall::JobCreate as u64, 51);
        assert_eq!(Syscall::JobSetLimits as u64, 52);
        assert_eq!(Syscall::JobBindQuotaPort as u64, 53);
        assert_eq!(Syscall::ProcessCreateInJob as u64, 54);
        assert_eq!(Syscall::JobSetName as u64, 55);
        assert_eq!(Syscall::ResourceMap as u64, 56);
        assert_eq!(Syscall::InterruptCreateForResource as u64, 57);
        assert_eq!(Syscall::PortQueue as u64, 58);
        assert_eq!(Syscall::VolumeKeyGet as u64, 59);
        assert_eq!(Syscall::COUNT, 60);
        assert_eq!(Syscall::from_raw(28), Some(Syscall::VmoCreateEx));
        assert_eq!(Syscall::from_raw(30), Some(Syscall::VmarProtect));
        assert_eq!(Syscall::from_raw(31), Some(Syscall::ChannelPeek));
        assert_eq!(Syscall::from_raw(32), Some(Syscall::ChannelConsume));
        assert_eq!(Syscall::from_raw(33), Some(Syscall::WaitSetWait));
        assert_eq!(Syscall::from_raw(34), Some(Syscall::ResourceCreate));
        assert_eq!(Syscall::from_raw(35), Some(Syscall::ProcessMarkCritical));
        assert_eq!(Syscall::from_raw(36), Some(Syscall::HardHalt));
        assert_eq!(Syscall::from_raw(37), Some(Syscall::IoPortWrite8));
        assert_eq!(Syscall::from_raw(38), Some(Syscall::IoPortRead8));
        assert_eq!(Syscall::from_raw(39), Some(Syscall::ProcessSetAffinity));
        assert_eq!(Syscall::from_raw(40), Some(Syscall::SystemCpuCount));
        assert_eq!(Syscall::from_raw(41), Some(Syscall::SystemCurrentCpu));
        assert_eq!(Syscall::from_raw(42), Some(Syscall::ProcessSetAffinityMask));
        assert_eq!(Syscall::from_raw(43), Some(Syscall::ProcessGetAffinity));
        assert_eq!(Syscall::from_raw(44), Some(Syscall::VmarCreateChild));
        assert_eq!(Syscall::from_raw(45), Some(Syscall::SignalCreate));
        assert_eq!(Syscall::from_raw(46), Some(Syscall::SignalSet));
        assert_eq!(Syscall::from_raw(47), Some(Syscall::SignalClear));
        assert_eq!(Syscall::from_raw(48), Some(Syscall::ProcessBindExitPort));
        assert_eq!(
            Syscall::from_raw(49),
            Some(Syscall::ProcessSetSchedulerFlags)
        );
        assert_eq!(Syscall::from_raw(50), Some(Syscall::JobDefault));
        assert_eq!(Syscall::from_raw(51), Some(Syscall::JobCreate));
        assert_eq!(Syscall::from_raw(52), Some(Syscall::JobSetLimits));
        assert_eq!(Syscall::from_raw(53), Some(Syscall::JobBindQuotaPort));
        assert_eq!(Syscall::from_raw(54), Some(Syscall::ProcessCreateInJob));
        assert_eq!(Syscall::from_raw(55), Some(Syscall::JobSetName));
        assert_eq!(Syscall::from_raw(56), Some(Syscall::ResourceMap));
        assert_eq!(
            Syscall::from_raw(57),
            Some(Syscall::InterruptCreateForResource)
        );
        assert_eq!(Syscall::from_raw(58), Some(Syscall::PortQueue));
        assert_eq!(Syscall::from_raw(59), Some(Syscall::VolumeKeyGet));
        assert_eq!(Syscall::from_raw(60), None);
    }

    #[test]
    fn resource_map_args_layout_smoke() {
        let args = ResourceMapArgs {
            resource: 7,
            resource_offset: 0x1000,
            addr: 0x7000_0000_0000,
            len: 0x2000,
            flags: vmar_flags::USER | vmar_flags::SPECIFIC | vmar_flags::READ,
        };
        assert_eq!(args.resource, 7);
        assert_eq!(args.len, 0x2000);
    }

    #[test]
    fn resource_kind_abi_round_trip() {
        for &kind in &[
            ResourceKindAbi::IoPort,
            ResourceKindAbi::Mmio,
            ResourceKindAbi::Irq,
            ResourceKindAbi::PowerControl,
            ResourceKindAbi::DmaPool,
            ResourceKindAbi::FrameDraw,
        ] {
            let raw = kind as u32;
            assert_eq!(ResourceKindAbi::from_raw(raw), Some(kind));
        }
        assert_eq!(ResourceKindAbi::from_raw(0), None);
        assert_eq!(ResourceKindAbi::from_raw(5), Some(ResourceKindAbi::DmaPool));
        assert_eq!(
            ResourceKindAbi::from_raw(6),
            Some(ResourceKindAbi::FrameDraw)
        );
        assert_eq!(ResourceKindAbi::from_raw(7), None);
        assert_eq!(ResourceKindAbi::from_raw(u32::MAX), None);
    }

    #[test]
    fn framebuffer_blit_is_capability_gated() {
        // The numeric value of FramebufferBlit is part of the append-only
        // syscall ABI: changing it would force every libcanvas consumer
        // to re-vendor. Lock the existing value here so a stealth
        // renumber fails this host test before it can reach users.
        assert_eq!(Syscall::FramebufferBlit as u64, 13);
        // And lock the INIT_FRAME_DRAW_HANDLE slot so the kernel-side
        // handle table that init relies on does not silently renumber.
        assert_eq!(super::INIT_FRAME_DRAW_HANDLE, 6);
        assert_eq!(super::INIT_STORAGE_BOOT_INFO_HANDLE, 5);
    }

    #[test]
    fn peer_closed_error_round_trips() {
        assert_eq!(ErrorCode::from_raw(-22), Some(ErrorCode::PeerClosed));
        assert_eq!(ErrorCode::PeerClosed.as_str(), "channel peer closed");
    }

    #[test]
    fn encode_syscall_result_ok_preserves_bit_pattern() {
        // Any non-negative i64 must round-trip through the ABI encoder
        // and be re-read by the caller as the same value.
        for v in [0i64, 1, 42, 4096, i64::MAX] {
            let raw = super::encode_syscall_result(Ok(v));
            assert_eq!(raw, v as u64);
            // Round-trip through the caller-side decode: raw as i64, sign
            // check, then value.
            let signed = raw as i64;
            assert!(
                signed >= 0,
                "Ok({v}) must decode as non-negative i64, got {signed}"
            );
            assert_eq!(signed, v);
        }
    }

    #[test]
    fn encode_syscall_result_err_sign_extends_correctly() {
        // Every ErrorCode discriminant must encode to a negative i64 that
        // ErrorCode::from_raw recovers back to the original variant. This
        // is the exact contract libcanvas::raw::decode depends on.
        for variant in [
            ErrorCode::InvalidArgs,
            ErrorCode::BadHandle,
            ErrorCode::WrongType,
            ErrorCode::AccessDenied,
            ErrorCode::NoMemory,
            ErrorCode::Busy,
            ErrorCode::ShouldWait,
            ErrorCode::TimedOut,
            ErrorCode::NotFound,
            ErrorCode::NoFramebuffer,
            ErrorCode::NotSupported,
            ErrorCode::Internal,
            ErrorCode::PeerClosed,
        ] {
            let raw = super::encode_syscall_result(Err(variant));
            let signed = raw as i64;
            assert!(
                signed < 0,
                "{variant:?} must encode as a negative i64, got {signed}"
            );
            assert_eq!(
                ErrorCode::from_raw(signed),
                Some(variant),
                "{variant:?} must round-trip through from_raw"
            );
        }
    }

    #[test]
    fn encode_syscall_result_specific_wire_values_are_locked() {
        // Lock the exact bit pattern for two representative variants so
        // a stealth ABI change (e.g. someone renumbering the enum, or
        // dropping #[repr(i32)]) fails a host test before it can reach
        // users. -10 is the smallest-magnitude InvalidArgs; -22 is the
        // largest-magnitude PeerClosed.
        assert_eq!(
            super::encode_syscall_result(Err(ErrorCode::InvalidArgs)),
            (-10i64) as u64,
        );
        assert_eq!(
            super::encode_syscall_result(Err(ErrorCode::PeerClosed)),
            (-22i64) as u64,
        );
        // Ensure sign-extension actually happened: the top 32 bits must be
        // all-ones for a negative encoded value. If the ABI shifted to a
        // zero-extension path (which would happen if ErrorCode became
        // #[repr(u32)]), the top half would be zero and this test would
        // fail with 0x00000000_fffffff6 instead of 0xffffffff_fffffff6.
        assert_eq!(
            super::encode_syscall_result(Err(ErrorCode::InvalidArgs)),
            0xffff_ffff_ffff_fff6,
        );
    }

    #[test]
    fn waitset_signal_bits_are_stable_abi() {
        // These numeric values are the ABI contract with userspace. Every
        // libcanvas caller passes them through as u32 into WaitSetWaitArgs,
        // and the kernel parses them via `huesos_waitset::Signals::from_bits`.
        // The kernel-side Signals bit layout must not diverge from these
        // constants; if it does, this host test fails before the divergence
        // can reach users.
        assert_eq!(super::signals::NONE, 0);
        assert_eq!(super::signals::READABLE, 1 << 0);
        assert_eq!(super::signals::WRITABLE, 1 << 1);
        assert_eq!(super::signals::CANCELED, 1 << 2);
        assert_eq!(super::signals::PEER_CLOSED, 1 << 3);
        assert_eq!(super::signals::SIGNALED, 1 << 4);
        assert_eq!(super::wait_mode::ANY, 0);
        assert_eq!(super::wait_mode::ALL, 1);
    }
}
