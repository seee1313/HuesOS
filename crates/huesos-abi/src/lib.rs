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
}

impl Syscall {
    /// Total number of defined syscalls (i.e. one past the highest
    /// currently-assigned number). The dispatcher uses this to reject
    /// obviously-out-of-range numbers before a `match`.
    pub const COUNT: u64 = 28;

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
        }
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
pub const USER_STACK_SIZE: u64 = 4096 * 16;

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

/// Port packet type for interrupt notifications.
pub const PORT_PACKET_INTERRUPT: u32 = 1;

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
