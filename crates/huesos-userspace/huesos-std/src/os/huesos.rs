//! The HuesOS-specific parts of the standard library.
//!
//! # Capabilities are data, not names
//! A HuesOS process does not discover services: it is *handed* channels at
//! start up and the loader publishes which ones it got as a bit mask. That mask
//! is the program's whole authority, so it is part of the standard library
//! rather than a detail of one tool:
//!
//! ```ignore
//! use huesos_std::os::huesos;
//!
//! if huesos::has_capability(Capability::HxfsService) {
//!     // the shell gave us the filesystem
//! }
//! ```
//!
//! The [`CommandCaps`] trait is the companion piece for children: a parent may
//! pass a *smaller* mask than its own, never a larger one, because the mask is
//! intersected with the parent's mask at spawn time.

use alloc::string::String;
use alloc::vec::Vec;

use libcanvas::stdio::CapKind;

use crate::error::{Error, Result};
use crate::sync::atomic::{AtomicU64, Ordering};

/// A capability a program may hold.
///
/// These mirror the loader's `AT_HUESOS_*` handle slots, plus the authority bits
/// in the process' capability mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Capability {
    /// Standard input channel.
    Stdin,
    /// Standard output channel.
    Stdout,
    /// Standard error channel.
    Stderr,
    /// Attenuated filesystem directory.
    HxfsDir,
    /// The filesystem service.
    HxfsService,
    /// A block device.
    BlockDevice,
    /// Framebuffer draw access.
    FrameDraw,
    /// Read-only boot filesystem.
    Bootfs,
    /// The driver registry.
    Registry,
    /// Plan 9 `/net/btl` Bluetooth Classic transport service.
    BtlService,
    /// Multi-stream `HARB` SPSC mixer + `VirtIO-Sound` / `A2DP` audio service.
    AudioService,
}

impl Capability {
    /// The loader's handle slot for this capability, if it has one.
    pub const fn kind(self) -> Option<CapKind> {
        Some(match self {
            Capability::Stdin => CapKind::Stdin,
            Capability::Stdout => CapKind::Stdout,
            Capability::Stderr => CapKind::Stderr,
            Capability::HxfsDir => CapKind::HxfsDir,
            Capability::HxfsService => CapKind::HxfsService,
            Capability::BlockDevice => CapKind::BlockDev,
            Capability::FrameDraw => CapKind::FrameDraw,
            Capability::Bootfs => CapKind::BootfsRo,
            Capability::Registry => CapKind::Registry,
            Capability::BtlService => CapKind::BtlService,
            Capability::AudioService => CapKind::AudioService,
        })
    }

    /// Name used in diagnostics and in the shell's `caps` command.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Stdin => "stdin",
            Capability::Stdout => "stdout",
            Capability::Stderr => "stderr",
            Capability::HxfsDir => "dir",
            Capability::HxfsService => "hxfs",
            Capability::BlockDevice => "blk",
            Capability::FrameDraw => "fb",
            Capability::Bootfs => "bootfs",
            Capability::Registry => "registry",
            Capability::BtlService => "btl",
            Capability::AudioService => "audio",
        }
    }
}

/// The process' whole capability mask.
pub fn caps_mask() -> u64 {
    crate::env::caps()
}

/// True when the program holds every capability in `needed`.
pub fn has_caps(needed: u64) -> bool {
    crate::env::has_caps(needed)
}

/// True when the program holds `capability`.
pub fn has_capability(capability: Capability) -> bool {
    match capability.kind() {
        Some(kind) => libcanvas::stdio::cap_handle(kind).is_some(),
        None => false,
    }
}

/// The capabilities present right now, in declaration order.
pub fn capabilities() -> Vec<Capability> {
    const ALL: [Capability; 11] = [
        Capability::Stdin,
        Capability::Stdout,
        Capability::Stderr,
        Capability::HxfsDir,
        Capability::HxfsService,
        Capability::BlockDevice,
        Capability::FrameDraw,
        Capability::Bootfs,
        Capability::Registry,
        Capability::BtlService,
        Capability::AudioService,
    ];
    ALL.iter()
        .copied()
        .filter(|capability| has_capability(*capability))
        .collect()
}

/// A one-line summary, e.g. `stdout stderr hxfs`, for logs and the shell prompt.
pub fn caps_summary() -> String {
    let mut summary = String::new();
    for capability in capabilities() {
        if !summary.is_empty() {
            summary.push(' ');
        }
        summary.push_str(capability.as_str());
    }
    summary
}

/// How many CPUs the kernel is running.
pub fn cpu_count() -> Result<usize> {
    libcanvas::system::cpu_count().map_err(Error::from)
}

/// Which CPU the calling thread is on.
pub fn current_cpu() -> Result<usize> {
    libcanvas::system::current_cpu().map_err(Error::from)
}

/// Ticks of the monotonic scheduler clock (100 per second).
pub fn monotonic_ticks() -> Result<u64> {
    libcanvas::system::monotonic_ticks().map_err(Error::from)
}

/// Ask the kernel to shut the machine down.
///
/// Requires the shutdown authority; a program without it gets `AccessDenied`
/// rather than a panic.
pub fn shutdown() -> Result<()> {
    libcanvas::system::shutdown().map_err(Error::from)
}

/// Cached copy of the loader's capability mask, for [`caps_mask`] callers that
/// must not take a handle.
static MASK_CACHE: AtomicU64 = AtomicU64::new(0);
/// Set once [`MASK_CACHE`] holds a value.
static MASK_CACHE_READY: AtomicU64 = AtomicU64::new(0);

/// The cached capability mask, read once.
pub fn caps_mask_cached() -> u64 {
    if MASK_CACHE_READY.load(Ordering::Acquire) == 0 {
        MASK_CACHE.store(crate::env::caps(), Ordering::Relaxed);
        MASK_CACHE_READY.store(1, Ordering::Release);
    }
    MASK_CACHE.load(Ordering::Relaxed)
}

/// Result of a child-process spawn, as `Command` reports it.
pub use crate::process::ExitStatus;

/// Extension trait: give a [`crate::process::Command`] an explicit capability
/// mask.
///
/// A child can never receive more authority than its parent: the mask is
/// intersected with the parent's at spawn time, so passing `u64::MAX` grants
/// exactly what the parent holds.
pub trait CommandCaps {
    /// Use `mask` as the child's capability mask.
    fn caps(self, mask: u64) -> Self;

    /// Grant exactly `capabilities` (and nothing else).
    fn caps_of(self, capabilities: &[Capability]) -> Self;
}

impl CommandCaps for crate::process::Command {
    fn caps(mut self, mask: u64) -> Self {
        self.set_caps_mask(mask);
        self
    }

    fn caps_of(mut self, capabilities: &[Capability]) -> Self {
        let mut mask = 0u64;
        for capability in capabilities {
            if let Some(bit) = capability_bit(*capability) {
                mask |= bit;
            }
        }
        self.set_caps_mask(mask);
        self
    }
}

/// The mask bit the loader publishes for `capability`, if the ABI names one.
///
/// The bit layout lives in `huesos-abi`'s `auxv::caps_mask`; this maps the
/// handle-slot capabilities onto the bits that are actually defined.
pub fn capability_bit(capability: Capability) -> Option<u64> {
    use huesos_abi::auxv::caps_mask as bits;
    Some(match capability {
        // The mask describes *rights*, not slots: a scoped directory is the
        // read-only flavour of the filesystem grant, and the service channel
        // rides along with the read-write flavour.
        Capability::HxfsDir => bits::HXFS_RO | bits::HXFS_DIR_SCOPED,
        Capability::HxfsService => bits::HXFS_RO | bits::HXFS_RW,
        Capability::BlockDevice => bits::BLOCK_RO | bits::BLOCK_RW,
        Capability::FrameDraw => bits::FB_RO,
        Capability::Bootfs => bits::BOOTFS_RO,
        Capability::Registry => bits::QUERY_RO,
        Capability::BtlService => bits::BTL_RO | bits::BTL_RW | bits::BTL_ADMIN,
        Capability::AudioService => bits::AUDIO_RO | bits::AUDIO_RW | bits::AUDIO_ADMIN,
        // The three standard streams are always wired by the loader and have no
        // opt-in bit of their own.
        Capability::Stdin | Capability::Stdout | Capability::Stderr => return None,
    })
}
