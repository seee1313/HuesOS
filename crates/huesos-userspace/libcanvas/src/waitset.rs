//! Safe wrapper for the [`WaitSetWait`][sw] multiplexed-wait syscall.
//!
//! The kernel accepts a small set (currently up to 16) of `(handle, awaited
//! signals, user key)` tuples and blocks the caller until either:
//!
//! - **Any** item's awaited signals become active (`wait_any`), or
//! - **All** items' awaited signals become active (`wait_all`),
//!
//! optionally with a scheduler-tick timeout. Without this call, a userspace
//! driver has to `sys_yield` in a busy loop, burning CPU while waiting on
//! more than one endpoint. With it, a driver that listens on both a control
//! Channel and a device Port becomes an ordinary event loop.
//!
//! ## Example — driver event loop
//!
//! ```ignore
//! use libcanvas::{wait_any, Signals, WaitItem};
//!
//! # fn example(ctrl: &libcanvas::Channel, port: &libcanvas::Port) -> libcanvas::Result<()> {
//! const CTRL_KEY: u64 = 0;
//! const PORT_KEY: u64 = 1;
//!
//! let items = [
//!     WaitItem::new(ctrl.handle_value(), Signals::READABLE | Signals::PEER_CLOSED, CTRL_KEY),
//!     WaitItem::new(port.handle_value(), Signals::READABLE,                       PORT_KEY),
//! ];
//!
//! loop {
//!     let outcome = wait_any(&items, /* timeout_ticks */ 0)?;
//!     for result in outcome.satisfied() {
//!         match result.key {
//!             CTRL_KEY => { /* drain ctrl */ }
//!             PORT_KEY => { /* drain port */ }
//!             _ => {}
//!         }
//!     }
//! }
//! # }
//! ```
//!
//! [sw]: huesos_abi::Syscall::WaitSetWait
//!
//! ## Rights
//!
//! Every handle listed in a request must carry [`rights::READ`][rr]. The
//! kernel returns [`ErrorCode::AccessDenied`][ad] otherwise.
//!
//! [rr]: huesos_abi::rights::READ
//! [ad]: huesos_abi::ErrorCode::AccessDenied

use core::ops::BitOr;

use huesos_abi::{
    signals as abi_signals, wait_mode, ErrorCode, HandleValue, Syscall, WaitSetItem, WaitSetResult,
    WaitSetWaitArgs,
};

use crate::{raw, Result};

/// Maximum items per [`WaitSetWait`][sw] request. Matches the kernel-side
/// `MAX_WAIT_ITEMS` in `huesos-syscalls`.
///
/// [sw]: huesos_abi::Syscall::WaitSetWait
pub const MAX_ITEMS: usize = 16;

/// Signal bits accepted in a [`WaitItem`]. Thin `Copy` newtype over `u32`
/// so common combinations compose with `|`, matching the kernel-side
/// `huesos_waitset::Signals` API by name and bit layout (verified by an
/// ABI test in `huesos-abi`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Signals(pub u32);

impl Signals {
    /// No signals.
    pub const NONE: Signals = Signals(abi_signals::NONE);
    /// Object is readable (e.g. a channel has queued messages).
    pub const READABLE: Signals = Signals(abi_signals::READABLE);
    /// Object is writable (e.g. a channel has buffer space).
    pub const WRITABLE: Signals = Signals(abi_signals::WRITABLE);
    /// Object was canceled (e.g. its handle was closed).
    pub const CANCELED: Signals = Signals(abi_signals::CANCELED);
    /// The peer end was closed.
    pub const PEER_CLOSED: Signals = Signals(abi_signals::PEER_CLOSED);
    /// Generic user signal (events, process exit, ...).
    pub const SIGNALED: Signals = Signals(abi_signals::SIGNALED);

    /// Whether every bit in `other` is present in `self`.
    #[inline]
    pub const fn contains(self, other: Signals) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Raw ABI bits, for interop with [`huesos_abi::signals`].
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl BitOr for Signals {
    type Output = Signals;
    #[inline]
    fn bitor(self, rhs: Signals) -> Signals {
        Signals(self.0 | rhs.0)
    }
}

/// One entry in a wait request. Newtype around [`WaitSetItem`] so callers
/// build the ABI struct through a typed constructor.
#[derive(Clone, Copy, Debug)]
pub struct WaitItem(WaitSetItem);

impl WaitItem {
    /// Wait on `handle` for any bit in `awaited` to become active, and tag
    /// the resulting completion with `key` (arbitrary user-supplied u64).
    ///
    /// The kernel enforces that `handle` carries [`rights::READ`][rr]; the
    /// wrapper does not re-check because the kernel is authoritative.
    ///
    /// [rr]: huesos_abi::rights::READ
    #[inline]
    pub const fn new(handle: HandleValue, awaited: Signals, key: u64) -> Self {
        WaitItem(WaitSetItem {
            handle,
            awaited_signals: awaited.0,
            key,
        })
    }

    /// The underlying ABI struct.
    #[inline]
    pub const fn as_abi(&self) -> WaitSetItem {
        self.0
    }
}

/// Successful outcome of a wait: the array of satisfied results plus a
/// slice view helper.
///
/// The kernel writes `count` entries to `results`, where `count <=
/// items.len()`. Non-satisfied items simply have no entry in the returned
/// slice; callers correlate by `key`.
#[derive(Debug)]
pub struct WaitOutcome {
    results: [WaitSetResult; MAX_ITEMS],
    count: u32,
}

impl WaitOutcome {
    /// Number of items whose awaited signals became active.
    #[inline]
    pub fn len(&self) -> usize {
        self.count as usize
    }

    /// Whether no items were satisfied. Kernel currently never returns an
    /// empty outcome on success — the loop keeps blocking — so this is
    /// mostly defensive for future non-blocking modes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Slice of satisfied results, in call order.
    #[inline]
    pub fn satisfied(&self) -> &[WaitSetResult] {
        &self.results[..self.count as usize]
    }
}

/// Common implementation for `wait_any` / `wait_all`.
fn wait_impl(items: &[WaitItem], timeout_ticks: u64, mode: u32) -> Result<WaitOutcome> {
    if items.is_empty() || items.len() > MAX_ITEMS {
        return Err(ErrorCode::InvalidArgs);
    }

    // Pack the newtypes into the ABI array. Local storage on the stack so
    // no allocation, and the array outlives the syscall.
    let mut abi_items = [WaitSetItem {
        handle: 0,
        awaited_signals: 0,
        key: 0,
    }; MAX_ITEMS];
    for (dst, src) in abi_items.iter_mut().zip(items.iter()) {
        *dst = src.as_abi();
    }

    let mut outcome = WaitOutcome {
        results: [WaitSetResult {
            key: 0,
            active_signals: 0,
        }; MAX_ITEMS],
        count: 0,
    };

    let args = WaitSetWaitArgs {
        items: abi_items.as_ptr(),
        item_count: items.len() as u32,
        mode,
        timeout_ticks,
        out_results: outcome.results.as_mut_ptr(),
        out_count: &mut outcome.count as *mut u32,
    };

    let rc = raw::syscall1(Syscall::WaitSetWait, &args as *const _ as u64);
    raw::decode(rc)?;

    Ok(outcome)
}

/// Block until *any* item's awaited signals become active.
///
/// `timeout_ticks == 0` means wait forever. A non-zero timeout returns
/// [`ErrorCode::TimedOut`] when it elapses with no item satisfied.
pub fn wait_any(items: &[WaitItem], timeout_ticks: u64) -> Result<WaitOutcome> {
    wait_impl(items, timeout_ticks, wait_mode::ANY)
}

/// Block until *every* item's awaited signals become active.
pub fn wait_all(items: &[WaitItem], timeout_ticks: u64) -> Result<WaitOutcome> {
    wait_impl(items, timeout_ticks, wait_mode::ALL)
}
