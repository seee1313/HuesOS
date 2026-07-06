//! Kernel object identifiers.

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_KOID: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh Kernel Object ID.
pub fn alloc_koid() -> Koid {
    Koid(NEXT_KOID.fetch_add(1, Ordering::SeqCst))
}

/// Kernel object unique ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct Koid(pub u64);

impl Koid {
    /// Invalid koid.
    pub const INVALID: Koid = Koid(0);
    /// Check validity.
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}
