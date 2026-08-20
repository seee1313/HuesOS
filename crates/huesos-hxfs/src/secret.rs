//! Non-debuggable, zeroizing fixed-size secret storage.

use core::ops::{Deref, DerefMut};

/// A 256-bit key that clears its backing bytes on drop.
///
/// Deliberately not `Debug`, `Clone`, or `Copy`.
pub(crate) struct SecretKey([u8; 32]);

impl SecretKey {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Deref for SecretKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
            let _ = core::hint::black_box(*byte);
        }
    }
}
