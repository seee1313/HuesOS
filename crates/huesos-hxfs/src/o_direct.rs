//! Stage B.4 O_DIRECT deny policy.
//!
//! The MVP does not support the O_DIRECT bypass of the page
//! cache: the kernel-side direct-IO alignment path is not
//! in place and the production-readiness ROADMAP exit
//! criterion for Stage B.4 is "O_DIRECT returns Unsupported".
//! Rather than silently falling back to a cached read/write
//! and risking a Linux client observing the flag and not
//! getting the direct semantics it expected, the policy
//! here returns `true` whenever the O_DIRECT bit is set, and
//! callers are expected to map that to a precise
//! `HxfsStatus::Unsupported` reply.
//!
//! The bit value matches the Linux `O_DIRECT` constant
//! (0x4000 = `040000` octal) so an unmodified Linux client
//! can pass the flag through the `request_flags::O_DIRECT`
//! constant in `huesos_abi::hxfs` without a translation
//! layer.

/// Mask for the O_DIRECT bit on an Hxfs request.
pub const O_DIRECT_BIT: u32 = 0x4000;

/// True if `flags` has the O_DIRECT bit set. Callers should
/// map this to `HxfsStatus::Unsupported` and stop the
/// operation; the MVP has no path that services the flag.
pub const fn has_o_direct(flags: u32) -> bool {
    flags & O_DIRECT_BIT != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_direct_bit_matches_linux_constant() {
        // The Stage B.4 bit value MUST be the Linux O_DIRECT
        // bit (0x4000) so a Linux client can pass the flag
        // through `request_flags::O_DIRECT` unchanged. If a
        // future refactor changes the bit value, the
        // `request_flags::O_DIRECT` constant in
        // `huesos_abi::hxfs` must change in lock-step.
        assert_eq!(O_DIRECT_BIT, 0x4000);
    }

    #[test]
    fn has_o_direct_detects_set_bit() {
        assert!(has_o_direct(O_DIRECT_BIT));
        assert!(has_o_direct(O_DIRECT_BIT | 0x01));
        assert!(has_o_direct(O_DIRECT_BIT | 0x8000_0000));
    }

    #[test]
    fn has_o_direct_rejects_unset_bit() {
        assert!(!has_o_direct(0));
        assert!(!has_o_direct(1));
        assert!(!has_o_direct(0x2000));
        assert!(!has_o_direct(0x8000));
        // All the other request_flags bits set, O_DIRECT
        // clear: 0x01 (ABSOLUTE_PATH) | 0x02 (EXCLUSIVE_CREATE)
        // | 0x04 (INLINE_PAYLOAD) | 0x08 (NOFOLLOW_FINAL_SYMLINK).
        assert!(!has_o_direct(0x0F));
    }
}
