//! Kernel entropy pool (`SystemGetEntropy` backing store).
//!
//! Userspace needs unpredictable bytes for hardened-allocator
//! metadata: the Scudo chunk-header cookie, quarantine/guard
//! patterns, and (later) userspace ASLR. Before this module the
//! tree had no randomness source at all — no RDRAND wrapper, no
//! DRBG, nothing in the ABI — so the allocator's integrity
//! checksum would have been forgeable from a known constant,
//! which defeats its purpose.
//!
//! Design:
//!
//! - The DRBG is **ChaCha20** in counter mode, implemented here in
//!   safe `no_std` Rust (no `unsafe`, host-testable, no external
//!   crate). ChaCha20 is the same construction Linux uses for
//!   `getrandom(2)`, and its core is 20 rounds of add-rotate-xor
//!   over a 16-word state, which is straightforward to verify
//!   against the RFC 8439 test vectors (see the tests below).
//! - The pool is seeded at boot by [`seed`] from whatever the
//!   platform can offer (RDRAND when the CPU reports it, plus the
//!   timestamp counter and boot-time values). Seeding is
//!   additive: every call mixes new material into the existing
//!   key rather than replacing it, so a weak source can never
//!   *reduce* the entropy already collected.
//! - [`fill`] rekeys after every request (fast-key-erasure): the
//!   first 32 bytes of fresh keystream become the next key and are
//!   never returned to the caller. Compromising the pool state
//!   therefore does not reveal previously issued bytes.
//!
//! Security note: this is a software DRBG. Its output is only as
//! unpredictable as the boot seed it was given. [`is_seeded`]
//! reports whether real seed material ever arrived, and the
//! syscall layer refuses to serve bytes from an unseeded pool
//! rather than silently handing out deterministic output.

use crate::irq_guard::IrqSafeMutex;

/// ChaCha20 quarter-round on four state words.
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// The ChaCha20 block function: 20 rounds over the 64-byte state.
fn chacha20_block(key: &[u8; 32], counter: u64, nonce: u64) -> [u8; 64] {
    // "expand 32-byte k" — the RFC 8439 constant.
    let mut state: [u32; 16] = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter as u32,
        (counter >> 32) as u32,
        nonce as u32,
        (nonce >> 32) as u32,
    ];

    let initial = state;
    for _ in 0..10 {
        // Column rounds.
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = state[i].wrapping_add(initial[i]);
        let bytes = word.to_le_bytes();
        out[i * 4] = bytes[0];
        out[i * 4 + 1] = bytes[1];
        out[i * 4 + 2] = bytes[2];
        out[i * 4 + 3] = bytes[3];
    }
    out
}

/// ChaCha20-based deterministic random bit generator with
/// fast key erasure.
pub struct Drbg {
    key: [u8; 32],
    nonce: u64,
    seeded: bool,
}

impl Drbg {
    /// A fresh, unseeded pool. Its key is all zeros; [`Self::fill`]
    /// still produces output but [`Self::is_seeded`] stays false
    /// until real material is mixed in.
    pub const fn new() -> Self {
        Self {
            key: [0u8; 32],
            nonce: 0,
            seeded: false,
        }
    }

    /// Whether any seed material has been mixed into this pool.
    pub fn is_seeded(&self) -> bool {
        self.seeded
    }

    /// Mix seed material into the pool.
    ///
    /// The new key is derived from keystream generated under the
    /// *current* key with the material XORed into the counter and
    /// nonce inputs, so this can only add uncertainty: an attacker
    /// who controls `material` entirely still cannot force a key
    /// they know unless they already knew the previous key.
    pub fn reseed(&mut self, material: &[u8]) {
        // Fold the material into two 64-bit mixers (FNV-1a style,
        // order-dependent) that drive the counter and nonce.
        let mut mix_a: u64 = 0xcbf2_9ce4_8422_2325;
        let mut mix_b: u64 = 0x9e37_79b9_7f4a_7c15;
        for (index, byte) in material.iter().enumerate() {
            mix_a ^= u64::from(*byte);
            mix_a = mix_a.wrapping_mul(0x0000_0100_0000_01b3);
            mix_b = mix_b
                .rotate_left(7)
                .wrapping_add(u64::from(*byte) ^ (index as u64));
        }

        self.nonce ^= mix_b;
        let block = chacha20_block(&self.key, mix_a, self.nonce);
        for (slot, byte) in self.key.iter_mut().zip(block.iter()) {
            // XOR rather than assign: preserves prior entropy.
            *slot ^= *byte;
        }
        self.nonce = self.nonce.wrapping_add(1);
        if !material.is_empty() {
            self.seeded = true;
        }
    }

    /// Fill `out` with keystream, then rekey (fast key erasure).
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut counter: u64 = 0;
        let mut written = 0usize;
        while written < out.len() {
            let block = chacha20_block(&self.key, counter, self.nonce);
            let take = core::cmp::min(64, out.len() - written);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            counter = counter.wrapping_add(1);
        }

        // Fast key erasure: derive the next key from fresh
        // keystream the caller never sees, so output already
        // handed out cannot be recomputed from the new state.
        let next = chacha20_block(&self.key, counter, self.nonce);
        self.key.copy_from_slice(&next[..32]);
        self.nonce = self.nonce.wrapping_add(1);
    }
}

impl Default for Drbg {
    fn default() -> Self {
        Self::new()
    }
}

/// The kernel-wide entropy pool.
pub static ENTROPY: IrqSafeMutex<Drbg> = IrqSafeMutex::new(Drbg::new());

/// Mix boot-time seed material into the kernel entropy pool.
///
/// Called during kernel init with whatever the platform provides
/// (RDRAND output when available, plus TSC and boot values).
pub fn seed(material: &[u8]) {
    ENTROPY.lock().reseed(material);
}

/// Whether the pool has received seed material.
pub fn is_seeded() -> bool {
    ENTROPY.lock().is_seeded()
}

/// Fill `out` with random bytes from the kernel pool.
///
/// Returns `false` without touching `out` when the pool was never
/// seeded, so callers cannot mistake deterministic output for
/// randomness.
pub fn fill(out: &mut [u8]) -> bool {
    let mut pool = ENTROPY.lock();
    if !pool.is_seeded() {
        return false;
    }
    pool.fill(out);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.3.2 test vector for the ChaCha20 block
    /// function. This is the standard known-answer test: if the
    /// core is wrong, every downstream security property is void.
    #[test]
    fn chacha20_matches_rfc8439_block_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        // RFC 8439 lays out state words 12..15 as a 32-bit block
        // counter followed by a 96-bit nonce; the vector sets
        // them to 0x00000001, 0x09000000, 0x4a000000, 0x00000000.
        // This block function instead splits those same four
        // words into a 64-bit counter (words 12,13) and a 64-bit
        // nonce (words 14,15), so the identical state is produced
        // by the values below. Matching the RFC output therefore
        // still exercises the real 20-round core.
        let counter: u64 = 0x0900_0000_0000_0001;
        let nonce: u64 = 0x0000_0000_4a00_0000;
        let block = chacha20_block(&key, counter, nonce);

        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(block, expected);
    }

    #[test]
    fn unseeded_pool_reports_unseeded() {
        let drbg = Drbg::new();
        assert!(!drbg.is_seeded());
    }

    #[test]
    fn reseed_marks_seeded_and_changes_output() {
        let mut a = Drbg::new();
        let mut b = Drbg::new();
        a.reseed(b"boot entropy A");
        b.reseed(b"boot entropy B");
        assert!(a.is_seeded());
        assert!(b.is_seeded());

        let mut out_a = [0u8; 64];
        let mut out_b = [0u8; 64];
        a.fill(&mut out_a);
        b.fill(&mut out_b);
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn successive_fills_differ() {
        let mut drbg = Drbg::new();
        drbg.reseed(b"seed");
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        drbg.fill(&mut first);
        drbg.fill(&mut second);
        assert_ne!(first, second);
    }

    #[test]
    fn fill_handles_unaligned_lengths() {
        let mut drbg = Drbg::new();
        drbg.reseed(b"seed");
        // Lengths that are not multiples of the 64-byte block.
        for len in [1usize, 7, 63, 65, 127, 200] {
            let mut buf = alloc::vec![0u8; len];
            drbg.fill(&mut buf);
            assert_eq!(buf.len(), len);
            // A run of all-zero output at these lengths would mean
            // the keystream never reached the tail.
            assert!(buf.iter().any(|byte| *byte != 0));
        }
    }

    #[test]
    fn reseed_is_additive_not_replacing() {
        // Two pools seeded with the same second material but
        // different first material must not converge.
        let mut a = Drbg::new();
        let mut b = Drbg::new();
        a.reseed(b"first-A");
        b.reseed(b"first-B");
        a.reseed(b"common");
        b.reseed(b"common");

        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        a.fill(&mut out_a);
        b.fill(&mut out_b);
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn empty_reseed_does_not_mark_seeded() {
        let mut drbg = Drbg::new();
        drbg.reseed(&[]);
        assert!(!drbg.is_seeded());
    }
}
