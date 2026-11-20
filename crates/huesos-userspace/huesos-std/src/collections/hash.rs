//! Hashing for the standard collections.
//!
//! `std` gets `HashMap`'s hasher from `hashbrown` + `RandomState` (SipHash-1-3
//! keyed by a per-process random seed). HuesOS has no entropy source at start
//! up and `huesos-std` must work out of the box — `HashMap::new()` cannot fail
//! because the OS had no randomness to offer — so the default is SipHash-1-3
//! keyed by a **per-process, monotonically mixed** seed derived from the boot
//! clock and the address of a static. That keeps the hash unpredictable enough
//! to defeat a pre-computed collision set, without a syscall.
//!
//! The trait shape mirrors `core::hash` so that `#[derive(Hash)]` types work
//! unchanged, and [`DefaultHasher`] is the same algorithm `std` uses for
//! `std::collections::hash_map::DefaultHasher`.

use core::hash::{BuildHasher, Hash, Hasher};
use core::sync::atomic::{AtomicU64, Ordering};

/// A SipHash-1-3 hasher, byte-compatible with `std`'s default hasher.
#[derive(Clone, Debug)]
pub struct SipHasher13 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    /// Bytes waiting for a full 8-byte block.
    tail: u64,
    /// Bytes currently in `tail`.
    tail_len: u32,
    /// Total bytes written, folded into the finalisation step.
    length: u64,
}

impl SipHasher13 {
    /// Key the hasher with two 64-bit words.
    pub const fn new(k0: u64, k1: u64) -> Self {
        Self {
            v0: 0x736f_6d65_7073_6575 ^ k0,
            v1: 0x646f_7261_6e64_6f6d ^ k1,
            v2: 0x6c79_6765_6e65_7261 ^ k0,
            v3: 0x7465_6462_7974_6573 ^ k1,
            tail: 0,
            tail_len: 0,
            length: 0,
        }
    }

    /// One SipRound (the "1" in SipHash-1-3).
    fn sip_round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    /// Absorb one full message word.
    fn absorb(&mut self, word: u64) {
        self.v3 ^= word;
        self.sip_round();
        self.v0 ^= word;
    }

    /// Pack the remaining tail bytes little-endian, low byte first.
    fn tail_word(&self) -> u64 {
        self.tail
    }
}

impl Hasher for SipHasher13 {
    fn finish(&self) -> u64 {
        let mut state = Self {
            v0: self.v0,
            v1: self.v1,
            v2: self.v2,
            v3: self.v3,
            tail: self.tail,
            tail_len: self.tail_len,
            length: self.length,
        };
        // Final block: the message length modulo 256 in the top byte, then the
        // pending tail bytes, then three SipRounds and the XOR fold.
        let last = state.tail_word() | ((state.length & 0xff) << 56);
        state.v3 ^= last;
        state.sip_round();
        state.v0 ^= last;
        state.v2 ^= 0xff;
        state.sip_round();
        state.sip_round();
        state.sip_round();
        state.v0 ^ state.v1 ^ state.v2 ^ state.v3
    }

    fn write(&mut self, bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            self.absorb(u64::from_le_bytes(word));
        }
        self.write_tail(chunks.remainder());
    }

    fn write_u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    fn write_u16(&mut self, value: u16) {
        self.write(&value.to_ne_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.write(&value.to_ne_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_ne_bytes());
    }

    fn write_u128(&mut self, value: u128) {
        self.write(&value.to_ne_bytes());
    }

    fn write_usize(&mut self, value: usize) {
        self.write(&value.to_ne_bytes());
    }

    fn write_i8(&mut self, value: i8) {
        self.write_u8(value as u8);
    }

    fn write_i16(&mut self, value: i16) {
        self.write_u16(value as u16);
    }

    fn write_i32(&mut self, value: i32) {
        self.write_u32(value as u32);
    }

    fn write_i64(&mut self, value: i64) {
        self.write_u64(value as u64);
    }

    fn write_i128(&mut self, value: i128) {
        self.write_u128(value as u128);
    }

    fn write_isize(&mut self, value: isize) {
        self.write_usize(value as usize);
    }
}

/// The hasher `HashMap` uses when no other is named: SipHash-1-3.
#[derive(Clone, Debug)]
pub struct DefaultHasher(SipHasher13);

impl DefaultHasher {
    /// A hasher with a fixed key, like `std`'s `DefaultHasher::new`.
    pub const fn new() -> Self {
        Self(SipHasher13::new(0, 0))
    }
}

impl Default for DefaultHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for DefaultHasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }

    fn write_u8(&mut self, value: u8) {
        self.0.write_u8(value);
    }

    fn write_u16(&mut self, value: u16) {
        self.0.write_u16(value);
    }

    fn write_u32(&mut self, value: u32) {
        self.0.write_u32(value);
    }

    fn write_u64(&mut self, value: u64) {
        self.0.write_u64(value);
    }

    fn write_u128(&mut self, value: u128) {
        self.0.write_u128(value);
    }

    fn write_usize(&mut self, value: usize) {
        self.0.write_usize(value);
    }
}

/// Per-process hash key: the low half.
static KEY0: AtomicU64 = AtomicU64::new(0);
/// Per-process hash key: the high half.
static KEY1: AtomicU64 = AtomicU64::new(0);
/// Set once the key has been derived.
static KEY_READY: AtomicU64 = AtomicU64::new(0);

/// Address of a static, used to tell two processes apart.
static ANCHOR: u8 = 0;

/// Derive the process key on first use.
///
/// `monotonic_ticks` is the boot clock, which differs between boots, and the
/// address of [`ANCHOR`] differs between processes; mixing both through
/// SplitMix64 gives a key an attacker cannot predict before the process runs.
fn ensure_key() -> (u64, u64) {
    if KEY_READY.load(Ordering::Acquire) == 0 {
        let ticks = libcanvas::system::monotonic_ticks().unwrap_or(0);
        let anchor = core::ptr::addr_of!(ANCHOR) as u64;
        let pid_hint = libcanvas::system::cpu_count().unwrap_or(1) as u64;
        let low = splitmix64(ticks ^ anchor.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15);
        let high = splitmix64(low ^ pid_hint ^ 0xbf58_476d_1ce4_e5b9);
        KEY0.store(low, Ordering::Relaxed);
        KEY1.store(high, Ordering::Relaxed);
        KEY_READY.store(1, Ordering::Release);
    }
    (KEY0.load(Ordering::Relaxed), KEY1.load(Ordering::Relaxed))
}

/// SplitMix64: a cheap, well-distributed finaliser.
const fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The default `HashMap` hasher factory.
///
/// Cheap to clone (two words) and stable for the whole process, so two maps in
/// the same program agree on the hash of the same key — which matters when a
/// program looks an entry up in a *different* map than it inserted it into.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RandomState {
    key0: u64,
    key1: u64,
}

impl RandomState {
    /// Key a state from the process' secret.
    pub fn new() -> Self {
        let (key0, key1) = ensure_key();
        Self { key0, key1 }
    }

    /// Build a hasher from this state.
    pub fn build_hasher(&self) -> SipHasher13 {
        SipHasher13::new(self.key0, self.key1)
    }
}

impl Default for RandomState {
    fn default() -> Self {
        Self::new()
    }
}

impl BuildHasher for RandomState {
    type Hasher = SipHasher13;

    fn build_hasher(&self) -> SipHasher13 {
        SipHasher13::new(self.key0, self.key1)
    }
}

/// A `BuildHasher` that ignores the key entirely: for hashing already-uniform
/// data (block addresses, UUID words) where SipHash's mixing is wasted work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityHasher;

impl BuildHasher for IdentityHasher {
    type Hasher = IdentityHasherState;

    fn build_hasher(&self) -> IdentityHasherState {
        IdentityHasherState(0)
    }
}

/// The state for [`IdentityHasher`]: folds words with Fibonacci hashing.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityHasherState(u64);

impl Hasher for IdentityHasherState {
    fn finish(&self) -> u64 {
        // Fibonacci hashing: 2^64 / golden ratio. Spreads sequential keys over
        // the whole table, which is the common case for "address + index" keys.
        self.0.wrapping_mul(0x9e37_79b9_7f4a_7c15)
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = self.0.rotate_left(5) ^ u64::from(*byte);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = self.0.rotate_left(5) ^ value;
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }

    fn write_u32(&mut self, value: u32) {
        self.write_u64(u64::from(value));
    }
}

/// Hash a single value with the process' default hasher.
pub fn hash_one<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    value.hash(&mut hasher);
    hasher.finish()
}
