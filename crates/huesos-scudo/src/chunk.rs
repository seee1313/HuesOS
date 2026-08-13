//! Chunk headers and their integrity checksum (Scudo `Chunk`).
//!
//! Every allocation is preceded by a 16-byte header describing it.
//! The header is the allocator's entire trust anchor: `dealloc` is
//! handed nothing but a pointer, so everything it needs to know —
//! which class the chunk came from, how big the user request was,
//! whether the chunk is even currently allocated — is read back out
//! of memory the application can write to.
//!
//! That is exactly how the previous allocator failed. Its free list
//! threaded raw `next` pointers through freed blocks with no
//! validation, so a single bad write (or a double free) silently
//! corrupted the list and the corruption only surfaced much later as
//! a wrong-sized allocation or a bogus OOM.
//!
//! Scudo's answer, reproduced here: store a **checksum** over the
//! header contents *and the chunk's own address*, keyed by a
//! per-process random cookie. Then:
//!
//! - a header overwritten by an overflowing neighbour fails the
//!   checksum, because the attacker cannot recompute it without the
//!   cookie;
//! - a header copied from another chunk fails too, because the
//!   address is part of the checksummed input;
//! - a double free is caught by the state field before any free-list
//!   pointer is touched.
//!
//! Failures are reported to the caller as typed errors rather than
//! silently ignored, so the embedding program decides the policy
//! (abort, log, leak the chunk) instead of the allocator guessing.

use core::sync::atomic::{AtomicU64, Ordering};

/// Bytes of metadata stored immediately before every user pointer.
///
/// Also the allocator's minimum alignment, so `header_end` is
/// 16-byte aligned whenever the header itself is.
pub const HEADER_BYTES: usize = 16;

/// Lifecycle state of a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkState {
    /// In a primary free list or secondary cache, ready for reuse.
    Available,
    /// Currently owned by the application.
    Allocated,
    /// Freed by the application but held back by the quarantine.
    Quarantined,
}

impl ChunkState {
    fn to_bits(self) -> u64 {
        match self {
            ChunkState::Available => 0,
            ChunkState::Allocated => 1,
            ChunkState::Quarantined => 2,
        }
    }

    fn from_bits(bits: u64) -> Option<Self> {
        match bits {
            0 => Some(ChunkState::Available),
            1 => Some(ChunkState::Allocated),
            2 => Some(ChunkState::Quarantined),
            _ => None,
        }
    }
}

/// Where a chunk came from, so `dealloc` returns it to the right place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Carved from a primary region and tracked by size class.
    Primary,
    /// Mapped by the secondary allocator with its own guard pages.
    Secondary,
}

impl Origin {
    fn to_bits(self) -> u64 {
        match self {
            Origin::Primary => 0,
            Origin::Secondary => 1,
        }
    }

    fn from_bits(bits: u64) -> Option<Self> {
        match bits {
            0 => Some(Origin::Primary),
            1 => Some(Origin::Secondary),
            _ => None,
        }
    }
}

/// Decoded chunk metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Lifecycle state.
    pub state: ChunkState,
    /// Which allocator produced the chunk.
    pub origin: Origin,
    /// Size class index (primary only; 0 for secondary chunks).
    pub class: u8,
    /// Distance in bytes from the start of the underlying block to
    /// this header, used when alignment forced the header to move.
    pub offset: u16,
    /// The size the application actually asked for. Kept so
    /// `dealloc` can verify the caller's `Layout` and so `realloc`
    /// knows how many bytes to copy.
    pub request_size: u32,
}

/// Why a header failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// The checksum did not match: the header was corrupted, forged,
    /// or the pointer does not point just past a real header.
    BadChecksum,
    /// The checksum matched but a field held a value outside its
    /// defined range (a kernel-side consistency failure, not
    /// something an attacker can reach without the cookie).
    Malformed,
    /// The chunk was not in the state the operation required — most
    /// importantly, a double free.
    UnexpectedState {
        /// State recorded in the header.
        found: ChunkState,
    },
}

/// Per-process cookie mixed into every checksum.
///
/// Seeded once at startup from kernel entropy. It is `AtomicU64`
/// rather than a plain field so the allocator's shared `&self` paths
/// can read it without a lock, and so a not-yet-seeded cookie is
/// observable rather than racy.
static COOKIE: AtomicU64 = AtomicU64::new(0);

/// Install the process-wide header cookie.
///
/// Called once during allocator initialisation with kernel entropy.
/// A zero cookie is rejected: it would make checksums predictable,
/// and the most likely way to get one is an entropy syscall whose
/// failure went unchecked.
pub fn set_cookie(value: u64) -> bool {
    if value == 0 {
        return false;
    }
    COOKIE.store(value, Ordering::Relaxed);
    true
}

/// Whether a non-zero cookie has been installed.
pub fn cookie_installed() -> bool {
    COOKIE.load(Ordering::Relaxed) != 0
}

fn cookie() -> u64 {
    COOKIE.load(Ordering::Relaxed)
}

/// Pack the header fields into their 64-bit on-disk form.
fn pack_body(header: &ChunkHeader) -> u64 {
    (header.state.to_bits() & 0x3)
        | ((header.origin.to_bits() & 0x1) << 2)
        | ((header.class as u64 & 0xff) << 3)
        | ((header.offset as u64 & 0xffff) << 11)
        | ((header.request_size as u64 & 0xffff_ffff) << 27)
}

fn unpack_body(body: u64) -> Option<ChunkHeader> {
    let state = ChunkState::from_bits(body & 0x3)?;
    let origin = Origin::from_bits((body >> 2) & 0x1)?;
    Some(ChunkHeader {
        state,
        origin,
        class: ((body >> 3) & 0xff) as u8,
        offset: ((body >> 11) & 0xffff) as u16,
        request_size: ((body >> 27) & 0xffff_ffff) as u32,
    })
}

/// Compute the header checksum for `body` at `address`.
///
/// Binding the address is what stops a valid header being copied
/// from one chunk onto another. The mixing function is a 64-bit
/// avalanche (SplitMix64's finaliser): cheap enough to run on every
/// allocation and free, and strong enough that recovering the cookie
/// from observed checksums is not practical.
fn checksum(body: u64, address: usize) -> u64 {
    let mut value = body ^ (address as u64).rotate_left(32) ^ cookie();
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    value
}

/// Write `header` to the 16 bytes ending at `header_end`.
///
/// # Safety
/// `header_end - HEADER_BYTES` must be a writable, 16-byte aligned
/// address inside a block this allocator owns.
pub unsafe fn write_header(header_end: *mut u8, header: &ChunkHeader) {
    let base = unsafe { header_end.sub(HEADER_BYTES) };
    let body = pack_body(header);
    let sum = checksum(body, header_end as usize);
    // Two aligned 64-bit stores; `base` is 16-byte aligned by
    // construction, so both are naturally aligned.
    unsafe {
        base.cast::<u64>().write(body);
        base.cast::<u64>().add(1).write(sum);
    }
}

/// Read and validate the header ending at `header_end`.
///
/// # Safety
/// `header_end - HEADER_BYTES` must be a readable, 16-byte aligned
/// address inside a block this allocator owns.
pub unsafe fn read_header(header_end: *const u8) -> Result<ChunkHeader, HeaderError> {
    let base = unsafe { header_end.sub(HEADER_BYTES) };
    let (body, sum) = unsafe { (base.cast::<u64>().read(), base.cast::<u64>().add(1).read()) };
    if sum != checksum(body, header_end as usize) {
        return Err(HeaderError::BadChecksum);
    }
    unpack_body(body).ok_or(HeaderError::Malformed)
}

/// Validate a header and require a particular state.
///
/// # Safety
/// Same contract as [`read_header`].
pub unsafe fn read_header_expecting(
    header_end: *const u8,
    expected: ChunkState,
) -> Result<ChunkHeader, HeaderError> {
    let header = unsafe { read_header(header_end)? };
    if header.state != expected {
        return Err(HeaderError::UnexpectedState {
            found: header.state,
        });
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_cookie<F: FnOnce()>(body: F) {
        assert!(set_cookie(0x0123_4567_89ab_cdef));
        body();
    }

    /// A 64-byte scratch block, 16-byte aligned, standing in for a
    /// real chunk during header round-trip tests.
    #[repr(align(16))]
    struct Block([u8; 64]);

    #[test]
    fn header_round_trips() {
        with_cookie(|| {
            let mut block = Block([0u8; 64]);
            let header_end = unsafe { block.0.as_mut_ptr().add(HEADER_BYTES) };
            let written = ChunkHeader {
                state: ChunkState::Allocated,
                origin: Origin::Primary,
                class: 7,
                offset: 0,
                request_size: 100,
            };
            unsafe { write_header(header_end, &written) };
            let read = unsafe { read_header(header_end) };
            assert_eq!(read, Ok(written));
        });
    }

    #[test]
    fn all_field_extremes_survive_packing() {
        with_cookie(|| {
            let mut block = Block([0u8; 64]);
            let header_end = unsafe { block.0.as_mut_ptr().add(HEADER_BYTES) };
            let written = ChunkHeader {
                state: ChunkState::Quarantined,
                origin: Origin::Secondary,
                class: u8::MAX,
                offset: u16::MAX,
                request_size: u32::MAX,
            };
            unsafe { write_header(header_end, &written) };
            assert_eq!(unsafe { read_header(header_end) }, Ok(written));
        });
    }

    /// The core hardening property: corrupting any header byte must
    /// be detected. This is the check the old allocator lacked.
    #[test]
    fn corrupted_header_is_detected() {
        with_cookie(|| {
            for byte_index in 0..HEADER_BYTES {
                let mut block = Block([0u8; 64]);
                let header_end = unsafe { block.0.as_mut_ptr().add(HEADER_BYTES) };
                let written = ChunkHeader {
                    state: ChunkState::Allocated,
                    origin: Origin::Primary,
                    class: 3,
                    offset: 0,
                    request_size: 48,
                };
                unsafe { write_header(header_end, &written) };
                block.0[byte_index] ^= 0x01;
                let read = unsafe { read_header(header_end) };
                assert_eq!(
                    read,
                    Err(HeaderError::BadChecksum),
                    "flipping byte {byte_index} of the header must be caught"
                );
            }
        });
    }

    /// A header lifted verbatim from another chunk must not validate
    /// at its new address.
    #[test]
    fn header_is_bound_to_its_address() {
        with_cookie(|| {
            let mut block = Block([0u8; 64]);
            let first_end = unsafe { block.0.as_mut_ptr().add(HEADER_BYTES) };
            let second_end = unsafe { block.0.as_mut_ptr().add(HEADER_BYTES * 2) };
            let written = ChunkHeader {
                state: ChunkState::Allocated,
                origin: Origin::Primary,
                class: 1,
                offset: 0,
                request_size: 16,
            };
            unsafe { write_header(first_end, &written) };
            // Copy the raw header bytes over the neighbouring chunk.
            let (first, second) = block.0.split_at_mut(HEADER_BYTES);
            second[..HEADER_BYTES].copy_from_slice(first);
            assert_eq!(
                unsafe { read_header(second_end) },
                Err(HeaderError::BadChecksum)
            );
        });
    }

    /// Different cookies must produce different checksums, otherwise
    /// the cookie is decorative.
    #[test]
    fn cookie_changes_the_checksum() {
        let mut block = Block([0u8; 64]);
        let header_end = unsafe { block.0.as_mut_ptr().add(HEADER_BYTES) };
        let header = ChunkHeader {
            state: ChunkState::Allocated,
            origin: Origin::Primary,
            class: 2,
            offset: 0,
            request_size: 32,
        };

        assert!(set_cookie(0xaaaa_bbbb_cccc_dddd));
        unsafe { write_header(header_end, &header) };
        let first_sum = unsafe { block.0.as_ptr().cast::<u64>().add(1).read() };

        assert!(set_cookie(0x1111_2222_3333_4444));
        unsafe { write_header(header_end, &header) };
        let second_sum = unsafe { block.0.as_ptr().cast::<u64>().add(1).read() };

        assert_ne!(first_sum, second_sum);
        // And the old checksum no longer validates under the new cookie.
        assert!(set_cookie(0xaaaa_bbbb_cccc_dddd));
        unsafe { write_header(header_end, &header) };
        assert!(set_cookie(0x1111_2222_3333_4444));
        assert_eq!(
            unsafe { read_header(header_end) },
            Err(HeaderError::BadChecksum)
        );
    }

    #[test]
    fn zero_cookie_is_rejected() {
        assert!(!set_cookie(0));
    }

    /// Double free: the second free sees `Quarantined`, not
    /// `Allocated`, and is refused before touching any free list.
    #[test]
    fn state_mismatch_is_reported() {
        with_cookie(|| {
            let mut block = Block([0u8; 64]);
            let header_end = unsafe { block.0.as_mut_ptr().add(HEADER_BYTES) };
            let header = ChunkHeader {
                state: ChunkState::Quarantined,
                origin: Origin::Primary,
                class: 0,
                offset: 0,
                request_size: 16,
            };
            unsafe { write_header(header_end, &header) };
            assert_eq!(
                unsafe { read_header_expecting(header_end, ChunkState::Allocated) },
                Err(HeaderError::UnexpectedState {
                    found: ChunkState::Quarantined
                })
            );
        });
    }
}
