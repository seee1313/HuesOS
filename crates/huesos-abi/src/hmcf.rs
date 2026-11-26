//! Validated PCI configuration-window snapshot (`HMCF`).
//!
//! `HMCF` is the bounded, pointer-free, versioned wire contract between the
//! producer of ECAM configuration windows (`acpi-manager`, which interprets
//! the archived `MCFG` table) and the holder of the configuration-mint
//! authority (DriverManager) and the dynamic kernel mint request
//! (see `docs/ACPI_RING3.md` and `docs/PCI_PRODUCTION_ROADMAP.md`, Stage C.1).
//!
//! ## What this format is
//!
//! - a complete, self-describing image: one fixed header plus a counted
//!   array of fixed-size records;
//! - bound to one immutable firmware snapshot through
//!   `firmware_snapshot_id` (the archive-v2 identity) and to one producer
//!   incarnation through `producer_generation` (the supervised process
//!   generation), so a stale generation cannot be confused with the
//!   current one;
//! - canonical: records are strictly increasing in
//!   `(segment, start_bus, ecam_base)`, and any set of valid records
//!   encodes to exactly one byte image.
//!
//! ## What this format is not
//!
//! - The 32-bit wrapping checksum is a **consistency** check for
//!   corruption and torn writes. It is **not** an authentication
//!   primitive and is not a substitute for the capability model:
//!   authenticity comes from the immutable VMO handle, the
//!   snapshot/generation binding, and the kernel cross-check against the
//!   bound archive's own `MCFG` bytes (AP-8). An attacker who can both
//!   write the VMO and recompute the checksum gains nothing unless they
//!   also hold a capability they were never granted.
//! - `HMCF` does not grant config access, and it must never be read as a
//!   claim that a BAR aperture is allocatable. It describes ECAM
//!   transport windows only. Semantic validation (no overlaps, no RAM
//!   aliases, no widened ranges) remains the producer's and the kernel's
//!   job; this decoder deliberately performs format checks only, so
//!   DriverManager can validate and retain a snapshot without
//!   re-interpreting PCI policy.
//!
//! ## Layout (all integers little-endian)
//!
//! Header, [`HEADER_BYTES`] (40) bytes:
//!
//! ```text
//! 0..4   magic                 "HMCF"
//! 4..6   version               u16 = 1
//! 6..8   header_bytes          u16 = 40
//! 8..12  total_size            u32 = HEADER_BYTES + record_count * RECORD_BYTES
//! 12..20 firmware_snapshot_id  u64, non-zero (archive-v2 snapshot identity)
//! 20..28 producer_generation   u64, non-zero (supervised process generation)
//! 28..32 record_count          u32, 1..=64
//! 32..36 flags                 u32 = 0 (no defined flags in v1)
//! 36..40 checksum              u32, wrapping byte-sum of the image with these
//!                               4 bytes treated as zero
//! ```
//!
//! Record, [`RECORD_BYTES`] (32) bytes each:
//!
//! ```text
//! 0..2   segment               u16
//! 2      start_bus             u8
//! 3      end_bus               u8, >= start_bus
//! 4..8   reserved              u32 = 0
//! 8..16  ecam_base             u64, 1 MiB aligned
//! 16..24 span_bytes            u64, exactly (end_bus - start_bus + 1) * 1 MiB
//! 24..28 flags                 u32 = 0 (no defined record flags in v1)
//! 28..32 reserved              u32 = 0
//! ```
//!
//! The image never exceeds [`MAX_BYTES`] (2088 bytes), so a consumer can
//! bound every allocation by construction. Both identity fields are
//! required to be non-zero, matching the archive-v2 rule that snapshot 0
//! means "no firmware snapshot".

/// Wire magic: ASCII `HMCF`.
pub const MAGIC: [u8; 4] = *b"HMCF";
/// Current wire version.
pub const VERSION: u16 = 1;
/// Fixed header bytes.
pub const HEADER_BYTES: usize = 40;
/// Fixed record bytes.
pub const RECORD_BYTES: usize = 32;
/// Maximum ECAM windows accepted in one snapshot. Mirrors the MCFG
/// decoder's `MAX_MCFG_ALLOCATIONS`.
pub const MAX_RECORDS: u32 = 64;
/// Maximum complete image bytes.
pub const MAX_BYTES: usize = HEADER_BYTES + MAX_RECORDS as usize * RECORD_BYTES;
/// Bytes covered by one ECAM bus (256 buses of 4 KiB functions of 8
/// functions). Mirrors `huesos_pci::ECAM_BUS_BYTES`; duplicated here so
/// this crate stays dependency-free.
pub const BUS_BYTES: u64 = 1 << 20;

const CHECKSUM_OFFSET: usize = 36;
const SEGMENT_OFFSET: usize = 0;
const START_BUS_OFFSET: usize = 2;
const END_BUS_OFFSET: usize = 3;
const ECAM_BASE_OFFSET: usize = 8;
const SPAN_BYTES_OFFSET: usize = 16;
const RECORD_FLAGS_OFFSET: usize = 24;

/// Rejection reason for an `HMCF` image or record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HmcfError {
    /// Fewer bytes than the fixed header, or an encode output buffer that
    /// cannot hold the image.
    Truncated,
    /// Magic, version, header size, total size, or a non-zero identity
    /// field was invalid.
    Format,
    /// A reserved field or a flag with no defined v1 meaning was non-zero.
    Reserved,
    /// `record_count` was zero, exceeded [`MAX_RECORDS`], or disagreed with
    /// the declared total size.
    Count,
    /// The wrapping byte-sum checksum did not match the image.
    Checksum,
    /// `start_bus` exceeded `end_bus`.
    BusRange,
    /// `ecam_base` was not aligned to [`BUS_BYTES`].
    MisalignedBase,
    /// `span_bytes` disagreed with the bus range.
    Span,
    /// `ecam_base + span_bytes` overflowed 64 bits.
    AddressOverflow,
    /// Records were not strictly increasing in
    /// `(segment, start_bus, ecam_base)`, or two records collided.
    NotCanonical,
    /// Two windows cover the same bus range in one segment, or their
    /// physical spans intersect. Rejected at encode time only; the wire
    /// decoder performs format checks only.
    Overlap,
    /// The image was produced by a different supervised generation than
    /// the one expected by the caller.
    StaleGeneration,
    /// The image belongs to a different firmware snapshot than the one
    /// bound to the caller's archive.
    SnapshotMismatch,
}

/// One ECAM configuration-window record (decoded view).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HmcfRecord {
    /// PCI segment group.
    pub segment: u16,
    /// First bus served by the window, inclusive.
    pub start_bus: u8,
    /// Last bus served by the window, inclusive.
    pub end_bus: u8,
    /// Physical base of the ECAM window, aligned to [`BUS_BYTES`].
    pub ecam_base: u64,
    /// Window length in bytes; exactly the bus span.
    pub span_bytes: u64,
    /// Record flags. No flags are defined in v1; must be zero.
    pub flags: u32,
}

impl HmcfRecord {
    /// Construct a checked window record, computing `span_bytes` from the
    /// bus range with checked arithmetic.
    pub fn new(
        segment: u16,
        start_bus: u8,
        end_bus: u8,
        ecam_base: u64,
    ) -> Result<Self, HmcfError> {
        let span_bytes = bus_span(start_bus, end_bus)?;
        let record = Self {
            segment,
            start_bus,
            end_bus,
            ecam_base,
            span_bytes,
            flags: 0,
        };
        record.validate()?;
        Ok(record)
    }

    /// Shared format checks for encode and decode paths.
    fn validate(&self) -> Result<(), HmcfError> {
        if self.start_bus > self.end_bus {
            return Err(HmcfError::BusRange);
        }
        if self.flags != 0 {
            return Err(HmcfError::Reserved);
        }
        if !self.ecam_base.is_multiple_of(BUS_BYTES) {
            return Err(HmcfError::MisalignedBase);
        }
        let expected_span = bus_span(self.start_bus, self.end_bus)?;
        if self.span_bytes != expected_span {
            return Err(HmcfError::Span);
        }
        let end_exclusive = self
            .ecam_base
            .checked_add(self.span_bytes)
            .ok_or(HmcfError::AddressOverflow)?;
        if end_exclusive <= self.ecam_base {
            return Err(HmcfError::AddressOverflow);
        }
        Ok(())
    }

    /// Canonical ordering key.
    fn key(self) -> (u16, u8, u64) {
        (self.segment, self.start_bus, self.ecam_base)
    }

    /// Exclusive physical end of the window.
    fn physical_end(self) -> u64 {
        // Callers hold a record that already passed `validate`, so the sum
        // cannot overflow.
        self.ecam_base + self.span_bytes
    }
}

/// Compute the span of a bus range, or [`HmcfError::AddressOverflow`] if
/// the bus count itself overflowed (impossible today, kept defensive).
fn bus_span(start_bus: u8, end_bus: u8) -> Result<u64, HmcfError> {
    if start_bus > end_bus {
        return Err(HmcfError::BusRange);
    }
    let bus_count = u64::from(end_bus) - u64::from(start_bus) + 1;
    bus_count
        .checked_mul(BUS_BYTES)
        .ok_or(HmcfError::AddressOverflow)
}

/// Decoded, checksum-verified view over a complete `HMCF` image.
///
/// The view borrows the image; record fields are read on demand. Cheap to
/// hold, impossible to misread: constructing it runs every format check.
#[derive(Clone, Copy)]
pub struct HmcfView<'a> {
    bytes: &'a [u8],
    record_count: usize,
}

impl<'a> core::fmt::Debug for HmcfView<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HmcfView")
            .field("firmware_snapshot_id", &self.firmware_snapshot_id())
            .field("producer_generation", &self.producer_generation())
            .field("record_count", &self.record_count)
            .finish()
    }
}

impl<'a> PartialEq for HmcfView<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<'a> Eq for HmcfView<'a> {}

impl<'a> HmcfView<'a> {
    /// Firmware snapshot identity bound to this image (archive-v2).
    pub fn firmware_snapshot_id(&self) -> u64 {
        u64_at(self.bytes, 12).unwrap_or(0)
    }

    /// Supervised producer generation that encoded this image.
    pub fn producer_generation(&self) -> u64 {
        u64_at(self.bytes, 20).unwrap_or(0)
    }

    /// Number of window records.
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    /// Decode one record by index. Returns `None` past `record_count`.
    pub fn record(&self, index: usize) -> Option<HmcfRecord> {
        if index >= self.record_count {
            return None;
        }
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        Some(HmcfRecord {
            segment: u16_at(self.bytes, offset + SEGMENT_OFFSET)?,
            start_bus: *self.bytes.get(offset + START_BUS_OFFSET)?,
            end_bus: *self.bytes.get(offset + END_BUS_OFFSET)?,
            ecam_base: u64_at(self.bytes, offset + ECAM_BASE_OFFSET)?,
            span_bytes: u64_at(self.bytes, offset + SPAN_BYTES_OFFSET)?,
            flags: u32_at(self.bytes, offset + RECORD_FLAGS_OFFSET)?,
        })
    }

    /// Iterate all records in canonical wire order.
    pub fn records(&self) -> impl Iterator<Item = HmcfRecord> + '_ {
        (0..self.record_count).filter_map(move |index| self.record(index))
    }

    /// Verify that this image belongs to `expected_generation` of the
    /// supervised producer and to `expected_snapshot` of the firmware
    /// archive.
    ///
    /// Fail-closed: any mismatch rejects the image. Callers must compare
    /// against the *current* supervised generation and the snapshot
    /// identity decoded from the bound archive, never against values the
    /// image itself merely carries.
    pub fn check_binding(
        &self,
        expected_generation: u64,
        expected_snapshot: u64,
    ) -> Result<(), HmcfError> {
        if self.producer_generation() != expected_generation {
            return Err(HmcfError::StaleGeneration);
        }
        if self.firmware_snapshot_id() != expected_snapshot {
            return Err(HmcfError::SnapshotMismatch);
        }
        Ok(())
    }
}

/// Validate the static header of a (possibly partial) image and return
/// its declared total size in bytes.
///
/// This is the two-phase read helper for consumers that must size a
/// read-only object before fetching it: it checks everything that fits in
/// the fixed header (magic, version, sizes, flags, non-zero identities,
/// record-count/size agreement) and nothing else. The returned size is
/// always in `HEADER_BYTES + RECORD_BYTES ..= MAX_BYTES`.
pub fn declared_size(prefix: &[u8]) -> Result<usize, HmcfError> {
    if prefix.len() < HEADER_BYTES {
        return Err(HmcfError::Truncated);
    }
    validate_header(prefix)
}

/// Decode and fully validate a complete `HMCF` image.
///
/// Performs format checks only (magic, version, sizes, flags, checksum,
/// per-record arithmetic, canonical order). Overlap and other PCI policy
/// are deliberately out of scope here; producers must encode through
/// [`encode`], and the kernel re-validates against the bound archive.
pub fn decode(bytes: &[u8]) -> Result<HmcfView<'_>, HmcfError> {
    let total = validate_header(bytes)?;
    if bytes.len() != total {
        return Err(HmcfError::Format);
    }
    verify_checksum(bytes)?;
    let record_count = u32_at(bytes, 28).ok_or(HmcfError::Truncated)? as usize;
    let mut previous: Option<HmcfRecord> = None;
    for index in 0..record_count {
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        let record = decode_record(bytes, offset)?;
        if let Some(previous) = previous {
            if record.key() <= previous.key() {
                return Err(HmcfError::NotCanonical);
            }
        }
        previous = Some(record);
    }
    Ok(HmcfView {
        bytes,
        record_count,
    })
}

/// Compute the encoded size for `record_count` records, or `None` if the
/// count is out of range.
pub fn encoded_len(record_count: usize) -> Option<usize> {
    if record_count == 0 || record_count > MAX_RECORDS as usize {
        return None;
    }
    Some(HEADER_BYTES + record_count * RECORD_BYTES)
}

/// Encode `records` into `output`, returning the number of bytes written.
///
/// The output is canonical: records are sorted by
/// `(segment, start_bus, ecam_base)` and strictly increasing keys are
/// required, so the same window set always produces the same byte image.
/// Encode additionally applies the producer-side semantic checks the wire
/// format intentionally leaves to consumers: no overlapping windows and no
/// duplicate keys.
pub fn encode(
    firmware_snapshot_id: u64,
    producer_generation: u64,
    records: &[HmcfRecord],
    output: &mut [u8],
) -> Result<usize, HmcfError> {
    if firmware_snapshot_id == 0 || producer_generation == 0 {
        return Err(HmcfError::Format);
    }
    if records.is_empty() || records.len() > MAX_RECORDS as usize {
        return Err(HmcfError::Count);
    }
    let total = encoded_len(records.len()).ok_or(HmcfError::Count)?;
    if output.len() < total {
        return Err(HmcfError::Truncated);
    }

    let mut scratch = [HmcfRecord {
        segment: 0,
        start_bus: 0,
        end_bus: 0,
        ecam_base: 0,
        span_bytes: BUS_BYTES,
        flags: 0,
    }; MAX_RECORDS as usize];
    for (slot, record) in scratch.iter_mut().zip(records.iter()) {
        record.validate()?;
        *slot = *record;
    }
    let scratch = &mut scratch[..records.len()];
    insertion_sort(scratch);

    for index in 1..scratch.len() {
        if scratch[index].key() <= scratch[index - 1].key() {
            return Err(HmcfError::NotCanonical);
        }
    }
    for index in 0..scratch.len() {
        for other in index + 1..scratch.len() {
            if windows_overlap(scratch[index], scratch[other]) {
                return Err(HmcfError::Overlap);
            }
        }
    }

    output[..total].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, VERSION)?;
    put_u16(output, 6, HEADER_BYTES as u16)?;
    put_u32(output, 8, total as u32)?;
    put_u64(output, 12, firmware_snapshot_id)?;
    put_u64(output, 20, producer_generation)?;
    put_u32(output, 28, records.len() as u32)?;
    put_u32(output, 32, 0)?;
    put_u32(output, CHECKSUM_OFFSET, 0)?;
    for (index, record) in scratch.iter().enumerate() {
        encode_record(record, &mut output[HEADER_BYTES + index * RECORD_BYTES..])?;
    }
    let sum = wrapping_sum(&output[..total]);
    put_u32(output, CHECKSUM_OFFSET, sum)?;
    Ok(total)
}

/// Static header checks shared by [`decode`] and [`declared_size`].
///
/// Returns the declared total size; callers compare against their actual
/// byte count.
fn validate_header(bytes: &[u8]) -> Result<usize, HmcfError> {
    if bytes.len() < HEADER_BYTES {
        return Err(HmcfError::Truncated);
    }
    if bytes[..4] != MAGIC
        || u16_at(bytes, 4).ok_or(HmcfError::Truncated)? != VERSION
        || u16_at(bytes, 6).ok_or(HmcfError::Truncated)? as usize != HEADER_BYTES
    {
        return Err(HmcfError::Format);
    }
    if u32_at(bytes, 32).ok_or(HmcfError::Truncated)? != 0 {
        return Err(HmcfError::Reserved);
    }
    let firmware_snapshot_id = u64_at(bytes, 12).ok_or(HmcfError::Truncated)?;
    let producer_generation = u64_at(bytes, 20).ok_or(HmcfError::Truncated)?;
    if firmware_snapshot_id == 0 || producer_generation == 0 {
        return Err(HmcfError::Format);
    }
    let record_count = u32_at(bytes, 28).ok_or(HmcfError::Truncated)?;
    if record_count == 0 || record_count > MAX_RECORDS {
        return Err(HmcfError::Count);
    }
    let expected_total = HEADER_BYTES + record_count as usize * RECORD_BYTES;
    if u32_at(bytes, 8).ok_or(HmcfError::Truncated)? as usize != expected_total {
        return Err(HmcfError::Format);
    }
    Ok(expected_total)
}

fn decode_record(bytes: &[u8], offset: usize) -> Result<HmcfRecord, HmcfError> {
    if u32_at(bytes, offset + 4).ok_or(HmcfError::Truncated)? != 0 {
        return Err(HmcfError::Reserved);
    }
    if u32_at(bytes, offset + RECORD_FLAGS_OFFSET).ok_or(HmcfError::Truncated)? != 0 {
        return Err(HmcfError::Reserved);
    }
    if u32_at(bytes, offset + 28).ok_or(HmcfError::Truncated)? != 0 {
        return Err(HmcfError::Reserved);
    }
    let record = HmcfRecord {
        segment: u16_at(bytes, offset + SEGMENT_OFFSET).ok_or(HmcfError::Truncated)?,
        start_bus: *bytes
            .get(offset + START_BUS_OFFSET)
            .ok_or(HmcfError::Truncated)?,
        end_bus: *bytes
            .get(offset + END_BUS_OFFSET)
            .ok_or(HmcfError::Truncated)?,
        ecam_base: u64_at(bytes, offset + ECAM_BASE_OFFSET).ok_or(HmcfError::Truncated)?,
        span_bytes: u64_at(bytes, offset + SPAN_BYTES_OFFSET).ok_or(HmcfError::Truncated)?,
        flags: u32_at(bytes, offset + RECORD_FLAGS_OFFSET).ok_or(HmcfError::Truncated)?,
    };
    record.validate()?;
    Ok(record)
}

fn encode_record(record: &HmcfRecord, output: &mut [u8]) -> Result<(), HmcfError> {
    if output.len() < RECORD_BYTES {
        return Err(HmcfError::Truncated);
    }
    output[..RECORD_BYTES].fill(0);
    put_u16(output, SEGMENT_OFFSET, record.segment)?;
    output[START_BUS_OFFSET] = record.start_bus;
    output[END_BUS_OFFSET] = record.end_bus;
    put_u64(output, ECAM_BASE_OFFSET, record.ecam_base)?;
    put_u64(output, SPAN_BYTES_OFFSET, record.span_bytes)?;
    put_u32(output, RECORD_FLAGS_OFFSET, record.flags)?;
    Ok(())
}

/// Producer-side overlap rule, mirroring the MCFG decoder: two windows
/// overlap when their physical spans intersect, or when they cover the
/// same bus range in one segment.
fn windows_overlap(a: HmcfRecord, b: HmcfRecord) -> bool {
    let physical = a.ecam_base < b.physical_end() && b.ecam_base < a.physical_end();
    let buses = a.segment == b.segment && a.start_bus <= b.end_bus && b.start_bus <= a.end_bus;
    physical || buses
}

fn insertion_sort(records: &mut [HmcfRecord]) {
    for index in 1..records.len() {
        let mut cursor = index;
        while cursor > 0 && records[cursor].key() < records[cursor - 1].key() {
            records.swap(cursor, cursor - 1);
            cursor -= 1;
        }
    }
}

fn verify_checksum(bytes: &[u8]) -> Result<(), HmcfError> {
    let stored = u32_at(bytes, CHECKSUM_OFFSET).ok_or(HmcfError::Truncated)?;
    let sum = wrapping_sum(bytes);
    if stored != sum {
        return Err(HmcfError::Checksum);
    }
    Ok(())
}

/// Wrapping byte-sum of the image with the checksum field treated as zero.
fn wrapping_sum(bytes: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if (CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4).contains(&index) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(*byte));
    }
    sum
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), HmcfError> {
    let end = offset.checked_add(2).ok_or(HmcfError::Truncated)?;
    let slice = output.get_mut(offset..end).ok_or(HmcfError::Truncated)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), HmcfError> {
    let end = offset.checked_add(4).ok_or(HmcfError::Truncated)?;
    let slice = output.get_mut(offset..end).ok_or(HmcfError::Truncated)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), HmcfError> {
    let end = offset.checked_add(8).ok_or(HmcfError::Truncated)?;
    let slice = output.get_mut(offset..end).ok_or(HmcfError::Truncated)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let value = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT: u64 = 0x1122_3344_5566_7788;
    const GENERATION: u64 = 42;

    const ZERO_RECORD: HmcfRecord = HmcfRecord {
        segment: 0,
        start_bus: 0,
        end_bus: 0,
        ecam_base: 0,
        span_bytes: BUS_BYTES,
        flags: 0,
    };

    fn record(segment: u16, start_bus: u8, end_bus: u8, ecam_base: u64) -> HmcfRecord {
        match HmcfRecord::new(segment, start_bus, end_bus, ecam_base) {
            Ok(record) => record,
            Err(_) => {
                assert!(false, "fixture record must construct");
                ZERO_RECORD
            }
        }
    }

    fn sample_records() -> [HmcfRecord; 3] {
        [
            record(0, 0, 63, 0x8000_0000),
            record(0, 128, 143, 0xa000_0000),
            record(7, 16, 31, 0x9000_0000),
        ]
    }

    /// Encode a fixture image; returns the buffer and the written length.
    fn encoded_image(
        snapshot: u64,
        generation: u64,
        records: &[HmcfRecord],
    ) -> ([u8; MAX_BYTES], usize) {
        let mut output = [0u8; MAX_BYTES];
        match encode(snapshot, generation, records, &mut output) {
            Ok(total) => (output, total),
            Err(_) => {
                assert!(false, "fixture must encode");
                (output, 0)
            }
        }
    }

    /// Recompute the checksum of an image in place (fixture helper for
    /// crafting corrupted-but-well-formed wire images).
    fn fix_checksum(bytes: &mut [u8]) {
        bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].fill(0);
        let sum = wrapping_sum(bytes);
        bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&sum.to_le_bytes());
    }

    #[test]
    fn multiple_segments_and_nonzero_start_bus_round_trip() {
        let records = sample_records();
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &records);
        let Ok(view) = decode(&image[..total]) else {
            assert!(false, "encoded image must decode");
            return;
        };
        assert_eq!(view.firmware_snapshot_id(), SNAPSHOT);
        assert_eq!(view.producer_generation(), GENERATION);
        assert_eq!(view.record_count(), 3);
        let mut expected = records;
        expected.sort_by_key(|record| record.key());
        let mut got = [ZERO_RECORD; 3];
        for (index, record) in view.records().enumerate() {
            assert!(index < got.len(), "iterator must stay in bounds");
            got[index] = record;
        }
        assert_eq!(got, expected);
        assert_eq!(view.record(3), None);
    }

    #[test]
    fn deterministic_canonical_encoding() {
        let records = sample_records();
        let (first, first_total) = encoded_image(SNAPSHOT, GENERATION, &records);
        let (second, second_total) = encoded_image(SNAPSHOT, GENERATION, &records);
        assert_eq!(first_total, second_total);
        assert_eq!(&first[..first_total], &second[..second_total]);
        // Any input permutation yields the same canonical bytes.
        let mut shuffled = records;
        shuffled.rotate_left(1);
        let (third, third_total) = encoded_image(SNAPSHOT, GENERATION, &shuffled);
        assert_eq!(first_total, third_total);
        assert_eq!(&first[..first_total], &third[..third_total]);
        assert_eq!(encoded_len(3), Some(HEADER_BYTES + 3 * RECORD_BYTES));
        assert_eq!(encoded_len(0), None);
        assert_eq!(encoded_len(MAX_RECORDS as usize + 1), None);
    }

    #[test]
    fn adjacent_windows_are_accepted() {
        let records = [
            record(0, 0, 63, 0x8000_0000),
            record(0, 64, 127, 0x8000_0000 + 64 * BUS_BYTES),
            record(3, 0, 15, 0xb000_0000),
        ];
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &records);
        let Ok(view) = decode(&image[..total]) else {
            assert!(false, "adjacent windows must decode");
            return;
        };
        assert_eq!(view.record_count(), 3);
    }

    #[test]
    fn overlapping_windows_are_rejected_at_encode_time() {
        // Same segment, overlapping buses.
        let same_segment = [
            record(0, 0, 63, 0x8000_0000),
            record(0, 32, 95, 0x9000_0000),
        ];
        let mut output = [0u8; MAX_BYTES];
        assert_eq!(
            encode(SNAPSHOT, GENERATION, &same_segment, &mut output),
            Err(HmcfError::Overlap)
        );
        // Different segments, same physical window.
        let physical = [record(0, 0, 63, 0x8000_0000), record(1, 0, 63, 0x8000_0000)];
        assert_eq!(
            encode(SNAPSHOT, GENERATION, &physical, &mut output),
            Err(HmcfError::Overlap)
        );
        // Adjacent physical windows never trip the check.
        let adjacent = [record(0, 0, 63, 0x8000_0000), record(1, 0, 63, 0x8400_0000)];
        assert!(encode(SNAPSHOT, GENERATION, &adjacent, &mut output).is_ok());
    }

    #[test]
    fn rejects_empty_and_oversized_record_sets() {
        let mut output = [0u8; MAX_BYTES];
        assert_eq!(
            encode(SNAPSHOT, GENERATION, &[], &mut output),
            Err(HmcfError::Count)
        );
        let too_many = [record(0, 0, 0, 0x8000_0000); (MAX_RECORDS as usize) + 1];
        assert_eq!(
            encode(SNAPSHOT, GENERATION, &too_many, &mut output),
            Err(HmcfError::Count)
        );
    }

    #[test]
    fn maximum_record_set_round_trips() {
        let mut records = [ZERO_RECORD; MAX_RECORDS as usize];
        for (index, slot) in records.iter_mut().enumerate() {
            *slot = record(index as u16, 0, 0, ((index as u64) + 1) << 20);
        }
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &records);
        assert_eq!(total, MAX_BYTES);
        let Ok(view) = decode(&image) else {
            assert!(false, "maximum set must decode");
            return;
        };
        assert_eq!(view.record_count() as u32, MAX_RECORDS);
        assert_eq!(view.records().count(), MAX_RECORDS as usize);
    }

    #[test]
    fn rejects_bad_magic_version_and_header_shape() {
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &sample_records());
        for (offset, value) in [(0usize, 0xFFu8), (4, 0x02), (6, 0x01)] {
            let mut corrupted = image;
            corrupted[offset] ^= value;
            assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Format));
        }
        // Declared total does not match the actual byte length.
        assert_eq!(decode(&image[..total - 1]), Err(HmcfError::Format));
        assert_eq!(decode(&image), Err(HmcfError::Format));
    }

    #[test]
    fn rejects_reserved_fields_and_flags() {
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &sample_records());
        // Header flags non-zero.
        let mut corrupted = image;
        corrupted[32] = 1;
        fix_checksum(&mut corrupted[..total]);
        assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Reserved));
        // Record flags non-zero.
        let mut corrupted = image;
        let offset = HEADER_BYTES + RECORD_FLAGS_OFFSET;
        corrupted[offset] = 1;
        fix_checksum(&mut corrupted[..total]);
        assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Reserved));
        // Record reserved field non-zero (bytes 4..8 of the record).
        let mut corrupted = image;
        corrupted[HEADER_BYTES + 4] = 1;
        fix_checksum(&mut corrupted[..total]);
        assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Reserved));
        // Trailing record reserved field non-zero (bytes 28..32).
        let mut corrupted = image;
        corrupted[HEADER_BYTES + 28] = 1;
        fix_checksum(&mut corrupted[..total]);
        assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Reserved));
    }

    #[test]
    fn rejects_zero_snapshot_or_generation_identities() {
        let mut output = [0u8; MAX_BYTES];
        let records = sample_records();
        assert_eq!(
            encode(0, GENERATION, &records, &mut output),
            Err(HmcfError::Format)
        );
        assert_eq!(
            encode(SNAPSHOT, 0, &records, &mut output),
            Err(HmcfError::Format)
        );
        // Hand-crafted wire images with zeroed identities must not decode.
        for identity_offset in [12usize, 20] {
            let (mut image, total) = encoded_image(SNAPSHOT, GENERATION, &records);
            image[identity_offset..identity_offset + 8].fill(0);
            fix_checksum(&mut image[..total]);
            assert_eq!(decode(&image[..total]), Err(HmcfError::Format));
        }
    }

    #[test]
    fn checksum_is_enforced_across_the_whole_image() {
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &sample_records());
        // Only fields whose corruption survives every semantic check reach
        // the checksum comparison: snapshot/generation identities, the
        // 1 MiB-aligned base high bytes, and the checksum word itself.
        // (Header/magic/count/total mutations fail earlier with Format,
        // reserved-field mutations with Reserved.)
        for offset in [12usize, 20, HEADER_BYTES + 12, CHECKSUM_OFFSET] {
            let mut corrupted = image;
            corrupted[offset] ^= 0x01;
            assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Checksum));
        }
    }

    #[test]
    fn count_must_match_declared_size() {
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &sample_records());
        // record_count disagrees with total_size.
        let mut corrupted = image;
        corrupted[28] = 2;
        fix_checksum(&mut corrupted[..total]);
        assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Format));
        // record_count out of bounds.
        let mut corrupted = image;
        corrupted[28] = 65;
        fix_checksum(&mut corrupted[..total]);
        assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Count));
        // total_size must be the exact canonical value.
        let mut corrupted = image;
        corrupted[8] ^= 0x01;
        fix_checksum(&mut corrupted[..total]);
        assert_eq!(decode(&corrupted[..total]), Err(HmcfError::Format));
    }

    #[test]
    fn bus_range_alignment_and_span_are_checked() {
        assert_eq!(
            HmcfRecord::new(0, 200, 100, 0x8000_0000),
            Err(HmcfError::BusRange)
        );
        assert_eq!(
            HmcfRecord::new(0, 0, 63, 0x8000_1000),
            Err(HmcfError::MisalignedBase)
        );
        // span_bytes larger than the bus span.
        let (mut image, total) = encoded_image(SNAPSHOT, GENERATION, &sample_records());
        let span_offset = HEADER_BYTES + SPAN_BYTES_OFFSET;
        let mut declared: u64 = 0;
        for (index, byte) in image[span_offset..span_offset + 8].iter().enumerate() {
            declared |= u64::from(*byte) << (8 * index);
        }
        image[span_offset..span_offset + 8].copy_from_slice(&(declared + 1).to_le_bytes());
        fix_checksum(&mut image[..total]);
        assert_eq!(decode(&image[..total]), Err(HmcfError::Span));
    }

    #[test]
    fn physical_span_overflow_is_rejected() {
        // Aligned base so close to u64::MAX that base + span wraps.
        let base = !(BUS_BYTES - 1);
        assert_eq!(
            HmcfRecord::new(0, 0, 1, base),
            Err(HmcfError::AddressOverflow)
        );
        // A hand-crafted wire record with the same overflow must not
        // decode either (format-level defence in depth).
        let mut crafted = [0u8; HEADER_BYTES + RECORD_BYTES];
        crafted[..4].copy_from_slice(&MAGIC);
        crafted[4..6].copy_from_slice(&VERSION.to_le_bytes());
        crafted[6..8].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        crafted[8..12].copy_from_slice(&((HEADER_BYTES + RECORD_BYTES) as u32).to_le_bytes());
        crafted[12..20].copy_from_slice(&SNAPSHOT.to_le_bytes());
        crafted[20..28].copy_from_slice(&GENERATION.to_le_bytes());
        crafted[28..32].copy_from_slice(&1u32.to_le_bytes());
        crafted[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&0u16.to_le_bytes());
        crafted[HEADER_BYTES + 2] = 0;
        crafted[HEADER_BYTES + 3] = 1;
        crafted[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&base.to_le_bytes());
        crafted[HEADER_BYTES + 16..HEADER_BYTES + 24]
            .copy_from_slice(&(2 * BUS_BYTES).to_le_bytes());
        fix_checksum(&mut crafted);
        assert_eq!(decode(&crafted), Err(HmcfError::AddressOverflow));
    }

    #[test]
    fn canonical_order_is_required_on_the_wire() {
        let (mut image, total) = encoded_image(SNAPSHOT, GENERATION, &sample_records());
        // Swap the first two records in place and repair the checksum.
        let first = HEADER_BYTES;
        let second = HEADER_BYTES + RECORD_BYTES;
        let mut record_a = [0u8; RECORD_BYTES];
        let mut record_b = [0u8; RECORD_BYTES];
        record_a.copy_from_slice(&image[first..first + RECORD_BYTES]);
        record_b.copy_from_slice(&image[second..second + RECORD_BYTES]);
        image[first..first + RECORD_BYTES].copy_from_slice(&record_b);
        image[second..second + RECORD_BYTES].copy_from_slice(&record_a);
        fix_checksum(&mut image[..total]);
        assert_eq!(decode(&image[..total]), Err(HmcfError::NotCanonical));
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let records = [record(0, 0, 0, 0x8000_0000), record(0, 0, 1, 0x8000_0000)];
        // Both records share the ordering key, so encode must refuse the
        // set regardless of physical overlap rules.
        let mut output = [0u8; MAX_BYTES];
        assert_eq!(
            encode(SNAPSHOT, GENERATION, &records, &mut output),
            Err(HmcfError::NotCanonical)
        );
    }

    #[test]
    fn binding_check_rejects_stale_generation_and_snapshot() {
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &sample_records());
        let Ok(view) = decode(&image[..total]) else {
            assert!(false, "encoded image must decode");
            return;
        };
        assert_eq!(view.check_binding(GENERATION, SNAPSHOT), Ok(()));
        assert_eq!(
            view.check_binding(GENERATION + 1, SNAPSHOT),
            Err(HmcfError::StaleGeneration)
        );
        assert_eq!(
            view.check_binding(GENERATION, SNAPSHOT + 1),
            Err(HmcfError::SnapshotMismatch)
        );
        // Zero expectations can never match a valid binding either.
        assert_eq!(
            view.check_binding(0, SNAPSHOT),
            Err(HmcfError::StaleGeneration)
        );
    }

    #[test]
    fn declared_size_is_checked_by_consumers() {
        let (image, total) = encoded_image(SNAPSHOT, GENERATION, &sample_records());
        assert_eq!(declared_size(&image[..HEADER_BYTES]), Ok(total));
        assert_eq!(declared_size(&image[..8]), Err(HmcfError::Truncated));
        let mut corrupted = image;
        corrupted[8] ^= 0xff;
        fix_checksum(&mut corrupted[..total]);
        assert_eq!(declared_size(&corrupted), Err(HmcfError::Format));
    }
}
