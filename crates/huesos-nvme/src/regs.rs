//! NVMe controller register map (BAR0) and bitfield helpers.
//!
//! Offsets and layouts follow the NVM Express Base Specification. All registers
//! are little-endian. 64-bit registers (CAP, ASQ, ACQ) are accessed as two
//! 32-bit halves by the transport; helpers here build/parse the full values.

/// Register offsets within BAR0 (bytes).
pub mod off {
    /// Controller Capabilities (64-bit, RO).
    pub const CAP: u32 = 0x00;
    /// Version (32-bit, RO).
    pub const VS: u32 = 0x08;
    /// Interrupt Mask Set (32-bit, RW).
    pub const INTMS: u32 = 0x0C;
    /// Interrupt Mask Clear (32-bit, RW).
    pub const INTMC: u32 = 0x10;
    /// Controller Configuration (32-bit, RW).
    pub const CC: u32 = 0x14;
    /// Controller Status (32-bit, RO / RW1C for CFS).
    pub const CSTS: u32 = 0x1C;
    /// NVM Subsystem Reset (32-bit, RW).
    pub const NSSR: u32 = 0x20;
    /// Admin Queue Attributes (32-bit, RW).
    pub const AQA: u32 = 0x24;
    /// Admin Submission Queue Base Address (64-bit, RW).
    pub const ASQ: u32 = 0x28;
    /// Admin Completion Queue Base Address (64-bit, RW).
    pub const ACQ: u32 = 0x30;
    /// First doorbell register base (SQ0 tail doorbell).
    pub const DOORBELL_BASE: u32 = 0x1000;
}

/// CAP register (64-bit) field shifts/masks.
#[allow(missing_docs)]
pub mod cap {
    /// Maximum Queue Entries Supported (bits 15:0), 0's-based.
    pub const MQES_MASK: u64 = 0xFFFF;
    /// Contiguous Queues Required (bit 16).
    pub const CQR: u64 = 1 << 16;
    /// Arbitration Mechanism Supported (bits 18:17).
    pub const AMS_SHIFT: u64 = 17;
    /// Timeout (bits 31:24), in 500 ms units.
    pub const TO_SHIFT: u64 = 24;
    pub const TO_MASK: u64 = 0xFF << TO_SHIFT;
    /// Doorbell Stride (bits 35:32): doorbell spacing is 4 << DSTRD bytes.
    pub const DSTRD_SHIFT: u64 = 32;
    pub const DSTRD_MASK: u64 = 0xF << DSTRD_SHIFT;
    /// NVM Subsystem Reset Supported (bit 36).
    pub const NSSRS: u64 = 1 << 36;
    /// Memory Page Size Minimum (bits 51:48): min page is 2^(12+MPSMIN).
    pub const MPSMIN_SHIFT: u64 = 48;
    pub const MPSMIN_MASK: u64 = 0xF << MPSMIN_SHIFT;
    /// Memory Page Size Maximum (bits 55:52): max page is 2^(12+MPSMAX).
    pub const MPSMAX_SHIFT: u64 = 52;
    pub const MPSMAX_MASK: u64 = 0xF << MPSMAX_SHIFT;

    /// Maximum queue depth (1's-based count) from a raw CAP value.
    pub const fn mqes(cap: u64) -> u16 {
        (cap & MQES_MASK) as u16 + 1
    }
    /// Doorbell stride in bytes (4 << DSTRD).
    pub const fn doorbell_stride_bytes(cap: u64) -> u32 {
        4u32 << ((cap & DSTRD_MASK) >> DSTRD_SHIFT)
    }
    /// Enable timeout in milliseconds (TO * 500).
    pub const fn timeout_ms(cap: u64) -> u64 {
        ((cap & TO_MASK) >> TO_SHIFT) * 500
    }
    /// Minimum supported memory page size in bytes.
    pub const fn min_page_size(cap: u64) -> u64 {
        1u64 << (12 + ((cap & MPSMIN_MASK) >> MPSMIN_SHIFT))
    }
    /// Maximum supported memory page size in bytes.
    pub const fn max_page_size(cap: u64) -> u64 {
        1u64 << (12 + ((cap & MPSMAX_MASK) >> MPSMAX_SHIFT))
    }
}

/// CC register (32-bit) field shifts/masks.
#[allow(missing_docs)]
pub mod cc {
    /// Enable (bit 0).
    pub const EN: u32 = 1 << 0;
    /// I/O Command Set Selected (bits 6:4).
    pub const CSS_SHIFT: u32 = 4;
    pub const CSS_MASK: u32 = 0x7 << CSS_SHIFT;
    /// Memory Page Size (bits 10:7): page is 2^(12+MPS).
    pub const MPS_SHIFT: u32 = 7;
    pub const MPS_MASK: u32 = 0xF << MPS_SHIFT;
    /// Arbitration Mechanism Selected (bits 13:11).
    pub const AMS_SHIFT: u32 = 11;
    /// Shutdown Notification (bits 15:14).
    pub const SHN_SHIFT: u32 = 14;
    pub const SHN_MASK: u32 = 0x3 << SHN_SHIFT;
    /// I/O Submission Queue Entry Size (bits 19:16), power of two (6 = 64B).
    pub const IOSQES_SHIFT: u32 = 16;
    pub const IOSQES_MASK: u32 = 0xF << IOSQES_SHIFT;
    /// I/O Completion Queue Entry Size (bits 23:20), power of two (4 = 16B).
    pub const IOCQES_SHIFT: u32 = 20;
    pub const IOCQES_MASK: u32 = 0xF << IOCQES_SHIFT;

    /// CC.CSS: NVM Command Set only.
    pub const CSS_NVM: u32 = 0;
    /// CC.CSS: all supported I/O Command Sets.
    pub const CSS_ALL: u32 = 6;

    /// Build a CC value for enabling the controller.
    /// mps: page-size exponent (page = 2^(12+mps)); iosqes/iocqes: entry-size
    /// exponents (6 = 64-byte SQE, 4 = 16-byte CQE).
    pub const fn enable(mps: u32, iosqes: u32, iocqes: u32, css: u32) -> u32 {
        EN | ((css << CSS_SHIFT) & CSS_MASK)
            | ((mps << MPS_SHIFT) & MPS_MASK)
            | ((iosqes << IOSQES_SHIFT) & IOSQES_MASK)
            | ((iocqes << IOCQES_SHIFT) & IOCQES_MASK)
    }
}

/// CSTS register (32-bit) bits.
#[allow(missing_docs)]
pub mod csts {
    /// Ready (bit 0).
    pub const RDY: u32 = 1 << 0;
    /// Controller Fatal Status (bit 1).
    pub const CFS: u32 = 1 << 1;
    /// Shutdown Status (bits 3:2).
    pub const SHST_SHIFT: u32 = 2;
    pub const SHST_MASK: u32 = 0x3 << SHST_SHIFT;
    /// NVM Subsystem Reset Occurred (bit 4).
    pub const NSSRO: u32 = 1 << 4;
    /// Processing Paused (bit 5).
    pub const PP: u32 = 1 << 5;

    pub const SHST_NORMAL: u32 = 0;
    pub const SHST_PROCESSING: u32 = 1;
    pub const SHST_COMPLETE: u32 = 2;
}

/// AQA register (32-bit): admin queue sizes (0's-based).
#[allow(missing_docs)]
pub mod aqa {
    pub const ASQS_MASK: u32 = 0xFFF; // bits 11:0
    pub const ACQS_SHIFT: u32 = 16;
    pub const ACQS_MASK: u32 = 0xFFF << ACQS_SHIFT;

    /// Build an AQA value from 1's-based queue depths.
    pub const fn build(asqs: u32, acqs: u32) -> u32 {
        ((asqs - 1) & ASQS_MASK) | (((acqs - 1) << ACQS_SHIFT) & ACQS_MASK)
    }
    /// Admin submission queue depth (1's-based).
    pub const fn asqs(aqa: u32) -> u32 {
        (aqa & ASQS_MASK) + 1
    }
    /// Admin completion queue depth (1's-based).
    pub const fn acqs(aqa: u32) -> u32 {
        ((aqa & ACQS_MASK) >> ACQS_SHIFT) + 1
    }
}

/// Byte offset of a queue's doorbell register.
/// queue_id is the queue number; is_completion selects the CQ head doorbell
/// (odd) vs the SQ tail doorbell (even). stride_bytes = cap::doorbell_stride_bytes.
pub const fn doorbell_offset(queue_id: u32, is_completion: bool, stride_bytes: u32) -> u32 {
    let n = queue_id * 2 + (is_completion as u32);
    off::DOORBELL_BASE + n * stride_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_offsets_are_spec_layout() {
        assert_eq!(off::CAP, 0x00);
        assert_eq!(off::VS, 0x08);
        assert_eq!(off::CC, 0x14);
        assert_eq!(off::CSTS, 0x1C);
        assert_eq!(off::AQA, 0x24);
        assert_eq!(off::ASQ, 0x28);
        assert_eq!(off::ACQ, 0x30);
        assert_eq!(off::DOORBELL_BASE, 0x1000);
    }

    #[test]
    fn cap_decodes_fields() {
        // MQES=2047, TO=2 (1000 ms), DSTRD=0, MPSMIN=0, MPSMAX=4.
        let cap: u64 = 2047
            | (2u64 << cap::TO_SHIFT)
            | (0u64 << cap::DSTRD_SHIFT)
            | (0u64 << cap::MPSMIN_SHIFT)
            | (4u64 << cap::MPSMAX_SHIFT);
        assert_eq!(cap::mqes(cap), 2048);
        assert_eq!(cap::doorbell_stride_bytes(cap), 4);
        assert_eq!(cap::timeout_ms(cap), 1000);
        assert_eq!(cap::min_page_size(cap), 4096);
        assert_eq!(cap::max_page_size(cap), 1 << 16);
    }

    #[test]
    fn cap_doorbell_stride_scales() {
        let cap = 2u64 << cap::DSTRD_SHIFT; // DSTRD=2 -> 16 bytes
        assert_eq!(cap::doorbell_stride_bytes(cap), 16);
    }

    #[test]
    fn cc_enable_sets_required_fields() {
        let v = cc::enable(0, 6, 4, cc::CSS_NVM); // 4 KiB, 64B SQE, 16B CQE
        assert_eq!(v & cc::EN, cc::EN);
        assert_eq!((v & cc::IOSQES_MASK) >> cc::IOSQES_SHIFT, 6);
        assert_eq!((v & cc::IOCQES_MASK) >> cc::IOCQES_SHIFT, 4);
        assert_eq!((v & cc::MPS_MASK) >> cc::MPS_SHIFT, 0);
        assert_eq!((v & cc::CSS_MASK) >> cc::CSS_SHIFT, cc::CSS_NVM);
    }

    #[test]
    fn aqa_round_trips_depths() {
        let v = aqa::build(64, 64);
        assert_eq!(aqa::asqs(v), 64);
        assert_eq!(aqa::acqs(v), 64);
        let v2 = aqa::build(256, 128);
        assert_eq!(aqa::asqs(v2), 256);
        assert_eq!(aqa::acqs(v2), 128);
    }

    #[test]
    fn doorbell_offsets_follow_stride() {
        let stride = 4; // DSTRD = 0
        // SQ0 tail at base, CQ0 head at base+4, SQ1 tail at base+8.
        assert_eq!(doorbell_offset(0, false, stride), 0x1000);
        assert_eq!(doorbell_offset(0, true, stride), 0x1004);
        assert_eq!(doorbell_offset(1, false, stride), 0x1008);
        assert_eq!(doorbell_offset(1, true, stride), 0x100C);
        // With a 16-byte stride the spacing widens.
        assert_eq!(doorbell_offset(1, false, 16), 0x1000 + 2 * 16);
    }

    #[test]
    fn csts_status_bits() {
        assert_eq!(csts::RDY, 1);
        assert_eq!(csts::CFS, 2);
        assert_eq!(csts::SHST_COMPLETE << csts::SHST_SHIFT, 0b1000);
    }
}
