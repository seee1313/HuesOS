//! NVMe command structures: submission queue entries (SQE), completion queue
//! entries (CQE), opcodes, and status decoding.
//!
//! Entries are modeled as little-endian 32-bit dword arrays (SQE = 16 dwords =
//! 64 bytes, CQE = 4 dwords = 16 bytes), matching the spec's DWn definitions.
//! This keeps the layout explicit and host-testable with no endianness or
//! alignment hazards.

/// A 64-byte Submission Queue Entry (16 little-endian dwords).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sqe(pub [u32; 16]);

impl Sqe {
    /// A zeroed SQE.
    pub const fn zeroed() -> Self {
        Sqe([0; 16])
    }

    /// Command opcode (DW0 bits 7:0).
    pub const fn opcode(&self) -> u8 {
        (self.0[0] & 0xFF) as u8
    }
    /// Set the command opcode.
    pub fn set_opcode(&mut self, op: u8) {
        self.0[0] = (self.0[0] & !0xFF) | op as u32;
    }
    /// Command identifier (DW0 bits 31:16).
    pub const fn cid(&self) -> u16 {
        (self.0[0] >> 16) as u16
    }
    /// Set the command identifier.
    pub fn set_cid(&mut self, cid: u16) {
        self.0[0] = (self.0[0] & 0x0000_FFFF) | ((cid as u32) << 16);
    }
    /// Namespace identifier (DW1).
    pub const fn nsid(&self) -> u32 {
        self.0[1]
    }
    /// Set the namespace identifier.
    pub fn set_nsid(&mut self, nsid: u32) {
        self.0[1] = nsid;
    }
    /// Metadata pointer (DW4:DW5, 64-bit).
    pub const fn mptr(&self) -> u64 {
        ((self.0[5] as u64) << 32) | self.0[4] as u64
    }
    /// PRP entry 1 (DW6:DW7, 64-bit).
    pub const fn prp1(&self) -> u64 {
        ((self.0[7] as u64) << 32) | self.0[6] as u64
    }
    /// Set PRP entry 1.
    pub fn set_prp1(&mut self, v: u64) {
        self.0[6] = v as u32;
        self.0[7] = (v >> 32) as u32;
    }
    /// PRP entry 2 (DW8:DW9, 64-bit).
    pub const fn prp2(&self) -> u64 {
        ((self.0[9] as u64) << 32) | self.0[8] as u64
    }
    /// Set PRP entry 2.
    pub fn set_prp2(&mut self, v: u64) {
        self.0[8] = v as u32;
        self.0[9] = (v >> 32) as u32;
    }
    /// Command dword 10.
    pub const fn cdw10(&self) -> u32 {
        self.0[10]
    }
    /// Set command dword 10.
    pub fn set_cdw10(&mut self, v: u32) {
        self.0[10] = v;
    }
    /// Command dword 11.
    pub const fn cdw11(&self) -> u32 {
        self.0[11]
    }
    /// Set command dword 11.
    pub fn set_cdw11(&mut self, v: u32) {
        self.0[11] = v;
    }
    /// Command dword 12.
    pub const fn cdw12(&self) -> u32 {
        self.0[12]
    }
    /// Set command dword 12.
    pub fn set_cdw12(&mut self, v: u32) {
        self.0[12] = v;
    }
    /// Command dword 13.
    pub const fn cdw13(&self) -> u32 {
        self.0[13]
    }
    /// Set command dword 13.
    pub fn set_cdw13(&mut self, v: u32) {
        self.0[13] = v;
    }
    /// The 64-bit starting LBA (DW11:DW10) used by Read/Write.
    pub const fn starting_lba(&self) -> u64 {
        ((self.0[11] as u64) << 32) | self.0[10] as u64
    }
    /// Set the 64-bit starting LBA (DW10 low, DW11 high).
    pub fn set_starting_lba(&mut self, lba: u64) {
        self.0[10] = lba as u32;
        self.0[11] = (lba >> 32) as u32;
    }
}

/// A 16-byte Completion Queue Entry (4 little-endian dwords).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cqe(pub [u32; 4]);

impl Cqe {
    /// A zeroed CQE.
    pub const fn zeroed() -> Self {
        Cqe([0; 4])
    }
    /// Command-specific result (DW0).
    pub const fn result(&self) -> u32 {
        self.0[0]
    }
    /// SQ head pointer reported by the controller (DW2 bits 15:0).
    pub const fn sq_head(&self) -> u16 {
        (self.0[2] & 0xFFFF) as u16
    }
    /// SQ identifier this completion is for (DW2 bits 31:16).
    pub const fn sq_id(&self) -> u16 {
        (self.0[2] >> 16) as u16
    }
    /// Command identifier (DW3 bits 15:0).
    pub const fn cid(&self) -> u16 {
        (self.0[3] & 0xFFFF) as u16
    }
    /// Raw status field (DW3 bits 31:16).
    pub const fn status_raw(&self) -> u16 {
        (self.0[3] >> 16) as u16
    }
}

/// Admin command opcodes (NVMe spec naming; constants are self-documenting).
#[allow(missing_docs)]
pub mod admin {
    pub const DELETE_IO_SQ: u8 = 0x00;
    pub const CREATE_IO_SQ: u8 = 0x01;
    pub const GET_LOG_PAGE: u8 = 0x02;
    pub const DELETE_IO_CQ: u8 = 0x04;
    pub const CREATE_IO_CQ: u8 = 0x05;
    pub const IDENTIFY: u8 = 0x06;
    pub const ABORT: u8 = 0x08;
    pub const SET_FEATURES: u8 = 0x09;
    pub const GET_FEATURES: u8 = 0x0A;
    pub const ASYNC_EVENT_REQUEST: u8 = 0x0C;
    pub const NS_MANAGEMENT: u8 = 0x0D;
    pub const FW_COMMIT: u8 = 0x10;
    pub const FW_IMAGE_DOWNLOAD: u8 = 0x11;
    pub const NS_ATTACH: u8 = 0x15;
    pub const FORMAT_NVM: u8 = 0x80;
    pub const SECURITY_SEND: u8 = 0x81;
    pub const SECURITY_RECEIVE: u8 = 0x82;
}

/// NVM I/O command set opcodes (NVMe spec naming).
#[allow(missing_docs)]
pub mod io {
    pub const FLUSH: u8 = 0x00;
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE_UNCORRECTABLE: u8 = 0x04;
    pub const COMPARE: u8 = 0x05;
    pub const WRITE_ZEROES: u8 = 0x08;
    pub const DATASET_MANAGEMENT: u8 = 0x09;
}

/// Completion status field decoding (CQE DW3 bits 31:16).
#[allow(missing_docs)]
pub mod status {
    /// Phase tag (bit 16 of DW3 = bit 0 of the status field).
    pub const PHASE: u16 = 1 << 0;
    /// Status Code Type (bits 18:17 of DW3 = bits 2:1 of the status field).
    pub const SCT_SHIFT: u32 = 1;
    pub const SCT_MASK: u16 = 0x3 << SCT_SHIFT;
    /// Status Code (bits 25:19 of DW3 = bits 9:3 of the status field).
    pub const SC_SHIFT: u32 = 3;
    pub const SC_MASK: u16 = 0x7F << SC_SHIFT;
    /// More (bit 30 of DW3 = bit 14 of the status field).
    pub const MORE: u16 = 1 << 14;
    /// Do Not Retry (bit 31 of DW3 = bit 15 of the status field).
    pub const DNR: u16 = 1 << 15;

    /// Status Code Type values.
    pub const SCT_GENERIC: u16 = 0x0;
    pub const SCT_COMMAND_SPECIFIC: u16 = 0x1;
    pub const SCT_MEDIA_ERRORS: u16 = 0x2;
    pub const SCT_PATH_RELATED: u16 = 0x3;

    /// Generic command status codes (SCT = Generic).
    pub const SC_SUCCESS: u16 = 0x00;
    pub const SC_INVALID_OPCODE: u16 = 0x01;
    pub const SC_INVALID_FIELD: u16 = 0x02;
    pub const SC_COMMAND_ID_CONFLICT: u16 = 0x03;
    pub const SC_DATA_TRANSFER_ERROR: u16 = 0x04;
    pub const SC_INTERNAL_ERROR: u16 = 0x06;

    /// Phase bit from a raw status field.
    pub const fn phase(raw: u16) -> bool {
        raw & PHASE != 0
    }
    /// Status Code Type (2 bits).
    pub const fn sct(raw: u16) -> u16 {
        (raw & SCT_MASK) >> SCT_SHIFT
    }
    /// Status Code (7 bits).
    pub const fn sc(raw: u16) -> u16 {
        (raw & SC_MASK) >> SC_SHIFT
    }
    /// Do-Not-Retry bit.
    pub const fn dnr(raw: u16) -> bool {
        raw & DNR != 0
    }
    /// True when the status indicates successful completion (SCT=0, SC=0).
    pub const fn is_success(raw: u16) -> bool {
        sct(raw) == SCT_GENERIC && sc(raw) == SC_SUCCESS
    }
    /// Build a raw status field from phase/sct/sc/dnr (for mock controllers).
    pub const fn build(phase: bool, sct: u16, sc: u16, dnr: bool) -> u16 {
        (if phase { PHASE } else { 0 })
            | ((sct << SCT_SHIFT) & SCT_MASK)
            | ((sc << SC_SHIFT) & SC_MASK)
            | (if dnr { DNR } else { 0 })
    }
}

/// Identify command CNS (Controller or Namespace Structure) values.
#[allow(missing_docs)]
pub mod identify {
    pub const NAMESPACE: u8 = 0x00;
    pub const CONTROLLER: u8 = 0x01;
    pub const ACTIVE_NS_LIST: u8 = 0x02;
    pub const NAMESPACE_ID_DESCRIPTOR: u8 = 0x03;
}

/// Set/Get Features feature identifiers (FID).
#[allow(missing_docs)]
pub mod feature {
    pub const ARBITRATION: u8 = 0x01;
    pub const POWER_MANAGEMENT: u8 = 0x02;
    pub const TEMPERATURE_THRESHOLD: u8 = 0x04;
    pub const ERROR_RECOVERY: u8 = 0x05;
    pub const VOLATILE_WRITE_CACHE: u8 = 0x06;
    pub const NUMBER_OF_QUEUES: u8 = 0x07;
    pub const INTERRUPT_COALESCING: u8 = 0x08;
    pub const INTERRUPT_VECTOR_CONFIGURATION: u8 = 0x09;
    pub const WRITE_ATOMICITY_NORMAL: u8 = 0x0A;
    pub const ASYNC_EVENT_CONFIGURATION: u8 = 0x0B;
}

impl Cqe {
    /// True when the completion reports successful status (ignoring phase).
    pub fn is_success(&self) -> bool {
        status::is_success(self.status_raw())
    }
    /// Phase bit of this completion.
    pub fn phase(&self) -> bool {
        status::phase(self.status_raw())
    }
    /// Status Code Type.
    pub fn sct(&self) -> u16 {
        status::sct(self.status_raw())
    }
    /// Status Code.
    pub fn sc(&self) -> u16 {
        status::sc(self.status_raw())
    }
}

/// SQE builders for admin and NVM I/O commands. Sizes/counts passed here are
/// 1's-based where the spec stores them 0's-based (the builder converts).
pub mod build {
    use super::*;

    /// Identify command. prp1 points to a 4096-byte identify data buffer.
    pub fn identify(cns: u8, cntid: u16, nsid: u32, prp1: u64) -> Sqe {
        let mut s = Sqe::zeroed();
        s.set_opcode(admin::IDENTIFY);
        s.set_nsid(nsid);
        s.set_prp1(prp1);
        s.set_cdw10(cns as u32 | ((cntid as u32) << 16));
        s
    }

    /// Create I/O Completion Queue (physically contiguous).
    pub fn create_io_cq(qid: u16, qsize: u16, prp1: u64, iv: u16, ien: bool) -> Sqe {
        let mut s = Sqe::zeroed();
        s.set_opcode(admin::CREATE_IO_CQ);
        s.set_prp1(prp1);
        s.set_cdw10(qid as u32 | ((qsize as u32 - 1) << 16));
        let mut cdw11 = 1u32; // PC = physically contiguous
        if ien {
            cdw11 |= 1 << 1;
        }
        cdw11 |= (iv as u32) << 16;
        s.set_cdw11(cdw11);
        s
    }

    /// Create I/O Submission Queue (physically contiguous), bound to cqid.
    pub fn create_io_sq(qid: u16, qsize: u16, prp1: u64, cqid: u16) -> Sqe {
        let mut s = Sqe::zeroed();
        s.set_opcode(admin::CREATE_IO_SQ);
        s.set_prp1(prp1);
        s.set_cdw10(qid as u32 | ((qsize as u32 - 1) << 16));
        let cdw11 = 1u32 | ((cqid as u32) << 16); // PC=1, CQID
        s.set_cdw11(cdw11);
        s
    }

    /// Set Features: Number of Queues. nsqr/ncqr are 1's-based requested counts.
    pub fn set_number_of_queues(nsqr: u16, ncqr: u16) -> Sqe {
        let mut s = Sqe::zeroed();
        s.set_opcode(admin::SET_FEATURES);
        s.set_cdw10(feature::NUMBER_OF_QUEUES as u32);
        s.set_cdw11((nsqr as u32 - 1) | ((ncqr as u32 - 1) << 16));
        s
    }

    /// NVM Read. nlb is the 1's-based number of logical blocks.
    pub fn read(nsid: u32, lba: u64, nlb: u16, prp1: u64, prp2: u64) -> Sqe {
        let mut s = Sqe::zeroed();
        s.set_opcode(io::READ);
        s.set_nsid(nsid);
        s.set_starting_lba(lba);
        s.set_cdw12(nlb as u32 - 1);
        s.set_prp1(prp1);
        s.set_prp2(prp2);
        s
    }

    /// NVM Write. nlb is the 1's-based number of logical blocks.
    pub fn write(nsid: u32, lba: u64, nlb: u16, prp1: u64, prp2: u64) -> Sqe {
        let mut s = Sqe::zeroed();
        s.set_opcode(io::WRITE);
        s.set_nsid(nsid);
        s.set_starting_lba(lba);
        s.set_cdw12(nlb as u32 - 1);
        s.set_prp1(prp1);
        s.set_prp2(prp2);
        s
    }

    /// Flush.
    pub fn flush(nsid: u32) -> Sqe {
        let mut s = Sqe::zeroed();
        s.set_opcode(io::FLUSH);
        s.set_nsid(nsid);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqe_opcode_and_cid() {
        let mut s = Sqe::zeroed();
        s.set_opcode(io::READ);
        s.set_cid(0xBEEF);
        assert_eq!(s.opcode(), io::READ);
        assert_eq!(s.cid(), 0xBEEF);
    }

    #[test]
    fn sqe_prp_round_trips_64bit() {
        let mut s = Sqe::zeroed();
        s.set_prp1(0x0000_0001_2345_6789);
        s.set_prp2(0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(s.prp1(), 0x0000_0001_2345_6789);
        assert_eq!(s.prp2(), 0xDEAD_BEEF_CAFE_BABE);
        // DW6 holds low, DW7 holds high.
        assert_eq!(s.0[6], 0x2345_6789);
        assert_eq!(s.0[7], 0x0000_0001);
    }

    #[test]
    fn sqe_starting_lba_is_dword10_11() {
        let mut s = Sqe::zeroed();
        s.set_starting_lba(0x0000_0002_0000_0001);
        assert_eq!(s.starting_lba(), 0x0000_0002_0000_0001);
        assert_eq!(s.0[10], 0x0000_0001);
        assert_eq!(s.0[11], 0x0000_0002);
    }

    #[test]
    fn cqe_decodes_status_and_ids() {
        let mut c = Cqe::zeroed();
        // DW2: sqhd=5, sqid=1
        c.0[2] = 5 | (1 << 16);
        // DW3: cid=7, status = success with phase=1
        c.0[3] = 7 | ((status::build(true, 0, 0, false) as u32) << 16);
        assert_eq!(c.sq_head(), 5);
        assert_eq!(c.sq_id(), 1);
        assert_eq!(c.cid(), 7);
        assert!(c.phase());
        assert!(c.is_success());
    }

    #[test]
    fn status_field_round_trips() {
        let raw = status::build(false, status::SCT_MEDIA_ERRORS, 0x10, true);
        assert!(!status::phase(raw));
        assert_eq!(status::sct(raw), status::SCT_MEDIA_ERRORS);
        assert_eq!(status::sc(raw), 0x10);
        assert!(status::dnr(raw));
        assert!(!status::is_success(raw));
    }

    #[test]
    fn status_success_detection() {
        let ok = status::build(true, status::SCT_GENERIC, status::SC_SUCCESS, false);
        assert!(status::is_success(ok));
        let bad = status::build(true, status::SCT_GENERIC, status::SC_INVALID_FIELD, false);
        assert!(!status::is_success(bad));
    }

    #[test]
    fn build_identify_layout() {
        let s = build::identify(identify::CONTROLLER, 0, 0, 0x4000_0000);
        assert_eq!(s.opcode(), admin::IDENTIFY);
        assert_eq!(s.cdw10() & 0xFF, identify::CONTROLLER as u32);
        assert_eq!(s.prp1(), 0x4000_0000);
    }

    #[test]
    fn build_create_io_cq_layout() {
        let s = build::create_io_cq(1, 64, 0x5000, 3, true);
        assert_eq!(s.opcode(), admin::CREATE_IO_CQ);
        // QID in low, QSIZE-1 in high.
        assert_eq!(s.cdw10() & 0xFFFF, 1);
        assert_eq!(s.cdw10() >> 16, 63);
        // PC=1, IEN=1, IV=3 in high half.
        assert_eq!(s.cdw11() & 0x1, 1);
        assert_eq!((s.cdw11() >> 1) & 0x1, 1);
        assert_eq!(s.cdw11() >> 16, 3);
        assert_eq!(s.prp1(), 0x5000);
    }

    #[test]
    fn build_create_io_sq_binds_cq() {
        let s = build::create_io_sq(1, 64, 0x6000, 1);
        assert_eq!(s.opcode(), admin::CREATE_IO_SQ);
        assert_eq!(s.cdw10() & 0xFFFF, 1);
        assert_eq!(s.cdw10() >> 16, 63);
        assert_eq!(s.cdw11() & 0x1, 1); // PC
        assert_eq!(s.cdw11() >> 16, 1); // CQID
    }

    #[test]
    fn build_set_number_of_queues_is_0based() {
        let s = build::set_number_of_queues(4, 4);
        assert_eq!(s.opcode(), admin::SET_FEATURES);
        assert_eq!(s.cdw10() & 0xFF, feature::NUMBER_OF_QUEUES as u32);
        // 4 requested -> stored as 3 (0's based) in both halves.
        assert_eq!(s.cdw11() & 0xFFFF, 3);
        assert_eq!(s.cdw11() >> 16, 3);
    }

    #[test]
    fn build_read_write_layout() {
        let r = build::read(1, 0x1000, 8, 0xA000, 0xB000);
        assert_eq!(r.opcode(), io::READ);
        assert_eq!(r.nsid(), 1);
        assert_eq!(r.starting_lba(), 0x1000);
        assert_eq!(r.cdw12(), 7); // 8 blocks -> 7 (0's based)
        assert_eq!(r.prp1(), 0xA000);
        assert_eq!(r.prp2(), 0xB000);

        let w = build::write(2, 0x2000, 1, 0xC000, 0);
        assert_eq!(w.opcode(), io::WRITE);
        assert_eq!(w.cdw12(), 0); // 1 block -> 0
    }

    #[test]
    fn build_flush() {
        let f = build::flush(1);
        assert_eq!(f.opcode(), io::FLUSH);
        assert_eq!(f.nsid(), 1);
    }
}
