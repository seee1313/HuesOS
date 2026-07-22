//! Synchronous NVMe controller driving a [`NvmeTransport`].
//!
//! This is the polling-based core: it initializes the controller (enable,
//! Identify, Set Features, Create I/O queues) and issues Read/Write/Flush via
//! PRP-described buffers, polling the completion queues. The async layer (in
//! `async_controller`) wraps this so each I/O is a `hues-async` future woken by
//! its completion; the queue/command machinery here is shared.

use crate::cmd::{build, identify, Cqe, Sqe};
use crate::regs::{aqa, cap, cc, csts, off};
use crate::transport::NvmeTransport;

/// Errors from controller operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeError {
    /// No room left in the DMA region.
    OutOfDma,
    /// Controller did not become ready.
    NotReady,
    /// A command completed with a non-success status.
    CommandFailed {
        /// Status code type.
        sct: u16,
        /// Status code.
        sc: u16,
    },
    /// No completion appeared within the poll budget.
    Timeout,
    /// An I/O request was malformed or the controller is not initialized.
    InvalidArgs,
    /// The request lies outside the identified namespace.
    OutOfRange,
    /// The caller buffer is smaller than the requested transfer.
    BufferTooSmall,
}

/// A polling NVMe controller over a transport `T`.
pub struct Controller<T: NvmeTransport> {
    t: T,
    page_size: u32,
    doorbell_stride: u32,
    dma_next: u64,
    dma_end: u64,
    dma_valid: bool,
    // Admin queue.
    admin_sq: u64,
    admin_cq: u64,
    admin_sq_tail: u16,
    admin_cq_head: u16,
    admin_cq_phase: bool,
    admin_size: u16,
    // I/O queue 1.
    io_sq: u64,
    io_cq: u64,
    io_sq_tail: u16,
    io_cq_head: u16,
    io_cq_phase: bool,
    io_size: u16,
    cid: u16,
    // Namespace.
    nsid: u32,
    nsze: u64,
    lba_size: u32,
    identify_buf: u64,
}

impl<T: NvmeTransport> Controller<T> {
    /// Wrap a transport. `dma_base`/`dma_size` describe the DMA address window
    /// the controller may allocate queues and buffers from.
    pub fn new(t: T, dma_base: u64, dma_size: u64) -> Self {
        let (dma_end, dma_valid) = match dma_base.checked_add(dma_size) {
            Some(end) => (end, true),
            None => (0, false),
        };
        Self {
            t,
            page_size: 4096,
            doorbell_stride: 4,
            dma_next: dma_base,
            dma_end,
            dma_valid,
            admin_sq: 0,
            admin_cq: 0,
            admin_sq_tail: 0,
            admin_cq_head: 0,
            admin_cq_phase: true,
            admin_size: 0,
            io_sq: 0,
            io_cq: 0,
            io_sq_tail: 0,
            io_cq_head: 0,
            io_cq_phase: true,
            io_size: 0,
            cid: 0,
            nsid: 1,
            nsze: 0,
            lba_size: 0,
            identify_buf: 0,
        }
    }

    /// Namespace size in logical blocks (valid after `init`).
    pub fn namespace_size(&self) -> u64 {
        self.nsze
    }
    /// LBA size in bytes (valid after `init`).
    pub fn lba_size(&self) -> u32 {
        self.lba_size
    }
    /// Borrow the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.t
    }

    fn dma_alloc(&mut self, bytes: u64, align: u64) -> Result<u64, NvmeError> {
        if !self.dma_valid || align == 0 || !align.is_power_of_two() {
            return Err(NvmeError::InvalidArgs);
        }
        let aligned = self
            .dma_next
            .checked_add(align - 1)
            .ok_or(NvmeError::OutOfDma)?
            & !(align - 1);
        let end = aligned.checked_add(bytes).ok_or(NvmeError::OutOfDma)?;
        if end > self.dma_end {
            return Err(NvmeError::OutOfDma);
        }
        self.dma_next = end;
        Ok(aligned)
    }

    pub(crate) fn checked_io_bytes(&self, lba: u64, nlb: u16) -> Result<u64, NvmeError> {
        if self.lba_size == 0 || self.nsze == 0 {
            return Err(NvmeError::NotReady);
        }
        if nlb == 0 {
            return Err(NvmeError::InvalidArgs);
        }
        let end = lba
            .checked_add(nlb as u64)
            .ok_or(NvmeError::OutOfRange)?;
        if end > self.nsze {
            return Err(NvmeError::OutOfRange);
        }
        (nlb as u64)
            .checked_mul(self.lba_size as u64)
            .ok_or(NvmeError::InvalidArgs)
    }

    fn next_cid(&mut self) -> u16 {
        let c = self.cid;
        self.cid = self.cid.wrapping_add(1);
        c
    }

    // --- low-level admin queue ---

    fn submit_admin(&mut self, mut sqe: Sqe) {
        let cid = self.next_cid();
        sqe.set_cid(cid);
        let base = self.admin_sq + (self.admin_sq_tail as u64) * 64;
        let bytes = sqe_to_bytes(&sqe);
        self.t.dma_write(base, &bytes);
        self.admin_sq_tail = (self.admin_sq_tail + 1) % self.admin_size.max(1);
        let db = off::DOORBELL_BASE; // SQ0 tail
        self.t.write32(db, self.admin_sq_tail as u32);
    }

    fn poll_admin(&mut self, budget: u32) -> Result<Cqe, NvmeError> {
        for _ in 0..budget {
            let base = self.admin_cq + (self.admin_cq_head as u64) * 16;
            let mut b = [0u8; 16];
            self.t.dma_read(base, &mut b);
            let cqe = cqe_from_bytes(&b);
            if cqe.phase() == self.admin_cq_phase {
                self.admin_cq_head = (self.admin_cq_head + 1) % self.admin_size.max(1);
                if self.admin_cq_head == 0 {
                    self.admin_cq_phase = !self.admin_cq_phase;
                }
                let db = off::DOORBELL_BASE + self.doorbell_stride; // CQ0 head
                self.t.write32(db, self.admin_cq_head as u32);
                return Ok(cqe);
            }
        }
        Err(NvmeError::Timeout)
    }

    fn admin_command(&mut self, sqe: Sqe) -> Result<Cqe, NvmeError> {
        self.submit_admin(sqe);
        let cqe = self.poll_admin(1024)?;
        if cqe.is_success() {
            Ok(cqe)
        } else {
            Err(NvmeError::CommandFailed {
                sct: cqe.sct(),
                sc: cqe.sc(),
            })
        }
    }

    /// Initialize the controller: enable, Identify, Set Features, Create I/O
    /// queue 1. After this, `namespace_size`/`lba_size` are valid and I/O can
    /// be issued.
    pub fn init(&mut self) -> Result<(), NvmeError> {
        let capv = self.t.read64(off::CAP);
        self.page_size = cap::min_page_size(capv) as u32;
        self.doorbell_stride = cap::doorbell_stride_bytes(capv);
        let mqes = cap::mqes(capv);
        self.admin_size = 16.min(mqes);
        self.io_size = 16.min(mqes);

        let ps = self.page_size as u64;
        self.admin_sq = self.dma_alloc(self.admin_size as u64 * 64, ps)?;
        self.admin_cq = self.dma_alloc(self.admin_size as u64 * 16, ps)?;

        self.t.write32(off::AQA, aqa::build(self.admin_size as u32, self.admin_size as u32));
        self.t.write64(off::ASQ, self.admin_sq);
        self.t.write64(off::ACQ, self.admin_cq);

        self.t.write32(off::CC, cc::enable(0, 6, 4, cc::CSS_NVM));

        let mut ready = false;
        for _ in 0..100_000 {
            if self.t.read32(off::CSTS) & csts::RDY != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(NvmeError::NotReady);
        }

        self.identify_buf = self.dma_alloc(4096, ps)?;
        self.admin_command(build::identify(identify::CONTROLLER, 0, 0, self.identify_buf))?;
        self.admin_command(build::identify(identify::NAMESPACE, 0, 1, self.identify_buf))?;

        let mut id = [0u8; 4096];
        self.t.dma_read(self.identify_buf, &mut id);
        self.nsze = u64::from_le_bytes([id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7]]);
        let lbads = id[128 + 2];
        self.lba_size = if (9..=16).contains(&lbads) { 1u32 << lbads } else { 512 };

        self.admin_command(build::set_number_of_queues(1, 1))?;

        self.io_cq = self.dma_alloc(self.io_size as u64 * 16, ps)?;
        self.io_sq = self.dma_alloc(self.io_size as u64 * 64, ps)?;
        self.admin_command(build::create_io_cq(1, self.io_size, self.io_cq, 0, true))?;
        self.admin_command(build::create_io_sq(1, self.io_size, self.io_sq, 1))?;

        Ok(())
    }

    // --- I/O queue ---

    fn setup_prp(&mut self, buf: u64, nbytes: u64) -> Result<(u64, u64), NvmeError> {
        let ps = self.page_size as u64;
        if nbytes <= ps {
            return Ok((buf, 0));
        }
        let pages = nbytes.div_ceil(ps) as usize;
        if pages == 2 {
            return Ok((buf, buf + ps));
        }
        let entries = pages - 1;
        let list = self.dma_alloc((entries as u64) * 8, ps)?;
        let mut i = 0;
        while i < entries {
            let e = buf + ((i + 1) as u64) * ps;
            self.t.dma_write(list + (i as u64) * 8, &e.to_le_bytes());
            i += 1;
        }
        Ok((buf, list))
    }

    fn submit_io(&mut self, mut sqe: Sqe) -> u16 {
        let cid = self.next_cid();
        sqe.set_cid(cid);
        let base = self.io_sq + (self.io_sq_tail as u64) * 64;
        let bytes = sqe_to_bytes(&sqe);
        self.t.dma_write(base, &bytes);
        self.io_sq_tail = (self.io_sq_tail + 1) % self.io_size.max(1);
        let db = off::DOORBELL_BASE + 2 * self.doorbell_stride; // SQ1 tail
        self.t.write32(db, self.io_sq_tail as u32);
        cid
    }

    fn poll_io(&mut self, want_cid: u16, budget: u32) -> Result<Cqe, NvmeError> {
        for _ in 0..budget {
            let base = self.io_cq + (self.io_cq_head as u64) * 16;
            let mut b = [0u8; 16];
            self.t.dma_read(base, &mut b);
            let cqe = cqe_from_bytes(&b);
            if cqe.phase() == self.io_cq_phase {
                self.io_cq_head = (self.io_cq_head + 1) % self.io_size.max(1);
                if self.io_cq_head == 0 {
                    self.io_cq_phase = !self.io_cq_phase;
                }
                let db = off::DOORBELL_BASE + 3 * self.doorbell_stride; // CQ1 head
                self.t.write32(db, self.io_cq_head as u32);
                if cqe.cid() == want_cid {
                    return Ok(cqe);
                }
            }
        }
        Err(NvmeError::Timeout)
    }

    fn check(cqe: &Cqe) -> Result<(), NvmeError> {
        if cqe.is_success() {
            Ok(())
        } else {
            Err(NvmeError::CommandFailed { sct: cqe.sct(), sc: cqe.sc() })
        }
    }

    /// Read `nlb` logical blocks starting at `lba` into `buf` (synchronous).
    pub fn read(&mut self, lba: u64, nlb: u16, buf: &mut [u8]) -> Result<(), NvmeError> {
        let nbytes = self.checked_io_bytes(lba, nlb)?;
        if buf.len() < nbytes as usize {
            return Err(NvmeError::BufferTooSmall);
        }
        let (cid, dma, nbytes) = self.prepare_read(lba, nlb)?;
        let cqe = self.poll_io(cid, 1_000_000)?;
        Self::check(&cqe)?;
        self.finish_read(dma, nbytes, buf);
        Ok(())
    }

    /// Write `nlb` logical blocks starting at `lba` from `buf` (synchronous).
    pub fn write(&mut self, lba: u64, nlb: u16, buf: &[u8]) -> Result<(), NvmeError> {
        let nbytes = self.checked_io_bytes(lba, nlb)?;
        if buf.len() < nbytes as usize {
            return Err(NvmeError::BufferTooSmall);
        }
        let (cid, _, _) = self.prepare_write(lba, nlb, buf)?;
        let cqe = self.poll_io(cid, 1_000_000)?;
        Self::check(&cqe)
    }

    /// Flush volatile write cache to non-volatile media.
    pub fn flush(&mut self) -> Result<(), NvmeError> {
        if self.io_size == 0 {
            return Err(NvmeError::NotReady);
        }
        let cid = self.submit_io(build::flush(self.nsid));
        let cqe = self.poll_io(cid, 1_000_000)?;
        Self::check(&cqe)
    }

    // --- split submit/complete primitives (shared with the async wrapper) ---

    /// Allocate the data buffer + PRP and submit a Read; returns
    /// `(cid, dma_addr, nbytes)`. The completion is awaited separately.
    pub(crate) fn prepare_read(&mut self, lba: u64, nlb: u16) -> Result<(u16, u64, u64), NvmeError> {
        let nbytes = self.checked_io_bytes(lba, nlb)?;
        let dma = self.dma_alloc(nbytes, self.page_size as u64)?;
        let (prp1, prp2) = self.setup_prp(dma, nbytes)?;
        let cid = self.submit_io(build::read(self.nsid, lba, nlb, prp1, prp2));
        Ok((cid, dma, nbytes))
    }

    /// Write `buf` into a fresh DMA buffer, set up PRP, and submit a Write;
    /// returns `(cid, dma_addr, nbytes)`.
    pub(crate) fn prepare_write(
        &mut self,
        lba: u64,
        nlb: u16,
        buf: &[u8],
    ) -> Result<(u16, u64, u64), NvmeError> {
        let nbytes = self.checked_io_bytes(lba, nlb)?;
        if buf.len() < nbytes as usize {
            return Err(NvmeError::BufferTooSmall);
        }
        let dma = self.dma_alloc(nbytes, self.page_size as u64)?;
        self.t.dma_write(dma, &buf[..nbytes as usize]);
        let (prp1, prp2) = self.setup_prp(dma, nbytes)?;
        let cid = self.submit_io(build::write(self.nsid, lba, nlb, prp1, prp2));
        Ok((cid, dma, nbytes))
    }

    /// Copy a completed read's data out of the DMA buffer into `buf`.
    pub(crate) fn finish_read(&mut self, dma: u64, nbytes: u64, buf: &mut [u8]) {
        self.t.dma_read(dma, &mut buf[..nbytes as usize]);
    }

    /// Non-blocking completion check: if the next CQE is present (phase match),
    /// consume it and return it when its CID matches `want_cid`.
    pub(crate) fn try_poll_io(&mut self, want_cid: u16) -> Option<Cqe> {
        let base = self.io_cq + (self.io_cq_head as u64) * 16;
        let mut b = [0u8; 16];
        self.t.dma_read(base, &mut b);
        let cqe = cqe_from_bytes(&b);
        if cqe.phase() == self.io_cq_phase {
            self.io_cq_head = (self.io_cq_head + 1) % self.io_size.max(1);
            if self.io_cq_head == 0 {
                self.io_cq_phase = !self.io_cq_phase;
            }
            let db = off::DOORBELL_BASE + 3 * self.doorbell_stride;
            self.t.write32(db, self.io_cq_head as u32);
            if cqe.cid() == want_cid {
                return Some(cqe);
            }
        }
        None
    }
}

fn sqe_to_bytes(sqe: &Sqe) -> [u8; 64] {
    let mut b = [0u8; 64];
    let mut i = 0;
    while i < 16 {
        let le = sqe.0[i].to_le_bytes();
        b[i * 4] = le[0];
        b[i * 4 + 1] = le[1];
        b[i * 4 + 2] = le[2];
        b[i * 4 + 3] = le[3];
        i += 1;
    }
    b
}

fn cqe_from_bytes(b: &[u8; 16]) -> Cqe {
    let mut c = [0u32; 4];
    let mut i = 0;
    while i < 4 {
        c[i] = u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        i += 1;
    }
    Cqe(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockNvme;
    use alloc::vec;

    #[test]
    fn init_and_identify() {
        let mock = MockNvme::new(1 << 20, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 20);
        assert!(c.init().is_ok());
        assert_eq!(c.namespace_size(), 1024);
        assert_eq!(c.lba_size(), 512);
    }

    #[test]
    fn single_block_round_trip() {
        let mock = MockNvme::new(1 << 20, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 20);
        assert!(c.init().is_ok());
        let mut data = [0u8; 512];
        let mut i = 0;
        while i < 512 {
            data[i] = (i & 0xFF) as u8;
            i += 1;
        }
        assert!(c.write(0, 1, &data).is_ok());
        let mut read = [0u8; 512];
        assert!(c.read(0, 1, &mut read).is_ok());
        assert_eq!(read, data);
    }

    #[test]
    fn two_page_round_trip() {
        let mock = MockNvme::new(1 << 21, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 21);
        assert!(c.init().is_ok());
        let n = 16u16; // 16 * 512 = 8192 = 2 pages
        let nbytes = (n as usize) * 512;
        let mut data = vec![0u8; nbytes];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        assert!(c.write(4, n, &data).is_ok());
        let mut read = vec![0u8; nbytes];
        assert!(c.read(4, n, &mut read).is_ok());
        assert_eq!(read, data);
    }

    #[test]
    fn prp_list_round_trip() {
        let mock = MockNvme::new(1 << 22, 4096, 9); // 4 MiB DMA
        let mut c = Controller::new(mock, 0, 1 << 22);
        assert!(c.init().is_ok());
        let n = 24u16; // 24 * 512 = 12288 = 3 pages -> PRP list
        let nbytes = (n as usize) * 512;
        let mut data = vec![0u8; nbytes];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 7) % 256) as u8;
        }
        assert!(c.write(100, n, &data).is_ok());
        let mut read = vec![0u8; nbytes];
        assert!(c.read(100, n, &mut read).is_ok());
        assert_eq!(read, data);
    }

    #[test]
    fn flush_succeeds() {
        let mock = MockNvme::new(1 << 20, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 20);
        assert!(c.init().is_ok());
        assert!(c.flush().is_ok());
    }
    #[test]
    fn rejects_short_buffers_and_out_of_range_requests() {
        let mut c = init_for_invalid_tests();
        assert_eq!(c.write(0, 2, &[0u8; 512]), Err(NvmeError::BufferTooSmall));
        assert_eq!(c.read(2048, 1, &mut [0u8; 512]), Err(NvmeError::OutOfRange));
        assert_eq!(c.read(0, 0, &mut []), Err(NvmeError::InvalidArgs));
    }

    fn init_for_invalid_tests() -> Controller<MockNvme> {
        let mock = MockNvme::new(1 << 20, 2048, 9);
        let mut c = Controller::new(mock, 0, 1 << 20);
        assert!(c.init().is_ok());
        c
    }

}
