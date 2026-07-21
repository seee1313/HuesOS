//! NVMe transport abstraction and an in-memory mock controller.
//!
//! The driver talks to a device through [`NvmeTransport`]: register accesses on
//! BAR0 plus DMA-memory reads/writes for the queues and data buffers. On real
//! hardware these are backed by the kernel's BAR mapping and DMA VMOs (see
//! docs/NVME.md); for host tests, [`MockNvme`] simulates a small NVMe
//! controller entirely in memory so the full submit -> CQE -> wake path can be
//! exercised without hardware.

use alloc::vec;
use alloc::vec::Vec;
use crate::cmd::{admin, feature, identify, io, status, Cqe, Sqe};
use crate::regs::{aqa, cap, cc, csts, off};

/// Abstraction over the controller's registers (BAR0) and DMA memory.
pub trait NvmeTransport {
    /// Read a 64-bit register at byte offset `off`.
    fn read64(&mut self, off: u32) -> u64;
    /// Write a 64-bit register at byte offset `off`.
    fn write64(&mut self, off: u32, val: u64);
    /// Read a 32-bit register at byte offset `off`.
    fn read32(&mut self, off: u32) -> u32;
    /// Write a 32-bit register at byte offset `off`.
    fn write32(&mut self, off: u32, val: u32);
    /// Read `buf.len()` bytes of DMA memory at physical address `addr`.
    fn dma_read(&mut self, addr: u64, buf: &mut [u8]);
    /// Write `buf` to DMA memory at physical address `addr`.
    fn dma_write(&mut self, addr: u64, buf: &[u8]);
}

/// One simulated I/O queue pair (SQ + CQ in DMA memory).
#[derive(Clone, Copy)]
struct IoQueue {
    sq_base: u64,
    cq_base: u64,
    size: u16,    // entry count
    cq_head: u16,
    sq_head: u16,
    cq_phase: bool,
    #[allow(dead_code)] // recorded from Create I/O CQ; used for MSI-X routing
    vector: u16,
}

/// An in-memory mock NVMe controller for host tests.
///
/// `mem` is the DMA address space (queues + data buffers); `disk` is the
/// namespace backing store (lba_size * nsze bytes). Commands are processed
/// synchronously when the corresponding SQ tail doorbell is written.
pub struct MockNvme {
    cap: u64,
    cc: u32,
    csts: u32,
    aqa: u32,
    asq: u64,
    acq: u64,
    admin_sq_head: u16,
    admin_cq_head: u16,
    admin_cq_phase: bool,
    admin_size: u16,
    io: [Option<IoQueue>; 16],
    mem: Vec<u8>,
    disk: Vec<u8>,
    page_size: u32,
    nsze: u64,
    lba_shift: u32,
    num_io_queues: u16,
    admin_sq_tail: u16,
}

impl MockNvme {
    /// Create a mock controller.
    /// `mem_size`: DMA address-space bytes. `disk_blocks`: namespace size in
    /// logical blocks. `lba_shift`: log2 of the LBA size (e.g. 9 = 512 B).
    pub fn new(mem_size: usize, disk_blocks: u64, lba_shift: u32) -> Self {
        let page_size = 4096u32;
        // CAP: MQES=63 (64 entries), DSTRD=0, TO=1 (500ms), MPSMIN=MPSMAX=0 (4K).
        let cap = 63u64 | (1u64 << cap::TO_SHIFT);
        Self {
            cap,
            cc: 0,
            csts: 0,
            aqa: 0,
            asq: 0,
            acq: 0,
            admin_sq_head: 0,
            admin_cq_head: 0,
            admin_cq_phase: true,
            admin_size: 0,
            io: [None; 16],
            mem: vec![0u8; mem_size],
            disk: vec![0u8; (disk_blocks as usize) << lba_shift],
            page_size,
            nsze: disk_blocks,
            lba_shift,
            num_io_queues: 0,
            admin_sq_tail: 0,
        }
    }

    /// Borrow the DMA memory (for the test/driver to set up buffers).
    pub fn mem(&mut self) -> &mut [u8] {
        &mut self.mem
    }
    /// Borrow the disk backing store.
    pub fn disk(&self) -> &[u8] {
        &self.disk
    }
    /// LBA size in bytes.
    pub fn lba_size(&self) -> u32 {
        1 << self.lba_shift
    }

    // --- command processing ---

    fn process_admin(&mut self) {
        // Process SQEs from admin_sq_head up to the SQ tail (stored when the
        // doorbell was written). We track the tail in a field set by doorbell.
        let sq_tail = self.admin_sq_tail;
        while self.admin_sq_head != sq_tail {
            let mut sqe = [0u32; 16];
            let base = self.asq as usize + (self.admin_sq_head as usize) * 64;
            for (i, dw) in sqe.iter_mut().enumerate() {
                let o = base + i * 4;
                *dw = u32::from_le_bytes([
                    self.mem[o],
                    self.mem[o + 1],
                    self.mem[o + 2],
                    self.mem[o + 3],
                ]);
            }
            let sqe = Sqe(sqe);
            let cqe = self.exec_admin(&sqe);
            self.post_admin_cqe(sqe.cid(), cqe);
            self.admin_sq_head = self.admin_sq_head.wrapping_add(1) % self.admin_size.max(1);
        }
    }

    fn exec_admin(&mut self, sqe: &Sqe) -> u32 {
        match sqe.opcode() {
            admin::IDENTIFY => {
                self.write_identify((sqe.cdw10() & 0xFF) as u8, sqe.prp1());
                0
            }
            admin::SET_FEATURES => {
                let fid = (sqe.cdw10() & 0xFF) as u8;
                if fid == feature::NUMBER_OF_QUEUES {
                    // Grant what was requested (echo back in CDW0 of CQE).
                    let nsqr = (sqe.cdw11() & 0xFFFF) as u16;
                    let ncqr = (sqe.cdw11() >> 16) as u16;
                    let granted = nsqr.min(ncqr);
                    self.num_io_queues = granted;
                    granted as u32 | ((granted as u32) << 16)
                } else {
                    0
                }
            }
            admin::CREATE_IO_CQ => {
                let qid = (sqe.cdw10() & 0xFFFF) as u16;
                let size = ((sqe.cdw10() >> 16) as u16) + 1;
                let vector = (sqe.cdw11() >> 16) as u16;
                if (qid as usize) < self.io.len() {
                    self.io[qid as usize] = Some(IoQueue {
                        sq_base: 0,
                        cq_base: sqe.prp1(),
                        size,
                        cq_head: 0,
                        sq_head: 0,
                        cq_phase: true,
                        vector,
                    });
                }
                0
            }
            admin::CREATE_IO_SQ => {
                let qid = (sqe.cdw10() & 0xFFFF) as u16;
                let size = ((sqe.cdw10() >> 16) as u16) + 1;
                if let Some(q) = self.io.get_mut(qid as usize).and_then(|x| x.as_mut()) {
                    q.sq_base = sqe.prp1();
                    q.size = size;
                }
                0
            }
            _ => 0,
        }
    }

    fn write_identify(&mut self, cns: u8, prp1: u64) {
        let mut data = [0u8; 4096];
        match cns {
            identify::CONTROLLER => {
                // A few fields: VID at 0, and a model string-ish; tests only
                // need a non-zero, plausible structure.
                data[0] = 0x86;
                data[1] = 0x80; // VID
            }
            identify::NAMESPACE => {
                // NSZE (bytes 7:0), NCAP (15:8), LBAF0 LBADS at byte 26.
                data[0..8].copy_from_slice(&self.nsze.to_le_bytes());
                data[8..16].copy_from_slice(&self.nsze.to_le_bytes());
                // LBAF0: LBADS at byte 26 (offset within the LBAF array at 128).
                data[128 + 2] = self.lba_shift as u8;
            }
            _ => {}
        }
        let base = prp1 as usize;
        if base + 4096 <= self.mem.len() {
            self.mem[base..base + 4096].copy_from_slice(&data);
        }
    }

    fn post_admin_cqe(&mut self, cid: u16, result: u32) {
        let cqe = self.build_cqe(cid, result, self.admin_cq_phase);
        let base = self.acq as usize + (self.admin_cq_head as usize) * 16;
        self.write_cqe(base, &cqe);
        self.admin_cq_head = self.admin_cq_head.wrapping_add(1) % self.admin_size.max(1);
        if self.admin_cq_head == 0 {
            self.admin_cq_phase = !self.admin_cq_phase;
        }
    }

    fn process_io(&mut self, qid: u16, sq_tail: u16) {
        let (sq_base, cq_base, size, mut cq_head, mut sq_head, mut cq_phase) =
            match self.io[qid as usize] {
                Some(q) => (q.sq_base, q.cq_base, q.size, q.cq_head, q.sq_head, q.cq_phase),
                None => return,
            };
        while sq_head != sq_tail {
            let mut sqe = [0u32; 16];
            let base = sq_base as usize + (sq_head as usize) * 64;
            for (i, dw) in sqe.iter_mut().enumerate() {
                let o = base + i * 4;
                *dw = u32::from_le_bytes([
                    self.mem[o],
                    self.mem[o + 1],
                    self.mem[o + 2],
                    self.mem[o + 3],
                ]);
            }
            let sqe = Sqe(sqe);
            let result = self.exec_io(&sqe);
            let cqe = self.build_cqe(sqe.cid(), result, cq_phase);
            let cbase = cq_base as usize + (cq_head as usize) * 16;
            self.write_cqe(cbase, &cqe);
            sq_head = sq_head.wrapping_add(1) % size.max(1);
            cq_head = cq_head.wrapping_add(1) % size.max(1);
            if cq_head == 0 {
                cq_phase = !cq_phase;
            }
        }
        if let Some(q) = self.io[qid as usize].as_mut() {
            q.sq_head = sq_head;
            q.cq_head = cq_head;
            q.cq_phase = cq_phase;
        }
    }

    fn exec_io(&mut self, sqe: &Sqe) -> u32 {
        let lba = sqe.starting_lba();
        let nlb = ((sqe.cdw12() & 0xFFFF) as u64) + 1;
        let lba_size = self.lba_size() as u64;
        let nbytes = (nlb * lba_size) as usize;
        let disk_off = (lba * lba_size) as usize;
        match sqe.opcode() {
            // `dma_scatter` borrows `&mut self` (writes `mem`), so the disk
            // slice is copied out first to avoid an overlapping borrow.
            #[allow(clippy::unnecessary_to_owned)]
            io::READ => {
                if disk_off + nbytes <= self.disk.len() {
                    let data = self.disk[disk_off..disk_off + nbytes].to_vec();
                    self.dma_scatter(sqe.prp1(), sqe.prp2(), &data);
                }
                0
            }
            io::WRITE => {
                let data = self.dma_gather(sqe.prp1(), sqe.prp2(), nbytes);
                if disk_off + nbytes <= self.disk.len() {
                    self.disk[disk_off..disk_off + nbytes].copy_from_slice(&data);
                }
                0
            }
            io::FLUSH => 0,
            _ => (status::SC_INVALID_OPCODE as u32) << status::SC_SHIFT,
        }
    }

    // Copy `data` into DMA memory at the PRP-described region.
    fn dma_scatter(&mut self, prp1: u64, prp2: u64, data: &[u8]) {
        let ps = self.page_size as usize;
        let first_off = (prp1 as usize) % ps;
        let first_len = (ps - first_off).min(data.len());
        let p1 = prp1 as usize;
        if p1 + first_len <= self.mem.len() {
            self.mem[p1..p1 + first_len].copy_from_slice(&data[..first_len]);
        }
        let mut rest = &data[first_len..];
        if rest.is_empty() {
            return;
        }
        // Remaining full pages via PRP2 (single page or PRP list).
        let entries = self.prp_entries(prp2, rest.len());
        for e in entries {
            let n = ps.min(rest.len());
            let a = e as usize;
            if a + n <= self.mem.len() {
                self.mem[a..a + n].copy_from_slice(&rest[..n]);
            }
            rest = &rest[n..];
            if rest.is_empty() {
                break;
            }
        }
    }

    // Gather `nbytes` from DMA memory at the PRP-described region.
    fn dma_gather(&mut self, prp1: u64, prp2: u64, nbytes: usize) -> Vec<u8> {
        let ps = self.page_size as usize;
        let mut out = Vec::with_capacity(nbytes);
        let first_off = (prp1 as usize) % ps;
        let first_len = (ps - first_off).min(nbytes);
        let p1 = prp1 as usize;
        if p1 + first_len <= self.mem.len() {
            out.extend_from_slice(&self.mem[p1..p1 + first_len]);
        }
        let mut need = nbytes - first_len;
        if need == 0 {
            return out;
        }
        let entries = self.prp_entries(prp2, need);
        for e in entries {
            let n = ps.min(need);
            let a = e as usize;
            if a + n <= self.mem.len() {
                out.extend_from_slice(&self.mem[a..a + n]);
            }
            need -= n;
            if need == 0 {
                break;
            }
        }
        out
    }

    // Resolve PRP2 into the list of subsequent page addresses for `nbytes`.
    fn prp_entries(&self, prp2: u64, nbytes: usize) -> Vec<u64> {
        let ps = self.page_size as usize;
        let pages = nbytes.div_ceil(ps);
        let mut v = Vec::with_capacity(pages);
        if pages == 1 {
            v.push(prp2);
        } else if pages > 1 && prp2 != 0 {
            // PRP2 points to a PRP list page.
            let base = prp2 as usize;
            for i in 0..pages {
                let o = base + i * 8;
                if o + 8 <= self.mem.len() {
                    let e = u64::from_le_bytes([
                        self.mem[o],
                        self.mem[o + 1],
                        self.mem[o + 2],
                        self.mem[o + 3],
                        self.mem[o + 4],
                        self.mem[o + 5],
                        self.mem[o + 6],
                        self.mem[o + 7],
                    ]);
                    v.push(e);
                }
            }
        }
        v
    }

    fn build_cqe(&self, cid: u16, result: u32, phase: bool) -> Cqe {
        let mut c = [0u32; 4];
        c[0] = result;
        let st = status::build(phase, status::SCT_GENERIC, status::SC_SUCCESS, false);
        c[3] = cid as u32 | ((st as u32) << 16);
        Cqe(c)
    }

    fn write_cqe(&mut self, base: usize, cqe: &Cqe) {
        if base + 16 <= self.mem.len() {
            for (i, dw) in cqe.0.iter().enumerate() {
                let b = dw.to_le_bytes();
                let o = base + i * 4;
                self.mem[o] = b[0];
                self.mem[o + 1] = b[1];
                self.mem[o + 2] = b[2];
                self.mem[o + 3] = b[3];
            }
        }
    }
}

impl NvmeTransport for MockNvme {
    fn read64(&mut self, off: u32) -> u64 {
        match off {
            off::CAP => self.cap,
            off::ASQ => self.asq,
            off::ACQ => self.acq,
            _ => {
                let lo = self.read32(off);
                let hi = self.read32(off + 4);
                ((hi as u64) << 32) | lo as u64
            }
        }
    }
    fn write64(&mut self, off: u32, val: u64) {
        match off {
            off::ASQ => self.asq = val & !0xFFF,
            off::ACQ => self.acq = val & !0xFFF,
            _ => {
                self.write32(off, val as u32);
                self.write32(off + 4, (val >> 32) as u32);
            }
        }
    }
    fn read32(&mut self, off: u32) -> u32 {
        match off {
            off::CC => self.cc,
            off::CSTS => self.csts,
            off::AQA => self.aqa,
            off::VS => 0x0001_0400, // NVMe 1.4
            _ => 0,
        }
    }
    fn write32(&mut self, off: u32, val: u32) {
        if off >= off::DOORBELL_BASE {
            self.write_doorbell(off, val);
            return;
        }
        match off {
            off::CC => {
                self.cc = val;
                if val & cc::EN != 0 {
                    self.csts |= csts::RDY;
                } else {
                    self.csts &= !csts::RDY;
                }
            }
            off::AQA => {
                self.aqa = val;
                self.admin_size = aqa::asqs(val) as u16;
            }
            _ => {}
        }
    }
    fn dma_read(&mut self, addr: u64, buf: &mut [u8]) {
        let a = addr as usize;
        if a + buf.len() <= self.mem.len() {
            buf.copy_from_slice(&self.mem[a..a + buf.len()]);
        }
    }
    fn dma_write(&mut self, addr: u64, buf: &[u8]) {
        let a = addr as usize;
        if a + buf.len() <= self.mem.len() {
            self.mem[a..a + buf.len()].copy_from_slice(buf);
        }
    }
}

impl MockNvme {
    fn write_doorbell(&mut self, off: u32, val: u32) {
        let stride = cap::doorbell_stride_bytes(self.cap);
        let n = (off - off::DOORBELL_BASE) / stride;
        let qid = (n / 2) as u16;
        let is_cq = n % 2 == 1;
        if is_cq {
            return; // CQ head doorbell: mock tracks its own CQ head
        }
        let tail = val as u16;
        if qid == 0 {
            self.admin_sq_tail = tail;
            self.process_admin();
        } else if (qid as usize) < self.io.len() && self.io[qid as usize].is_some() {
            self.process_io(qid, tail);
        }
    }
}
