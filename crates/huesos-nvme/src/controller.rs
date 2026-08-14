//! Synchronous NVMe controller driving a [`NvmeTransport`].
//!
//! This is the polling-based core: it initializes the controller (enable,
//! Identify, Set Features, Create I/O queues) and issues Read/Write/Flush via
//! PRP-described buffers, polling the completion queues. The async layer (in
//! `async_controller`) wraps this so each I/O is a `hues-async` future woken by
//! its completion; the queue/command machinery here is shared.

use crate::cmd::{build, identify, Cqe, Sqe};
use crate::identify::{
    parse_controller, parse_namespace, ControllerInfo, IdentifyError, NamespaceInfo, IDENTIFY_BYTES,
};
use crate::queue_plan::{plan_queues, InterruptMode, QueuePlan, QueuePlanInput};
// Synchronous completion-poll budget. Iterations are cheap (one
// 16-byte DMA read of the CQ slot); a slow emulated controller
// (QEMU under TCG on a contended CI runner) can take longer than
// 1M iterations to post a completion, and an exhausted budget
// surfaces as NvmeError::Timeout -> an Io error to the Hxfs
// service. 50M is still a bounded wait (a few seconds worst
// case) but absorbs realistic emulation jitter.
const IO_POLL_BUDGET: u32 = 50_000_000;

/// PRP-list pages allocated beyond the first, for chaining.
///
/// With 4 KiB pages one list page addresses 511 data pages once its
/// last slot is spent on the chain pointer, so 1 + 4 pages cover
/// 2045 data pages — just over 8 MiB, comfortably above the 1 MiB
/// MDTS cap this driver advertises. `setup_prp` rejects anything that
/// still does not fit rather than programming a truncated list.
const MAX_EXTRA_PRP_LIST_PAGES: usize = 4;

/// Upper bound on planned PRP-list slots, sized for the largest
/// transfer the allocated list pages can describe (5 pages x 512
/// slots). Kept as a stack array so the I/O path stays allocation
/// free, which the no-heap NVMe DriverHost policy requires.
const MAX_PRP_SLOTS: usize = (1 + MAX_EXTRA_PRP_LIST_PAGES) * 512;

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
    /// Queue planning failed for the discovered CAP/CPU/interrupt inputs.
    InvalidQueuePlan,
    /// Identify Controller returned data that failed parser validation.
    InvalidIdentifyController,
    /// Identify Namespace returned data that failed parser validation.
    InvalidIdentifyNamespace,
    /// PRP layout for a transfer is not supported by the current bounded pool.
    InvalidPrp,
    /// The request lies outside the identified namespace.
    OutOfRange,
    /// The caller buffer is smaller than the requested transfer.
    BufferTooSmall,
}

/// Production initialization policy for a controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerConfig {
    /// Online CPU count used for per-CPU I/O queue planning.
    pub cpu_count: usize,
    /// Whether MSI-X metadata/resources are available.
    pub msix_available: bool,
    /// Whether MSI metadata/resources are available.
    pub msi_available: bool,
    /// Operator cap on queue depth from the `nvme.max_queue_depth`
    /// runtime knob. `0` means the operator has expressed no opinion
    /// and only the hardware limit applies.
    pub max_queue_depth: u16,
}

impl ControllerConfig {
    /// Conservative single-queue polling configuration used by legacy tests.
    pub const fn single_queue_polling() -> Self {
        Self {
            cpu_count: 1,
            msix_available: false,
            msi_available: false,
            max_queue_depth: 0,
        }
    }
}

/// Result of controller initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerInitInfo {
    /// Parsed controller Identify data.
    pub controller: ControllerInfo,
    /// Parsed namespace Identify data.
    pub namespace: NamespaceInfo,
    /// Queue/DMA plan used for admin and I/O queue creation.
    pub queue_plan: QueuePlan,
    /// I/O queues successfully created.
    pub io_queue_count: usize,
}

/// A polling NVMe controller over a transport `T`.
pub struct Controller<T: NvmeTransport> {
    t: T,
    page_size: u32,
    doorbell_stride: u32,
    dma_next: u64,
    /// Base of the DMA window. `dma_next` is a bump pointer, so a
    /// controller reset must rewind to this before re-running init;
    /// otherwise every reset permanently consumes the pool and the
    /// third or fourth one fails with `OutOfDma`.
    dma_base: u64,
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
    io_queue_count: usize,
    cid: u16,
    // Namespace.
    nsid: u32,
    nsze: u64,
    lba_size: u32,
    // Last Identify parser error (for diagnostics; `None` until a parse
    // failure is observed). Public accessor exposes the reason so the
    // userspace DriverHost can print a precise failure marker without
    // changing the public error type.
    last_identify_error: Option<&'static str>,
    identify_buf: u64,
    io_data_buf: u64,
    io_data_buf_size: u64,
    io_prp_list: u64,
    // Additional PRP-list pages for chaining. `io_prp_list` is the
    // first; these follow it. A transfer needing more entries than one
    // page can hold links pages together through the last slot of each.
    io_prp_list_extra: [u64; MAX_EXTRA_PRP_LIST_PAGES],
    io_prp_list_count: usize,
    // Capabilities (validated during init).
    mdts: u32,
    max_queue_size: u16,
    /// Config of the last successful init, replayed by `reset()`.
    last_config: Option<ControllerConfig>,
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
            dma_base,
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
            io_queue_count: 0,
            cid: 0,
            nsid: 1,
            nsze: 0,
            lba_size: 0,
            last_identify_error: None,
            identify_buf: 0,
            io_data_buf: 0,
            io_data_buf_size: 0,
            io_prp_list: 0,
            io_prp_list_extra: [0; MAX_EXTRA_PRP_LIST_PAGES],
            io_prp_list_count: 0,
            mdts: 0,
            max_queue_size: 0,
            last_config: None,
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

    /// Maximum data transfer size in bytes (MDTS).
    pub fn mdts(&self) -> u32 {
        self.mdts
    }

    /// Maximum queue size (entries) supported by the controller.
    pub fn max_queue_size(&self) -> u16 {
        self.max_queue_size
    }

    /// Number of I/O queue pairs created during initialization.
    pub fn io_queue_count(&self) -> usize {
        self.io_queue_count
    }

    /// Reason of the most recent Identify parse failure, if any.
    ///
    /// The synchronous `NvmeError::InvalidIdentifyController` and
    /// `NvmeError::InvalidIdentifyNamespace` variants intentionally do not
    /// carry a sub-reason to keep the public error type stable, but on a
    /// real bring-up failure it is essential for the DriverHost to log the
    /// exact parser rejection (`buffer-too-small`, `empty-namespace`, etc.)
    /// rather than a single opaque marker. The DriverHost calls this
    /// immediately after `init_with_config` returns an
    /// `InvalidIdentify{Controller,Namespace}` to print a precise reason.
    /// `None` before the first failure (including the success path).
    pub fn last_identify_error(&self) -> Option<&'static str> {
        self.last_identify_error
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

    fn dma_alloc_zeroed(&mut self, bytes: u64, align: u64) -> Result<u64, NvmeError> {
        let addr = self.dma_alloc(bytes, align)?;
        self.dma_zero(addr, bytes);
        Ok(addr)
    }

    fn dma_zero(&mut self, addr: u64, bytes: u64) {
        let zero = [0u8; 64];
        let mut done = 0u64;
        while done < bytes {
            let chunk = (bytes - done).min(zero.len() as u64) as usize;
            self.t.dma_write(addr + done, &zero[..chunk]);
            done += chunk as u64;
        }
    }

    pub(crate) fn checked_io_bytes(&self, lba: u64, nlb: u16) -> Result<u64, NvmeError> {
        if self.lba_size == 0 || self.nsze == 0 {
            return Err(NvmeError::NotReady);
        }
        if nlb == 0 {
            return Err(NvmeError::InvalidArgs);
        }
        let end = lba.checked_add(nlb as u64).ok_or(NvmeError::OutOfRange)?;
        if end > self.nsze {
            return Err(NvmeError::OutOfRange);
        }
        let bytes = (nlb as u64)
            .checked_mul(self.lba_size as u64)
            .ok_or(NvmeError::InvalidQueuePlan)?;
        // MDTS validation: transfer size must not exceed controller capability.
        if bytes > self.mdts as u64 {
            return Err(NvmeError::InvalidArgs);
        }
        // Alignment validation: buffer must be aligned to LBA size.
        // (Caller is responsible for providing aligned buffers; we validate the
        // transfer size is a multiple of LBA size.)
        if bytes % (self.lba_size as u64) != 0 {
            return Err(NvmeError::InvalidArgs);
        }
        Ok(bytes)
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
        let cqe = self.poll_admin(IO_POLL_BUDGET)?;
        if cqe.is_success() {
            Ok(cqe)
        } else {
            Err(NvmeError::CommandFailed {
                sct: cqe.sct(),
                sc: cqe.sc(),
            })
        }
    }

    /// Reset the controller and rebuild admin/I/O queues from scratch.
    ///
    /// This is the recovery half of the timeout path: a command that
    /// never completes leaves the controller with queues the host can
    /// no longer reason about (the device may still complete the
    /// command later and write into a slot the host has reused), so
    /// the only safe move is CC.EN=0 followed by a full
    /// re-initialization.
    ///
    /// Queue state is rebuilt rather than reused: doorbells, phase
    /// bits and command ids all restart from zero on the device side,
    /// so keeping the host-side copies would desynchronize the two.
    ///
    /// Replays the configuration of the last successful init, so a
    /// controller brought up with multiple I/O queues comes back with
    /// the same shape. Returns `NotReady` if the controller was never
    /// initialized.
    pub fn reset(&mut self) -> Result<ControllerInitInfo, NvmeError> {
        let config = self.last_config.ok_or(NvmeError::NotReady)?;
        let capv = self.t.read64(off::CAP);
        // Best-effort disable. A controller that is already wedged may
        // never clear CSTS.RDY; that is not a reason to skip the
        // re-init attempt, since CC.EN=0 has still been written.
        let _ = self.disable_controller(capv);
        self.init_with_config(config)
    }

    /// Initialize the controller with a conservative single-queue polling plan.
    pub fn init(&mut self) -> Result<(), NvmeError> {
        self.init_with_config(ControllerConfig::single_queue_polling())
            .map(|_| ())
    }

    /// Initialize the controller: disable/reset, bring up the admin queue from
    /// the preallocated DMA pool, Identify controller/namespace, and create
    /// per-CPU I/O queues according to `config`.
    pub fn init_with_config(
        &mut self,
        config: ControllerConfig,
    ) -> Result<ControllerInitInfo, NvmeError> {
        // Init allocates every queue and buffer from the DMA bump
        // allocator. Re-running it after a reset must start from the
        // same base, or each recovery would leak the whole previous
        // set of queues and the pool would run dry.
        self.dma_next = self.dma_base;
        self.last_config = Some(config);
        // Host-side queue state must match a freshly enabled
        // controller, since CC.EN=0 makes the device restart its
        // doorbells, phase bits and command ids from zero. Doing this
        // here rather than in `reset()` keeps one definition of "a
        // just-initialized controller" for both the first bring-up
        // and every recovery.
        self.admin_sq_tail = 0;
        self.admin_cq_head = 0;
        self.admin_cq_phase = true;
        self.io_sq_tail = 0;
        self.io_cq_head = 0;
        self.io_cq_phase = true;
        self.cid = 0;
        self.io_queue_count = 0;
        let capv = self.t.read64(off::CAP);
        self.page_size = cap::min_page_size(capv) as u32;
        self.doorbell_stride = cap::doorbell_stride_bytes(capv);
        let mqes_entries = cap::mqes(capv).max(2);
        self.max_queue_size = mqes_entries;
        let plan = plan_queues(QueuePlanInput {
            cpu_count: config.cpu_count.max(1),
            cap_mqes: mqes_entries.saturating_sub(1),
            msix_available: config.msix_available,
            msi_available: config.msi_available,
            max_queue_depth: config.max_queue_depth,
        })
        .ok_or(NvmeError::InvalidArgs)?;
        self.admin_size = plan.admin_depth.min(mqes_entries).max(2);
        self.io_size = plan.io_depth.min(mqes_entries).max(2);

        self.disable_controller(capv)?;

        let ps = self.page_size as u64;
        self.admin_sq = self.dma_alloc_zeroed(self.admin_size as u64 * 64, ps)?;
        self.admin_cq = self.dma_alloc_zeroed(self.admin_size as u64 * 16, ps)?;

        self.t.write32(
            off::AQA,
            aqa::build(self.admin_size as u32, self.admin_size as u32),
        );
        self.t.write64(off::ASQ, self.admin_sq);
        self.t.write64(off::ACQ, self.admin_cq);

        self.t.write32(off::CC, cc::enable(0, 6, 4, cc::CSS_NVM));
        self.wait_ready(capv, true)?;

        self.identify_buf = self.dma_alloc_zeroed(IDENTIFY_BYTES as u64, ps)?;
        self.admin_command(build::identify(
            identify::CONTROLLER,
            0,
            0,
            self.identify_buf,
        ))?;

        let mut ctrl_id = [0u8; IDENTIFY_BYTES];
        self.t.dma_read(self.identify_buf, &mut ctrl_id);
        let controller_info = parse_controller(&ctrl_id, self.page_size).map_err(|e| {
            self.last_identify_error = Some(identify_error_label(e));
            NvmeError::InvalidIdentifyController
        })?;
        self.mdts = controller_info.max_request_bytes;
        self.io_data_buf_size = self.mdts as u64;
        self.io_data_buf = self.dma_alloc_zeroed(self.io_data_buf_size, ps)?;
        self.io_prp_list = self.dma_alloc_zeroed(ps, ps)?;
        // Chain pages: allocated up front so the I/O path never
        // allocates. Each must be page aligned because the chain
        // pointer names a page base.
        let mut extra = 0usize;
        while extra < MAX_EXTRA_PRP_LIST_PAGES {
            self.io_prp_list_extra[extra] = self.dma_alloc_zeroed(ps, ps)?;
            extra += 1;
        }
        self.io_prp_list_count = 1 + MAX_EXTRA_PRP_LIST_PAGES;

        self.admin_command(build::identify(
            identify::NAMESPACE,
            0,
            self.nsid,
            self.identify_buf,
        ))?;

        let mut ns_id = [0u8; IDENTIFY_BYTES];
        self.t.dma_read(self.identify_buf, &mut ns_id);
        let namespace_info = parse_namespace(self.nsid, &ns_id).map_err(|e| {
            self.last_identify_error = Some(identify_error_label(e));
            NvmeError::InvalidIdentifyNamespace
        })?;
        self.nsze = namespace_info.block_count;
        self.lba_size = namespace_info.block_size;

        let requested = plan.io_queue_count.clamp(1, u16::MAX as usize) as u16;
        let set_queues = self.admin_command(build::set_number_of_queues(requested, requested))?;
        let granted_sq = ((set_queues.result() & 0xffff) as u16)
            .saturating_add(1)
            .min(requested);
        let granted_cq = ((set_queues.result() >> 16) as u16)
            .saturating_add(1)
            .min(requested);
        let create_count = granted_sq.min(granted_cq).max(1) as usize;
        self.create_io_queues(create_count, plan.interrupt_mode)?;

        Ok(ControllerInitInfo {
            controller: controller_info,
            namespace: namespace_info,
            queue_plan: plan,
            io_queue_count: self.io_queue_count,
        })
    }

    fn disable_controller(&mut self, capv: u64) -> Result<(), NvmeError> {
        self.t.write32(off::CC, 0);
        self.wait_ready(capv, false)
    }

    fn wait_ready(&mut self, capv: u64, ready: bool) -> Result<(), NvmeError> {
        let budget = ready_poll_budget(capv);
        let target = if ready { csts::RDY } else { 0 };
        for _ in 0..budget {
            if self.t.read32(off::CSTS) & csts::RDY == target {
                return Ok(());
            }
        }
        Err(NvmeError::NotReady)
    }

    fn create_io_queues(
        &mut self,
        count: usize,
        interrupt_mode: InterruptMode,
    ) -> Result<(), NvmeError> {
        let ps = self.page_size as u64;
        self.io_queue_count = 0;
        for index in 0..count {
            let qid = (index + 1) as u16;
            let cq = self.dma_alloc_zeroed(self.io_size as u64 * 16, ps)?;
            let sq = self.dma_alloc_zeroed(self.io_size as u64 * 64, ps)?;
            let vector = index.min(u16::MAX as usize) as u16;
            let interrupt_enabled = !matches!(interrupt_mode, InterruptMode::Polling);
            self.admin_command(build::create_io_cq(
                qid,
                self.io_size,
                cq,
                vector,
                interrupt_enabled,
            ))?;
            self.admin_command(build::create_io_sq(qid, self.io_size, sq, qid))?;
            if qid == 1 {
                self.io_cq = cq;
                self.io_sq = sq;
                self.io_sq_tail = 0;
                self.io_cq_head = 0;
                self.io_cq_phase = true;
            }
            self.io_queue_count += 1;
        }
        Ok(())
    }

    // --- I/O queue ---

    /// Compute PRP1/PRP2 for a transfer, delegating the layout rules
    /// to the audited [`crate::prp`] module.
    ///
    /// The previous implementation computed page addresses as
    /// `buf + n * page_size`, which silently assumed `buf` was page
    /// aligned. For an unaligned buffer that names the wrong physical
    /// pages: the device would then DMA over memory the driver never
    /// intended to expose. It also derived the page count from
    /// `nbytes` alone, ignoring the offset within the first page, so
    /// a transfer straddling one extra page programmed one PRP entry
    /// too few.
    ///
    /// `prp::pages_touched` and `prp::fill_rest` handle both cases
    /// (that is what they were written and unit-tested for), so this
    /// function now routes through them instead of duplicating —
    /// incorrectly — the same arithmetic.
    fn setup_prp(&mut self, buf: u64, nbytes: u64) -> Result<(u64, u64), NvmeError> {
        let ps = self.page_size as u64;
        let page_size = self.page_size;
        // The offset of the buffer within its own page: this is what
        // the old code dropped.
        let offset = (buf & (ps - 1)) as u32;
        let base = buf - u64::from(offset);
        let length = u32::try_from(nbytes).map_err(|_| NvmeError::InvalidPrp)?;

        let pages = crate::prp::pages_touched(offset, length, page_size);
        match pages {
            0 | 1 => Ok((crate::prp::prp1(base, offset), 0)),
            2 => Ok((
                crate::prp::prp1(base, offset),
                crate::prp::rest_page(base, offset, page_size, 0),
            )),
            _ => {
                if self.io_prp_list == 0 {
                    return Err(NvmeError::InvalidPrp);
                }
                // Collect the list pages: the first plus however many
                // chain pages were allocated at init.
                let mut pages = [0u64; 1 + MAX_EXTRA_PRP_LIST_PAGES];
                pages[0] = self.io_prp_list;
                let available = self.io_prp_list_count.min(pages.len()).max(1);
                let mut i = 1usize;
                while i < available {
                    pages[i] = self.io_prp_list_extra[i - 1];
                    i += 1;
                }

                // Plan the layout, including chain pointers. A
                // transfer too large for the allocated pages is
                // rejected here: programming a partial list would let
                // the device DMA into whatever the unwritten slots
                // happen to hold.
                let mut slots = [crate::prp::ListSlot {
                    list_page: 0,
                    slot: 0,
                    value: 0,
                    is_chain: false,
                }; MAX_PRP_SLOTS];
                let planned = crate::prp::plan_list(
                    base,
                    offset,
                    length,
                    page_size,
                    &pages[..available],
                    &mut slots,
                )
                .ok_or(NvmeError::InvalidPrp)?;

                let mut index = 0usize;
                while index < planned {
                    let entry = slots[index];
                    let page = pages[entry.list_page];
                    self.t
                        .dma_write(page + (entry.slot as u64) * 8, &entry.value.to_le_bytes());
                    index += 1;
                }
                Ok((crate::prp::prp1(base, offset), self.io_prp_list))
            }
        }
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
            Err(NvmeError::CommandFailed {
                sct: cqe.sct(),
                sc: cqe.sc(),
            })
        }
    }

    /// Read `nlb` logical blocks starting at `lba` into `buf` (synchronous).
    pub fn read(&mut self, lba: u64, nlb: u16, buf: &mut [u8]) -> Result<(), NvmeError> {
        let nbytes = self.checked_io_bytes(lba, nlb)?;
        if buf.len() < nbytes as usize {
            return Err(NvmeError::BufferTooSmall);
        }
        let (cid, dma, nbytes) = self.prepare_read(lba, nlb)?;
        let cqe = self.poll_io(cid, IO_POLL_BUDGET)?;
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
        let cqe = self.poll_io(cid, IO_POLL_BUDGET)?;
        Self::check(&cqe)
    }

    /// Flush volatile write cache to non-volatile media.
    pub fn flush(&mut self) -> Result<(), NvmeError> {
        if self.io_size == 0 {
            return Err(NvmeError::NotReady);
        }
        let cid = self.submit_io(build::flush(self.nsid));
        let cqe = self.poll_io(cid, IO_POLL_BUDGET)?;
        Self::check(&cqe)
    }

    // --- split submit/complete primitives (shared with the async wrapper) ---

    /// Allocate the data buffer + PRP and submit a Read; returns
    /// `(cid, dma_addr, nbytes)`. The completion is awaited separately.
    pub(crate) fn prepare_read(
        &mut self,
        lba: u64,
        nlb: u16,
    ) -> Result<(u16, u64, u64), NvmeError> {
        let nbytes = self.checked_io_bytes(lba, nlb)?;
        if self.io_data_buf == 0 || nbytes > self.io_data_buf_size {
            return Err(NvmeError::OutOfDma);
        }
        let dma = self.io_data_buf;
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
        if self.io_data_buf == 0 || nbytes > self.io_data_buf_size {
            return Err(NvmeError::OutOfDma);
        }
        let dma = self.io_data_buf;
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

fn ready_poll_budget(capv: u64) -> u32 {
    let timeout_ms = cap::timeout_ms(capv).max(500);
    timeout_ms.saturating_mul(200).min(u32::MAX as u64) as u32
}

fn identify_error_label(error: IdentifyError) -> &'static str {
    match error {
        IdentifyError::BufferTooSmall => "buffer-too-small",
        IdentifyError::InvalidMdts => "invalid-mdts",
        IdentifyError::EmptyNamespace => "empty-namespace",
        IdentifyError::InvalidLbaFormat => "invalid-lba-format",
        IdentifyError::UnsupportedLbaSize => "unsupported-lba-size",
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

    /// A reset must leave the controller usable again.
    #[test]
    fn reset_rebuilds_the_controller_and_io_keeps_working() {
        let mock = MockNvme::new(1 << 20, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 20);
        assert!(c.init().is_ok());
        let data = [0x5Au8; 512];
        assert!(c.write(0, 1, &data).is_ok());

        assert!(c.reset().is_ok(), "reset must bring the controller back");

        // Namespace geometry must be re-identified, not stale.
        assert_eq!(c.namespace_size(), 1024);
        assert_eq!(c.lba_size(), 512);
        // And I/O must work against the rebuilt queues.
        let mut read = [0u8; 512];
        assert!(c.read(0, 1, &mut read).is_ok());
        assert_eq!(read, data, "data written before the reset must survive");
    }

    /// Resets must not leak the DMA pool.
    ///
    /// Queues and buffers come from a bump allocator, so re-running
    /// init without rewinding it consumes the window a few resets in
    /// and recovery starts failing with `OutOfDma` — exactly when the
    /// device is already misbehaving and recovery matters most.
    #[test]
    fn repeated_resets_do_not_exhaust_the_dma_pool() {
        let mock = MockNvme::new(1 << 20, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 20);
        assert!(c.init().is_ok());
        let after_first_init = c.dma_next;
        let mut round = 0u32;
        while round < 32 {
            let outcome = c.reset();
            assert!(outcome.is_ok(), "reset {round} failed: {outcome:?}");
            assert_eq!(
                c.dma_next, after_first_init,
                "reset {round} did not rewind the DMA bump pointer"
            );
            round += 1;
        }
        let mut read = [0u8; 512];
        assert!(c.read(0, 1, &mut read).is_ok(), "I/O after 32 resets");
    }

    /// Resetting a controller that was never initialized is a
    /// programming error, not a silent no-op.
    #[test]
    fn reset_before_init_is_rejected() {
        let mock = MockNvme::new(1 << 20, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 20);
        assert_eq!(c.reset().err(), Some(NvmeError::NotReady));
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

    /// `setup_prp` must derive page addresses from the buffer's own
    /// page base, not from the buffer address itself.
    ///
    /// The old implementation returned `buf + n * page_size`, which
    /// for an unaligned buffer names addresses that are not page
    /// bases at all — the device would DMA to the wrong physical
    /// pages. It also ignored the offset when counting pages, so a
    /// transfer that straddles one more page than `nbytes / ps`
    /// suggests programmed too few entries.
    #[test]
    fn setup_prp_handles_unaligned_buffers() {
        let mock = MockNvme::new(1 << 21, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 21);
        assert!(c.init().is_ok());
        let ps = c.page_size as u64;

        // A buffer sitting half a page in. 2 pages' worth of bytes
        // starting mid-page touches THREE pages.
        let unaligned = (ps * 4) + (ps / 2);
        let Ok((prp1, prp2)) = c.setup_prp(unaligned, ps * 2) else {
            assert!(false, "unaligned three-page transfer must be accepted");
            return;
        };
        assert_eq!(prp1, unaligned, "PRP1 is the first byte address");
        assert_ne!(prp2, 0, "three pages require a PRP list");
        assert_eq!(prp2, c.io_prp_list);

        // The first list entry must be the NEXT page boundary, which
        // is `ps * 5` — not `unaligned + ps`.
        let mut entry = [0u8; 8];
        c.t.dma_read(c.io_prp_list, &mut entry);
        assert_eq!(
            u64::from_le_bytes(entry),
            ps * 5,
            "list entries must be page-aligned bases"
        );

        // An unaligned transfer that fits inside one page needs no PRP2.
        let Ok((_, small_prp2)) = c.setup_prp(unaligned, 16) else {
            assert!(false, "single-page transfer must be accepted");
            return;
        };
        assert_eq!(small_prp2, 0);

        // Exactly two pages from an aligned base uses a direct PRP2.
        let Ok((aligned_prp1, aligned_prp2)) = c.setup_prp(ps * 4, ps * 2) else {
            assert!(false, "two-page transfer must be accepted");
            return;
        };
        assert_eq!(aligned_prp1, ps * 4);
        assert_eq!(aligned_prp2, ps * 5, "PRP2 is the second page base");
    }

    /// A transfer needing more PRP entries than one list page can
    /// hold must chain to a second list page, not be rejected.
    ///
    /// Before chaining existed, `setup_prp` returned `InvalidPrp`
    /// here, which made the advertised MDTS a promise the driver
    /// could not keep.
    #[test]
    fn setup_prp_chains_across_list_pages() {
        let mock = MockNvme::new(1 << 26, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 26);
        assert!(c.init().is_ok());
        let ps = c.page_size as u64;
        let per_page = (c.page_size / 8) as u64;

        // One more data page than a single list page can address once
        // its last slot is spent on the chain pointer.
        let data_pages = per_page + 2;
        let nbytes = data_pages * ps;
        let buf = ps * 16;

        let Ok((prp1, prp2)) = c.setup_prp(buf, nbytes) else {
            assert!(false, "a chained transfer must be accepted");
            return;
        };
        assert_eq!(prp1, buf);
        assert_eq!(prp2, c.io_prp_list, "PRP2 names the first list page");

        // Last slot of the first list page must point at the second
        // list page, not at a data page.
        let mut raw = [0u8; 8];
        c.t.dma_read(c.io_prp_list + (per_page - 1) * 8, &mut raw);
        let chain = u64::from_le_bytes(raw);
        assert_eq!(
            chain, c.io_prp_list_extra[0],
            "last slot must chain to the next list page"
        );

        // Data entries stay page-aligned and sequential across the
        // chain boundary.
        c.t.dma_read(c.io_prp_list, &mut raw);
        assert_eq!(u64::from_le_bytes(raw), buf + ps);
        c.t.dma_read(c.io_prp_list + (per_page - 2) * 8, &mut raw);
        assert_eq!(u64::from_le_bytes(raw), buf + (per_page - 1) * ps);
        // First slot of the chained page continues the sequence.
        c.t.dma_read(c.io_prp_list_extra[0], &mut raw);
        assert_eq!(u64::from_le_bytes(raw), buf + per_page * ps);
    }

    /// A transfer larger than every allocated list page can describe
    /// must be refused, never programmed as a truncated list.
    #[test]
    fn setup_prp_rejects_transfers_beyond_list_capacity() {
        let mock = MockNvme::new(1 << 26, 1024, 9);
        let mut c = Controller::new(mock, 0, 1 << 26);
        assert!(c.init().is_ok());
        let ps = c.page_size as u64;
        let per_page = (c.page_size / 8) as u64;
        // Far beyond 5 list pages' worth of data pages.
        let nbytes = per_page * (2 + MAX_EXTRA_PRP_LIST_PAGES as u64) * ps;
        assert_eq!(c.setup_prp(ps * 16, nbytes), Err(NvmeError::InvalidPrp));
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
    fn one_mib_transfer_limit_works_and_oversize_is_rejected() {
        let mut mock = MockNvme::new(8 << 20, 1024, 12);
        mock.set_mdts_raw(8); // 4096 * 2^8 = 1 MiB
        let mut c = Controller::new(mock, 0, 8 << 20);
        assert!(c.init().is_ok());
        let n = 256u16; // 256 * 4096 = 1 MiB
        let nbytes = (n as usize) * 4096;
        let mut data = vec![0u8; nbytes];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = ((i * 13) & 0xff) as u8;
        }
        assert!(c.write(0, n, &data).is_ok());
        let mut read = vec![0u8; nbytes];
        assert!(c.read(0, n, &mut read).is_ok());
        assert_eq!(read, data);
        let mut oversized = vec![0u8; nbytes + 4096];
        assert_eq!(
            c.read(0, n + 1, &mut oversized),
            Err(NvmeError::InvalidArgs)
        );
    }

    #[test]
    fn init_with_config_creates_per_cpu_queues_and_identifies() {
        let mock = MockNvme::new(1 << 22, 4096, 12);
        let mut c = Controller::new(mock, 0, 1 << 22);
        let info = c.init_with_config(ControllerConfig {
            cpu_count: 4,
            msix_available: true,
            msi_available: true,
            max_queue_depth: 0,
        });
        assert!(info.is_ok());
        let Ok(info) = info else {
            return;
        };
        assert_eq!(info.namespace.block_size, 4096);
        assert_eq!(info.io_queue_count, 4);
        assert_eq!(c.io_queue_count(), 4);
        assert_eq!(info.queue_plan.interrupt_mode, InterruptMode::Msix);
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
