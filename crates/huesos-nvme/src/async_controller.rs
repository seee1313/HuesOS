//! Async NVMe controller: wraps the polling [`Controller`] so each I/O is a
//! future driven by [`hues_async::block_on`].
//!
//! An I/O future submits via the controller's split primitives (`prepare_*`)
//! and completes when its completion-queue entry appears (`try_poll_io`). The
//! future parks (returns `Pending`) and wakes itself to be re-polled until the
//! completion arrives; `block_on` drives this loop. With the in-memory mock the
//! completion is immediate, so the submit -> park/wake -> CQE -> complete path
//! is exercised end-to-end on the host. A real DriverHost passes a `park` that
//! processes completions and/or awaits the MSI-X interrupt via a HuesOS Port.
//!
//! ## Event-driven completions (MSI-X)
//!
//! For real hardware, the completion loop can be driven by MSI-X interrupts
//! instead of polling. The [`InterruptController`] trait abstracts interrupt
//! delivery: when an interrupt arrives, the corresponding task is woken via
//! the hues-async waker mechanism. The hybrid model (poll briefly, then wait
//! for interrupt) balances latency and efficiency.

use crate::controller::{Controller, NvmeError};
use crate::transport::NvmeTransport;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Abstraction over interrupt delivery for event-driven completions.
///
/// Implementations register a waker for a command ID (CID) and invoke it
/// when the corresponding completion arrives (via MSI-X interrupt or Port
/// notification). The default [`PollingInterrupts`] implementation wakes
/// immediately, preserving the polling behavior.
pub trait InterruptController {
    /// Register a waker for the given CID. When the completion arrives,
    /// the waker will be invoked to re-poll the I/O future.
    fn register_waker(&mut self, cid: u16, waker: &core::task::Waker);
    /// Notify that a completion has arrived for the given CID. This invokes
    /// the registered waker (if any) to re-poll the I/O future.
    fn notify_completion(&mut self, cid: u16);
    /// Clear the waker registration for the given CID (after completion).
    fn clear_waker(&mut self, cid: u16);
}

/// Polling-based interrupt controller: wakes immediately on notification.
/// This preserves the existing polling behavior for host tests and mock
/// transports. Real drivers will use an MSI-X-backed implementation.
pub struct PollingInterrupts;

impl InterruptController for PollingInterrupts {
    fn register_waker(&mut self, _cid: u16, waker: &core::task::Waker) {
        // Polling model: wake immediately to re-poll.
        waker.wake_by_ref();
    }
    fn notify_completion(&mut self, _cid: u16) {
        // No-op: polling model doesn't track completions.
    }
    fn clear_waker(&mut self, _cid: u16) {
        // No-op: polling model doesn't track wakers.
    }
}

/// An async NVMe controller over a transport `T` with interrupt controller `I`.
///
/// The interrupt controller `I` abstracts completion delivery: polling-based
/// ([`PollingInterrupts`]) for host tests, or MSI-X-backed for real hardware.
pub struct AsyncController<T: NvmeTransport, I: InterruptController = PollingInterrupts> {
    ctrl: Controller<T>,
    interrupts: I,
}

impl<T: NvmeTransport> AsyncController<T, PollingInterrupts> {
    /// Wrap a (not-yet-initialized) controller with polling interrupts.
    pub fn new(ctrl: Controller<T>) -> Self {
        Self {
            ctrl,
            interrupts: PollingInterrupts,
        }
    }
}

impl<T: NvmeTransport, I: InterruptController> AsyncController<T, I> {
    /// Wrap a controller with a custom interrupt controller.
    pub fn with_interrupts(ctrl: Controller<T>, interrupts: I) -> Self {
        Self { ctrl, interrupts }
    }

    /// Borrow the inner controller (for geometry, etc.).
    pub fn controller(&self) -> &Controller<T> {
        &self.ctrl
    }

    /// Borrow the interrupt controller (for MSI-X registration, etc.).
    pub fn interrupts(&mut self) -> &mut I {
        &mut self.interrupts
    }

    /// Initialize the controller (delegates to the sync controller).
    pub fn init(&mut self) -> Result<(), NvmeError> {
        self.ctrl.init()
    }

    /// Namespace size in blocks.
    pub fn namespace_size(&self) -> u64 {
        self.ctrl.namespace_size()
    }

    /// LBA size in bytes.
    pub fn lba_size(&self) -> u32 {
        self.ctrl.lba_size()
    }

    /// Read `nlb` blocks at `lba` into `buf`, asynchronously. `park` is invoked
    /// whenever the I/O is pending and not yet woken.
    pub fn read_async(
        &mut self,
        lba: u64,
        nlb: u16,
        buf: &mut [u8],
        park: impl FnMut(),
    ) -> Result<(), NvmeError> {
        let nbytes = self.ctrl.checked_io_bytes(lba, nlb)?;
        if buf.len() < nbytes as usize {
            return Err(NvmeError::BufferTooSmall);
        }
        let (cid, dma, nbytes) = self.ctrl.prepare_read(lba, nlb)?;
        let fut = IoFuture {
            ctrl: &mut self.ctrl,
            interrupts: &mut self.interrupts,
            cid,
            dma,
            nbytes,
            out: Some(buf),
            phase: 0,
        };
        hues_async::block_on(fut, park)
    }

    /// Write `nlb` blocks at `lba` from `buf`, asynchronously.
    pub fn write_async(
        &mut self,
        lba: u64,
        nlb: u16,
        buf: &[u8],
        park: impl FnMut(),
    ) -> Result<(), NvmeError> {
        let (cid, _, _) = self.ctrl.prepare_write(lba, nlb, buf)?;
        let fut = IoFuture {
            ctrl: &mut self.ctrl,
            interrupts: &mut self.interrupts,
            cid,
            dma: 0,
            nbytes: 0,
            out: None,
            phase: 0,
        };
        hues_async::block_on(fut, park)
    }
}

/// The I/O completion future: yields once (exercising the waker), then polls
/// the completion queue until the command's CQE appears. Uses the interrupt
/// controller to register wakers for event-driven completions.
struct IoFuture<'a, T: NvmeTransport, I: InterruptController> {
    ctrl: &'a mut Controller<T>,
    interrupts: &'a mut I,
    cid: u16,
    dma: u64,
    nbytes: u64,
    out: Option<&'a mut [u8]>,
    phase: u8,
}

impl<T: NvmeTransport, I: InterruptController> Future for IoFuture<'_, T, I> {
    type Output = Result<(), NvmeError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.phase == 0 {
            this.phase = 1;
            // Register waker for event-driven completion (MSI-X).
            this.interrupts.register_waker(this.cid, cx.waker());
            return Poll::Pending;
        }
        match this.ctrl.try_poll_io(this.cid) {
            Some(cqe) => {
                // Completion arrived. Clear waker registration.
                this.interrupts.clear_waker(this.cid);
                if !cqe.is_success() {
                    return Poll::Ready(Err(NvmeError::CommandFailed {
                        sct: cqe.sct(),
                        sc: cqe.sc(),
                    }));
                }
                if let Some(buf) = this.out.take() {
                    this.ctrl.finish_read(this.dma, this.nbytes, buf);
                }
                Poll::Ready(Ok(()))
            }
            None => {
                // No completion yet. Re-register waker and park.
                this.interrupts.register_waker(this.cid, cx.waker());
                Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockNvme;
    use alloc::vec;
    use core::sync::atomic::{AtomicU32, Ordering};

    fn init_async() -> AsyncController<MockNvme> {
        let mock = MockNvme::new(1 << 21, 2048, 9);
        let ctrl = Controller::new(mock, 0, 1 << 21);
        let mut a = AsyncController::new(ctrl);
        assert!(a.init().is_ok());
        a
    }

    #[test]
    fn async_write_then_read_round_trip() {
        static PARKS: AtomicU32 = AtomicU32::new(0);
        PARKS.store(0, Ordering::SeqCst);
        let mut a = init_async();
        let mut data = vec![0u8; 512];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        assert!(a.write_async(3, 1, &data, || {}).is_ok());
        let mut read = vec![0u8; 512];
        assert!(a.read_async(3, 1, &mut read, || {}).is_ok());
        assert_eq!(read, data);
    }

    #[test]
    fn async_io_parks_zero_times_with_immediate_completion() {
        // The mock completes synchronously, and the future wakes itself, so the
        // park hook is never needed.
        let mut a = init_async();
        let parks = AtomicU32::new(0);
        let data = vec![7u8; 512];
        assert!(a
            .write_async(0, 1, &data, || {
                parks.fetch_add(1, Ordering::SeqCst);
            })
            .is_ok());
        assert_eq!(parks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn async_multi_block_round_trip() {
        let mut a = init_async();
        let n = 16u16; // 8192 bytes = 2 pages
        let nbytes = (n as usize) * 512;
        let mut data = vec![0u8; nbytes];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 3) % 256) as u8;
        }
        assert!(a.write_async(20, n, &data, || {}).is_ok());
        let mut read = vec![0u8; nbytes];
        assert!(a.read_async(20, n, &mut read, || {}).is_ok());
        assert_eq!(read, data);
    }
}
